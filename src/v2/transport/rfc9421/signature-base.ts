// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * @fileoverview RFC 9421 signature-base serialization and RFC 9530
 * content-digest construction.
 *
 * Every string here follows the byte conventions specified in RFC 9421 §2.3 and
 * §2.5 and RFC 9530 §2. The functions are pure and deterministic so they can be
 * byte-matched against the published RFC vectors (RFC 9421 Appendix B.2.6, RFC
 * 9530 Appendix B.1).
 *
 * Line format (RFC 9421 §2.5): each covered-component line is
 *   "<lowercased-component-name>": <component-value>\n
 * i.e. the identifier wrapped in DQUOTE, then COLON SPACE, then the value, then
 * a single LF (0x0A, NOT CRLF). The final line is always the @signature-params
 * line and has NO trailing newline.
 */

import crypto from 'node:crypto'
import type {
  CoveredComponent,
  ContentDigestAlgorithm,
  RequestContext,
  SignatureParams,
} from './types.js'

/** ASCII separator between component identifier and value: COLON SPACE. */
const SEP = ': '
/** Line join is a single LF, never CRLF (RFC 9421 §2.5). */
const LF = '\n'

/**
 * Derive @authority per RFC 9421 §2.2.3: lowercased host, with port appended
 * only when it is not the default for the scheme (80 for http, 443 for https).
 */
export function deriveAuthority(url: URL): string {
  const host = url.hostname.toLowerCase()
  const port = url.port
  if (port === '') return host
  const scheme = url.protocol.replace(/:$/, '').toLowerCase()
  const isDefault =
    (scheme === 'http' && port === '80') ||
    (scheme === 'https' && port === '443')
  return isDefault ? host : `${host}:${port}`
}

/**
 * Derive @path per RFC 9421 §2.2.6: the absolute path portion of the target URI
 * in percent-encoded form, with an empty path normalized to "/". Query is NOT
 * included (it is a separate @query component).
 */
export function derivePath(url: URL): string {
  const path = url.pathname
  return path === '' ? '/' : path
}

/**
 * Compute the RFC 9530 Content-Digest field value for the given algorithm over
 * the exact body bytes. Returns the Structured-Fields Dictionary member value,
 * e.g. 'sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:'.
 *
 * The digest is standard base64 (with padding) wrapped in colons (SF Byte
 * Sequence). This binds the body only if 'content-digest' is in the covered set
 * AND the verifier recomputes over received bytes.
 */
export function computeContentDigest(
  body: Uint8Array,
  algorithm: ContentDigestAlgorithm = 'sha-256',
): string {
  if (algorithm !== 'sha-256') {
    throw new Error(`unsupported content-digest algorithm: ${algorithm}`)
  }
  const hash = crypto.createHash('sha256').update(Buffer.from(body)).digest('base64')
  return `sha-256=:${hash}:`
}

/**
 * Serialize the Inner List of covered component identifiers, e.g.
 *   ("@method" "@authority" "@path")
 * Empty list is (). Each identifier is lowercased and DQUOTE-wrapped.
 */
function serializeInnerList(covered: CoveredComponent[]): string {
  const items = covered.map(c => `"${c.toLowerCase()}"`)
  return `(${items.join(' ')})`
}

/**
 * Serialize the Structured-Fields parameters that follow the Inner List, in the
 * fixed declared order created, keyid, nonce, tag, then optional alg, expires.
 * Order is part of the signed bytes (RFC 9421 §2.3).
 *
 * created/expires are Integers (UNQUOTED). keyid/nonce/tag/alg are Strings
 * (QUOTED). Quoted strings escape backslash and DQUOTE per RFC 8941 §4.1.6.
 */
function serializeParams(params: SignatureParams): string {
  const parts: string[] = []
  parts.push(`created=${params.created}`)
  parts.push(`keyid=${sfString(params.keyid)}`)
  parts.push(`nonce=${sfString(params.nonce)}`)
  parts.push(`tag=${sfString(params.tag)}`)
  if (params.alg !== undefined) parts.push(`alg=${sfString(params.alg)}`)
  if (params.expires !== undefined) parts.push(`expires=${params.expires}`)
  return parts.map(p => `;${p}`).join('')
}

/** Serialize a Structured-Fields String (RFC 8941 §4.1.6): DQUOTE-wrapped. */
function sfString(value: string): string {
  const escaped = value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
  return `"${escaped}"`
}

/**
 * Build the value that appears both in the @signature-params base line and in
 * the Signature-Input field value for this label. These MUST be byte-identical.
 */
export function buildSignatureParamsValue(
  covered: CoveredComponent[],
  params: SignatureParams,
): string {
  return `${serializeInnerList(covered)}${serializeParams(params)}`
}

/** Resolve the value for a single covered component from the request context. */
export function resolveComponentValue(
  component: CoveredComponent,
  ctx: RequestContext,
  contentDigest: string | undefined,
): string {
  switch (component) {
    case '@method':
      return ctx.method.toUpperCase()
    case '@authority':
      return deriveAuthority(new URL(ctx.url))
    case '@path':
      return derivePath(new URL(ctx.url))
    case 'content-digest':
      if (contentDigest === undefined) {
        throw new Error('content-digest covered but no digest available')
      }
      return contentDigest
    default: {
      const exhaustive: never = component
      throw new Error(`unknown covered component: ${String(exhaustive)}`)
    }
  }
}

/**
 * Construct the full signature base string per RFC 9421 §2.5: one line per
 * covered component in declared order, each terminated by LF, then the
 * @signature-params line with NO trailing newline.
 *
 * The covered-components list does NOT itself include "@signature-params"; that
 * identifier only appears as the final trailer line.
 *
 * @returns the ASCII base string and the content-digest value used (if any).
 */
export function buildSignatureBase(
  covered: CoveredComponent[],
  ctx: RequestContext,
  params: SignatureParams,
): { base: string; contentDigest?: string } {
  let contentDigest: string | undefined
  if (covered.includes('content-digest')) {
    if (ctx.body === undefined) {
      throw new Error('content-digest covered but request has no body')
    }
    contentDigest = computeContentDigest(ctx.body, 'sha-256')
  }

  const lines: string[] = []
  for (const component of covered) {
    const id = `"${component.toLowerCase()}"`
    const value = resolveComponentValue(component, ctx, contentDigest)
    lines.push(`${id}${SEP}${value}`)
  }
  const paramsValue = buildSignatureParamsValue(covered, params)
  lines.push(`"@signature-params"${SEP}${paramsValue}`)

  return { base: lines.join(LF), contentDigest }
}
