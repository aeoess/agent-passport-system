// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════════
// sharesRoot - signer independence from the key and DID graph
// ══════════════════════════════════════════════════════════════════════
//
// Independence is the SHARP metric for an evidence descriptor. Two signers
// that share a confidence backbone are not independent witnesses, no matter
// how many distinct keys or DIDs they present. Witnesses that chain to the
// same gateway root of trust are still self-attestation.
//
// This file derives that relation MECHANICALLY from a graph the verifier
// already holds: each signer is a node identified by its public key or DID,
// and `chainsTo` edges name the anchors (issuer DID, gateway root, JWKS
// origin, trust-anchor fingerprint) it depends on. Two signers `sharesRoot`
// when their anchor closures intersect. Nothing here reads an issuer-written
// field; nothing grades or scores. It answers one yes/no question per pair:
// do these two signers reduce to a common root?
//
// The relation is reflexive (a signer always shares a root with itself),
// symmetric (order does not matter), and computed over the transitive
// closure of `chainsTo` so an indirect common ancestor still collapses
// independence. It is NOT transitive across signers: A and B sharing a
// root, and B and C sharing a DIFFERENT root, does not make A and C share
// a root. Independence is a per-pair fact, not a partition.
// ══════════════════════════════════════════════════════════════════════

/**
 * One signer as a node in the key and DID graph. A signer is whatever
 * produced a signature the verifier checked: an agent, a gateway, a
 * notary, an external anchor. `id` is its stable identity (public key hex
 * or DID). `chainsTo` lists the roots/anchors it directly depends on:
 * issuer DID, gateway root-of-trust fingerprint, JWKS origin, trust-anchor
 * key id. These are the edges the independence relation closes over.
 *
 * This is a verifier-side projection of facts already on the receipt and
 * in resolution results (e.g. a KeyResolution's selected kid / JWKS
 * origin). It carries no assurance level and no issuer claim.
 */
export interface SignerNode {
  /** Stable signer identity: Ed25519 public key hex, or a DID. */
  id: string
  /** Anchors this signer directly chains to (issuer DID, gateway root,
   *  JWKS origin, trust-anchor fingerprint). Empty = no declared anchor. */
  chainsTo?: string[]
  /** Optional self-describing role, carried through for the descriptor.
   *  Never used to compute independence - only `id`/`chainsTo` are. */
  role?: string
}

/**
 * The signer graph the verifier assembles before computing independence.
 * `nodes` are the signers. `anchorEdges` lets a caller express that two
 * anchors are themselves the same root (e.g. a gateway root that is also a
 * JWKS origin under a different label), without rewriting every node. Both
 * inputs are verifier-supplied facts, never issuer-supplied.
 */
export interface SignerGraph {
  nodes: SignerNode[]
  /** Equivalences between anchor identifiers: each pair names two anchor
   *  ids that denote the same root. Closed over transitively. */
  anchorEdges?: Array<[string, string]>
}

/**
 * Result of the independence relation for one ordered (here symmetric)
 * pair of signers. `independent` is the headline yes/no. `sharedRoots`
 * names the common anchors when they are NOT independent, so a descriptor
 * can report WHY, never a score.
 */
export interface IndependenceRelation {
  signerA: string
  signerB: string
  /** True iff the two signers' anchor closures do not intersect. */
  independent: boolean
  /** The anchors both signers reduce to. Empty iff independent. */
  sharedRoots: string[]
}

/**
 * Build a union-find over anchor identifiers so that `anchorEdges`
 * equivalences collapse to a single representative. This lets two anchors
 * that are really the same root count as shared even under different labels.
 */
function buildAnchorUnion(anchorEdges?: Array<[string, string]>): (a: string) => string {
  const parent = new Map<string, string>()
  const find = (x: string): string => {
    let root = x
    while (parent.has(root) && parent.get(root) !== root) {
      root = parent.get(root)!
    }
    // Path compression for stable, repeatable output.
    let cur = x
    while (parent.has(cur) && parent.get(cur) !== root) {
      const next = parent.get(cur)!
      parent.set(cur, root)
      cur = next
    }
    return root
  }
  const union = (a: string, b: string): void => {
    if (!parent.has(a)) parent.set(a, a)
    if (!parent.has(b)) parent.set(b, b)
    const ra = find(a)
    const rb = find(b)
    if (ra !== rb) {
      // Deterministic representative: lexicographically smaller wins.
      if (ra < rb) parent.set(rb, ra)
      else parent.set(ra, rb)
    }
  }
  for (const [a, b] of anchorEdges ?? []) union(a, b)
  return (a: string): string => (parent.has(a) ? find(a) : a)
}

/**
 * The anchor closure of one signer: the set of canonical root
 * representatives it reduces to. A signer with no `chainsTo` anchors its
 * own identity, so two distinct anchorless signers are independent of each
 * other but a signer always shares a root with itself.
 */
function anchorClosure(node: SignerNode, canonical: (a: string) => string): Set<string> {
  const anchors = node.chainsTo && node.chainsTo.length > 0 ? node.chainsTo : [node.id]
  const out = new Set<string>()
  for (const a of anchors) out.add(canonical(a))
  return out
}

/**
 * sharesRoot: do two signers reduce to a common root in the key/DID graph?
 *
 * Returns the relation, including the shared anchors when they are not
 * independent. Reflexive: a signer always shares a root with itself.
 * Symmetric: the answer does not depend on argument order. Pure: identical
 * inputs always yield identical output, so the descriptor is reproducible.
 *
 * This is the only place independence is decided. It reads `id` and
 * `chainsTo` and nothing else - never an assurance level, never an
 * issuer-written field.
 */
export function sharesRoot(
  a: SignerNode,
  b: SignerNode,
  graph?: Pick<SignerGraph, 'anchorEdges'>
): IndependenceRelation {
  const canonical = buildAnchorUnion(graph?.anchorEdges)
  const closureA = anchorClosure(a, canonical)
  const closureB = anchorClosure(b, canonical)
  const shared: string[] = []
  for (const anchor of closureA) {
    if (closureB.has(anchor)) shared.push(anchor)
  }
  shared.sort()
  return {
    signerA: a.id,
    signerB: b.id,
    independent: shared.length === 0,
    sharedRoots: shared,
  }
}

/**
 * All pairwise independence relations over a signer graph, in a stable
 * order (sorted by signer id, then partner id). Self-pairs are omitted -
 * a signer is trivially non-independent of itself and that fact carries no
 * descriptor signal. Distinct signers that share an `id` collapse to one
 * relation set keyed by first occurrence.
 *
 * Pure over the graph: the same graph always produces the same relations,
 * which is what lets the advisory scalar be reproducible from the
 * descriptor alone.
 */
export function allPairwiseIndependence(graph: SignerGraph): IndependenceRelation[] {
  // De-duplicate signers by id, keeping first occurrence (which carries the
  // chainsTo the verifier assembled for that identity).
  const seen = new Map<string, SignerNode>()
  for (const node of graph.nodes) {
    if (!seen.has(node.id)) seen.set(node.id, node)
  }
  const nodes = [...seen.values()].sort((x, y) => (x.id < y.id ? -1 : x.id > y.id ? 1 : 0))
  const relations: IndependenceRelation[] = []
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      relations.push(sharesRoot(nodes[i], nodes[j], graph))
    }
  }
  return relations
}

/**
 * Count of signers that are independent of EVERY other signer in the graph
 * (no shared root with any peer). This is a mechanical census, not a grade:
 * it just reports how many fully-independent corroborators the evidence
 * carries. A lone signer trivially counts as 1.
 */
export function independentSignerCount(graph: SignerGraph): number {
  const seen = new Map<string, SignerNode>()
  for (const node of graph.nodes) {
    if (!seen.has(node.id)) seen.set(node.id, node)
  }
  const nodes = [...seen.values()]
  if (nodes.length <= 1) return nodes.length
  let count = 0
  for (let i = 0; i < nodes.length; i++) {
    let independentOfAll = true
    for (let j = 0; j < nodes.length; j++) {
      if (i === j) continue
      if (!sharesRoot(nodes[i], nodes[j], graph).independent) {
        independentOfAll = false
        break
      }
    }
    if (independentOfAll) count++
  }
  return count
}
