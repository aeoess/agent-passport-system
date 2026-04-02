import type { PublicKey } from "@solana/web3.js";
import type {
  IdentityProvider,
  IdentityResult,
  VerifyOptions,
  Credential,
} from "../types";

const DEFAULT_GATEWAY = "https://gateway.aeoess.com";
const DEFAULT_TIMEOUT_MS = 5000;

export interface APSConfig {
  /** APS gateway URL (default: gateway.aeoess.com) */
  gatewayUrl?: string;
  /** Request timeout in milliseconds (default: 5000) */
  timeoutMs?: number;
  /** Minimum passport grade to consider verified (default: 1) */
  minGrade?: number;
}

interface TrustProfile {
  agentId: string;
  passportGrade: number;
  flags: string[];
  attestationBundleHash?: string;
  reputationScore?: number;
  delegationDepth?: number;
  lastActiveAt?: string;
}

/**
 * Agent Passport System (APS) identity provider.
 *
 * Queries the APS gateway for cryptographic trust profiles:
 * - Passport grade (0-3) based on attestation depth
 * - Attestation flags (issuer_bound, runtime_bound, provider_bound, principal_bound)
 * - Reputation score (Bayesian, confidence-weighted)
 * - Delegation chain depth
 *
 * Public endpoints — no API key needed for verification:
 * - GET /api/v1/public/trust/:agentId → trust profile
 * - GET /api/v1/public/trust/:agentId/attestation → JWS-signed attestation
 * - GET /.well-known/jwks.json → verification keys
 *
 * npm: agent-passport-system | Docs: https://aeoess.com/llms-full.txt
 *
 * @example
 * ```typescript
 * const aps = new APSProvider({ minGrade: 2 });
 * const result = await aps.verify("agent-abc123");
 * console.log(result.trustLevel); // 2 (runtime_bound)
 * console.log(result.credentials); // [{type: "runtime_bound", ...}]
 * ```
 */
export class APSProvider implements IdentityProvider {
  readonly name = "aps";

  private gatewayUrl: string;
  private defaultTimeoutMs: number;
  private minGrade: number;

  constructor(config?: APSConfig) {
    this.gatewayUrl = config?.gatewayUrl ?? DEFAULT_GATEWAY;
    this.defaultTimeoutMs = config?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.minGrade = config?.minGrade ?? 1;
  }

  async verify(
    identifier: string,
    options?: VerifyOptions
  ): Promise<IdentityResult> {
    const timeout = options?.timeoutMs ?? this.defaultTimeoutMs;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    try {
      const res = await fetch(
        `${this.gatewayUrl}/api/v1/public/trust/${encodeURIComponent(identifier)}`,
        { signal: controller.signal }
      );

      if (!res.ok) {
        return {
          verified: false,
          provider: this.name,
          error: `APS gateway returned ${res.status}`,
        };
      }

      const profile: TrustProfile = await res.json();
      const verified = profile.passportGrade >= this.minGrade;

      // Map attestation flags to credentials
      const credentials: Credential[] = profile.flags.map((flag) => ({
        type: flag,
        issuer: this.gatewayUrl,
        subject: profile.agentId,
        issuedAt: profile.lastActiveAt,
      }));

      return {
        verified,
        provider: this.name,
        name: profile.agentId,
        trustLevel: profile.passportGrade,
        credentials,
        reputation: {
          score: profile.reputationScore,
          signals: {
            passportGrade: profile.passportGrade,
            attestationBundleHash: profile.attestationBundleHash,
            delegationDepth: profile.delegationDepth,
            flags: profile.flags,
          },
        },
        metadata: {
          gatewayUrl: this.gatewayUrl,
          jwksUrl: `${this.gatewayUrl}/.well-known/jwks.json`,
          attestationUrl: `${this.gatewayUrl}/api/v1/public/trust/${profile.agentId}/attestation`,
        },
      };
    } catch (err) {
      return {
        verified: false,
        provider: this.name,
        error: err instanceof Error ? err.message : "Unknown error",
      };
    } finally {
      clearTimeout(timer);
    }
  }

  async checkCredentials(
    identifier: string,
    credentialType?: string
  ): Promise<Credential[]> {
    const result = await this.verify(identifier);
    if (!result.credentials) return [];
    if (!credentialType) return result.credentials;
    return result.credentials.filter((c) => c.type === credentialType);
  }
}
