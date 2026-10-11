/**
 * M2 authorization types — Oracle69 AgentPay.
 *
 * SECURITY MODEL:
 * - `authorizePayment` ESTABLISHES human approval cryptographically. It never
 *   accepts a caller-supplied boolean as proof.
 * - A valid signature NEVER overrides a policy violation: policy is evaluated
 *   first with approval explicitly ungranted, and only `MISSING_APPROVAL` may
 *   be cured by a verified signature.
 * - A successful result means AUTHORIZATION ONLY (`executed: false`). It must
 *   never be treated as submitted, executed, or settled. No execution or
 *   broadcast capability exists in this module.
 */
import type { PolicyConfig, RejectionCode as PolicyRejectionCode } from "../policy/types.js";
import type { ReplayStore } from "./store/types.js";

/** EIP-712 domain protocol version for the off-chain approval scheme. */
export const AUTH_PROTOCOL_VERSION = "2";

/** Application name bound in the EIP-712 domain. */
export const AUTH_APP_NAME = "Oracle69 AgentPay";

/** Current policy-version identifier. Bump whenever authorization-relevant policy changes. */
export const CURRENT_POLICY_VERSION = "m2.1";

/** Trusted server-side authorization configuration. Approver comes from here, never the request. */
export interface ServerAuthConfig {
  policy: PolicyConfig;
  /** Expected approver EOA address (checksummed at validation). */
  approver: string;
  /** Environment identity, e.g. "agentpay-dev-v1". Must match deployment env. */
  domainId: string;
  /** Policy version this server enforces, e.g. "m2.1". */
  policyVersion: string;
}

/** Untrusted authorization proof transported with the request. No booleans. */
export interface AuthorizationProof {
  /** 65-byte ECDSA signature (0x hex) over the EIP-712 PaymentAuthorization struct. */
  signature: string;
  /** Claimed environment identity; must equal server domainId. */
  domainId: string;
  /** Claimed policy version; must equal server policyVersion. */
  policyVersion: string;
  /** Claimed policy digest (bytes32 hex); must equal recomputed digest. */
  policyDigest: string;
}

/** Full untrusted authorization request. */
export interface AuthorizeInput {
  intent: unknown;
  proof: unknown;
  config: unknown;
  /** Injected unix seconds for deterministic expiry checks. */
  now: unknown;
  store: unknown;
}

export type AuthRejectionCode =
  | PolicyRejectionCode
  | "INVALID_PROOF"
  | "DOMAIN_MISMATCH"
  | "POLICY_VERSION_MISMATCH"
  | "POLICY_DIGEST_MISMATCH"
  | "INVALID_SIGNATURE"
  | "WRONG_SIGNER"
  | "REPLAY_DETECTED"
  | "STORE_UNAVAILABLE";

export interface AuthReason {
  code: AuthRejectionCode;
  message: string;
}

/**
 * Deterministic ordering for authorization reasons. Policy-shape codes keep
 * their M1 relative order; auth-specific codes follow in pipeline order.
 */
export const AUTH_REASON_ORDER: readonly AuthRejectionCode[] = [
  "INVALID_CONFIG",
  "INVALID_REQUEST",
  "INVALID_PROOF",
  "INVALID_ASSET",
  "WRONG_CHAIN",
  "INVALID_ADDRESS",
  "INVALID_AMOUNT",
  "NOT_ALLOWLISTED",
  "EXCEEDS_LIMIT",
  "EXPIRED_REQUEST",
  "DOMAIN_MISMATCH",
  "POLICY_VERSION_MISMATCH",
  "POLICY_DIGEST_MISMATCH",
  "INVALID_SIGNATURE",
  "WRONG_SIGNER",
  "REPLAY_DETECTED",
  "STORE_UNAVAILABLE",
  "MISSING_APPROVAL",
];

export interface AuthorizedPayment {
  authorized: true;
  /** Always false in M2: authorization is not execution. */
  executed: false;
  requestId: string;
  recipient: string;
  amountWei: bigint;
  asset: "MON";
  chainId: number;
  nonce: string;
  expiresAt: number;
  approver: string;
  policyDigest: string;
}

export interface AuthorizationRejected {
  authorized: false;
  reasons: AuthReason[];
}

export type AuthorizationDecision = AuthorizedPayment | AuthorizationRejected;

export type { ReplayStore };
