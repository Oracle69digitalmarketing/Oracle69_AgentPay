/**
 * M1 payment-policy types — Oracle69 AgentPay.
 *
 * SECURITY BOUNDARY (M1):
 * - `evaluatePolicy` decides whether a payment intent SATISFIES POLICY.
 * - It does NOT verify cryptographic signatures, does NOT authorize spending,
 *   and does NOT submit transactions.
 * - A result of `{ allowed: true }` means "policy satisfied, pending complete
 *   authorization" — it must NEVER be treated as executable on its own.
 *   A later authorization module (human-signature verification + replay store)
 *   and a gated executor must re-check policy AND authorization before any
 *   chain interaction.
 */

/** Only supported asset in M1. Native MON on Monad. */
export type SupportedAsset = "MON";

/** Monad Testnet chain id (official docs: docs.monad.xyz/developer-essentials/testnets). */
export const MONAD_TESTNET_CHAIN_ID = 10143;

/** 1 MON in wei. Amounts are ALWAYS bigint wei — never floating point. */
export const WEI_PER_MON = 1_000_000_000_000_000_000n;

/** M1 demonstration limit: 1 MON per transaction. */
export const DEMO_MAX_PER_PAYMENT_WEI = WEI_PER_MON;

/**
 * ABSOLUTE hard ceiling (M4 safeguard): no policy configuration may permit,
 * and no payment may carry, more than 1 MON per transaction. Enforced at the
 * policy-validation boundary (validateConfig rejects larger limits) and
 * re-checked at the execution boundary. Exact bigint; never floats.
 */
export const ABSOLUTE_MAX_PAYMENT_WEI = 1_000_000_000_000_000_000n;

/** Max uint256 value (inclusive upper bound for amounts). */
export const MAX_UINT256 = (1n << 256n) - 1n;

/** Zero address — never a valid recipient. */
export const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

/** Structured payment intent supplied to the policy engine. */
export interface PaymentIntent {
  requestId: string;
  recipient: string;
  amountWei: bigint;
  asset: SupportedAsset;
  purpose: string;
  chainId: number;
  nonce: string;
  /** Unix timestamp in seconds. The request is valid while `now < expiresAt`. */
  expiresAt: number;
}

/** Policy configuration bounding payment authority. */
export interface PolicyConfig {
  approvedRecipients: string[];
  maxPerPaymentWei: bigint;
  allowedChainId: number;
  requireHumanApproval: boolean;
}

/**
 * Evaluation context (M1).
 * - `now`: unix seconds used for expiry checks (injected for reproducibility).
 * - `humanApprovalVerified`: whether a LATER authorization module has already
 *   verified a human approval for the EXACT intent. The engine never verifies
 *   signatures itself; it only reads this flag.
 */
export interface PolicyContext {
  now: number;
  humanApprovalVerified: boolean;
}

/** Stable machine-readable rejection codes. Order matters — see REASON_ORDER. */
export type RejectionCode =
  | "INVALID_REQUEST"
  | "INVALID_ADDRESS"
  | "INVALID_AMOUNT"
  | "INVALID_ASSET"
  | "WRONG_CHAIN"
  | "NOT_ALLOWLISTED"
  | "EXCEEDS_LIMIT"
  | "EXPIRED_REQUEST"
  | "MISSING_APPROVAL"
  | "INVALID_CONFIG";

export interface PolicyReason {
  code: RejectionCode;
  message: string;
}

/**
 * Deterministic ordering of rejection codes.
 * Reasons are ALWAYS sorted by this order (then by message) so the same
 * input produces byte-identical output regardless of object insertion order.
 */
export const REASON_ORDER: readonly RejectionCode[] = [
  "INVALID_CONFIG",
  "INVALID_REQUEST",
  "INVALID_ASSET",
  "WRONG_CHAIN",
  "INVALID_ADDRESS",
  "INVALID_AMOUNT",
  "NOT_ALLOWLISTED",
  "EXCEEDS_LIMIT",
  "EXPIRED_REQUEST",
  "MISSING_APPROVAL",
];

export interface PolicyAllowed {
  allowed: true;
  /** Echoes config.requireHumanApproval: true means a verified approval was required (and present). */
  requiresApproval: boolean;
  approvalVerified: boolean;
  chainId: number;
  asset: SupportedAsset;
}

export interface PolicyRejected {
  allowed: false;
  reasons: PolicyReason[];
}

export type PolicyDecision = PolicyAllowed | PolicyRejected;
