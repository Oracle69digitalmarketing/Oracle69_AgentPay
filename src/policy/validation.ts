/**
 * M1 validation helpers — pure, no I/O, no network, no LLM.
 *
 * All helpers validate UNTRUSTED runtime input (unknown) and fail closed.
 * viem is used ONLY for its pure address utilities (isAddress / getAddress).
 */
import { getAddress, isAddress } from "viem";
import {
  ABSOLUTE_MAX_PAYMENT_WEI,
  MAX_UINT256,
  WEI_PER_MON,
  ZERO_ADDRESS,
  type PolicyReason,
  type RejectionCode,
} from "./types.js";

export const REQUEST_ID_MAX_LEN = 128;
export const NONCE_MAX_LEN = 128;
export const PURPOSE_MAX_LEN = 280;

/** Allowed chars for opaque ids: letters, digits, `_ - : .` */
const ID_PATTERN = /^[A-Za-z0-9_\-:.]+$/;

function reason(code: RejectionCode, message: string): PolicyReason {
  return { code, message };
}

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// ---------------------------------------------------------------------------
// Scalar field validators (return PolicyReason[] so callers stay deterministic)
// ---------------------------------------------------------------------------

export function validateRequestId(v: unknown): PolicyReason[] {
  if (typeof v !== "string" || v.trim().length === 0)
    return [reason("INVALID_REQUEST", "requestId must be a non-empty string")];
  if (v.length > REQUEST_ID_MAX_LEN || !ID_PATTERN.test(v))
    return [reason("INVALID_REQUEST", "requestId is malformed")];
  return [];
}

export function validateNonce(v: unknown): PolicyReason[] {
  if (typeof v !== "string" || v.length === 0)
    return [reason("INVALID_REQUEST", "nonce must be a non-empty string")];
  if (v.length > NONCE_MAX_LEN || !ID_PATTERN.test(v))
    return [reason("INVALID_REQUEST", "nonce is malformed")];
  return [];
}

export function validateExpiresAt(v: unknown): PolicyReason[] {
  if (typeof v !== "number" || !Number.isInteger(v) || !Number.isFinite(v) || v < 0)
    return [reason("INVALID_REQUEST", "expiresAt must be a non-negative integer unix timestamp (seconds)")];
  return [];
}

export function validatePurpose(v: unknown): PolicyReason[] {
  if (typeof v !== "string" || v.trim().length === 0)
    return [reason("INVALID_REQUEST", "purpose must be a non-empty string")];
  if (v.length > PURPOSE_MAX_LEN)
    return [reason("INVALID_REQUEST", "purpose exceeds maximum length")];
  return [];
}

export function validateAsset(v: unknown): PolicyReason[] {
  if (v !== "MON") return [reason("INVALID_ASSET", "only native asset MON is supported")];
  return [];
}

export function validateChainId(v: unknown, allowedChainId: number): PolicyReason[] {
  if (typeof v !== "number" || !Number.isInteger(v) || !Number.isFinite(v) || v <= 0)
    return [reason("INVALID_REQUEST", "chainId must be a positive integer")];
  if (v !== allowedChainId)
    return [reason("WRONG_CHAIN", `wrong chain: got ${String(v)}, expected ${String(allowedChainId)}`)];
  return [];
}

// ---------------------------------------------------------------------------
// Amount validation — bigint wei only, never floating point
// ---------------------------------------------------------------------------

export function validateAmountWei(v: unknown): PolicyReason[] {
  if (typeof v !== "bigint")
    return [reason("INVALID_AMOUNT", "amountWei must be a bigint in wei")];
  if (v <= 0n) return [reason("INVALID_AMOUNT", "amountWei must be greater than zero")];
  if (v > MAX_UINT256) return [reason("INVALID_AMOUNT", "amountWei exceeds uint256")];
  return [];
}

/**
 * Strict decimal MON string → wei bigint parser.
 * Rejects: signs, scientific notation, empty parts, >18 decimals, malformed.
 * Never rounds: excess precision is an error, not a rounding event.
 * Pure helper for future intent-parsing layers; NOT used to accept floats.
 */
export function parseDecimalMonToWei(input: unknown): bigint {
  if (typeof input !== "string") throw new Error("mon amount must be a decimal string");
  if (input.length === 0 || input.length > 64) throw new Error("mon amount malformed");
  if (!/^\d+(\.\d+)?$/.test(input)) throw new Error("mon amount malformed");
  const [whole, frac = ""] = input.split(".") as [string, string?];
  const fraction = frac ?? "";
  if (fraction.length > 18) throw new Error("mon amount exceeds 18 decimal places");
  if (whole === undefined || whole === "") throw new Error("mon amount malformed");
  const padded = fraction.padEnd(18, "0");
  const wei = BigInt(whole) * WEI_PER_MON + (padded === "" ? 0n : BigInt(padded));
  if (wei <= 0n) throw new Error("mon amount must be greater than zero");
  if (wei > MAX_UINT256) throw new Error("mon amount exceeds uint256");
  return wei;
}

// ---------------------------------------------------------------------------
// Address validation (viem pure utilities)
// ---------------------------------------------------------------------------

export function isWellFormedAddress(v: unknown): boolean {
  return typeof v === "string" && isAddress(v);
}

/** Returns checksummed address, or null when malformed. */
export function toChecksumAddress(v: unknown): string | null {
  if (typeof v !== "string" || !isAddress(v)) return null;
  try {
    return getAddress(v);
  } catch {
    return null;
  }
}

export function isZeroAddress(checksummed: string): boolean {
  return checksummed.toLowerCase() === ZERO_ADDRESS.toLowerCase();
}

export function validateRecipient(v: unknown): PolicyReason[] {
  if (typeof v !== "string" || !isAddress(v))
    return [reason("INVALID_ADDRESS", "recipient must be a valid EVM address")];
  let checksummed: string;
  try {
    checksummed = getAddress(v);
  } catch {
    return [reason("INVALID_ADDRESS", "recipient must be a valid EVM address")];
  }
  if (checksummed.toLowerCase() === ZERO_ADDRESS.toLowerCase())
    return [reason("INVALID_ADDRESS", "recipient must not be the zero address")];
  return [];
}

/** Normalize for allowlist comparison: checksummed if valid, else raw string. */
export function normalizeAddress(v: string): string {
  try {
    if (isAddress(v)) return getAddress(v).toLowerCase();
  } catch {
    // fall through
  }
  return v.toLowerCase();
}

// ---------------------------------------------------------------------------
// Config validation — fail closed, never silently correct
// ---------------------------------------------------------------------------

export function validateConfig(v: unknown): PolicyReason[] {
  const out: PolicyReason[] = [];
  if (!isPlainObject(v)) return [reason("INVALID_CONFIG", "config must be an object")];
  const c = v as Record<string, unknown>;

  // allowedChainId
  if (typeof c["allowedChainId"] !== "number" || !Number.isInteger(c["allowedChainId"]) || (c["allowedChainId"] as number) <= 0)
    out.push(reason("INVALID_CONFIG", "allowedChainId must be a positive integer"));

  // maxPerPaymentWei: bigint in (0, uint256], AND at or below the absolute
  // 1 MON ceiling. A configuration permitting more is rejected outright —
  // the engine's per-payment limit check can then never authorize > 1 MON.
  if (typeof c["maxPerPaymentWei"] !== "bigint" || (c["maxPerPaymentWei"] as bigint) <= 0n || (c["maxPerPaymentWei"] as bigint) > MAX_UINT256)
    out.push(reason("INVALID_CONFIG", "maxPerPaymentWei must be a bigint in (0, uint256]"));
  else if ((c["maxPerPaymentWei"] as bigint) > ABSOLUTE_MAX_PAYMENT_WEI)
    out.push(reason("INVALID_CONFIG", "maxPerPaymentWei must not exceed the absolute 1 MON ceiling"));

  // requireHumanApproval
  if (typeof c["requireHumanApproval"] !== "boolean")
    out.push(reason("INVALID_CONFIG", "requireHumanApproval must be a boolean"));

  // approvedRecipients
  if (!Array.isArray(c["approvedRecipients"]) || c["approvedRecipients"].length === 0) {
    out.push(reason("INVALID_CONFIG", "approvedRecipients must be a non-empty array"));
  } else {
    const seen = new Set<string>();
    for (const entry of c["approvedRecipients"] as unknown[]) {
      if (typeof entry !== "string" || !isAddress(entry)) {
        out.push(reason("INVALID_CONFIG", "approvedRecipients contains a malformed address"));
        break;
      }
      let cs: string;
      try {
        cs = getAddress(entry);
      } catch {
        out.push(reason("INVALID_CONFIG", "approvedRecipients contains a malformed address"));
        break;
      }
      if (cs.toLowerCase() === ZERO_ADDRESS.toLowerCase()) {
        out.push(reason("INVALID_CONFIG", "approvedRecipients must not contain the zero address"));
        break;
      }
      const key = cs.toLowerCase();
      if (seen.has(key)) {
        out.push(reason("INVALID_CONFIG", "approvedRecipients contains a duplicate address"));
        break;
      }
      seen.add(key);
    }
  }
  return out;
}

/** Validate evaluation context. Returns reasons (INVALID_REQUEST) + parsed values. */
export function parseContext(v: unknown): { reasons: PolicyReason[]; now: number; approval: boolean } {
  if (!isPlainObject(v)) return { reasons: [reason("INVALID_REQUEST", "context must be an object")], now: 0, approval: false };
  const c = v as Record<string, unknown>;
  const reasons: PolicyReason[] = [];
  let now = 0;
  if (typeof c["now"] !== "number" || !Number.isInteger(c["now"]) || !Number.isFinite(c["now"]) || (c["now"] as number) < 0) {
    reasons.push(reason("INVALID_REQUEST", "context.now must be a non-negative integer unix timestamp"));
  } else {
    now = c["now"] as number;
  }
  let approval = false;
  if (typeof c["humanApprovalVerified"] !== "boolean") {
    reasons.push(reason("INVALID_REQUEST", "context.humanApprovalVerified must be a boolean"));
  } else {
    approval = c["humanApprovalVerified"] as boolean;
  }
  return { reasons, now, approval };
}
