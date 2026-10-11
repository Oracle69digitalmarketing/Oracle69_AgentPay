/**
 * M1 deterministic policy engine — pure function, no I/O.
 *
 * Guarantees:
 * - No LLM, network, wallet, key, database, or clock access. Time (`now`)
 *   is injected via context for reproducibility.
 * - Fails closed: any malformed input or config yields rejection.
 * - Deterministic: reasons sorted by REASON_ORDER then message; identical
 *   input always yields identical output.
 * - Approval never overrides policy: MISSING_APPROVAL is appended LAST and
 *   only matters when every other check passes.
 * - `allowed: true` means POLICY SATISFIED ONLY — not authorized, not
 *   executable. Signature verification + replay protection + gated execution
 *   arrive in later milestones.
 *
 * Expiry boundary: a request is EXPIRED when `now >= expiresAt`.
 * Equality (now === expiresAt) is therefore rejected.
 */
import {
  REASON_ORDER,
  type PaymentIntent,
  type PolicyAllowed,
  type PolicyConfig,
  type PolicyContext,
  type PolicyDecision,
  type PolicyReason,
  type RejectionCode,
} from "./types.js";
import {
  isPlainObject,
  normalizeAddress,
  parseContext,
  toChecksumAddress,
  validateAmountWei,
  validateAsset,
  validateChainId,
  validateConfig,
  validateExpiresAt,
  validateNonce,
  validatePurpose,
  validateRecipient,
  validateRequestId,
} from "./validation.js";

const ORDER_INDEX: ReadonlyMap<RejectionCode, number> = new Map(
  REASON_ORDER.map((code, i) => [code, i]),
);

export function sortReasons(reasons: PolicyReason[]): PolicyReason[] {
  return [...reasons].sort((a, b) => {
    const oa = ORDER_INDEX.get(a.code) ?? 999;
    const ob = ORDER_INDEX.get(b.code) ?? 999;
    if (oa !== ob) return oa - ob;
    return a.message < b.message ? -1 : a.message > b.message ? 1 : 0;
  });
}

function isExpired(expiresAt: number, now: number): boolean {
  return now >= expiresAt;
}

export function evaluatePolicy(intent: unknown, config: unknown, context: unknown): PolicyDecision {
  // 1. Config first — never evaluate against an unsafe config.
  const configReasons = validateConfig(config);
  if (configReasons.length > 0) return { allowed: false, reasons: sortReasons(configReasons) };
  const cfg = config as PolicyConfig;

  const reasons: PolicyReason[] = [];

  // 2. Context must be well-formed; malformed context fails closed.
  const parsed = parseContext(context);
  reasons.push(...parsed.reasons);

  // 3. Intent must be a plain object.
  if (!isPlainObject(intent)) {
    reasons.push({ code: "INVALID_REQUEST", message: "intent must be an object" });
    return { allowed: false, reasons: sortReasons(reasons) };
  }
  const raw = intent as Record<string, unknown>;
  const intentT = intent as Partial<PaymentIntent>;

  // Required-field presence check (deterministic field order).
  const requiredFields = [
    "requestId",
    "recipient",
    "amountWei",
    "asset",
    "purpose",
    "chainId",
    "nonce",
    "expiresAt",
  ] as const;
  for (const f of requiredFields) {
    if (!(f in raw) || raw[f] === undefined) {
      reasons.push({ code: "INVALID_REQUEST", message: `missing required field: ${f}` });
    }
  }

  // 4. Field validations in documented deterministic order.
  reasons.push(...validateRequestId(intentT.requestId));
  reasons.push(...validateNonce(intentT.nonce));
  reasons.push(...validateExpiresAt(intentT.expiresAt));
  reasons.push(...validatePurpose(intentT.purpose));
  reasons.push(...validateAsset(intentT.asset));
  reasons.push(...validateChainId(intentT.chainId, cfg.allowedChainId));
  reasons.push(...validateRecipient(intentT.recipient));

  const amountReasons = validateAmountWei(intentT.amountWei);
  reasons.push(...amountReasons);
  const amountValid =
    amountReasons.length === 0 && typeof intentT.amountWei === "bigint";

  // 5. Allowlist (only when recipient is well-formed).
  const checksummed = toChecksumAddress(intentT.recipient);
  if (checksummed !== null) {
    const allow = new Set((cfg.approvedRecipients as string[]).map((a) => normalizeAddress(a)));
    if (!allow.has(checksummed.toLowerCase())) {
      reasons.push({ code: "NOT_ALLOWLISTED", message: "recipient is not in the approved allowlist" });
    }
  }

  // 6. Spending limit (only when amount is a valid positive bigint).
  if (amountValid) {
    const amount = intentT.amountWei as bigint;
    if (amount > (cfg.maxPerPaymentWei as bigint)) {
      reasons.push({ code: "EXCEEDS_LIMIT", message: "amount exceeds maximum per-payment limit" });
    }
  }

  // 7. Expiry (only when both timestamps are valid integers).
  if (
    typeof intentT.expiresAt === "number" &&
    Number.isInteger(intentT.expiresAt) &&
    parsed.reasons.length === 0
  ) {
    if (isExpired(intentT.expiresAt, parsed.now)) {
      reasons.push({ code: "EXPIRED_REQUEST", message: "request has expired" });
    }
  }

  // 8. Approval LAST — never bypasses any other violation.
  if (cfg.requireHumanApproval === true && parsed.approval !== true) {
    reasons.push({ code: "MISSING_APPROVAL", message: "human approval has not been verified" });
  }

  if (reasons.length > 0) return { allowed: false, reasons: sortReasons(reasons) };

  const allowed: PolicyAllowed = {
    allowed: true,
    requiresApproval: cfg.requireHumanApproval,
    approvalVerified: parsed.approval,
    chainId: intentT.chainId as number,
    asset: intentT.asset as PolicyAllowed["asset"],
  };
  return allowed;
}
