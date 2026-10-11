/**
 * Server-side authorization — Oracle69 AgentPay (M2).
 *
 * PIPELINE (strict order, fail closed at every step):
 *  1. Validate server config (approver identity originates here).
 *  2. Validate proof shape (hex signature, non-empty envelope fields).
 *  3. Validate `now` (injected; no wall-clock reads).
 *  4. Validate store presence.
 *  5. Run M1 policy with approval explicitly UNGRANTED. Only MISSING_APPROVAL
 *     may proceed.
 *  5b. Build a validated, frozen snapshot of the intent (HIGH-1 fix, see
 *     `snapshotIntent`). Every stage downstream — message construction,
 *     signature verification, replay claim, result — reads ONLY the snapshot,
 *     never the caller-owned object, so post-invoke mutation cannot alter
 *     what was verified.
 *  6. Bind domainId / policyVersion / recomputed policyDigest to server config
 *     (digest computed pre-await from the same policy reference evaluated in
 *     step 5; `cfg`, `proof`, and `currentDigest` are function-local values
 *     the caller cannot reach, and `cfg.policy` is never dereferenced after
 *     the first await).
 *  7. Recover the signer from the server-constructed EIP-712 struct and
 *     compare to the configured approver.
 *  8. Atomically claim (nonce, requestId) in the durable store. Invalid
 *     attempts never reach the store, so they burn nothing; crash after a
 *     successful claim leaves identifiers consumed (fail closed).
 *
 * Result is AUTHORIZATION ONLY (`executed: false`).
 *
 * M3 split: `verifyAuthorization` performs steps 1-3 and 5-7 with NO store
 * interaction and returns the verified snapshot for execution to consume;
 * `authorizePayment` adds step 4 (store presence) and step 8 (claim).
 */
import {
  getAddress,
  isAddress,
  isHex,
  recoverTypedDataAddress,
  type Hex,
} from "viem";
import { evaluatePolicy } from "../policy/engine.js";
import type { PolicyConfig } from "../policy/types.js";
import { ZERO_ADDRESS } from "../policy/types.js";
import { isPlainObject } from "../policy/validation.js";
import {
  PAYMENT_AUTHORIZATION_TYPES,
  PRIMARY_TYPE,
  buildDomain,
  type ApprovalMessage,
} from "./domain.js";
import { computePolicyDigest } from "./policy-digest.js";
import type { ReplayStore } from "./store/types.js";
import {
  AUTH_REASON_ORDER,
  type AuthReason,
  type AuthRejectionCode,
  type AuthorizationDecision,
  type AuthorizeInput,
} from "./types.js";

const ORDER_INDEX = new Map<AuthRejectionCode, number>(
  AUTH_REASON_ORDER.map((code, i) => [code, i]),
);

function sortAuthReasons(reasons: AuthReason[]): AuthReason[] {
  return [...reasons].sort((a, b) => {
    const oa = ORDER_INDEX.get(a.code) ?? 999;
    const ob = ORDER_INDEX.get(b.code) ?? 999;
    if (oa !== ob) return oa - ob;
    return a.message < b.message ? -1 : a.message > b.message ? 1 : 0;
  });
}

function reason(code: AuthRejectionCode, message: string): AuthReason {
  return { code, message };
}

interface ValidServerConfig {
  policy: PolicyConfig;
  approver: string;
  domainId: string;
  policyVersion: string;
}

function validateServerConfig(v: unknown): { reasons: AuthReason[]; cfg: ValidServerConfig | null } {
  if (!isPlainObject(v)) {
    return { reasons: [reason("INVALID_CONFIG", "server config must be an object")], cfg: null };
  }
  const reasons: AuthReason[] = [];
  const c = v as Record<string, unknown>;

  let approver: string | null = null;
  if (typeof c["approver"] !== "string" || !isAddress(c["approver"] as string)) {
    reasons.push(reason("INVALID_CONFIG", "server approver must be a valid EVM address"));
  } else {
    const cs = getAddress(c["approver"] as string);
    if (cs.toLowerCase() === ZERO_ADDRESS.toLowerCase()) {
      reasons.push(reason("INVALID_CONFIG", "server approver must not be the zero address"));
    } else {
      approver = cs;
    }
  }

  let domainId: string | null = null;
  if (typeof c["domainId"] !== "string" || (c["domainId"] as string).trim().length === 0 || (c["domainId"] as string).length > 128) {
    reasons.push(reason("INVALID_CONFIG", "server domainId must be a non-empty string"));
  } else {
    domainId = c["domainId"] as string;
  }

  let policyVersion: string | null = null;
  if (typeof c["policyVersion"] !== "string" || (c["policyVersion"] as string).trim().length === 0 || (c["policyVersion"] as string).length > 64) {
    reasons.push(reason("INVALID_CONFIG", "server policyVersion must be a non-empty string"));
  } else {
    policyVersion = c["policyVersion"] as string;
  }

  if (!isPlainObject(c["policy"])) {
    reasons.push(reason("INVALID_CONFIG", "server policy must be an object"));
  }

  if (reasons.length > 0 || approver === null || domainId === null || policyVersion === null || !isPlainObject(c["policy"])) {
    return { reasons, cfg: null };
  }
  return {
    reasons,
    cfg: {
      policy: c["policy"] as unknown as PolicyConfig,
      approver,
      domainId,
      policyVersion,
    },
  };
}

interface ValidProof {
  signature: Hex;
  domainId: string;
  policyVersion: string;
  policyDigest: Hex;
}

function validateProof(v: unknown): { reasons: AuthReason[]; proof: ValidProof | null } {
  if (!isPlainObject(v)) {
    return { reasons: [reason("INVALID_PROOF", "proof must be an object")], proof: null };
  }
  const reasons: AuthReason[] = [];
  const p = v as Record<string, unknown>;

  let signature: Hex | null = null;
  if (typeof p["signature"] !== "string" || !isHex(p["signature"] as string) || (p["signature"] as string).length !== 132) {
    reasons.push(reason("INVALID_PROOF", "proof.signature must be 0x hex of 65 bytes"));
  } else {
    signature = p["signature"] as Hex;
  }

  let domainId: string | null = null;
  if (typeof p["domainId"] !== "string" || (p["domainId"] as string).length === 0) {
    reasons.push(reason("INVALID_PROOF", "proof.domainId must be a non-empty string"));
  } else {
    domainId = p["domainId"] as string;
  }

  let policyVersion: string | null = null;
  if (typeof p["policyVersion"] !== "string" || (p["policyVersion"] as string).length === 0) {
    reasons.push(reason("INVALID_PROOF", "proof.policyVersion must be a non-empty string"));
  } else {
    policyVersion = p["policyVersion"] as string;
  }

  let policyDigest: Hex | null = null;
  if (typeof p["policyDigest"] !== "string" || !isHex(p["policyDigest"] as string) || (p["policyDigest"] as string).length !== 66) {
    reasons.push(reason("INVALID_PROOF", "proof.policyDigest must be 0x hex of 32 bytes"));
  } else {
    policyDigest = (p["policyDigest"] as string).toLowerCase() as Hex;
  }

  if (reasons.length > 0 || signature === null || domainId === null || policyVersion === null || policyDigest === null) {
    return { reasons, proof: null };
  }
  return { reasons, proof: { signature, domainId, policyVersion, policyDigest } };
}

function isReplayStore(v: unknown): v is ReplayStore {
  return (
    typeof v === "object" &&
    v !== null &&
    typeof (v as { claim?: unknown }).claim === "function"
  );
}

/**
 * HIGH-1 remediation — validated intent snapshot.
 *
 * The caller retains a reference to the `intent` object passed in, and this
 * function suspends at `await recoverTypedDataAddress`. Caller code running
 * before the continuation resumes could otherwise mutate intent fields, so
 * that the replay claim and returned decision reflect values that were never
 * policy-checked or signed.
 *
 * `snapshotIntent` copies every security-relevant field into fresh primitives
 * (checksumming the recipient once) and freezes the result, synchronously,
 * BEFORE the first await. All downstream stages use only the snapshot.
 * `readonly` is documentation; enforcement is copy-at-construction plus
 * `Object.freeze`. A `structuredClone` alone was deliberately not used: it
 * would copy without validating or normalizing (e.g. non-checksummed
 * addresses, wrong runtime types), and a clone taken at the wrong point
 * would not fix the check-vs-use gap.
 *
 * Returns null on any shape violation (fail closed). Null is unreachable when
 * the preceding policy evaluation passed without fatal reasons, since the M1
 * validators enforce the same shapes; the guard exists so the snapshot never
 * trusts the policy result blindly.
 */
export interface IntentSnapshot {
  readonly requestId: string;
  /** Checksummed recipient address. */
  readonly recipient: string;
  readonly amountWei: bigint;
  readonly asset: "MON";
  readonly purpose: string;
  readonly chainId: number;
  readonly nonce: string;
  readonly expiresAt: number;
}

function snapshotIntent(v: unknown): IntentSnapshot | null {
  if (!isPlainObject(v)) return null;
  const r = v as Record<string, unknown>;
  if (typeof r["requestId"] !== "string") return null;
  if (typeof r["recipient"] !== "string" || !isAddress(r["recipient"])) return null;
  let recipient: string;
  try {
    recipient = getAddress(r["recipient"]);
  } catch {
    return null;
  }
  if (typeof r["amountWei"] !== "bigint") return null;
  if (r["asset"] !== "MON") return null;
  if (typeof r["purpose"] !== "string") return null;
  if (typeof r["chainId"] !== "number" || !Number.isInteger(r["chainId"])) return null;
  if (typeof r["nonce"] !== "string") return null;
  if (typeof r["expiresAt"] !== "number" || !Number.isInteger(r["expiresAt"])) return null;
  return Object.freeze({
    requestId: r["requestId"],
    recipient,
    amountWei: r["amountWei"],
    asset: "MON" as const,
    purpose: r["purpose"],
    chainId: r["chainId"],
    nonce: r["nonce"],
    expiresAt: r["expiresAt"],
  });
}

/**
 * M3 split (deliberate, behavior-preserving for M2 callers): pure
 * verification without replay consumption. `verifyAuthorization` runs every
 * check and returns the verified snapshot; `authorizePayment` below adds the
 * single-use M2 claim. M3 execution calls `verifyAuthorization` (repeatable,
 * no state change) and enforces single-use in its own execution-reservation
 * table — so execution never re-redeems an M2 claim and never treats a stale
 * `authorized: true` value as authority.
 */
export interface VerifyInput {
  intent: unknown;
  proof: unknown;
  config: unknown;
  now: unknown;
}

export type VerifyResult =
  | { ok: true; snapshot: IntentSnapshot; digest: string; approver: string; now: number; domainId: string; policyVersion: string }
  | { ok: false; reasons: AuthReason[] };

export async function verifyAuthorization(args: VerifyInput): Promise<VerifyResult> {
  const { intent, proof: proofRaw, config: configRaw, now: nowRaw } = args;

  // 1. Server config (approver identity originates here).
  const checked = validateServerConfig(configRaw);
  if (checked.cfg === null) {
    return { ok: false, reasons: sortAuthReasons(checked.reasons) };
  }
  const cfg = checked.cfg;

  // 2. Proof shape.
  const checkedProof = validateProof(proofRaw);
  if (checkedProof.proof === null) {
    return { ok: false, reasons: sortAuthReasons(checkedProof.reasons) };
  }
  const proof = checkedProof.proof;

  // 3. Injected time.
  if (typeof nowRaw !== "number" || !Number.isInteger(nowRaw) || !Number.isFinite(nowRaw) || (nowRaw as number) < 0) {
    return { ok: false, reasons: [reason("INVALID_REQUEST", "now must be a non-negative integer unix timestamp")] };
  }
  const now = nowRaw as number;

  // 5. Policy FIRST, approval ungranted. Only MISSING_APPROVAL may proceed.
  const policyDecision = evaluatePolicy(intent, cfg.policy, { now, humanApprovalVerified: false });
  if (!policyDecision.allowed) {
    const fatal = policyDecision.reasons.filter((r) => r.code !== "MISSING_APPROVAL");
    if (fatal.length > 0) {
      return {
        ok: false,
        reasons: sortAuthReasons(fatal.map((r) => reason(r.code, r.message))),
      };
    }
  }
  // Snapshot BEFORE the first await: every stage below (message,
  // signature recovery, replay claim, result) reads `snap`, never the
  // caller-owned intent object.
  const snap = snapshotIntent(intent);
  if (snap === null) {
    return { ok: false, reasons: [reason("INVALID_REQUEST", "intent failed snapshot validation")] };
  }

  // 6. Domain / version / digest binding against server config.
  if (proof.domainId !== cfg.domainId) {
    return { ok: false, reasons: [reason("DOMAIN_MISMATCH", "authorization domain does not match this environment")] };
  }
  if (proof.policyVersion !== cfg.policyVersion) {
    return { ok: false, reasons: [reason("POLICY_VERSION_MISMATCH", "authorization policy version is stale")] };
  }
  const currentDigest = computePolicyDigest(cfg.policy).toLowerCase();
  if (proof.policyDigest.toLowerCase() !== currentDigest) {
    return { ok: false, reasons: [reason("POLICY_DIGEST_MISMATCH", "authorization policy digest does not match current policy")] };
  }

  // 7. Signature over the SERVER-constructed struct. The caller never
  // supplies the domain or message; tampering with any signed field changes
  // the recovered address (WRONG_SIGNER) or breaks recovery (INVALID_SIGNATURE).
  const domain = buildDomain(cfg.policy.allowedChainId, cfg.domainId);
  const message: ApprovalMessage = {
    domainId: cfg.domainId,
    policyVersion: cfg.policyVersion,
    policyDigest: currentDigest as Hex,
    chainId: BigInt(snap.chainId),
    requestId: snap.requestId,
    recipient: snap.recipient as Hex,
    amountWei: snap.amountWei,
    asset: snap.asset,
    nonce: snap.nonce,
    expiresAt: BigInt(snap.expiresAt),
  };
  let recovered: string;
  try {
    recovered = await recoverTypedDataAddress({
      domain,
      types: PAYMENT_AUTHORIZATION_TYPES,
      primaryType: PRIMARY_TYPE,
      message,
      signature: proof.signature,
    });
  } catch {
    return { ok: false, reasons: [reason("INVALID_SIGNATURE", "authorization signature is invalid")] };
  }
  if (recovered.toLowerCase() !== cfg.approver.toLowerCase()) {
    return { ok: false, reasons: [reason("WRONG_SIGNER", "authorization was not signed by the configured approver")] };
  }

  return { ok: true, snapshot: snap, digest: currentDigest, approver: cfg.approver, now, domainId: cfg.domainId, policyVersion: cfg.policyVersion };
}

/**
 * M2 authorization with single-use redemption: pure verification plus the
 * durable M2 replay claim. Behavior-preserving wrapper around
 * `verifyAuthorization` (store-presence check kept, then claim, then the M2
 * decision shape). M3 execution does NOT call this (it would double-consume);
 * it calls `verifyAuthorization` and reserves in its own execution table.
 */
export async function authorizePayment(input: AuthorizeInput): Promise<AuthorizationDecision> {
  const v = await verifyAuthorization(input);
  if (!v.ok) return { authorized: false, reasons: v.reasons };
  if (!isReplayStore(input.store)) {
    return { authorized: false, reasons: [reason("INVALID_CONFIG", "replay store is misconfigured")] };
  }
  const store = input.store;
  const snap = v.snapshot;
  // Durable single-use claim. Runs LAST: failed attempts burn nothing.
  let claim: { ok: true } | { ok: false; reused: "nonce" | "requestId" };
  try {
    claim = store.claim({
      nonce: snap.nonce,
      requestId: snap.requestId,
      recipient: snap.recipient,
      amountWei: snap.amountWei.toString(),
      expiresAt: snap.expiresAt,
      consumedAt: v.now,
      policyDigest: v.digest,
    });
  } catch {
    // Any storage failure (locked/corrupt/closed/unavailable) fails closed.
    // The identifiers were NOT consumed by us, but the authorization cannot
    // be proven single-use, so it must not be granted.
    return { authorized: false, reasons: [reason("STORE_UNAVAILABLE", "replay store failed; failing closed")] };
  }
  if (!claim.ok) {
    return { authorized: false, reasons: [reason("REPLAY_DETECTED", `authorization identifier already consumed (${claim.reused})`)] };
  }

  return {
    authorized: true,
    executed: false,
    requestId: snap.requestId,
    recipient: snap.recipient,
    amountWei: snap.amountWei,
    asset: snap.asset,
    chainId: snap.chainId,
    nonce: snap.nonce,
    expiresAt: snap.expiresAt,
    approver: v.approver,
    policyDigest: v.digest,
  };
}
