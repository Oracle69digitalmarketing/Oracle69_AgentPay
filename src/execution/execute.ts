/**
 * Secure payment execution — Oracle69 AgentPay M3 (native MON, testnet only).
 *
 * EXECUTION PROTOCOL (every attempt, no exceptions):
 *  1. Validate execution config (testnet chain, allowlisted RPC posture via
 *     the injected port, present signer), injected `now`, store and port
 *     presence. Fail closed.
 *  2. Re-verify via M2's pure `verifyAuthorization` against CURRENT trusted
 *     config. Cached `authorized: true` values, client booleans, and stale
 *     approvals are all worthless here.
 *  3. Chain triple-check: snapshot.chainId === exec.chainId ===
 *     live port chainId === 10143.
 *  4. Atomically reserve in the executions table (PK request_id, UNIQUE
 *     nonce). Losers never submit. Existing rows are handled by state (see
 *     `resumeOrReject`), including STALE-marking when the reservation's own
 *     approval no longer verifies.
 *  5. Build the unsigned transfer from the SNAPSHOT only. No caller gas
 *     price, calldata, destination, or chain overrides exist.
 *  6. Sign locally (hash knowable pre-send) → record UNKNOWN + hash in ONE
 *     update → send bytes.
 *  7. Classify the outcome: matching hash → SENT; ANY send-RPC error →
 *     UNKNOWN (reconcile by hash only, never auto-resend). Error CLASS is
 *     preserved for diagnostics (RPC_TIMEOUT vs RPC_REJECTED) but never
 *     drives retry: once signed bytes reached the transport, no error shape
 *     proves non-acceptance.
 *  8. Payer-lease fencing: acquisition returns a monotonic token; the
 *     UNKNOWN hash-record is a single atomic statement conditional on STILL
 *     owning the current token, so a holder that lost the lease (steal)
 *     affects zero rows and aborts with EXEC_FENCE_LOST before sending.
 *     Residual race (steal landing between the fenced record and send
 *     initiation) cannot be closed by any check-then-act across an external
 *     call: chain nonce slotting bounds it to one confirmation, the loser
 *     failing closed with retry. Exactly-once submission is NOT claimed.
 *
 * HANDOFF BOUNDARY (P0 invariant). Provably pre-submit failures — local
 * transaction construction, fee-gate rejection, signing failure, and
 * read-only/simulate RPCs (eth_getTransactionCount, eth_estimateGas,
 * eth_feeHistory/eth_gasPrice, eth_chainId), which by Ethereum JSON-RPC
 * semantics cannot broadcast — stay definitive and retryable (RESERVED).
 * The single handoff point is `sendRawTransaction(signed)`: from the moment
 * it is invoked, every outcome, including rejection-shaped errors, is
 * submission ambiguity, because a proxy/transport can return an error after
 * the node accepted. Post-handoff there is NO path back to a sendable
 * RESERVED state; UNKNOWN reconciles only.
 *
 * Crash windows: pre-reserve (safe retry) / RESERVED (re-verify + resume) /
 * UNKNOWN-or-later (reconcile only). See README M3 section.
 *
 * TRUSTED WIRING (deployment requirement, not code-enforceable): `authConfig`
 * (policy, approver, domain, version), `execConfig` (chain, signer),
 * `execStore`, and `chain` MUST originate from trusted server-side wiring.
 * A caller able to inject a hostile ChainPort (lying about chain ID or
 * receipts), a permissive ReplayStore/ExecutionStore, a rogue signer, or a
 * substituted policy bypasses every guarantee below. The function validates
 * shapes and values but cannot attest provenance. No untrusted caller may
 * supply implementations or configuration.
 */
import { getAddress, isAddress, type Address, type Hex } from "viem";
import { verifyAuthorization, type IntentSnapshot } from "../auth/verify.js";
import { computePolicyDigest } from "../auth/policy-digest.js";
import { ABSOLUTE_MAX_PAYMENT_WEI } from "../policy/types.js";
import type { AuthReason } from "../auth/types.js";
import { hashSignedTransaction, type ChainPort } from "./chain.js";
import { safeExternalError, safeSendError } from "./errors.js";
import { checkFeePolicy } from "./fee-policy.js";
import { ExecutionStore } from "./store.js";
import type { ExecutorSigner } from "./signer.js";
import {
  EXPECTED_CHAIN_ID,
  PAYER_LEASE_SENDING_GRACE_S,
  type ExecReason,
  type ExecRejectionCode,
  type ExecuteDecision,
  type ExecutionRecord,
  type ExecutionState,
  type ReconcileDecision,
} from "./types.js";

export interface ExecutionConfig {
  chainId: unknown;
  signer: unknown;
}

export interface ExecuteInput {
  intent: unknown;
  proof: unknown;
  authConfig: unknown;
  execConfig: unknown;
  now: unknown;
  execStore: unknown;
  chain: unknown;
}

export interface ReconcileInput {
  requestId: unknown;
  execStore: unknown;
  chain: unknown;
  now: unknown;
}

function execReason(code: ExecRejectionCode, message: string): ExecReason {
  return { code, message };
}

function isExecutionStore(v: unknown): v is ExecutionStore {
  return typeof v === "object" && v !== null && typeof (v as { reserve?: unknown }).reserve === "function";
}

function isChainPort(v: unknown): v is ChainPort {
  return (
    typeof v === "object" &&
    v !== null &&
    typeof (v as { sendRawTransaction?: unknown }).sendRawTransaction === "function" &&
    typeof (v as { getChainId?: unknown }).getChainId === "function" &&
    typeof (v as { getReceipt?: unknown }).getReceipt === "function"
  );
}

function isExecutorSigner(v: unknown): v is ExecutorSigner {
  return (
    typeof v === "object" &&
    v !== null &&
    typeof (v as { address?: unknown }).address === "string" &&
    isAddress((v as { address: string }).address) &&
    typeof (v as { signTransfer?: unknown }).signTransfer === "function"
  );
}

/** Duplicate-style decision for a row that changed underfoot: never submit. */
function duplicateForRow(row: ExecutionRecord | null): ExecuteDecision {
  const state = row?.state ?? "UNKNOWN";
  if (state === "RESERVED") {
    return {
      submitted: false,
      state,
      reasons: [execReason("EXEC_DUPLICATE", "reservation changed concurrently; retry explicitly, never auto-resubmitted")],
    };
  }
  if (state === "UNKNOWN" || state === "SENT" || state === "SENDING") {
    return {
      submitted: false,
      state,
      reasons: [execReason("EXEC_DUPLICATE", "payment already submitted or outcome uncertain; reconcile by transaction hash instead of resubmitting")],
    };
  }
  return {
    submitted: false,
    state,
    reasons: [execReason("EXEC_DUPLICATE", `payment is terminal (${state}); fresh approval required for any new attempt`)],
  };
}

/** Definitive-failure path: conditional move back to RESERVED, else duplicate. */
function failToReserved(
  execStore: ExecutionStore,
  releaseLease: () => void,
  snap: IntentSnapshot,
  now: number,
  lastError: string,
  attempts: number,
  from: ExecutionState[],
  message: string,
): ExecuteDecision {
  let moved = false;
  try {
    moved = execStore.notePreSubmitFailure(snap.requestId, now, lastError, attempts, from);
    releaseLease();
  } catch {
    return { submitted: false, state: "NONE", reasons: [execReason("STORE_UNAVAILABLE", "execution store failed; failing closed")] };
  }
  if (!moved) {
    let row: ExecutionRecord | null = null;
    try {
      row = execStore.get(snap.requestId);
    } catch {
      return { submitted: false, state: "NONE", reasons: [execReason("STORE_UNAVAILABLE", "execution store failed; failing closed")] };
    }
    releaseLease();
    return duplicateForRow(row);
  }
  return { submitted: false, state: "RESERVED", reasons: [execReason("EXEC_SEND_FAILED", message)] };
}

function snapshotMatchesRow(snap: IntentSnapshot, row: ExecutionRecord): boolean {
  return (
    row.requestId === snap.requestId &&
    row.nonce === snap.nonce &&
    row.recipient.toLowerCase() === snap.recipient.toLowerCase() &&
    row.amountWei === snap.amountWei.toString() &&
    row.asset === snap.asset &&
    row.chainId === snap.chainId &&
    row.expiresAt === snap.expiresAt
  );
}

/** Raw (untrusted) details match a stored row: used ONLY to decide STALE-marking, never for execution. */
function rawDetailsMatchRow(row: ExecutionRecord, raw: unknown): boolean {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return false;
  const r = raw as Record<string, unknown>;
  try {
    return (
      r["requestId"] === row.requestId &&
      r["nonce"] === row.nonce &&
      typeof r["recipient"] === "string" &&
      (r["recipient"] as string).toLowerCase() === row.recipient.toLowerCase() &&
      typeof r["amountWei"] === "bigint" &&
      (r["amountWei"] as bigint).toString() === row.amountWei &&
      r["asset"] === row.asset &&
      r["chainId"] === row.chainId &&
      r["expiresAt"] === row.expiresAt
    );
  } catch {
    return false;
  }
}

export async function executePayment(input: ExecuteInput): Promise<ExecuteDecision> {
  const { intent, proof, authConfig, execConfig, now: nowRaw, execStore: execStoreRaw, chain: chainRaw } = input;

  // 1a. Execution config: testnet only, signer present. No mainnet path exists.
  if (typeof execConfig !== "object" || execConfig === null || Array.isArray(execConfig)) {
    return { submitted: false, state: "NONE", reasons: [execReason("INVALID_CONFIG", "execution config must be an object")] };
  }
  const ec = execConfig as Record<string, unknown>;
  if (typeof ec["chainId"] !== "number" || ec["chainId"] !== EXPECTED_CHAIN_ID) {
    return { submitted: false, state: "NONE", reasons: [execReason("EXEC_CHAIN_MISMATCH", "execution requires Monad Testnet (10143)")] };
  }
  if (!isExecutorSigner(ec["signer"])) {
    return { submitted: false, state: "NONE", reasons: [execReason("EXEC_SIGNER_UNAVAILABLE", "executor signer is not configured")] };
  }
  const signer = ec["signer"];

  // 1b. Time, store, port presence.
  if (typeof nowRaw !== "number" || !Number.isInteger(nowRaw) || !Number.isFinite(nowRaw) || (nowRaw as number) < 0) {
    return { submitted: false, state: "NONE", reasons: [execReason("INVALID_REQUEST", "now must be a non-negative integer unix timestamp")] };
  }
  const now = nowRaw as number;
  if (!isExecutionStore(execStoreRaw)) {
    return { submitted: false, state: "NONE", reasons: [execReason("INVALID_CONFIG", "execution store is misconfigured")] };
  }
  const execStore = execStoreRaw;
  if (!isChainPort(chainRaw)) {
    return { submitted: false, state: "NONE", reasons: [execReason("INVALID_CONFIG", "chain port is misconfigured")] };
  }
  const chain = chainRaw;

  // 2. Fresh verification against CURRENT trusted config. Cached approvals
  // worthless; client booleans unread.
  const v = await verifyAuthorization({ intent, proof, config: authConfig, now });
  if (!v.ok) {
    maybeMarkStale(execStore, intent, authConfig, now);
    return { submitted: false, state: "NONE", reasons: v.reasons.map((r: AuthReason) => execReason(r.code, r.message)) };
  }
  const snap = v.snapshot;

  // Absolute 1 MON ceiling (M4 safeguard, defense in depth): policy
  // validation already rejects limits above the ceiling, so a verified
  // snapshot can never exceed it — but execution re-asserts directly on the
  // payment amount rather than trusting the pipeline alone.
  if (snap.amountWei > ABSOLUTE_MAX_PAYMENT_WEI) {
    return { submitted: false, state: "NONE", reasons: [execReason("EXCEEDS_LIMIT", "payment exceeds the absolute 1 MON ceiling")] };
  }

  // 3. Chain triple-check (config already validated; snapshot + live port here).
  if (snap.chainId !== EXPECTED_CHAIN_ID) {
    return { submitted: false, state: "NONE", reasons: [execReason("EXEC_CHAIN_MISMATCH", "snapshot chain is not Monad Testnet")] };
  }
  let liveChainId: number;
  try {
    liveChainId = await chain.getChainId();
  } catch (err) {
    const safe = safeExternalError("RPC_UNAVAILABLE", err);
    return { submitted: false, state: "NONE", reasons: [execReason("EXEC_CHAIN_MISMATCH", `chain unavailable (${safe.category}): ${safe.detail}`)] };
  }
  if (liveChainId !== EXPECTED_CHAIN_ID) {
    return { submitted: false, state: "NONE", reasons: [execReason("EXEC_CHAIN_MISMATCH", "connected chain is not Monad Testnet")] };
  }

  // 4. Atomic reservation. From here on only `snap` and `row` are read.
  let reservation;
  try {
    reservation = execStore.reserve({
      requestId: snap.requestId,
      nonce: snap.nonce,
      recipient: snap.recipient,
      amountWei: snap.amountWei.toString(),
      asset: snap.asset,
      chainId: snap.chainId,
      expiresAt: snap.expiresAt,
      policyDigest: v.digest,
      approver: v.approver,
      domainId: v.domainId,
      policyVersion: v.policyVersion,
      createdAt: now,
    });
  } catch {
    return { submitted: false, state: "NONE", reasons: [execReason("STORE_UNAVAILABLE", "execution store failed; failing closed")] };
  }
  if (!reservation.created) {
    const existing = reservation.existing;
    if (!snapshotMatchesRow(snap, existing)) {
      return {
        submitted: false,
        state: existing.state,
        reasons: [execReason("EXEC_CONFLICT", "request ID or nonce already used with different payment details")],
      };
    }
    if (existing.state === "RESERVED") {
      // Retry path: verification above just re-passed against CURRENT policy,
      // so resume the send with the stored reservation. Refresh the recorded
      // approval bindings to the freshly verified ones first. attempts continue.
      try {
        execStore.refreshApproval(existing.requestId, { digest: v.digest, domainId: v.domainId, policyVersion: v.policyVersion, approver: v.approver }, now);
      } catch {
        return { submitted: false, state: "NONE", reasons: [execReason("STORE_UNAVAILABLE", "execution store failed; failing closed")] };
      }
      return sendFromReserved(execStore, chain, signer, snap, now, existing.attempts);
    }
    if (existing.state === "UNKNOWN" || existing.state === "SENT" || existing.state === "SENDING") {
      return {
        submitted: false,
        state: existing.state,
        reasons: [execReason("EXEC_DUPLICATE", "payment already submitted or outcome uncertain; reconcile by transaction hash instead of resubmitting")],
      };
    }
    return {
      submitted: false,
      state: existing.state,
      reasons: [execReason("EXEC_DUPLICATE", `payment is terminal (${existing.state}); fresh approval required for any new attempt`)],
    };
  }

  return sendFromReserved(execStore, chain, signer, snap, now, 0);
}

/**
 * Send path for a RESERVED row. First wins the send right via atomic
 * RESERVED -> SENDING CAS (exactly one concurrent caller proceeds); losers
 * return a duplicate decision WITHOUT sending. Signs locally (hash knowable
 * pre-send), records UNKNOWN + hash atomically, then sends exactly once.
 */
async function sendFromReserved(
  execStore: ExecutionStore,
  chain: ChainPort,
  signer: ExecutorSigner,
  snap: IntentSnapshot,
  now: number,
  priorAttempts: number,
): Promise<ExecuteDecision> {
  let holdsRight: boolean;
  try {
    holdsRight = execStore.claimSendRight(snap.requestId, now);
  } catch {
    return { submitted: false, state: "NONE", reasons: [execReason("STORE_UNAVAILABLE", "execution store failed; failing closed")] };
  }
  if (!holdsRight) {
    let row: ExecutionRecord | null = null;
    try {
      row = execStore.get(snap.requestId);
    } catch {
      return { submitted: false, state: "NONE", reasons: [execReason("STORE_UNAVAILABLE", "execution store failed; failing closed")] };
    }
    const state = row?.state ?? "UNKNOWN";
    return {
      submitted: false,
      state,
      reasons: [execReason("EXEC_DUPLICATE", "another execution holds this payment; not submitting a second time")],
    };
  }
  const sender = getAddress(signer.address) as Address;
  const payer = sender.toLowerCase();
  // Single-payer serialization with fencing: hold the lease (and its
  // monotonic token) across nonce allocation, signing, hash recording, and
  // send initiation. Never held across the RPC call itself beyond initiation;
  // released right after the outcome row. The token is re-checked atomically
  // at the hash-record step, so a holder that lost the lease cannot proceed
  // to send (see recordUnknownAttempt).
  let lease: { held: boolean; token: number };
  try {
    lease = execStore.acquirePayerLease(payer, snap.requestId, now, PAYER_LEASE_SENDING_GRACE_S);
  } catch {
    return { submitted: false, state: "NONE", reasons: [execReason("STORE_UNAVAILABLE", "execution store failed; failing closed")] };
  }
  if (!lease.held) {
    // Yield the send right back so our own retry is not deadlocked, then
    // report busy: explicit retry only, nothing sent.
    try {
      execStore.yieldSendRight(snap.requestId, now);
    } catch {
      return { submitted: false, state: "NONE", reasons: [execReason("STORE_UNAVAILABLE", "execution store failed; failing closed")] };
    }
    return { submitted: false, state: "RESERVED", reasons: [execReason("EXEC_PAYER_BUSY", "payer has another payment in flight; retry later")] };
  }
  const fence = { payer, holder: snap.requestId, token: lease.token };
  // Release is best-effort AFTER the outcome row: a crash between leaves the
  // row advanced (stealable) while the lease stays held, which the next
  // acquirer resolves via the steal rule. Conditional on (holder, token) so
  // a stolen hold is never freed for the thief. Never throws outward.
  const releaseLease = (): void => {
    try {
      execStore.releasePayerLease(payer, snap.requestId, fence.token, now);
    } catch {
      // Row already advanced; steal path covers recovery.
    }
  };
  let unsigned:
    | {
        to: Address;
        value: bigint;
        chainId: number;
        nonce: number;
        gas: bigint;
        maxFeePerGas: bigint;
        maxPriorityFeePerGas: bigint;
      }
    | undefined;
  let feeRejection: string | null = null;
  try {
    const [senderNonce, gas, fees] = await Promise.all([
      chain.getSenderNonce(sender),
      chain.estimateTransferGas(snap.recipient as Address, snap.amountWei, sender),
      chain.estimateFees(),
    ]);
    feeRejection = checkFeePolicy(gas, fees);
    if (feeRejection === null) {
      unsigned = {
        to: snap.recipient as Address,
        value: snap.amountWei,
        chainId: EXPECTED_CHAIN_ID,
        nonce: senderNonce,
        gas,
        maxFeePerGas: (fees as { maxFeePerGas: bigint }).maxFeePerGas,
        maxPriorityFeePerGas: (fees as { maxPriorityFeePerGas: bigint }).maxPriorityFeePerGas,
      };
    }
  } catch (err) {
    // Preparation failed before anything left this host: row stays RESERVED,
    // attempt recorded, explicit retry allowed. Error text is sanitized: fee
    // and gas estimation errors originate from the RPC layer.
    const safe = safeExternalError("PREPARATION_FAILED", err);
    return failToReserved(execStore, releaseLease, snap, now, `${safe.category}: ${safe.detail}`, priorAttempts, ["SENDING"], `${safe.category}: ${safe.detail}`);
  }

  // Trusted fee gate: enforced BEFORE signing. Definitive pre-submit failure.
  if (feeRejection !== null) {
    return failToReserved(execStore, releaseLease, snap, now, `fee policy rejected: ${feeRejection}`, priorAttempts, ["SENDING"], `fee policy rejected: ${feeRejection}`);
  }
  if (unsigned === undefined) {
    // Unreachable: feeRejection === null implies assignment above. Defensive.
    return { submitted: false, state: "RESERVED", reasons: [execReason("EXEC_SEND_FAILED", "fee policy rejected: unsigned transfer missing")] };
  }

  let signed: Hex;
  try {
    signed = await signer.signTransfer(unsigned);
  } catch {
    // Local failure: static text only — never propagate signer-side error
    // internals outward.
    return failToReserved(execStore, releaseLease, snap, now, "SIGNING_FAILED: local signing failed", priorAttempts, ["SENDING"], "SIGNING_FAILED: local signing failed");
  }
  const localHash = hashSignedTransaction(signed);

  // FENCED hash record: moves SENDING -> UNKNOWN with the hash ONLY while
  // this holder still owns the current payer lease (single atomic statement).
  // Proven guarantee: a holder that has lost its fencing token cannot create
  // or record a NEW submission attempt through this gate — it affects zero
  // rows and must yield back to RESERVED so an explicit retry (fresh lease)
  // remains possible.
  // Distributed-systems limitation (not an authorization bypass): if this
  // process pauses AFTER this record commits but BEFORE sendRawTransaction()
  // is invoked, another process may legitimately steal the lease, and this
  // process's already-authorized sendRawTransaction() call may still occur
  // on resume, because SQLite cannot atomically fence an external network
  // side effect. Bounded consequence: the bytes were authorized before the
  // race; the competing execution uses the same sender nonce, so the chain
  // admits at most one canonical transaction for that nonce slot; the loser
  // stays UNKNOWN (reconcile-only) and never auto-resends. The liveness /
  // operator consequence is handled through UNKNOWN / reconciliation /
  // fresh-approval. Exactly-once external submission is NOT claimed.
  let recorded = false;
  try {
    recorded = execStore.recordUnknownAttempt(
      snap.requestId,
      { txHash: localHash, senderNonce: unsigned.nonce, now, attempts: priorAttempts + 1 },
      fence,
    );
  } catch {
    releaseLease();
    return { submitted: false, state: "NONE", reasons: [execReason("STORE_UNAVAILABLE", "execution store failed; failing closed")] };
  }
  if (!recorded) {
    // Either lost the lease (fencing) or lost the row race. Yield so our own
    // retry is not deadlocked, then report without sending anything.
    try {
      execStore.yieldSendRight(snap.requestId, now);
    } catch {
      return { submitted: false, state: "NONE", reasons: [execReason("STORE_UNAVAILABLE", "execution store failed; failing closed")] };
    }
    releaseLease();
    return { submitted: false, state: "RESERVED", reasons: [execReason("EXEC_FENCE_LOST", "payer lease lost before submission; send right yielded, retry explicitly")] };
  }

  let returnedHash: Hex;
  try {
    returnedHash = await chain.sendRawTransaction(signed);
  } catch (err) {
    // POST-HANDOFF RULE (P0): signed bytes already reached the transport, so
    // NO error — timeouts, aborts, or rejection-shaped errors — proves
    // non-acceptance. A proxy can return an error after the node accepted.
    // Classify for diagnostics only, then ALWAYS land UNKNOWN. There is no
    // path from here back to a sendable RESERVED state.
    const safe = safeSendError(err);
    releaseLease();
    return { submitted: false, state: "UNKNOWN", reasons: [execReason("EXEC_UNKNOWN_OUTCOME", `${safe.error.category}: ${safe.error.detail}; reconcile by transaction hash, never auto-resubmit`)] };
  }
  if (returnedHash.toLowerCase() !== localHash.toLowerCase()) {
    let kept = false;
    try {
      kept = execStore.transitionFrom(snap.requestId, "UNKNOWN", { now, lastError: "node returned a different hash; failing closed" }, ["UNKNOWN"]);
      releaseLease();
    } catch {
      return { submitted: false, state: "NONE", reasons: [execReason("STORE_UNAVAILABLE", "execution store failed; failing closed")] };
    }
    if (!kept) {
      let row: ExecutionRecord | null = null;
      try {
        row = execStore.get(snap.requestId);
      } catch {
        return { submitted: false, state: "NONE", reasons: [execReason("STORE_UNAVAILABLE", "execution store failed; failing closed")] };
      }
      return duplicateForRow(row);
    }
    return { submitted: false, state: "UNKNOWN", reasons: [execReason("EXEC_UNKNOWN_OUTCOME", "node returned an unexpected hash; reconcile before any further action")] };
  }
  // Conditional SENT: never regress a concurrently reconciled CONFIRMED.
  // On a lost race, report the actual row state instead of overwriting it.
  let marked = false;
  try {
    marked = execStore.transitionFrom(snap.requestId, "SENT", { now }, ["UNKNOWN"]);
    releaseLease();
  } catch {
    return { submitted: false, state: "NONE", reasons: [execReason("STORE_UNAVAILABLE", "execution store failed; failing closed")] };
  }
  if (!marked) {
    let row: ExecutionRecord | null = null;
    try {
      row = execStore.get(snap.requestId);
    } catch {
      return { submitted: false, state: "NONE", reasons: [execReason("STORE_UNAVAILABLE", "execution store failed; failing closed")] };
    }
    const state = row?.state ?? "SENT";
    return { submitted: true, requestId: snap.requestId, txHash: returnedHash, state, attempts: priorAttempts + 1 };
  }
  return { submitted: true, requestId: snap.requestId, txHash: returnedHash, state: "SENT", attempts: priorAttempts + 1 };
}

/**
 * STALE-marking on verification failure — restricted to PROVEN external
 * change (P1 remediation). A matching request ID + details proves NOTHING
 * about the caller's legitimacy: a forged proof over observed details must
 * never kill a legitimate RESERVED row. Mark STALE only when stored-vs-
 * current comparison (never attacker input) establishes staleness:
 * policy digest, domain, or version changed, or the reservation expired.
 * Signature/proof-shape failures alone never mark. Best-effort; store errors
 * are swallowed because the rejection stands anyway.
 */
function maybeMarkStale(execStore: ExecutionStore, rawIntent: unknown, authConfig: unknown, now: number): void {
  try {
    if (typeof rawIntent !== "object" || rawIntent === null || Array.isArray(rawIntent)) return;
    const requestId = (rawIntent as Record<string, unknown>)["requestId"];
    if (typeof requestId !== "string") return;
    const row = execStore.get(requestId);
    if (row === null || row.state !== "RESERVED") return;
    if (!rawDetailsMatchRow(row, rawIntent)) return;
    const cur = currentBindings(authConfig);
    if (cur === null) return;
    const changed =
      row.policyDigest.toLowerCase() !== cur.digest.toLowerCase() ||
      row.domainId !== cur.domainId ||
      row.policyVersion !== cur.policyVersion;
    const expired = now >= row.expiresAt;
    if (!changed && !expired) return;
    // Conditional on RESERVED: never clobber an in-flight send right.
    try {
      execStore.transitionFrom(requestId, "STALE", { now, lastError: "approval no longer verifies against current policy" }, ["RESERVED"]);
    } catch {
      // Rejection already decided; STALE is observability only.
    }
  } catch {
    // Rejection already decided; STALE is observability only.
  }
}

/**
 * Current bindings from TRUSTED server wiring (same trust class as the
 * config passed to verification — never caller input). Null when unusable,
 * in which case no STALE-marking occurs (fail closed, rejection stands).
 */
function currentBindings(authConfig: unknown): { digest: string; domainId: string; policyVersion: string } | null {
  try {
    if (typeof authConfig !== "object" || authConfig === null || Array.isArray(authConfig)) return null;
    const c = authConfig as Record<string, unknown>;
    if (typeof c["domainId"] !== "string" || (c["domainId"] as string).length === 0) return null;
    if (typeof c["policyVersion"] !== "string" || (c["policyVersion"] as string).length === 0) return null;
    if (typeof c["policy"] !== "object" || c["policy"] === null || Array.isArray(c["policy"])) return null;
    return {
      digest: computePolicyDigest(c["policy"] as import("../policy/types.js").PolicyConfig).toLowerCase(),
      domainId: c["domainId"] as string,
      policyVersion: c["policyVersion"] as string,
    };
  } catch {
    return null;
  }
}

export async function reconcileExecution(input: ReconcileInput): Promise<ReconcileDecision> {
  const { requestId: requestIdRaw, execStore: execStoreRaw, chain: chainRaw, now: nowRaw } = input;
  if (typeof requestIdRaw !== "string" || requestIdRaw.length === 0) {
    return { reconciled: false, requestId: "", state: "NONE", reasons: [execReason("INVALID_REQUEST", "requestId must be a non-empty string")] };
  }
  if (typeof nowRaw !== "number" || !Number.isInteger(nowRaw) || (nowRaw as number) < 0) {
    return { reconciled: false, requestId: requestIdRaw, state: "NONE", reasons: [execReason("INVALID_REQUEST", "now must be a non-negative integer unix timestamp")] };
  }
  if (!isExecutionStore(execStoreRaw)) {
    return { reconciled: false, requestId: requestIdRaw, state: "NONE", reasons: [execReason("INVALID_CONFIG", "execution store is misconfigured")] };
  }
  if (!isChainPort(chainRaw)) {
    return { reconciled: false, requestId: requestIdRaw, state: "NONE", reasons: [execReason("INVALID_CONFIG", "chain port is misconfigured")] };
  }
  const now = nowRaw as number;
  let row;
  try {
    row = execStoreRaw.get(requestIdRaw);
  } catch {
    return { reconciled: false, requestId: requestIdRaw, state: "NONE", reasons: [execReason("STORE_UNAVAILABLE", "execution store failed; failing closed")] };
  }
  if (row === null) {
    return { reconciled: false, requestId: requestIdRaw, state: "NONE", reasons: [execReason("EXEC_NOT_FOUND", "no execution record for request ID")] };
  }
  if (row.state === "CONFIRMED" || row.state === "REVERTED" || row.state === "STALE") {
    return { reconciled: true, requestId: row.requestId, state: row.state, txHash: row.txHash };
  }
  if (row.state === "RESERVED") {
    return { reconciled: false, requestId: row.requestId, state: row.state, reasons: [execReason("EXEC_NO_SUBMISSION", "nothing submitted yet; resume via execution, not reconciliation")] };
  }
  // UNKNOWN, SENT, or SENDING: reconcile by recorded hash only. Never
  // resubmit here. SENDING (send right held, submission uncertain) is
  // recovered exactly like UNKNOWN; without a hash only an operator path
  // remains.
  if (row.txHash === null) {
    return { reconciled: false, requestId: row.requestId, state: row.state, reasons: [execReason("EXEC_UNKNOWN_OUTCOME", "no transaction hash recorded; operator intervention required")] };
  }
  let receipt;
  try {
    receipt = await chainRaw.getReceipt(row.txHash as Hex);
  } catch (err) {
    const safe = safeExternalError("RPC_UNAVAILABLE", err);
    return { reconciled: false, requestId: row.requestId, state: row.state, reasons: [execReason("EXEC_UNKNOWN_OUTCOME", `${safe.category}: ${safe.detail}; retry reconciliation later`)] };
  }
  if (receipt === null) {
    return { reconciled: false, requestId: row.requestId, state: row.state, reasons: [execReason("EXEC_UNKNOWN_OUTCOME", "no receipt yet; retry reconciliation later")] };
  }
  const to: ExecutionState = receipt.status === "success" ? "CONFIRMED" : "REVERTED";
  // Conditional: concurrent reconciles converge idempotently; a lost race
  // re-reads instead of overwriting.
  let settled = false;
  try {
    settled = execStoreRaw.transitionFrom(row.requestId, to, { now }, ["UNKNOWN", "SENT"]);
  } catch {
    return { reconciled: false, requestId: row.requestId, state: row.state, reasons: [execReason("STORE_UNAVAILABLE", "execution store failed; failing closed")] };
  }
  if (!settled) {
    let current: ExecutionRecord | null = null;
    try {
      current = execStoreRaw.get(row.requestId);
    } catch {
      return { reconciled: false, requestId: row.requestId, state: row.state, reasons: [execReason("STORE_UNAVAILABLE", "execution store failed; failing closed")] };
    }
    const state = current?.state ?? to;
    return { reconciled: true, requestId: row.requestId, state, txHash: row.txHash };
  }
  return { reconciled: true, requestId: row.requestId, state: to, txHash: row.txHash };
}
