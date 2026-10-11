/**
 * Durable execution ledger — Oracle69 AgentPay M3.
 *
 * Separate table from M2's `consumed_authorizations`, in the SAME SQLite file
 * when co-located (one connection pool per process is fine; separate
 * connections share the file safely). Separate table because the lifecycles
 * differ: M2 rows are write-once consumed markers; execution rows move
 * through a state machine.
 *
 * SCHEMA: executions(request_id PK, nonce UNIQUE, ...snapshot fields...,
 *   state, tx_hash NULL, sender_nonce NULL, attempts, created_at, updated_at,
 *   last_error NULL).
 *
 * RESERVATION (the single-use gate for spends):
 *   BEGIN IMMEDIATE → SELECT by request_id → SELECT by nonce → INSERT
 *   RESERVED → COMMIT. Losers read the committed row and NEVER submit.
 * All transitions are single-row UPDATEs keyed by request_id; every storage
 * error throws StoreError (fail closed). No DELETE API exists.
 */
import Database from "better-sqlite3";
import { StoreError } from "../auth/store/sqlite-store.js";
import type { ExecutionRecord, ExecutionState } from "./types.js";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS executions (
  request_id TEXT PRIMARY KEY,
  nonce TEXT NOT NULL UNIQUE,
  recipient TEXT NOT NULL,
  amount_wei TEXT NOT NULL,
  asset TEXT NOT NULL,
  chain_id INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  policy_digest TEXT NOT NULL,
  approver TEXT NOT NULL,
  domain_id TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  state TEXT NOT NULL,
  tx_hash TEXT,
  sender_nonce INTEGER,
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_error TEXT
);

CREATE TABLE IF NOT EXISTS payer_leases (
  payer TEXT PRIMARY KEY,
  state TEXT NOT NULL,
  holder_request_id TEXT,
  version INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL
);`;

export interface Reservation {
  requestId: string;
  nonce: string;
  recipient: string;
  amountWei: string;
  asset: string;
  chainId: number;
  expiresAt: number;
  policyDigest: string;
  approver: string;
  domainId: string;
  policyVersion: string;
  createdAt: number;
}

export type ReserveResult = { created: true } | { created: false; existing: ExecutionRecord };

function rowToRecord(row: Record<string, unknown>): ExecutionRecord {
  return {
    requestId: row["request_id"] as string,
    nonce: row["nonce"] as string,
    recipient: row["recipient"] as string,
    amountWei: row["amount_wei"] as string,
    asset: row["asset"] as string,
    chainId: row["chain_id"] as number,
    expiresAt: row["expires_at"] as number,
    policyDigest: row["policy_digest"] as string,
    approver: row["approver"] as string,
    domainId: row["domain_id"] as string,
    policyVersion: row["policy_version"] as string,
    state: row["state"] as ExecutionState,
    txHash: (row["tx_hash"] as string | null) ?? null,
    senderNonce: (row["sender_nonce"] as number | null) ?? null,
    attempts: row["attempts"] as number,
    createdAt: row["created_at"] as number,
    updatedAt: row["updated_at"] as number,
    lastError: (row["last_error"] as string | null) ?? null,
  };
}

export class ExecutionStore {
  private readonly db: Database.Database;

  constructor(path: string) {
    if (typeof path !== "string" || path.length === 0) {
      throw new Error("execution store path must be a non-empty string");
    }
    try {
      this.db = new Database(path);
    } catch (err) {
      throw new StoreError(`cannot open execution database: ${(err as Error).message}`);
    }
    try {
      if (path !== ":memory:") {
        this.db.pragma("journal_mode = WAL");
      }
      this.db.pragma("busy_timeout = 5000");
      this.db.exec(SCHEMA);
    } catch (err) {
      throw new StoreError(`cannot initialize execution database: ${(err as Error).message}`);
    }
  }

  /** Atomically create the RESERVED row or return the conflicting row. */
  reserve(entry: Reservation): ReserveResult {
    this.execOrThrow("BEGIN IMMEDIATE");
    try {
      const byRequest = this.getRow(entry.requestId);
      if (byRequest !== null) {
        this.execOrThrow("ROLLBACK");
        return { created: false, existing: byRequest };
      }
      const byNonce = this.db
        .prepare("SELECT * FROM executions WHERE nonce = ?")
        .get(entry.nonce) as Record<string, unknown> | undefined;
      if (byNonce !== undefined) {
        this.execOrThrow("ROLLBACK");
        return { created: false, existing: rowToRecord(byNonce) };
      }
      try {
        this.db
          .prepare(
            "INSERT INTO executions (request_id, nonce, recipient, amount_wei, asset, chain_id, expires_at, policy_digest, approver, domain_id, policy_version, state, tx_hash, sender_nonce, attempts, created_at, updated_at, last_error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'RESERVED', NULL, NULL, 0, ?, ?, NULL)",
          )
          .run(
            entry.requestId,
            entry.nonce,
            entry.recipient,
            entry.amountWei,
            entry.asset,
            entry.chainId,
            entry.expiresAt,
            entry.policyDigest,
            entry.approver,
            entry.domainId,
            entry.policyVersion,
            entry.createdAt,
            entry.createdAt,
          );
      } catch (insertErr) {
        this.rollbackQuiet();
        if (!isUniqueViolation(insertErr)) {
          throw new StoreError(`execution reserve failed: ${(insertErr as Error).message}`);
        }
        const retry = this.getRow(entry.requestId) ?? this.getRowByNonce(entry.nonce);
        if (retry === null) {
          throw new StoreError("execution reserve failed: unresolved constraint collision");
        }
        return { created: false, existing: retry };
      }
      this.execOrThrow("COMMIT");
      const created = this.getRow(entry.requestId);
      if (created === null) {
        throw new StoreError("execution reserve failed: row missing after commit");
      }
      return { created: true };
    } catch (err) {
      this.rollbackQuiet();
      if (err instanceof StoreError) throw err;
      throw new StoreError(`execution reserve failed: ${(err as Error).message}`);
    }
  }

  transition(requestId: string, to: ExecutionState, patch: { txHash?: string; senderNonce?: number; lastError?: string; now: number; attempts?: number }): void {
    try {
      const result = this.db
        .prepare(
          "UPDATE executions SET state = ?, tx_hash = COALESCE(?, tx_hash), sender_nonce = COALESCE(?, sender_nonce), last_error = ?, attempts = COALESCE(?, attempts), updated_at = ? WHERE request_id = ?",
        )
        .run(to, patch.txHash ?? null, patch.senderNonce ?? null, patch.lastError ?? null, patch.attempts ?? null, patch.now, requestId);
      if (result.changes !== 1) {
        throw new StoreError(`execution transition affected ${String(result.changes)} rows`);
      }
    } catch (err) {
      if (err instanceof StoreError) throw err;
      throw new StoreError(`execution transition failed: ${(err as Error).message}`);
    }
  }

  /** Back to RESERVED after a definitive pre-submit failure (explicit retry only). */
  notePreSubmitFailure(
    requestId: string,
    now: number,
    lastError: string,
    attempts: number,
    from: ExecutionState[],
  ): boolean {
    return this.transitionFrom(requestId, "RESERVED", { now, lastError, attempts }, from);
  }

  /**
   * Conditional transition: moves only from one of the expected states.
   * Returns false (instead of throwing) when the row is elsewhere, so
   * callers can re-read and decide without regressing a concurrent update
   * (e.g. never overwrite a concurrently reconciled CONFIRMED with SENT).
   * Storage errors still throw (fail closed).
   */
  transitionFrom(
    requestId: string,
    to: ExecutionState,
    patch: { txHash?: string; senderNonce?: number; lastError?: string; now: number; attempts?: number },
    from: ExecutionState[],
  ): boolean {
    if (from.length === 0) return false;
    try {
      const placeholders = from.map(() => "?").join(",");
      const result = this.db
        .prepare(
          `UPDATE executions SET state = ?, tx_hash = COALESCE(?, tx_hash), sender_nonce = COALESCE(?, sender_nonce), last_error = ?, attempts = COALESCE(?, attempts), updated_at = ? WHERE request_id = ? AND state IN (${placeholders})`,
        )
        .run(to, patch.txHash ?? null, patch.senderNonce ?? null, patch.lastError ?? null, patch.attempts ?? null, patch.now, requestId, ...from);
      return result.changes === 1;
    } catch (err) {
      throw new StoreError(`conditional execution transition failed: ${(err as Error).message}`);
    }
  }

  /**
   * Refresh the recorded approval bindings when a RESERVED row resumes under
   * a fresh successful verification, so the row always describes the approval
   * actually being executed (not a superseded reservation-time copy).
   */
  refreshApproval(requestId: string, approval: { digest: string; domainId: string; policyVersion: string; approver: string }, now: number): void {
    try {
      const result = this.db
        .prepare(
          "UPDATE executions SET policy_digest = ?, domain_id = ?, policy_version = ?, approver = ?, updated_at = ? WHERE request_id = ? AND state = 'RESERVED'",
        )
        .run(approval.digest, approval.domainId, approval.policyVersion, approval.approver, now, requestId);
      if (result.changes !== 1) {
        throw new StoreError("approval refresh affected unexpected row count");
      }
    } catch (err) {
      if (err instanceof StoreError) throw err;
      throw new StoreError(`approval refresh failed: ${(err as Error).message}`);
    }
  }

  /**
   * FENCED submission-attempt record: moves SENDING -> UNKNOWN with the hash
   * ONLY while the caller still owns the current payer lease. The lease
   * check and the state move are ONE atomic statement, so a holder whose
   * lease was stolen (fencing token advanced) affects zero rows and must
   * abort before sending. Returns false on fencing loss (never throws for
   * it); storage errors throw (fail closed).
   */
  recordUnknownAttempt(
    requestId: string,
    patch: { txHash: string; senderNonce: number; now: number; attempts: number },
    lease: { payer: string; holder: string; token: number },
  ): boolean {
    try {
      const result = this.db
        .prepare(
          `UPDATE executions SET state = 'UNKNOWN', tx_hash = ?, sender_nonce = ?, attempts = ?, updated_at = ?
           WHERE request_id = ? AND state = 'SENDING'
           AND EXISTS (SELECT 1 FROM payer_leases WHERE payer = ? AND holder_request_id = ? AND version = ?)`,
        )
        .run(patch.txHash, patch.senderNonce, patch.attempts, patch.now, requestId, lease.payer, lease.holder, lease.token);
      return result.changes === 1;
    } catch (err) {
      throw new StoreError(`fenced unknown-record failed: ${(err as Error).message}`);
    }
  }

  /**
   * Atomic compare-and-swap RESERVED -> SENDING. Exactly one concurrent
   * claimant wins the send right, across connections and processes. Losers
   * must NOT send. A crash while SENDING leaves submission uncertain, so
   * recovery treats SENDING exactly like UNKNOWN.
   */
  claimSendRight(requestId: string, now: number): boolean {
    try {
      const result = this.db
        .prepare("UPDATE executions SET state = 'SENDING', updated_at = ? WHERE request_id = ? AND state = 'RESERVED'")
        .run(now, requestId);
      return result.changes === 1;
    } catch (err) {
      throw new StoreError(`send-right claim failed: ${(err as Error).message}`);
    }
  }

  /**
   * Yield a held send right back to RESERVED (used when the payer lease is
   * busy: we must not keep SENDING while doing nothing, or our own retry
   * would deadlock). Conditional so a raced row is never clobbered.
   */
  yieldSendRight(requestId: string, now: number): void {
    try {
      const result = this.db
        .prepare("UPDATE executions SET state = 'RESERVED', updated_at = ? WHERE request_id = ? AND state = 'SENDING'")
        .run(now, requestId);
      if (result.changes !== 1) {
        throw new StoreError("send-right yield affected unexpected row count");
      }
    } catch (err) {
      if (err instanceof StoreError) throw err;
      throw new StoreError(`send-right yield failed: ${(err as Error).message}`);
    }
  }

  /**
   * Single-payer send serialization lease with monotonic fencing tokens.
   * Acquire AFTER winning the send right, BEFORE estimating the sender nonce;
   * release AFTER the outcome is durably recorded (UNKNOWN/SENT/RESERVED).
   * Same-holder re-acquire always succeeds WITHOUT advancing the token
   * (retry safety). Steal from another holder ONLY when its execution can
   * never allocate again (terminal/submitted states) or its SENDING hold is
   * older than `sendingGraceS` (presumed crashed); every successful
   * acquisition or steal advances the token, and the steal is a single
   * conditional UPDATE so races resolve in the database, never in JS.
   * Missing-holder rows fail closed (busy). Returned token 0 always means
   * "not held" (real tokens start at 1).
   */
  acquirePayerLease(
    payer: string,
    holderRequestId: string,
    now: number,
    sendingGraceS: number,
  ): { held: boolean; token: number } {
    try {
      this.db.prepare("INSERT OR IGNORE INTO payer_leases (payer, state, holder_request_id, version, updated_at) VALUES (?, 'FREE', NULL, 0, ?)").run(payer, now);
      const takeFree = this.db
        .prepare("UPDATE payer_leases SET state = 'HELD', holder_request_id = ?, version = version + 1, updated_at = ? WHERE payer = ? AND state = 'FREE'")
        .run(holderRequestId, now, payer);
      if (takeFree.changes === 1) return { held: true, token: this.readLeaseToken(payer) };
      const current = this.db
        .prepare("SELECT holder_request_id, version FROM payer_leases WHERE payer = ?")
        .get(payer) as { holder_request_id: string | null; version: number } | undefined;
      if (current === undefined || current.holder_request_id === null) return { held: false, token: 0 };
      if (current.holder_request_id === holderRequestId) {
        this.db
          .prepare("UPDATE payer_leases SET updated_at = ? WHERE payer = ? AND holder_request_id = ?")
          .run(now, payer, holderRequestId);
        return { held: true, token: current.version };
      }
      const steal = this.db
        .prepare(
          `UPDATE payer_leases SET state = 'HELD', holder_request_id = ?, version = version + 1, updated_at = ?
           WHERE payer = ? AND holder_request_id = ? AND (
             EXISTS (SELECT 1 FROM executions WHERE request_id = ? AND state IN ('UNKNOWN','SENT','CONFIRMED','REVERTED','STALE'))
             OR EXISTS (SELECT 1 FROM executions WHERE request_id = ? AND state = 'SENDING' AND updated_at <= ?)
           )`,
        )
        .run(holderRequestId, now, payer, current.holder_request_id, current.holder_request_id, current.holder_request_id, now - sendingGraceS);
      if (steal.changes !== 1) return { held: false, token: 0 };
      return { held: true, token: this.readLeaseToken(payer) };
    } catch (err) {
      throw new StoreError(`payer lease acquire failed: ${(err as Error).message}`);
    }
  }

  private readLeaseToken(payer: string): number {
    try {
      const row = this.db
        .prepare("SELECT version FROM payer_leases WHERE payer = ?")
        .get(payer) as { version: number } | undefined;
      if (row === undefined || typeof row.version !== "number") {
        throw new StoreError("lease token missing after acquisition");
      }
      return row.version;
    } catch (err) {
      if (err instanceof StoreError) throw err;
      throw new StoreError(`lease token read failed: ${(err as Error).message}`);
    }
  }

  /**
   * Release a held lease. Conditional on holder identity AND fencing token so
   * a stolen hold is never freed for the thief (and a stale release is a
   * harmless no-op). Best-effort by design: if the outcome row is already
   * advanced, the next acquirer steals cleanly.
   */
  releasePayerLease(payer: string, holderRequestId: string, token: number, now: number): void {
    try {
      this.db
        .prepare("UPDATE payer_leases SET state = 'FREE', holder_request_id = NULL, updated_at = ? WHERE payer = ? AND holder_request_id = ? AND version = ?")
        .run(now, payer, holderRequestId, token);
    } catch (err) {
      throw new StoreError(`payer lease release failed: ${(err as Error).message}`);
    }
  }

  get(requestId: string): ExecutionRecord | null {
    try {
      return this.getRow(requestId);
    } catch (err) {
      throw new StoreError(`execution lookup failed: ${(err as Error).message}`);
    }
  }

  private getRow(requestId: string): ExecutionRecord | null {
    const row = this.db
      .prepare("SELECT * FROM executions WHERE request_id = ?")
      .get(requestId) as Record<string, unknown> | undefined;
    return row === undefined ? null : rowToRecord(row);
  }

  private getRowByNonce(nonce: string): ExecutionRecord | null {
    const row = this.db
      .prepare("SELECT * FROM executions WHERE nonce = ?")
      .get(nonce) as Record<string, unknown> | undefined;
    return row === undefined ? null : rowToRecord(row);
  }

  private execOrThrow(sql: "BEGIN IMMEDIATE" | "COMMIT" | "ROLLBACK"): void {
    try {
      this.db.exec(sql);
    } catch (err) {
      throw new StoreError(`execution transaction failed (${sql}): ${(err as Error).message}`);
    }
  }

  private rollbackQuiet(): void {
    try {
      this.db.exec("ROLLBACK");
    } catch {
      // Fail closed upstream.
    }
  }

  close(): void {
    this.db.close();
  }
}

function isUniqueViolation(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    "code" in err &&
    typeof (err as { code: unknown }).code === "string" &&
    ((err as { code: string }).code.startsWith("SQLITE_CONSTRAINT_PRIMARYKEY") ||
      (err as { code: string }).code.startsWith("SQLITE_CONSTRAINT_UNIQUE"))
  );
}
