/**
 * Durable SQLite replay store — Oracle69 AgentPay (M2, production default).
 *
 * DRIVER CHOICE: better-sqlite3 (synchronous API).
 * - Synchronous check-and-set inside one transaction eliminates async-gap
 *   races that an async driver would leave between SELECT and INSERT.
 * - Real SQLite file locking + UNIQUE constraints enforce single-use across
 *   separate store instances and OS processes; no JS mutex is trusted for
 *   correctness.
 * - `node:sqlite` was evaluated and rejected: experimental API with
 *   change-at-any-time warnings on Node 22, unsuitable as a trust anchor.
 *
 * SCHEMA (see also store/schema.sql):
 *   consumed_authorizations(
 *     nonce TEXT PRIMARY KEY,          -- durable nonce uniqueness
 *     request_id TEXT NOT NULL UNIQUE, -- durable requestId uniqueness
 *     ...metadata..., consumed_at INTEGER NOT NULL, policy_digest TEXT NOT NULL)
 *
 * TRANSACTION STRATEGY (claim):
 *   BEGIN IMMEDIATE → SELECT by nonce → SELECT by requestId → INSERT → COMMIT.
 * - BEGIN IMMEDIATE takes the write lock up front, so a concurrent claimant
 *   blocks (busy_timeout) then sees the committed row and reports precise
 *   reuse instead of racing on INSERT.
 * - A residual UNIQUE-violation race is caught and resolved by re-reading to
 *   identify the collided identifier.
 * - busy_timeout is short and finite: contention surfaces as an error (fail
 *   closed), never a hang.
 * - Any storage error (locked/corrupt/closed handle) throws StoreError → the
 *   verifier maps it to STORE_UNAVAILABLE (fail closed).
 *
 * CRASH SAFETY: claim() runs AFTER signature/policy verification and is the
 * single durability event. Crash before claim → nothing persisted, safe retry.
 * Crash after claim → row persisted, retry reports REPLAY_DETECTED (fail
 * closed, never double-authorized). There is intentionally no release path and
 * no cleanup API: consumed identifiers are never reusable.
 *
 * DEPLOYMENT BOUNDARIES (read before operating):
 * - The concurrency guarantee targets a SINGLE HOST with the database on a
 *   LOCAL filesystem. Network filesystems (notably NFS, where SQLite locking
 *   is unreliable) are NOT supported; cross-process tests cover same-host
 *   processes only.
 * - Multi-host deployment requires a shared replay store with equivalent
 *   transactional uniqueness guarantees (e.g. a single authoritative database
 *   with UNIQUE constraints, or consensus on consumption). Two hosts with
 *   independent SQLite files WILL double-authorize.
 * - TRUSTED WIRING: the server config (approver, domainId, policyVersion,
 *   policy) and the ReplayStore instance passed to `authorizePayment` must
 *   originate from trusted application wiring. A caller able to inject a
 *   hostile store (e.g. one whose claim() always succeeds) or substitute the
 *   configuration bypasses replay protection and approver binding entirely;
 *   the function cannot distinguish trusted from hostile collaborators.
 * - This module never executes or settles payments; authorization output must
 *   be re-verified at execution time by the future executor.
 */
import Database from "better-sqlite3";
import type { ClaimResult, ReplayEntry, ReplayStore } from "./types.js";

export class StoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StoreError";
  }
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS consumed_authorizations (
  nonce TEXT PRIMARY KEY,
  request_id TEXT NOT NULL UNIQUE,
  recipient TEXT NOT NULL,
  amount_wei TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER NOT NULL,
  policy_digest TEXT NOT NULL
);`;

export class SqliteReplayStore implements ReplayStore {
  private readonly db: Database.Database;

  constructor(path: string) {
    if (typeof path !== "string" || path.length === 0) {
      throw new Error("sqlite store path must be a non-empty string");
    }
    try {
      this.db = new Database(path);
    } catch (err) {
      throw new StoreError(`cannot open replay database: ${(err as Error).message}`);
    }
    try {
      if (path !== ":memory:") {
        this.db.pragma("journal_mode = WAL");
      }
      this.db.pragma("busy_timeout = 5000");
      this.db.exec(SCHEMA);
    } catch (err) {
      throw new StoreError(`cannot initialize replay database: ${(err as Error).message}`);
    }
  }

  claim(entry: ReplayEntry): ClaimResult {
    this.execOrThrow("BEGIN IMMEDIATE");
    try {
      const hit = this.findCollision(entry);
      if (hit !== null) {
        this.execOrThrow("ROLLBACK");
        return { ok: false, reused: hit };
      }
      try {
        this.db
          .prepare(
            "INSERT INTO consumed_authorizations (nonce, request_id, recipient, amount_wei, expires_at, consumed_at, policy_digest) VALUES (?, ?, ?, ?, ?, ?, ?)",
          )
          .run(
            entry.nonce,
            entry.requestId,
            entry.recipient,
            entry.amountWei,
            entry.expiresAt,
            entry.consumedAt,
            entry.policyDigest,
          );
      } catch (insertErr) {
        // Residual race: a concurrent claimant committed between our SELECTs
        // and INSERT. Constraints held; re-read to name the collided side.
        this.rollbackQuiet();
        if (!isUniqueViolation(insertErr)) {
          throw new StoreError(`replay claim failed: ${(insertErr as Error).message}`);
        }
        const late = this.findCollision(entry);
        if (late === null) {
          throw new StoreError("replay claim failed: unresolved constraint collision");
        }
        return { ok: false, reused: late };
      }
      this.execOrThrow("COMMIT");
      return { ok: true };
    } catch (err) {
      this.rollbackQuiet();
      if (err instanceof StoreError) throw err;
      throw new StoreError(`replay claim failed: ${(err as Error).message}`);
    }
  }

  /** Returns which identifier is already consumed, or null when both are free. */
  private findCollision(entry: ReplayEntry): "nonce" | "requestId" | null {
    let byNonce: unknown;
    let byRequest: unknown;
    try {
      byNonce = this.db
        .prepare("SELECT nonce FROM consumed_authorizations WHERE nonce = ?")
        .get(entry.nonce);
      byRequest = this.db
        .prepare("SELECT request_id FROM consumed_authorizations WHERE request_id = ?")
        .get(entry.requestId);
    } catch (err) {
      throw new StoreError(`replay lookup failed: ${(err as Error).message}`);
    }
    if (byNonce !== undefined) return "nonce";
    if (byRequest !== undefined) return "requestId";
    return null;
  }

  private execOrThrow(sql: "BEGIN IMMEDIATE" | "COMMIT" | "ROLLBACK"): void {
    try {
      this.db.exec(sql);
    } catch (err) {
      throw new StoreError(`replay transaction failed (${sql}): ${(err as Error).message}`);
    }
  }

  private rollbackQuiet(): void {
    try {
      this.db.exec("ROLLBACK");
    } catch {
      // Already rolled back, read-only, or connection lost: fail closed upstream.
    }
  }

  isConsumedByNonce(nonce: string): boolean {
    try {
      const row = this.db
        .prepare("SELECT nonce FROM consumed_authorizations WHERE nonce = ?")
        .get(nonce);
      return row !== undefined;
    } catch (err) {
      throw new StoreError(`replay lookup failed: ${(err as Error).message}`);
    }
  }

  isConsumedByRequestId(requestId: string): boolean {
    try {
      const row = this.db
        .prepare("SELECT request_id FROM consumed_authorizations WHERE request_id = ?")
        .get(requestId) as unknown;
      return row !== undefined;
    } catch (err) {
      throw new StoreError(`replay lookup failed: ${(err as Error).message}`);
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
