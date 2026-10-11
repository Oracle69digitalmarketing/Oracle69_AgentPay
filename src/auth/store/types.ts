/**
 * Replay-store interface — Oracle69 AgentPay (M2).
 *
 * INVARIANTS (enforced by the durable backend, never by caller discipline):
 * - A nonce is single-use forever. A requestId is single-use forever.
 * - There is intentionally NO delete/cleanup API: consumed identifiers must
 *   never become reusable, so time-based cleanup is forbidden by structure.
 */
export interface ReplayEntry {
  nonce: string;
  requestId: string;
  recipient: string;
  /** Decimal string of the exact bigint wei amount (never float). */
  amountWei: string;
  expiresAt: number;
  /** Server `now` at consumption (unix seconds). */
  consumedAt: number;
  policyDigest: string;
}

export type ClaimResult = { ok: true } | { ok: false; reused: "nonce" | "requestId" };

export interface ReplayStore {
  /**
   * Atomically consume (nonce, requestId). Exactly one caller wins when
   * identifiers collide. MUST throw on storage failure (fail closed).
   */
  claim(entry: ReplayEntry): ClaimResult;
  isConsumedByNonce(nonce: string): boolean;
  isConsumedByRequestId(requestId: string): boolean;
  close(): void;
}
