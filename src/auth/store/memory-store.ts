/**
 * In-memory replay store — TESTS ONLY.
 *
 * Same single-use semantics as the SQLite backend, but durability ends with
 * the process: a restart wipes consumed identifiers, so a previously used
 * authorization would verify again. NEVER use as the durable implementation.
 * Production default is SqliteReplayStore.
 */
import type { ClaimResult, ReplayEntry, ReplayStore } from "./types.js";

export class MemoryReplayStore implements ReplayStore {
  private readonly byNonce = new Map<string, ReplayEntry>();
  private readonly byRequestId = new Map<string, string>();
  private closed = false;

  claim(entry: ReplayEntry): ClaimResult {
    this.assertOpen();
    // Synchronous check-and-set: atomic within the Node event loop.
    if (this.byNonce.has(entry.nonce)) return { ok: false, reused: "nonce" };
    if (this.byRequestId.has(entry.requestId)) return { ok: false, reused: "requestId" };
    this.byNonce.set(entry.nonce, entry);
    this.byRequestId.set(entry.requestId, entry.nonce);
    return { ok: true };
  }

  isConsumedByNonce(nonce: string): boolean {
    this.assertOpen();
    return this.byNonce.has(nonce);
  }

  isConsumedByRequestId(requestId: string): boolean {
    this.assertOpen();
    return this.byRequestId.has(requestId);
  }

  close(): void {
    this.closed = true;
    this.byNonce.clear();
    this.byRequestId.clear();
  }

  private assertOpen(): void {
    if (this.closed) throw new Error("replay store is closed");
  }
}
