/**
 * Execution-ledger tests: reservation single-use, state transitions, restart
 * durability. Chain interaction is NOT exercised here (see execute.test.ts
 * with the mock port, concurrent.test.ts for races).
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ExecutionStore, type Reservation } from "../../src/execution/store.js";
import { ADDR_A, NOW } from "./helpers.js";

const DIGEST = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

function reservation(over: Partial<Reservation> = {}): Reservation {
  return {
    requestId: "req-x001",
    nonce: "nonce-x001",
    recipient: ADDR_A,
    amountWei: "400000000000000000",
    asset: "MON",
    chainId: 10143,
    expiresAt: NOW + 3600,
    policyDigest: DIGEST,
    approver: ADDR_A,
    domainId: "agentpay-dev-v1",
    policyVersion: "m2.1",
    createdAt: NOW,
    ...over,
  };
}

const tempDirs: string[] = [];
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function tempDbPath(): string {
  const dir = mkdtempSync(join(tmpdir(), "agentpay-m3-"));
  tempDirs.push(dir);
  return join(dir, "exec.db");
}

describe("execution ledger", () => {
  it("first reservation creates a RESERVED row", () => {
    const s = new ExecutionStore(":memory:");
    try {
      expect(s.reserve(reservation())).toEqual({ created: true });
      expect(s.get("req-x001")?.state).toBe("RESERVED");
    } finally {
      s.close();
    }
  });

  it("duplicate reservation returns the existing row", () => {
    const s = new ExecutionStore(":memory:");
    try {
      expect(s.reserve(reservation()).created).toBe(true);
      const again = s.reserve(reservation());
      expect(again.created).toBe(false);
      if (!again.created) expect(again.existing.state).toBe("RESERVED");
    } finally {
      s.close();
    }
  });

  it("nonce reuse across request IDs collides", () => {
    const s = new ExecutionStore(":memory:");
    try {
      expect(s.reserve(reservation()).created).toBe(true);
      const clash = s.reserve(reservation({ requestId: "req-other" }));
      expect(clash.created).toBe(false);
      if (!clash.created) expect(clash.existing.requestId).toBe("req-x001");
    } finally {
      s.close();
    }
  });

  it("transitions move through the lifecycle", () => {
    const s = new ExecutionStore(":memory:");
    try {
      s.reserve(reservation());
      s.transition("req-x001", "UNKNOWN", { txHash: "0xabc", now: NOW });
      expect(s.get("req-x001")?.state).toBe("UNKNOWN");
      expect(s.get("req-x001")?.txHash).toBe("0xabc");
      s.transition("req-x001", "SENT", { now: NOW + 1 });
      expect(s.get("req-x001")?.txHash).toBe("0xabc");
      s.transition("req-x001", "CONFIRMED", { now: NOW + 2 });
      expect(s.get("req-x001")?.state).toBe("CONFIRMED");
    } finally {
      s.close();
    }
  });

  it("pre-submit failure returns the row to RESERVED with attempts recorded", () => {
    const s = new ExecutionStore(":memory:");
    try {
      s.reserve(reservation());
      expect(s.claimSendRight("req-x001", NOW)).toBe(true);
      expect(s.notePreSubmitFailure("req-x001", NOW, "boom", 1, ["SENDING"])).toBe(true);
      const row = s.get("req-x001");
      expect(row?.state).toBe("RESERVED");
      expect(row?.attempts).toBe(1);
      expect(row?.lastError).toBe("boom");
    } finally {
      s.close();
    }
  });

  it("conditional transitions never regress concurrent updates", () => {
    const s = new ExecutionStore(":memory:");
    try {
      s.reserve(reservation());
      // Wrong expected state: no write, returns false.
      expect(s.transitionFrom("req-x001", "SENT", { now: NOW }, ["UNKNOWN"])).toBe(false);
      expect(s.get("req-x001")?.state).toBe("RESERVED");
      // Right expected state: writes.
      expect(s.claimSendRight("req-x001", NOW)).toBe(true);
      expect(s.transitionFrom("req-x001", "UNKNOWN", { txHash: "0xabc", now: NOW }, ["SENDING"])).toBe(true);
      expect(s.transitionFrom("req-x001", "SENT", { now: NOW }, ["UNKNOWN"])).toBe(true);
      // Concurrent CONFIRMED then a late SENT update: SENT must not regress it.
      expect(s.transitionFrom("req-x001", "CONFIRMED", { now: NOW }, ["UNKNOWN", "SENT"])).toBe(true);
      expect(s.transitionFrom("req-x001", "SENT", { now: NOW }, ["UNKNOWN"])).toBe(false);
      expect(s.get("req-x001")?.state).toBe("CONFIRMED");
      // notePreSubmitFailure from the wrong state refuses as well.
      expect(s.notePreSubmitFailure("req-x001", NOW, "x", 9, ["UNKNOWN"])).toBe(false);
      expect(s.get("req-x001")?.attempts).toBe(0);
    } finally {
      s.close();
    }
  });

  it("missing rows and unknown transitions fail closed", () => {
    const s = new ExecutionStore(":memory:");
    try {
      expect(s.get("nope")).toBeNull();
      expect(() => s.transition("nope", "SENT", { now: NOW })).toThrow();
    } finally {
      s.close();
    }
  });

  it("restart preserves reservations and states", () => {
    const path = tempDbPath();
    const a = new ExecutionStore(path);
    a.reserve(reservation());
    a.transition("req-x001", "UNKNOWN", { txHash: "0xabc", now: NOW });
    a.close();
    const b = new ExecutionStore(path);
    try {
      expect(b.get("req-x001")?.state).toBe("UNKNOWN");
      expect(b.reserve(reservation()).created).toBe(false);
    } finally {
      b.close();
    }
  });

  it("use after close throws", () => {
    const s = new ExecutionStore(":memory:");
    s.close();
    expect(() => s.reserve(reservation())).toThrow();
  });
});

describe("payer lease", () => {
  const PAYER = "0xpayer000000000000000000000000000000000001";

  it("acquire/release round-trip with holder-conditional release", () => {
    const s = new ExecutionStore(":memory:");
    try {
      const a = s.acquirePayerLease(PAYER, "req-a", NOW, 300);
      expect(a.held).toBe(true);
      expect(a.token).toBeGreaterThan(0);
      expect(s.acquirePayerLease(PAYER, "req-b", NOW, 300).held).toBe(false);
      // A different holder cannot release our hold (token mismatch too).
      s.releasePayerLease(PAYER, "req-b", 9999, NOW);
      expect(s.acquirePayerLease(PAYER, "req-c", NOW, 300).held).toBe(false);
      s.releasePayerLease(PAYER, "req-a", a.token, NOW);
      const c = s.acquirePayerLease(PAYER, "req-c", NOW, 300);
      expect(c.held).toBe(true);
      expect(c.token).toBeGreaterThan(a.token);
    } finally {
      s.close();
    }
  });

  it("same-holder re-acquire succeeds without advancing the token (retry safety)", () => {
    const s = new ExecutionStore(":memory:");
    try {
      const a1 = s.acquirePayerLease(PAYER, "req-a", NOW, 300);
      const a2 = s.acquirePayerLease(PAYER, "req-a", NOW + 1, 300);
      expect(a1.held).toBe(true);
      expect(a2.held).toBe(true);
      expect(a2.token).toBe(a1.token);
    } finally {
      s.close();
    }
  });

  it("steals from terminal/submitted holders, refuses live ones", () => {
    const s = new ExecutionStore(":memory:");
    try {
      s.reserve(reservation({ requestId: "req-h", nonce: "nonce-h" }));
      const h = s.acquirePayerLease(PAYER, "req-h", NOW, 300);
      expect(h.held).toBe(true);
      // Holder RESERVED (allocation may resume) -> busy.
      expect(s.acquirePayerLease(PAYER, "req-n", NOW, 300).held).toBe(false);
      // Holder advanced to UNKNOWN (submitted or uncertain; never allocates
      // again) -> steal succeeds with an advanced token.
      s.transition("req-h", "UNKNOWN", { txHash: "0xabc", now: NOW });
      const n = s.acquirePayerLease(PAYER, "req-n", NOW, 300);
      expect(n.held).toBe(true);
      expect(n.token).toBeGreaterThan(h.token);
    } finally {
      s.close();
    }
  });

  it("stale SENDING holds are stealable after grace, fresh ones block", () => {
    const s = new ExecutionStore(":memory:");
    try {
      s.reserve(reservation({ requestId: "req-h", nonce: "nonce-h" }));
      s.claimSendRight("req-h", 1_000);
      const h = s.acquirePayerLease(PAYER, "req-h", 1_000, 300);
      expect(h.held).toBe(true);
      // Fresh SENDING hold (likely alive) -> busy.
      expect(s.acquirePayerLease(PAYER, "req-n", 1_000 + 299, 300).held).toBe(false);
      // Past-grace SENDING hold (presumed crashed) -> steal with new token.
      const n = s.acquirePayerLease(PAYER, "req-n", 1_000 + 301, 300);
      expect(n.held).toBe(true);
      expect(n.token).toBeGreaterThan(h.token);
    } finally {
      s.close();
    }
  });

  it("old fencing token cannot record after a steal (stale holder fenced)", () => {
    const s = new ExecutionStore(":memory:");
    try {
      s.reserve(reservation({ requestId: "req-h", nonce: "nonce-h" }));
      s.claimSendRight("req-h", 1_000);
      const old = s.acquirePayerLease(PAYER, "req-h", 1_000, 300);
      expect(old.held).toBe(true);
      // Thief steals past grace (holder SENDING since t=1000, now past 1300).
      s.reserve(reservation({ requestId: "req-n", nonce: "nonce-n" }));
      const thief = s.acquirePayerLease(PAYER, "req-n", 1_000 + 301, 300);
      expect(thief.held).toBe(true);
      // Old holder's fenced write affects zero rows.
      expect(
        s.recordUnknownAttempt(
          "req-h",
          { txHash: "0xdef", senderNonce: 0, now: 1_000 + 302, attempts: 1 },
          { payer: PAYER, holder: "req-h", token: old.token },
        ),
      ).toBe(false);
      expect(s.get("req-h")?.state).toBe("SENDING");
      expect(s.get("req-h")?.txHash).toBeNull();
    } finally {
      s.close();
    }
  });
});
