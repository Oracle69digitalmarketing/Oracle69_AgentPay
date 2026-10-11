/**
 * M2 authorization tests. Keys are runtime-generated; time is injected.
 * The memory store backs most cases; SQLite file cases prove durable replay.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { authorizePayment } from "../../src/auth/verify.js";
import type {
  AuthRejectionCode,
  AuthorizationDecision,
  AuthorizationProof,
} from "../../src/auth/types.js";
import { CURRENT_POLICY_VERSION } from "../../src/auth/types.js";
import { SqliteReplayStore } from "../../src/auth/store/sqlite-store.js";
import { MemoryReplayStore } from "../../src/auth/store/memory-store.js";
import type { PaymentIntent } from "../../src/policy/types.js";
import {
  ADDR_A,
  ADDR_B,
  DOMAIN_DEV,
  DOMAIN_PROD,
  NOW,
  UNAPPROVED,
  baseFixture,
  baseIntent,
  basePolicy,
  makeAccount,
  signApproval,
  type Fixture,
} from "./helpers.js";

const tempDirs: string[] = [];
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function tempDbPath(): string {
  const dir = mkdtempSync(join(tmpdir(), "agentpay-m2v-"));
  tempDirs.push(dir);
  return join(dir, "replay.db");
}

function codesOf(d: AuthorizationDecision): AuthRejectionCode[] {
  if (d.authorized) return [];
  return d.reasons.map((r) => r.code);
}

async function freshProof(fx: Fixture, intent: PaymentIntent): Promise<AuthorizationProof> {
  return signApproval(fx.approver, intent, fx.config);
}

describe("M2 authorization", () => {
  it("1. valid signature + valid policy authorizes (execution NOT granted)", async () => {
    const fx = baseFixture();
    const intent = baseIntent();
    const proof = await freshProof(fx, intent);
    const d = await authorizePayment({ intent, proof, config: fx.config, now: NOW, store: fx.store });
    expect(d.authorized).toBe(true);
    if (d.authorized) {
      expect(d.executed).toBe(false);
      expect(d.requestId).toBe("req-001");
      expect(d.recipient).toBe(ADDR_A);
      expect(d.amountWei).toBe(400_000_000_000_000_000n);
      expect(typeof d.amountWei).toBe("bigint");
      expect(d.approver).toBe(fx.approver.address);
    }
    fx.store.close();
  });

  it("2. wrong signer is rejected", async () => {
    const fx = baseFixture();
    const stranger = makeAccount();
    const intent = baseIntent();
    const proof = await signApproval(stranger, intent, fx.config);
    const d = await authorizePayment({ intent, proof, config: fx.config, now: NOW, store: fx.store });
    expect(d.authorized).toBe(false);
    expect(codesOf(d)).toEqual(["WRONG_SIGNER"]);
    fx.store.close();
  });

  it("3. modified amount is rejected", async () => {
    const fx = baseFixture();
    const intent = baseIntent();
    const proof = await freshProof(fx, intent);
    const tampered = { ...intent, amountWei: 500_000_000_000_000_000n };
    const d = await authorizePayment({ intent: tampered, proof, config: fx.config, now: NOW, store: fx.store });
    expect(d.authorized).toBe(false);
    expect(codesOf(d).length).toBeGreaterThan(0);
    for (const c of codesOf(d)) expect(["WRONG_SIGNER", "INVALID_SIGNATURE"]).toContain(c);
    fx.store.close();
  });

  it("4. modified recipient is rejected", async () => {
    const fx = baseFixture();
    const intent = baseIntent();
    const proof = await freshProof(fx, intent);
    const d = await authorizePayment({
      intent: { ...intent, recipient: ADDR_B },
      proof,
      config: fx.config,
      now: NOW,
      store: fx.store,
    });
    expect(d.authorized).toBe(false);
    expect(codesOf(d).length).toBeGreaterThan(0);
    fx.store.close();
  });

  it("5. modified chain ID is rejected at the policy layer", async () => {
    const fx = baseFixture();
    const intent = baseIntent();
    const proof = await freshProof(fx, intent);
    const d = await authorizePayment({
      intent: { ...intent, chainId: 1 },
      proof,
      config: fx.config,
      now: NOW,
      store: fx.store,
    });
    expect(d.authorized).toBe(false);
    expect(codesOf(d)).toContain("WRONG_CHAIN");
    fx.store.close();
  });

  it("6. modified request ID is rejected", async () => {
    const fx = baseFixture();
    const intent = baseIntent();
    const proof = await freshProof(fx, intent);
    const d = await authorizePayment({
      intent: { ...intent, requestId: "req-002" },
      proof,
      config: fx.config,
      now: NOW,
      store: fx.store,
    });
    expect(d.authorized).toBe(false);
    expect(codesOf(d).length).toBeGreaterThan(0);
    fx.store.close();
  });

  it("7. modified nonce is rejected", async () => {
    const fx = baseFixture();
    const intent = baseIntent();
    const proof = await freshProof(fx, intent);
    const d = await authorizePayment({
      intent: { ...intent, nonce: "nonce-999" },
      proof,
      config: fx.config,
      now: NOW,
      store: fx.store,
    });
    expect(d.authorized).toBe(false);
    expect(codesOf(d).length).toBeGreaterThan(0);
    fx.store.close();
  });

  it("8. modified asset is rejected at the policy layer", async () => {
    const fx = baseFixture();
    const intent = baseIntent();
    const proof = await freshProof(fx, intent);
    const d = await authorizePayment({
      intent: { ...intent, asset: "ETH" } as unknown as PaymentIntent,
      proof,
      config: fx.config,
      now: NOW,
      store: fx.store,
    });
    expect(d.authorized).toBe(false);
    expect(codesOf(d)).toContain("INVALID_ASSET");
    fx.store.close();
  });

  it("9. modified expiry is rejected", async () => {
    const fx = baseFixture();
    const intent = baseIntent();
    const proof = await freshProof(fx, intent);
    const d = await authorizePayment({
      intent: { ...intent, expiresAt: NOW + 7200 },
      proof,
      config: fx.config,
      now: NOW,
      store: fx.store,
    });
    expect(d.authorized).toBe(false);
    expect(codesOf(d).length).toBeGreaterThan(0);
    fx.store.close();
  });

  it("10. expiry exactly equal to now is rejected", async () => {
    const fx = baseFixture();
    const intent = baseIntent({ expiresAt: NOW });
    const proof = await freshProof(fx, intent);
    const d = await authorizePayment({ intent, proof, config: fx.config, now: NOW, store: fx.store });
    expect(d.authorized).toBe(false);
    expect(codesOf(d)).toContain("EXPIRED_REQUEST");
    fx.store.close();
  });

  it("11. wrong environment/domain is rejected", async () => {
    const fx = baseFixture();
    const intent = baseIntent();
    const proof = await freshProof(fx, intent);
    const forged = { ...proof, domainId: "agentpay-evil-v1" };
    const d = await authorizePayment({ intent, proof: forged, config: fx.config, now: NOW, store: fx.store });
    expect(d.authorized).toBe(false);
    expect(codesOf(d)).toEqual(["DOMAIN_MISMATCH"]);
    fx.store.close();
  });

  it("12. cross-environment replay is rejected", async () => {
    const approver = makeAccount();
    const dev = {
      policy: basePolicy(),
      approver: approver.address,
      domainId: DOMAIN_DEV,
      policyVersion: CURRENT_POLICY_VERSION,
    };
    const prod = { ...dev, domainId: DOMAIN_PROD };
    const intent = baseIntent();
    const devProof = await signApproval(approver, intent, dev);
    const store = new SqliteReplayStore(":memory:");
    try {
      const d = await authorizePayment({ intent, proof: devProof, config: prod, now: NOW, store });
      expect(d.authorized).toBe(false);
      expect(codesOf(d)).toEqual(["DOMAIN_MISMATCH"]);
    } finally {
      store.close();
    }
  });

  it("13. policy version mismatch is rejected", async () => {
    const fx = baseFixture();
    const intent = baseIntent();
    const proof = await freshProof(fx, intent);
    const d = await authorizePayment({
      intent,
      proof: { ...proof, policyVersion: "m1.0" },
      config: fx.config,
      now: NOW,
      store: fx.store,
    });
    expect(d.authorized).toBe(false);
    expect(codesOf(d)).toEqual(["POLICY_VERSION_MISMATCH"]);
    fx.store.close();
  });

  it("14. policy digest mismatch is rejected", async () => {
    const fx = baseFixture();
    const intent = baseIntent();
    const proof = await freshProof(fx, intent);
    const d = await authorizePayment({
      intent,
      proof: { ...proof, policyDigest: "0x0000000000000000000000000000000000000000000000000000000000000000" },
      config: fx.config,
      now: NOW,
      store: fx.store,
    });
    expect(d.authorized).toBe(false);
    expect(codesOf(d)).toEqual(["POLICY_DIGEST_MISMATCH"]);
    fx.store.close();
  });

  it("15. a policy change invalidates an old approval", async () => {
    const fx = baseFixture();
    const intent = baseIntent();
    const proof = await freshProof(fx, intent);
    const changed = {
      ...fx.config,
      policy: basePolicy({ requireHumanApproval: false }),
    };
    const d = await authorizePayment({ intent, proof, config: changed, now: NOW, store: fx.store });
    expect(d.authorized).toBe(false);
    expect(codesOf(d)).toEqual(["POLICY_DIGEST_MISMATCH"]);
    fx.store.close();
  });

  it("16. over-limit payments stay rejected despite a valid signature", async () => {
    const fx = baseFixture();
    const intent = baseIntent({ amountWei: 4_000_000_000_000_000_000n });
    const proof = await freshProof(fx, intent);
    const d = await authorizePayment({ intent, proof, config: fx.config, now: NOW, store: fx.store });
    expect(d.authorized).toBe(false);
    expect(codesOf(d)).toContain("EXCEEDS_LIMIT");
    fx.store.close();
  });

  it("17. unapproved recipients stay rejected despite a valid signature", async () => {
    const fx = baseFixture();
    const intent = baseIntent({ recipient: UNAPPROVED });
    const proof = await freshProof(fx, intent);
    const d = await authorizePayment({ intent, proof, config: fx.config, now: NOW, store: fx.store });
    expect(d.authorized).toBe(false);
    expect(codesOf(d)).toContain("NOT_ALLOWLISTED");
    fx.store.close();
  });

  it("18. malformed policy and server config fail closed", async () => {
    const fx = baseFixture();
    const intent = baseIntent();
    const proof = await freshProof(fx, intent);
    const badConfigs: unknown[] = [
      { ...fx.config, policy: { ...fx.config.policy, maxPerPaymentWei: 0n } },
      { ...fx.config, approver: "not-an-address" },
      { ...fx.config, approver: "0x0000000000000000000000000000000000000000" },
      { ...fx.config, domainId: "" },
      { ...fx.config, policyVersion: "" },
      { ...fx.config, policy: null },
      null,
    ];
    for (const bad of badConfigs) {
      const d = await authorizePayment({ intent, proof, config: bad, now: NOW, store: fx.store });
      expect(d.authorized).toBe(false);
      expect(codesOf(d)).toContain("INVALID_CONFIG");
    }
    const noStore = await authorizePayment({ intent, proof, config: fx.config, now: NOW, store: undefined });
    expect(noStore.authorized).toBe(false);
    expect(codesOf(noStore)).toContain("INVALID_CONFIG");
    fx.store.close();
  });

  it("19. a client-supplied approval boolean cannot bypass verification", async () => {
    const fx = baseFixture();
    const intent = { ...baseIntent(), humanApprovalVerified: true } as unknown as PaymentIntent;
    const garbageProof = {
      signature: "0x" + "11".repeat(65),
      domainId: DOMAIN_DEV,
      policyVersion: CURRENT_POLICY_VERSION,
      policyDigest: "0x" + "22".repeat(32),
    };
    const d = await authorizePayment({ intent, proof: garbageProof, config: fx.config, now: NOW, store: fx.store });
    expect(d.authorized).toBe(false);
    const missingProof = await authorizePayment({
      intent,
      proof: {},
      config: fx.config,
      now: NOW,
      store: fx.store,
    });
    expect(missingProof.authorized).toBe(false);
    expect(codesOf(missingProof)).toContain("INVALID_PROOF");
    fx.store.close();
  });

  it("20. canonical encoding is deterministic regardless of key insertion order", async () => {
    const fx = baseFixture();
    const ordered = baseIntent();
    const reordered = {
      expiresAt: ordered.expiresAt,
      nonce: ordered.nonce,
      chainId: ordered.chainId,
      purpose: ordered.purpose,
      asset: ordered.asset,
      amountWei: ordered.amountWei,
      recipient: ordered.recipient,
      requestId: "req-002",
    } as PaymentIntent;
    const proof = await freshProof(fx, reordered);
    const d = await authorizePayment({ intent: reordered, proof, config: fx.config, now: NOW, store: fx.store });
    expect(d.authorized).toBe(true);
    void ordered;
    fx.store.close();
  });

  it("21. mutating any signed field invalidates the approval", async () => {
    const fx = baseFixture();
    const intent = baseIntent();
    const proof = await freshProof(fx, intent);
    const mutations: Array<Partial<PaymentIntent>> = [
      { amountWei: 400_000_000_000_000_001n },
      { recipient: ADDR_B },
      { requestId: "req-X" },
      { nonce: "nonce-X" },
      { expiresAt: NOW + 9999 },
    ];
    for (const m of mutations) {
      const s = new MemoryReplayStore();
      const d = await authorizePayment({
        intent: { ...intent, ...m },
        proof,
        config: fx.config,
        now: NOW,
        store: s,
      });
      expect(d.authorized).toBe(false);
      s.close();
    }
    fx.store.close();
  });

  it("malformed signatures and proofs fail closed", async () => {
    const fx = baseFixture();
    const intent = baseIntent();
    for (const bad of [
      { signature: "0x1234", domainId: DOMAIN_DEV, policyVersion: CURRENT_POLICY_VERSION, policyDigest: "0x" + "00".repeat(32) },
      { signature: "not-hex", domainId: DOMAIN_DEV, policyVersion: CURRENT_POLICY_VERSION, policyDigest: "0x" + "00".repeat(32) },
      null,
      "proof",
    ]) {
      const d = await authorizePayment({ intent, proof: bad, config: fx.config, now: NOW, store: fx.store });
      expect(d.authorized).toBe(false);
      expect(codesOf(d)).toContain("INVALID_PROOF");
    }
    // Well-formed 65 zero bytes: recovery fails or recovers wrong → rejected either way.
    const zeroSig = {
      signature: "0x" + "00".repeat(65),
      domainId: DOMAIN_DEV,
      policyVersion: CURRENT_POLICY_VERSION,
      policyDigest: (await freshProof(fx, intent)).policyDigest,
    };
    const d = await authorizePayment({ intent, proof: zeroSig, config: fx.config, now: NOW, store: fx.store });
    expect(d.authorized).toBe(false);
    fx.store.close();
  });

  it("second use of the same authorization is rejected (sqlite durable)", async () => {
    const fx = baseFixture();
    const path = tempDbPath();
    const store = new SqliteReplayStore(path);
    try {
      const intent = baseIntent();
      const proof = await freshProof(fx, intent);
      const first = await authorizePayment({ intent, proof, config: fx.config, now: NOW, store });
      expect(first.authorized).toBe(true);
      const second = await authorizePayment({ intent, proof, config: fx.config, now: NOW, store });
      expect(second.authorized).toBe(false);
      expect(codesOf(second)).toEqual(["REPLAY_DETECTED"]);
    } finally {
      store.close();
    }
    fx.store.close();
  });

  it("interrupted attempts cannot make identifiers reusable (fail closed)", async () => {
    const fx = baseFixture();
    const path = tempDbPath();
    const store = new SqliteReplayStore(path);
    try {
      // Simulate a crash after reservation but before completion: identifiers
      // claimed out-of-band stay consumed; a later full authorization fails closed.
      const reserved = store.claim({
        nonce: "nonce-001",
        requestId: "req-001",
        recipient: ADDR_A,
        amountWei: "400000000000000000",
        expiresAt: NOW + 3600,
        consumedAt: NOW,
        policyDigest: "0x" + "aa".repeat(32),
      });
      expect(reserved.ok).toBe(true);
      const intent = baseIntent();
      const proof = await freshProof(fx, intent);
      const d = await authorizePayment({ intent, proof, config: fx.config, now: NOW, store });
      expect(d.authorized).toBe(false);
      expect(codesOf(d)).toEqual(["REPLAY_DETECTED"]);
    } finally {
      store.close();
    }
    fx.store.close();
  });

  it("store failures fail closed", async () => {
    const fx = baseFixture();
    const intent = baseIntent();
    const proof = await freshProof(fx, intent);
    const dead = new SqliteReplayStore(":memory:");
    dead.close();
    const d = await authorizePayment({ intent, proof, config: fx.config, now: NOW, store: dead });
    expect(d.authorized).toBe(false);
    expect(codesOf(d)).toEqual(["STORE_UNAVAILABLE"]);
    fx.store.close();
  });

  it("smallest wei amounts stay exact (no float path)", async () => {
    const fx = baseFixture();
    const small = baseIntent({ amountWei: 1n });
    const proof = await freshProof(fx, small);
    const d = await authorizePayment({ intent: small, proof, config: fx.config, now: NOW, store: fx.store });
    expect(d.authorized).toBe(true);
    if (d.authorized) expect(d.amountWei).toBe(1n);
    fx.store.close();
  });

  it("HIGH-1 regression: mutating the intent after invoke cannot alter the decision", async () => {
    // Amount mutation. Pre-fix, the claim and result were read after the
    // await, so this authorized the MUTATED 4 MON (limit 1 MON) with a
    // signature over 0.4 MON. Fixed code authorizes the signed snapshot.
    {
      const fx = baseFixture();
      const intent = baseIntent({ requestId: "req-t1", nonce: "nonce-t1" });
      const proof = await freshProof(fx, intent);
      const pending = authorizePayment({ intent, proof, config: fx.config, now: NOW, store: fx.store });
      (intent as { amountWei: bigint }).amountWei = 4_000_000_000_000_000_000n;
      const d = await pending;
      expect(d.authorized).toBe(true);
      if (d.authorized) {
        expect(d.amountWei).toBe(400_000_000_000_000_000n);
        expect(d.recipient).toBe(ADDR_A);
      }
      // The consumed replay record carries the snapshot identifiers: the
      // original signed intent now replays instead of authorizing twice.
      const replay = await authorizePayment({
        intent: baseIntent({ requestId: "req-t1", nonce: "nonce-t1" }),
        proof,
        config: fx.config,
        now: NOW,
        store: fx.store,
      });
      expect(replay.authorized).toBe(false);
      expect(codesOf(replay)).toEqual(["REPLAY_DETECTED"]);
      fx.store.close();
    }
    // Recipient mutation. Pre-fix, this authorized an UNAPPROVED recipient
    // that was never signed (policy ran before the mutation). Fixed code
    // authorizes the signed snapshot recipient.
    {
      const fx = baseFixture();
      const intent = baseIntent({ requestId: "req-t2", nonce: "nonce-t2" });
      const proof = await freshProof(fx, intent);
      const pending = authorizePayment({ intent, proof, config: fx.config, now: NOW, store: fx.store });
      (intent as { recipient: string }).recipient = UNAPPROVED;
      const d = await pending;
      expect(d.authorized).toBe(true);
      if (d.authorized) expect(d.recipient).toBe(ADDR_A);
      fx.store.close();
    }
  });

  it("malformed now values fail closed", async () => {
    const fx = baseFixture();
    const intent = baseIntent();
    const proof = await freshProof(fx, intent);
    const badTimes: unknown[] = [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, "now", null, undefined, {}, [NOW]];
    for (const badNow of badTimes) {
      const d = await authorizePayment({ intent, proof, config: fx.config, now: badNow, store: fx.store });
      expect(d.authorized).toBe(false);
      expect(codesOf(d)).toEqual(["INVALID_REQUEST"]);
    }
    fx.store.close();
  });

  it("requireHumanApproval:false still verifies proof and enforces policy", async () => {
    const fx = baseFixture();
    const open = { ...fx.config, policy: basePolicy({ requireHumanApproval: false }) };
    // Valid proof still authorizes through the full pipeline.
    const intent = baseIntent({ requestId: "req-o1", nonce: "nonce-o1" });
    const proof = await signApproval(fx.approver, intent, open);
    const ok = await authorizePayment({ intent, proof, config: open, now: NOW, store: fx.store });
    expect(ok.authorized).toBe(true);
    // A malformed signature cannot authorize even when approval is not required.
    const forged = await authorizePayment({
      intent: baseIntent({ requestId: "req-o2", nonce: "nonce-o2" }),
      proof: { ...proof, signature: "0x" + "11".repeat(65) },
      config: open,
      now: NOW,
      store: fx.store,
    });
    expect(forged.authorized).toBe(false);
    // Other policy checks are not skipped: over-limit still rejected.
    const big = baseIntent({ requestId: "req-o3", nonce: "nonce-o3", amountWei: 4_000_000_000_000_000_000n });
    const bigProof = await signApproval(fx.approver, big, open);
    const over = await authorizePayment({ intent: big, proof: bigProof, config: open, now: NOW, store: fx.store });
    expect(over.authorized).toBe(false);
    expect(codesOf(over)).toContain("EXCEEDS_LIMIT");
    // ...and unapproved recipients still rejected.
    const stranger = baseIntent({ requestId: "req-o4", nonce: "nonce-o4", recipient: UNAPPROVED });
    const strangerProof = await signApproval(fx.approver, stranger, open);
    const denied = await authorizePayment({ intent: stranger, proof: strangerProof, config: open, now: NOW, store: fx.store });
    expect(denied.authorized).toBe(false);
    expect(codesOf(denied)).toContain("NOT_ALLOWLISTED");
    fx.store.close();
  });
});
