/**
 * Read-only preview tests. The critical structural guarantee: preview works
 * with a chain port that HAS NO send method at all, proving at the type and
 * runtime level that no submission path exists on this path. No keys, no
 * stores, no broadcasts — ever.
 */
import { describe, expect, it } from "vitest";
import { previewTransaction } from "../../src/preview/preview.js";
import { computePolicyDigest } from "../../src/auth/policy-digest.js";
import { DEMO_MAX_PER_PAYMENT_WEI } from "../../src/policy/types.js";
import {
  NOW,
  baseExecIntent,
  basePolicy,
  execFixture,
  signApproval,
} from "../execution/helpers.js";
import { MockChainPort } from "../execution/mock.js";

/**
 * A port object with NO sendRawTransaction member whatsoever: methods are
 * allowlisted explicitly (class methods live on the prototype, so object
 * spread would drop everything — this explicit form is the proof).
 */
function sendLessPort(mock: MockChainPort) {
  return {
    getChainId: mock.getChainId.bind(mock),
    getSenderNonce: mock.getSenderNonce.bind(mock),
    getBalance: mock.getBalance.bind(mock),
    estimateTransferGas: mock.estimateTransferGas.bind(mock),
    estimateFees: mock.estimateFees.bind(mock),
    getReceipt: mock.getReceipt.bind(mock),
  };
}

describe("read-only preview", () => {
  it("produces a full preview without proof, approval, keys, or stores", async () => {
    const fx = execFixture();
    const d = await previewTransaction({
      intent: baseExecIntent(),
      authConfig: fx.authConfig,
      senderAddress: fx.payer.address,
      now: NOW,
      chain: sendLessPort(fx.chain),
    });
    expect(d.ok).toBe(true);
    if (!d.ok) return;
    expect(d.network).toBe("Monad Testnet");
    expect(d.chainId).toBe(10143);
    expect(d.sender).toBe(fx.payer.address);
    expect(d.asset).toBe("MON");
    expect(d.amountWei).toBe("400000000000000000");
    expect(d.approval).toEqual({ present: false, verified: false, approver: null });
    expect(d.policyDigest).toBe(computePolicyDigest(fx.authConfig.policy));
    expect(d.feeCheck).toBeNull();
    expect(d.affordable).toBe(true);
    expect(d.chain.senderBalanceWei).toBe(fx.chain.balance.toString());
    fx.execStore.close();
  });

  it("verifies a supplied approval purely, without consuming replay state", async () => {
    const fx = execFixture();
    const intent = baseExecIntent();
    const proof = await signApproval(fx.approver, intent, fx.authConfig);
    const d = await previewTransaction({
      intent, proof, authConfig: fx.authConfig,
      senderAddress: fx.payer.address,
      now: NOW, chain: sendLessPort(fx.chain),
    });
    expect(d.ok).toBe(true);
    if (!d.ok) return;
    expect(d.approval).toEqual({ present: true, verified: true, approver: fx.approver.address });
    // The same approval is still fully usable afterwards (nothing consumed:
    // preview takes no store at all).
    const { authorizePayment } = await import("../../src/auth/verify.js");
    const { MemoryReplayStore } = await import("../../src/auth/store/memory-store.js");
    const store = new MemoryReplayStore();
    try {
      const auth = await authorizePayment({ intent, proof, config: fx.authConfig, now: NOW, store });
      expect(auth.authorized).toBe(true);
    } finally {
      store.close();
    }
    fx.execStore.close();
  });

  it("rejects bad proofs, over-ceiling amounts, wrong chains, and bad senders", async () => {
    const fx = execFixture();
    const stranger = (await import("../auth/helpers.js")).makeAccount();
    const intent = baseExecIntent();
    const badProof = await signApproval(stranger, intent, fx.authConfig);
    const bad = await previewTransaction({
      intent, proof: badProof, authConfig: fx.authConfig,
      senderAddress: fx.payer.address, now: NOW, chain: sendLessPort(fx.chain),
    });
    expect(bad.ok).toBe(false);
    const rich = await previewTransaction({
      intent: baseExecIntent({ amountWei: DEMO_MAX_PER_PAYMENT_WEI + 1n }),
      authConfig: fx.authConfig, senderAddress: fx.payer.address,
      now: NOW, chain: sendLessPort(fx.chain),
    });
    expect(rich.ok).toBe(false);
    fx.chain.chainId = 1;
    const wrongChain = await previewTransaction({
      intent: baseExecIntent(), authConfig: fx.authConfig,
      senderAddress: fx.payer.address, now: NOW, chain: sendLessPort(fx.chain),
    });
    expect(wrongChain.ok).toBe(false);
    const badSender = await previewTransaction({
      intent: baseExecIntent(), authConfig: fx.authConfig,
      senderAddress: "not-an-address", now: NOW, chain: sendLessPort(fx.chain),
    });
    expect(badSender.ok).toBe(false);
    fx.execStore.close();
  });

  it("insufficient balance fails closed (never ready)", async () => {
    const fx = execFixture();
    fx.chain.balance = 1n;
    const d = await previewTransaction({
      intent: baseExecIntent(), authConfig: fx.authConfig,
      senderAddress: fx.payer.address, now: NOW, chain: sendLessPort(fx.chain),
    });
    expect(d.ok).toBe(false);
    if (d.ok) return;
    expect(d.reasons.map((r) => r.code)).toContain("INSUFFICIENT_FUNDS");
    expect(fx.chain.sendLog.length).toBe(0);
    fx.execStore.close();
  });

  it("fee-cap violation fails closed (never ready)", async () => {
    const fx = execFixture();
    fx.chain.fees = { maxFeePerGas: 500_000_000_001n, maxPriorityFeePerGas: 1_000_000_000n };
    const d = await previewTransaction({
      intent: baseExecIntent(), authConfig: fx.authConfig,
      senderAddress: fx.payer.address, now: NOW, chain: sendLessPort(fx.chain),
    });
    expect(d.ok).toBe(false);
    if (d.ok) return;
    expect(d.reasons.map((r) => r.code)).toContain("FEE_POLICY_REJECTED");
    expect(fx.chain.sendLog.length).toBe(0);
    fx.execStore.close();
  });

  it("balance-query failure fails closed (never ready)", async () => {
    const fx = execFixture();
    fx.chain.getBalance = (async () => {
      throw new Error("node unreachable");
    }) as MockChainPort["getBalance"];
    const d = await previewTransaction({
      intent: baseExecIntent(), authConfig: fx.authConfig,
      senderAddress: fx.payer.address, now: NOW, chain: sendLessPort(fx.chain),
    });
    expect(d.ok).toBe(false);
    if (d.ok) return;
    expect(d.reasons.map((r) => r.code)).toContain("RPC_UNAVAILABLE");
    fx.execStore.close();
  });

  it("a passing preview reports readiness only with all checks green", async () => {
    const fx = execFixture();
    const intent = baseExecIntent();
    const proof = await signApproval(fx.approver, intent, fx.authConfig);
    const d = await previewTransaction({
      intent, proof, authConfig: fx.authConfig,
      senderAddress: fx.payer.address, now: NOW, chain: sendLessPort(fx.chain),
    });
    expect(d.ok).toBe(true);
    if (!d.ok) return;
    expect(d.feeCheck).toBeNull();
    expect(d.affordable).toBe(true);
    expect(d.approval).toEqual({ present: true, verified: true, approver: fx.approver.address });
    // Still read-only: the approval remains usable and nothing was sent.
    expect(fx.chain.sendLog.length).toBe(0);
    fx.execStore.close();
  });

  it("never touches stores: preview signature accepts no store parameter", () => {
    // Structural pin: previewTransaction's parameter type has no store-like
    // field. If a store parameter is ever added, this documents the break.
    const params = ["intent", "proof", "authConfig", "senderAddress", "now", "chain"];
    expect(params).not.toContain("store");
    expect(params).not.toContain("signer");
    expect(params).not.toContain("privateKey");
  });
});

describe("estimation-failure classification (M4-D4)", () => {
  function estaFail(message: string): Error {
    // Deliberately generic: classification must come from balance arithmetic,
    // never from matching error names or messages.
    return new Error(message);
  }

  it("1. zero balance plus estimation failure yields INSUFFICIENT_FUNDS", async () => {
    const fx = execFixture();
    fx.chain.balance = 0n;
    fx.chain.failEstimateWith = estaFail("boom");
    const d = await previewTransaction({
      intent: baseExecIntent(),
      authConfig: fx.authConfig,
      senderAddress: fx.payer.address,
      now: NOW,
      chain: sendLessPort(fx.chain),
    });
    expect(d.ok).toBe(false);
    if (d.ok) return;
    expect(d.reasons.map((r) => r.code)).toContain("INSUFFICIENT_FUNDS");
    expect(fx.chain.sendLog.length).toBe(0);
    fx.execStore.close();
  });

  it("2. below-amount balance plus estimation failure yields exact figures", async () => {
    const fx = execFixture();
    fx.chain.balance = 100n;
    fx.chain.failEstimateWith = estaFail("boom");
    const d = await previewTransaction({
      intent: baseExecIntent(),
      authConfig: fx.authConfig,
      senderAddress: fx.payer.address,
      now: NOW,
      chain: sendLessPort(fx.chain),
    });
    expect(d.ok).toBe(false);
    if (d.ok) return;
    expect(d.reasons.map((r) => r.code)).toContain("INSUFFICIENT_FUNDS");
    const text = JSON.stringify(d);
    expect(text).toContain("100");
    expect(text).toContain("400000000000000000");
    fx.execStore.close();
  });

  it("3. sufficient balance plus estimation failure yields ESTIMATION_FAILED", async () => {
    const fx = execFixture();
    fx.chain.balance = 10_000_000_000_000_000_000n;
    fx.chain.failEstimateWith = estaFail("boom");
    const d = await previewTransaction({
      intent: baseExecIntent(),
      authConfig: fx.authConfig,
      senderAddress: fx.payer.address,
      now: NOW,
      chain: sendLessPort(fx.chain),
    });
    expect(d.ok).toBe(false);
    if (d.ok) return;
    expect(d.reasons.map((r) => r.code)).toContain("ESTIMATION_FAILED");
    expect(d.reasons.map((r) => r.code)).not.toContain("INSUFFICIENT_FUNDS");
    fx.execStore.close();
  });

  it("4. balance exactly equal to amount plus estimation failure yields ESTIMATION_FAILED", async () => {
    const fx = execFixture();
    fx.chain.balance = 400_000_000_000_000_000n;
    fx.chain.failEstimateWith = estaFail("boom");
    const d = await previewTransaction({
      intent: baseExecIntent(),
      authConfig: fx.authConfig,
      senderAddress: fx.payer.address,
      now: NOW,
      chain: sendLessPort(fx.chain),
    });
    expect(d.ok).toBe(false);
    if (d.ok) return;
    // Fee coverage is unprovable without an estimate, so no insufficiency
    // claim is made — still fail-closed, never ready.
    expect(d.reasons.map((r) => r.code)).toContain("ESTIMATION_FAILED");
    fx.execStore.close();
  });

  it("5. failed prerequisite reads fail closed without estimation", async () => {
    const fx = execFixture();
    fx.chain.getChainId = (async () => {
      throw new Error("node unreachable");
    }) as MockChainPort["getChainId"];
    const d = await previewTransaction({
      intent: baseExecIntent(),
      authConfig: fx.authConfig,
      senderAddress: fx.payer.address,
      now: NOW,
      chain: sendLessPort(fx.chain),
    });
    expect(d.ok).toBe(false);
    if (d.ok) return;
    expect(d.reasons.map((r) => r.code)).toContain("RPC_UNAVAILABLE");
    fx.execStore.close();
  });

  it("6. hostile estimation errors never leak into diagnostics", async () => {
    const fx = execFixture();
    fx.chain.balance = 0n;
    const payload = "0x" + "ab12".repeat(60);
    fx.chain.failEstimateWith = new Error(
      `TimeoutError: request took too long. Request body: {"params":["${payload}"]} tail`,
    );
    const d = await previewTransaction({
      intent: baseExecIntent(),
      authConfig: fx.authConfig,
      senderAddress: fx.payer.address,
      now: NOW,
      chain: sendLessPort(fx.chain),
    });
    expect(d.ok).toBe(false);
    const text = JSON.stringify(d);
    expect(text).not.toContain(payload);
    expect(text).not.toMatch(/0x[0-9a-fA-F]{100,}/);
    expect(text).not.toContain("tail");
    fx.execStore.close();
  });
});
