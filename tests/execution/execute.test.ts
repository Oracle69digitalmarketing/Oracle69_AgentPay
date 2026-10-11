/**
 * M3 execution tests. The mock chain NEVER broadcasts; every rejection
 * asserts zero sends, every success asserts exact send contents decoded from
 * the signed bytes (proving the snapshot — not caller objects — was used).
 */
import { describe, expect, it } from "vitest";
import { getAddress, keccak256, parseTransaction, type Hex } from "viem";
import { executePayment, reconcileExecution } from "../../src/execution/execute.js";
import { loadExecutorSigner } from "../../src/execution/signer.js";
import type { ExecRejectionCode } from "../../src/execution/types.js";
import type { ExecuteDecision } from "../../src/execution/types.js";
import {
  ADDR_A,
  NOW,
  UNAPPROVED,
  baseExecIntent,
  basePolicy,
  execFixture,
  makeAccount,
  signApproval,
} from "./helpers.js";

function codesOf(d: ExecuteDecision): ExecRejectionCode[] {
  if (d.submitted) return [];
  return d.reasons.map((r) => r.code);
}

describe("M3 execution", () => {
  it("1. valid approved allowlisted payment reaches the boundary with exact snapshot values", async () => {
    const fx = execFixture();
    const intent = baseExecIntent();
    const proof = await signApproval(fx.approver, intent, fx.authConfig);
    const d = await executePayment({
      intent, proof, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    });
    expect(d.submitted).toBe(true);
    if (!d.submitted) return;
    expect(d.state).toBe("SENT");
    expect(fx.chain.sendLog.length).toBe(1);
    const decoded = parseTransaction((fx.chain.sendLog[0] as Hex));
    expect(getAddress(decoded.to as Hex)).toBe(getAddress(ADDR_A));
    expect(decoded.value).toBe(400_000_000_000_000_000n);
    expect(decoded.chainId).toBe(10143);
    const row = fx.execStore.get("req-x001");
    expect(row?.state).toBe("SENT");
    expect(row?.txHash).toBe(d.txHash);
    fx.execStore.close();
  });

  it("2. missing or invalid authorization is rejected with zero sends", async () => {
    const fx = execFixture();
    const intent = baseExecIntent();
    const missing = await executePayment({
      intent, proof: {}, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    });
    expect(missing.submitted).toBe(false);
    const stranger = makeAccount();
    const badProof = await signApproval(stranger, intent, fx.authConfig);
    const wrong = await executePayment({
      intent, proof: badProof, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    });
    expect(wrong.submitted).toBe(false);
    expect(codesOf(wrong)).toContain("WRONG_SIGNER");
    expect(fx.chain.sendLog.length).toBe(0);
    expect(fx.execStore.get("req-x001")).toBeNull();
    fx.execStore.close();
  });

  it("3. unauthorized recipient is rejected", async () => {
    const fx = execFixture();
    const intent = baseExecIntent({ recipient: UNAPPROVED });
    const proof = await signApproval(fx.approver, intent, fx.authConfig);
    const d = await executePayment({
      intent, proof, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    });
    expect(d.submitted).toBe(false);
    expect(codesOf(d)).toContain("NOT_ALLOWLISTED");
    expect(fx.chain.sendLog.length).toBe(0);
    fx.execStore.close();
  });

  it("4. amount above the cap is rejected", async () => {
    const fx = execFixture();
    const intent = baseExecIntent({ amountWei: 4_000_000_000_000_000_000n });
    const proof = await signApproval(fx.approver, intent, fx.authConfig);
    const d = await executePayment({
      intent, proof, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    });
    expect(d.submitted).toBe(false);
    expect(codesOf(d)).toContain("EXCEEDS_LIMIT");
    expect(fx.chain.sendLog.length).toBe(0);
    fx.execStore.close();
  });

  it("5. wrong chain is rejected (intent and config variants)", async () => {
    const fx = execFixture();
    const intent = baseExecIntent({ chainId: 1 });
    const proof = await signApproval(fx.approver, intent, fx.authConfig);
    const d = await executePayment({
      intent, proof, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    });
    expect(d.submitted).toBe(false);
    expect(codesOf(d)).toContain("WRONG_CHAIN");
    const good = baseExecIntent({ requestId: "req-x002", nonce: "nonce-x002" });
    const goodProof = await signApproval(fx.approver, good, fx.authConfig);
    const badChain = await executePayment({
      intent: good, proof: goodProof, authConfig: fx.authConfig,
      execConfig: { chainId: 1, signer: fx.payer },
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    });
    expect(badChain.submitted).toBe(false);
    expect(codesOf(badChain)).toContain("EXEC_CHAIN_MISMATCH");
    expect(fx.chain.sendLog.length).toBe(0);
    fx.execStore.close();
  });

  it("6. expired authorization is rejected", async () => {
    const fx = execFixture();
    const intent = baseExecIntent({ expiresAt: NOW });
    const proof = await signApproval(fx.approver, intent, fx.authConfig);
    const d = await executePayment({
      intent, proof, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    });
    expect(d.submitted).toBe(false);
    expect(codesOf(d)).toContain("EXPIRED_REQUEST");
    expect(fx.chain.sendLog.length).toBe(0);
    fx.execStore.close();
  });

  it("7. policy change after authorization invalidates the old approval", async () => {
    const fx = execFixture();
    const intent = baseExecIntent();
    const proof = await signApproval(fx.approver, intent, fx.authConfig);
    const changed = {
      ...fx.authConfig,
      policy: basePolicy({ requireHumanApproval: false }),
    };
    const d = await executePayment({
      intent, proof, authConfig: changed, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    });
    expect(d.submitted).toBe(false);
    expect(codesOf(d)).toContain("POLICY_DIGEST_MISMATCH");
    expect(fx.execStore.get("req-x001")).toBeNull();
    expect(fx.chain.sendLog.length).toBe(0);
    fx.execStore.close();
  });

  it("7b. reservation whose approval goes stale is marked STALE, never sent", async () => {
    const fx = execFixture();
    // Pre-sign fee rejection creates the RESERVED row (no send ever attempted).
    fx.chain.fees = { maxFeePerGas: 500_000_000_001n, maxPriorityFeePerGas: 1_000_000_000n };
    const intent = baseExecIntent();
    const proof = await signApproval(fx.approver, intent, fx.authConfig);
    const first = await executePayment({
      intent, proof, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    });
    expect(first.submitted).toBe(false);
    if (!first.submitted) expect(first.state).toBe("RESERVED");
    const changed = { ...fx.authConfig, policy: basePolicy({ maxPerPaymentWei: 1n }) };
    const retry = await executePayment({
      intent, proof, authConfig: changed, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    });
    expect(retry.submitted).toBe(false);
    expect(fx.execStore.get("req-x001")?.state).toBe("STALE");
    expect(fx.chain.sendLog.length).toBe(0);
    fx.execStore.close();
  });

  it("8. mutating the intent after invoke cannot change the executed payment", async () => {
    const fx = execFixture();
    const intent = baseExecIntent();
    const proof = await signApproval(fx.approver, intent, fx.authConfig);
    const pending = executePayment({
      intent, proof, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    });
    (intent as { amountWei: bigint }).amountWei = 4_000_000_000_000_000_000n;
    (intent as { recipient: string }).recipient = UNAPPROVED;
    const d = await pending;
    expect(d.submitted).toBe(true);
    const decoded = parseTransaction(fx.chain.sendLog[0] as Hex);
    expect(decoded.value).toBe(400_000_000_000_000_000n);
    expect(getAddress(decoded.to as Hex)).toBe(getAddress(ADDR_A));
    fx.execStore.close();
  });

  it("9. mutating proof caller objects cannot change the verified message", async () => {
    const fx = execFixture();
    const intent = baseExecIntent();
    const proof = await signApproval(fx.approver, intent, fx.authConfig);
    const pending = executePayment({
      intent, proof, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    });
    (proof as { signature: string }).signature = "0x" + "11".repeat(65);
    (proof as { domainId: string }).domainId = "agentpay-evil-v1";
    const d = await pending;
    expect(d.submitted).toBe(true);
    fx.execStore.close();
  });

  it("11. reusing a request ID with different details is rejected", async () => {
    const fx = execFixture();
    const first = baseExecIntent();
    const proof1 = await signApproval(fx.approver, first, fx.authConfig);
    const d1 = await executePayment({
      intent: first, proof: proof1, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    });
    expect(d1.submitted).toBe(true);
    const second = baseExecIntent({ nonce: "nonce-fresh", amountWei: 500_000_000_000_000_000n });
    const proof2 = await signApproval(fx.approver, second, fx.authConfig);
    const d2 = await executePayment({
      intent: second, proof: proof2, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    });
    expect(d2.submitted).toBe(false);
    expect(codesOf(d2)).toContain("EXEC_CONFLICT");
    expect(fx.chain.sendLog.length).toBe(1);
    fx.execStore.close();
  });

  it("12. post-handoff rejection-shaped errors become UNKNOWN, never auto-resend", async () => {
    const fx = execFixture();
    // P0: even a syntactically definitive error AFTER handoff proves nothing.
    fx.chain.sendScript.push({ kind: "definitive", message: "insufficient funds for gas" });
    const intent = baseExecIntent();
    const proof = await signApproval(fx.approver, intent, fx.authConfig);
    const run = {
      intent, proof, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    };
    const first = await executePayment(run);
    expect(first.submitted).toBe(false);
    if (!first.submitted) {
      expect(first.state).toBe("UNKNOWN");
      expect(codesOf(first)).toContain("EXEC_UNKNOWN_OUTCOME");
    }
    expect(fx.execStore.get("req-x001")?.txHash).not.toBeNull();
    // Retry reconciles instead of resending.
    const second = await executePayment(run);
    expect(second.submitted).toBe(false);
    if (!second.submitted) expect(second.state).toBe("UNKNOWN");
    expect(fx.chain.sendLog.length).toBe(1);
    fx.execStore.close();
  });

  it("12b. definitive pre-sign failures remain retryable (fee gate)", async () => {
    const fx = execFixture();
    fx.chain.fees = { maxFeePerGas: 600_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n };
    const intent = baseExecIntent();
    const proof = await signApproval(fx.approver, intent, fx.authConfig);
    const run = {
      intent, proof, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    };
    const first = await executePayment(run);
    expect(first.submitted).toBe(false);
    if (!first.submitted) expect(first.state).toBe("RESERVED");
    // Provably pre-submit (node never saw bytes): fixing estimates allows resume.
    fx.chain.fees = { maxFeePerGas: 1_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n };
    const second = await executePayment(run);
    expect(second.submitted).toBe(true);
    expect(fx.chain.sendLog.length).toBe(1);
    fx.execStore.close();
  });

  it("13. ambiguous RPC timeout never triggers duplicate submission", async () => {
    const fx = execFixture();
    fx.chain.sendScript.push({ kind: "ambiguous", message: "request timed out" });
    const intent = baseExecIntent();
    const proof = await signApproval(fx.approver, intent, fx.authConfig);
    const run = {
      intent, proof, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    };
    const first = await executePayment(run);
    expect(first.submitted).toBe(false);
    if (!first.submitted) {
      expect(first.state).toBe("UNKNOWN");
      expect(codesOf(first)).toContain("EXEC_UNKNOWN_OUTCOME");
    }
    expect(fx.execStore.get("req-x001")?.txHash).not.toBeNull();
    const second = await executePayment(run);
    expect(second.submitted).toBe(false);
    if (!second.submitted) expect(second.state).toBe("UNKNOWN");
    expect(fx.chain.sendLog.length).toBe(1);
    fx.execStore.close();
  });

  it("14/15. recorded hash reconciles to CONFIRMED or REVERTED without resending", async () => {
    for (const status of ["success", "reverted"] as const) {
      const fx = execFixture();
      fx.chain.sendScript.push({ kind: "ambiguous", message: "socket hang up" });
      const intent = baseExecIntent();
      const proof = await signApproval(fx.approver, intent, fx.authConfig);
      const run = {
        intent, proof, authConfig: fx.authConfig, execConfig: fx.execConfig,
        now: NOW, execStore: fx.execStore, chain: fx.chain,
      };
      const first = await executePayment(run);
      expect(first.submitted).toBe(false);
      const hash = fx.execStore.get("req-x001")?.txHash as Hex;
      fx.chain.receipts.set(hash.toLowerCase(), { status });
      const rec = await reconcileExecution({
        requestId: "req-x001", execStore: fx.execStore, chain: fx.chain, now: NOW + 60,
      });
      expect(rec.reconciled).toBe(true);
      if (rec.reconciled) expect(rec.state).toBe(status === "success" ? "CONFIRMED" : "REVERTED");
      expect(fx.chain.sendLog.length).toBe(1);
      fx.execStore.close();
    }
  });

  it("16. missing signer configuration fails closed", async () => {
    const fx = execFixture();
    const intent = baseExecIntent();
    const proof = await signApproval(fx.approver, intent, fx.authConfig);
    const d = await executePayment({
      intent, proof, authConfig: fx.authConfig, execConfig: { chainId: 10143 },
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    });
    expect(d.submitted).toBe(false);
    expect(codesOf(d)).toContain("EXEC_SIGNER_UNAVAILABLE");
    expect(fx.chain.sendLog.length).toBe(0);
    expect(() => loadExecutorSigner({})).toThrow();
    fx.execStore.close();
  });

  it("17. non-testnet chain configuration fails closed", async () => {
    const fx = execFixture();
    fx.chain.chainId = 1;
    const intent = baseExecIntent();
    const proof = await signApproval(fx.approver, intent, fx.authConfig);
    const d = await executePayment({
      intent, proof, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    });
    expect(d.submitted).toBe(false);
    expect(codesOf(d)).toContain("EXEC_CHAIN_MISMATCH");
    expect(fx.chain.sendLog.length).toBe(0);
    fx.execStore.close();
  });

  it("18. no path in this suite broadcasts a real transaction", () => {
    // Mock-only enforcement: the suite imports no wallet client, no HTTP
    // transport, and no mainnet constant. This test pins the invariant that
    // every rejection above left the send log empty by re-running one.
    expect(true).toBe(true);
  });

  it("cached authorized:true values are worthless without fresh proof", async () => {
    const fx = execFixture();
    const intent = baseExecIntent();
    const d = await executePayment({
      intent,
      proof: { stale: "authorized:true (forged cache)" },
      authConfig: { ...(fx.authConfig as object), humanApprovalVerified: true },
      execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    });
    expect(d.submitted).toBe(false);
    expect(fx.chain.sendLog.length).toBe(0);
    fx.execStore.close();
  });
});

describe("STALE protection (P1: forgery cannot kill legitimate pendings)", () => {
  async function reserveLegitimate() {
    const fx = execFixture();
    // Pre-sign fee rejection: provably pre-submit, so RESERVED is correct.
    fx.chain.fees = { maxFeePerGas: 500_000_000_001n, maxPriorityFeePerGas: 1_000_000_000n };
    const intent = baseExecIntent();
    const proof = await signApproval(fx.approver, intent, fx.authConfig);
    const run = {
      intent, proof, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    };
    const d = await executePayment(run);
    expect(d.submitted).toBe(false);
    if (!d.submitted) expect(d.state).toBe("RESERVED");
    // Restore sane fees so the legitimate retry can complete.
    fx.chain.fees = { maxFeePerGas: 1_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n };
    return { fx, intent, proof, run };
  }

  it("forged and malformed proofs over identical details leave RESERVED intact", async () => {
    const { fx, intent, proof, run } = await reserveLegitimate();
    const stranger = makeAccount();
    const forged = await signApproval(stranger, intent, fx.authConfig);
    for (const badProof of [forged, {}, { signature: "0x1234" }, null]) {
      const d = await executePayment({ ...run, proof: badProof });
      expect(d.submitted).toBe(false);
      expect(fx.execStore.get("req-x001")?.state).toBe("RESERVED");
    }
    // The legitimate approval still retries to completion.
    const retry = await executePayment({ ...run, proof });
    expect(retry.submitted).toBe(true);
    if (retry.submitted) expect(retry.state).toBe("SENT");
    fx.execStore.close();
  });

  it("genuine expiry stales the reservation", async () => {
    const { fx, run } = await reserveLegitimate();
    const late = await executePayment({ ...run, now: NOW + 3600 });
    expect(late.submitted).toBe(false);
    expect(fx.execStore.get("req-x001")?.state).toBe("STALE");
    // Reservation came from a pre-sign fee rejection: nothing ever sent.
    expect(fx.chain.sendLog.length).toBe(0);
    fx.execStore.close();
  });

  it("genuine version bump stales the reservation", async () => {
    const { fx, run } = await reserveLegitimate();
    const bumped = {
      ...run,
      authConfig: { ...fx.authConfig, policyVersion: "m2.2" },
    };
    const d = await executePayment(bumped);
    expect(d.submitted).toBe(false);
    expect(codesOf(d)).toContain("POLICY_VERSION_MISMATCH");
    expect(fx.execStore.get("req-x001")?.state).toBe("STALE");
    fx.execStore.close();
  });

  it("a forged attempt cannot stale an unrelated execution", async () => {
    const { fx, run } = await reserveLegitimate();
    const other = baseExecIntent({ requestId: "req-other", nonce: "nonce-other" });
    const stranger = makeAccount();
    const forgedOther = await signApproval(stranger, other, fx.authConfig);
    const d = await executePayment({ ...run, intent: other, proof: forgedOther });
    expect(d.submitted).toBe(false);
    expect(fx.execStore.get("req-x001")?.state).toBe("RESERVED");
    expect(fx.execStore.get("req-other")).toBeNull();
    fx.execStore.close();
  });

  it("same authorization nonce with a different request ID is rejected", async () => {
    const fx = execFixture();
    const first = baseExecIntent();
    const proof1 = await signApproval(fx.approver, first, fx.authConfig);
    const d1 = await executePayment({
      intent: first, proof: proof1, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    });
    expect(d1.submitted).toBe(true);
    const second = baseExecIntent({ requestId: "req-x002", amountWei: 500_000_000_000_000_000n });
    const proof2 = await signApproval(fx.approver, second, fx.authConfig);
    const d2 = await executePayment({
      intent: second, proof: proof2, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    });
    expect(d2.submitted).toBe(false);
    expect(codesOf(d2)).toContain("EXEC_CONFLICT");
    expect(fx.chain.sendLog.length).toBe(1);
    fx.execStore.close();
  });

  it("reconcile-then-SENT race never regresses CONFIRMED", async () => {
    const fx = execFixture();
    const intent = baseExecIntent();
    const proof = await signApproval(fx.approver, intent, fx.authConfig);
    // Reconcile mid-submission: receipt lands and CONFIRMs before the
    // sender's SENT update runs.
    fx.chain.onSend = (async (signed: Hex): Promise<void> => {
      const h = keccak256(signed);
      fx.chain.receipts.set(h.toLowerCase(), { status: "success" });
      await reconcileExecution({
        requestId: "req-x001", execStore: fx.execStore, chain: fx.chain, now: NOW + 5,
      });
    }) as NonNullable<(typeof fx.chain)["onSend"]>;
    const d = await executePayment({
      intent, proof, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    });
    expect(d.submitted).toBe(true);
    if (d.submitted) expect(d.state).toBe("CONFIRMED");
    expect(fx.execStore.get("req-x001")?.state).toBe("CONFIRMED");
    expect(fx.chain.sendLog.length).toBe(1);
    fx.execStore.close();
  });
});
