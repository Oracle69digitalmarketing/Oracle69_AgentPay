/**
 * Fee-policy boundary tests. Units are wei, exact bigint. Caps live in
 * src/execution/types.ts (MAX_FEE_PER_GAS_WEI = 500 gwei, MAX_TX_GAS =
 * 100_000, total = 5e16 wei). Mock sends are counted: over-cap estimates
 * must never reach signing or submission.
 */
import { describe, expect, it } from "vitest";
import { executePayment } from "../../src/execution/execute.js";
import {
  MAX_FEE_PER_GAS_WEI,
  MAX_TOTAL_FEE_WEI,
  MAX_TX_GAS,
  type ExecRejectionCode,
} from "../../src/execution/types.js";
import { NOW, baseExecIntent, execFixture, signApproval } from "./helpers.js";

const GWEI = 1_000_000_000n;

describe("fee policy", () => {
  it("documents the cap arithmetic", () => {
    expect(MAX_FEE_PER_GAS_WEI).toBe(500n * GWEI);
    expect(MAX_TX_GAS).toBe(100_000n);
    expect(MAX_TOTAL_FEE_WEI).toBe(MAX_TX_GAS * MAX_FEE_PER_GAS_WEI);
  });

  async function runWithFees(fees: { maxFeePerGas: bigint; maxPriorityFeePerGas: bigint }, gas: bigint) {
    const fx = execFixture();
    fx.chain.fees = { ...fees };
    fx.chain.gas = gas;
    const intent = baseExecIntent();
    const proof = await signApproval(fx.approver, intent, fx.authConfig);
    const d = await executePayment({
      intent, proof, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    });
    return { fx, d };
  }

  function codesOf(d: { submitted: boolean; reasons?: Array<{ code: ExecRejectionCode }> }): ExecRejectionCode[] {
    return d.submitted ? [] : (d.reasons ?? []).map((r) => r.code);
  }

  it("fee just below, exactly at the cap proceeds; just above is rejected pre-sign", async () => {
    for (const [label, fee, ok] of [
      ["below", MAX_FEE_PER_GAS_WEI - 1n, true],
      ["exact", MAX_FEE_PER_GAS_WEI, true],
      ["above", MAX_FEE_PER_GAS_WEI + 1n, false],
    ] as const) {
      const { fx, d } = await runWithFees(
        { maxFeePerGas: fee, maxPriorityFeePerGas: 1n * GWEI },
        21_000n,
      );
      if (ok) {
        expect(d.submitted, label).toBe(true);
      } else {
        expect(d.submitted, label).toBe(false);
        expect(codesOf(d), label).toContain("EXEC_SEND_FAILED");
        expect(fx.chain.sendLog.length, label).toBe(0);
        expect(fx.execStore.get("req-x001")?.state, label).toBe("RESERVED");
      }
      fx.execStore.close();
    }
  });

  it("total fee exactly at cap proceeds (gas cap * fee cap)", async () => {
    const { fx, d } = await runWithFees(
      { maxFeePerGas: MAX_FEE_PER_GAS_WEI, maxPriorityFeePerGas: MAX_FEE_PER_GAS_WEI },
      MAX_TX_GAS,
    );
    expect(MAX_TX_GAS * MAX_FEE_PER_GAS_WEI).toBe(MAX_TOTAL_FEE_WEI);
    expect(d.submitted).toBe(true);
    fx.execStore.close();
  });

  it("excessive gas, zero/negative fees, and priority above max are rejected with zero sends", async () => {
    const bad: Array<[string, { maxFeePerGas: bigint; maxPriorityFeePerGas: bigint }, bigint]> = [
      ["gas over cap", { maxFeePerGas: 1n * GWEI, maxPriorityFeePerGas: 1n * GWEI }, MAX_TX_GAS + 1n],
      ["zero max fee", { maxFeePerGas: 0n, maxPriorityFeePerGas: 0n }, 21_000n],
      ["negative max fee", { maxFeePerGas: -1n, maxPriorityFeePerGas: 0n }, 21_000n],
      ["priority above max", { maxFeePerGas: 10n * GWEI, maxPriorityFeePerGas: 11n * GWEI }, 21_000n],
      ["zero gas", { maxFeePerGas: 1n * GWEI, maxPriorityFeePerGas: 1n * GWEI }, 0n],
    ];
    for (const [label, fees, gas] of bad) {
      const { fx, d } = await runWithFees(fees, gas);
      expect(d.submitted, label).toBe(false);
      expect(codesOf(d), label).toContain("EXEC_SEND_FAILED");
      expect(fx.chain.sendLog.length, label).toBe(0);
      fx.execStore.close();
    }
  });

  it("malformed RPC fee estimate fails closed without sending", async () => {
    const fx = execFixture();
    fx.chain.estimateFees = (async () => {
      throw new Error("fee oracle exploded");
    }) as MockEstimateFees;
    const intent = baseExecIntent();
    const proof = await signApproval(fx.approver, intent, fx.authConfig);
    const d = await executePayment({
      intent, proof, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    });
    expect(d.submitted).toBe(false);
    expect(fx.chain.sendLog.length).toBe(0);
    fx.execStore.close();
  });
});

type MockEstimateFees = () => Promise<{ maxFeePerGas: bigint; maxPriorityFeePerGas: bigint }>;
