/**
 * M4 adversarial ceiling tests (execution boundary). Proves executePayment
 * cannot bypass the absolute 1 MON ceiling through a malformed or
 * over-ceiling policy. Mock-only; asserts zero sends on every rejection.
 */
import { describe, expect, it } from "vitest";
import { executePayment } from "../../src/execution/execute.js";
import type { ExecRejectionCode, ExecuteDecision } from "../../src/execution/types.js";
import type { PolicyConfig } from "../../src/policy/types.js";
import {
  NOW,
  baseExecIntent,
  basePolicy,
  execFixture,
  signApproval,
} from "./helpers.js";

function codesOf(d: ExecuteDecision): ExecRejectionCode[] {
  return d.submitted ? [] : d.reasons.map((r) => r.code);
}

describe("absolute 1 MON ceiling (execution boundary)", () => {
  it("6a. over-ceiling configured limit is rejected with zero sends", async () => {
    const fx = execFixture();
    const badPolicy = basePolicy({ maxPerPaymentWei: 2_000_000_000_000_000_000n });
    const cfg = { ...fx.authConfig, policy: badPolicy };
    const intent = baseExecIntent({ amountWei: 1_500_000_000_000_000_000n });
    // Signed under the bad policy so the test isolates the ceiling gate
    // (not signature verification).
    const proof = await signApproval(fx.approver, intent, cfg);
    const d = await executePayment({
      intent, proof, authConfig: cfg, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    });
    expect(d.submitted).toBe(false);
    expect(codesOf(d)).toContain("INVALID_CONFIG");
    expect(fx.chain.sendLog.length).toBe(0);
    expect(fx.execStore.get("req-x001")).toBeNull();
    fx.execStore.close();
  });

  it("6b. malformed policy limits fail closed with zero sends", async () => {
    const fx = execFixture();
    const intent = baseExecIntent();
    const proof = await signApproval(fx.approver, intent, fx.authConfig);
    for (const badLimit of ["1000000000000000000", 1.5, null, undefined]) {
      const cfg = {
        ...fx.authConfig,
        policy: { ...fx.authConfig.policy, maxPerPaymentWei: badLimit },
      } as unknown as typeof fx.authConfig;
      const d = await executePayment({
        intent, proof, authConfig: cfg, execConfig: fx.execConfig,
        now: NOW, execStore: fx.execStore, chain: fx.chain,
      });
      expect(d.submitted).toBe(false);
      expect(codesOf(d)).toContain("INVALID_CONFIG");
    }
    expect(fx.chain.sendLog.length).toBe(0);
    fx.execStore.close();
  });

  it("6c. payment above 1 MON is rejected even at the ceiling limit", async () => {
    const fx = execFixture();
    const intent = baseExecIntent({ amountWei: 1_000_000_000_000_000_001n });
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

  it("exactly 1 MON at a 1 MON limit still executes", async () => {
    const fx = execFixture();
    const intent = baseExecIntent({ amountWei: 1_000_000_000_000_000_000n });
    const proof = await signApproval(fx.approver, intent, fx.authConfig);
    const d = await executePayment({
      intent, proof, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    });
    expect(d.submitted).toBe(true);
    expect(fx.chain.sendLog.length).toBe(1);
    fx.execStore.close();
  });

  it("per-payment limit below the ceiling is still enforced", async () => {
    const fx = execFixture();
    const tight = {
      ...fx.authConfig,
      policy: { ...fx.authConfig.policy, maxPerPaymentWei: 100n } as PolicyConfig,
    };
    const intent = baseExecIntent({ amountWei: 101n });
    const proof = await signApproval(fx.approver, intent, tight);
    const d = await executePayment({
      intent, proof, authConfig: tight, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    });
    expect(d.submitted).toBe(false);
    expect(codesOf(d)).toContain("EXCEEDS_LIMIT");
    expect(fx.chain.sendLog.length).toBe(0);
    fx.execStore.close();
  });
});
