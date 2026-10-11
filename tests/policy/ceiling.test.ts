/**
 * M4 adversarial ceiling tests (policy boundary). Exact bigint wei; no floats.
 * Proves the absolute 1 MON ceiling at configuration and payment level.
 */
import { describe, expect, it } from "vitest";
import { evaluatePolicy } from "../../src/policy/engine.js";
import {
  ABSOLUTE_MAX_PAYMENT_WEI,
  MONAD_TESTNET_CHAIN_ID,
  WEI_PER_MON,
  type PaymentIntent,
  type PolicyConfig,
  type PolicyContext,
  type RejectionCode,
} from "../../src/policy/types.js";
import { validateConfig } from "../../src/policy/validation.js";

const ADDR_A = "0x1111111111111111111111111111111111111111";
const NOW = 1_800_000_000;
const ONE_MON = WEI_PER_MON;

function config(over: Partial<PolicyConfig> = {}): PolicyConfig {
  return {
    approvedRecipients: [ADDR_A],
    maxPerPaymentWei: ONE_MON,
    allowedChainId: MONAD_TESTNET_CHAIN_ID,
    requireHumanApproval: false,
    ...over,
  };
}

function intent(over: Partial<PaymentIntent> = {}): PaymentIntent {
  return {
    requestId: "req-c1",
    recipient: ADDR_A,
    amountWei: 400_000_000_000_000_000n,
    asset: "MON",
    purpose: "ceiling probe",
    chainId: MONAD_TESTNET_CHAIN_ID,
    nonce: "nonce-c1",
    expiresAt: NOW + 3600,
    ...over,
  };
}

const ctx: PolicyContext = { now: NOW, humanApprovalVerified: false };

function codesOf(d: ReturnType<typeof evaluatePolicy>): RejectionCode[] {
  return d.allowed ? [] : d.reasons.map((r) => r.code);
}

describe("absolute 1 MON ceiling (policy boundary)", () => {
  it("ceiling constant equals exactly 1 MON in wei", () => {
    expect(ABSOLUTE_MAX_PAYMENT_WEI).toBe(1_000_000_000_000_000_000n);
    expect(ABSOLUTE_MAX_PAYMENT_WEI).toBe(ONE_MON);
  });

  it("1. configured limit of exactly 1 MON is accepted", () => {
    expect(validateConfig(config({ maxPerPaymentWei: ONE_MON }))).toEqual([]);
    const d = evaluatePolicy(intent({ amountWei: ONE_MON }), config(), ctx);
    expect(d.allowed).toBe(true);
  });

  it("2. configured limit below 1 MON is accepted", () => {
    expect(validateConfig(config({ maxPerPaymentWei: ONE_MON - 1n }))).toEqual([]);
    expect(validateConfig(config({ maxPerPaymentWei: 1n }))).toEqual([]);
  });

  it("3. configured limit above 1 MON is rejected", () => {
    for (const bad of [ONE_MON + 1n, 2n * ONE_MON, (1n << 256n) - 1n]) {
      const reasons = validateConfig(config({ maxPerPaymentWei: bad }));
      expect(reasons.map((r) => r.code)).toContain("INVALID_CONFIG");
      const d = evaluatePolicy(intent(), config({ maxPerPaymentWei: bad }), ctx);
      expect(d.allowed).toBe(false);
      expect(codesOf(d)).toContain("INVALID_CONFIG");
    }
  });

  it("4. payment above its configured policy limit is rejected", () => {
    const cfg = config({ maxPerPaymentWei: 100n });
    const d = evaluatePolicy(intent({ amountWei: 101n }), cfg, ctx);
    expect(d.allowed).toBe(false);
    expect(codesOf(d)).toContain("EXCEEDS_LIMIT");
  });

  it("5. payment above 1 MON is rejected (boundary ±1 wei)", () => {
    for (const amount of [ONE_MON + 1n, 4_000_000_000_000_000_000n]) {
      const d = evaluatePolicy(intent({ amountWei: amount }), config(), ctx);
      expect(d.allowed).toBe(false);
      expect(codesOf(d)).toContain("EXCEEDS_LIMIT");
    }
  });

  it("malformed limits fail closed (non-bigint, zero, negative)", () => {
    for (const bad of [0n, -1n, 1.5, "1000000000000000000", null, undefined, Number.NaN]) {
      const cfg = { ...config(), maxPerPaymentWei: bad } as unknown as PolicyConfig;
      expect(validateConfig(cfg).map((r) => r.code)).toContain("INVALID_CONFIG");
    }
  });
});
