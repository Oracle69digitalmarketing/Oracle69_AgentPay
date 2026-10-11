import { describe, expect, it } from "vitest";
import { evaluatePolicy } from "../../src/policy/engine.js";
import {
  DEMO_MAX_PER_PAYMENT_WEI,
  MAX_UINT256,
  MONAD_TESTNET_CHAIN_ID,
  WEI_PER_MON,
  ZERO_ADDRESS,
  type PaymentIntent,
  type PolicyConfig,
  type PolicyContext,
  type RejectionCode,
} from "../../src/policy/types.js";

const ADDR_A = "0x1111111111111111111111111111111111111111";
const ADDR_B = "0x2222222222222222222222222222222222222222";
const UNAPPROVED = "0x3333333333333333333333333333333333333333";
const NOW = 1_800_000_000;
const ONE_MON = WEI_PER_MON;

function baseConfig(over: Partial<PolicyConfig> = {}): PolicyConfig {
  return {
    approvedRecipients: [ADDR_A, ADDR_B],
    maxPerPaymentWei: DEMO_MAX_PER_PAYMENT_WEI,
    allowedChainId: MONAD_TESTNET_CHAIN_ID,
    requireHumanApproval: true,
    ...over,
  };
}

function baseIntent(over: Partial<PaymentIntent> = {}): PaymentIntent {
  return {
    requestId: "req-001",
    recipient: ADDR_A,
    amountWei: 400_000_000_000_000_000n, // 0.4 MON
    asset: "MON",
    purpose: "demo payment",
    chainId: MONAD_TESTNET_CHAIN_ID,
    nonce: "nonce-001",
    expiresAt: NOW + 3600,
    ...over,
  };
}

function ctx(over: Partial<PolicyContext> = {}): PolicyContext {
  return { now: NOW, humanApprovalVerified: true, ...over };
}

function codesOf(d: ReturnType<typeof evaluatePolicy>): RejectionCode[] {
  if (d.allowed) return [];
  return d.reasons.map((r) => r.code);
}

describe("M1 policy engine", () => {
  // 1. Valid, approval not required
  it("1. allows approved recipient below limit when approval not required", () => {
    const d = evaluatePolicy(baseIntent(), baseConfig({ requireHumanApproval: false }), ctx({ humanApprovalVerified: false }));
    expect(d.allowed).toBe(true);
    if (d.allowed) {
      expect(d.requiresApproval).toBe(false);
      expect(d.chainId).toBe(MONAD_TESTNET_CHAIN_ID);
    }
  });

  // 2. Valid, approval required + verified
  it("2. allows approved recipient below limit when approval verified", () => {
    const d = evaluatePolicy(baseIntent(), baseConfig(), ctx({ humanApprovalVerified: true }));
    expect(d.allowed).toBe(true);
    if (d.allowed) {
      expect(d.requiresApproval).toBe(true);
      expect(d.approvalVerified).toBe(true);
    }
  });

  // 3. Missing approval
  it("3. rejects with MISSING_APPROVAL when approval required but not verified", () => {
    const d = evaluatePolicy(baseIntent(), baseConfig(), ctx({ humanApprovalVerified: false }));
    expect(d.allowed).toBe(false);
    expect(codesOf(d)).toContain("MISSING_APPROVAL");
  });

  // 4. Exceeds limit
  it("4. rejects approved recipient above limit (4 MON > 1 MON)", () => {
    const d = evaluatePolicy(
      baseIntent({ amountWei: 4_000_000_000_000_000_000n }),
      baseConfig(),
      ctx(),
    );
    expect(d.allowed).toBe(false);
    expect(codesOf(d)).toContain("EXCEEDS_LIMIT");
  });

  // 5. Unapproved recipient
  it("5. rejects unapproved recipient within limit", () => {
    const d = evaluatePolicy(baseIntent({ recipient: UNAPPROVED }), baseConfig(), ctx());
    expect(d.allowed).toBe(false);
    expect(codesOf(d)).toContain("NOT_ALLOWLISTED");
  });

  // 6. Malformed recipient
  it("6. rejects malformed recipient addresses", () => {
    for (const bad of ["not-an-address", "0x123", "0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", "", "0x"]) {
      const d = evaluatePolicy(baseIntent({ recipient: bad }), baseConfig(), ctx());
      expect(d.allowed).toBe(false);
      expect(codesOf(d)).toContain("INVALID_ADDRESS");
    }
  });

  // 7. Zero address
  it("7. rejects the zero address", () => {
    const d = evaluatePolicy(baseIntent({ recipient: ZERO_ADDRESS }), baseConfig(), ctx());
    expect(d.allowed).toBe(false);
    expect(codesOf(d)).toContain("INVALID_ADDRESS");
  });

  // 8. Zero amount
  it("8. rejects zero amount", () => {
    const d = evaluatePolicy(baseIntent({ amountWei: 0n }), baseConfig(), ctx());
    expect(d.allowed).toBe(false);
    expect(codesOf(d)).toContain("INVALID_AMOUNT");
  });

  // 9. Negative amount
  it("9. rejects negative amount", () => {
    const d = evaluatePolicy(baseIntent({ amountWei: -1n }), baseConfig(), ctx());
    expect(d.allowed).toBe(false);
    expect(codesOf(d)).toContain("INVALID_AMOUNT");
  });

  // 10. Above uint256
  it("10. rejects amount above uint256", () => {
    const d = evaluatePolicy(baseIntent({ amountWei: MAX_UINT256 + 1n }), baseConfig(), ctx());
    expect(d.allowed).toBe(false);
    expect(codesOf(d)).toContain("INVALID_AMOUNT");
  });

  // 11. Invalid runtime amount type (number/string/float instead of bigint)
  it("11. rejects non-bigint runtime amount types", () => {
    for (const bad of [0.4, 1, "1000000000000000000", null, undefined, Number.NaN]) {
      const intent = { ...baseIntent(), amountWei: bad } as unknown as PaymentIntent;
      const d = evaluatePolicy(intent, baseConfig(), ctx());
      expect(d.allowed).toBe(false);
      expect(codesOf(d)).toContain("INVALID_AMOUNT");
    }
  });

  // 12. Unsupported asset
  it("12. rejects unsupported asset", () => {
    const intent = { ...baseIntent(), asset: "ETH" } as unknown as PaymentIntent;
    const d = evaluatePolicy(intent, baseConfig(), ctx());
    expect(d.allowed).toBe(false);
    expect(codesOf(d)).toContain("INVALID_ASSET");
  });

  // 13. Wrong chain
  it("13. rejects wrong chain id", () => {
    const d = evaluatePolicy(baseIntent({ chainId: 1 }), baseConfig(), ctx());
    expect(d.allowed).toBe(false);
    expect(codesOf(d)).toContain("WRONG_CHAIN");
  });

  // 14. Expired
  it("14. rejects expired request", () => {
    const d = evaluatePolicy(baseIntent({ expiresAt: NOW - 1 }), baseConfig(), ctx());
    expect(d.allowed).toBe(false);
    expect(codesOf(d)).toContain("EXPIRED_REQUEST");
  });

  // 15. Expiry exactly equal to now → expired (documented boundary)
  it("15. rejects request expiring exactly at evaluation time (now >= expiresAt)", () => {
    const d = evaluatePolicy(baseIntent({ expiresAt: NOW }), baseConfig(), ctx({ now: NOW }));
    expect(d.allowed).toBe(false);
    expect(codesOf(d)).toContain("EXPIRED_REQUEST");
  });

  it("15b. allows request expiring one second after now", () => {
    const d = evaluatePolicy(baseIntent({ expiresAt: NOW + 1 }), baseConfig(), ctx({ now: NOW }));
    expect(d.allowed).toBe(true);
  });

  // 16. Missing request id
  it("16. rejects missing/empty requestId", () => {
    for (const bad of ["", "   ", undefined]) {
      const intent = { ...baseIntent(), requestId: bad } as unknown as PaymentIntent;
      const d = evaluatePolicy(intent, baseConfig(), ctx());
      expect(d.allowed).toBe(false);
      expect(codesOf(d)).toContain("INVALID_REQUEST");
    }
    const { requestId: _drop, ...rest } = baseIntent();
    void _drop;
    const d = evaluatePolicy(rest, baseConfig(), ctx());
    expect(d.allowed).toBe(false);
    expect(codesOf(d)).toContain("INVALID_REQUEST");
  });

  // 17. Invalid nonce
  it("17. rejects invalid nonce", () => {
    for (const bad of ["", 123, null, undefined]) {
      const intent = { ...baseIntent(), nonce: bad } as unknown as PaymentIntent;
      const d = evaluatePolicy(intent, baseConfig(), ctx());
      expect(d.allowed).toBe(false);
      expect(codesOf(d)).toContain("INVALID_REQUEST");
    }
  });

  // 18. Invalid policy limit
  it("18. rejects invalid policy limits (fail closed on config)", () => {
    for (const bad of [0n, -1n, MAX_UINT256 + 1n, 1.5, "1000", undefined]) {
      const cfg = { ...baseConfig(), maxPerPaymentWei: bad } as unknown as PolicyConfig;
      const d = evaluatePolicy(baseIntent(), cfg, ctx());
      expect(d.allowed).toBe(false);
      expect(codesOf(d)).toContain("INVALID_CONFIG");
    }
  });

  // 19. Invalid allowlist
  it("19. rejects invalid allowlist configuration", () => {
    const cases: unknown[] = [
      [],
      ["not-an-address"],
      [ZERO_ADDRESS],
      [ADDR_A, ADDR_A.toLowerCase()], // duplicate
      "0x123",
      undefined,
    ];
    for (const bad of cases) {
      const cfg = { ...baseConfig(), approvedRecipients: bad } as unknown as PolicyConfig;
      const d = evaluatePolicy(baseIntent(), cfg, ctx());
      expect(d.allowed).toBe(false);
      expect(codesOf(d)).toContain("INVALID_CONFIG");
    }
  });

  // Boundary: exactly 1 MON / ±1 wei
  it("boundary: exactly 1 MON is allowed", () => {
    const d = evaluatePolicy(baseIntent({ amountWei: ONE_MON }), baseConfig(), ctx());
    expect(d.allowed).toBe(true);
  });

  it("boundary: one wei below 1 MON is allowed", () => {
    const d = evaluatePolicy(baseIntent({ amountWei: ONE_MON - 1n }), baseConfig(), ctx());
    expect(d.allowed).toBe(true);
  });

  it("boundary: one wei above 1 MON is rejected", () => {
    const d = evaluatePolicy(baseIntent({ amountWei: ONE_MON + 1n }), baseConfig(), ctx());
    expect(d.allowed).toBe(false);
    expect(codesOf(d)).toContain("EXCEEDS_LIMIT");
  });

  // 20. Deterministic reason ordering under simultaneous violations
  it("20. returns deterministic reason ordering for simultaneous violations", () => {
    const badIntent = {
      requestId: "",
      recipient: "bad-address",
      amountWei: 4_000_000_000_000_000_000n,
      asset: "ETH",
      purpose: "",
      chainId: 1,
      nonce: "",
      expiresAt: NOW - 100,
    } as unknown as PaymentIntent;
    const badCtx = ctx({ humanApprovalVerified: false });
    const a = evaluatePolicy(badIntent, baseConfig(), badCtx);
    expect(a.allowed).toBe(false);
    if (!a.allowed) {
      const codes = a.reasons.map((r) => r.code);
      // Must be sorted by documented REASON_ORDER
      const order = [
        "INVALID_CONFIG",
        "INVALID_REQUEST",
        "INVALID_ASSET",
        "WRONG_CHAIN",
        "INVALID_ADDRESS",
        "INVALID_AMOUNT",
        "NOT_ALLOWLISTED",
        "EXCEEDS_LIMIT",
        "EXPIRED_REQUEST",
        "MISSING_APPROVAL",
      ];
      const idx = (c: string): number => order.indexOf(c);
      for (let i = 1; i < codes.length; i++) {
        expect(idx(codes[i] as string)).toBeGreaterThanOrEqual(idx(codes[i - 1] as string));
      }
      // Key violations all present
      for (const expected of ["INVALID_REQUEST", "INVALID_ASSET", "WRONG_CHAIN", "INVALID_ADDRESS", "EXCEEDS_LIMIT", "EXPIRED_REQUEST", "MISSING_APPROVAL"] as const) {
        expect(codes).toContain(expected);
      }
      // Insertion-order independence: same fields, different key order → identical result
      const reordered = {
        expiresAt: NOW - 100,
        nonce: "",
        chainId: 1,
        purpose: "",
        asset: "ETH",
        amountWei: 4_000_000_000_000_000_000n,
        recipient: "bad-address",
        requestId: "",
      } as unknown as PaymentIntent;
      const b = evaluatePolicy(reordered, baseConfig(), badCtx);
      expect(JSON.stringify(b)).toBe(JSON.stringify(a));
    }
  });

  // 21. Same input → same output
  it("21. is deterministic across repeated evaluations", () => {
    const intent = baseIntent();
    const cfg = baseConfig();
    const c = ctx();
    const a = evaluatePolicy(intent, cfg, c);
    const b = evaluatePolicy({ ...intent }, { ...cfg, approvedRecipients: [...cfg.approvedRecipients] }, { ...c });
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });

  // 22. Approval never overrides policy violations
  it("22. verified approval never overrides amount/recipient/chain/expiry violations", () => {
    const approved = ctx({ humanApprovalVerified: true });
    const violations: Array<Partial<PaymentIntent>> = [
      { amountWei: 4_000_000_000_000_000_000n },
      { recipient: UNAPPROVED },
      { recipient: "0xbad" },
      { chainId: 1 },
      { expiresAt: NOW - 5 },
      { amountWei: 0n },
    ];
    for (const v of violations) {
      const d = evaluatePolicy(baseIntent(v), baseConfig(), approved);
      expect(d.allowed).toBe(false);
      expect(codesOf(d)).not.toContain("MISSING_APPROVAL");
      expect(codesOf(d).length).toBeGreaterThan(0);
    }
  });

  it("allowlist comparison is case-insensitive (checksummed vs lowercase)", () => {
    const d = evaluatePolicy(
      baseIntent({ recipient: ADDR_A.toLowerCase() }),
      baseConfig(),
      ctx(),
    );
    expect(d.allowed).toBe(true);
  });

  it("malformed intent root fails closed", () => {
    for (const bad of [null, undefined, 42, "x", []]) {
      const d = evaluatePolicy(bad, baseConfig(), ctx());
      expect(d.allowed).toBe(false);
      expect(codesOf(d)).toContain("INVALID_REQUEST");
    }
  });
});
