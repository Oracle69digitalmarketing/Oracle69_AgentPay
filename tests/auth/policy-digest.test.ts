import { describe, expect, it } from "vitest";
import {
  canonicalAllowlist,
  computePolicyDigest,
} from "../../src/auth/policy-digest.js";
import { ADDR_A, ADDR_B, basePolicy } from "./helpers.js";

describe("policy digest", () => {
  it("is deterministic for identical policy", () => {
    expect(computePolicyDigest(basePolicy())).toBe(computePolicyDigest(basePolicy()));
  });

  it("is a 32-byte hex value", () => {
    const d = computePolicyDigest(basePolicy());
    expect(d).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("is invariant to allowlist order and casing", () => {
    const a = basePolicy({ approvedRecipients: [ADDR_A, ADDR_B] });
    const b = basePolicy({ approvedRecipients: [ADDR_B.toUpperCase(), ADDR_A.toUpperCase()] });
    expect(computePolicyDigest(a)).toBe(computePolicyDigest(b));
    expect(canonicalAllowlist([ADDR_B, ADDR_A])).toEqual(canonicalAllowlist([ADDR_A, ADDR_B]));
  });

  it("changes when any authorization-relevant field changes", () => {
    const base = computePolicyDigest(basePolicy());
    expect(computePolicyDigest(basePolicy({ maxPerPaymentWei: 1n }))).not.toBe(base);
    expect(computePolicyDigest(basePolicy({ allowedChainId: 1 }))).not.toBe(base);
    expect(computePolicyDigest(basePolicy({ requireHumanApproval: false }))).not.toBe(base);
    expect(
      computePolicyDigest(
        basePolicy({ approvedRecipients: [ADDR_A, "0x4444444444444444444444444444444444444444"] }),
      ),
    ).not.toBe(base);
    expect(computePolicyDigest(basePolicy({ approvedRecipients: [ADDR_A] }))).not.toBe(base);
  });

  it("canonical allowlist is sorted, lowercased, checksummed-source", () => {
    const canon = canonicalAllowlist([ADDR_B.toUpperCase(), ADDR_A]);
    expect(canon).toEqual([ADDR_A.toLowerCase(), ADDR_B.toLowerCase()]);
    expect(canon).toEqual([...canon].sort());
  });
});
