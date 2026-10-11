import { describe, expect, it } from "vitest";
import {
  normalizeAddress,
  parseDecimalMonToWei,
  toChecksumAddress,
  validateAmountWei,
  validateConfig,
  validateRecipient,
} from "../../src/policy/validation.js";
import { MAX_UINT256, WEI_PER_MON } from "../../src/policy/types.js";

describe("validation helpers", () => {
  it("parses whole MON strings to wei without floats", () => {
    expect(parseDecimalMonToWei("1")).toBe(WEI_PER_MON);
    expect(parseDecimalMonToWei("0.4")).toBe(400_000_000_000_000_000n);
    expect(parseDecimalMonToWei("0.000000000000000001")).toBe(1n);
  });

  it("rejects scientific notation, signs, excess precision, malformed", () => {
    for (const bad of ["1e18", "+1", "-1", "1.0000000000000000001", "abc", "", "1.", ".5", " 1", "1 ", "0", "0.0"]) {
      expect(() => parseDecimalMonToWei(bad)).toThrow();
    }
    expect(() => parseDecimalMonToWei(1 as unknown as string)).toThrow();
  });

  it("validates recipient addresses strictly", () => {
    expect(validateRecipient("0x1111111111111111111111111111111111111111")).toEqual([]);
    expect(validateRecipient("0x0000000000000000000000000000000000000000")[0]?.code).toBe("INVALID_ADDRESS");
    expect(validateRecipient("0x123")[0]?.code).toBe("INVALID_ADDRESS");
    expect(validateRecipient(123 as unknown as string)[0]?.code).toBe("INVALID_ADDRESS");
  });

  it("normalizes allowlist comparison case-insensitively", () => {
    const lower = "0x1111111111111111111111111111111111111111";
    expect(normalizeAddress(lower)).toBe(normalizeAddress(lower.toUpperCase()));
    expect(toChecksumAddress(lower)).not.toBeNull();
    expect(toChecksumAddress("bad")).toBeNull();
  });

  it("rejects non-bigint and out-of-range amounts", () => {
    expect(validateAmountWei(1 as unknown as bigint)[0]?.code).toBe("INVALID_AMOUNT");
    expect(validateAmountWei(0n)[0]?.code).toBe("INVALID_AMOUNT");
    expect(validateAmountWei(-5n)[0]?.code).toBe("INVALID_AMOUNT");
    expect(validateAmountWei(MAX_UINT256 + 1n)[0]?.code).toBe("INVALID_AMOUNT");
    expect(validateAmountWei(1n)).toEqual([]);
  });

  it("rejects contradictory config instead of correcting it", () => {
    const good = {
      approvedRecipients: ["0x1111111111111111111111111111111111111111"],
      maxPerPaymentWei: 1_000_000_000_000_000_000n,
      allowedChainId: 10143,
      requireHumanApproval: true,
    };
    expect(validateConfig(good)).toEqual([]);
    expect(validateConfig({ ...good, allowedChainId: 0 })[0]?.code).toBe("INVALID_CONFIG");
    expect(validateConfig({ ...good, requireHumanApproval: "yes" })[0]?.code).toBe("INVALID_CONFIG");
    expect(validateConfig(null)[0]?.code).toBe("INVALID_CONFIG");
  });
});
