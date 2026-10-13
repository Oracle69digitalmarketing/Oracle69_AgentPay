/**
 * Qwen adapter tests — Oracle69 AgentPay.
 *
 * ALL TESTS USE globalThis.fetch MOCKING. No API key, no network, no Qwen service
 * required. Each test mocks fetch to control the Qwen response.
 *
 * Key design separation (per the integration plan):
 *   - proposal validity: does Qwen JSON map to valid PaymentIntent?
 *   - policy eligibility: does evaluatePolicy allow/reject?
 *   - authorization status: approvalStatus ("NOT_REQUIRED" | "REQUIRES_APPROVAL" | "REQUIRED_UNVERIFIED")
 *   - isExecutable: always false — never true in any test case.
 *   - previewResult: read-only preview, never implies authorization.
 */

import { describe, expect, it, vi } from "vitest";
import { processQwenIntent } from "../../src/qwen/adapter.js";
import { type ServerAuthConfig } from "../../src/auth/types.js";
import {
  MONAD_TESTNET_CHAIN_ID,
  WEI_PER_MON,
  ABSOLUTE_MAX_PAYMENT_WEI,
} from "../../src/policy/types.js";
import { evaluatePolicy } from "../../src/policy/engine.js";
import { baseIntent, basePolicy } from "../auth/helpers.js";

const NOW = 1_800_000_000;

// →≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺
// Helper: create a minimal ServerAuthConfig with given policy override
// →≺→→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺
function makeAuthConfig(requireHumanApproval: boolean = true): ServerAuthConfig {
  const defaultPolicy = {
    approvedRecipients: ["0x1111111111111111111111111111111111111111"],
    maxPerPaymentWei: WEI_PER_MON,
    allowedChainId: MONAD_TESTNET_CHAIN_ID,
    requireHumanApproval,
  };
  return {
    policy: defaultPolicy,
    approver: "0xE38e4f4a4554a3dcE15eA372B0c74DAAC3E83F55",
    domainId: "agentpay-demo-v1",
    policyVersion: "m2.1",
  };
}

// →≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺
// Helper: create a PaymentIntent (partial, for mock Qwen responses)
// →≺→→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺
function makeIntent(
  over: {
    requestId?: string;
    recipient?: string;
    amountWei?: bigint;
    purpose?: string;
    nonce?: string;
    expiresAt?: number;
  } = {},
): { requestId: string; recipient: string; amountWei: bigint; purpose: string; chainId: number; nonce: string; expiresAt: number } {
  const base: {
    requestId: string;
    recipient: string;
    amountWei: bigint;
    purpose: string;
    chainId: number;
    nonce: string;
    expiresAt: number;
  } = {
    requestId: "demo-req-1",
    recipient: "0x1111111111111111111111111111111111111111",
    amountWei: 400_000_000_000_000_000n, // 0.4 MON
    purpose: "demo payment",
    chainId: 10143,
    nonce: "demo-nonce-1",
    expiresAt: NOW + 3600,
  };
  if (over.requestId !== undefined) base.requestId = over.requestId;
  if (over.recipient !== undefined) base.recipient = over.recipient;
  if (over.amountWei !== undefined) base.amountWei = over.amountWei;
  if (over.purpose !== undefined) base.purpose = over.purpose;
  if (over.nonce !== undefined) base.nonce = over.nonce;
  if (over.expiresAt !== undefined) base.expiresAt = over.expiresAt;
  return base;
}

// →≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺
// Helper: stub chain port for preview
// →≺→→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺
function makeChainPort() {
  return {
    getChainId: async () => 10143,
    getSenderNonce: async () => 0,
    getBalance: async () => BIGINT_ONE_MON,
    estimateTransferGas: async () => 21_000n,
    estimateFees: async () => ({
      maxFeePerGas: 500_000_000_000n,
      maxPriorityFeePerGas: 1_000_000_000n,
    }),
    getReceipt: async () => null,
  };
}

// →≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺
// Constant: 1 MON in wei for test assertions
// →≺→→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺
const BIGINT_ONE_MON = 1_000_000_000_000_000_000n;

// →≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺
describe("Qwen adapter (globalThis.fetch mocked, no API key)", () => {

  // →≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺
  // 1. Valid model output → valid PaymentIntent, requireHumanApproval: false
  //    → policy allowed, approval NOT required, preview ok (if funds/fees pass)
  // →≺→→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺
  it("1. valid model output, requireHumanApproval: false → policy allowed, approval not required", async () => {
    // Mock fetch to return valid Qwen JSON
    const successContent = JSON.stringify({
      requestId: "demo-1",
      recipient: "0x1111111111111111111111111111111111111111",
      amountWei: "0.4",
      asset: "MON",
      purpose: "demo",
      chainId: 10143,
      nonce: "nonce-1",
      expiresAt: NOW + 3600,
    });
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => successContent,
    } as unknown as Response);

    const config = makeAuthConfig(false); // approval NOT required
    const chain = makeChainPort();
    const result = await processQwenIntent("Pay 0.001 MON to executor", NOW, config, chain);

    // Expectations
    expect(result.ok).toBe(true);
    if (result.ok) {
      // Policy allowed because requireHumanApproval === false
      expect(result.policyDecision.allowed).toBe(true);
      expect(result.policyDecision.requiresApproval).toBe(false);
      // Approval status: NOT_REQUIRED — model output is valid, approval not needed by config
      expect(result.approvalStatus).toBe("NOT_REQUIRED");
      // isExecutable is a compile-time guarantee: always false
      expect(result.isExecutable).toBe(false);
      // Preview should have passed read-only checks
      expect(result.previewResult.ok).toBe(true);
      if (result.previewResult.ok) {
        // Preview approval field: {present: false, verified: false, approver: null}
        // (since we pass proof: undefined, the "no proof" branch)
        expect(result.previewResult.approval).toEqual({
          present: false,
          verified: false,
          approver: null,
        });
      }
      // Qwen intent was successfully mapped
      expect(result.qwenIntent).toBeDefined();
      expect(result.qwenIntent!.amountWei).toBe(400_000_000_000_000_000n);
    }
  });

  // →≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺
  // 2. Valid model output, requireHumanApproval: true → MISSING_APPROVAL
  //    → policy not allowed (but other checks may pass), approvalStatus = REQUIRES_APPROVAL
  // →≺→→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺
  it("2. valid model output, requireHumanApproval: true → MISSING_APPROVAL, approvalStatus REQUIRES_APPROVAL", async () => {
    const successContent = JSON.stringify({
      requestId: "demo-2",
      recipient: "0x1111111111111111111111111111111111111111",
      amountWei: "0.001",
      asset: "MON",
      purpose: "demo",
      chainId: 10143,
      nonce: "nonce-2",
      expiresAt: NOW + 3600,
    });
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => successContent,
    } as unknown as Response);

    const config = makeAuthConfig(true); // approval REQUIRED
    const chain = makeChainPort();
    const result = await processQwenIntent("Pay 0.001 MON to executor", NOW, config, chain);

    // Expectations
    expect(result.ok).toBe(false);
    if (!result.ok) {
      // Policy not allowed because requireHumanApproval === true and model never provides signature
      expect(result.policyDecision.allowed).toBe(false);
      // The engine returned MISSING_APPROVAL as the only fatal reason (other checks passed)
      expect(
        result.policyDecision.reasons.some((r) => r.code === "MISSING_APPROVAL"),
      ).toBe(true);
      // Authorization status: approval is required but not yet verified by signature
      expect(result.approvalStatus).toBe("REQUIRES_APPROVAL");
      // isExecutable is always false — never true
      expect(result.isExecutable).toBe(false);
      // rejectionReasons should include MISSING_APPROVAL
      expect(result.rejectionReasons.some((r) => r.code === "MISSING_APPROVAL")).toBe(true);
    }
  });

  // →≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺
  // 3. Malformed JSON from Qwen → INVALID_REQUEST
  // →≺→→≺→≺→≺→→≺
  it("3. malformed JSON from Qwen → INVALID_REQUEST, approvalStatus REQUIRES_APPROVAL", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => {
        throw new Error("invalid json");
      },
    } as unknown as Response);

    const config = makeAuthConfig(); // requireHumanApproval: true (default)
    const chain = makeChainPort();
    const result = await processQwenIntent("pay", NOW, config, chain);

    // Expectations
    expect(result.ok).toBe(false);
    if (!result.ok) {
      // Failed to parse Qwen response
      expect(result.policyDecision.allowed).toBe(false);
      expect(result.policyDecision.reasons.some((r) => r.code === "INVALID_REQUEST")).toBe(true);
      // approvalStatus: since engine couldn't even evaluate (INVALID_REQUEST),
      // approval is effectively required (we can't approve what we can't validate)
      expect(result.approvalStatus).toBe("REQUIRES_APPROVAL");
      expect(result.isExecutable).toBe(false);
      expect(result.rejectionReasons.some((r) => r.code === "INVALID_REQUEST")).toBe(true);
    }
  });

  // →≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺
  // 4. Excessive amount (>1 MON) → EXCEEDS_LIMIT / INVALID_AMOUNT
  // →≺→→≺→≺→≺→→≺
  it("4. amount exceeding 1 MON ceiling → EXCEEDS_LIMIT or INVALID_AMOUNT", async () => {
    const successContent = JSON.stringify({
      requestId: "over-amount",
      recipient: "0x1111111111111111111111111111111111111111",
      amountWei: "999999999999999999999", // > 1 MON
      asset: "MON",
      purpose: "x",
      chainId: 10143,
      nonce: "n",
      expiresAt: NOW + 3600,
    });
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => successContent,
    } as unknown as Response);

    const config = makeAuthConfig();
    const chain = makeChainPort();
    const result = await processQwenIntent("pay", NOW, config, chain);

    // Expectations
    expect(result.ok).toBe(false);
    if (!result.ok) {
      // The mapQwenToIntent ceiling check or evaluatePolicy ceiling check should trigger
      expect(
        result.policyDecision.reasons.some(
          (r) => r.code === "EXCEEDS_LIMIT" || r.code === "INVALID_AMOUNT",
        ),
      ).toBe(true);
      expect(result.isExecutable).toBe(false);
      expect(result.approvalStatus).not.toBe("NOT_REQUIRED"); // must not be "not required" when amount is invalid
    }
  });

  // →≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺
  // 5. Unapproved recipient (not in allowlist) → NOT_ALLOWLISTED
  // →≺→→≺→≺→≺→→≺
  it("5. unapproved recipient → NOT_ALLOWLISTED, approvalStatus not NOT_REQUIRED", async () => {
    const successContent = JSON.stringify({
      requestId: "bad-recipient",
      recipient: "0x3333333333333333333333333333333333333333", // NOT in allowlist
      amountWei: "0.001",
      asset: "MON",
      purpose: "x",
      chainId: 10143,
      nonce: "n",
      expiresAt: NOW + 3600,
    });
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => successContent,
    } as unknown as Response);

    const config = makeAuthConfig(); // allowlist only has 0x111...
    const chain = makeChainPort();
    const result = await processQwenIntent("pay", NOW, config, chain);

    // Expectations
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(
        result.policyDecision.reasons.some((r) => r.code === "NOT_ALLOWLISTED"),
      ).toBe(true);
      // approvalStatus should NOT be "NOT_REQUIRED" — recipient not allowed
      expect(result.approvalStatus).not.toBe("NOT_REQUIRED");
      expect(result.isExecutable).toBe(false);
    }
  });

  // →≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺
  // 6. Wrong chain ID (not 10143) → WRONG_CHAIN
  // →≺→→≺→≺→≺→→≺
  it("6. wrong chain ID → WRONG_CHAIN, approvalStatus not NOT_REQUIRED", async () => {
    const successContent = JSON.stringify({
      requestId: "wrong-chain",
      recipient: "0x1111111111111111111111111111111111111111",
      amountWei: "0.001",
      asset: "MON",
      purpose: "x",
      chainId: 9999, // NOT Monad Testnet
      nonce: "n",
      expiresAt: NOW + 3600,
    });
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => successContent,
    } as unknown as Response);

    const config = makeAuthConfig();
    const chain = makeChainPort();
    const result = await processQwenIntent("pay", NOW, config, chain);

    // Expectations
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(
        result.policyDecision.reasons.some((r) => r.code === "WRONG_CHAIN"),
      ).toBe(true);
      expect(result.approvalStatus).not.toBe("NOT_REQUIRED");
      expect(result.isExecutable).toBe(false);
    }
  });

  // →≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺
  // 7. API failure / timeout → fail closed, INVALID_REQUEST
  // →≺→→≺→≺→≺→≺≺
  it("7. API failure / timeout → fail closed, INVALID_REQUEST", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: false,
      status: 500,
      statusText: "Internal Server Error",
    } as unknown as Response);

    const config = makeAuthConfig();
    const chain = makeChainPort();
    const result = await processQwenIntent("pay", NOW, config, chain);

    // Expectations
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.policyDecision.allowed).toBe(false);
      expect(result.policyDecision.reasons.some((r) => r.code === "INVALID_REQUEST")).toBe(true);
      expect(result.approvalStatus).not.toBe("NOT_REQUIRED");
      expect(result.isExecutable).toBe(false);
    }
  });

  // →≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺
  // 8. Core security: missing human authorization
  // →≺→→≺→≺→≺→≺
  it("8. core security: missing human authorization → MISSING_APPROVAL, approvalStatus REQUIRES_APPROVAL, isExecutable=false", async () => {
    const successContent = JSON.stringify({
      requestId: "no-auth",
      recipient: "0x1111111111111111111111111111111111111111",
      amountWei: "0.001",
      asset: "MON",
      purpose: "x",
      chainId: 10143,
      nonce: "n",
      expiresAt: NOW + 3600,
    });
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => successContent,
    } as unknown as Response);

    const config = makeAuthConfig(); // requireHumanApproval: true (default)
    const chain = makeChainPort();
    const result = await processQwenIntent("pay", NOW, config, chain);

    // CRITICAL ASSERTIONS — these must all pass:
    expect(result.ok).toBe(false);
    if (!result.ok) {
      // 1. Engine returned MISSING_APPROVAL
      expect(
        result.policyDecision.reasons.some((r) => r.code === "MISSING_APPROVAL"),
      ).toBe(true);
      // 2. approvalStatus is REQUIRES_APPROVAL — model output cannot bypass approval
      expect(result.approvalStatus).toBe("REQUIRES_APPROVAL");
      // 3. isExecutable is always false — never true in any test case
      expect(result.isExecutable).toBe(false);
      // 4. rejectionReasons includes MISSING_APPROVAL
      expect(result.rejectionReasons.some((r) => r.code === "MISSING_APPROVAL")).toBe(true);
      // 5. previewResult should NOT imply authorization
      // (preview goes through "no proof" branch: approval: {present: false, verified: false, approver: null})
      expect((result.previewResult as any).approval).toEqual({
        present: false,
        verified: false,
        approver: null,
      });
    }
  });

  // →≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺
  // 9. Malformed model output (missing fields) → INVALID_REQUEST
  // →≺→→≺→≺→≺→→≺
  it("9. malformed model output (missing fields) → INVALID_REQUEST, approvalStatus REQUIRES_APPROVAL", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => {
        return { choices: [{ message: { content: "ok" } }] };
      },
    } as unknown as Response);

    const config = makeAuthConfig();
    const chain = makeChainPort();
    const result = await processQwenIntent("pay", NOW, config, chain);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.policyDecision.allowed).toBe(false);
      expect(result.policyDecision.reasons.some((r) => r.code === "INVALID_REQUEST")).toBe(true);
      expect(result.approvalStatus).not.toBe("NOT_REQUIRED");
      expect(result.isExecutable).toBe(false);
      expect(result.rejectionReasons.some((r) => r.code === "INVALID_REQUEST")).toBe(true);
    }
  });

  // →≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺→≺
  // 10. Missing Qwen credentials (no API key or endpoint) → fail closed
  // →≺→→≺→≺→≺→→≺
  it("10. missing Qwen credentials → fail closed, INVALID_REQUEST", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => {
        return { error: { message: "API key missing" } };
      },
    } as unknown as Response);

    const config = makeAuthConfig();
    const chain = makeChainPort();
    const result = await processQwenIntent("pay", NOW, config, chain);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.policyDecision.allowed).toBe(false);
      expect(result.policyDecision.reasons.some((r) => r.code === "INVALID_REQUEST")).toBe(true);
      expect(result.approvalStatus).not.toBe("NOT_REQUIRED");
      expect(result.isExecutable).toBe(false);
      expect(result.rejectionReasons.some((r) => r.code === "INVALID_REQUEST")).toBe(true);
    }
  });
});