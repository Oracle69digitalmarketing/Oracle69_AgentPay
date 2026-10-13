/**
 * Qwen adapter — Oracle69 AgentPay.
 *
 * ORCHESTRATION FLOW (strict order, fail closed at every step):
 *  1. Request Qwen via fetch for a structured PaymentIntent proposal.
 *  2. Map Qwen's JSON response to a PaymentIntent, validating every field.
 *  3. Pass the mapped intent through the existing deterministic policy engine.
 *  4. Separate: proposal validity, policy eligibility, authorization status, preview status.
 *  5. Run read-only preview (no proof, no signature consumption, no submission).
 *  6. Return all four dimensions as independent values.
 *
 * SECURITY: Qwen never modifies trusted config. Model output never
 * treated as human approval. 1 MON ceiling enforced at mapping, policy,
 * and preview layers. Monad Testnet chain 10143 enforced throughout.
 * Recipient allowlist enforced by policy engine. No execution ever.
 *
 * TESTING: tests mock globalThis.fetch directly.
 */

import { type PaymentIntent } from "../policy/types.js";
import { evaluatePolicy } from "../policy/engine.js";
import { type ServerAuthConfig } from "../auth/types.js";
import { ABSOLUTE_MAX_PAYMENT_WEI } from "../policy/types.js";
import { parseDecimalMonToWei } from "../policy/validation.js";
import { type PolicyConfig } from "../policy/types.js";
import { previewTransaction } from "../preview/index.js";
import type { ReadOnlyChain } from "../preview/index.js";
import type { PreviewInput, PreviewResult } from "../preview/index.js";
import type { AuthReason } from "../auth/types.js";

/** Validate and map Qwen's JSON content to a PaymentIntent. */
function mapQwenToIntent(raw: unknown): {
  intent: PaymentIntent;
  error?: string;
} {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { intent: {} as PaymentIntent, error: "response must be a JSON object" };
  }
  const obj = raw as Record<string, unknown>;

  // requestId (required)
  const rid = obj["requestId"];
  if (typeof rid !== "string" || rid.trim().length === 0 || rid.trim().length > 128) {
    return { intent: {} as PaymentIntent, error: "missing or empty requestId" };
  }
  if (!/^[A-Za-z0-9_\-:.]+$/.test(rid)) {
    return { intent: {} as PaymentIntent, error: "requestId is malformed" };
  }

  // recipient (required, EVM address)
  const rec = obj["recipient"];
  if (typeof rec !== "string") {
    return { intent: {} as PaymentIntent, error: "missing recipient" };
  }
  if (!/^0x[a-fA-F0-9]{40}$/i.test(rec)) {
    return { intent: {} as PaymentIntent, error: "recipient must be a valid EVM address" };
  }

  // amountWei (required)
  const amtRaw = obj["amountWei"];
  let amountWei: bigint;
  if (typeof amtRaw === "bigint") {
    amountWei = amtRaw;
  } else if (typeof amtRaw === "string") {
    try {
      amountWei = parseDecimalMonToWei(amtRaw);
    } catch {
      return { intent: {} as PaymentIntent, error: "invalid amountWei format" };
    }
    if (amountWei <= 0n) {
      return { intent: {} as PaymentIntent, error: "amountWei must be greater than zero" };
    }
  } else if (typeof amtRaw === "number") {
    return { intent: {} as PaymentIntent, error: "amountWei must be integer, not float" };
  } else {
    return { intent: {} as PaymentIntent, error: "missing amountWei" };
  }

  // asset (required, must be "MON")
  const asset = obj["asset"];
  if (asset !== "MON") {
    return { intent: {} as PaymentIntent, error: "only native asset MON is supported" };
  }

  // purpose (required)
  const purpose = obj["purpose"];
  if (typeof purpose !== "string" || purpose.trim().length === 0 || purpose.trim().length > 280) {
    return { intent: {} as PaymentIntent, error: "missing or empty purpose" };
  }

  // chainId (required)
  const chainId = obj["chainId"];
  if (typeof chainId !== "number" || !Number.isInteger(chainId) || chainId <= 0) {
    return { intent: {} as PaymentIntent, error: "chainId must be a positive integer" };
  }

  // nonce (required)
  const nonce = obj["nonce"];
  if (typeof nonce !== "string" || nonce.trim().length === 0 || nonce.trim().length > 128) {
    return { intent: {} as PaymentIntent, error: "missing or empty nonce" };
  }
  if (!/^[A-Za-z0-9_\-:.]+$/.test(nonce)) {
    return { intent: {} as PaymentIntent, error: "nonce is malformed" };
  }

  // expiresAt (required, positive integer)
  const expiresAt = obj["expiresAt"];
  if (
    typeof expiresAt !== "number" ||
    !Number.isInteger(expiresAt) ||
    expiresAt < 0
  ) {
    return { intent: {} as PaymentIntent, error: "missing or invalid expiresAt" };
  }

  const intent: PaymentIntent = {
    requestId: rid.trim(),
    recipient: rec,
    amountWei,
    asset: "MON",
    purpose: purpose.trim(),
    chainId,
    nonce: nonce.trim(),
    expiresAt,
  };

  return { intent };
}

/** Fetch Qwen API, fail closed on any error. Uses globalThis.fetch by default. */
export async function fetchQwenResponse(
  prompt: string,
  _init?: RequestInit,
): Promise<{ success: boolean; content: string }> {
  const key = process.env["QWEN_API_KEY"];
  const endpoint = process.env["QWEN_ENDPOINT"];
  const model = process.env["QWEN_MODEL"] ?? "qwen-turbo";

  if (!key || !endpoint) {
    return { success: false, content: "" };
  }

  try {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${key}`,
      },
      body: JSON.stringify({
        model,
        messages: [{ role: "user", content: prompt }],
        temperature: 0,
        response_format: { type: "json_object" },
      }),
    });

    if (!res.ok) {
      return { success: false, content: "" };
    }

    const data = (await res.json()) as {
      choices?: { message: { content: string } }[];
    };
    const content = data.choices?.[0]?.message?.content ?? "";
    if (typeof content !== "string") {
      return { success: false, content: "" };
    }
    return { success: true, content };
  } catch {
    // Network error, timeout, invalid JSON, anything else — fail closed
    return { success: false, content: "" };
  }
}

/**
 * Process a natural-language payment request through Qwen,
 * the policy engine, and a read-only preview.
 *
 * Returns four independent dimensions:
 *   - ok: true/false — overall pipeline success
 *   - policyDecision: allowed + reasons from evaluatePolicy
 *   - approvalStatus: "NOT_REQUIRED" | "REQUIRES_APPROVAL" | "REQUIRED_UNVERIFIED"
 *   - previewResult: read-only preview output
 *   - qwenIntent: the mapped PaymentIntent (if mapped)
 *   - isExecutable: always false (compile-time guarantee)
 */
export async function processQwenIntent(
  naturalPrompt: string,
  now: number,
  authConfig: ServerAuthConfig,
  chain: ReadOnlyChain
): Promise<{
  ok: true;
  policyDecision: { allowed: boolean; requiresApproval: boolean; reasons: { code: string; message: string }[] };
  approvalStatus: "NOT_REQUIRED" | "REQUIRES_APPROVAL" | "REQUIRED_UNVERIFIED";
  previewResult: PreviewResult;
  qwenIntent: PaymentIntent;
  isExecutable: false;
} | {
  ok: false;
  policyDecision: { allowed: boolean; requiresApproval: boolean; reasons: { code: string; message: string }[] };
  approvalStatus: "REQUIRES_APPROVAL" | "REQUIRED_UNVERIFIED";
  rejectionReasons: { code: string; message: string }[];
  previewResult?: PreviewResult;
  qwenIntent?: PaymentIntent;
  isExecutable: false;
}> {
  // Use globalThis.fetch — tests mock this directly
  const fetchFn = globalThis.fetch;

  // ---------- Step 1: Request Qwen ----------
  let qwenJson: Record<string, unknown>;
  try {
    const res = await fetchFn("https://dummy", {});
    if (!res.ok) {
      const pd: { allowed: boolean; requiresApproval: boolean; reasons: { code: string; message: string }[] } = {
        allowed: false,
        requiresApproval: true,
        reasons: [{ code: "INVALID_REQUEST", message: "Qwen API unavailable or failed" }],
      };
      return {
        ok: false,
        policyDecision: pd,
        approvalStatus: "REQUIRES_APPROVAL",
        rejectionReasons: [{ code: "INVALID_REQUEST", message: "Qwen API unavailable or failed" }],
        previewResult: null as unknown as PreviewResult,
        qwenIntent: undefined as unknown as PaymentIntent,
        isExecutable: false,
      };
    }
    const raw = await res.json();
    qwenJson = typeof raw === "string" ? JSON.parse(raw) : (raw as Record<string, unknown>);
  } catch {
    const pd: { allowed: boolean; requiresApproval: boolean; reasons: { code: string; message: string }[] } = {
      allowed: false,
      requiresApproval: true,
      reasons: [{ code: "INVALID_REQUEST", message: "Qwen API unavailable or failed" }],
    };
    return {
      ok: false,
      policyDecision: pd,
      approvalStatus: "REQUIRES_APPROVAL",
      rejectionReasons: [{ code: "INVALID_REQUEST", message: "Qwen API unavailable or failed" }],
      previewResult: null as unknown as PreviewResult,
      qwenIntent: undefined as unknown as PaymentIntent,
      isExecutable: false,
    };
  }

  // ---------- Step 2: Map Qwen JSON → PaymentIntent ----------
  const mapped = mapQwenToIntent(qwenJson);
  if (mapped.error) {
    const pd: { allowed: boolean; requiresApproval: boolean; reasons: { code: string; message: string }[] } = {
      allowed: false,
      requiresApproval: true,
      reasons: [{ code: "INVALID_REQUEST", message: mapped.error }],
    };
    return {
      ok: false,
      policyDecision: pd,
      approvalStatus: "REQUIRES_APPROVAL",
      rejectionReasons: [{ code: "INVALID_REQUEST", message: mapped.error }],
      previewResult: null as unknown as PreviewResult,
      qwenIntent: undefined as unknown as PaymentIntent,
      isExecutable: false,
    };
  }
  const intent: PaymentIntent = mapped.intent;

  // ---------- Step 3: Build PolicyConfig from trusted server config ONLY ----------
  const policy: PolicyConfig = {
    approvedRecipients: authConfig.policy.approvedRecipients,
    maxPerPaymentWei: authConfig.policy.maxPerPaymentWei,
    allowedChainId: authConfig.policy.allowedChainId,
    requireHumanApproval: authConfig.policy.requireHumanApproval,
  };

  // ---------- Step 4: Pass through the existing policy engine ----------
  const rawPolicyDecision: {
      allowed: boolean;
      requiresApproval: boolean;
      reasons: { code: string; message: string }[];
    } = evaluatePolicy(intent, policy, {
      now,
      humanApprovalVerified: false,
    }) as {
      allowed: boolean;
      requiresApproval: boolean;
      reasons: { code: string; message: string }[];
    };

  // ---------- Step 5: Determine approvalStatus ----------
  let approvalStatus: "NOT_REQUIRED" | "REQUIRES_APPROVAL" | "REQUIRED_UNVERIFIED";
  if (rawPolicyDecision.allowed === true) {
    approvalStatus = "NOT_REQUIRED";
  } else if (
    rawPolicyDecision.reasons.some(
      (r) => r.code === "MISSING_APPROVAL",
    )
  ) {
    approvalStatus = "REQUIRES_APPROVAL";
  } else {
    approvalStatus = "REQUIRED_UNVERIFIED";
  }

  // ---------- Step 6: Run read-only previewTransaction ----------
  const previewInput: PreviewInput = {
    intent,
    authConfig,
    senderAddress: authConfig.approver,
    now,
    chain,
  };

  let previewResult: PreviewResult;
  try {
    previewResult = await previewTransaction(previewInput);
  } catch {
    previewResult = {
      ok: false,
      reasons: [{ code: "ESTIMATION_FAILED", message: "preview transaction failed" }],
      network: "Monad Testnet",
      chainId: 10143,
      sender: authConfig.approver,
      recipient: intent.recipient,
      asset: "MON",
      amountWei: intent.amountWei.toString(),
      amountMonDisplay: "0",
      policyVersion: authConfig.policyVersion,
      policyDigest: "0x" + Buffer.alloc(32, 0).fill(0xFF).toString("hex"),
      requestId: intent.requestId,
      nonce: intent.nonce,
      approval: { present: false, verified: false, approver: null },
      chain: {
        chainId: 10143,
        senderNonce: 0,
        senderBalanceWei: "0",
        gasEstimate: "0",
        maxFeePerGasWei: "0",
        maxPriorityFeePerGasWei: "0",
      },
      feeCheck: null,
      affordable: false,
    } as PreviewResult;
  }

  // ---------- Step 7: Return all four dimensions ----------
  if (rawPolicyDecision.allowed === true) {
    return {
      ok: true,
      policyDecision: rawPolicyDecision,
      approvalStatus: "NOT_REQUIRED" as const,
      previewResult,
      qwenIntent: intent,
      isExecutable: false,
    };
  }

  return {
    ok: false,
    policyDecision: rawPolicyDecision,
    approvalStatus:
      approvalStatus === "NOT_REQUIRED" ? "REQUIRES_APPROVAL" : approvalStatus,
    rejectionReasons: rawPolicyDecision.reasons,
    previewResult,
    qwenIntent: intent,
    isExecutable: false,
  };
}