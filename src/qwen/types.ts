/**
 * Qwen adapter types — Oracle69 AgentPay.
 *
 * All types are pure; no runtime I/O. The adapter validates every
 * model-generated field against the existing PaymentIntent type and
 * policy engine before any decision is made.
 */

/** Structured response from the Qwen API. */
export interface QwenResponse {
  success?: boolean;
  choices?: {
    index: number;
    message: {
      role: string;
      content: string;
    };
    finish_reason?: string;
  }[];
  error?: {
    message: string;
    type?: string;
    code?: string;
  };
  usage?: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}

/** Mapping from Qwen's JSON content to our PaymentIntent structure. */
export interface QwenIntentMapping {
  requestId: string;
  recipient: string;
  amountWei: bigint;
  asset: "MON";
  purpose: string;
  chainId: number;
  nonce: string;
  expiresAt: number;
}

/** Result of the full Qwen adapter pipeline. */
export type QwenAdapterResult =
  | {
      ok: true;
      policyDecision: import("../policy/types.js").PolicyDecision;
      approvalStatus: "NOT_REQUIRED" | "REQUIRES_APPROVAL" | "REQUIRED_UNVERIFIED";
      previewResult: import("../preview/index.js").PreviewResult;
      qwenIntent: QwenIntentMapping;
      isExecutable: false;
    }
  | {
      ok: false;
      policyDecision: import("../policy/types.js").PolicyDecision;
      approvalStatus: "REQUIRES_APPROVAL" | "REQUIRED_UNVERIFIED";
      rejectionReasons: import("../auth/types.js").AuthReason[];
      previewResult?: import("../preview/index.js").PreviewResult;
      qwenIntent?: QwenIntentMapping;
      isExecutable: false;
    };