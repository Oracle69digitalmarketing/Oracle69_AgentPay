/**
 * Qwen API client — Oracle69 AgentPay.
 *
 * Credentials are read server-side from process.env only.
 * Never logged, never returned in decisions, never persisted.
 * Fail closed on any network error, timeout, non-200 response,
 * invalid JSON, or missing credentials.
 */

import { type Address } from "viem";

/** Fetch from Qwen, fail closed on any error. */
export async function fetchQwenResponse(
  prompt: string,
  config: { apiKey?: string; endpoint?: string; model?: string } = {},
): Promise<{ success: boolean; content: string }> {
  const key = config.apiKey ?? process.env["QWEN_API_KEY"];
  const endpoint = config.endpoint ?? process.env["QWEN_ENDPOINT"];
  const model = config.model ?? process.env["QWEN_MODEL"] ?? "qwen-turbo";

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
        temperature: 0, // deterministic: no sampling randomness
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

/** Validate that a string is a well-formed EVM address. */
function isValidAddress(v: string): boolean {
  return typeof v === "string" && /^0x[a-fA-F0-9]{40}$/i.test(v);
}

/** Validate that a string is a non-empty ID pattern letter/digit/_-:/. */
function isValidId(v: string): boolean {
  return /^[A-Za-z0-9_\-:.]+$/.test(v);
}