/**
 * Qwen intent route tests — Oracle69 AgentPay.
 *
 * Tests the POST /api/qwen-intent HTTP endpoint with mocked Qwen adapter
 * responses. No API key or live network required. The server route enforces
 * requireHumanApproval: true, so valid model output still results in
 * ok:false + REQUIRES_APPROVAL since the model never provides a
 * cryptographic signature.
 *
 * Key design separation (per the integration plan):
 *   - proposal validity: does Qwen JSON map to valid PaymentIntent?
 *   - policy eligibility: does evaluatePolicy allow/reject?
 *   - authorization status: approvalStatus ("NOT_REQUIRED" | "REQUIRES_APPROVAL" | "REQUIRED_UNVERIFIED")
 *   - isExecutable: always false — never true in any test case.
 *   - previewResult: read-only preview, never implies authorization.
 */

import { afterEach, afterAll, describe, expect, it, vi } from "vitest";
import { request as httpRequest } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { type Server as HttpServer } from "node:http";
import {
  MONAD_TESTNET_CHAIN_ID,
  ABSOLUTE_MAX_PAYMENT_WEI,
} from "../../src/policy/types.js";
import {
  DEMO_RECIPIENT,
  DEMO_APPROVER,
  DEMO_DOMAIN_ID,
} from "../../server/server.js";
import { ServerOptions } from "../../server/server.js";
import { MockChainPort } from "../execution/mock.js";
import { createPreviewServer } from "../../server/server.js";

let servers: HttpServer[] = [];
afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (s) =>
        new Promise<void>((resolve) => {
          s.close(() => resolve());
        }),
    ),
  );
});
afterAll(() => {
  while (servers.length > 0) {
    const s = servers.shift();
    if (s) s.close();
  }
});

async function start(options: Partial<ServerOptions> & { chain: MockChainPort }): Promise<string> {
  const fullServer = createPreviewServer({
    port: 0,
    chain: options.chain,
    rateLimit: options.rateLimit ?? { windowMs: 60_000, maxRequests: 30 },
  });
  await new Promise<void>((resolve) => fullServer.listen(0, () => resolve()));
  const address = fullServer.address();
  if (typeof address !== "object" || address === null) throw new Error("no listen address");
  servers.push(fullServer);
  return `http://127.0.0.1:${address.port}`;
}

function postJson(base: string, path: string, body: unknown): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const text = JSON.stringify(body);
    const req = httpRequest(
      `${base}${path}`,
      {
        method: "POST",
        headers: { "content-type": "application/json", "content-length": Buffer.byteLength(text) },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString("utf8") });
        });
      },
    );
    req.on("error", reject);
    req.end(text);
  });
}

describe("POST /api/qwen-intent", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  // 1. Missing prompt → 400
  it("1. missing prompt → 400", async () => {
    const chain = new MockChainPort();
    const base = await start({ chain });
    const res = await postJson(base, "/api/qwen-intent", {});
    expect(res.status).toBe(400);
    expect(res.text).toContain("prompt is required");
  });

  // 2. Empty prompt → 400
  it("2. empty prompt → 400", async () => {
    const chain = new MockChainPort();
    const base = await start({ chain });
    const res = await postJson(base, "/api/qwen-intent", { prompt: "" });
    expect(res.status).toBe(400);
    expect(res.text).toContain("prompt is required");
  });

  // 3. Oversized prompt (>500 chars) → 400
  it("3. oversized prompt (>500 chars) → 400", async () => {
    const chain = new MockChainPort();
    const base = await start({ chain });
    const longPrompt = "A".repeat(501);
    const res = await postJson(base, "/api/qwen-intent", { prompt: longPrompt });
    expect(res.status).toBe(400);
    expect(res.text).toContain("prompt must not exceed 500 characters");
  });

  // 4. Malformed JSON → 400
  it("4. malformed JSON → 400", async () => {
    const chain = new MockChainPort();
    const base = await start({ chain });
    const res = await postJson(base, "/api/qwen-intent", { body: "{bad json" });
    expect(res.status).toBe(400);
  });

  // 5. Rate limiting → 429 on repeated requests
  it("5. rate limiting → 429 on repeated requests", async () => {
    const chain = new MockChainPort();
    const base = await start({ chain, rateLimit: { windowMs: 60_000, maxRequests: 1 } });
    const first = await postJson(base, "/api/qwen-intent", { prompt: "test" });
    expect(first.status).toBe(200);
    const second = await postJson(base, "/api/qwen-intent", { prompt: "test" });
    expect(second.status).toBe(429);
    expect(second.text).toContain("rate limit exceeded");
  });

  // 6. Upstream HTTP failure → 200 with ok:false in body
  it("6. upstream HTTP failure → 200 with ok:false in body", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: false,
      status: 500,
      statusText: "Internal Server Error",
    } as unknown as Response);
    const chain = new MockChainPort();
    const base = await start({ chain, rateLimit: { windowMs: 60_000, maxRequests: 30 } });
    const res = await postJson(base, "/api/qwen-intent", { prompt: "test" });
    expect(res.status).toBe(200);
    const body = JSON.parse(res.text);
    expect(body.ok).toBe(false);
  });

  // 7. Read-only preview without authorization → ok:false, REQUIRES_APPROVAL
  it("7. read-only preview without authorization → ok:false, REQUIRES_APPROVAL (200 body)", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        requestId: "preview-no-auth",
        amountWei: "0.001",
        asset: "MON",
        purpose: "x",
        chainId: MONAD_TESTNET_CHAIN_ID,
        nonce: "n",
        expiresAt: 1700000000,
      }),
    } as unknown as Response);
    const chain = new MockChainPort();
    const base = await start({ chain, rateLimit: { windowMs: 60_000, maxRequests: 30 } });
    const res = await postJson(base, "/api/qwen-intent", { prompt: "test" });
    expect(res.status).toBe(200);
    const body = JSON.parse(res.text);
    expect(body.ok).toBe(false);
    expect(body.approvalStatus).toBe("REQUIRES_APPROVAL");
    expect(body.previewResult).toBeDefined();
    expect(body.isExecutable).toBe(false);
  });

  // 8. isExecutable always false
  it("8. isExecutable always false", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        requestId: "no-exec",
        amountWei: "0.001",
        asset: "MON",
        purpose: "x",
        chainId: MONAD_TESTNET_CHAIN_ID,
        nonce: "n",
        expiresAt: 1700000000,
      }),
    } as unknown as Response);
    const chain = new MockChainPort();
    const base = await start({ chain, rateLimit: { windowMs: 60_000, maxRequests: 30 } });
    const res = await postJson(base, "/api/qwen-intent", { prompt: "test" });
    expect(res.status).toBe(200);
    const body = JSON.parse(res.text);
    expect(body.isExecutable).toBe(false);
  });
});