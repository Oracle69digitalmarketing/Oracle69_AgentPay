/**
 * Web demo server tests. Every HTTP test uses an injected mock chain port;
 * no test contacts a live network. A full send-capable mock is handed to
 * the server to prove the HTTP path never submits, even when it could.
 */
import { readFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import type { Address } from "viem";
import {
  createPreviewServer,
  DEMO_APPROVER,
  DEMO_RECIPIENT,
  type ServerOptions,
} from "../../server/server.js";
import { MockChainPort } from "../execution/mock.js";
import { makeAccount, signApproval, NOW, basePolicy } from "../auth/helpers.js";
import { CURRENT_POLICY_VERSION } from "../../src/auth/types.js";
import type { Server as HttpServer } from "node:http";

const ADDR_A = "0x1111111111111111111111111111111111111111";

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

async function start(options: Partial<ServerOptions> & { chain: MockChainPort }): Promise<string> {
  const server = createPreviewServer({
    port: 0,
    rateLimit: { windowMs: 60_000, maxRequests: 1000 },
    ...options,
  });
  await new Promise<void>((resolve) => server.listen(0, () => resolve()));
  servers.push(server);
  const address = server.address();
  if (typeof address !== "object" || address === null) throw new Error("no listen address");
  return `http://127.0.0.1:${address.port}`;
}

interface HttpResult {
  status: number;
  headers: Record<string, string | undefined>;
  text: string;
}

function postJson(base: string, path: string, body: unknown, raw?: string): Promise<HttpResult> {
  return new Promise((resolve, reject) => {
    const text = raw ?? JSON.stringify(body);
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
          const headers: Record<string, string | undefined> = {};
          for (const [k, v] of Object.entries(res.headers)) headers[k] = Array.isArray(v) ? v.join(",") : v;
          resolve({ status: res.statusCode ?? 0, headers, text: Buffer.concat(chunks).toString("utf8") });
        });
      },
    );
    req.on("error", reject);
    req.end(text);
  });
}

function get(base: string, path: string): Promise<HttpResult> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      `${base}${path}`,
      { method: "GET" },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          const headers: Record<string, string | undefined> = {};
          for (const [k, v] of Object.entries(res.headers)) headers[k] = Array.isArray(v) ? v.join(",") : v;
          resolve({ status: res.statusCode ?? 0, headers, text: Buffer.concat(chunks).toString("utf8") });
        });
      },
    );
    req.on("error", reject);
    req.end();
  });
}

function method(
  base: string,
  path: string,
  verb: string,
): Promise<HttpResult> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(`${base}${path}`, { method: verb }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: {}, text: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    req.end();
  });
}

describe("demo server import graph (no execution capability)", () => {
  it("server imports exclude execution, signer, stores, and submission", () => {
    const here = dirname(fileURLToPath(import.meta.url));
    const source = readFileSync(join(here, "..", "..", "server", "server.ts"), "utf8");
    const specifiers = [...source.matchAll(/from\s+["']([^"']+)["']/g)].map((m) => m[1] as string);
    expect(specifiers.length).toBeGreaterThan(0);
    for (const spec of specifiers) {
      // execution/types.js holds chain IDs, RPC allowlist, fee caps
      // (constants only). Every other execution/ module is forbidden.
      if (spec === "../src/execution/types.js") continue;
      expect(spec, `forbidden import ${spec}`).not.toMatch(/execution\//);
      expect(spec, `forbidden import ${spec}`).not.toMatch(/auth\/verify/);
      expect(spec, `forbidden import ${spec}`).not.toMatch(/auth\/store/);
      expect(spec, `forbidden import ${spec}`).not.toMatch(/policy\/engine/);
    }
    const noBlocks = source.replace(/\/\*[\s\S]*?\*\//g, "");
    const code = noBlocks
      .split("\n")
      .filter((line) => !line.trimStart().startsWith("//"))
      .join("\n");
    for (const token of [
      "executePayment",
      "sendRawTransaction",
      "loadExecutorSigner",
      "createSignerFromPrivateKey",
      "ExecutionStore",
      "SqliteReplayStore",
      "MemoryReplayStore",
      "EXECUTOR_PRIVATE_KEY",
      "signTransfer",
      "privateKey",
      "createWalletClient",
      "better-sqlite3",
    ]) {
      expect(code, `forbidden token ${token}`).not.toContain(token);
    }
  });
});

describe("demo server HTTP behavior (mock chain only)", () => {
  it("GET / serves the interface with Testnet and no-execution statements", async () => {
    const base = await start({ chain: new MockChainPort() });
    const res = await get(base, "/");
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toContain("text/html");
    expect(res.text).toContain("Oracle69 AgentPay");
    expect(res.text).toContain("Monad Testnet");
    expect(res.text).toContain("AI proposes. Policy governs. Humans authorize. Blockchain settles.");
    expect(res.text).toContain("does not execute payments");
    expect(res.text).not.toContain("executePayment");
  });

  it("POST /api/preview with valid input returns a labeled preview, zero sends", async () => {
    const chain = new MockChainPort();
    const base = await start({ chain });
    const res = await postJson(base, "/api/preview", { amountMon: "0.001" });
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toContain("application/json");
    const body = JSON.parse(res.text) as { banner: string; preview: { ok: boolean; network: string; chainId: number } };
    expect(body.banner).toContain("NOT AUTHORIZATION TO EXECUTE");
    expect(body.preview.ok).toBe(true);
    expect(body.preview.network).toBe("Monad Testnet");
    expect(body.preview.chainId).toBe(10143);
    expect(chain.sendLog.length).toBe(0);
  });

  it("rejects invalid amounts and over-ceiling amounts", async () => {
    const base = await start({ chain: new MockChainPort() });
    for (const bad of ["abc", "-1", "", "1.0000000000000000001", "2", "1.000000000000000001"]) {
      const res = await postJson(base, "/api/preview", { amountMon: bad });
      expect(res.status, bad).toBe(400);
    }
    const missing = await postJson(base, "/api/preview", {});
    expect(missing.status).toBe(400);
  });

  it("ignores no caller recipient: unknown fields rejected, fixed allowlist enforced", async () => {
    const base = await start({ chain: new MockChainPort() });
    const res = await postJson(base, "/api/preview", { amountMon: "0.001", recipient: ADDR_A });
    expect(res.status).toBe(400);
    expect(res.text).toContain("unexpected field");
  });

  it("rejects malformed and oversized JSON", async () => {
    const base = await start({ chain: new MockChainPort() });
    const malformed = await postJson(base, "/api/preview", undefined, "{not json");
    expect(malformed.status).toBe(400);
    const big = await postJson(base, "/api/preview", undefined, `{"amountMon":"${"9".repeat(17 * 1024)}"}`);
    expect(big.status).toBe(413);
  });

  it("rejects unsupported methods and routes", async () => {
    const base = await start({ chain: new MockChainPort() });
    expect((await method(base, "/api/preview", "GET")).status).toBe(405);
    expect((await method(base, "/api/preview", "DELETE")).status).toBe(405);
    expect((await method(base, "/nope", "POST")).status).toBe(404);
    expect((await get(base, "/nope")).status).toBe(404);
  });

  it("rate-limits repeated requests", async () => {
    const base = await start({ chain: new MockChainPort(), rateLimit: { windowMs: 60_000, maxRequests: 2 } });
    expect((await postJson(base, "/api/preview", { amountMon: "0.001" })).status).toBe(200);
    expect((await postJson(base, "/api/preview", { amountMon: "0.001" })).status).toBe(200);
    const limited = await postJson(base, "/api/preview", { amountMon: "0.001" });
    expect(limited.status).toBe(429);
  });

  it("returns fail-closed preview on RPC failure without leaking internals", async () => {
    const chain = new MockChainPort();
    chain.getChainId = (async () => {
      throw new Error("connection reset by peer: dial tcp 10.0.0.9:443");
    }) as MockChainPort["getChainId"];
    const base = await start({ chain });
    const res = await postJson(base, "/api/preview", { amountMon: "0.001" });
    expect(res.status).toBe(200);
    const body = JSON.parse(res.text) as { preview: { ok: boolean } };
    expect(body.preview.ok).toBe(false);
    expect(res.text).not.toContain("10.0.0.9");
    expect(res.text).not.toContain("stack");
    expect(chain.sendLog.length).toBe(0);
  });

  it("accepts a well-formed proof object and rejects malformed proofs", async () => {
    const chain = new MockChainPort();
    const base = await start({ chain });
    const asString = await postJson(base, "/api/preview", { amountMon: "0.001", proof: "0xdead" });
    expect(asString.status).toBe(400);
    const stranger = makeAccount();
    const proof = await signApproval(
      stranger,
      {
        requestId: "web-x",
        recipient: DEMO_RECIPIENT,
        amountWei: 1_000_000_000_000_000n,
        asset: "MON",
        purpose: "x",
        chainId: 10143,
        nonce: "web-n",
        expiresAt: NOW + 3600,
      },
      {
        policy: basePolicy({ approvedRecipients: [DEMO_RECIPIENT] }),
        approver: DEMO_APPROVER,
        domainId: "agentpay-demo-v1",
        policyVersion: CURRENT_POLICY_VERSION,
      },
    );
    const wrong = await postJson(base, "/api/preview", {
      amountMon: "0.001",
      requestId: "web-x",
      nonce: "web-n",
      proof,
    });
    expect(wrong.status).toBe(200);
    const body = JSON.parse(wrong.text) as { preview: { ok: boolean } };
    expect(body.preview.ok).toBe(false);
    // Signature material never appears in responses.
    expect(wrong.text).not.toContain(proof.signature.slice(2, 42));
    expect(chain.sendLog.length).toBe(0);
  });

  it("uses server-generated identifiers when omitted and validates supplied ones", async () => {
    const base = await start({ chain: new MockChainPort() });
    const auto = await postJson(base, "/api/preview", { amountMon: "0.001" });
    const autoBody = JSON.parse(auto.text) as { preview: { ok: boolean; requestId: string; nonce: string } };
    expect(autoBody.preview.ok).toBe(true);
    expect(autoBody.preview.requestId.length).toBeGreaterThan(0);
    const numeric = await postJson(base, "/api/preview", { amountMon: "0.001", requestId: 42 });
    expect(numeric.status).toBe(400);
  });
});

describe("demo server hardening (abort, timeouts, limiter bounds)", () => {
  it("survives a client abort mid-upload and serves the next request", async () => {
    const { Socket } = await import("node:net");
    const base = await start({ chain: new MockChainPort() });
    const port = Number(new URL(base).port);
    await new Promise<void>((resolve) => {
      const sock = new Socket();
      sock.connect(port, "127.0.0.1", () => {
        // Claim a large body, send a fragment, then abort mid-upload.
        sock.write("POST /api/preview HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 5000\r\n\r\n{\"amountMon\":\"0.0");
        setTimeout(() => {
          sock.destroy();
          resolve();
        }, 100);
      });
      sock.on("error", () => resolve());
      setTimeout(resolve, 3000);
    });
    // The process must still be alive: a normal request succeeds afterwards.
    // (In-process server: survival here proves no unhandled rejection crash.)
    const res = await postJson(base, "/api/preview", { amountMon: "0.001" });
    expect(res.status).toBe(200);
    const body = JSON.parse(res.text) as { preview: { ok: boolean } };
    expect(body.preview.ok).toBe(true);
  });

  it("malformed HTTP at the socket level ends with 400, not a crash", async () => {
    const { Socket } = await import("node:net");
    const base = await start({ chain: new MockChainPort() });
    const port = Number(new URL(base).port);
    const reply = await new Promise<string>((resolve) => {
      const sock = new Socket();
      let data = "";
      sock.connect(port, "127.0.0.1", () => {
        sock.write("THIS IS NOT HTTP\r\n\r\n");
      });
      sock.on("data", (c: Buffer) => {
        data += c.toString("utf8");
      });
      sock.on("close", () => resolve(data));
      setTimeout(() => resolve(data), 3000);
    });
    expect(reply).toContain("400");
    const res = await get(base, "/");
    expect(res.status).toBe(200);
  });

  it("RPC calls time out within a bounded window", async () => {
    const { rpcCall, RPC_TIMEOUT_MS } = await import("../../server/server.js");
    expect(RPC_TIMEOUT_MS).toBeLessThanOrEqual(20_000);
    // Blackhole server: accepts connections, never responds.
    const { createServer } = await import("node:http");
    const blackhole = createServer(() => {
      // Intentionally never respond.
    });
    await new Promise<void>((resolve) => blackhole.listen(0, "127.0.0.1", () => resolve()));
    const address = blackhole.address();
    if (typeof address !== "object" || address === null) throw new Error("no listen address");
    const started = Date.now();
    await expect(
      rpcCall(`http://127.0.0.1:${address.port}`, "eth_chainId", []),
    ).rejects.toThrow();
    const elapsed = Date.now() - started;
    expect(elapsed).toBeLessThan(RPC_TIMEOUT_MS + 15_000);
    blackhole.close();
  }, 60_000);

  it("rate limiter evicts expired entries and enforces a hard cap", async () => {
    const { createRateLimiter } = await import("../../server/server.js");
    const allow = createRateLimiter({ windowMs: 1000, maxRequests: 100, maxEntries: 2 });
    expect(allow("10.0.0.1", 0)).toBe(true);
    expect(allow("10.0.0.2", 0)).toBe(true);
    // Third distinct client while full: refused, memory stays bounded.
    expect(allow("10.0.0.3", 0)).toBe(false);
    // After the window passes, expired entries are evicted and newcomers pass.
    expect(allow("10.0.0.3", 2000)).toBe(true);
    expect(allow("10.0.0.1", 2000)).toBe(true);
  });

  it("per-IP counting ignores spoofed X-Forwarded-For headers", async () => {
    const base = await start({ chain: new MockChainPort(), rateLimit: { windowMs: 60_000, maxRequests: 1 } });
    const first = await new Promise<{ status: number }>((resolve, reject) => {
      const req = httpRequest(
        `${base}/api/preview`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "content-length": 21,
            "x-forwarded-for": "9.9.9.9",
          },
        },
        (res) => {
          res.resume();
          res.on("end", () => resolve({ status: res.statusCode ?? 0 }));
        },
      );
      req.on("error", reject);
      req.end(JSON.stringify({ amountMon: "0.001" }));
    });
    expect(first.status).toBe(200);
    // Same socket peer, different forged header: still the same bucket.
    const second = await new Promise<{ status: number }>((resolve, reject) => {
      const req = httpRequest(
        `${base}/api/preview`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "content-length": 21,
            "x-forwarded-for": "8.8.8.8",
          },
        },
        (res) => {
          res.resume();
          res.on("end", () => resolve({ status: res.statusCode ?? 0 }));
        },
      );
      req.on("error", reject);
      req.end(JSON.stringify({ amountMon: "0.001" }));
    });
    expect(second.status).toBe(429);
  });
});
