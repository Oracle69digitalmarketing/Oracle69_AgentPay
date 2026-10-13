/**
 * Read-only AgentPay demo server — Monad Testnet preflight only.
 *
 * Serves a static browser page (GET /) and evaluates payment previews
 * (POST /api/preview) using the existing previewTransaction implementation.
 *
 * STRUCTURAL NON-EXECUTION GUARANTEES (enforced by tests/server-audit):
 * - Imports ONLY: preview entry, policy constants/validators, auth
 *   constants, viem pure address utilities, node builtins (http/url/fs).
 *   NEVER execution engine, stores, signers, keys, or submission methods.
 * - Fixed server-side policy: chain 10143, MON, 1 MON ceiling, approval
 *   required, single allowlisted recipient, fixed approver, fixed sender.
 *   Callers CANNOT change approver, limits, chain, version, domain, or
 *   allowlist. Unknown request fields are rejected.
 * - No private keys anywhere: sender/approver/recipient are public address
 *   constants. No signer is constructed. No database is opened.
 * - Rate limiting is in-memory per process (not distributed); client IP is
 *   taken from the direct socket peer only — X-Forwarded-For is untrusted
 *   and ignored, so limits behind shared proxies act as global throttles.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { readFileSync } from "node:fs";
import { getAddress } from "viem";
import {
  ABSOLUTE_MAX_PAYMENT_WEI,
  MONAD_TESTNET_CHAIN_ID,
} from "../src/policy/types.js";
import { CURRENT_POLICY_VERSION } from "../src/auth/types.js";
import { parseDecimalMonToWei } from "../src/policy/validation.js";
import { ALLOWED_RPC_URLS, PRIMARY_RPC_URL } from "../src/execution/types.js";
import {
  previewTransaction,
  type PreviewResult,
  type ReadOnlyChain,
} from "../src/preview/index.js";
import { processQwenIntent } from "../src/qwen/adapter.js";
import type { Address } from "viem";

// Minimal fetch typing (global fetch exists on Node 22; DOM lib is off).
declare function fetch(
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal },
): Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

/** Read-only JSON-RPC methods. Anything else throws before any request. */
const READ_METHODS = [
  "eth_chainId",
  "eth_getTransactionCount",
  "eth_getBalance",
  "eth_estimateGas",
  "eth_gasPrice",
] as const;

type ReadMethod = (typeof READ_METHODS)[number];

/** RPC timeout: bounds every read-only call so a hanging endpoint cannot
 * pin a handler (and its rate-limit slot) indefinitely. Timeouts surface as
 * ordinary errors and fail closed downstream. */
export const RPC_TIMEOUT_MS = 15_000;

export async function rpcCall(rpcUrl: string, method: ReadMethod, params: unknown[]): Promise<unknown> {
  const res = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`RPC HTTP ${res.status}`);
  const body = (await res.json()) as { result?: unknown; error?: { message?: string } };
  if (body.error !== undefined) throw new Error("RPC error response");
  return body.result;
}

function hexQuantity(value: bigint): string {
  return `0x${value.toString(16)}`;
}

function parseHexQuantity(v: unknown, label: string): bigint {
  if (typeof v !== "string" || !/^0x[0-9a-fA-F]+$/.test(v)) throw new Error(`bad ${label}`);
  return BigInt(v);
}

/**
 * Server-side read-only port bound to the allowlisted Testnet endpoint.
 * Contains no submission capability: only the five read methods above can
 * ever be requested, and the URL must be allowlisted.
 */
export function createServerPort(rpcUrl: string = PRIMARY_RPC_URL): ReadOnlyChain {
  if (!(ALLOWED_RPC_URLS as readonly string[]).includes(rpcUrl)) {
    throw new Error("RPC URL not allowlisted for Monad Testnet demo");
  }
  return {
    getChainId: async () => {
      const r = await rpcCall(rpcUrl, "eth_chainId", []);
      if (typeof r !== "string") throw new Error("bad chainId");
      return parseInt(r, 16);
    },
    getSenderNonce: async (sender: Address) => {
      const r = await rpcCall(rpcUrl, "eth_getTransactionCount", [sender, "latest"]);
      return Number(parseHexQuantity(r, "nonce"));
    },
    getBalance: async (address: Address) => {
      const r = await rpcCall(rpcUrl, "eth_getBalance", [address, "latest"]);
      return parseHexQuantity(r, "balance");
    },
    estimateTransferGas: async (to: Address, value: bigint, from: Address) => {
      const r = await rpcCall(rpcUrl, "eth_estimateGas", [{ to, from, value: hexQuantity(value) }, "latest"]);
      return parseHexQuantity(r, "gas");
    },
    estimateFees: async () => {
      const base = parseHexQuantity(await rpcCall(rpcUrl, "eth_gasPrice", []), "gas price");
      return { maxFeePerGas: base * 2n, maxPriorityFeePerGas: 2_000_000_000n };
    },
    getReceipt: async () => null,
  };
}

/** Fixed demo identities: public addresses, never credentials. */
export const DEMO_EXECUTOR = "0xF5aB622c4D9F2C3b068401AF16EFeD05ABA92C50";
export const DEMO_APPROVER = "0xE38e4f4a4554a3dcE15eA372B0c74DAAC3E83F55";
export const DEMO_RECIPIENT = "0x5cf66568b51b308BCf13319F5e84cff28104E1aF";
export const DEMO_DOMAIN_ID = "agentpay-demo-v1";
export const DEMO_MAX_WEI = ABSOLUTE_MAX_PAYMENT_WEI;
const DEMO_PURPOSE = "AgentPay web demo (preflight, no execution)";
const DEMO_EXPIRY_SECONDS = 3600;

/** Public request schema: amount, identifiers, optional proof. Nothing else. */
const ALLOWED_FIELDS = ["amountMon", "requestId", "nonce", "proof"] as const;
type AllowedField = (typeof ALLOWED_FIELDS)[number];

const MAX_BODY_BYTES = 16 * 1024;

export interface RateLimitOptions {
  windowMs: number;
  maxRequests: number;
  /** Hard cap on tracked client entries. Defaults to 10_000. */
  maxEntries?: number;
}

export interface ServerOptions {
  port?: number;
  chain: ReadOnlyChain;
  rateLimit?: RateLimitOptions;
  nowFn?: () => number;
  randomIdFn?: () => string;
}

const DEFAULT_RATE_LIMIT: RateLimitOptions = { windowMs: 60_000, maxRequests: 30 };

function jsonBody(res: ServerResponse, status: number, value: unknown): void {
  // Never throw outward: the socket may already be dead (client abort), in
  // which case there is simply nobody left to answer. All callers treat a
  // silent drop as acceptable; the request itself already failed closed.
  try {
    if (res.destroyed || res.writableEnded) return;
    const text = JSON.stringify(value);
    res.writeHead(status, { "content-type": "application/json; charset=utf-8" });
    res.end(text);
  } catch {
    // Dead socket: nothing further can or should be done here.
  }
}

function failOut(message: string): { banner: string; preview: PreviewResult } {
  return {
    banner: "INFORMATIONAL PREFLIGHT — NOT AUTHORIZATION TO EXECUTE — NO BROADCAST",
    preview: { ok: false, reasons: [{ code: "INVALID_REQUEST", message }] },
  };
}

function readBody(req: IncomingMessage, limit: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let failed = false;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > limit) {
        // Over limit: drop further bytes but keep draining so the connection
        // stays clean and the caller always receives a deterministic 413.
        // Only pre-limit bytes are retained, so memory stays bounded.
        failed = true;
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (failed) reject(new Error("body too large"));
      else resolve(Buffer.concat(chunks).toString("utf8"));
    });
    req.on("error", (err: unknown) => {
      reject(err instanceof Error ? err : new Error("body read failed"));
    });
  });
}

function clientIp(req: IncomingMessage): string {
  // Direct socket peer only. X-Forwarded-For is caller-controlled and
  // ignored: behind shared proxies this degrades to a global throttle,
  // which is the safe direction (fail closed, never fail open).
  return req.socket.remoteAddress ?? "unknown";
}

const DEFAULT_MAX_RATE_ENTRIES = 10_000;

export function createRateLimiter(options: RateLimitOptions): (ip: string, now: number) => boolean {
  const maxEntries = options.maxEntries ?? DEFAULT_MAX_RATE_ENTRIES;
  const counts = new Map<string, { windowStart: number; count: number }>();
  const evictExpired = (now: number): void => {
    for (const [key, slot] of counts) {
      if (now - slot.windowStart >= options.windowMs) counts.delete(key);
    }
  };
  return (ip: string, now: number): boolean => {
    const slot = counts.get(ip);
    if (slot !== undefined && now - slot.windowStart < options.windowMs) {
      slot.count += 1;
      return slot.count <= options.maxRequests;
    }
    // New window (or new client): bound memory first. Opportunistically drop
    // expired entries; if still at capacity, refuse rather than grow without
    // bound (fail closed: some legitimate newcomer may see 429 under flood).
    evictExpired(now);
    if (!counts.has(ip) && counts.size >= maxEntries) return false;
    counts.set(ip, { windowStart: now, count: 1 });
    return true;
  };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function createPreviewServer(options: ServerOptions): Server {
  const rateLimit = options.rateLimit ?? DEFAULT_RATE_LIMIT;
  const allowRequest = createRateLimiter(rateLimit);  const nowFn = options.nowFn ?? (() => Math.floor(Date.now() / 1000));
  const randomIdFn =
    options.randomIdFn ??
    (() => `web-${Date.now().toString(36)}-${Math.floor(Math.random() * 0xffff).toString(36)}`);
  const page = readFileSync(new URL("./public/index.html", import.meta.url), "utf8");

  const policy = {
    approvedRecipients: [DEMO_RECIPIENT],
    maxPerPaymentWei: DEMO_MAX_WEI,
    allowedChainId: MONAD_TESTNET_CHAIN_ID,
    requireHumanApproval: true,
  };
  const authConfig = {
    policy,
    approver: DEMO_APPROVER,
    domainId: DEMO_DOMAIN_ID,
    policyVersion: CURRENT_POLICY_VERSION,
  };

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async (): Promise<void> => {
      try {
        const url = new URL(req.url ?? "/", "http://localhost");
        if (req.method === "GET" && url.pathname === "/") {
          res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
          res.end(page);
          return;
        }
        if (url.pathname === "/api/preview") {
          if (req.method !== "POST") {
            jsonBody(res, 405, { error: "method not allowed" });
            return;
          }
          if (!allowRequest(clientIp(req), Date.now())) {
            jsonBody(res, 429, { error: "rate limit exceeded" });
            return;
          }
          let raw: string;
          try {
            raw = await readBody(req, MAX_BODY_BYTES);
          } catch {
            jsonBody(res, 413, { error: "request body too large or unreadable" });
            return;
          }
          let body: unknown;
          try {
            body = JSON.parse(raw) as unknown;
          } catch {
            jsonBody(res, 400, failOut("request body must be valid JSON"));
            return;
          }
          if (!isRecord(body)) {
            jsonBody(res, 400, failOut("request body must be a JSON object"));
            return;
          }
          for (const key of Object.keys(body)) {
            if (!(ALLOWED_FIELDS as readonly string[]).includes(key)) {
              jsonBody(res, 400, failOut(`unexpected field ${key}`));
              return;
            }
          }
          const amountRaw = (body as Partial<Record<AllowedField, unknown>>).amountMon;
          if (typeof amountRaw !== "string") {
            jsonBody(res, 400, failOut("amountMon must be a decimal MON string"));
            return;
          }
          let amountWei: bigint;
          try {
            amountWei = parseDecimalMonToWei(amountRaw);
          } catch {
            jsonBody(res, 400, failOut("amountMon must be a decimal MON string with at most 18 places"));
            return;
          }
          if (amountWei <= 0n || amountWei > ABSOLUTE_MAX_PAYMENT_WEI) {
            jsonBody(res, 400, failOut("amount must be within (0, 1 MON]"));
            return;
          }
          const requestRaw = (body as Partial<Record<AllowedField, unknown>>).requestId;
          const nonceRaw = (body as Partial<Record<AllowedField, unknown>>).nonce;
          if (requestRaw !== undefined && typeof requestRaw !== "string") {
            jsonBody(res, 400, failOut("requestId must be a string"));
            return;
          }
          if (nonceRaw !== undefined && typeof nonceRaw !== "string") {
            jsonBody(res, 400, failOut("nonce must be a string"));
            return;
          }
          const requestId = requestRaw ?? randomIdFn();
          const nonce = nonceRaw ?? randomIdFn();
          const proofRaw = (body as Partial<Record<AllowedField, unknown>>).proof;
          const proof = proofRaw === undefined ? undefined : proofRaw;
          if (proof !== undefined && !isRecord(proof)) {
            jsonBody(res, 400, failOut("proof must be a JSON object"));
            return;
          }
          const now = nowFn();
          const preview = await previewTransaction({
            intent: {
              requestId,
              recipient: getAddress(DEMO_RECIPIENT),
              amountWei,
              asset: "MON",
              purpose: DEMO_PURPOSE,
              chainId: MONAD_TESTNET_CHAIN_ID,
              nonce,
              expiresAt: now + DEMO_EXPIRY_SECONDS,
            },
            proof,
            authConfig,
            senderAddress: getAddress(DEMO_EXECUTOR),
            now,
            chain: options.chain,
          });
          jsonBody(res, 200, {
            banner: "INFORMATIONAL PREFLIGHT — NOT AUTHORIZATION TO EXECUTE — NO BROADCAST",
            preview,
          });
          return;
        }
        if (url.pathname === "/api/qwen-intent") {
          if (req.method !== "POST") {
            jsonBody(res, 405, { error: "method not allowed" });
            return;
          }
          if (!allowRequest(clientIp(req), Date.now())) {
            jsonBody(res, 429, { error: "rate limit exceeded" });
            return;
          }
          let raw: string;
          try {
            raw = await readBody(req, MAX_BODY_BYTES);
          } catch {
            jsonBody(res, 413, { error: "request body too large or unreadable" });
            return;
          }
          let body: unknown;
          try {
            body = JSON.parse(raw) as unknown;
          } catch {
            jsonBody(res, 400, { error: "request body must be valid JSON" });
            return;
          }
          if (!isRecord(body)) {
            jsonBody(res, 400, { error: "request body must be a JSON object" });
            return;
          }
          if (!("prompt" in body) || typeof body.prompt !== "string" || body.prompt.trim().length === 0) {
            jsonBody(res, 400, { error: "prompt is required and must be a non-empty string" });
            return;
          }
          if (body.prompt.length > 500) {
            jsonBody(res, 400, { error: "prompt must not exceed 500 characters" });
            return;
          }
          const prompt = body.prompt.trim();

          // Use the fixed demo auth config (server-side only, never from client)
          const authConfig = {
            policy: {
              approvedRecipients: [DEMO_RECIPIENT],
              maxPerPaymentWei: DEMO_MAX_WEI,
              allowedChainId: MONAD_TESTNET_CHAIN_ID,
              requireHumanApproval: true,
            },
            approver: DEMO_APPROVER,
            domainId: DEMO_DOMAIN_ID,
            policyVersion: CURRENT_POLICY_VERSION,
          };

          // Use the server port (already allowlisted for Monad Testnet)
          const chain = options.chain;

          // Call the Qwen adapter — fail closed on any error
          const now = nowFn();
          let qwenResult;
          try {
            qwenResult = await processQwenIntent(prompt, now, authConfig, chain);
          } catch {
            jsonBody(res, 500, { error: "qwen adapter internal error" });
            return;
          }

          // Return the structured 4D result
          jsonBody(res, 200, {
            ok: qwenResult.ok,
            policyDecision: {
              allowed: qwenResult.policyDecision.allowed,
              requiresApproval: qwenResult.policyDecision.requiresApproval,
              reasons: qwenResult.policyDecision.reasons,
            },
            approvalStatus: qwenResult.approvalStatus,
            previewResult: qwenResult.previewResult,
            qwenIntent: qwenResult.qwenIntent,
            isExecutable: qwenResult.isExecutable,
          });
          return;
        }
        jsonBody(res, 404, { error: "not found" });
      } catch {
        jsonBody(res, 500, { error: "internal error" });
      }
    })();
  });
  // Hardened transport behavior (availability, not policy):
  // - Malformed HTTP / aborted connections end here with a minimal 400
  //   instead of crashing the process (default 'clientError' rethrow would).
  //   No request bodies, proofs, or provider data are logged.
  // - Explicit timeouts bound slow-drip connections; legitimate small-JSON
  //   requests complete far inside them.
  server.on("clientError", (err: Error, socket) => {
    void err;
    try {
      socket.end("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    } catch {
      // Socket already dead; nothing further to do.
    }
    try {
      socket.destroy();
    } catch {
      // Already destroyed; safe to ignore.
    }
  });
  server.requestTimeout = 30_000;
  server.headersTimeout = 10_000;
  return server;
}

export function startPreviewServer(options: ServerOptions & { port?: number }): Server {
  const port = options.port ?? (process.env["PORT"] !== undefined ? Number(process.env["PORT"]) : 3000);
  const server = createPreviewServer(options);
  server.on("listening", () => {
    const addr = server.address();
    const desc = typeof addr === "object" && addr !== null ? String(addr.port) : "?";
    process.stdout.write(`agentpay demo listening on port ${desc} (Monad Testnet preflight, no execution)\n`);
  });
  server.listen(port);
  return server;
}

const invokedAsScript =
  process.argv[1] !== undefined && import.meta.url.endsWith("/server/server.js");
if (invokedAsScript) {
  const server = startPreviewServer({ chain: createServerPort() });
  void server;
}
