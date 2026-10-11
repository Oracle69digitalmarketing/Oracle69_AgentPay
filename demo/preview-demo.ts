/**
 * Read-only Monad Testnet demo driver — Oracle69 AgentPay (preflight only).
 *
 * WHAT THIS IS: assembles the existing policy, preview, and constants
 * modules to display a transaction preview. It cannot execute anything.
 *
 * STRUCTURAL NON-EXECUTION GUARANTEES (enforced by tests/demo/preview-driver.test.ts):
 * - Imports ONLY: src/preview (preview entry), src/policy/types + src/auth
 *   types (constants), viem pure address/format utilities, node builtins for
 *   argv/stdout/file-reading. NEVER execution, stores, signers, or keys.
 * - No EXECUTOR_PRIVATE_KEY, no process.env secrets, no signTransfer, no
 *   sendRawTransaction anywhere (imports, code, or output strings).
 * - The live chain port below performs ONLY read-only JSON-RPC methods
 *   (eth_chainId, eth_getTransactionCount, eth_getBalance, eth_estimateGas,
 *   eth_gasPrice). Any other method name throws before any network call.
 * - No route, flag, or environment switch triggers execution: the only
 *   action is printing a labeled preflight preview. Unknown flags fail.
 * - Sender/approver/recipient are explicit public-address inputs and must be
 *   three distinct normalized addresses.
 */
import { getAddress, isAddress } from "viem";
import {
  ABSOLUTE_MAX_PAYMENT_WEI,
  DEMO_MAX_PER_PAYMENT_WEI,
  MONAD_TESTNET_CHAIN_ID,
} from "../src/policy/types.js";
import { CURRENT_POLICY_VERSION } from "../src/auth/types.js";
import { ALLOWED_RPC_URLS, PRIMARY_RPC_URL } from "../src/execution/types.js";
import {
  previewTransaction,
  type PreviewResult,
  type ReadOnlyChain,
} from "../src/preview/index.js";
import type { Address } from "viem";
import { readFile } from "node:fs/promises";

// Minimal fetch typing (global fetch exists on Node 22; DOM lib is off).
declare function fetch(
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string },
): Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

const READ_METHODS = [
  "eth_chainId",
  "eth_getTransactionCount",
  "eth_getBalance",
  "eth_estimateGas",
  "eth_gasPrice",
] as const;

type ReadMethod = (typeof READ_METHODS)[number];

async function rpcCall(rpcUrl: string, method: ReadMethod, params: unknown[]): Promise<unknown> {
  const res = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  if (!res.ok) throw new Error(`RPC HTTP ${res.status}`);
  const body = (await res.json()) as { result?: unknown; error?: { message?: string } };
  if (body.error !== undefined) throw new Error(`RPC error: ${String(body.error.message ?? "unknown")}`);
  return body.result;
}

function hexQuantity(value: bigint): string {
  return `0x${value.toString(16)}`;
}

function parseHexQuantity(v: unknown, label: string): bigint {
  if (typeof v !== "string" || !/^0x[0-9a-fA-F]+$/.test(v)) throw new Error(`bad ${label}`);
  return BigInt(v);
}

/** Live read-only port. Contains no submission capability by construction. */
export function createReadOnlyPort(rpcUrl: string): ReadOnlyChain {
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
      // Preview-display heuristic only: 2x current gas price, 2 gwei priority.
      // Execution re-estimates independently; the fee gate judges the values.
      const base = parseHexQuantity(await rpcCall(rpcUrl, "eth_gasPrice", []), "gas price");
      return { maxFeePerGas: base * 2n, maxPriorityFeePerGas: 2_000_000_000n };
    },
    getReceipt: async () => null,
  };
}

export interface DemoArgs {
  recipient: string;
  approver: string;
  sender: string;
  allowlist: string[];
  amountWei: bigint;
  requestId: string;
  nonce: string;
  domainId: string;
  policyVersion: string;
  now: number;
  rpcUrl: string;
  proofFile: string | null;
}

export interface DemoOutput {
  banner: string;
  preview: PreviewResult;
}

function failOut(message: string): DemoOutput {
  return {
    banner: "INFORMATIONAL PREFLIGHT — NOT AUTHORIZATION TO EXECUTE — NO BROADCAST",
    preview: { ok: false, reasons: [{ code: "INVALID_REQUEST", message }] },
  };
}

function checkAddress(value: string, label: string): string | null {
  if (typeof value !== "string" || !isAddress(value)) return `${label} must be a valid EVM address`;
  return null;
}

/** Pure assembly + preview. No stores, no keys, no signing, no submission. */
export async function runDemoPreview(
  args: DemoArgs,
  chain: ReadOnlyChain,
): Promise<DemoOutput> {
  const banner = "INFORMATIONAL PREFLIGHT — NOT AUTHORIZATION TO EXECUTE — NO BROADCAST";
  for (const [label, value] of [["recipient", args.recipient], ["approver", args.approver], ["sender", args.sender]] as const) {
    const problem = checkAddress(value, label);
    if (problem !== null) return { banner, preview: { ok: false, reasons: [{ code: "INVALID_REQUEST", message: problem }] } };
  }
  const recipient = getAddress(args.recipient);
  const approver = getAddress(args.approver);
  const sender = getAddress(args.sender);
  const distinct = new Set([recipient.toLowerCase(), approver.toLowerCase(), sender.toLowerCase()]);
  if (distinct.size !== 3) {
    return { banner, preview: { ok: false, reasons: [{ code: "INVALID_REQUEST", message: "executor, approver, and recipient must be three distinct addresses" }] } };
  }
  for (const entry of args.allowlist) {
    const problem = checkAddress(entry, "allowlist entry");
    if (problem !== null) return { banner, preview: { ok: false, reasons: [{ code: "INVALID_REQUEST", message: problem }] } };
  }
  const allowSet = new Set(args.allowlist.map((a) => getAddress(a).toLowerCase()));
  if (!allowSet.has(recipient.toLowerCase())) {
    return { banner, preview: { ok: false, reasons: [{ code: "NOT_ALLOWLISTED", message: "recipient is not in the configured allowlist" }] } };
  }
  if (args.amountWei <= 0n || args.amountWei > ABSOLUTE_MAX_PAYMENT_WEI) {
    return { banner, preview: { ok: false, reasons: [{ code: "INVALID_AMOUNT", message: "demo amount must be within (0, 1 MON]" }] } };
  }
  if (args.requestId.length === 0 || args.nonce.length === 0) {
    return { banner, preview: { ok: false, reasons: [{ code: "INVALID_REQUEST", message: "requestId and nonce must be non-empty" }] } };
  }

  const policy = {
    approvedRecipients: [...allowSet].map((a) => getAddress(a)),
    maxPerPaymentWei: DEMO_MAX_PER_PAYMENT_WEI,
    allowedChainId: MONAD_TESTNET_CHAIN_ID,
    requireHumanApproval: true,
  };
  const authConfig = { policy, approver, domainId: args.domainId, policyVersion: args.policyVersion };
  const intent = {
    requestId: args.requestId,
    recipient,
    amountWei: args.amountWei,
    asset: "MON",
    purpose: "AgentPay controlled demo (preflight, no execution)",
    chainId: MONAD_TESTNET_CHAIN_ID,
    nonce: args.nonce,
    expiresAt: args.now + 3600,
  };

  let proof: unknown;
  if (args.proofFile !== null) {
    try {
      proof = JSON.parse(await readFile(args.proofFile, "utf8")) as unknown;
    } catch {
      return { banner, preview: { ok: false, reasons: [{ code: "INVALID_PROOF", message: "could not read proof file" }] } };
    }
  }

  const preview = await previewTransaction({
    intent, proof, authConfig, senderAddress: sender, now: args.now, chain,
  });
  return { banner, preview };
}

function usage(): string {
  return [
    "AgentPay read-only demo preview (Monad Testnet, no execution).",
    "Required: --recipient 0x.. --approver 0x.. --sender 0x..",
    "Optional: --allowlist 0x..,0x.. (default: recipient) --amount-wei N (default 1000000000000000 = 0.001 MON)",
    "  --request-id ID --nonce N --domain ID (default agentpay-demo-v1) --policy-version V",
    "  --now EPOCH --rpc-url URL (allowlisted Testnet only) --proof-file PATH --help",
    "Reads: chain ID, nonce, balance, gas/fee estimates. Writes: nothing. Sends: nothing.",
  ].join("\n");
}

function parseAmountWei(raw: string): bigint {
  if (!/^[0-9]+$/.test(raw)) throw new Error("--amount-wei must be a decimal integer string");
  return BigInt(raw);
}

export async function main(argv: string[]): Promise<number> {
  const knownFlags = [
    "--recipient", "--approver", "--sender", "--allowlist", "--amount-wei",
    "--request-id", "--nonce", "--domain", "--policy-version", "--now",
    "--rpc-url", "--proof-file",
  ];
  // Duplicate flags are rejected up front — even identical repeats — so no
  // invocation can silently resolve to an unintended value. Checked before
  // help, parsing, file reads, or any RPC access. Only the flag NAME is
  // ever echoed, never any value.
  {
    const seen = new Set<string>();
    for (const a of argv) {
      if (!knownFlags.includes(a)) continue;
      if (seen.has(a)) {
        process.stdout.write(`${JSON.stringify(failOut(`duplicate flag ${a}`))}\n`);
        return 2;
      }
      seen.add(a);
    }
  }
  if (argv.includes("--help") || argv.includes("-h")) {
    process.stdout.write(`${usage()}\n`);
    return 0;
  }
  for (const a of argv) {
    if (a.startsWith("--") && !knownFlags.includes(a)) {
      process.stdout.write(`${JSON.stringify(failOut(`unknown flag ${a}`))}\n`);
      return 2;
    }
  }
  const get = (flag: string): string | null => {
    const i = argv.indexOf(flag);
    if (i === -1 || i + 1 >= argv.length) return null;
    return argv[i + 1] as string;
  };
  try {
    const recipient = get("--recipient");
    const approver = get("--approver");
    const sender = get("--sender");
    if (recipient === null || approver === null || sender === null) {
      process.stdout.write(`${JSON.stringify(failOut("missing required --recipient/--approver/--sender"))}\n`);
      return 2;
    }
    const allowRaw = get("--allowlist");
    const amountWei = parseAmountWei(get("--amount-wei") ?? "1000000000000000");
    const now = get("--now") !== null ? Number(get("--now")) : Math.floor(Date.now() / 1000);
    if (!Number.isInteger(now) || now < 0) throw new Error("--now must be a non-negative integer");
    const rpcUrl = get("--rpc-url") ?? PRIMARY_RPC_URL;
    const args: DemoArgs = {
      recipient,
      approver,
      sender,
      allowlist: allowRaw !== null ? allowRaw.split(",").map((s) => s.trim()).filter((s) => s.length > 0) : [recipient],
      amountWei,
      requestId: get("--request-id") ?? `demo-${now}`,
      nonce: get("--nonce") ?? `demo-nonce-${now}`,
      domainId: get("--domain") ?? "agentpay-demo-v1",
      policyVersion: get("--policy-version") ?? CURRENT_POLICY_VERSION,
      now,
      rpcUrl,
      proofFile: get("--proof-file"),
    };
    const chain = createReadOnlyPort(rpcUrl);
    const out = await runDemoPreview(args, chain);
    process.stdout.write(`${JSON.stringify(out, (_k, v) => (typeof v === "bigint" ? v.toString() : v) as unknown, 2)}\n`);
    return out.preview.ok ? 0 : 1;
  } catch (err) {
    process.stdout.write(`${JSON.stringify(failOut(err instanceof Error ? err.message : "invalid arguments"))}\n`);
    return 2;
  }
}

const invokedAsScript = process.argv[1] !== undefined && import.meta.url.endsWith("/demo/preview-demo.js");
if (invokedAsScript) {
  void main(process.argv.slice(2)).then((code) => process.exit(code));
}
