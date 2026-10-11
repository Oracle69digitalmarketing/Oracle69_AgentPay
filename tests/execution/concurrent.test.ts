/**
 * M3 concurrency tests.
 *
 * 10. In-process: two overlapping executePayment calls on one approval yield
 *     exactly one submission (atomic send-right CAS, not timing luck — the
 *     mock send blocks until both callers have reserved).
 * Cross-process: separate OS processes running FULL executePayment against
 * one database yield exactly one submission; losers never send.
 */
import { execFile, execFileSync } from "node:child_process";
import { appendFileSync, existsSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import type { Hex } from "viem";
import { parseTransaction } from "viem";
import { executePayment } from "../../src/execution/execute.js";
import type { ExecRejectionCode, ExecuteDecision } from "../../src/execution/types.js";
import { ExecutionStore } from "../../src/execution/store.js";
import { NOW, baseExecIntent, execFixture, signApproval } from "./helpers.js";
import { MockChainPort } from "./mock.js";

const tempDirs: string[] = [];
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function codesOf(d: ExecuteDecision): ExecRejectionCode[] {
  return d.submitted ? [] : d.reasons.map((r) => r.code);
}

async function waitForState(
  get: () => string | null | undefined,
  want: string,
  label: string,
): Promise<void> {
  const start = Date.now();
  for (;;) {
    if (get() === want) return;
    if (Date.now() - start > 5000) throw new Error(`timed out waiting for ${label}`);
    await new Promise((r) => setTimeout(r, 10));
  }
}

describe("M3 concurrent execution (in-process)", () => {
  it("10. concurrent requests on one authorization submit exactly once", async () => {
    const fx = execFixture();
    const intent = baseExecIntent();
    const proof = await signApproval(fx.approver, intent, fx.authConfig);
    const run = {
      intent, proof, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    };
    // Gate the mock send until both callers are inside the pipeline, forcing
    // genuine overlap (not sequential calls).
    let releaseSend!: () => void;
    const gate = new Promise<void>((r) => { releaseSend = r; });
    let entered = 0;
    const origSend = fx.chain.sendRawTransaction.bind(fx.chain);
    fx.chain.sendRawTransaction = (async (signed: Hex): Promise<Hex> => {
      entered += 1;
      if (entered < 2) await gate;
      return origSend(signed);
    }) as MockChainPort["sendRawTransaction"];
    const a = executePayment(run);
    const b = executePayment(run);
    // Let both reach the send gate, then release together.
    await new Promise((r) => setTimeout(r, 200));
    releaseSend();
    const [ra, rb] = await Promise.all([a, b]);
    const submitted = [ra, rb].filter((d) => d.submitted);
    const rejected = [ra, rb].filter((d) => !d.submitted);
    expect(submitted.length).toBe(1);
    expect(rejected.length).toBe(1);
    expect(fx.chain.sendLog.length).toBe(1);
    fx.execStore.close();
  });

  it("P1: stale lease holder cannot submit after a steal (fencing gate)", async () => {
    const fx = execFixture();
    // A starts with old-now and pauses inside signing (holds send right +
    // lease token t1, row SENDING).
    const a = baseExecIntent({ requestId: "req-fa", nonce: "nonce-fa" });
    const proofA = await signApproval(fx.approver, a, fx.authConfig);
    let releaseSigner!: () => void;
    const signGate = new Promise<void>((r) => { releaseSigner = r; });
    const realSign = fx.payer.signTransfer.bind(fx.payer);
    const hangingSigner = {
      address: fx.payer.address,
      signTransfer: (async (tx: Parameters<typeof realSign>[0]) => {
        await signGate;
        return realSign(tx);
      }) as typeof realSign,
    };
    const runA = {
      intent: a, proof: proofA, authConfig: fx.authConfig,
      execConfig: { chainId: 10143, signer: hangingSigner },
      now: 1_000, execStore: fx.execStore, chain: fx.chain,
    };
    const pendingA = executePayment(runA);
    await waitForState(() => fx.execStore.get("req-fa")?.state, "SENDING", "A SENDING");
    // B (different payment, past grace) steals the lease and completes.
    const b = baseExecIntent({ requestId: "req-fb", nonce: "nonce-fb", amountWei: 200_000_000_000_000_000n });
    const proofB = await signApproval(fx.approver, b, fx.authConfig);
    const dB = await executePayment({
      intent: b, proof: proofB, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: 1_000 + 301, execStore: fx.execStore, chain: fx.chain,
    });
    expect(dB.submitted).toBe(true);
    // A resumes: its fenced hash-record finds a stale token and aborts
    // BEFORE sending anything.
    releaseSigner();
    const dA = await pendingA;
    expect(dA.submitted).toBe(false);
    expect(codesOf(dA)).toContain("EXEC_FENCE_LOST");
    expect(fx.chain.sendLog.length).toBe(1);
    expect(fx.execStore.get("req-fa")?.state).toBe("RESERVED");
    expect(fx.execStore.get("req-fa")?.txHash).toBeNull();
    fx.execStore.close();
  });

  it("different approved payments from one payer serialize sender nonces", async () => {
    // Strict-nonce mock chain: any sender-nonce reuse or gap is a definitive
    // rejection. Both payments must land with distinct nonces.
    const fx = execFixture();
    const a = baseExecIntent({ requestId: "req-pa", nonce: "nonce-pa", amountWei: 300_000_000_000_000_000n });
    const b = baseExecIntent({ requestId: "req-pb", nonce: "nonce-pb", amountWei: 200_000_000_000_000_000n });
    const proofA = await signApproval(fx.approver, a, fx.authConfig);
    const proofB = await signApproval(fx.approver, b, fx.authConfig);
    const runA = {
      intent: a, proof: proofA, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    };
    const runB = {
      intent: b, proof: proofB, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    };
    async function drive(run: typeof runA) {
      for (let i = 0; i < 6; i++) {
        const d = await executePayment(run);
        if (d.submitted) return d;
        if (!d.submitted && d.reasons.some((r) => r.code === "EXEC_PAYER_BUSY")) continue;
        return d;
      }
      throw new Error("payment did not complete after retries");
    }
    const [ra, rb] = await Promise.all([drive(runA), drive(runB)]);
    expect(ra.submitted).toBe(true);
    expect(rb.submitted).toBe(true);
    expect(fx.chain.sendLog.length).toBe(2);
    const nonces = fx.chain.sendLog.map((s) => parseTransaction(s).nonce);
    expect(new Set(nonces).size).toBe(2);
    expect(fx.chain.acceptedCount).toBe(2);
    fx.execStore.close();
  });
});

describe("M3 cross-process execution (separate OS processes)", () => {
  const execFileAsync = promisify(execFile);
  const THIS_FILE = fileURLToPath(import.meta.url);
  const REPO_ROOT = resolve(dirname(THIS_FILE), "..", "..");
  let root = "";
  let childScript = "";
  let goCounter = 0;

  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), "agentpay-m3x-"));
    symlinkSync(join(REPO_ROOT, "node_modules"), join(root, "node_modules"));
    const build = join(root, "build");
    // Compile the real sources (execution + auth + policy) for child import.
    execFileSync(join(REPO_ROOT, "node_modules", ".bin", "tsc"), [
      "--project", join(REPO_ROOT, "tsconfig.json"),
      "--noEmit", "false",
      "--outDir", build,
      "--declaration", "false",
      "--sourceMap", "false",
    ]);
    if (!existsSync(join(build, "src", "execution", "execute.js"))) {
      throw new Error("cross-process setup failed: compiled execution module missing");
    }
    // Child: full executePayment with a file-append send log as the mock
    // chain. Key material below is a runtime-generated throwaway passed via
    // argv (test-only, no funds, no network).
    childScript = join(root, "execute-child.mjs");
    writeFileSync(
      childScript,
      `import fs from "node:fs";\n` +
        `import { executePayment } from "./build/src/execution/execute.js";\n` +
        `import { ExecutionStore } from "./build/src/execution/store.js";\n` +
        `import { createSignerFromPrivateKey } from "./build/src/execution/signer.js";\n` +
        `const [dbPath, goFile, logFile, payloadJson] = process.argv.slice(2);\n` +
        `const payload = JSON.parse(payloadJson, (k, v) => (k === "amountWei" || k === "maxPerPaymentWei" ? BigInt(v) : v));\n` +
        `const start = Date.now();\n` +
        `while (!fs.existsSync(goFile)) {\n` +
        `  if (Date.now() - start > 15000) { console.log(JSON.stringify({ submitted: false, error: "barrier-timeout" })); process.exit(2); }\n` +
        `  await new Promise((r) => setTimeout(r, 5));\n` +
        `}\n` +
        `const chain = {\n` +
        `  getChainId: async () => 10143,\n` +
        `  getSenderNonce: async () => 0,\n` +
        `  estimateTransferGas: async () => 21000n,\n` +
        `  estimateFees: async () => ({ maxFeePerGas: 1000000000n, maxPriorityFeePerGas: 1000000000n }),\n` +
        `  sendRawTransaction: async (signed) => { fs.appendFileSync(logFile, signed + "\\n"); const h = (await import("viem")).keccak256(signed); return h; },\n` +
        `  getReceipt: async () => null,\n` +
        `};\n` +
        `const store = new ExecutionStore(dbPath);\n` +
        `try {\n` +
        `  const signer = createSignerFromPrivateKey(payload.payerKey);\n` +
        `  const d = await executePayment({ intent: payload.intent, proof: payload.proof, authConfig: payload.authConfig, execConfig: { chainId: 10143, signer }, now: payload.now, execStore: store, chain });\n` +
        `  console.log(JSON.stringify({ submitted: d.submitted, state: d.submitted ? d.state : d.state }));\n` +
        `} catch (e) {\n` +
        `  console.log(JSON.stringify({ submitted: false, error: String((e && e.message) || e) }));\n` +
        `  process.exitCode = 1;\n` +
        `} finally {\n` +
        `  try { store.close(); } catch {}\n` +
        `}\n`,
    );
  }, 180_000);

  afterAll(() => {
    if (root !== "") rmSync(root, { recursive: true, force: true });
  });

  it("separate processes executing one approval submit exactly once", async () => {
    const fx = execFixture();
    const intent = baseExecIntent({ requestId: "req-xp1", nonce: "nonce-xp1" });
    const proof = await signApproval(fx.approver, intent, fx.authConfig);
    fx.execStore.close();
    // Throwaway payer key for the child processes (runtime-generated).
    const { generatePrivateKey } = await import("viem/accounts");
    const payerKey = generatePrivateKey();
    const dir = mkdtempSync(join(tmpdir(), "agentpay-m3xp-"));
    tempDirs.push(dir);
    const dbPath = join(dir, "exec.db");
    const logFile = join(dir, "sends.log");
    writeFileSync(logFile, "");
    // Signer address is derived from payerKey inside the child; the approval
    // is independent of the payer, so reuse the parent's proof/intent/config.
    const payload = JSON.stringify({
      intent: { ...intent, amountWei: intent.amountWei.toString() },
      proof,
      authConfig: {
        ...fx.authConfig,
        policy: { ...fx.authConfig.policy, maxPerPaymentWei: fx.authConfig.policy.maxPerPaymentWei.toString() },
      },
      now: NOW,
      payerKey,
    });
    const goFile = join(root, `go-${goCounter++}`);
    const N = 4;
    const runs = Array.from({ length: N }, () =>
      execFileAsync(process.execPath, [childScript, dbPath, goFile, logFile, payload], { timeout: 60_000 }).then(
        ({ stdout }) => JSON.parse(stdout.trim().split("\n").at(-1) as string) as unknown,
        (err: unknown) => ({ submitted: false, error: String(err) }),
      ),
    );
    await new Promise((r) => setTimeout(r, 1200));
    writeFileSync(goFile, "go");
    const results = await Promise.all(runs);
    const submitted = results.filter((r) => (r as { submitted?: boolean }).submitted === true);
    expect(submitted.length, `expected exactly 1 submission, got: ${JSON.stringify(results)}`).toBe(1);
    const { readFileSync } = await import("node:fs");
    const sends = readFileSync(logFile, "utf8").trim().split("\n").filter((l) => l.length > 0);
    expect(sends.length, `expected exactly 1 send line, got ${sends.length}`).toBe(1);
  }, 180_000);
});
