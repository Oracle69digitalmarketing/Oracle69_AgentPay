/**
 * Demo driver tests. Proves structurally (import graph) and behaviorally
 * (mock-only runs) that the driver cannot submit transactions.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { main, runDemoPreview, type DemoArgs } from "../../demo/preview-demo.js";
import { computePolicyDigest } from "../../src/auth/policy-digest.js";
import { MockChainPort } from "../execution/mock.js";
import { NOW, basePolicy, makeAccount, signApproval } from "../auth/helpers.js";

const ADDR_A = "0x1111111111111111111111111111111111111111";
const ADDR_B = "0x2222222222222222222222222222222222222222";
const ADDR_C = "0x3333333333333333333333333333333333333333";

function args(over: Partial<DemoArgs> = {}): DemoArgs {
  return {
    recipient: ADDR_A,
    approver: ADDR_B,
    sender: ADDR_C,
    allowlist: [ADDR_A],
    amountWei: 1_000_000_000_000_000n,
    requestId: "demo-req-1",
    nonce: "demo-nonce-1",
    domainId: "agentpay-demo-v1",
    policyVersion: "m2.1",
    now: NOW,
    rpcUrl: "https://testnet-rpc.monad.xyz",
    proofFile: null,
    ...over,
  };
}

function stripComments(source: string): string {
  const noBlocks = source.replace(/\/\*[\s\S]*?\*\//g, "");
  return noBlocks
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("//"))
    .join("\n");
}

describe("demo driver import graph (no execution capability)", () => {
  it("imports only preview, constants, pure utils, and node builtins", () => {
    const here = dirname(fileURLToPath(import.meta.url));
    const source = readFileSync(join(here, "..", "..", "demo", "preview-demo.ts"), "utf8");
    const specifiers = [...source.matchAll(/from\s+["']([^"']+)["']/g)].map((m) => m[1] as string);
    expect(specifiers.length).toBeGreaterThan(0);
    for (const spec of specifiers) {
      // Only constants may come from execution/: types.js holds chain IDs,
      // RPC allowlist, and fee caps (no behavior). Every other execution/
      // module — execute, chain, signer, store, errors, fee-policy — is
      // forbidden, as are stateful auth/policy modules.
      if (spec === "../src/execution/types.js") continue;
      expect(spec, `forbidden import ${spec}`).not.toMatch(/execution\//);
      expect(spec, `forbidden import ${spec}`).not.toMatch(/auth\/verify/);
      expect(spec, `forbidden import ${spec}`).not.toMatch(/auth\/store/);
      expect(spec, `forbidden import ${spec}`).not.toMatch(/policy\/engine/);
    }
    const code = stripComments(source);
    for (const token of [
      "executePayment",
      "sendRawTransaction",
      "loadExecutorSigner",
      "createSignerFromPrivateKey",
      "ExecutionStore",
      "SqliteReplayStore",
      "MemoryReplayStore",
      "EXECUTOR_PRIVATE_KEY",
      "process.env",
      "signTransfer",
      "privateKey",
    ]) {
      expect(code, `forbidden token ${token}`).not.toContain(token);
    }
  });
});

describe("demo driver behavior (mock chain only)", () => {
  it("produces a labeled preflight preview with zero sends", async () => {
    const chain = new MockChainPort();
    const out = await runDemoPreview(args(), chain);
    expect(out.banner).toContain("NOT AUTHORIZATION TO EXECUTE");
    expect(out.preview.ok).toBe(true);
    if (!out.preview.ok) return;
    expect(out.preview.network).toBe("Monad Testnet");
    expect(out.preview.chainId).toBe(10143);
    expect(out.preview.amountWei).toBe("1000000000000000");
    expect(out.preview.policyDigest).toBe(
      computePolicyDigest(basePolicy({ approvedRecipients: [ADDR_A] })),
    );
    expect(chain.sendLog.length).toBe(0);
  });

  it("rejects non-distinct identities", async () => {
    const chain = new MockChainPort();
    for (const dup of [
      args({ approver: ADDR_A }),
      args({ sender: ADDR_A }),
      args({ sender: ADDR_B, approver: ADDR_B }),
      args({ recipient: ADDR_A.toLowerCase(), approver: ADDR_A.toUpperCase() }),
    ]) {
      const out = await runDemoPreview(dup, chain);
      expect(out.preview.ok).toBe(false);
    }
    expect(chain.sendLog.length).toBe(0);
  });

  it("rejects invalid/missing inputs and non-allowlisted recipients", async () => {
    const chain = new MockChainPort();
    const bad: DemoArgs[] = [
      args({ recipient: "not-an-address" }),
      args({ recipient: ADDR_B }),
      args({ amountWei: 0n }),
      args({ amountWei: 1_000_000_000_000_000_001n }),
      args({ amountWei: -5n }),
      args({ requestId: "" }),
    ];
    for (const b of bad) {
      const out = await runDemoPreview(b, chain);
      expect(out.preview.ok).toBe(false);
    }
    expect(chain.sendLog.length).toBe(0);
  });

  it("proof file loading is exercised without logging the signature", async () => {
    const approver = makeAccount();
    const policy = basePolicy({ approvedRecipients: [ADDR_A] });
    const authConfig = {
      policy,
      approver: approver.address,
      domainId: "agentpay-demo-v1",
      policyVersion: "m2.1",
    };
    const intent = {
      requestId: "demo-req-7",
      recipient: ADDR_A,
      amountWei: 1_000_000_000_000_000n,
      asset: "MON",
      purpose: "demo",
      chainId: 10143,
      nonce: "demo-nonce-7",
      expiresAt: NOW + 3600,
    } as const;
    const proof = await signApproval(approver, { ...intent }, authConfig);
    const { writeFileSync, mkdtempSync, rmSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join: joinPath } = await import("node:path");
    const dir = mkdtempSync(joinPath(tmpdir(), "agentpay-demo-"));
    try {
      const proofPath = joinPath(dir, "proof.json");
      writeFileSync(proofPath, JSON.stringify(proof));
      const chain = new MockChainPort();
      const out = await runDemoPreview(
        {
          ...args(),
          recipient: ADDR_A,
          approver: approver.address,
          sender: ADDR_C,
          allowlist: [ADDR_A],
          requestId: "demo-req-7",
          nonce: "demo-nonce-7",
          proofFile: proofPath,
        },
        chain,
      );
      expect(out.preview.ok).toBe(true);
      if (!out.preview.ok) return;
      expect(out.preview.approval).toEqual({ present: true, verified: true, approver: approver.address });
      // The signature itself appears nowhere in the output.
      expect(JSON.stringify(out)).not.toContain(proof.signature.slice(2, 42));
      expect(chain.sendLog.length).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("demo CLI duplicate flags (fail closed, no RPC)", () => {
  async function runArgv(argv: string[]): Promise<{ code: number; output: string }> {
    let output = "";
    const spy = vi.spyOn(process.stdout, "write").mockImplementation(((chunk: unknown) => {
      output += String(chunk);
      return true;
    }) as typeof process.stdout.write);
    try {
      const code = await main(argv);
      return { code, output };
    } finally {
      spy.mockRestore();
    }
  }

  const base = [
    "--recipient", ADDR_A,
    "--approver", ADDR_B,
    "--sender", ADDR_C,
  ];

  it("rejects duplicate --recipient even with identical values", async () => {
    const { code, output } = await runArgv([...base, "--recipient", ADDR_A]);
    expect(code).toBe(2);
    expect(output).toContain("duplicate flag --recipient");
    expect(output).not.toContain(ADDR_A.toLowerCase().slice(2, 18));
  });

  it("rejects duplicate --rpc-url and every other known flag", async () => {
    for (const flag of [
      "--recipient", "--approver", "--sender", "--allowlist", "--amount-wei",
      "--request-id", "--nonce", "--now", "--domain", "--policy-version",
      "--rpc-url", "--proof-file",
    ]) {
      const { code, output } = await runArgv([...base, flag, "x", flag, "y"]);
      expect(code, flag).toBe(2);
      expect(output, flag).toContain(`duplicate flag ${flag}`);
    }
  });

  it("rejects duplicates before any RPC access (no network possible)", async () => {
    // An unreachable RPC URL plus duplicates must still fail on duplicates
    // first — proving rejection precedes port construction, not RPC errors.
    const { code, output } = await runArgv([
      ...base,
      "--rpc-url", "http://127.0.0.1:9/unreachable",
      "--rpc-url", "http://127.0.0.1:9/unreachable",
    ]);
    expect(code).toBe(2);
    expect(output).toContain("duplicate flag --rpc-url");
    expect(output).not.toContain("127.0.0.1");
  });

  it("unknown flags and missing values still fail closed", async () => {
    const unknown = await runArgv([...base, "--execute"]);
    expect(unknown.code).toBe(2);
    const missing = await runArgv(["--recipient", ADDR_A]);
    expect(missing.code).toBe(2);
  });
});
