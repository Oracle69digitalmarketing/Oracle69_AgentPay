/**
 * P0 regression: RPC error sanitization. All payloads are synthetic
 * (repeating patterns, never real signed material). Proves that long hex
 * payloads and JSON-RPC request bodies never survive into decisions or
 * persisted fields, while classification (ambiguous vs definitive) is
 * preserved.
 */
import { describe, expect, it } from "vitest";
import { sanitizeDetail, safeSendError } from "../../src/execution/errors.js";
import { executePayment, reconcileExecution } from "../../src/execution/execute.js";
import type { ExecRejectionCode, ExecuteDecision } from "../../src/execution/types.js";
import { NOW, baseExecIntent, execFixture, signApproval } from "./helpers.js";

function codesOf(d: ExecuteDecision): ExecRejectionCode[] {
  return d.submitted ? [] : d.reasons.map((r) => r.code);
}

const PAYLOAD = "0x" + "ab12".repeat(60); // 240 synthetic hex chars
const PAYLOAD_UPPER = PAYLOAD.toUpperCase();
const LONG_HEX_RE = /0x[0-9a-fA-F]{100,}/;

function timeoutWithBody(bodyVariant: string, trailing: string): Error {
  const err = new Error(
    `The request took too long to respond. Request body: ${bodyVariant} ${trailing}`,
  );
  err.name = "TimeoutError";
  return err;
}

describe("error sanitization", () => {
  it("strips a JSON-RPC body with a signed-tx-like payload but keeps diagnostics", () => {
    const body = `{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["${PAYLOAD}"]}`;
    const out = sanitizeDetail(timeoutWithBody(body, "node: testnet-rpc"));
    expect(out).not.toContain(PAYLOAD);
    expect(out).not.toMatch(LONG_HEX_RE);
    expect(out).not.toMatch(/request\s*body\s*:\s*\{/i);
    expect(out).toContain("node: testnet-rpc");
  });

  it("handles uppercase hex and varied whitespace/capitalization", () => {
    const err = new Error(`boom.   REQUEST\tBODY  : {"params":["${PAYLOAD_UPPER}"]} tail-marker`);
    const out = sanitizeDetail(err);
    expect(out).not.toContain(PAYLOAD_UPPER);
    expect(out).not.toMatch(LONG_HEX_RE);
    expect(out).toContain("tail-marker");
  });

  it("preserves short diagnostic hashes/addresses and bounds length", () => {
    const hash64 = "0x" + "cd".repeat(32);
    const addr40 = "0x1111111111111111111111111111111111111111";
    const out = sanitizeDetail(new Error(`receipt ${hash64} for ${addr40} missing`));
    expect(out).toContain(hash64);
    expect(out).toContain(addr40);
    // A 65-byte authorization signature (130 hex chars) is redacted too.
    const sig130 = "0x" + "ef".repeat(65);
    expect(sanitizeDetail(new Error(`sig ${sig130} rejected`))).not.toContain(sig130);
    const huge = sanitizeDetail(new Error("x".repeat(5000)));
    expect(huge.length).toBeLessThanOrEqual(300);
    expect(sanitizeDetail(null)).toBe("unavailable");
    expect(sanitizeDetail(undefined)).toBe("unavailable");
  });

  it("classifies ambiguous vs definitive on raw signals, sanitizes both", () => {
    const amb = safeSendError(timeoutWithBody(`{"params":["${PAYLOAD}"]}`, "t"));
    expect(amb.ambiguous).toBe(true);
    expect(amb.error.category).toBe("RPC_TIMEOUT");
    expect(JSON.stringify(amb)).not.toContain(PAYLOAD);
    const def = safeSendError(new Error(`rejected. Request body: {"params":["${PAYLOAD}"]}`));
    expect(def.ambiguous).toBe(false);
    expect(def.error.category).toBe("RPC_REJECTED");
    expect(JSON.stringify(def)).not.toContain(PAYLOAD);
  });

  it("ambiguous send failure with hostile error text stays UNKNOWN without leaking", async () => {
    const fx = execFixture();
    const body = `{"method":"eth_sendRawTransaction","params":["${PAYLOAD}"]}`;
    fx.chain.sendScript.push({ kind: "ambiguous", message: `timeout. Request body: ${body} diag-7` });
    const intent = baseExecIntent();
    const proof = await signApproval(fx.approver, intent, fx.authConfig);
    const run = {
      intent, proof, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    };
    const d = await executePayment(run);
    expect(d.submitted).toBe(false);
    if (!d.submitted) {
      expect(d.state).toBe("UNKNOWN");
      expect(JSON.stringify(d)).not.toContain(PAYLOAD);
      expect(JSON.stringify(d)).not.toMatch(LONG_HEX_RE);
    }
    // No-resubmit preserved: retry duplicates without a second send.
    const retry = await executePayment(run);
    expect(retry.submitted).toBe(false);
    expect(fx.chain.sendLog.length).toBe(1);
    fx.execStore.close();
  });

  it("post-handoff rejection-shaped errors become UNKNOWN with clean records", async () => {
    const fx = execFixture();
    fx.chain.sendScript.push({ kind: "definitive", message: `rejected. Request body: {"params":["${PAYLOAD_UPPER}"]} end` });
    const intent = baseExecIntent();
    const proof = await signApproval(fx.approver, intent, fx.authConfig);
    const run = {
      intent, proof, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    };
    // P0: post-handoff shape proves nothing — UNKNOWN, never RESERVED-resend.
    const first = await executePayment(run);
    expect(first.submitted).toBe(false);
    if (!first.submitted) {
      expect(first.state).toBe("UNKNOWN");
      expect(codesOf(first)).toContain("EXEC_UNKNOWN_OUTCOME");
    }
    const stored = fx.execStore.get("req-x001")?.lastError ?? "";
    expect(stored).not.toContain(PAYLOAD_UPPER);
    expect(stored).not.toMatch(LONG_HEX_RE);
    expect(JSON.stringify(first)).not.toContain(PAYLOAD_UPPER);
    // Category preserved for diagnostics (rejection-shaped, not timeout).
    expect(JSON.stringify(first)).toContain("RPC_REJECTED");
    // No automatic resend on retry.
    const second = await executePayment(run);
    expect(second.submitted).toBe(false);
    expect(fx.chain.sendLog.length).toBe(1);
    fx.execStore.close();
  });

  it("P0: false-negative transport (accepted, then rejection-shaped error)", async () => {
    const fx = execFixture();
    fx.chain.sendScript.push({ kind: "accept-then-reject", message: "rejected after acceptance" });
    const intent = baseExecIntent();
    const proof = await signApproval(fx.approver, intent, fx.authConfig);
    const run = {
      intent, proof, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    };
    // 1-5: accepted internally, error reported, execution lands UNKNOWN.
    const first = await executePayment(run);
    expect(first.submitted).toBe(false);
    if (!first.submitted) expect(first.state).toBe("UNKNOWN");
    expect(fx.chain.acceptedCount).toBe(1);
    expect(fx.chain.sendLog.length).toBe(1);
    const recorded = fx.execStore.get("req-x001")?.txHash;
    expect(recorded).not.toBeNull();
    // 6-7: retry submits nothing new.
    const retry = await executePayment(run);
    expect(retry.submitted).toBe(false);
    expect(fx.chain.sendLog.length).toBe(1);
    expect(fx.chain.acceptedCount).toBe(1);
    // 8: the recorded hash reconciles the ORIGINAL transaction.
    const rec = await reconcileExecution({
      requestId: "req-x001", execStore: fx.execStore, chain: fx.chain, now: NOW + 60,
    });
    expect(rec.reconciled).toBe(true);
    if (rec.reconciled) {
      expect(rec.state).toBe("CONFIRMED");
      expect(rec.txHash).toBe(recorded);
    }
    fx.execStore.close();
  });

  it("P0: rejection with proven non-acceptance still never auto-resends", async () => {
    const fx = execFixture();
    fx.chain.sendScript.push({ kind: "definitive", message: "rejected before acceptance" });
    const intent = baseExecIntent();
    const proof = await signApproval(fx.approver, intent, fx.authConfig);
    const run = {
      intent, proof, authConfig: fx.authConfig, execConfig: fx.execConfig,
      now: NOW, execStore: fx.execStore, chain: fx.chain,
    };
    const first = await executePayment(run);
    expect(first.submitted).toBe(false);
    if (!first.submitted) expect(first.state).toBe("UNKNOWN");
    // The mock confirms NOTHING was accepted, yet the system must not resend:
    // acceptance is unprovable from the caller's side of the transport.
    expect(fx.chain.acceptedCount).toBe(0);
    const retry = await executePayment(run);
    expect(retry.submitted).toBe(false);
    expect(fx.chain.sendLog.length).toBe(1);
    fx.execStore.close();
  });
});
