/**
 * Mock chain port for M3 tests. NEVER broadcasts. Records every send attempt
 * so tests can assert exact submission counts (the core anti-double-spend
 * property). Default send behavior mirrors a healthy node: returns the
 * keccak of the submitted bytes, like `eth_sendRawTransaction` does.
 */
import { keccak256, parseTransaction, type Address, type Hex } from "viem";
import type { ChainPort } from "../../src/execution/chain.js";

export type SendScript =
  | { kind: "ok" }
  | { kind: "definitive"; message?: string }
  | { kind: "ambiguous"; message?: string }
  | { kind: "accept-then-reject"; message?: string };

export class MockChainPort implements ChainPort {
  chainId = 10143;
  gas = 21_000n;
  fees = { maxFeePerGas: 1_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n };
  sendLog: Hex[] = [];
  receipts = new Map<string, { status: "success" | "reverted" }>();
  sendScript: SendScript[] = [];
  failReceiptWith: string | null = null;
  /** When set, send blocks on it (overlap control for concurrency tests). */
  gateSend: (() => Promise<void>) | null = null;
  /** When set, runs after accept-checks but before returning the hash
   * (lets tests interleave reconciliation mid-submission). */
  onSend: ((signedTx: Hex) => Promise<void>) | null = null;
  /**
   * Chain-truth nonce model: the next expected sender nonce equals the number
   * of accepted sends. Replays/gaps are definitively rejected — mirroring how
   * a node treats a reused sender nonce — so any implementation nonce reuse
   * surfaces as a retryable rejection, never a silent double-spend.
   */
  acceptedCount = 0;

  /** Configurable mock balance for preview headroom checks. */
  balance = 10_000_000_000_000_000_000n;
  /** When set, estimateTransferGas throws this (gas-estimation failure path). */
  failEstimateWith: Error | null = null;

  async getChainId(): Promise<number> {
    return this.chainId;
  }

  async getSenderNonce(_sender: Address): Promise<number> {
    return this.acceptedCount;
  }

  async getBalance(_address: Address): Promise<bigint> {
    return this.balance;
  }

  async estimateTransferGas(_to: Address, _value: bigint, _from: Address): Promise<bigint> {
    if (this.failEstimateWith !== null) throw this.failEstimateWith;
    return this.gas;
  }

  async estimateFees(): Promise<{ maxFeePerGas: bigint; maxPriorityFeePerGas: bigint }> {
    return { ...this.fees };
  }

  async sendRawTransaction(signedTx: Hex): Promise<Hex> {
    this.sendLog.push(signedTx);
    const step = this.sendScript.shift() ?? { kind: "ok" as const };
    if (step.kind === "ambiguous") {
      const err = new Error(step.message ?? "request timed out");
      err.name = "TimeoutError";
      throw err;
    }
    if (step.kind === "definitive") {
      throw new Error(step.message ?? "insufficient funds for gas");
    }
    if (step.kind === "accept-then-reject") {
      // False-negative transport: the node ACCEPTS (chain-observable) but
      // the transport reports a rejection-shaped error. Must be treated as
      // UNKNOWN by correct implementations, never as proof of non-acceptance.
      const nonce = parseTransaction(signedTx).nonce;
      if (nonce !== this.acceptedCount) {
        throw new Error(`sender nonce already used or gap: got ${nonce}, chain has ${this.acceptedCount}`);
      }
      this.acceptedCount += 1;
      const hash = keccak256(signedTx);
      this.receipts.set(hash.toLowerCase(), { status: "success" });
      throw new Error(step.message ?? "rejected after acceptance");
    }
    if (this.gateSend) await this.gateSend();
    const nonce = parseTransaction(signedTx).nonce;
    if (nonce !== this.acceptedCount) {
      throw new Error(`sender nonce already used or gap: got ${nonce}, chain has ${this.acceptedCount}`);
    }
    this.acceptedCount += 1;
    if (this.onSend) await this.onSend(signedTx);
    return keccak256(signedTx);
  }

  async getReceipt(txHash: Hex): Promise<{ status: "success" | "reverted" } | null> {
    if (this.failReceiptWith !== null) throw new Error(this.failReceiptWith);
    return this.receipts.get(txHash.toLowerCase()) ?? null;
  }
}
