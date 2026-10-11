/**
 * Chain port — Oracle69 AgentPay M3.
 *
 * `ChainPort` is the ONLY channel to the outside world. Production uses
 * `ViemChainAdapter` (viem, Monad Testnet only); every ordinary test uses a
 * mock. No test may broadcast.
 *
 * ERROR CLASSIFICATION (heuristic, documented limitation): viem surfaces
 * transport timeouts/aborts as errors whose names/messages indicate ambiguity
 * (the bytes may have reached the node). Explicit node rejections (validation,
 * insufficient funds, gas estimation) mean the node responded WITHOUT
 * accepting the transaction, so retry is safe. A hostile or broken proxy that
 * returns errors for accepted transactions would break this assumption — the
 * design stays conservative by treating anything timeout/network-shaped as
 * ambiguous and requiring UNKNOWN-state reconciliation.
 */
import {
  createPublicClient,
  createWalletClient,
  http,
  keccak256,
  type Address,
  type Hex,
} from "viem";
import { monadTestnet } from "viem/chains";
import {
  ALLOWED_RPC_URLS,
  EXPECTED_CHAIN_ID,
  PRIMARY_RPC_URL,
} from "./types.js";

export interface UnsignedTransfer {
  to: Address;
  value: bigint;
  chainId: number;
  nonce: number;
  gas: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
}

export interface ChainPort {
  /** Chain ID the port is actually connected to. Checked against testnet. */
  getChainId(): Promise<number>;
  getSenderNonce(sender: Address): Promise<number>;
  /** Read-only balance query (no state change, no submission). */
  getBalance(address: Address): Promise<bigint>;
  estimateTransferGas(to: Address, value: bigint, from: Address): Promise<bigint>;
  estimateFees(): Promise<{ maxFeePerGas: bigint; maxPriorityFeePerGas: bigint }>;
  sendRawTransaction(signedTx: Hex): Promise<Hex>;
  getReceipt(txHash: Hex): Promise<{ status: "success" | "reverted" } | null>;
}

/** True when the send outcome is ambiguous (bytes may have been broadcast). */
export function isAmbiguousSendError(err: unknown): boolean {
  const name = err instanceof Error ? err.name : "";
  const msg = err instanceof Error ? err.message : String(err);
  if (/TimeoutError|AbortError/i.test(name)) return true;
  return /timed?\s*out|timeout|abort|ECONNRESET|ENOTFOUND|EAI_AGAIN|EPIPE|socket\s*hang\s*up|network|fetch\s*failed|Failed to fetch/i.test(
    msg,
  );
}

export function assertTestnetUrl(rpcUrl: string): void {
  if (!(ALLOWED_RPC_URLS as readonly string[]).includes(rpcUrl)) {
    throw new Error("refusing non-allowlisted RPC URL");
  }
}

export class ViemChainAdapter implements ChainPort {
  private readonly publicClient;
  private readonly walletClient;

  constructor(rpcUrl: string = PRIMARY_RPC_URL) {
    assertTestnetUrl(rpcUrl);
    if (monadTestnet.id !== EXPECTED_CHAIN_ID) {
      throw new Error("viem Monad Testnet definition drifted; failing closed");
    }
    const chain = { ...monadTestnet, rpcUrls: { default: { http: [rpcUrl] }, public: { http: [rpcUrl] } } };
    const transport = http(rpcUrl);
    this.publicClient = createPublicClient({ chain, transport });
    this.walletClient = createWalletClient({ chain, transport });
  }

  async getChainId(): Promise<number> {
    return this.publicClient.getChainId();
  }

  async getSenderNonce(sender: Address): Promise<number> {
    return this.publicClient.getTransactionCount({ address: sender });
  }

  async getBalance(address: Address): Promise<bigint> {
    return this.publicClient.getBalance({ address });
  }

  async estimateTransferGas(to: Address, value: bigint, from: Address): Promise<bigint> {
    return this.publicClient.estimateGas({ to, value, account: from });
  }

  async estimateFees(): Promise<{ maxFeePerGas: bigint; maxPriorityFeePerGas: bigint }> {
    const fees = await this.publicClient.estimateFeesPerGas();
    if (fees.maxFeePerGas === undefined || fees.maxPriorityFeePerGas === undefined) {
      throw new Error("fee estimation unavailable");
    }
    return { maxFeePerGas: fees.maxFeePerGas, maxPriorityFeePerGas: fees.maxPriorityFeePerGas };
  }

  async sendRawTransaction(signedTx: Hex): Promise<Hex> {
    return this.walletClient.sendRawTransaction({ serializedTransaction: signedTx });
  }

  async getReceipt(txHash: Hex): Promise<{ status: "success" | "reverted" } | null> {
    let receipt;
    try {
      receipt = await this.publicClient.getTransactionReceipt({ hash: txHash });
    } catch (err) {
      // viem throws TransactionReceiptNotFoundError when no receipt exists
      // yet; that is "pending", not failure. Anything else propagates.
      if (err instanceof Error && err.name === "TransactionReceiptNotFoundError") return null;
      throw err;
    }
    if (receipt === null || receipt === undefined) return null;
    return receipt.status === "success" ? { status: "success" } : { status: "reverted" };
  }
}

export function hashSignedTransaction(signedTx: Hex): Hex {
  return keccak256(signedTx);
}
