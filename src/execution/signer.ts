/**
 * Executor signer boundary — Oracle69 AgentPay M3.
 *
 * RULES:
 * - Key material enters ONLY via an explicit environment mapping
 *   (`EXECUTOR_PRIVATE_KEY`, 0x-prefixed 64-hex). Never hardcoded, never
 *   logged, never returned in decisions, never persisted.
 * - The key is validated and the sender address derived up front; execution
 *   is refused without a usable signer (fail closed).
 * - Tests MUST NOT use this loader with real keys: they build signers from
 *   runtime-generated keys via `createSignerFromPrivateKey` (documented
 *   test-only usage pattern; the function itself is key-agnostic).
 * - Signing is local: the transaction hash is therefore knowable BEFORE
 *   broadcast for a particular signing result, which is what makes the
 *   pre-send hash record (and safe reconciliation) possible. Note signing is
 *   NOT deterministic across calls — ECDSA uses fresh randomness per
 *   signature, so re-signing the same transfer yields different bytes and a
 *   different hash. Recovery paths must never assume a re-signed transaction
 *   reproduces an earlier hash; the recorded hash always refers to the exact
 *   bytes of one signing event.
 */
import { privateKeyToAccount, type PrivateKeyAccount } from "viem/accounts";
import { isHex, type Address, type Hex } from "viem";
import type { UnsignedTransfer } from "./chain.js";

export const SIGNER_ENV_VAR = "EXECUTOR_PRIVATE_KEY";

export class SignerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SignerError";
  }
}

export interface ExecutorSigner {
  readonly address: Address;
  signTransfer(tx: UnsignedTransfer): Promise<Hex>;
}

export function createSignerFromPrivateKey(keyHex: string): ExecutorSigner {
  if (typeof keyHex !== "string" || !isHex(keyHex) || keyHex.length !== 66) {
    throw new SignerError("signer key must be 0x hex of 32 bytes");
  }
  let account: PrivateKeyAccount;
  try {
    account = privateKeyToAccount(keyHex as Hex);
  } catch {
    throw new SignerError("signer key is not a valid secp256k1 private key");
  }
  return {
    address: account.address,
    signTransfer: (tx: UnsignedTransfer): Promise<Hex> =>
      account.signTransaction({
        to: tx.to,
        value: tx.value,
        chainId: tx.chainId,
        nonce: tx.nonce,
        gas: tx.gas,
        maxFeePerGas: tx.maxFeePerGas,
        maxPriorityFeePerGas: tx.maxPriorityFeePerGas,
        type: "eip1559",
      }),
  };
}

/** Production loader: reads ONLY the documented env var. Throws when absent/invalid. */
export function loadExecutorSigner(env: NodeJS.ProcessEnv = process.env): ExecutorSigner {
  const raw = env[SIGNER_ENV_VAR];
  if (typeof raw !== "string" || raw.length === 0) {
    throw new SignerError("executor signer is not configured");
  }
  return createSignerFromPrivateKey(raw.trim());
}
