/**
 * M3 execution types — Oracle69 AgentPay.
 *
 * SECURITY MODEL:
 * - Execution NEVER trusts a previously returned `authorized: true` value, a
 *   cached policy decision, or a client approval flag. Every execution
 *   attempt re-runs full verification (policy + EIP-712 signature + digest +
 *   domain + expiry) against CURRENT trusted configuration via M2's pure
 *   `verifyAuthorization`, then reserves single-use in its own executions
 *   table. M2's claim ledger is never re-redeemed by this path.
 * - `submitted: true` means bytes were accepted by the node (hash returned),
 *   NOT that funds moved. Settlement is established only by receipt
 *   reconciliation (`CONFIRMED`). No exactly-once submission is claimed.
 */
import type { AuthRejectionCode } from "../auth/types.js";

/** Monad Testnet chain ID. No other chain is representable in M3. */
export const EXPECTED_CHAIN_ID = 10143;

/** Primary Testnet RPC. */
export const PRIMARY_RPC_URL = "https://testnet-rpc.monad.xyz";

/** Fallback Testnet RPC. */
export const FALLBACK_RPC_URL = "https://rpc-testnet.monadinfra.com";

/** The ONLY RPC URLs M3 will ever talk to. There is deliberately no mainnet entry. */
export const ALLOWED_RPC_URLS: readonly string[] = [PRIMARY_RPC_URL, FALLBACK_RPC_URL];

/** Native currency symbol. Only MON transfers are supported. */
export const NATIVE_ASSET = "MON";

/**
 * Trusted server-side fee caps (Testnet MVP). Units are wei; all arithmetic
 * is exact bigint. Rationale: Monad Testnet minimum base fee is 100 gwei
 * (official docs, gas pricing); 500 gwei (5x floor) absorbs spikes while
 * bounding fee drain from a misbehaving estimator to 0.05 MON per attempt
 * (100k gas * 500 gwei). Native transfers cost ~21k gas; 100k is ~5x
 * headroom. These are CODE constants — never caller-supplied — so a
 * malicious RPC cannot lift them. No mainnet values exist.
 */
export const MAX_FEE_PER_GAS_WEI = 500_000_000_000n;
export const MAX_TX_GAS = 100_000n;
export const MAX_TOTAL_FEE_WEI = MAX_TX_GAS * MAX_FEE_PER_GAS_WEI;

/**
 * Single-payer send serialization. One in-flight send per payer address;
 * the lease is held from send-right acquisition through send initiation
 * (UNKNOWN/SENT recorded) or definitive failure, then released. A crashed
 * holder in SENDING older than this grace is presumed dead and its lease is
 * stealable (wrong-steal cost is bounded: a retryable node rejection, never
 * a double-spend — the chain admits one transaction per sender nonce).
 * Single-host SQLite deployment only, like the rest of M3 state.
 */
export const PAYER_LEASE_SENDING_GRACE_S = 300;

export type ExecutionState =
  | "RESERVED" // verified + row created; nothing sent; retryable (re-verify first)
  | "SENDING" // send right held by exactly one caller; submission uncertain; recovery treats as UNKNOWN
  | "UNKNOWN" // send attempted, outcome ambiguous; NEVER auto-resend; reconcile by hash only
  | "SENT" // node returned a matching hash; reconcile receipt only, never resend
  | "CONFIRMED" // receipt status success; terminal
  | "REVERTED" // receipt status failure; terminal for these identifiers
  | "STALE"; // policy/signature no longer verifies on retry; terminal, never send

export interface ExecutionRecord {
  requestId: string;
  nonce: string;
  recipient: string;
  amountWei: string;
  asset: string;
  chainId: number;
  expiresAt: number;
  policyDigest: string;
  approver: string;
  domainId: string;
  policyVersion: string;
  state: ExecutionState;
  txHash: string | null;
  senderNonce: number | null;
  attempts: number;
  createdAt: number;
  updatedAt: number;
  lastError: string | null;
}

export type ExecRejectionCode =
  | AuthRejectionCode
  | "EXEC_DUPLICATE"
  | "EXEC_CONFLICT"
  | "EXEC_SIGNER_UNAVAILABLE"
  | "EXEC_CHAIN_MISMATCH"
  | "EXEC_SEND_FAILED"
  | "EXEC_UNKNOWN_OUTCOME"
  | "EXEC_NOT_FOUND"
  | "EXEC_NO_SUBMISSION"
  | "EXEC_PAYER_BUSY"
  | "EXEC_FENCE_LOST";

export interface ExecReason {
  code: ExecRejectionCode;
  message: string;
}

export type ExecuteDecision =
  | {
      submitted: true;
      requestId: string;
      txHash: string;
      /** Row state after recording: normally SENT; CONFIRMED if a concurrent
       * reconciliation already observed the receipt (never regressed). */
      state: ExecutionState;
      attempts: number;
    }
  | { submitted: false; state: ExecutionState | "NONE"; reasons: ExecReason[] };

export type ReconcileDecision =
  | { reconciled: true; requestId: string; state: ExecutionState; txHash: string | null }
  | { reconciled: false; requestId: string; state: ExecutionState | "NONE"; reasons: ExecReason[] };
