/**
 * Read-only Testnet transaction preview — Oracle69 AgentPay.
 *
 * HARD BOUNDARIES (structural, not just conventional):
 * - This module imports NO execution capability: no `executePayment`, no
 *   `sendRawTransaction` (not even as a type — the local ReadOnlyChain
 *   interface omits it, so a port WITHOUT a send method typechecks and a
 *   test proves a send-less port suffices), no signer, no stores.
 * - It NEVER loads a private key: the sender is an operator-supplied PUBLIC
 *   address string used only for display, nonce, gas, and balance reads.
 * - It NEVER consumes replay state: approval verification uses M2's pure
 *   `verifyAuthorization` (no store interaction), so a previewed approval
 *   remains fully usable afterwards.
 * - It NEVER creates an executable authorization: output is a display-only
 *   preview object. There is deliberately no path from here to submission.
 * - Amount math stays exact bigint wei. Human-readable MON strings are
 *   display-only (viem formatEther produces exact decimal strings, never
 *   binary floats) and never feed decisions.
 */
import { formatEther, getAddress, isAddress, type Address, type Hex } from "viem";
import { evaluatePolicy } from "../policy/engine.js";
import { validateConfig } from "../policy/validation.js";
import {
  ABSOLUTE_MAX_PAYMENT_WEI,
  MONAD_TESTNET_CHAIN_ID,
  type PolicyConfig,
} from "../policy/types.js";
import { computePolicyDigest } from "../auth/policy-digest.js";
import { verifyAuthorization } from "../auth/verify.js";
import type { ServerAuthConfig } from "../auth/types.js";
import { checkFeePolicy } from "../execution/fee-policy.js";
import { EXPECTED_CHAIN_ID } from "../execution/types.js";

/** Minimal read surface. Deliberately excludes sendRawTransaction. */
export interface ReadOnlyChain {
  getChainId(): Promise<number>;
  getSenderNonce(sender: Address): Promise<number>;
  getBalance(address: Address): Promise<bigint>;
  estimateTransferGas(to: Address, value: bigint, from: Address): Promise<bigint>;
  estimateFees(): Promise<{ maxFeePerGas: bigint; maxPriorityFeePerGas: bigint }>;
  getReceipt(txHash: Hex): Promise<{ status: "success" | "reverted" } | null>;
}

export interface PreviewInput {
  intent: unknown;
  /** Optional externally created proof; verified purely, never consumed. */
  proof?: unknown;
  authConfig: unknown;
  /** Operator-supplied PUBLIC sender address (display + reads only). */
  senderAddress: unknown;
  now: unknown;
  chain: unknown;
}

export interface PreviewChainData {
  chainId: number;
  senderNonce: number;
  senderBalanceWei: string;
  gasEstimate: string;
  maxFeePerGasWei: string;
  maxPriorityFeePerGasWei: string;
}

export type PreviewResult =
  | {
      /**
       * ok: true means EVERY mandatory preview check passed: valid policy
       * within the absolute ceiling, valid approval when supplied, correct
       * Testnet chain, fee policy satisfied, and balance sufficient. It is
       * informational readiness only — NEVER authorization to execute or
       * permission to broadcast.
       */
      ok: true;
      network: "Monad Testnet";
      chainId: number;
      sender: string;
      recipient: string;
      asset: "MON";
      amountWei: string;
      amountMonDisplay: string;
      policyVersion: string;
      policyDigest: string;
      requestId: string;
      nonce: string;
      approval: { present: boolean; verified: boolean; approver: string | null };
      chain: PreviewChainData;
      feeCheck: string | null;
      affordable: boolean;
    }
  | { ok: false; reasons: Array<{ code: string; message: string }> };

function fail(code: string, message: string): PreviewResult {
  return { ok: false, reasons: [{ code, message }] };
}

export async function previewTransaction(input: PreviewInput): Promise<PreviewResult> {
  const { intent, proof, authConfig, senderAddress: senderRaw, now: nowRaw, chain: chainRaw } = input;

  if (typeof senderRaw !== "string" || !isAddress(senderRaw)) {
    return fail("INVALID_REQUEST", "senderAddress must be a valid public EVM address");
  }
  const sender = getAddress(senderRaw);
  if (typeof nowRaw !== "number" || !Number.isInteger(nowRaw) || !Number.isFinite(nowRaw) || (nowRaw as number) < 0) {
    return fail("INVALID_REQUEST", "now must be a non-negative integer unix timestamp");
  }
  const now = nowRaw as number;
  if (
    typeof chainRaw !== "object" ||
    chainRaw === null ||
    typeof (chainRaw as { getChainId?: unknown }).getChainId !== "function" ||
    typeof (chainRaw as { getSenderNonce?: unknown }).getSenderNonce !== "function" ||
    typeof (chainRaw as { getBalance?: unknown }).getBalance !== "function" ||
    typeof (chainRaw as { estimateTransferGas?: unknown }).estimateTransferGas !== "function" ||
    typeof (chainRaw as { estimateFees?: unknown }).estimateFees !== "function"
  ) {
    return fail("INVALID_CONFIG", "chain port is misconfigured");
  }
  const chain = chainRaw as ReadOnlyChain;

  if (
    typeof authConfig !== "object" ||
    authConfig === null ||
    Array.isArray(authConfig)
  ) {
    return fail("INVALID_CONFIG", "auth config must be an object");
  }
  const cfg = authConfig as Record<string, unknown> & Partial<ServerAuthConfig>;
  const policy = cfg["policy"] as PolicyConfig | undefined;

  // Policy shape + absolute ceiling, reported (not executed).
  const configProblems = validateConfig(policy);
  if (configProblems.length > 0) {
    return { ok: false, reasons: configProblems.map((r) => ({ code: r.code, message: r.message })) };
  }
  const digest = computePolicyDigest(policy as PolicyConfig);

  // Pure policy evaluation (informational; approval flag unread from caller).
  const policyDecision = evaluatePolicy(intent, policy, { now, humanApprovalVerified: false });
  const reasons: Array<{ code: string; message: string }> = [];
  if (!policyDecision.allowed) {
    for (const r of policyDecision.reasons) {
      if (r.code !== "MISSING_APPROVAL") reasons.push({ code: r.code, message: r.message });
    }
    if (reasons.length > 0) return { ok: false, reasons };
  }

  // Optional approval verification: pure, never consumes replay state.
  let approval = { present: proof !== undefined, verified: false, approver: null as string | null };
  let snapshotFields: { requestId: string; recipient: string; amountWei: bigint; asset: "MON"; chainId: number; nonce: string; expiresAt: number } | null = null;
  if (proof !== undefined) {
    const v = await verifyAuthorization({ intent, proof, config: authConfig, now });
    if (!v.ok) {
      return { ok: false, reasons: v.reasons.map((r) => ({ code: r.code, message: r.message })) };
    }
    approval = { present: true, verified: true, approver: v.approver };
    snapshotFields = {
      requestId: v.snapshot.requestId,
      recipient: v.snapshot.recipient,
      amountWei: v.snapshot.amountWei,
      asset: v.snapshot.asset,
      chainId: v.snapshot.chainId,
      nonce: v.snapshot.nonce,
      expiresAt: v.snapshot.expiresAt,
    };
  } else {
    // Without a proof, echo policy-validated intent fields for display only.
    // These are NOT an authorization and must never be treated as one.
    const raw = intent as Record<string, unknown>;
    if (
      typeof raw["requestId"] !== "string" ||
      typeof raw["recipient"] !== "string" ||
      !isAddress(raw["recipient"] as string) ||
      typeof raw["amountWei"] !== "bigint" ||
      raw["asset"] !== "MON" ||
      typeof raw["chainId"] !== "number" ||
      typeof raw["nonce"] !== "string" ||
      typeof raw["expiresAt"] !== "number"
    ) {
      return fail("INVALID_REQUEST", "intent fields malformed for preview");
    }
    snapshotFields = {
      requestId: raw["requestId"] as string,
      recipient: getAddress(raw["recipient"] as string),
      amountWei: raw["amountWei"] as bigint,
      asset: "MON",
      chainId: raw["chainId"] as number,
      nonce: raw["nonce"] as string,
      expiresAt: raw["expiresAt"] as number,
    };
  }
  if (snapshotFields === null) return fail("INVALID_REQUEST", "no previewable intent");
  if (snapshotFields.amountWei > ABSOLUTE_MAX_PAYMENT_WEI) {
    return fail("EXCEEDS_LIMIT", "preview amount exceeds the absolute 1 MON ceiling");
  }

  // Read-only chain data. No submission method exists on this path.
  // Reads are staged so a gas-estimation failure can be classified precisely:
  // chain identity/nonce/balance first (connectivity-sensitive), estimation
  // second. If estimation throws, the already-retrieved balance decides:
  // balance < amount proves the value transfer is unfundable regardless of
  // gas (INSUFFICIENT_FUNDS); otherwise the cause is genuinely unknown
  // (ESTIMATION_FAILED). Never match on error text or messages.
  // Limitation: balance < amount establishes the payment cannot be funded
  // from the observed balance, but balance >= amount does NOT prove
  // affordability, because fees are additional — that case stays failed-
  // closed as ESTIMATION_FAILED.
  let chainId: number;
  let senderNonce: number;
  let balance: bigint;
  try {
    chainId = await chain.getChainId();
    senderNonce = await chain.getSenderNonce(sender);
    balance = await chain.getBalance(sender);
  } catch {
    return fail("RPC_UNAVAILABLE", "read-only chain query failed");
  }
  if (chainId !== EXPECTED_CHAIN_ID || chainId !== MONAD_TESTNET_CHAIN_ID) {
    return fail("WRONG_CHAIN", "connected chain is not Monad Testnet");
  }
  let gas: bigint;
  let fees: { maxFeePerGas: bigint; maxPriorityFeePerGas: bigint };
  try {
    gas = await chain.estimateTransferGas(snapshotFields.recipient as Address, snapshotFields.amountWei, sender);
    fees = await chain.estimateFees();
  } catch {
    if (balance < snapshotFields.amountWei) {
      return fail(
        "INSUFFICIENT_FUNDS",
        `insufficient balance: have ${balance.toString()} wei, need at least ${snapshotFields.amountWei.toString()} wei plus fees (gas estimation unavailable)`,
      );
    }
    return fail("ESTIMATION_FAILED", "gas estimation failed and fee coverage cannot be established");
  }
  const feeProblem = checkFeePolicy(gas, fees);
  // LOW-1 fix: `ok: true` means EVERY mandatory check passed, including fee
  // policy and balance sufficiency. A fee violation or shortfall fails closed
  // here with diagnostics — never as a ready-looking preview.
  if (feeProblem !== null) {
    return fail("FEE_POLICY_REJECTED", `fee policy rejected: ${feeProblem}`);
  }
  let affordable = false;
  try {
    const totalFee = gas * (fees as { maxFeePerGas: bigint }).maxFeePerGas;
    affordable = balance >= snapshotFields.amountWei + totalFee;
    if (!affordable) {
      return fail(
        "INSUFFICIENT_FUNDS",
        `insufficient balance: need ${snapshotFields.amountWei.toString()} wei plus ${totalFee.toString()} wei fee, have ${balance.toString()} wei`,
      );
    }
  } catch {
    return fail("FEE_POLICY_REJECTED", "could not evaluate fee affordability");
  }

  return {
    ok: true,
    network: "Monad Testnet",
    chainId,
    sender,
    recipient: snapshotFields.recipient,
    asset: "MON",
    amountWei: snapshotFields.amountWei.toString(),
    amountMonDisplay: formatEther(snapshotFields.amountWei),
    policyVersion: typeof cfg["policyVersion"] === "string" ? (cfg["policyVersion"] as string) : "unknown",
    policyDigest: digest,
    requestId: snapshotFields.requestId,
    nonce: snapshotFields.nonce,
    approval,
    chain: {
      chainId,
      senderNonce,
      senderBalanceWei: balance.toString(),
      gasEstimate: gas.toString(),
      maxFeePerGasWei: (fees as { maxFeePerGas: bigint }).maxFeePerGas.toString(),
      maxPriorityFeePerGasWei: (fees as { maxPriorityFeePerGas: bigint }).maxPriorityFeePerGas.toString(),
    },
    feeCheck: feeProblem,
    affordable,
  };
}
