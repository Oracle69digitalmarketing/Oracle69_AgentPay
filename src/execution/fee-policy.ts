/**
 * Trusted fee policy — Oracle69 AgentPay (shared by execution and preview).
 *
 * Exact bigint wei arithmetic; no floats. Lives here (not inside
 * execute.ts) so the read-only preview can reuse the IDENTICAL rule without
 * importing the execution module. There is exactly one implementation.
 */
import { isPlainObject } from "../policy/validation.js";
import {
  MAX_FEE_PER_GAS_WEI,
  MAX_TOTAL_FEE_WEI,
  MAX_TX_GAS,
} from "./types.js";

/**
 * Returns null when estimates satisfy policy, else a human-readable reason.
 * Pure; no I/O. Callers treat any non-null result as a definitive
 * pre-submit failure (the node was never touched in the execution path).
 */
export function checkFeePolicy(gas: unknown, fees: unknown): string | null {
  if (typeof gas !== "bigint" || gas <= 0n) return "gas estimate must be a positive bigint";
  if (gas > MAX_TX_GAS) return `gas estimate ${gas.toString()} exceeds maximum ${MAX_TX_GAS.toString()}`;
  if (!isPlainObject(fees)) return "fee estimate must be an object";
  const f = fees as Record<string, unknown>;
  if (typeof f["maxFeePerGas"] !== "bigint" || (f["maxFeePerGas"] as bigint) <= 0n) {
    return "maxFeePerGas must be a positive bigint";
  }
  if (typeof f["maxPriorityFeePerGas"] !== "bigint" || (f["maxPriorityFeePerGas"] as bigint) < 0n) {
    return "maxPriorityFeePerGas must be a non-negative bigint";
  }
  const maxFee = f["maxFeePerGas"] as bigint;
  const priority = f["maxPriorityFeePerGas"] as bigint;
  if (maxFee > MAX_FEE_PER_GAS_WEI) {
    return `maxFeePerGas ${maxFee.toString()} exceeds cap ${MAX_FEE_PER_GAS_WEI.toString()} wei`;
  }
  if (priority > maxFee) return "maxPriorityFeePerGas must not exceed maxFeePerGas";
  if (gas * maxFee > MAX_TOTAL_FEE_WEI) {
    return `total fee exceeds cap ${MAX_TOTAL_FEE_WEI.toString()} wei`;
  }
  return null;
}
