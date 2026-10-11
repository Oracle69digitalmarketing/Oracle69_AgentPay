/**
 * EIP-712 approval domain — Oracle69 AgentPay (M2).
 *
 * OFF-CHAIN SIGNING DOMAIN (no contract deployed):
 * - domain: { name: "Oracle69 AgentPay", version: "2", chainId, salt }
 * - `salt` = keccak256(domainId), binding every signature to one environment
 *   (e.g. "agentpay-dev-v1" vs "agentpay-prod-v1").
 * - No `verifyingContract` is set: there is deliberately no contract to imply.
 *   When a future milestone deploys an on-chain verifier, the domain MUST gain
 *   `verifyingContract` and the protocol version MUST bump, invalidating all
 *   off-chain-only approvals.
 *
 * LIMITATIONS: signatures are valid only within this application's verifier.
 * They confer no on-chain authority and must never be submitted to a contract
 * expecting a different domain.
 */
import { keccak256, toHex, type Hex } from "viem";
import { AUTH_APP_NAME, AUTH_PROTOCOL_VERSION } from "./types.js";

export const PRIMARY_TYPE = "PaymentAuthorization" as const;

/** Exact EIP-712 field layout. Field ORDER here is canonical for type hashing. */
export const PAYMENT_AUTHORIZATION_TYPES = {
  PaymentAuthorization: [
    { name: "domainId", type: "string" },
    { name: "policyVersion", type: "string" },
    { name: "policyDigest", type: "bytes32" },
    { name: "chainId", type: "uint256" },
    { name: "requestId", type: "string" },
    { name: "recipient", type: "address" },
    { name: "amountWei", type: "uint256" },
    { name: "asset", type: "string" },
    { name: "nonce", type: "string" },
    { name: "expiresAt", type: "uint256" },
  ],
} as const;

export interface ApprovalDomain {
  name: string;
  version: string;
  chainId: number;
  salt: Hex;
}

export interface ApprovalMessage {
  domainId: string;
  policyVersion: string;
  policyDigest: Hex;
  chainId: bigint;
  requestId: string;
  recipient: Hex;
  amountWei: bigint;
  asset: string;
  nonce: string;
  expiresAt: bigint;
}

/** Environment salt: keccak256 over the UTF-8 domainId. Deterministic. */
export function domainSalt(domainId: string): Hex {
  return keccak256(toHex(domainId));
}

/** Server-side domain construction. Never accept a caller-supplied domain. */
export function buildDomain(chainId: number, domainId: string): ApprovalDomain {
  return {
    name: AUTH_APP_NAME,
    version: AUTH_PROTOCOL_VERSION,
    chainId,
    salt: domainSalt(domainId),
  };
}
