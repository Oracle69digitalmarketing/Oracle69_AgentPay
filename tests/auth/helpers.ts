/**
 * M2 test helpers. All keys are generated at runtime via generatePrivateKey
 * and never leave the test process. No real keys, no fixtures with secrets.
 */
import { getAddress, type Hex } from "viem";
import {
  generatePrivateKey,
  privateKeyToAccount,
} from "viem/accounts";
import {
  PAYMENT_AUTHORIZATION_TYPES,
  PRIMARY_TYPE,
  buildDomain,
  type ApprovalMessage,
} from "../../src/auth/domain.js";
import { computePolicyDigest } from "../../src/auth/policy-digest.js";
import type { PaymentIntent, PolicyConfig } from "../../src/policy/types.js";
import {
  DEMO_MAX_PER_PAYMENT_WEI,
  MONAD_TESTNET_CHAIN_ID,
} from "../../src/policy/types.js";
import type { AuthorizationProof, ServerAuthConfig } from "../../src/auth/types.js";
import { CURRENT_POLICY_VERSION } from "../../src/auth/types.js";
import { MemoryReplayStore } from "../../src/auth/store/memory-store.js";

export const ADDR_A = "0x1111111111111111111111111111111111111111";
export const ADDR_B = "0x2222222222222222222222222222222222222222";
export const UNAPPROVED = "0x3333333333333333333333333333333333333333";
export const NOW = 1_800_000_000;
export const DOMAIN_DEV = "agentpay-dev-v1";
export const DOMAIN_PROD = "agentpay-prod-v1";

export function makeAccount(): ReturnType<typeof privateKeyToAccount> {
  return privateKeyToAccount(generatePrivateKey());
}

export function basePolicy(over: Partial<PolicyConfig> = {}): PolicyConfig {
  return {
    approvedRecipients: [ADDR_A, ADDR_B],
    maxPerPaymentWei: DEMO_MAX_PER_PAYMENT_WEI,
    allowedChainId: MONAD_TESTNET_CHAIN_ID,
    requireHumanApproval: true,
    ...over,
  };
}

export function baseIntent(over: Partial<PaymentIntent> = {}): PaymentIntent {
  return {
    requestId: "req-001",
    recipient: ADDR_A,
    amountWei: 400_000_000_000_000_000n,
    asset: "MON",
    purpose: "m2 demo payment",
    chainId: MONAD_TESTNET_CHAIN_ID,
    nonce: "nonce-001",
    expiresAt: NOW + 3600,
    ...over,
  };
}

export interface Fixture {
  approver: ReturnType<typeof privateKeyToAccount>;
  config: ServerAuthConfig;
  store: MemoryReplayStore;
}

export function baseFixture(over: Partial<ServerAuthConfig> = {}): Fixture {
  const approver = makeAccount();
  return {
    approver,
    config: {
      policy: basePolicy(),
      approver: approver.address,
      domainId: DOMAIN_DEV,
      policyVersion: CURRENT_POLICY_VERSION,
      ...over,
    },
    store: new MemoryReplayStore(),
  };
}

/** Build the exact server-side message for an intent (mirrors verify.ts). */
export function buildMessage(
  intent: PaymentIntent,
  cfg: ServerAuthConfig,
  digest: Hex,
): ApprovalMessage {
  return {
    domainId: cfg.domainId,
    policyVersion: cfg.policyVersion,
    policyDigest: digest,
    chainId: BigInt(intent.chainId),
    requestId: intent.requestId,
    recipient: getAddress(intent.recipient),
    amountWei: intent.amountWei,
    asset: intent.asset,
    nonce: intent.nonce,
    expiresAt: BigInt(intent.expiresAt),
  };
}

export async function signApproval(
  signer: ReturnType<typeof privateKeyToAccount>,
  intent: PaymentIntent,
  cfg: ServerAuthConfig,
): Promise<AuthorizationProof> {
  const digest = computePolicyDigest(cfg.policy);
  const signature = await signer.signTypedData({
    domain: buildDomain(cfg.policy.allowedChainId, cfg.domainId),
    types: PAYMENT_AUTHORIZATION_TYPES,
    primaryType: PRIMARY_TYPE,
    message: buildMessage(intent, cfg, digest),
  });
  return {
    signature,
    domainId: cfg.domainId,
    policyVersion: cfg.policyVersion,
    policyDigest: digest,
  };
}
