/**
 * M3 test helpers. Payer keys are runtime-generated throwaways (no funds, no
 * network). Approver keys come from the M2 auth helpers (also runtime-only).
 */
import { generatePrivateKey } from "viem/accounts";
import { createSignerFromPrivateKey, type ExecutorSigner } from "../../src/execution/signer.js";
import { ExecutionStore } from "../../src/execution/store.js";
import type { ServerAuthConfig } from "../../src/auth/types.js";
import { CURRENT_POLICY_VERSION } from "../../src/auth/types.js";
import type { PaymentIntent, PolicyConfig } from "../../src/policy/types.js";
import {
  ADDR_A,
  ADDR_B,
  DOMAIN_DEV,
  NOW,
  basePolicy,
  makeAccount,
  signApproval,
} from "../auth/helpers.js";
import { MockChainPort } from "./mock.js";

export { ADDR_A, ADDR_B, NOW, basePolicy, makeAccount, signApproval };
export const UNAPPROVED = "0x3333333333333333333333333333333333333333";

export interface ExecFixture {
  approver: ReturnType<typeof makeAccount>;
  payer: ExecutorSigner;
  authConfig: ServerAuthConfig;
  execConfig: { chainId: number; signer: ExecutorSigner };
  execStore: ExecutionStore;
  chain: MockChainPort;
}

export function execFixture(policyOver: Partial<PolicyConfig> = {}): ExecFixture {
  const approver = makeAccount();
  const payer = createSignerFromPrivateKey(generatePrivateKey());
  const policy = basePolicy(policyOver);
  return {
    approver,
    payer,
    authConfig: {
      policy,
      approver: approver.address,
      domainId: DOMAIN_DEV,
      policyVersion: CURRENT_POLICY_VERSION,
    },
    execConfig: { chainId: 10143, signer: payer },
    execStore: new ExecutionStore(":memory:"),
    chain: new MockChainPort(),
  };
}

export function baseExecIntent(over: Partial<PaymentIntent> = {}): PaymentIntent {
  return {
    requestId: "req-x001",
    recipient: ADDR_A,
    amountWei: 400_000_000_000_000_000n,
    asset: "MON",
    purpose: "m3 demo payment",
    chainId: 10143,
    nonce: "nonce-x001",
    expiresAt: NOW + 3600,
    ...over,
  };
}
