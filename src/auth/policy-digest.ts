/**
 * Deterministic policy digest — Oracle69 AgentPay (M2).
 *
 * CANONICALIZATION RULES (all required for byte-identical digests):
 * 1. chainId: exact integer → uint256.
 * 2. maxPerPaymentWei: exact bigint wei → uint256. No floats anywhere.
 * 3. requireHumanApproval: exact boolean → bool.
 * 4. allowlist: each entry checksummed, lowercased, then sorted ascending by
 *    UTF-8 byte order; duplicates impossible post-validation → address[].
 * 5. Encoding: viem `encodeAbiParameters` over
 *    (uint256 chainId, uint256 maxPerPaymentWei, bool requireHumanApproval,
 *     address[] allowlist), then keccak256.
 *
 * Deliberately NOT JSON: object insertion order and whitespace can never
 * affect the digest. Any change to any authorization-relevant policy field
 * changes the digest, invalidating approvals signed under the old policy.
 */
import { encodeAbiParameters, getAddress, keccak256, type Hex } from "viem";
import type { PolicyConfig } from "../policy/types.js";
import { normalizeAddress } from "../policy/validation.js";

/** Canonical sorted lowercase allowlist. Exported for tests. */
export function canonicalAllowlist(approvedRecipients: string[]): string[] {
  const normalized = approvedRecipients.map((a) => normalizeAddress(a));
  return [...new Set(normalized)].sort();
}

export function computePolicyDigest(policy: PolicyConfig): Hex {
  const allowlist = canonicalAllowlist(policy.approvedRecipients).map(
    (a) => getAddress(a) as Hex,
  );
  const encoded = encodeAbiParameters(
    [
      { name: "chainId", type: "uint256" },
      { name: "maxPerPaymentWei", type: "uint256" },
      { name: "requireHumanApproval", type: "bool" },
      { name: "allowlist", type: "address[]" },
    ],
    [
      BigInt(policy.allowedChainId),
      policy.maxPerPaymentWei,
      policy.requireHumanApproval,
      allowlist,
    ],
  );
  return keccak256(encoded);
}
