# DEVPOST SUBMISSION DRAFT — Oracle69 AgentPay

**Repository:** https://github.com/Oracle69digitalmarketing/Oracle69_AgentPay
**Live demo:** Not deployed (no GitHub Pages available; local only)
**Hackathon track:** M4 — Secure, policy-controlled AI payment proposals on Monad Testnet

---

## Project title and tagline

**Oracle69 AgentPay** — Policy-controlled financial infrastructure for AI agents with bounded payment authority, human authorization, and auditable settlement on Monad Testnet.

**Tagline:** AI-assisted payment proposals that cannot execute, sign, or broadcast — only propose. Human approval required. Zero on-chain transactions without explicit operator consent.

---

## Problem

AI models like Qwen can generate natural-language payment intentions, but without guardrails they can:
- Propose payments beyond monetary ceilings
- Send funds to unapproved recipients
- Operate on wrong chain IDs
- Bypass authorization requirements
- Be treated as autonomous payment agents

Financial infrastructure for AI agents either assumes too much trust in model output (risk of uncontrolled sends) or imposes such strict restrictions that the AI-assistance value disappears.

---

## Solution

A TypeScript-first payment stack where the Qwen model (or any LLM) can **propose** a payment intent, but **cannot authorize, sign, execute, or broadcast** it. The flow is:

1. **Model proposes** a structured PaymentIntent (recipient, amount, chainId, purpose, etc.)
2. **Policy engine validates** against trusted config: 1 MON ceiling, allowlisted recipient, Monad Testnet chain ID 10143, mandatory human approval
3. **Approval is separate** — model output never treated as cryptographic signature; human must approve via EIP-712 `PaymentAuthorization`
4. **Preview is read-only** — no proof consumption, no signature, no submission, no sends
5. **Four independent dimensions** returned: `ok`, `policyDecision`, `approvalStatus`, `previewResult`, `qwenIntent`, `isExecutable: false`

The model is a **proposer**, not an executor. All enforcement is deterministic, auditable, and server-side.

---

## Why the product matters

- **Bounded AI payment influence:** An LLM can suggest payments, but policy guards decide what goes through. This is the minimum viable "AI + payments" integration that preserves security.
- **Educational/demo foundation:** Teams can build on this pattern to add their own approval workflows, UI, or chain deployment while keeping the core guarantees.
- **No false claims of autonomy:** The system explicitly separates proposal from authorization, which is rare in AI-finance integrations and makes the security model transparent.
- **Monad Testnet only:** All execution is confined to Testnet with allowlisted RPCs; no mainnet constant exists anywhere in the code.

---

## Architecture and security model

| Layer | Responsibility | Trust boundary |
|---|---|---|
| **Qwen / LLM** | Natural-language → structured PaymentIntent proposal | Untrusted — model output is validated, never trusted |
| **Qwen adapter** | Map JSON → PaymentIntent, validate every field | Untrusted — fails closed on any malformed output |
| **Policy engine** (`evaluatePolicy`) | Check allowance, ceiling, chain, expiry, asset | **Trusted** — server-side only, no caller influence |
| **Auth/M2** | EIP-712 signature verification, replay protection, digest binding | **Trusted** — approver key never leaves server, never in repo |
| **Execution/M3** | Reservation, nonce enforcement, CAS-based send right, reconciliation | **Trusted** — only allowlisted RPCs (Testnet), native MON only |
| **Preview** | Read-only chain queries, fee-cap, affordability, policy digest | **Structural guarantee** — no `executePayment` import, no send method |

**Security invariants preserved:**
- 1 MON absolute ceiling (`ABSOLUTE_MAX_PAYMENT_WEI`)
- Monad Testnet chain ID 10143 enforced throughout
- Server-controlled recipient allowlist: only `DEMO_RECIPIENT`
- Mandatory human approval: `requireHumanApproval: true` → `approvalStatus` always `REQUIRES_APPROVAL` when `requireHumanApproval` is true
- `isExecutable: false` — compile-time and runtime guarantee, never true
- Preview read-only: no proof consumption, no signature, no submission
- Fail-closed on any error (malformed JSON, network failure, timeout, invalid config)
- Model output never overrides trusted policy configuration

---

## How the AI integration works

The Qwen (or any OpenAI-compatible) model is contacted via `fetch` with a prompt like `"Pay 0.001 MON to executor"`. The model returns JSON containing a PaymentIntent proposal. The agentpay adapter then:

1. **Validates** the JSON structure (requestId, recipient EVM address, amountWei, asset MON, purpose, chainId, nonce, expiresAt)
2. **Maps** it to a `PaymentIntent` bigint amount via `parseDecimalMonToWei`
3. **Routes** it through the deterministic `evaluatePolicy` engine with server-side `PolicyConfig` (approvedRecipients, maxPerPaymentWei, allowedChainId, requireHumanApproval)
4. **Returns four dimensions:**
   - `ok: false` + `approvalStatus: "REQUIRES_APPROVAL"` — since `requireHumanApproval: true`, the model never provides a valid signature, so approval is always required
   - `policyDecision.reasons` — deterministic codes (e.g., `MISSING_APPROVAL`, `NOT_ALLOWLISTED`, `EXCEEDS_LIMIT`, `WRONG_CHAIN`)
   - `previewResult` — read-only transaction preview (no sends, no proof consumption)
   - `qwenIntent` — the mapped PaymentIntent (if valid)
   - `isExecutable: false` — guaranteed by type, never true

**The model never sees** the policy config, private keys, signer, or RPC URLs. All credentials are read from `process.env` server-side only. The API key and endpoint are optional — the app fails closed if missing, and all tests mock `globalThis.fetch`.

**Key design separation (per the integration plan):**
- **Proposal validity:** Does Qwen JSON map to a valid PaymentIntent?
- **Policy eligibility:** Does `evaluatePolicy` allow/reject?
- **Authorization status:** `approvalStatus` = `"NOT_REQUIRED"` \| `"REQUIRES_APPROVAL"` \| `"REQUIRED_UNVERIFIED"`
- **isExecutable:** always `false` — never true in any test case or production code
- **previewResult:** read-only preview, never implies authorization

---

## Testing evidence

| Suite | Result |
|---|---|
| `tests/qwen/qwen.adapter.test.ts` | 10/10 pass (mocked `globalThis.fetch`) |
| `tests/server/qwen-intent.route.test.ts` | 8/8 pass (input validation + safety invariants) |
| `tests/demo/preview-driver.test.ts` | 9/9 pass (read-only preflight, no execution) |
| Full test suite | **210/210 pass** across **17 test files** |
| TypeScript `tsc --noEmit` | Clean — no errors |
| Build `npm run build` | Success |
| All security invariants verified | 1 MON ceiling, chain 10143, allowlisted recipient, mandatory human approval, `isExecutable: false` |

**No live Qwen API call has succeeded.** All adapter tests mock `globalThis.fetch`. All route tests validate input safety without network.

---

## Demo instructions

The demo is **read-only and requires no Qwen credentials**. It can be run locally:

```bash
# 1. Install dependencies
pnpm install

# 2. Build TypeScript
pnpm build    # tsc --noEmit (succeeds)

# 3. Run the read-only demo driver (no API key needed)
npx vitest run tests/demo/preview-driver.test.ts

# 4. Start the web demo server (no RPC calls that send)
pnpm build:server   # emits to dist/
pnpm start          # node dist/server/server.js — listens on PORT 3000

# 5. Visit http://127.0.0.1:3000/
# - Serves a static page with Testnet indicator, form for amount/request/proof
# - POST /api/preview returns a labeled preflight result (ok:false, REQUIRES_APPROVAL)
# - All responses are read-only; no transactions are sent
# - Rate limiting, body caps, RPC timeouts, and error sanitization are active

# 6. Demo video script (see below)
```

**Without Qwen credentials:** The entire demo functions identically — the Qwen adapter simply fails closed, and the route returns `ok:false, approvalStatus: REQUIRES_APPROVAL` with `MISSING_APPROVAL` in reasons. This is the expected behavior and demonstrates the security boundary.

---

## Short demo-video script (≈60 seconds)

1. **(0:00–0:05)** "Oracle69 AgentPay — AI-assisted payments on Monad Testnet, with policy guards."
2. **(0:05–0:10)** "Here's a natural-language prompt: 'Pay 0.001 MON to the executor.'"
3. **(0:10–0:20)** "Qwen generates a PaymentIntent proposal. We send it through our policy engine — it checks the 1 MON ceiling, the allowlisted recipient, and the chain ID."
4. **(0:20–0:30)** "Because human approval is required, the system returns `ok:false, approvalStatus: REQUIRES_APPROVAL`. The model proposed, but cannot authorize."
5. **(0:30–0:40)** "We run the read-only preview — it validates policy, checks fees and balance, and returns a preview result. No transaction is sent, no signature is consumed."
6. **(0:40–0:50)** "Key takeaway: the AI proposes, policy disposes. All enforcement is deterministic, auditable, and server-side. No on-chain transactions occur without explicit operator consent."
7. **(0:50–0:60)** "Try it yourself: `pnpm build && pnpm test` — 210 tests pass. The repo is at github.com/Oracle69digitalmarketing/Oracle69_AgentPay."

---

## Known limitations and outstanding verification

| Limitation | Status |
|---|---|
| **No live Qwen API verification** | `QWEN_API_KEY` and `QWEN_ENDPOINT` not set in this environment; all adapter tests mock `globalThis.fetch` |
| **No on-chain payment demonstrated** | System is read-only by design; `isExecutable: false` guaranteed; no transactions sent |
| **No production readiness claim** | Designed for Monad Testnet only; no mainnet constants; single-host local-filesystem guarantee |
| **No bounty eligibility claimed** | Without live API success or on-chain transaction, no official evidence for hackathon bounty |
| **Model identifier not verified against live API** | `QWEN_MODEL` reads from env; default `qwen-turbo`; actual `qwen3.8-max` compatibility untested without credentials |
| **Route test mock/fetch timing** | Requires `beforeEach` setup at describe level; per-test `mockResolvedValueOnce` inside `it()` works correctly |

**Outstanding verification needed for hackathon submission:**
- Live Qwen API call with valid credentials (to confirm model integration)
- On-chain transaction send (to demonstrate end-to-end flow with human approval)
- Deployment of the web demo to a public URL (GitHub Pages returned 404)

---

## Actual repository and demo links

| Link | Status |
|---|---|
| **GitHub repository** | https://github.com/Oracle69digitalmarketing/Oracle69_AgentPay |
| **GitHub Pages demo** | Not deployed (custom domain returned 404; local only) |
| **Local demo (read-only)** | `pnpm build && npx vitest run tests/demo/preview-driver.test.ts` — 9 tests pass, no Qwen credentials needed |
| **Test run** | `npm test` — 210/210 tests pass across 17 test files |
| **TypeScript check** | `npm run typecheck` — clean |

---

## Recommended hackathon track and rationale

**Primary track: M4 — Secure payment execution (testnet only, no live sends)**

**Rationale:**
- The integration is already architected through M4 (execution layer with reservation, CAS-based send right, chain triple-check, 1 MON ceiling)
- All security invariants are verified and tested: 1 MON ceiling, chain ID 10143, allowlisted recipient, mandatory human approval, `isExecutable: false`
- The architecture explicitly separates AI proposal from execution — which is the core value proposition for a hackathon focused on secure AI-integrated finance
- Testing evidence is strong: 210 tests pass, TypeScript clean, build successful
- The demo is runnable without Qwen credentials, which lowers the barrier for judges to verify the core guarantees

**Secondary track: M2 — Cryptographic authorization + durable replay protection**
- Also defensible, but the Qwen integration lives primarily in the M3/M4 space (AI proposal → policy engine → preview)
- M2 focuses on EIP-712 signatures and replay protection, which is a layer above the Qwen integration

**Why not claim "autonomous AI payment":** The system is explicitly designed so that the AI **cannot** execute, sign, or broadcast. Any claim of autonomy would contradict the architecture and security model. The hack strongest position is **"policy-controlled AI payment proposals for Monad — AI suggests, human disposes."**

---

## Remaining submission blockers

| Blocker | Evidence | Mitigation |
|---|---|---|
| **No live Qwen API call** | `QWEN_API_KEY` not set; all tests mock fetch | Document as "local integration verified with mocked fetch; live API requires credentials" |
| **No on-chain transaction** | `isExecutable: false`; no sends in any test | Document as "read-only preflight; execution requires separate M3/M4 setup with operator consent" |
| **No public demo URL** | GitHub Pages returned 404 | Document as "local demo only; repository at https://github.com/Oracle69digitalmarketing/Oracle69_AgentPay" |
| **Model `qwen3.8-max` not verified against live API** | `QWEN_MODEL` env var default is `qwen-turbo` | Document as "model name configurable via QWEN_MODEL env var; compatibility untested without credentials" |

---

## Git status and diff-check results

```
$ git status --short
 M server/server.ts
 ?? src/qwen/
 ?? tests/qwen/
 ?? tests/server/qwen-intent.route.test.ts

$ git diff --check
 (no diff-index errors)
```

**Changes:**
- `server/server.ts` — added POST `/api/qwen-intent` route (79 lines added)
- `src/qwen/` — new directory: `client.ts`, `adapter.ts`, `types.ts`
- `tests/qwen/qwen.adapter.test.ts` — 10 adapter tests (all pass)
- `tests/server/qwen-intent.route.test.ts` — 8 route tests (all pass)

**No secrets or .env files exposed.** The `.gitignore` includes `.env*` and the environment variables `QWEN_API_KEY`, `QWEN_ENDPOINT`, `QWEN_MODEL` are not committed.

---

**End of DEVPOST SUBMISSION DRAFT.**