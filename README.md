# Oracle69_AgentPay
Policy-controlled financial infrastructure for AI agents with bounded payment authority, human authorization, risk controls, and auditable settlement on Monad.

## M1 — Deterministic payment-policy module (implemented)

Pure TypeScript function `evaluatePolicy(intent, config, context)` in `src/policy/`:

- Validates a structured `PaymentIntent` (requestId, recipient, amountWei bigint, asset `MON`, purpose, chainId, nonce, expiresAt) against a `PolicyConfig` (allowlist, maxPerPaymentWei, allowedChainId, requireHumanApproval).
- Returns `{ allowed: true, ... }` when policy is satisfied, else `{ allowed: false, reasons: [{ code, message }] }` with stable codes: `INVALID_REQUEST`, `INVALID_ADDRESS`, `INVALID_AMOUNT`, `INVALID_ASSET`, `WRONG_CHAIN`, `NOT_ALLOWLISTED`, `EXCEEDS_LIMIT`, `EXPIRED_REQUEST`, `MISSING_APPROVAL`, `INVALID_CONFIG`.
- Reasons are sorted deterministically (`REASON_ORDER`, then message); identical input always yields identical output.
- Amounts are bigint wei only (1 MON = 10^18 wei); demo limit is 1 MON. No floating-point arithmetic anywhere.
- Expiry boundary: a request is expired when `now >= expiresAt`, so `expiresAt === now` is rejected.
- Approval flag (`context.humanApprovalVerified`) is checked LAST and never overrides any other violation. The engine does not verify signatures itself.

### Security boundary

`allowed: true` means **policy satisfied, pending complete authorization** — it is NOT executable on its own. Human-signature verification, replay protection, gated execution, chain submission, and audit logging are explicitly out of scope for M1 and must be added in later milestones. The engine has no LLM, network, wallet, key, database, or clock dependency (time is injected via `context.now`).

### Commands

- `pnpm install` — install dependencies
- `pnpm typecheck` — `tsc --noEmit`
- `pnpm test` — `vitest run`

### What is NOT in M1

No transaction executor, no signature verification, no blockchain transactions, no testnet integration claims, no private keys, no Next.js UI, no database.

## M2 — Cryptographic authorization + durable replay protection (implemented)

Async `authorizePayment({ intent, proof, config, now, store })` in `src/auth/`:

- Accepts NO caller-supplied approval boolean. Approval is established only by an EIP-712 `PaymentAuthorization` signature from the server-configured approver, verified with viem's `recoverTypedDataAddress` (offline, no RPC).
- Signed struct binds domainId, policyVersion, policyDigest, chainId, requestId, recipient (address), amountWei (uint256, exact bigint), asset, nonce, expiresAt. EIP-712 domain: name `Oracle69 AgentPay`, version `2`, chainId, `salt = keccak256(domainId)`. No `verifyingContract` — no contract is deployed; signatures are valid only within this verifier.
- Policy digest = `keccak256(abiEncode(chainId, maxPerPaymentWei, requireHumanApproval, sortedAllowlist))`; recomputed from live server policy, so any policy change invalidates old approvals.
- Pipeline: validate config → proof → time → store → M1 policy with approval ungranted (only `MISSING_APPROVAL` curable) → domain/version/digest binding → signature recovery → atomic SQLite claim. Success returns `{ authorized: true, executed: false, ... }` — authorization only, never execution.
- Replay store: `SqliteReplayStore` (better-sqlite3, UNIQUE nonce + requestId, `BEGIN IMMEDIATE` claim, fail-closed errors, no cleanup API). `MemoryReplayStore` is tests-only.
- Expiry boundary `now >= expiresAt` is expired, same as M1.

### What is NOT in M2

No transaction execution or broadcast, no chain RPC calls, no wallet management, no frontend, no smart contract, no mainnet support. Approver private keys never enter the repo — tests generate throwaway keys at runtime.

### Deployment and trust boundaries

- SQLite replay protection targets a single host with the database on a local filesystem. Network filesystems (e.g. NFS) are not supported; multi-host deployment requires a shared store with equivalent transactional uniqueness.
- Server authorization configuration and the `ReplayStore` instance must come from trusted application wiring — a caller that can substitute either bypasses the guarantees.
- `authorized: true` means authorization only. A future executor must re-verify (policy, signature, digest, replay state) at execution time and must never trust a cached decision.
- `authorized: true` means authorization only. A future executor must re-verify (policy, signature, digest, replay state) at execution time and must never trust a cached decision.

## M3 — Secure payment execution (implemented, testnet only, no live sends)

`executePayment({ intent, proof, authConfig, execConfig, now, execStore, chain })` in `src/execution/`:

- Re-verifies EVERY attempt via M2's pure `verifyAuthorization` against current trusted config (policy + EIP-712 signature + digest + domain + expiry). Cached decisions and client booleans are worthless. M2's claim ledger is never re-redeemed; single-use for spends is enforced by the executions table, so authorization no longer conflicts with execution.
- Chain triple-check: snapshot, config, and live port chain ID must all equal 10143. Only `https://testnet-rpc.monad.xyz` and `https://rpc-testnet.monadinfra.com` are allowlisted; no mainnet constant exists anywhere.
- Reservation: `executions(request_id PK, nonce UNIQUE)` INSERT under `BEGIN IMMEDIATE`; concurrent duplicates read the committed row and never submit. An atomic `RESERVED → SENDING` CAS grants the send right to exactly one caller.
- Transfer built from the frozen snapshot only (to/value/chainId); no caller gas price, calldata, destination, or chain overrides. Native MON only. Local signing makes the hash knowable pre-send: hash is recorded with the `UNKNOWN` state before bytes leave, enabling reconciliation without resubmission.

### Execution state machine

`RESERVED` (verified, nothing sent; retry resumes after re-verification) → `SENDING` (send right held; recovery = `UNKNOWN`) → `UNKNOWN` (ambiguous outcome; reconcile by hash only, never auto-resend) / `SENT` (node accepted hash; reconcile receipt only) → `CONFIRMED` / `REVERTED` (terminal). Definitive pre-submit failures return to `RESERVED` with attempts recorded (explicit retry only). `STALE` (reservation whose approval provably no longer verifies — policy/digest/domain/version change or expiry established from stored-vs-current comparison, never from a forged proof; terminal). All state writes are conditional on the expected current state, so concurrent reconcile/execution paths converge instead of regressing each other. `CONFIRMED`/`REVERTED`/`STALE` never reuse identifiers — a new payment needs a fresh approval.

### Configuration (placeholders only; see `.env.example`)

- `EXECUTOR_PRIVATE_KEY=0x<64-hex-testnet-payer-key-never-commit>` — sole key entry point, read server-side, never logged or persisted.
- `EXECUTOR_RPC_URL=https://testnet-rpc.monad.xyz` — must be allowlisted.
- The signer is isolated: only `{ address, signTransfer }` reaches the executor; the key never appears in decisions, records, or logs. Missing/invalid signer fails closed.

### Failure and reconciliation

- `reconcileExecution({ requestId, execStore, chain, now })` polls the receipt for the RECORDED hash only: success → `CONFIRMED`, revert → `REVERTED`, absent → stays pending. It never submits.
- Handoff rule: only failures provably before submission (local construction, fee-gate rejection, signing failure, read-only/simulate RPCs that cannot broadcast by protocol semantics) return to sendable `RESERVED`. Once signed bytes reach `sendRawTransaction`, EVERY outcome — including rejection-shaped errors — is `UNKNOWN`; there is no path back to `RESERVED`, only reconciliation or operator intervention with fresh authorization.
- `UNKNOWN` without a hash, or irreconcilable outcomes, stop for explicit operator intervention (fresh approval with fresh identifiers). Consumed identifiers are never released.
- Crash windows: pre-reserve (safe retry) / `RESERVED` (resume after re-verify) / `SENDING`+ (reconcile only). A DB transaction is never held across an RPC call.

### Limitations

- Error classes (`RPC_TIMEOUT` vs `RPC_REJECTED`) are diagnostic only and never drive retry: any post-handoff error yields `UNKNOWN`. Retryable paths are restricted to failures provably before submission (local construction/fee-gate/signing, read-only RPCs). RPC error text is sanitized before persistence/display: long hex payloads and request bodies are redacted, keeping only safe categories (`RPC_TIMEOUT`, `RPC_REJECTED`, `RPC_UNAVAILABLE`, `HASH_MISMATCH`, `PREPARATION_FAILED`, `SIGNING_FAILED`).
- Single-host local-filesystem guarantee (same as M2). Fee/nonce estimation is per-attempt; replacement-by-fee is not implemented.
- Fee policy (code constants, never caller-supplied): max 500 gwei fee-per-gas (5x the documented 100 gwei testnet floor), max 100k gas, max 0.05 MON total fee per attempt; violations fail closed pre-sign.
- One in-flight send per payer address (durable lease with monotonic fencing tokens): concurrent same-payer payments serialize sender-nonce allocation; a second payment retries explicitly while one is in flight. Every lease acquisition/steal advances the token, and the hash-record step is atomic on still owning the current token — a stale holder affects zero rows and aborts with `EXEC_FENCE_LOST` before sending. A crashed `SENDING` hold becomes stealable after a 5-minute grace; availability during the grace window is reduced by design, never safety. Residual race (steal landing between the fenced record and send initiation) cannot be closed by any check-then-act across an external call: chain nonce slotting bounds it to a single confirmation, with the loser failing closed. Exactly-once submission is not claimed.
- ECDSA signing is NOT deterministic across calls: each signing event yields fresh bytes/hash. Recovery never assumes re-signing reproduces a hash; only recorded hashes are reconciled.
- **No live transaction has been sent.** All tests use a mock chain port; the suite asserts zero sends on every rejection path.

### Trust boundary (M3)

`authConfig`, `execConfig`, `execStore`, and `chain` are trusted server-side dependencies. The code validates their shape and values but cannot attest provenance: a hostile injected `ChainPort` (lying receipts/chain ID), store, signer, or policy bypasses all guarantees. No untrusted caller may supply implementations or configuration. `authorized: true` from M2 remains authorization-only and is never sufficient authority to execute.

## Demo driver — read-only preflight (`demo/preview-demo.ts`)

Standalone Testnet preview; structurally incapable of execution (import-graph audited by `tests/demo/preview-driver.test.ts`: no execution/store/signer/key imports; live port exposes only `eth_chainId`, `eth_getTransactionCount`, `eth_getBalance`, `eth_estimateGas`, `eth_gasPrice`). Run: compile with the repo TypeScript to a temp dir outside the repo, then `node <tmp>/demo/preview-demo.js --recipient 0x.. --approver 0x.. --sender 0x..` (all three must be distinct public addresses; unknown or duplicate flags fail closed; `--help` lists options). Reads chain state, writes nothing, sends nothing, loads no keys; output is labeled informational preflight, never authorization.

## M4 safeguards — 1 MON ceiling, RPC docs, read-only preview
- Absolute payment ceiling `ABSOLUTE_MAX_PAYMENT_WEI = 1 MON`: `validateConfig` rejects any `maxPerPaymentWei` above it, and `executePayment` re-asserts the payment amount against it after verification. Exact bigint, no floats.
- RPC configuration: no RPC URL is read from the environment. `ViemChainAdapter` connects only to the allowlisted Testnet endpoints; anything else is refused at construction (see `.env.example` note).
- Read-only preview (`src/preview/preview.ts`, `previewTransaction`): validates policy, computes the digest, optionally verifies a supplied approval **without consuming replay state** (pure `verifyAuthorization`), and performs read-only chain queries (chain ID, nonce, balance, gas/fees) plus fee-cap and affordability checks. `ok: true` means every mandatory check passed (policy, approval if supplied, chain, ceiling, fees, balance) — fee violations, shortfalls, and query failures fail closed, never as ready. `ok` is informational readiness only, never authorization to execute. Structural guarantees: no `executePayment` import, no submission method (works with a port object that has no send method at all), no private-key loading (sender is a public address string), no stores, no signing, no broadcast. Human-readable MON strings are display-only; decisions stay in wei.

## M4-E1 web demo — read-only browser preflight (`server/`)

- `GET /` serves a static page (product name, tagline, Testnet indicator, amount/request/proof form, result panel, no-execution statement). `POST /api/preview` evaluates `{amountMon, requestId?, nonce?, proof?}` with a fixed server-side policy (Testnet 10143, MON, 1 MON ceiling, approval required, single allowlisted recipient, fixed approver/sender) and returns the preview result. Unknown routes/methods → 404/405.
- Request validation: strict decimal MON parsing (exact bigint, ≤18 places), amount within (0, 1 MON], unknown fields rejected, 16 KiB body cap with deterministic 413, per-IP fixed-window rate limiting (in-memory, per process; socket peer only, `X-Forwarded-For` ignored; expired entries evicted with a hard entry cap).
- Availability hardening: responses are never written to dead sockets (aborted uploads fail closed without crashing); malformed HTTP ends via `clientError` handling; RPC reads time out after 15 s; explicit 30 s request / 10 s headers server timeouts. No request bodies, proofs, or provider data are logged.
- Isolation: the server imports only preview/policy-constants/validation/pure-vi-em/node-builtins — no execution engine, stores, signers, keys, or submission methods (import-graph tested). The browser renders all responses as text; no `innerHTML` with response data.
- Build/start: `pnpm build:server` emits to `dist/` (git-ignored) and copies the static page; `pnpm start` runs `node dist/server/server.js` (`PORT` env or 3000). The server logs only its listen port. No database, no secrets, no execution.
