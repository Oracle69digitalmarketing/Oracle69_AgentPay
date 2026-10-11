-- Durable replay-protection schema — Oracle69 AgentPay (M2).
--
-- One row per CONSUMED authorization. No DELETE or cleanup path exists by
-- design: consumed nonces and request IDs must never become reusable.
CREATE TABLE IF NOT EXISTS consumed_authorizations (
  nonce TEXT PRIMARY KEY,
  request_id TEXT NOT NULL UNIQUE,
  recipient TEXT NOT NULL,
  amount_wei TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER NOT NULL,
  policy_digest TEXT NOT NULL
);
