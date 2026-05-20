-- RFC 0014 (Sui receipt anchoring) adds a nullable on-chain anchor
-- column to the receipt_seal table. Receipts sealed by LocalSealer
-- (no external commitment) leave this NULL; receipts sealed by
-- SuiSealer populate it with the 32-byte Sui tx digest of the
-- commit_batch transaction.
--
-- The schema is additive — existing rows (none in production yet,
-- since the receipt_seal table has been an empty scaffold) are
-- unaffected.

ALTER TABLE receipt_seal
    ADD COLUMN on_chain_anchor_tx_digest BYTEA;

COMMENT ON COLUMN receipt_seal.on_chain_anchor_tx_digest IS
    'Sui transaction digest of the commit_batch transaction that anchored '
    'this receipt''s batch on-chain. 32 raw bytes. NULL when sealed by '
    'LocalSealer (no external commitment) — see RFC 0014 + '
    '/spec/verifiability/sui-anchoring.md §7.';
