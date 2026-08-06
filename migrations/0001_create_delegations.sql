CREATE TABLE IF NOT EXISTS delegations (
    id               TEXT PRIMARY KEY NOT NULL,
    account          TEXT NOT NULL,
    implementation   TEXT NOT NULL,
    chain_id         TEXT NOT NULL,
    block_number     TEXT NOT NULL,
    transaction_hash TEXT NOT NULL,
    status           TEXT NOT NULL,
    created_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_delegations_created_at
    ON delegations (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_delegations_account
    ON delegations (account);