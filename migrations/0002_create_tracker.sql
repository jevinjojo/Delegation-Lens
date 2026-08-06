-- Blocks we've processed. `canonical = 0` means reverted (orphaned) but kept for history.
CREATE TABLE IF NOT EXISTS blocks (
    number       INTEGER NOT NULL,
    hash         TEXT PRIMARY KEY NOT NULL,
    parent_hash  TEXT NOT NULL,
    timestamp    INTEGER NOT NULL,
    canonical    INTEGER NOT NULL DEFAULT 1,
    applied_at   TEXT NOT NULL,
    reverted_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_blocks_canonical_number ON blocks (canonical, number DESC);

-- Every delegation change, with the value it overwrote (so we can reverse it).
CREATE TABLE IF NOT EXISTS delegation_changes (
    id                      TEXT PRIMARY KEY NOT NULL,
    block_hash              TEXT NOT NULL,
    block_number            INTEGER NOT NULL,
    authority               TEXT NOT NULL,
    previous_implementation TEXT,           -- NULL = no delegation before this
    new_implementation      TEXT,           -- NULL = this change CLEARS the delegation
    tx_hash                 TEXT NOT NULL,
    canonical               INTEGER NOT NULL DEFAULT 1,
    applied_at              TEXT NOT NULL,
    reverted_at             TEXT,
    FOREIGN KEY (block_hash) REFERENCES blocks (hash)
);
CREATE INDEX IF NOT EXISTS idx_changes_block ON delegation_changes (block_hash);
CREATE INDEX IF NOT EXISTS idx_changes_authority ON delegation_changes (authority);

-- The fast-lookup "truth": each account's current implementation.
CREATE TABLE IF NOT EXISTS current_delegations (
    authority       TEXT PRIMARY KEY NOT NULL,
    implementation  TEXT,                    -- NULL = no active delegation
    block_number    INTEGER NOT NULL,
    block_hash      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

-- Audit trail of reorgs.
CREATE TABLE IF NOT EXISTS reorg_events (
    id                  TEXT PRIMARY KEY NOT NULL,
    reverted_block_hash TEXT NOT NULL,
    block_number        INTEGER NOT NULL,
    depth               INTEGER NOT NULL,
    detected_at         TEXT NOT NULL
);