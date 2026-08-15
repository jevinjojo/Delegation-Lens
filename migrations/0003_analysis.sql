-- Static analysis per implementation (independent of blocks/reorgs).
CREATE TABLE IF NOT EXISTS implementations (
    address          TEXT PRIMARY KEY NOT NULL,
    bytecode_hash    TEXT NOT NULL,
    source_available INTEGER NOT NULL DEFAULT 0,
    analyzer_version TEXT NOT NULL,
    analyzed_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id               TEXT PRIMARY KEY NOT NULL,
    implementation   TEXT NOT NULL,
    rule_id          TEXT NOT NULL,
    title            TEXT NOT NULL,
    severity         TEXT NOT NULL,
    confidence       TEXT NOT NULL,
    evidence         TEXT NOT NULL,
    explanation      TEXT NOT NULL,
    remediation      TEXT NOT NULL,
    analyzer_version TEXT NOT NULL,
    rule_version     TEXT NOT NULL,
    source_hash      TEXT,
    bytecode_hash    TEXT NOT NULL,
    created_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_impl ON findings (implementation);

-- Carry the EIP-7702 authorization nonce through history.
ALTER TABLE delegation_changes ADD COLUMN nonce INTEGER;