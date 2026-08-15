//! Canonical block processor. Sits on top of the Phase 4 tracker and makes
//! ingestion reorg-safe: extend on match, reconcile on parent mismatch.
//!
//! Every block is applied via `tracker`, which uses DB transactions, so a
//! failure never leaves a partially-applied block.

use std::future::Future;
use std::time::Duration;

use sqlx::SqlitePool;

use crate::error::AppError;
use crate::tracker::{self, BlockInput, ChangeInput};

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// A block as fetched from a source, ready to feed the tracker.
#[derive(Debug, Clone)]
pub struct FetchedBlock {
    pub number: u64,
    pub hash: String,
    pub parent_hash: String,
    pub timestamp: u64,
    pub changes: Vec<ChangeInput>,
}

impl FetchedBlock {
    fn to_input(&self) -> BlockInput {
        BlockInput {
            number: self.number,
            hash: self.hash.clone(),
            parent_hash: self.parent_hash.clone(),
            timestamp: self.timestamp,
            changes: self.changes.clone(),
        }
    }
}

/// Abstracts the data source so the reconciler can be tested with a fake.
#[allow(async_fn_in_trait)]
pub trait BlockProvider {
    async fn block_by_number(&self, number: u64) -> Result<Option<FetchedBlock>, AppError>;
    async fn block_by_hash(&self, hash: &str) -> Result<Option<FetchedBlock>, AppError>;
    async fn head_number(&self) -> Result<u64, AppError>;
    async fn code_at(&self, address: &str) -> Result<Option<String>, AppError>; // NEW
}

pub async fn process_block<P: BlockProvider>(
    pool: &SqlitePool,
    provider: &P,
    block: FetchedBlock,
) -> Result<Vec<ChangeInput>, AppError> {
    let started = std::time::Instant::now();
    let result = process_block_inner(pool, provider, block).await;
    if let Ok(changes) = &result {
        metrics::histogram!("block_processing_duration_seconds")
            .record(started.elapsed().as_secs_f64());
        metrics::counter!("blocks_processed_total").increment(1);
        metrics::counter!("authorizations_detected_total").increment(changes.len() as u64);
    }
    result
}

/// Process a block, then analyze any newly-seen implementation. Analysis errors
/// are isolated: they never fail block processing.
pub async fn process_and_analyze<P: BlockProvider>(
    pool: &SqlitePool,
    provider: &P,
    chain_id: u64,
    block: FetchedBlock,
) -> Result<Vec<ChangeInput>, AppError> {
    let changes = process_block(pool, provider, block).await?;
    for change in &changes {
        if let Some(impl_addr) = change.new_implementation.clone() {
            if let Err(error) = analyze_implementation(pool, provider, chain_id, &impl_addr).await {
                tracing::warn!(%error, impl_addr, "analysis failed (isolated)");
            }
        }
    }
    Ok(changes)
}

async fn analyze_implementation<P: BlockProvider>(
    pool: &SqlitePool,
    provider: &P,
    chain_id: u64,
    impl_addr: &str,
) -> Result<(), AppError> {
    use crate::analyzer::{run_analysis, Analyzer, ResolvedImplementation, ANALYZER_VERSION};

    // Idempotent: skip if already analyzed at the current analyzer version.
    let existing: Option<(String,)> =
        sqlx::query_as("SELECT analyzer_version FROM implementations WHERE address = ?")
            .bind(impl_addr)
            .fetch_optional(pool)
            .await?;
    if matches!(&existing, Some((v,)) if v == ANALYZER_VERSION) {
        return Ok(());
    }

    let bytecode = provider.code_at(impl_addr).await?; // None => EOA/no code
    let resolved = bytecode
        .as_ref()
        .map(|bc| ResolvedImplementation::new(chain_id, impl_addr.to_owned(), bc.clone(), None));
    let bytecode_hash = resolved
        .as_ref()
        .map(|r| r.bytecode_hash.clone())
        .unwrap_or_else(|| "0x".into());

    let mut analyzer = Analyzer::new();
    let outcome = run_analysis(&mut analyzer, Ok(resolved));

    let now = now_iso();
    sqlx::query(
        "INSERT INTO implementations (address, bytecode_hash, source_available, analyzer_version, analyzed_at)
         VALUES (?, ?, 0, ?, ?)
         ON CONFLICT(address) DO UPDATE SET
            bytecode_hash = excluded.bytecode_hash,
            analyzer_version = excluded.analyzer_version,
            analyzed_at = excluded.analyzed_at",
    )
    .bind(impl_addr)
    .bind(&bytecode_hash)
    .bind(ANALYZER_VERSION)
    .bind(&now)
    .execute(pool)
    .await?;

    sqlx::query("DELETE FROM findings WHERE implementation = ?")
        .bind(impl_addr)
        .execute(pool)
        .await?;
    for f in &outcome.findings {
        sqlx::query(
            "INSERT INTO findings
             (id, implementation, rule_id, title, severity, confidence, evidence, explanation,
              remediation, analyzer_version, rule_version, source_hash, bytecode_hash, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(impl_addr)
        .bind(&f.rule_id)
        .bind(&f.title)
        .bind(format!("{:?}", f.severity)) // "High", "Medium", ...
        .bind(format!("{:?}", f.confidence)) // "Heuristic", "Probable", ...
        .bind(&f.evidence)
        .bind(&f.explanation)
        .bind(&f.remediation)
        .bind(&f.analyzer_version)
        .bind(&f.rule_version)
        .bind(&f.source_hash)
        .bind(&f.bytecode_hash)
        .bind(&now)
        .execute(pool)
        .await?;
    }
    Ok(())
}

/// Process one block. Returns the changes that became canonical (for SSE).
async fn process_block_inner<P: BlockProvider>(
    pool: &SqlitePool,
    provider: &P,
    block: FetchedBlock,
) -> Result<Vec<ChangeInput>, AppError> {
    match canonical_head(pool).await? {
        // First block, or it cleanly extends our head => apply directly.
        None => {
            tracker::apply_block(pool, &block.to_input()).await?;
            Ok(block.changes)
        }
        Some((_, head_hash)) if head_hash == block.parent_hash => {
            tracker::apply_block(pool, &block.to_input()).await?;
            Ok(block.changes)
        }
        // Mismatch: either a duplicate we already have, or a reorg.
        Some(_) => {
            if is_canonical(pool, &block.hash).await? {
                return Ok(vec![]); // already processed => idempotent no-op
            }
            reconcile(pool, provider, block).await
        }
    }
}

/// Walk the new chain back to the common ancestor, revert orphaned canonical
/// blocks, then apply the new blocks oldest-first.
async fn reconcile<P: BlockProvider>(
    pool: &SqlitePool,
    provider: &P,
    new_head: FetchedBlock,
) -> Result<Vec<ChangeInput>, AppError> {
    let mut to_apply: Vec<FetchedBlock> = Vec::new();
    let mut cursor = new_head;

    loop {
        // Found the fork point: cursor's parent is a block we already trust.
        if cursor.parent_hash == "GENESIS" || is_canonical(pool, &cursor.parent_hash).await? {
            let ancestor_number = cursor.number.saturating_sub(1) as i64;
            revert_above(pool, ancestor_number).await?; // undo the orphaned canonical blocks
            to_apply.push(cursor);
            break;
        }
        // Otherwise climb to the parent on the new chain.
        let parent = provider
            .block_by_hash(&cursor.parent_hash)
            .await?
            .ok_or_else(|| AppError::Reorg(format!("missing parent {}", cursor.parent_hash)))?;
        to_apply.push(cursor);
        cursor = parent;

        if to_apply.len() > 128 {
            return Err(AppError::Reorg(
                "reorg deeper than 128 blocks; refusing".into(),
            ));
        }
    }

    let mut applied = Vec::new();
    for block in to_apply.into_iter().rev() {
        let changes = block.changes.clone();
        tracker::apply_block(pool, &block.to_input()).await?;
        applied.extend(changes);
    }
    Ok(applied)
}

/// The next block number to process (resume point after restart).
pub async fn next_block_to_process(pool: &SqlitePool) -> Result<Option<u64>, AppError> {
    let row: (Option<i64>,) = sqlx::query_as("SELECT MAX(number) FROM blocks WHERE canonical = 1")
        .fetch_one(pool)
        .await?;
    Ok(row.0.map(|n| n as u64 + 1))
}

/// Backfill an inclusive range, resiliently.
pub async fn backfill<P: BlockProvider>(
    pool: &SqlitePool,
    provider: &P,
    chain_id: u64,
    from: u64,
    to: u64,
) -> Result<(), AppError> {
    for number in from..=to {
        metrics::gauge!("ingestion_lag_blocks").set(to.saturating_sub(number) as f64);
        if let Some(block) = with_retry(|| provider.block_by_number(number)).await? {
            process_and_analyze(pool, provider, chain_id, block).await?;
        }
    }
    Ok(())
}

/// Retry with exponential backoff — the core of provider resilience.
pub async fn with_retry<T, F, Fut>(mut op: F) -> Result<T, AppError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, AppError>>,
{
    let mut delay = Duration::from_millis(500);
    for attempt in 1..=5u32 {
        match op().await {
            Ok(value) => return Ok(value),
            Err(error) if attempt < 5 => {
                metrics::counter!("rpc_errors_total").increment(1);
                tracing::warn!(attempt, %error, "rpc call failed; retrying");
                tokio::time::sleep(delay).await;
                delay *= 2;
            }
            Err(error) => {
                metrics::counter!("rpc_errors_total").increment(1);
                return Err(error);
            }
        }
    }
    unreachable!()
}

async fn canonical_head(pool: &SqlitePool) -> Result<Option<(i64, String)>, AppError> {
    Ok(sqlx::query_as(
        "SELECT number, hash FROM blocks WHERE canonical = 1 ORDER BY number DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await?)
}

async fn is_canonical(pool: &SqlitePool, hash: &str) -> Result<bool, AppError> {
    let row: Option<(i64,)> = sqlx::query_as("SELECT canonical FROM blocks WHERE hash = ?")
        .bind(hash)
        .fetch_optional(pool)
        .await?;
    Ok(matches!(row, Some((1,))))
}

async fn revert_above(pool: &SqlitePool, ancestor_number: i64) -> Result<(), AppError> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT hash FROM blocks WHERE canonical = 1 AND number > ? ORDER BY number DESC",
    )
    .bind(ancestor_number)
    .fetch_all(pool)
    .await?;
    for (hash,) in rows {
        tracker::revert_block(pool, &hash).await?; // head-first
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Storage;
    use std::collections::HashMap;

    struct FakeProvider {
        by_hash: HashMap<String, FetchedBlock>,
    }
    impl BlockProvider for FakeProvider {
        async fn block_by_number(&self, _n: u64) -> Result<Option<FetchedBlock>, AppError> {
            Ok(None)
        }
        async fn block_by_hash(&self, hash: &str) -> Result<Option<FetchedBlock>, AppError> {
            Ok(self.by_hash.get(hash).cloned())
        }
        async fn head_number(&self) -> Result<u64, AppError> {
            Ok(0)
        }
        async fn code_at(&self, _address: &str) -> Result<Option<String>, AppError> {
            Ok(None)
        }
    }

    fn fb(
        number: u64,
        hash: &str,
        parent: &str,
        authority: &str,
        imp: Option<&str>,
    ) -> FetchedBlock {
        FetchedBlock {
            number,
            hash: hash.to_owned(),
            parent_hash: parent.to_owned(),
            timestamp: number,
            changes: vec![ChangeInput {
                authority: authority.to_owned(),
                new_implementation: imp.map(str::to_owned),
                tx_hash: format!("0xtx_{hash}"),
                nonce: None,
            }],
        }
    }

    #[tokio::test]
    async fn live_reorg_reconciles_at_ingestion() {
        let storage = Storage::in_memory().await.unwrap();
        let pool = storage.pool();
        let auth = "0xaa";

        let a = fb(1, "A", "GENESIS", auth, Some("0x11"));
        let b = fb(2, "B", "A", auth, Some("0x22"));
        let c = fb(3, "C", "B", auth, Some("0x33"));
        let d = fb(2, "D", "A", auth, Some("0xdd"));
        let e = fb(3, "E", "D", auth, Some("0xee"));

        let mut by_hash = HashMap::new();
        for blk in [&a, &b, &c, &d, &e] {
            by_hash.insert(blk.hash.clone(), blk.clone());
        }
        let provider = FakeProvider { by_hash };

        // Canonical chain A -> B -> C.
        process_block(pool, &provider, a.clone()).await.unwrap();
        process_block(pool, &provider, b.clone()).await.unwrap();
        process_block(pool, &provider, c.clone()).await.unwrap();
        assert_eq!(
            tracker::current_delegation(pool, auth).await.unwrap(),
            Some("0x33".into())
        );

        // Reorg: D (parent A) arrives while head is C => reconcile back to A, apply D.
        process_block(pool, &provider, d.clone()).await.unwrap();
        assert_eq!(
            tracker::current_delegation(pool, auth).await.unwrap(),
            Some("0xdd".into())
        );

        // E extends D normally.
        process_block(pool, &provider, e.clone()).await.unwrap();
        assert_eq!(
            tracker::current_delegation(pool, auth).await.unwrap(),
            Some("0xee".into())
        );

        // Re-feeding a canonical head is a no-op (idempotent).
        let applied = process_block(pool, &provider, e).await.unwrap();
        assert!(applied.is_empty());
    }
}
