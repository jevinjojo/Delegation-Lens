//! Delegation tracker + reorg journal. Maintains each account's canonical
//! delegation over time and reverses changes correctly on reorgs.
//!
//! Every mutation runs inside a DB transaction: on any error the transaction is
//! dropped (rolled back), so a block is never partially applied.

use sqlx::SqlitePool;

use crate::error::AppError;

#[derive(Debug, Clone)]
pub struct BlockInput {
    pub number: u64,
    pub hash: String,
    pub parent_hash: String,
    pub timestamp: u64,
    pub changes: Vec<ChangeInput>,
}

#[derive(Debug, Clone)]
pub struct ChangeInput {
    pub authority: String,
    pub new_implementation: Option<String>, // None => clears the delegation
    pub tx_hash: String,
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Apply a block: verify parent, record changes (with the previous value), and
/// update current state. Idempotent: re-applying a canonical block is a no-op.
pub async fn apply_block(pool: &SqlitePool, block: &BlockInput) -> Result<(), AppError> {
    let mut tx = pool.begin().await?;

    // Idempotency: already-canonical block => nothing to do.
    let existing: Option<(i64,)> = sqlx::query_as("SELECT canonical FROM blocks WHERE hash = ?")
        .bind(&block.hash)
        .fetch_optional(&mut *tx)
        .await?;
    if matches!(existing, Some((1,))) {
        tx.commit().await?;
        return Ok(());
    }

    // Verify this block builds on the current canonical head.
    let head: Option<(String,)> =
        sqlx::query_as("SELECT hash FROM blocks WHERE canonical = 1 ORDER BY number DESC LIMIT 1")
            .fetch_optional(&mut *tx)
            .await?;
    if let Some((head_hash,)) = &head {
        if head_hash != &block.parent_hash {
            // Rolls back on return (tx dropped without commit).
            return Err(AppError::Reorg(format!(
                "parent mismatch: head is {head_hash}, block parent is {}",
                block.parent_hash
            )));
        }
    }

    let now = now_iso();

    // Upsert the block as canonical (re-applying a reverted block re-canonicalizes it).
    sqlx::query(
        "INSERT INTO blocks (number, hash, parent_hash, timestamp, canonical, applied_at, reverted_at)
         VALUES (?, ?, ?, ?, 1, ?, NULL)
         ON CONFLICT(hash) DO UPDATE SET canonical = 1, reverted_at = NULL",
    )
    .bind(block.number as i64)
    .bind(&block.hash)
    .bind(&block.parent_hash)
    .bind(block.timestamp as i64)
    .bind(&now)
    .execute(&mut *tx)
    .await?;

    for change in &block.changes {
        // The value we're about to overwrite — this is what makes revert exact.
        let previous_impl: Option<String> = sqlx::query_scalar::<_, Option<String>>(
            "SELECT implementation FROM current_delegations WHERE authority = ?",
        )
        .bind(&change.authority)
        .fetch_optional(&mut *tx)
        .await?
        .flatten();

        sqlx::query(
            "INSERT INTO delegation_changes
             (id, block_hash, block_number, authority, previous_implementation,
              new_implementation, tx_hash, canonical, applied_at, reverted_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, NULL)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&block.hash)
        .bind(block.number as i64)
        .bind(&change.authority)
        .bind(&previous_impl)
        .bind(&change.new_implementation)
        .bind(&change.tx_hash)
        .bind(&now)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO current_delegations (authority, implementation, block_number, block_hash, updated_at)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(authority) DO UPDATE SET
                implementation = excluded.implementation,
                block_number   = excluded.block_number,
                block_hash     = excluded.block_hash,
                updated_at     = excluded.updated_at",
        )
        .bind(&change.authority)
        .bind(&change.new_implementation)
        .bind(block.number as i64)
        .bind(&block.hash)
        .bind(&now)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(())
}

/// Revert a block: reverse its changes newest-first, restoring each to its
/// previous value. Marks everything noncanonical (kept for history) and logs a
/// reorg event. Idempotent: reverting an unknown/already-reverted block is a no-op.
pub async fn revert_block(pool: &SqlitePool, block_hash: &str) -> Result<(), AppError> {
    let mut tx = pool.begin().await?;

    let block: Option<(i64, i64)> =
        sqlx::query_as("SELECT number, canonical FROM blocks WHERE hash = ?")
            .bind(block_hash)
            .fetch_optional(&mut *tx)
            .await?;

    let (number, canonical) = match block {
        Some(b) => b,
        None => {
            tx.commit().await?;
            return Ok(()); // unknown block => no-op
        }
    };
    if canonical == 0 {
        tx.commit().await?;
        return Ok(()); // already reverted => no-op
    }

    let now = now_iso();

    // Reverse the block's canonical changes, newest first.
    let changes: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, authority, previous_implementation
         FROM delegation_changes
         WHERE block_hash = ? AND canonical = 1
         ORDER BY rowid DESC",
    )
    .bind(block_hash)
    .fetch_all(&mut *tx)
    .await?;

    for (id, authority, previous_impl) in changes {
        match previous_impl {
            Some(prev) => {
                sqlx::query(
                    "INSERT INTO current_delegations (authority, implementation, block_number, block_hash, updated_at)
                     VALUES (?, ?, ?, ?, ?)
                     ON CONFLICT(authority) DO UPDATE SET
                        implementation = excluded.implementation,
                        updated_at     = excluded.updated_at",
                )
                .bind(&authority)
                .bind(&prev)
                .bind(number)
                .bind(block_hash)
                .bind(&now)
                .execute(&mut *tx)
                .await?;
            }
            None => {
                // No delegation existed before this block => remove the row.
                sqlx::query("DELETE FROM current_delegations WHERE authority = ?")
                    .bind(&authority)
                    .execute(&mut *tx)
                    .await?;
            }
        }

        sqlx::query("UPDATE delegation_changes SET canonical = 0, reverted_at = ? WHERE id = ?")
            .bind(&now)
            .bind(&id)
            .execute(&mut *tx)
            .await?;
    }

    sqlx::query("UPDATE blocks SET canonical = 0, reverted_at = ? WHERE hash = ?")
        .bind(&now)
        .bind(block_hash)
        .execute(&mut *tx)
        .await?;

    sqlx::query(
        "INSERT INTO reorg_events (id, reverted_block_hash, block_number, depth, detected_at)
         VALUES (?, ?, ?, 1, ?)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(block_hash)
    .bind(number)
    .bind(&now)
    .execute(&mut *tx)
    .await?;
    metrics::counter!("reorgs_total").increment(1);
    tx.commit().await?;
    Ok(())
}

/// The current canonical implementation for an account (None = no active delegation).
pub async fn current_delegation(
    pool: &SqlitePool,
    authority: &str,
) -> Result<Option<String>, AppError> {
    let row: Option<Option<String>> = sqlx::query_scalar::<_, Option<String>>(
        "SELECT implementation FROM current_delegations WHERE authority = ?",
    )
    .bind(authority)
    .fetch_optional(pool)
    .await?;
    Ok(row.flatten())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Storage;

    fn block(
        number: u64,
        hash: &str,
        parent: &str,
        authority: &str,
        new_impl: Option<&str>,
    ) -> BlockInput {
        BlockInput {
            number,
            hash: hash.to_owned(),
            parent_hash: parent.to_owned(),
            timestamp: number,
            changes: vec![ChangeInput {
                authority: authority.to_owned(),
                new_implementation: new_impl.map(str::to_owned),
                tx_hash: format!("0xtx_{hash}"),
            }],
        }
    }

    #[tokio::test]
    async fn reorg_replaces_canonical_history() {
        let storage = Storage::in_memory().await.unwrap();
        let pool = storage.pool();
        let auth = "0xaa";

        // Chain A -> B -> C
        apply_block(pool, &block(1, "A", "GENESIS", auth, Some("0x11")))
            .await
            .unwrap();
        apply_block(pool, &block(2, "B", "A", auth, Some("0x22")))
            .await
            .unwrap();
        apply_block(pool, &block(3, "C", "B", auth, Some("0x33")))
            .await
            .unwrap();
        assert_eq!(
            current_delegation(pool, auth).await.unwrap(),
            Some("0x33".to_owned())
        );

        // Reorg: revert C then B, back to A's state.
        revert_block(pool, "C").await.unwrap();
        revert_block(pool, "B").await.unwrap();
        assert_eq!(
            current_delegation(pool, auth).await.unwrap(),
            Some("0x11".to_owned())
        );

        // Replacement fork D -> E.
        apply_block(pool, &block(2, "D", "A", auth, Some("0xdd")))
            .await
            .unwrap();
        apply_block(pool, &block(3, "E", "D", auth, Some("0xee")))
            .await
            .unwrap();
        assert_eq!(
            current_delegation(pool, auth).await.unwrap(),
            Some("0xee".to_owned())
        );
    }

    #[tokio::test]
    async fn apply_and_revert_are_idempotent() {
        let storage = Storage::in_memory().await.unwrap();
        let pool = storage.pool();
        let auth = "0xaa";

        let a = block(1, "A", "GENESIS", auth, Some("0x11"));
        apply_block(pool, &a).await.unwrap();
        apply_block(pool, &a).await.unwrap(); // re-apply: no-op
        assert_eq!(
            current_delegation(pool, auth).await.unwrap(),
            Some("0x11".to_owned())
        );

        revert_block(pool, "A").await.unwrap();
        revert_block(pool, "A").await.unwrap(); // re-revert: no-op
        assert_eq!(current_delegation(pool, auth).await.unwrap(), None);
    }

    #[tokio::test]
    async fn clearing_then_revert_restores_previous() {
        let storage = Storage::in_memory().await.unwrap();
        let pool = storage.pool();
        let auth = "0xaa";

        apply_block(pool, &block(1, "A", "GENESIS", auth, Some("0x11")))
            .await
            .unwrap();
        apply_block(pool, &block(2, "B", "A", auth, None))
            .await
            .unwrap(); // clear delegation
        assert_eq!(current_delegation(pool, auth).await.unwrap(), None);

        revert_block(pool, "B").await.unwrap(); // undo the clear
        assert_eq!(
            current_delegation(pool, auth).await.unwrap(),
            Some("0x11".to_owned())
        );
    }

    #[tokio::test]
    async fn rejects_parent_mismatch() {
        let storage = Storage::in_memory().await.unwrap();
        let pool = storage.pool();
        let auth = "0xaa";

        apply_block(pool, &block(1, "A", "GENESIS", auth, Some("0x11")))
            .await
            .unwrap();
        // C claims parent B, but B was never applied.
        let result = apply_block(pool, &block(3, "C", "B", auth, Some("0x33"))).await;
        assert!(matches!(result, Err(AppError::Reorg(_))));
    }

    #[tokio::test]
    async fn double_apply_creates_no_duplicate_changes() {
        let storage = Storage::in_memory().await.unwrap();
        let pool = storage.pool();

        let blk = block(1, "A", "GENESIS", "0xaa", Some("0x11"));
        apply_block(pool, &blk).await.unwrap();
        apply_block(pool, &blk).await.unwrap(); // idempotent

        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM delegation_changes WHERE block_hash = 'A'")
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!(
            count, 1,
            "re-applying a block must not duplicate its changes"
        );
        assert_eq!(
            current_delegation(pool, "0xaa").await.unwrap(),
            Some("0x11".into())
        );
    }

    /// Model-based stateful property test: a random sequence of applies and
    /// reverts must always leave `current_delegations` equal to the latest
    /// canonical change per authority. Seeded => fully reproducible.
    #[tokio::test]
    async fn stateful_reorg_invariants_hold() {
        use rand::{rngs::StdRng, Rng, SeedableRng};

        let storage = Storage::in_memory().await.unwrap();
        let pool = storage.pool();
        let mut rng = StdRng::seed_from_u64(0xDECAFBAD);

        let authorities = ["0xa1", "0xa2", "0xa3"];

        struct Applied {
            hash: String,
            change_auth: usize,
            new_impl: Option<String>,
        }
        let mut stack: Vec<Applied> = Vec::new();
        let mut counter = 0u64;

        for _ in 0..300 {
            let revert = !stack.is_empty() && rng.gen_bool(0.35);

            if revert {
                let top = stack.pop().unwrap();
                revert_block(pool, &top.hash).await.unwrap();
            } else {
                let number = stack.len() as u64 + 1; // canonical height stays contiguous
                let parent = stack
                    .last()
                    .map(|b| b.hash.clone())
                    .unwrap_or_else(|| "GENESIS".into());
                let hash = format!("BLK{counter}");
                counter += 1;

                let auth_idx = rng.gen_range(0..authorities.len());
                let new_impl = if rng.gen_bool(0.2) {
                    None // clear delegation
                } else {
                    Some(format!("0xi{}", rng.gen_range(0..5)))
                };

                apply_block(
                    pool,
                    &BlockInput {
                        number,
                        hash: hash.clone(),
                        parent_hash: parent,
                        timestamp: number,
                        changes: vec![ChangeInput {
                            authority: authorities[auth_idx].into(),
                            new_implementation: new_impl.clone(),
                            tx_hash: format!("0xtx_{hash}"),
                        }],
                    },
                )
                .await
                .unwrap();

                stack.push(Applied {
                    hash,
                    change_auth: auth_idx,
                    new_impl,
                });
            }

            // INVARIANT: for every authority, the tracker's current delegation equals
            // the latest canonical change to it (or None if never/cleared last).
            for (idx, authority) in authorities.iter().enumerate() {
                let expected = stack
                    .iter()
                    .rev()
                    .find(|b| b.change_auth == idx)
                    .and_then(|b| b.new_impl.clone());
                let actual = current_delegation(pool, authority).await.unwrap();
                assert_eq!(actual, expected, "invariant broken for {authority}");
            }
        }
    }
}
