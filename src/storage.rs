use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};

use crate::{domain::Delegation, error::AppError};

#[derive(Clone)]
pub struct Storage {
    pool: SqlitePool,
}

impl Storage {
    pub async fn connect(database_url: &str) -> Result<Self, AppError> {
        let options = database_url
            .parse::<sqlx::sqlite::SqliteConnectOptions>()
            .map_err(|error| AppError::Config(error.to_string()))?
            .create_if_missing(true)
            .foreign_keys(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;

        sqlx::migrate!()
            .run(&pool)
            .await
            .map_err(|error| AppError::Internal(format!("failed to run migrations: {error}")))?;

        Ok(Self { pool })
    }

    /// Access to the underlying pool for modules that manage their own transactions.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn in_memory() -> Result<Self, AppError> {
        // Single connection so the in-memory DB persists across queries in tests.
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await?;
        sqlx::migrate!()
            .run(&pool)
            .await
            .map_err(|error| AppError::Internal(format!("failed to run migrations: {error}")))?;
        Ok(Self { pool })
    }

    pub async fn is_ready(&self) -> Result<(), AppError> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    pub async fn insert(&self, item: &Delegation) -> Result<Delegation, AppError> {
        sqlx::query(
            r#"INSERT INTO delegations
               (id, account, implementation, chain_id, block_number,
                transaction_hash, status, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(&item.id)
        .bind(&item.account)
        .bind(&item.implementation)
        .bind(&item.chain_id)
        .bind(&item.block_number)
        .bind(&item.transaction_hash)
        .bind(&item.status)
        .bind(item.created_at)
        .execute(&self.pool)
        .await?;

        Ok(item.clone())
    }

    pub async fn list(&self) -> Result<Vec<Delegation>, AppError> {
        let rows = sqlx::query_as::<_, Delegation>(
            r#"SELECT id, account, implementation, chain_id, block_number,
                      transaction_hash, status, created_at
               FROM delegations
               ORDER BY created_at DESC, id DESC"#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::CreateDelegation;

    #[tokio::test]
    async fn inserts_and_lists_newest_first() {
        let storage = Storage::in_memory().await.expect("test storage");

        let first = CreateDelegation::default().into_delegation();
        let mut second = CreateDelegation::default().into_delegation();
        second.created_at = first.created_at + chrono::Duration::seconds(1);

        storage.insert(&first).await.expect("insert first");
        storage.insert(&second).await.expect("insert second");

        let rows = storage.list().await.expect("list");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].id, second.id);
        assert_eq!(rows[1].id, first.id);
    }
}

use serde::Serialize;

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct AccountDelegation {
    #[serde(skip)]
    pub rowid: i64,
    pub authority: String,
    pub implementation: Option<String>,
    pub block_number: i64,
    pub block_hash: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct HistoryRow {
    #[serde(skip)]
    pub rowid: i64,
    pub id: String,
    pub block_number: i64,
    pub block_hash: String,
    pub authority: String,
    pub previous_implementation: Option<String>,
    pub new_implementation: Option<String>,
    pub tx_hash: String,
    pub canonical: i64,
    pub applied_at: String,
    pub reverted_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ImplementationSummary {
    pub implementation: String,
    pub delegated_accounts: i64,
    pub total_delegations: i64,
    pub first_seen_block: Option<i64>,
    pub last_seen_block: Option<i64>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Stats {
    pub active_delegations: i64,
    pub tracked_accounts: i64,
    pub canonical_blocks: i64,
    pub reorgs: i64,
    pub latest_block: Option<i64>,
}

impl Storage {
    pub async fn account_delegation(
        &self,
        authority: &str,
    ) -> Result<Option<AccountDelegation>, AppError> {
        Ok(sqlx::query_as::<_, AccountDelegation>(
            "SELECT rowid, authority, implementation, block_number, block_hash, updated_at
             FROM current_delegations WHERE authority = ?",
        )
        .bind(authority)
        .fetch_optional(&self.pool)
        .await?)
    }

    pub async fn account_history(
        &self,
        authority: &str,
        limit: i64,
        cursor: i64,
    ) -> Result<Vec<HistoryRow>, AppError> {
        Ok(sqlx::query_as::<_, HistoryRow>(
            "SELECT rowid, id, block_number, block_hash, authority, previous_implementation,
                    new_implementation, tx_hash, canonical, applied_at, reverted_at
             FROM delegation_changes
             WHERE authority = ? AND rowid < ?
             ORDER BY rowid DESC LIMIT ?",
        )
        .bind(authority)
        .bind(cursor)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn transaction_changes(&self, tx_hash: &str) -> Result<Vec<HistoryRow>, AppError> {
        Ok(sqlx::query_as::<_, HistoryRow>(
            "SELECT rowid, id, block_number, block_hash, authority, previous_implementation,
                    new_implementation, tx_hash, canonical, applied_at, reverted_at
             FROM delegation_changes WHERE tx_hash = ? ORDER BY rowid",
        )
        .bind(tx_hash)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn implementation_summary(
        &self,
        address: &str,
    ) -> Result<Option<ImplementationSummary>, AppError> {
        let (delegated_accounts,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM current_delegations WHERE implementation = ?")
                .bind(address)
                .fetch_one(&self.pool)
                .await?;

        let (total_delegations, first_seen_block, last_seen_block): (
            i64,
            Option<i64>,
            Option<i64>,
        ) = sqlx::query_as(
            "SELECT COUNT(*), MIN(block_number), MAX(block_number)
                 FROM delegation_changes WHERE new_implementation = ? AND canonical = 1",
        )
        .bind(address)
        .fetch_one(&self.pool)
        .await?;

        if delegated_accounts == 0 && total_delegations == 0 {
            return Ok(None);
        }
        Ok(Some(ImplementationSummary {
            implementation: address.to_owned(),
            delegated_accounts,
            total_delegations,
            first_seen_block,
            last_seen_block,
        }))
    }

    pub async fn stats(&self) -> Result<Stats, AppError> {
        Ok(sqlx::query_as::<_, Stats>(
            "SELECT
                (SELECT COUNT(*) FROM current_delegations WHERE implementation IS NOT NULL) AS active_delegations,
                (SELECT COUNT(*) FROM current_delegations) AS tracked_accounts,
                (SELECT COUNT(*) FROM blocks WHERE canonical = 1) AS canonical_blocks,
                (SELECT COUNT(*) FROM reorg_events) AS reorgs,
                (SELECT MAX(number) FROM blocks WHERE canonical = 1) AS latest_block",
        )
        .fetch_one(&self.pool)
        .await?)
    }
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ReorgEvent {
    pub id: String,
    pub reverted_block_hash: String,
    pub block_number: i64,
    pub depth: i64,
    pub detected_at: String,
}

impl Storage {
    pub async fn recent_changes(
        &self,
        limit: i64,
        cursor: i64,
    ) -> Result<Vec<HistoryRow>, AppError> {
        Ok(sqlx::query_as::<_, HistoryRow>(
            "SELECT rowid, id, block_number, block_hash, authority, previous_implementation,
                    new_implementation, tx_hash, canonical, applied_at, reverted_at
             FROM delegation_changes WHERE rowid < ? ORDER BY rowid DESC LIMIT ?",
        )
        .bind(cursor)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn recent_reorgs(&self, limit: i64) -> Result<Vec<ReorgEvent>, AppError> {
        Ok(sqlx::query_as::<_, ReorgEvent>(
            "SELECT id, reverted_block_hash, block_number, depth, detected_at
             FROM reorg_events ORDER BY rowid DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }
}
