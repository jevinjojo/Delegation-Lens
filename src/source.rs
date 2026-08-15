//! Chain data sources: recorded JSON fixtures (Phase 3) and live RPC (Phase 7).
//! This module decodes EIP-7702 transactions into structural results and
//! validates them semantically.

use alloy::eips::eip7702::{Authorization, SignedAuthorization};
use alloy::primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};

use crate::error::AppError;

/// EIP-7702 "set code" transaction type.
pub const EIP7702_TX_TYPE: u8 = 4;

// ───────────────────────── Fixture (input) shapes ─────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxFixture {
    #[serde(default)]
    pub hash: Option<String>,
    #[serde(rename = "type")]
    pub tx_type: u8,
    pub chain_id: u64,
    #[serde(default)]
    pub authorization_list: Vec<AuthFixture>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthFixture {
    pub chain_id: U256, // hex string in JSON ("0x0" = any chain)
    pub address: Address,
    pub nonce: u64,
    pub y_parity: u8,
    pub r: U256,
    pub s: U256,
}

// ───────────────────────── Decoded (structural) shapes ─────────────────────

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DecodedAuth {
    pub chain_id: U256,
    pub implementation: Address,
    pub nonce: u64,
    pub is_clear: bool,                       // address == 0 => clears delegation
    pub recovered_authority: Option<Address>, // None => signature didn't recover
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DecodedTx {
    pub hash: Option<String>,
    pub tx_type: u8,
    pub chain_id: u64,
    pub authorizations: Vec<DecodedAuth>,
}

// ───────────────────────── Validation (semantic) shapes ────────────────────

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "issue", rename_all = "snake_case")]
pub enum ValidationIssue {
    UnrecoverableSignature {
        index: usize,
    },
    ChainMismatch {
        index: usize,
        auth_chain_id: String,
        node_chain_id: u64,
    },
    DuplicateAuthority {
        authority: Address,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct InspectionReport {
    pub decoded: DecodedTx,
    pub issues: Vec<ValidationIssue>,
}

// ───────────────────────── Decoding (structural) ───────────────────────────

/// Structural decode. Rejects non-7702 transactions with a typed error;
/// otherwise maps every authorization tuple (recovering the authority).
pub fn decode_transaction(tx: &TxFixture) -> Result<DecodedTx, AppError> {
    if tx.tx_type != EIP7702_TX_TYPE {
        return Err(AppError::UnsupportedTransaction(format!(
            "expected tx type {EIP7702_TX_TYPE}, got {}",
            tx.tx_type
        )));
    }

    let authorizations = tx.authorization_list.iter().map(decode_auth).collect();

    Ok(DecodedTx {
        hash: tx.hash.clone(),
        tx_type: tx.tx_type,
        chain_id: tx.chain_id,
        authorizations,
    })
}

/// Decode a single tuple: rebuild the signed authorization and recover its signer.
fn decode_auth(a: &AuthFixture) -> DecodedAuth {
    let inner = Authorization {
        chain_id: a.chain_id,
        address: a.address,
        nonce: a.nonce,
    };
    let signed = SignedAuthorization::new_unchecked(inner, a.y_parity, a.r, a.s);

    DecodedAuth {
        chain_id: a.chain_id,
        implementation: a.address,
        nonce: a.nonce,
        is_clear: a.address == Address::ZERO,
        recovered_authority: signed.recover_authority().ok(), // Err => None
    }
}

// ───────────────────────── Validation (semantic) ───────────────────────────

/// Semantic checks, kept separate from decoding. `node_chain_id` is the chain
/// we're indexing; a tuple's chain_id must be 0 (any) or equal to it.
pub fn validate_transaction(tx: &DecodedTx, node_chain_id: u64) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    let mut seen: Vec<Address> = Vec::new();

    for (index, auth) in tx.authorizations.iter().enumerate() {
        match auth.recovered_authority {
            None => issues.push(ValidationIssue::UnrecoverableSignature { index }),
            Some(authority) => {
                if seen.contains(&authority) {
                    issues.push(ValidationIssue::DuplicateAuthority { authority });
                } else {
                    seen.push(authority);
                }
            }
        }

        if auth.chain_id != U256::ZERO && auth.chain_id != U256::from(node_chain_id) {
            issues.push(ValidationIssue::ChainMismatch {
                index,
                auth_chain_id: auth.chain_id.to_string(),
                node_chain_id,
            });
        }
    }

    issues
}

// ───────────────────────── Fixture generator ───────────────────────────────

/// Writes the crypto-dependent fixtures (real signatures, fixed key) plus each
/// one's `.expected.json`. Deterministic: same key + inputs => same output.
pub fn generate_fixtures() -> Result<(), AppError> {
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;

    let dir = "fixtures/transactions";
    std::fs::create_dir_all(dir).map_err(|e| AppError::Internal(e.to_string()))?;

    // Well-known Anvil test key #0 (public, safe to commit).
    let signer: PrivateKeySigner =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .map_err(|e| AppError::Internal(format!("bad key: {e}")))?;

    let sign = |chain_id: U256, address: Address, nonce: u64| -> AuthFixture {
        let auth = Authorization {
            chain_id,
            address,
            nonce,
        };
        let sig = signer.sign_hash_sync(&auth.signature_hash()).expect("sign");
        let signed = auth.into_signed(sig);
        AuthFixture {
            chain_id,
            address,
            nonce,
            y_parity: signed.y_parity() as u8,
            r: signed.r(),
            s: signed.s(),
        }
    };

    let sepolia = U256::from(11_155_111u64);
    let impl_a: Address = "0x00000000000000000000000000000000000000aa"
        .parse()
        .unwrap();

    // name, node_chain_id, tx
    let fixtures = vec![
        ("valid_set", 11_155_111u64, vec![sign(sepolia, impl_a, 0)]),
        (
            "clear_delegation",
            11_155_111,
            vec![sign(sepolia, Address::ZERO, 1)],
        ),
        (
            "chain_agnostic",
            11_155_111,
            vec![sign(U256::ZERO, impl_a, 0)],
        ),
        (
            "multiple_auths",
            11_155_111,
            vec![sign(sepolia, impl_a, 0), sign(sepolia, impl_a, 1)],
        ),
        (
            "duplicate_authority",
            11_155_111,
            vec![sign(sepolia, impl_a, 0), sign(sepolia, impl_a, 0)],
        ),
    ];

    for (name, node_chain_id, list) in fixtures {
        let tx = TxFixture {
            hash: Some(format!("0x{:0>64}", name.replace('_', ""))),
            tx_type: EIP7702_TX_TYPE,
            chain_id: node_chain_id,
            authorization_list: list,
        };
        write_json(dir, name, &tx)?;

        let decoded = decode_transaction(&tx)?;
        let issues = validate_transaction(&decoded, node_chain_id);
        write_json(
            dir,
            &format!("{name}.expected"),
            &InspectionReport { decoded, issues },
        )?;
    }

    println!("fixtures written to {dir}/");
    Ok(())
}

fn write_json<T: Serialize>(dir: &str, name: &str, value: &T) -> Result<(), AppError> {
    let path = format!("{dir}/{name}.json");
    let json =
        serde_json::to_string_pretty(value).map_err(|e| AppError::Internal(e.to_string()))?;
    std::fs::write(&path, json).map_err(|e| AppError::Internal(format!("write {path}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;

    fn signer() -> PrivateKeySigner {
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .unwrap()
    }

    fn signed(chain_id: U256, addr: Address, nonce: u64, s: &PrivateKeySigner) -> AuthFixture {
        let auth = Authorization {
            chain_id,
            address: addr,
            nonce,
        };
        let sig = s.sign_hash_sync(&auth.signature_hash()).unwrap();
        let sa = auth.into_signed(sig);
        AuthFixture {
            chain_id,
            address: addr,
            nonce,
            y_parity: sa.y_parity() as u8,
            r: sa.r(),
            s: sa.s(),
        }
    }

    #[test]
    fn rejects_non_7702() {
        let tx = TxFixture {
            hash: None,
            tx_type: 2,
            chain_id: 1,
            authorization_list: vec![],
        };
        assert!(matches!(
            decode_transaction(&tx),
            Err(AppError::UnsupportedTransaction(_))
        ));
    }

    #[test]
    fn recovers_the_authority() {
        let s = signer();
        let a = signed(
            U256::from(1u64),
            address!("00000000000000000000000000000000000000aa"),
            0,
            &s,
        );
        assert_eq!(decode_auth(&a).recovered_authority, Some(s.address()));
    }

    #[test]
    fn detects_clearing() {
        let s = signer();
        let a = signed(U256::from(1u64), Address::ZERO, 0, &s);
        assert!(decode_auth(&a).is_clear);
    }

    #[test]
    fn preserves_authorization_order() {
        let s = signer();
        let tx = TxFixture {
            hash: None,
            tx_type: EIP7702_TX_TYPE,
            chain_id: 1,
            authorization_list: vec![
                signed(
                    U256::from(1u64),
                    address!("00000000000000000000000000000000000000aa"),
                    0,
                    &s,
                ),
                signed(
                    U256::from(1u64),
                    address!("00000000000000000000000000000000000000bb"),
                    1,
                    &s,
                ),
            ],
        };
        let decoded = decode_transaction(&tx).unwrap();
        assert_eq!(decoded.authorizations[0].nonce, 0);
        assert_eq!(decoded.authorizations[1].nonce, 1);
    }

    #[test]
    fn flags_bad_signature_and_chain_and_duplicate() {
        // Unrecoverable: r = 0 is out of range, so recovery genuinely fails.
        let bad = AuthFixture {
            chain_id: U256::from(1u64),
            address: address!("00000000000000000000000000000000000000aa"),
            nonce: 0,
            y_parity: 0,
            r: U256::ZERO, // <-- was U256::from(1u64)
            s: U256::from(1u64),
        };
        let decoded = decode_transaction(&TxFixture {
            hash: None,
            tx_type: EIP7702_TX_TYPE,
            chain_id: 1,
            authorization_list: vec![bad],
        })
        .unwrap();
        let issues = validate_transaction(&decoded, 1);
        assert!(issues
            .iter()
            .any(|i| matches!(i, ValidationIssue::UnrecoverableSignature { .. })));

        // Chain mismatch: auth chain_id 999 while node is 1.
        let s = signer();
        let mism = signed(
            U256::from(999u64),
            address!("00000000000000000000000000000000000000aa"),
            0,
            &s,
        );
        let decoded = decode_transaction(&TxFixture {
            hash: None,
            tx_type: EIP7702_TX_TYPE,
            chain_id: 1,
            authorization_list: vec![mism],
        })
        .unwrap();
        assert!(validate_transaction(&decoded, 1)
            .iter()
            .any(|i| matches!(i, ValidationIssue::ChainMismatch { .. })));

        // Duplicate authority: same key + same nonce twice.
        let dup = signed(
            U256::from(1u64),
            address!("00000000000000000000000000000000000000aa"),
            0,
            &s,
        );
        let decoded = decode_transaction(&TxFixture {
            hash: None,
            tx_type: EIP7702_TX_TYPE,
            chain_id: 1,
            authorization_list: vec![dup.clone(), dup],
        })
        .unwrap();
        assert!(validate_transaction(&decoded, 1)
            .iter()
            .any(|i| matches!(i, ValidationIssue::DuplicateAuthority { .. })));
    }

    #[test]
    fn serialization_is_deterministic() {
        let s = signer();
        let tx = TxFixture {
            hash: None,
            tx_type: EIP7702_TX_TYPE,
            chain_id: 1,
            authorization_list: vec![signed(
                U256::from(1u64),
                address!("00000000000000000000000000000000000000aa"),
                0,
                &s,
            )],
        };
        let decoded = decode_transaction(&tx).unwrap();
        assert_eq!(
            serde_json::to_string(&decoded).unwrap(),
            serde_json::to_string(&decoded).unwrap()
        );
    }

    #[tokio::test]
    async fn fixture_replay_updates_tracker() {
        use crate::storage::Storage;
        use crate::tracker::{apply_block, current_delegation, BlockInput, ChangeInput};

        let signer = signer();
        let impl_addr = address!("00000000000000000000000000000000000000bb");
        let auth_fixture = signed(U256::from(11_155_111u64), impl_addr, 0, &signer);

        let tx = TxFixture {
            hash: Some("0xtx".into()),
            tx_type: EIP7702_TX_TYPE,
            chain_id: 11_155_111,
            authorization_list: vec![auth_fixture],
        };

        // Decode, then bridge into tracker changes (the same mapping the live path uses).
        let decoded = decode_transaction(&tx).unwrap();
        let changes: Vec<ChangeInput> = decoded
            .authorizations
            .iter()
            .filter_map(|d| {
                d.recovered_authority.map(|authority| ChangeInput {
                    authority: format!("{authority:#x}"),
                    new_implementation: if d.is_clear {
                        None
                    } else {
                        Some(format!("{:#x}", d.implementation))
                    },
                    tx_hash: "0xtx".into(),
                    nonce: None,
                })
            })
            .collect();

        let storage = Storage::in_memory().await.unwrap();
        apply_block(
            storage.pool(),
            &BlockInput {
                number: 1,
                hash: "A".into(),
                parent_hash: "GENESIS".into(),
                timestamp: 1,
                changes,
            },
        )
        .await
        .unwrap();

        let authority = format!("{:#x}", signer.address());
        assert_eq!(
            current_delegation(storage.pool(), &authority)
                .await
                .unwrap(),
            Some(format!("{impl_addr:#x}"))
        );
    }
}

// ───────────────────────── Live RPC ingestion (Phase 7) ─────────────────────

use alloy::consensus::Transaction as _;
use alloy::eips::BlockNumberOrTag;
// use alloy::primitives::{Address, B256};
use alloy::network::TransactionResponse;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::{Block, Transaction};
use futures_util::StreamExt;
use tokio::sync::broadcast;

use crate::chain::{self, BlockProvider, FetchedBlock};
use crate::domain::{Delegation, DelegationCreatedEvent};
use crate::tracker::ChangeInput;

/// A live source backed by an Alloy provider (HTTP or WS).
pub struct RpcSource<P> {
    pub provider: P,
}

impl<P: Provider + Send + Sync> BlockProvider for RpcSource<P> {
    async fn block_by_number(&self, number: u64) -> Result<Option<FetchedBlock>, AppError> {
        let block = self
            .provider
            .get_block_by_number(BlockNumberOrTag::Number(number))
            .full()
            .await
            .map_err(|e| AppError::Rpc(format!("{e:?}")))?;
        Ok(block.map(to_fetched))
    }

    async fn block_by_hash(&self, hash: &str) -> Result<Option<FetchedBlock>, AppError> {
        let h: B256 = hash
            .parse()
            .map_err(|e| AppError::Rpc(format!("bad hash {hash}: {e:?}")))?;
        let block = self
            .provider
            .get_block(h.into())
            .full()
            .await
            .map_err(|e| AppError::Rpc(format!("{e:?}")))?;
        Ok(block.map(to_fetched))
    }

    async fn head_number(&self) -> Result<u64, AppError> {
        self.provider
            .get_block_number()
            .await
            .map_err(|e| AppError::Rpc(format!("{e:?}")))
    }

    async fn code_at(&self, address: &str) -> Result<Option<String>, AppError> {
        let addr: Address = address
            .parse()
            .map_err(|e| AppError::Rpc(format!("bad address {address}: {e}")))?;
        let code = self
            .provider
            .get_code_at(addr)
            .await
            .map_err(|e| AppError::Rpc(e.to_string()))?;
        if code.is_empty() {
            Ok(None)
        } else {
            Ok(Some(format!("0x{}", alloy::hex::encode(&code))))
        }
    }
}

/// Convert an Alloy block into our source-agnostic FetchedBlock.
fn to_fetched(block: Block) -> FetchedBlock {
    let changes = block
        .transactions
        .as_transactions()
        .unwrap_or(&[])
        .iter()
        .flat_map(extract_changes)
        .collect();

    FetchedBlock {
        number: block.header.number,
        hash: format!("{:#x}", block.header.hash),
        parent_hash: format!("{:#x}", block.header.parent_hash),
        timestamp: block.header.timestamp,
        changes,
    }
}

/// Pull EIP-7702 delegation changes out of one transaction.
fn extract_changes(tx: &Transaction) -> Vec<ChangeInput> {
    let Some(list) = tx.authorization_list() else {
        return Vec::new();
    };
    let tx_hash = format!("{:#x}", tx.tx_hash());

    list.iter()
        .filter_map(|signed| {
            let authority = signed.recover_authority().ok()?;
            let implementation = signed.inner().address;
            let new_implementation = if implementation == Address::ZERO {
                None // delegating to 0x0 clears the delegation
            } else {
                Some(format!("{implementation:#x}"))
            };
            Some(ChangeInput {
                authority: format!("{authority:#x}"),
                new_implementation,
                tx_hash: tx_hash.clone(),
                nonce: Some(signed.inner().nonce),
            })
        })
        .collect()
}

fn to_event(chain_id: u64, block_number: u64, c: &ChangeInput) -> DelegationCreatedEvent {
    let delegation = Delegation {
        id: uuid::Uuid::new_v4().to_string(),
        account: c.authority.clone(),
        implementation: c
            .new_implementation
            .clone()
            .unwrap_or_else(|| "0x0000000000000000000000000000000000000000".into()),
        chain_id: chain_id.to_string(),
        block_number: block_number.to_string(),
        transaction_hash: c.tx_hash.clone(),
        status: if c.new_implementation.is_some() {
            "active".into()
        } else {
            "cleared".into()
        },
        created_at: chrono::Utc::now(),
    };
    DelegationCreatedEvent {
        kind: "delegation.created",
        delegation,
    }
}

/// Backfill from the resume point to head over HTTP, then follow new heads over WS.
pub async fn run_ingestion(
    pool: sqlx::SqlitePool,
    events: broadcast::Sender<DelegationCreatedEvent>,
    http_url: String,
    ws_url: Option<String>,
    chain_id: u64,
    start_block: u64,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), AppError> {
    let http = ProviderBuilder::new()
        .connect(&http_url)
        .await
        .map_err(|e| AppError::Rpc(format!("http connect: {e}")))?;
    let http_source = RpcSource { provider: http };

    let resume = chain::next_block_to_process(&pool)
        .await?
        .unwrap_or(start_block);
    let head = chain::with_retry(|| http_source.head_number()).await?;
    if resume <= head {
        tracing::info!(resume, head, "backfilling");
        chain::backfill(&pool, &http_source, chain_id, resume, head).await?;
    }

    let Some(ws_url) = ws_url else {
        tracing::warn!("RPC_WS_URL not set; backfill-only mode");
        pool.close().await;
        return Ok(());
    };

    let ws = ProviderBuilder::new()
        .connect(&ws_url)
        .await
        .map_err(|e| AppError::Rpc(format!("ws connect: {e}")))?;
    let ws_source = RpcSource { provider: ws };
    let subscription = ws_source
        .provider
        .subscribe_blocks()
        .await
        .map_err(|e| AppError::Rpc(format!("subscribe: {e}")))?;
    let mut stream = subscription.into_stream();
    tracing::info!("subscribed to new heads");

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                tracing::info!("ingestion received shutdown; finishing");
                break;
            }
            maybe_header = stream.next() => {
                let Some(header) = maybe_header else { break };
                let number = header.number;
                match chain::with_retry(|| ws_source.block_by_number(number)).await {
                    Ok(Some(block)) => {
                        let block_number = block.number;
                        // Failure isolation: a bad block is logged and skipped, never fatal.
                        match chain::process_and_analyze(&pool, &ws_source, chain_id, block).await {
                            Ok(changes) => {
                                for change in &changes {
                                    let _ = events.send(to_event(chain_id, block_number, change));
                                }
                                metrics::gauge!("ingestion_lag_blocks").set(0.0);
                            }
                            Err(error) => tracing::error!(%error, number, "process_block failed"),
                        }
                    }
                    Ok(None) => tracing::warn!(number, "head block not found"),
                    Err(error) => tracing::error!(%error, number, "fetch head failed"),
                }
            }
        }
    }

    pool.close().await; // flush + close the DB pool on shutdown
    tracing::info!("ingestion stopped");
    Ok(())
}
