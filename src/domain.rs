use alloy::primitives::{Address, B256, U256};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::FromRow)]
pub struct Delegation {
    pub id: String,
    pub account: String,
    pub implementation: String,
    pub chain_id: String,
    pub block_number: String,
    pub transaction_hash: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Default, Deserialize)]
pub struct CreateDelegation {
    pub account: Option<String>,
    pub implementation: Option<String>,
    pub chain_id: Option<String>,
    pub block_number: Option<String>,
    pub transaction_hash: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DelegationCreatedEvent {
    pub kind: &'static str,
    pub delegation: Delegation,
}

// ─────────────────────────────────────────────────────────────
// Phase 1 domain model (blockchain-typed). These are the "truth"
// types the decoder/tracker will produce; the string-based
// `Delegation` above remains the API/DB transport shape for now.
// ─────────────────────────────────────────────────────────────

/// A pointer to one block in the chain. `parent_hash` is what lets the
/// tracker detect reorgs (Phase 4): if a new block's parent doesn't match
/// the head we stored, the chain reorganized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockRef {
    pub number: u64,
    pub hash: B256,
    pub parent_hash: B256,
    pub timestamp: u64,
}

/// One EIP-7702 authorization tuple. Mirrors alloy's `Authorization`
/// (chain_id / address / nonce); `authority` is the signer we recover
/// from the signature in Phase 3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authorization {
    pub chain_id: U256,   // 0 means "valid on any chain"
    pub address: Address, // the implementation the account points to
    pub nonce: u64,
    pub authority: Address, // recovered account being delegated
}

/// A change to an account's delegation, tied to the block/tx that caused it.
/// `new_implementation == None` means the delegation was CLEARED
/// (EIP-7702 sets the pointer to the zero address).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationChange {
    pub authority: Address,
    pub previous_implementation: Option<Address>,
    pub new_implementation: Option<Address>,
    pub authorization: Authorization,
    pub block: BlockRef,
    pub tx_hash: B256,
}

/// What the chain source emits to the rest of the system. Modeling this as
/// an enum makes reorgs first-class: a block is either applied or reverted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainUpdate {
    Applied(BlockRef),
    Reverted(BlockRef),
}

impl CreateDelegation {
    pub fn into_delegation(self) -> Delegation {
        // Build a valid 0x + 64-hex transaction hash from a uuid when none is given.
        let hex = uuid::Uuid::new_v4().simple().to_string(); // 32 hex chars
        let tx = format!("0x{hex}{hex}"); // 64 hex chars

        Delegation {
            id: uuid::Uuid::new_v4().to_string(),
            account: self
                .account
                .unwrap_or_else(|| "0x1111111111111111111111111111111111111111".to_owned()),
            implementation: self
                .implementation
                .unwrap_or_else(|| "0x2222222222222222222222222222222222222222".to_owned()),
            chain_id: self.chain_id.unwrap_or_else(|| "11155111".to_owned()),
            block_number: self.block_number.unwrap_or_else(|| "6100000".to_owned()),
            transaction_hash: self.transaction_hash.unwrap_or(tx),
            status: self.status.unwrap_or_else(|| "active".to_owned()),
            created_at: Utc::now(),
        }
    }
}
