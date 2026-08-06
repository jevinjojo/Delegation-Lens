//! Reproducible in-memory benchmark. Run: `cargo run --release -- bench`
//! Numbers are hardware-dependent; report the run alongside its machine.

use std::time::Instant;

use crate::analyzer::{Analyzer, ResolvedImplementation};
use crate::error::AppError;
use crate::storage::Storage;
use crate::tracker::{apply_block, revert_block, BlockInput, ChangeInput};

const SAMPLE_SRC: &str =
    "contract C { function execute(address t,uint256 v,bytes calldata d) external { (bool ok,)=t.call{value:v}(d); } }";

pub async fn run() -> Result<(), AppError> {
    let storage = Storage::in_memory().await?;
    let pool = storage.pool();

    // 1. Block application throughput.
    let blocks: u64 = 2000;
    let auths_per_block = 3usize;
    let mut hashes = Vec::with_capacity(blocks as usize);
    let apply_start = Instant::now();
    for n in 1..=blocks {
        let parent = if n == 1 {
            "GENESIS".to_string()
        } else {
            format!("B{}", n - 1)
        };
        let hash = format!("B{n}");
        let changes = (0..auths_per_block)
            .map(|i| ChangeInput {
                authority: format!("0x{:040x}", (n as usize * auths_per_block + i) % 500),
                new_implementation: Some(format!("0x{:040x}", i + 1)),
                tx_hash: format!("0xtx{n}_{i}"),
            })
            .collect();
        apply_block(
            pool,
            &BlockInput {
                number: n,
                hash: hash.clone(),
                parent_hash: parent,
                timestamp: n,
                changes,
            },
        )
        .await?;
        hashes.push(hash);
    }
    let apply = apply_start.elapsed();
    let total_auths = blocks as usize * auths_per_block;

    // 2. Reorg rollback: revert the last 100 blocks (head-first).
    let revert_n = 100usize;
    let revert_start = Instant::now();
    for hash in hashes.iter().rev().take(revert_n) {
        revert_block(pool, hash).await?;
    }
    let revert = revert_start.elapsed();

    // 3. Analyzer throughput (distinct addresses => not cache hits).
    let mut analyzer = Analyzer::new();
    let runs = 5000usize;
    let analyze_start = Instant::now();
    for i in 0..runs {
        let imp = ResolvedImplementation::new(
            1,
            format!("0x{i:040x}"),
            "0x6080604052".into(),
            Some(SAMPLE_SRC.into()),
        );
        let _ = analyzer.analyze(&imp);
    }
    let analyze = analyze_start.elapsed();

    println!("=== DelegationLens benchmark (in-memory SQLite) ===");
    println!(
        "apply:   {blocks} blocks / {total_auths} auths in {:.3}s  =>  {:.0} blocks/s, {:.0} auths/s",
        apply.as_secs_f64(),
        blocks as f64 / apply.as_secs_f64(),
        total_auths as f64 / apply.as_secs_f64()
    );
    println!(
        "reorg:   reverted {revert_n} blocks in {:.3}s  =>  {:.2} ms/block",
        revert.as_secs_f64(),
        revert.as_secs_f64() * 1000.0 / revert_n as f64
    );
    println!(
        "analyze: {runs} runs in {:.3}s  =>  {:.0} analyses/s",
        analyze.as_secs_f64(),
        runs as f64 / analyze.as_secs_f64()
    );
    Ok(())
}
