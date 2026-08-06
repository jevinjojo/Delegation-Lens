//! Evidence-based security analyzer for EIP-7702 delegate implementations.
//!
//! Principles: prefer verified source over bytecode; separate severity from
//! confidence; attach evidence + remediation to every finding; never claim to
//! detect all vulnerabilities.

use std::collections::HashMap;

use alloy::primitives::keccak256;
use serde::Serialize;

pub const ANALYZER_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Confidence {
    Heuristic, // pattern match only (e.g. bytecode selector)
    Probable,  // strong source-based evidence, not formally proven
    Confirmed, // proven (e.g. exploit fixture) — reserved for the strongest cases
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub evidence: String,
    pub explanation: String,
    pub remediation: String,
    // Versioning (5.5) — every finding is reproducible.
    pub analyzer_version: String,
    pub rule_version: String,
    pub source_hash: Option<String>,
    pub bytecode_hash: String,
    pub timestamp: String,
}

// ───────────────────────── Resolver (5.1) ─────────────────────────

#[derive(Debug, Clone)]
pub struct ResolvedImplementation {
    pub chain_id: u64,
    pub address: String,
    pub bytecode: String,
    pub bytecode_hash: String,
    pub verified_source: Option<String>,
    pub source_hash: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
}

impl ResolvedImplementation {
    pub fn new(
        chain_id: u64,
        address: String,
        bytecode: String,
        verified_source: Option<String>,
    ) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        let bytecode_hash = hex_keccak(bytecode.as_bytes());
        let source_hash = verified_source.as_ref().map(|s| hex_keccak(s.as_bytes()));
        Self {
            chain_id,
            address,
            bytecode,
            bytecode_hash,
            verified_source,
            source_hash,
            first_seen: now.clone(),
            last_seen: now,
        }
    }

    // Cache key: chain_id + address + bytecode_hash + analyzer_version (5.1).
    fn cache_key(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.chain_id, self.address, self.bytecode_hash, ANALYZER_VERSION
        )
    }
}

// ───────────────────────── Analyzer (with cache) ─────────────────────────

#[derive(Default)]
pub struct Analyzer {
    cache: HashMap<String, Vec<Finding>>,
}

impl Analyzer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns (findings, from_cache). Results are cached by the resolver key.
    pub fn analyze(&mut self, imp: &ResolvedImplementation) -> (Vec<Finding>, bool) {
        let key = imp.cache_key();
        if let Some(cached) = self.cache.get(&key) {
            return (cached.clone(), true);
        }
        let findings: Vec<Finding> = [rule_dl001(imp), rule_dl002(imp), rule_dl003(imp)]
            .into_iter()
            .flatten()
            .collect();
        self.cache.insert(key, findings.clone());
        (findings, false)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AnalysisStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalysisOutcome {
    pub status: AnalysisStatus,
    pub findings: Vec<Finding>,
}

/// Runs analysis with total failure isolation. A resolver error => Failed,
/// missing code => Skipped, success => Completed. Never panics or propagates,
/// so a single bad analysis can never stop the ingestion loop.
pub fn run_analysis(
    analyzer: &mut Analyzer,
    resolved: Result<Option<ResolvedImplementation>, String>,
) -> AnalysisOutcome {
    match resolved {
        Err(error) => {
            tracing::warn!(%error, "analysis resolver failed");
            metrics::counter!("implementations_analyzed_total").increment(1);
            AnalysisOutcome {
                status: AnalysisStatus::Failed,
                findings: Vec::new(),
            }
        }
        Ok(None) => {
            metrics::counter!("implementations_analyzed_total").increment(1);
            AnalysisOutcome {
                status: AnalysisStatus::Skipped,
                findings: Vec::new(),
            }
        }
        Ok(Some(imp)) => {
            let started = std::time::Instant::now();
            let (findings, _cached) = analyzer.analyze(&imp);
            metrics::histogram!("analysis_duration_seconds")
                .record(started.elapsed().as_secs_f64());
            metrics::counter!("implementations_analyzed_total").increment(1);
            metrics::counter!("findings_total").increment(findings.len() as u64);
            AnalysisOutcome {
                status: AnalysisStatus::Completed,
                findings,
            }
        }
    }
}

// ───────────────────────── Rules (5.3) ─────────────────────────

fn rule_dl001(imp: &ResolvedImplementation) -> Option<Finding> {
    match imp.verified_source.as_deref() {
        Some(source) => {
            let body = function_span(source, "initialize")?; // no initializer => no finding
            let guarded = body.contains("msg.sender")
                || body.contains("onlyOwner")
                || body.contains("initializer")
                || body.contains("!initialized");
            if guarded {
                None
            } else {
                Some(finding(
                    imp,
                    "DL-001",
                    Severity::High,
                    Confidence::Probable,
                    "public initialize() has no caller guard or one-time protection",
                    "The delegate exposes an unguarded initializer. Because anyone can call a \
                     delegated EOA, an attacker can initialize it and seize any owner/admin role.",
                    "Gate initialization to `msg.sender == address(this)` (or verify an EOA \
                     signature) and enforce a one-time `initialized` flag.",
                ))
            }
        }
        None => {
            if has_selector(&imp.bytecode, "initialize(address)") {
                Some(finding(
                    imp,
                    "DL-001",
                    Severity::Low,
                    Confidence::Heuristic,
                    "initialize(address) selector present in bytecode",
                    "An initializer selector exists, but without source we cannot confirm whether \
                     it is access-controlled.",
                    "Verify the source, or confirm the initializer is caller-guarded and one-time.",
                ))
            } else {
                None
            }
        }
    }
}

fn rule_dl002(imp: &ResolvedImplementation) -> Option<Finding> {
    match imp.verified_source.as_deref() {
        Some(source) => {
            let body = function_span(source, "execute")?;
            let makes_arbitrary_call = body.contains(".call{") || body.contains(".call(");
            if !makes_arbitrary_call {
                return None;
            }
            let authenticated = body.contains("ecrecover") || body.contains("msg.sender");
            if authenticated {
                None
            } else {
                Some(finding(
                    imp,
                    "DL-002",
                    Severity::High,
                    Confidence::Probable,
                    "public execute() performs an arbitrary call with no authentication",
                    "The delegate lets any caller make the account perform arbitrary calls/value \
                     transfers, i.e. full control of the EOA's funds and actions.",
                    "Require an EOA signature (or `msg.sender == address(this)`) authorizing the \
                     exact target, value, and calldata before executing.",
                ))
            }
        }
        None => {
            if has_selector(&imp.bytecode, "execute(address,uint256,bytes)") {
                Some(finding(
                    imp,
                    "DL-002",
                    Severity::Medium,
                    Confidence::Heuristic,
                    "execute(address,uint256,bytes) selector present in bytecode",
                    "An arbitrary-execution selector exists, but without source we cannot confirm \
                     whether the call path is authenticated.",
                    "Verify the source and confirm the execute path checks authorization.",
                ))
            } else {
                None
            }
        }
    }
}

fn rule_dl003(imp: &ResolvedImplementation) -> Option<Finding> {
    // Replay controls only matter where there IS a signature check. Bytecode-only
    // cannot reliably assess this, so we stay silent there (no overclaiming).
    let source = imp.verified_source.as_deref()?;
    let body = function_span(source, "execute").unwrap_or_default();
    if !body.contains("ecrecover") {
        return None;
    }

    let mut missing = Vec::new();
    if !body.contains("nonce") {
        missing.push("nonce");
    }
    if !body.contains("deadline") {
        missing.push("deadline");
    }
    if !body.contains("chainid") {
        missing.push("chainId");
    }

    if missing.is_empty() {
        None
    } else {
        Some(finding(
            imp,
            "DL-003",
            Severity::Medium,
            Confidence::Probable,
            &format!(
                "signed action is missing replay controls: {}",
                missing.join(", ")
            ),
            "The signature-verified action does not bind all replay-protection fields, so a valid \
             signature can be replayed (repeated, or reused across chains/accounts).",
            "Bind nonce, deadline, chainId, and the account into the signed digest, and consume \
             the nonce before the external call.",
        ))
    }
}

// ───────────────────────── Helpers ─────────────────────────

fn finding(
    imp: &ResolvedImplementation,
    rule_id: &str,
    severity: Severity,
    confidence: Confidence,
    evidence: &str,
    explanation: &str,
    remediation: &str,
) -> Finding {
    Finding {
        rule_id: rule_id.to_owned(),
        title: rule_title(rule_id).to_owned(),
        severity,
        confidence,
        evidence: evidence.to_owned(),
        explanation: explanation.to_owned(),
        remediation: remediation.to_owned(),
        analyzer_version: ANALYZER_VERSION.to_owned(),
        rule_version: "1".to_owned(),
        source_hash: imp.source_hash.clone(),
        bytecode_hash: imp.bytecode_hash.clone(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    }
}

fn rule_title(rule_id: &str) -> &'static str {
    match rule_id {
        "DL-001" => "Unsafe initialization",
        "DL-002" => "Unprotected arbitrary execution",
        "DL-003" => "Missing signed-action replay controls",
        _ => "Unknown rule",
    }
}

fn hex_keccak(bytes: &[u8]) -> String {
    format!("0x{}", alloy::hex::encode(keccak256(bytes)))
}

/// First 4-byte function selector for a signature, as lowercase hex.
fn selector(signature: &str) -> String {
    alloy::hex::encode(&keccak256(signature.as_bytes()).as_slice()[..4])
}

fn has_selector(bytecode: &str, signature: &str) -> bool {
    bytecode.to_lowercase().contains(&selector(signature))
}

/// Returns the "function <name> ... { ... }" span (signature through the matching
/// closing brace) so guard checks are scoped to that function, not the whole file.
fn function_span(source: &str, name: &str) -> Option<String> {
    let start = source.find(&format!("function {name}"))?;
    let rest = &source[start..];
    let open = rest.find('{')?;
    let mut depth = 0i32;
    for (i, b) in rest.bytes().enumerate().skip(open) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(rest[..=i].to_owned());
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAFE_SRC: &str = r#"
        contract SafeDelegate {
            function initialize(address _owner) external {
                require(msg.sender == address(this), "only self");
                owner = _owner;
            }
            function execute(address target, uint256 value, bytes calldata data, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
                require(block.timestamp <= deadline, "expired");
                bytes32 digest = keccak256(abi.encode(address(this), block.chainid, nonce, deadline, target, value));
                address signer = ecrecover(digest, v, r, s);
                require(signer == address(this), "bad signature");
                execNonce = nonce + 1;
                (bool ok, ) = target.call{value: value}(data);
            }
        }
    "#;

    const UNSAFE_INIT_SRC: &str = r#"
        contract UnsafeInitDelegate {
            function initialize(address _owner) external {
                owner = _owner;
                initialized = true;
            }
            function sweep(address to) external {
                require(msg.sender == owner, "not owner");
                (bool ok, ) = to.call{value: address(this).balance}("");
            }
        }
    "#;

    const OPEN_EXECUTE_SRC: &str = r#"
        contract OpenExecuteDelegate {
            function execute(address target, uint256 value, bytes calldata data) external returns (bytes memory) {
                (bool ok, bytes memory ret) = target.call{value: value}(data);
                require(ok, "call failed");
                return ret;
            }
        }
    "#;

    const REPLAYABLE_SRC: &str = r#"
        contract ReplayableDelegate {
            function execute(address target, uint256 value, bytes calldata data, uint8 v, bytes32 r, bytes32 s) external {
                bytes32 digest = keccak256(abi.encode(target, value, keccak256(data)));
                address signer = ecrecover(digest, v, r, s);
                require(signer == address(this), "bad signature");
                (bool ok, ) = target.call{value: value}(data);
            }
        }
    "#;

    fn resolve(name: &str, src: &str) -> ResolvedImplementation {
        ResolvedImplementation::new(
            11_155_111,
            format!("0x{name}"),
            "0x6080604052".into(),
            Some(src.into()),
        )
    }

    // 5.4: TP/FP/FN — safe is clean, each vulnerable fires exactly its own rule.
    #[test]
    fn true_and_false_positive_measurement() {
        let mut a = Analyzer::new();
        let cases: [(&str, &str, Option<&str>); 4] = [
            ("safe", SAFE_SRC, None),
            ("unsafe_init", UNSAFE_INIT_SRC, Some("DL-001")),
            ("open_execute", OPEN_EXECUTE_SRC, Some("DL-002")),
            ("replayable", REPLAYABLE_SRC, Some("DL-003")),
        ];
        for (name, src, expected) in cases {
            let (findings, _) = a.analyze(&resolve(name, src));
            let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
            match expected {
                None => assert!(findings.is_empty(), "{name} should be clean; got {ids:?}"),
                Some(rule) => {
                    assert_eq!(
                        findings.len(),
                        1,
                        "{name} should fire exactly one rule; got {ids:?}"
                    );
                    assert_eq!(ids[0], rule, "{name} fired the wrong rule");
                }
            }
        }
    }

    #[test]
    fn severity_and_confidence_are_independent() {
        let mut a = Analyzer::new();
        let (findings, _) = a.analyze(&resolve("open", OPEN_EXECUTE_SRC));
        let dl002 = findings.iter().find(|f| f.rule_id == "DL-002").unwrap();
        assert_eq!(dl002.severity, Severity::High); // bad if real
        assert_eq!(dl002.confidence, Confidence::Probable); // but not "Confirmed"
    }

    #[test]
    fn results_are_cached() {
        let mut a = Analyzer::new();
        let imp = resolve("abc", SAFE_SRC);
        let (_, first) = a.analyze(&imp);
        let (_, second) = a.analyze(&imp);
        assert!(!first, "first call should compute");
        assert!(second, "second call should hit cache");
    }

    #[test]
    fn bytecode_only_is_lower_confidence() {
        let sel = selector("execute(address,uint256,bytes)");
        let bytecode = format!("0x6080604052{sel}");
        let mut a = Analyzer::new();
        let imp = ResolvedImplementation::new(1, "0xbc".into(), bytecode, None); // no source
        let (findings, _) = a.analyze(&imp);
        let dl002 = findings.iter().find(|f| f.rule_id == "DL-002").unwrap();
        assert_eq!(dl002.confidence, Confidence::Heuristic); // can't confirm without source
    }

    #[test]
    fn analysis_status_reflects_input() {
        let mut a = Analyzer::new();

        // Resolver failure is isolated -> Failed, no panic.
        let failed = run_analysis(&mut a, Err("rpc down".into()));
        assert_eq!(failed.status, AnalysisStatus::Failed);

        // No code available -> Skipped.
        let skipped = run_analysis(&mut a, Ok(None));
        assert_eq!(skipped.status, AnalysisStatus::Skipped);

        // Vulnerable source -> Completed with a finding.
        let imp = resolve("open", OPEN_EXECUTE_SRC);
        let done = run_analysis(&mut a, Ok(Some(imp)));
        assert_eq!(done.status, AnalysisStatus::Completed);
        assert_eq!(done.findings.len(), 1);
    }
}
