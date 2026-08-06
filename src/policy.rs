//! Risk policy engine: turns findings into explainable, policy-weighted account
//! risk. Anomaly signals are kept strictly separate from vulnerability findings,
//! and alert status follows the canonical chain state.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::analyzer::{Confidence, Finding, Severity};
use crate::error::AppError;

// ───────────────────────── Policy (6.1) ─────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct RiskPolicy {
    pub version: u32,
    pub rule_weights: HashMap<String, f64>,
    pub severity_multipliers: HashMap<String, f64>,
    pub confidence_multipliers: HashMap<String, f64>,
    pub thresholds: Thresholds,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Thresholds {
    pub medium: f64,
    pub high: f64,
    pub critical: f64,
}

impl RiskPolicy {
    pub fn from_yaml_str(yaml: &str) -> Result<Self, AppError> {
        serde_yaml::from_str(yaml)
            .map_err(|e| AppError::Config(format!("invalid risk policy: {e}")))
    }

    pub fn load(path: &str) -> Result<Self, AppError> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| AppError::Config(format!("read {path}: {e}")))?;
        Self::from_yaml_str(&raw)
    }
}

// ───────────────────────── Scoring (6.2) ─────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// One finding's traceable contribution to the score.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RiskContribution {
    pub rule_id: String,
    pub weight: f64,
    pub severity_multiplier: f64,
    pub confidence_multiplier: f64,
    pub points: f64,
}

#[derive(Debug, Clone, Default)]
pub struct Observations {
    pub implementation_first_seen_within_24h: bool,
    pub redelegations_last_hour: u32,
    pub delegations_to_impl_last_hour: u32,
    pub accounts_sharing_implementation: u32,
    pub source_available: bool,
}

pub struct AccountInput {
    pub authority: String,
    pub implementation: Option<String>,
    pub bytecode_hash: Option<String>,
    pub delegation_block: Option<u64>,
    pub canonical: bool,
    pub findings: Vec<Finding>,
    pub observations: Observations,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountRisk {
    pub authority: String,
    pub implementation: Option<String>,
    pub bytecode_hash: Option<String>,
    pub delegation_block: Option<u64>,
    pub canonical: bool,
    pub score: f64,
    pub level: RiskLevel,
    pub confidence: Confidence,
    pub contributions: Vec<RiskContribution>, // traceability
    pub findings: Vec<Finding>,
    pub anomalies: Vec<AnomalySignal>, // separate from score
    pub last_analyzed: String,
}

pub fn compute_account_risk(policy: &RiskPolicy, input: &AccountInput) -> AccountRisk {
    let (score, contributions) = score_findings(policy, &input.findings);

    AccountRisk {
        authority: input.authority.clone(),
        implementation: input.implementation.clone(),
        bytecode_hash: input.bytecode_hash.clone(),
        delegation_block: input.delegation_block,
        canonical: input.canonical,
        score,
        level: level_for(policy, score),
        confidence: aggregate_confidence(&input.findings),
        contributions,
        findings: input.findings.clone(),
        anomalies: detect_anomalies(&input.observations),
        last_analyzed: chrono::Utc::now().to_rfc3339(),
    }
}

fn score_findings(policy: &RiskPolicy, findings: &[Finding]) -> (f64, Vec<RiskContribution>) {
    let mut total = 0.0;
    let mut contributions = Vec::new();

    for f in findings {
        let weight = *policy.rule_weights.get(&f.rule_id).unwrap_or(&0.0);
        let severity_multiplier = *policy
            .severity_multipliers
            .get(severity_key(f.severity))
            .unwrap_or(&1.0);
        let confidence_multiplier = *policy
            .confidence_multipliers
            .get(confidence_key(f.confidence))
            .unwrap_or(&1.0);
        let points = weight * severity_multiplier * confidence_multiplier;
        total += points;
        contributions.push(RiskContribution {
            rule_id: f.rule_id.clone(),
            weight,
            severity_multiplier,
            confidence_multiplier,
            points,
        });
    }

    (total, contributions)
}

fn level_for(policy: &RiskPolicy, score: f64) -> RiskLevel {
    if score >= policy.thresholds.critical {
        RiskLevel::Critical
    } else if score >= policy.thresholds.high {
        RiskLevel::High
    } else if score >= policy.thresholds.medium {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    }
}

fn aggregate_confidence(findings: &[Finding]) -> Confidence {
    findings
        .iter()
        .map(|f| f.confidence)
        .max_by_key(|c| confidence_rank(*c))
        .unwrap_or(Confidence::Heuristic)
}

// ───────────────────────── Anomalies (6.3) — heuristic, separate ─────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AnomalyKind {
    NewImplementation,
    DelegationSpike,
    RapidRedelegation,
    SharedImplementation,
    MissingSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnomalySignal {
    pub kind: AnomalyKind,
    pub description: String,
    pub heuristic: bool, // always true — these are signals, not proof
}

fn detect_anomalies(obs: &Observations) -> Vec<AnomalySignal> {
    let mut signals = Vec::new();
    let mut push = |kind, description: &str| {
        signals.push(AnomalySignal {
            kind,
            description: description.to_owned(),
            heuristic: true,
        });
    };

    if obs.implementation_first_seen_within_24h {
        push(
            AnomalyKind::NewImplementation,
            "implementation first seen within the last 24h",
        );
    }
    if obs.redelegations_last_hour >= 3 {
        push(
            AnomalyKind::RapidRedelegation,
            "account re-delegated 3+ times in the last hour",
        );
    }
    if obs.delegations_to_impl_last_hour >= 50 {
        push(
            AnomalyKind::DelegationSpike,
            "50+ accounts delegated to this implementation in the last hour",
        );
    }
    if obs.accounts_sharing_implementation >= 100 {
        push(
            AnomalyKind::SharedImplementation,
            "implementation is shared by 100+ accounts",
        );
    }
    if !obs.source_available {
        push(
            AnomalyKind::MissingSource,
            "no verified source available for the implementation",
        );
    }
    signals
}

// ───────────────────────── Alert lifecycle (6.4) ─────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AlertStatus {
    Active,
    Resolved,
    RevertedByReorg,
    Superseded,
}

/// Derive an alert's status from the world's current facts.
pub fn evaluate_alert(canonical: bool, superseded: bool, resolved: bool) -> AlertStatus {
    if !canonical {
        AlertStatus::RevertedByReorg
    } else if superseded {
        AlertStatus::Superseded
    } else if resolved {
        AlertStatus::Resolved
    } else {
        AlertStatus::Active
    }
}

/// React to a canonical-state change from the reorg engine: an Active alert whose
/// block is reverted becomes RevertedByReorg; if that block returns, it restores.
pub fn on_canonical_change(status: AlertStatus, canonical: bool) -> AlertStatus {
    match (status, canonical) {
        (AlertStatus::Active, false) => AlertStatus::RevertedByReorg,
        (AlertStatus::RevertedByReorg, true) => AlertStatus::Active,
        (other, _) => other,
    }
}

// ───────────────────────── Key mappings ─────────────────────────

fn severity_key(s: Severity) -> &'static str {
    match s {
        Severity::Informational => "Informational",
        Severity::Low => "Low",
        Severity::Medium => "Medium",
        Severity::High => "High",
        Severity::Critical => "Critical",
    }
}

fn confidence_key(c: Confidence) -> &'static str {
    match c {
        Confidence::Heuristic => "Heuristic",
        Confidence::Probable => "Probable",
        Confidence::Confirmed => "Confirmed",
    }
}

fn confidence_rank(c: Confidence) -> u8 {
    match c {
        Confidence::Heuristic => 0,
        Confidence::Probable => 1,
        Confidence::Confirmed => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The committed policy file must parse.
    fn policy() -> RiskPolicy {
        RiskPolicy::from_yaml_str(include_str!("../config/risk-policy.yaml")).unwrap()
    }

    fn finding(rule_id: &str, severity: Severity, confidence: Confidence) -> Finding {
        Finding {
            rule_id: rule_id.to_owned(),
            title: "t".into(),
            severity,
            confidence,
            evidence: "e".into(),
            explanation: "x".into(),
            remediation: "r".into(),
            analyzer_version: "0.1.0".into(),
            rule_version: "1".into(),
            source_hash: None,
            bytecode_hash: "0x00".into(),
            timestamp: "t".into(),
        }
    }

    fn input(findings: Vec<Finding>, obs: Observations, canonical: bool) -> AccountInput {
        AccountInput {
            authority: "0xaa".into(),
            implementation: Some("0x11".into()),
            bytecode_hash: Some("0x00".into()),
            delegation_block: Some(100),
            canonical,
            findings,
            observations: obs,
        }
    }

    #[test]
    fn score_is_traceable_to_findings() {
        let p = policy();
        // DL-002 High Probable: 50 * 1.5 * 0.85 = 63.75
        let risk = compute_account_risk(
            &p,
            &input(
                vec![finding("DL-002", Severity::High, Confidence::Probable)],
                Observations::default(),
                true,
            ),
        );
        assert_eq!(risk.contributions.len(), 1);
        assert!((risk.contributions[0].points - 63.75).abs() < 1e-9);
        let sum: f64 = risk.contributions.iter().map(|c| c.points).sum();
        assert!((sum - risk.score).abs() < 1e-9); // score == sum of contributions
        assert_eq!(risk.level, RiskLevel::Medium); // 63.75 is in [40, 80)
    }

    #[test]
    fn policy_change_triggers_reevaluation() {
        let strict = RiskPolicy::from_yaml_str(
            "version: 1\nrule_weights:\n  DL-002: 100\nseverity_multipliers:\n  High: 1.0\nconfidence_multipliers:\n  Probable: 1.0\nthresholds:\n  medium: 40\n  high: 80\n  critical: 120\n",
        ).unwrap();
        let lenient = RiskPolicy::from_yaml_str(
            "version: 1\nrule_weights:\n  DL-002: 10\nseverity_multipliers:\n  High: 1.0\nconfidence_multipliers:\n  Probable: 1.0\nthresholds:\n  medium: 40\n  high: 80\n  critical: 120\n",
        ).unwrap();
        let f = vec![finding("DL-002", Severity::High, Confidence::Probable)];
        let strict_score =
            compute_account_risk(&strict, &input(f.clone(), Observations::default(), true)).score;
        let lenient_score =
            compute_account_risk(&lenient, &input(f, Observations::default(), true)).score;
        assert!(strict_score > lenient_score); // same findings, different policy => different score
    }

    #[test]
    fn anomalies_do_not_affect_score() {
        let p = policy();
        let obs = Observations {
            implementation_first_seen_within_24h: true,
            source_available: false,
            ..Default::default()
        };
        let with_anomalies = compute_account_risk(&p, &input(vec![], obs, true));
        assert!(!with_anomalies.anomalies.is_empty()); // signals present
        assert_eq!(with_anomalies.score, 0.0); // but score unaffected (no findings)
        assert!(with_anomalies.anomalies.iter().all(|a| a.heuristic));
    }

    #[test]
    fn alerts_follow_canonical_state() {
        assert_eq!(
            evaluate_alert(false, false, false),
            AlertStatus::RevertedByReorg
        );
        assert_eq!(evaluate_alert(true, true, false), AlertStatus::Superseded);
        assert_eq!(evaluate_alert(true, false, true), AlertStatus::Resolved);
        assert_eq!(evaluate_alert(true, false, false), AlertStatus::Active);

        // Reorg reverts an active alert; restoring the block reactivates it.
        assert_eq!(
            on_canonical_change(AlertStatus::Active, false),
            AlertStatus::RevertedByReorg
        );
        assert_eq!(
            on_canonical_change(AlertStatus::RevertedByReorg, true),
            AlertStatus::Active
        );
        // Resolved stays resolved regardless.
        assert_eq!(
            on_canonical_change(AlertStatus::Resolved, false),
            AlertStatus::Resolved
        );
    }
}
