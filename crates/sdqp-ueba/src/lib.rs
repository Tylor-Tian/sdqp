use std::collections::{HashMap, HashSet};

use chrono::{Timelike, Utc};
use sdqp_audit::{ActionResult, ActionType, AuditEvent};
use sdqp_system_security::AdaptiveResponse;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UebaRule {
    HighFrequencyQuery,
    ExportSpike,
    UnauthorizedQueryBurst,
    AfterHoursAccess,
    HiddenChannelDns,
    HiddenChannelHttp,
}

impl UebaRule {
    pub fn rule_id(&self) -> &'static str {
        match self {
            Self::HighFrequencyQuery => "high_frequency_query",
            Self::ExportSpike => "export_spike",
            Self::UnauthorizedQueryBurst => "unauthorized_query_burst",
            Self::AfterHoursAccess => "after_hours_access",
            Self::HiddenChannelDns => "hidden_channel_dns",
            Self::HiddenChannelHttp => "hidden_channel_http",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MitigationAction {
    Observe,
    StepUpAuth,
    SuspendPermissions,
    TerminateSession,
}

impl MitigationAction {
    pub fn severity(&self) -> u8 {
        match self {
            Self::Observe => 0,
            Self::StepUpAuth => 1,
            Self::SuspendPermissions => 2,
            Self::TerminateSession => 3,
        }
    }

    pub fn from_score(score: f64) -> Self {
        match AdaptiveResponse::for_score(score) {
            AdaptiveResponse::Allow => Self::Observe,
            AdaptiveResponse::StepUpAuth => Self::StepUpAuth,
            AdaptiveResponse::TerminateSession if score < 85.0 => Self::SuspendPermissions,
            AdaptiveResponse::TerminateSession => Self::TerminateSession,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UebaRuleStatus {
    Draft,
    Active,
    Disabled,
    Retired,
}

impl UebaRuleStatus {
    pub fn is_enabled(&self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UebaRuleLifecycleState {
    NoVersions,
    DraftOnly,
    Active,
    Disabled,
    Retired,
    ConflictingActiveVersions,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UebaRuleLifecycleAction {
    CreateDraft,
    Activate,
    Disable,
    Enable,
    Retire,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UebaRuleStateSnapshot {
    pub rule_id: String,
    pub rule: UebaRule,
    pub latest_version: Option<u32>,
    pub active_version: Option<u32>,
    pub draft_versions: Vec<u32>,
    pub disabled_versions: Vec<u32>,
    pub retired_versions: Vec<u32>,
    pub lifecycle_state: UebaRuleLifecycleState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UebaRuleLifecycleTransition {
    pub rule_id: String,
    pub action: UebaRuleLifecycleAction,
    pub version: u32,
    pub previous_status: Option<UebaRuleStatus>,
    pub next_status: UebaRuleStatus,
    pub active_version_after: Option<u32>,
    pub retired_versions: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UebaRuleThresholds {
    pub min_events: usize,
    pub baseline_multiplier: f64,
    pub baseline_offset: usize,
    pub risk_score: u8,
    pub business_hours_start_utc: Option<u8>,
    pub business_hours_end_utc: Option<u8>,
}

impl UebaRuleThresholds {
    pub fn alert_threshold(&self, baseline_count: usize) -> usize {
        let multiplier = finite_non_negative(self.baseline_multiplier).unwrap_or(1.0);
        ((baseline_count as f64) * multiplier).ceil() as usize + self.baseline_offset
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UebaRulePattern {
    pub any_terms: Vec<String>,
    pub all_terms: Vec<String>,
}

impl UebaRulePattern {
    pub fn matches_context(&self, context: &str) -> bool {
        let context = context.to_ascii_lowercase();
        let all_terms_match = self
            .all_terms
            .iter()
            .all(|term| context.contains(&term.to_ascii_lowercase()));
        let any_terms_match = self.any_terms.is_empty()
            || self
                .any_terms
                .iter()
                .any(|term| context.contains(&term.to_ascii_lowercase()));
        all_terms_match && any_terms_match
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UebaRuleTuning {
    pub thresholds: UebaRuleThresholds,
    pub action_override: Option<MitigationAction>,
    pub pattern: Option<UebaRulePattern>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UebaRuleVersion {
    pub version: u32,
    pub status: UebaRuleStatus,
    pub tuning: UebaRuleTuning,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UebaRuleDefinition {
    pub rule_id: String,
    pub rule: UebaRule,
    pub name: String,
    pub description: String,
    pub versions: Vec<UebaRuleVersion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UebaRuleManagementError {
    RuleNotFound,
    VersionNotFound,
    InvalidLifecycleTransition,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UebaReplayHit {
    pub rule_id: String,
    pub version: u32,
    pub rule: UebaRule,
    pub user_id: String,
    pub tenant_id: String,
    pub project_id: Option<String>,
    pub observed_count: usize,
    pub baseline_count: usize,
    pub threshold_count: usize,
    pub risk_score: u8,
    pub action: MitigationAction,
    pub evidence: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UebaReplayRuleSummary {
    pub rule_id: String,
    pub version: u32,
    pub rule: UebaRule,
    pub users_evaluated: usize,
    pub hit_count: usize,
    pub alert_count: usize,
    pub min_observed_count: usize,
    pub max_observed_count: usize,
    pub average_observed_count: f64,
    pub max_risk_score: u8,
    pub strongest_action: Option<MitigationAction>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UebaReplaySummary {
    pub event_count: usize,
    pub users_evaluated: usize,
    pub rules_evaluated: usize,
    pub hit_count: usize,
    pub alert_count: usize,
    #[serde(default)]
    pub rule_summaries: Vec<UebaReplayRuleSummary>,
    pub hits: Vec<UebaReplayHit>,
    pub alerts: Vec<UebaAlert>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UebaTuningObjective {
    pub target_alert_volume: Option<usize>,
    pub target_precision: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UebaTuningProposal {
    pub rule_id: String,
    pub base_version: u32,
    pub observed_alerts: usize,
    pub estimated_precision: f64,
    pub target_alert_volume: Option<usize>,
    pub target_precision: Option<f64>,
    pub proposed_tuning: UebaRuleTuning,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum UebaCalibrationStatus {
    Ready,
    Sparse,
    #[default]
    InsufficientSamples,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct UebaCalibrationQuality {
    pub sample_factor: f64,
    pub user_factor: f64,
    pub window_factor: f64,
    pub score: f64,
    pub status: UebaCalibrationStatus,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UebaCalibrationWindow {
    pub start: Option<String>,
    pub end: Option<String>,
    pub duration_hours: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UebaCalibrationRuleRecommendation {
    pub rule_id: String,
    pub rule: UebaRule,
    pub sample_p50: usize,
    pub sample_p95: usize,
    pub observed_users: usize,
    pub recommended_thresholds: UebaRuleThresholds,
    pub recommended_action: MitigationAction,
    pub recommended_tuning: UebaRuleTuning,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UebaCalibrationResult {
    pub model_version: String,
    pub sample_count: usize,
    pub distinct_users: usize,
    pub window: UebaCalibrationWindow,
    pub baseline_snapshot: HashMap<String, UserBaseline>,
    #[serde(default)]
    pub quality: UebaCalibrationQuality,
    pub recommendations: Vec<UebaCalibrationRuleRecommendation>,
    pub quality_score: f64,
    pub status: UebaCalibrationStatus,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserBaseline {
    pub query_count: usize,
    pub export_count: usize,
    pub denied_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntityBaselineKey {
    pub entity_type: String,
    pub entity_id: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityBaseline {
    pub query_count: usize,
    pub export_count: usize,
    pub denied_count: usize,
    pub distinct_users: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UebaAlert {
    pub alert_id: String,
    pub user_id: String,
    pub tenant_id: String,
    pub project_id: Option<String>,
    pub rule: UebaRule,
    pub risk_score: u8,
    pub action: MitigationAction,
    pub evidence: String,
}

pub fn default_rule_set() -> Vec<UebaRuleDefinition> {
    vec![
        default_rule_definition(
            UebaRule::HighFrequencyQuery,
            "High frequency query",
            "Detects successful query volume above a user's calibrated query baseline.",
            UebaRuleTuning {
                thresholds: UebaRuleThresholds {
                    min_events: 5,
                    baseline_multiplier: 2.0,
                    baseline_offset: 0,
                    risk_score: 58,
                    business_hours_start_utc: None,
                    business_hours_end_utc: None,
                },
                action_override: None,
                pattern: None,
            },
        ),
        default_rule_definition(
            UebaRule::ExportSpike,
            "Export spike",
            "Detects successful export volume above a user's calibrated export baseline.",
            UebaRuleTuning {
                thresholds: UebaRuleThresholds {
                    min_events: 3,
                    baseline_multiplier: 1.0,
                    baseline_offset: 1,
                    risk_score: 92,
                    business_hours_start_utc: None,
                    business_hours_end_utc: None,
                },
                action_override: None,
                pattern: None,
            },
        ),
        default_rule_definition(
            UebaRule::UnauthorizedQueryBurst,
            "Unauthorized query burst",
            "Detects repeated denied query attempts by the same user.",
            UebaRuleTuning {
                thresholds: UebaRuleThresholds {
                    min_events: 2,
                    baseline_multiplier: 0.0,
                    baseline_offset: 0,
                    risk_score: 78,
                    business_hours_start_utc: None,
                    business_hours_end_utc: None,
                },
                action_override: None,
                pattern: None,
            },
        ),
        default_rule_definition(
            UebaRule::AfterHoursAccess,
            "After-hours access",
            "Detects successful view activity outside the governed UTC business-hours window.",
            UebaRuleTuning {
                thresholds: UebaRuleThresholds {
                    min_events: 1,
                    baseline_multiplier: 0.0,
                    baseline_offset: 0,
                    risk_score: 44,
                    business_hours_start_utc: Some(6),
                    business_hours_end_utc: Some(22),
                },
                action_override: None,
                pattern: None,
            },
        ),
        default_rule_definition(
            UebaRule::HiddenChannelDns,
            "Hidden channel DNS",
            "Detects DNS-like covert-channel indicators in audit context.",
            UebaRuleTuning {
                thresholds: UebaRuleThresholds {
                    min_events: 1,
                    baseline_multiplier: 0.0,
                    baseline_offset: 0,
                    risk_score: 90,
                    business_hours_start_utc: None,
                    business_hours_end_utc: None,
                },
                action_override: None,
                pattern: Some(UebaRulePattern {
                    any_terms: vec!["dns://".into(), " txt ".into(), "base32".into()],
                    all_terms: Vec::new(),
                }),
            },
        ),
        default_rule_definition(
            UebaRule::HiddenChannelHttp,
            "Hidden channel HTTP",
            "Detects HTTP-like covert-channel indicators in audit context.",
            UebaRuleTuning {
                thresholds: UebaRuleThresholds {
                    min_events: 1,
                    baseline_multiplier: 0.0,
                    baseline_offset: 0,
                    risk_score: 88,
                    business_hours_start_utc: None,
                    business_hours_end_utc: None,
                },
                action_override: None,
                pattern: Some(UebaRulePattern {
                    any_terms: vec!["beacon".into(), "pixel".into(), "chunk=".into()],
                    all_terms: vec!["http".into()],
                }),
            },
        ),
    ]
}

pub fn find_rule_version<'a>(
    rules: &'a [UebaRuleDefinition],
    rule_id: &str,
    version: u32,
) -> Option<&'a UebaRuleVersion> {
    rules
        .iter()
        .find(|definition| definition.rule_id == rule_id)
        .and_then(|definition| {
            definition
                .versions
                .iter()
                .find(|rule_version| rule_version.version == version)
        })
}

pub fn find_active_rule_version<'a>(
    rules: &'a [UebaRuleDefinition],
    rule_id: &str,
) -> Option<&'a UebaRuleVersion> {
    rules
        .iter()
        .find(|definition| definition.rule_id == rule_id)
        .and_then(|definition| {
            definition
                .versions
                .iter()
                .find(|rule_version| rule_version.status.is_enabled())
        })
}

pub fn summarize_rule_states(rules: &[UebaRuleDefinition]) -> Vec<UebaRuleStateSnapshot> {
    rules.iter().map(rule_state_snapshot).collect()
}

pub fn create_rule_draft(
    rules: &[UebaRuleDefinition],
    rule_id: &str,
    tuning: UebaRuleTuning,
) -> Result<Vec<UebaRuleDefinition>, UebaRuleManagementError> {
    let mut updated = rules.to_vec();
    let definition = updated
        .iter_mut()
        .find(|definition| definition.rule_id == rule_id)
        .ok_or(UebaRuleManagementError::RuleNotFound)?;
    let version = next_rule_version(definition);
    definition.versions.push(UebaRuleVersion {
        version,
        status: UebaRuleStatus::Draft,
        tuning,
    });
    Ok(updated)
}

pub fn activate_rule_version(
    rules: &[UebaRuleDefinition],
    rule_id: &str,
    version: u32,
) -> Result<Vec<UebaRuleDefinition>, UebaRuleManagementError> {
    set_rule_version_status(rules, rule_id, version, UebaRuleStatus::Active)
}

pub fn activate_rule_version_with_transition(
    rules: &[UebaRuleDefinition],
    rule_id: &str,
    version: u32,
) -> Result<(Vec<UebaRuleDefinition>, UebaRuleLifecycleTransition), UebaRuleManagementError> {
    set_rule_version_status_with_transition(
        rules,
        rule_id,
        version,
        UebaRuleStatus::Active,
        UebaRuleLifecycleAction::Activate,
    )
}

pub fn retire_rule_version(
    rules: &[UebaRuleDefinition],
    rule_id: &str,
    version: u32,
) -> Result<Vec<UebaRuleDefinition>, UebaRuleManagementError> {
    set_rule_version_status(rules, rule_id, version, UebaRuleStatus::Retired)
}

pub fn retire_rule_version_with_transition(
    rules: &[UebaRuleDefinition],
    rule_id: &str,
    version: u32,
) -> Result<(Vec<UebaRuleDefinition>, UebaRuleLifecycleTransition), UebaRuleManagementError> {
    set_rule_version_status_with_transition(
        rules,
        rule_id,
        version,
        UebaRuleStatus::Retired,
        UebaRuleLifecycleAction::Retire,
    )
}

pub fn disable_rule_version(
    rules: &[UebaRuleDefinition],
    rule_id: &str,
    version: u32,
) -> Result<Vec<UebaRuleDefinition>, UebaRuleManagementError> {
    set_rule_version_status(rules, rule_id, version, UebaRuleStatus::Disabled)
}

pub fn disable_rule_version_with_transition(
    rules: &[UebaRuleDefinition],
    rule_id: &str,
    version: u32,
) -> Result<(Vec<UebaRuleDefinition>, UebaRuleLifecycleTransition), UebaRuleManagementError> {
    set_rule_version_status_with_transition(
        rules,
        rule_id,
        version,
        UebaRuleStatus::Disabled,
        UebaRuleLifecycleAction::Disable,
    )
}

pub fn enable_rule_version(
    rules: &[UebaRuleDefinition],
    rule_id: &str,
    version: u32,
) -> Result<Vec<UebaRuleDefinition>, UebaRuleManagementError> {
    set_rule_version_status(rules, rule_id, version, UebaRuleStatus::Active)
}

pub fn enable_rule_version_with_transition(
    rules: &[UebaRuleDefinition],
    rule_id: &str,
    version: u32,
) -> Result<(Vec<UebaRuleDefinition>, UebaRuleLifecycleTransition), UebaRuleManagementError> {
    set_rule_version_status_with_transition(
        rules,
        rule_id,
        version,
        UebaRuleStatus::Active,
        UebaRuleLifecycleAction::Enable,
    )
}

pub fn tune_rule_version(
    rules: &[UebaRuleDefinition],
    rule_id: &str,
    source_version: u32,
    tuning: UebaRuleTuning,
) -> Result<Vec<UebaRuleDefinition>, UebaRuleManagementError> {
    find_rule_version(rules, rule_id, source_version)
        .ok_or(UebaRuleManagementError::VersionNotFound)?;
    create_rule_draft(rules, rule_id, tuning)
}

pub fn replay_ueba_rules(
    events: &[AuditEvent],
    baselines: &HashMap<String, UserBaseline>,
    rules: &[UebaRuleDefinition],
) -> UebaReplaySummary {
    let mut events_by_user: HashMap<String, Vec<&AuditEvent>> = HashMap::new();
    for event in events {
        events_by_user
            .entry(event.actor.user_id.clone())
            .or_default()
            .push(event);
    }

    let active_versions = active_rule_versions(rules);
    let mut hits = Vec::new();
    let mut alerts = Vec::new();
    let mut rule_accumulators: HashMap<(String, u32), UebaReplayRuleAccumulator> = HashMap::new();

    for (user_id, user_events) in &events_by_user {
        let tenant_id = user_events
            .last()
            .map(|event| event.target.tenant_id.clone())
            .unwrap_or_else(|| "unknown".into());
        let project_id = user_events
            .last()
            .and_then(|event| event.target.project_id.clone());
        let baseline = baselines.get(user_id).cloned().unwrap_or_default();

        for (definition, version) in &active_versions {
            let observed_count =
                rule_observed_count(&definition.rule, &version.tuning, user_events);
            let baseline_count = baseline_count_for_rule(&definition.rule, &baseline);
            let threshold_count = version.tuning.thresholds.alert_threshold(baseline_count);
            rule_accumulators
                .entry((definition.rule_id.clone(), version.version))
                .or_insert_with(|| {
                    UebaReplayRuleAccumulator::new(
                        &definition.rule_id,
                        version.version,
                        definition.rule.clone(),
                    )
                })
                .record_observation(observed_count);
            if observed_count < version.tuning.thresholds.min_events
                || observed_count <= threshold_count
            {
                continue;
            }

            let risk_score = version.tuning.thresholds.risk_score.min(100);
            let action = version
                .tuning
                .action_override
                .clone()
                .unwrap_or_else(|| MitigationAction::from_score(risk_score as f64));
            if let Some(accumulator) =
                rule_accumulators.get_mut(&(definition.rule_id.clone(), version.version))
            {
                accumulator.record_hit(risk_score, &action);
            }
            let evidence = format!(
                "rule {} v{} observed {} events over threshold {} with baseline {}",
                definition.rule_id,
                version.version,
                observed_count,
                threshold_count,
                baseline_count
            );
            hits.push(UebaReplayHit {
                rule_id: definition.rule_id.clone(),
                version: version.version,
                rule: definition.rule.clone(),
                user_id: user_id.clone(),
                tenant_id: tenant_id.clone(),
                project_id: project_id.clone(),
                observed_count,
                baseline_count,
                threshold_count,
                risk_score,
                action: action.clone(),
                evidence: evidence.clone(),
            });
            alerts.push(build_alert_with_action(
                user_id,
                &tenant_id,
                project_id.clone(),
                definition.rule.clone(),
                risk_score,
                action,
                evidence,
            ));
        }
    }
    for (definition, version) in &active_versions {
        rule_accumulators
            .entry((definition.rule_id.clone(), version.version))
            .or_insert_with(|| {
                UebaReplayRuleAccumulator::new(
                    &definition.rule_id,
                    version.version,
                    definition.rule.clone(),
                )
            });
    }

    UebaReplaySummary {
        event_count: events.len(),
        users_evaluated: events_by_user.len(),
        rules_evaluated: active_versions.len(),
        hit_count: hits.len(),
        alert_count: alerts.len(),
        rule_summaries: rule_accumulators
            .into_values()
            .map(UebaReplayRuleAccumulator::finish)
            .collect(),
        hits,
        alerts,
    }
}

pub fn propose_rule_tuning(
    replay: &UebaReplaySummary,
    rules: &[UebaRuleDefinition],
    objective: &UebaTuningObjective,
) -> Vec<UebaTuningProposal> {
    let Some(_) = objective.target_alert_volume.or_else(|| {
        objective
            .target_precision
            .filter(|target| target.is_finite())
            .map(|_| 0)
    }) else {
        return Vec::new();
    };

    active_rule_versions(rules)
        .into_iter()
        .filter_map(|(definition, version)| {
            let rule_hits: Vec<&UebaReplayHit> = replay
                .hits
                .iter()
                .filter(|hit| hit.rule_id == definition.rule_id)
                .collect();
            let observed_alerts = rule_hits.len();
            let estimated_precision = estimated_precision(&rule_hits);
            let volume_too_high = objective
                .target_alert_volume
                .is_some_and(|target| observed_alerts > target);
            let volume_too_low = objective
                .target_alert_volume
                .is_some_and(|target| observed_alerts < target);
            let precision_too_low = objective
                .target_precision
                .filter(|target| target.is_finite())
                .is_some_and(|target| estimated_precision < target.clamp(0.0, 1.0));

            if !volume_too_high && !volume_too_low && !precision_too_low {
                return None;
            }

            let mut proposed_tuning = version.tuning.clone();
            let mut rationale = Vec::new();
            if volume_too_high || precision_too_low {
                let pressure = objective
                    .target_alert_volume
                    .map(|target| observed_alerts.saturating_sub(target).max(1))
                    .unwrap_or(1);
                make_tuning_stricter(&mut proposed_tuning, pressure);
                if volume_too_high {
                    rationale.push("replay alert volume exceeded target".to_string());
                }
                if precision_too_low {
                    rationale.push("estimated precision was below target".to_string());
                }
            } else if volume_too_low {
                make_tuning_looser(&mut proposed_tuning);
                rationale.push("replay alert volume was below target".to_string());
            }

            Some(UebaTuningProposal {
                rule_id: definition.rule_id.clone(),
                base_version: version.version,
                observed_alerts,
                estimated_precision,
                target_alert_volume: objective.target_alert_volume,
                target_precision: objective.target_precision,
                proposed_tuning,
                rationale: rationale.join("; "),
            })
        })
        .collect()
}

pub fn apply_tuning_proposal(
    rules: &[UebaRuleDefinition],
    proposal: &UebaTuningProposal,
) -> Result<Vec<UebaRuleDefinition>, UebaRuleManagementError> {
    let definition = rules
        .iter()
        .find(|definition| definition.rule_id == proposal.rule_id)
        .ok_or(UebaRuleManagementError::RuleNotFound)?;
    if !definition
        .versions
        .iter()
        .any(|version| version.version == proposal.base_version)
    {
        return Err(UebaRuleManagementError::VersionNotFound);
    }
    let next_version = next_rule_version(definition);
    let drafted = create_rule_draft(rules, &proposal.rule_id, proposal.proposed_tuning.clone())?;
    activate_rule_version(&drafted, &proposal.rule_id, next_version)
}

pub fn calibrate_ueba_rules(events: &[AuditEvent]) -> UebaCalibrationResult {
    let baseline_snapshot = build_user_baselines(events);
    let mut users = HashSet::new();
    let mut events_by_user: HashMap<String, Vec<&AuditEvent>> = HashMap::new();
    for event in events {
        users.insert(event.actor.user_id.clone());
        events_by_user
            .entry(event.actor.user_id.clone())
            .or_default()
            .push(event);
    }

    let sample_count = events.len();
    let distinct_users = users.len();
    let window = calibration_window(events);
    let window_factor = if window.duration_hours >= 24 {
        1.0
    } else {
        window.duration_hours as f64 / 24.0
    };
    let sample_factor = (sample_count as f64 / 50.0).min(1.0);
    let user_factor = (distinct_users as f64 / 5.0).min(1.0);
    let quality_score =
        round_ratio((sample_factor * 0.45) + (user_factor * 0.35) + (window_factor * 0.20));
    let status = if sample_count < 10 || distinct_users < 2 {
        UebaCalibrationStatus::InsufficientSamples
    } else if quality_score < 0.45 {
        UebaCalibrationStatus::Sparse
    } else {
        UebaCalibrationStatus::Ready
    };
    let quality = UebaCalibrationQuality {
        sample_factor: round_ratio(sample_factor),
        user_factor: round_ratio(user_factor),
        window_factor: round_ratio(window_factor),
        score: quality_score,
        status: status.clone(),
    };

    let recommendations = default_rule_set()
        .into_iter()
        .filter_map(|definition| {
            let active_version = definition
                .versions
                .iter()
                .find(|version| version.status.is_enabled())?;
            let mut counts: Vec<usize> = events_by_user
                .values()
                .map(|user_events| {
                    rule_observed_count(&definition.rule, &active_version.tuning, user_events)
                })
                .collect();
            if counts.is_empty() {
                counts.push(0);
            }
            let sample_p50 = percentile_nearest(&counts, 0.50);
            let sample_p75 = percentile_nearest(&counts, 0.75);
            let sample_p95 = percentile_nearest(&counts, 0.95);
            let observed_users = counts.iter().filter(|count| **count > 0).count();
            let risk_score =
                calibrated_risk_score(sample_p95, observed_users, distinct_users.max(1));
            let recommended_action = MitigationAction::from_score(risk_score as f64);

            let mut recommended_tuning = active_version.tuning.clone();
            recommended_tuning.thresholds.min_events = sample_p95.max(sample_p50 + 1).max(1);
            recommended_tuning.thresholds.baseline_offset = sample_p75.saturating_sub(sample_p50);
            recommended_tuning.thresholds.baseline_multiplier = calibrated_multiplier(
                sample_p50,
                sample_p95,
                observed_users,
                distinct_users.max(1),
            );
            recommended_tuning.thresholds.risk_score = risk_score;
            recommended_tuning.action_override = Some(recommended_action.clone());

            Some(UebaCalibrationRuleRecommendation {
                rule_id: definition.rule_id,
                rule: definition.rule,
                sample_p50,
                sample_p95,
                observed_users,
                recommended_thresholds: recommended_tuning.thresholds.clone(),
                recommended_action,
                recommended_tuning,
            })
        })
        .collect();

    UebaCalibrationResult {
        model_version: "ueba-statistical-calibration-v1".into(),
        sample_count,
        distinct_users,
        window,
        baseline_snapshot,
        quality,
        recommendations,
        quality_score,
        status,
    }
}

pub fn build_user_baselines(events: &[AuditEvent]) -> HashMap<String, UserBaseline> {
    let mut baselines: HashMap<String, UserBaseline> = HashMap::new();

    for event in events {
        let entry = baselines.entry(event.actor.user_id.clone()).or_default();
        match event.action {
            ActionType::Query if event.result == ActionResult::Success => {
                entry.query_count += 1;
            }
            ActionType::Export if event.result == ActionResult::Success => {
                entry.export_count += 1;
            }
            _ if event.result == ActionResult::Denied => {
                entry.denied_count += 1;
            }
            _ => {}
        }
    }

    for baseline in baselines.values_mut() {
        baseline.query_count = baseline.query_count.saturating_div(2).max(1);
        baseline.export_count = baseline.export_count.saturating_div(2);
        baseline.denied_count = baseline.denied_count.saturating_div(2);
    }

    baselines
}

pub fn build_role_baselines(
    events: &[AuditEvent],
    roles_by_user: &HashMap<String, Vec<String>>,
) -> HashMap<String, EntityBaseline> {
    let mut baselines: HashMap<String, EntityBaseline> = HashMap::new();
    let mut distinct_users: HashMap<String, HashSet<String>> = HashMap::new();

    for event in events {
        let Some(roles) = roles_by_user.get(&event.actor.user_id) else {
            continue;
        };
        for role in roles {
            let entry = baselines.entry(role.clone()).or_default();
            update_activity_counts(
                &mut entry.query_count,
                &mut entry.export_count,
                &mut entry.denied_count,
                event,
            );
            distinct_users
                .entry(role.clone())
                .or_default()
                .insert(event.actor.user_id.clone());
        }
    }

    for (role, baseline) in &mut baselines {
        normalize_entity_baseline(
            baseline,
            distinct_users
                .get(role)
                .map(HashSet::len)
                .unwrap_or_default(),
        );
    }

    baselines
}

pub fn build_entity_baselines(events: &[AuditEvent]) -> HashMap<EntityBaselineKey, EntityBaseline> {
    let mut baselines: HashMap<EntityBaselineKey, EntityBaseline> = HashMap::new();
    let mut distinct_users: HashMap<EntityBaselineKey, HashSet<String>> = HashMap::new();

    for event in events {
        let key = match &event.target.project_id {
            Some(project_id) => EntityBaselineKey {
                entity_type: "project".into(),
                entity_id: project_id.clone(),
            },
            None => EntityBaselineKey {
                entity_type: "resource".into(),
                entity_id: event.target.resource_id.clone(),
            },
        };
        let entry = baselines.entry(key.clone()).or_default();
        update_activity_counts(
            &mut entry.query_count,
            &mut entry.export_count,
            &mut entry.denied_count,
            event,
        );
        distinct_users
            .entry(key)
            .or_default()
            .insert(event.actor.user_id.clone());
    }

    for (key, baseline) in &mut baselines {
        normalize_entity_baseline(
            baseline,
            distinct_users
                .get(key)
                .map(HashSet::len)
                .unwrap_or_default(),
        );
    }

    baselines
}

pub fn evaluate_alerts(
    events: &[AuditEvent],
    baselines: &HashMap<String, UserBaseline>,
) -> Vec<UebaAlert> {
    let mut alerts = Vec::new();
    let mut events_by_user: HashMap<String, Vec<&AuditEvent>> = HashMap::new();
    for event in events {
        events_by_user
            .entry(event.actor.user_id.clone())
            .or_default()
            .push(event);
    }

    for (user_id, user_events) in events_by_user {
        let tenant_id = user_events
            .last()
            .map(|event| event.target.tenant_id.clone())
            .unwrap_or_else(|| "unknown".into());
        let project_id = user_events
            .last()
            .and_then(|event| event.target.project_id.clone());
        let baseline = baselines.get(&user_id).cloned().unwrap_or_default();

        let successful_queries = user_events
            .iter()
            .filter(|event| {
                event.action == ActionType::Query && event.result == ActionResult::Success
            })
            .count();
        if successful_queries >= 5 && successful_queries > baseline.query_count.saturating_mul(2) {
            alerts.push(build_alert(
                &user_id,
                &tenant_id,
                project_id.clone(),
                UebaRule::HighFrequencyQuery,
                58,
                format!(
                    "query count {} exceeds baseline {}",
                    successful_queries, baseline.query_count
                ),
            ));
        }

        let successful_exports = user_events
            .iter()
            .filter(|event| {
                event.action == ActionType::Export && event.result == ActionResult::Success
            })
            .count();
        if successful_exports >= 3 && successful_exports > baseline.export_count.saturating_add(1) {
            alerts.push(build_alert(
                &user_id,
                &tenant_id,
                project_id.clone(),
                UebaRule::ExportSpike,
                92,
                format!(
                    "export count {} exceeds baseline {}",
                    successful_exports, baseline.export_count
                ),
            ));
        }

        let denied_queries = user_events
            .iter()
            .filter(|event| {
                event.action == ActionType::Query && event.result == ActionResult::Denied
            })
            .count();
        if denied_queries >= 2 {
            alerts.push(build_alert(
                &user_id,
                &tenant_id,
                project_id.clone(),
                UebaRule::UnauthorizedQueryBurst,
                78,
                format!("{} denied query attempts detected", denied_queries),
            ));
        }

        if user_events.iter().any(|event| {
            event.action == ActionType::View && event.result == ActionResult::Success && {
                let hour = event.timestamp.with_timezone(&Utc).hour();
                !(6..22).contains(&hour)
            }
        }) {
            alerts.push(build_alert(
                &user_id,
                &tenant_id,
                project_id.clone(),
                UebaRule::AfterHoursAccess,
                44,
                "after-hours audit activity detected".into(),
            ));
        }

        if user_events.iter().any(|event| {
            let context = event.context.to_ascii_lowercase();
            context.contains("dns://") || context.contains(" txt ") || context.contains("base32")
        }) {
            alerts.push(build_alert(
                &user_id,
                &tenant_id,
                project_id.clone(),
                UebaRule::HiddenChannelDns,
                90,
                "suspicious dns covert-channel pattern detected".into(),
            ));
        }

        if user_events.iter().any(|event| {
            let context = event.context.to_ascii_lowercase();
            (context.contains("http://") || context.contains("https://"))
                && (context.contains("beacon")
                    || context.contains("pixel")
                    || context.contains("chunk="))
        }) {
            alerts.push(build_alert(
                &user_id,
                &tenant_id,
                project_id.clone(),
                UebaRule::HiddenChannelHttp,
                88,
                "suspicious http covert-channel pattern detected".into(),
            ));
        }
    }

    alerts
}

fn build_alert(
    user_id: &str,
    tenant_id: &str,
    project_id: Option<String>,
    rule: UebaRule,
    risk_score: u8,
    evidence: String,
) -> UebaAlert {
    build_alert_with_action(
        user_id,
        tenant_id,
        project_id,
        rule,
        risk_score,
        MitigationAction::from_score(risk_score as f64),
        evidence,
    )
}

fn build_alert_with_action(
    user_id: &str,
    tenant_id: &str,
    project_id: Option<String>,
    rule: UebaRule,
    risk_score: u8,
    action: MitigationAction,
    evidence: String,
) -> UebaAlert {
    UebaAlert {
        alert_id: Ulid::new().to_string(),
        user_id: user_id.to_string(),
        tenant_id: tenant_id.to_string(),
        project_id,
        rule,
        risk_score,
        action,
        evidence,
    }
}

fn default_rule_definition(
    rule: UebaRule,
    name: &str,
    description: &str,
    tuning: UebaRuleTuning,
) -> UebaRuleDefinition {
    let rule_id = rule.rule_id().to_string();
    UebaRuleDefinition {
        rule_id,
        rule,
        name: name.to_string(),
        description: description.to_string(),
        versions: vec![UebaRuleVersion {
            version: 1,
            status: UebaRuleStatus::Active,
            tuning,
        }],
    }
}

fn next_rule_version(definition: &UebaRuleDefinition) -> u32 {
    definition
        .versions
        .iter()
        .map(|version| version.version)
        .max()
        .unwrap_or(0)
        .saturating_add(1)
}

fn rule_state_snapshot(definition: &UebaRuleDefinition) -> UebaRuleStateSnapshot {
    let latest_version = definition
        .versions
        .iter()
        .map(|version| version.version)
        .max();
    let active_versions: Vec<u32> = definition
        .versions
        .iter()
        .filter(|version| version.status == UebaRuleStatus::Active)
        .map(|version| version.version)
        .collect();
    let draft_versions: Vec<u32> = definition
        .versions
        .iter()
        .filter(|version| version.status == UebaRuleStatus::Draft)
        .map(|version| version.version)
        .collect();
    let disabled_versions: Vec<u32> = definition
        .versions
        .iter()
        .filter(|version| version.status == UebaRuleStatus::Disabled)
        .map(|version| version.version)
        .collect();
    let retired_versions: Vec<u32> = definition
        .versions
        .iter()
        .filter(|version| version.status == UebaRuleStatus::Retired)
        .map(|version| version.version)
        .collect();
    let lifecycle_state = if definition.versions.is_empty() {
        UebaRuleLifecycleState::NoVersions
    } else if active_versions.len() > 1 {
        UebaRuleLifecycleState::ConflictingActiveVersions
    } else if active_versions.len() == 1 {
        UebaRuleLifecycleState::Active
    } else if !disabled_versions.is_empty() {
        UebaRuleLifecycleState::Disabled
    } else if !draft_versions.is_empty() {
        UebaRuleLifecycleState::DraftOnly
    } else {
        UebaRuleLifecycleState::Retired
    };

    UebaRuleStateSnapshot {
        rule_id: definition.rule_id.clone(),
        rule: definition.rule.clone(),
        latest_version,
        active_version: active_versions.first().copied(),
        draft_versions,
        disabled_versions,
        retired_versions,
        lifecycle_state,
    }
}

fn set_rule_version_status(
    rules: &[UebaRuleDefinition],
    rule_id: &str,
    version: u32,
    status: UebaRuleStatus,
) -> Result<Vec<UebaRuleDefinition>, UebaRuleManagementError> {
    set_rule_version_status_with_transition(
        rules,
        rule_id,
        version,
        status,
        UebaRuleLifecycleAction::Activate,
    )
    .map(|(rules, _)| rules)
}

fn set_rule_version_status_with_transition(
    rules: &[UebaRuleDefinition],
    rule_id: &str,
    version: u32,
    status: UebaRuleStatus,
    action: UebaRuleLifecycleAction,
) -> Result<(Vec<UebaRuleDefinition>, UebaRuleLifecycleTransition), UebaRuleManagementError> {
    let mut updated = rules.to_vec();
    let definition = updated
        .iter_mut()
        .find(|definition| definition.rule_id == rule_id)
        .ok_or(UebaRuleManagementError::RuleNotFound)?;
    let previous_status = definition
        .versions
        .iter()
        .find(|rule_version| rule_version.version == version)
        .map(|rule_version| rule_version.status.clone())
        .ok_or(UebaRuleManagementError::VersionNotFound)?;
    if !valid_status_transition(&previous_status, &status) {
        return Err(UebaRuleManagementError::InvalidLifecycleTransition);
    }

    let enabling = status.is_enabled();
    let mut retired_versions = Vec::new();
    for rule_version in &mut definition.versions {
        if rule_version.version == version {
            rule_version.status = status.clone();
        } else if enabling && rule_version.status.is_enabled() {
            rule_version.status = UebaRuleStatus::Retired;
            retired_versions.push(rule_version.version);
        }
    }
    let snapshot = rule_state_snapshot(definition);
    let transition = UebaRuleLifecycleTransition {
        rule_id: rule_id.to_string(),
        action,
        version,
        previous_status: Some(previous_status),
        next_status: status,
        active_version_after: snapshot.active_version,
        retired_versions,
    };
    Ok((updated, transition))
}

fn valid_status_transition(previous: &UebaRuleStatus, next: &UebaRuleStatus) -> bool {
    !matches!(
        (previous, next),
        (
            UebaRuleStatus::Retired,
            UebaRuleStatus::Active | UebaRuleStatus::Disabled
        )
    )
}

fn active_rule_versions(
    rules: &[UebaRuleDefinition],
) -> Vec<(&UebaRuleDefinition, &UebaRuleVersion)> {
    rules
        .iter()
        .flat_map(|definition| {
            definition
                .versions
                .iter()
                .filter(|version| version.status.is_enabled())
                .map(move |version| (definition, version))
        })
        .collect()
}

struct UebaReplayRuleAccumulator {
    rule_id: String,
    version: u32,
    rule: UebaRule,
    users_evaluated: usize,
    hit_count: usize,
    min_observed_count: usize,
    max_observed_count: usize,
    total_observed_count: usize,
    max_risk_score: u8,
    strongest_action: Option<MitigationAction>,
}

impl UebaReplayRuleAccumulator {
    fn new(rule_id: &str, version: u32, rule: UebaRule) -> Self {
        Self {
            rule_id: rule_id.to_string(),
            version,
            rule,
            users_evaluated: 0,
            hit_count: 0,
            min_observed_count: usize::MAX,
            max_observed_count: 0,
            total_observed_count: 0,
            max_risk_score: 0,
            strongest_action: None,
        }
    }

    fn record_observation(&mut self, observed_count: usize) {
        self.users_evaluated += 1;
        self.min_observed_count = self.min_observed_count.min(observed_count);
        self.max_observed_count = self.max_observed_count.max(observed_count);
        self.total_observed_count = self.total_observed_count.saturating_add(observed_count);
    }

    fn record_hit(&mut self, risk_score: u8, action: &MitigationAction) {
        self.hit_count += 1;
        self.max_risk_score = self.max_risk_score.max(risk_score);
        let replace_action = self
            .strongest_action
            .as_ref()
            .map(|current| action.severity() > current.severity())
            .unwrap_or(true);
        if replace_action {
            self.strongest_action = Some(action.clone());
        }
    }

    fn finish(self) -> UebaReplayRuleSummary {
        UebaReplayRuleSummary {
            rule_id: self.rule_id,
            version: self.version,
            rule: self.rule,
            users_evaluated: self.users_evaluated,
            hit_count: self.hit_count,
            alert_count: self.hit_count,
            min_observed_count: if self.users_evaluated == 0 {
                0
            } else {
                self.min_observed_count
            },
            max_observed_count: self.max_observed_count,
            average_observed_count: if self.users_evaluated == 0 {
                0.0
            } else {
                round_ratio(self.total_observed_count as f64 / self.users_evaluated as f64)
            },
            max_risk_score: self.max_risk_score,
            strongest_action: self.strongest_action,
        }
    }
}

fn rule_observed_count(rule: &UebaRule, tuning: &UebaRuleTuning, events: &[&AuditEvent]) -> usize {
    match rule {
        UebaRule::HighFrequencyQuery => events
            .iter()
            .filter(|event| {
                event.action == ActionType::Query && event.result == ActionResult::Success
            })
            .count(),
        UebaRule::ExportSpike => events
            .iter()
            .filter(|event| {
                event.action == ActionType::Export && event.result == ActionResult::Success
            })
            .count(),
        UebaRule::UnauthorizedQueryBurst => events
            .iter()
            .filter(|event| {
                event.action == ActionType::Query && event.result == ActionResult::Denied
            })
            .count(),
        UebaRule::AfterHoursAccess => events
            .iter()
            .filter(|event| {
                event.action == ActionType::View
                    && event.result == ActionResult::Success
                    && is_outside_business_hours(event, &tuning.thresholds)
            })
            .count(),
        UebaRule::HiddenChannelDns | UebaRule::HiddenChannelHttp => tuning
            .pattern
            .as_ref()
            .map(|pattern| {
                events
                    .iter()
                    .filter(|event| pattern.matches_context(&event.context))
                    .count()
            })
            .unwrap_or_default(),
    }
}

fn baseline_count_for_rule(rule: &UebaRule, baseline: &UserBaseline) -> usize {
    match rule {
        UebaRule::HighFrequencyQuery => baseline.query_count,
        UebaRule::ExportSpike => baseline.export_count,
        UebaRule::UnauthorizedQueryBurst => baseline.denied_count,
        UebaRule::AfterHoursAccess | UebaRule::HiddenChannelDns | UebaRule::HiddenChannelHttp => 0,
    }
}

fn is_outside_business_hours(event: &AuditEvent, thresholds: &UebaRuleThresholds) -> bool {
    let hour = event.timestamp.with_timezone(&Utc).hour() as u8;
    let start = thresholds.business_hours_start_utc.unwrap_or(6).min(23);
    let end = thresholds.business_hours_end_utc.unwrap_or(22).min(24);
    !is_inside_business_hours(hour, start, end)
}

fn is_inside_business_hours(hour: u8, start: u8, end: u8) -> bool {
    if start == end {
        true
    } else if start < end {
        hour >= start && hour < end
    } else {
        hour >= start || hour < end
    }
}

fn estimated_precision(hits: &[&UebaReplayHit]) -> f64 {
    if hits.is_empty() {
        return 1.0;
    }
    let high_confidence = hits
        .iter()
        .filter(|hit| hit.risk_score >= 80 || hit.action.severity() >= 2)
        .count();
    round_ratio(high_confidence as f64 / hits.len() as f64)
}

fn make_tuning_stricter(tuning: &mut UebaRuleTuning, pressure: usize) {
    let pressure = pressure.clamp(1, 10);
    tuning.thresholds.min_events = tuning.thresholds.min_events.saturating_add(pressure);
    tuning.thresholds.baseline_offset = tuning.thresholds.baseline_offset.saturating_add(pressure);
    let multiplier = finite_non_negative(tuning.thresholds.baseline_multiplier).unwrap_or(1.0);
    tuning.thresholds.baseline_multiplier =
        round_ratio((multiplier * (1.0 + (pressure as f64 * 0.15))).min(10.0));
    tuning.thresholds.risk_score = tuning.thresholds.risk_score.saturating_add(5).min(100);
}

fn make_tuning_looser(tuning: &mut UebaRuleTuning) {
    tuning.thresholds.min_events = tuning.thresholds.min_events.saturating_sub(1).max(1);
    tuning.thresholds.baseline_offset = tuning.thresholds.baseline_offset.saturating_sub(1);
    let multiplier = finite_non_negative(tuning.thresholds.baseline_multiplier).unwrap_or(1.0);
    tuning.thresholds.baseline_multiplier = round_ratio((multiplier * 0.90).max(0.0));
}

fn calibration_window(events: &[AuditEvent]) -> UebaCalibrationWindow {
    let Some(start_event) = events
        .iter()
        .min_by_key(|event| event.timestamp.timestamp_millis())
    else {
        return UebaCalibrationWindow::default();
    };
    let Some(end_event) = events
        .iter()
        .max_by_key(|event| event.timestamp.timestamp_millis())
    else {
        return UebaCalibrationWindow::default();
    };
    let duration_seconds = end_event
        .timestamp
        .timestamp()
        .saturating_sub(start_event.timestamp.timestamp())
        .max(0) as u64;

    UebaCalibrationWindow {
        start: Some(start_event.timestamp.to_rfc3339()),
        end: Some(end_event.timestamp.to_rfc3339()),
        duration_hours: duration_seconds / 3_600,
    }
}

fn calibrated_risk_score(sample_p95: usize, observed_users: usize, distinct_users: usize) -> u8 {
    if sample_p95 == 0 || observed_users == 0 {
        return 35;
    }
    let prevalence = observed_users as f64 / distinct_users as f64;
    let rarity = 1.0 - prevalence.clamp(0.0, 1.0);
    let volume_pressure = ((sample_p95 as f64 + 1.0).ln() / 4.0).min(1.0);
    (40.0 + (rarity * 35.0) + (volume_pressure * 25.0))
        .round()
        .clamp(1.0, 100.0) as u8
}

fn calibrated_multiplier(
    sample_p50: usize,
    sample_p95: usize,
    observed_users: usize,
    distinct_users: usize,
) -> f64 {
    let multiplier = if sample_p50 > 0 {
        sample_p95.max(sample_p50) as f64 / sample_p50 as f64
    } else if sample_p95 > 0 {
        1.0 + (observed_users as f64 / distinct_users as f64)
    } else {
        1.0
    };
    round_ratio(multiplier.clamp(1.0, 6.0))
}

fn percentile_nearest(values: &[usize], percentile: f64) -> usize {
    if values.is_empty() {
        return 0;
    }
    let mut values = values.to_vec();
    values.sort_unstable();
    let percentile = percentile.clamp(0.0, 1.0);
    let index = ((values.len().saturating_sub(1) as f64) * percentile).round() as usize;
    values[index]
}

fn finite_non_negative(value: f64) -> Option<f64> {
    if value.is_finite() && value >= 0.0 {
        Some(value)
    } else {
        None
    }
}

fn round_ratio(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

fn update_activity_counts(
    query_count: &mut usize,
    export_count: &mut usize,
    denied_count: &mut usize,
    event: &AuditEvent,
) {
    match event.action {
        ActionType::Query if event.result == ActionResult::Success => {
            *query_count += 1;
        }
        ActionType::Export if event.result == ActionResult::Success => {
            *export_count += 1;
        }
        _ if event.result == ActionResult::Denied => {
            *denied_count += 1;
        }
        _ => {}
    }
}

fn normalize_entity_baseline(baseline: &mut EntityBaseline, distinct_users: usize) {
    baseline.query_count = baseline.query_count.saturating_div(2).max(1);
    baseline.export_count = baseline.export_count.saturating_div(2);
    baseline.denied_count = baseline.denied_count.saturating_div(2);
    baseline.distinct_users = distinct_users.max(1);
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Duration, TimeZone, Utc};
    use sdqp_audit::{ActionResult, ActionType, ActorInfo, AuditEvent, TargetRef};

    use std::collections::HashMap;

    use super::{
        EntityBaselineKey, MitigationAction, UebaCalibrationStatus, UebaRule,
        UebaRuleLifecycleAction, UebaRuleLifecycleState, UebaRuleManagementError, UebaRuleStatus,
        UebaTuningObjective, activate_rule_version, apply_tuning_proposal, build_entity_baselines,
        build_role_baselines, build_user_baselines, calibrate_ueba_rules, create_rule_draft,
        default_rule_set, disable_rule_version, disable_rule_version_with_transition,
        enable_rule_version, evaluate_alerts, find_active_rule_version, find_rule_version,
        replay_ueba_rules, retire_rule_version, summarize_rule_states, tune_rule_version,
    };

    fn actor() -> ActorInfo {
        ActorInfo {
            user_id: "user-analyst".into(),
            session_id: "session-ueba".into(),
            ip_address: "127.0.0.1".into(),
        }
    }

    fn target() -> TargetRef {
        TargetRef {
            tenant_id: "tenant-alpha".into(),
            project_id: Some("project-alpha".into()),
            resource_id: "resource-a".into(),
        }
    }

    fn event(
        action: ActionType,
        result: ActionResult,
        context: &str,
        minutes_offset: i64,
    ) -> AuditEvent {
        let mut event = AuditEvent::new(actor(), action, target(), context, result, None, None);
        event.timestamp = Utc::now() + Duration::minutes(minutes_offset);
        event
    }

    fn event_for_user(
        user_id: &str,
        action: ActionType,
        result: ActionResult,
        context: &str,
        timestamp: DateTime<Utc>,
    ) -> AuditEvent {
        let mut actor = actor();
        actor.user_id = user_id.to_string();
        let mut event = AuditEvent::new(actor, action, target(), context, result, None, None);
        event.timestamp = timestamp;
        event
    }

    #[test]
    fn mitigation_action_maps_score_bands() {
        assert_eq!(
            MitigationAction::from_score(10.0),
            MitigationAction::Observe
        );
        assert_eq!(
            MitigationAction::from_score(55.0),
            MitigationAction::StepUpAuth
        );
        assert_eq!(
            MitigationAction::from_score(78.0),
            MitigationAction::SuspendPermissions
        );
        assert_eq!(
            MitigationAction::from_score(92.0),
            MitigationAction::TerminateSession
        );
    }

    #[test]
    fn engine_detects_high_frequency_queries_and_hidden_channel_patterns() {
        let mut events = vec![
            event(ActionType::Query, ActionResult::Success, "query-1", 0),
            event(ActionType::Query, ActionResult::Success, "query-2", 1),
            event(ActionType::Query, ActionResult::Success, "query-3", 2),
            event(ActionType::Query, ActionResult::Success, "query-4", 3),
            event(ActionType::Query, ActionResult::Success, "query-5", 4),
            event(
                ActionType::View,
                ActionResult::Success,
                "dns://exfil.example TXT chunk",
                5,
            ),
            event(
                ActionType::View,
                ActionResult::Success,
                "https://exfil.example/pixel.gif?chunk=abc",
                6,
            ),
        ];
        events[5].timestamp = Utc
            .with_ymd_and_hms(2026, 3, 29, 23, 30, 0)
            .single()
            .expect("time");
        let alerts = evaluate_alerts(&events, &build_user_baselines(&events));

        assert!(
            alerts
                .iter()
                .any(|alert| alert.rule == UebaRule::HighFrequencyQuery)
        );
        assert!(
            alerts
                .iter()
                .any(|alert| alert.rule == UebaRule::AfterHoursAccess)
        );
        assert!(
            alerts
                .iter()
                .any(|alert| alert.rule == UebaRule::HiddenChannelDns)
        );
        assert!(
            alerts
                .iter()
                .any(|alert| alert.rule == UebaRule::HiddenChannelHttp)
        );
    }

    #[test]
    fn after_hours_detection_ignores_query_only_activity() {
        let mut events = vec![
            event(ActionType::Query, ActionResult::Success, "query-1", 0),
            event(ActionType::Query, ActionResult::Success, "query-2", 1),
        ];
        events[0].timestamp = Utc
            .with_ymd_and_hms(2026, 3, 29, 23, 30, 0)
            .single()
            .expect("time");
        events[1].timestamp = Utc
            .with_ymd_and_hms(2026, 3, 29, 23, 31, 0)
            .single()
            .expect("time");

        let alerts = evaluate_alerts(&events, &build_user_baselines(&events));

        assert!(
            !alerts
                .iter()
                .any(|alert| alert.rule == UebaRule::AfterHoursAccess)
        );
    }

    #[test]
    fn engine_builds_role_and_entity_baselines() {
        let events = vec![
            event(ActionType::Query, ActionResult::Success, "query-1", 0),
            event(ActionType::Export, ActionResult::Success, "export-1", 1),
            event(ActionType::Query, ActionResult::Denied, "denied-1", 2),
        ];
        let roles = HashMap::from([(
            "user-analyst".to_string(),
            vec!["analyst".to_string(), "auditor".to_string()],
        )]);

        let role_baselines = build_role_baselines(&events, &roles);
        let entity_baselines = build_entity_baselines(&events);

        assert!(role_baselines.contains_key("analyst"));
        assert!(role_baselines.contains_key("auditor"));
        let project_baseline = entity_baselines
            .get(&EntityBaselineKey {
                entity_type: "project".into(),
                entity_id: "project-alpha".into(),
            })
            .expect("project baseline");
        assert_eq!(project_baseline.distinct_users, 1);
        assert_eq!(project_baseline.query_count, 1);
        assert_eq!(project_baseline.export_count, 0);
        assert_eq!(project_baseline.denied_count, 0);
    }

    #[test]
    fn rule_management_creates_and_transitions_versions() {
        let rules = default_rule_set();
        let rule_id = UebaRule::HighFrequencyQuery.rule_id();
        let mut tuned = find_rule_version(&rules, rule_id, 1)
            .expect("default version")
            .tuning
            .clone();
        tuned.thresholds.min_events = 7;
        tuned.action_override = Some(MitigationAction::StepUpAuth);

        let drafted = create_rule_draft(&rules, rule_id, tuned.clone()).expect("draft");
        assert_eq!(
            find_rule_version(&drafted, rule_id, 2)
                .expect("draft version")
                .status,
            UebaRuleStatus::Draft
        );

        let activated = activate_rule_version(&drafted, rule_id, 2).expect("activate");
        assert_eq!(
            find_rule_version(&activated, rule_id, 1)
                .expect("old version")
                .status,
            UebaRuleStatus::Retired
        );
        assert_eq!(
            find_active_rule_version(&activated, rule_id)
                .expect("active version")
                .tuning,
            tuned
        );

        let disabled = disable_rule_version(&activated, rule_id, 2).expect("disable");
        assert_eq!(
            find_rule_version(&disabled, rule_id, 2)
                .expect("disabled version")
                .status,
            UebaRuleStatus::Disabled
        );
        let enabled = enable_rule_version(&disabled, rule_id, 2).expect("enable");
        assert_eq!(
            find_active_rule_version(&enabled, rule_id)
                .expect("enabled version")
                .version,
            2
        );
        let retired = retire_rule_version(&enabled, rule_id, 2).expect("retire");
        assert_eq!(
            find_rule_version(&retired, rule_id, 2)
                .expect("retired version")
                .status,
            UebaRuleStatus::Retired
        );
    }

    #[test]
    fn rule_management_exports_state_snapshots_and_terminal_lifecycle_guards() {
        let rules = default_rule_set();
        let rule_id = UebaRule::ExportSpike.rule_id();
        let disabled = disable_rule_version(&rules, rule_id, 1).expect("disable");
        let snapshots = summarize_rule_states(&disabled);
        let snapshot = snapshots
            .iter()
            .find(|snapshot| snapshot.rule_id == rule_id)
            .expect("export snapshot");

        assert_eq!(snapshot.active_version, None);
        assert_eq!(snapshot.disabled_versions, vec![1]);
        assert_eq!(snapshot.lifecycle_state, UebaRuleLifecycleState::Disabled);

        let (disabled_again, transition) =
            disable_rule_version_with_transition(&rules, rule_id, 1).expect("transition");
        assert_eq!(transition.action, UebaRuleLifecycleAction::Disable);
        assert_eq!(transition.previous_status, Some(UebaRuleStatus::Active));
        assert_eq!(transition.next_status, UebaRuleStatus::Disabled);
        assert_eq!(transition.active_version_after, None);

        let retired = retire_rule_version(&disabled_again, rule_id, 1).expect("retire");
        let invalid = enable_rule_version(&retired, rule_id, 1).expect_err("retired is terminal");
        assert_eq!(invalid, UebaRuleManagementError::InvalidLifecycleTransition);
    }

    #[test]
    fn replay_uses_governed_rules_without_changing_runtime_alerts() {
        let base = Utc
            .with_ymd_and_hms(2026, 3, 29, 12, 0, 0)
            .single()
            .expect("time");
        let events: Vec<AuditEvent> = (0..5)
            .map(|offset| {
                event_for_user(
                    "user-replay",
                    ActionType::Query,
                    ActionResult::Success,
                    "query",
                    base + Duration::minutes(offset),
                )
            })
            .collect();
        let baselines = build_user_baselines(&events);
        let rules = default_rule_set();
        let rule_id = UebaRule::HighFrequencyQuery.rule_id();
        let mut tuned = find_rule_version(&rules, rule_id, 1)
            .expect("default version")
            .tuning
            .clone();
        tuned.action_override = Some(MitigationAction::TerminateSession);
        let drafted = tune_rule_version(&rules, rule_id, 1, tuned).expect("tune draft");
        let rules = activate_rule_version(&drafted, rule_id, 2).expect("activate tuned rule");

        let replay = replay_ueba_rules(&events, &baselines, &rules);
        let runtime_alerts = evaluate_alerts(&events, &baselines);

        let hit = replay
            .hits
            .iter()
            .find(|hit| hit.rule == UebaRule::HighFrequencyQuery)
            .expect("replay hit");
        assert_eq!(hit.version, 2);
        assert_eq!(hit.action, MitigationAction::TerminateSession);
        assert_eq!(replay.alert_count, replay.hits.len());
        let rule_summary = replay
            .rule_summaries
            .iter()
            .find(|summary| summary.rule == UebaRule::HighFrequencyQuery)
            .expect("high-frequency rule summary");
        assert_eq!(rule_summary.version, 2);
        assert_eq!(rule_summary.users_evaluated, 1);
        assert_eq!(rule_summary.hit_count, 1);
        assert_eq!(rule_summary.max_observed_count, 5);
        assert_eq!(
            rule_summary.strongest_action,
            Some(MitigationAction::TerminateSession)
        );
        assert!(
            runtime_alerts
                .iter()
                .any(|alert| alert.rule == UebaRule::HighFrequencyQuery)
        );
    }

    #[test]
    fn tuning_proposal_can_be_applied_as_new_active_config() {
        let base = Utc
            .with_ymd_and_hms(2026, 3, 29, 12, 0, 0)
            .single()
            .expect("time");
        let events: Vec<AuditEvent> = (0..5)
            .map(|offset| {
                event_for_user(
                    "user-tuning",
                    ActionType::Query,
                    ActionResult::Success,
                    "query",
                    base + Duration::minutes(offset),
                )
            })
            .collect();
        let baselines = build_user_baselines(&events);
        let rules = default_rule_set();
        let replay = replay_ueba_rules(&events, &baselines, &rules);
        let proposals = super::propose_rule_tuning(
            &replay,
            &rules,
            &UebaTuningObjective {
                target_alert_volume: Some(0),
                target_precision: None,
            },
        );
        let proposal = proposals
            .iter()
            .find(|proposal| proposal.rule_id == UebaRule::HighFrequencyQuery.rule_id())
            .expect("high-frequency proposal");

        assert!(proposal.proposed_tuning.thresholds.min_events > 5);
        let applied = apply_tuning_proposal(&rules, proposal).expect("apply proposal");
        let active = find_active_rule_version(&applied, UebaRule::HighFrequencyQuery.rule_id())
            .expect("new active version");

        assert_eq!(active.version, 2);
        assert_eq!(active.tuning, proposal.proposed_tuning);
    }

    #[test]
    fn calibration_derives_quality_baseline_snapshot_and_recommendations() {
        let base = Utc
            .with_ymd_and_hms(2026, 3, 28, 0, 0, 0)
            .single()
            .expect("time");
        let mut events = Vec::new();
        for user_index in 0..3 {
            for offset in 0..6 {
                events.push(event_for_user(
                    &format!("user-calibration-{}", user_index),
                    ActionType::Query,
                    ActionResult::Success,
                    "query",
                    base + Duration::hours((user_index * 6 + offset) as i64),
                ));
            }
        }

        let calibration = calibrate_ueba_rules(&events);
        let high_frequency = calibration
            .recommendations
            .iter()
            .find(|recommendation| recommendation.rule == UebaRule::HighFrequencyQuery)
            .expect("high-frequency recommendation");

        assert_eq!(calibration.status, UebaCalibrationStatus::Ready);
        assert_eq!(calibration.quality.status, UebaCalibrationStatus::Ready);
        assert_eq!(calibration.quality.score, calibration.quality_score);
        assert!(calibration.quality.sample_factor > 0.0);
        assert_eq!(calibration.sample_count, 18);
        assert_eq!(calibration.distinct_users, 3);
        assert_eq!(calibration.baseline_snapshot.len(), 3);
        assert_eq!(calibration.model_version, "ueba-statistical-calibration-v1");
        assert!(calibration.window.duration_hours >= 17);
        assert!(calibration.quality_score > 0.45);
        assert_eq!(high_frequency.sample_p95, 6);
        assert!(high_frequency.recommended_thresholds.min_events >= 7);
        assert!(
            high_frequency.recommended_action.severity() >= MitigationAction::Observe.severity()
        );
    }
}
