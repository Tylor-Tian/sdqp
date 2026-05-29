use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SensitivityLevel {
    L1Public,
    L2Internal,
    L3Confidential,
    L4Sensitive,
    L5Restricted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClassificationStatus {
    PendingConfirmation,
    Confirmed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataCategory {
    PublicReference,
    InternalOperational,
    PersonalContact,
    PersonalIdentifier,
    FinancialIdentifier,
    InvestigationSensitive,
    GeneralConfidential,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MaskingStrategy {
    None,
    PartialEmail,
    PartialPhone,
    Full,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WatermarkStrength {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SensitivePattern {
    ChinaIdCard,
    BankCard,
    MobilePhone,
    Email,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetentionDisposalAction {
    Review,
    Archive,
    Purge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegulationReference {
    pub code: String,
    pub jurisdiction: String,
    pub title: String,
    pub retention_basis: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub policy_id: String,
    pub retain_for_days: i64,
    pub disposal_action: RetentionDisposalAction,
    pub legal_hold_supported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassificationCatalogEntry {
    pub catalog_entry_id: String,
    pub data_category: DataCategory,
    pub level: SensitivityLevel,
    pub applicable_regulations: Vec<RegulationReference>,
    pub retention_policy: RetentionPolicy,
    pub manual_confirmation_required: bool,
    pub rule_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedPattern {
    pub pattern: SensitivePattern,
    pub status: ClassificationStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldClassification {
    pub field_name: String,
    pub level: SensitivityLevel,
    pub status: ClassificationStatus,
    pub masking_strategy: MaskingStrategy,
    pub watermark_strength: WatermarkStrength,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClassificationPolicySource {
    RuleEngine,
    SampleDetection,
    ManualConfirmation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleVersionStatus {
    Draft,
    Active,
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassificationRule {
    pub rule_id: String,
    #[serde(default = "default_catalog_entry_id")]
    pub catalog_entry_id: String,
    pub field_matchers: Vec<String>,
    pub sample_patterns: Vec<SensitivePattern>,
    pub level: SensitivityLevel,
    #[serde(default = "default_rule_data_category")]
    pub data_category: DataCategory,
    #[serde(default)]
    pub applicable_regulations: Vec<RegulationReference>,
    #[serde(default = "default_retention_policy")]
    pub retention_policy: RetentionPolicy,
    #[serde(default = "default_manual_confirmation_required")]
    pub manual_confirmation_required: bool,
    pub masking_strategy: MaskingStrategy,
    pub watermark_strength: WatermarkStrength,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassificationRuleVersion {
    pub rule_version_id: String,
    pub project_id: String,
    pub data_source_id: String,
    pub version_number: i32,
    pub status: RuleVersionStatus,
    pub rules: Vec<ClassificationRule>,
    #[serde(default)]
    pub catalog_entries: Vec<ClassificationCatalogEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldClassificationPolicy {
    pub field_name: String,
    pub level: SensitivityLevel,
    pub data_category: DataCategory,
    pub status: ClassificationStatus,
    pub masking_strategy: MaskingStrategy,
    pub watermark_strength: WatermarkStrength,
    pub source: ClassificationPolicySource,
    pub pattern_hints: Vec<SensitivePattern>,
    pub sample_value: Option<String>,
    pub rule_version_id: Option<String>,
    pub detection_run_id: Option<String>,
    pub catalog_entry_id: Option<String>,
    pub applicable_regulations: Vec<RegulationReference>,
    pub retention_policy: RetentionPolicy,
    pub manual_confirmation_required: bool,
}

impl FieldClassificationPolicy {
    pub fn as_display_policy(&self) -> FieldClassification {
        FieldClassification {
            field_name: self.field_name.clone(),
            level: self.level,
            status: self.status.clone(),
            masking_strategy: self.masking_strategy.clone(),
            watermark_strength: self.watermark_strength.clone(),
        }
    }
}

pub fn default_rule_version(project_id: &str, data_source_id: &str) -> ClassificationRuleVersion {
    let rules = vec![
        ClassificationRule {
            rule_id: "email".into(),
            catalog_entry_id: "catalog-personal-contact".into(),
            field_matchers: vec!["email".into()],
            sample_patterns: vec![SensitivePattern::Email],
            level: SensitivityLevel::L4Sensitive,
            data_category: DataCategory::PersonalContact,
            applicable_regulations: vec![pipl_regulation(), cybersecurity_law()],
            retention_policy: retention_policy(
                "retention-personal-contact",
                365,
                RetentionDisposalAction::Review,
            ),
            manual_confirmation_required: true,
            masking_strategy: MaskingStrategy::PartialEmail,
            watermark_strength: WatermarkStrength::High,
        },
        ClassificationRule {
            rule_id: "mobile-phone".into(),
            catalog_entry_id: "catalog-personal-contact".into(),
            field_matchers: vec!["phone".into(), "mobile".into()],
            sample_patterns: vec![SensitivePattern::MobilePhone],
            level: SensitivityLevel::L4Sensitive,
            data_category: DataCategory::PersonalContact,
            applicable_regulations: vec![pipl_regulation(), cybersecurity_law()],
            retention_policy: retention_policy(
                "retention-personal-contact",
                365,
                RetentionDisposalAction::Review,
            ),
            manual_confirmation_required: true,
            masking_strategy: MaskingStrategy::PartialPhone,
            watermark_strength: WatermarkStrength::High,
        },
        ClassificationRule {
            rule_id: "identity".into(),
            catalog_entry_id: "catalog-legal-identifier".into(),
            field_matchers: vec!["id_card".into(), "identity".into(), "bank_card".into()],
            sample_patterns: vec![SensitivePattern::ChinaIdCard, SensitivePattern::BankCard],
            level: SensitivityLevel::L5Restricted,
            data_category: DataCategory::PersonalIdentifier,
            applicable_regulations: vec![pipl_regulation(), data_security_law()],
            retention_policy: retention_policy(
                "retention-legal-identifier",
                1825,
                RetentionDisposalAction::Purge,
            ),
            manual_confirmation_required: true,
            masking_strategy: MaskingStrategy::Full,
            watermark_strength: WatermarkStrength::Critical,
        },
        ClassificationRule {
            rule_id: "project-internal".into(),
            catalog_entry_id: "catalog-internal-operational".into(),
            field_matchers: vec!["employee_id".into(), "_id".into(), "department".into()],
            sample_patterns: Vec::new(),
            level: SensitivityLevel::L2Internal,
            data_category: DataCategory::InternalOperational,
            applicable_regulations: vec![internal_governance_policy()],
            retention_policy: retention_policy(
                "retention-internal-operational",
                730,
                RetentionDisposalAction::Archive,
            ),
            manual_confirmation_required: false,
            masking_strategy: MaskingStrategy::None,
            watermark_strength: WatermarkStrength::Low,
        },
    ];
    let catalog_entries = derive_catalog_entries(&rules);
    ClassificationRuleVersion {
        rule_version_id: format!("crv-{project_id}-{data_source_id}-v1"),
        project_id: project_id.to_string(),
        data_source_id: data_source_id.to_string(),
        version_number: 1,
        status: RuleVersionStatus::Active,
        rules,
        catalog_entries,
    }
}

pub fn normalize_rule_version_catalog(
    mut rule_version: ClassificationRuleVersion,
) -> ClassificationRuleVersion {
    rule_version.catalog_entries = derive_catalog_entries(&rule_version.rules);
    rule_version
}

pub fn derive_catalog_entries(rules: &[ClassificationRule]) -> Vec<ClassificationCatalogEntry> {
    let mut entries = Vec::<ClassificationCatalogEntry>::new();
    for rule in rules {
        let catalog_entry_id = if rule.catalog_entry_id.trim().is_empty() {
            format!("catalog-{}", rule.rule_id)
        } else {
            rule.catalog_entry_id.clone()
        };
        if let Some(entry) = entries
            .iter_mut()
            .find(|entry| entry.catalog_entry_id == catalog_entry_id)
        {
            if !entry.rule_ids.contains(&rule.rule_id) {
                entry.rule_ids.push(rule.rule_id.clone());
            }
            if entry.level < rule.level {
                entry.level = rule.level;
            }
            entry.manual_confirmation_required |= rule.manual_confirmation_required;
            continue;
        }

        entries.push(ClassificationCatalogEntry {
            catalog_entry_id,
            data_category: rule.data_category.clone(),
            level: rule.level,
            applicable_regulations: rule.applicable_regulations.clone(),
            retention_policy: rule.retention_policy.clone(),
            manual_confirmation_required: rule.manual_confirmation_required,
            rule_ids: vec![rule.rule_id.clone()],
        });
    }
    entries
}

pub fn apply_retention_overrides(
    rule_version: &mut ClassificationRuleVersion,
    standard_retention_days: i64,
    restricted_retention_days: i64,
) {
    for rule in &mut rule_version.rules {
        rule.retention_policy.retain_for_days = if rule.level >= SensitivityLevel::L5Restricted {
            restricted_retention_days
        } else {
            standard_retention_days
        };
    }
    rule_version.catalog_entries = derive_catalog_entries(&rule_version.rules);
}

pub fn recommend_field_classification(field_name: &str) -> FieldClassification {
    classify_field_from_samples(
        &default_rule_version("project-default", "datasource-default"),
        field_name,
        &[],
        None,
    )
    .as_display_policy()
}

pub fn classify_fields(
    rule_version: &ClassificationRuleVersion,
    rows: &[HashMap<String, String>],
    fields: &[String],
    detection_run_id: Option<&str>,
) -> Vec<FieldClassificationPolicy> {
    dedupe_fields(rows, fields)
        .into_iter()
        .map(|field_name| {
            let samples = rows
                .iter()
                .filter_map(|row| row.get(&field_name).cloned())
                .filter(|value| !value.is_empty())
                .take(5)
                .collect::<Vec<_>>();
            classify_field_from_samples(
                rule_version,
                &field_name,
                &samples,
                detection_run_id.map(str::to_string),
            )
        })
        .collect()
}

pub fn confirm_field_policy(policy: &FieldClassificationPolicy) -> FieldClassificationPolicy {
    let mut confirmed = policy.clone();
    confirmed.status = ClassificationStatus::Confirmed;
    confirmed.source = ClassificationPolicySource::ManualConfirmation;
    confirmed
}

pub fn confirm_field_policy_with_rule_version(
    policy: &FieldClassificationPolicy,
    rule_version: &ClassificationRuleVersion,
) -> FieldClassificationPolicy {
    let mut confirmed = confirm_field_policy(policy);
    if let Some(rule) = rule_version
        .rules
        .iter()
        .find(|rule| matches_field(rule, &policy.field_name))
    {
        apply_rule_metadata(&mut confirmed, rule, &rule_version.rule_version_id);
    } else {
        confirmed.rule_version_id = Some(rule_version.rule_version_id.clone());
    }
    confirmed
}

pub fn detect_sensitive_patterns(value: &str) -> Vec<DetectedPattern> {
    let mut patterns = Vec::new();
    let tokens = value
        .split(|char: char| char.is_whitespace() || [',', ';'].contains(&char))
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();

    for token in tokens {
        let trimmed = token.trim();
        let digit_count = trimmed.chars().filter(|char| char.is_ascii_digit()).count();

        if trimmed.contains('@')
            && trimmed
                .split('@')
                .nth(1)
                .is_some_and(|part| part.contains('.'))
        {
            push_detected_pattern(&mut patterns, SensitivePattern::Email);
        }
        if trimmed.len() == 11 && digit_count == 11 && trimmed.starts_with('1') {
            push_detected_pattern(&mut patterns, SensitivePattern::MobilePhone);
        }
        if trimmed.len() == 18 && digit_count >= 17 {
            push_detected_pattern(&mut patterns, SensitivePattern::ChinaIdCard);
        }
        if (16..=19).contains(&trimmed.len()) && digit_count == trimmed.len() {
            push_detected_pattern(&mut patterns, SensitivePattern::BankCard);
        }
    }

    patterns
}

pub fn mask_value(strategy: &MaskingStrategy, value: &str) -> String {
    match strategy {
        MaskingStrategy::None => value.to_string(),
        MaskingStrategy::PartialEmail => match value.split_once('@') {
            Some((prefix, domain)) => {
                let leading = prefix.chars().take(1).collect::<String>();
                format!("{leading}***@{domain}")
            }
            None => "***".into(),
        },
        MaskingStrategy::PartialPhone => {
            if value.len() >= 7 {
                format!("{}****{}", &value[..3], &value[value.len() - 4..])
            } else {
                "****".into()
            }
        }
        MaskingStrategy::Full => "*".repeat(value.chars().count().max(4)),
    }
}

fn classify_field_from_samples(
    rule_version: &ClassificationRuleVersion,
    field_name: &str,
    sample_values: &[String],
    detection_run_id: Option<String>,
) -> FieldClassificationPolicy {
    let base_rule = rule_version
        .rules
        .iter()
        .find(|rule| matches_field(rule, field_name));
    let fallback = default_fallback_policy(field_name);
    let mut policy = base_rule
        .map(|rule| policy_from_rule(field_name, rule, &rule_version.rule_version_id))
        .unwrap_or_else(|| fallback);

    let pattern_hints = detect_patterns_from_samples(sample_values);
    if !pattern_hints.is_empty() {
        apply_pattern_escalation(&mut policy, &pattern_hints);
        policy.status = ClassificationStatus::PendingConfirmation;
        policy.source = ClassificationPolicySource::SampleDetection;
        policy.sample_value = sample_values.first().cloned();
        policy.detection_run_id = detection_run_id;
    } else if let Some(rule) = base_rule {
        policy.status = if requires_manual_confirmation(rule) {
            ClassificationStatus::PendingConfirmation
        } else {
            ClassificationStatus::Confirmed
        };
    }

    policy
}

fn policy_from_rule(
    field_name: &str,
    rule: &ClassificationRule,
    rule_version_id: &str,
) -> FieldClassificationPolicy {
    let mut policy = FieldClassificationPolicy {
        field_name: field_name.to_string(),
        level: rule.level,
        data_category: rule.data_category.clone(),
        status: ClassificationStatus::PendingConfirmation,
        masking_strategy: rule.masking_strategy.clone(),
        watermark_strength: rule.watermark_strength.clone(),
        source: ClassificationPolicySource::RuleEngine,
        pattern_hints: rule.sample_patterns.clone(),
        sample_value: None,
        rule_version_id: Some(rule_version_id.to_string()),
        detection_run_id: None,
        catalog_entry_id: Some(rule.catalog_entry_id.clone()),
        applicable_regulations: rule.applicable_regulations.clone(),
        retention_policy: rule.retention_policy.clone(),
        manual_confirmation_required: rule.manual_confirmation_required,
    };
    apply_rule_metadata(&mut policy, rule, rule_version_id);
    policy
}

fn default_fallback_policy(field_name: &str) -> FieldClassificationPolicy {
    FieldClassificationPolicy {
        field_name: field_name.to_string(),
        level: SensitivityLevel::L3Confidential,
        data_category: DataCategory::GeneralConfidential,
        status: ClassificationStatus::PendingConfirmation,
        masking_strategy: MaskingStrategy::Full,
        watermark_strength: WatermarkStrength::Medium,
        source: ClassificationPolicySource::RuleEngine,
        pattern_hints: Vec::new(),
        sample_value: None,
        rule_version_id: None,
        detection_run_id: None,
        catalog_entry_id: None,
        applicable_regulations: vec![data_security_law()],
        retention_policy: retention_policy(
            "retention-general-confidential",
            365,
            RetentionDisposalAction::Review,
        ),
        manual_confirmation_required: true,
    }
}

fn matches_field(rule: &ClassificationRule, field_name: &str) -> bool {
    let normalized = field_name.to_ascii_lowercase();
    rule.field_matchers
        .iter()
        .any(|matcher| normalized.contains(&matcher.to_ascii_lowercase()))
}

fn requires_manual_confirmation(rule: &ClassificationRule) -> bool {
    !rule.sample_patterns.is_empty() || rule.level >= SensitivityLevel::L4Sensitive
}

fn detect_patterns_from_samples(sample_values: &[String]) -> Vec<SensitivePattern> {
    let mut patterns = Vec::new();
    for value in sample_values {
        for detected in detect_sensitive_patterns(value) {
            if !patterns.contains(&detected.pattern) {
                patterns.push(detected.pattern);
            }
        }
    }
    patterns
}

fn apply_pattern_escalation(policy: &mut FieldClassificationPolicy, patterns: &[SensitivePattern]) {
    for pattern in patterns {
        match pattern {
            SensitivePattern::ChinaIdCard | SensitivePattern::BankCard => {
                if policy.level < SensitivityLevel::L5Restricted {
                    policy.level = SensitivityLevel::L5Restricted;
                    policy.masking_strategy = MaskingStrategy::Full;
                    policy.watermark_strength = WatermarkStrength::Critical;
                }
                policy.data_category = if matches!(pattern, SensitivePattern::BankCard) {
                    DataCategory::FinancialIdentifier
                } else {
                    DataCategory::PersonalIdentifier
                };
                policy.catalog_entry_id = Some("catalog-legal-identifier".into());
                policy.applicable_regulations = vec![pipl_regulation(), data_security_law()];
                policy.retention_policy = retention_policy(
                    "retention-legal-identifier",
                    1825,
                    RetentionDisposalAction::Purge,
                );
                policy.manual_confirmation_required = true;
            }
            SensitivePattern::Email => {
                if policy.level < SensitivityLevel::L4Sensitive {
                    policy.level = SensitivityLevel::L4Sensitive;
                    policy.masking_strategy = MaskingStrategy::PartialEmail;
                    policy.watermark_strength = WatermarkStrength::High;
                }
                policy.data_category = DataCategory::PersonalContact;
                policy.catalog_entry_id = Some("catalog-personal-contact".into());
                policy.applicable_regulations = vec![pipl_regulation(), cybersecurity_law()];
                policy.retention_policy = retention_policy(
                    "retention-personal-contact",
                    365,
                    RetentionDisposalAction::Review,
                );
                policy.manual_confirmation_required = true;
            }
            SensitivePattern::MobilePhone => {
                if policy.level < SensitivityLevel::L4Sensitive {
                    policy.level = SensitivityLevel::L4Sensitive;
                    policy.masking_strategy = MaskingStrategy::PartialPhone;
                    policy.watermark_strength = WatermarkStrength::High;
                }
                policy.data_category = DataCategory::PersonalContact;
                policy.catalog_entry_id = Some("catalog-personal-contact".into());
                policy.applicable_regulations = vec![pipl_regulation(), cybersecurity_law()];
                policy.retention_policy = retention_policy(
                    "retention-personal-contact",
                    365,
                    RetentionDisposalAction::Review,
                );
                policy.manual_confirmation_required = true;
            }
        }
    }
    policy.pattern_hints = patterns.to_vec();
}

fn apply_rule_metadata(
    policy: &mut FieldClassificationPolicy,
    rule: &ClassificationRule,
    rule_version_id: &str,
) {
    policy.level = rule.level;
    policy.data_category = rule.data_category.clone();
    policy.masking_strategy = rule.masking_strategy.clone();
    policy.watermark_strength = rule.watermark_strength.clone();
    policy.rule_version_id = Some(rule_version_id.to_string());
    policy.catalog_entry_id = Some(rule.catalog_entry_id.clone());
    policy.applicable_regulations = rule.applicable_regulations.clone();
    policy.retention_policy = rule.retention_policy.clone();
    policy.manual_confirmation_required = rule.manual_confirmation_required;
}

fn dedupe_fields(rows: &[HashMap<String, String>], fields: &[String]) -> Vec<String> {
    let mut deduped = Vec::new();
    for field in fields {
        if !deduped.contains(field) {
            deduped.push(field.clone());
        }
    }
    for row in rows {
        for field in row.keys() {
            if !deduped.contains(field) {
                deduped.push(field.clone());
            }
        }
    }
    deduped
}

fn push_detected_pattern(patterns: &mut Vec<DetectedPattern>, pattern: SensitivePattern) {
    if patterns.iter().any(|existing| existing.pattern == pattern) {
        return;
    }
    patterns.push(DetectedPattern {
        pattern,
        status: ClassificationStatus::PendingConfirmation,
    });
}

fn default_catalog_entry_id() -> String {
    String::new()
}

fn default_rule_data_category() -> DataCategory {
    DataCategory::GeneralConfidential
}

fn default_manual_confirmation_required() -> bool {
    true
}

fn default_retention_policy() -> RetentionPolicy {
    retention_policy(
        "retention-general-confidential",
        365,
        RetentionDisposalAction::Review,
    )
}

fn retention_policy(
    policy_id: &str,
    retain_for_days: i64,
    disposal_action: RetentionDisposalAction,
) -> RetentionPolicy {
    RetentionPolicy {
        policy_id: policy_id.to_string(),
        retain_for_days,
        disposal_action,
        legal_hold_supported: true,
    }
}

fn pipl_regulation() -> RegulationReference {
    RegulationReference {
        code: "PIPL".into(),
        jurisdiction: "CN".into(),
        title: "Personal Information Protection Law".into(),
        retention_basis: "minimum necessary retention for approved investigation purpose".into(),
    }
}

fn data_security_law() -> RegulationReference {
    RegulationReference {
        code: "DSL".into(),
        jurisdiction: "CN".into(),
        title: "Data Security Law".into(),
        retention_basis: "important data governance and auditability".into(),
    }
}

fn cybersecurity_law() -> RegulationReference {
    RegulationReference {
        code: "CSL".into(),
        jurisdiction: "CN".into(),
        title: "Cybersecurity Law".into(),
        retention_basis: "network data security and traceability".into(),
    }
}

fn internal_governance_policy() -> RegulationReference {
    RegulationReference {
        code: "SDQP-INTERNAL".into(),
        jurisdiction: "ORG".into(),
        title: "SDQP internal data governance policy".into(),
        retention_basis: "project-scoped operational audit and access control".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ClassificationPolicySource, ClassificationStatus, DataCategory, MaskingStrategy,
        SensitivePattern, SensitivityLevel, WatermarkStrength, classify_fields,
        confirm_field_policy, default_rule_version, detect_sensitive_patterns, mask_value,
        recommend_field_classification,
    };
    use std::collections::HashMap;

    #[test]
    fn field_recommendation_maps_email_to_sensitive_policy() {
        let classification = recommend_field_classification("employee_email");
        assert_eq!(classification.level, SensitivityLevel::L4Sensitive);
        assert_eq!(
            classification.masking_strategy,
            MaskingStrategy::PartialEmail
        );
        assert_eq!(classification.watermark_strength, WatermarkStrength::High);
        assert_eq!(
            classification.status,
            ClassificationStatus::PendingConfirmation
        );
    }

    #[test]
    fn pattern_detection_flags_common_sensitive_values_as_pending() {
        let patterns = detect_sensitive_patterns("13800138000 alice@example.com");
        assert!(
            patterns
                .iter()
                .any(|pattern| pattern.pattern == SensitivePattern::Email)
        );
        assert!(
            patterns
                .iter()
                .any(|pattern| pattern.pattern == SensitivePattern::MobilePhone)
        );
        assert!(
            patterns
                .iter()
                .all(|pattern| pattern.status == ClassificationStatus::PendingConfirmation)
        );
    }

    #[test]
    fn masking_strategies_hide_sensitive_segments() {
        assert_eq!(
            mask_value(&MaskingStrategy::PartialPhone, "13800138000"),
            "138****8000"
        );
        assert_eq!(
            mask_value(&MaskingStrategy::PartialEmail, "alice@example.com"),
            "a***@example.com"
        );
    }

    #[test]
    fn classification_rules_confirm_internal_project_fields() {
        let policies = classify_fields(
            &default_rule_version("project-alpha", "datasource-rest"),
            &[HashMap::from([("department".into(), "fraud".into())])],
            &["department".into()],
            Some("run-1"),
        );

        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].level, SensitivityLevel::L2Internal);
        assert_eq!(policies[0].data_category, DataCategory::InternalOperational);
        assert_eq!(policies[0].status, ClassificationStatus::Confirmed);
        assert_eq!(policies[0].source, ClassificationPolicySource::RuleEngine);
        assert_eq!(policies[0].retention_policy.retain_for_days, 730);
    }

    #[test]
    fn sample_detection_keeps_pending_until_manual_confirmation() {
        let policies = classify_fields(
            &default_rule_version("project-alpha", "datasource-rest"),
            &[HashMap::from([(
                "employee_email".into(),
                "alice@example.com".into(),
            )])],
            &["employee_email".into()],
            Some("run-email"),
        );

        let policy = &policies[0];
        assert_eq!(policy.status, ClassificationStatus::PendingConfirmation);
        assert_eq!(policy.source, ClassificationPolicySource::SampleDetection);
        assert_eq!(policy.detection_run_id.as_deref(), Some("run-email"));

        let confirmed = confirm_field_policy(policy);
        assert_eq!(confirmed.status, ClassificationStatus::Confirmed);
        assert_eq!(
            confirmed.source,
            ClassificationPolicySource::ManualConfirmation
        );
    }

    #[test]
    fn default_rule_version_contains_governance_catalog_metadata() {
        let rule_version = default_rule_version("project-alpha", "datasource-rest");

        assert_eq!(rule_version.catalog_entries.len(), 3);
        assert!(rule_version.catalog_entries.iter().any(|entry| {
            entry.catalog_entry_id == "catalog-personal-contact"
                && entry
                    .applicable_regulations
                    .iter()
                    .any(|regulation| regulation.code == "PIPL")
                && entry.retention_policy.retain_for_days == 365
                && entry.manual_confirmation_required
        }));
    }
}
