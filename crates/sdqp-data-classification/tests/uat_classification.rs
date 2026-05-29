use sdqp_data_classification::{
    ClassificationStatus, MaskingStrategy, SensitivePattern, detect_sensitive_patterns, mask_value,
    recommend_field_classification,
};

#[test]
fn uat_sensitive_detection_requires_confirmation_and_emits_masking_policy() {
    let classification = recommend_field_classification("bank_card_number");
    let patterns = detect_sensitive_patterns("6222021001112223334");

    assert_eq!(
        classification.status,
        ClassificationStatus::PendingConfirmation
    );
    assert_eq!(classification.masking_strategy, MaskingStrategy::Full);
    assert!(
        patterns
            .iter()
            .any(|pattern| pattern.pattern == SensitivePattern::BankCard)
    );
    assert!(
        patterns
            .iter()
            .all(|pattern| pattern.status == ClassificationStatus::PendingConfirmation)
    );
    assert_eq!(
        mask_value(&classification.masking_strategy, "6222021001112223334"),
        "*******************"
    );
}
