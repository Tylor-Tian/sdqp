use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptionPipelineConfig {
    pub require_masking: bool,
    pub require_watermark: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PipelineError {
    #[error("decryption pipeline must require watermark injection")]
    MissingWatermarkStep,
    #[error("decryption pipeline must require masking")]
    MissingMaskingStep,
}

impl DecryptionPipelineConfig {
    pub fn validate(&self) -> Result<(), PipelineError> {
        if !self.require_watermark {
            return Err(PipelineError::MissingWatermarkStep);
        }
        if !self.require_masking {
            return Err(PipelineError::MissingMaskingStep);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{DecryptionPipelineConfig, PipelineError};

    #[test]
    fn decryption_pipeline_requires_watermark_and_masking() {
        assert_eq!(
            DecryptionPipelineConfig {
                require_masking: true,
                require_watermark: false,
            }
            .validate(),
            Err(PipelineError::MissingWatermarkStep)
        );
    }
}
