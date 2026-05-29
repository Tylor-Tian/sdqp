use std::{collections::HashMap, time::Duration};

#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    threshold: u32,
    retry_backoff: Duration,
    failures: HashMap<String, CircuitFailureRecord>,
}

#[derive(Debug, Clone)]
struct CircuitFailureRecord {
    consecutive_failures: u32,
    opened_at: Option<std::time::Instant>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitBreakerSnapshot {
    pub source_id: String,
    pub failure_count: u32,
    pub open: bool,
    pub retry_after: Option<Duration>,
}

impl CircuitBreaker {
    pub fn new(threshold: u32) -> Self {
        Self::with_backoff(threshold, Duration::from_secs(30))
    }

    pub fn with_backoff(threshold: u32, retry_backoff: Duration) -> Self {
        Self {
            threshold,
            retry_backoff,
            failures: HashMap::new(),
        }
    }

    pub fn allow(&self, source_id: &str) -> bool {
        if self.threshold == 0 {
            return true;
        }

        let Some(record) = self.failures.get(source_id) else {
            return true;
        };
        if record.consecutive_failures < self.threshold {
            return true;
        }

        record
            .opened_at
            .is_some_and(|opened_at| opened_at.elapsed() >= self.retry_backoff)
    }

    pub fn record_success(&mut self, source_id: &str) {
        self.failures.remove(source_id);
    }

    pub fn record_failure(&mut self, source_id: &str) {
        let entry = self
            .failures
            .entry(source_id.to_string())
            .or_insert(CircuitFailureRecord {
                consecutive_failures: 0,
                opened_at: None,
            });
        entry.consecutive_failures += 1;
        if self.threshold > 0
            && entry.consecutive_failures >= self.threshold
            && entry.opened_at.is_none()
        {
            entry.opened_at = Some(std::time::Instant::now());
        }
    }

    pub fn failure_count(&self, source_id: &str) -> u32 {
        self.failures
            .get(source_id)
            .map(|record| record.consecutive_failures)
            .unwrap_or_default()
    }

    pub fn is_open(&self, source_id: &str) -> bool {
        !self.allow(source_id)
    }

    pub fn retry_after(&self, source_id: &str) -> Option<Duration> {
        let record = self.failures.get(source_id)?;
        if self.threshold == 0 || record.consecutive_failures < self.threshold {
            return None;
        }
        let elapsed = record.opened_at?.elapsed();
        Some(self.retry_backoff.saturating_sub(elapsed))
    }

    pub fn source_snapshot(&self, source_id: &str) -> CircuitBreakerSnapshot {
        CircuitBreakerSnapshot {
            source_id: source_id.to_string(),
            failure_count: self.failure_count(source_id),
            open: self.is_open(source_id),
            retry_after: self.retry_after(source_id),
        }
    }

    pub fn snapshot(&self) -> Vec<(String, u32)> {
        self.failures
            .iter()
            .map(|(source_id, record)| (source_id.clone(), record.consecutive_failures))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::CircuitBreaker;

    #[test]
    fn circuit_breaker_opens_after_threshold() {
        let mut breaker = CircuitBreaker::new(2);
        breaker.record_failure("rest");
        assert!(breaker.allow("rest"));
        breaker.record_failure("rest");
        assert!(!breaker.allow("rest"));
    }
}
