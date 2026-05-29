use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

use crate::{McpGatewayError, McpResult, registry::AgentRateLimits};

/// Token bucket configuration.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TokenBucketConfig {
    /// Maximum burst capacity.
    pub capacity: u32,
    /// Tokens refilled per second.
    pub refill_per_second: f64,
}

impl TokenBucketConfig {
    /// Builds a token bucket from a count over a fixed period.
    #[must_use]
    pub fn per_period(capacity: u32, period: Duration) -> Self {
        let refill_per_second = if period.is_zero() {
            0.0
        } else {
            f64::from(capacity) / period.as_secs_f64()
        };
        Self {
            capacity,
            refill_per_second,
        }
    }
}

/// Result of a rate-limit check.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RateLimitDecision {
    /// Whether the request is allowed.
    pub allowed: bool,
    /// Remaining whole tokens in the most constrained bucket.
    pub remaining: u32,
    /// Suggested retry delay when denied.
    pub retry_after: Option<Duration>,
}

#[derive(Debug, Clone)]
struct TokenBucket {
    config: TokenBucketConfig,
    available: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(config: TokenBucketConfig) -> Self {
        Self {
            config,
            available: f64::from(config.capacity),
            last_refill: Instant::now(),
        }
    }

    fn consume(&mut self) -> RateLimitDecision {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;
        self.available = (self.available + elapsed * self.config.refill_per_second)
            .min(f64::from(self.config.capacity));

        if self.available >= 1.0 {
            self.available -= 1.0;
            return RateLimitDecision {
                allowed: true,
                remaining: self.available.floor() as u32,
                retry_after: None,
            };
        }

        let retry_after = if self.config.refill_per_second > 0.0 {
            Duration::from_secs_f64((1.0 - self.available) / self.config.refill_per_second)
        } else {
            Duration::from_secs(3_600)
        };
        RateLimitDecision {
            allowed: false,
            remaining: 0,
            retry_after: Some(retry_after),
        }
    }
}

/// In-memory token-bucket rate limiter for MCP agent calls.
#[derive(Debug, Clone, Default)]
pub struct InMemoryRateLimiter {
    buckets: Arc<Mutex<HashMap<String, TokenBucket>>>,
}

impl InMemoryRateLimiter {
    /// Checks and consumes rate-limit tokens for the agent/tool pair.
    pub fn check(
        &self,
        agent_id: &str,
        tool_name: &str,
        limits: AgentRateLimits,
    ) -> McpResult<RateLimitDecision> {
        let minute = self.consume_bucket(
            &format!("{agent_id}:{tool_name}:minute"),
            TokenBucketConfig::per_period(limits.per_minute, Duration::from_secs(60)),
        )?;
        let hour = self.consume_bucket(
            &format!("{agent_id}:{tool_name}:hour"),
            TokenBucketConfig::per_period(limits.per_hour, Duration::from_secs(3_600)),
        )?;
        if minute.allowed && hour.allowed {
            return Ok(RateLimitDecision {
                allowed: true,
                remaining: minute.remaining.min(hour.remaining),
                retry_after: None,
            });
        }

        Ok(RateLimitDecision {
            allowed: false,
            remaining: 0,
            retry_after: minute.retry_after.max(hour.retry_after),
        })
    }

    fn consume_bucket(&self, key: &str, config: TokenBucketConfig) -> McpResult<RateLimitDecision> {
        let mut buckets = self
            .buckets
            .lock()
            .map_err(|_| McpGatewayError::Backend("rate limiter lock poisoned".into()))?;
        Ok(buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket::new(config))
            .consume())
    }
}
