//! Scheduling policy and backoff for the sync engine.

/// Scheduling policy: 750 ms write debounce, pull before upload, 60-second
/// active polling, bounded exponential backoff with jitter honoring
/// provider Retry-After.
#[derive(Clone, Copy, Debug)]
pub struct SchedulerConfig {
    pub debounce_ms: u64,
    pub poll_interval_s: u64,
    pub initial_backoff_ms: u64,
    pub backoff_cap_ms: u64,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        SchedulerConfig {
            debounce_ms: 750,
            poll_interval_s: 60,
            initial_backoff_ms: 1000,
            backoff_cap_ms: 5 * 60 * 1000,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BackoffState {
    pub attempt: u32,
    pub until_unix_ms: Option<u64>,
}

impl BackoffState {
    /// Next retry delay after a transport failure. Honors an explicit
    /// provider Retry-After; otherwise bounded exponential backoff with
    /// jitter. A manual retry may run sooner but never ignores an explicit
    /// provider rate limit.
    pub fn next_delay_ms(
        &self,
        config: &SchedulerConfig,
        retry_after_ms: Option<u64>,
        jitter_ms: u64,
    ) -> u64 {
        let exp = config
            .initial_backoff_ms
            .saturating_mul(1u64 << self.attempt.min(20))
            .min(config.backoff_cap_ms);
        let base = match retry_after_ms {
            Some(r) => r.min(config.backoff_cap_ms),
            None => exp,
        };
        base + (jitter_ms % 251)
    }

    pub fn record_failure(&mut self) {
        self.attempt = self.attempt.saturating_add(1);
    }

    pub fn record_success(&mut self) {
        self.attempt = 0;
        self.until_unix_ms = None;
    }

    pub fn ready(&self, now_unix_ms: u64) -> bool {
        match self.until_unix_ms {
            Some(t) => now_unix_ms >= t,
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_honors_retry_after_and_caps() {
        let cfg = SchedulerConfig::default();
        let b = BackoffState::default();
        let d = b.next_delay_ms(&cfg, Some(90_000), 0);
        assert_eq!(d, 90_000);
        let mut b2 = BackoffState::default();
        b2.record_failure();
        b2.record_failure();
        assert_eq!(b2.attempt, 2);
        let d2 = b2.next_delay_ms(&cfg, None, 0);
        assert_eq!(d2, 4000);
        let b3 = BackoffState {
            attempt: 40,
            until_unix_ms: None,
        };
        assert_eq!(b3.next_delay_ms(&cfg, None, 0), cfg.backoff_cap_ms);
    }
}
