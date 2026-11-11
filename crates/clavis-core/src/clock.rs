//! Clock abstraction. Wall-clock time is used only for TOTP computation;
//! inactivity locking always uses the monotonic clock.

use std::time::Duration;

pub trait Clock: Send + Sync {
    fn now_unix_seconds(&self) -> u64;
    fn now_monotonic(&self) -> Duration;
}

#[derive(Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_seconds(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn now_monotonic(&self) -> Duration {
        std::time::Instant::now().elapsed()
    }
}

/// Deterministic clock for tests and fixtures.
#[derive(Default, Clone)]
pub struct TestClock {
    pub unix_seconds: std::sync::Arc<std::sync::atomic::AtomicU64>,
    pub monotonic_micros: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl TestClock {
    pub fn new(unix_seconds: u64) -> Self {
        TestClock {
            unix_seconds: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(unix_seconds)),
            monotonic_micros: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }
    pub fn set_unix(&self, secs: u64) {
        self.unix_seconds
            .store(secs, std::sync::atomic::Ordering::Relaxed);
    }
    pub fn advance_monotonic(&self, d: Duration) {
        self.monotonic_micros
            .fetch_add(d.as_micros() as u64, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Clock for TestClock {
    fn now_unix_seconds(&self) -> u64 {
        self.unix_seconds.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn now_monotonic(&self) -> Duration {
        Duration::from_micros(
            self.monotonic_micros
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    }
}
