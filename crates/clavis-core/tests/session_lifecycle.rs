use secrecy::SecretString;

use clavis_core::error::CoreError;
use clavis_core::session::SessionRegistry;
use clavis_core::vault::keys::{create_vault, UnlockedVault};
use std::time::Duration;

fn pass(s: &str) -> SecretString {
    SecretString::new(s.to_string().into())
}

#[test]
fn locked_or_unknown_handle_returns_locked() {
    let registry = SessionRegistry::new();
    let handle = registry.create(UnlockedVaultDebug::make());
    registry.lock(handle).unwrap();
    let result: Result<(), CoreError> = registry.with_session(handle, |_| Ok(()));
    assert_eq!(result.unwrap_err(), CoreError::Locked);
    // Locking twice: the second lock reports Locked (already gone).
    assert_eq!(registry.lock(handle).unwrap_err(), CoreError::Locked);
}

#[test]
fn generation_increments_for_staleness_checks() {
    let registry = SessionRegistry::new();
    let handle = registry.create(UnlockedVaultDebug::make());
    assert_eq!(registry.generation(handle).unwrap(), 1);
    assert_eq!(registry.bump_generation(handle).unwrap(), 2);
    assert_eq!(registry.generation(handle).unwrap(), 2);
}

#[test]
fn inactivity_lock_uses_monotonic_time() {
    let registry = SessionRegistry::new();
    let handle = registry.create(UnlockedVaultDebug::make());
    // No wall-clock manipulation can unlock a session that timed out
    // monotonically.
    assert!(!registry.lock_if_inactive(handle, Duration::from_secs(300)));
    std::thread::sleep(Duration::from_millis(30));
    assert!(registry.lock_if_inactive(handle, Duration::from_millis(10)));
    assert!(!registry.is_unlocked(handle));
}

#[test]
fn canceled_session_is_gone_before_delayed_results() {
    // Simulates: operation holds the registry open, lock happens, then the
    // delayed job tries to write through the handle.
    let registry = SessionRegistry::new();
    let handle = registry.create(UnlockedVaultDebug::make());
    registry.lock(handle).unwrap();
    let late_write: Result<u64, CoreError> = registry.bump_generation(handle);
    assert_eq!(late_write.unwrap_err(), CoreError::Locked);
}

/// Helper constructing an UnlockedVault for session tests without storing
/// any real data.
pub struct UnlockedVaultDebug;

impl UnlockedVaultDebug {
    pub fn make() -> UnlockedVault {
        let created = create_vault(pass("test session vault passphrase")).unwrap();
        created.unlocked
    }
}
