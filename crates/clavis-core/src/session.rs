//! In-process unlocked sessions. A `SessionHandle` is an opaque ID; it is
//! never a serialized root key. Locking invalidates handles, cancels vault
//! operations and clears session state; a delayed/stale operation sees
//! `CoreError::Locked` instead of repopulating a closed session.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::CoreError;
use crate::vault::keys::UnlockedVault;

/// Opaque handle, local to one process and one registry instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionHandle(u128);

pub struct Session {
    pub vault: UnlockedVault,
    /// Monotonic operation generation; write operations bump it so queued
    /// work can detect that state moved under it.
    pub generation: u64,
    pub last_activity: Instant,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Session(gen={})", self.generation)
    }
}

pub struct SessionRegistry {
    inner: Mutex<RegistryInner>,
}

struct RegistryInner {
    next_id: u128,
    sessions: HashMap<SessionHandle, Session>,
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionRegistry {
    pub fn new() -> Self {
        SessionRegistry {
            inner: Mutex::new(RegistryInner {
                next_id: 1,
                sessions: HashMap::new(),
            }),
        }
    }

    pub fn create(&self, vault: UnlockedVault) -> SessionHandle {
        let mut inner = self.inner.lock().expect("registry lock");
        let id = SessionHandle(inner.next_id);
        inner.next_id += 1;
        inner.sessions.insert(
            id,
            Session {
                vault,
                generation: 1,
                last_activity: Instant::now(),
            },
        );
        id
    }

    /// Run an operation against a live session. Missing/stale handles return
    /// `Locked`; operations must never resurrect a closed session.
    pub fn with_session<T>(
        &self,
        handle: SessionHandle,
        op: impl FnOnce(&mut Session) -> Result<T, CoreError>,
    ) -> Result<T, CoreError> {
        let mut inner = self.inner.lock().expect("registry lock");
        let session = inner.sessions.get_mut(&handle).ok_or(CoreError::Locked)?;
        session.last_activity = Instant::now();
        op(session)
    }

    /// Read the current generation for staleness checks.
    pub fn generation(&self, handle: SessionHandle) -> Result<u64, CoreError> {
        let inner = self.inner.lock().expect("registry lock");
        Ok(inner
            .sessions
            .get(&handle)
            .ok_or(CoreError::Locked)?
            .generation)
    }

    /// Bump the generation after a committed local write.
    pub fn bump_generation(&self, handle: SessionHandle) -> Result<u64, CoreError> {
        let mut inner = self.inner.lock().expect("registry lock");
        let session = inner.sessions.get_mut(&handle).ok_or(CoreError::Locked)?;
        session.generation += 1;
        Ok(session.generation)
    }

    /// Lock this app: drop the session. The vault data on disk is untouched.
    pub fn lock(&self, handle: SessionHandle) -> Result<(), CoreError> {
        let mut inner = self.inner.lock().expect("registry lock");
        inner
            .sessions
            .remove(&handle)
            .map(|_| ())
            .ok_or(CoreError::Locked)
    }

    /// Enforce the inactivity timeout using the monotonic clock. Wall-clock
    /// jumps never unlock or keep unlocked a session that timed out.
    pub fn lock_if_inactive(&self, handle: SessionHandle, max_idle: Duration) -> bool {
        let mut inner = self.inner.lock().expect("registry lock");
        let expired = match inner.sessions.get(&handle) {
            Some(s) => s.last_activity.elapsed() >= max_idle,
            None => return false,
        };
        if expired {
            inner.sessions.remove(&handle);
        }
        expired
    }

    pub fn is_unlocked(&self, handle: SessionHandle) -> bool {
        self.inner
            .lock()
            .expect("registry lock")
            .sessions
            .contains_key(&handle)
    }
}
