//! Clavis shared Rust core: domain types, OTP, import parsing, cryptography
//! and unlocked sessions. Cryptography must never move into UI code.

pub mod accounts;
pub mod canonical;
pub mod causal;
pub mod clock;
pub mod dto;
pub mod error;
pub mod ids;
pub mod import;
pub mod otp;
pub mod session;
pub mod vault;

pub use clock::{Clock, SystemClock, TestClock};
pub use error::CoreError;
pub use ids::{DeviceId, EntryId, RevisionId, VaultId, WriterId};
pub use session::{SessionHandle, SessionRegistry};

/// Format version of the `clavis-v1` container family. Every client and the
/// native bridge must agree on this value.
pub const FORMAT_VERSION: u16 = 1;
