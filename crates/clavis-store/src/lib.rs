//! Local SQLite persistence: a transactional container for encrypted
//! revision blobs, pending uploads and non-secret configuration. Plaintext
//! secrets, labels or seeds must never enter these tables, the WAL or temp
//! files.

pub mod credentials;
pub mod db;
pub mod outbox;
pub mod repository;

pub use db::Store;
