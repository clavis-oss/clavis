//! Provider-independent sync engine. See docs/security/sync-protocol-v1.md.

pub mod conflict;
pub mod engine;
pub mod fake_remote;
pub mod graph;
pub mod local;
pub mod merge;
pub mod scheduler;
pub mod status;
pub mod transport;

pub use engine::{sync_once, SyncReport};
pub use graph::{validate_graph, RevisionNode};
pub use status::decide_status;
pub use transport::{RemoteObject, RemoteStore, SyncError, UploadReceipt};
