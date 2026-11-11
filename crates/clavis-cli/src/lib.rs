//! Clavis terminal client library: shared by the binary and the tests.

pub mod app;
pub mod args;
pub mod output;
pub mod prompt;
pub mod tui;

use clap::Parser;

use args::Args;
use clavis_core::error::CoreError;

/// Stable exit codes: 0 success, 2 usage, 3 locked/credential, 4
/// storage/network, 5 conflict/integrity.
pub fn exit_code_for(err: &CoreError) -> i32 {
    match err {
        CoreError::InvalidInput(_) => 2,
        CoreError::Locked | CoreError::InvalidCredentialOrData => 3,
        CoreError::StorageFailure | CoreError::IncompleteSync => 4,
        CoreError::IntegrityFailure | CoreError::CapacityReached | CoreError::StaleRevision => 5,
        _ => 1,
    }
}

pub fn run() {
    let args = Args::parse();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let code = match rt.block_on(app::run(args)) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            exit_code_for(&e)
        }
    };
    std::process::exit(code);
}
