use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "clavis",
    about = "Local-first authenticator with encrypted sync through your own storage",
    version
)]
pub struct Args {
    /// Data directory holding the local store (defaults to the OS data dir).
    #[arg(long, value_name = "DIR")]
    pub data_dir: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create a new vault or open an existing one interactively.
    Init,
    /// Connect a storage provider through the browser (interactive).
    Connect {
        #[arg(value_name = "google|onedrive|dropbox")]
        provider: String,
    },
    /// List accounts (labels only; requires unlock).
    List,
    /// Print the current code for one account by stable ID.
    Code { account_id: String },
    /// Add an account interactively (URI or manual entry; never arguments).
    Add,
    /// Run one sync pass now.
    Sync,
    /// Write an encrypted export to a file.
    Export { path: String },
    /// Recover a vault from an encrypted export with its recovery key.
    Recover { backup_path: String },
    /// Run the interactive terminal UI.
    Tui,
    /// Report toolchain/environment versions (no environment variables).
    Doctor,
}
