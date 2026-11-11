//! Command orchestration. All subcommands run against the shared core; the
//! CLI holds no security logic of its own.

use std::path::PathBuf;

use secrecy::{ExposeSecret, SecretString};

use crate::args::{Args, Command};
use crate::prompt;
use clavis_core::accounts::{self};
use clavis_core::clock::{Clock, SystemClock};
use clavis_core::error::CoreError;
use clavis_core::ids::VaultId;
use clavis_core::otp::totp_at;
use clavis_core::vault::keys::{create_vault, open_revision, UnlockCredential, UnlockedVault};
use clavis_core::vault::{export as vault_export, recovery as vault_recovery};
use clavis_store::db::{read_private_file, write_private_file, Store};
use clavis_store::repository;
use clavis_sync::engine::{sync_once, Cancel, SyncTrigger};
use clavis_sync::local::{self, NewAccount};

fn sync_err(e: clavis_sync::transport::SyncError) -> CoreError {
    match e {
        clavis_sync::transport::SyncError::Canceled => CoreError::Canceled,
        clavis_sync::transport::SyncError::IntegrityFailure => CoreError::IntegrityFailure,
        clavis_sync::transport::SyncError::Unauthorized => CoreError::InvalidCredentialOrData,
        _ => CoreError::StorageFailure,
    }
}

pub fn data_dir(args: &Args) -> PathBuf {
    if let Some(d) = &args.data_dir {
        return PathBuf::from(d);
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    home.join(".local/share/clavis")
}

pub(crate) fn db_path(args: &Args) -> PathBuf {
    data_dir(args).join("clavis.sqlite")
}

fn open_store(args: &Args) -> Result<Store, CoreError> {
    Store::open(&db_path(args))
}

pub(crate) fn active_vault_id(store: &Store) -> Result<VaultId, CoreError> {
    let id = repository::active_vault(store)?.ok_or(CoreError::Locked)?;
    let uuid: uuid::Uuid = id.parse().map_err(|_| CoreError::IntegrityFailure)?;
    Ok(VaultId(uuid))
}

pub(crate) fn latest_blob(store: &Store, vault_id: &VaultId) -> Result<Vec<u8>, CoreError> {
    let (heads, _) = repository::read_heads(store, vault_id)?;
    let head = heads.last().ok_or(CoreError::IntegrityFailure)?;
    repository::load_blob(store, vault_id, head)?.ok_or(CoreError::IntegrityFailure)
}

pub async fn run(args: Args) -> Result<(), CoreError> {
    match args.command {
        Command::Doctor => {
            println!("clavis format version: {}", clavis_core::FORMAT_VERSION);
            println!("clavis-store schema: 1");
            println!("sync protocol: clavis-sync/1 (immutable revisions)");
            println!("providers: google_drive, onedrive, dropbox, webdav");
            println!("data directory: {}", data_dir(&args).display());
            Ok(())
        }
        Command::Init => init(args).await,
        Command::Connect { ref provider } => {
            let provider = provider.clone();
            connect(args, &provider).await
        }
        Command::List => list(args).await,
        Command::Code { ref account_id } => {
            let account_id = account_id.clone();
            code(args, &account_id).await
        }
        Command::Add => add(args).await,
        Command::Sync => sync(args).await,
        Command::Export { ref path } => {
            let path = path.clone();
            export(args, &path).await
        }
        Command::Recover { ref backup_path } => {
            let backup_path = backup_path.clone();
            recover(args, &backup_path).await
        }
        Command::Tui => crate::tui::run_tui(args).await,
    }
}

async fn init(args: Args) -> Result<(), CoreError> {
    let store = open_store(&args)?;
    if repository::active_vault(&store)?.is_some() {
        println!("A vault already exists. Use the unlock flow; never replace a vault after a failed unlock.");
        return Err(CoreError::InvalidInput("vault already exists"));
    }
    println!("Create a new vault, or restore an encrypted backup.");
    let choice = prompt::prompt_line("Type 'create' or 'restore'")?;
    match choice.trim() {
        "create" => {
            let passphrase = prompt::prompt_secret_twice("Choose a passphrase (12+ characters)")?;
            if passphrase.expose_secret().chars().count() < 12 {
                return Err(CoreError::InvalidInput(
                    "passphrase must be at least 12 characters",
                ));
            }
            let created = create_vault(passphrase)?;
            repository::register_vault(&store, &created.vault_id, Some("Vault"), None, true)?;
            repository::insert_remote_revision(
                &store,
                &created.vault_id,
                &created.first_revision.0,
                &[created.revision_id],
                1,
            )?;
            println!("Vault created on this device (local-only until you connect storage).");
            let mut presentation = created.recovery_key;
            let key = presentation.present()?;
            println!("\nRecovery key (show once): {}\n", key);
            println!("Keep this key somewhere safe, separate from your encrypted backup. Anyone with both can unlock the backup.");
            let check =
                prompt::prompt_line("To confirm you saved it, type 4 characters from the key")?;
            let wanted: Vec<char> = key.chars().collect();
            if check.trim().chars().collect::<Vec<char>>() != wanted[..4] {
                // The vault exists; the user can re-run recovery later. We do
                // not finalize without verification.
                return Err(CoreError::InvalidInput(
                    "verification failed; run `clavis export` after saving the key",
                ));
            }
            let export_path = prompt::prompt_line("Encrypted export path (empty to skip)")?;
            if !export_path.trim().is_empty() {
                write_export(&store, &created.unlocked, &export_path).await?;
                println!("Encrypted export written and verified.");
            }
            Ok(())
        }
        "restore" => {
            let path = prompt::prompt_line("Encrypted backup path")?;
            recover(args, path.trim()).await
        }
        _ => Err(CoreError::InvalidInput("choose 'create' or 'restore'")),
    }
}

async fn write_export(store: &Store, vault: &UnlockedVault, path: &str) -> Result<(), CoreError> {
    let state = local::load_state(store, &vault.vault_id, vault)?;
    let bytes = vault_export::seal_export(vault, &state.snapshot, &state.heads)?;
    // Independent verification: reopen the export with the root key before
    // reporting completion.
    let (payload, _) = clavis_core::vault::keys::open_revision_with_root(&bytes, vault.root_key())?;
    match payload {
        clavis_core::vault::keys::OpenedPayload::Snapshot(_) => {}
        _ => return Err(CoreError::IntegrityFailure),
    }
    write_private_file(std::path::Path::new(path), &bytes)?;
    Ok(())
}

async fn connect(args: Args, provider: &str) -> Result<(), CoreError> {
    let store = open_store(&args)?;
    let vault_id = active_vault_id(&store)?;
    let kind = clavis_providers::ProviderKind::parse(provider).ok_or(CoreError::InvalidInput(
        "unknown provider; use google|onedrive|dropbox",
    ))?;
    // OAuth runs through the external browser with a loopback callback.
    let port = pick_loopback_port()?;
    let config = match kind {
        clavis_providers::ProviderKind::GoogleDrive => {
            let client_id = require_client_id("CLAVIS_GOOGLE_CLIENT_ID")?;
            clavis_providers::oauth::google_config(&client_id, port)
        }
        clavis_providers::ProviderKind::OneDrive => {
            let client_id = require_client_id("CLAVIS_ONEDRIVE_CLIENT_ID")?;
            clavis_providers::oauth::onedrive_config(&client_id, port)
        }
        clavis_providers::ProviderKind::Dropbox => {
            let client_id = require_client_id("CLAVIS_DROPBOX_CLIENT_ID")?;
            clavis_providers::oauth::dropbox_config(&client_id, port)
        }
        clavis_providers::ProviderKind::WebDav => {
            return Err(CoreError::InvalidInput(
                "use `clavis connect webdav` guided prompts (not yet available in this build)",
            ))
        }
    };
    let pending_store = clavis_providers::oauth::PendingStore::new();
    let now = SystemClock.now_unix_seconds();
    let (pending_id, url) = pending_store.begin(config.clone(), now);
    println!("Opening your browser to authorize {} …", kind.as_str());
    println!("URL: {}", url);
    let callback = prompt::prompt_line("Paste the full callback URL after authorizing")?;
    let (pending, params) =
        pending_store.complete(&pending_id, &callback, SystemClock.now_unix_seconds())?;
    let transport = clavis_providers::oauth::ReqwestTransport::new()?;
    let tokens = clavis_providers::oauth::exchange_code(&transport, &pending, &params.code).await?;
    let connection = clavis_providers::oauth::ProviderConnection {
        id: uuid::Uuid::new_v4().to_string(),
        provider: kind,
        account_email: None,
        access_token: SecretString::new(tokens.access_token.into()),
        refresh_token: tokens.refresh_token.map(|r| SecretString::new(r.into())),
        expires_at_unix: now.checked_add(tokens.expires_in.unwrap_or(3600)),
    };
    // Encrypt and persist the credentials with the device key.
    let device_key = clavis_providers::oauth::credentials::ConnectionRecord::new(
        connection.id.clone(),
        kind,
        connection.account_email.clone(),
        &connection.access_token,
        connection.refresh_token.as_ref(),
        connection.expires_at_unix,
    );
    let dk = clavis_store::credentials::load_or_create_device_key(&db_path(&args))?;
    let cred_store = clavis_store::credentials::CredentialStore::new(vault_id, dk);
    cred_store.put(
        &store,
        &format!("provider:{}", kind.as_str()),
        &device_key.serialize()?,
    )?;
    repository::register_vault(&store, &vault_id, None, Some(kind.as_str()), true)?;
    println!(
        "Connected to {}. Your vault stays encrypted with its passphrase.",
        kind.as_str()
    );
    Ok(())
}

fn require_client_id(env: &str) -> Result<String, CoreError> {
    // Reading one specific registration variable is configuration, not
    // secret input; the doctor never dumps environment values.
    std::env::var(env).map_err(|_| {
        CoreError::InvalidInput("provider OAuth client registration required; see docs/providers/")
    })
}

fn pick_loopback_port() -> Result<u16, CoreError> {
    std::net::TcpListener::bind("127.0.0.1:0")
        .map(|l| l.local_addr().map(|a| a.port()).unwrap_or(0))
        .map_err(|_| CoreError::StorageFailure)
}

async fn list(args: Args) -> Result<(), CoreError> {
    let store = open_store(&args)?;
    let vault_id = active_vault_id(&store)?;
    let blob = latest_blob(&store, &vault_id)?;
    let passphrase = prompt::prompt_secret("Vault passphrase")?;
    let (_, vault, _) = open_revision(&blob, &UnlockCredential::Passphrase(passphrase))?;
    let state = local::load_state(&store, &vault_id, &vault)?;
    let summaries = accounts::list_summaries(&state.snapshot);
    let mut shown = 0;
    for s in summaries {
        if s.deleted {
            continue;
        }
        println!(
            "{}",
            crate::output::format_summary(
                &s.id.to_string(),
                &s.issuer,
                &s.account_label,
                s.favorite
            )
        );
        if s.has_conflict {
            println!(
                "    (conflicted: {:?})",
                s.conflicted_fields
                    .iter()
                    .map(|f| f.name())
                    .collect::<Vec<_>>()
            );
        }
        shown += 1;
    }
    if shown == 0 {
        println!("No accounts yet. Run `clavis add`.");
    }
    Ok(())
}

async fn code(args: Args, account_id: &str) -> Result<(), CoreError> {
    let store = open_store(&args)?;
    let vault_id = active_vault_id(&store)?;
    let blob = latest_blob(&store, &vault_id)?;
    let passphrase = prompt::prompt_secret("Vault passphrase")?;
    let (snapshot, _vault, _) = open_revision(&blob, &UnlockCredential::Passphrase(passphrase))?;
    let entry_id: uuid::Uuid = account_id
        .parse()
        .map_err(|_| CoreError::InvalidInput("account id must be a UUID"))?;
    let cfg = accounts::otp_config_for(&snapshot, clavis_core::ids::EntryId(entry_id))?;
    let now = SystemClock.now_unix_seconds();
    let code = totp_at(&accounts::to_otp_config(&cfg), now)?;
    let remaining = code.valid_until_unix_ms.saturating_sub(now * 1000) / 1000;
    println!(
        "{}  (valid {}s)",
        crate::output::group_code(&code.value),
        remaining
    );
    Ok(())
}

async fn add(args: Args) -> Result<(), CoreError> {
    let store = open_store(&args)?;
    let vault_id = active_vault_id(&store)?;
    let blob = latest_blob(&store, &vault_id)?;
    let passphrase = prompt::prompt_secret("Vault passphrase")?;
    let credential = UnlockCredential::Passphrase(passphrase);
    let (_, vault, _) = open_revision(&blob, &credential)?;
    let state = local::load_state(&store, &vault_id, &vault)?;
    let fingerprints: Vec<[u8; 32]> = state
        .snapshot
        .accounts
        .values()
        .filter_map(|e| {
            e.registers
                .get(&clavis_core::causal::Field::OtpConfig)
                .and_then(|r| r.single_value())
        })
        .filter_map(|v| match v {
            clavis_core::causal::FieldValue::OtpConfig(c) => {
                Some(clavis_core::import::config_fingerprint(&c))
            }
            _ => None,
        })
        .collect();
    let registry = clavis_core::import::ImportPreviewRegistry::new();
    let mode = prompt::prompt_line("Import via 'uri' or 'manual'")?;
    let input = match mode.trim() {
        "uri" => {
            let uri = prompt::prompt_line("Paste the otpauth:// URI")?;
            clavis_core::import::ImportInput::Uri(uri)
        }
        "manual" => {
            let issuer = prompt::prompt_line("Issuer (optional)")?;
            let label = prompt::prompt_line("Account label")?;
            let secret = prompt::prompt_secret("Secret (Base32)")?;
            let algorithm = prompt::prompt_line("Algorithm (SHA1/SHA256/SHA512, default SHA1)")?;
            let digits = prompt::prompt_line("Digits (6/8, default 6)")?
                .trim()
                .parse()
                .unwrap_or(6u8);
            let period = prompt::prompt_line("Period seconds (default 30)")?
                .trim()
                .parse()
                .unwrap_or(30u32);
            clavis_core::import::ImportInput::Manual(clavis_core::import::manual::ManualEntry {
                issuer,
                account_label: label,
                secret_base32: secret.expose_secret().to_string(),
                algorithm: if algorithm.trim().is_empty() {
                    "SHA1".into()
                } else {
                    algorithm.trim().to_uppercase()
                },
                digits,
                period_seconds: period,
            })
        }
        _ => return Err(CoreError::InvalidInput("choose 'uri' or 'manual'")),
    };
    let (handle, preview) = clavis_core::import::preview_import(&registry, &input, &fingerprints)?;
    if preview.duplicate_warning {
        println!("Warning: this OTP configuration matches an existing account.");
    }
    println!(
        "Import: issuer={:?} label={:?} alg={:?} digits={} period={}s",
        preview.issuer,
        preview.account_label,
        preview.algorithm,
        preview.digits,
        preview.period_seconds
    );
    let confirm = prompt::prompt_line("Add this account? (y/N)")?;
    if confirm.trim().eq_ignore_ascii_case("y") {
        let parsed = registry.take(handle)?;
        let (entry_id, _rid, _gen) = local::add_account(
            &store,
            &vault,
            NewAccount {
                issuer: parsed.issuer.unwrap_or_default(),
                account_label: parsed.account_label.unwrap_or_default(),
                favorite: false,
                config: parsed.config,
            },
            state.generation,
        )?;
        println!("Added account {}", entry_id);
    } else {
        registry.take(handle).ok();
    }
    Ok(())
}

async fn sync(args: Args) -> Result<(), CoreError> {
    let store = open_store(&args)?;
    let vault_id = active_vault_id(&store)?;
    let blob = latest_blob(&store, &vault_id)?;
    let passphrase = prompt::prompt_secret("Vault passphrase")?;
    let (_, vault, _) = open_revision(&blob, &UnlockCredential::Passphrase(passphrase))?;
    let provider = repository::list_vaults(&store)?
        .into_iter()
        .find(|(id, _, _, _)| id == &vault_id.to_string())
        .and_then(|(_, _, pk, _)| pk)
        .and_then(|pk| clavis_providers::ProviderKind::parse(&pk));
    let report = match provider {
        None => {
            println!("Local-only vault: nothing to sync.");
            return Ok(());
        }
        Some(kind) => {
            let dk = clavis_store::credentials::load_or_create_device_key(&db_path(&args))?;
            let cred_store = clavis_store::credentials::CredentialStore::new(vault_id, dk);
            let blob = cred_store
                .get(&store, &format!("provider:{}", kind.as_str()))?
                .ok_or(CoreError::InvalidInput("no connection; run clavis connect"))?;
            let record =
                clavis_providers::oauth::credentials::ConnectionRecord::deserialize(&blob)?;
            let transport: std::sync::Arc<dyn clavis_providers::oauth::HttpTransport> =
                std::sync::Arc::new(clavis_providers::oauth::ReqwestTransport::new()?);
            let remote: Box<dyn clavis_sync::transport::RemoteStore> = match kind {
                clavis_providers::ProviderKind::GoogleDrive => {
                    let cfg = clavis_providers::oauth::google_config("", 0);
                    let store_adapter =
                        clavis_providers::google::GoogleDriveStore::new(transport.clone(), cfg);
                    store_adapter.set_access_token(record.access_token());
                    Box::new(store_adapter)
                }
                clavis_providers::ProviderKind::OneDrive => {
                    let cfg = clavis_providers::oauth::onedrive_config("", 0);
                    let adapter =
                        clavis_providers::onedrive::OneDriveStore::new(transport.clone(), cfg);
                    adapter.set_access_token(record.access_token());
                    Box::new(adapter)
                }
                clavis_providers::ProviderKind::Dropbox => {
                    let cfg = clavis_providers::oauth::dropbox_config("", 0);
                    let adapter =
                        clavis_providers::dropbox::DropboxStore::new(transport.clone(), cfg);
                    adapter.set_access_token(record.access_token());
                    Box::new(adapter)
                }
                clavis_providers::ProviderKind::WebDav => {
                    return Err(CoreError::InvalidInput(
                        "webdav connect is not available in this build",
                    ))
                }
            };
            sync_once(
                &store,
                &vault,
                remote.as_ref(),
                &Cancel::new(),
                SyncTrigger::Manual,
                SystemClock.now_unix_seconds(),
            )
            .await
            .map_err(sync_err)?
        }
    };
    println!(
        "Sync: {:?} downloaded={} uploaded={} pending={}",
        report.status, report.downloaded, report.uploaded, report.pending
    );
    Ok(())
}

async fn export(args: Args, path: &str) -> Result<(), CoreError> {
    let store = open_store(&args)?;
    let vault_id = active_vault_id(&store)?;
    let blob = latest_blob(&store, &vault_id)?;
    let passphrase = prompt::prompt_secret("Vault passphrase")?;
    let (_, vault, _) = open_revision(&blob, &UnlockCredential::Passphrase(passphrase))?;
    write_export(&store, &vault, path).await?;
    println!("Encrypted export written to {}", path);
    Ok(())
}

async fn recover(args: Args, backup_path: &str) -> Result<(), CoreError> {
    let store = open_store(&args)?;
    if repository::active_vault(&store)?.is_some() {
        println!("An active vault already exists; recovery would replace it explicitly.");
        return Err(CoreError::InvalidInput("active vault exists"));
    }
    let bytes = read_private_file(std::path::Path::new(backup_path))?
        .ok_or(CoreError::InvalidInput("backup file not found"))?;
    let key = prompt::prompt_secret("Recovery key (clavis-recovery-v1:...)")?;
    let session = vault_recovery::recover(&bytes, key.expose_secret())?;
    println!("Backup verified: source vault {}.", session.source_vault_id);
    let new_passphrase = prompt::prompt_secret_twice("Choose a new passphrase (12+ characters)")?;
    if new_passphrase.expose_secret().chars().count() < 12 {
        return Err(CoreError::InvalidInput(
            "passphrase must be at least 12 characters",
        ));
    }
    let created = vault_recovery::complete_recovery(session, new_passphrase)?;
    repository::register_vault(
        &store,
        &created.vault_id,
        Some("Recovered vault"),
        None,
        true,
    )?;
    repository::insert_remote_revision(
        &store,
        &created.vault_id,
        &created.first_revision.0,
        &[created.revision_id],
        1,
    )?;
    let mut presentation = created.recovery_key;
    let key = presentation.present()?;
    println!("\nNew recovery key (show once): {}\n", key);
    println!("Keep this key somewhere safe, separate from your encrypted backup.");
    Ok(())
}
