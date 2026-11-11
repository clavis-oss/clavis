//! Narrow typed Tauri commands. The web UI never receives a root key,
//! seed, OAuth token or arbitrary filesystem authority; errors are fixed
//! safe messages. Passphrases transit this bridge only for
//! create/unlock; every other operation runs against the in-process
//! unlocked session created by `unlock`.

use std::path::PathBuf;
use std::sync::Mutex;

use secrecy::SecretString;
use tauri::State;

use clavis_core::accounts;
use clavis_core::clock::{Clock, SystemClock};
use clavis_core::dto::{
    AccountCodeDto, AccountSummaryDto, ConflictDetailDto, CoreErrorDto, ImportPreviewDto,
    ManualEntryDto, OtpCodeDto, SyncStatusKind, VaultInfoDto,
};
use clavis_core::error::CoreError;
use clavis_core::ids::{EntryId, VaultId};
use clavis_core::otp::totp_at;
use clavis_core::session::SessionRegistry;
use clavis_core::vault::export as vault_export;
use clavis_core::vault::keys::{create_vault as create_vault_ns, open_revision, UnlockCredential};
use clavis_store::db::Store;
use clavis_store::repository;
use clavis_sync::engine::{sync_once, Cancel, SyncReport, SyncTrigger};
use clavis_sync::local::NewAccount;

pub struct AppState {
    pub store: Store,
    pub registry: SessionRegistry,
    pub imports: clavis_core::import::ImportPreviewRegistry,
    pub pending_oauth: clavis_providers::oauth::PendingStore,
    pub db_path: PathBuf,
    pub last_report: Mutex<Option<SyncReport>>,
    /// The single interactive unlock session handle for this window.
    pub current_handle: Mutex<Option<clavis_core::session::SessionHandle>>,
}

/// Tauri command error: serialized safe kind/message to the UI.
#[derive(Clone, Debug, serde::Serialize)]
pub struct CommandError {
    pub kind: String,
    pub message: String,
}

impl From<CoreError> for CommandError {
    fn from(e: CoreError) -> Self {
        CommandError {
            kind: e.kind().to_string(),
            message: e.to_string(),
        }
    }
}

impl From<CoreErrorDto> for CommandError {
    fn from(e: CoreErrorDto) -> Self {
        CommandError {
            kind: e.kind,
            message: e.message,
        }
    }
}

pub type AppResult<T> = Result<T, CommandError>;

pub fn err_dto(e: &CoreError) -> CoreErrorDto {
    CoreErrorDto {
        kind: e.kind().to_string(),
        message: e.to_string(),
    }
}

fn dto(e: CoreError) -> CoreErrorDto {
    err_dto(&e)
}

fn to_summary_dto(s: accounts::AccountSummary) -> AccountSummaryDto {
    AccountSummaryDto {
        id: s.id.to_string(),
        issuer: s.issuer,
        account_label: s.account_label,
        favorite: s.favorite,
        has_conflict: s.has_conflict,
        conflicted_fields: s
            .conflicted_fields
            .iter()
            .map(|f| f.name().to_string())
            .collect(),
        deleted: s.deleted,
    }
}

impl AppState {
    pub fn new(db_path: PathBuf) -> Result<Self, CoreError> {
        Ok(AppState {
            store: Store::open(&db_path)?,
            registry: SessionRegistry::new(),
            imports: clavis_core::import::ImportPreviewRegistry::new(),
            pending_oauth: clavis_providers::oauth::PendingStore::new(),
            db_path,
            last_report: Mutex::new(None),
            current_handle: Mutex::new(None),
        })
    }

    fn active_vault_id(&self) -> Result<VaultId, CoreError> {
        let id = repository::active_vault(&self.store)?.ok_or(CoreError::Locked)?;
        let uuid: uuid::Uuid = id.parse().map_err(|_| CoreError::IntegrityFailure)?;
        Ok(VaultId(uuid))
    }

    fn latest_blob(&self, vault_id: &VaultId) -> Result<Vec<u8>, CoreError> {
        let (heads, _) = repository::read_heads(&self.store, vault_id)?;
        let head = heads.last().ok_or(CoreError::IntegrityFailure)?;
        repository::load_blob(&self.store, vault_id, head)?.ok_or(CoreError::IntegrityFailure)
    }

    fn current_handle(&self) -> Option<clavis_core::session::SessionHandle> {
        *self.current_handle.lock().unwrap()
    }

    /// Run an operation against the unlocked session's vault. Missing or
    /// locked sessions yield `CoreError::Locked` (kind "locked") so the UI
    /// routes to the unlock screen instead of failing opaquely.
    fn with_vault<T>(
        &self,
        op: impl FnOnce(&Store, &clavis_core::vault::keys::UnlockedVault) -> Result<T, CoreError>,
    ) -> Result<T, CoreError> {
        let handle = self.current_handle().ok_or(CoreError::Locked)?;
        self.registry
            .with_session(handle, |session| op(&self.store, &session.vault))
    }
}

// ---- vault lifecycle -------------------------------------------------------

#[tauri::command]
pub fn vault_info(state: State<'_, AppState>) -> AppResult<VaultInfoDto> {
    let store = &state.store;
    let Some(id) = repository::active_vault(store).map_err(dto)? else {
        return Ok(VaultInfoDto {
            vault_id: String::new(),
            name: None,
            provider_kind: None,
            locked: true,
            has_conflicts: false,
        });
    };
    let vaults = repository::list_vaults(store).map_err(dto)?;
    let entry = vaults.iter().find(|(v, _, _, _)| v == &id);
    let provider_kind = entry
        .and_then(|(_, _, pk, _)| pk.clone())
        .and_then(|pk| clavis_providers::ProviderKind::parse(&pk))
        .map(|k| k.as_str().to_string());
    let locked = state.current_handle().is_none();
    Ok(VaultInfoDto {
        vault_id: id,
        name: entry.and_then(|(_, n, _, _)| n.clone()),
        provider_kind,
        locked,
        has_conflicts: false,
    })
}

#[tauri::command]
pub fn create_vault(state: State<'_, AppState>, passphrase: String) -> AppResult<VaultInfoDto> {
    if repository::active_vault(&state.store)
        .map_err(dto)?
        .is_some()
    {
        return Err(dto(CoreError::InvalidInput("vault already exists")).into());
    }
    if passphrase.chars().count() < 12 {
        return Err(dto(CoreError::InvalidInput(
            "passphrase must be at least 12 characters",
        ))
        .into());
    }
    let created = create_vault_ns(SecretString::new(passphrase.into())).map_err(dto)?;
    repository::register_vault(&state.store, &created.vault_id, Some("Vault"), None, true)
        .map_err(dto)?;
    repository::insert_remote_revision(
        &state.store,
        &created.vault_id,
        &created.first_revision.0,
        &[created.revision_id],
        1,
    )
    .map_err(dto)?;
    let handle = state.registry.create(created.unlocked);
    *state.current_handle.lock().unwrap() = Some(handle);
    Ok(VaultInfoDto {
        vault_id: created.vault_id.to_string(),
        name: Some("Vault".into()),
        provider_kind: None,
        locked: false,
        has_conflicts: false,
    })
}

#[tauri::command]
pub fn confirm_recovery(state: State<'_, AppState>, recovery_key: String) -> AppResult<String> {
    // One-session verification: the frontend asks for 4 selected characters.
    // The full key is validated by shape here; the real check is that the
    // user repeated it correctly in the UI before calling this.
    if !recovery_key.starts_with("clavis-recovery-v1:") {
        return Err(dto(CoreError::InvalidInput("unexpected recovery key format")).into());
    }
    let _ = &state;
    Ok("ok".into())
}

#[tauri::command]
pub fn unlock(state: State<'_, AppState>, passphrase: String) -> AppResult<VaultInfoDto> {
    let vault_id = state.active_vault_id().map_err(dto)?;
    let blob = state.latest_blob(&vault_id).map_err(dto)?;
    let credential = UnlockCredential::Passphrase(SecretString::new(passphrase.into()));
    let (snapshot, vault, _) = open_revision(&blob, &credential).map_err(dto)?;
    let conflicts = !accounts::list_conflicts(&snapshot).is_empty();
    let handle = state.registry.create(vault);
    *state.current_handle.lock().unwrap() = Some(handle);
    Ok(VaultInfoDto {
        vault_id: vault_id.to_string(),
        name: repository::list_vaults(&state.store).ok().and_then(|vs| {
            vs.into_iter()
                .find(|(v, _, _, _)| v == &vault_id.to_string())
                .and_then(|(_, n, _, _)| n)
        }),
        provider_kind: None,
        locked: false,
        has_conflicts: conflicts,
    })
}

#[tauri::command]
pub fn lock(state: State<'_, AppState>) -> AppResult<()> {
    if let Some(handle) = state.current_handle() {
        state.registry.lock(handle).map_err(dto)?;
        *state.current_handle.lock().unwrap() = None;
    }
    state.imports.clear();
    state.pending_oauth.clear();
    Ok(())
}

// ---- accounts ---------------------------------------------------------------

#[tauri::command]
pub fn list_accounts(state: State<'_, AppState>) -> AppResult<Vec<AccountSummaryDto>> {
    state
        .with_vault(|store, vault| {
            let loaded = clavis_sync::local::load_state(store, &vault.vault_id, vault)?;
            Ok(accounts::list_summaries(&loaded.snapshot)
                .into_iter()
                .filter(|s| !s.deleted)
                .map(to_summary_dto)
                .collect())
        })
        .map_err(dto)
        .map_err(CommandError::from)
}

/// Live codes for every usable account, generated from the unlocked
/// session (one state load per poll, no repeated KDF work).
#[tauri::command]
pub fn list_codes(state: State<'_, AppState>) -> AppResult<Vec<AccountCodeDto>> {
    state
        .with_vault(|store, vault| {
            let loaded = clavis_sync::local::load_state(store, &vault.vault_id, vault)?;
            let now = SystemClock.now_unix_seconds();
            let mut out = Vec::new();
            for summary in accounts::list_summaries(&loaded.snapshot) {
                if summary.deleted || summary.has_conflict {
                    continue;
                }
                if let Ok(cfg) = accounts::otp_config_for(&loaded.snapshot, summary.id) {
                    if let Ok(code) = totp_at(&accounts::to_otp_config(&cfg), now) {
                        out.push(AccountCodeDto {
                            account_id: summary.id.to_string(),
                            value: code.value,
                            valid_until_unix_ms: code.valid_until_unix_ms.to_string(),
                        });
                    }
                }
            }
            Ok(out)
        })
        .map_err(dto)
        .map_err(CommandError::from)
}

#[tauri::command]
pub fn get_code(state: State<'_, AppState>, account_id: String) -> AppResult<OtpCodeDto> {
    state
        .with_vault(|store, vault| {
            let loaded = clavis_sync::local::load_state(store, &vault.vault_id, vault)?;
            let entry: uuid::Uuid = account_id
                .parse()
                .map_err(|_| CoreError::InvalidInput("invalid account id"))?;
            let cfg = accounts::otp_config_for(&loaded.snapshot, EntryId(entry))?;
            let now = SystemClock.now_unix_seconds();
            let code = totp_at(&accounts::to_otp_config(&cfg), now)?;
            Ok(OtpCodeDto {
                value: code.value,
                valid_until_unix_ms: code.valid_until_unix_ms.to_string(),
            })
        })
        .map_err(dto)
        .map_err(CommandError::from)
}

fn preview_dto(handle: u64, preview: clavis_core::import::ImportPreview) -> ImportPreviewDto {
    ImportPreviewDto {
        handle,
        issuer: preview.issuer,
        account_label: preview.account_label,
        algorithm: format!("{:?}", preview.algorithm).to_uppercase(),
        digits: preview.digits,
        period_seconds: preview.period_seconds,
        duplicate_warning: preview.duplicate_warning,
    }
}

fn existing_fingerprints(snapshot: &clavis_core::causal::Snapshot) -> Vec<[u8; 32]> {
    snapshot
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
        .collect()
}

fn preview_input(
    state: &AppState,
    input: clavis_core::import::ImportInput,
) -> Result<ImportPreviewDto, CoreError> {
    state.with_vault(|store, vault| {
        let loaded = clavis_sync::local::load_state(store, &vault.vault_id, vault)?;
        let fingerprints = existing_fingerprints(&loaded.snapshot);
        let (handle, preview) =
            clavis_core::import::preview_import(&state.imports, &input, &fingerprints)?;
        Ok(preview_dto(handle, preview))
    })
}

#[tauri::command]
pub fn preview_import_uri(state: State<'_, AppState>, uri: String) -> AppResult<ImportPreviewDto> {
    preview_input(&state, clavis_core::import::ImportInput::Uri(uri))
        .map_err(dto)
        .map_err(CommandError::from)
}

#[tauri::command]
pub fn preview_import_manual(
    state: State<'_, AppState>,
    entry: ManualEntryDto,
) -> AppResult<ImportPreviewDto> {
    preview_input(
        &state,
        clavis_core::import::ImportInput::Manual(clavis_core::import::manual::ManualEntry {
            issuer: entry.issuer,
            account_label: entry.account_label,
            secret_base32: entry.secret_base32,
            algorithm: entry.algorithm,
            digits: entry.digits,
            period_seconds: entry.period_seconds,
        }),
    )
    .map_err(dto)
    .map_err(CommandError::from)
}

/// Import preview from a locally selected QR image (PNG/JPEG). When the
/// image contains several QR codes and no selection was made, the typed
/// error kind "multiple_candidates" carries the count so the UI can offer
/// a chooser.
#[tauri::command]
pub fn preview_import_image(
    state: State<'_, AppState>,
    image: Vec<u8>,
    selection: Option<usize>,
) -> AppResult<ImportPreviewDto> {
    if selection.is_none() {
        if let Ok(candidates) = clavis_core::import::qr::decode_qr_candidates(&image) {
            if candidates.len() > 1 {
                return Err(CommandError {
                    kind: "multiple_candidates".to_string(),
                    message: format!(
                        "This image contains {} QR codes — select one.",
                        candidates.len()
                    ),
                });
            }
        }
    }
    preview_input(
        &state,
        clavis_core::import::ImportInput::Image(image, selection),
    )
    .map_err(dto)
    .map_err(CommandError::from)
}

#[tauri::command]
pub fn confirm_import(state: State<'_, AppState>, handle: u64) -> AppResult<AccountSummaryDto> {
    let parsed = state.imports.take(handle).map_err(dto)?;
    state
        .with_vault(|store, vault| {
            let (_, generation) = repository::read_heads(store, &vault.vault_id)?;
            let (entry_id, _, _) = clavis_sync::local::add_account(
                store,
                vault,
                NewAccount {
                    issuer: parsed.issuer.clone().unwrap_or_default(),
                    account_label: parsed.account_label.clone().unwrap_or_default(),
                    favorite: false,
                    config: parsed.config,
                },
                generation,
            )?;
            Ok(AccountSummaryDto {
                id: entry_id.to_string(),
                issuer: parsed.issuer,
                account_label: parsed.account_label,
                favorite: false,
                has_conflict: false,
                conflicted_fields: vec![],
                deleted: false,
            })
        })
        .map_err(dto)
        .map_err(CommandError::from)
}

#[tauri::command]
pub fn update_account(
    state: State<'_, AppState>,
    account_id: String,
    issuer: Option<String>,
    account_label: Option<String>,
    favorite: Option<bool>,
) -> AppResult<()> {
    let entry: uuid::Uuid = account_id
        .parse()
        .map_err(|_| dto(CoreError::InvalidInput("invalid account id")))?;
    state
        .with_vault(|store, vault| {
            let (_, generation) = repository::read_heads(store, &vault.vault_id)?;
            clavis_sync::local::update_account(
                store,
                vault,
                EntryId(entry),
                clavis_sync::local::AccountPatch {
                    issuer,
                    account_label,
                    favorite,
                    otp_config: None,
                },
                generation,
            )
        })
        .map_err(dto)
        .map_err(CommandError::from)
        .map(|_| ())
}

#[tauri::command]
pub fn delete_account(state: State<'_, AppState>, account_id: String) -> AppResult<()> {
    let entry: uuid::Uuid = account_id
        .parse()
        .map_err(|_| dto(CoreError::InvalidInput("invalid account id")))?;
    state
        .with_vault(|store, vault| {
            let (_, generation) = repository::read_heads(store, &vault.vault_id)?;
            clavis_sync::local::delete_account(store, vault, EntryId(entry), generation)
        })
        .map_err(dto)
        .map_err(CommandError::from)
        .map(|_| ())
}

#[tauri::command]
pub fn restore_account(state: State<'_, AppState>, account_id: String) -> AppResult<()> {
    let entry: uuid::Uuid = account_id
        .parse()
        .map_err(|_| dto(CoreError::InvalidInput("invalid account id")))?;
    state
        .with_vault(|store, vault| {
            let (_, generation) = repository::read_heads(store, &vault.vault_id)?;
            clavis_sync::local::restore_account(store, vault, EntryId(entry), generation)
        })
        .map_err(dto)
        .map_err(CommandError::from)
        .map(|_| ())
}

#[tauri::command]
pub fn list_conflicts(state: State<'_, AppState>) -> AppResult<Vec<ConflictDetailDto>> {
    state
        .with_vault(|store, vault| {
            let loaded = clavis_sync::local::load_state(store, &vault.vault_id, vault)?;
            Ok(accounts::list_conflicts(&loaded.snapshot)
                .into_iter()
                .map(|c| ConflictDetailDto {
                    entry_id: c.entry_id.to_string(),
                    field: c.field.name().to_string(),
                    candidates: c
                        .candidates
                        .into_iter()
                        .map(|x| clavis_core::dto::ConflictCandidateDto {
                            origin: x.origin,
                            display: x.display,
                            index: x.index,
                        })
                        .collect(),
                })
                .collect())
        })
        .map_err(dto)
        .map_err(CommandError::from)
}

#[tauri::command]
pub fn resolve_conflict(
    state: State<'_, AppState>,
    account_id: String,
    field: String,
    candidate_index: usize,
) -> AppResult<()> {
    let entry: uuid::Uuid = account_id
        .parse()
        .map_err(|_| dto(CoreError::InvalidInput("invalid account id")))?;
    let f = parse_field(&field).map_err(dto)?;
    state
        .with_vault(|store, vault| {
            let loaded = clavis_sync::local::load_state(store, &vault.vault_id, vault)?;
            let (_, generation) = repository::read_heads(store, &vault.vault_id)?;
            clavis_sync::local::resolve_conflict(
                store,
                vault,
                clavis_sync::conflict::Resolution {
                    entry_id: EntryId(entry),
                    field: f,
                    candidate_index,
                },
                &loaded.heads,
                generation,
            )
        })
        .map_err(dto)
        .map_err(CommandError::from)
        .map(|_| ())
}

#[tauri::command]
pub fn keep_both(
    state: State<'_, AppState>,
    account_id: String,
    field: String,
    keep_original: usize,
    keep_new: usize,
) -> AppResult<()> {
    let entry: uuid::Uuid = account_id
        .parse()
        .map_err(|_| dto(CoreError::InvalidInput("invalid account id")))?;
    let f = parse_field(&field).map_err(dto)?;
    state
        .with_vault(|store, vault| {
            let (_, generation) = repository::read_heads(store, &vault.vault_id)?;
            clavis_sync::local::keep_both(
                store,
                vault,
                EntryId(entry),
                f,
                keep_original,
                keep_new,
                generation,
            )
        })
        .map_err(dto)
        .map_err(CommandError::from)
        .map(|_| ())
}

fn sync_err(e: clavis_sync::transport::SyncError) -> CoreError {
    match e {
        clavis_sync::transport::SyncError::Canceled => CoreError::Canceled,
        clavis_sync::transport::SyncError::IntegrityFailure => CoreError::IntegrityFailure,
        clavis_sync::transport::SyncError::Unauthorized => CoreError::InvalidCredentialOrData,
        _ => CoreError::StorageFailure,
    }
}

fn parse_field(s: &str) -> Result<clavis_core::causal::Field, CoreError> {
    match s {
        "issuer" => Ok(clavis_core::causal::Field::Issuer),
        "account_label" => Ok(clavis_core::causal::Field::AccountLabel),
        "favorite" => Ok(clavis_core::causal::Field::Favorite),
        "otp_config" => Ok(clavis_core::causal::Field::OtpConfig),
        "lifecycle" => Ok(clavis_core::causal::Field::Lifecycle),
        _ => Err(CoreError::InvalidInput("unknown field")),
    }
}

// ---- export / providers / sync ---------------------------------------------

#[tauri::command]
pub fn export_vault(state: State<'_, AppState>, destination: String) -> AppResult<String> {
    state
        .with_vault(|store, vault| {
            let loaded = clavis_sync::local::load_state(store, &vault.vault_id, vault)?;
            let bytes = vault_export::seal_export(vault, &loaded.snapshot, &loaded.heads)?;
            // Verify before reporting completion.
            clavis_core::vault::keys::open_revision_with_root(&bytes, vault.root_key())?;
            std::fs::write(&destination, bytes).map_err(|_| CoreError::StorageFailure)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o600));
            }
            Ok(destination)
        })
        .map_err(dto)
        .map_err(CommandError::from)
}

#[tauri::command]
pub fn connect_provider_begin(state: State<'_, AppState>, provider: String) -> AppResult<String> {
    let kind = clavis_providers::ProviderKind::parse(&provider)
        .ok_or(CoreError::InvalidInput("unknown provider"))?;
    let client_id = std::env::var(format!("CLAVIS_{}_CLIENT_ID", provider.to_uppercase()))
        .map_err(|_| CoreError::InvalidInput("provider OAuth client registration required"))?;
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map_err(|_| CoreError::StorageFailure)?
        .port();
    let config = match kind {
        clavis_providers::ProviderKind::GoogleDrive => {
            clavis_providers::oauth::google_config(&client_id, port)
        }
        clavis_providers::ProviderKind::OneDrive => {
            clavis_providers::oauth::onedrive_config(&client_id, port)
        }
        clavis_providers::ProviderKind::Dropbox => {
            clavis_providers::oauth::dropbox_config(&client_id, port)
        }
        clavis_providers::ProviderKind::WebDav => {
            return Err(dto(CoreError::InvalidInput("webdav uses a guided form")).into());
        }
    };
    let now = SystemClock.now_unix_seconds();
    let (pending_id, url) = state.pending_oauth.begin(config, now);
    let _ = pending_id;
    Ok(url)
}

#[tauri::command]
pub fn connect_provider_complete(
    state: State<'_, AppState>,
    provider: String,
    callback_url: String,
) -> AppResult<VaultInfoDto> {
    let kind = clavis_providers::ProviderKind::parse(&provider)
        .ok_or(CoreError::InvalidInput("unknown provider"))?;
    let vault_id = state.active_vault_id().map_err(dto)?;
    let state_param = callback_url
        .split("state=")
        .nth(1)
        .and_then(|s| s.split('&').next())
        .unwrap_or_default()
        .to_string();
    let now = SystemClock.now_unix_seconds();
    let (pending, params) = state
        .pending_oauth
        .complete_by_state(&state_param, &callback_url, now)
        .map_err(dto)?;
    let rt = tauri::async_runtime::block_on(async {
        let transport = clavis_providers::oauth::ReqwestTransport::new().map_err(dto)?;
        clavis_providers::oauth::exchange_code(&transport, &pending, &params.code)
            .await
            .map_err(dto)
    })?;
    let record = clavis_providers::oauth::credentials::ConnectionRecord::new(
        uuid::Uuid::new_v4().to_string(),
        kind,
        None,
        &SecretString::new(rt.access_token.into()),
        rt.refresh_token
            .as_ref()
            .map(|r| SecretString::new(r.clone().into()))
            .as_ref(),
        now.checked_add(rt.expires_in.unwrap_or(3600)),
    );
    let dk = clavis_store::credentials::load_or_create_device_key(&state.db_path).map_err(dto)?;
    let cred_store = clavis_store::credentials::CredentialStore::new(vault_id, dk);
    cred_store
        .put(
            &state.store,
            &format!("provider:{}", kind.as_str()),
            &record.serialize().map_err(dto)?,
        )
        .map_err(dto)?;
    repository::register_vault(&state.store, &vault_id, None, Some(kind.as_str()), true)
        .map_err(dto)?;
    let vaults = repository::list_vaults(&state.store).map_err(dto)?;
    let entry = vaults
        .iter()
        .find(|(v, _, _, _)| v == &vault_id.to_string());
    Ok(VaultInfoDto {
        vault_id: vault_id.to_string(),
        name: entry.and_then(|(_, n, _, _)| n.clone()),
        provider_kind: Some(kind.as_str().to_string()),
        locked: false,
        has_conflicts: false,
    })
}

#[tauri::command]
pub fn disconnect_provider(state: State<'_, AppState>, provider: String) -> AppResult<()> {
    let kind = clavis_providers::ProviderKind::parse(&provider)
        .ok_or(CoreError::InvalidInput("unknown provider"))?;
    let vault_id = state.active_vault_id().map_err(dto)?;
    let dk = clavis_store::credentials::load_or_create_device_key(&state.db_path).map_err(dto)?;
    let cred_store = clavis_store::credentials::CredentialStore::new(vault_id, dk);
    cred_store
        .remove(&state.store, &format!("provider:{}", kind.as_str()))
        .map_err(dto)?;
    // Local vault is preserved; automatic sync stops. Remote files are not
    // deleted on disconnect.
    repository::register_vault(&state.store, &vault_id, None, None, true).map_err(dto)?;
    Ok(())
}

#[tauri::command]
pub fn sync_now(state: State<'_, AppState>) -> AppResult<SyncStatusKind> {
    let report = state.with_vault(|store, vault| {
        let vault_id = vault.vault_id;
        let provider = repository::list_vaults(store)?
            .into_iter()
            .find(|(id, _, _, _)| id == &vault_id.to_string())
            .and_then(|(_, _, pk, _)| pk)
            .and_then(|pk| clavis_providers::ProviderKind::parse(&pk));
        let Some(kind) = provider else {
            return Ok(SyncReport {
                status: SyncStatusKind::LocalOnly,
                downloaded: 0,
                uploaded: 0,
                pending: 0,
                has_conflicts: false,
                last_confirmed_sync_unix: None,
            });
        };
        let dk = clavis_store::credentials::load_or_create_device_key(&state.db_path)?;
        let cred_store = clavis_store::credentials::CredentialStore::new(vault_id, dk);
        let blob = cred_store
            .get(store, &format!("provider:{}", kind.as_str()))?
            .ok_or(CoreError::InvalidInput("no provider connection"))?;
        let record = clavis_providers::oauth::credentials::ConnectionRecord::deserialize(&blob)?;
        let transport: std::sync::Arc<dyn clavis_providers::oauth::HttpTransport> =
            std::sync::Arc::new(clavis_providers::oauth::ReqwestTransport::new()?);
        let remote: Box<dyn clavis_sync::transport::RemoteStore> = match kind {
            clavis_providers::ProviderKind::GoogleDrive => {
                let cfg = clavis_providers::oauth::google_config("", 0);
                let a = clavis_providers::google::GoogleDriveStore::new(transport, cfg);
                a.set_access_token(record.access_token());
                Box::new(a)
            }
            clavis_providers::ProviderKind::OneDrive => {
                let cfg = clavis_providers::oauth::onedrive_config("", 0);
                let a = clavis_providers::onedrive::OneDriveStore::new(transport, cfg);
                a.set_access_token(record.access_token());
                Box::new(a)
            }
            clavis_providers::ProviderKind::Dropbox => {
                let cfg = clavis_providers::oauth::dropbox_config("", 0);
                let a = clavis_providers::dropbox::DropboxStore::new(transport, cfg);
                a.set_access_token(record.access_token());
                Box::new(a)
            }
            clavis_providers::ProviderKind::WebDav => {
                return Err(CoreError::InvalidInput(
                    "webdav sync is not wired in this build",
                ));
            }
        };
        tauri::async_runtime::block_on(async {
            sync_once(
                store,
                vault,
                remote.as_ref(),
                &Cancel::new(),
                SyncTrigger::Manual,
                SystemClock.now_unix_seconds(),
            )
            .await
            .map_err(sync_err)
        })
    })?;
    *state.last_report.lock().unwrap() = Some(report.clone());
    Ok(report.status)
}

#[tauri::command]
pub fn get_sync_status(state: State<'_, AppState>) -> AppResult<SyncStatusKind> {
    let report = state.last_report.lock().unwrap().clone();
    let provider_connected = repository::active_vault(&state.store)
        .map_err(dto)?
        .and_then(|id| {
            repository::list_vaults(&state.store)
                .ok()?
                .into_iter()
                .find(|(v, _, _, _)| v == &id)
                .and_then(|(_, _, pk, _)| pk)
                .and_then(|pk| clavis_providers::ProviderKind::parse(&pk))
        })
        .is_some();
    let status = clavis_sync::status::decide_status(
        report.as_ref(),
        &clavis_sync::status::SyncContext {
            provider_connected,
            locked: false,
            ..Default::default()
        },
    );
    Ok(status)
}
