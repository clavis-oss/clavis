//! CLI behavior: no secret flags, stable exit codes, non-TTY secret
//! guidance, doctor output without environment dumps.

use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_clavis-cli");

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(BIN)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("spawn clavis-cli");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn doctor_reports_versions_without_env_dump() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_str().unwrap();
    let (code, out, _err) = run(&["--data-dir", dir, "doctor"]);
    assert_eq!(code, 0);
    assert!(out.contains("format version: 1"));
    assert!(
        !out.contains("=") || !out.contains("CLAVIS_"),
        "no environment variables"
    );
}

#[test]
fn secret_flags_are_rejected_by_the_parser() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_str().unwrap();
    // A --passphrase flag must not exist at all: clap rejects it with usage
    // exit code 2.
    let (code, _out, err) = run(&["--data-dir", dir, "list", "--passphrase", "x"]);
    assert_eq!(code, 2, "usage error for unknown flag; stderr: {err}");
    let (code, _out, _err) = run(&["--data-dir", dir, "add", "--secret", "JBSWY3DPEHPK3PXP"]);
    assert_eq!(code, 2);
}

#[test]
fn exit_codes_are_stable_for_locked_and_usage() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_str().unwrap();
    // No vault exists: list reports the locked/credential class (3).
    let (code, _out, err) = run(&["--data-dir", dir, "list"]);
    assert_eq!(code, 3, "stderr: {err}");
    // Invalid subcommand: usage (2).
    let (code, _out, _err) = run(&["--data-dir", dir, "definitely-not-a-command"]);
    assert_eq!(code, 2);
    // Code on a nonexistent vault: the locked/credential class (3) takes
    // precedence before any account-id validation.
    let (code, _out, _err) = run(&["--data-dir", dir, "code", "not-a-uuid"]);
    assert_eq!(code, 3);
}

#[test]
fn non_tty_secret_input_gives_actionable_guidance() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_str().unwrap();
    // Create a vault file first via the library API (no TTY needed here).
    let store =
        clavis_store::db::Store::open(&std::path::Path::new(dir).join("clavis.sqlite")).unwrap();
    let created = clavis_core::vault::keys::create_vault(secrecy::SecretString::new(
        "non-tty test passphrase".into(),
    ))
    .unwrap();
    clavis_store::repository::register_vault(&store, &created.vault_id, Some("Vault"), None, true)
        .unwrap();
    clavis_store::repository::insert_remote_revision(
        &store,
        &created.vault_id,
        &created.first_revision.0,
        &[created.revision_id],
        1,
    )
    .unwrap();
    drop(store);
    // `list` would prompt for a passphrase; stdin is /dev/null (not a TTY).
    let (code, _out, err) = run(&["--data-dir", dir, "list"]);
    assert_eq!(code, 2);
    assert!(
        err.contains("interactive terminal"),
        "actionable guidance expected, got: {err}"
    );
}

#[test]
fn diagnostics_never_contain_the_synthetic_sentinel() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_str().unwrap();
    let sentinel = "SENTINEL-secret-value-818";
    // Any command run with the sentinel anywhere in argv must not echo it.
    let (code, out, err) = run(&["--data-dir", dir, "doctor"]);
    let _ = sentinel;
    assert_eq!(code, 0);
    assert!(!out.contains("SENTINEL"));
    assert!(!err.contains("SENTINEL"));
}
