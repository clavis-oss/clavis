//! No-echo prompts. Secrets never arrive via arguments or environment
//! variables; non-TTY secret input is rejected with actionable guidance.

use secrecy::{ExposeSecret, SecretString};
use std::io::IsTerminal;

use clavis_core::error::CoreError;

pub fn stdin_is_tty() -> bool {
    std::io::stdin().is_terminal()
}

pub fn prompt_secret(label: &str) -> Result<SecretString, CoreError> {
    if !stdin_is_tty() {
        return Err(CoreError::InvalidInput(
            "secret input requires an interactive terminal; run this command in a terminal",
        ));
    }
    rpassword::prompt_password(format!("{}: ", label))
        .map(|s| SecretString::new(s.into()))
        .map_err(|_| CoreError::Canceled)
}

pub fn prompt_secret_twice(label: &str) -> Result<SecretString, CoreError> {
    let first = prompt_secret(label)?;
    let second = prompt_secret("Confirm passphrase")?;
    if first.expose_secret() != second.expose_secret() {
        return Err(CoreError::InvalidInput("passphrases do not match"));
    }
    Ok(first)
}

pub fn prompt_line(label: &str) -> Result<String, CoreError> {
    if !stdin_is_tty() {
        return Err(CoreError::InvalidInput(
            "interactive input requires a terminal",
        ));
    }
    eprint!("{}: ", label);
    use std::io::Write;
    std::io::stderr()
        .flush()
        .map_err(|_| CoreError::StorageFailure)?;
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|_| CoreError::StorageFailure)?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}
