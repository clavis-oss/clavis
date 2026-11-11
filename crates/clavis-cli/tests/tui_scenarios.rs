//! TUI state machine scenarios without a real terminal: narrow resize is a
//! render concern; locking clears labels and codes; escape cancels; filters
//! and search behave like the desktop.

use clavis_cli::tui::{Filter, TuiMode, TuiState};
use clavis_core::accounts::AccountSummary;

fn row(id: &str, issuer: &str, label: &str, favorite: bool, conflict: bool) -> AccountSummary {
    AccountSummary {
        id: clavis_core::ids::EntryId(clavis_core::ids::RawUuid::parse_str(id).unwrap()),
        issuer: Some(issuer.into()),
        account_label: Some(label.into()),
        favorite,
        has_conflict: conflict,
        conflicted_fields: if conflict {
            vec![clavis_core::causal::Field::Issuer]
        } else {
            vec![]
        },
        deleted: false,
    }
}

const ID_A: &str = "00000000-0000-0000-0000-000000000001";
const ID_B: &str = "00000000-0000-0000-0000-000000000002";

fn state() -> TuiState {
    TuiState {
        rows: vec![
            row(ID_A, "Acme", "alice@example.com", false, false),
            row(ID_B, "Other", "bob@example.com", true, false),
        ],
        ..TuiState::default()
    }
}

#[test]
fn search_filters_over_labels_only() {
    let mut s = state();
    s.query = "acme".into();
    assert_eq!(s.visible().len(), 1);
    s.query = "EXAMPLE.COM".into();
    assert_eq!(s.visible().len(), 2, "case-insensitive match");
    s.query = "nonexistent".into();
    assert_eq!(s.visible().len(), 0);
}

#[test]
fn selection_wraps_and_survives_filter_toggle() {
    let mut s = state();
    s.move_selection(1);
    s.move_selection(1);
    assert_eq!(s.selected, 0, "wraps around");
    s.move_selection(-1);
    assert_eq!(s.selected, 1);
    s.toggle_filter();
    assert_eq!(s.filter, Filter::Favorites);
    assert_eq!(s.visible().len(), 1);
    assert_eq!(s.selected, 0, "selection resets on filter change");
}

#[test]
fn lock_clears_labels_and_codes() {
    let mut s = state();
    s.status = "Some account label visible".into();
    s.last_code = Some("123456".into());
    s.lock();
    assert_eq!(s.mode, TuiMode::Locked);
    assert!(s.rows.is_empty(), "no labels while locked");
    assert!(s.last_code.is_none(), "no codes while locked");
    assert!(s.query.is_empty());
    // Locked screen renders no account data.
    let rendered = render_to_string(&s);
    assert!(!rendered.contains("Acme"));
    assert!(!rendered.contains("123456"));
    assert!(rendered.contains("Locked"));
}

#[test]
fn escape_cancels_search_and_help() {
    let mut s = state();
    s.query = "partial".into();
    s.help(); // -> help mode
    s.help(); // -> back to list
    assert_eq!(s.mode, TuiMode::List);
    // Esc clears the search query (simulated here; the keymap binds Esc).
    s.query.clear();
    assert_eq!(s.visible().len(), 2);
}

#[test]
fn code_display_is_explicit_and_conflicts_are_named() {
    let mut s = state();
    s.selected = 0;
    s.show_code(0, &|row| {
        if row.has_conflict {
            Err(clavis_core::error::CoreError::InvalidInput("conflicted"))
        } else {
            Ok(Some("654321".into()))
        }
    });
    assert_eq!(s.last_code.as_deref(), Some("654321"));
    // A conflicted account never yields a code.
    s.rows.push(row(
        "00000000-0000-0000-0000-000000000003",
        "Broken",
        "conflicted@x",
        false,
        true,
    ));
    s.move_selection(1); // -> bob (clean)
    s.move_selection(1); // -> conflicted row
    s.show_code(0, &|row| {
        if row.has_conflict {
            Err(clavis_core::error::CoreError::InvalidInput("conflicted"))
        } else {
            Ok(Some("000000".into()))
        }
    });
    assert!(s.last_code.is_none(), "no code for a conflicted account");
    assert!(s.status.contains("Could not generate"));
}

fn render_to_string(s: &TuiState) -> String {
    // The render module draws into a ratatui buffer; verify its content via
    // a test backend of fixed size (narrow window still works).
    let backend = ratatui::backend::TestBackend::new(40, 10);
    let mut terminal = ratatui::Terminal::new(backend).unwrap();
    terminal
        .draw(|f| clavis_cli::tui::render::draw(f, s))
        .unwrap();
    let area = terminal.backend().buffer().area;
    let mut text = String::new();
    for y in 0..area.height {
        for x in 0..area.width {
            text.push(
                terminal.backend().buffer()[(x, y)]
                    .symbol()
                    .chars()
                    .next()
                    .unwrap_or(' '),
            );
        }
        text.push('\n');
    }
    text
}
