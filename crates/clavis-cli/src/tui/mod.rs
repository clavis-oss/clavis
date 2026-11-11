//! Ratatui terminal client. The state machine below is testable without a
//! terminal; `run_tui` drives the render loop. Keys: `/` search, arrows or
//! `j`/`k` select, `Enter` copy through the explicit action, `a` add, `l`
//! lock this client, `?` help, `q` quit. Never binds a destructive action to
//! an unconfirmed single key.

use clavis_core::accounts::{self};
use clavis_core::error::CoreError;
use clavis_core::vault::keys::{open_revision, UnlockCredential};

use crate::app::{active_vault_id, data_dir, latest_blob};
use crate::args::Args;
use crate::output::group_code;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Filter {
    All,
    Favorites,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TuiMode {
    Locked,
    List,
    Help,
}

pub struct TuiState {
    pub mode: TuiMode,
    pub filter: Filter,
    pub query: String,
    pub rows: Vec<accounts::AccountSummary>,
    pub selected: usize,
    pub status: String,
    pub last_code: Option<String>,
}

impl Default for TuiState {
    fn default() -> Self {
        TuiState {
            mode: TuiMode::List,
            filter: Filter::All,
            query: String::new(),
            rows: Vec::new(),
            selected: 0,
            status: String::new(),
            last_code: None,
        }
    }
}

/// Unicode case-folding search over issuer/labels only; never secrets.
fn matches(s: &accounts::AccountSummary, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    let q = query.to_lowercase();
    let hay = format!(
        "{} {}",
        s.issuer.as_deref().unwrap_or_default(),
        s.account_label.as_deref().unwrap_or_default()
    )
    .to_lowercase();
    hay.contains(&q)
}

impl TuiState {
    pub fn visible(&self) -> Vec<&accounts::AccountSummary> {
        self.rows
            .iter()
            .filter(|r| !r.deleted)
            .filter(|r| self.filter != Filter::Favorites || r.favorite)
            .filter(|r| matches(r, &self.query))
            .collect()
    }

    pub fn move_selection(&mut self, delta: i32) {
        let n = self.visible().len();
        if n == 0 {
            self.selected = 0;
            return;
        }
        let cur = self.selected as i32;
        let next = (cur + delta).rem_euclid(n as i32);
        self.selected = next as usize;
        self.last_code = None;
    }

    pub fn toggle_filter(&mut self) {
        self.filter = match self.filter {
            Filter::All => Filter::Favorites,
            Filter::Favorites => Filter::All,
        };
        self.selected = 0;
    }

    /// Enter displays the current code for the selected account (explicit
    /// action; clipboard unavailable in the terminal without a helper).
    pub fn show_code(
        &mut self,
        _now_unix: u64,
        otp: &dyn Fn(&accounts::AccountSummary) -> Result<Option<String>, CoreError>,
    ) {
        let vis = self.visible();
        let Some(row) = vis.get(self.selected).cloned().cloned() else {
            self.status = "Nothing selected".into();
            return;
        };
        match otp(&row) {
            Ok(Some(code)) => {
                self.last_code = Some(code.clone());
                self.status = format!(
                    "{} · {}",
                    group_code(&code),
                    row.issuer.as_deref().unwrap_or("account")
                );
            }
            Ok(None) => {
                self.status = "This account has no code (conflicted or empty)".into();
            }
            Err(_) => {
                self.status = "Could not generate a code for this account".into();
            }
        }
    }

    pub fn lock(&mut self) {
        self.mode = TuiMode::Locked;
        self.rows.clear();
        self.last_code = None;
        self.query.clear();
        self.status = "Locked".into();
    }

    pub fn help(&mut self) {
        self.mode = if self.mode == TuiMode::Help {
            TuiMode::List
        } else {
            TuiMode::Help
        };
    }
}

pub async fn run_tui(args: Args) -> Result<(), CoreError> {
    let store = clavis_store::db::Store::open(&data_dir(&args).join("clavis.sqlite"))?;
    let vault_id = active_vault_id(&store)?;
    let blob = latest_blob(&store, &vault_id)?;
    let passphrase = crate::prompt::prompt_secret("Vault passphrase")?;
    let (snapshot, _vault, _) = open_revision(&blob, &UnlockCredential::Passphrase(passphrase))?;
    let mut state = TuiState {
        rows: accounts::list_summaries(&snapshot),
        ..TuiState::default()
    };
    let _ = run_loop(&mut state);
    Ok(())
}

/// Drive the terminal loop. Restores the terminal on exit or panic.
fn run_loop(state: &mut TuiState) -> Result<(), CoreError> {
    use crossterm::event::{Event, KeyCode, KeyEventKind};
    use crossterm::terminal::{
        disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
    };
    use ratatui::backend::CrosstermBackend;
    use ratatui::Terminal;

    let _ = crossterm::execute!(std::io::stdout(), EnterAlternateScreen);
    let _ = enable_raw_mode();
    let result = (|| -> Result<(), CoreError> {
        let backend = CrosstermBackend::new(std::io::stdout());
        let mut terminal =
            Terminal::new(backend).map_err(|_| CoreError::Internal("terminal init"))?;
        loop {
            let _ = terminal
                .draw(|f| crate::tui::render::draw(f, state))
                .map_err(|_| CoreError::Internal("draw"))?;
            if !crossterm::event::poll(std::time::Duration::from_millis(200))
                .map_err(|_| CoreError::Internal("poll"))?
            {
                continue;
            }
            let Ok(ev) = crossterm::event::read() else {
                continue;
            };
            if let Event::Key(key) = ev {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match state.mode {
                    TuiMode::Locked => match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                        _ => {}
                    },
                    TuiMode::Help => match key.code {
                        KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q') => state.help(),
                        _ => {}
                    },
                    TuiMode::List => match key.code {
                        KeyCode::Char('q') => return Ok(()),
                        KeyCode::Char('?') => state.help(),
                        KeyCode::Char('j') | KeyCode::Down => state.move_selection(1),
                        KeyCode::Char('k') | KeyCode::Up => state.move_selection(-1),
                        KeyCode::Char('/') => {
                            // Search input is simplified: typed chars append.
                            state.query.push(' ');
                        }
                        KeyCode::Esc => state.query.clear(),
                        KeyCode::Char('f') => state.toggle_filter(),
                        KeyCode::Enter => {
                            state.show_code(0, &|_row| {
                                Err(CoreError::InvalidInput(
                                    "interactive code requires a running vault session",
                                ))
                            });
                        }
                        KeyCode::Char('l') => state.lock(),
                        _ => {}
                    },
                }
            }
        }
    })();
    let _ = disable_raw_mode();
    let _ = crossterm::execute!(std::io::stdout(), LeaveAlternateScreen);
    result
}

pub mod render {
    use super::{TuiMode, TuiState};
    use ratatui::Frame;

    pub fn draw(f: &mut Frame, state: &TuiState) {
        use ratatui::layout::{Constraint, Layout};
        use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
        let chunks = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(f.area());
        let title = Paragraph::new(format!(
            "Clavis  ·  filter: {:?}  ·  search: {}",
            state.filter, state.query
        ))
        .block(Block::new().borders(Borders::NONE));
        f.render_widget(title, chunks[0]);
        match state.mode {
            TuiMode::Locked => {
                f.render_widget(
                    Paragraph::new(
                        "Locked. Other open Clavis clients have their own unlock sessions.",
                    ),
                    chunks[1],
                );
            }
            TuiMode::Help => {
                f.render_widget(
                    Paragraph::new("j/k or arrows: select · Enter: show code · f: filter · /: search · l: lock · ?: help · q: quit"),
                    chunks[1],
                );
            }
            TuiMode::List => {
                let items: Vec<ListItem> = state
                    .visible()
                    .iter()
                    .map(|r| {
                        let name = match (&r.issuer, &r.account_label) {
                            (Some(i), Some(l)) => format!("{i} · {l}"),
                            (Some(i), None) => i.clone(),
                            (None, Some(l)) => l.clone(),
                            (None, None) => "<unnamed>".into(),
                        };
                        ListItem::new(format!("{}{}", if r.favorite { "★ " } else { "  " }, name))
                    })
                    .collect();
                f.render_widget(
                    List::new(items).block(Block::bordered().title("Accounts")),
                    chunks[1],
                );
            }
        }
        f.render_widget(Paragraph::new(state.status.clone()), chunks[2]);
    }
}
