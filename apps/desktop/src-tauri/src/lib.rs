pub mod commands;

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            use tauri::Manager;
            // Local store lives in the OS app-data dir; created with
            // user-only permissions by the store itself.
            let dir = app
                .path()
                .app_data_dir()
                .expect("app data directory is available on supported platforms");
            let state = commands::AppState::new(dir.join("clavis.sqlite"))
                .expect("local vault store could not be opened");
            app.manage(state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::vault_info,
            commands::create_vault,
            commands::confirm_recovery,
            commands::unlock,
            commands::lock,
            commands::list_accounts,
            commands::list_codes,
            commands::get_code,
            commands::preview_import_uri,
            commands::preview_import_image,
            commands::preview_import_manual,
            commands::confirm_import,
            commands::update_account,
            commands::delete_account,
            commands::restore_account,
            commands::resolve_conflict,
            commands::keep_both,
            commands::list_conflicts,
            commands::export_vault,
            commands::connect_provider_begin,
            commands::connect_provider_complete,
            commands::disconnect_provider,
            commands::sync_now,
            commands::get_sync_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Clavis desktop");
}
