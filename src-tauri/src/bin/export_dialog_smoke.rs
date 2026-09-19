//! Native regression check: exercises the JavaScript dialog command and its ACL.
//! Uses the main window capability, without loading credentials or tenant data.
use tauri::webview::PageLoadEvent;

#[tauri::command]
fn finish_export_smoke(app: tauri::AppHandle, error: Option<String>) {
    if let Some(error) = error {
        eprintln!("Export dialog failed: {error}");
        app.exit(1);
    } else {
        println!("Export dialog invocation succeeded.");
        app.exit(0);
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![finish_export_smoke])
        .on_page_load(|window, payload| {
            if matches!(payload.event(), PageLoadEvent::Finished) {
                let script = r#"
                    window.__TAURI_INTERNALS__.invoke('plugin:dialog|save', {
                        options: {
                            title: 'FastPAS HTML export test',
                            defaultPath: 'fastpas-export-test.html',
                            filters: [{ name: 'HTML dashboard', extensions: ['html'] }]
                        }
                    }).then(() => window.__TAURI_INTERNALS__.invoke('finish_export_smoke', {error: null}))
                      .catch(error => window.__TAURI_INTERNALS__.invoke('finish_export_smoke', {error: String(error)}));
                "#;
                if let Err(error) = window.eval(script) {
                    eprintln!("Could not start export dialog check: {error}");
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("Could not start export dialog check");
}
