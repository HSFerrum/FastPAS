# Building and Packaging

## Development Build

```bash
npm install
npm run tauri:dev
```

## Production Build

```bash
npm run tauri:build
```

The Tauri production build runs `npm run build` and embeds `web-dist` in the
application. A production executable does not connect to the Vite development
server.

## Frontend Verification

```bash
npm run build
```

## Rust Verification

```bash
cd src-tauri
cargo fmt --check
cargo check --lib
cargo test --lib
```

## Rotation Health Verification

The shared classification rules and frontend report behavior can be tested
without native WebView dependencies:

```bash
cargo test --manifest-path src-tauri/rotation-tests/Cargo.toml
node scripts/tests/rotation-ui.cjs
```

These checks cover reported-age boundaries, missing dates, classification,
platform settings, HTML escaping, CSV deduplication and formula protection,
and session-context isolation. They do not replace a full Tauri build or testing
against a tenant with representative CPM/SRS data and permissions.

The local main-window capability must include `dialog:allow-save` for browser
code to open native export dialogs. The native dialog/permission smoke check is:

```bash
cargo run --manifest-path src-tauri/Cargo.toml --bin export_dialog_smoke --features tauri/custom-protocol
```

This check opens an HTML Save dialog using the JavaScript plugin command and
the same window capability. Cancel the dialog to finish the check; it does not
load tenant configuration or credentials or write an export file.

## Windows Portable Package

On Windows, install the Tauri prerequisites and download a Microsoft WebView2
Fixed Version Runtime. Then run:

```powershell
powershell -ExecutionPolicy Bypass `
  -File .\scripts\windows\build-portable.ps1 `
  -WebView2RuntimePath "C:\path\to\WebView2FixedRuntime"
```

The output folder is `dist\FastPAS-portable`.

The launcher sets `WEBVIEW2_BROWSER_EXECUTABLE_FOLDER` to the bundled runtime,
allowing FastPAS to run without a separately installed WebView2 runtime.

## Linux-to-Windows Cross-Build

A Windows executable can also be produced with `cargo-xwin`:

```bash
rustup target add x86_64-pc-windows-msvc
cargo install cargo-xwin --locked
npm run build
cd src-tauri
cargo xwin build --release --target x86_64-pc-windows-msvc --bin fastpas --features tauri/custom-protocol
```

Native dependencies such as `ring` require `clang-cl` and `lld-link` on the
Linux host. The `tauri/custom-protocol` feature is required for production
builds; without it, Tauri loads the development URL and displays a blank window
when the Vite server is not running.

## Release Packaging

Do not commit generated installers, portable runtimes, `target`, `web-dist`, or
`node_modules`. Upload release binaries as GitHub Release assets.
