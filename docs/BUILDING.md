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
cd src-tauri
cargo xwin build --release --target x86_64-pc-windows-msvc --bin fastpas
```

Native dependencies such as `ring` require `clang-cl` and `lld-link` on the
Linux host.

## Release Packaging

Do not commit generated installers, portable runtimes, `target`, `web-dist`, or
`node_modules`. Upload release binaries as GitHub Release assets.
