# FastPAS

[![Download FastPAS Portable for Windows x64](https://img.shields.io/badge/Download-FastPAS%20Portable%20for%20Windows%20x64-0078D4?style=for-the-badge&logo=windows)](https://github.com/HSFerrum/FastPAS/releases/download/v0.1.1/FastPAS-portable-windows-x64.zip)

> **Windows users:** Use the download button above. Do not use GitHub's
> **Code → Download ZIP** option; that downloads the source code and does not
> include `FastPAS.exe`.

FastPAS is a desktop administration client for CyberArk Identity and Privilege
Cloud. It combines authentication, common Vault API workflows, operational
telemetry, CSV reporting, and guarded account remediation in one Tauri
application.

## Features

- Interactive and OAuth client-credential authentication profiles
- CyberArk Identity and Privilege Cloud platform token workflows
- Local profile and tenant management
- OS keychain storage for passwords, client secrets, and Audit API keys
- Guided Vault API requests for accounts, safes, platforms, users, and members
- CSV exports for API responses and telemetry dashboards
- Telemetry for PSM component usage, Identity user activity, and account failures
- Bulk remediation for accounts with automatic management disabled
- Lock detection, account unlock, management re-enable, reconcile, and CPM status polling
- Session passcode, inactivity lock, token expiration, and guarded token copying
- Portable Windows distribution with a bundled WebView2 fixed runtime

## Technology

- Tauri 2 and Rust
- Vite and plain JavaScript
- `reqwest` for CyberArk API communication
- Native OS keychain integration through `keyring`

## Quick Start

### Windows portable release

**[Download the complete FastPAS Portable Windows package (277 MB)](https://github.com/HSFerrum/FastPAS/releases/download/v0.1.1/FastPAS-portable-windows-x64.zip)**

1. Download `FastPAS-portable-windows-x64.zip` using the link above.
2. Extract the complete ZIP.
3. Run `Run-FastPAS.bat`.

The portable release includes WebView2 and does not require Node.js, Rust, Vite,
or an installer. See [all releases](https://github.com/HSFerrum/FastPAS/releases)
for newer versions.

### Development

Prerequisites:

- Node.js 20 or newer
- Rust stable
- Tauri 2 system dependencies for your platform

```bash
npm install
npm run tauri:dev
```

Production build:

```bash
npm run tauri:build
```

## Documentation

- [Using FastPAS](docs/USAGE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Building and packaging](docs/BUILDING.md)
- [Security model](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

## Important Safety Notes

FastPAS can perform privileged CyberArk operations. Review the active profile,
tenant, account set, and confirmation prompt before running a change.

Account remediation reports an account as resolved only after CyberArk returns
a successful CPM secret-management status. Requests that fail or remain
incomplete after five minutes are reported as unresolved.

## Project Status

FastPAS is under active development. Some tasks shown in the UI are intentionally
marked as requiring additional workflow support and cannot be executed.

## License

No open-source license has been granted. All rights are reserved unless a
separate license is added to this repository.
