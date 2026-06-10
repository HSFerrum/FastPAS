# Architecture

## Overview

FastPAS is a Tauri 2 desktop application with a plain JavaScript frontend and a
Rust backend.

```text
Vite UI
  |
  | Tauri invoke commands
  v
Rust application service
  |
  +-- CyberArk Identity APIs
  +-- Privilege Cloud Vault APIs
  +-- OS credential store
  +-- Local configuration file
```

## Frontend

The frontend is implemented in `src/main.js` and `src/styles.css`.

Responsibilities include:

- Page rendering and form state
- Guided request builders
- Telemetry visualization
- CSV generation and save dialogs
- Confirmation prompts
- Interactive authentication challenge handling

The production frontend is built into `web-dist` and embedded in the Tauri
binary. `devUrl` is used only by `tauri dev`.

## Rust Backend

The backend is implemented in `src-tauri/src/lib.rs`.

Responsibilities include:

- Configuration persistence
- Keychain access
- Session lock and token lifecycle
- Identity authentication
- Platform token acquisition
- Vault API execution
- Telemetry collection
- Account remediation and CPM completion polling

Tauri commands form the boundary between the frontend and backend.

## Data Storage

Non-secret profile and tenant configuration is written under the Tauri
application configuration directory for `com.fastpas.client`.

The Windows portable package instead writes configuration to `FastPASData`
beside `FastPAS.exe` and uses separate OS credential-manager service names.
This prevents a newly extracted portable copy from loading profiles, tenants,
or passcodes created by another FastPAS installation.

Secrets are stored with the platform credential manager:

- Windows Credential Manager
- macOS Keychain
- Linux Secret Service-compatible keychain

Runtime tokens are not written to the configuration file.

## Network Model

FastPAS communicates directly with the configured CyberArk tenant over HTTPS.
There is no FastPAS cloud service or local API server in production builds.

The Vite server at `127.0.0.1:5173` is a development-only dependency.
