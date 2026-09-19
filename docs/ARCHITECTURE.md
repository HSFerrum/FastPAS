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
- Tenant-aware outbound HTTPS connectivity diagnostics
- Account remediation and CPM completion polling

Tauri commands form the boundary between the frontend and backend.

## Rotation Health Reporting

`src-tauri/src/rotation_health.rs` collects GET-only account inventories, failed
operation saved filters, and platform details. `rotation_analysis.rs` contains
the account classification and platform finding rules. Returned account records
are allowlisted and never include the secret field. Requests have timeouts and
do not follow redirects; inventory pagination never follows a server-provided
URL with an authentication token. Session context is checked between requests.

The report distinguishes observed configuration, review suggestions, and unknown
coverage. Management modification dates are explicitly not successful-rotation
evidence. Effective policy and SRS-specific health require additional data sources.
The frontend hides and discards reports when session context changes and exports
unique account rows alongside platform findings and coverage warnings.

The shared analysis rules can be tested without native WebView dependencies:

```bash
cargo test --manifest-path src-tauri/rotation-tests/Cargo.toml
```

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

The outbound firewall diagnostic uses the active tenant, validates an explicit
HTTPS URL, resolves DNS, connects only to TCP/443, performs normal TLS
certificate validation, and sends a bounded unauthenticated HTTP request. It
does not scan address or port ranges. Tenant-specific rules are stored as
non-secret tenant configuration with a documentation reference; tokens and
credentials are never attached to diagnostic requests.

The Vite server at `127.0.0.1:5173` is a development-only dependency.
