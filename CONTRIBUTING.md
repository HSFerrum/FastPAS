# Contributing

## Workflow

1. Create a branch from `main`.
2. Keep changes scoped to one behavior.
3. Do not commit credentials, configuration exports, build output, or customer data.
4. Run the frontend and Rust verification commands.
5. Open a pull request describing behavior changes and test coverage.

## Verification

```bash
npm install
npm run build
cd src-tauri
cargo fmt --check
cargo check --lib
cargo test --lib
```

Changes to privileged operations should include:

- Explicit confirmation behavior
- Per-item error reporting
- A non-destructive failure path
- Exportable results where appropriate
- Documentation updates
