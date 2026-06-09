# Security

## Sensitive Data

FastPAS stores credentials in the operating system credential manager. Runtime
access tokens remain in memory and are cleared when the application is locked
or closed.

Repository commits must never include:

- FastPAS configuration files
- CyberArk tenant exports containing organization details
- Passwords, client secrets, or Audit API keys
- Access or refresh tokens
- Diagnostic output containing customer identifiers

## Operational Permissions

Use a least-privilege CyberArk identity. The active identity determines which
Vault and Identity operations FastPAS can perform.

Bulk remediation can unlock accounts, enable automatic management, and start
reconcile. Operators must review the account count and confirmation prompt
before continuing.

## Reporting a Vulnerability

Do not open a public issue containing vulnerability details or credentials.
Report security concerns privately to the repository owner through GitHub.

Include:

- A concise description
- Affected version or commit
- Reproduction steps
- Expected impact
- Suggested mitigation, if known
