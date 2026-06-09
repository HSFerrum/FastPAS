# Using FastPAS

## Initial Setup

1. Open **Profiles** and create either an interactive user profile or an OAuth
   client-credential profile.
2. Open **Tenants** and add the CyberArk customer subdomain and Identity host.
3. Select the active profile and tenant.
4. Configure a FastPAS session passcode when prompted.
5. Request the required Identity or platform token from the **API** page.

Passwords, client secrets, and Audit API keys are stored in the operating
system's credential store. Access tokens remain in application memory and are
removed when the session is locked or the application closes.

## API Workflows

The API page provides guided requests for:

- Vault health
- Account search and account details
- Safes and safe members
- Platforms
- Vault users
- Safe creation and membership changes
- Account inventory reports

FastPAS displays the request URL, HTTP status, response body, and follow-up
actions. Tabular responses can be exported as CSV.

## Telemetry

### Most Used Components

Queries recent PSM recordings, groups sessions by connection component, and
reports usage totals and percentages.

### Active Users

Uses the Identity API to group users into:

- Active this week
- Inactive for one to four weeks
- Inactive for at least one month

### Account Failures

Scans Vault accounts and recent PSM recordings for CPM and PSM failures. Results
are grouped by service and failure type.

Every telemetry dashboard can export its current result as CSV.

## Automatic Account Resolution

The **Account Failures** dashboard offers automatic resolution when accounts
have automatic management disabled.

For each account, FastPAS:

1. Retrieves the current account record.
2. Checks whether the account is locked.
3. Unlocks it only when required.
4. Enables automatic secret management.
5. Starts reconcile.
6. Checks CPM status every ten seconds for up to five minutes.

An account is marked **completed** only when CPM reports a successful
secret-management status. Timeouts and request failures remain unresolved.

The remediation result provides:

- A complete CSV report
- A separate CSV for accounts that were already unlocked but could not be resolved
- Final CPM status and operation details for each account

## Session Security

- FastPAS locks after the configured inactivity interval.
- Repeated incorrect passcodes are rate-limited.
- Changing the active profile or tenant clears runtime tokens.
- Token copying is disabled by default and can be enabled only for a short window.
- Closing FastPAS clears all in-memory tokens.
