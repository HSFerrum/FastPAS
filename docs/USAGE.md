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

## Rotation Health

Open **Telemetry → Rotation Health** and choose **Scan active tenant** after
requesting a platform token. The default reported-age threshold is 100 days;
it can be changed from 1 to 3650 days. The scan is read-only and never retrieves
passwords or invokes account remediation.

Platforms expand into configuration findings, then issue categories, then the
affected accounts. Accounts may appear in several categories, but platform and
dashboard account totals count each account once. Failed change, reconcile, and
verification classifications come from CyberArk saved filters. Disabled automatic
management is separate from operation failure; manual disablement notes are not
treated as failure evidence. Explicit error text can add connectivity, permission,
authentication, password-policy, and dependency issue tags.

Age uses the latest valid management modification/reconciliation timestamp;
verification and account-property modification dates do not reset it. These dates
are **reported metadata, not confirmation of successful target rotation**. Missing,
zero, invalid, or future timestamps produce an unknown-history finding. Successful
manual target changes cannot yet be distinguished from Vault-only updates or
unsuccessful attempts using this metadata. This dashboard does not certify rotation
compliance or infer an effective Master Policy interval.

Platform inspection reports explicitly disabled processing settings and inactive
platforms. Schedule and reconciliation-credential settings are review findings,
not established causes. Missing settings, permission failures, effective-policy
overrides, linked credentials, and SRS-specific engine health remain explicit
coverage limitations. The scan includes only accounts visible to the active
identity. Pagination has a 500,000-account safety limit per inventory; repeated
pages or reaching that limit mark the inventory incomplete. Failed classification
queries are reported without discarding the main account inventory.

**Export CSV** includes unique account rows, platform findings, scan context, and
coverage warnings. Switching profile/tenant or locking the session makes the old
report unavailable. Reports are snapshots and are not persisted automatically.

**Export HTML dashboard** saves a self-contained browser report with an overview,
platform tabs, platform summaries, plain-language recommendations, searchable
account groups, and print/PDF support. Open the saved `.html` file in a browser;
Excel, FastPAS, and an internet connection are not required. It includes the same
coverage limitations as the source scan. Recommendations appear separately from
expandable technical evidence. No external scripts, styles, fonts, or services are
loaded. The HTML snapshot contains the account inventory included in the report.

## Outbound Firewall Diagnostic

Open **Tools**, then **Outbound Firewall Diagnostic**. The diagnostic always
uses the active tenant and shows explicit rules for CyberArk Identity, Secure
Infrastructure Access, Privileged Session Manager, Central Policy Manager,
Secrets Rotation Service, and Central Credential Provider.

FastPAS derives only endpoints already present in the tenant configuration.
Where a product, region, or version-specific endpoint cannot be derived safely,
the rule is shown as **Unknown / untestable**. You can add an exact HTTPS/443
endpoint with its CyberArk documentation reference to the active tenant.

For each enabled endpoint FastPAS reports the first observable outcome:

- DNS failure
- TCP/443 timeout, refusal, reset, or other connection failure
- TLS handshake or certificate validation failure
- HTTP success or failure
- Unknown or untestable requirement

The request is unauthenticated and does not include tokens, passwords, client
secrets, cookies, or request bodies. FastPAS does not expand host ranges or scan
ports. A pass records client-side behavior only; it cannot prove that an
application-layer firewall, proxy, or bypass policy is correctly scoped.

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

## Rotation Health administrative actions

Rotation Health separates **Core issues** (observed account management blockers,
failed operations, and relevant disabled platform processing), **Additional
recommendations** (security and configuration improvements), and **Further
investigation** (unavailable evidence). A failure does not automatically establish
its root cause. The standalone HTML dashboard includes the same sections and
remains an offline snapshot.

Expand a platform's **Administrative actions** to select visible accounts and:

- Enable automatic management for explicitly disabled accounts, without unlocking
  accounts or starting a password reset.
- Request reconciliation for automatically managed accounts.
- Replace account-level reconciliation associations using linked-account index 3,
  where the platform supports the standard reconciliation association.

Actions require an explicit review and acknowledgment. The backend rechecks
platform assignment and account configuration before each update. Reviews expire
after five minutes, are single-use, and are bound to the active tenant, profile,
token and Vault URL. Up to 500 accounts can be reviewed at a time. Results show
accepted requests and individual failures; acceptance does not establish a
completed target rotation. Export the results and rescan afterward.

Recovery lookup requires an exact Vault object name. Select the correct safe and
account when duplicate names exist. Enter the actual Vault folder if the API
does not expose it; FastPAS never guesses it or retrieves the password.

The **platform settings guide** prepares the password-change and automatic
reconciliation settings, plus the selected recovery object's safe/name/folder.
Apply them in CyberArk's platform management interface: the supported platform
REST surface does not provide an editor for these existing INI settings. The
guide does not modify platform defaults. Bulk account linking is an explicit
account-level override and does not enable platform reconciliation policies.

Missing platform IDs are retried through individual account-detail lookup.
Unresolved assignments are labeled unavailable, rather than treated as proof
that an account has no platform. Administrative actions require a readable
platform assignment.

## Session Security

- FastPAS locks after the configured inactivity interval.
- Repeated incorrect passcodes are rate-limited.
- Changing the active profile or tenant clears runtime tokens.
- Token copying is disabled by default and can be enabled only for a short window.
- Closing FastPAS clears all in-memory tokens.
