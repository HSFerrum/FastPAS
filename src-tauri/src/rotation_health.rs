use super::rotation_analysis::{
    classify_account, finding, platform_findings, PlatformFindingContext,
};
use super::*;
use futures_util::stream::{self, StreamExt};
use std::collections::{BTreeMap, HashSet};

// GET-only inventory. No secret retrieval, rotation, or remediation commands.
#[tauri::command]
pub(crate) async fn get_rotation_health(
    app: tauri::AppHandle,
    session: tauri::State<'_, Mutex<SessionState>>,
    threshold_days: u32,
) -> Result<Value, String> {
    if !(1..=3650).contains(&threshold_days) {
        return Err("Age threshold must be between 1 and 3650 days.".into());
    }
    ensure_unlocked(&session)?;
    let config = load_config(&app).map_err(error_to_string)?;
    let (tenant, token, profile_id) = {
        let state = session.lock().map_err(|_| "Session state unavailable")?;
        let tenant = find_active_tenant(&config, state.active_tenant_id.as_deref())?;
        let token = state
            .platform_token
            .clone()
            .ok_or("Request the platform token first.")?;
        if token.invalidated || token.expires_at <= now_millis() {
            return Err("Request a fresh platform token first.".into());
        }
        (tenant, token.access_token, state.active_profile_id.clone())
    };
    let base = tenant.vault_api_base_url.trim().trim_end_matches('/');
    if base.is_empty() {
        return Err("Active tenant is missing a Vault API URL.".into());
    }
    let base_url = reqwest::Url::parse(base).map_err(|_| "Invalid Vault API URL")?;
    if base_url.scheme() != "https"
        || !base_url.username().is_empty()
        || base_url.password().is_some()
        || base_url.query().is_some()
        || base_url.fragment().is_some()
    {
        return Err("Rotation scanning requires an HTTPS Vault API URL without credentials, query, or fragment.".into());
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(error_to_string)?;
    let mut warnings = vec![
        "Inventory covers only accounts visible to the active identity. This is a current snapshot, not historical failure tracking.".to_string(),
        "Reported management modification/reconciliation dates are age indicators, not proof of a successful target rotation. Verification and account-property dates never reset age.".to_string(),
    ];
    let (mut accounts, inventory_complete) = inventory(
        &client,
        base,
        &token,
        None,
        &session,
        &tenant.id,
        &profile_id,
    )
    .await?;
    if !inventory_complete {
        warnings.push("Account scan reached its safety limit or returned repeated accounts; inventory is incomplete.".into());
    }
    let mut failures: HashMap<String, Vec<String>> = HashMap::new();
    for (filter, label) in [
        ("FailedChange", "Change failed"),
        ("FailedReconcile", "Reconcile failed"),
        ("FailedVerify", "Verification failed"),
        ("PolicyFailures", "Platform policy failure"),
        (
            "DisabledPasswordByCPM",
            "Automatic management disabled by CPM",
        ),
        (
            "DisabledPasswordByUser",
            "Automatic management disabled by user",
        ),
    ] {
        match inventory(
            &client,
            base,
            &token,
            Some(filter),
            &session,
            &tenant.id,
            &profile_id,
        )
        .await
        {
            Ok((rows, complete)) => {
                if !complete {
                    warnings.push(format!("{label} classification scan is incomplete."));
                }
                for row in rows {
                    if let Some(id) = audit_string(&row, &["id", "ID"]) {
                        failures.entry(id).or_default().push(label.into());
                    }
                }
            }
            Err(error) => warnings.push(format!("Could not inspect {label}: {error}")),
        }
    }
    let now = Utc::now();
    let mut unresolved = 0;
    for account in &mut accounts {
        if super::rotation_analysis::platform_id(account).is_none() {
            check_context(&session, &tenant.id, &profile_id)?;
            if let Some(id) = audit_string(account, &["id", "ID"]) {
                if let Ok(detail) =
                    get_json(&client, &endpoint(base, "Accounts", &id)?, &token).await
                {
                    if let Some(platform) = super::rotation_analysis::platform_id(&detail) {
                        account["platformId"] = json!(platform);
                    }
                }
            }
            if super::rotation_analysis::platform_id(account).is_none() {
                unresolved += 1;
            }
        }
    }
    if unresolved > 0 {
        warnings.push(format!("{unresolved} accounts still have no readable platform assignment after individual account lookup. This does not establish that they are unassigned."));
    }
    let mut classified = Vec::with_capacity(accounts.len());
    for account in &accounts {
        classified.push(classify_account(
            account,
            failures.get(&audit_string(account, &["id", "ID"]).unwrap_or_default()),
            threshold_days,
            now,
        ));
    }
    enrich_affected_accounts(
        &client,
        base,
        &token,
        &mut classified,
        &mut warnings,
        &session,
        &tenant.id,
        &profile_id,
        now,
        threshold_days,
    )
    .await?;
    let mut platforms: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for row in classified {
        platforms
            .entry(
                row["platform_id"]
                    .as_str()
                    .unwrap_or("Platform assignment unavailable")
                    .into(),
            )
            .or_default()
            .push(row);
    }
    let mut reports = Vec::new();
    for (id, rows) in platforms {
        check_context(&session, &tenant.id, &profile_id)?;
        let disabled = rows
            .iter()
            .filter(|row| row["automatic_management_enabled"] == false)
            .count();
        let affected: Vec<Value> = rows
            .iter()
            .filter(|row| !row["issues"].as_array().unwrap().is_empty())
            .cloned()
            .collect();
        let mut categories: BTreeMap<String, Vec<Value>> = BTreeMap::new();
        for row in &affected {
            for issue in row["issues"].as_array().unwrap() {
                categories
                    .entry(issue.as_str().unwrap().into())
                    .or_default()
                    .push(row.clone());
            }
        }
        let finding_context = PlatformFindingContext {
            change_needed: categories.keys().any(|label| {
                matches!(
                    label.as_str(),
                    "Change failed"
                        | "Reported age exceeds threshold"
                        | "Last successful change exceeds threshold"
                        | "No management activity timestamp above threshold"
                        | "Platform policy failure"
                        | "Password change action disabled"
                        | "Account not managed by CPM"
                )
            }),
            reconcile_needed: categories.contains_key("Reconcile failed")
                || categories.contains_key("Reconciliation action disabled"),
            verification_needed: categories.contains_key("Verification failed")
                || categories.contains_key("Verification action disabled"),
        };
        let details = if id == "Platform assignment unavailable" {
            Err("Platform assignment was unavailable even after account detail lookup; no unassigned-platform conclusion can be drawn.".into())
        } else {
            get_json(&client, &endpoint(base, "Platforms", &id)?, &token).await
        };
        let mut findings = match details {
            Ok(value) => platform_findings(&value, &finding_context),
            Err(error) => vec![finding(
                "Unknown",
                "Platform configuration could not be inspected",
                &error,
            )],
        };
        if disabled == rows.len() {
            findings.push(finding("Confirmed account pattern", "All visible accounts have automatic management disabled", "This is an account-level setting, not evidence that the platform itself is disabled."));
        }
        for accounts in categories.values_mut() {
            accounts.sort_by_key(|row| {
                std::cmp::Reverse(row["reported_age_days"].as_i64().unwrap_or(-1))
            });
        }
        if !affected.is_empty() || findings.iter().any(|f| f["level"] == "Confirmed setting") {
            reports.push(json!({"platform_id": id, "total_accounts": rows.len(), "affected_accounts": affected.len(),
                "disabled_accounts": disabled, "oldest_reported_age_days": rows.iter().filter_map(|r| r["reported_age_days"].as_i64()).max(),
                "actionable": id != "Platform assignment unavailable", "accounts": rows, "findings": findings, "categories": categories.into_iter().map(|(label, accounts)| json!({"label": label, "accounts": accounts})).collect::<Vec<_>>() }));
        }
    }
    reports.sort_by_key(|p| std::cmp::Reverse(p["affected_accounts"].as_u64().unwrap_or(0)));
    check_context(&session, &tenant.id, &profile_id)?;
    Ok(
        json!({"tenant_id": tenant.id, "tenant_name": tenant.name, "profile_id": profile_id,
        "generated_at": now.to_rfc3339(), "threshold_days": threshold_days, "inventory_complete": inventory_complete,
        "total_accounts": accounts.len(), "affected_accounts": reports.iter().filter_map(|p| p["affected_accounts"].as_u64()).sum::<u64>(),
        "warnings": warnings, "platforms": reports}),
    )
}

fn value_at<'a>(value: &'a Value, names: &[&str]) -> Option<&'a Value> {
    names.iter().find_map(|name| value.get(*name))
}

fn bool_at(value: &Value, names: &[&str]) -> Option<bool> {
    value_at(value, names).and_then(Value::as_bool)
}

fn string_at(value: &Value, names: &[&str]) -> Option<String> {
    value_at(value, names)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
}

fn add_issue(row: &mut Value, issue: &str) {
    let Some(issues) = row.get_mut("issues").and_then(Value::as_array_mut) else {
        return;
    };
    if !issues.iter().any(|current| current.as_str() == Some(issue)) {
        issues.push(json!(issue));
    }
}

fn remove_issue(row: &mut Value, issue: &str) {
    if let Some(issues) = row.get_mut("issues").and_then(Value::as_array_mut) {
        issues.retain(|current| current.as_str() != Some(issue));
    }
}

fn has_issue(row: &Value, names: &[&str]) -> bool {
    row["issues"]
        .as_array()
        .map(|issues| {
            issues.iter().any(|issue| {
                issue
                    .as_str()
                    .map(|issue| names.iter().any(|name| issue == *name))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

fn code_text(value: &str) -> String {
    let lowered = value.trim().replace(['_', '-'], " ").to_ascii_lowercase();
    let mut chars = lowered.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().collect::<String>() + chars.as_str())
        .unwrap_or_default()
}

fn operational_disable_reason(value: &str) -> bool {
    !matches!(
        value.trim().to_ascii_uppercase().as_str(),
        "MISSING_PERMISSIONS" | "INSUFFICIENT_PERMISSIONS" | "NOT_AUTHORIZED" | "UNAUTHORIZED"
    )
}

fn add_failure_detail_issues(row: &mut Value, detail: &str) {
    let detail = detail.to_ascii_lowercase();
    for (needles, issue) in [
        (
            &[
                "timeout",
                "timed out",
                "connection refused",
                "unreachable",
                "resolve host",
            ][..],
            "Reported connectivity failure",
        ),
        (
            &[
                "access denied",
                "permission denied",
                "insufficient privilege",
            ][..],
            "Reported permission failure",
        ),
        (
            &[
                "authentication failed",
                "logon failure",
                "invalid credentials",
            ][..],
            "Reported authentication failure",
        ),
        (
            &["password policy", "complexity", "password history"][..],
            "Reported password-policy rejection",
        ),
        (
            &["dependency", "dependent account"][..],
            "Reported dependency failure",
        ),
    ] {
        if needles.iter().any(|needle| detail.contains(needle)) {
            add_issue(row, issue);
        }
    }
}

fn merge_compliance(row: &mut Value, compliance: &Value, now: DateTime<Utc>, threshold_days: u32) {
    if let Some(state) = string_at(compliance, &["accountState", "account_state"]) {
        row["account_state"] = json!(code_text(&state));
        if state.eq_ignore_ascii_case("PLATFORM_DELETED") {
            add_issue(row, "Assigned platform unavailable");
        }
    }
    if let Some(reason) = string_at(compliance, &["disableReason", "disable_reason"]) {
        row["compliance_disable_reason"] = json!(code_text(&reason));
    }
    if let Some(management_type) = string_at(compliance, &["managementType", "management_type"]) {
        row["management_type"] = json!(management_type);
    }
    if row["platform_id"] == "Platform assignment unavailable" {
        if let Some(platform_id) = string_at(compliance, &["platformId", "platform_id"]) {
            row["platform_id"] = json!(platform_id);
        }
    }
    if let Some(change) = value_at(compliance, &["change", "Change"]) {
        if let Some(last_success) = string_at(change, &["lastSuccess", "last_success"]) {
            row["authoritative_change_time"] = json!(last_success.clone());
            if let Ok(time) = DateTime::parse_from_rfc3339(&last_success) {
                let elapsed = now - time.with_timezone(&Utc);
                row["authoritative_age_days"] = json!(elapsed.num_days());
                remove_issue(row, "Reported age exceeds threshold");
                remove_issue(row, "No management activity timestamp above threshold");
                if elapsed.num_seconds() > threshold_days as i64 * 86400 {
                    add_issue(row, "Last successful change exceeds threshold");
                }
            }
        } else if let Some(days) =
            value_at(change, &["daysSinceLastSuccess", "days_since_last_success"])
                .and_then(Value::as_i64)
        {
            if days > 0 {
                row["authoritative_age_days"] = json!(days);
                if days > threshold_days as i64 {
                    remove_issue(row, "Reported age exceeds threshold");
                    remove_issue(row, "No management activity timestamp above threshold");
                    add_issue(row, "Last successful change exceeds threshold");
                }
            }
        }
        if let Some(interval) =
            value_at(change, &["policyInterval", "policy_interval"]).and_then(Value::as_i64)
        {
            row["policy_interval_days"] = json!(interval);
        }
        if let Some(next) = string_at(change, &["nextSchedule", "next_schedule"]) {
            row["next_change_schedule"] = json!(next);
        }
        if let Some(status) = string_at(change, &["compliant", "Compliant"]) {
            row["change_compliance"] = json!(code_text(&status));
        }
        if let Some(reason) = string_at(change, &["actionDisabledReason", "action_disabled_reason"])
        {
            if operational_disable_reason(&reason) {
                row["change_disabled_reason"] = json!(code_text(&reason));
            } else {
                row["caller_permission_limited"] = json!(true);
            }
            if operational_disable_reason(&reason)
                && bool_at(change, &["actionEnabled", "action_enabled"]) == Some(false)
                && has_issue(
                    row,
                    &[
                        "Change failed",
                        "Reported age exceeds threshold",
                        "No management activity timestamp above threshold",
                        "Platform policy failure",
                    ],
                )
            {
                add_issue(row, "Password change action disabled");
            }
        }
    }
    if let Some(verify) = value_at(compliance, &["verify", "Verify"]) {
        if let Some(reason) = string_at(verify, &["actionDisabledReason", "action_disabled_reason"])
        {
            if operational_disable_reason(&reason) {
                row["verify_disabled_reason"] = json!(code_text(&reason));
            } else {
                row["caller_permission_limited"] = json!(true);
            }
            if operational_disable_reason(&reason)
                && bool_at(verify, &["actionEnabled", "action_enabled"]) == Some(false)
                && has_issue(row, &["Verification failed"])
            {
                add_issue(row, "Verification action disabled");
            }
        }
    }
    if let Some(reconcile) = value_at(compliance, &["reconcile", "Reconcile"]) {
        if let Some(reason) = string_at(
            reconcile,
            &["actionDisabledReason", "action_disabled_reason"],
        ) {
            if operational_disable_reason(&reason) {
                row["reconcile_disabled_reason"] = json!(code_text(&reason));
            } else {
                row["caller_permission_limited"] = json!(true);
            }
            if operational_disable_reason(&reason)
                && bool_at(reconcile, &["actionEnabled", "action_enabled"]) == Some(false)
                && has_issue(row, &["Reconcile failed"])
            {
                add_issue(row, "Reconciliation action disabled");
            }
        }
    }
    if let Some(messages) = value_at(compliance, &["lastMessages", "last_messages"]) {
        if let Some(messages) = messages.as_array() {
            row["last_management_message_count"] = json!(messages.len());
        }
    }
    row["compliance_inspected"] = json!(true);
}

fn merge_overview(row: &mut Value, overview: &Value) {
    if let Some(details) = value_at(overview, &["Details", "details"]) {
        let srs_managed = row["management_type"]
            .as_str()
            .map(|value| value.to_ascii_lowercase().contains("srs"))
            .unwrap_or(false);
        if !srs_managed
            && bool_at(details, &["ManagedByCPM", "managedByCPM", "managed_by_cpm"]) == Some(false)
        {
            add_issue(row, "Account not managed by CPM");
        }
        if let Some(disabled) = string_at(details, &["CPMDisabled", "cpmDisabled", "cpm_disabled"])
        {
            row["cpm_disabled_reason"] = json!(disabled);
        }
        if let Some(status) = string_at(details, &["CPMStatus", "cpmStatus", "cpm_status"]) {
            row["cpm_status"] = json!(status);
        }
        if let Some(error) = string_at(
            details,
            &["CPMErrorDetails", "cpmErrorDetails", "cpm_error_details"],
        ) {
            row["cpm_error_detail"] = json!(error.clone());
            row["detail"] = json!(error.clone());
            add_failure_detail_issues(row, &error);
        }
        if let Some(linked) = value_at(
            details,
            &["LinkedAccounts", "linkedAccounts", "linked_accounts"],
        ) {
            row["linked_accounts_visible"] = json!(!linked.is_null());
        }
    }
    if value_at(
        overview,
        &[
            "FailedDependencies",
            "failedDependencies",
            "failed_dependencies",
        ],
    )
    .and_then(Value::as_i64)
    .unwrap_or(0)
        > 0
    {
        add_issue(row, "Reported dependency failure");
    }
    row["overview_inspected"] = json!(true);
}

fn account_inspection_urls(base: &str, id: &str) -> Result<(String, String), String> {
    if id.is_empty() || id == "." || id == ".." {
        return Err("Invalid account identifier.".into());
    }
    let mut root = reqwest::Url::parse(base).map_err(|_| "Invalid Vault API URL")?;
    root.set_query(None);
    root.set_fragment(None);
    root.set_path("/");
    {
        let mut segments = root
            .path_segments_mut()
            .map_err(|_| "Invalid Vault API URL")?;
        segments
            .clear()
            .extend(["api", "rotation", "accounts", id, "compliance-info"]);
    }
    let compliance = root.to_string();
    let mut overview = reqwest::Url::parse(base).map_err(|_| "Invalid Vault API URL")?;
    overview
        .path_segments_mut()
        .map_err(|_| "Invalid Vault API URL")?
        .pop_if_empty()
        .extend(["ExtendedAccounts", id, "overview"]);
    Ok((compliance, overview.to_string()))
}

async fn inspect_account(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    id: &str,
    compliance_supported: bool,
    overview_supported: bool,
) -> (String, Option<Value>, Option<Value>) {
    let Ok((compliance_url, overview_url)) = account_inspection_urls(base, id) else {
        return (id.into(), None, None);
    };
    let compliance = if compliance_supported {
        get_json(client, &compliance_url, token).await.ok()
    } else {
        None
    };
    let overview = if overview_supported {
        get_json(client, &overview_url, token).await.ok()
    } else {
        None
    };
    (id.into(), compliance, overview)
}

#[allow(clippy::too_many_arguments)]
async fn enrich_affected_accounts(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    rows: &mut [Value],
    warnings: &mut Vec<String>,
    session: &tauri::State<'_, Mutex<SessionState>>,
    tenant_id: &str,
    profile_id: &Option<String>,
    now: DateTime<Utc>,
    threshold_days: u32,
) -> Result<(), String> {
    let ids: Vec<String> = rows
        .iter()
        .filter(|row| !row["issues"].as_array().map(Vec::is_empty).unwrap_or(true))
        .filter_map(|row| row["account_id"].as_str().map(str::to_string))
        .collect();
    let Some(first) = ids.first() else {
        return Ok(());
    };
    check_context(session, tenant_id, profile_id)?;
    let (compliance_url, overview_url) = account_inspection_urls(base, first)?;
    let first_compliance = get_json(client, &compliance_url, token).await;
    let first_overview = get_json(client, &overview_url, token).await;
    let compliance_supported = first_compliance.is_ok();
    let overview_supported = first_overview.is_ok();
    if !compliance_supported {
        warnings.push("Account compliance details were unavailable. Effective action enablement, policy interval, last successful change, next schedule, and retry state could not be added; the endpoint may be unsupported or the identity may lack access.".into());
    }
    if !overview_supported {
        warnings.push("Extended account overview was unavailable. CPM error details, dependency counts, and linked-account visibility could not be added; the endpoint may be unsupported or the identity may lack access.".into());
    }
    let mut inspected = Vec::new();
    inspected.push((first.clone(), first_compliance.ok(), first_overview.ok()));
    let rest = stream::iter(ids.into_iter().skip(1).map(|id| async move {
        inspect_account(
            client,
            base,
            token,
            &id,
            compliance_supported,
            overview_supported,
        )
        .await
    }))
    .buffer_unordered(8)
    .collect::<Vec<_>>()
    .await;
    inspected.extend(rest);
    if compliance_supported {
        let missing = inspected
            .iter()
            .filter(|(_, value, _)| value.is_none())
            .count();
        if missing > 0 {
            warnings.push(format!("Compliance details could not be read for {missing} affected accounts. No issue was inferred from those missing responses."));
        }
    }
    if overview_supported {
        let missing = inspected
            .iter()
            .filter(|(_, _, value)| value.is_none())
            .count();
        if missing > 0 {
            warnings.push(format!("Extended account overview could not be read for {missing} affected accounts. No issue was inferred from those missing responses."));
        }
    }
    let evidence: HashMap<String, (Option<Value>, Option<Value>)> = inspected
        .into_iter()
        .map(|(id, compliance, overview)| (id, (compliance, overview)))
        .collect();
    for row in rows.iter_mut() {
        if let Some((compliance, overview)) =
            row["account_id"].as_str().and_then(|id| evidence.get(id))
        {
            if let Some(compliance) = compliance {
                merge_compliance(row, compliance, now, threshold_days);
            }
            if let Some(overview) = overview {
                merge_overview(row, overview);
            }
        }
    }
    let permission_limited = rows
        .iter()
        .filter(|row| row["caller_permission_limited"] == true)
        .count();
    if permission_limited > 0 {
        warnings.push(format!("Action controls were hidden from the scanning identity for {permission_limited} affected accounts. Caller permission limits were not treated as password-management blockers."));
    }
    check_context(session, tenant_id, profile_id)
}

pub(super) fn check_context(
    session: &tauri::State<'_, Mutex<SessionState>>,
    tenant_id: &str,
    profile_id: &Option<String>,
) -> Result<(), String> {
    ensure_unlocked(session)?;
    let state = session.lock().map_err(|_| "Session state unavailable")?;
    if state.active_tenant_id.as_deref() != Some(tenant_id)
        || &state.active_profile_id != profile_id
    {
        return Err("Active tenant or profile changed during the scan; run it again.".into());
    }
    Ok(())
}

pub(super) async fn get_json(
    client: &reqwest::Client,
    url: &str,
    token: &str,
) -> Result<Value, String> {
    let response = client
        .get(url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|_| "Network request failed or timed out.".to_string())?;
    if !response.status().is_success() {
        // Do not return raw responses, which can contain tenant data or secrets.
        return Err(format!(
            "HTTP {}. Check permissions and endpoint support.",
            response.status().as_u16()
        ));
    }
    response
        .json()
        .await
        .map_err(|_| "Response was not valid JSON.".into())
}

pub(super) fn endpoint(base: &str, resource: &str, id: &str) -> Result<String, String> {
    if id.is_empty() || id == "." || id == ".." {
        return Err("Invalid resource identifier.".into());
    }
    let mut url =
        reqwest::Url::parse(&format!("{base}/{resource}/")).map_err(|_| "Invalid Vault API URL")?;
    url.path_segments_mut()
        .map_err(|_| "Invalid Vault API URL")?
        .pop_if_empty()
        .push(id);
    Ok(url.to_string())
}

async fn inventory(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    filter: Option<&str>,
    session: &tauri::State<'_, Mutex<SessionState>>,
    tenant_id: &str,
    profile_id: &Option<String>,
) -> Result<(Vec<Value>, bool), String> {
    let mut rows = Vec::new();
    let mut seen = HashSet::new();
    let mut offset = 0;
    for _ in 0..1000 {
        check_context(session, tenant_id, profile_id)?;
        let mut url = reqwest::Url::parse(&format!("{base}/Accounts"))
            .map_err(|_| "Invalid Vault API URL")?;
        url.query_pairs_mut()
            .append_pair("limit", "500")
            .append_pair("offset", &offset.to_string());
        if let Some(filter) = filter {
            url.query_pairs_mut().append_pair("savedFilter", filter);
        }
        let parsed = get_json(client, url.as_str(), token).await?;
        check_context(session, tenant_id, profile_id)?;
        let page = account_rows(&parsed);
        if parsed.get("value").and_then(Value::as_array).is_none() && !parsed.is_array() {
            return Err("Account response has an unsupported inventory format.".into());
        }
        if page.is_empty() {
            return Ok((rows, true));
        }
        let count = page.len();
        let mut added = 0;
        for row in page {
            let id = audit_string(&row, &["id", "ID"])
                .ok_or("Account response omitted an account ID.")?;
            if seen.insert(id) {
                rows.push(row);
                added += 1;
            }
        }
        if added != count {
            return Ok((rows, false));
        }
        offset += count;
        // nextLink is an availability signal only; never follow an arbitrary URL with the token.
        let has_next = parsed
            .get("nextLink")
            .and_then(Value::as_str)
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        // Some versions return a page count rather than a global count. Ignore it.
        if !has_next && count < 500 {
            return Ok((rows, true));
        }
    }
    Ok((rows, false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authoritative_change_replaces_a_stale_metadata_age() {
        let now = Utc::now();
        let mut row = json!({
            "platform_id": "Windows",
            "issues": ["Reported age exceeds threshold"],
            "reported_age_days": 150
        });
        merge_compliance(
            &mut row,
            &json!({"change": {
                "lastSuccess": (now - chrono::Duration::days(5)).to_rfc3339(),
                "policyInterval": 30,
                "actionEnabled": true
            }}),
            now,
            100,
        );
        assert_eq!(row["authoritative_age_days"], 5);
        assert!(!has_issue(&row, &["Reported age exceeds threshold"]));
        assert!(!has_issue(
            &row,
            &["Last successful change exceeds threshold"]
        ));
    }

    #[test]
    fn caller_permissions_are_not_reported_as_a_rotation_blocker() {
        let mut row = json!({
            "platform_id": "Windows",
            "issues": ["Change failed"]
        });
        merge_compliance(
            &mut row,
            &json!({"change": {
                "actionEnabled": false,
                "actionDisabledReason": "MISSING_PERMISSIONS"
            }}),
            Utc::now(),
            100,
        );
        assert!(!has_issue(&row, &["Password change action disabled"]));
        assert!(row["change_disabled_reason"].is_null());
        assert_eq!(row["caller_permission_limited"], true);
    }

    #[test]
    fn overview_adds_confirmed_cpm_and_dependency_evidence() {
        let mut row = json!({"issues": [], "management_type": "CPM"});
        merge_overview(
            &mut row,
            &json!({
                "Details": {"ManagedByCPM": false, "CPMErrorDetails": "Permission denied"},
                "FailedDependencies": 2
            }),
        );
        assert!(has_issue(&row, &["Account not managed by CPM"]));
        assert!(has_issue(&row, &["Reported permission failure"]));
        assert!(has_issue(&row, &["Reported dependency failure"]));
    }

    #[test]
    fn inspection_urls_stay_on_the_configured_host() {
        let (compliance, overview) =
            account_inspection_urls("https://tenant.example/PasswordVault/API", "12_3").unwrap();
        assert_eq!(
            compliance,
            "https://tenant.example/api/rotation/accounts/12_3/compliance-info"
        );
        assert_eq!(
            overview,
            "https://tenant.example/PasswordVault/API/ExtendedAccounts/12_3/overview"
        );
    }
}
