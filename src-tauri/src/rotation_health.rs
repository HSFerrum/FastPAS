use super::rotation_analysis::{classify_account, finding, platform_findings};
use super::*;
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
        "Effective Master Policy, account overrides, linked credential availability, and SRS-specific service health are not fully established by the Vault platform API.".to_string(),
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
    let mut platforms: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for account in &accounts {
        let row = classify_account(
            account,
            failures.get(&audit_string(account, &["id", "ID"]).unwrap_or_default()),
            threshold_days,
            now,
        );
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
        let details = if id == "Platform assignment unavailable" {
            Err("Platform assignment was unavailable even after account detail lookup; no unassigned-platform conclusion can be drawn.".into())
        } else {
            get_json(&client, &endpoint(base, "Platforms", &id)?, &token).await
        };
        let mut findings = match details {
            Ok(value) => platform_findings(&value),
            Err(error) => vec![finding(
                "Unknown",
                "Platform configuration could not be inspected",
                &error,
            )],
        };
        let disabled = rows
            .iter()
            .filter(|row| row["automatic_management_enabled"] == false)
            .count();
        if disabled == rows.len() {
            findings.push(finding("Confirmed account pattern", "All visible accounts have automatic management disabled", "This is an account-level setting, not evidence that the platform itself is disabled."));
        }
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
