//! Explicit, reviewed account operations. Platform INI settings are not writable
//! through the supported platform REST surface and are never silently replaced.
use super::rotation_analysis::{classify_account, platform_id};
use super::rotation_health::{check_context, endpoint, get_json};
use super::*;
use std::collections::HashSet;

#[derive(Clone)]
pub(super) struct ActionPlan {
    tenant_id: String,
    profile_id: Option<String>,
    token: String,
    base: String,
    expires: u64,
    operation: String,
    platform: String,
    accounts: Vec<Value>,
    recovery: Option<Value>,
}

struct ActionRunGuard<'a>(&'a Mutex<SessionState>);
impl Drop for ActionRunGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.0.lock() {
            state.rotation_action_running = false;
        }
    }
}

fn plan_matches_context(
    plan: &ActionPlan,
    tenant: &str,
    profile: &Option<String>,
    token: &str,
    base: &str,
    now: u64,
) -> bool {
    plan.expires > now
        && plan.tenant_id == tenant
        && &plan.profile_id == profile
        && plan.token == token
        && plan.base == base
}

#[derive(Deserialize)]
pub(crate) struct ActionRequest {
    operation: String,
    platform_id: String,
    account_ids: Vec<String>,
    recovery_account_id: Option<String>,
    recovery_folder: Option<String>,
}

fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(error_to_string)
}

fn context(
    app: &tauri::AppHandle,
    session: &tauri::State<'_, Mutex<SessionState>>,
) -> Result<(String, Option<String>, String, String), String> {
    ensure_unlocked(session)?;
    let config = load_config(app).map_err(error_to_string)?;
    let state = session.lock().map_err(|_| "Session state unavailable")?;
    let tenant = find_active_tenant(&config, state.active_tenant_id.as_deref())?;
    let token = state
        .platform_token
        .as_ref()
        .ok_or("Request a platform token first.")?;
    if token.invalidated || token.expires_at <= now_millis() {
        return Err("Request a fresh platform token first.".into());
    }
    let base = tenant
        .vault_api_base_url
        .trim()
        .trim_end_matches('/')
        .to_string();
    let url = reqwest::Url::parse(&base).map_err(|_| "Invalid Vault API URL")?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("Account operations require an HTTPS Vault API URL without credentials, query, or fragment.".into());
    }
    Ok((
        tenant.id,
        state.active_profile_id.clone(),
        token.access_token.clone(),
        base,
    ))
}

fn validate_request(payload: &ActionRequest) -> Result<(), String> {
    if !["enable_management", "reconcile", "link_recovery"].contains(&payload.operation.as_str()) {
        return Err("Unsupported rotation action.".into());
    }
    if payload.platform_id.trim().is_empty()
        || payload.platform_id == "Platform assignment unavailable"
        || payload.platform_id == "Unknown platform"
    {
        return Err("A verified platform assignment is required.".into());
    }
    let ids: HashSet<_> = payload.account_ids.iter().collect();
    if ids.is_empty()
        || ids.len() > 500
        || ids.len() != payload.account_ids.len()
        || ids.iter().any(|id| !valid_account_id(id))
    {
        return Err("Select 1–500 unique account IDs.".into());
    }
    Ok(())
}

fn valid_account_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 256
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn same_account(before: &Value, after: &Value, platform: &str) -> bool {
    platform_id(after).as_deref() == Some(platform)
        && before["name"] == after["name"]
        && before["safeName"] == after["safeName"]
        && before["userName"] == after["userName"]
        && before["address"] == after["address"]
        && before["secretManagement"]["automaticManagementEnabled"]
            == after["secretManagement"]["automaticManagementEnabled"]
        && before["secretManagement"]["manualManagementReason"]
            == after["secretManagement"]["manualManagementReason"]
        && before["platformAccountProperties"] == after["platformAccountProperties"]
}

fn recovery_details(account: &Value, supplied_folder: Option<&str>) -> Result<Value, String> {
    let name =
        audit_string(account, &["name"]).ok_or("Recovery account has no readable object name.")?;
    let safe = audit_string(account, &["safeName"])
        .ok_or("Recovery account has no readable safe name.")?;
    let observed = audit_string(account, &["folder", "folderName"]);
    let folder = observed.as_deref().or(supplied_folder.map(str::trim).filter(|s| !s.is_empty()))
        .ok_or("The API does not expose this account's folder. Enter its confirmed Vault folder; it will not be guessed.")?;
    Ok(
        json!({"account_id": audit_string(account, &["id", "ID"]), "name": name,
        "safe": safe, "folder": folder, "username": audit_string(account, &["userName"]),
        "address": audit_string(account, &["address"]), "folder_verified": observed.is_some()}),
    )
}

#[tauri::command]
pub(crate) async fn find_rotation_recovery_accounts(
    app: tauri::AppHandle,
    session: tauri::State<'_, Mutex<SessionState>>,
    object_name: String,
) -> Result<Value, String> {
    let name = object_name.trim();
    if name.is_empty() || name.len() > 256 {
        return Err("Enter the exact account object name (up to 256 characters).".into());
    }
    let (tenant, profile, token, base) = context(&app, &session)?;
    let client = client()?;
    let mut matches = Vec::new();
    let mut seen = HashSet::new();
    for page in 0..100 {
        check_context(&session, &tenant, &profile)?;
        let mut url = reqwest::Url::parse(&format!("{base}/Accounts"))
            .map_err(|_| "Invalid Vault API URL")?;
        url.query_pairs_mut()
            .append_pair("search", name)
            .append_pair("limit", "500")
            .append_pair("offset", &(page * 500).to_string());
        let value = get_json(&client, url.as_str(), &token).await?;
        let rows = value
            .get("value")
            .and_then(Value::as_array)
            .ok_or("Unsupported account search response.")?;
        for row in rows {
            let id = audit_string(row, &["id", "ID"]).ok_or("Search omitted an account ID.")?;
            if !seen.insert(id.clone()) {
                return Err(
                    "Search returned repeated pages; narrow the search in CyberArk.".into(),
                );
            }
            if audit_string(row, &["name"]).as_deref() == Some(name) {
                matches.push(json!({"account_id": id, "name": name, "safe": audit_string(row, &["safeName"]),
                    "username": audit_string(row, &["userName"]), "address": audit_string(row, &["address"]),
                    "folder": audit_string(row, &["folder", "folderName"])}));
            }
        }
        if rows.len() < 500
            && value
                .get("nextLink")
                .and_then(Value::as_str)
                .unwrap_or("")
                .is_empty()
        {
            check_context(&session, &tenant, &profile)?;
            return Ok(json!({"tenant_id": tenant, "profile_id": profile, "matches": matches}));
        }
    }
    Err("Search exceeded its safety limit; results cannot be safely selected.".into())
}

#[tauri::command]
pub(crate) async fn prepare_rotation_action(
    app: tauri::AppHandle,
    session: tauri::State<'_, Mutex<SessionState>>,
    payload: ActionRequest,
) -> Result<Value, String> {
    validate_request(&payload)?;
    let (tenant, profile, token, base) = context(&app, &session)?;
    let client = client()?;
    let mut accounts = Vec::new();
    let mut preview = Vec::new();
    for id in &payload.account_ids {
        check_context(&session, &tenant, &profile)?;
        let row = get_json(&client, &endpoint(&base, "Accounts", id)?, &token).await?;
        if platform_id(&row).as_deref() != Some(&payload.platform_id) {
            return Err("An account changed platform or its assignment is unavailable. Rescan before applying changes.".into());
        }
        let enabled = row["secretManagement"]["automaticManagementEnabled"].as_bool();
        if payload.operation == "enable_management" && enabled != Some(false) {
            return Err("Only explicitly disabled accounts can be included in this management action. Rescan and review the selection.".into());
        }
        if payload.operation == "reconcile" && enabled != Some(true) {
            return Err("Reconciliation requires automatic management. Enable eligible disabled accounts as a separate reviewed action first.".into());
        }
        let mut item = classify_account(&row, None, 100, Utc::now());
        item["account_id"] = json!(id);
        preview.push(item);
        // Keep only metadata necessary to detect reassignment or configuration drift.
        accounts.push(json!({"id": id, "name": row["name"], "safeName": row["safeName"],
            "userName": row["userName"], "address": row["address"], "platformAccountProperties": row["platformAccountProperties"],
            "secretManagement": {"automaticManagementEnabled": enabled, "manualManagementReason": row["secretManagement"]["manualManagementReason"]}}));
    }
    let recovery = if payload.operation == "link_recovery" {
        let id = payload
            .recovery_account_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or("Choose a recovery account from exact-name search results.")?;
        if !valid_account_id(id) {
            return Err("Invalid recovery account ID.".into());
        }
        if payload.account_ids.iter().any(|target| target == id) {
            return Err("The recovery account cannot be linked to itself.".into());
        }
        let row = get_json(&client, &endpoint(&base, "Accounts", id)?, &token).await?;
        Some(recovery_details(&row, payload.recovery_folder.as_deref())?)
    } else {
        None
    };
    check_context(&session, &tenant, &profile)?;
    let plan_id = Uuid::new_v4().to_string();
    let expires = now_millis() + 300_000;
    let mut state = session.lock().map_err(|_| "Session state unavailable")?;
    state
        .rotation_plans
        .retain(|_, plan| plan.expires > now_millis());
    if state.rotation_plans.len() >= 20 {
        return Err("Too many pending reviews; wait for older reviews to expire.".into());
    }
    state.rotation_plans.insert(
        plan_id.clone(),
        ActionPlan {
            tenant_id: tenant.clone(),
            profile_id: profile.clone(),
            token,
            base,
            expires,
            operation: payload.operation.clone(),
            platform: payload.platform_id.clone(),
            accounts,
            recovery: recovery.clone(),
        },
    );
    Ok(
        json!({"plan_id": plan_id, "tenant_id": tenant, "profile_id": profile, "platform_id": payload.platform_id,
        "operation": payload.operation, "expires_at": expires, "accounts": preview, "recovery": recovery}),
    )
}

#[tauri::command]
pub(crate) async fn apply_rotation_action(
    app: tauri::AppHandle,
    session: tauri::State<'_, Mutex<SessionState>>,
    plan_id: String,
) -> Result<Value, String> {
    let (tenant, profile, token, base) = context(&app, &session)?;
    let plan = {
        let mut state = session.lock().map_err(|_| "Session state unavailable")?;
        if state.rotation_action_running {
            return Err("Another rotation action is still running. Wait for its results before applying this review.".into());
        }
        let plan = state
            .rotation_plans
            .remove(&plan_id)
            .ok_or("Review expired or already applied. Prepare a new review.")?;
        state.rotation_action_running = true;
        plan
    };
    let _running_guard = ActionRunGuard(&session);
    if !plan_matches_context(&plan, &tenant, &profile, &token, &base, now_millis()) {
        return Err(
            "Session or configuration changed, or review expired. Prepare a new review.".into(),
        );
    }
    let client = client()?;
    if let Some(recovery) = &plan.recovery {
        let id = recovery["account_id"]
            .as_str()
            .ok_or("Recovery account ID unavailable")?;
        let current = get_json(&client, &endpoint(&base, "Accounts", id)?, &token).await?;
        let details = recovery_details(&current, recovery["folder"].as_str())?;
        if details["name"] != recovery["name"]
            || details["safe"] != recovery["safe"]
            || details["folder"] != recovery["folder"]
        {
            return Err("Recovery account moved or changed. Prepare a new review.".into());
        }
    }
    let mut results = Vec::new();
    for account in &plan.accounts {
        let id = account["id"].as_str().unwrap();
        let result = async {
            let (active_tenant, active_profile, active_token, active_base) = context(&app, &session)?;
            if active_tenant != tenant || active_profile != profile || active_token != token || active_base != base {
                return Err("Session changed; action was not submitted.".to_string());
            }
            let url = endpoint(&base, "Accounts", id)?;
            let current = get_json(&client, &url, &token).await?;
            if !same_account(account, &current, &plan.platform) { return Err("Account configuration changed since review; rescan and review again.".into()); }
            check_context(&session, &tenant, &profile)?;
            let (latest_tenant, latest_profile, latest_token, latest_base) = context(&app, &session)?;
            if latest_tenant != tenant || latest_profile != profile || latest_token != token || latest_base != base {
                return Err("Session changed before submission; action was not submitted.".into());
            }
            let (method, action_url, body) = match plan.operation.as_str() {
                "enable_management" => (reqwest::Method::PATCH, url,
                    json!([{"op": "replace", "path": "/secretManagement/automaticManagementEnabled", "value": true}])),
                "reconcile" => (reqwest::Method::POST, format!("{}/Reconcile", url.trim_end_matches('/')), json!({})),
                "link_recovery" => {
                    let recovery = plan.recovery.as_ref().ok_or("Recovery account unavailable")?;
                    (reqwest::Method::POST, format!("{}/LinkAccount", url.trim_end_matches('/')),
                        json!({"safe": recovery["safe"], "name": recovery["name"], "folder": recovery["folder"], "extraPasswordIndex": 3}))
                },
                _ => return Err("Unsupported action".into()),
            };
            let response = client.request(method, action_url).bearer_auth(&token).json(&body).send().await
                .map_err(|_| "Network request failed or timed out; outcome is uncertain. Check CyberArk activity before retrying.".to_string())?;
            if !response.status().is_success() { return Err(format!("HTTP {}. Check permissions and the original CyberArk activity.", response.status().as_u16())); }
            Ok::<_, String>(if plan.operation == "reconcile" { "Reconciliation request accepted. Target password rotation is not yet confirmed." } else { "Configuration update accepted. Rescan to verify the resulting settings." }.to_string())
        }.await;
        results.push(
            json!({"account_id": id, "name": account["name"], "safe_name": account["safeName"],
            "accepted": result.is_ok(), "detail": result.unwrap_or_else(|error| error)}),
        );
    }
    Ok(
        json!({"tenant_id": tenant, "profile_id": profile, "platform_id": plan.platform,
        "operation": plan.operation, "results": results, "completed_at": Utc::now().to_rfc3339()}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn review_cannot_cross_tenant_profile_token_url_or_expiry() {
        let profile = Some("profile".into());
        let plan = ActionPlan {
            tenant_id: "tenant".into(),
            profile_id: profile.clone(),
            token: "token".into(),
            base: "https://example/api".into(),
            expires: 100,
            operation: "reconcile".into(),
            platform: "Windows".into(),
            accounts: vec![],
            recovery: None,
        };
        assert!(plan_matches_context(
            &plan,
            "tenant",
            &profile,
            "token",
            "https://example/api",
            99
        ));
        assert!(!plan_matches_context(
            &plan,
            "other",
            &profile,
            "token",
            "https://example/api",
            99
        ));
        assert!(!plan_matches_context(
            &plan,
            "tenant",
            &Some("other".into()),
            "token",
            "https://example/api",
            99
        ));
        assert!(!plan_matches_context(
            &plan,
            "tenant",
            &profile,
            "new-token",
            "https://example/api",
            99
        ));
        assert!(!plan_matches_context(
            &plan,
            "tenant",
            &profile,
            "token",
            "https://other/api",
            99
        ));
        assert!(!plan_matches_context(
            &plan,
            "tenant",
            &profile,
            "token",
            "https://example/api",
            100
        ));
    }
    #[test]
    fn scope_requires_unique_known_accounts_and_supported_operation() {
        let mut request = ActionRequest {
            operation: "reconcile".into(),
            platform_id: "Windows".into(),
            account_ids: vec!["1_1".into()],
            recovery_account_id: None,
            recovery_folder: None,
        };
        assert!(validate_request(&request).is_ok());
        request.account_ids.push("1_1".into());
        assert!(validate_request(&request).is_err());
        request.account_ids.pop();
        request.operation = "delete".into();
        assert!(validate_request(&request).is_err());
        request.operation = "reconcile".into();
        request.platform_id = "Platform assignment unavailable".into();
        assert!(validate_request(&request).is_err());
    }
    #[test]
    fn configuration_drift_is_rejected() {
        let before = json!({"platformId": "Windows", "name": "object", "safeName": "safe", "secretManagement": {"automaticManagementEnabled": false}});
        assert!(same_account(&before, &before, "Windows"));
        let mut after = before.clone();
        after["platformId"] = json!("Unix");
        assert!(!same_account(&before, &after, "Windows"));
        after = before.clone();
        after["secretManagement"]["automaticManagementEnabled"] = json!(true);
        assert!(!same_account(&before, &after, "Windows"));
    }
    #[test]
    fn folder_is_never_guessed_and_secrets_are_not_returned() {
        let row =
            json!({"id": "1_1", "name": "Recovery", "safeName": "Safe", "secret": "sensitive"});
        assert!(recovery_details(&row, None).is_err());
        let result = recovery_details(&row, Some("Root")).unwrap();
        assert_eq!(result["folder_verified"], false);
        assert!(!result.to_string().contains("sensitive"));
    }
}
