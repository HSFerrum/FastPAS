use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use keyring::Entry;
use reqwest::header::CONTENT_TYPE;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::Value;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;
use tauri::Manager;
use uuid::Uuid;

#[derive(Default)]
struct SessionState {
    active_profile_id: Option<String>,
    active_tenant_id: Option<String>,
    identity_token: Option<RuntimeToken>,
    identity_client: Option<reqwest::Client>,
    platform_token: Option<RuntimeToken>,
    interactive_auth: Option<InteractiveAuthSession>,
    session_locked: bool,
    failed_unlock_attempts: u32,
    unlock_blocked_until: u64,
}

struct InteractiveAuthSession {
    client: reqwest::Client,
    advance_url: String,
    session_id: String,
    profile_id: String,
    pending_challenges: Vec<Vec<InteractiveAuthMechanism>>,
    next_challenge_index: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OAuthProfile {
    id: String,
    name: String,
    #[serde(default = "default_profile_auth_type")]
    auth_type: String,
    #[serde(default)]
    nickname: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    subdomain: String,
    #[serde(default)]
    identity_tenant_host: String,
    #[serde(default)]
    application_id: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    client_secret: String,
    #[serde(default)]
    client_secret_stored: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TenantConfig {
    id: String,
    name: String,
    #[serde(default)]
    subdomain: String,
    #[serde(default)]
    identity_tenant_host: String,
    #[serde(default)]
    identity_base_url: String,
    #[serde(default)]
    identity_oauth_url: String,
    #[serde(default)]
    platform_token_url: String,
    #[serde(default)]
    vault_api_base_url: String,
    #[serde(default)]
    audit_api_base_url: String,
    #[serde(default)]
    audit_api_key: String,
    #[serde(default)]
    audit_api_key_stored: bool,
    #[serde(default)]
    notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RuntimeToken {
    access_token: String,
    token_type: String,
    expires_at: u64,
    source: String,
    endpoint: String,
    #[serde(default)]
    invalidated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenView {
    status: String,
    status_label: String,
    endpoint: String,
    source: String,
    expires_at_label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AppStatePayload {
    profiles: Vec<OAuthProfile>,
    tenants: Vec<TenantConfig>,
    active_profile_id: Option<String>,
    active_tenant_id: Option<String>,
    tokens: TokenBundle,
    passcode_configured: bool,
    session_locked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenBundle {
    identity: TokenView,
    platform: TokenView,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct StoredConfig {
    profiles: Vec<OAuthProfile>,
    tenants: Vec<TenantConfig>,
    active_profile_id: Option<String>,
    active_tenant_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
    token_type: Option<String>,
    expires_in: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PlatformTokenResponse {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultRequestPayload {
    method: String,
    path: String,
    query: String,
    body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultResponsePayload {
    status: u16,
    url: String,
    body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SaveTextFilePayload {
    path: String,
    content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UpdateProfileSecretPayload {
    profile_id: String,
    client_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UpdateSessionPasscodePayload {
    current_passcode: String,
    new_passcode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TenantResolution {
    subdomain: String,
    shared_services_url: String,
    identity_tenant_host: String,
    identity_token_url_prefix: String,
    platform_token_url: String,
    vault_api_base_url: String,
    inferred_identity_host: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InteractiveAuthMechanism {
    mechanism_id: String,
    name: String,
    prompt: String,
    answer_type: String,
    actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InteractiveAuthChallenge {
    summary: String,
    session_id: String,
    mechanisms: Vec<InteractiveAuthMechanism>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InteractiveAuthResult {
    state: AppStatePayload,
    authenticated: bool,
    challenge: Option<InteractiveAuthChallenge>,
    message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InteractiveAuthAdvancePayload {
    mechanism_id: String,
    action: String,
    #[serde(default)]
    answer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CopyRuntimeTokenPayload {
    kind: String,
    profile_password: String,
}

#[derive(Debug, Clone, Serialize)]
struct ConnectionComponentTelemetry {
    generated_at: String,
    date_from: String,
    date_to: String,
    audit_api_base_url: String,
    total_connections: u64,
    components: Vec<ConnectionComponentMetric>,
}

#[derive(Debug, Clone, Serialize)]
struct ConnectionComponentMetric {
    name: String,
    total_connections: u64,
    percent_of_total: f64,
    access_methods: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct AccountFailureTelemetry {
    generated_at: String,
    account_source_url: String,
    recording_source_url: String,
    total_failures: u64,
    total_accounts: u64,
    categories: Vec<AccountFailureCategory>,
}

#[derive(Debug, Clone, Serialize)]
struct AccountFailureCategory {
    service: String,
    failure_type: String,
    total_failures: u64,
    accounts: Vec<AccountFailureItem>,
}

#[derive(Debug, Clone, Serialize)]
struct AccountFailureItem {
    account_id: String,
    account_name: String,
    safe_name: String,
    username: String,
    address: String,
    platform_id: String,
    detail: String,
}

#[derive(Debug, Clone, Deserialize)]
struct RemediateAccountFailuresPayload {
    account_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct AccountRemediationReport {
    generated_at: String,
    requested_count: u64,
    resolved_count: u64,
    unlocked_then_resolved_count: u64,
    unresolved_count: u64,
    unlocked_account_failures: Vec<AccountRemediationItem>,
    results: Vec<AccountRemediationItem>,
}

#[derive(Debug, Clone, Serialize)]
struct AccountRemediationItem {
    account_id: String,
    account_name: String,
    safe_name: String,
    username: String,
    address: String,
    platform_id: String,
    was_locked: bool,
    unlocked: bool,
    automatic_management_enabled: bool,
    reconcile_started: bool,
    resolved: bool,
    final_management_status: String,
    completion_status: String,
    detail: String,
}

#[derive(Debug, Clone, Serialize)]
struct ActiveUserTelemetry {
    generated_at: String,
    identity_error: Option<String>,
    identity_active_count: u64,
    identity_recently_inactive_count: u64,
    identity_long_inactive_count: u64,
    identity_active_users: Vec<UserTelemetryItem>,
    identity_recently_inactive_users: Vec<UserTelemetryItem>,
    identity_long_inactive_users: Vec<UserTelemetryItem>,
}

#[derive(Debug, Clone, Serialize)]
struct UserTelemetryItem {
    username: String,
    display_name: String,
    source: String,
    last_seen: String,
    detail: String,
}

#[tauri::command]
fn get_app_state(
    app: tauri::AppHandle,
    session: tauri::State<'_, Mutex<SessionState>>,
) -> Result<AppStatePayload, String> {
    let config = load_config(&app).map_err(error_to_string)?;
    let session = session
        .lock()
        .map_err(|_| "session state poisoned".to_string())?;
    Ok(build_state_payload(&config, &session))
}

#[tauri::command]
fn configure_session_passcode(
    app: tauri::AppHandle,
    session: tauri::State<'_, Mutex<SessionState>>,
    passcode: String,
) -> Result<AppStatePayload, String> {
    validate_passcode(&passcode)?;
    confirm_os_keychain_access().map_err(error_to_string)?;
    store_session_passcode(&passcode).map_err(error_to_string)?;
    let config = load_config(&app).map_err(error_to_string)?;
    let mut session = session
        .lock()
        .map_err(|_| "session state poisoned".to_string())?;
    session.session_locked = false;
    session.failed_unlock_attempts = 0;
    session.unlock_blocked_until = 0;
    Ok(build_state_payload(&config, &session))
}

#[tauri::command]
fn unlock_session(
    app: tauri::AppHandle,
    session: tauri::State<'_, Mutex<SessionState>>,
    passcode: String,
) -> Result<AppStatePayload, String> {
    {
        let mut session = session
            .lock()
            .map_err(|_| "session state poisoned".to_string())?;
        enforce_unlock_rate_limit(&mut session)?;
        let expected = load_session_passcode().map_err(error_to_string)?;
        if expected != passcode {
            register_failed_unlock_attempt(&mut session);
            return Err(unlock_error_message(&session));
        }
        session.failed_unlock_attempts = 0;
        session.unlock_blocked_until = 0;
    }
    let expected = load_session_passcode().map_err(error_to_string)?;
    if expected != passcode {
        return Err("Passcode was incorrect.".to_string());
    }
    let config = load_config(&app).map_err(error_to_string)?;
    let mut session = session
        .lock()
        .map_err(|_| "session state poisoned".to_string())?;
    session.session_locked = false;
    Ok(build_state_payload(&config, &session))
}

#[tauri::command]
fn lock_session(
    app: tauri::AppHandle,
    session: tauri::State<'_, Mutex<SessionState>>,
) -> Result<AppStatePayload, String> {
    let config = load_config(&app).map_err(error_to_string)?;
    let mut session = session
        .lock()
        .map_err(|_| "session state poisoned".to_string())?;
    session.session_locked = true;
    session.identity_token = None;
    session.identity_client = None;
    session.platform_token = None;
    session.interactive_auth = None;
    Ok(build_state_payload(&config, &session))
}

#[tauri::command]
fn update_session_passcode(
    app: tauri::AppHandle,
    session: tauri::State<'_, Mutex<SessionState>>,
    payload: UpdateSessionPasscodePayload,
) -> Result<AppStatePayload, String> {
    ensure_unlocked(&session)?;
    confirm_os_keychain_access().map_err(error_to_string)?;
    let expected = load_session_passcode().map_err(error_to_string)?;
    if expected != payload.current_passcode {
        return Err("Current passcode was incorrect.".to_string());
    }
    validate_passcode(&payload.new_passcode)?;
    store_session_passcode(&payload.new_passcode).map_err(error_to_string)?;
    let config = load_config(&app).map_err(error_to_string)?;
    let session = session
        .lock()
        .map_err(|_| "session state poisoned".to_string())?;
    Ok(build_state_payload(&config, &session))
}

#[tauri::command]
fn save_profile(
    app: tauri::AppHandle,
    session: tauri::State<'_, Mutex<SessionState>>,
    payload: OAuthProfile,
) -> Result<AppStatePayload, String> {
    let mut config = load_config(&app).map_err(error_to_string)?;
    ensure_unlocked(&session)?;
    let existing = config
        .profiles
        .iter()
        .find(|item| item.id == payload.id)
        .cloned();
    let mut profile = OAuthProfile {
        id: normalized_id(&payload.id),
        ..payload
    };
    profile.auth_type = normalized_profile_auth_type(&profile.auth_type);
    if profile.name.trim().is_empty() {
        profile.name = if is_interactive_profile(&profile) {
            if !profile.nickname.trim().is_empty() {
                profile.nickname.clone()
            } else {
                profile.username.clone()
            }
        } else {
            profile.nickname.clone()
        };
    }
    if profile.client_secret.trim().is_empty() {
        profile.client_secret_stored = existing
            .as_ref()
            .map(|item| item.client_secret_stored)
            .unwrap_or(profile.client_secret_stored);
    } else {
        confirm_os_keychain_access().map_err(error_to_string)?;
        store_profile_secret(&profile.id, &profile.client_secret).map_err(error_to_string)?;
        profile.client_secret_stored = true;
    }
    profile.client_secret.clear();
    upsert_by_id(&mut config.profiles, profile.clone(), |item| {
        item.id.clone()
    });
    let mut session = session
        .lock()
        .map_err(|_| "session state poisoned".to_string())?;
    if session.active_profile_id.is_none() {
        session.active_profile_id = Some(profile.id.clone());
    }
    session.interactive_auth = None;
    config.active_profile_id = session.active_profile_id.clone();
    config.active_tenant_id = session.active_tenant_id.clone();
    save_config(&app, &config).map_err(error_to_string)?;
    Ok(build_state_payload(&config, &session))
}

#[tauri::command]
fn update_profile_secret(
    app: tauri::AppHandle,
    session: tauri::State<'_, Mutex<SessionState>>,
    payload: UpdateProfileSecretPayload,
) -> Result<AppStatePayload, String> {
    ensure_unlocked(&session)?;
    if payload.profile_id.trim().is_empty() {
        return Err("Select a profile first.".to_string());
    }
    if payload.client_secret.trim().is_empty() {
        return Err("Enter a new password or client secret first.".to_string());
    }
    let mut config = load_config(&app).map_err(error_to_string)?;
    let profile = config
        .profiles
        .iter_mut()
        .find(|item| item.id == payload.profile_id)
        .ok_or_else(|| "Selected profile was not found.".to_string())?;
    confirm_os_keychain_access().map_err(error_to_string)?;
    store_profile_secret(&payload.profile_id, &payload.client_secret).map_err(error_to_string)?;
    profile.client_secret.clear();
    profile.client_secret_stored = true;
    save_config(&app, &config).map_err(error_to_string)?;
    let session = session
        .lock()
        .map_err(|_| "session state poisoned".to_string())?;
    Ok(build_state_payload(&config, &session))
}

#[tauri::command]
fn delete_profile(
    app: tauri::AppHandle,
    session: tauri::State<'_, Mutex<SessionState>>,
    profile_id: String,
) -> Result<AppStatePayload, String> {
    let mut config = load_config(&app).map_err(error_to_string)?;
    ensure_unlocked(&session)?;
    config.profiles.retain(|item| item.id != profile_id);
    let _ = delete_profile_secret(&profile_id);
    let mut session = session
        .lock()
        .map_err(|_| "session state poisoned".to_string())?;
    if session.active_profile_id.as_deref() == Some(profile_id.as_str()) {
        session.active_profile_id = config.profiles.first().map(|item| item.id.clone());
    }
    session.identity_token = None;
    session.identity_client = None;
    session.platform_token = None;
    session.interactive_auth = None;
    config.active_profile_id = session.active_profile_id.clone();
    config.active_tenant_id = session.active_tenant_id.clone();
    save_config(&app, &config).map_err(error_to_string)?;
    Ok(build_state_payload(&config, &session))
}

#[tauri::command]
fn set_active_profile(
    app: tauri::AppHandle,
    session: tauri::State<'_, Mutex<SessionState>>,
    profile_id: String,
) -> Result<AppStatePayload, String> {
    let mut config = load_config(&app).map_err(error_to_string)?;
    ensure_unlocked(&session)?;
    let mut session = session
        .lock()
        .map_err(|_| "session state poisoned".to_string())?;
    session.active_profile_id = Some(profile_id);
    session.identity_token = None;
    session.identity_client = None;
    session.platform_token = None;
    session.interactive_auth = None;
    config.active_profile_id = session.active_profile_id.clone();
    config.active_tenant_id = session.active_tenant_id.clone();
    save_config(&app, &config).map_err(error_to_string)?;
    Ok(build_state_payload(&config, &session))
}

#[tauri::command]
fn save_tenant(
    app: tauri::AppHandle,
    session: tauri::State<'_, Mutex<SessionState>>,
    payload: TenantConfig,
) -> Result<AppStatePayload, String> {
    let mut config = load_config(&app).map_err(error_to_string)?;
    ensure_unlocked(&session)?;
    let existing = config
        .tenants
        .iter()
        .find(|item| item.id == payload.id)
        .cloned();
    let mut tenant = TenantConfig {
        id: normalized_id(&payload.id),
        ..payload
    };
    if tenant.audit_api_base_url.trim().is_empty() {
        let subdomain = tenant_subdomain(&tenant);
        if !subdomain.is_empty() {
            tenant.audit_api_base_url = format!("https://{subdomain}.audit.cyberark.cloud");
        }
    }
    if tenant.audit_api_key.trim().is_empty() {
        tenant.audit_api_key_stored = existing
            .as_ref()
            .map(|item| item.audit_api_key_stored)
            .unwrap_or(tenant.audit_api_key_stored);
    } else {
        confirm_os_keychain_access().map_err(error_to_string)?;
        store_tenant_audit_api_key(&tenant.id, &tenant.audit_api_key).map_err(error_to_string)?;
        tenant.audit_api_key_stored = true;
    }
    tenant.audit_api_key.clear();
    upsert_by_id(&mut config.tenants, tenant.clone(), |item| item.id.clone());
    let mut session = session
        .lock()
        .map_err(|_| "session state poisoned".to_string())?;
    if session.active_tenant_id.is_none() {
        session.active_tenant_id = Some(tenant.id.clone());
    }
    session.interactive_auth = None;
    config.active_profile_id = session.active_profile_id.clone();
    config.active_tenant_id = session.active_tenant_id.clone();
    save_config(&app, &config).map_err(error_to_string)?;
    Ok(build_state_payload(&config, &session))
}

#[tauri::command]
fn delete_tenant(
    app: tauri::AppHandle,
    session: tauri::State<'_, Mutex<SessionState>>,
    tenant_id: String,
) -> Result<AppStatePayload, String> {
    let mut config = load_config(&app).map_err(error_to_string)?;
    ensure_unlocked(&session)?;
    config.tenants.retain(|item| item.id != tenant_id);
    let _ = delete_tenant_audit_api_key(&tenant_id);
    let mut session = session
        .lock()
        .map_err(|_| "session state poisoned".to_string())?;
    if session.active_tenant_id.as_deref() == Some(tenant_id.as_str()) {
        session.active_tenant_id = config.tenants.first().map(|item| item.id.clone());
    }
    session.identity_token = None;
    session.identity_client = None;
    session.platform_token = None;
    session.interactive_auth = None;
    config.active_profile_id = session.active_profile_id.clone();
    config.active_tenant_id = session.active_tenant_id.clone();
    save_config(&app, &config).map_err(error_to_string)?;
    Ok(build_state_payload(&config, &session))
}

#[tauri::command]
fn set_active_tenant(
    app: tauri::AppHandle,
    session: tauri::State<'_, Mutex<SessionState>>,
    tenant_id: String,
) -> Result<AppStatePayload, String> {
    let mut config = load_config(&app).map_err(error_to_string)?;
    ensure_unlocked(&session)?;
    let mut session = session
        .lock()
        .map_err(|_| "session state poisoned".to_string())?;
    session.active_tenant_id = Some(tenant_id);
    session.identity_token = None;
    session.identity_client = None;
    session.platform_token = None;
    session.interactive_auth = None;
    config.active_profile_id = session.active_profile_id.clone();
    config.active_tenant_id = session.active_tenant_id.clone();
    save_config(&app, &config).map_err(error_to_string)?;
    Ok(build_state_payload(&config, &session))
}

#[tauri::command]
async fn request_identity_token(
    app: tauri::AppHandle,
    session: tauri::State<'_, Mutex<SessionState>>,
) -> Result<AppStatePayload, String> {
    let config = load_config(&app).map_err(error_to_string)?;
    ensure_unlocked(&session)?;
    let (profile, tenant) = {
        let session = session
            .lock()
            .map_err(|_| "session state poisoned".to_string())?;
        (
            find_active_profile(&config, session.active_profile_id.as_deref())?,
            find_active_tenant(&config, session.active_tenant_id.as_deref())?,
        )
    };

    let client = reqwest::Client::new();
    let identity_oauth_url = identity_token_url(&profile, &tenant);

    if identity_oauth_url.trim().is_empty() {
        return Err(
            "FastPAS could not build the Identity OAuth token URL from the active profile and tenant."
                .to_string(),
        );
    }
    if is_interactive_profile(&profile) {
        return Err(
            "Interactive profiles must use StartAuthentication and AdvanceAuthentication. Use Interactive Authentication in the API page."
                .to_string(),
        );
    }

    let credential = load_profile_secret(&profile.id).map_err(error_to_string)?;
    let form_fields = vec![
        ("grant_type", "client_credentials".to_string()),
        ("client_id", profile.client_id.clone()),
        ("client_secret", credential),
    ];
    let response = client
        .post(&identity_oauth_url)
        .form(&form_fields)
        .send()
        .await
        .map_err(error_to_string)?;

    let payload: OAuthTokenResponse = response.json().await.map_err(error_to_string)?;
    let mut session = session
        .lock()
        .map_err(|_| "session state poisoned".to_string())?;
    session.identity_token = Some(RuntimeToken {
        access_token: payload.access_token,
        token_type: payload.token_type.unwrap_or_else(|| "Bearer".to_string()),
        expires_at: now_millis() + (payload.expires_in.unwrap_or(3600) * 1000),
        source: format!("{} @ {}", profile.name, tenant.name),
        endpoint: identity_oauth_url,
        invalidated: false,
    });
    session.identity_client = None;
    session.platform_token = None;
    session.interactive_auth = None;
    Ok(build_state_payload(&config, &session))
}

#[tauri::command]
async fn request_platform_token(
    app: tauri::AppHandle,
    session: tauri::State<'_, Mutex<SessionState>>,
) -> Result<AppStatePayload, String> {
    let config = load_config(&app).map_err(error_to_string)?;
    ensure_unlocked(&session)?;
    let (profile, tenant) = {
        let session = session
            .lock()
            .map_err(|_| "session state poisoned".to_string())?;
        (
            find_active_profile(&config, session.active_profile_id.as_deref())?,
            find_active_tenant(&config, session.active_tenant_id.as_deref())?,
        )
    };

    let platform_token_url = if !tenant.platform_token_url.trim().is_empty() {
        tenant.platform_token_url.clone()
    } else {
        let host = identity_tenant_host(&tenant);
        if host.is_empty() {
            String::new()
        } else {
            format!("https://{host}/oauth2/platformtoken")
        }
    };

    if platform_token_url.trim().is_empty() {
        return Err("Active tenant is missing a platform token URL.".to_string());
    }
    if is_interactive_profile(&profile) {
        return Err(
            "Interactive profiles must use StartAuthentication and AdvanceAuthentication. Use Interactive Authentication in the API page."
                .to_string(),
        );
    }

    let credential = load_profile_secret(&profile.id).map_err(error_to_string)?;
    let client = reqwest::Client::new();
    let form_fields = vec![
        ("grant_type", "client_credentials".to_string()),
        ("client_id", profile.client_id.clone()),
        ("client_secret", credential),
    ];
    let response = client
        .post(&platform_token_url)
        .form(&form_fields)
        .send()
        .await
        .map_err(error_to_string)?;

    let status = response.status();
    let body_text = response.text().await.map_err(error_to_string)?;
    let body_preview = match serde_json::from_str::<serde_json::Value>(&body_text) {
        Ok(json) => serde_json::to_string_pretty(&json).unwrap_or(body_text.clone()),
        Err(_) => body_text.clone(),
    };

    if !status.is_success() {
        return Err(format!(
            "Platform token request failed: HTTP {} from {}\n{}",
            status.as_u16(),
            platform_token_url,
            body_preview
        ));
    }

    let payload: PlatformTokenResponse = serde_json::from_str(&body_text).map_err(|error| {
        format!(
            "Platform token response could not be parsed: {} from {}\n{}",
            error, platform_token_url, body_preview
        )
    })?;
    let token_value = payload.access_token.or(payload.token).ok_or_else(|| {
        format!(
            "Platform token response did not contain a token field from {}\n{}",
            platform_token_url, body_preview
        )
    })?;

    let mut session = session
        .lock()
        .map_err(|_| "session state poisoned".to_string())?;
    session.platform_token = Some(RuntimeToken {
        access_token: token_value,
        token_type: payload.token_type.unwrap_or_else(|| "Bearer".to_string()),
        expires_at: now_millis() + (payload.expires_in.unwrap_or(900) * 1000),
        source: tenant.name.clone(),
        endpoint: platform_token_url,
        invalidated: false,
    });
    session.interactive_auth = None;
    Ok(build_state_payload(&config, &session))
}

#[tauri::command]
fn copy_runtime_token(
    app: tauri::AppHandle,
    session: tauri::State<'_, Mutex<SessionState>>,
    payload: CopyRuntimeTokenPayload,
) -> Result<(), String> {
    ensure_unlocked(&session)?;
    if payload.profile_password.trim().is_empty() {
        return Err("Enter the active profile password first.".to_string());
    }
    let config = load_config(&app).map_err(error_to_string)?;
    let (profile, token) = {
        let session = session
            .lock()
            .map_err(|_| "session state poisoned".to_string())?;
        let profile = find_active_profile(&config, session.active_profile_id.as_deref())?;
        let token = match payload.kind.trim().to_ascii_lowercase().as_str() {
            "identity" => session.identity_token.clone(),
            "platform" => session.platform_token.clone(),
            _ => return Err("Unsupported token kind.".to_string()),
        };
        (profile, token)
    };

    let expected_password = load_profile_secret(&profile.id).map_err(error_to_string)?;
    if payload.profile_password != expected_password {
        return Err("Profile password was incorrect.".to_string());
    }

    let runtime_token = token.ok_or_else(|| {
        if payload.kind.trim().eq_ignore_ascii_case("identity") {
            "Identity token is not available yet. Request it first.".to_string()
        } else {
            "Platform token is not available yet. Request it first.".to_string()
        }
    })?;
    if runtime_token.access_token.trim().is_empty() {
        return Err("Token value is empty.".to_string());
    }
    let copied_token = runtime_token.access_token;
    let mut clipboard = arboard::Clipboard::new().map_err(error_to_string)?;
    clipboard
        .set_text(copied_token.clone())
        .map_err(error_to_string)?;
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(30));
        if let Ok(mut delayed_clipboard) = arboard::Clipboard::new() {
            let should_clear = delayed_clipboard
                .get_text()
                .map(|current| current == copied_token || current.trim() == copied_token.trim())
                .unwrap_or(true);
            if should_clear {
                let _ = delayed_clipboard.set_text(String::new());
            }
        }
    });
    Ok(())
}

#[tauri::command]
async fn authenticate_interactive_user(
    app: tauri::AppHandle,
    session: tauri::State<'_, Mutex<SessionState>>,
) -> Result<InteractiveAuthResult, String> {
    let config = load_config(&app).map_err(error_to_string)?;
    ensure_unlocked(&session)?;
    let (profile, tenant) = {
        let session = session
            .lock()
            .map_err(|_| "session state poisoned".to_string())?;
        (
            find_active_profile(&config, session.active_profile_id.as_deref())?,
            find_active_tenant(&config, session.active_tenant_id.as_deref())?,
        )
    };

    if !is_interactive_profile(&profile) {
        return Err("Active profile is not an interactive user.".to_string());
    }
    if profile.username.trim().is_empty() {
        return Err("Active interactive profile is missing a username.".to_string());
    }

    let identity_host = identity_host_for_profile(&profile, &tenant);
    if identity_host.trim().is_empty() {
        return Err(
            "Active interactive profile is missing an Identity host/subdomain.".to_string(),
        );
    }

    let password = load_profile_secret(&profile.id).map_err(error_to_string)?;
    let start_url = format!("https://{identity_host}/Security/StartAuthentication");
    let advance_url = format!("https://{identity_host}/Security/AdvanceAuthentication");
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .map_err(error_to_string)?;

    let mut start_payload = json!({
        "User": profile.username,
        "Version": "1.0",
    });
    let tenant_subdomain = clean_subdomain(&profile.subdomain);
    if let Some(start_map) = start_payload.as_object_mut() {
        if !tenant_subdomain.is_empty() {
            start_map.insert("TenantId".to_string(), json!(tenant_subdomain));
        }
    }

    let start_response = client
        .post(&start_url)
        .header(CONTENT_TYPE, "application/json")
        .header("X-IDAP-NATIVE-CLIENT", "true")
        .json(&start_payload)
        .send()
        .await
        .map_err(error_to_string)?;
    let start_status = start_response.status();
    let start_text = start_response.text().await.map_err(error_to_string)?;
    let start_json: serde_json::Value = serde_json::from_str(&start_text).map_err(|error| {
        format!(
            "StartAuthentication response could not be parsed: {} from {}\n{}",
            error, start_url, start_text
        )
    })?;
    if !start_status.is_success() {
        let preview = serde_json::to_string_pretty(&start_json).unwrap_or(start_text.clone());
        return Err(format!(
            "StartAuthentication failed: HTTP {} from {}\n{}",
            start_status.as_u16(),
            start_url,
            preview
        ));
    }

    let session_id = start_json
        .pointer("/Result/SessionId")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string();
    if session_id.trim().is_empty() {
        return Err(format!(
            "StartAuthentication did not return a SessionId from {}",
            start_url
        ));
    }

    let mechanism_id = find_password_mechanism_id(&start_json).unwrap_or_default();

    if mechanism_id.trim().is_empty() {
        return Err(
            "StartAuthentication did not return a username/password mechanism (UP).".to_string(),
        );
    }
    let challenge_sets = extract_challenge_sets(&start_json);
    {
        let mut guard = session
            .lock()
            .map_err(|_| "session state poisoned".to_string())?;
        guard.interactive_auth = Some(InteractiveAuthSession {
            client: client.clone(),
            advance_url: advance_url.clone(),
            session_id: session_id.clone(),
            profile_id: profile.id.clone(),
            pending_challenges: challenge_sets,
            next_challenge_index: 1,
        });
    }

    let advance_payload = json!({
        "SessionId": session_id,
        "MechanismId": mechanism_id,
        "Action": "Answer",
        "Answer": password,
    });
    apply_interactive_advance(
        &config,
        &session,
        &client,
        &advance_url,
        &profile,
        &tenant,
        &session_id,
        &advance_payload,
    )
    .await
}

#[tauri::command]
async fn advance_interactive_authentication(
    app: tauri::AppHandle,
    session: tauri::State<'_, Mutex<SessionState>>,
    payload: InteractiveAuthAdvancePayload,
) -> Result<InteractiveAuthResult, String> {
    let config = load_config(&app).map_err(error_to_string)?;
    ensure_unlocked(&session)?;
    let (profile, tenant, auth_session) = {
        let guard = session
            .lock()
            .map_err(|_| "session state poisoned".to_string())?;
        let profile = find_active_profile(&config, guard.active_profile_id.as_deref())?;
        let tenant = find_active_tenant(&config, guard.active_tenant_id.as_deref())?;
        let auth_session = guard
            .interactive_auth
            .as_ref()
            .ok_or_else(|| "No interactive authentication session is in progress.".to_string())?;
        if auth_session.profile_id != profile.id {
            return Err(
                "Interactive authentication session no longer matches the active profile."
                    .to_string(),
            );
        }
        (
            profile,
            tenant,
            (
                auth_session.client.clone(),
                auth_session.advance_url.clone(),
                auth_session.session_id.clone(),
            ),
        )
    };

    let (client, advance_url, session_id) = auth_session;
    let action = payload.action.trim();
    if action.is_empty() {
        return Err("Choose an interactive authentication action first.".to_string());
    }
    let request_payload = if action.eq_ignore_ascii_case("Answer") {
        if payload.answer.trim().is_empty() {
            return Err("Enter the challenge answer first.".to_string());
        }
        let mut payload_json = json!({
            "SessionId": session_id,
            "Action": action,
            "Answer": payload.answer,
        });
        if !payload.mechanism_id.trim().is_empty() {
            payload_json["MechanismId"] = json!(payload.mechanism_id);
        }
        payload_json
    } else {
        let mut payload_json = json!({
            "SessionId": session_id,
            "Action": action,
        });
        if !payload.mechanism_id.trim().is_empty() {
            payload_json["MechanismId"] = json!(payload.mechanism_id);
        }
        payload_json
    };

    apply_interactive_advance(
        &config,
        &session,
        &client,
        &advance_url,
        &profile,
        &tenant,
        &session_id,
        &request_payload,
    )
    .await
}

#[tauri::command]
async fn execute_vault_request(
    app: tauri::AppHandle,
    session: tauri::State<'_, Mutex<SessionState>>,
    payload: VaultRequestPayload,
) -> Result<VaultResponsePayload, String> {
    let config = load_config(&app).map_err(error_to_string)?;
    ensure_unlocked(&session)?;
    let tenant = {
        let session = session
            .lock()
            .map_err(|_| "session state poisoned".to_string())?;
        find_active_tenant(&config, session.active_tenant_id.as_deref())?
    };

    let platform_token = {
        let session = session
            .lock()
            .map_err(|_| "session state poisoned".to_string())?;
        session
            .platform_token
            .clone()
            .ok_or_else(|| "Request the platform token first.".to_string())?
    };

    if tenant.vault_api_base_url.trim().is_empty() {
        return Err("Active tenant is missing a vault API base URL.".to_string());
    }

    let method = reqwest::Method::from_bytes(payload.method.trim().as_bytes())
        .map_err(|_| "Unsupported HTTP method.".to_string())?;
    let path = payload.path.trim().trim_start_matches('/');
    let mut url = format!(
        "{}/{}",
        tenant.vault_api_base_url.trim_end_matches('/'),
        path
    );
    if !payload.query.trim().is_empty() {
        url = format!("{url}?{}", payload.query.trim().trim_start_matches('?'));
    }

    let client = reqwest::Client::new();
    let mut request = client
        .request(method.clone(), &url)
        .bearer_auth(platform_token.access_token);
    if matches!(
        method,
        reqwest::Method::POST
            | reqwest::Method::PUT
            | reqwest::Method::PATCH
            | reqwest::Method::DELETE
    ) && !payload.body.trim().is_empty()
    {
        request = request
            .header(CONTENT_TYPE, "application/json")
            .body(payload.body);
    }

    let response = request.send().await.map_err(error_to_string)?;
    let status = response.status().as_u16();
    let response_url = response.url().to_string();
    let text = response.text().await.map_err(error_to_string)?;
    let body = match serde_json::from_str::<serde_json::Value>(&text) {
        Ok(json) => serde_json::to_string_pretty(&json).map_err(error_to_string)?,
        Err(_) => text,
    };

    if status == 401 {
        let mut session = session
            .lock()
            .map_err(|_| "session state poisoned".to_string())?;
        if let Some(token) = session.platform_token.as_mut() {
            token.invalidated = true;
        }
    }

    Ok(VaultResponsePayload {
        status,
        url: response_url,
        body,
    })
}

#[tauri::command]
async fn get_connection_component_telemetry(
    app: tauri::AppHandle,
    session: tauri::State<'_, Mutex<SessionState>>,
) -> Result<ConnectionComponentTelemetry, String> {
    let config = load_config(&app).map_err(error_to_string)?;
    ensure_unlocked(&session)?;
    let tenant = {
        let session = session
            .lock()
            .map_err(|_| "session state poisoned".to_string())?;
        find_active_tenant(&config, session.active_tenant_id.as_deref())?
    };
    let platform_token = {
        let session = session
            .lock()
            .map_err(|_| "session state poisoned".to_string())?;
        session
            .platform_token
            .clone()
            .ok_or_else(|| "Request the platform token first.".to_string())?
    };

    if tenant.vault_api_base_url.trim().is_empty() {
        return Err("Active tenant is missing a vault API base URL.".to_string());
    }

    let recordings_api_base_url = tenant
        .vault_api_base_url
        .trim()
        .trim_end_matches('/')
        .to_string();
    let date_to = Utc::now();
    let date_from = date_to - ChronoDuration::days(7);
    let date_format = "%Y-%m-%d %H:%M:%S";
    let date_from_label = date_from.format(date_format).to_string();
    let date_to_label = date_to.format(date_format).to_string();
    let client = reqwest::Client::new();

    let mut component_counts: HashMap<String, (u64, Vec<String>)> = HashMap::new();
    let mut total_connections = 0_u64;

    let from_time = date_from.timestamp();
    let to_time = date_to.timestamp();
    let limit = 500_i64;
    let mut offset = 0_i64;

    for _ in 0..20 {
        let recordings_url = format!(
            "{}/Recordings?limit={limit}&offset={offset}&sort=-PSMStartTime&fromTime={from_time}&toTime={to_time}",
            recordings_api_base_url
        );
        let response = client
            .get(&recordings_url)
            .bearer_auth(&platform_token.access_token)
            .send()
            .await
            .map_err(error_to_string)?;
        let status = response.status();
        let body = response.text().await.map_err(error_to_string)?;
        if !status.is_success() {
            return Err(format!(
                "PSM recordings request failed: HTTP {} from {}\n{}",
                status.as_u16(),
                recordings_url,
                pretty_json_or_text(&body)
            ));
        }

        let parsed: Value = serde_json::from_str(&body).map_err(|error| {
            format!(
                "PSM recordings response could not be parsed: {} from {}\n{}",
                error,
                recordings_url,
                pretty_json_or_text(&body)
            )
        })?;
        let rows = recording_rows(&parsed);
        if rows.is_empty() {
            break;
        }

        for row in rows {
            if let Some((component, access_method)) = connection_component_from_recording_row(&row)
            {
                total_connections += 1;
                let entry = component_counts.entry(component).or_insert((0, Vec::new()));
                entry.0 += 1;
                if !access_method.is_empty() && !entry.1.iter().any(|item| item == &access_method) {
                    entry.1.push(access_method);
                }
            }
        }

        if !has_more_recording_rows(&parsed, offset, limit) {
            break;
        }
        offset += limit;
    }

    let mut components: Vec<ConnectionComponentMetric> = component_counts
        .into_iter()
        .map(|(name, (count, mut access_methods))| {
            access_methods.sort();
            ConnectionComponentMetric {
                name,
                total_connections: count,
                percent_of_total: if total_connections == 0 {
                    0.0
                } else {
                    ((count as f64 / total_connections as f64) * 1000.0).round() / 10.0
                },
                access_methods,
            }
        })
        .collect();
    components.sort_by(|left, right| {
        right
            .total_connections
            .cmp(&left.total_connections)
            .then_with(|| left.name.cmp(&right.name))
    });

    Ok(ConnectionComponentTelemetry {
        generated_at: Utc::now().to_rfc3339(),
        date_from: date_from_label,
        date_to: date_to_label,
        audit_api_base_url: recordings_api_base_url,
        total_connections,
        components,
    })
}

#[tauri::command]
async fn get_account_failure_telemetry(
    app: tauri::AppHandle,
    session: tauri::State<'_, Mutex<SessionState>>,
) -> Result<AccountFailureTelemetry, String> {
    let config = load_config(&app).map_err(error_to_string)?;
    ensure_unlocked(&session)?;
    let tenant = {
        let session = session
            .lock()
            .map_err(|_| "session state poisoned".to_string())?;
        find_active_tenant(&config, session.active_tenant_id.as_deref())?
    };
    let platform_token = {
        let session = session
            .lock()
            .map_err(|_| "session state poisoned".to_string())?;
        session
            .platform_token
            .clone()
            .ok_or_else(|| "Request the platform token first.".to_string())?
    };
    if tenant.vault_api_base_url.trim().is_empty() {
        return Err("Active tenant is missing a vault API base URL.".to_string());
    }

    let api_base = tenant
        .vault_api_base_url
        .trim()
        .trim_end_matches('/')
        .to_string();
    let client = reqwest::Client::new();
    let mut categories: HashMap<String, AccountFailureCategory> = HashMap::new();
    let mut total_accounts = 0_u64;
    let limit = 500_i64;
    let mut offset = 0_i64;
    let mut account_source_url = format!("{api_base}/Accounts");

    for _ in 0..30 {
        let url = format!("{api_base}/Accounts?limit={limit}&offset={offset}");
        if offset == 0 {
            account_source_url = url.clone();
        }
        let response = client
            .get(&url)
            .bearer_auth(&platform_token.access_token)
            .send()
            .await
            .map_err(error_to_string)?;
        let status = response.status();
        let body = response.text().await.map_err(error_to_string)?;
        if !status.is_success() {
            return Err(format!(
                "Account failure scan failed: HTTP {} from {}\n{}",
                status.as_u16(),
                url,
                pretty_json_or_text(&body)
            ));
        }
        let parsed: Value = serde_json::from_str(&body).map_err(|error| {
            format!(
                "Account failure scan response could not be parsed: {} from {}\n{}",
                error,
                url,
                pretty_json_or_text(&body)
            )
        })?;
        let rows = account_rows(&parsed);
        if rows.is_empty() {
            break;
        }
        total_accounts += rows.len() as u64;
        for account in rows {
            add_account_management_failures(&mut categories, &account);
        }
        if !has_more_account_rows(&parsed, offset, limit) {
            break;
        }
        offset += limit;
    }

    let date_to = Utc::now();
    let date_from = date_to - ChronoDuration::days(7);
    let from_time = date_from.timestamp();
    let to_time = date_to.timestamp();
    let mut recording_source_url = format!("{api_base}/Recordings");
    let mut recording_offset = 0_i64;

    for _ in 0..20 {
        let url = format!(
            "{api_base}/Recordings?limit={limit}&offset={recording_offset}&sort=-PSMStartTime&fromTime={from_time}&toTime={to_time}"
        );
        if recording_offset == 0 {
            recording_source_url = url.clone();
        }
        let response = client
            .get(&url)
            .bearer_auth(&platform_token.access_token)
            .send()
            .await
            .map_err(error_to_string)?;
        let status = response.status();
        let body = response.text().await.map_err(error_to_string)?;
        if !status.is_success() {
            return Err(format!(
                "PSM failure scan failed: HTTP {} from {}\n{}",
                status.as_u16(),
                url,
                pretty_json_or_text(&body)
            ));
        }
        let parsed: Value = serde_json::from_str(&body).map_err(|error| {
            format!(
                "PSM failure scan response could not be parsed: {} from {}\n{}",
                error,
                url,
                pretty_json_or_text(&body)
            )
        })?;
        let rows = recording_rows(&parsed);
        if rows.is_empty() {
            break;
        }
        for recording in rows {
            add_psm_recording_failure(&mut categories, &recording);
        }
        if !has_more_recording_rows(&parsed, recording_offset, limit) {
            break;
        }
        recording_offset += limit;
    }

    let mut category_list: Vec<AccountFailureCategory> = categories.into_values().collect();
    for category in &mut category_list {
        category.accounts.sort_by(|left, right| {
            left.safe_name
                .cmp(&right.safe_name)
                .then_with(|| left.account_name.cmp(&right.account_name))
        });
    }
    category_list.sort_by(|left, right| {
        right
            .total_failures
            .cmp(&left.total_failures)
            .then_with(|| left.service.cmp(&right.service))
            .then_with(|| left.failure_type.cmp(&right.failure_type))
    });
    let total_failures = category_list.iter().map(|item| item.total_failures).sum();

    Ok(AccountFailureTelemetry {
        generated_at: Utc::now().to_rfc3339(),
        account_source_url,
        recording_source_url,
        total_failures,
        total_accounts,
        categories: category_list,
    })
}

#[tauri::command]
async fn remediate_account_failures(
    app: tauri::AppHandle,
    session: tauri::State<'_, Mutex<SessionState>>,
    payload: RemediateAccountFailuresPayload,
) -> Result<AccountRemediationReport, String> {
    let config = load_config(&app).map_err(error_to_string)?;
    ensure_unlocked(&session)?;
    let tenant = {
        let session = session
            .lock()
            .map_err(|_| "session state poisoned".to_string())?;
        find_active_tenant(&config, session.active_tenant_id.as_deref())?
    };
    let platform_token = {
        let session = session
            .lock()
            .map_err(|_| "session state poisoned".to_string())?;
        session
            .platform_token
            .clone()
            .ok_or_else(|| "Request the platform token first.".to_string())?
    };
    if tenant.vault_api_base_url.trim().is_empty() {
        return Err("Active tenant is missing a vault API base URL.".to_string());
    }

    let mut account_ids = payload
        .account_ids
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    account_ids.sort();
    account_ids.dedup();
    if account_ids.is_empty() {
        return Err("Select at least one account to remediate.".to_string());
    }
    if account_ids.len() > 500 {
        return Err("Bulk remediation is limited to 500 accounts per run.".to_string());
    }
    if account_ids
        .iter()
        .any(|value| value.contains('/') || value.contains('?') || value.contains('#'))
    {
        return Err("One or more account IDs contain unsupported path characters.".to_string());
    }

    let api_base = tenant.vault_api_base_url.trim().trim_end_matches('/');
    let client = reqwest::Client::new();
    let mut results = Vec::with_capacity(account_ids.len());
    let mut pending_checks = Vec::new();

    for account_id in account_ids {
        let account_url = format!("{api_base}/Accounts/{account_id}");
        let account_response = client
            .get(&account_url)
            .bearer_auth(&platform_token.access_token)
            .send()
            .await
            .map_err(error_to_string)?;
        let account_status = account_response.status();
        let account_body = account_response.text().await.map_err(error_to_string)?;
        if !account_status.is_success() {
            results.push(empty_account_remediation_item(
                &account_id,
                false,
                format!(
                    "Account lookup failed: HTTP {}. {}",
                    account_status.as_u16(),
                    pretty_json_or_text(&account_body)
                ),
            ));
            continue;
        }

        let account: Value = match serde_json::from_str(&account_body) {
            Ok(value) => value,
            Err(error) => {
                results.push(empty_account_remediation_item(
                    &account_id,
                    false,
                    format!("Account lookup response could not be parsed: {error}"),
                ));
                continue;
            }
        };
        let was_locked = account_is_locked(&account);
        let mut item = account_remediation_item_from_account(&account, &account_id, was_locked);

        if was_locked {
            let unlock_url = format!("{account_url}/Unlock");
            if let Err(error) = send_vault_action(
                &client,
                &platform_token.access_token,
                reqwest::Method::POST,
                &unlock_url,
                None,
            )
            .await
            {
                item.detail = format!("Unlock failed: {error}");
                results.push(item);
                continue;
            }
            item.unlocked = true;
        }

        let patch_body = json!([
            {
                "op": "replace",
                "path": "/secretManagement/automaticManagementEnabled",
                "value": true
            }
        ]);
        if let Err(error) = send_vault_action(
            &client,
            &platform_token.access_token,
            reqwest::Method::PATCH,
            &account_url,
            Some(patch_body),
        )
        .await
        {
            item.detail = format!("Automatic management could not be enabled: {error}");
            results.push(item);
            continue;
        }
        item.automatic_management_enabled = true;

        let reconcile_url = format!("{account_url}/Reconcile");
        if let Err(error) = send_vault_action(
            &client,
            &platform_token.access_token,
            reqwest::Method::POST,
            &reconcile_url,
            None,
        )
        .await
        {
            item.detail =
                format!("Automatic management was enabled, but reconcile failed: {error}");
            results.push(item);
            continue;
        }

        item.reconcile_started = true;
        item.completion_status = "processing".to_string();
        item.detail = "Reconcile started. Waiting for CPM completion.".to_string();
        pending_checks.push((results.len(), account_url));
        results.push(item);
    }

    for attempt in 0..30 {
        if pending_checks.is_empty() {
            break;
        }
        if attempt > 0 {
            tokio::time::sleep(Duration::from_secs(10)).await;
        }

        let mut still_pending = Vec::new();
        for (result_index, account_url) in pending_checks {
            let response = match client
                .get(&account_url)
                .bearer_auth(&platform_token.access_token)
                .send()
                .await
            {
                Ok(response) => response,
                Err(error) => {
                    results[result_index].detail =
                        format!("Reconcile started, but status check failed: {error}");
                    still_pending.push((result_index, account_url));
                    continue;
                }
            };
            let status = response.status();
            let body = match response.text().await {
                Ok(body) => body,
                Err(error) => {
                    results[result_index].detail =
                        format!("Reconcile started, but status response failed: {error}");
                    still_pending.push((result_index, account_url));
                    continue;
                }
            };
            if !status.is_success() {
                results[result_index].detail = format!(
                    "Reconcile started, but status check returned HTTP {}.",
                    status.as_u16()
                );
                still_pending.push((result_index, account_url));
                continue;
            }
            let account: Value = match serde_json::from_str(&body) {
                Ok(account) => account,
                Err(error) => {
                    results[result_index].detail =
                        format!("Reconcile started, but status could not be parsed: {error}");
                    still_pending.push((result_index, account_url));
                    continue;
                }
            };
            let management_status = account_management_status(&account);
            results[result_index].final_management_status = management_status.clone();
            if account_management_succeeded(&account) {
                results[result_index].resolved = true;
                results[result_index].completion_status = "completed".to_string();
                results[result_index].detail = if results[result_index].was_locked {
                    "CPM completed successfully after FastPAS unlocked the account.".to_string()
                } else {
                    "CPM completed successfully.".to_string()
                };
            } else {
                let reason = account_management_failure_reason(&account);
                results[result_index].detail = if reason.is_empty() {
                    format!(
                        "Reconcile is still processing. Current status: {}.",
                        management_status_or_unknown(&management_status)
                    )
                } else {
                    format!(
                        "Reconcile is still processing. Current status: {}. {}",
                        management_status_or_unknown(&management_status),
                        reason
                    )
                };
                still_pending.push((result_index, account_url));
            }
        }
        pending_checks = still_pending;
    }

    for (result_index, _) in pending_checks {
        results[result_index].completion_status = "timed_out".to_string();
        results[result_index].detail = format!(
            "Timed out after 5 minutes waiting for CPM. Last status: {}.",
            management_status_or_unknown(&results[result_index].final_management_status)
        );
    }

    let resolved_count = results.iter().filter(|item| item.resolved).count() as u64;
    let unlocked_then_resolved_count = results
        .iter()
        .filter(|item| item.was_locked && item.resolved)
        .count() as u64;
    let unlocked_account_failures = results
        .iter()
        .filter(|item| !item.was_locked && !item.resolved)
        .cloned()
        .collect::<Vec<_>>();

    Ok(AccountRemediationReport {
        generated_at: Utc::now().to_rfc3339(),
        requested_count: results.len() as u64,
        resolved_count,
        unlocked_then_resolved_count,
        unresolved_count: results.len() as u64 - resolved_count,
        unlocked_account_failures,
        results,
    })
}

#[tauri::command]
async fn get_active_user_telemetry(
    app: tauri::AppHandle,
    session: tauri::State<'_, Mutex<SessionState>>,
) -> Result<ActiveUserTelemetry, String> {
    let config = load_config(&app).map_err(error_to_string)?;
    ensure_unlocked(&session)?;
    let (tenant, identity_token, identity_client) = {
        let session = session
            .lock()
            .map_err(|_| "session state poisoned".to_string())?;
        (
            find_active_tenant(&config, session.active_tenant_id.as_deref())?,
            session
                .identity_token
                .clone()
                .ok_or_else(|| "Request the identity token first.".to_string())?,
            session.identity_client.clone(),
        )
    };

    let now = Utc::now();
    let active_since = now - ChronoDuration::days(7);
    let recently_inactive_since = now - ChronoDuration::days(28);
    let long_inactive_before = now - ChronoDuration::days(30);
    let client = identity_client.unwrap_or_else(reqwest::Client::new);
    let (
        identity_active_users,
        identity_recently_inactive_users,
        identity_long_inactive_users,
        identity_error,
    ) = match load_identity_user_activity(
        &client,
        &tenant,
        &identity_token,
        active_since,
        recently_inactive_since,
        long_inactive_before,
    )
    .await
    {
        Ok((active, recent, long)) => (active, recent, long, None),
        Err(error) => (Vec::new(), Vec::new(), Vec::new(), Some(error)),
    };

    Ok(ActiveUserTelemetry {
        generated_at: now.to_rfc3339(),
        identity_error,
        identity_active_count: identity_active_users.len() as u64,
        identity_recently_inactive_count: identity_recently_inactive_users.len() as u64,
        identity_long_inactive_count: identity_long_inactive_users.len() as u64,
        identity_active_users,
        identity_recently_inactive_users,
        identity_long_inactive_users,
    })
}

#[tauri::command]
fn clear_tokens(
    app: tauri::AppHandle,
    session: tauri::State<'_, Mutex<SessionState>>,
) -> Result<AppStatePayload, String> {
    let config = load_config(&app).map_err(error_to_string)?;
    ensure_unlocked(&session)?;
    let mut session = session
        .lock()
        .map_err(|_| "session state poisoned".to_string())?;
    session.identity_token = None;
    session.identity_client = None;
    session.platform_token = None;
    session.interactive_auth = None;
    Ok(build_state_payload(&config, &session))
}

#[tauri::command]
fn export_config(app: tauri::AppHandle) -> Result<String, String> {
    let config = load_config(&app).map_err(error_to_string)?;
    serde_json::to_string_pretty(&config).map_err(error_to_string)
}

#[tauri::command]
fn save_text_file(
    session: tauri::State<'_, Mutex<SessionState>>,
    payload: SaveTextFilePayload,
) -> Result<(), String> {
    ensure_unlocked(&session)?;
    fs::write(&payload.path, payload.content)
        .with_context(|| format!("failed to write {}", payload.path))
        .map_err(error_to_string)
}

#[tauri::command]
fn import_config(
    app: tauri::AppHandle,
    payload: String,
    session: tauri::State<'_, Mutex<SessionState>>,
) -> Result<AppStatePayload, String> {
    ensure_unlocked(&session)?;
    let imported: StoredConfig = serde_json::from_str(&payload).map_err(error_to_string)?;
    save_config(&app, &imported).map_err(error_to_string)?;
    let mut session = session
        .lock()
        .map_err(|_| "session state poisoned".to_string())?;
    session.active_profile_id = imported
        .active_profile_id
        .clone()
        .or_else(|| imported.profiles.first().map(|item| item.id.clone()));
    session.active_tenant_id = imported
        .active_tenant_id
        .clone()
        .or_else(|| imported.tenants.first().map(|item| item.id.clone()));
    session.identity_token = None;
    session.identity_client = None;
    session.platform_token = None;
    session.interactive_auth = None;
    Ok(build_state_payload(&imported, &session))
}

#[tauri::command]
async fn resolve_tenant(subdomain: String) -> Result<TenantResolution, String> {
    let subdomain = clean_subdomain(&subdomain);
    if subdomain.is_empty() {
        return Err("Enter a tenant subdomain first.".to_string());
    }

    let discovered_host = discover_identity_tenant_host(&subdomain)
        .await
        .unwrap_or_default();
    let inferred_identity_host = !discovered_host.is_empty();
    let identity_tenant_host = if inferred_identity_host {
        discovered_host
    } else {
        format!("{subdomain}.id.cyberark.cloud")
    };

    Ok(TenantResolution {
        subdomain: subdomain.clone(),
        shared_services_url: format!("https://{subdomain}.cyberark.cloud"),
        identity_tenant_host: identity_tenant_host.clone(),
        identity_token_url_prefix: format!("https://{identity_tenant_host}/oauth2/token"),
        platform_token_url: format!("https://{identity_tenant_host}/oauth2/platformtoken"),
        vault_api_base_url: format!(
            "https://{subdomain}.privilegecloud.cyberark.cloud/PasswordVault/API"
        ),
        inferred_identity_host,
    })
}

fn build_state_payload(config: &StoredConfig, session: &SessionState) -> AppStatePayload {
    AppStatePayload {
        profiles: config.profiles.clone(),
        tenants: config.tenants.clone(),
        active_profile_id: session.active_profile_id.clone(),
        active_tenant_id: session.active_tenant_id.clone(),
        tokens: TokenBundle {
            identity: token_view(session.identity_token.as_ref()),
            platform: token_view(session.platform_token.as_ref()),
        },
        passcode_configured: session_passcode_exists(),
        session_locked: session.session_locked,
    }
}

fn ensure_unlocked(session: &tauri::State<'_, Mutex<SessionState>>) -> Result<(), String> {
    let session = session
        .lock()
        .map_err(|_| "session state poisoned".to_string())?;
    if session.session_locked {
        Err("Unlock the FastPAS session first.".to_string())
    } else {
        Ok(())
    }
}

fn token_view(token: Option<&RuntimeToken>) -> TokenView {
    match token {
        Some(token) => {
            let active = !token.invalidated && token.expires_at > now_millis();
            TokenView {
                status: if token.invalidated {
                    "invalid".to_string()
                } else if active {
                    "active".to_string()
                } else {
                    "inactive".to_string()
                },
                status_label: if token.invalidated {
                    "Invalid".to_string()
                } else if active {
                    "Active".to_string()
                } else {
                    "Inactive".to_string()
                },
                endpoint: token.endpoint.clone(),
                source: token.source.clone(),
                expires_at_label: token.expires_at.to_string(),
            }
        }
        None => TokenView {
            status: "not-requested".to_string(),
            status_label: "Not requested".to_string(),
            endpoint: String::new(),
            source: String::new(),
            expires_at_label: "Not requested".to_string(),
        },
    }
}

fn find_active_profile(
    config: &StoredConfig,
    profile_id: Option<&str>,
) -> Result<OAuthProfile, String> {
    let id = profile_id.ok_or_else(|| "Set an active profile first.".to_string())?;
    config
        .profiles
        .iter()
        .find(|item| item.id == id)
        .cloned()
        .ok_or_else(|| "Active profile was not found.".to_string())
}

fn find_active_tenant(
    config: &StoredConfig,
    tenant_id: Option<&str>,
) -> Result<TenantConfig, String> {
    let id = tenant_id.ok_or_else(|| "Set an active tenant first.".to_string())?;
    config
        .tenants
        .iter()
        .find(|item| item.id == id)
        .cloned()
        .ok_or_else(|| "Active tenant was not found.".to_string())
}

fn load_config(app: &tauri::AppHandle) -> Result<StoredConfig> {
    let path = config_path(app)?;
    if !path.exists() {
        return Ok(StoredConfig::default());
    }
    let text =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut config: StoredConfig =
        serde_json::from_str(&text).context("failed to parse config file")?;
    for profile in &mut config.profiles {
        profile.auth_type = normalized_profile_auth_type(&profile.auth_type);
    }
    let migrated = migrate_profile_secrets(&mut config)?;
    if migrated {
        save_config(app, &config)?;
    }
    Ok(config)
}

fn save_config(app: &tauri::AppHandle, config: &StoredConfig) -> Result<()> {
    let path = config_path(app)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let text = serde_json::to_string_pretty(config).context("failed to serialize config")?;
    fs::write(&path, text).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn config_path(app: &tauri::AppHandle) -> Result<PathBuf> {
    let base = app
        .path()
        .app_config_dir()
        .context("failed to resolve app config directory")?;
    Ok(base.join("fastpas-config.json"))
}

fn normalized_id(id: &str) -> String {
    if id.trim().is_empty() {
        Uuid::new_v4().to_string()
    } else {
        id.to_string()
    }
}

fn upsert_by_id<T, F>(items: &mut Vec<T>, next_item: T, id_fn: F)
where
    F: Fn(&T) -> String,
{
    let next_id = id_fn(&next_item);
    if let Some(existing) = items.iter_mut().find(|item| id_fn(item) == next_id) {
        *existing = next_item;
    } else {
        items.push(next_item);
    }
}

fn now_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

fn error_to_string(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn pretty_json_or_text(text: &str) -> String {
    match serde_json::from_str::<Value>(text) {
        Ok(value) => serde_json::to_string_pretty(&value).unwrap_or_else(|_| text.to_string()),
        Err(_) => text.to_string(),
    }
}

fn recording_rows(parsed: &Value) -> Vec<Value> {
    if let Some(rows) = parsed.as_array() {
        return rows.clone();
    }
    for key in [
        "Recordings",
        "recordings",
        "value",
        "data",
        "Items",
        "items",
    ] {
        if let Some(rows) = parsed.get(key).and_then(Value::as_array) {
            return rows.clone();
        }
    }
    Vec::new()
}

fn has_more_recording_rows(parsed: &Value, offset: i64, limit: i64) -> bool {
    let returned = recording_rows(parsed).len() as i64;
    if returned < limit {
        return false;
    }
    let total = parsed
        .get("Total")
        .or_else(|| parsed.get("total"))
        .or_else(|| parsed.get("count"))
        .or_else(|| parsed.get("Count"))
        .and_then(Value::as_i64);
    total
        .map(|value| offset + returned < value)
        .unwrap_or(returned == limit)
}

fn account_rows(parsed: &Value) -> Vec<Value> {
    if let Some(rows) = parsed.as_array() {
        return rows.clone();
    }
    for key in ["value", "accounts", "Accounts", "data", "items", "Items"] {
        if let Some(rows) = parsed.get(key).and_then(Value::as_array) {
            return rows.clone();
        }
    }
    Vec::new()
}

fn has_more_account_rows(parsed: &Value, offset: i64, limit: i64) -> bool {
    let returned = account_rows(parsed).len() as i64;
    if returned < limit {
        return false;
    }
    let total = parsed
        .get("count")
        .or_else(|| parsed.get("Count"))
        .or_else(|| parsed.get("total"))
        .or_else(|| parsed.get("Total"))
        .and_then(Value::as_i64);
    total
        .map(|value| offset + returned < value)
        .unwrap_or(returned == limit)
}

fn add_account_management_failures(
    categories: &mut HashMap<String, AccountFailureCategory>,
    account: &Value,
) {
    let secret_management = account
        .get("secretManagement")
        .or_else(|| account.get("SecretManagement"));
    let status = secret_management
        .and_then(|value| audit_string(value, &["status", "Status"]))
        .unwrap_or_default();
    let reason = secret_management
        .and_then(|value| {
            audit_string(
                value,
                &[
                    "manualManagementReason",
                    "ManualManagementReason",
                    "failureReason",
                    "FailureReason",
                    "lastTaskFailureReason",
                ],
            )
        })
        .or_else(|| audit_string(account, &["manualManagementReason", "failureReason"]))
        .unwrap_or_default();
    let automatic_management = secret_management
        .and_then(|value| {
            value
                .get("automaticManagementEnabled")
                .or_else(|| value.get("AutomaticManagementEnabled"))
        })
        .and_then(Value::as_bool);

    if status.eq_ignore_ascii_case("failure") || !reason.trim().is_empty() {
        let failure_type = if !reason.trim().is_empty() {
            normalize_failure_label(&reason)
        } else {
            "CPM password management failed".to_string()
        };
        insert_failure_category(
            categories,
            "CPM",
            &failure_type,
            account_failure_item_from_account(account, &reason),
        );
    }

    if automatic_management == Some(false) {
        insert_failure_category(
            categories,
            "CPM",
            "Automatic management disabled",
            account_failure_item_from_account(
                account,
                "Automatic password management is disabled.",
            ),
        );
    }
}

fn account_is_locked(account: &Value) -> bool {
    account
        .get("locked")
        .or_else(|| account.get("Locked"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || audit_string(account, &["lockedBy", "LockedBy"])
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
}

fn account_remediation_item_from_account(
    account: &Value,
    fallback_account_id: &str,
    was_locked: bool,
) -> AccountRemediationItem {
    AccountRemediationItem {
        account_id: audit_string(account, &["id", "ID"])
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| fallback_account_id.to_string()),
        account_name: audit_string(account, &["name", "Name"]).unwrap_or_default(),
        safe_name: audit_string(account, &["safeName", "SafeName"]).unwrap_or_default(),
        username: audit_string(account, &["userName", "UserName", "username"]).unwrap_or_default(),
        address: audit_string(account, &["address", "Address"]).unwrap_or_default(),
        platform_id: audit_string(account, &["platformId", "PlatformID"]).unwrap_or_default(),
        was_locked,
        unlocked: false,
        automatic_management_enabled: false,
        reconcile_started: false,
        resolved: false,
        final_management_status: String::new(),
        completion_status: "failed".to_string(),
        detail: String::new(),
    }
}

fn empty_account_remediation_item(
    account_id: &str,
    was_locked: bool,
    detail: String,
) -> AccountRemediationItem {
    AccountRemediationItem {
        account_id: account_id.to_string(),
        account_name: String::new(),
        safe_name: String::new(),
        username: String::new(),
        address: String::new(),
        platform_id: String::new(),
        was_locked,
        unlocked: false,
        automatic_management_enabled: false,
        reconcile_started: false,
        resolved: false,
        final_management_status: String::new(),
        completion_status: "failed".to_string(),
        detail,
    }
}

fn account_management_status(account: &Value) -> String {
    account
        .get("secretManagement")
        .or_else(|| account.get("SecretManagement"))
        .and_then(|value| audit_string(value, &["status", "Status"]))
        .unwrap_or_default()
}

fn account_management_failure_reason(account: &Value) -> String {
    account
        .get("secretManagement")
        .or_else(|| account.get("SecretManagement"))
        .and_then(|value| {
            audit_string(
                value,
                &[
                    "manualManagementReason",
                    "ManualManagementReason",
                    "failureReason",
                    "FailureReason",
                    "lastTaskFailureReason",
                ],
            )
        })
        .unwrap_or_default()
}

fn account_management_succeeded(account: &Value) -> bool {
    let status = account_management_status(account);
    let automatic_management = account
        .get("secretManagement")
        .or_else(|| account.get("SecretManagement"))
        .and_then(|value| {
            value
                .get("automaticManagementEnabled")
                .or_else(|| value.get("AutomaticManagementEnabled"))
        })
        .and_then(Value::as_bool);
    automatic_management == Some(true)
        && matches!(
            status.trim().to_ascii_lowercase().as_str(),
            "success" | "succeeded" | "successful"
        )
}

fn management_status_or_unknown(status: &str) -> &str {
    if status.trim().is_empty() {
        "unknown"
    } else {
        status
    }
}

async fn send_vault_action(
    client: &reqwest::Client,
    access_token: &str,
    method: reqwest::Method,
    url: &str,
    body: Option<Value>,
) -> Result<(), String> {
    let mut request = client.request(method, url).bearer_auth(access_token);
    if let Some(body) = body {
        request = request.header(CONTENT_TYPE, "application/json").json(&body);
    }
    let response = request.send().await.map_err(error_to_string)?;
    let status = response.status();
    let response_body = response.text().await.map_err(error_to_string)?;
    if status.is_success() {
        Ok(())
    } else {
        Err(format!(
            "HTTP {} from {}. {}",
            status.as_u16(),
            url,
            pretty_json_or_text(&response_body)
        ))
    }
}

fn add_psm_recording_failure(
    categories: &mut HashMap<String, AccountFailureCategory>,
    recording: &Value,
) {
    let status = audit_string(
        recording,
        &[
            "Status",
            "status",
            "SessionStatus",
            "sessionStatus",
            "RecordingStatus",
            "recordingStatus",
        ],
    )
    .unwrap_or_default();
    let failure_reason = audit_string(
        recording,
        &[
            "FailureReason",
            "failureReason",
            "Error",
            "error",
            "Message",
            "message",
            "Details",
            "details",
        ],
    )
    .unwrap_or_default();
    let combined = format!("{status} {failure_reason}").to_ascii_lowercase();
    let failed = [
        "fail",
        "error",
        "disconnect",
        "terminated",
        "denied",
        "timeout",
        "exception",
    ]
    .iter()
    .any(|needle| combined.contains(needle));
    if !failed {
        return;
    }

    let failure_type = if !failure_reason.trim().is_empty() {
        normalize_failure_label(&failure_reason)
    } else if !status.trim().is_empty() {
        normalize_failure_label(&status)
    } else {
        "PSM connection failed".to_string()
    };
    insert_failure_category(
        categories,
        "PSM",
        &failure_type,
        account_failure_item_from_recording(recording, &failure_reason),
    );
}

fn insert_failure_category(
    categories: &mut HashMap<String, AccountFailureCategory>,
    service: &str,
    failure_type: &str,
    item: AccountFailureItem,
) {
    let key = format!("{service}\u{1f}{failure_type}");
    let category = categories
        .entry(key)
        .or_insert_with(|| AccountFailureCategory {
            service: service.to_string(),
            failure_type: failure_type.to_string(),
            total_failures: 0,
            accounts: Vec::new(),
        });
    category.total_failures += 1;
    category.accounts.push(item);
}

fn account_failure_item_from_account(account: &Value, detail: &str) -> AccountFailureItem {
    AccountFailureItem {
        account_id: audit_string(account, &["id", "ID", "accountId", "AccountID"])
            .unwrap_or_default(),
        account_name: audit_string(account, &["name", "Name"])
            .unwrap_or_else(|| "Unnamed account".to_string()),
        safe_name: audit_string(account, &["safeName", "SafeName", "safe"])
            .unwrap_or_else(|| "Unknown safe".to_string()),
        username: audit_string(account, &["userName", "UserName", "username"]).unwrap_or_default(),
        address: audit_string(account, &["address", "Address"]).unwrap_or_default(),
        platform_id: audit_string(account, &["platformId", "PlatformID", "platformID"])
            .unwrap_or_default(),
        detail: if detail.trim().is_empty() {
            "No failure detail provided.".to_string()
        } else {
            detail.trim().to_string()
        },
    }
}

fn account_failure_item_from_recording(recording: &Value, detail: &str) -> AccountFailureItem {
    AccountFailureItem {
        account_id: audit_string(recording, &["AccountID", "accountId", "accountID"])
            .unwrap_or_default(),
        account_name: audit_string(
            recording,
            &["AccountName", "accountName", "Account", "account"],
        )
        .unwrap_or_else(|| "Unknown account".to_string()),
        safe_name: audit_string(recording, &["SafeName", "safeName", "Safe", "safe"])
            .unwrap_or_else(|| "Unknown safe".to_string()),
        username: audit_string(
            recording,
            &[
                "User",
                "user",
                "Username",
                "username",
                "AccountUsername",
                "accountUsername",
            ],
        )
        .unwrap_or_default(),
        address: audit_string(
            recording,
            &[
                "Address",
                "address",
                "RemoteMachine",
                "remoteMachine",
                "Target",
                "target",
            ],
        )
        .unwrap_or_default(),
        platform_id: audit_string(
            recording,
            &["PlatformID", "platformId", "Platform", "platform"],
        )
        .unwrap_or_default(),
        detail: if detail.trim().is_empty() {
            audit_string(recording, &["Status", "status"])
                .unwrap_or_else(|| "PSM recording indicates failure.".to_string())
        } else {
            detail.trim().to_string()
        },
    }
}

fn normalize_failure_label(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return "Unknown failure".to_string();
    }
    let compact = trimmed.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.len() > 96 {
        format!("{}...", &compact[..96])
    } else {
        compact
    }
}

async fn load_identity_user_activity(
    client: &reqwest::Client,
    tenant: &TenantConfig,
    identity_token: &RuntimeToken,
    active_since: DateTime<Utc>,
    recently_inactive_since: DateTime<Utc>,
    long_inactive_before: DateTime<Utc>,
) -> Result<
    (
        Vec<UserTelemetryItem>,
        Vec<UserTelemetryItem>,
        Vec<UserTelemetryItem>,
    ),
    String,
> {
    let identity_host = identity_tenant_host(tenant);
    if identity_host.trim().is_empty() {
        return Err("Active tenant is missing an Identity host.".to_string());
    }

    let count = 200_i64;
    let mut start_index = 1_i64;
    let mut active_users = Vec::new();
    let mut recently_inactive_users = Vec::new();
    let mut long_inactive_users = Vec::new();

    for _ in 0..50 {
        let url =
            format!("https://{identity_host}/scim/Users?startIndex={start_index}&count={count}");
        let response = client
            .get(&url)
            .bearer_auth(&identity_token.access_token)
            .header("X-IDAP-NATIVE-CLIENT", "true")
            .send()
            .await
            .map_err(error_to_string)?;
        let status = response.status();
        let body = response.text().await.map_err(error_to_string)?;
        if !status.is_success() {
            return Err(format!(
                "Identity active-user scan failed: HTTP {} from {}\n{}",
                status.as_u16(),
                url,
                pretty_json_or_text(&body)
            ));
        }
        let parsed: Value = serde_json::from_str(&body).map_err(|error| {
            format!(
                "Identity active-user response could not be parsed: {} from {}\n{}",
                error,
                url,
                pretty_json_or_text(&body)
            )
        })?;
        let rows = parsed
            .get("Resources")
            .or_else(|| parsed.get("resources"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if rows.is_empty() {
            break;
        }
        for user in rows {
            let username = audit_string(&user, &["userName", "username", "UserName"])
                .unwrap_or_else(|| "Unknown user".to_string());
            let display_name = audit_string(&user, &["displayName", "name", "DisplayName"])
                .unwrap_or_else(|| username.clone());
            let last_seen_raw = identity_last_seen_value(&user);
            let last_seen = last_seen_raw
                .clone()
                .unwrap_or_else(|| "Never logged in".to_string());
            let item = UserTelemetryItem {
                username,
                display_name,
                source: "Identity".to_string(),
                last_seen: last_seen.clone(),
                detail: if user.get("active").and_then(Value::as_bool) == Some(false) {
                    "Identity user is disabled.".to_string()
                } else {
                    "Identity user activity.".to_string()
                },
            };
            match last_seen_raw.as_deref().and_then(parse_identity_time) {
                Some(timestamp) if timestamp >= active_since => active_users.push(item),
                Some(timestamp)
                    if timestamp >= recently_inactive_since && timestamp < active_since =>
                {
                    recently_inactive_users.push(item)
                }
                Some(timestamp) if timestamp < long_inactive_before => {
                    long_inactive_users.push(item)
                }
                None => long_inactive_users.push(item),
                _ => {}
            }
        }

        let total_results = parsed
            .get("totalResults")
            .or_else(|| parsed.get("TotalResults"))
            .and_then(Value::as_i64)
            .unwrap_or_default();
        start_index += count;
        if total_results > 0 && start_index > total_results {
            break;
        }
    }

    active_users.sort_by(|left, right| left.username.cmp(&right.username));
    recently_inactive_users.sort_by(|left, right| left.username.cmp(&right.username));
    long_inactive_users.sort_by(|left, right| left.username.cmp(&right.username));
    Ok((active_users, recently_inactive_users, long_inactive_users))
}

fn identity_last_seen_value(user: &Value) -> Option<String> {
    audit_string(
        user,
        &[
            "lastLogin",
            "lastLoginDate",
            "lastSuccessfulLogin",
            "lastLoginTime",
            "LastLogin",
            "LastLoginDate",
            "LastSuccessfulLogin",
            "LastLoginTime",
        ],
    )
    .or_else(|| {
        user.as_object().and_then(|object| {
            object.values().find_map(|value| {
                if value.is_object() {
                    identity_last_seen_value(value)
                } else {
                    None
                }
            })
        })
    })
}

fn parse_identity_time(value: &str) -> Option<DateTime<Utc>> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("never") {
        return None;
    }
    if let Ok(epoch) = trimmed.parse::<i64>() {
        let seconds = if epoch > 10_000_000_000 {
            epoch / 1000
        } else {
            epoch
        };
        return DateTime::from_timestamp(seconds, 0);
    }
    DateTime::parse_from_rfc3339(trimmed)
        .map(|value| value.with_timezone(&Utc))
        .ok()
        .or_else(|| {
            DateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S")
                .map(|value| value.with_timezone(&Utc))
                .ok()
        })
}

fn connection_component_from_recording_row(row: &Value) -> Option<(String, String)> {
    let component = audit_string(
        row,
        &[
            "ConnectionComponent",
            "connectionComponent",
            "ConnectionComponentID",
            "connectionComponentId",
            "Client",
            "client",
            "Protocol",
            "protocol",
        ],
    )
    .unwrap_or_default();
    let protocol = audit_string(row, &["Protocol", "protocol"]).unwrap_or_default();
    let client = audit_string(row, &["Client", "client"]).unwrap_or_default();

    let normalized_component = if !component.trim().is_empty() {
        component.trim().to_string()
    } else if !client.trim().is_empty() {
        client.trim().to_string()
    } else if !protocol.trim().is_empty() {
        protocol.trim().to_string()
    } else {
        "Unknown PSM component".to_string()
    };

    Some((normalized_component, protocol.trim().to_string()))
}

fn audit_string(row: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| row.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn migrate_profile_secrets(config: &mut StoredConfig) -> Result<bool> {
    let mut changed = false;
    for profile in &mut config.profiles {
        let normalized_type = normalized_profile_auth_type(&profile.auth_type);
        if profile.auth_type != normalized_type {
            profile.auth_type = normalized_type;
            changed = true;
        }
        if !profile.client_secret.trim().is_empty() {
            store_profile_secret(&profile.id, &profile.client_secret)?;
            profile.client_secret.clear();
            profile.client_secret_stored = true;
            changed = true;
        } else if profile.client_secret_stored {
            profile.client_secret_stored = profile_secret_exists(&profile.id);
            changed = true;
        }
    }
    Ok(changed)
}

fn validate_passcode(passcode: &str) -> Result<(), String> {
    let trimmed = passcode.trim();
    if trimmed.len() < 8 {
        return Err("Passcode must be at least 8 characters.".to_string());
    }
    if !trimmed.chars().any(|char| char.is_ascii_uppercase()) {
        return Err("Passcode must include at least one uppercase letter.".to_string());
    }
    if !trimmed.chars().any(|char| char.is_ascii_lowercase()) {
        return Err("Passcode must include at least one lowercase letter.".to_string());
    }
    if !trimmed.chars().any(|char| char.is_ascii_digit()) {
        return Err("Passcode must include at least one number.".to_string());
    }
    Ok(())
}

fn session_passcode_entry() -> Result<Entry> {
    Entry::new("com.fastpas.client.session", "passcode")
        .context("failed to open session passcode entry in the OS keychain")
}

fn store_session_passcode(passcode: &str) -> Result<()> {
    session_passcode_entry()?
        .set_password(passcode)
        .context("failed to store session passcode in the OS keychain")
}

fn load_session_passcode() -> Result<String> {
    session_passcode_entry()?
        .get_password()
        .context("session passcode is not available in the OS keychain")
}

fn session_passcode_exists() -> bool {
    load_session_passcode().is_ok()
}

fn profile_secret_entry(profile_id: &str) -> Result<Entry> {
    Entry::new("com.fastpas.client", profile_id).context("failed to open OS keychain entry")
}

fn store_profile_secret(profile_id: &str, client_secret: &str) -> Result<()> {
    profile_secret_entry(profile_id)?
        .set_password(client_secret)
        .context("failed to store client secret in OS keychain")
}

fn load_profile_secret(profile_id: &str) -> Result<String> {
    profile_secret_entry(profile_id)?
        .get_password()
        .context("client secret is not available in the OS keychain")
}

fn tenant_audit_api_key_entry(tenant_id: &str) -> Result<Entry> {
    Entry::new("com.fastpas.client.audit", tenant_id).context("failed to open OS keychain entry")
}

fn store_tenant_audit_api_key(tenant_id: &str, api_key: &str) -> Result<()> {
    tenant_audit_api_key_entry(tenant_id)?
        .set_password(api_key)
        .context("failed to store Audit API key in OS keychain")
}

fn delete_tenant_audit_api_key(tenant_id: &str) -> Result<()> {
    match tenant_audit_api_key_entry(tenant_id)?.delete_credential() {
        Ok(_) => Ok(()),
        Err(error) => {
            let message = error.to_string();
            if message.contains("NoEntry") || message.contains("no matching entry") {
                Ok(())
            } else {
                Err(anyhow!(error).context("failed to remove Audit API key from OS keychain"))
            }
        }
    }
}

fn delete_profile_secret(profile_id: &str) -> Result<()> {
    match profile_secret_entry(profile_id)?.delete_credential() {
        Ok(_) => Ok(()),
        Err(error) => {
            let message = error.to_string();
            if message.contains("NoEntry") || message.contains("no matching entry") {
                Ok(())
            } else {
                Err(anyhow!(error).context("failed to remove client secret from OS keychain"))
            }
        }
    }
}

fn profile_secret_exists(profile_id: &str) -> bool {
    load_profile_secret(profile_id).is_ok()
}

fn clean_subdomain(value: &str) -> String {
    value
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .split('.')
        .next()
        .unwrap_or_default()
        .to_string()
}

fn confirm_os_keychain_access() -> Result<()> {
    let _ = session_passcode_entry()?.get_password();
    Ok(())
}

fn enforce_unlock_rate_limit(session: &mut SessionState) -> Result<(), String> {
    let now = now_millis();
    if session.unlock_blocked_until > now {
        let wait_seconds = ((session.unlock_blocked_until - now) / 1000).max(1);
        return Err(format!(
            "Too many failed passcode attempts. Try again in {} seconds.",
            wait_seconds
        ));
    }
    if session.unlock_blocked_until != 0 && session.unlock_blocked_until <= now {
        session.unlock_blocked_until = 0;
        session.failed_unlock_attempts = 0;
    }
    Ok(())
}

fn register_failed_unlock_attempt(session: &mut SessionState) {
    session.failed_unlock_attempts = session.failed_unlock_attempts.saturating_add(1);
    if session.failed_unlock_attempts >= 5 {
        session.unlock_blocked_until = now_millis() + 5 * 60 * 1000;
    }
}

fn unlock_error_message(session: &SessionState) -> String {
    if session.unlock_blocked_until > now_millis() {
        let wait_seconds = ((session.unlock_blocked_until - now_millis()) / 1000).max(1);
        format!(
            "Too many failed passcode attempts. Try again in {} seconds.",
            wait_seconds
        )
    } else {
        "Passcode was incorrect.".to_string()
    }
}

fn tenant_subdomain(tenant: &TenantConfig) -> String {
    if !tenant.subdomain.trim().is_empty() {
        clean_subdomain(&tenant.subdomain)
    } else if !tenant.vault_api_base_url.trim().is_empty() {
        host_from_url(&tenant.vault_api_base_url)
            .and_then(|host| host.split('.').next().map(str::to_string))
            .unwrap_or_default()
    } else {
        clean_subdomain(&tenant.name)
    }
}

fn identity_tenant_host(tenant: &TenantConfig) -> String {
    if !tenant.identity_tenant_host.trim().is_empty() {
        clean_host(&tenant.identity_tenant_host)
    } else if !tenant.identity_oauth_url.trim().is_empty() {
        host_from_url(&tenant.identity_oauth_url).unwrap_or_default()
    } else if !tenant.platform_token_url.trim().is_empty() {
        host_from_url(&tenant.platform_token_url).unwrap_or_default()
    } else {
        let subdomain = tenant_subdomain(tenant);
        if subdomain.is_empty() {
            String::new()
        } else {
            format!("{subdomain}.id.cyberark.cloud")
        }
    }
}

fn identity_token_url(profile: &OAuthProfile, tenant: &TenantConfig) -> String {
    let identity_host = identity_host_for_profile(profile, tenant);
    if is_interactive_profile(profile) && !identity_host.is_empty() {
        return format!("https://{identity_host}/oauth2/token");
    }
    let application_id = profile.application_id.trim();
    if !identity_host.is_empty() && !application_id.is_empty() {
        format!("https://{identity_host}/oauth2/token/{application_id}")
    } else {
        tenant.identity_oauth_url.clone()
    }
}

fn identity_host_for_profile(profile: &OAuthProfile, tenant: &TenantConfig) -> String {
    if !profile.identity_tenant_host.trim().is_empty() {
        clean_host(&profile.identity_tenant_host)
    } else if !profile.subdomain.trim().is_empty() {
        format!("{}.id.cyberark.cloud", clean_subdomain(&profile.subdomain))
    } else {
        identity_tenant_host(tenant)
    }
}

#[allow(clippy::too_many_arguments)]
async fn apply_interactive_advance(
    config: &StoredConfig,
    session: &tauri::State<'_, Mutex<SessionState>>,
    client: &reqwest::Client,
    advance_url: &str,
    profile: &OAuthProfile,
    tenant: &TenantConfig,
    session_id: &str,
    request_payload: &serde_json::Value,
) -> Result<InteractiveAuthResult, String> {
    let requested_action = request_payload
        .get("Action")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string();
    let requested_mechanism_id = request_payload
        .get("MechanismId")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string();
    let advance_response = client
        .post(advance_url)
        .header(CONTENT_TYPE, "application/json")
        .header("X-IDAP-NATIVE-CLIENT", "true")
        .json(request_payload)
        .send()
        .await
        .map_err(error_to_string)?;
    let advance_status = advance_response.status();
    let advance_text = advance_response.text().await.map_err(error_to_string)?;
    let advance_json: serde_json::Value = serde_json::from_str(&advance_text).map_err(|error| {
        format!(
            "AdvanceAuthentication response could not be parsed: {} from {}\n{}",
            error, advance_url, advance_text
        )
    })?;
    if !advance_status.is_success() {
        let preview = serde_json::to_string_pretty(&advance_json).unwrap_or(advance_text.clone());
        return Err(format!(
            "AdvanceAuthentication failed: HTTP {} from {}\n{}",
            advance_status.as_u16(),
            advance_url,
            preview
        ));
    }

    let summary = advance_json
        .pointer("/Result/Summary")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string();
    let api_success = advance_json
        .get("success")
        .and_then(|value| value.as_bool())
        .unwrap_or(true);
    let api_message = advance_json
        .get("Message")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string();
    let api_error_id = advance_json
        .get("ErrorID")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string();

    let working_json = advance_json.clone();
    let working_summary = summary.clone();
    let working_api_success = api_success;
    let working_api_message = api_message.clone();
    let working_api_error_id = api_error_id.clone();

    let mut guard = session
        .lock()
        .map_err(|_| "session state poisoned".to_string())?;

    if working_api_success && working_summary.eq_ignore_ascii_case("OobPending") {
        let prior_challenges = guard
            .interactive_auth
            .as_ref()
            .map(|item| item.pending_challenges.clone())
            .unwrap_or_default();
        let prior_index = guard
            .interactive_auth
            .as_ref()
            .map(|item| item.next_challenge_index)
            .unwrap_or(0);
        guard.interactive_auth = Some(InteractiveAuthSession {
            client: client.clone(),
            advance_url: advance_url.to_string(),
            session_id: session_id.to_string(),
            profile_id: profile.id.clone(),
            pending_challenges: prior_challenges,
            next_challenge_index: prior_index,
        });
        return Ok(InteractiveAuthResult {
            state: build_state_payload(config, &guard),
            authenticated: false,
            challenge: Some(InteractiveAuthChallenge {
                summary: "OobPending".to_string(),
                session_id: session_id.to_string(),
                mechanisms: vec![InteractiveAuthMechanism {
                    mechanism_id: requested_mechanism_id,
                    name: "Approval Pending".to_string(),
                    prompt: "Approval request was sent. FastPAS is polling automatically."
                        .to_string(),
                    answer_type: String::new(),
                    actions: vec!["Poll".to_string()],
                }],
            }),
            message: "Approval request sent. Waiting for approval.".to_string(),
        });
    }

    if !working_api_success {
        let prior_challenges = guard
            .interactive_auth
            .as_ref()
            .map(|item| item.pending_challenges.clone())
            .unwrap_or_default();
        let prior_index = guard
            .interactive_auth
            .as_ref()
            .map(|item| item.next_challenge_index)
            .unwrap_or(0);
        guard.interactive_auth = Some(InteractiveAuthSession {
            client: client.clone(),
            advance_url: advance_url.to_string(),
            session_id: session_id.to_string(),
            profile_id: profile.id.clone(),
            pending_challenges: prior_challenges,
            next_challenge_index: prior_index,
        });
        let mut details = if working_api_message.is_empty() {
            "Interactive challenge was rejected by CyberArk.".to_string()
        } else {
            format!("Interactive challenge failed: {}", working_api_message)
        };
        if !working_summary.is_empty() {
            details.push_str(&format!(" (Summary: {})", working_summary));
        }
        if !working_api_error_id.is_empty() {
            details.push_str(&format!(" [ErrorID: {}]", working_api_error_id));
        }
        if requested_action.eq_ignore_ascii_case("StartNextChallenge") {
            details.push_str(" Try selecting the returned mechanism and use Send/Submit actions instead of repeating StartNextChallenge.");
        }
        return Err(details);
    }

    let working_token_value = working_json
        .pointer("/Result/Token")
        .and_then(|value| value.as_str())
        .or_else(|| {
            working_json
                .pointer("/Result/Auth")
                .and_then(|value| value.as_str())
        })
        .unwrap_or_default()
        .to_string();

    if !working_token_value.trim().is_empty() {
        let interactive_token = RuntimeToken {
            access_token: working_token_value,
            token_type: "Bearer".to_string(),
            expires_at: now_millis() + (900 * 1000),
            source: format!("Interactive {} @ {}", profile.username, tenant.name),
            endpoint: advance_url.to_string(),
            invalidated: false,
        };
        guard.identity_token = Some(interactive_token.clone());
        guard.identity_client = Some(client.clone());
        guard.platform_token = Some(interactive_token);
        guard.interactive_auth = None;
        return Ok(InteractiveAuthResult {
            state: build_state_payload(config, &guard),
            authenticated: true,
            challenge: None,
            message: "Interactive authentication succeeded.".to_string(),
        });
    }

    let challenge = extract_interactive_challenge(&working_json, session_id.to_string());
    if let Some(challenge) = challenge {
        guard.interactive_auth = Some(InteractiveAuthSession {
            client: client.clone(),
            advance_url: advance_url.to_string(),
            session_id: session_id.to_string(),
            profile_id: profile.id.clone(),
            pending_challenges: guard
                .interactive_auth
                .as_ref()
                .map(|item| item.pending_challenges.clone())
                .unwrap_or_default(),
            next_challenge_index: guard
                .interactive_auth
                .as_ref()
                .map(|item| item.next_challenge_index)
                .unwrap_or(0),
        });
        let message = if working_summary.is_empty() {
            "Interactive authentication requires another challenge.".to_string()
        } else {
            format!("Interactive authentication summary: {}.", working_summary)
        };
        return Ok(InteractiveAuthResult {
            state: build_state_payload(config, &guard),
            authenticated: false,
            challenge: Some(challenge),
            message,
        });
    }

    if working_summary.eq_ignore_ascii_case("StartNextChallenge") {
        let (next_mechanisms, next_index) = guard
            .interactive_auth
            .as_ref()
            .and_then(|auth| {
                auth.pending_challenges
                    .get(auth.next_challenge_index)
                    .cloned()
                    .map(|mechanisms| (mechanisms, auth.next_challenge_index + 1))
            })
            .unwrap_or_default();

        if !next_mechanisms.is_empty() {
            guard.interactive_auth = Some(InteractiveAuthSession {
                client: client.clone(),
                advance_url: advance_url.to_string(),
                session_id: session_id.to_string(),
                profile_id: profile.id.clone(),
                pending_challenges: guard
                    .interactive_auth
                    .as_ref()
                    .map(|item| item.pending_challenges.clone())
                    .unwrap_or_default(),
                next_challenge_index: next_index,
            });
            return Ok(InteractiveAuthResult {
                state: build_state_payload(config, &guard),
                authenticated: false,
                challenge: Some(InteractiveAuthChallenge {
                    summary: working_summary.clone(),
                    session_id: session_id.to_string(),
                    mechanisms: next_mechanisms,
                }),
                message:
                    "Interactive authentication requires the next challenge from the start package."
                        .to_string(),
            });
        }
    }

    let preview = serde_json::to_string_pretty(&working_json).unwrap_or(advance_text);
    Err(format!(
        "AdvanceAuthentication did not return a token or challenge from {}\n{}",
        advance_url, preview
    ))
}

fn extract_interactive_challenge(
    response: &serde_json::Value,
    fallback_session_id: String,
) -> Option<InteractiveAuthChallenge> {
    let summary = response
        .pointer("/Result/Summary")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string();
    let session_id = response
        .pointer("/Result/SessionId")
        .and_then(|value| value.as_str())
        .unwrap_or(&fallback_session_id)
        .to_string();
    let mechanisms = response
        .pointer("/Result/Challenges")
        .and_then(|value| value.as_array())
        .map(|challenges| {
            challenges
                .iter()
                .flat_map(|challenge| {
                    challenge
                        .get("Mechanisms")
                        .and_then(|value| value.as_array())
                        .cloned()
                        .unwrap_or_default()
                })
                .filter_map(|mechanism| {
                    let mechanism_id = mechanism
                        .get("MechanismId")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
                        .to_string();
                    if mechanism_id.is_empty() {
                        return None;
                    }
                    let name = mechanism
                        .get("Name")
                        .and_then(|value| value.as_str())
                        .unwrap_or("Unknown")
                        .to_string();
                    let prompt = mechanism
                        .get("PromptSelectMech")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let answer_type = mechanism
                        .get("AnswerType")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let actions =
                        merged_mechanism_actions(&mechanism, &name, &prompt, &answer_type);
                    Some(InteractiveAuthMechanism {
                        mechanism_id,
                        name,
                        prompt,
                        answer_type,
                        actions,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if mechanisms.is_empty() {
        None
    } else {
        Some(InteractiveAuthChallenge {
            summary,
            session_id,
            mechanisms,
        })
    }
}

fn extract_challenge_sets(response: &serde_json::Value) -> Vec<Vec<InteractiveAuthMechanism>> {
    response
        .pointer("/Result/Challenges")
        .and_then(|value| value.as_array())
        .map(|challenges| {
            challenges
                .iter()
                .map(|challenge| {
                    challenge
                        .get("Mechanisms")
                        .and_then(|value| value.as_array())
                        .cloned()
                        .unwrap_or_default()
                        .into_iter()
                        .filter_map(|mechanism| {
                            let mechanism_id = mechanism
                                .get("MechanismId")
                                .and_then(|value| value.as_str())
                                .unwrap_or_default()
                                .to_string();
                            if mechanism_id.is_empty() {
                                return None;
                            }
                            let name = mechanism
                                .get("Name")
                                .and_then(|value| value.as_str())
                                .unwrap_or("Unknown")
                                .to_string();
                            let prompt = mechanism
                                .get("PromptSelectMech")
                                .and_then(|value| value.as_str())
                                .unwrap_or_default()
                                .to_string();
                            let answer_type = mechanism
                                .get("AnswerType")
                                .and_then(|value| value.as_str())
                                .unwrap_or_default()
                                .to_string();
                            let actions =
                                merged_mechanism_actions(&mechanism, &name, &prompt, &answer_type);
                            Some(InteractiveAuthMechanism {
                                mechanism_id,
                                name,
                                prompt,
                                answer_type,
                                actions,
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn mechanism_actions(name: &str, prompt: &str, answer_type: &str) -> Vec<String> {
    let mut actions = Vec::<String>::new();
    let hint = format!(
        "{} {} {}",
        name.to_lowercase(),
        prompt.to_lowercase(),
        answer_type.to_lowercase()
    );
    if hint.contains("sms")
        || hint.contains("email")
        || hint.contains("text")
        || hint.contains("phone")
        || hint.contains("cell")
        || hint.contains("message")
    {
        actions.push("StartTextOob".to_string());
    }
    if hint.contains("mobile")
        || hint.contains("push")
        || hint.contains("oob")
        || hint.contains("app")
    {
        actions.push("StartOOB".to_string());
        actions.push("Poll".to_string());
    }
    if answer_type.eq_ignore_ascii_case("text")
        || answer_type.eq_ignore_ascii_case("numeric")
        || hint.contains("otp")
        || hint.contains("code")
        || hint.contains("answer")
    {
        actions.push("Answer".to_string());
    }
    if actions.is_empty() {
        actions.push("Answer".to_string());
        actions.push("Poll".to_string());
    }
    actions.sort();
    actions.dedup();
    actions
}

fn merged_mechanism_actions(
    mechanism: &serde_json::Value,
    name: &str,
    prompt: &str,
    answer_type: &str,
) -> Vec<String> {
    let mut actions = extract_actions_from_mechanism(mechanism).unwrap_or_default();
    actions.extend(mechanism_actions(name, prompt, answer_type));
    actions.sort();
    actions.dedup();
    actions
}

fn extract_actions_from_mechanism(mechanism: &serde_json::Value) -> Option<Vec<String>> {
    let raw_actions = mechanism.get("Actions")?.as_array()?;
    let mut actions = raw_actions
        .iter()
        .filter_map(|action| {
            if let Some(value) = action.as_str() {
                return Some(value.to_string());
            }
            action
                .get("Name")
                .and_then(|value| value.as_str())
                .map(str::to_string)
        })
        .filter(|value| !value.trim().is_empty())
        .collect::<Vec<_>>();
    actions.sort();
    actions.dedup();
    if actions.is_empty() {
        None
    } else {
        Some(actions)
    }
}

fn find_password_mechanism_id(response: &serde_json::Value) -> Option<String> {
    response
        .pointer("/Result/Challenges")
        .and_then(|value| value.as_array())
        .and_then(|challenges| {
            challenges.iter().find_map(|challenge| {
                challenge
                    .get("Mechanisms")
                    .and_then(|value| value.as_array())
                    .and_then(|mechanisms| {
                        mechanisms
                            .iter()
                            .find(|mechanism| {
                                mechanism.get("Name").and_then(|value| value.as_str()) == Some("UP")
                            })
                            .or_else(|| {
                                mechanisms.iter().find(|mechanism| {
                                    mechanism
                                        .get("PromptSelectMech")
                                        .and_then(|value| value.as_str())
                                        .unwrap_or_default()
                                        .to_lowercase()
                                        .contains("password")
                                })
                            })
                            .or_else(|| {
                                mechanisms.iter().find(|mechanism| {
                                    mechanism.get("AnswerType").and_then(|value| value.as_str())
                                        == Some("Text")
                                })
                            })
                            .and_then(|mechanism| {
                                mechanism
                                    .get("MechanismId")
                                    .and_then(|value| value.as_str())
                                    .map(str::to_string)
                            })
                    })
            })
        })
}

fn default_profile_auth_type() -> String {
    "oauth".to_string()
}

fn normalized_profile_auth_type(value: &str) -> String {
    if value.trim().eq_ignore_ascii_case("interactive") {
        "interactive".to_string()
    } else {
        "oauth".to_string()
    }
}

fn is_interactive_profile(profile: &OAuthProfile) -> bool {
    profile.auth_type == "interactive"
}

fn clean_host(value: &str) -> String {
    host_from_url(value).unwrap_or_else(|| {
        value
            .trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_string()
    })
}

fn host_from_url(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    reqwest::Url::parse(value)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .or_else(|| Some(value.trim_matches('/').to_string()))
}

async fn discover_identity_tenant_host(subdomain: &str) -> Option<String> {
    let client = reqwest::Client::builder()
        .user_agent("FastPAS/0.1.0")
        .redirect(reqwest::redirect::Policy::limited(10))
        .timeout(std::time::Duration::from_secs(6))
        .build()
        .ok()?;

    let candidates = [
        format!("https://{subdomain}.cyberark.cloud"),
        format!("https://{subdomain}-userportal.cyberark.cloud"),
        format!("https://{subdomain}.privilegecloud.cyberark.cloud"),
    ];

    for candidate in candidates {
        if let Some(host) = discover_identity_tenant_host_from_candidate(&client, &candidate).await
        {
            return Some(host);
        }
    }

    None
}

async fn discover_identity_tenant_host_from_candidate(
    client: &reqwest::Client,
    candidate: &str,
) -> Option<String> {
    let response = client.get(candidate).send().await.ok()?;

    if let Some(host) = response.url().host_str().and_then(match_identity_host) {
        return Some(host.into_owned());
    }

    let body = response.text().await.ok()?;
    for capture in body
        .split(|ch: char| ch.is_whitespace() || ch == '"' || ch == '\'' || ch == '<' || ch == '>')
    {
        if let Some(host) = match_identity_host(capture) {
            return Some(host.into_owned());
        }
    }

    None
}

fn match_identity_host(value: &str) -> Option<Cow<'_, str>> {
    let value = value.trim_matches(|ch| ch == '/' || ch == '"' || ch == '\'');
    if value.ends_with(".id.cyberark.cloud") || value.ends_with(".my.idaptive.app") {
        Some(Cow::Borrowed(value))
    } else {
        None
    }
}

pub fn run() {
    tauri::Builder::default()
        .manage(Mutex::new(SessionState::default()))
        .invoke_handler(tauri::generate_handler![
            get_app_state,
            configure_session_passcode,
            unlock_session,
            lock_session,
            update_session_passcode,
            save_profile,
            update_profile_secret,
            delete_profile,
            set_active_profile,
            save_tenant,
            delete_tenant,
            set_active_tenant,
            request_identity_token,
            request_platform_token,
            copy_runtime_token,
            authenticate_interactive_user,
            advance_interactive_authentication,
            execute_vault_request,
            get_connection_component_telemetry,
            get_account_failure_telemetry,
            remediate_account_failures,
            get_active_user_telemetry,
            clear_tokens,
            export_config,
            save_text_file,
            import_config,
            resolve_tenant
        ])
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let config = load_config(&app.handle()).unwrap_or_default();
            let session_state = app.state::<Mutex<SessionState>>();
            let mut session = session_state
                .lock()
                .map_err(|_| anyhow!("session state poisoned"))?;
            session.active_profile_id = config
                .active_profile_id
                .clone()
                .or_else(|| config.profiles.first().map(|item| item.id.clone()));
            session.active_tenant_id = config
                .active_tenant_id
                .clone()
                .or_else(|| config.tenants.first().map(|item| item.id.clone()));
            session.session_locked = session_passcode_exists();
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("failed to run FastPAS");
}
