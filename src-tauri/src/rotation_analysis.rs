use chrono::{DateTime, Utc};
use serde_json::{json, Value};

fn audit_string(row: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| row.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn timestamp(value: Option<&Value>, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let value = value?;
    let parsed = value
        .as_i64()
        .or_else(|| value.as_str()?.parse().ok())
        .and_then(|n| {
            if n > 0 {
                DateTime::from_timestamp(n, 0)
            } else {
                None
            }
        })
        .or_else(|| {
            value
                .as_str()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.with_timezone(&Utc))
        })?;
    if parsed > now {
        None
    } else {
        Some(parsed)
    }
}

pub(crate) fn classify_account(
    account: &Value,
    failures: Option<&Vec<String>>,
    threshold: u32,
    now: DateTime<Utc>,
) -> Value {
    let management = account.get("secretManagement").unwrap_or(&Value::Null);
    let enabled = management
        .get("automaticManagementEnabled")
        .and_then(Value::as_bool);
    let status = audit_string(management, &["status"]).unwrap_or_default();
    let reason = audit_string(
        management,
        &[
            "manualManagementReason",
            "failureReason",
            "lastTaskFailureReason",
        ],
    )
    .unwrap_or_default();
    let modified = timestamp(management.get("lastModifiedTime"), now);
    let reconciled = timestamp(management.get("lastReconciledTime"), now);
    let reported = modified.into_iter().chain(reconciled).max();
    let age = reported.map(|time| (now - time).num_days());
    let mut issues = failures.cloned().unwrap_or_default();
    if enabled == Some(false) {
        issues.push("Automatic management disabled".into());
    }
    if enabled.is_none() {
        issues.push("Management setting unknown".into());
    }
    if status.eq_ignore_ascii_case("failure") && failures.map(|f| f.is_empty()).unwrap_or(true) {
        issues.push("Management failed — operation unknown".into());
    }
    if reported
        .map(|t| (now - t).num_seconds() > threshold as i64 * 86400)
        .unwrap_or(false)
    {
        issues.push("Reported age exceeds threshold".into());
    }
    let failure_detail = audit_string(management, &["failureReason", "lastTaskFailureReason"]);
    if status.eq_ignore_ascii_case("failure") || failures.map(|f| !f.is_empty()).unwrap_or(false) {
        if let Some(error) = failure_detail {
            let error = error.to_ascii_lowercase();
            for (needles, label) in [
                (
                    vec![
                        "timeout",
                        "timed out",
                        "connection refused",
                        "unreachable",
                        "resolve host",
                    ],
                    "Reported connectivity failure",
                ),
                (
                    vec![
                        "access denied",
                        "permission denied",
                        "insufficient privilege",
                    ],
                    "Reported permission failure",
                ),
                (
                    vec![
                        "authentication failed",
                        "logon failure",
                        "invalid credentials",
                    ],
                    "Reported authentication failure",
                ),
                (
                    vec!["password policy", "complexity", "password history"],
                    "Reported password-policy rejection",
                ),
                (
                    vec!["dependency", "dependent account"],
                    "Reported dependency failure",
                ),
            ] {
                if needles.iter().any(|n| error.contains(n)) {
                    issues.push(label.into());
                }
            }
        }
    }
    if reported.is_none() {
        issues.push("Rotation history unavailable".into());
    }
    // Confirmation is a separate coverage limitation, not a failure assigned to every account.
    json!({"account_id": audit_string(account, &["id", "ID"]).unwrap_or_default(),
        "name": audit_string(account, &["name"]).unwrap_or_default(),
        "safe_name": audit_string(account, &["safeName"]).unwrap_or_default(),
        "username": audit_string(account, &["userName"]).unwrap_or_default(),
        "address": audit_string(account, &["address"]).unwrap_or_default(),
        "platform_id": platform_id(account).unwrap_or("Platform assignment unavailable".into()),
        "automatic_management_enabled": enabled, "status": status, "detail": reason,
        "reported_change_time": reported.map(|t| t.to_rfc3339()), "reported_age_days": age,
        "age_evidence": "Management metadata only; successful target rotation unconfirmed", "issues": issues})
}

pub(crate) fn platform_id(account: &Value) -> Option<String> {
    audit_string(
        account,
        &["platformId", "platformID", "PlatformID", "PlatformId"],
    )
}

pub(crate) fn finding(level: &str, title: &str, evidence: &str) -> Value {
    json!({"level": level, "title": title, "evidence": evidence})
}

fn settings(value: &Value, path: &str, result: &mut Vec<(String, String, Value)>) {
    match value {
        Value::Object(map) => {
            // Some platform APIs represent INI properties as Key/Value or Name/Value pairs.
            let property_name = map
                .get("Key")
                .or_else(|| map.get("Name"))
                .or_else(|| map.get("key"))
                .or_else(|| map.get("name"))
                .and_then(Value::as_str);
            let property_value = map.get("Value").or_else(|| map.get("value"));
            if let (Some(name), Some(value)) = (property_name, property_value) {
                if !value.is_object() && !value.is_array() {
                    result.push((name.into(), format!("{path}/{name}"), value.clone()));
                }
            }
            for (key, value) in map {
                let next = format!("{path}/{key}");
                if !value.is_object() && !value.is_array() {
                    result.push((key.clone(), next.clone(), value.clone()));
                }
                settings(value, &next, result);
            }
        }
        Value::Array(array) => {
            for (i, item) in array.iter().enumerate() {
                settings(item, &format!("{path}/{i}"), result);
            }
        }
        _ => (),
    }
}

pub(crate) fn platform_findings(platform: &Value) -> Vec<Value> {
    let mut fields = Vec::new();
    settings(platform, "", &mut fields);
    let mut findings = Vec::new();
    if platform
        .get("Active")
        .or_else(|| platform.get("active"))
        .and_then(Value::as_bool)
        == Some(false)
    {
        findings.push(finding(
            "Confirmed setting",
            "Platform inactive",
            "Platform API reports Active = false. Review effective policy and relevant exceptions.",
        ));
    }
    for (key, title) in [
        ("PerformPeriodicChange", "Periodic password change disabled"),
        ("PerformChangeTask", "Password change processing disabled"),
        (
            "PerformPeriodicVerification",
            "Periodic verification disabled",
        ),
        ("PerformVerifyTask", "Verification processing disabled"),
        (
            "AutomaticReconcileWhenUnsynched",
            "Automatic reconciliation when unsynchronized disabled",
        ),
        ("PerformReconcileTask", "Reconciliation processing disabled"),
    ] {
        let matches: Vec<_> = fields
            .iter()
            .filter(|(name, _, _)| name.eq_ignore_ascii_case(key))
            .collect();
        if matches.is_empty() {
            findings.push(finding(
                "Unknown",
                &format!("{key} not exposed"),
                "Missing settings are not treated as enabled or disabled.",
            ));
        }
        for (_, path, value) in matches {
            let disabled = value == &Value::Bool(false)
                || value
                    .as_str()
                    .map(|s| s.eq_ignore_ascii_case("no") || s.eq_ignore_ascii_case("false"))
                    .unwrap_or(false);
            if disabled {
                findings.push(finding(
                    "Confirmed setting",
                    title,
                    &format!("{path} = {value}. Relevance depends on the platform workflow."),
                ));
            }
        }
    }
    for (key, path, value) in &fields {
        if [
            "FromHour",
            "ToHour",
            "ExecutionDays",
            "ReconcileAccountSafe",
            "ReconcileAccountName",
            "ReconcileAccountFolder",
            "PasswordChangeInterval",
            "MinValidityPeriod",
        ]
        .iter()
        .any(|k| key.eq_ignore_ascii_case(k))
        {
            findings.push(finding("Review", "Schedule or credential configuration", &format!("{path} = {value}. Review effective policy, scheduling, and account-level overrides; this setting alone does not prove a cause.")));
        }
        if ["ReconcileAccountSafe", "ReconcileAccountName"]
            .iter()
            .any(|k| key.eq_ignore_ascii_case(k))
            && value.as_str() == Some("")
        {
            findings.push(finding("Review", "Platform reconciliation credential setting is empty", &format!("{path} is empty. An account-level association may override this; only an effective missing credential blocks workflows that require reconciliation.")));
        }
    }
    findings.push(finding("Unknown", "Effective policy and linked credentials require further inspection", "No effective rotation interval or missing reconciliation credential is inferred from omitted fields. SRS engine attribution is unconfirmed unless exposed by tenant-specific APIs."));
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn verification_and_property_edits_do_not_reset_age() {
        let now = DateTime::from_timestamp(2_000_000_000, 0).unwrap();
        let account = json!({"categoryModificationTime": now.timestamp(), "secretManagement": {
            "automaticManagementEnabled": true, "lastModifiedTime": now.timestamp() - 101*86400,
            "lastVerifiedTime": now.timestamp() }});
        let row = classify_account(&account, None, 100, now);
        assert_eq!(row["reported_age_days"], 101);
        assert!(row["issues"]
            .as_array()
            .unwrap()
            .contains(&json!("Reported age exceeds threshold")));
    }
    #[test]
    fn unknown_and_future_dates_are_not_healthy() {
        let now = Utc::now();
        let row = classify_account(
            &json!({"secretManagement": {"lastModifiedTime": now.timestamp()+86400}}),
            None,
            100,
            now,
        );
        assert!(row["reported_age_days"].is_null());
        assert!(row["issues"]
            .as_array()
            .unwrap()
            .contains(&json!("Rotation history unavailable")));
    }
    #[test]
    fn disabled_is_not_automatically_a_failed_operation() {
        let row = classify_account(
            &json!({"secretManagement": {"automaticManagementEnabled": false,
            "manualManagementReason": "Approved exception"}}),
            None,
            100,
            Utc::now(),
        );
        assert!(!row["issues"]
            .as_array()
            .unwrap()
            .contains(&json!("Management failed — operation unknown")));
    }
    #[test]
    fn overlapping_failures_preserve_evidence_without_secrets() {
        let row = classify_account(
            &json!({"secret": "never-export", "secretManagement": {"status": "failure"}}),
            Some(&vec!["Change failed".into(), "Reconcile failed".into()]),
            100,
            Utc::now(),
        );
        assert!(!row.to_string().contains("never-export"));
        assert!(row["issues"]
            .as_array()
            .unwrap()
            .contains(&json!("Reconcile failed")));
    }
    #[test]
    fn missing_platform_settings_do_not_become_confirmed_failures() {
        let findings = platform_findings(&json!({}));
        assert!(findings.iter().all(|f| f["level"] != "Confirmed setting"));
        let findings = platform_findings(&json!({"Details": {"PerformPeriodicChange": "No"}}));
        assert!(findings.iter().any(|f| f["level"] == "Confirmed setting"));
    }
    #[test]
    fn age_threshold_is_strict_even_for_partial_days() {
        let now = Utc::now();
        let account = |seconds| json!({"secretManagement": {"automaticManagementEnabled": true, "lastModifiedTime": now.timestamp()-seconds}});
        let exact = classify_account(&account(100 * 86400), None, 100, now);
        let over = classify_account(&account(100 * 86400 + 1), None, 100, now);
        assert!(!exact["issues"]
            .as_array()
            .unwrap()
            .contains(&json!("Reported age exceeds threshold")));
        assert!(over["issues"]
            .as_array()
            .unwrap()
            .contains(&json!("Reported age exceeds threshold")));
    }
    #[test]
    fn property_pairs_and_inactive_platform_are_supported() {
        let findings = platform_findings(
            &json!({"Active": false, "Properties": [{"Key": "PerformChangeTask", "Value": "No"}]}),
        );
        assert_eq!(
            findings
                .iter()
                .filter(|f| f["level"] == "Confirmed setting")
                .count(),
            2
        );
    }
    #[test]
    fn failure_detail_is_classified_but_manual_notes_are_not() {
        let now = Utc::now();
        let failed = classify_account(
            &json!({"secretManagement": {"status": "failure", "failureReason": "Permission denied"}}),
            None,
            100,
            now,
        );
        assert!(failed["issues"]
            .as_array()
            .unwrap()
            .contains(&json!("Reported permission failure")));
        let disabled = classify_account(
            &json!({"secretManagement": {"automaticManagementEnabled": false, "manualManagementReason": "Permission denied exception"}}),
            None,
            100,
            now,
        );
        assert!(!disabled["issues"]
            .as_array()
            .unwrap()
            .contains(&json!("Reported permission failure")));
    }
}
