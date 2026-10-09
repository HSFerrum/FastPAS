const escape = value => String(value ?? "").replace(/[&<>"']/g, char => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[char]));
const number = value => Number.isFinite(Number(value)) ? Math.max(0, Number(value)) : 0;
const date = value => value && !Number.isNaN(Date.parse(value)) ? new Date(value).toLocaleString("en-US", {timeZone: "UTC", dateStyle: "medium", timeStyle: "short"}) + " UTC" : "Not available";
const issueBuckets = [
  [/Automatic management disabled/i, "Automatic management disabled", 1, "Restore management for approved accounts after reviewing the disablement reasons."],
  [/Account not managed by CPM/i, "Accounts outside CPM management", 1, "Confirm the account should be CPM-managed, then restore management after resolving its disablement reason."],
  [/Assigned platform unavailable/i, "Assigned platform is unavailable", 1, "Assign an active, supported platform before attempting another management operation."],
  [/Password change action disabled/i, "Password changes disabled for affected accounts", 1, "Review the returned disablement reason and effective policy before enabling password changes."],
  [/Reconciliation action disabled/i, "Reconciliation disabled for failed accounts", 1, "Resolve the returned disablement reason and recovery-account requirements before another reconciliation."],
  [/authentication failure/i, "Credentials rejected by the target", 1, "Validate the stored or recovery credential and the target authentication path."],
  [/permission failure/i, "Insufficient target permissions", 1, "Correct the CPM or recovery identity permissions before retrying management."],
  [/connectivity failure/i, "Target connectivity failures", 1, "Restore name resolution, network access, and target service availability."],
  [/password-policy rejection/i, "Target password-policy rejection", 1, "Align the generated credential with the target password requirements."],
  [/dependency failure/i, "Dependent-account failures", 1, "Resolve the dependent account workflow and retry after the primary credential is healthy."],
  [/Platform policy failure/i, "Platform policy failures", 1, "Review the platform policy and the account's applicable policy exceptions."],
  [/Reconcile failed/i, "Reconciliation failures", 1, "Validate the recovery-account association, safe access, and target reset permissions."],
  [/Change failed/i, "Password-change failures", 1, "Review the original change error, target access, and password requirements."],
  [/Management failed/i, "Unclassified management failures", 1, "Use CyberArk activity history to identify the failed operation and original cause."],
  [/Verification failed/i, "Verification failures", 2, "Determine whether the stored credential matches the target before requesting another change."],
  [/Verification action disabled/i, "Verification disabled for failed accounts", 2, "Review the returned disablement reason before relying on verification for these accounts."],
  [/Last successful change exceeds threshold/i, "Credentials past the successful-change threshold", 2, "Address the oldest accounts first using the last successful change reported by CyberArk compliance data."],
  [/Reported age exceeds threshold/i, "Credentials above the reported-age threshold", 2, "Confirm authoritative rotation history, then address the oldest eligible credentials first."],
  [/No management activity timestamp above threshold/i, "Old accounts without management activity", 2, "Confirm whether these accounts have ever been managed, then validate their policy eligibility and activity history."]
];

function insightAccountKey(account, platformId) { return `${platformId || account.platform_id || ""}/${account.account_id || account.name || "unknown"}`; }

export function rotationIssueBucket(issue) {
  const match = issueBuckets.find(([pattern]) => pattern.test(issue || ""));
  return match ? {label: match[1], priority: match[2], next_step: match[3]} : {label: issue || "Other finding", priority: 3, next_step: "Review the original evidence before selecting a remediation."};
}

export function buildRotationInsights(report = {}) {
  const queues = new Map();
  const uniqueAccounts = new Map();
  const platformRows = [];
  for (const [index, platform] of (report.platforms || []).entries()) {
    const accounts = platform.accounts || [...new Map((platform.categories || []).flatMap(category => category.accounts.map(account => [account.account_id, account]))).values()];
    const platformQueue = new Map();
    const platformPriorities = new Map();
    for (const account of accounts) {
      const key = insightAccountKey(account, platform.platform_id);
      const issues = account.issues || [];
      let highest = 4;
      const specificFailure = issues.some(issue => /^Reported (authentication|permission|connectivity|password-policy|dependency)/i.test(issue));
      for (const issue of issues) {
        if (specificFailure && /^(Change|Reconcile|Verification) failed$/i.test(issue)) continue;
        const bucket = rotationIssueBucket(issue);
        highest = Math.min(highest, bucket.priority);
        const global = queues.get(bucket.label) || {label: bucket.label, priority: bucket.priority, next_step: bucket.next_step, accounts: new Map(), platforms: new Set()};
        global.accounts.set(key, account); global.platforms.add(platform.platform_id); queues.set(bucket.label, global);
        const local = platformQueue.get(bucket.label) || {label: bucket.label, priority: bucket.priority, count: 0, keys: new Set()};
        local.keys.add(key); local.count = local.keys.size; platformQueue.set(bucket.label, local);
      }
      if (highest < 4) {
        uniqueAccounts.set(key, Math.min(uniqueAccounts.get(key) || 4, highest));
        platformPriorities.set(key, Math.min(platformPriorities.get(key) || 4, highest));
      }
    }
    const blockers = (platform.findings || []).filter(finding => finding.level === "Confirmed setting" && !/verification/i.test(finding.title || "")).length;
    const ordered = [...platformQueue.values()].sort((a, b) => a.priority - b.priority || b.count - a.count || a.label.localeCompare(b.label));
    const immediate = new Set(); const watch = new Set(); const investigate = new Set();
    for (const [key, priority] of platformPriorities) (priority === 1 ? immediate : priority === 2 ? watch : investigate).add(key);
    const tier = blockers || immediate.size ? 1 : watch.size ? 2 : 3;
    platformRows.push({index, platform_id: platform.platform_id, tier, priority_label: tier === 1 ? "Start first" : tier === 2 ? "Next" : "Review", immediate: immediate.size,
      watch: watch.size, investigate: investigate.size, blockers, affected: platform.affected_accounts || 0, total: platform.total_accounts || accounts.length,
      dominant_issue: ordered[0]?.label || (blockers ? "Platform configuration blockers" : "Further review"),
      next_step: ordered[0] ? (queues.get(ordered[0].label)?.next_step || "Review the platform evidence.") : blockers ? "Review the confirmed platform settings before retrying account operations." : "Review missing evidence and policy applicability.",
      score: blockers * 20 + immediate.size * 6 + watch.size * 3 + investigate.size});
  }
  platformRows.sort((a, b) => a.tier - b.tier || b.score - a.score || b.affected - a.affected || a.platform_id.localeCompare(b.platform_id));
  const workQueues = [...queues.values()].map(queue => ({label: queue.label, priority: queue.priority, next_step: queue.next_step, account_count: queue.accounts.size, platform_count: queue.platforms.size,
    first_platform_index: platformRows.find(row => queue.platforms.has(row.platform_id))?.index ?? 0})).sort((a, b) => a.priority - b.priority || b.account_count - a.account_count || a.label.localeCompare(b.label));
  return {immediate_accounts: [...uniqueAccounts.values()].filter(value => value === 1).length, watch_accounts: [...uniqueAccounts.values()].filter(value => value === 2).length,
    investigate_accounts: [...uniqueAccounts.values()].filter(value => value === 3).length, work_queues: workQueues, platforms: platformRows};
}

export function describeRotationFinding(finding) {
  const title = finding.title || "Platform review";
  const evidence = finding.evidence || "No supporting details were returned.";
  const level = finding.level === "Confirmed setting" ? "Configuration finding" : finding.level === "Confirmed account pattern" ? "Account pattern" : finding.level === "Unknown" ? "Inspection gap" : "Review recommended";
  const descriptions = {
    "Platform inactive": ["Platform is inactive", "CyberArk reports this platform as inactive. Accounts assigned to it may not receive the expected automatic management.", "Confirm that the platform should be in service, then review its activation status and applicable policy exceptions."],
    "Periodic password change disabled": ["Scheduled password changes are turned off", "Periodic password changes are disabled in the returned platform configuration. Accounts may rely on manual or other workflow-driven changes.", "If these accounts require scheduled rotation, review the effective policy and enable periodic changes through your approved configuration process."],
    "Password change processing disabled": ["Password change processing is turned off", "The platform is configured not to carry out password change tasks.", "Confirm the intended management workflow and review change processing before enabling it for accounts that require rotation."],
    "Periodic verification disabled": ["Scheduled credential verification is turned off", "The platform does not run periodic verification. This can delay detection of credentials that no longer match the target; it does not by itself prove a rotation failure.", "Review whether periodic verification is required for this platform and align it with the approved verification policy."],
    "Verification processing disabled": ["Credential verification processing is turned off", "Verification tasks are disabled in the returned configuration. Verification checks a credential; it does not change it.", "Review whether this workflow requires verification and enable processing only where supported and intended."],
    "Automatic reconciliation when unsynchronized disabled": ["Automatic recovery of out-of-sync credentials is turned off", "The platform will not automatically reconcile an out-of-sync credential under this setting.", "For workflows that need automatic recovery, review reconciliation policy and validate the associated recovery account and permissions."],
    "Reconciliation processing disabled": ["Credential reconciliation processing is turned off", "The platform is configured not to process reconciliation tasks. This matters when a credential needs to be reset through a separate recovery identity.", "Confirm whether reconciliation is supported and required, then review the processing setting and recovery-account configuration."],
    "All visible accounts have automatic management disabled": ["Automatic management is disabled for every visible account", "Every account returned for this platform has automatic management disabled. This is an account-level pattern rather than proof of a platform configuration defect.", "Review the disablement reasons and approved exceptions. Re-enable eligible accounts through a controlled process after resolving their underlying issues."],
    "Platform reconciliation credential setting is empty": ["The platform has no default recovery credential in this setting", "A platform-level recovery-account setting is empty. Individual accounts may still have a valid recovery association.", "Check the affected accounts for an effective reconciliation identity before treating this as a missing credential. Validate access only where reconciliation is required."],
    "Effective policy and linked credentials require further inspection": ["Effective policy and recovery credentials need further review", "This scan cannot establish the final rotation interval, account-level overrides, usable linked credentials, or SRS-specific service health.", "Compare these findings with the effective CyberArk policy and account associations. Use service-specific diagnostics where the rotation engine is not exposed by the Vault API."],
    "Platform configuration could not be inspected": ["Platform configuration was unavailable", "The scan could not retrieve the platform configuration. Its settings cannot be assessed from this report.", "Check the scanning identity’s permissions and the tenant’s API support, then rerun the scan. Do not interpret unavailable settings as healthy or faulty."]
  };
  let description = descriptions[title];
  description ||= [title, evidence, "Review this finding with the platform owner and confirm its relevance to the affected accounts before making changes."];
  return {level, title: description[0], summary: description[1], recommendation: description[2], technical: evidence};
}

export function presentRotationFindings(findings = []) {
  return findings
    .filter(f => !f.title?.endsWith(" not exposed") && f.title !== "Schedule or credential configuration" && f.title !== "Effective policy and linked credentials require further inspection")
    .map(describeRotationFinding);
}

function categoryAdvice(label) {
  const advice = {
    "Change failed": "Review the original change error, target connectivity, permissions, and password requirements. Confirm a successful target change after the underlying issue is resolved.",
    "Reconcile failed": "Review the recovery-account association, its safe access and target permissions, and the original reconciliation error.",
    "Verification failed": "Check whether the stored credential matches the target. Review authentication and connectivity errors; verification alone does not rotate a secret.",
    "Automatic management disabled": "Review each disablement reason and approved exception. Restore automatic management only after the reason for disabling it has been addressed.",
    "Account not managed by CPM": "Confirm the account belongs in the CPM workflow and review the returned disablement reason before restoring management.",
    "Assigned platform unavailable": "Assign an active platform that supports the account before retrying management.",
    "Password change action disabled": "Review the effective action state and its returned disablement reason before enabling change processing.",
    "Reconciliation action disabled": "Review the effective reconcile state, recovery account, and returned disablement reason before retrying.",
    "Verification action disabled": "Review the effective verification state and its returned disablement reason before retrying.",
    "Reported age exceeds threshold": "Confirm the last successful target change against authoritative activity records. Review the effective rotation interval and scheduling before treating reported metadata age as a compliance failure.",
    "Last successful change exceeds threshold": "Use the CyberArk compliance timestamp to prioritize the oldest eligible accounts, then resolve any accompanying blockers before requesting a change.",
    "No management activity timestamp above threshold": "Confirm whether the account has ever been managed, then inspect policy eligibility and authoritative activity history.",
    "Platform policy failure": "Review the platform policy and the account's applicable policy exceptions before retrying management.",
    "Management failed — operation unknown": "Review the account’s activity history to identify the failed operation and original error before choosing a recovery action."
  };
  return advice[label] || "Review the original error and validate the relevant connectivity, access, or platform requirements before attempting recovery.";
}

export function groupRotationRecommendations(platform) {
  const groups = {core: [], additional: [], inspection: []};
  for (const finding of presentRotationFindings(platform.findings || [])) {
    if (finding.level === "Account pattern" && (platform.categories || []).some(c => c.label.startsWith("Automatic management disabled"))) continue;
    const core = finding.level === "Account pattern" || finding.title.includes("recovery credential") || finding.level === "Configuration finding" && !/verif/i.test(finding.title);
    groups[finding.level === "Inspection gap" ? "inspection" : core ? "core" : "additional"].push(finding);
  }
  for (const category of platform.categories || []) {
    const bucket = rotationIssueBucket(category.label);
    const isFailure = /failed|failure|rejection/i.test(category.label);
    const confirmedBlocker = bucket.priority === 1 && !isFailure;
    const group = bucket.priority === 1 ? "core" : bucket.priority === 2 ? "additional" : "inspection";
    groups[group].push({level: confirmedBlocker ? "Confirmed account blocker" : isFailure ? "Observed operation failure" : bucket.priority === 2 ? "Review next" : "Further evidence needed",
      title: `${category.label} · ${category.accounts.length} account${category.accounts.length === 1 ? "" : "s"}`,
      summary: confirmedBlocker ? "CyberArk returned an account-level state that can prevent the expected management workflow." : isFailure ? "CyberArk reports a management failure for these accounts. The original error identifies what must be resolved; the failure alone does not establish a platform-wide cause." : "This account finding requires investigation before a cause or remediation can be established.",
      recommendation: categoryAdvice(category.label), technical: "Affected accounts and original details are listed in the corresponding account issue group."});
  }
  return groups;
}

function renderedFindingCards(findings) {
  return findings.map(f => `<article class="finding"><span class="badge ${/blocker|failure|Configuration/.test(f.level) ? "amber" : ""}">${escape(f.level)}</span><h3>${escape(f.title)}</h3><p>${escape(f.summary)}</p><div class="action"><b>Recommended next step</b><p>${escape(f.recommendation)}</p></div><details class="technical"><summary>Supporting technical evidence</summary><pre>${escape(f.technical)}</pre></details></article>`).join("");
}

function recommendationSections(platform) {
  const groups = groupRotationRecommendations(platform);
  return [["core", "Core issues", "Observed blockers and failures to address first. More than one may apply to an account."], ["additional", "Additional recommendations", "Security and configuration improvements that are not established causes of this rotation failure."], ["inspection", "Further investigation", "Missing evidence and settings that require validation before changes are justified."]].map(([key, title, subtitle]) => `<h3>${title}</h3><p class="muted">${subtitle}</p><div class="findings">${renderedFindingCards(groups[key]) || '<p>No findings in this section.</p>'}</div>`).join("");
}


function accountTable(accounts) {
  return `<div class="table-wrap"><table><thead><tr><th>Account</th><th>Safe & target</th><th>Credential age</th><th>Management</th><th>Findings & evidence</th></tr></thead><tbody>${accounts.map(a => `<tr data-account><td><b>${escape(a.name || a.username || "Unnamed account")}</b><small>ID ${escape(a.account_id)}</small></td><td>${escape(a.safe_name)}<small>${escape(a.username)} @ ${escape(a.address)}</small></td><td>${a.authoritative_age_days != null ? `${number(a.authoritative_age_days)} days` : a.reported_age_days == null ? "Unknown" : `${number(a.reported_age_days)} days`}<small>${escape(date(a.authoritative_change_time || a.reported_change_time))}</small><small>${a.authoritative_change_time ? "Last successful change from compliance API" : "Successful target rotation unconfirmed"}</small></td><td>${a.automatic_management_enabled == null ? "Unknown" : a.automatic_management_enabled ? "Automatic" : "Disabled"}<small>${escape(a.cpm_status || a.status || "Status unavailable")}</small>${a.change_disabled_reason ? `<small>Change disabled: ${escape(a.change_disabled_reason)}</small>` : ""}</td><td>${escape((a.issues || []).join(" · "))}<small>${escape(a.cpm_error_detail || a.detail || "No additional error details were returned.")}</small></td></tr>`).join("")}</tbody></table></div>`;
}

export function buildRotationHealthHtml(report) {
  const platforms = report.platforms || [];
  const insights = buildRotationInsights(report);
  const categories = platforms.flatMap(p => p.categories || []);
  const unique = label => new Set(categories.filter(c => c.label === label).flatMap(c => c.accounts.map(a => `${a.platform_id || ""}/${a.account_id}`))).size;
  const metrics = [["Start first", insights.immediate_accounts], ["Work next", insights.watch_accounts], ["Investigate", insights.investigate_accounts], ["Visible accounts scanned", report.total_accounts], ["Accounts with findings", report.affected_accounts], ["Platforms to review", platforms.length]];
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>FastPAS · Rotation Health · ${escape(report.tenant_name)}</title><style>
  :root{color-scheme:light;--ink:#172b42;--muted:#536477;--line:#dce5ed;--blue:#176386;--soft:#eef5f8}*{box-sizing:border-box}body{margin:0;background:#f3f6f9;color:var(--ink);font:15px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif}header{background:#132b42;color:#fff;padding:36px max(24px,calc((100vw - 1320px)/2))}.brand{letter-spacing:.18em;font-size:12px;font-weight:700;color:#8ed6db}h1{font-size:34px;line-height:1.2;margin:12px 0}h2{font-size:24px;margin:0 0 12px}h3{font-size:17px;line-height:1.4;margin:12px 0 8px}p{margin:8px 0}.meta{color:#c7d6e4;font-size:13px}.layout{max-width:1368px;margin:auto;padding:24px}.metrics{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:22px}.metric,.panel{background:#fff;border:1px solid var(--line);border-radius:12px}.metric{padding:18px}.metric span{display:block;color:var(--muted);font-size:12px;line-height:1.4}.metric strong{display:block;font-size:30px;margin-top:8px}.panel{padding:24px;margin:20px 0}.toolbar{display:flex;gap:12px;align-items:center;justify-content:space-between;flex-wrap:wrap}input{border:1px solid var(--line);border-radius:8px;padding:12px;font:inherit;width:min(480px,100%)}button,.tabs a{font:inherit;color:var(--ink);background:#fff;border:1px solid var(--line);border-radius:8px;padding:10px 15px;cursor:pointer;text-decoration:none}button:hover,.tabs a:hover{background:var(--soft)}button:focus-visible,a:focus-visible,input:focus-visible,summary:focus-visible{outline:3px solid #168faf;outline-offset:3px}.tabs{position:sticky;top:0;z-index:20;background:#f3f6f9;display:flex;gap:8px;overflow-x:auto;padding:12px 0;align-items:center;border-bottom:1px solid var(--line)}.report-panel{scroll-margin-top:80px}.tabs a{white-space:nowrap}.tabs a[aria-selected=true]{background:var(--ink);color:white;border-color:var(--ink)}.badge,.priority{display:inline-block;background:var(--soft);color:var(--blue);border-radius:30px;font-size:11px;font-weight:700;padding:4px 10px}.priority.p1{background:#fbe5df;color:#8d3021}.priority.p2{background:#fbf0d5;color:#7a5311}.priority.p3{background:#e7eef4;color:#425b72}.amber{background:#fff1d6;color:#80520d}.muted,small{color:var(--muted)}.queue-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:18px 0}.queue{padding:15px;border:1px solid var(--line);border-radius:10px}.queue h3{margin:8px 0 2px}.queue small{display:block}.findings{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.finding{border:1px solid var(--line);border-radius:10px;padding:20px}.finding p{font-size:14px}.action{background:#f5f8fa;border-left:3px solid #2b8b96;padding:12px 14px;margin-top:16px}.action b{font-size:12px;color:var(--blue)}.technical{font-size:12px;margin-top:12px}.technical pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f5f8fa;padding:12px}summary{cursor:pointer;font-weight:600}.group{border:1px solid var(--line);border-radius:10px;padding:16px;margin-top:14px}.group>summary{font-size:17px}.group>p{color:var(--muted);font-size:14px;margin:12px 0}.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;text-align:left;font-size:13px}th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.04em;background:#f5f8fa}td,th{padding:14px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}td{min-width:145px}td small{display:block;font-size:12px;margin-top:4px}.summary-table td:first-child a{color:var(--blue);font-weight:700}.coverage{background:#f8fafc}.coverage li{margin:8px 0}.empty{padding:24px;color:var(--muted)}footer{text-align:center;color:var(--muted);font-size:12px;padding:16px} [hidden]{display:none!important}.print-only{display:none}@media(max-width:1000px){.metrics,.queue-grid{grid-template-columns:repeat(3,1fr)}}@media(max-width:640px){.metrics,.queue-grid{grid-template-columns:1fr}.findings{grid-template-columns:1fr}.layout{padding:14px}.panel{padding:18px}h1{font-size:28px}}@media print{body{background:#fff;font-size:11px}header{padding:18px;background:#fff;color:#172b42}.brand,.meta{color:#536477}.layout{padding:0}.toolbar,.tabs,.technical{display:none}.report-panel[hidden]{display:block!important}.panel{break-before:auto;border:0;padding:14px 0}.finding{break-inside:avoid}.metrics{grid-template-columns:repeat(3,1fr)}.table-wrap{overflow:visible}td{min-width:0}a{color:inherit;text-decoration:none}.print-only{display:block}}
  </style></head><body><header><div class="brand">FASTPAS / TELEMETRY</div><h1>Rotation Health</h1><p>Platform configuration, account findings, and recommended next steps.</p><div class="meta">${escape(report.tenant_name || "Tenant")} · Snapshot ${escape(date(report.generated_at))} · Reported-age threshold ${number(report.threshold_days)} days</div></header><main class="layout">
  <div class="metrics">${metrics.map(([label, value]) => `<div class="metric"><span>${escape(label)}</span><strong>${number(value)}</strong></div>`).join("")}</div>
  <div class="toolbar"><label>Find an account <input id="account-search" type="search" placeholder="Search name, safe, username, target or error"></label><button id="print-report" type="button">Print / save as PDF</button></div><p id="search-status" class="muted" role="status" aria-live="polite"></p>
  <nav class="tabs" aria-label="Report sections"><a href="#overview" data-tab="overview">Overview</a>${platforms.map((p, i) => `<a href="#platform-${i}" data-tab="platform-${i}">${escape(p.platform_id)} <span class="badge">${number(p.affected_accounts)}</span></a>`).join("")}</nav>
  <section id="overview" class="panel report-panel"><h2>Where to start</h2><p class="muted">Address confirmed blockers and reported failures first, then overdue credentials, followed by gaps that need more evidence. Work-queue totals may overlap; urgency metrics assign each account to its highest priority.</p>
  <div class="queue-grid">${insights.work_queues.slice(0, 6).map(queue => `<article class="queue"><span class="priority p${queue.priority}">${queue.priority === 1 ? "Start first" : queue.priority === 2 ? "Next" : "Investigate"}</span><h3>${escape(queue.label)}</h3><p><b>${queue.account_count}</b> accounts · ${queue.platform_count} platforms</p><small>${escape(queue.next_step)}</small></article>`).join("") || '<p class="empty">No prioritized work queues were returned.</p>'}</div><h2>Platforms ranked by priority</h2>
  <div class="table-wrap"><table class="summary-table"><thead><tr><th>Priority</th><th>Platform</th><th>First / next</th><th>Primary issue</th><th>Affected</th></tr></thead><tbody>${insights.platforms.map(row => `<tr><td><span class="priority p${row.tier}">${row.priority_label}</span></td><td><a href="#platform-${row.index}" data-open="platform-${row.index}">${escape(row.platform_id)}</a><small>${row.blockers} platform blockers</small></td><td>${row.immediate} / ${row.watch}</td><td>${escape(row.dominant_issue)}<small>${escape(row.next_step)}</small></td><td>${row.affected} of ${row.total}</td></tr>`).join("")}</tbody></table></div>${platforms.length ? "" : '<p class="empty">No matching account or confirmed platform findings were returned. Review the coverage information before drawing conclusions.</p>'}</section>
  ${platforms.map((p, i) => `<section id="platform-${i}" class="panel report-panel"><h2>${escape(p.platform_id)}</h2><p class="muted">${number(p.affected_accounts)} of ${number(p.total_accounts)} visible accounts have findings. ${number(p.disabled_accounts)} ${number(p.disabled_accounts) === 1 ? "account has" : "accounts have"} automatic management disabled.</p><h3>Failure groups</h3><p class="muted">Groups are collapsed to keep the platform summary compact. Open a group only when individual account evidence is needed.</p>${(p.categories || []).map(c => `<details class="group"><summary>${escape(c.label)} <span class="badge">${c.accounts.length} ${c.accounts.length === 1 ? "account" : "accounts"}</span></summary><p>${escape(categoryAdvice(c.label))}</p>${accountTable(c.accounts)}</details>`).join("") || '<p class="empty">No matching account issues were returned for this platform.</p>'}<details class="group"><summary>Platform configuration and recommendations</summary>${recommendationSections(p)}</details></section>`).join("")}
  <section class="panel coverage"><h2>Scope and evidence</h2><span class="badge ${report.inventory_complete ? "" : "amber"}">${report.inventory_complete ? "Pagination complete for visible accounts" : "Incomplete account inventory"}</span><p>This is a static snapshot of accounts visible to the scanning identity. Reported modification and reconciliation dates are age indicators, not proof of a successful credential change on the target. Verification does not reset credential age.</p><ul>${(report.warnings || []).map(w => `<li>${escape(w)}</li>`).join("")}</ul><p>Configuration findings describe observed settings. Recommendations require review of the intended workflow, effective policy, and account-level overrides. Inspection gaps indicate unavailable information rather than confirmed defects.</p></section></main><footer>FastPAS · Self-contained report · No live connection or external resources required</footer><script>
  (()=>{
    const tabs=[...document.querySelectorAll('[data-tab]')], panels=[...document.querySelectorAll('.report-panel')];
    const nav=document.querySelector('.tabs');nav.setAttribute('role','tablist');
    tabs.forEach(tab=>{tab.setAttribute('role','tab');tab.setAttribute('aria-controls',tab.dataset.tab);tab.id='tab-'+tab.dataset.tab;});
    panels.forEach(panel=>{panel.setAttribute('role','tabpanel');panel.setAttribute('aria-labelledby','tab-'+panel.id);});
    const choose=id=>{if(!panels.some(p=>p.id===id))id='overview';panels.forEach(p=>p.hidden=p.id!==id);tabs.forEach(t=>{const on=t.dataset.tab===id;t.setAttribute('aria-selected',String(on));t.tabIndex=on?0:-1;});};
    const selected=()=>location.hash.slice(1)||'overview';choose(selected());
    window.addEventListener('hashchange',()=>choose(selected()));
    tabs.forEach((tab,index)=>{tab.addEventListener('click',()=>choose(tab.dataset.tab));tab.addEventListener('keydown',event=>{let next;if(event.key==='ArrowRight')next=(index+1)%tabs.length;if(event.key==='ArrowLeft')next=(index+tabs.length-1)%tabs.length;if(event.key==='Home')next=0;if(event.key==='End')next=tabs.length-1;if(next!==undefined){event.preventDefault();tabs[next].focus();location.hash=tabs[next].dataset.tab;choose(tabs[next].dataset.tab);}});});
    document.querySelectorAll('[data-open]').forEach(link=>link.addEventListener('click',()=>choose(link.dataset.open)));
    const search=document.querySelector('#account-search'), rows=[...document.querySelectorAll('[data-account]')];
    search.addEventListener('input',()=>{const query=search.value.trim().toLowerCase();rows.forEach(row=>row.hidden=!row.textContent.toLowerCase().includes(query));document.querySelectorAll('.group').forEach(group=>{group.hidden=query!==''&&![...group.querySelectorAll('[data-account]')].some(row=>!row.hidden);if(query)group.open=true;});document.querySelector('#search-status').textContent=query?rows.filter(row=>!row.hidden).length+' matching account rows across all platforms (accounts may appear in several issue groups).':'';});
    const expand=()=>{rows.forEach(row=>row.hidden=false);document.querySelectorAll('.group').forEach(group=>{group.hidden=false;group.open=true;});};
    const restore=()=>search.dispatchEvent(new Event('input'));
    window.addEventListener('beforeprint',expand);window.addEventListener('afterprint',restore);
    document.querySelector('#print-report').addEventListener('click',()=>{expand();window.print();restore();});
  })();
  </script></body></html>`;
}
