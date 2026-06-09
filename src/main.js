import "./styles.css";

const PAGES = ["api", "tools", "telemetry", "profiles", "tenants", "docs", "settings"];
const DEBUG_PAGE = "debug";
const TELEMETRY_DASHBOARDS = [
  { id: "most-used-components", label: "Most Used Components" },
  { id: "active-users", label: "Active Users" },
  { id: "account-failures", label: "Account Failures" }
];
const PROFILE_TYPE_OAUTH = "oauth";
const PROFILE_TYPE_INTERACTIVE = "interactive";
const isTauri = Boolean(window.__TAURI_INTERNALS__);
const DEFAULT_INACTIVITY_TIMEOUT_MINUTES = 30;
const MIN_INACTIVITY_TIMEOUT_MINUTES = 10;
const MAX_INACTIVITY_TIMEOUT_MINUTES = 60;
const TOKEN_COPY_WINDOW_MS = 30 * 1000;
const SESSION_ACTIVITY_EVENTS = ["pointerdown", "keydown", "input", "mousedown", "touchstart"];
let inactivityIntervalId = null;
let inactivityListenersBound = false;
let sessionLockInFlight = false;
let interactivePollIntervalId = null;
let interactivePollInFlight = false;
let interactivePollAttempts = 0;
let interactivePollMechanismId = "";
let profileUpdateArmedId = "";
let profileEditorMode = "idle";
let tokenCopyWindowIntervalId = null;
const PREBUILT_CALLS = [
  {
    section: "Look Up",
    items: [
      {
        id: "health",
        name: "Check Vault Health",
        description: "Check the health and connectivity status of CyberArk components.",
        method: "GET",
        path: "System/Health",
        query: "",
        body: "",
        ready: true
      },
      {
        id: "account-search",
        name: "Find Accounts",
        description: "Search vault accounts by name, username, address, or keyword.",
        method: "GET",
        path: "Accounts",
        query: "search={{query}}&limit=25",
        body: "",
        ready: true
      },
      {
        id: "account-details",
        name: "View Account Details",
        description: "Open the full details for one specific account.",
        method: "GET",
        path: "Accounts/{{account_id}}",
        query: "",
        body: "",
        ready: true
      },
      {
        id: "safe-members",
        name: "View Safe Members",
        description: "See who has access to a safe and what memberships exist.",
        method: "GET",
        path: "Safes/{{safe_name}}/Members",
        query: "",
        body: "",
        ready: true
      },
      {
        id: "safe-details",
        name: "View Safe Details",
        description: "Open one safe and review its settings before making changes.",
        method: "GET",
        path: "Safes/{{safe_name}}",
        query: "",
        body: "",
        ready: true
      },
      {
        id: "platform-details",
        name: "View Platform Details",
        description: "Open the configuration details for one target platform.",
        method: "GET",
        path: "Platforms/{{platform_id}}",
        query: "",
        body: "",
        ready: true
      }
    ]
  },
  {
    section: "Reports",
    items: [
      {
        id: "platforms",
        name: "View Platforms",
        description: "List the target platforms available in the current tenant.",
        method: "GET",
        path: "Platforms",
        query: "",
        body: "",
        ready: true
      },
      {
        id: "safes",
        name: "View Safes",
        description: "List the safes available to the current session.",
        method: "GET",
        path: "Safes",
        query: "limit=100&offset=0",
        body: "",
        ready: true
      },
      {
        id: "account-report",
        name: "Account Inventory Report",
        description: "Report accounts where secret management failed but automatic management is enabled.",
        method: "GET",
        path: "Accounts",
        query: "limit=1000&offset=0",
        body: "",
        report: "managed-failure-accounts",
        ready: true
      }
    ]
  },
  {
    section: "Safe Changes",
    items: [
      {
        id: "user-template",
        name: "Create Vault User Request",
        description: "Prepare a new vault-user creation request.",
        method: "POST",
        path: "Users",
        query: "",
        body: '{\n  "username": "new.user",\n  "initialPassword": "ChangeMeNow1!",\n  "userTypeName": "EPVUser",\n  "location": "\\\\",\n  "expiryDate": 0,\n  "authenticationMethod": ["AuthTypePass"]\n}',
        ready: true
      },
      {
        id: "create-safe",
        name: "Create Safe",
        description: "Create a new safe with retention and CPM settings.",
        method: "POST",
        path: "Safes",
        query: "",
        body: "",
        ready: true
      },
      {
        id: "add-safe-member",
        name: "Add User Or Group To Safe",
        description: "Grant access to a safe using a guided permission role.",
        method: "POST",
        path: "Safes/{{safe_name}}/Members",
        query: "",
        body: "",
        ready: true
      }
    ]
  },
  {
    section: "Advanced Changes",
    items: [
      {
        id: "activate-user",
        name: "Reactivate Suspended User",
        description: "Prepare a guided action to reactivate a suspended user.",
        method: "POST",
        path: "",
        query: "",
        body: "",
        ready: false,
        blockedReason: "This task needs a validated user-activation endpoint and permission model before it should run in FastPAS."
      },
      {
        id: "update-account",
        name: "Update Account Fields",
        description: "Prepare a guided update for one or more account properties.",
        method: "PATCH",
        path: "",
        query: "",
        body: "",
        ready: false,
        blockedReason: "This task needs a validated account-patch payload before it should run in FastPAS."
      }
    ]
  },
  {
    section: "Bulk Operations",
    items: [
      {
        id: "bulk-account-actions",
        name: "Bulk Verify, Change, or Reconcile",
        description: "Run bulk account maintenance actions using filters.",
        method: "POST",
        path: "",
        query: "",
        body: "",
        ready: false,
        blockedReason: "This workflow needs batch execution, filters, and stronger confirmations before it should run in FastPAS."
      },
      {
        id: "account-onboard-utility",
        name: "Bulk Account Onboarding from CSV",
        description: "Create, update, or delete accounts in bulk from a CSV file.",
        method: "POST",
        path: "",
        query: "",
        body: "",
        ready: false,
        blockedReason: "This workflow needs CSV upload, safe creation logic, and duplicate-handling rules before it should run in FastPAS."
      },
      {
        id: "safe-bulk-csv",
        name: "Bulk Safe and Member Updates from CSV",
        description: "Create safes and manage safe members in bulk from CSV files.",
        method: "POST",
        path: "",
        query: "",
        body: "",
        ready: false,
        blockedReason: "This workflow needs CSV upload and multi-request execution before it should run in FastPAS."
      }
    ]
  },
  {
    section: "Imports / Exports",
    items: [
      {
        id: "platform-import-export",
        name: "Platform Package Import / Export",
        description: "Import or export platform ZIP packages for migration or reuse.",
        method: "POST",
        path: "",
        query: "",
        body: "",
        ready: false,
        blockedReason: "This workflow needs ZIP file import/export support before it should run in FastPAS."
      }
    ]
  }
];
const REPORT_TASK_IDS = new Set(
  PREBUILT_CALLS
    .filter((group) => group.section === "Reports")
    .flatMap((group) => group.items.map((item) => item.id))
);

const state = {
  page: "api",
  theme: loadTheme(),
  settings: loadSettings(),
  snapshot: emptySnapshot(),
  session: {
    lastActivityAt: Date.now()
  },
  activity: [],
  forms: {
    profile: emptyProfile(),
    tenant: emptyTenant(),
    importJson: "",
    session: emptySessionForm()
  },
  api: {
    builder: emptyApiBuilder(),
    selectedPresetId: "",
    searchQuery: "",
    taskInputs: {},
    response: null,
    report: null,
    lastRunPresetId: "",
    interactiveAuth: emptyInteractiveAuthState(),
    tokenRequestFailures: {
      identity: false,
      platform: false
    }
  },
  telemetry: {
    selectedDashboardId: "most-used-components",
    componentUsage: null,
    componentUsageLoading: false,
    componentUsageError: "",
    accountFailures: null,
    accountFailuresLoading: false,
    accountFailuresError: "",
    accountRemediation: null,
    accountRemediationLoading: false,
    accountRemediationError: "",
    activeUsers: null,
    activeUsersLoading: false,
    activeUsersError: ""
  }
};

const bridge = createBridge();

boot().catch((error) => {
  renderFatalScreen(`Boot failed: ${formatError(error)}`);
});

async function boot() {
  await refreshSnapshot();
  syncFormsFromSelection();
  enforceTokenCopyWindow();
  startTokenCopyWindowMonitor();
  applyTheme();
  initializeSessionTimeout();
  log(isTauri ? "Running in Tauri mode." : "Running in browser mode.");
  render();
}

function initializeSessionTimeout() {
  refreshSessionActivity();
  if (!inactivityListenersBound) {
    for (const eventName of SESSION_ACTIVITY_EVENTS) {
      window.addEventListener(eventName, trackSessionActivity, true);
    }
    inactivityListenersBound = true;
  }
  if (!inactivityIntervalId) {
    inactivityIntervalId = window.setInterval(tickSessionTimeout, 1000);
  }
  updateSessionTimeoutIndicator();
}

function createBridge() {
  if (!isTauri) {
    return createBrowserBridge();
  }

  return {
    async invoke(command, args = {}) {
      const { invoke } = await import("@tauri-apps/api/core");
      return invoke(command, args);
    },
    getState() {
      return this.invoke("get_app_state");
    },
    saveProfile(payload) {
      return this.invoke("save_profile", { payload });
    },
    deleteProfile(profileId) {
      return this.invoke("delete_profile", { profileId });
    },
    setActiveProfile(profileId) {
      return this.invoke("set_active_profile", { profileId });
    },
    saveTenant(payload) {
      return this.invoke("save_tenant", { payload });
    },
    deleteTenant(tenantId) {
      return this.invoke("delete_tenant", { tenantId });
    },
    setActiveTenant(tenantId) {
      return this.invoke("set_active_tenant", { tenantId });
    },
    requestIdentityToken() {
      return this.invoke("request_identity_token");
    },
    requestPlatformToken() {
      return this.invoke("request_platform_token");
    },
    copyRuntimeToken(payload) {
      return this.invoke("copy_runtime_token", { payload });
    },
    authenticateInteractiveUser() {
      return this.invoke("authenticate_interactive_user");
    },
    advanceInteractiveAuthentication(payload) {
      return this.invoke("advance_interactive_authentication", { payload });
    },
    configureSessionPasscode(passcode) {
      return this.invoke("configure_session_passcode", { passcode });
    },
    unlockSession(passcode) {
      return this.invoke("unlock_session", { passcode });
    },
    lockSession() {
      return this.invoke("lock_session");
    },
    updateSessionPasscode(payload) {
      return this.invoke("update_session_passcode", { payload });
    },
    executeVaultRequest(payload) {
      return this.invoke("execute_vault_request", { payload });
    },
    clearTokens() {
      return this.invoke("clear_tokens");
    },
    exportConfig() {
      return this.invoke("export_config");
    },
    saveTextFile(payload) {
      return this.invoke("save_text_file", { payload });
    },
    updateProfileSecret(payload) {
      return this.invoke("update_profile_secret", { payload });
    },
    importConfig(payload) {
      return this.invoke("import_config", { payload });
    },
    resolveTenant(subdomain) {
      return this.invoke("resolve_tenant", { subdomain });
    },
    getConnectionComponentTelemetry() {
      return this.invoke("get_connection_component_telemetry");
    },
    getAccountFailureTelemetry() {
      return this.invoke("get_account_failure_telemetry");
    },
    remediateAccountFailures(payload) {
      return this.invoke("remediate_account_failures", { payload });
    },
    getActiveUserTelemetry() {
      return this.invoke("get_active_user_telemetry");
    }
  };
}

function createBrowserBridge() {
  const storage = {
    get(key, fallback) {
      const raw = localStorage.getItem(key);
      return raw ? JSON.parse(raw) : fallback;
    },
    set(key, value) {
      localStorage.setItem(key, JSON.stringify(value));
    }
  };

  function load() {
    return storage.get("fastpas-browser-state", {
      profiles: [],
      tenants: [],
      active_profile_id: null,
      active_tenant_id: null,
      tokens: {
        identity: null,
        platform: null
      }
    });
  }

  function save(data) {
    storage.set("fastpas-browser-state", data);
    return data;
  }

  function snapshot(data) {
    return {
      profiles: data.profiles,
      tenants: data.tenants,
      active_profile_id: data.active_profile_id,
      active_tenant_id: data.active_tenant_id,
      passcode_configured: false,
      session_locked: false,
      tokens: {
        identity: tokenStatus(data.tokens.identity),
        platform: tokenStatus(data.tokens.platform)
      }
    };
  }

  return {
    async getState() {
      return snapshot(load());
    },
    async configureSessionPasscode() {
      throw new Error("Session passcodes are only available in the desktop app.");
    },
    async unlockSession() {
      throw new Error("Session passcodes are only available in the desktop app.");
    },
    async lockSession() {
      const data = load();
      data.tokens = { identity: null, platform: null };
      save(data);
      return snapshot(data);
    },
    async updateSessionPasscode() {
      throw new Error("Session passcodes are only available in the desktop app.");
    },
    async saveProfile(payload) {
      const data = load();
      ensureBrowserUnlocked(data);
      if (String(payload.client_secret || "").trim()) {
        throw new Error("Client secrets can only be stored in the desktop app.");
      }
      const profile = normalizeProfile(payload, payload.id || crypto.randomUUID());
      data.profiles = upsertById(data.profiles, profile);
      if (!data.active_profile_id) {
        data.active_profile_id = profile.id;
      }
      save(data);
      return snapshot(data);
    },
    async deleteProfile(profileId) {
      const data = load();
      ensureBrowserUnlocked(data);
      data.profiles = data.profiles.filter((item) => item.id !== profileId);
      if (data.active_profile_id === profileId) {
        data.active_profile_id = data.profiles[0]?.id || null;
      }
      data.tokens.identity = null;
      data.tokens.platform = null;
      save(data);
      return snapshot(data);
    },
    async setActiveProfile(profileId) {
      const data = load();
      ensureBrowserUnlocked(data);
      data.active_profile_id = profileId;
      data.tokens.identity = null;
      data.tokens.platform = null;
      save(data);
      return snapshot(data);
    },
    async saveTenant(payload) {
      const data = load();
      ensureBrowserUnlocked(data);
      const tenant = normalizeTenant(payload, payload.id || crypto.randomUUID());
      data.tenants = upsertById(data.tenants, tenant);
      if (!data.active_tenant_id) {
        data.active_tenant_id = tenant.id;
      }
      save(data);
      return snapshot(data);
    },
    async deleteTenant(tenantId) {
      const data = load();
      ensureBrowserUnlocked(data);
      data.tenants = data.tenants.filter((item) => item.id !== tenantId);
      if (data.active_tenant_id === tenantId) {
        data.active_tenant_id = data.tenants[0]?.id || null;
      }
      data.tokens.identity = null;
      data.tokens.platform = null;
      save(data);
      return snapshot(data);
    },
    async setActiveTenant(tenantId) {
      const data = load();
      ensureBrowserUnlocked(data);
      data.active_tenant_id = tenantId;
      data.tokens.identity = null;
      data.tokens.platform = null;
      save(data);
      return snapshot(data);
    },
    async resolveTenant(subdomain) {
      const clean = cleanSubdomain(subdomain);
      if (!clean) {
        throw new Error("Enter a tenant subdomain first.");
      }
      const identityTenantHost = `${clean}.id.cyberark.cloud`;
      return {
        subdomain: clean,
        shared_services_url: `https://${clean}.cyberark.cloud`,
        identity_tenant_host: identityTenantHost,
        identity_token_url_prefix: `https://${identityTenantHost}/oauth2/token`,
        platform_token_url: `https://${identityTenantHost}/oauth2/platformtoken`,
        vault_api_base_url: `https://${clean}.privilegecloud.cyberark.cloud/PasswordVault/API`,
        audit_api_base_url: `https://${clean}.audit.cyberark.cloud`,
        inferred_identity_host: false
      };
    },
    async requestIdentityToken() {
      throw new Error("Token requests are only available in the desktop app.");
    },
    async requestPlatformToken() {
      throw new Error("Token requests are only available in the desktop app.");
    },
    async copyRuntimeToken() {
      throw new Error("Token copy is only available in the desktop app.");
    },
    async authenticateInteractiveUser() {
      throw new Error("Interactive authentication is only available in the desktop app.");
    },
    async advanceInteractiveAuthentication() {
      throw new Error("Interactive authentication is only available in the desktop app.");
    },
    async clearTokens() {
      const data = load();
      ensureBrowserUnlocked(data);
      data.tokens = { identity: null, platform: null };
      save(data);
      return snapshot(data);
    },
    async executeVaultRequest(payload) {
      throw new Error("Vault requests are only available in the desktop app.");
    },
    async getConnectionComponentTelemetry() {
      const now = new Date();
      return {
        generated_at: now.toISOString(),
        date_from: new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString(),
        date_to: now.toISOString(),
        audit_api_base_url: "Browser preview",
        total_connections: 0,
        components: []
      };
    },
    async getAccountFailureTelemetry() {
      return {
        generated_at: new Date().toISOString(),
        account_source_url: "Browser preview",
        recording_source_url: "Browser preview",
        total_failures: 0,
        total_accounts: 0,
        categories: []
      };
    },
    async remediateAccountFailures() {
      throw new Error("Account remediation is only available in the desktop app.");
    },
    async getActiveUserTelemetry() {
      return {
        generated_at: new Date().toISOString(),
        identity_error: null,
        identity_active_count: 0,
        identity_recently_inactive_count: 0,
        identity_long_inactive_count: 0,
        identity_active_users: [],
        identity_recently_inactive_users: [],
        identity_long_inactive_users: []
      };
    },
    async exportConfig() {
      const data = load();
      return JSON.stringify(
        {
          profiles: data.profiles,
          tenants: data.tenants,
          active_profile_id: data.active_profile_id,
          active_tenant_id: data.active_tenant_id
        },
        null,
        2
      );
    },
    async saveTextFile() {
      throw new Error("Native save dialogs are only available in the desktop app.");
    },
    async updateProfileSecret(payload) {
      throw new Error("Client secrets can only be stored in the desktop app.");
    },
    async importConfig(payload) {
      const current = load();
      ensureBrowserUnlocked(current);
      const parsed = JSON.parse(payload);
      const data = {
        profiles: Array.isArray(parsed.profiles) ? parsed.profiles : [],
        tenants: Array.isArray(parsed.tenants) ? parsed.tenants : [],
        active_profile_id: parsed.active_profile_id || parsed.profiles?.[0]?.id || null,
        active_tenant_id: parsed.active_tenant_id || parsed.tenants?.[0]?.id || null,
        tokens: {
          identity: null,
          platform: null
        }
      };
      save(data);
      return snapshot(data);
    }
  };
}

async function refreshSnapshot() {
  state.snapshot = await bridge.getState();
}

function render() {
  try {
    const lockButtonLabel = state.snapshot.session_locked ? "Locked" : "Lock";
    document.querySelector("#app").innerHTML = `
    <div class="shell">
      <header class="topbar card">
        <div class="brand">
          <div class="logo-mark" aria-hidden="true">FP</div>
          <div>
            <p class="eyebrow">Your fast-pass to CyberArk API</p>
            <h1>FastPAS</h1>
          </div>
        </div>
        <nav class="top-nav">
          ${PAGES.map((page) => `<button class="nav-item ${state.page === page ? "active" : ""}" data-page="${page}">${capitalize(page)}</button>`).join("")}
        </nav>
        <div class="top-actions">
          <button id="session-lock-toggle" class="theme-toggle ghost">${lockButtonLabel}</button>
        </div>
      </header>
      ${renderTokenCopyWarningBanner()}
      <main class="main">
        ${renderPage()}
      </main>
      ${renderSessionOverlay()}
    </div>
  `;

    wireEvents();
    updateSessionTimeoutIndicator();
  } catch (error) {
    renderFatalScreen(`Render failed: ${formatError(error)}`);
  }
}

function renderFatalScreen(message) {
  const root = document.querySelector("#app");
  if (!root) {
    return;
  }
  root.innerHTML = `
    <div class="fatal-screen">
      <h2>FastPAS startup error</h2>
      <p>The app failed to initialize correctly.</p>
      ${renderConsoleViewer(message, {
        title: "Startup Trace",
        emptyMessage: "No startup details were provided.",
        compact: true
      })}
    </div>
  `;
}

function renderTokenCopyWarningBanner() {
  if (!state.settings.enableTokenCopy) {
    return "";
  }
  const remainingMs = tokenCopyWindowRemainingMs();
  if (remainingMs <= 0) {
    return "";
  }
  const remainingSeconds = Math.ceil(remainingMs / 1000);
  return `
    <section class="card token-copy-warning">
      <strong>Token copy is temporarily enabled.</strong>
      <span id="token-copy-warning-text">It will turn off automatically in ${remainingSeconds}s.</span>
    </section>
  `;
}

function renderSessionOverlay() {
  if (!state.snapshot.passcode_configured) {
    return `
      <section class="session-overlay">
        <div class="session-modal card">
        <div class="card-head">
          <h3>Secure FastPAS</h3>
          <p>Set a session passcode for this app. It will be stored in the OS keychain and required when the app is reopened.</p>
        </div>
        <form id="session-setup-form" class="form-grid">
          <label class="wide field"><span>Passcode</span><input name="passcode" type="password" value="${escapeAttr(state.forms.session.setupPasscode)}" placeholder="At least 8 characters, with upper/lowercase and a number" /></label>
          <label class="wide field"><span>Confirm Passcode</span><input name="confirm_passcode" type="password" value="${escapeAttr(state.forms.session.confirmPasscode)}" placeholder="Re-enter passcode" /></label>
            <div class="button-row wide session-actions">
              <button type="submit">Save Passcode</button>
            </div>
          </form>
        </div>
      </section>
    `;
  }

  if (!state.snapshot.session_locked) {
    return "";
  }

  return `
    <section class="session-overlay">
      <div class="session-modal card">
        <div class="card-head">
          <h3>Session Locked</h3>
          <p>Enter the FastPAS passcode to unlock this session.</p>
        </div>
        <form id="session-unlock-form" class="form-grid">
          <label class="wide field"><span>Passcode</span><input name="passcode" type="password" value="${escapeAttr(state.forms.session.unlockPasscode)}" placeholder="Enter passcode" /></label>
          <div class="button-row wide session-actions">
            <button type="submit">Unlock Session</button>
          </div>
        </form>
      </div>
    </section>
  `;
}

function renderActivityPanel() {
  if (!state.activity.length) {
    return "";
  }

  return `
    <section class="card">
      <div class="card-head">
        <h3>Activity</h3>
        <p>Recent actions and request errors appear here immediately.</p>
      </div>
      ${renderConsoleViewer(state.activity.slice(0, 6).join("\n"), {
        title: "Session Log",
        emptyMessage: "No recent actions yet.",
        compact: true
      })}
    </section>
  `;
}

function renderPage() {
  if (state.page === "api") {
    return `${renderApiPage()}${renderActivityPanel()}`;
  }
  if (state.page === "tools") {
    return renderToolsPage();
  }
  if (state.page === "telemetry") {
    return renderTelemetryPage();
  }
  if (state.page === "profiles") {
    return renderProfilesPage();
  }
  if (state.page === "tenants") {
    return renderTenantsPage();
  }
  if (state.page === "settings") {
    return renderSettingsPage();
  }
  if (state.page === DEBUG_PAGE) {
    return renderDebugPage();
  }
  return renderDocsPage();
}

function renderApiPage() {
  const activeProfile = getActiveProfile();
  const activeTenant = getActiveTenant();
  const response = state.api.response;
  const report = state.api.report;
  const selectedTask = findPresetById(state.api.selectedPresetId);
  const filteredGroups = filterTaskGroups(state.api.searchQuery);
  const searchMatches = findTaskMatches(state.api.searchQuery);
  const activeUrls = deriveTenantUrls(activeTenant, activeProfile);
  const identityUrls = deriveIdentityUrls(activeProfile, activeTenant);
  const interactiveUrls = deriveInteractiveAuthUrls(activeProfile, activeTenant);
  const oauthProfileActive = Boolean(activeProfile) && !isInteractiveProfile(activeProfile);
  const interactiveProfileActive = isInteractiveProfile(activeProfile);
  const interactiveChallengePanel = renderInteractiveChallengePanel();
  const identityTokenView = tokenIndicatorView("identity");
  const platformTokenView = tokenIndicatorView("platform");
  return `
    <section class="page-grid api-layout">
      <section class="card api-sidebar">
        <div class="card-head">
          <div class="auth-headline">
            <h3>Authentication</h3>
            ${renderSessionTimeoutBadge()}
          </div>
        </div>
        <section class="flow-step auth-compact">
          <div class="auth-summary">
            <div class="auth-summary-card auth-summary-primary">
              <span class="auth-label">Profile</span>
              <strong>${escapeHtml(profileDisplayName(activeProfile))}</strong>
              <small>${escapeHtml(profileSummaryLabel(activeProfile))}</small>
            </div>
            <div class="auth-summary-card auth-summary-primary">
              <span class="auth-label">Tenant</span>
              <strong>${escapeHtml(activeTenant?.name || "None")}</strong>
              <small>${escapeHtml(activeTenant?.subdomain || "No subdomain configured")}</small>
            </div>
            <div class="auth-summary-card auth-status-card ${identityTokenView.status}">
              ${state.settings.enableTokenCopy && identityTokenView.status === "active"
                ? `<button type="button" class="token-copy-btn" data-copy-runtime-token="identity">Copy</button>`
                : ""}
              <span class="auth-label">Identity</span>
              <strong>${identityTokenView.status_label}</strong>
              <small>${escapeHtml(identityUrls.identityTenantHost || "No host")}</small>
            </div>
            <div class="auth-summary-card auth-status-card ${platformTokenView.status}">
              ${state.settings.enableTokenCopy && platformTokenView.status === "active"
                ? `<button type="button" class="token-copy-btn" data-copy-runtime-token="platform">Copy</button>`
                : ""}
              <span class="auth-label">Platform</span>
              <strong>${platformTokenView.status_label}</strong>
              <small>${escapeHtml(activeUrls.platformTokenUrl ? "Privilege Cloud ready" : "No endpoint")}</small>
            </div>
          </div>
          <div class="auth-actions">
            ${oauthProfileActive ? `
            <div class="auth-action">
              <div class="step-copy">
                <span class="step-tag">OAuth Session (Identity + Platform)</span>
                <p class="auth-endpoint">${escapeHtml(identityUrls.identityTokenUrl || "No Identity endpoint configured")}</p>
                <p class="auth-endpoint">${escapeHtml(activeUrls.platformTokenUrl || "No platform endpoint configured")}</p>
              </div>
              <div class="button-row">
                <button id="request-oauth-session" class="auth-action-button">Request OAuth + Platform Tokens <span aria-hidden="true">→</span></button>
                <button type="button" id="copy-oauth-curl" class="ghost copy-curl-btn">Copy CURL</button>
                <button type="button" id="copy-oauth-powershell" class="ghost copy-powershell-btn">Copy PowerShell</button>
              </div>
            </div>
            ` : ""}
            ${interactiveProfileActive ? `
            <div class="auth-action">
              <div class="step-copy">
                <span class="step-tag">Interactive Authentication (Start/Advance)</span>
                <p class="auth-endpoint">${escapeHtml(interactiveUrls.startAuthenticationUrl || "No interactive endpoint configured")}</p>
              </div>
              <div class="button-row">
                <button id="request-interactive-token" class="auth-action-button">Authenticate Interactive User <span aria-hidden="true">→</span></button>
                <button type="button" id="copy-interactive-curl" class="ghost copy-curl-btn">Copy CURL</button>
                <button type="button" id="copy-interactive-powershell" class="ghost copy-powershell-btn">Copy PowerShell</button>
              </div>
            </div>
            ` : ""}
          </div>
          ${interactiveProfileActive ? interactiveChallengePanel : ""}
        </section>
      </section>
      <section class="api-main">
        <section class="card">
          <div class="card-head">
            <h3>What Do You Want To Do?</h3>
            <p>Pick a task below. FastPAS prepares the request for you.</p>
          </div>
          <label class="field task-search">
            <input id="task-search" value="${escapeAttr(state.api.searchQuery)}" placeholder="Search Tasks..." />
          </label>
          ${renderTaskSearchResults(searchMatches, state.api.searchQuery)}
          <div class="task-groups">
            ${filteredGroups.map(renderPresetSection).join("") || `<p class="empty-task">No tasks match your search.</p>`}
          </div>
          ${renderTaskWorkspace(selectedTask)}
        </section>
        <section class="card">
          <div class="card-head">
            <h3>Response Viewer</h3>
            <p>The response body is shown here after a vault request is executed.</p>
          </div>
          <div class="button-row response-actions">
            <button type="button" id="download-response-txt" class="ghost" ${response || report ? "" : "disabled"}>Download as TXT</button>
            <button type="button" id="download-response-csv" class="ghost" ${response || report ? "" : "disabled"}>Download as CSV</button>
          </div>
          ${report ? renderApiReport(report) : ""}
          <div class="response-meta">
            <div class="context-pill">
              <span>Status</span>
              <strong>${response ? response.status : "Not sent"}</strong>
            </div>
            <div class="context-pill response-url">
              <span>URL</span>
              <strong>${escapeHtml(response?.url || "No request sent yet")}</strong>
            </div>
          </div>
          ${renderConsoleViewer(response?.body || "", {
            title: "Vault Response",
            emptyMessage: "Run a request to inspect the response body here."
          })}
        </section>
      </section>
    </section>
  `;
}

function renderSessionTimeoutBadge() {
  if (!state.snapshot.passcode_configured) {
    return "";
  }
  const label = state.snapshot.session_locked
    ? "Locked"
    : formatSessionTimeout(remainingSessionTimeoutMs());
  return `<span id="auth-timeout-indicator" class="session-timeout-badge">${escapeHtml(label)}</span>`;
}

function renderTaskWorkspace(task) {
  if (!task) {
    return `
      <section class="task-workspace empty-task">
        <p>Select a task above to continue.</p>
      </section>
    `;
  }

  const values = state.api.taskInputs;
  if (task.ready === false) {
    return `
      <section class="task-workspace">
        <div class="card-head">
          <h4>${escapeHtml(task.name)}</h4>
          <p>${escapeHtml(task.description)}</p>
        </div>
        <div class="task-summary">
          <span class="step-tag">Next Step</span>
          <p>${escapeHtml(task.blockedReason || "This task is not yet wired into FastPAS.")}</p>
        </div>
      </section>
    `;
  }
  return `
    <form id="task-run-form" class="task-workspace">
      <div class="card-head">
        <h4>${escapeHtml(task.name)}</h4>
        <p>${escapeHtml(task.description)}</p>
      </div>
      <div class="task-field-grid">
        ${renderTaskFields(task, values)}
      </div>
      <div class="task-summary">
        <span class="step-tag">FastPAS Will</span>
        <p>${escapeHtml(describeTask(task, values))}</p>
      </div>
      ${state.api.lastRunPresetId === task.id ? renderTaskChains(task, values, state.api.response) : ""}
      <div class="button-row">
        <button type="submit">Run Task</button>
        ${REPORT_TASK_IDS.has(task.id)
          ? `<button type="button" id="copy-task-curl" class="ghost copy-curl-btn">Copy CURL</button>
             <button type="button" id="copy-task-powershell" class="ghost copy-powershell-btn">Copy PowerShell</button>`
          : ""}
        <button type="button" id="task-selection-clear" class="ghost">Choose A Different Task</button>
      </div>
    </form>
  `;
}

function renderTaskFields(task, values) {
  if (task.id === "account-search") {
    return `
      <label class="wide field"><span>Search For</span><input name="query" value="${escapeAttr(values.query || "")}" placeholder="Account name, username, or host" /></label>
    `;
  }
  if (task.id === "account-details") {
    return `
      <label class="wide field"><span>Account ID</span><input name="account_id" value="${escapeAttr(values.account_id || "")}" placeholder="12_34" /></label>
    `;
  }
  if (task.id === "safe-members") {
    return `
      <label class="wide field"><span>Safe Name</span><input name="safe_name" value="${escapeAttr(values.safe_name || "")}" placeholder="MySafe" /></label>
    `;
  }
  if (task.id === "safe-details") {
    return `
      <label class="wide field"><span>Safe Name</span><input name="safe_name" value="${escapeAttr(values.safe_name || "")}" placeholder="MySafe" /></label>
    `;
  }
  if (task.id === "platform-details") {
    return `
      <label class="wide field"><span>Platform ID</span><input name="platform_id" value="${escapeAttr(values.platform_id || "")}" placeholder="WinServerLocal" /></label>
    `;
  }
  if (task.id === "safes") {
    return `
      <label class="field"><span>Limit</span><input name="limit" value="${escapeAttr(values.limit || "100")}" placeholder="100" /></label>
      <label class="field"><span>Offset</span><input name="offset" value="${escapeAttr(values.offset || "0")}" placeholder="0" /></label>
    `;
  }
  if (task.id === "account-report") {
    return `
      <label class="field"><span>Limit</span><input name="limit" value="${escapeAttr(values.limit || "1000")}" placeholder="1000" /></label>
      <label class="field"><span>Offset</span><input name="offset" value="${escapeAttr(values.offset || "0")}" placeholder="0" /></label>
    `;
  }
  if (task.id === "platform-report") {
    return `
      <label class="wide field"><span>Report Scope</span><input name="report_scope" value="${escapeAttr(values.report_scope || "All visible platforms")}" placeholder="All visible platforms" /></label>
    `;
  }
  if (task.id === "user-template") {
    return `
      <label class="field"><span>Username</span><input name="username" value="${escapeAttr(values.username || "")}" placeholder="new.user" /></label>
      <label class="field"><span>Initial Password</span><input name="initialPassword" type="password" value="${escapeAttr(values.initialPassword || "")}" placeholder="ChangeMeNow1!" /></label>
    `;
  }
  if (task.id === "create-safe") {
    return `
      <label class="field"><span>Safe Name</span><input name="safe_name" value="${escapeAttr(values.safe_name || "")}" placeholder="Operations-Shared" /></label>
      <label class="field"><span>Description</span><input name="description" value="${escapeAttr(values.description || "")}" placeholder="Shared operations access" /></label>
      <label class="field"><span>Managing CPM</span><input name="managing_cpm" value="${escapeAttr(values.managing_cpm || "")}" placeholder="PasswordManager" /></label>
      <label class="field"><span>Retention Days</span><input name="retention_days" value="${escapeAttr(values.retention_days || "")}" placeholder="Leave blank to keep 7 versions" /></label>
    `;
  }
  if (task.id === "add-safe-member") {
    return `
      <label class="field"><span>Safe Name</span><input name="safe_name" value="${escapeAttr(values.safe_name || "")}" placeholder="Operations-Shared" /></label>
      <label class="field"><span>User Or Group</span><input name="member_name" value="${escapeAttr(values.member_name || "")}" placeholder="svc-fastpas" /></label>
      <label class="field"><span>Role</span>
        <select name="member_role">
          ${["EndUser", "Auditor", "Approver", "Owner", "Admin"].map((role) => `
            <option value="${role}" ${values.member_role === role ? "selected" : ""}>${role}</option>
          `).join("")}
        </select>
      </label>
      <label class="field"><span>Member Type</span>
        <select name="member_type">
          ${["User", "Group", "Role"].map((type) => `
            <option value="${type}" ${values.member_type === type ? "selected" : ""}>${type}</option>
          `).join("")}
        </select>
      </label>
      <label class="wide field"><span>Search In</span><input name="member_location" value="${escapeAttr(values.member_location || "")}" placeholder="Vault or LDAP directory name" /></label>
    `;
  }
  return `<p class="task-helper">No extra details are needed for this task.</p>`;
}

function describeTask(task, values) {
  if (task.id === "account-search") {
    return values.query?.trim()
      ? `Search accounts in the active tenant for "${values.query.trim()}".`
      : "Search accounts in the active tenant after you enter a search term.";
  }
  if (task.id === "account-details") {
    return values.account_id?.trim()
      ? `Look up the details for account ID ${values.account_id.trim()}.`
      : "Look up the details for one account after you enter the account ID.";
  }
  if (task.id === "safe-members") {
    return values.safe_name?.trim()
      ? `List the members assigned to safe ${values.safe_name.trim()}.`
      : "List the members assigned to one safe after you enter the safe name.";
  }
  if (task.id === "safe-details") {
    return values.safe_name?.trim()
      ? `Open safe ${values.safe_name.trim()} and review its current settings.`
      : "Open one safe after you enter the safe name.";
  }
  if (task.id === "platform-details") {
    return values.platform_id?.trim()
      ? `Look up platform details for ${values.platform_id.trim()}.`
      : "Look up one platform after you enter the platform ID.";
  }
  if (task.id === "safes") {
    return `List safes using limit ${values.limit || "100"} and offset ${values.offset || "0"}.`;
  }
  if (task.id === "account-report") {
    return `Build a managed-failure report using page limit ${values.limit || "1000"} starting at offset ${values.offset || "0"}.`;
  }
  if (task.id === "platform-report") {
    return "Export a platform inventory report for the current session.";
  }
  if (task.id === "user-template") {
    return `Create a new vault user starter request${values.username?.trim() ? ` for ${values.username.trim()}` : ""}.`;
  }
  if (task.id === "create-safe") {
    return values.safe_name?.trim()
      ? `Create safe ${values.safe_name.trim()}${values.managing_cpm?.trim() ? ` with CPM ${values.managing_cpm.trim()}` : ""}.`
      : "Create a new safe after you enter the safe name and optional retention settings.";
  }
  if (task.id === "add-safe-member") {
    const memberName = values.member_name?.trim();
    const safeName = values.safe_name?.trim();
    if (memberName && safeName) {
      return `Add ${memberName} to safe ${safeName} with the ${values.member_role || "EndUser"} role.`;
    }
    return "Add a user or group to a safe using a guided permission role.";
  }
  if (task.id === "health") {
    return "Check the Password Vault health endpoint for the active tenant.";
  }
  if (task.id === "platforms") {
    return "List the configured platforms in the active tenant.";
  }
  if (task.id === "safes") {
    return "List the safes available to the active platform token.";
  }
  if (task.id === "out-of-sync-accounts") {
    return "Find accounts with failed secret management status and build a report.";
  }
  return task.description;
}

function buildTaskRequest(task, values) {
  if (task.id === "account-search") {
    const search = values.query?.trim();
    if (!search) {
      throw new Error("Enter what you want to search for first.");
    }
    return {
      name: task.name,
      description: task.description,
      method: task.method,
      path: task.path,
      query: `search=${encodeURIComponent(search)}&limit=25`,
      body: ""
    };
  }
  if (task.id === "account-details") {
    const accountId = values.account_id?.trim();
    if (!accountId) {
      throw new Error("Enter an account ID first.");
    }
    return {
      name: task.name,
      description: task.description,
      method: task.method,
      path: `Accounts/${accountId}`,
      query: "",
      body: ""
    };
  }
  if (task.id === "safe-members") {
    const safeName = values.safe_name?.trim();
    if (!safeName) {
      throw new Error("Enter a safe name first.");
    }
    return {
      name: task.name,
      description: task.description,
      method: task.method,
      path: `Safes/${encodeURIComponent(safeName)}/Members`,
      query: "",
      body: ""
    };
  }
  if (task.id === "safe-details") {
    const safeName = values.safe_name?.trim();
    if (!safeName) {
      throw new Error("Enter a safe name first.");
    }
    return {
      name: task.name,
      description: task.description,
      method: task.method,
      path: `Safes/${encodeURIComponent(safeName)}`,
      query: "",
      body: ""
    };
  }
  if (task.id === "platform-details") {
    const platformId = values.platform_id?.trim();
    if (!platformId) {
      throw new Error("Enter a platform ID first.");
    }
    return {
      name: task.name,
      description: task.description,
      method: task.method,
      path: `Platforms/${encodeURIComponent(platformId)}`,
      query: "",
      body: ""
    };
  }
  if (task.id === "safes") {
    const limit = values.limit?.trim() || "100";
    const offset = values.offset?.trim() || "0";
    return {
      name: task.name,
      description: task.description,
      method: task.method,
      path: task.path,
      query: `limit=${encodeURIComponent(limit)}&offset=${encodeURIComponent(offset)}`,
      body: ""
    };
  }
  if (task.id === "account-report") {
    const limit = values.limit?.trim() || "1000";
    const offset = values.offset?.trim() || "0";
    return {
      name: task.name,
      description: task.description,
      method: task.method,
      path: task.path,
      query: `limit=${encodeURIComponent(limit)}&offset=${encodeURIComponent(offset)}`,
      body: ""
    };
  }
  if (task.id === "platform-report") {
    return {
      name: task.name,
      description: task.description,
      method: task.method,
      path: task.path,
      query: "",
      body: ""
    };
  }
  if (task.id === "user-template") {
    const username = values.username?.trim() || "new.user";
    const initialPassword = values.initialPassword?.trim() || "ChangeMeNow1!";
    return {
      name: task.name,
      description: task.description,
      method: task.method,
      path: task.path,
      query: "",
      body: JSON.stringify(
        {
          username,
          initialPassword,
          userTypeName: "EPVUser",
          location: "\\",
          expiryDate: 0,
          authenticationMethod: ["AuthTypePass"]
        },
        null,
        2
      )
    };
  }
  if (task.id === "create-safe") {
    const safeName = values.safe_name?.trim();
    if (!safeName) {
      throw new Error("Enter a safe name first.");
    }
    const retentionDaysRaw = values.retention_days?.trim();
    const retentionDays = retentionDaysRaw ? Number(retentionDaysRaw) : null;
    if (retentionDaysRaw && (!Number.isFinite(retentionDays) || retentionDays < 0)) {
      throw new Error("Retention days must be 0 or greater.");
    }
    const body = {
      SafeName: safeName,
      Description: values.description?.trim() || "",
      OLACEnabled: false,
      ManagingCPM: values.managing_cpm?.trim() || "",
      ...(retentionDaysRaw ? { NumberOfDaysRetention: retentionDays } : { NumberOfVersionsRetention: 7 })
    };
    return {
      name: task.name,
      description: task.description,
      method: task.method,
      path: task.path,
      query: "",
      body: JSON.stringify(body, null, 2)
    };
  }
  if (task.id === "add-safe-member") {
    const safeName = values.safe_name?.trim();
    const memberName = values.member_name?.trim();
    if (!safeName) {
      throw new Error("Enter a safe name first.");
    }
    if (!memberName) {
      throw new Error("Enter the user or group name first.");
    }
    return {
      name: task.name,
      description: task.description,
      method: task.method,
      path: `Safes/${encodeURIComponent(safeName)}/Members`,
      query: "",
      body: JSON.stringify(
        {
          MemberName: memberName,
          SearchIn: values.member_location?.trim() || "Vault",
          MemberType: values.member_type || "User",
          MembershipExpirationDate: null,
          Permissions: safeMemberPermissions(values.member_role || "EndUser")
        },
        null,
        2
      )
    };
  }
  return {
    name: task.name,
    description: task.description,
    method: task.method,
    path: task.path,
    query: task.query,
    body: task.body
  };
}

async function executeAccountReportRequest(builder, values) {
  const limit = Number.parseInt(values.limit?.trim() || "1000", 10);
  const startOffset = Number.parseInt(values.offset?.trim() || "0", 10);
  if (!Number.isFinite(limit) || limit <= 0) {
    throw new Error("Limit must be a positive number.");
  }
  if (!Number.isFinite(startOffset) || startOffset < 0) {
    throw new Error("Offset must be 0 or greater.");
  }

  const allAccounts = [];
  let offset = startOffset;
  let totalCount = 0;
  let firstUrl = "";
  const maxPages = 200;

  for (let page = 0; page < maxPages; page += 1) {
    const query = `limit=${encodeURIComponent(String(limit))}&offset=${encodeURIComponent(String(offset))}`;
    const pageResponse = await bridge.executeVaultRequest({
      method: builder.method,
      path: builder.path,
      query,
      body: builder.body
    });
    if (!firstUrl) {
      firstUrl = pageResponse.url || "";
    }
    if (!responseSucceeded(pageResponse)) {
      return pageResponse;
    }

    const parsed = parseResponseBody(pageResponse.body);
    const pageItems = Array.isArray(parsed?.value) ? parsed.value : null;
    if (!pageItems) {
      return pageResponse;
    }

    if (Number.isFinite(parsed?.count)) {
      totalCount = parsed.count;
    }
    allAccounts.push(...pageItems);

    if (pageItems.length < limit) {
      break;
    }
    if (totalCount > 0 && allAccounts.length >= totalCount) {
      break;
    }
    offset += limit;
  }

  return {
    status: 200,
    url: firstUrl ? `${firstUrl} (paged aggregate)` : "",
    body: JSON.stringify(
      {
        count: totalCount || allAccounts.length,
        value: allAccounts
      },
      null,
      2
    )
  };
}

function runtimeBlock(label, token) {
  return `
    <div class="runtime-card">
      <h4>${label}</h4>
      <p><strong>Status</strong><span>${token.status_label}</span></p>
      <p><strong>Source</strong><span>${escapeHtml(token.source || "None")}</span></p>
      <p><strong>Endpoint</strong><span>${escapeHtml(token.endpoint || "None")}</span></p>
      <p><strong>Expires</strong><span>${escapeHtml(token.expires_at_label)}</span></p>
    </div>
  `;
}

function renderPresetSection(group) {
  return `
    <details class="preset-section">
      <summary class="preset-summary">
        <h4>${escapeHtml(group.section)}</h4>
      </summary>
      <div class="preset-list">
        ${group.items.map((item) => `
          <button
            class="preset-item ${state.api.selectedPresetId === item.id ? "active" : ""}"
            type="button"
            data-preset-id="${item.id}"
          >
            <strong>${escapeHtml(item.name)}</strong>
            <span>${escapeHtml(item.description)}</span>
            ${item.ready === false ? `<small class="task-status">Needs workflow support</small>` : ""}
          </button>
        `).join("")}
      </div>
    </details>
  `;
}

function renderTaskSearchResults(matches, query) {
  if (!query.trim()) {
    return "";
  }
  return `
    <section class="task-search-results">
      ${matches.length
        ? matches.map((item) => `
          <button
            class="preset-item ${state.api.selectedPresetId === item.id ? "active" : ""}"
            type="button"
            data-task-search-select="${item.id}"
          >
            <strong>${escapeHtml(item.name)}</strong>
            <span>${escapeHtml(item.section)} · ${escapeHtml(item.description)}</span>
            ${item.ready === false ? `<small class="task-status">Needs workflow support</small>` : ""}
          </button>
        `).join("")
        : `<p class="task-helper">No matching tasks found.</p>`}
    </section>
  `;
}

function renderTaskChains(task, values, response) {
  const options = buildTaskChains(task, values, response);
  if (!options.length) {
    return "";
  }
  return `
    <section class="task-chain-panel">
      <div class="task-chain-head">
        <span class="step-tag">Continue With</span>
        <p>FastPAS can carry this context into the next task.</p>
      </div>
      <div class="task-chain-list">
        ${options.map((option) => `
          <button
            type="button"
            class="task-chain-button"
            data-chain-task="${option.id}"
            data-chain-seed="${escapeAttr(JSON.stringify(option.seed || {}))}"
          >
            <strong>${escapeHtml(option.label)}</strong>
            <span>${escapeHtml(option.description)}</span>
          </button>
        `).join("")}
      </div>
    </section>
  `;
}

function renderApiReport(report) {
  return `
    <section class="report-panel">
      <div class="card-head">
        <h3>${escapeHtml(report.title)}</h3>
        <p>${escapeHtml(report.subtitle)}</p>
      </div>
      <div class="report-summary-grid">
        <div class="context-pill report-pill"><span>Failed Accounts</span><strong>${report.failedCount}</strong></div>
        <div class="context-pill report-pill"><span>Total Accounts</span><strong>${report.totalCount}</strong></div>
        <div class="context-pill report-pill"><span>Failure Reasons</span><strong>${report.reasonCount}</strong></div>
      </div>
      ${renderConsoleViewer(report.body, {
        title: "Report Output",
        emptyMessage: "No report output available.",
        compact: true
      })}
    </section>
  `;
}

function renderConsoleViewer(content, options = {}) {
  const {
    title = "Console",
    emptyMessage = "Nothing to display yet.",
    compact = false
  } = options;
  const consoleState = normalizeConsoleContent(content);
  const panelClass = compact ? "console-panel compact" : "console-panel";
  const formatLabel = consoleState.format === "json"
    ? "JSON"
    : consoleState.format === "markup"
      ? "HTML"
      : "Text";

  return `
    <section class="${panelClass}">
      <div class="console-toolbar">
        <div class="console-toolbar-left">
          <div class="console-dots" aria-hidden="true">
            <span class="console-dot dot-red"></span>
            <span class="console-dot dot-amber"></span>
            <span class="console-dot dot-green"></span>
          </div>
          <strong class="console-title">${escapeHtml(title)}</strong>
        </div>
        <div class="console-toolbar-right">
          <span class="console-pill">${formatLabel}</span>
          <span class="console-pill">${consoleState.lines.length} line${consoleState.lines.length === 1 ? "" : "s"}</span>
          <span class="console-pill">${consoleState.text.length} chars</span>
        </div>
      </div>
      <div class="console-window" role="region" aria-label="${escapeAttr(title)}">
        ${consoleState.hasContent
          ? consoleState.lines.map((line, index) => `
            <div class="console-line">
              <span class="console-gutter">${index + 1}</span>
              <span class="console-code">${highlightConsoleLine(line, consoleState.format)}</span>
            </div>
          `).join("")
          : `<div class="console-empty">${escapeHtml(emptyMessage)}</div>`}
      </div>
    </section>
  `;
}

function normalizeConsoleContent(content) {
  let text = "";
  if (typeof content === "string") {
    text = content;
  } else if (content != null) {
    try {
      text = JSON.stringify(content, null, 2);
    } catch {
      text = String(content);
    }
  }

  text = text.replaceAll("\r\n", "\n");
  const trimmed = text.trim();
  let format = "text";

  if (trimmed) {
    if ((trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
      try {
        text = JSON.stringify(JSON.parse(trimmed), null, 2);
        format = "json";
      } catch {
        format = "text";
      }
    } else if (trimmed.startsWith("<") && trimmed.endsWith(">")) {
      format = "markup";
    }
  }

  const lines = text ? text.split("\n") : [];
  return {
    text,
    format,
    lines,
    hasContent: Boolean(trimmed)
  };
}

function highlightConsoleLine(line, format) {
  if (!line) {
    return "&nbsp;";
  }
  if (format !== "json") {
    return escapeHtml(line);
  }

  const keyMatch = line.match(/^(\s*)("(?:\\.|[^"\\])*")(\s*:)(.*)$/);
  if (keyMatch) {
    const [, indent, key, colon, rest] = keyMatch;
    return `${escapeHtml(indent)}<span class="token-key">${escapeHtml(key)}</span>${escapeHtml(colon)}${highlightJsonValue(rest)}`;
  }

  return highlightJsonValue(line);
}

function highlightJsonValue(segment) {
  const leadingWhitespace = segment.match(/^\s*/)?.[0] || "";
  const trimmed = segment.slice(leadingWhitespace.length);
  if (!trimmed) {
    return escapeHtml(segment);
  }

  const stringMatch = trimmed.match(/^("(?:\\.|[^"\\])*")(,?)$/);
  if (stringMatch) {
    return `${escapeHtml(leadingWhitespace)}<span class="token-string">${escapeHtml(stringMatch[1])}</span>${escapeHtml(stringMatch[2])}`;
  }

  const numberMatch = trimmed.match(/^(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)(,?)$/);
  if (numberMatch) {
    return `${escapeHtml(leadingWhitespace)}<span class="token-number">${escapeHtml(numberMatch[1])}</span>${escapeHtml(numberMatch[2])}`;
  }

  const literalMatch = trimmed.match(/^(true|false|null)(,?)$/);
  if (literalMatch) {
    return `${escapeHtml(leadingWhitespace)}<span class="token-literal">${escapeHtml(literalMatch[1])}</span>${escapeHtml(literalMatch[2])}`;
  }

  return escapeHtml(segment);
}

function buildPresetReport(presetId, response, tenantName) {
  const preset = findPresetById(presetId);
  if (!preset?.report) {
    return null;
  }
  if (preset.report === "managed-failure-accounts") {
    return buildManagedFailureAccountsReport(response, tenantName);
  }
  if (preset.report === "out-of-sync-accounts") {
    return buildOutOfSyncAccountsReport(response, tenantName);
  }
  return null;
}

function buildManagedFailureAccountsReport(response, tenantName) {
  let parsed;
  try {
    parsed = JSON.parse(response?.body || "{}");
  } catch {
    return {
      title: "Managed Failure Accounts",
      subtitle: "The vault response could not be parsed into a report.",
      failedCount: 0,
      totalCount: 0,
      reasonCount: 0,
      body: "Unable to parse the vault response body as JSON.",
      csv: "message\r\nUnable to parse the vault response body as JSON.\r\n"
    };
  }

  const accounts = Array.isArray(parsed?.value) ? parsed.value : [];
  const failedManagedAccounts = accounts.filter(
    (account) =>
      account?.secretManagement?.status === "failure" &&
      account?.secretManagement?.automaticManagementEnabled === true
  );
  const reasonCounts = new Map();
  for (const account of failedManagedAccounts) {
    const reason = account?.secretManagement?.manualManagementReason?.trim() || "No reason provided";
    reasonCounts.set(reason, (reasonCounts.get(reason) || 0) + 1);
  }
  const topReasons = [...reasonCounts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  const generatedAt = new Date().toLocaleString();
  const lines = [
    `Tenant: ${tenantName || "Unknown tenant"}`,
    `Generated: ${generatedAt}`,
    "Criteria: secretManagement.status = failure AND secretManagement.automaticManagementEnabled = true",
    `Total accounts scanned: ${parsed?.count ?? accounts.length}`,
    `Matched accounts: ${failedManagedAccounts.length}`,
    "",
    "Top failure reasons:",
    ...(topReasons.length
      ? topReasons.slice(0, 10).map(([reason, count]) => `- ${reason}: ${count}`)
      : ["- None"]),
    "",
    "Accounts:",
    ...(failedManagedAccounts.length
      ? failedManagedAccounts.map((account) => formatManagedFailureAccount(account))
      : ["- No matching accounts found."])
  ];

  return {
    title: "Managed Failure Accounts",
    subtitle:
      "Accounts where secretManagement.status = failure and secretManagement.automaticManagementEnabled = true.",
    failedCount: failedManagedAccounts.length,
    totalCount: parsed?.count ?? accounts.length,
    reasonCount: reasonCounts.size,
    body: lines.join("\n"),
    csv: buildManagedFailureAccountsCsv(failedManagedAccounts)
  };
}

function formatManagedFailureAccount(account) {
  const safe = account?.safeName || "Unknown safe";
  const platform = account?.platformId || "Unknown platform";
  const address = account?.address || "Unknown address";
  const username = account?.userName || "Unknown user";
  const name = account?.name || "Unnamed account";
  const id = account?.id || "Unknown ID";
  const reason = account?.secretManagement?.manualManagementReason?.trim() || "No reason provided";
  return `- [${safe}] ${name} | ${username} @ ${address} | ${platform} | ${reason} | id=${id}`;
}

function buildManagedFailureAccountsCsv(accounts) {
  const rows = [
    [
      "safe_name",
      "account_name",
      "username",
      "address",
      "platform_id",
      "secret_management_status",
      "automatic_management_enabled",
      "manual_management_reason",
      "account_id"
    ]
  ];
  if (!accounts.length) {
    rows.push(["", "No matching accounts found.", "", "", "", "", "", "", ""]);
  }
  for (const account of accounts) {
    rows.push([
      account?.safeName || "",
      account?.name || "",
      account?.userName || "",
      account?.address || "",
      account?.platformId || "",
      account?.secretManagement?.status || "",
      String(account?.secretManagement?.automaticManagementEnabled === true),
      account?.secretManagement?.manualManagementReason?.trim() || "",
      account?.id || ""
    ]);
  }
  return toCsv(rows);
}

function buildOutOfSyncAccountsReport(response, tenantName) {
  let parsed;
  try {
    parsed = JSON.parse(response?.body || "{}");
  } catch {
    return {
      title: "Out of Sync Accounts",
      subtitle: "The vault response could not be parsed into a report.",
      failedCount: 0,
      totalCount: 0,
      reasonCount: 0,
      body: "Unable to parse the vault response body as JSON.",
      csv: "message\r\nUnable to parse the vault response body as JSON.\r\n"
    };
  }

  const accounts = Array.isArray(parsed?.value) ? parsed.value : [];
  const failedAccounts = accounts.filter((account) => account?.secretManagement?.status === "failure");
  const reasonCounts = new Map();
  for (const account of failedAccounts) {
    const reason = account?.secretManagement?.manualManagementReason?.trim() || "No reason provided";
    reasonCounts.set(reason, (reasonCounts.get(reason) || 0) + 1);
  }
  const topReasons = [...reasonCounts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  const generatedAt = new Date().toLocaleString();
  const lines = [
    `Tenant: ${tenantName || "Unknown tenant"}`,
    `Generated: ${generatedAt}`,
    `Total accounts scanned: ${parsed?.count ?? accounts.length}`,
    `Out-of-sync accounts: ${failedAccounts.length}`,
    "",
    "Top failure reasons:",
    ...(topReasons.length
      ? topReasons.slice(0, 10).map(([reason, count]) => `- ${reason}: ${count}`)
      : ["- None"]),
    "",
    "Accounts:",
    ...(failedAccounts.length
      ? failedAccounts.map((account) => formatOutOfSyncAccount(account))
      : ["- No out-of-sync accounts found."])
  ];

  return {
    title: "Out of Sync Accounts",
    subtitle: "Accounts with secretManagement.status = failure in the current vault response.",
    failedCount: failedAccounts.length,
    totalCount: parsed?.count ?? accounts.length,
    reasonCount: reasonCounts.size,
    body: lines.join("\n"),
    csv: buildOutOfSyncAccountsCsv(failedAccounts)
  };
}

function formatOutOfSyncAccount(account) {
  const safe = account?.safeName || "Unknown safe";
  const platform = account?.platformId || "Unknown platform";
  const address = account?.address || "Unknown address";
  const username = account?.userName || "Unknown user";
  const name = account?.name || "Unnamed account";
  const id = account?.id || "Unknown ID";
  const reason = account?.secretManagement?.manualManagementReason?.trim() || "No reason provided";
  return `- [${safe}] ${name} | ${username} @ ${address} | ${platform} | ${reason} | id=${id}`;
}

function buildOutOfSyncAccountsCsv(accounts) {
  const rows = [
    ["safe_name", "account_name", "username", "address", "platform_id", "manual_management_reason", "account_id"]
  ];
  if (!accounts.length) {
    rows.push(["", "No out-of-sync accounts found.", "", "", "", "", ""]);
  }
  for (const account of accounts) {
    rows.push([
      account?.safeName || "",
      account?.name || "",
      account?.userName || "",
      account?.address || "",
      account?.platformId || "",
      account?.secretManagement?.manualManagementReason?.trim() || "",
      account?.id || ""
    ]);
  }
  return toCsv(rows);
}

function downloadResponseAsText() {
  const payload = state.api.report?.body || state.api.response?.body || "";
  if (!payload) {
    log("No response content available to download.");
    return;
  }
  saveDownload(payload, "text/plain;charset=utf-8", buildResponseFilename("txt"), "text").catch((error) => {
    log(formatError(error));
    render();
  });
}

function downloadResponseAsCsv() {
  const payload = state.api.report?.csv || buildCsvFromResponse(state.api.response);
  if (!payload) {
    log("No tabular response content available to download as CSV.");
    return;
  }
  saveDownload(payload, "text/csv;charset=utf-8", buildResponseFilename("csv"), "csv").catch((error) => {
    log(formatError(error));
    render();
  });
}

function buildCsvFromResponse(response) {
  if (!response?.body) {
    return "";
  }

  try {
    const parsed = JSON.parse(response.body);
    const rows = Array.isArray(parsed?.value)
      ? parsed.value
      : Array.isArray(parsed)
        ? parsed
        : parsed && typeof parsed === "object"
          ? [parsed]
          : [];
    return rows.length ? objectsToCsv(rows) : "";
  } catch {
    return toCsv([["response_body"], [response.body]]);
  }
}

function objectsToCsv(rows) {
  const keys = [...new Set(rows.flatMap((row) => Object.keys(flattenObject(row))))];
  const csvRows = [keys];
  for (const row of rows) {
    const flattened = flattenObject(row);
    csvRows.push(keys.map((key) => flattened[key] ?? ""));
  }
  return toCsv(csvRows);
}

function flattenObject(value, prefix = "", output = {}) {
  if (Array.isArray(value)) {
    output[prefix] = JSON.stringify(value);
    return output;
  }
  if (value && typeof value === "object") {
    for (const [key, nested] of Object.entries(value)) {
      const nextPrefix = prefix ? `${prefix}.${key}` : key;
      flattenObject(nested, nextPrefix, output);
    }
    return output;
  }
  output[prefix] = value ?? "";
  return output;
}

function toCsv(rows) {
  return rows.map((row) => row.map(csvCell).join(",")).join("\r\n").concat("\r\n");
}

function csvCell(value) {
  const normalized = String(value ?? "");
  return /[",\r\n]/.test(normalized) ? `"${normalized.replaceAll("\"", "\"\"")}"` : normalized;
}

function buildResponseFilename(extension) {
  const slug = slugify(state.api.builder.name || state.api.selectedPresetId || "response-viewer");
  return `${slug}.${extension}`;
}

async function copyCommandToClipboard(command, label) {
  try {
    await copyTextToClipboard(command);
    log(`Copied ${label} command.`);
    render();
  } catch (error) {
    log(`Failed to copy ${label} command: ${formatError(error)}`);
    render();
  }
}

async function copyRuntimeTokenWithPassword(kind) {
  if (!state.settings.enableTokenCopy || tokenCopyWindowRemainingMs() <= 0) {
    state.settings.enableTokenCopy = false;
    state.settings.tokenCopyEnabledAt = 0;
    persistSettings();
    stopTokenCopyWindowMonitor();
    log("Token copy is disabled. Re-enable it in Settings > Advanced.");
    render();
    return;
  }
  const normalizedKind = String(kind || "").trim().toLowerCase();
  if (normalizedKind !== "identity" && normalizedKind !== "platform") {
    return;
  }
  const activeProfile = getActiveProfile();
  if (!activeProfile) {
    log("Select an active profile first.");
    render();
    return;
  }
  const password = await promptForSecret({
    title: `Copy ${capitalize(normalizedKind)} Token`,
    message: `Enter password for ${profileDisplayName(activeProfile)}.`,
    confirmLabel: "Copy Token"
  });
  if (password === null) {
    return;
  }
  if (!password.trim()) {
    log("Password is required to copy the token.");
    render();
    return;
  }
  try {
    await bridge.copyRuntimeToken({
      kind: normalizedKind,
      profile_password: password
    });
    log(`Copied ${capitalize(normalizedKind)} token to clipboard. It will auto-clear in 30 seconds if unchanged.`);
    render();
  } catch (error) {
    log(formatError(error));
    render();
  }
}

function promptForSecret({ title = "Enter Password", message = "", confirmLabel = "Continue" } = {}) {
  return new Promise((resolve) => {
    const overlay = document.createElement("section");
    overlay.className = "session-overlay";
    overlay.innerHTML = `
      <div class="session-modal card">
        <div class="card-head">
          <h3>${escapeHtml(title)}</h3>
          <p>${escapeHtml(message)}</p>
        </div>
        <form class="form-grid" data-secret-prompt-form>
          <label class="wide field">
            <span>Password</span>
            <input name="secret" type="password" autocomplete="current-password" autofocus />
          </label>
          <div class="button-row wide session-actions">
            <button type="button" class="ghost" data-secret-prompt-cancel>Cancel</button>
            <button type="submit">${escapeHtml(confirmLabel)}</button>
          </div>
        </form>
      </div>
    `;

    const cleanup = (value) => {
      overlay.remove();
      resolve(value);
    };

    overlay.querySelector("[data-secret-prompt-cancel]")?.addEventListener("click", () => {
      cleanup(null);
    });

    overlay.querySelector("[data-secret-prompt-form]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      const payload = Object.fromEntries(new FormData(event.currentTarget).entries());
      cleanup(String(payload.secret || ""));
    });

    overlay.addEventListener("click", (event) => {
      if (event.target === overlay) {
        cleanup(null);
      }
    });

    document.body.appendChild(overlay);
    const input = overlay.querySelector("input[name='secret']");
    if (input) {
      input.focus();
      input.select();
    }
  });
}

async function copyTextToClipboard(value) {
  const text = String(value || "");
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "true");
  textarea.style.position = "absolute";
  textarea.style.left = "-9999px";
  document.body.appendChild(textarea);
  textarea.select();
  const copied = document.execCommand("copy");
  document.body.removeChild(textarea);
  if (!copied) {
    throw new Error("Clipboard API is unavailable in this context.");
  }
}

function buildOAuthSessionCurlCommand() {
  const activeProfile = getActiveProfile();
  const activeTenant = getActiveTenant();
  const identityUrls = deriveIdentityUrls(activeProfile, activeTenant);
  const tenantUrls = deriveTenantUrls(activeTenant, activeProfile);
  const identityUrl = identityUrls.identityTokenUrl || "<IDENTITY_TOKEN_URL>";
  const platformUrl = tenantUrls.platformTokenUrl || "<PLATFORM_TOKEN_URL>";
  return [
    `curl -X POST "${identityUrl}" \\`,
    `  -H "Content-Type: application/x-www-form-urlencoded" \\`,
    `  --data-urlencode "grant_type=client_credentials" \\`,
    `  --data-urlencode "client_id=<USERNAME HERE>" \\`,
    `  --data-urlencode "client_secret=<PASSWORD HERE>"`,
    ``,
    `curl -X POST "${platformUrl}" \\`,
    `  -H "Content-Type: application/x-www-form-urlencoded" \\`,
    `  --data-urlencode "grant_type=client_credentials" \\`,
    `  --data-urlencode "client_id=<USERNAME HERE>" \\`,
    `  --data-urlencode "client_secret=<PASSWORD HERE>"`
  ].join("\n");
}

function buildOAuthSessionPowerShellCommand() {
  const activeProfile = getActiveProfile();
  const activeTenant = getActiveTenant();
  const identityUrls = deriveIdentityUrls(activeProfile, activeTenant);
  const tenantUrls = deriveTenantUrls(activeTenant, activeProfile);
  const identityUrl = identityUrls.identityTokenUrl || "<IDENTITY_TOKEN_URL>";
  const platformUrl = tenantUrls.platformTokenUrl || "<PLATFORM_TOKEN_URL>";
  return [
    `$identityForm = @{`,
    `  grant_type = "client_credentials"`,
    `  client_id = "<USERNAME HERE>"`,
    `  client_secret = "<PASSWORD HERE>"`,
    `}`,
    `Invoke-RestMethod -Method Post -Uri "${identityUrl}" -ContentType "application/x-www-form-urlencoded" -Body $identityForm`,
    ``,
    `$platformForm = @{`,
    `  grant_type = "client_credentials"`,
    `  client_id = "<USERNAME HERE>"`,
    `  client_secret = "<PASSWORD HERE>"`,
    `}`,
    `Invoke-RestMethod -Method Post -Uri "${platformUrl}" -ContentType "application/x-www-form-urlencoded" -Body $platformForm`
  ].join("\n");
}

function buildInteractiveCurlCommand() {
  const activeProfile = getActiveProfile();
  const activeTenant = getActiveTenant();
  const interactiveUrls = deriveInteractiveAuthUrls(activeProfile, activeTenant);
  const startUrl = interactiveUrls.startAuthenticationUrl || "<START_AUTHENTICATION_URL>";
  const advanceUrl = interactiveUrls.advanceAuthenticationUrl || "<ADVANCE_AUTHENTICATION_URL>";
  return [
    `# 1) Start authentication`,
    `curl -X POST "${startUrl}" \\`,
    `  -H "Content-Type: application/json" \\`,
    `  -H "X-IDAP-NATIVE-CLIENT: true" \\`,
    `  -d '{"User":"<USERNAME HERE>","Version":"1.0","TenantId":"${escapeJsonString(activeProfile?.subdomain || "<TENANT_SUBDOMAIN>")}"}'`,
    ``,
    `# 2) Submit password challenge using values returned from step 1`,
    `curl -X POST "${advanceUrl}" \\`,
    `  -H "Content-Type: application/json" \\`,
    `  -H "X-IDAP-NATIVE-CLIENT: true" \\`,
    `  -d '{"SessionId":"<SESSION_ID_FROM_START>","MechanismId":"<PASSWORD_MECHANISM_ID>","Action":"Answer","Answer":"<PASSWORD HERE>"}'`,
    ``,
    `# 3) For MFA follow-ups, call AdvanceAuthentication again with the returned mechanism and action.`,
    `#    If the call requires a bearer token, use: Authorization: Bearer <TOKEN HERE>`
  ].join("\n");
}

function buildInteractivePowerShellCommand() {
  const activeProfile = getActiveProfile();
  const activeTenant = getActiveTenant();
  const interactiveUrls = deriveInteractiveAuthUrls(activeProfile, activeTenant);
  const startUrl = interactiveUrls.startAuthenticationUrl || "<START_AUTHENTICATION_URL>";
  const advanceUrl = interactiveUrls.advanceAuthenticationUrl || "<ADVANCE_AUTHENTICATION_URL>";
  return [
    `$startHeaders = @{ "X-IDAP-NATIVE-CLIENT" = "true" }`,
    `$startBody = @{`,
    `  User = "<USERNAME HERE>"`,
    `  Version = "1.0"`,
    `  TenantId = "${escapePowerShellString(activeProfile?.subdomain || "<TENANT_SUBDOMAIN>")}"`,
    `} | ConvertTo-Json`,
    `$start = Invoke-RestMethod -Method Post -Uri "${startUrl}" -Headers $startHeaders -ContentType "application/json" -Body $startBody`,
    ``,
    `$advanceBody = @{`,
    `  SessionId = "<SESSION_ID_FROM_START>"`,
    `  MechanismId = "<PASSWORD_MECHANISM_ID>"`,
    `  Action = "Answer"`,
    `  Answer = "<PASSWORD HERE>"`,
    `} | ConvertTo-Json`,
    `Invoke-RestMethod -Method Post -Uri "${advanceUrl}" -Headers $startHeaders -ContentType "application/json" -Body $advanceBody`,
    ``,
    `# If a bearer token is required in follow-up calls, use:`,
    `# $headers = @{ Authorization = "Bearer <TOKEN HERE>" }`
  ].join("\n");
}

function buildTaskCurlCommand(task, values = {}) {
  const request = buildTaskRequestForCopy(task, values);
  const url = buildVaultRequestUrlForCopy(request);
  const lines = [
    `curl -X ${request.method} "${url}" \\`,
    `  -H "Authorization: Bearer <TOKEN HERE>" \\`,
    `  -H "Content-Type: application/json"`
  ];
  if (request.body?.trim() && !request.method.toUpperCase().startsWith("GET")) {
    lines[lines.length - 1] += " \\";
    lines.push(`  --data-raw '${escapeSingleQuotedShell(request.body)}'`);
  }
  return lines.join("\n");
}

function buildTaskPowerShellCommand(task, values = {}) {
  const request = buildTaskRequestForCopy(task, values);
  const url = buildVaultRequestUrlForCopy(request);
  const lines = [
    `$headers = @{`,
    `  Authorization = "Bearer <TOKEN HERE>"`,
    `  "Content-Type" = "application/json"`,
    `}`
  ];
  if (request.body?.trim() && !request.method.toUpperCase().startsWith("GET")) {
    lines.push(`$body = @'`);
    lines.push(request.body);
    lines.push(`'@`);
    lines.push(
      `Invoke-RestMethod -Method ${request.method} -Uri "${url}" -Headers $headers -Body $body`
    );
  } else {
    lines.push(`Invoke-RestMethod -Method ${request.method} -Uri "${url}" -Headers $headers`);
  }
  return lines.join("\n");
}

function buildTaskRequestForCopy(task, values = {}) {
  try {
    return buildTaskRequest(task, values);
  } catch {
    return {
      method: task.method || "GET",
      path: task.path || "",
      query: task.query || "",
      body: task.body || ""
    };
  }
}

function buildVaultRequestUrlForCopy(request) {
  const tenant = getActiveTenant();
  const baseUrl = tenant?.vault_api_base_url?.trim() || "<VAULT_API_BASE_URL>";
  const normalizedBase = baseUrl.replace(/\/+$/, "");
  const normalizedPath = String(request.path || "").replace(/^\/+/, "");
  const query = String(request.query || "").trim();
  return `${normalizedBase}/${normalizedPath}${query ? `?${query}` : ""}`;
}

function escapeSingleQuotedShell(value) {
  return String(value || "").replaceAll("'", "'\"'\"'");
}

function escapeJsonString(value) {
  return JSON.stringify(String(value || "")).slice(1, -1);
}

function escapePowerShellString(value) {
  return String(value || "").replaceAll("\"", "`\"");
}

function trackSessionActivity() {
  if (state.snapshot.session_locked || !state.snapshot.passcode_configured) {
    return;
  }
  refreshSessionActivity();
  updateSessionTimeoutIndicator();
}

function refreshSessionActivity() {
  state.session.lastActivityAt = Date.now();
}

function remainingSessionTimeoutMs() {
  return Math.max(0, sessionTimeoutMs() - (Date.now() - state.session.lastActivityAt));
}

function formatSessionTimeout(milliseconds) {
  const totalSeconds = Math.max(0, Math.ceil(milliseconds / 1000));
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}

function updateSessionTimeoutIndicator() {
  const indicator = document.querySelector("#auth-timeout-indicator");
  if (!indicator) {
    return;
  }
  indicator.textContent = state.snapshot.session_locked
    ? "Locked"
    : formatSessionTimeout(remainingSessionTimeoutMs());
}

async function tickSessionTimeout() {
  if (!state.snapshot.passcode_configured) {
    return;
  }
  if (state.snapshot.session_locked) {
    updateSessionTimeoutIndicator();
    return;
  }
  const remaining = remainingSessionTimeoutMs();
  updateSessionTimeoutIndicator();
  if (remaining > 0 || sessionLockInFlight) {
    return;
  }
  sessionLockInFlight = true;
  try {
    state.snapshot = await bridge.lockSession();
    state.forms.session.unlockPasscode = "";
    log(`Session locked after ${state.settings.inactivityTimeoutMinutes} minutes of inactivity.`);
    render();
  } catch (error) {
    log(formatError(error));
    render();
  } finally {
    sessionLockInFlight = false;
  }
}

function slugify(value) {
  return String(value || "response-viewer")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "") || "response-viewer";
}

function downloadBlob(payload, type, filename) {
  const blob = new Blob([payload], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

async function saveDownload(payload, type, filename, kindLabel) {
  if (!isTauri) {
    downloadBlob(payload, type, filename);
    log(`Downloaded response as ${kindLabel.toUpperCase()}.`);
    render();
    return;
  }

  const { save } = await import("@tauri-apps/plugin-dialog");
  const targetPath = await save({
    defaultPath: filename,
    filters: [
      {
        name: kindLabel.toUpperCase(),
        extensions: [filename.split(".").pop()]
      }
    ]
  });
  if (!targetPath) {
    log(`Canceled ${kindLabel.toUpperCase()} download.`);
    render();
    return;
  }
  await bridge.saveTextFile({ path: targetPath, content: payload });
  log(`Saved ${kindLabel.toUpperCase()} file to ${targetPath}.`);
  render();
}

function activeTenantName() {
  return getActiveTenant()?.name || "Unknown tenant";
}

function renderProfilesPage() {
  const previewIdentityUrls = deriveIdentityUrls(state.forms.profile, getActiveTenant());
  const isInteractive = isInteractiveProfile(state.forms.profile);
  const editorActive = profileEditorMode === "create" || profileEditorMode === "update";
  const credentialLabel = isInteractive ? "Password" : "Client Secret";
  const credentialPlaceholder = state.forms.profile.client_secret_stored
    ? "Stored in OS keychain"
    : isInteractive
      ? "Set when saving a new interactive user"
      : "Set when saving a new profile";
  const identityUrlHelp = isInteractive
    ? "Enter a subdomain to build the Identity OAuth token URL."
    : "Enter a subdomain and application ID to build the Identity OAuth token URL.";
  return `
    <section class="page-grid split-page">
      <section class="card">
        <div class="card-head">
          <h3>Identity Accounts</h3>
        </div>
        <div class="button-row">
          <button id="profile-new-oauth" class="ghost">Add OAuth Profile</button>
          <button id="profile-new-interactive" class="ghost">Add Interactive User</button>
        </div>
        <div class="list">
          ${state.snapshot.profiles.length
            ? state.snapshot.profiles.map(renderProfileListItem).join("")
            : `<p class="empty">No profiles configured.</p>`}
        </div>
      </section>
      <section class="card">
        <div class="card-head">
          <h3>Profile Editor</h3>
          <p>Configure an OAuth profile or an interactive user. FastPAS resolves the Identity host and builds the token endpoint from the tenant subdomain.</p>
          <p>${editorActive ? (profileEditorMode === "update" ? "Editing existing profile." : "Creating new profile.") : "Click Add OAuth Profile, Add Interactive User, or Update on a profile to edit."}</p>
        </div>
        ${editorActive ? `
        <form id="profile-form" class="form-grid">
          <fieldset class="form-grid wide">
          <input type="hidden" name="id" value="${escapeAttr(state.forms.profile.id)}" />
          <label class="field"><span>Profile Type</span>
            <select name="auth_type">
              <option value="${PROFILE_TYPE_OAUTH}" ${!isInteractive ? "selected" : ""}>OAuth</option>
              <option value="${PROFILE_TYPE_INTERACTIVE}" ${isInteractive ? "selected" : ""}>Interactive User</option>
            </select>
          </label>
          ${isInteractive
            ? `<label class="field"><span>Nickname</span><input name="nickname" value="${escapeAttr(state.forms.profile.nickname)}" placeholder="Helpdesk Interactive User" /></label>
               <input type="hidden" name="name" value="${escapeAttr(state.forms.profile.nickname || state.forms.profile.name)}" />`
            : `<label class="field"><span>Name</span><input name="name" value="${escapeAttr(state.forms.profile.name)}" placeholder="Admin Identity Account" /></label>`}
          ${isInteractive
            ? `<label class="field"><span>Username</span><input name="username" value="${escapeAttr(state.forms.profile.username)}" placeholder="admin.user" /></label>`
            : `<label class="field"><span>Application ID</span><input name="application_id" value="${escapeAttr(state.forms.profile.application_id)}" placeholder="a1b2c3d4-application-id" /></label>`}
          <label class="field"><span>Tenant Subdomain</span><input name="subdomain" value="${escapeAttr(state.forms.profile.subdomain)}" placeholder="customer-subdomain" /></label>
          ${isInteractive ? "" : `<label class="field"><span>Client ID</span><input name="client_id" value="${escapeAttr(state.forms.profile.client_id)}" /></label>`}
          <label class="field"><span>${credentialLabel}</span><input name="client_secret" type="password" value="${escapeAttr(state.forms.profile.client_secret)}" placeholder="${credentialPlaceholder}" /></label>
          <div class="wide flow-step compact">
            <div class="step-copy">
              <span class="step-tag">Identity Host</span>
              <p>${escapeHtml(previewIdentityUrls.identityTenantHost || "Save the profile to resolve the Identity host.")}</p>
            </div>
            <div class="step-copy">
              <span class="step-tag">Secret Storage</span>
              <p>${state.forms.profile.client_secret_stored ? `${credentialLabel} is stored in the OS keychain.` : `${credentialLabel} has not been stored yet.`}</p>
            </div>
            <div class="step-copy">
              <span class="step-tag">Built URL</span>
              <p>${escapeHtml(previewIdentityUrls.identityTokenUrl || identityUrlHelp)}</p>
            </div>
          </div>
          <div class="button-row wide">
            <button type="submit">${profileEditorMode === "update" ? "Update Profile" : "Save Profile"}</button>
            <button type="button" id="profile-activate" class="ghost" ${state.forms.profile.id ? "" : "disabled"}>Set Active</button>
            <button type="button" id="profile-delete" class="danger" ${state.forms.profile.id ? "" : "disabled"}>Delete</button>
          </div>
          </fieldset>
        </form>
        ${state.forms.profile.id ? `
        <form id="profile-secret-form" class="form-grid profile-secret-form">
          <div class="wide card-head">
            <h3>Update Credential</h3>
            <p>Rotate the ${isInteractive ? "password" : "client secret"} for this profile without changing the rest of the account details.</p>
          </div>
          <label class="wide field"><span>New ${credentialLabel}</span><input name="client_secret" type="password" value="${escapeAttr(state.forms.profile.secret_update || "")}" placeholder="Enter a replacement ${isInteractive ? "password" : "client secret"}" /></label>
          <div class="button-row wide">
            <button type="submit">Update Credential</button>
          </div>
        </form>` : ""}` : `
        <section class="flow-step compact">
          <div class="step-copy">
            <span class="step-tag">Profile Editor Hidden</span>
            <p>Select Add OAuth Profile, Add Interactive User, or Update from a profile row to open the editor.</p>
          </div>
        </section>`}
        <form id="session-passcode-form" class="form-grid profile-secret-form">
          <div class="wide card-head">
            <h3>Update Passcode</h3>
            <p>Enter the current passcode before saving a new one. Your OS keychain may ask you to confirm the change.</p>
          </div>
          <label class="field"><span>Current Passcode</span><input name="current_passcode" type="password" value="${escapeAttr(state.forms.session.currentPasscode)}" /></label>
          <label class="field"><span>New Passcode</span><input name="new_passcode" type="password" value="${escapeAttr(state.forms.session.newPasscode)}" placeholder="At least 8 characters, with upper/lowercase and a number" /></label>
          <label class="wide field"><span>Confirm New Passcode</span><input name="confirm_new_passcode" type="password" value="${escapeAttr(state.forms.session.confirmNewPasscode)}" /></label>
          <div class="button-row wide">
            <button type="submit">Update Passcode</button>
          </div>
        </form>
      </section>
    </section>
  `;
}

function renderProfileListItem(profile) {
  const urls = deriveIdentityUrls(profile);
  const typeLabel = isInteractiveProfile(profile) ? "Interactive" : "OAuth";
  const displayName = isInteractiveProfile(profile)
    ? profile.nickname || profile.name || profile.username
    : profile.name;
  const secondary = isInteractiveProfile(profile)
    ? profile.username
    : profile.application_id || profile.client_id;
  return `
    <div class="list-item ${state.snapshot.active_profile_id === profile.id ? "active" : ""}">
      <button class="list-select" data-profile-select="${profile.id}">
        <span>${escapeHtml(displayName)} <small>(${typeLabel})</small></span>
        <small>${escapeHtml(urls.identityTokenUrl || secondary || "No token URL configured")}</small>
      </button>
      <button class="small ghost" data-profile-update="${profile.id}">Update</button>
      <button class="small ghost" data-profile-active="${profile.id}">${state.snapshot.active_profile_id === profile.id ? "Active" : "Set Active"}</button>
    </div>
  `;
}

function renderTenantsPage() {
  const previewUrls = deriveTenantUrls(state.forms.tenant, getActiveProfile());
  return `
    <section class="page-grid split-page">
      <section class="card">
        <div class="card-head">
          <h3>Tenants</h3>
        </div>
        <div class="button-row">
          <button id="tenant-new" class="ghost">Add Tenant</button>
        </div>
        <div class="list">
          ${state.snapshot.tenants.length
            ? state.snapshot.tenants.map(renderTenantListItem).join("")
            : `<p class="empty">No tenants configured.</p>`}
        </div>
      </section>
      <section class="card">
        <div class="card-head">
          <h3>Tenant Editor</h3>
          <p>Enter the tenant name and customer subdomain. FastPAS discovers the Identity host and builds the required URLs automatically.</p>
        </div>
        <form id="tenant-form" class="form-grid">
          <input type="hidden" name="id" value="${escapeAttr(state.forms.tenant.id)}" />
          <label class="field"><span>Name</span><input name="name" value="${escapeAttr(state.forms.tenant.name)}" placeholder="Production" /></label>
          <label class="field"><span>Customer Subdomain</span><input name="subdomain" value="${escapeAttr(state.forms.tenant.subdomain)}" placeholder="customer-subdomain" /></label>
          <div class="wide flow-step compact">
            <div class="step-copy">
              <span class="step-tag">Derived URLs</span>
            </div>
            <div class="kv compact">
              <p><strong>Shared Services</strong><span>${escapeHtml(previewUrls.sharedServicesUrl || "Not configured")}</span></p>
              <p><strong>Identity Host</strong><span>${escapeHtml(previewUrls.identityHost || "Not configured")}</span></p>
              <p><strong>Identity Token Prefix</strong><span>${escapeHtml(previewUrls.identityTokenUrlPrefix || "Not configured")}</span></p>
              <p><strong>Platform Token</strong><span>${escapeHtml(previewUrls.platformTokenUrl || "Not configured")}</span></p>
              <p><strong>Vault API Base</strong><span>${escapeHtml(previewUrls.vaultApiBaseUrl || "Not configured")}</span></p>
              <p><strong>Audit API Base</strong><span>${escapeHtml(previewUrls.auditApiBaseUrl || "Not configured")}</span></p>
              <p><strong>Audit API Key</strong><span>${state.forms.tenant.audit_api_key_stored ? "Stored in OS keychain" : "Not stored"}</span></p>
            </div>
          </div>
          <label class="wide field"><span>Audit API Key</span><input name="audit_api_key" type="password" value="${escapeAttr(state.forms.tenant.audit_api_key || "")}" placeholder="${state.forms.tenant.audit_api_key_stored ? "Stored in OS keychain" : "Paste Export to SIEM API key"}" /></label>
          <div class="button-row wide">
            <button type="submit">Save Tenant</button>
            <button type="button" id="tenant-activate" class="ghost" ${state.forms.tenant.id ? "" : "disabled"}>Set Active</button>
            <button type="button" id="tenant-delete" class="danger" ${state.forms.tenant.id ? "" : "disabled"}>Delete</button>
          </div>
        </form>
      </section>
    </section>
  `;
}

function renderTenantListItem(tenant) {
  const urls = deriveTenantUrls(tenant);
  return `
    <div class="list-item ${state.snapshot.active_tenant_id === tenant.id ? "active" : ""}">
      <button class="list-select" data-tenant-select="${tenant.id}">
        <span>${escapeHtml(tenant.name)}</span>
        <small><strong>Privilege Cloud API:</strong> ${escapeHtml(urls.vaultApiBaseUrl || "No Privilege Cloud URL")}</small>
        <small><strong>Identity URL:</strong> ${escapeHtml(urls.identityHost || "No Identity URL")}</small>
      </button>
      <button class="small ghost" data-tenant-active="${tenant.id}">${state.snapshot.active_tenant_id === tenant.id ? "Active" : "Set Active"}</button>
    </div>
  `;
}

function renderDocsPage() {
  return `
    <section class="page-grid docs-grid">
      <details class="card docs-card docs-disclosure docs-faq-card">
          <summary class="card-head docs-head docs-disclosure-summary">
            <h3>FAQ</h3>
          </summary>
          <div class="docs-faq-list">
            <details class="docs-faq-item">
              <summary class="docs-faq-question">How does FastPAS protect my secrets and passcode?</summary>
              <div class="docs-faq-answer">
                <p>FastPAS stores profile client secrets and the FastPAS session passcode in the OS keychain on the desktop app instead of writing them into the app config file.</p>
                <p>Identity and platform tokens stay in runtime memory only. FastPAS clears them when you lock the session, switch profiles, switch tenants, or clear the token session manually.</p>
                <p>The desktop app now enforces a stronger passcode policy, requires the current passcode before passcode changes, and rate-limits repeated failed unlock attempts.</p>
                <p>For sensitive secret and passcode updates, FastPAS also rechecks access through the OS keychain path before committing the change.</p>
              </div>
            </details>
          </div>
      </details>
      <details class="card docs-card docs-disclosure">
        <summary class="card-head docs-head docs-disclosure-summary">
          <h3>Create OAuth User</h3>
        </summary>
        <div class="docs-disclosure-body">
        <ol class="docs-list docs-steps">
          <li>Sign in to the CyberArk Identity Admin Portal.</li>
          <li>In the left navigation, click <strong>Core Services</strong>, then click <strong>Users</strong>.</li>
          <li>Click <strong>Add User</strong>.</li>
          <li>Enter a <strong>Login name</strong>.</li>
          <li>Enter a <strong>Display name</strong>.</li>
          <li>Enter a <strong>Password</strong>.</li>
          <li>In the <strong>Status</strong> checklist, enable <strong>Is OAuth confidential client</strong>.</li>
          <li>Confirm that CyberArk auto-selects <strong>Is Service User</strong> and <strong>Password never expires</strong>.</li>
          <li>Click <strong>Create User</strong>.</li>
          <li>Record the <strong>Login name</strong> and <strong>Password</strong>. Those are the credentials used when requesting a platform token.</li>
        </ol>
        <div class="docs-callout">
          <span class="step-tag">Important</span>
          <p>The user must be configured as an OAuth confidential client and service user, or platform-token requests will fail.</p>
        </div>
        </div>
      </details>
      <details class="card docs-card docs-disclosure">
        <summary class="card-head docs-head docs-disclosure-summary">
          <h3>Create OAuth Client App</h3>
        </summary>
        <div class="docs-disclosure-body">
        <ol class="docs-list docs-steps">
          <li>Sign in to the CyberArk Identity Admin Portal.</li>
          <li>In the left navigation, click <strong>Apps &amp; Widgets</strong>, then click <strong>Web Apps</strong>.</li>
          <li>Click <strong>Add Web Apps</strong>.</li>
          <li>In the dialog, click the <strong>Custom</strong> tab.</li>
          <li>Find <strong>OAuth2 Client</strong> and click <strong>Add</strong>.</li>
          <li>When CyberArk asks for confirmation, click <strong>Yes</strong>.</li>
          <li>Close the Add Web Apps dialog so you land on the new app configuration screen.</li>
          <li>On <strong>Settings</strong>, enter the <strong>Application ID</strong>. This is the value FastPAS uses to build the token URL.</li>
          <li>Enter the application name you want admins to recognize.</li>
          <li>Save the application.</li>
          <li>Copy the app <strong>Application ID</strong>.</li>
          <li>Copy the app <strong>Client ID</strong>.</li>
          <li>Copy or generate the app <strong>Client Secret</strong>.</li>
          <li>In FastPAS, enter the tenant subdomain, application ID, client ID, and client secret on the profile.</li>
        </ol>
        <div class="docs-callout">
          <span class="step-tag">FastPAS Uses</span>
          <p>The application ID is what FastPAS uses to build the final Identity OAuth token URL for the profile.</p>
        </div>
        </div>
      </details>
      <details class="card docs-card docs-disclosure">
        <summary class="card-head docs-head docs-disclosure-summary">
          <h3>Add User To App</h3>
        </summary>
        <div class="docs-disclosure-body">
        <ol class="docs-list docs-steps">
          <li>Open the OAuth client application you created in the CyberArk Identity Admin Portal.</li>
          <li>In the app configuration navigation, click <strong>Permissions</strong>.</li>
          <li>Click <strong>Add</strong>.</li>
          <li>Search for the OAuth user you created earlier under <strong>Core Services &gt; Users</strong>.</li>
          <li>Select that user and add it to the application permissions list.</li>
          <li>For that user entry, enable <strong>Run</strong> permission so the user can use the application.</li>
          <li>Save the permission change.</li>
          <li>Return to FastPAS and test the Identity OAuth token request for that profile.</li>
          <li>If the Identity token succeeds, request the platform token next for Privilege Cloud access.</li>
        </ol>
        <div class="docs-callout">
          <span class="step-tag">Required Permission</span>
          <p>Give the OAuth user <strong>Run</strong> permission on the app so it can be used for authentication.</p>
        </div>
        </div>
      </details>
      <details class="card docs-card docs-disclosure">
        <summary class="card-head docs-head docs-disclosure-summary">
          <h3>Quick Tips</h3>
        </summary>
        <div class="docs-disclosure-body">
        <ul class="docs-list docs-tips">
          <li>In Privilege Cloud administration, whitelist the endpoint or network location that will run FastPAS so Privilege Cloud API traffic is allowed from that source.</li>
          <li>Consider creating a dedicated role for the OAuth user and placing it in its own authentication policy so API use can be limited to a secure zone defined in Identity Administration.</li>
          <li>Apply least-privilege access when granting the API user access to safes or Privilege Cloud roles. Only assign the exact permissions needed for the workflows it must perform.</li>
          <li>Do not leave FastPAS unattended while a session is unlocked. Someone with access to the open app could use it to make unauthorized API calls.</li>
        </ul>
        </div>
      </details>
    </section>
  `;
}

function renderToolsPage() {
  return `
    <section class="page-grid tools-grid">
      <section class="card tools-hero">
        <div class="card-head">
          <h3>Tools</h3>
          <p>Operator utilities and guided helpers will live here as FastPAS grows.</p>
        </div>
        <div class="tool-launch-grid">
          <button type="button" class="tool-launch-card" data-page="api">
            <strong>API Request Builder</strong>
            <span>Open the current CyberArk API task workspace.</span>
          </button>
          <button type="button" class="tool-launch-card" data-page="profiles">
            <strong>Identity Profiles</strong>
            <span>Manage OAuth and interactive authentication profiles.</span>
          </button>
          <button type="button" class="tool-launch-card" data-page="tenants">
            <strong>Tenant Resolver</strong>
            <span>Review tenant endpoints and Privilege Cloud API bases.</span>
          </button>
          <button type="button" class="tool-launch-card disabled" disabled>
            <strong>CSV Utilities</strong>
            <span>Bulk safe, member, and account workflows can be added here.</span>
          </button>
        </div>
      </section>
      ${renderActivityPanel()}
    </section>
  `;
}

function renderTelemetryPage() {
  const activeProfile = getActiveProfile();
  const activeTenant = getActiveTenant();
  const identityTokenView = tokenIndicatorView("identity");
  const platformTokenView = tokenIndicatorView("platform");
  const selectedDashboard = TELEMETRY_DASHBOARDS.some((dashboard) => dashboard.id === state.telemetry.selectedDashboardId)
    ? state.telemetry.selectedDashboardId
    : TELEMETRY_DASHBOARDS[0].id;

  return `
    <section class="page-grid telemetry-grid">
      <section class="card">
        <div class="card-head">
          <h3>Telemetry</h3>
          <p>Runtime status for the current FastPAS session.</p>
        </div>
        <div class="telemetry-metrics">
          <div class="context-pill telemetry-pill">
            <span>Profile</span>
            <strong>${escapeHtml(activeProfile?.name || "None")}</strong>
          </div>
          <div class="context-pill telemetry-pill">
            <span>Tenant</span>
            <strong>${escapeHtml(activeTenant?.name || "None")}</strong>
          </div>
          <div class="context-pill telemetry-pill ${identityTokenView.status}">
            <span>Identity Token</span>
            <strong>${escapeHtml(identityTokenView.status_label)}</strong>
          </div>
          <div class="context-pill telemetry-pill ${platformTokenView.status}">
            <span>Platform Token</span>
            <strong>${escapeHtml(platformTokenView.status_label)}</strong>
          </div>
        </div>
        <div class="telemetry-dashboard-nav" role="tablist" aria-label="Telemetry dashboards">
          ${TELEMETRY_DASHBOARDS.map((dashboard) => `
            <button
              type="button"
              class="telemetry-dashboard-tab ${selectedDashboard === dashboard.id ? "active" : ""}"
              data-telemetry-dashboard="${dashboard.id}"
              role="tab"
              aria-selected="${selectedDashboard === dashboard.id ? "true" : "false"}"
            >
              ${escapeHtml(dashboard.label)}
            </button>
          `).join("")}
        </div>
      </section>
      ${renderTelemetryDashboard(selectedDashboard)}
      <section class="card">
        <div class="card-head">
          <h3>Session Events</h3>
          <p>Recent app actions, token requests, and request errors.</p>
        </div>
        ${renderConsoleViewer(state.activity.slice(0, 16).join("\n"), {
          title: "Telemetry Log",
          emptyMessage: "No telemetry events recorded yet.",
          compact: false
        })}
      </section>
    </section>
  `;
}

function renderTelemetryDashboard(dashboardId) {
  if (dashboardId === "active-users") {
    return renderActiveUsersDashboard();
  }
  if (dashboardId === "account-failures") {
    return renderAccountFailuresDashboard();
  }
  return renderMostUsedComponentsDashboard();
}

function renderMostUsedComponentsDashboard() {
  const data = state.telemetry.componentUsage;
  const components = data?.components || [];

  return `
    <section class="card telemetry-dashboard-panel">
      <div class="card-head telemetry-dashboard-head">
        <div>
          <h3>Most Used Components</h3>
          <p>PSM session recording components used in the past 7 days.</p>
        </div>
        <div class="telemetry-actions">
          <button type="button" id="export-component-telemetry" class="ghost" ${data ? "" : "disabled"}>Export CSV</button>
          <button
            type="button"
            id="refresh-component-telemetry"
            class="ghost"
            ${state.telemetry.componentUsageLoading ? "disabled" : ""}
          >
            ${state.telemetry.componentUsageLoading ? "Loading..." : "Refresh"}
          </button>
        </div>
      </div>
      ${state.telemetry.componentUsageError ? `<div class="telemetry-error">${escapeHtml(state.telemetry.componentUsageError)}</div>` : ""}
      ${data ? renderConnectionComponentTelemetry(data, components) : renderTelemetryEmptyState()}
    </section>
  `;
}

function renderConnectionComponentTelemetry(data, components) {
  return `
    <div class="telemetry-summary-strip">
      <div class="context-pill telemetry-pill">
        <span>Total Connections</span>
        <strong>${Number(data.total_connections || 0)}</strong>
      </div>
      <div class="context-pill telemetry-pill">
        <span>Window</span>
        <strong>Past 7 days</strong>
      </div>
      <div class="context-pill telemetry-pill">
        <span>Components</span>
        <strong>${components.length}</strong>
      </div>
      <div class="context-pill telemetry-pill">
        <span>Source</span>
        <strong>${escapeHtml(data.audit_api_base_url || "Vault recordings API")}</strong>
      </div>
    </div>
    ${components.length ? `
      <div class="component-usage-layout">
        ${renderComponentPieChart(components)}
        <div class="component-usage-list">
          ${components.map((component, index) => renderConnectionComponentRow(component, index)).join("")}
        </div>
      </div>
    ` : `
      <div class="telemetry-empty">
        <strong>No PSM or SIA connection components found.</strong>
        <span>The recordings API returned no matching PSM sessions for the past week.</span>
      </div>
    `}
  `;
}

function renderTelemetryEmptyState() {
  return `
    <div class="telemetry-empty">
      <strong>No component telemetry loaded.</strong>
      <span>Refresh after a platform token is active to query Privilege Cloud PSM recordings for the past week.</span>
    </div>
  `;
}

function renderConnectionComponentRow(component, index) {
  return `
    <div class="component-usage-row">
      <span class="component-color-dot" style="background: ${componentChartColor(index)}"></span>
      <div>
        <strong>${escapeHtml(component.name || "Unknown component")}</strong>
        <span>${Number(component.total_connections || 0)} connection${Number(component.total_connections || 0) === 1 ? "" : "s"} · ${Number(component.percent_of_total || 0).toFixed(1)}%</span>
        ${component.access_methods?.length ? `<small>${component.access_methods.map(escapeHtml).join(", ")}</small>` : ""}
      </div>
    </div>
  `;
}

function renderComponentPieChart(components) {
  const segments = [];
  let cursor = 0;
  components.forEach((component, index) => {
    const next = index === components.length - 1
      ? 100
      : Math.min(100, cursor + Number(component.percent_of_total || 0));
    segments.push(`${componentChartColor(index)} ${cursor}% ${next}%`);
    cursor = next;
  });
  const background = segments.length
    ? `conic-gradient(${segments.join(", ")})`
    : "var(--panel-3)";

  return `
    <div class="component-pie-wrap">
      <div class="component-pie" style="background: ${background}">
        <div>
          <strong>${components.length}</strong>
          <span>components</span>
        </div>
      </div>
    </div>
  `;
}

function componentChartColor(index) {
  const colors = ["#f04d1e", "#2f765a", "#3478d4", "#9d4265", "#b87413", "#5d55c7", "#268f62", "#bc4f41"];
  return colors[index % colors.length];
}

async function refreshComponentTelemetry() {
  try {
    state.telemetry.componentUsageLoading = true;
    state.telemetry.componentUsageError = "";
    render();
    state.telemetry.componentUsage = await bridge.getConnectionComponentTelemetry();
    log("Loaded connection component telemetry from the Audit API.");
  } catch (error) {
    state.telemetry.componentUsageError = formatError(error);
    log(`Connection component telemetry failed: ${formatError(error)}`);
  } finally {
    state.telemetry.componentUsageLoading = false;
    render();
  }
}

async function refreshAccountFailures() {
  try {
    state.telemetry.accountFailuresLoading = true;
    state.telemetry.accountFailuresError = "";
    render();
    state.telemetry.accountFailures = await bridge.getAccountFailureTelemetry();
    log("Loaded account failure telemetry.");
  } catch (error) {
    state.telemetry.accountFailuresError = formatError(error);
    log(`Account failure telemetry failed: ${formatError(error)}`);
  } finally {
    state.telemetry.accountFailuresLoading = false;
    render();
  }
}

async function refreshActiveUsers(event) {
  event?.preventDefault();
  try {
    state.telemetry.activeUsersLoading = true;
    state.telemetry.activeUsersError = "";
    render();
    state.telemetry.activeUsers = await bridge.getActiveUserTelemetry();
    log("Loaded Identity user activity telemetry.");
  } catch (error) {
    state.telemetry.activeUsersError = formatError(error);
    log(`Identity user activity telemetry failed: ${formatError(error)}`);
  } finally {
    state.telemetry.activeUsersLoading = false;
    render();
  }
}

function renderActiveUsersDashboard() {
  const data = state.telemetry.activeUsers;
  const groups = data ? [
    {
      id: "identity-active",
      label: "Active This Week",
      count: data.identity_active_count,
      users: data.identity_active_users || []
    },
    {
      id: "identity-recently-inactive",
      label: "Recently Inactive",
      count: data.identity_recently_inactive_count,
      users: data.identity_recently_inactive_users || []
    },
    {
      id: "identity-long-inactive",
      label: "Inactive At Least A Month",
      count: data.identity_long_inactive_count,
      users: data.identity_long_inactive_users || []
    }
  ] : [];

  return `
    <section class="card telemetry-dashboard-panel">
      <div class="card-head telemetry-dashboard-head">
        <div>
          <h3>Identity Users</h3>
          <p>Identity activity grouped by recent login recency.</p>
        </div>
        <form id="active-users-form" class="active-users-form">
          <button type="button" id="export-active-users" class="ghost" ${data ? "" : "disabled"}>Export CSV</button>
          <button type="submit" class="ghost" ${state.telemetry.activeUsersLoading ? "disabled" : ""}>
            ${state.telemetry.activeUsersLoading ? "Loading..." : "Refresh"}
          </button>
        </form>
      </div>
      ${state.telemetry.activeUsersError ? `<div class="telemetry-error">${escapeHtml(state.telemetry.activeUsersError)}</div>` : ""}
      ${data ? renderActiveUserTelemetry(data, groups) : renderActiveUsersEmptyState()}
    </section>
  `;
}

function renderActiveUserTelemetry(data, groups) {
  const total = groups.reduce((sum, group) => sum + Number(group.count || 0), 0);
  return `
    <div class="telemetry-summary-strip">
      <div class="context-pill telemetry-pill active"><span>Active This Week</span><strong>${Number(data.identity_active_count || 0)}</strong></div>
      <div class="context-pill telemetry-pill inactive"><span>Inactive 1-4 Weeks</span><strong>${Number(data.identity_recently_inactive_count || 0)}</strong></div>
      <div class="context-pill telemetry-pill ${Number(data.identity_long_inactive_count || 0) > 0 ? "failed" : "active"}"><span>Inactive 1+ Month</span><strong>${Number(data.identity_long_inactive_count || 0)}</strong></div>
      <div class="context-pill telemetry-pill"><span>Source</span><strong>Identity</strong></div>
    </div>
    ${data.identity_error ? `<div class="telemetry-error">${escapeHtml(data.identity_error)}</div>` : ""}
    <div class="active-users-layout">
      ${renderActiveUsersPie(groups, total)}
      <div class="active-user-group-list">
        ${groups.map((group, index) => renderActiveUserGroup(group, index)).join("")}
      </div>
    </div>
  `;
}

function renderActiveUsersEmptyState() {
  return `
    <div class="telemetry-empty">
      <strong>No active-user telemetry loaded.</strong>
      <span>Refresh after an Identity API token is active to classify users by login recency.</span>
    </div>
  `;
}

function renderActiveUsersPie(groups, total) {
  const segments = [];
  let cursor = 0;
  groups.forEach((group, index) => {
    const percent = total ? (Number(group.count || 0) / total) * 100 : 0;
    const next = index === groups.length - 1 ? 100 : Math.min(100, cursor + percent);
    segments.push(`${activeUserChartColor(index)} ${cursor}% ${next}%`);
    cursor = next;
  });
  const background = total ? `conic-gradient(${segments.join(", ")})` : "var(--panel-3)";
  return `
    <div class="component-pie-wrap">
      <div class="component-pie" style="background: ${background}">
        <div>
          <strong>${total}</strong>
          <span>users</span>
        </div>
      </div>
    </div>
  `;
}

function renderActiveUserGroup(group, index) {
  return `
    <details class="failure-category active-user-category">
      <summary>
        <div>
          <strong style="color: ${activeUserChartColor(index)}">${escapeHtml(group.label)}</strong>
          <span>${Number(group.count || 0)} user${Number(group.count || 0) === 1 ? "" : "s"}</span>
        </div>
        <b>${Number(group.count || 0)}</b>
      </summary>
      <div class="failure-account-list">
        ${group.users?.length
          ? group.users.map(renderActiveUserRow).join("")
          : `<div class="failure-account-row"><span>No users returned for this category.</span></div>`}
      </div>
    </details>
  `;
}

function activeUserChartColor(index) {
  const colors = ["#268f62", "#b87413", "#bc4f41"];
  return colors[index % colors.length];
}

function renderActiveUserRow(user) {
  return `
    <div class="failure-account-row">
      <div>
        <strong>${escapeHtml(user.display_name || user.username || "Unknown user")}</strong>
        <span>${escapeHtml(user.username || "No username")}</span>
        <small>${escapeHtml(user.source || "Unknown source")}</small>
      </div>
      <p>${escapeHtml(user.last_seen || "No activity timestamp")} · ${escapeHtml(user.detail || "")}</p>
    </div>
  `;
}

function renderAccountFailuresDashboard() {
  const data = state.telemetry.accountFailures;
  const categories = data?.categories || [];

  return `
    <section class="card telemetry-dashboard-panel">
      <div class="card-head telemetry-dashboard-head">
        <div>
          <h3>Account Failures</h3>
          <p>CPM account-management errors and failed PSM sessions grouped by service and failure type.</p>
        </div>
        <div class="telemetry-actions">
          <button type="button" id="export-account-failures" class="ghost" ${data ? "" : "disabled"}>Export CSV</button>
          <button
            type="button"
            id="refresh-account-failures"
            class="ghost"
            ${state.telemetry.accountFailuresLoading ? "disabled" : ""}
          >
            ${state.telemetry.accountFailuresLoading ? "Loading..." : "Refresh"}
          </button>
        </div>
      </div>
      ${state.telemetry.accountFailuresError ? `<div class="telemetry-error">${escapeHtml(state.telemetry.accountFailuresError)}</div>` : ""}
      ${state.telemetry.accountRemediationError ? `<div class="telemetry-error">${escapeHtml(state.telemetry.accountRemediationError)}</div>` : ""}
      ${data ? renderAccountFailureTelemetry(data, categories) : renderAccountFailureEmptyState()}
      ${state.telemetry.accountRemediation ? renderAccountRemediationReport(state.telemetry.accountRemediation) : ""}
    </section>
  `;
}

function renderAccountFailureTelemetry(data, categories) {
  const disabledAccounts = automaticManagementDisabledAccounts(categories);
  return `
    <div class="telemetry-summary-strip">
      <div class="context-pill telemetry-pill ${Number(data.total_failures || 0) > 0 ? "failed" : "active"}">
        <span>Total Failures</span>
        <strong>${Number(data.total_failures || 0)}</strong>
      </div>
      <div class="context-pill telemetry-pill">
        <span>Categories</span>
        <strong>${categories.length}</strong>
      </div>
      <div class="context-pill telemetry-pill">
        <span>Accounts Scanned</span>
        <strong>${Number(data.total_accounts || 0)}</strong>
      </div>
      <div class="context-pill telemetry-pill">
        <span>PSM Window</span>
        <strong>Past 7 days</strong>
      </div>
    </div>
    ${disabledAccounts.length ? `
      <section class="remediation-panel">
        <div>
          <strong>Automatic Resolution</strong>
          <span>${disabledAccounts.length} account${disabledAccounts.length === 1 ? "" : "s"} have automatic management disabled. FastPAS will check lock state, unlock locked accounts, re-enable management, and start reconcile.</span>
        </div>
        <button
          type="button"
          id="remediate-disabled-accounts"
          class="danger"
          ${state.telemetry.accountRemediationLoading ? "disabled" : ""}
        >
          ${state.telemetry.accountRemediationLoading ? "Resolving..." : `Resolve ${disabledAccounts.length} Accounts`}
        </button>
      </section>
    ` : ""}
    ${categories.length ? `
      <div class="failure-category-list">
        ${categories.map(renderFailureCategory).join("")}
      </div>
    ` : `
      <div class="telemetry-empty">
        <strong>No account failures found.</strong>
        <span>No CPM failures or failed PSM sessions were found in the current scan.</span>
      </div>
    `}
  `;
}

function renderAccountFailureEmptyState() {
  return `
    <div class="telemetry-empty">
      <strong>No account failure scan loaded.</strong>
      <span>Refresh after a platform token is active to scan accounts and recent PSM recordings.</span>
    </div>
  `;
}

function renderFailureCategory(category) {
  const accountCount = category.accounts?.length || 0;
  return `
    <details class="failure-category">
      <summary>
        <div>
          <strong>${escapeHtml(category.service || "Unknown service")}</strong>
          <span>${escapeHtml(category.failure_type || "Unknown failure")}</span>
        </div>
        <b>${Number(category.total_failures || 0)}</b>
      </summary>
      <div class="failure-account-list">
        ${accountCount
          ? category.accounts.map(renderFailureAccount).join("")
          : `<div class="failure-account-row"><span>No accounts returned for this category.</span></div>`}
      </div>
    </details>
  `;
}

function renderFailureAccount(account) {
  const identity = [
    account.username,
    account.address
  ].filter(Boolean).join(" @ ");
  return `
    <div class="failure-account-row">
      <div>
        <strong>${escapeHtml(account.account_name || "Unknown account")}</strong>
        <span>${escapeHtml(account.safe_name || "Unknown safe")}${identity ? ` · ${escapeHtml(identity)}` : ""}</span>
        <small>${escapeHtml(account.platform_id || "No platform")} ${account.account_id ? `· id=${escapeHtml(account.account_id)}` : ""}</small>
      </div>
      <p>${escapeHtml(account.detail || "No detail provided.")}</p>
    </div>
  `;
}

function automaticManagementDisabledAccounts(categories) {
  const seen = new Set();
  return categories
    .filter((category) =>
      String(category.service || "").toLowerCase() === "cpm" &&
      String(category.failure_type || "").toLowerCase() === "automatic management disabled"
    )
    .flatMap((category) => category.accounts || [])
    .filter((account) => {
      if (!account.account_id || seen.has(account.account_id)) {
        return false;
      }
      seen.add(account.account_id);
      return true;
    });
}

function renderAccountRemediationReport(report) {
  const unlockedFailures = report.unlocked_account_failures || [];
  return `
    <section class="remediation-report">
      <div class="card-head telemetry-dashboard-head">
        <div>
          <h4>Automatic Resolution Results</h4>
          <p>Status checks completed ${escapeHtml(formatTelemetryTimestamp(report.generated_at))}. Resolved means CPM reported success.</p>
        </div>
        <div class="telemetry-actions">
          <button type="button" id="export-remediation-report" class="ghost">Export Full CSV</button>
          <button type="button" id="export-unlocked-remediation-failures" class="ghost" ${unlockedFailures.length ? "" : "disabled"}>Export Unresolved Unlocked CSV</button>
        </div>
      </div>
      <div class="telemetry-summary-strip">
        <div class="context-pill telemetry-pill"><span>Requested</span><strong>${Number(report.requested_count || 0)}</strong></div>
        <div class="context-pill telemetry-pill active"><span>Resolved</span><strong>${Number(report.resolved_count || 0)}</strong></div>
        <div class="context-pill telemetry-pill"><span>Unlocked + Resolved</span><strong>${Number(report.unlocked_then_resolved_count || 0)}</strong></div>
        <div class="context-pill telemetry-pill ${Number(report.unresolved_count || 0) ? "failed" : "active"}"><span>Unresolved</span><strong>${Number(report.unresolved_count || 0)}</strong></div>
      </div>
      ${unlockedFailures.length ? `
        <div class="telemetry-error">
          ${unlockedFailures.length} account${unlockedFailures.length === 1 ? "" : "s"} were already unlocked and could not be fully resolved. Use the separate CSV report for follow-up.
        </div>
      ` : ""}
      <div class="failure-account-list">
        ${(report.results || []).map((item) => `
          <div class="failure-account-row">
            <div>
              <strong>${escapeHtml(item.account_name || item.account_id || "Unknown account")}</strong>
              <span>${escapeHtml(item.safe_name || "Unknown safe")} · ${item.was_locked ? "Was locked" : "Was unlocked"}</span>
              <small>${escapeHtml(item.completion_status || (item.resolved ? "completed" : "unresolved"))} · CPM ${escapeHtml(item.final_management_status || "unknown")} · id=${escapeHtml(item.account_id || "")}</small>
            </div>
            <p>${escapeHtml(item.detail || "")}</p>
          </div>
        `).join("")}
      </div>
    </section>
  `;
}

function formatTelemetryTimestamp(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value || "") : date.toLocaleString();
}

async function remediateDisabledAccounts() {
  const accounts = automaticManagementDisabledAccounts(state.telemetry.accountFailures?.categories || []);
  if (!accounts.length) {
    return;
  }
  const confirmed = window.confirm(
    `Resolve ${accounts.length} account${accounts.length === 1 ? "" : "s"} with automatic management disabled?\n\nLocked accounts will be unlocked. Automatic management will be enabled and reconcile will be started. FastPAS will monitor CPM status for up to five minutes.`
  );
  if (!confirmed) {
    return;
  }
  try {
    state.telemetry.accountRemediationLoading = true;
    state.telemetry.accountRemediationError = "";
    state.telemetry.accountRemediation = null;
    render();
    state.telemetry.accountRemediation = await bridge.remediateAccountFailures({
      account_ids: accounts.map((account) => account.account_id)
    });
    log(`Account remediation completed: ${state.telemetry.accountRemediation.resolved_count || 0} resolved.`);
    state.telemetry.accountFailures = await bridge.getAccountFailureTelemetry();
  } catch (error) {
    state.telemetry.accountRemediationError = formatError(error);
    log(`Account remediation failed: ${formatError(error)}`);
  } finally {
    state.telemetry.accountRemediationLoading = false;
    render();
  }
}

function telemetryCsv(kind, data) {
  if (!data) {
    return "";
  }
  if (kind === "components") {
    return toCsv([
      ["generated_at", "date_from", "date_to", "component", "total_connections", "percent_of_total", "access_methods"],
      ...(data.components || []).map((item) => [
        data.generated_at, data.date_from, data.date_to, item.name, item.total_connections,
        item.percent_of_total, (item.access_methods || []).join("; ")
      ])
    ]);
  }
  if (kind === "users") {
    const groups = [
      ["active_this_week", data.identity_active_users || []],
      ["inactive_1_to_4_weeks", data.identity_recently_inactive_users || []],
      ["inactive_1_plus_month", data.identity_long_inactive_users || []]
    ];
    return toCsv([
      ["generated_at", "activity_group", "username", "display_name", "source", "last_seen", "detail"],
      ...groups.flatMap(([group, users]) => users.map((user) => [
        data.generated_at, group, user.username, user.display_name, user.source, user.last_seen, user.detail
      ]))
    ]);
  }
  if (kind === "failures") {
    return toCsv([
      ["generated_at", "service", "failure_type", "account_id", "account_name", "safe_name", "username", "address", "platform_id", "detail"],
      ...(data.categories || []).flatMap((category) => (category.accounts || []).map((account) => [
        data.generated_at, category.service, category.failure_type, account.account_id, account.account_name,
        account.safe_name, account.username, account.address, account.platform_id, account.detail
      ]))
    ]);
  }
  return "";
}

function remediationCsv(items) {
  return toCsv([
    ["account_id", "account_name", "safe_name", "username", "address", "platform_id", "was_locked", "unlocked", "automatic_management_enabled", "reconcile_started", "completion_status", "final_management_status", "resolved", "detail"],
    ...(items || []).map((item) => [
      item.account_id, item.account_name, item.safe_name, item.username, item.address, item.platform_id,
      item.was_locked, item.unlocked, item.automatic_management_enabled, item.reconcile_started,
      item.completion_status, item.final_management_status, item.resolved, item.detail
    ])
  ]);
}

function exportTelemetryCsv(kind, data, filename) {
  const payload = telemetryCsv(kind, data);
  if (!payload) {
    return;
  }
  saveDownload(payload, "text/csv;charset=utf-8", filename, "csv").catch((error) => {
    log(formatError(error));
    render();
  });
}

function renderTelemetryBar(label, value, maxValue) {
  const width = Math.max(4, Math.min(100, Math.round((Number(value) / Number(maxValue || 1)) * 100)));
  return `
    <div class="telemetry-bar-row">
      <div class="telemetry-bar-label">
        <strong>${escapeHtml(label)}</strong>
        <span>${Number(value) || 0}</span>
      </div>
      <div class="telemetry-bar-track" aria-hidden="true">
        <span style="width: ${width}%"></span>
      </div>
    </div>
  `;
}

function renderSettingsPage() {
  return `
    <section class="settings-stack">
      <section class="card settings-card">
        <div class="card-head">
          <h3>General Settings</h3>
          <p>Core preferences for the FastPAS experience.</p>
        </div>
        <form id="settings-general-form" class="form-grid">
          <label class="settings-toggle-row">
            <input type="checkbox" name="dark_mode" ${state.theme === "dark" ? "checked" : ""} />
            <span class="settings-toggle-switch" aria-hidden="true">
              <span class="settings-toggle-knob"></span>
            </span>
            <span class="settings-toggle-label">Enable Dark Mode</span>
          </label>
        </form>
        <div class="flow-step compact">
          <div class="step-copy">
            <span class="step-tag">Inactivity Lockout Timer</span>
            <p>This value is in minutes.</p>
          </div>
          <form id="settings-inactivity-form" class="button-row">
            <input
              class="minutes-input"
              type="number"
              name="inactivity_timeout_minutes"
              min="${MIN_INACTIVITY_TIMEOUT_MINUTES}"
              max="${MAX_INACTIVITY_TIMEOUT_MINUTES}"
              step="1"
              value="${escapeAttr(String(state.settings.inactivityTimeoutMinutes))}"
            />
            <button type="submit" class="ghost">Save</button>
          </form>
        </div>
      </section>
      <section class="card settings-card">
        <div class="card-head">
          <h3>Debug Tools</h3>
          <p>Hidden diagnostics and sensitive operator controls.</p>
        </div>
        <div class="button-row">
          <button id="settings-open-debug" type="button" class="ghost">Open Debug Page</button>
        </div>
      </section>
    </section>
  `;
}

function renderDebugPage() {
  return `
    <section class="settings-stack">
      <section class="card settings-card">
        <div class="card-head">
          <h3>Debug</h3>
          <p>Security-sensitive controls. Use these only for troubleshooting and operator workflows.</p>
        </div>
        <form id="debug-token-copy-form" class="form-grid">
          <label class="settings-toggle-row">
            <input type="checkbox" name="enable_token_copy" ${state.settings.enableTokenCopy ? "checked" : ""} />
            <span class="settings-toggle-switch" aria-hidden="true">
              <span class="settings-toggle-knob"></span>
            </span>
            <span class="settings-toggle-label">Enable Token Copy</span>
          </label>
          <p class="hint">Token copy stays enabled for 30 seconds, then auto-disables.</p>
        </form>
        <div class="button-row">
          <button id="debug-back-settings" type="button" class="ghost">Back To Settings</button>
        </div>
      </section>
    </section>
  `;
}

function wireEvents() {
  document.querySelectorAll("[data-page]").forEach((button) => {
    button.addEventListener("click", () => {
      state.page = button.dataset.page;
      render();
    });
  });

  document.querySelectorAll("[data-telemetry-dashboard]").forEach((button) => {
    button.addEventListener("click", () => {
      state.telemetry.selectedDashboardId = button.dataset.telemetryDashboard;
      render();
    });
  });

  bind("#refresh-component-telemetry", "click", refreshComponentTelemetry);
  bind("#export-component-telemetry", "click", () => exportTelemetryCsv("components", state.telemetry.componentUsage, "fastpas-component-telemetry.csv"));
  bind("#refresh-account-failures", "click", refreshAccountFailures);
  bind("#export-account-failures", "click", () => exportTelemetryCsv("failures", state.telemetry.accountFailures, "fastpas-account-failures.csv"));
  bind("#remediate-disabled-accounts", "click", remediateDisabledAccounts);
  bind("#active-users-form", "submit", refreshActiveUsers);
  bind("#export-active-users", "click", () => exportTelemetryCsv("users", state.telemetry.activeUsers, "fastpas-active-users.csv"));
  bind("#export-remediation-report", "click", () => {
    const payload = remediationCsv(state.telemetry.accountRemediation?.results || []);
    saveDownload(payload, "text/csv;charset=utf-8", "fastpas-account-remediation.csv", "csv").catch((error) => log(formatError(error)));
  });
  bind("#export-unlocked-remediation-failures", "click", () => {
    const payload = remediationCsv(state.telemetry.accountRemediation?.unlocked_account_failures || []);
    saveDownload(payload, "text/csv;charset=utf-8", "fastpas-unresolved-unlocked-accounts.csv", "csv").catch((error) => log(formatError(error)));
  });

  bind("#settings-general-form", "change", (event) => {
    const payload = Object.fromEntries(new FormData(event.currentTarget).entries());
    state.theme = payload.dark_mode ? "dark" : "light";
    persistTheme();
    applyTheme();
    render();
  });

  bind("#settings-inactivity-form", "submit", (event) => {
    event.preventDefault();
    const payload = Object.fromEntries(new FormData(event.currentTarget).entries());
    const parsed = Number.parseInt(String(payload.inactivity_timeout_minutes || "").trim(), 10);
    if (!Number.isFinite(parsed) || parsed < MIN_INACTIVITY_TIMEOUT_MINUTES || parsed > MAX_INACTIVITY_TIMEOUT_MINUTES) {
      log(`Inactivity lockout timer must be ${MIN_INACTIVITY_TIMEOUT_MINUTES}-${MAX_INACTIVITY_TIMEOUT_MINUTES} minutes.`);
      render();
      return;
    }
    state.settings.inactivityTimeoutMinutes = parsed;
    persistSettings();
    updateSessionTimeoutIndicator();
    log(`Inactivity lockout timer set to ${parsed} minutes.`);
    render();
  });

  bind("#settings-open-debug", "click", () => {
    state.page = DEBUG_PAGE;
    render();
  });

  bind("#debug-back-settings", "click", () => {
    state.page = "settings";
    render();
  });

  bind("#debug-token-copy-form", "change", (event) => {
    const payload = Object.fromEntries(new FormData(event.currentTarget).entries());
    state.settings.enableTokenCopy = Boolean(payload.enable_token_copy);
    state.settings.tokenCopyEnabledAt = state.settings.enableTokenCopy ? Date.now() : 0;
    persistSettings();
    if (state.settings.enableTokenCopy) {
      startTokenCopyWindowMonitor();
    } else {
      stopTokenCopyWindowMonitor();
    }
    render();
  });

  bind("#session-lock-toggle", "click", async () => {
    if (!state.snapshot.passcode_configured) {
      state.forms.session = emptySessionForm();
      render();
      return;
    }
    if (state.snapshot.session_locked) {
      return;
    }
    state.snapshot = await bridge.lockSession();
    state.forms.session.unlockPasscode = "";
    log("Locked the FastPAS session.");
    render();
  });

  bind("#session-setup-form", "submit", async (event) => {
    event.preventDefault();
    const payload = Object.fromEntries(new FormData(event.currentTarget).entries());
    state.forms.session.setupPasscode = payload.passcode || "";
    state.forms.session.confirmPasscode = payload.confirm_passcode || "";
    if (payload.passcode !== payload.confirm_passcode) {
      log("Passcode confirmation does not match.");
      render();
      return;
    }
    try {
      state.snapshot = await bridge.configureSessionPasscode(payload.passcode || "");
      state.forms.session = emptySessionForm();
      refreshSessionActivity();
      log("Stored the FastPAS session passcode in the OS keychain.");
      render();
    } catch (error) {
      log(formatError(error));
      render();
    }
  });

  bind("#session-unlock-form", "submit", async (event) => {
    event.preventDefault();
    const payload = Object.fromEntries(new FormData(event.currentTarget).entries());
    state.forms.session.unlockPasscode = payload.passcode || "";
    try {
      state.snapshot = await bridge.unlockSession(payload.passcode || "");
      state.forms.session.unlockPasscode = "";
      refreshSessionActivity();
      log("Unlocked the FastPAS session.");
      render();
    } catch (error) {
      log(formatError(error));
      render();
    }
  });

  bind("#session-passcode-form", "submit", async (event) => {
    event.preventDefault();
    const payload = Object.fromEntries(new FormData(event.currentTarget).entries());
    state.forms.session.currentPasscode = payload.current_passcode || "";
    state.forms.session.newPasscode = payload.new_passcode || "";
    state.forms.session.confirmNewPasscode = payload.confirm_new_passcode || "";
    if (payload.new_passcode !== payload.confirm_new_passcode) {
      log("New passcode confirmation does not match.");
      render();
      return;
    }
    try {
      state.snapshot = await bridge.updateSessionPasscode({
        current_passcode: payload.current_passcode || "",
        new_passcode: payload.new_passcode || ""
      });
      state.forms.session.currentPasscode = "";
      state.forms.session.newPasscode = "";
      state.forms.session.confirmNewPasscode = "";
      log("Updated the FastPAS session passcode.");
      render();
    } catch (error) {
      log(formatError(error));
      render();
    }
  });

  bind("#clear-tokens", "click", async () => {
    stopInteractivePolling();
    state.snapshot = await bridge.clearTokens();
    state.api.interactiveAuth = emptyInteractiveAuthState();
    state.api.tokenRequestFailures.identity = false;
    state.api.tokenRequestFailures.platform = false;
    log("Cleared in-memory token session.");
    render();
  });

  bind("#export-config", "click", exportConfig);
  bind("#import-config", "click", async () => {
    if (!state.forms.importJson.trim()) {
      log("Paste configuration JSON on the Docs page first.");
      state.page = "docs";
      render();
      return;
    }
    state.snapshot = await bridge.importConfig(state.forms.importJson);
    syncFormsFromSelection();
    log("Imported configuration.");
    render();
  });

  bind("#request-oauth-session", "click", async () => {
    let phase = "identity";
    try {
      stopInteractivePolling();
      state.api.tokenRequestFailures.identity = false;
      state.snapshot = await bridge.requestIdentityToken();
      state.api.interactiveAuth = emptyInteractiveAuthState();
      log("Requested Identity OAuth token. Requesting platform token next...");
      render();
      await wait(2000);
      phase = "platform";
      state.api.tokenRequestFailures.platform = false;
      state.snapshot = await bridge.requestPlatformToken();
      state.api.interactiveAuth = emptyInteractiveAuthState();
      log("Requested platform token.");
      render();
    } catch (error) {
      if (phase === "identity") {
        state.api.tokenRequestFailures.identity = true;
      } else if (phase === "platform") {
        state.api.tokenRequestFailures.platform = true;
      }
      log(formatError(error));
      render();
    }
  });

  bind("#request-interactive-token", "click", async () => {
    try {
      const result = await bridge.authenticateInteractiveUser();
      applyInteractiveAuthResult(result);
      log(result.message || "Interactive authentication step completed.");
      render();
    } catch (error) {
      log(formatError(error));
      render();
    }
  });

  bind("#copy-oauth-curl", "click", async () => {
    await copyCommandToClipboard(buildOAuthSessionCurlCommand(), "OAuth curl");
  });

  bind("#copy-oauth-powershell", "click", async () => {
    await copyCommandToClipboard(buildOAuthSessionPowerShellCommand(), "OAuth PowerShell");
  });

  bind("#copy-interactive-curl", "click", async () => {
    await copyCommandToClipboard(buildInteractiveCurlCommand(), "interactive curl");
  });

  bind("#copy-interactive-powershell", "click", async () => {
    await copyCommandToClipboard(buildInteractivePowerShellCommand(), "interactive PowerShell");
  });

  document.querySelectorAll("[data-copy-runtime-token]").forEach((button) => {
    button.addEventListener("click", async () => {
      await copyRuntimeTokenWithPassword(button.dataset.copyRuntimeToken || "");
    });
  });

  bind("#interactive-auth-form", "submit", async (event) => {
    event.preventDefault();
    const payload = Object.fromEntries(new FormData(event.currentTarget).entries());
    await submitInteractiveAuthStep(payload);
  });

  document.querySelectorAll("[data-interactive-quick-action]").forEach((button) => {
    button.addEventListener("click", async () => {
      const form = document.querySelector("#interactive-auth-form");
      if (!form) {
        return;
      }
      const payload = Object.fromEntries(new FormData(form).entries());
      payload.action = button.dataset.interactiveQuickAction || payload.action || "Answer";
      await submitInteractiveAuthStep(payload);
    });
  });

  bind("#task-run-form", "submit", async (event) => {
    event.preventDefault();
    const task = findPresetById(state.api.selectedPresetId);
    if (!task) {
      log("Choose a task first.");
      render();
      return;
    }
    const payload = Object.fromEntries(new FormData(event.currentTarget).entries());
    state.api.taskInputs = payload;
    try {
      state.api.builder = buildTaskRequest(task, payload);
      state.api.response = task.id === "account-report"
        ? await executeAccountReportRequest(state.api.builder, payload)
        : await bridge.executeVaultRequest({
          method: state.api.builder.method,
          path: state.api.builder.path,
          query: state.api.builder.query,
          body: state.api.builder.body
        });
      state.api.lastRunPresetId = task.id;
      state.api.report = buildPresetReport(state.api.selectedPresetId, state.api.response, activeTenantName());
      log(
        task.id === "account-report"
          ? `Sent vault request ${state.api.builder.method} ${state.api.builder.path} across all pages.`
          : `Sent vault request ${state.api.builder.method} ${state.api.builder.path}.`
      );
      render();
    } catch (error) {
      state.api.report = null;
      state.api.lastRunPresetId = "";
      log(formatError(error));
      render();
    }
  });

  bind("#copy-task-curl", "click", async () => {
    const task = findPresetById(state.api.selectedPresetId);
    if (!task || !REPORT_TASK_IDS.has(task.id)) {
      return;
    }
    await copyCommandToClipboard(buildTaskCurlCommand(task, state.api.taskInputs), `${task.name} curl`);
  });

  bind("#copy-task-powershell", "click", async () => {
    const task = findPresetById(state.api.selectedPresetId);
    if (!task || !REPORT_TASK_IDS.has(task.id)) {
      return;
    }
    await copyCommandToClipboard(
      buildTaskPowerShellCommand(task, state.api.taskInputs),
      `${task.name} PowerShell`
    );
  });

  bind("#task-selection-clear", "click", () => {
    state.api.builder = emptyApiBuilder();
    state.api.selectedPresetId = "";
    state.api.taskInputs = {};
    state.api.report = null;
    state.api.lastRunPresetId = "";
    render();
  });

  bind("#task-search", "input", (event) => {
    const nextValue = event.currentTarget.value;
    const cursor = event.currentTarget.selectionStart ?? nextValue.length;
    state.api.searchQuery = nextValue;
    render();
    const searchInput = document.querySelector("#task-search");
    if (searchInput) {
      searchInput.focus();
      searchInput.setSelectionRange(cursor, cursor);
    }
  });

  bind("#download-response-txt", "click", downloadResponseAsText);
  bind("#download-response-csv", "click", downloadResponseAsCsv);

  document.querySelectorAll("[data-preset-id]").forEach((button) => {
    button.addEventListener("click", () => {
      selectTask(button.dataset.presetId);
    });
  });

  document.querySelectorAll("[data-task-search-select]").forEach((button) => {
    button.addEventListener("click", () => {
      selectTask(button.dataset.taskSearchSelect);
    });
  });

  document.querySelectorAll("[data-chain-task]").forEach((button) => {
    button.addEventListener("click", () => {
      let seed = {};
      try {
        seed = JSON.parse(button.dataset.chainSeed || "{}");
      } catch {
        seed = {};
      }
      selectTask(button.dataset.chainTask, seed);
    });
  });

  bind("#profile-new-oauth", "click", () => {
    profileUpdateArmedId = "";
    profileEditorMode = "create";
    state.forms.profile = emptyProfileByType(PROFILE_TYPE_OAUTH);
    render();
  });

  bind("#profile-new-interactive", "click", () => {
    profileUpdateArmedId = "";
    profileEditorMode = "create";
    state.forms.profile = emptyProfileByType(PROFILE_TYPE_INTERACTIVE);
    render();
  });

  bind("select[name='auth_type']", "change", (event) => {
    const nextType = normalizeProfileType(event.currentTarget.value);
    const current = state.forms.profile;
    state.forms.profile = {
      ...emptyProfileByType(nextType),
      ...current,
      auth_type: nextType
    };
    render();
  });

  bind("#profile-form", "submit", async (event) => {
    event.preventDefault();
    if (profileEditorMode !== "create" && profileEditorMode !== "update") {
      log("Click Add or Update before editing a profile.");
      render();
      return;
    }
    let payload = Object.fromEntries(new FormData(event.currentTarget).entries());
    if (payload.id && payload.id !== profileUpdateArmedId) {
      log("Click Update on a profile in the list before saving changes to an existing profile.");
      render();
      return;
    }
    if (payload.subdomain?.trim()) {
      const resolution = await bridge.resolveTenant(payload.subdomain);
      payload = {
        ...payload,
        subdomain: resolution.subdomain,
        identity_tenant_host: resolution.identity_tenant_host,
        name: payload.name || payload.nickname || payload.username || resolution.subdomain
      };
    }
    state.snapshot = await bridge.saveProfile(payload);
    const savedProfileId = payload.id || state.snapshot.profiles.at(-1)?.id || "";
    const savedProfile = state.snapshot.profiles.find((item) => item.id === savedProfileId);
    profileEditorMode = payload.id ? "update" : "create";
    profileUpdateArmedId = savedProfile?.id || "";
    state.forms.profile = savedProfile ? normalizeProfile(savedProfile, savedProfile.id) : emptyProfile();
    log(`Saved profile ${payload.name || "unnamed"}.`);
    render();
  });

  bind("#profile-activate", "click", async () => {
    if (!state.forms.profile.id) {
      return;
    }
    state.snapshot = await bridge.setActiveProfile(state.forms.profile.id);
    log(`Set active profile to ${state.forms.profile.name}.`);
    render();
  });

  bind("#profile-delete", "click", async () => {
    if (!state.forms.profile.id) {
      return;
    }
    state.snapshot = await bridge.deleteProfile(state.forms.profile.id);
    syncFormsFromSelection();
    log("Deleted profile.");
    render();
  });

  bind("#profile-secret-form", "submit", async (event) => {
    event.preventDefault();
    const payload = Object.fromEntries(new FormData(event.currentTarget).entries());
    state.forms.profile.secret_update = payload.client_secret || "";
    try {
      state.snapshot = await bridge.updateProfileSecret({
        profile_id: state.forms.profile.id,
        client_secret: payload.client_secret || ""
      });
      const savedProfile = state.snapshot.profiles.find((item) => item.id === state.forms.profile.id);
      state.forms.profile = savedProfile ? normalizeProfile(savedProfile, savedProfile.id) : emptyProfile();
      log(`Updated the stored credential for ${savedProfile?.name || "the selected profile"}.`);
      render();
    } catch (error) {
      log(formatError(error));
      render();
    }
  });

  document.querySelectorAll("[data-profile-select]").forEach((button) => {
    button.addEventListener("click", () => {
      profileUpdateArmedId = "";
      profileEditorMode = "idle";
      state.forms.profile = emptyProfile();
      render();
    });
  });

  document.querySelectorAll("[data-profile-update]").forEach((button) => {
    button.addEventListener("click", () => {
      const profile = state.snapshot.profiles.find((item) => item.id === button.dataset.profileUpdate);
      if (!profile) {
        return;
      }
      profileEditorMode = "update";
      profileUpdateArmedId = profile.id;
      state.forms.profile = normalizeProfile(profile, profile.id);
      log(`Editing mode enabled for ${profile.name || profile.nickname || profile.username || "selected profile"}.`);
      render();
    });
  });

  document.querySelectorAll("[data-profile-active]").forEach((button) => {
    button.addEventListener("click", async () => {
      state.snapshot = await bridge.setActiveProfile(button.dataset.profileActive);
      log("Updated active profile.");
      render();
    });
  });

  bind("#tenant-new", "click", () => {
    state.forms.tenant = emptyTenant();
    render();
  });

  bind("#tenant-form", "submit", async (event) => {
    event.preventDefault();
    let payload = Object.fromEntries(new FormData(event.currentTarget).entries());
    if (payload.subdomain?.trim()) {
      const resolution = await bridge.resolveTenant(payload.subdomain);
      payload = {
        ...payload,
        name: payload.name || resolution.subdomain,
        subdomain: resolution.subdomain,
        identity_tenant_host: payload.identity_tenant_host?.trim() || resolution.identity_tenant_host,
        platform_token_url: resolution.platform_token_url,
        vault_api_base_url: resolution.vault_api_base_url,
        audit_api_base_url: payload.audit_api_base_url?.trim() || resolution.audit_api_base_url
      };
    }
    state.snapshot = await bridge.saveTenant(payload);
    state.forms.tenant = normalizeTenant(payload, payload.id || state.snapshot.tenants.at(-1)?.id || "");
    log(`Saved tenant ${payload.name || "unnamed"}.`);
    render();
  });

  bind("#tenant-activate", "click", async () => {
    if (!state.forms.tenant.id) {
      return;
    }
    state.snapshot = await bridge.setActiveTenant(state.forms.tenant.id);
    log(`Set active tenant to ${state.forms.tenant.name}.`);
    render();
  });

  bind("#tenant-delete", "click", async () => {
    if (!state.forms.tenant.id) {
      return;
    }
    state.snapshot = await bridge.deleteTenant(state.forms.tenant.id);
    syncFormsFromSelection();
    log("Deleted tenant.");
    render();
  });

  document.querySelectorAll("[data-tenant-select]").forEach((button) => {
    button.addEventListener("click", () => {
      const tenant = state.snapshot.tenants.find((item) => item.id === button.dataset.tenantSelect);
      state.forms.tenant = tenant ? normalizeTenant(tenant, tenant.id) : emptyTenant();
      render();
    });
  });

  document.querySelectorAll("[data-tenant-active]").forEach((button) => {
    button.addEventListener("click", async () => {
      state.snapshot = await bridge.setActiveTenant(button.dataset.tenantActive);
      log("Updated active tenant.");
      render();
    });
  });

  bind("#import-json", "input", (event) => {
    state.forms.importJson = event.currentTarget.value;
  });
}

async function submitInteractiveAuthStep(payload) {
  state.api.interactiveAuth.mechanismId = payload.mechanism_id || "";
  state.api.interactiveAuth.action = payload.action || "Answer";
  state.api.interactiveAuth.answer = payload.answer || "";
  if ((payload.action || "").toLowerCase() !== "poll") {
    stopInteractivePolling();
  }
  try {
    const result = await bridge.advanceInteractiveAuthentication({
      mechanism_id: payload.mechanism_id || "",
      action: payload.action || "",
      answer: payload.answer || ""
    });
    applyInteractiveAuthResult(result);
    log(result.message || "Interactive authentication step completed.");
    render();
  } catch (error) {
    log(formatError(error));
    render();
  }
}

async function exportConfig() {
  const payload = await bridge.exportConfig();
  downloadBlob(payload, "application/json", "fastpas-config.json");
  log("Exported configuration.");
}

function syncFormsFromSelection() {
  stopInteractivePolling();
  profileUpdateArmedId = "";
  profileEditorMode = "idle";
  state.forms.profile = emptyProfile();
  state.forms.tenant = getActiveTenant()
    ? normalizeTenant(getActiveTenant(), getActiveTenant().id)
    : emptyTenant();
  state.api.interactiveAuth = emptyInteractiveAuthState();
}

function getActiveProfile() {
  return state.snapshot.profiles.find((item) => item.id === state.snapshot.active_profile_id) || null;
}

function getActiveTenant() {
  return state.snapshot.tenants.find((item) => item.id === state.snapshot.active_tenant_id) || null;
}

function bind(selector, event, handler) {
  document.querySelector(selector)?.addEventListener(event, handler);
}

function wait(ms) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

function normalizeProfile(payload, id) {
  return {
    id,
    auth_type: normalizeProfileType(payload.auth_type),
    name: payload.name || payload.nickname || "",
    nickname: payload.nickname || payload.name || "",
    username: payload.username || "",
    subdomain: payload.subdomain || "",
    identity_tenant_host: payload.identity_tenant_host || "",
    application_id: payload.application_id || "",
    client_id: payload.client_id || "",
    client_secret: payload.client_secret || "",
    client_secret_stored: Boolean(payload.client_secret_stored),
    secret_update: ""
  };
}

function normalizeTenant(payload, id) {
  return {
    id,
    name: payload.name || "",
    subdomain: payload.subdomain || extractSubdomainFromTenant(payload),
    identity_tenant_host: payload.identity_tenant_host || extractIdentityHost(payload),
    identity_base_url: payload.identity_base_url || "",
    identity_oauth_url: payload.identity_oauth_url || "",
    platform_token_url: payload.platform_token_url || "",
    vault_api_base_url: payload.vault_api_base_url || "",
    audit_api_base_url: payload.audit_api_base_url || "",
    audit_api_key: payload.audit_api_key || "",
    audit_api_key_stored: Boolean(payload.audit_api_key_stored),
    notes: payload.notes || ""
  };
}

function upsertById(items, nextItem) {
  const index = items.findIndex((item) => item.id === nextItem.id);
  if (index === -1) {
    return [...items, nextItem];
  }
  return items.map((item, currentIndex) => (currentIndex === index ? nextItem : item));
}

function ensureBrowserUnlocked(data) {
  if (data.session_passcode && data.session_locked) {
    throw new Error("Unlock the FastPAS session first.");
  }
}

function findPresetById(presetId) {
  return PREBUILT_CALLS.flatMap((group) => group.items).find((item) => item.id === presetId) || null;
}

function findTaskMatches(query) {
  const normalized = query.trim().toLowerCase();
  if (!normalized) {
    return [];
  }
  return PREBUILT_CALLS.flatMap((group) =>
    group.items
      .filter((item) =>
        `${group.section} ${item.name} ${item.description}`.toLowerCase().includes(normalized)
      )
      .map((item) => ({ ...item, section: group.section }))
  );
}

function selectTask(presetId, seedValues = {}) {
  const preset = findPresetById(presetId);
  if (!preset) {
    return;
  }
  state.api.builder = {
    name: preset.name,
    description: preset.description,
    method: preset.method,
    path: preset.path,
    query: preset.query,
    body: preset.body
  };
  state.api.selectedPresetId = preset.id;
  state.api.taskInputs = {
    ...defaultTaskInputs(preset.id),
    ...seedValues
  };
  state.api.report = null;
  render();
}

function filterTaskGroups(query) {
  const normalized = query.trim().toLowerCase();
  if (!normalized) {
    return PREBUILT_CALLS;
  }
  return PREBUILT_CALLS
    .map((group) => ({
      ...group,
      items: group.items.filter((item) =>
        `${group.section} ${item.name} ${item.description}`.toLowerCase().includes(normalized)
      )
    }))
    .filter((group) => group.items.length);
}

function defaultTaskInputs(presetId) {
  if (presetId === "safes") {
    return { limit: "100", offset: "0" };
  }
  if (presetId === "account-report") {
    return { limit: "1000", offset: "0" };
  }
  if (presetId === "user-template") {
    return {
      username: "new.user",
      initialPassword: "ChangeMeNow1!"
    };
  }
  if (presetId === "create-safe") {
    return {
      safe_name: "",
      description: "",
      managing_cpm: "",
      retention_days: ""
    };
  }
  if (presetId === "add-safe-member") {
    return {
      safe_name: "",
      member_name: "",
      member_role: "EndUser",
      member_type: "User",
      member_location: "Vault"
    };
  }
  return {};
}

function safeMemberPermissions(role) {
  const permissions = {
    useAccounts: false,
    retrieveAccounts: false,
    listAccounts: false,
    addAccounts: false,
    updateAccountContent: false,
    updateAccountProperties: false,
    initiateCPMAccountManagementOperations: false,
    specifyNextAccountContent: false,
    renameAccounts: false,
    deleteAccounts: false,
    unlockAccounts: false,
    manageSafe: false,
    manageSafeMembers: false,
    backupSafe: false,
    viewAuditLog: false,
    viewSafeMembers: false,
    accessWithoutConfirmation: false,
    createFolders: false,
    deleteFolders: false,
    moveAccountsAndFolders: false,
    requestsAuthorizationLevel1: false,
    requestsAuthorizationLevel2: false
  };
  if (role === "Admin") {
    return {
      ...Object.fromEntries(Object.keys(permissions).map((key) => [key, true])),
      requestsAuthorizationLevel1: true,
      requestsAuthorizationLevel2: false
    };
  }
  if (role === "Auditor") {
    return {
      ...permissions,
      listAccounts: true,
      viewAuditLog: true,
      viewSafeMembers: true
    };
  }
  if (role === "Approver") {
    return {
      ...permissions,
      listAccounts: true,
      viewAuditLog: true,
      viewSafeMembers: true,
      requestsAuthorizationLevel1: true
    };
  }
  if (role === "Owner") {
    return {
      ...permissions,
      useAccounts: true,
      retrieveAccounts: true,
      listAccounts: true,
      addAccounts: true,
      updateAccountContent: true,
      updateAccountProperties: true,
      initiateCPMAccountManagementOperations: true,
      specifyNextAccountContent: true,
      renameAccounts: true,
      deleteAccounts: true,
      unlockAccounts: true,
      manageSafeMembers: true,
      viewAuditLog: true,
      viewSafeMembers: true,
      moveAccountsAndFolders: true,
      requestsAuthorizationLevel1: true
    };
  }
  return {
    ...permissions,
    useAccounts: true,
    retrieveAccounts: true,
    listAccounts: true,
    viewAuditLog: true,
    viewSafeMembers: true
  };
}

function buildTaskChains(task, values, response) {
  if (!task || !responseSucceeded(response)) {
    return [];
  }
  const parsed = parseResponseBody(response?.body);
  const context = {
    safe_name: values.safe_name?.trim() || inferPrimaryValue(parsed, ["safeName", "SafeName"]),
    account_id: values.account_id?.trim() || inferPrimaryValue(parsed, ["id", "ID"]),
    platform_id: values.platform_id?.trim() || inferPrimaryValue(parsed, ["id", "platformID", "PlatformID"])
  };
  const options = [];
  if (task.id === "safes") {
    if (context.safe_name) {
      options.push({
        id: "safe-details",
        label: "Review That Safe",
        description: `Open ${context.safe_name} and inspect its settings.`,
        seed: { safe_name: context.safe_name }
      });
      options.push({
        id: "safe-members",
        label: "View Its Members",
        description: `Check who already has access to ${context.safe_name}.`,
        seed: { safe_name: context.safe_name }
      });
    }
    options.push({
      id: "create-safe",
      label: "Create A Safe",
      description: "Move straight into a guided safe creation request.",
      seed: {}
    });
  }
  if (task.id === "safe-details") {
    options.push({
      id: "safe-members",
      label: "View Safe Members",
      description: `See who has access to ${context.safe_name || "this safe"}.`,
      seed: { safe_name: context.safe_name || "" }
    });
    options.push({
      id: "add-safe-member",
      label: "Add Safe Member",
      description: `Grant a user or group access to ${context.safe_name || "this safe"}.`,
      seed: { safe_name: context.safe_name || "" }
    });
  }
  if (task.id === "safe-members") {
    options.push({
      id: "add-safe-member",
      label: "Grant Additional Access",
      description: `Add another user or group to ${context.safe_name || "this safe"}.`,
      seed: { safe_name: context.safe_name || "" }
    });
    options.push({
      id: "safe-details",
      label: "Review Safe Settings",
      description: `Open the safe settings for ${context.safe_name || "this safe"}.`,
      seed: { safe_name: context.safe_name || "" }
    });
  }
  if (task.id === "create-safe") {
    options.push({
      id: "safe-details",
      label: "Review New Safe",
      description: `Open ${context.safe_name || "the new safe"} and confirm the settings.`,
      seed: { safe_name: context.safe_name || "" }
    });
    options.push({
      id: "add-safe-member",
      label: "Add Members Next",
      description: `Start granting access to ${context.safe_name || "the new safe"}.`,
      seed: { safe_name: context.safe_name || "" }
    });
  }
  if (task.id === "add-safe-member") {
    options.push({
      id: "safe-members",
      label: "Review Membership",
      description: `Check the updated membership on ${context.safe_name || "this safe"}.`,
      seed: { safe_name: context.safe_name || "" }
    });
    options.push({
      id: "add-safe-member",
      label: "Add Another Member",
      description: `Keep ${context.safe_name || "the safe"} selected and add someone else.`,
      seed: { safe_name: context.safe_name || "" }
    });
  }
  if (task.id === "account-search" && context.account_id) {
    options.push({
      id: "account-details",
      label: "Open Matching Account",
      description: `Review the details for account ${context.account_id}.`,
      seed: { account_id: context.account_id }
    });
  }
  if (task.id === "platform-details") {
    options.push({
      id: "platforms",
      label: "Back To Platform List",
      description: "Return to the broader platform inventory view.",
      seed: {}
    });
  }
  return dedupeTaskChains(options);
}

function dedupeTaskChains(options) {
  const seen = new Set();
  return options.filter((option) => {
    const key = `${option.id}:${JSON.stringify(option.seed || {})}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function responseSucceeded(response) {
  return Number(response?.status) >= 200 && Number(response?.status) < 300;
}

function parseResponseBody(body) {
  try {
    return JSON.parse(body || "null");
  } catch {
    return null;
  }
}

function inferPrimaryValue(parsed, keys) {
  if (!parsed || !keys.length) {
    return "";
  }
  for (const key of keys) {
    const direct = parsed?.[key];
    if (typeof direct === "string" && direct.trim()) {
      return direct.trim();
    }
  }
  const collection = Array.isArray(parsed?.value) ? parsed.value : Array.isArray(parsed) ? parsed : [];
  if (collection.length === 1) {
    for (const key of keys) {
      const candidate = collection[0]?.[key];
      if (typeof candidate === "string" && candidate.trim()) {
        return candidate.trim();
      }
    }
  }
  return "";
}

function normalizeApiBuilder(payload = {}) {
  return {
    name: payload.name || "",
    description: payload.description || "",
    method: payload.method || "GET",
    path: payload.path || "",
    query: payload.query || "",
    body: payload.body || ""
  };
}

function emptyApiBuilder() {
  return {
    name: "",
    description: "",
    method: "GET",
    path: "",
    query: "",
    body: ""
  };
}

function emptyInteractiveAuthState() {
  return {
    challenge: null,
    mechanismId: "",
    action: "Answer",
    answer: "",
    message: "",
    polling: false
  };
}

function tokenStatus(token) {
  if (!token) {
    return {
      status: "not-requested",
      status_label: "Not requested",
      endpoint: "",
      source: "",
      expires_at_label: "Not requested"
    };
  }
  const active = token.expires_at > Date.now();
  return {
    status: active ? "active" : "inactive",
    status_label: active ? "Active" : "Inactive",
    endpoint: token.endpoint || "",
    source: token.source || "",
    expires_at_label: new Date(token.expires_at).toLocaleString()
  };
}

function emptyProfile() {
  return emptyProfileByType(PROFILE_TYPE_OAUTH);
}

function emptyProfileByType(authType) {
  const normalizedType = normalizeProfileType(authType);
  return {
    id: "",
    auth_type: normalizedType,
    name: "",
    nickname: "",
    username: "",
    subdomain: "",
    identity_tenant_host: "",
    application_id: "",
    client_id: "",
    client_secret: "",
    client_secret_stored: false,
    secret_update: ""
  };
}

function emptyTenant() {
  return {
    id: "",
    name: "",
    subdomain: "",
    identity_tenant_host: "",
    identity_base_url: "",
    identity_oauth_url: "",
    platform_token_url: "",
    vault_api_base_url: "",
    audit_api_base_url: "",
    audit_api_key: "",
    audit_api_key_stored: false,
    notes: ""
  };
}

function emptySessionForm() {
  return {
    setupPasscode: "",
    confirmPasscode: "",
    unlockPasscode: "",
    currentPasscode: "",
    newPasscode: "",
    confirmNewPasscode: ""
  };
}

function emptySnapshot() {
  return {
    profiles: [],
    tenants: [],
    active_profile_id: null,
    active_tenant_id: null,
    passcode_configured: false,
    session_locked: false,
    tokens: {
      identity: tokenStatus(null),
      platform: tokenStatus(null)
    }
  };
}

function deriveTenantUrls(tenant, profile = null) {
  const subdomain = cleanSubdomain(
    tenant?.subdomain ||
      extractSubdomainFromTenant(tenant || {})
  );
  const identityHost = cleanHost(
    tenant?.identity_tenant_host ||
      extractIdentityHost(tenant || {}) ||
      (subdomain ? `${subdomain}.id.cyberark.cloud` : "")
  );
  const applicationId = profile?.application_id?.trim() || "";
  return {
    sharedServicesUrl: subdomain ? `https://${subdomain}.cyberark.cloud` : "",
    identityHost: identityHost,
    identityTenantHost: identityHost,
    identityTokenUrlPrefix: identityHost ? `https://${identityHost}/oauth2/token` : "",
    identityTokenUrl:
      identityHost && applicationId ? `https://${identityHost}/oauth2/token/${applicationId}` : "",
    platformTokenUrl:
      tenant?.platform_token_url ||
      (identityHost ? `https://${identityHost}/oauth2/platformtoken` : ""),
    vaultApiBaseUrl:
      tenant?.vault_api_base_url ||
      (subdomain ? `https://${subdomain}.privilegecloud.cyberark.cloud/PasswordVault/API` : ""),
    auditApiBaseUrl:
      tenant?.audit_api_base_url ||
      (subdomain ? `https://${subdomain}.audit.cyberark.cloud` : "")
  };
}

function deriveIdentityUrls(profile, tenant = null) {
  const subdomain = cleanSubdomain(
    profile?.subdomain ||
      tenant?.subdomain ||
      extractSubdomainFromTenant(tenant || {})
  );
  const identityTenantHost = cleanHost(
    profile?.identity_tenant_host ||
      tenant?.identity_tenant_host ||
      extractIdentityHost(tenant || {}) ||
      (subdomain ? `${subdomain}.id.cyberark.cloud` : "")
  );
  const applicationId = profile?.application_id?.trim() || "";
  const interactive = isInteractiveProfile(profile);
  return {
    subdomain,
    identityTenantHost,
    identityTokenUrlPrefix: identityTenantHost ? `https://${identityTenantHost}/oauth2/token` : "",
    identityTokenUrl:
      identityTenantHost && interactive
        ? `https://${identityTenantHost}/oauth2/token`
        : identityTenantHost && applicationId
          ? `https://${identityTenantHost}/oauth2/token/${applicationId}`
          : ""
  };
}

function deriveInteractiveAuthUrls(profile, tenant = null) {
  const identityTenantHost = deriveIdentityUrls(profile, tenant).identityTenantHost;
  return {
    startAuthenticationUrl: identityTenantHost ? `https://${identityTenantHost}/Security/StartAuthentication` : "",
    advanceAuthenticationUrl: identityTenantHost ? `https://${identityTenantHost}/Security/AdvanceAuthentication` : ""
  };
}

function renderInteractiveChallengePanel() {
  const challenge = state.api.interactiveAuth.challenge;
  if (!challenge) {
    return "";
  }
  const selectedMechanismId =
    state.api.interactiveAuth.mechanismId ||
    challenge.mechanisms[0]?.mechanism_id ||
    "";
  const selectedMechanism =
    challenge.mechanisms.find((item) => item.mechanism_id === selectedMechanismId) ||
    challenge.mechanisms[0] ||
    null;
  const selectedAction =
    state.api.interactiveAuth.action ||
    selectedMechanism?.actions?.[0] ||
    "Answer";
  const mechanismKind = classifyInteractiveMechanism(selectedMechanism);
  const challengeHint = interactiveChallengeHint(mechanismKind, selectedAction);
  const quickActions = availableInteractiveQuickActions(selectedMechanism);
  const sendButtonLabel = quickActions.sendLabel || "Send Code";
  return `
    <form id="interactive-auth-form" class="form-grid profile-secret-form">
      <div class="wide card-head">
        <h3>Interactive Challenge</h3>
        <p>${escapeHtml(state.api.interactiveAuth.message || challenge.summary || "Choose the next MFA step to continue.")}</p>
        ${state.api.interactiveAuth.polling ? "<p>Auto-checking for approval...</p>" : ""}
        <p>${escapeHtml(challengeHint)}</p>
      </div>
      <label class="field">
        <span>Mechanism</span>
        <select name="mechanism_id">
          ${challenge.mechanisms.map((mechanism) => `<option value="${escapeAttr(mechanism.mechanism_id)}" ${mechanism.mechanism_id === selectedMechanismId ? "selected" : ""}>${escapeHtml(formatMechanismLabel(mechanism))}</option>`).join("")}
        </select>
      </label>
      <label class="field">
        <span>Action</span>
        <select name="action">
          ${(selectedMechanism?.actions || ["Answer"]).map((action) => `<option value="${escapeAttr(action)}" ${action === selectedAction ? "selected" : ""}>${escapeHtml(formatInteractiveActionLabel(action))}</option>`).join("")}
        </select>
      </label>
      <label class="wide field">
        <span>Challenge Answer / OTP</span>
        <input name="answer" value="${escapeAttr(state.api.interactiveAuth.answer || "")}" placeholder="Enter code or answer if this action requires it" />
      </label>
      <div class="button-row wide">
        <button type="button" class="ghost" data-interactive-quick-action="${escapeAttr(quickActions.sendAction || "")}" ${quickActions.sendAction ? "" : "disabled"}>${escapeHtml(sendButtonLabel)}</button>
        <button type="submit">Continue Interactive Auth</button>
      </div>
    </form>
  `;
}

function applyInteractiveAuthResult(result) {
  state.snapshot = result.state || state.snapshot;
  if (result.authenticated) {
    state.api.tokenRequestFailures.platform = false;
    stopInteractivePolling();
    state.api.interactiveAuth = emptyInteractiveAuthState();
    return;
  }
  const priorMechanismId = state.api.interactiveAuth.mechanismId || "";
  state.api.interactiveAuth = {
    challenge: result.challenge || null,
    mechanismId:
      priorMechanismId && (result.challenge?.mechanisms || []).some((item) => item.mechanism_id === priorMechanismId)
        ? priorMechanismId
        : result.challenge?.mechanisms?.[0]?.mechanism_id || "",
    action: result.challenge?.mechanisms?.[0]?.actions?.[0] || "Answer",
    answer: "",
    message: result.message || "",
    polling: false
  };
  if (shouldAutoPollInteractiveChallenge(result.challenge, state.api.interactiveAuth.mechanismId)) {
    startInteractivePolling(state.api.interactiveAuth.mechanismId);
  } else {
    stopInteractivePolling();
  }
}

function tokenIndicatorView(kind) {
  const token = state.snapshot?.tokens?.[kind] || {
    status: "not-requested",
    status_label: "Not requested"
  };
  if (state.api.tokenRequestFailures?.[kind]) {
    return {
      ...token,
      status: "invalid",
      status_label: "Failed"
    };
  }
  return token;
}

function shouldAutoPollInteractiveChallenge(challenge, mechanismId = "") {
  if (!challenge) {
    return false;
  }
  const summary = String(challenge.summary || "").toLowerCase();
  if (summary !== "oobpending") {
    return false;
  }
  const mechanisms = Array.isArray(challenge.mechanisms) ? challenge.mechanisms : [];
  const selectedMechanism =
    mechanisms.find((item) => item.mechanism_id === mechanismId) ||
    mechanisms[0] ||
    null;
  const actions = Array.isArray(selectedMechanism?.actions) ? selectedMechanism.actions : [];
  return actions.includes("Poll");
}

function startInteractivePolling(mechanismId = "") {
  const challenge = state.api.interactiveAuth.challenge;
  if (!shouldAutoPollInteractiveChallenge(challenge, mechanismId)) {
    return;
  }
  interactivePollMechanismId =
    mechanismId ||
    state.api.interactiveAuth.mechanismId ||
    challenge?.mechanisms?.[0]?.mechanism_id ||
    "";
  if (!interactivePollMechanismId) {
    return;
  }
  if (interactivePollIntervalId) {
    state.api.interactiveAuth.polling = true;
    return;
  }
  interactivePollAttempts = 0;
  state.api.interactiveAuth.polling = true;
  interactivePollInFlight = false;
  interactivePollIntervalId = window.setInterval(async () => {
    if (interactivePollInFlight || !state.api.interactiveAuth.challenge) {
      return;
    }
    if (interactivePollAttempts >= 120) {
      stopInteractivePolling();
      state.api.interactiveAuth.message =
        "Approval check timed out. Click Check Approval or Send Challenge to continue.";
      log("Interactive approval polling timed out. You can retry Check Approval.");
      render();
      return;
    }
    interactivePollInFlight = true;
    interactivePollAttempts += 1;
    try {
      const result = await bridge.advanceInteractiveAuthentication({
        mechanism_id: interactivePollMechanismId,
        action: "Poll",
        answer: ""
      });
      const wasAuthenticated = Boolean(result.authenticated);
      applyInteractiveAuthResult(result);
      if (wasAuthenticated) {
        log("Interactive approval detected and authentication completed.");
      }
      render();
    } catch (error) {
      stopInteractivePolling();
      log(formatError(error));
      render();
    } finally {
      interactivePollInFlight = false;
    }
  }, 2500);
}

function stopInteractivePolling() {
  if (interactivePollIntervalId) {
    window.clearInterval(interactivePollIntervalId);
  }
  interactivePollIntervalId = null;
  interactivePollInFlight = false;
  interactivePollAttempts = 0;
  interactivePollMechanismId = "";
  if (state?.api?.interactiveAuth) {
    state.api.interactiveAuth.polling = false;
  }
}

function classifyInteractiveMechanism(mechanism) {
  const text = `${mechanism?.name || ""} ${mechanism?.prompt || ""} ${mechanism?.answer_type || ""}`.toLowerCase();
  if (text.includes("email")) {
    return "email";
  }
  if (text.includes("sms") || text.includes("text")) {
    return "sms";
  }
  if (text.includes("mobile") || text.includes("push") || text.includes("oob") || text.includes("app")) {
    return "mobile";
  }
  if (text.includes("otp") || text.includes("code")) {
    return "otp";
  }
  return "unknown";
}

function formatMechanismLabel(mechanism) {
  const kind = classifyInteractiveMechanism(mechanism);
  const kindLabel = kind === "unknown" ? "Challenge" : kind.toUpperCase();
  const base = mechanism?.name || "Mechanism";
  const prompt = mechanism?.prompt ? ` - ${mechanism.prompt}` : "";
  return `${base} [${kindLabel}]${prompt}`;
}

function formatInteractiveActionLabel(action) {
  if (action === "StartNextChallenge") {
    return "Fetch Next Challenge";
  }
  if (action === "StartTextOob") {
    return "Send SMS Code";
  }
  if (action === "StartOOB") {
    return "Send Push (Mobile App)";
  }
  if (action === "Poll") {
    return "Check App Approval";
  }
  if (action === "Answer") {
    return "Submit Code / Answer";
  }
  return action;
}

function interactiveChallengeHint(kind, action) {
  if (action === "StartNextChallenge") {
    return "CyberArk requested a follow-up package. Run Fetch Next Challenge first, then choose the returned mechanism action.";
  }
  if (kind === "email") {
    if (action === "StartTextOob") {
      return "Click Continue to send the SMS/email code.";
    }
    if (action === "Answer") {
      return "Enter the email verification code, then continue.";
    }
    return "For this MFA method, send the code first, then Submit Code / Answer.";
  }
  if (kind === "sms") {
    return "For SMS MFA, use Send Code first, then Submit Code / Answer.";
  }
  if (kind === "mobile") {
    return "For mobile app MFA, use Send Push, approve in app, then Check App Approval.";
  }
  return "If you're expecting an MFA challenge, send the challenge first, then Submit Code / Answer if a code is required.";
}

function availableInteractiveQuickActions(mechanism) {
  const actions = Array.isArray(mechanism?.actions) ? mechanism.actions : [];
  const has = (name) => actions.includes(name);
  const kind = classifyInteractiveMechanism(mechanism);
  let sendAction = "";
  let sendLabel = "Send Code";

  if (has("StartNextChallenge")) {
    return {
      sendAction: "StartNextChallenge",
      sendLabel: "Fetch Next Challenge",
      pollAction: has("Poll") ? "Poll" : "",
      answerAction: has("Answer") ? "Answer" : ""
    };
  }

  if (kind === "email") {
    sendAction = has("StartOOB") ? "StartOOB" : has("StartTextOob") ? "StartTextOob" : "";
    sendLabel = "Send Push";
  } else if (kind === "sms") {
    sendAction = has("StartTextOob") ? "StartTextOob" : has("StartOOB") ? "StartOOB" : "";
    sendLabel = "Send SMS Code";
  } else {
    sendAction = has("StartOOB") ? "StartOOB" : has("StartTextOob") ? "StartTextOob" : "";
    sendLabel = "Send Challenge";
  }

  return {
    sendAction,
    sendLabel,
    pollAction: has("Poll") ? "Poll" : "",
    answerAction: has("Answer") ? "Answer" : ""
  };
}

function normalizeProfileType(value = "") {
  return String(value).trim().toLowerCase() === PROFILE_TYPE_INTERACTIVE
    ? PROFILE_TYPE_INTERACTIVE
    : PROFILE_TYPE_OAUTH;
}

function isInteractiveProfile(profile = {}) {
  if (!profile) {
    return false;
  }
  if (normalizeProfileType(profile.auth_type) === PROFILE_TYPE_INTERACTIVE) {
    return true;
  }
  const hasInteractiveIdentity = Boolean(String(profile.username || "").trim());
  const hasOauthIdentity = Boolean(String(profile.client_id || "").trim() || String(profile.application_id || "").trim());
  return hasInteractiveIdentity && !hasOauthIdentity;
}

function profileDisplayName(profile) {
  if (!profile) {
    return "None";
  }
  if (isInteractiveProfile(profile)) {
    return profile.nickname || profile.name || profile.username || "Unnamed interactive user";
  }
  return profile.name || profile.nickname || "Unnamed profile";
}

function profileSummaryLabel(profile) {
  if (!profile) {
    return "No profile configured";
  }
  if (isInteractiveProfile(profile)) {
    return profile.username || "No username configured";
  }
  return profile.client_id || "No client ID configured";
}

function extractSubdomainFromTenant(tenant) {
  const host =
    hostFromUrl(tenant?.vault_api_base_url) ||
    hostFromUrl(tenant?.identity_base_url) ||
    hostFromUrl(tenant?.platform_token_url);
  return host?.split(".")?.[0] || "";
}

function extractIdentityHost(tenant) {
  return (
    hostFromUrl(tenant?.identity_oauth_url) ||
    hostFromUrl(tenant?.platform_token_url) ||
    ""
  );
}

function hostFromUrl(value = "") {
  if (!value) {
    return "";
  }
  try {
    return new URL(value).host;
  } catch {
    return value.replace(/^https?:\/\//, "").replace(/\/.*$/, "").trim();
  }
}

function cleanSubdomain(value = "") {
  return value
    .trim()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "")
    .split(".")[0]
    .toLowerCase();
}

function cleanHost(value = "") {
  return value
    .trim()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "")
    .toLowerCase();
}

function capitalize(value) {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function loadTheme() {
  const stored = localStorage.getItem("fastpas-theme");
  if (stored === "light" || stored === "dark") {
    return stored;
  }
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function persistTheme() {
  localStorage.setItem("fastpas-theme", state.theme);
}

function loadSettings() {
  const defaults = {
    enableTokenCopy: true,
    tokenCopyEnabledAt: Date.now(),
    inactivityTimeoutMinutes: DEFAULT_INACTIVITY_TIMEOUT_MINUTES
  };
  try {
    const raw = localStorage.getItem("fastpas-settings");
    if (!raw) {
      return {
        ...defaults,
        enableTokenCopy: false,
        tokenCopyEnabledAt: 0
      };
    }
    const parsed = JSON.parse(raw);
    const enabledAt = Number(parsed?.tokenCopyEnabledAt) || 0;
    const withinWindow = enabledAt > 0 && Date.now() - enabledAt < TOKEN_COPY_WINDOW_MS;
    return {
      ...defaults,
      ...parsed,
      enableTokenCopy: parsed?.enableTokenCopy === true && withinWindow,
      tokenCopyEnabledAt: parsed?.enableTokenCopy === true && withinWindow ? enabledAt : 0,
      inactivityTimeoutMinutes: sanitizeInactivityTimeoutMinutes(parsed?.inactivityTimeoutMinutes)
    };
  } catch {
    return {
      ...defaults,
      enableTokenCopy: false,
      tokenCopyEnabledAt: 0
    };
  }
}

function persistSettings() {
  localStorage.setItem("fastpas-settings", JSON.stringify(state.settings));
}

function tokenCopyWindowRemainingMs() {
  if (!state.settings.enableTokenCopy) {
    return 0;
  }
  const enabledAt = Number(state.settings.tokenCopyEnabledAt) || 0;
  if (!enabledAt) {
    return 0;
  }
  return Math.max(0, enabledAt + TOKEN_COPY_WINDOW_MS - Date.now());
}

function enforceTokenCopyWindow() {
  if (!state.settings.enableTokenCopy) {
    return;
  }
  if (tokenCopyWindowRemainingMs() > 0) {
    return;
  }
  state.settings.enableTokenCopy = false;
  state.settings.tokenCopyEnabledAt = 0;
  persistSettings();
}

function startTokenCopyWindowMonitor() {
  stopTokenCopyWindowMonitor();
  if (!state.settings.enableTokenCopy) {
    return;
  }
  tokenCopyWindowIntervalId = window.setInterval(() => {
    const remainingMs = tokenCopyWindowRemainingMs();
    if (remainingMs <= 0) {
      state.settings.enableTokenCopy = false;
      state.settings.tokenCopyEnabledAt = 0;
      persistSettings();
      stopTokenCopyWindowMonitor();
      log("Temporary token copy window expired. Token copy is now disabled.");
      render();
      return;
    }
    updateTokenCopyWarningIndicator(remainingMs);
  }, 1000);
}

function stopTokenCopyWindowMonitor() {
  if (tokenCopyWindowIntervalId) {
    window.clearInterval(tokenCopyWindowIntervalId);
  }
  tokenCopyWindowIntervalId = null;
}

function updateTokenCopyWarningIndicator(remainingMs = tokenCopyWindowRemainingMs()) {
  const node = document.querySelector("#token-copy-warning-text");
  if (!node) {
    return;
  }
  node.textContent = `It will turn off automatically in ${Math.ceil(remainingMs / 1000)}s.`;
}

function sessionTimeoutMs() {
  return sanitizeInactivityTimeoutMinutes(state.settings.inactivityTimeoutMinutes) * 60 * 1000;
}

function sanitizeInactivityTimeoutMinutes(value) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  if (!Number.isFinite(parsed)) {
    return DEFAULT_INACTIVITY_TIMEOUT_MINUTES;
  }
  if (parsed < MIN_INACTIVITY_TIMEOUT_MINUTES) {
    return MIN_INACTIVITY_TIMEOUT_MINUTES;
  }
  if (parsed > MAX_INACTIVITY_TIMEOUT_MINUTES) {
    return MAX_INACTIVITY_TIMEOUT_MINUTES;
  }
  return parsed;
}

function safeJsonParse(value) {
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

function formatError(error) {
  if (typeof error === "string" && error.trim()) {
    return error;
  }
  if (error && typeof error === "object") {
    if (typeof error.message === "string" && error.message.trim()) {
      return error.message;
    }
    if (typeof error.error === "string" && error.error.trim()) {
      return error.error;
    }
    if (typeof error.toString === "function") {
      const rendered = error.toString();
      if (rendered && rendered !== "[object Object]") {
        return rendered;
      }
    }
    try {
      return JSON.stringify(error);
    } catch {
      return "Unknown error";
    }
  }
  return "Unknown error";
}

function applyTheme() {
  document.documentElement.dataset.theme = state.theme;
}

function log(message) {
  state.activity = [`${new Date().toLocaleTimeString()} ${message}`, ...state.activity].slice(0, 16);
}

function escapeHtml(value = "") {
  return value
    .toString()
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function escapeAttr(value = "") {
  return escapeHtml(value).replaceAll('"', "&quot;");
}
