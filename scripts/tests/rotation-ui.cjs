const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
let source = fs.readFileSync(require('node:path').join(__dirname, '../../src/main.js'), 'utf8');
source = source.replace('import "./styles.css";', '');
source = source.replace('import { buildRotationHealthHtml, presentRotationFindings, groupRotationRecommendations } from "./rotation-report.js";', '');
source = source.replace(/boot\(\)\.catch\(\(error\) => \{[\s\S]*?\n\}\);/, '');
let download;
const sandbox = {window: {matchMedia: () => ({matches: false})}, localStorage: {getItem: () => null}, console, Date,
  document: {querySelector: () => null}};
vm.createContext(sandbox);
const reportSource = fs.readFileSync(require('node:path').join(__dirname, '../../src/rotation-report.js'), 'utf8').replace(/^export /gm, '');
Object.assign(sandbox, vm.runInContext(`(() => {${reportSource}; return {buildRotationHealthHtml, presentRotationFindings, groupRotationRecommendations};})()`, sandbox));
vm.runInContext(source + '\nglobalThis.api = {state, renderRotationHealthDashboard, exportRotationHealth, exportRotationHtml, currentRotationReport};', sandbox);
vm.runInContext('saveDownload = async payload => capture(payload);', Object.assign(sandbox, {capture: payload => {download = payload;}}));
const {state, renderRotationHealthDashboard, exportRotationHealth, currentRotationReport} = sandbox.api;
state.snapshot.active_tenant_id = 'tenant';
state.snapshot.active_profile_id = 'profile';
state.snapshot.session_locked = false;
const account = {account_id: 'a1', name: '=malicious', safe_name: '<script>bad</script>', username: 'user', address: 'host',
  reported_age_days: 101, reported_change_time: null, automatic_management_enabled: false, status: 'failure',
  issues: ['Change failed', 'Automatic management disabled'], age_evidence: 'unconfirmed', detail: 'reason'};
state.telemetry.rotationHealth = {tenant_id: 'tenant', profile_id: 'profile', tenant_name: 'Fixture', generated_at: '2026-09-17T00:00:00Z',
  threshold_days: 100, inventory_complete: false, total_accounts: 2, affected_accounts: 1, warnings: ['Incomplete inventory'],
  platforms: [{platform_id: 'Windows', total_accounts: 2, affected_accounts: 1, oldest_reported_age_days: 101,
    findings: [{level: 'Unknown', title: 'Missing setting', evidence: 'Not exposed'}],
    categories: [{label: 'Change failed', accounts: [account]}, {label: 'Automatic management disabled', accounts: [account]}]}]};
const html = renderRotationHealthDashboard();
assert.ok(html.includes('Incomplete inventory'));
assert.ok(html.includes('&lt;script&gt;'));
assert.ok(!html.includes('<script>bad</script>'));
assert.ok(html.includes('Change failed (1)'));
assert.ok(html.includes('Core issues'));
assert.ok(html.includes('Additional recommendations'));
assert.ok(html.includes('Review selected account action'));
const grouped = sandbox.groupRotationRecommendations({findings: [
  {level: 'Confirmed setting', title: 'Periodic password change disabled', evidence: 'No'},
  {level: 'Confirmed setting', title: 'Periodic verification disabled', evidence: 'No'},
  {level: 'Unknown', title: 'Platform configuration could not be inspected', evidence: 'HTTP 403'}], categories: []});
assert.equal(grouped.core.length, 1);
assert.equal(grouped.additional.length, 1);
assert.equal(grouped.inspection.length, 1);
exportRotationHealth();
assert.equal(download.split('\r\n').filter(line => line.startsWith('account,')).length, 1);
assert.ok(download.includes("'=malicious"));
assert.ok(download.includes('platform_finding'));
assert.ok(download.includes('coverage'));
const standalone = sandbox.buildRotationHealthHtml(state.telemetry.rotationHealth);
assert.ok(standalone.includes('Core issues'));
assert.ok(standalone.includes('Additional recommendations'));
assert.ok(standalone.startsWith('<!doctype html>'));
assert.ok(standalone.includes('data-tab="platform-0"'));
assert.ok(standalone.includes('Scope and evidence'));
assert.ok(standalone.includes('account-search'));
assert.ok(!standalone.includes('<script>bad</script>'));
assert.ok(!standalone.includes('src="http'));
const script = standalone.match(/<script>([\s\S]*?)<\/script>/)[1];
new vm.Script(script);
if (process.argv[2]) {
  const fixture = JSON.parse(JSON.stringify(state.telemetry.rotationHealth));
  fixture.tenant_name = 'Example tenant'; fixture.inventory_complete = true;
  fixture.warnings = ['This demonstration uses synthetic account data. Inventory includes only accounts visible to the scanning identity.'];
  fixture.platforms[0].platform_id = 'Windows Domain Accounts'; fixture.platforms[0].disabled_accounts = 1;
  fixture.platforms[0].findings = [
    {level: 'Confirmed setting', title: 'Periodic password change disabled', evidence: '/Properties/PerformPeriodicChange = "No". Relevance depends on the platform workflow.'},
    {level: 'Review', title: 'Schedule or credential configuration', evidence: '/Properties/FromHour = "22". Review effective policy, scheduling, and account-level overrides; this setting alone does not prove a cause.'},
    {level: 'Unknown', title: 'PerformVerifyTask not exposed', evidence: 'Missing settings are not treated as enabled or disabled.'},
    {level: 'Unknown', title: 'Effective policy and linked credentials require further inspection', evidence: 'Effective policy is not established.'}
  ];
  fixture.platforms[0].categories.forEach(c => c.accounts.forEach(a => { a.name = 'Service account — reporting'; a.safe_name = 'Production service accounts'; a.platform_id = 'Windows Domain Accounts'; a.username = 'svc_reporting'; a.detail = 'The target rejected the password change. Review the account permissions.'; }));
  const unix = JSON.parse(JSON.stringify(fixture.platforms[0]));
  unix.platform_id = 'Unix SSH Accounts'; unix.findings = [{level: 'Confirmed setting', title: 'Reconciliation processing disabled', evidence: '/Properties/PerformReconcileTask = "No". Relevance depends on the platform workflow.'}];
  unix.categories = [{label: 'Reconcile failed', accounts: [{...unix.categories[0].accounts[0], account_id: 'a2', name: 'Linux administrator', platform_id: unix.platform_id, username: 'admin', issues: ['Reconcile failed'], detail: 'The recovery identity could not authenticate to the target.'}]}];
  fixture.platforms.push(unix); fixture.total_accounts = 4; fixture.affected_accounts = 2;
  fs.writeFileSync(process.argv[2], sandbox.buildRotationHealthHtml(fixture), 'utf8');
}
const recommendations = sandbox.presentRotationFindings([
  {level: 'Confirmed setting', title: 'Periodic password change disabled', evidence: '/Details/PerformPeriodicChange = "No". Relevance depends on the platform workflow.'},
  {level: 'Unknown', title: 'PerformChangeTask not exposed', evidence: 'Missing settings are not treated as enabled or disabled.'},
  {level: 'Unknown', title: 'PerformVerifyTask not exposed', evidence: 'Missing settings are not treated as enabled or disabled.'}
]);
assert.equal(recommendations.length, 2);
assert.ok(recommendations[0].summary.includes('Periodic password changes'));
assert.ok(recommendations[0].recommendation.includes('effective policy'));
assert.ok(!recommendations[0].summary.includes('= "No"'));
assert.ok(recommendations[1].summary.includes('2 management settings'));
state.snapshot.active_tenant_id = 'different';
assert.equal(currentRotationReport(), null);
const capability = JSON.parse(fs.readFileSync(require('node:path').join(__dirname, '../../src-tauri/capabilities/main.json'), 'utf8'));
assert.ok(capability.windows.includes('main'));
assert.ok(capability.permissions.includes('dialog:allow-save'));
assert.ok(!capability.remote);
(async () => {
  await Promise.resolve();
  state.snapshot.active_tenant_id = 'tenant';
  state.snapshot.session_locked = false;
  vm.runInContext('saveDownload = async () => {throw new Error("Test export failure");}; render = () => {};', sandbox);
  await sandbox.api.exportRotationHtml();
  assert.ok(state.telemetry.rotationError.includes('Test export failure'));
  console.log('Export permission and visible error handling checks passed.');
})().catch(error => { console.error(error); process.exitCode = 1; });
assert.ok(!renderRotationHealthDashboard().includes('Fixture'));
state.snapshot.active_tenant_id = 'tenant';
state.snapshot.session_locked = true;
assert.equal(currentRotationReport(), null);
console.log('Rotation UI checks passed: escaped HTML, issue groups, unique CSV rows, formula protection, coverage export, tenant isolation, session lock, standalone HTML tabs/search, export script syntax, readable recommendations.');
