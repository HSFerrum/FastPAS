const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const root = path.join(__dirname, '../..');
let source = fs.readFileSync(path.join(root, 'src/main.js'), 'utf8')
  .replace(/^import .*;\r?\n/gm, '')
  .replace(/boot\(\)\.catch\(\(error\) => \{[\s\S]*?\n\}\);/, '');
const reportSource = fs.readFileSync(path.join(root, 'src/rotation-report.js'), 'utf8').replace(/^export /gm, '');
let acknowledged = false;
const sandbox = {console, Date, window: {matchMedia: () => ({matches: false})}, localStorage: {getItem: () => null},
  document: {querySelector: selector => selector === '#rotation-acknowledge' ? {checked: acknowledged} : null},
  FormData: class {constructor(form) {this.fields = form.fields;} get(key) {return this.fields[key] || '';} getAll(key) {return this.fields[key] || [];}}};
vm.createContext(sandbox);
Object.assign(sandbox, vm.runInContext(`(()=>{${reportSource};return {buildRotationHealthHtml,presentRotationFindings,groupRotationRecommendations};})()`, sandbox));
vm.runInContext(source + '\nglobalThis.api={state,bridge,prepareRotationAction,applyRotationAction,prepareRotationConfiguration,renderRotationActionStatus,renderRotationHealthDashboard};render=()=>{};log=()=>{};', sandbox);
const {api} = sandbox;
const account = {account_id:'1_1',name:'Service account',safe_name:'Application credentials',username:'svc',address:'example',automatic_management_enabled:false,issues:['Automatic management disabled'],detail:'Approved maintenance exclusion'};
api.state.snapshot.active_tenant_id = 'tenant'; api.state.snapshot.active_profile_id = 'profile'; api.state.snapshot.session_locked = false;
api.state.telemetry.rotationHealth = {tenant_id:'tenant',profile_id:'profile',tenant_name:'Synthetic demonstration',generated_at:'2026-09-17T00:00:00Z',threshold_days:100,total_accounts:1,affected_accounts:1,inventory_complete:true,warnings:['Synthetic data only'],platforms:[{platform_id:'Windows',total_accounts:1,affected_accounts:1,disabled_accounts:1,accounts:[account],findings:[{level:'Confirmed setting',title:'Periodic password change disabled',evidence:'PerformPeriodicChange = No'},{level:'Confirmed setting',title:'Periodic verification disabled',evidence:'PerformPeriodicVerification = No'}],categories:[{label:'Automatic management disabled',accounts:[account]}]}]};
const form = {dataset:{platformIndex:'0'},fields:{operation:'enable_management',account_id:['1_1']}};
let prepared = 0, applied = 0;
api.bridge.prepareRotationAction = async payload => {prepared++; assert.equal(payload.platform_id,'Windows'); assert.equal(payload.account_ids.length,1); return {plan_id:'plan',operation:payload.operation,platform_id:'Windows',accounts:[account]};};
api.bridge.applyRotationAction = async () => {applied++; return {operation:'enable_management',platform_id:'Windows',results:[{account_id:'1_1',name:'Service account',accepted:true,detail:'Configuration update accepted.'},{account_id:'1_2',name:'Second account',accepted:false,detail:'HTTP 403. Check permissions.'}]};};
(async()=>{
  const event = {preventDefault(){},currentTarget:form};
  await api.prepareRotationAction(event);
  assert.equal(prepared,1); assert.ok(api.renderRotationActionStatus().includes('Approved maintenance exclusion'));
  assert.ok(api.renderRotationActionStatus().includes('authorize the displayed changes'));
  await api.applyRotationAction(); assert.equal(applied,0);
  acknowledged=true; await api.applyRotationAction(); assert.equal(applied,1);
  assert.ok(api.renderRotationActionStatus().includes('1 of 2 requests accepted'));
  assert.ok(api.renderRotationActionStatus().includes('HTTP 403'));
  api.state.snapshot.active_tenant_id='other'; assert.equal(api.renderRotationActionStatus(),'');
  api.state.snapshot.active_tenant_id='tenant';
  let finish;
  api.bridge.prepareRotationAction = () => new Promise(resolve => {finish=resolve;});
  const pending = api.prepareRotationAction(event);
  api.state.snapshot.active_profile_id='other'; finish({plan_id:'stale',accounts:[account]}); await pending;
  assert.ok(api.state.telemetry.rotationError.includes('context changed'));
  assert.equal(api.renderRotationActionStatus(),'');
  api.state.snapshot.active_profile_id='profile';
  form.fields.account_id=[]; await api.prepareRotationAction(event);
  assert.ok(api.state.telemetry.rotationError.includes('between 1 and 500'));
  api.state.telemetry.rotationAction=null; api.state.telemetry.rotationError='';
  api.prepareRotationConfiguration({currentTarget:{closest:()=>form}});
  assert.ok(api.renderRotationActionStatus().includes('PerformPeriodicChange = Yes'));
  assert.ok(api.renderRotationActionStatus().includes('has not modified the platform'));
  if(process.argv[2]) fs.writeFileSync(process.argv[2],`<!doctype html><html><head><meta charset="utf-8"><style>${fs.readFileSync(path.join(root,'src/styles.css'),'utf8')}</style></head><body><div id="app" style="max-width:1300px;margin:auto;padding:24px">${api.renderRotationHealthDashboard()}</div></body></html>`);
  console.log('Rotation action UI checks passed: exact scope review, acknowledgment required, partial results, stale context rejection, empty selection rejection, honest platform guide.');
})().catch(error=>{console.error(error);process.exitCode=1;});
