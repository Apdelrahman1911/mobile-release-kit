// Closed display/transport checks only: core derives all target paths and bytes.
import { sameJson } from './catalog.ts';
import { isU32, U32_MAX, isConfigPreview } from './configEditProtocol.ts';
import { GITHUB_WORKFLOWS, githubSetupRequestFits } from './githubSetupProtocol.ts';
import type { ApiError, CoreEditOutcome, JsonValue } from './types.ts';
import type { ProjectInitializationProjection, ProjectInitializationStatus, InitializationView, InitializationRecoveryView } from './projectInitializationTypes.ts';
const encoder = new TextEncoder();
const phases = ['opening', 'editing', 'preparing', 'reviewing', 'applying', 'finalizing', 'final', 'unknown'] as const;
const nativeReasons = ['none', 'discarded', 'cancelled', 'active_timeout', 'review_expired', 'caller_lost', 'window_lost', 'shutdown', 'runtime_unavailable', 'spawn_failed', 'protocol_error', 'io_error', 'output_limit', 'cleanup_unknown'];
const coreReasons = ['ignore_conflict', 'none', 'invalid_params', 'invalid_config', 'stale_revision', 'pending_state', 'busy', 'cancelled', 'filesystem_error', 'custody_unknown', 'unsupported_platform'];
const availability = ['available', 'unsupported_platform', 'runtime_unqualified', 'cleanup_unknown', 'shutdown', 'other_edit_active'];
const repository = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$/;

function record(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
function keys(value: unknown, expected: readonly string[]): value is Record<string, unknown> {
  if (!record(value)) return false;
  const names = Reflect.ownKeys(value);
  return names.length === expected.length && names.every((name) => {
    if (typeof name !== 'string' || !expected.includes(name)) return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
  });
}
function text(value: unknown, max: number, plain = true): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max &&
    !/[\ud800-\udfff]/u.test(value) && (!plain || !/[\u0000-\u001f\u007f]/u.test(value)) && encoder.encode(value).byteLength <= max;
}
function oneOf(value: unknown, choices: readonly string[]): boolean { return typeof value === 'string' && choices.includes(value); }
function token(value: unknown): value is string { return typeof value === 'string' && /^[0-9a-f]{32}$/.test(value); }
function digest(value: unknown): value is string { return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value); }
function length(value: unknown, max: number): value is number { return isU32(value) && value <= max; }

// Reject accessors/exotic objects, sparse arrays, cycles and hidden keys before
// copying data or allocating a serialized aggregate. Count keys as JSON nodes.
function boundedJson(value: unknown, bytes: number, maxNodes: number, maxDepth: number): boolean {
  let nodes = 0;
  let floor = 0;
  const ancestors = new Set<object>();
  const visit = (item: unknown, depth: number): boolean => {
    if (++nodes > maxNodes || depth > maxDepth) return false;
    if (item === null || typeof item === 'boolean') floor += 1;
    else if (typeof item === 'number') { if (!Number.isFinite(item)) return false; floor += 1; }
    else if (typeof item === 'string') {
      if (item.length > bytes || /[\ud800-\udfff]/u.test(item)) return false;
      floor += encoder.encode(item).byteLength + 2;
    } else {
      if (typeof item !== 'object' || depth >= maxDepth || ancestors.has(item)) return false;
      ancestors.add(item);
      if (Array.isArray(item)) {
        if (Object.getPrototypeOf(item) !== Array.prototype || item.length > maxNodes - nodes || Reflect.ownKeys(item).length !== item.length + 1) return false;
        floor += 2 + Math.max(0, item.length - 1);
        if (floor > bytes) return false;
        for (let index = 0; index < item.length; index += 1) {
          const descriptor = Object.getOwnPropertyDescriptor(item, String(index));
          if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, 'value') || !visit(descriptor.value, depth + 1)) return false;
        }
      } else {
        if (!record(item)) return false;
        const names = Reflect.ownKeys(item);
        if (names.length > maxNodes - nodes) return false;
        floor += 2 + Math.max(0, names.length * 2 - 1);
        if (floor > bytes) return false;
        for (const name of names) {
          if (typeof name !== 'string') return false;
          const descriptor = Object.getOwnPropertyDescriptor(item, name);
          if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, 'value') || !visit(name, depth + 1) || !visit(descriptor.value, depth + 1)) return false;
        }
      }
      ancestors.delete(item);
    }
    return floor <= bytes;
  };
  try { return visit(value, 0) && encoder.encode(JSON.stringify(value)).byteLength <= bytes; }
  catch { return false; }
}

export type ProjectInitializationCommand = 'project_initialization_open' | 'project_initialization_prepare' | 'project_initialization_apply' | 'project_initialization_discard' | 'project_initialization_status';
export function initializationRequestFits(command: ProjectInitializationCommand, value: unknown): boolean {
  try {
    if (!boundedJson(value, 1024 * 1024, 18000, 32)) return false;
    switch (command) {
      case 'project_initialization_status': return keys(value, []);
      case 'project_initialization_discard': return keys(value, ['sessionId']) && token(value.sessionId);
      case 'project_initialization_prepare': return keys(value, ['sessionId', 'revision', 'intent']) && token(value.sessionId) && token(value.revision) && oneOf(value.intent, ['initialize', 'recover']);
      case 'project_initialization_apply': return keys(value, ['sessionId', 'planToken', 'intent']) && token(value.sessionId) && token(value.planToken) && oneOf(value.intent, ['initialize', 'recover']);
      case 'project_initialization_open':
        if (!record(value)) return false;
        if (value.intent === 'recover') return keys(value, ['projectId', 'intent']) && text(value.projectId, 128);
        return keys(value, ['projectId', 'intent', 'draft', 'toolingRepository', 'toolingSha', 'draftRevision', 'baselineGeneration']) && value.intent === 'initialize' && text(value.projectId, 128) &&
          counter(value.draftRevision) && counter(value.baselineGeneration) && githubSetupRequestFits({ draft: value.draft, toolingRepository: value.toolingRepository, toolingSha: value.toolingSha, suppliedSnapshot: null });
    }
  } catch { return false; }
}
function counter(value: unknown): value is number { return isU32(value) && value < U32_MAX; }
function equal(first: unknown, next: unknown): boolean { return sameJson(first as JsonValue, next as JsonValue); }
function relative(value: unknown): value is string {
  return text(value, 4096) && !value.includes('\\') && !value.includes(':') && value.split('/').every((part) => part !== '' && part !== '.' && part !== '..' && encoder.encode(part).byteLength <= 255 && !/[. ]$/.test(part));
}
const fixed = [{kind:'configuration',path:'release/mobile-release.json'}, {kind:'gitignore',path:'.gitignore'}, ...GITHUB_WORKFLOWS.map(({path})=>({kind:'workflow',path}))];
function position(row: Record<string, unknown>, index: number): boolean {
  return row.index === index && relative(row.path) && (index < 6 ? row.kind === fixed[index]?.kind && row.path === fixed[index]?.path : row.kind === 'metadata');
}
function roster(rows: unknown): rows is Record<string, unknown>[] {
  if (!Array.isArray(rows) || rows.length < 6 || rows.length > 256) return false;
  const seen = new Set<string>(); let previous = '';
  return rows.every((row,index) => {
    if (!record(row) || !position(row,index) || typeof row.path !== 'string' || seen.has(row.path)) return false;
    if (index >= 6 && previous && comparePaths(row.path, previous) <= 0) return false;
    if (index >= 6) previous = row.path;
    seen.add(row.path); return true;
  });
}
function tuple(template: unknown, tooling: unknown): boolean {
  return keys(template, ['coreVersion', 'resourceVersion', 'resourceSha256']) && text(template.coreVersion, 32) && /^[0-9]+\.[0-9]+\.[0-9]+$/.test(template.coreVersion) && template.resourceVersion === 1 && digest(template.resourceSha256) &&
    keys(tooling, ['repository','sha','schemaReference','state']) && text(tooling.repository,140) && repository.test(tooling.repository) && typeof tooling.sha === 'string' && /^[0-9a-f]{40}$/.test(tooling.sha) && tooling.state === 'format-only' &&
    tooling.schemaReference === `https://raw.githubusercontent.com/${tooling.repository}/${tooling.sha}/schemas/project.schema.json`;
}
const ignoreLines = ['.mobile-release/', '.mobile-release-init-prepare/', '.mobile-release-init/', '.mobile-release-init-cleanup/', '.mobile-release-metadata-text-prepare/', '.mobile-release-metadata-text/', '.mobile-release-metadata-text-cleanup/', '.mobile-release-version-prepare/', '.mobile-release-version/', '.mobile-release-version-cleanup/', '.mobile-release-metadata-images-prepare/', '.mobile-release-metadata-images/', '.mobile-release-metadata-images-cleanup/'];
// Generated callers are small; observed originals may legitimately be larger.
function limit(kind: unknown): number { return kind === 'configuration' ? 512*1024 : kind === 'workflow' ? 16384 : kind === 'gitignore' ? 1024*1024 : 8*1024*1024; }
function observedLimit(kind: unknown): number { return kind === 'workflow' ? 1024*1024 : limit(kind); }
export function initializationView(value: unknown): value is InitializationView {
  if (!boundedJson(value, 768*1024, 20000, 30) || !keys(value,['schemaVersion','kind','files','directoryCount','createDirectories','configurationPreview','workflows','ignoreAdditions','templateSet','tooling']) ||
      value.schemaVersion !== 1 || value.kind !== 'project-initialization' || !roster(value.files) || !boundedJson(value.files,128*1024,12000,8) ||
      !length(value.directoryCount,256) || !Array.isArray(value.createDirectories) || value.createDirectories.length > value.directoryCount ||
      !isConfigPreview(value.configurationPreview) || !tuple(value.templateSet,value.tooling) || !Array.isArray(value.workflows) || value.workflows.length !== 4 ||
      !Array.isArray(value.ignoreAdditions) || value.ignoreAdditions.length > ignoreLines.length) return false;
  let bytes = 0; let beforeBytes = 0;
  if (!value.files.every((row) => {
    if (!keys(row,['index','kind','path','action','beforeBytes','afterBytes']) || !length(row.afterBytes,limit(row.kind)) ||
        !(row.beforeBytes === null || length(row.beforeBytes,limit(row.kind))) || !oneOf(row.action,row.kind === 'gitignore' ? ['create','append','preserve'] : ['create','preserve'])) return false;
    if (row.action === 'create' ? row.beforeBytes !== null : row.beforeBytes === null) return false;
    if (row.action === 'preserve' && row.beforeBytes !== row.afterBytes || row.action === 'append' && !(typeof row.beforeBytes === 'number' && row.afterBytes > row.beforeBytes)) return false;
    if ((row.kind === 'configuration' || row.kind === 'workflow') && row.afterBytes === 0 || row.kind === 'metadata' && row.action === 'create' && row.afterBytes !== 0) return false;
    bytes += row.afterBytes; beforeBytes += row.beforeBytes ?? 0; return bytes <= 64*1024*1024 && beforeBytes <= 64*1024*1024;
  })) return false;
  let previous = ''; let depth = 0; const parents = new Set<string>();
  for (const row of value.files) { const parts = (row.path as string).split('/'); for(let n=1;n<parts.length;n++) parents.add(parts.slice(0,n).join('/')); }
  if (parents.size !== value.directoryCount || value.files.some((row) => parents.has(row.path as string))) return false;
  if (!value.createDirectories.every((path) => {
    if (!relative(path) || !parents.has(path)) return false;
    const d = path.split('/').length;
    if (d < depth || d === depth && comparePaths(path, previous) <= 0) return false;
    depth = d; previous = path; return true;
  })) return false;
  let ix = -1;
  if (!value.ignoreAdditions.every((line) => { const n=ignoreLines.indexOf(line); if(n<0 || n<=ix)return false; ix=n;return true; })) return false;
  const ignore = value.files[1];
  if (ignore?.action === 'preserve' && value.ignoreAdditions.length !== 0 || ignore?.action !== 'preserve' && value.ignoreAdditions.length === 0) return false;
  const files = value.files; // Retain the already checked roster narrowing in the callback.
  return value.workflows.every((row,index) => keys(row,['id','path','content','byteLength','sha256']) && row.id === GITHUB_WORKFLOWS[index]?.id && row.path === GITHUB_WORKFLOWS[index]?.path && text(row.content,16384,false) && length(row.byteLength,16384) && row.byteLength === encoder.encode(row.content).byteLength && digest(row.sha256) && row.byteLength === files[index+2]?.afterBytes);
}
function recoveryFact(value: unknown, bytes: number): boolean { return value === null || keys(value,['byteLength','sha256','mode']) && length(value.byteLength,bytes) && digest(value.sha256) && length(value.mode,0o777); }
export function initializationRecoveryView(value: unknown): value is InitializationRecoveryView {
  if (!boundedJson(value,768*1024,20000,30) || !keys(value,['schemaVersion','kind','state','reason','action','transactionId','context','files','privateCleanup']) || value.schemaVersion !== 1 || value.kind !== 'project-initialization-recovery' ||
      !oneOf(value.state,['idle','recoverable','conflict']) || !oneOf(value.reason,['none','incomplete_journal','foreign_journal','legacy_journal','invalid_journal','unsupported_descriptor','resource_changed','target_changed','control_changed','namespace_changed']) ||
      !Array.isArray(value.files) || !boundedJson(value.files,128*1024,12000,8) || !keys(value.privateCleanup,['fileCount','directoryCount','scope']) ||
      value.privateCleanup.scope !== 'inspected-owned-journal-only' || !length(value.privateCleanup.fileCount,1024) || !length(value.privateCleanup.directoryCount,257)) return false;
  if (value.state !== 'recoverable') return value.action === null && value.transactionId === null && value.context === null && value.files.length === 0 && value.privateCleanup.fileCount === 0 && value.privateCleanup.directoryCount === 0 && (value.state === 'idle' ? value.reason === 'none' : value.reason !== 'none');
  if (value.reason !== 'none' || !token(value.transactionId) || !oneOf(value.action,['rollback','preparing_cleanup','committed_cleanup','rolled_back_cleanup']) || !keys(value.context,['configuration','templateSet','tooling']) ||
      !keys(value.context.configuration,['byteLength','sha256']) || !length(value.context.configuration.byteLength,512*1024) || value.context.configuration.byteLength === 0 || !digest(value.context.configuration.sha256) || !tuple(value.context.templateSet,value.context.tooling)) return false;
  if (value.files.length === 0) return oneOf(value.action,['committed_cleanup','rolled_back_cleanup']) && value.privateCleanup.fileCount === 2 && value.privateCleanup.directoryCount === 1;
  if (!roster(value.files)) return false;
  return value.files.every((row) => {
    if (!keys(row,['index','kind','path','effect','before','after']) || !recoveryFact(row.before,observedLimit(row.kind)) || !recoveryFact(row.after,limit(row.kind)) || row.before === null && row.after === null) return false;
    const expected = row.after === null ? 'preserve' : value.action === 'rollback' ? row.before === null ? 'remove_new' : 'restore_original' : value.action === 'committed_cleanup' ? 'keep_committed' : 'preserve';
    if (row.effect !== expected || row.effect === 'restore_original' && row.kind !== 'gitignore') return false;
    if (record(row.after) && ((row.kind === 'configuration' || row.kind === 'workflow') && row.after.byteLength === 0 || row.kind === 'metadata' && row.after.byteLength !== 0)) return false;
    return !record(row.after) || (record(row.before) ? row.after.mode === row.before.mode : row.after.mode === 0o644);
  });
}
function conflict(value: unknown): boolean {
  if (!keys(value,['schemaVersion','reason','files']) || value.schemaVersion !== 1 || value.reason !== 'existing_targets_differ' || !Array.isArray(value.files) || value.files.length === 0 || value.files.length > 5) return false;
  let previous=-1;
  return value.files.every((row)=> { if(!keys(row,['kind','path','beforeBytes']) || !length(row.beforeBytes,observedLimit(row.kind)))return false;
    const ix=fixed.findIndex((item)=>item.kind===row.kind && item.path===row.path && item.kind!=='gitignore'); if(ix<0 || ix<=previous)return false;previous=ix;return true; });
}

function comparePaths(first: string, next: string): number {
  const a=Array.from(first), b=Array.from(next); for(let n=0;n<Math.min(a.length,b.length);n++){const d=a[n]!.codePointAt(0)!-b[n]!.codePointAt(0)!;if(d)return d;}return a.length-b.length;
}
function outcome(value: unknown): value is CoreEditOutcome {
  if (!keys(value, ['effect', 'journal', 'resources', 'reason']) ||
      !oneOf(value.effect, ['not_started', 'unchanged', 'rolled_back', 'committed', 'unknown']) ||
      !oneOf(value.journal, ['not_created', 'clean', 'recovery_required', 'unknown']) ||
      !oneOf(value.resources, ['settled', 'unknown']) || !oneOf(value.reason, coreReasons)) return false;
  if (value.effect === 'unchanged' && value.journal !== 'not_created') return false;
  if (oneOf(value.effect, ['committed', 'rolled_back']) && value.journal === 'not_created') return false;
  return value.reason !== 'none' || value.resources === 'settled' &&
    value.effect !== 'unknown' && value.journal !== 'unknown' && value.journal !== 'recovery_required';
}
function checkout(value: unknown): boolean {
  if (!record(value) || !token(value.revision)) return false;
  if(value.intent === 'recover')return keys(value,['intent','revision','recovery']) && initializationRecoveryView(value.recovery);
  return keys(value,['intent','revision','draftRevision','baselineGeneration','observed']) && value.intent === 'initialize' && counter(value.draftRevision) && counter(value.baselineGeneration) &&
    keys(value.observed,['schemaVersion','fileCount','directoryCount']) && value.observed.schemaVersion === 1 && length(value.observed.fileCount,256) && value.observed.fileCount >=6 && length(value.observed.directoryCount,256);
}
function prepared(value: unknown): boolean {
  if(!record(value) || !token(value.revision) || !token(value.planToken) || value.revision===value.planToken)return false;
  if(value.intent === 'recover') return keys(value,['intent','revision','planToken','recovery']) && initializationRecoveryView(value.recovery) && value.recovery.state === 'recoverable';
  return keys(value,['intent','revision','planToken','draftRevision','baselineGeneration','view']) && value.intent==='initialize' && counter(value.draftRevision) && counter(value.baselineGeneration) && initializationView(value.view);
}
function recoveryExpected(view: InitializationRecoveryView): CoreEditOutcome['effect'] | null {
  if(view.state !== 'recoverable')return null;
  return view.action === 'committed_cleanup' ? 'committed' : view.action === 'preparing_cleanup' ? 'not_started' : view.action === 'rollback' || view.action === 'rolled_back_cleanup' ? 'rolled_back' : null;
}
function projection(value: unknown): value is ProjectInitializationProjection {
  if(!keys(value,['domain','intent','projectId','sessionId','ownerGeneration','phase','reviewRemainingMs','checkout','prepared','conflict','applySubmitted','coreOutcome','nativeReason','nativeFinality','lateSettled']) || value.domain !== 'project_initialization' || !oneOf(value.intent,['initialize','recover']) ||
     !text(value.projectId,128) || !token(value.sessionId) || !token(value.ownerGeneration) || !oneOf(value.phase,phases) || !length(value.reviewRemainingMs,900000) ||
     typeof value.applySubmitted !== 'boolean' || typeof value.lateSettled !== 'boolean' || !oneOf(value.nativeReason,nativeReasons) || !oneOf(value.nativeFinality,['pending','settled','unknown']) ||
     !(value.checkout===null || checkout(value.checkout)) || !(value.prepared===null || prepared(value.prepared)) || !(value.conflict===null || conflict(value.conflict)) || !(value.coreOutcome===null || outcome(value.coreOutcome))) return false;
  const p=value as unknown as ProjectInitializationProjection;
  if(p.checkout && p.checkout.intent!==p.intent || p.prepared && p.prepared.intent!==p.intent || p.intent==='recover' && p.conflict)return false;
  if(p.prepared){
    if(!p.checkout || p.prepared.revision!==p.checkout.revision)return false;
    if(p.prepared.intent==='initialize'){
      if(p.checkout.intent!=='initialize' || p.prepared.draftRevision!==p.checkout.draftRevision || p.prepared.baselineGeneration!==p.checkout.baselineGeneration || p.prepared.view.files.length!==p.checkout.observed.fileCount || p.prepared.view.directoryCount!==p.checkout.observed.directoryCount)return false;
    } else if(p.checkout.intent!=='recover' || !equal(p.prepared.recovery,p.checkout.recovery))return false;
  }
  if(p.conflict && (p.prepared || p.applySubmitted || !p.checkout || !['finalizing','final','unknown'].includes(p.phase) || p.coreOutcome && (p.coreOutcome.effect!=='not_started'||p.coreOutcome.journal!=='not_created')))return false;
  if(p.phase==='final'){
    if(p.nativeFinality!=='settled'||p.lateSettled)return false;
    if(p.coreOutcome===null){if(p.checkout||p.prepared||p.conflict||p.applySubmitted||p.nativeReason==='none')return false;}
    else if(p.coreOutcome.resources==='unknown'||p.coreOutcome.effect==='unknown'||p.coreOutcome.journal==='unknown')return false;
  } else if(p.phase==='unknown'){if(p.nativeFinality!=='unknown')return false;}
  else if(p.nativeFinality!=='pending'||p.lateSettled)return false;
  if(p.phase==='opening'&&(p.checkout||p.prepared||p.applySubmitted||p.conflict))return false;
  if(['editing','preparing','reviewing','applying'].includes(p.phase)&&!p.checkout)return false;
  if(['editing','preparing'].includes(p.phase)&&(p.prepared||p.conflict||p.applySubmitted))return false;
  if(['reviewing','applying'].includes(p.phase)&&!p.prepared)return false;
  if(p.phase==='reviewing'&&p.applySubmitted || p.phase==='applying'&&!p.applySubmitted || p.applySubmitted&&!p.prepared)return false;
  if(['opening','editing','preparing','reviewing'].includes(p.phase)&&p.coreOutcome)return false;
  const core=p.coreOutcome;
  if(p.intent==='initialize' && core && ['committed','rolled_back','unchanged'].includes(core.effect)){
    if(p.prepared?.intent!=='initialize'||!p.applySubmitted||p.conflict)return false;
    const noWrites=p.prepared.view.files.every(row=>row.action==='preserve');
    if(core.effect==='unchanged'?!noWrites:noWrites)return false;
  }
  if(p.intent==='recover' && core){
    if(core.effect==='unchanged'||!p.applySubmitted&&core.journal==='clean')return false;
    const view=p.checkout?.intent==='recover'?p.checkout.recovery:null;
    if(view){
      const expected=recoveryExpected(view);
      if(view.state==='recoverable'&&core.journal==='not_created')return false;
      if(view.action==='rollback' ? core.effect!=='not_started'&&(!p.applySubmitted||!['rolled_back','unknown'].includes(core.effect)) : core.effect!==(expected??'not_started'))return false;
    }
    if(p.applySubmitted && core.reason==='none' && (p.prepared?.intent!=='recover'||core.resources!=='settled'||core.journal!=='clean'||core.effect!==recoveryExpected(p.prepared.recovery)))return false;
  }
  return true;
}
export function parseProjectInitializationStatus(value: unknown): ProjectInitializationStatus | null {
  try {
    if(!boundedJson(value,2*1024*1024,65000,32)||!keys(value,['schemaVersion','domain','windowGeneration','statusRevision','capability','active','lastTerminal'])||value.schemaVersion!==1||value.domain!=='project_initialization'||!token(value.windowGeneration)||!isU32(value.statusRevision)||
      !keys(value.capability,['available','reason'])||typeof value.capability.available!=='boolean'||!oneOf(value.capability.reason,availability)||value.capability.available!==(value.capability.reason==='available')||!(value.active===null||projection(value.active))||!(value.lastTerminal===null||projection(value.lastTerminal)))return null;
    const s=value as unknown as ProjectInitializationStatus;
    if(s.active?.phase==='final'||s.active?.lateSettled||s.active&&s.capability.reason==='other_edit_active'||s.lastTerminal&&!['final','unknown'].includes(s.lastTerminal.phase)||s.active&&s.active.sessionId===s.lastTerminal?.sessionId)return null;
    return s;
  } catch{return null;}
}
export function normalInitializationResult(p: ProjectInitializationProjection): 'initialized'|'unchanged'|null {
  const c=p.coreOutcome;
  if(p.intent!=='initialize'||p.prepared?.intent!=='initialize'||!p.checkout||p.phase!=='final'||p.nativeFinality!=='settled'||p.nativeReason!=='none'||p.lateSettled||!p.applySubmitted||p.conflict||!c||c.resources!=='settled'||c.reason!=='none')return null;
  const noop=p.prepared.view.files.every(f=>f.action==='preserve');
  return c.effect==='committed'&&c.journal==='clean'&&!noop?'initialized':c.effect==='unchanged'&&c.journal==='not_created'&&noop?'unchanged':null;
}
export function normalInitializationRecovery(p: ProjectInitializationProjection): boolean {
  const c=p.coreOutcome;
  return p.intent==='recover'&&p.prepared?.intent==='recover'&&p.checkout?.intent==='recover'&&p.phase==='final'&&p.nativeFinality==='settled'&&p.nativeReason==='none'&&!p.lateSettled&&p.applySubmitted&&Boolean(c&&c.resources==='settled'&&c.reason==='none'&&c.journal==='clean'&&c.effect===recoveryExpected(p.prepared.recovery));
}
function sameFacts(a:ProjectInitializationProjection,b:ProjectInitializationProjection):boolean{return equal({...a,reviewRemainingMs:0},{...b,reviewRemainingMs:0});}
export function initializationProjectionProgress(a:ProjectInitializationProjection,b:ProjectInitializationProjection):boolean {
  if(a.domain!==b.domain||a.intent!==b.intent||a.projectId!==b.projectId||a.sessionId!==b.sessionId||a.ownerGeneration!==b.ownerGeneration||a.checkout!==null&&!equal(a.checkout,b.checkout)||a.prepared!==null&&!equal(a.prepared,b.prepared)||a.conflict!==null&&!equal(a.conflict,b.conflict)||a.applySubmitted&&!b.applySubmitted||a.lateSettled&&!b.lateSettled)return false;
  if(a.phase==='final')return sameFacts(a,b);
  if(a.phase==='unknown'&&b.phase!=='unknown'||phases.indexOf(b.phase)<phases.indexOf(a.phase)||a.nativeReason!=='none'&&a.nativeReason!==b.nativeReason)return false;
  if(a.coreOutcome&&(!b.coreOutcome||a.coreOutcome.effect!=='unknown'&&a.coreOutcome.effect!==b.coreOutcome.effect||a.coreOutcome.reason!=='none'&&a.coreOutcome.reason!==b.coreOutcome.reason))return false;
  return true;
}
export function initializationStatusProgress(a:ProjectInitializationStatus,b:ProjectInitializationStatus):boolean {
  if(a.windowGeneration!==b.windowGeneration||b.statusRevision<a.statusRevision)return true;
  if(a.statusRevision===b.statusRevision)return equal(a.capability,b.capability)&&(['active','lastTerminal'] as const).every(k=>a[k]===null||b[k]===null?a[k]===b[k]:sameFacts(a[k],b[k]));
  return [a.active,a.lastTerminal].every(p=>{if(!p)return true;const n=[b.active,b.lastTerminal].find(o=>o?.sessionId===p.sessionId);return !n||initializationProjectionProgress(p,n);});
}
export function initializationError(error:unknown):ApiError {
  let code:unknown;try{code=record(error)?Object.getOwnPropertyDescriptor(error,'code')?.value:undefined;}catch{/* Never reveal arbitrary rejection text. */}
  if(code==='ProjectInitializationRequestInvalid')return{code,message:'The bounded initialization request was refused before sending. Nothing was truncated.',retryable:false};
  if(code==='ProjectInitializationStatusInvalid')return{code,message:'Initialization status failed its closed contract. Retain the original owner; no success is confirmed.',retryable:false};
  return{code:'ProjectInitializationUnavailable',message:'Initialization cannot be confirmed. Observe the original operation; never repeat an ambiguous Apply. Browser preview cannot initialize files.',retryable:false};
}
