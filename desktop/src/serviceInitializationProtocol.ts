// Compact original-request DATA. Only the existing native Initialization owner
// can capture source, prepare its inventory, issue permission or publish files.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { initializationRequestFits, parseProjectInitializationStatus } from './projectInitializationProtocol.ts';
import type { OpenProjectInitializationRequest, ProjectInitializationStatus } from './projectInitializationTypes.ts';
import type { ConfigurationOrigin, ConfigurationOriginal, ConfigurationResult } from './serviceConfigurationProtocol.ts';

export const INITIALIZATION_CONSENT = 'initialize-project-v1';
export const INITIALIZATION_EVENT = 'mrk:agent-initialization';
export type InitializationOrigin = ConfigurationOrigin;
export type InitializationOriginal = ConfigurationOriginal;
export interface InitializationAgentReview {
  planToken: string; nativeStatusRevision: number; draftRevision: number; baselineGeneration: number;
  fileCount: number; createdFiles: number; preservedFiles: number; appendedFiles: number; createdDirectories: number;
  toolingRepository: string; toolingSha: string;
}
export type InitializationAgentPhase = 'queued-open' | 'opening' | 'opened' | 'preparing' | 'reviewing' | 'queued-apply' | 'applying' | 'stopping' | 'refused' | 'final' | 'unknown';
export interface InitializationAgentRequest {
  schemaVersion: 1; origin: InitializationOrigin; runtimeProjectId: string; revision: number;
  phase: InitializationAgentPhase; settlement: 'pending' | 'settled' | 'unknown';
  original: InitializationOriginal | null; review: InitializationAgentReview | null;
  permissionAvailable: boolean; permissionConsumed: boolean; remainingMs: number; cancelRequested: boolean;
  result: ConfigurationResult | null; doNotReplay: true;
}
export interface InitializationAgentStatus { serviceInstance: string; request: InitializationAgentRequest | null }
export interface InitializationAgentAllow {
  origin: InitializationOrigin; original: InitializationOriginal; planToken: string;
  expectedNativeStatusRevision: number; expectedRequestRevision: number; consentVersion: typeof INITIALIZATION_CONSENT;
}
export interface InitializationAgentApi {
  status(origin?: InitializationOrigin): Promise<InitializationAgentStatus>;
  allow(input: InitializationAgentAllow): Promise<InitializationAgentStatus>;
  revoke(origin: InitializationOrigin): Promise<InitializationAgentStatus>;
  open(origin: InitializationOrigin, input: Extract<OpenProjectInitializationRequest, {intent: 'initialize'}>): Promise<ProjectInitializationStatus>;
  prepare(origin: InitializationOrigin, sessionId: string, revision: string): Promise<ProjectInitializationStatus>;
  apply(origin: InitializationOrigin, sessionId: string, planToken: string): Promise<ProjectInitializationStatus>;
  subscribe(listener: (status: unknown) => void): Promise<() => void>;
}
const keys = (v: unknown, names: readonly string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v) &&
  Object.keys(v).length === names.length && names.every(k => Object.hasOwn(v, k));
const id = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{32}(?![\s\S])/.test(v) && !/^0+$/.test(v);
const uint = (v: unknown, max = 0xfffffffe, min = 0): v is number => typeof v === 'number' && Number.isInteger(v) && v >= min && v <= max;
const nullable = <T>(v: unknown, f: (x: unknown) => x is T): v is T | null => v === null || f(v);
const origin = (v: unknown): v is InitializationOrigin => keys(v, ['projectId','serviceInstance','requestId']) && Object.values(v).every(id);
const original = (v: unknown): v is InitializationOriginal => keys(v, ['sessionId','ownerGeneration','revision']) && Object.values(v).every(id);
const repository = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?(?![\s\S])/;
const phases: readonly string[] = ['queued-open','opening','opened','preparing','reviewing','queued-apply','applying','stopping','refused','final','unknown'];
export const sameInitializationOrigin = (a: InitializationOrigin, b: InitializationOrigin): boolean =>
  a.projectId === b.projectId && a.serviceInstance === b.serviceInstance && a.requestId === b.requestId;
export function freezeInitializationData<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) { for (const child of Object.values(value)) freezeInitializationData(child); Object.freeze(value); }
  return value;
}
function review(v: unknown): v is InitializationAgentReview {
  return keys(v, ['planToken','nativeStatusRevision','draftRevision','baselineGeneration','fileCount','createdFiles','preservedFiles','appendedFiles','createdDirectories','toolingRepository','toolingSha']) &&
    id(v.planToken) && uint(v.nativeStatusRevision) && uint(v.draftRevision) && uint(v.baselineGeneration) && uint(v.fileCount,256,6) &&
    uint(v.createdFiles,256) && uint(v.preservedFiles,256) && uint(v.appendedFiles,1) && uint(v.createdDirectories,256) &&
    v.createdFiles + v.preservedFiles + v.appendedFiles === v.fileCount && typeof v.toolingRepository === 'string' && repository.test(v.toolingRepository) &&
    typeof v.toolingSha === 'string' && /^[0-9a-f]{40}(?![\s\S])/.test(v.toolingSha);
}
function result(v: unknown): v is ConfigurationResult {
  return keys(v, ['effect','journal','cancelled','applySubmitted']) && ['not_started','unchanged','rolled_back','committed'].includes(String(v.effect)) &&
    ['not_created','clean','recovery_required'].includes(String(v.journal)) && typeof v.cancelled === 'boolean' && typeof v.applySubmitted === 'boolean';
}
function request(v: unknown): v is InitializationAgentRequest {
  if (!keys(v, ['schemaVersion','origin','runtimeProjectId','revision','phase','settlement','original','review','permissionAvailable','permissionConsumed','remainingMs','cancelRequested','result','doNotReplay']) ||
    v.schemaVersion !== 1 || !origin(v.origin) || typeof v.runtimeProjectId !== 'string' || !/^[A-Za-z0-9_-]{1,64}(?![\s\S])/.test(v.runtimeProjectId) ||
    !uint(v.revision,0xfffffffe,1) || !phases.includes(String(v.phase)) || v.settlement !== (v.phase === 'final' ? 'settled' : v.phase === 'unknown' ? 'unknown' : 'pending') ||
    !nullable(v.original, original) || !nullable(v.review, review) || !nullable(v.result, result) || (v.phase === 'final') !== (v.result !== null) ||
    typeof v.permissionAvailable !== 'boolean' || typeof v.permissionConsumed !== 'boolean' || typeof v.cancelRequested !== 'boolean' || !uint(v.remainingMs,900000) || v.doNotReplay !== true) return false;
  return !(v.review && !v.original || v.permissionAvailable && (v.permissionConsumed || v.cancelRequested || v.phase !== 'reviewing' || !v.review) ||
    v.permissionConsumed && !v.review || ['opened','preparing','reviewing','queued-apply','applying'].includes(String(v.phase)) && !v.original ||
    ['reviewing','queued-apply','applying'].includes(String(v.phase)) && !v.review);
}
export function parseInitializationAgentStatus(value: unknown): InitializationAgentStatus | null {
  try {
    const v = copyBoundedComparisonData(value, 16 * 1024, 256);
    if (!keys(v, ['serviceInstance','request']) || !id(v.serviceInstance) || !nullable(v.request, request) || v.request && v.request.origin.serviceInstance !== v.serviceInstance) return null;
    return freezeInitializationData(v as unknown as InitializationAgentStatus);
  } catch { return null; }
}
type Invoke = <T>(command: string, input?: Record<string, unknown> | Uint8Array) => Promise<T>;
type Listen = (event: typeof INITIALIZATION_EVENT, callback: (value: unknown) => void) => Promise<() => void>;
export function createInitializationAgentApi(mode: string, invoke: Invoke, listen?: Listen): InitializationAgentApi | null {
  if (mode !== 'native' || !listen) return null;
  const failure = () => ({code: 'agent_initialization_unconfirmed', message: 'Inspect or stop the original initialization request; never repeat its Apply.', retryable: false});
  const query = (q: unknown): InitializationOrigin => { const v = copyBoundedComparisonData(q, 512, 16); if (!origin(v)) throw failure(); return v; };
  const controls = async (command: string, input: unknown) => {
    try {
      const body = new TextEncoder().encode(JSON.stringify(input)); if (body.length > 4096) throw failure();
      const s = parseInitializationAgentStatus(await invoke(command, body)); if (!s) throw failure(); return s;
    } catch { throw failure(); }
  };
  const continuation = async (step: 'open' | 'prepare' | 'apply', q: InitializationOrigin, input: unknown): Promise<ProjectInitializationStatus> => {
    try {
      const command = ({open:'project_initialization_open',prepare:'project_initialization_prepare',apply:'project_initialization_apply'} as const)[step];
      if (!initializationRequestFits(command,input) || (input as {intent?: unknown}).intent !== 'initialize') throw failure();
      const bytes = new TextEncoder().encode(JSON.stringify({agentInitialization:true,origin:query(q),input}));
      if (bytes.length > 1024 * 1024) throw failure();
      const s = parseProjectInitializationStatus(await invoke(command,bytes)); if (!s) throw failure(); return s;
    } catch { throw failure(); }
  };
  return Object.freeze({
    status: (q?: InitializationOrigin) => controls('agent_initialization_status',{origin:q === undefined ? null : query(q)}),
    allow: (input: InitializationAgentAllow) => {
      try {
        const a = copyBoundedComparisonData(input,4096,80);
        if (!keys(a,['origin','original','planToken','expectedNativeStatusRevision','expectedRequestRevision','consentVersion']) || !origin(a.origin) || !original(a.original) || !id(a.planToken) ||
          !uint(a.expectedNativeStatusRevision) || !uint(a.expectedRequestRevision,0xfffffffe,1) || a.consentVersion !== INITIALIZATION_CONSENT) throw failure();
        return controls('allow_agent_initialization',a);
      } catch { return Promise.reject(failure()); }
    },
    revoke: (q: InitializationOrigin) => controls('revoke_agent_initialization',query(q)),
    open: (q: InitializationOrigin, input: Extract<OpenProjectInitializationRequest,{intent:'initialize'}>) => continuation('open',q,input),
    prepare: (q: InitializationOrigin, sessionId: string, revision: string) => continuation('prepare',q,{sessionId,revision,intent:'initialize'}),
    apply: (q: InitializationOrigin, sessionId: string, planToken: string) => continuation('apply',q,{sessionId,planToken,intent:'initialize'}),
    subscribe: (fn: (v: unknown) => void) => listen(INITIALIZATION_EVENT,fn),
  });
}
