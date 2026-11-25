// A bounded local failure journal. Raw messages, stacks, paths, request bodies
// and project/credential values are deliberately outside this schema.
export const WORKSPACE_DIAGNOSTICS_KEY = 'mrk.workspace.failures.v1';
export const WORKSPACE_DIAGNOSTICS_LIMIT = 16;
export const WORKSPACE_DIAGNOSTICS_BYTES = 12_288;
const TYPES = ['Error', 'TypeError', 'RangeError', 'ReferenceError', 'SyntaxError', 'URIError', 'EvalError', 'UnknownError'] as const;
const CATEGORIES = ['unknown', 'nullish-property', 'hook-order', 'render-loop', 'invalid-child', 'react-error'] as const;
const SOURCES = ['boundary', 'window-error', 'unhandled-rejection'] as const;
const PHASES = ['startup', 'connecting', 'runtime-available', 'runtime-unavailable', 'focus-return'] as const;
type Category = typeof CATEGORIES[number];
type Source = typeof SOURCES[number];
type Phase = typeof PHASES[number];
export interface WorkspaceFailure {
  sequence: number; atMs: number; source: Source; phase: Phase;
  errorType: typeof TYPES[number]; category: Category; reactCode: number | null; components: string[];
}
export interface DiagnosticStorage { getItem(key: string): string | null; setItem(key: string, value: string): void }
export interface RecordedFailure { failure: WorkspaceFailure; persisted: boolean }
const componentName = /^[A-Za-z_$][A-Za-z0-9_$]{0,63}$/;
const ownString = (value: unknown, key: string): string | null => {
  try {
    if (value === null || typeof value !== 'object') return null;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor && 'value' in descriptor && typeof descriptor.value === 'string' ? descriptor.value : null;
  } catch { return null; }
};
function errorType(value: unknown): WorkspaceFailure['errorType'] {
  const own = ownString(value, 'name');
  if (TYPES.some(type => type === own)) return own as WorkspaceFailure['errorType'];
  try {
    const prototype = Object.getPrototypeOf(value);
    for (const type of [Error, TypeError, RangeError, ReferenceError, SyntaxError, URIError, EvalError]) {
      if (prototype === type.prototype) return type.name as WorkspaceFailure['errorType'];
    }
  } catch { /* Untrusted rejection values do not get stringified. */ }
  return 'UnknownError';
}
function classify(value: unknown): { category: Category; reactCode: number | null } {
  const message = ownString(value, 'message')?.slice(0, 2_048) ?? '';
  if (/Cannot (?:read|set) properties of (?:undefined|null)/.test(message)) return { category: 'nullish-property', reactCode: null };
  if (/Rendered (?:more|fewer) hooks|change in the order of Hooks/.test(message)) return { category: 'hook-order', reactCode: null };
  if (/Maximum update depth exceeded|Too many re-renders/.test(message)) return { category: 'render-loop', reactCode: null };
  if (/Objects are not valid as a React child/.test(message)) return { category: 'invalid-child', reactCode: null };
  const code = /Minified React error #([1-9][0-9]{0,4});/.exec(message)?.[1];
  return code ? { category: 'react-error', reactCode: Number(code) } : { category: 'unknown', reactCode: null };
}
function components(stack: unknown): string[] {
  if (typeof stack !== 'string') return [];
  return stack.slice(0, 4_096).split('\n').flatMap(line => {
    const name = /^\s*(?:at|in)\s+([A-Za-z_$][A-Za-z0-9_$]{0,63})(?:\s|$|\()/.exec(line)?.[1];
    return name ? [name] : [];
  }).slice(0, 4);
}
function validRecord(value: unknown): value is WorkspaceFailure {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const v = value as WorkspaceFailure;
  return Object.keys(v).sort().join(',') === 'atMs,category,components,errorType,phase,reactCode,sequence,source'
    && Number.isSafeInteger(v.sequence) && v.sequence > 0
    && Number.isSafeInteger(v.atMs) && v.atMs >= 0
    && SOURCES.includes(v.source) && PHASES.includes(v.phase) && TYPES.includes(v.errorType) && CATEGORIES.includes(v.category)
    && (v.reactCode === null || Number.isSafeInteger(v.reactCode) && v.reactCode > 0 && v.reactCode <= 99_999)
    && (v.category === 'react-error') === (v.reactCode !== null)
    && Array.isArray(v.components) && v.components.length <= 4 && v.components.every(x => typeof x === 'string' && componentName.test(x));
}
export class WorkspaceDiagnostics {
  private records: WorkspaceFailure[] = [];
  private phase: Phase = 'startup';
  private readonly storage: () => DiagnosticStorage | null;
  private readonly now: () => number;
  constructor(storage: () => DiagnosticStorage | null, now = Date.now) {
    this.storage = storage; this.now = now;
    try {
      const text = storage()?.getItem(WORKSPACE_DIAGNOSTICS_KEY);
      if (!text || text.length > WORKSPACE_DIAGNOSTICS_BYTES) return;
      const data: unknown = JSON.parse(text);
      if (data === null || typeof data !== 'object' || Array.isArray(data)) return;
      const envelope = data as { schemaVersion?: unknown; records?: unknown };
      if (Object.keys(envelope).sort().join(',') !== 'records,schemaVersion' || envelope.schemaVersion !== 1
        || !Array.isArray(envelope.records) || envelope.records.length > WORKSPACE_DIAGNOSTICS_LIMIT || !envelope.records.every(validRecord)) return;
      const records = envelope.records as WorkspaceFailure[];
      if (records.some((r, i) => i > 0 && r.sequence <= records[i - 1]!.sequence)) return;
      this.records = records;
      this.persisted = true;
    } catch { /* Corrupt/unavailable WebView storage never blocks the workspace. */ }
  }
  setPhase(phase: Phase): void { if (PHASES.includes(phase)) this.phase = phase; }
  snapshot(): readonly WorkspaceFailure[] { return this.records.map(r => ({ ...r, components: [...r.components] })); }
  capture(value: unknown, source: Source, componentStack: unknown = ''): RecordedFailure {
    const previous = this.records.at(-1);
    let atMs = 0;
    try { const now = this.now(); if (Number.isSafeInteger(now) && now >= 0) atMs = now; } catch { /* Bounded fallback. */ }
    const failure: WorkspaceFailure = { sequence: (previous?.sequence ?? 0) < Number.MAX_SAFE_INTEGER ? (previous?.sequence ?? 0) + 1 : 1,
      atMs, source: SOURCES.includes(source) ? source : 'boundary', phase: this.phase, errorType: errorType(value), ...classify(value), components: components(componentStack) };
    // Repeated render/global notifications for the same failure cannot fill
    // persistent storage or turn a failure storm into synchronous IO per event.
    for (let i = this.records.length - 1; i >= 0; i -= 1) {
      const seen = this.records[i]!;
      if (atMs >= seen.atMs && atMs - seen.atMs < 1_000
        && seen.source === failure.source && seen.phase === failure.phase && seen.errorType === failure.errorType
        && seen.category === failure.category && seen.reactCode === failure.reactCode
        && seen.components.join(',') === failure.components.join(',')) {
        return { failure: { ...seen, components: [...seen.components] }, persisted: this.persisted };
      }
    }
    this.records = previous?.sequence === Number.MAX_SAFE_INTEGER ? [failure]
      : [...this.records, failure].slice(-WORKSPACE_DIAGNOSTICS_LIMIT);
    this.persisted = false;
    try {
      const text = JSON.stringify({ schemaVersion: 1, records: this.records });
      if (text.length <= WORKSPACE_DIAGNOSTICS_BYTES) {
        const storage = this.storage();
        if (storage) { storage.setItem(WORKSPACE_DIAGNOSTICS_KEY, text); this.persisted = true; }
      }
    } catch { /* Reporting an exception must not throw a second exception. */ }
    return { failure: { ...failure, components: [...failure.components] }, persisted: this.persisted };
  }
  private persisted = false;
}
let journal: WorkspaceDiagnostics | null = null;
export function workspaceDiagnostics(): WorkspaceDiagnostics {
  return journal ??= new WorkspaceDiagnostics(() => { try { return window.localStorage; } catch { return null; } });
}
export function installWorkspaceDiagnostics(target: Pick<Window, 'addEventListener' | 'removeEventListener'>,
  diagnostics = workspaceDiagnostics()): () => void {
  const error = (event: Event) => { diagnostics.capture((event as ErrorEvent).error, 'window-error'); };
  const rejection = (event: Event) => { diagnostics.capture((event as PromiseRejectionEvent).reason, 'unhandled-rejection'); };
  const focus = () => diagnostics.setPhase('focus-return');
  target.addEventListener('error', error); target.addEventListener('unhandledrejection', rejection); target.addEventListener('focus', focus);
  return () => { target.removeEventListener('error', error); target.removeEventListener('unhandledrejection', rejection); target.removeEventListener('focus', focus); };
}
export function workspaceFailureDescription(failure: WorkspaceFailure): string {
  const descriptions: Record<Category, string> = { unknown: 'An unexpected workspace error occurred.', 'nullish-property': 'A required workspace value was unavailable.',
    'hook-order': 'A workspace component changed its hook order.', 'render-loop': 'A workspace component repeatedly updated itself.',
    'invalid-child': 'A workspace component received an unsupported display value.', 'react-error': 'React reported a workspace error.' };
  return descriptions[failure.category];
}
