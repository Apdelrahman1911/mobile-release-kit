// Public, read-only access DATA only. These IDs are not runtime project IDs,
// native session authority, paths, credentials, or permission to run a task.
export interface CliReadAccessStatus {
  readonly enabled: boolean;
  readonly remainingMs: number;
  readonly projectIds: readonly string[];
}
export const CLI_READ_ACCESS_MAX_MS = 60 * 60 * 1000;
export const CLI_READ_ACCESS_SCOPE = 'Read only the permitted projects’ published, redacted saved snapshots and recorded operation history. This does not expose your in-memory drafts, credentials or arbitrary files, and cannot edit files, run commands, build, sign or publish a release.';

export function parseCliReadAccessStatus(value: unknown): CliReadAccessStatus | null {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return null;
    const expected = ['enabled', 'remainingMs', 'projectIds'];
    const names = Reflect.ownKeys(value);
    if (names.length !== expected.length || names.some((key) => typeof key !== 'string' || !expected.includes(key))) return null;
    const data: Record<string, unknown> = {};
    for (const key of expected) {
      const field = Object.getOwnPropertyDescriptor(value, key);
      if (!field?.enumerable || !Object.hasOwn(field, 'value')) return null;
      data[key] = field.value;
    }
    if (typeof data.enabled !== 'boolean' || typeof data.remainingMs !== 'number' || !Number.isSafeInteger(data.remainingMs) ||
        data.remainingMs < 0 || data.remainingMs > CLI_READ_ACCESS_MAX_MS) return null;
    const input = data.projectIds;
    if (!Array.isArray(input) || Object.getPrototypeOf(input) !== Array.prototype) return null;
    const length = Object.getOwnPropertyDescriptor(input, 'length')?.value;
    if (!Number.isInteger(length) || length < 0 || length > 64 || Reflect.ownKeys(input).length !== length + 1) return null;
    const ids: string[] = [];
    for (let i = 0; i < length; i += 1) {
      const field = Object.getOwnPropertyDescriptor(input, String(i));
      if (!field?.enumerable || !Object.hasOwn(field, 'value') || typeof field.value !== 'string' || field.value.length !== 32 ||
          !/^[0-9a-f]{32}$/.test(field.value) || field.value === '0'.repeat(32) || ids.includes(field.value)) return null;
      ids.push(field.value);
    }
    if (data.enabled ? ids.length === 0 : data.remainingMs !== 0 || ids.length !== 0) return null;
    // An enabled observation may legitimately reach 0ms between the native
    // live-grant check and its remaining-time read. Never turn it into Off.
    return Object.freeze({ enabled: data.enabled, remainingMs: data.remainingMs, projectIds: Object.freeze(ids) });
  } catch { return null; } // Never invoke getters/toJSON or display raw errors.
}

// Transport bounds only. Root must supply the genuinely registered selection;
// a matching string does not register a project or grant native authority.
export function cliReadAccessProjectIdFits(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 64 && !/[^A-Za-z0-9_-]/.test(value);
}

export interface CliReadAccessSummary { readonly title: string; readonly detail: string; readonly tone: 'neutral' | 'info' | 'warning' }
export function cliReadAccessSummary(status: CliReadAccessStatus | null, elapsedMs = 0): CliReadAccessSummary {
  if (!status) return { title: 'Access not checked', detail: 'Check access in the running app. Checking does not allow or renew access.', tone: 'neutral' };
  if (!status.enabled) return { title: 'Off at last check', detail: 'The app reported no CLI read permission at that check. Checking status does not grant permission.', tone: 'neutral' };
  if (!Number.isFinite(elapsedMs) || elapsedMs < 0 || status.remainingMs <= elapsedMs)
    return { title: 'Access needs another check', detail: 'The previously reported permission may have expired. Check access; it is never renewed automatically.', tone: 'warning' };
  const minutes = Math.ceil((status.remainingMs - elapsedMs) / 60_000), count = status.projectIds.length;
  return { title: `${count} ${count === 1 ? 'project was' : 'projects were'} allowed at last check`,
    detail: `Up to ${minutes} ${minutes === 1 ? 'minute' : 'minutes'} remaining, estimated from that check. This does not confirm that the currently selected project is permitted.`, tone: 'info' };
}
