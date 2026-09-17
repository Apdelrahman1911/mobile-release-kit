import type { CredentialGuide } from './types.ts';

// A presentation contract, not a second credential-policy or requirement table.
// A future/malformed guide becomes unavailable; it never enables collection.
const KIND_IDS = ['android-keystore', 'android-firebase', 'apple-p12', 'apple-profile', 'asc-p8', 'ios-firebase', 'google-wif', 'project-read-token'];
const CONTROL_IDS = ['project', 'platform', 'stage', 'purpose', 'mode', 'label', 'choose', 'prepare', 'review', 'save', 'assign', 'replace', 'delete', 'cancel', 'discard', 'lock'];
const STATE_IDS = ['unknown', 'missing', 'invalid', 'configured', 'format-valid', 'native-not-run', 'service-not-run', 'stored', 'locked', 'unlocked', 'assigned', 'stale', 'cleanup-unknown', 'unavailable'];
const HELP_KEYS = ['label', 'requiredness', 'requiredWhen', 'what', 'why', 'where', 'format', 'failure'];

type RecordValue = Record<string, unknown>;
function record(value: unknown): value is RecordValue {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function keys(value: unknown, expected: string[]): value is RecordValue {
  return record(value) && Object.keys(value).length === expected.length && expected.every((key) => Object.hasOwn(value, key));
}
function text(value: unknown, limit = 4096): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= limit && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value);
}
function names(value: unknown, limit: number): value is string[] {
  return Array.isArray(value) && value.length <= limit && value.every((item) => text(item, 256)) && new Set(value).size === value.length;
}
function help(value: RecordValue): boolean {
  return ['required', 'optional', 'conditional'].includes(value.requiredness as string)
    && HELP_KEYS.filter((key) => key !== 'requiredness').every((key) => text(value[key]));
}
function roster(value: unknown, ids: string[]): value is RecordValue[] {
  return Array.isArray(value) && value.length === ids.length
    && value.every((row) => record(row) && ids.includes(row.id as string))
    && new Set(value.map((row) => row.id)).size === ids.length;
}
function field(value: unknown): boolean {
  if (!keys(value, [...HELP_KEYS, 'id', 'requirement', 'alternatives', 'input', 'maxBytes', 'suffixes'])
    || !help(value) || value.requiredness !== 'conditional' || !text(value.id, 80)
    || !text(value.requirement, 128) || !names(value.alternatives, 8) || !names(value.suffixes, 8)
    || !['file', 'secret', 'text'].includes(value.input as string)) return false;
  // Bounds are supplied by the core; no per-kind size or format rules live here.
  return value.input === 'file'
    ? Number.isSafeInteger(value.maxBytes) && (value.maxBytes as number) > 0
    : value.maxBytes === null && value.suffixes.length === 0;
}

export function parseCredentialGuide(value: unknown): CredentialGuide | null {
  try {
    if (!keys(value, ['schemaVersion', 'policyVersion', 'availability', 'kinds', 'controls', 'states'])
      || value.schemaVersion !== 1 || value.policyVersion !== 'credential-policy-v1' || value.availability !== 'guide-only'
      || !roster(value.kinds, KIND_IDS) || !roster(value.controls, CONTROL_IDS) || !roster(value.states, STATE_IDS)) return null;
    for (const kind of value.kinds) {
      if (!keys(kind, ['id', 'label', 'platform', 'defaultLabel', 'fields', 'plannedChecks', 'notVerified'])
        || !text(kind.label, 256) || !text(kind.defaultLabel, 256) || !['android', 'ios', 'project'].includes(kind.platform as string)
        || !Array.isArray(kind.fields) || kind.fields.length < 1 || kind.fields.length > 8 || !kind.fields.every(field)
        || new Set(kind.fields.map((item) => item.id)).size !== kind.fields.length
        || !Array.isArray(kind.plannedChecks) || kind.plannedChecks.length > 12 || !kind.plannedChecks.every((item) => text(item))
        || !Array.isArray(kind.notVerified) || kind.notVerified.length < 1 || kind.notVerified.length > 12 || !kind.notVerified.every((item) => text(item))) return null;
    }
    if (!value.controls.every((row) => keys(row, ['id', ...HELP_KEYS]) && help(row))
      || !value.states.every((row) => keys(row, ['id', 'label', 'meaning']) && text(row.label, 256) && text(row.meaning))) return null;
    // Retain no reference that an invocation provider can mutate after validation.
    return structuredClone(value) as unknown as CredentialGuide;
  } catch {
    return null;
  }
}

export function parseCatalogCredentialGuide(value: unknown): CredentialGuide | null {
  return record(value) ? parseCredentialGuide(value.credentialGuide) : null;
}
