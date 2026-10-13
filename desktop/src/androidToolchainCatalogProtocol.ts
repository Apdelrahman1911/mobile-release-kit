import type { ApiError } from './types.ts';
import type { AndroidMacToolchainSelection } from './androidBuildTypes.ts';
import type { AndroidCatalogComparison, AndroidCatalogIdentity, AndroidToolchainCatalogStatus, AndroidToolchainEntry, AndroidToolchainVersions } from './androidToolchainCatalogTypes.ts';
export const ANDROID_CATALOG_EVENT = 'android-toolchain-catalog-state-changed' as const;
export type AndroidCatalogCommand = 'android_toolchain_catalog_status' | 'refresh_android_toolchain_catalog' |
  'recover_android_toolchain' | 'select_android_toolchain' | 'cancel_android_toolchain_catalog';
const max = 0xffffffff;
const counter = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v) && v >= 0 && v < max;
const hex = (v: unknown, length: number): v is string => typeof v === 'string' && v.length === length && /^[0-9a-f]+$/.test(v);
function fields(value: unknown, names: string[]): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return null;
  const keys = Reflect.ownKeys(value);
  if (keys.length !== names.length || keys.some((key) => typeof key !== 'string' || !names.includes(key))) return null;
  const copy: Record<string, unknown> = {};
  for (const name of names) {
    const item = Object.getOwnPropertyDescriptor(value, name);
    if (!item?.enumerable || !Object.hasOwn(item, 'value')) return null;
    copy[name] = item.value;
  }
  return copy;
}
function array(value: unknown, limit: number): unknown[] | null {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > limit ||
      Reflect.ownKeys(value).length !== value.length + 1) return null;
  const copy: unknown[] = [];
  for (let i = 0; i < value.length; i++) {
    const item = Object.getOwnPropertyDescriptor(value, String(i));
    if (!item?.enumerable || !Object.hasOwn(item, 'value')) return null;
    copy.push(item.value);
  }
  return copy;
}
function selection(value: unknown): AndroidMacToolchainSelection | null {
  const v = fields(value, ['instance', 'ownerUid', 'catalogGeneration', 'recordSha256', 'inventorySha256', 'osProviderSha256']);
  if (!v || !hex(v.instance, 32) || !counter(v.ownerUid) || v.ownerUid === 0 ||
      !counter(v.catalogGeneration) || v.catalogGeneration === 0 ||
      ![v.recordSha256, v.inventorySha256, v.osProviderSha256].every((h) => hex(h, 64))) return null;
  return v as unknown as AndroidMacToolchainSelection;
}
function comparison(value: unknown): AndroidCatalogComparison | null {
  const v = fields(value, ['catalogGeneration', 'instance', 'recordSha256', 'inventorySha256', 'osProviderSha256']);
  if (!v || !counter(v.catalogGeneration) || v.catalogGeneration === 0 || !hex(v.instance, 32) ||
      ![v.recordSha256, v.inventorySha256, v.osProviderSha256].every((h) => hex(h, 64))) return null;
  return v as unknown as AndroidCatalogComparison;
}
function entry(value: unknown, generation: number): AndroidToolchainEntry | null {
  const v = fields(value, ['instance', 'occupants', 'status', 'versions', 'recovery', 'selection']);
  if (!v || !hex(v.instance, 32) || !counter(v.occupants) || v.occupants < 1 || v.occupants > 7) return null;
  if (v.status === 'busy' || v.status === 'interrupted' || v.status === 'refused') {
    return v.versions === null && v.recovery === null && v.selection === null ?
      { instance: v.instance, occupants: v.occupants, status: v.status, versions: null, recovery: null, selection: null } : null;
  }
  const versions = fields(v.versions, ['jdkVendor', 'jdkVersion', 'gradleVersion', 'agpVersion', 'sdkPlatform', 'sdkBuildToolsVersion']);
  if (!versions || !Object.values(versions).every((v) => typeof v === 'string' && v.length > 0 && v.length <= 128 && /^[A-Za-z0-9 ._+()-]+$/.test(v))) return null;
  if (v.status === 'recovery-required') {
    const recovery = comparison(v.recovery);
    return recovery && recovery.catalogGeneration === generation && recovery.instance === v.instance && v.selection === null ?
      { instance: v.instance, occupants: v.occupants, status: v.status, versions: versions as unknown as AndroidToolchainVersions, recovery, selection: null } : null;
  }
  if (v.status === 'verified-this-session') {
    const selected = selection(v.selection);
    return selected && selected.catalogGeneration === generation && selected.instance === v.instance && v.recovery === null ?
      { instance: v.instance, occupants: v.occupants, status: v.status, versions: versions as unknown as AndroidToolchainVersions, recovery: null, selection: selected } : null;
  }
  return null;
}
export function androidCatalogComparison(value: AndroidCatalogComparison): AndroidCatalogComparison {
  // Deliberately excludes ownerUid from every Recover/Choose request.
  return { catalogGeneration: value.catalogGeneration, instance: value.instance, recordSha256: value.recordSha256,
    inventorySha256: value.inventorySha256, osProviderSha256: value.osProviderSha256 };
}
export function sameAndroidCatalogSelection(a: AndroidMacToolchainSelection | null, b: AndroidMacToolchainSelection | null): boolean {
  return a === null || b === null ? a === b : a.instance === b.instance && a.ownerUid === b.ownerUid &&
    a.catalogGeneration === b.catalogGeneration && a.recordSha256 === b.recordSha256 &&
    a.inventorySha256 === b.inventorySha256 && a.osProviderSha256 === b.osProviderSha256;
}
export function sameAndroidCatalogIdentity(a: AndroidCatalogIdentity | null, b: AndroidCatalogIdentity | null): boolean {
  return a === null || b === null ? a === b : a.catalogGeneration === b.catalogGeneration && a.operationId === b.operationId;
}
export const androidCatalogActive = (status: AndroidToolchainCatalogStatus | null): boolean =>
  status !== null && ['reading', 'stopping', 'unknown'].includes(status.phase);
export function parseAndroidToolchainCatalogStatus(value: unknown): AndroidToolchainCatalogStatus | null {
  try {
    const v = fields(value, ['schemaVersion', 'statusRevision', 'catalogGeneration', 'operationId', 'availability', 'phase', 'reason', 'entries', 'selected']);
    if (!v || v.schemaVersion !== 1 || !counter(v.statusRevision) || !counter(v.catalogGeneration) ||
        !(v.operationId === null || hex(v.operationId, 32)) ||
        !['available', 'busy', 'shutdown', 'cleanup-unknown', 'document-lost', 'unsupported-platform', 'runtime-unqualified', 'toolchain-unqualified'].includes(v.availability as string) ||
        !['idle', 'reading', 'stopping', 'ready', 'refused', 'cancelled', 'unknown'].includes(v.phase as string) ||
        !['none', 'not-inspected', 'cancelled', 'timed-out', 'document-lost', 'shutdown', 'catalog-changed', 'catalog-unavailable', 'cleanup-unknown'].includes(v.reason as string)) return null;
    const rows = array(v.entries, 32); if (!rows) return null;
    const entries = rows.map((row) => entry(row, v.catalogGeneration as number));
    if (entries.some((row) => row === null) || new Set(entries.map((row) => row!.instance)).size !== entries.length) return null;
    if (entries.filter((row) => row?.status === 'verified-this-session').length > 1) return null;
    const selected = v.selected === null ? null : selection(v.selected);
    if (v.selected !== null && !selected || selected && !entries.some((e) => e?.status === 'verified-this-session' && sameAndroidCatalogSelection(e.selection, selected))) return null;
    if (v.phase === 'idle' ? v.operationId !== null || v.catalogGeneration !== 0 || v.reason !== 'not-inspected' :
        v.operationId === null || v.catalogGeneration === 0) return null;
    if (v.phase !== 'ready' && (entries.length > 0 || selected !== null) ||
        v.phase === 'ready' && v.reason !== 'none' ||
        v.phase === 'unknown' && (v.reason !== 'cleanup-unknown' || v.availability !== 'cleanup-unknown')) return null;
    const result = { ...v, entries, selected } as unknown as AndroidToolchainCatalogStatus;
    return new TextEncoder().encode(JSON.stringify(result)).byteLength <= 64 * 1024 ? result : null;
  } catch { return null; }
}
export function encodeAndroidCatalogRequest(command: AndroidCatalogCommand, value: unknown): Uint8Array | null {
  try {
    let v: Record<string, unknown> | null;
    if (command === 'android_toolchain_catalog_status' || command === 'refresh_android_toolchain_catalog') {
      v = fields(value, ['schemaVersion']);
    } else if (command === 'recover_android_toolchain' || command === 'select_android_toolchain') {
      v = fields(value, ['schemaVersion', 'catalogGeneration', 'instance', 'recordSha256', 'inventorySha256', 'osProviderSha256']);
      if (!v || !counter(v.catalogGeneration) || v.catalogGeneration === 0 || !hex(v.instance, 32) ||
          ![v.recordSha256, v.inventorySha256, v.osProviderSha256].every((h) => hex(h, 64))) return null;
    } else if (command === 'cancel_android_toolchain_catalog') {
      v = fields(value, ['schemaVersion', 'catalogGeneration', 'operationId']);
      if (!v || !counter(v.catalogGeneration) || v.catalogGeneration === 0 || !hex(v.operationId, 32)) return null;
    } else return null;
    if (!v || v.schemaVersion !== 1) return null;
    const raw = new TextEncoder().encode(JSON.stringify(v));
    return raw.byteLength <= 1024 ? raw : null;
  } catch { return null; }
}
export function androidCatalogError(value: unknown): ApiError {
  let code: unknown = null;
  try { if (value && typeof value === 'object') code = Object.getOwnPropertyDescriptor(value, 'code')?.value; } catch { /* Never show raw rejection data. */ }
  if (code === 'android_catalog_invalid') return { code, message: 'The selected catalog changed or the request was invalid. Check the original catalog before choosing again.', retryable: false };
  if (code === 'android_catalog_unavailable' || code === 'android_build_busy') return { code: 'android_catalog_unavailable', message: 'The original document cannot read or change the protected tool catalog now. Check original Status; no new outcome is confirmed.', retryable: false };
  return { code: 'android_catalog_unconfirmed', message: 'The protected-tool catalog response was not confirmed. Keep original Status and Cancel; do not repeat the request.', retryable: false };
}
