import type { ApiError } from './types.ts';
import type { AndroidMacToolchainSelection } from './androidBuildTypes.ts';
import type { AndroidCatalogIdentity, AndroidToolchainCatalogStatus, AndroidToolchainEntry } from './androidToolchainCatalogTypes.ts';
export const ANDROID_CATALOG_EVENT = 'android-toolchain-catalog-state-changed' as const;
export type AndroidCatalogCommand = 'android_toolchain_catalog_status' | 'refresh_android_toolchain_catalog' |
  'select_android_toolchain' | 'cancel_android_toolchain_catalog';
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
function entry(value: unknown, generation: number): AndroidToolchainEntry | null {
  const v = fields(value, ['selection', 'versions']);
  const selected = v && selection(v.selection);
  const versions = v && fields(v.versions, ['jdkVendor', 'jdkVersion', 'gradleVersion', 'agpVersion', 'sdkPlatform', 'sdkBuildToolsVersion']);
  if (!selected || selected.catalogGeneration !== generation || !versions ||
      !Object.values(versions).every((v) => typeof v === 'string' && v.length > 0 && v.length <= 128 && /^[A-Za-z0-9 ._+()-]+$/.test(v))) return null;
  return { selection: selected, versions: versions as unknown as AndroidToolchainEntry['versions'] };
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
    const rows = array(v.entries, 16); if (!rows) return null;
    const entries = rows.map((row) => entry(row, v.catalogGeneration as number));
    if (entries.some((row) => row === null) || new Set(entries.map((row) => row!.selection.instance)).size !== entries.length) return null;
    const selected = v.selected === null ? null : selection(v.selected);
    if (v.selected !== null && !selected || selected && !entries.some((e) => sameAndroidCatalogSelection(e!.selection, selected))) return null;
    if (v.phase === 'idle' ? v.operationId !== null || v.catalogGeneration !== 0 || v.reason !== 'not-inspected' :
        v.operationId === null || v.catalogGeneration === 0) return null;
    if (v.phase !== 'ready' && (entries.length > 0 || selected !== null) ||
        v.phase === 'ready' && v.reason !== 'none' ||
        v.phase === 'unknown' && (v.reason !== 'cleanup-unknown' || v.availability !== 'cleanup-unknown')) return null;
    const result = { ...v, entries, selected } as unknown as AndroidToolchainCatalogStatus;
    return new TextEncoder().encode(JSON.stringify(result)).byteLength <= 32 * 1024 ? result : null;
  } catch { return null; }
}
export function encodeAndroidCatalogRequest(command: AndroidCatalogCommand, value: unknown): Uint8Array | null {
  try {
    let v: Record<string, unknown> | null;
    if (command === 'android_toolchain_catalog_status' || command === 'refresh_android_toolchain_catalog') {
      v = fields(value, ['schemaVersion']);
    } else if (command === 'select_android_toolchain') {
      v = fields(value, ['schemaVersion', 'catalogGeneration', 'instance', 'recordSha256']);
      if (!v || !counter(v.catalogGeneration) || v.catalogGeneration === 0 || !hex(v.instance, 32) || !hex(v.recordSha256, 64)) return null;
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
