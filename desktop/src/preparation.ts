import { isObject } from './catalog.ts';
import type { JsonObject, SuggestionHints, ValueSummary } from './types.ts';

export interface DraftBinding { revision: number; baselineGeneration: number }
export interface PreparationRequest extends DraftBinding { id: number }

export interface HintProjection {
  hints: SuggestionHints;
  omittedStrings: number;
}

// Documented core-owned projection of M1 static hints into config.suggest's
// closed input. Never select candidates, infer an absent platform, approve an
// identity, copy a branch/root, or truncate a value into a different hint.
export function suggestionHints(observed: JsonObject | null): HintProjection {
  const hints: SuggestionHints = {};
  let omittedStrings = 0;
  if (!observed) return { hints, omittedStrings };
  const copy = (value: unknown, key: Exclude<keyof SuggestionHints, 'platforms'>) => {
    if (value === undefined) return;
    // ASCII controls/DEL follow the core contract. Lone surrogates cannot be
    // admitted as UTF-8; TextEncoder alone would silently replace them.
    if (typeof value !== 'string' || value.length === 0 || /[\u0000-\u001f\u007f\ud800-\udfff]/u.test(value) || new TextEncoder().encode(value).byteLength > 512) {
      omittedStrings += 1;
      return;
    }
    hints[key] = value;
  };
  const platforms: ('android' | 'ios')[] = [];
  const android = Object.hasOwn(observed, 'android') ? observed.android : undefined;
  const ios = Object.hasOwn(observed, 'ios') ? observed.ios : undefined;
  if (isObject(android) && Object.keys(android).length > 0) {
    platforms.push('android');
    if ((!Object.hasOwn(android, 'ambiguous') || android.ambiguous !== true) && Object.hasOwn(android, 'applicationId')) copy(android.applicationId, 'androidApplicationId');
  }
  if (isObject(ios) && Object.keys(ios).length > 0) {
    platforms.push('ios');
    if (Object.hasOwn(ios, 'bundleId')) copy(ios.bundleId, 'iosBundleId');
  }
  if (platforms.length > 0) hints.platforms = platforms;
  for (const key of ['versionSource', 'versionNameKey', 'versionBuildKey'] as const) {
    if (Object.hasOwn(observed, key)) copy(observed[key], key);
  }
  return { hints, omittedStrings };
}

export function valueSummary(summary: ValueSummary): string {
  if (!summary.present) return 'Not set';
  if (summary.type === 'null') return 'null';
  if (summary.type === 'array') return summary.count === undefined ? 'Array' : `Array · ${summary.count} items`;
  if (summary.type === 'object') return summary.count === undefined ? 'Object' : `Object · ${summary.count} keys`;
  if (summary.type === 'string') return 'String · value omitted';
  if (summary.type === 'boolean') return 'Boolean · value omitted';
  if (summary.type === 'number') return 'Number · value omitted';
  return 'Present · type not supplied';
}

export function pathsOverlap(first: string, second: string): boolean {
  return first === second || first.startsWith(`${second}.`) || second.startsWith(`${first}.`);
}
