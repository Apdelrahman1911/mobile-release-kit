import type { Catalog, FieldHelp, JsonObject, JsonValue, MetadataRules } from './types.ts';

export function isObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

const unsafeKeys = new Set(['__proto__', 'prototype', 'constructor']);

export function pathSegments(path: string): string[] {
  const segments = path.split('.');
  if (segments.some((segment) => !segment || unsafeKeys.has(segment))) {
    throw new Error('Unsupported field path.');
  }
  return segments;
}

export function getValue(draft: JsonObject | null, path: string): JsonValue | undefined {
  let current: JsonValue | undefined = draft ?? undefined;
  for (const segment of pathSegments(path)) {
    if (!isObject(current) || !Object.hasOwn(current, segment)) return undefined;
    current = current[segment];
  }
  return current;
}

// A malformed parent is preserved, not silently replaced with an object merely
// because one of its schema-driven child controls was edited or unset.
export function blockingAncestor(draft: JsonObject, path: string): string | null {
  const segments = pathSegments(path);
  let current = draft;
  for (let offset = 0; offset < segments.length - 1; offset += 1) {
    const key = segments[offset];
    if (key === undefined || !Object.hasOwn(current, key)) return null;
    const child = current[key];
    if (!isObject(child)) return segments.slice(0, offset + 1).join('.');
    current = child;
  }
  return null;
}

export function setValue(draft: JsonObject, path: string, value: JsonValue | undefined): JsonObject {
  const segments = pathSegments(path);
  if (blockingAncestor(draft, path) !== null || sameJson(getValue(draft, path), value)) return draft;
  const visit = (source: JsonObject, offset: number): JsonObject => {
    const key = segments[offset];
    if (!key) return source;
    const next = { ...source };
    if (offset === segments.length - 1) {
      if (value === undefined) delete next[key];
      else next[key] = value;
    } else {
      const child = Object.hasOwn(source, key) ? source[key] : undefined;
      const result = visit(isObject(child) ? child : {}, offset + 1);
      if (value === undefined && Object.keys(result).length === 0) delete next[key];
      else next[key] = result;
    }
    return next;
  };
  return visit(draft, 0);
}

export function fieldsFor(catalog: Catalog, prefixes: readonly string[], search = ''): FieldHelp[] {
  const query = search.trim().toLocaleLowerCase();
  return catalog.fields.filter((field) =>
    prefixes.some((prefix) => field.path === prefix || field.path.startsWith(`${prefix}.`)) &&
    (!query || `${field.label} ${field.path} ${field.what}`.toLocaleLowerCase().includes(query)),
  );
}

export function localeRequirements(metadata: MetadataRules | null | undefined): { platform: string; files: string[] }[] {
  if (!metadata) return [];
  return Object.entries(metadata.requiredLocaleText).map(([platform, files]) => ({ platform, files }));
}

// This builds empty controls, not application policy. It never inserts identifiers,
// branches, commands, or credentials. Only an explicit user action calls it.
export function emptyDraft(schema: JsonObject): JsonObject {
  const expand = (candidate: JsonValue | undefined, depth: number): JsonValue | undefined => {
    if (!isObject(candidate) || depth > 16) return undefined;
    let node = candidate;
    if (typeof node.$ref === 'string') {
      if (!node.$ref.startsWith('#/$defs/')) return undefined;
      const name = node.$ref.slice('#/$defs/'.length);
      const definitions = schema.$defs;
      if (!isObject(definitions) || !Object.hasOwn(definitions, name)) return undefined;
      const resolved = definitions[name];
      if (!isObject(resolved)) return undefined;
      node = resolved;
    }
    if (Object.hasOwn(node, 'const')) return node.const;
    if (node.type === 'object') {
      const result: JsonObject = {};
      const properties = node.properties;
      if (!isObject(properties) || !Array.isArray(node.required)) return result;
      for (const key of node.required) {
        if (typeof key !== 'string' || unsafeKeys.has(key)) continue;
        const value = expand(properties[key], depth + 1);
        if (value !== undefined) result[key] = value;
      }
      return result;
    }
    if (node.type === 'array') return [];
    if (node.type === 'boolean') return false;
    if (node.type === 'string') return '';
    return undefined;
  };
  const result = expand(schema, 0);
  return isObject(result) ? result : {};
}

export function textValue(value: JsonValue | undefined, fallback = 'Not configured'): string {
  return typeof value === 'string' && value.length > 0 ? value : fallback;
}

// Renderer draft equality only, not a disk revision or byte-preservation claim.
// JSON number lexical forms (1 vs 1.0) cannot be recovered after JS parsing.
export function sameJson(first: JsonValue | undefined, second: JsonValue | undefined): boolean {
  if (first === second) return true;
  if (Array.isArray(first) || Array.isArray(second)) {
    return Array.isArray(first) && Array.isArray(second) && first.length === second.length &&
      first.every((value, index) => sameJson(value, second[index]));
  }
  if (!isObject(first) || !isObject(second)) return false;
  const keys = Object.keys(first);
  return keys.length === Object.keys(second).length &&
    keys.every((key) => Object.hasOwn(second, key) && sameJson(first[key], second[key]));
}
