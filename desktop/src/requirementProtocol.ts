// Shared closed wire admission only; the core remains the requirements/policy authority.
const encoder = new TextEncoder();

export const ENVIRONMENTS = [
  { stage: 'candidate', name: 'mobile-candidate' },
  { stage: 'external-testing', name: 'mobile-external-testing' },
  { stage: 'production', name: 'mobile-production' },
] as const;
export function record(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export function keys(value: unknown, expected: readonly string[]): value is Record<string, unknown> {
  if (!record(value)) return false;
  const names = Reflect.ownKeys(value);
  return names.length === expected.length && names.every((key) => {
    if (typeof key !== 'string' || !expected.includes(key)) return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
  });
}

export function text(value: unknown, max: number, nonempty = true, plain = false): value is string {
  return typeof value === 'string' && (!nonempty || value.length > 0) && value.length <= max &&
    !/[\ud800-\udfff]/u.test(value) && (!plain || !/[\u0000-\u001f\u007f]/u.test(value)) && encoder.encode(value).byteLength <= max;
}

export function oneOf(value: unknown, expected: readonly string[]): value is string {
  return typeof value === 'string' && expected.includes(value);
}

// Count keys and values as the core does. Reject exotic prototypes, accessors,
// hidden/symbol keys, sparse arrays, cycles and lone surrogates before copying or
// encoding. The early byte floor prevents a large aggregate stringify allocation.
export function boundedJson(value: unknown, maxBytes: number, maxNodes: number, maxDepth: number): boolean {
  let nodes = 0;
  let minimumBytes = 0;
  const ancestors = new Set<object>();
  const visit = (item: unknown, depth: number): boolean => {
    if (++nodes > maxNodes || depth > maxDepth) return false;
    if (item === null || typeof item === 'boolean') { minimumBytes += 1; }
    else if (typeof item === 'number') {
      if (!Number.isFinite(item)) return false;
      minimumBytes += 1;
    } else if (typeof item === 'string') {
      if (!text(item, maxBytes, false)) return false;
      minimumBytes += encoder.encode(item).byteLength + 2;
    } else {
      if (typeof item !== 'object' || depth >= maxDepth || ancestors.has(item)) return false;
      ancestors.add(item);
      if (Array.isArray(item)) {
        if (Object.getPrototypeOf(item) !== Array.prototype || item.length > maxNodes - nodes ||
            Reflect.ownKeys(item).length !== item.length + 1) return false;
        minimumBytes += 2 + Math.max(0, item.length - 1);
        if (minimumBytes > maxBytes) return false;
        for (let index = 0; index < item.length; index += 1) {
          const descriptor = Object.getOwnPropertyDescriptor(item, String(index));
          if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, 'value') || !visit(descriptor.value, depth + 1)) return false;
        }
      } else {
        if (!record(item)) return false;
        const names = Reflect.ownKeys(item);
        if (names.length > maxNodes - nodes) return false;
        minimumBytes += 2 + Math.max(0, 2 * names.length - 1);
        if (minimumBytes > maxBytes) return false;
        for (const key of names) {
          if (typeof key !== 'string') return false;
          const descriptor = Object.getOwnPropertyDescriptor(item, key);
          if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, 'value') ||
              !visit(key, depth + 1) || !visit(descriptor.value, depth + 1)) return false;
        }
      }
      ancestors.delete(item);
    }
    return minimumBytes <= maxBytes;
  };
  try { return visit(value, 0) && encoder.encode(JSON.stringify(value)).byteLength <= maxBytes; }
  catch { return false; }
}

export function assurance(value: unknown): boolean {
  return keys(value, ['basis', 'projectCodeExecuted', 'toolsProbed', 'credentialsRead', 'gitObserved', 'storeContacted', 'writesPerformed', 'releaseReadiness']) &&
    value.basis === 'schema-policy' && value.projectCodeExecuted === false && value.toolsProbed === false &&
    value.credentialsRead === false && value.gitObserved === false && value.storeContacted === false &&
    value.writesPerformed === false && value.releaseReadiness === 'unknown';
}

export function requirementName(item: unknown): item is string {
  return text(item, 96, true, true) && /^MOBILE_RELEASE_[A-Z0-9_]+$/.test(item);
}

export function requirement(value: unknown): value is Record<string, unknown> {
  return keys(value, ['name', 'kind', 'stage', 'platform', 'environment', 'alternatives', 'reason', 'state']) &&
    requirementName(value.name) && oneOf(value.kind, ['secret', 'variable', 'file', 'manual']) &&
    oneOf(value.platform, ['android', 'ios', 'project']) &&
    ENVIRONMENTS.some((entry) => value.stage === entry.stage && value.environment === entry.name) &&
    Array.isArray(value.alternatives) && value.alternatives.length <= 2 && value.alternatives.every(requirementName) &&
    text(value.reason, 1024) && value.state === 'unknown';
}

