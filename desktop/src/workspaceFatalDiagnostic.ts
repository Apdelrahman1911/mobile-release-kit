// In-memory fixed DATA only. No error message, stack or ErrorInfo is retained.
export interface WorkspaceFatalDiagnostic {
  code: 'workspace-render-error';
  category: 'error' | 'type-error' | 'range-error' | 'reference-error' | 'syntax-error' | 'uri-error' | 'eval-error' | 'unknown';
  reactCode: number | null;
  component: 'App' | 'Boundary' | 'InstallationDetails' | null;
}
export function workspaceFatalDiagnostic(error: unknown, info?: unknown): WorkspaceFatalDiagnostic {
  let category: WorkspaceFatalDiagnostic['category'] = 'unknown';
  let reactCode: number | null = null;
  try {
    const prototype = typeof error === 'object' && error !== null ? Object.getPrototypeOf(error) : null;
    const known = [[TypeError.prototype, 'type-error'], [RangeError.prototype, 'range-error'],
      [ReferenceError.prototype, 'reference-error'], [SyntaxError.prototype, 'syntax-error'],
      [URIError.prototype, 'uri-error'], [EvalError.prototype, 'eval-error'], [Error.prototype, 'error']] as const;
    category = known.find(([value]) => value === prototype)?.[1] ?? 'unknown';
    if (category !== 'unknown') {
      const descriptor = Object.getOwnPropertyDescriptor(error, 'message');
      // Inspect a bounded own data value; never invoke a message/name/stack getter.
      if (descriptor && 'value' in descriptor && typeof descriptor.value === 'string' && descriptor.value.length <= 512) {
        const match = /^Minified React error #([1-9][0-9]{0,4});/.exec(descriptor.value);
        const number = match ? Number(match[1]) : 0;
        if (number > 0 && number <= 65535) reactCode = number;
      }
    }
  } catch { /* Unknown classification only; no logging or raw error retention. */ }
  let component: WorkspaceFatalDiagnostic['component'] = null;
  try {
    const descriptor = typeof info === 'object' && info !== null ? Object.getOwnPropertyDescriptor(info, 'componentStack') : undefined;
    if (descriptor && 'value' in descriptor && typeof descriptor.value === 'string' && descriptor.value.length <= 2048) {
      // Source-owned tokens only. The original stack and paths are discarded.
      const match = /^\s*(?:at\s+)?(App|Boundary|InstallationDetails)(?:\s|\(|@|$)/m.exec(descriptor.value);
      if (match?.[1] === 'App' || match?.[1] === 'Boundary' || match?.[1] === 'InstallationDetails') component = match[1];
    }
  } catch { /* Component token unavailable. */ }
  return Object.freeze({ code: 'workspace-render-error', category, reactCode, component });
}
