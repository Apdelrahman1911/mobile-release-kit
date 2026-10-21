// Identity-specific immutable Check/ACK DATA. App retains its existing two
// actual Promise slots; this leaf has no invoke, owner, timer or subscription.
import { agentIdentityPermissionRevisionFits } from './projectIdentityNative.ts';
import type { AgentIdentityApi } from './projectIdentityNative.ts';

export interface IdentityPermissionContext {
  readonly service: object;
  readonly api: AgentIdentityApi | null;
  readonly projectId: string | null;
  readonly epoch: number;
}
interface Witness {
  readonly context: IdentityPermissionContext;
  readonly revision: string;
}
export interface IdentityPermission {
  readonly checked: Witness | null;
  readonly acknowledged: Witness | null;
}
export const emptyIdentityPermission: IdentityPermission = Object.freeze({ checked: null, acknowledged: null });
const usable = (revision: unknown): revision is string => agentIdentityPermissionRevisionFits(revision) &&
  (revision.length < 20 || revision < '18446744073709551614');
const contextFits = (context: IdentityPermissionContext): boolean => !!context.api && context.api.mode === 'native' &&
  context.projectId !== null && Number.isSafeInteger(context.epoch) && context.epoch >= 0 && context.epoch < Number.MAX_SAFE_INTEGER;
function matches(witness: Witness | null, context: IdentityPermissionContext): witness is Witness {
  return witness !== null && contextFits(context) && usable(witness.revision) && witness.context.service === context.service &&
    witness.context.api === context.api && witness.context.projectId === context.projectId && witness.context.epoch === context.epoch;
}
/** App calls this only for its genuinely returned, still-current explicit
 * Check. Replacing even an equal revision always drops the old checkbox ACK. */
export function observedIdentityPermission(context: IdentityPermissionContext, revision: unknown): IdentityPermission {
  if (!contextFits(context) || !usable(revision)) return emptyIdentityPermission;
  return Object.freeze({ checked: Object.freeze({ context: Object.freeze({ ...context }), revision }), acknowledged: null });
}
export function identityPermissionChecked(permission: IdentityPermission, context: IdentityPermissionContext): boolean {
  return matches(permission.checked, context);
}
export function acknowledgeIdentityPermission(permission: IdentityPermission, value: boolean, context: IdentityPermissionContext): IdentityPermission {
  return Object.freeze({ checked: permission.checked, acknowledged: value && matches(permission.checked, context) ? permission.checked : null });
}
export function identityPermissionAcknowledged(permission: IdentityPermission, context: IdentityPermissionContext): boolean {
  return permission.checked !== null && permission.acknowledged === permission.checked && matches(permission.acknowledged, context);
}
/** Assign the returned empty state BEFORE publishing App's work latch. The
 * revision is immutable comparison DATA, never a native grant or receipt. */
export function consumeIdentityPermission(permission: IdentityPermission, context: IdentityPermissionContext): {
  readonly permission: IdentityPermission; readonly expectedPermissionRevision: string | null;
} {
  return Object.freeze({ permission: emptyIdentityPermission,
    expectedPermissionRevision: identityPermissionAcknowledged(permission, context) ? permission.acknowledged!.revision : null });
}
