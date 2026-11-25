// Presentation/admission DATA only. Native vault, assessment, Bind and durable
// journal owners remain authoritative. No method here generates/exports keys.
export type CredentialSetupPlan = 'unavailable' | 'unlock-storage' | 'recovery-required'
  | 'reuse-ready' | 'assessment-needed' | 'select-existing' | 'existing-key-required'
  | 'conflict' | 'confirm-application-history' | 'offer-generation';
export type CredentialSetupRole = 'android-upload' | 'apple-distribution' | 'apple-signing-key';
export interface CredentialSetupStatus {
  schemaVersion: 1;
  projectId: string;
  observationRevision: number;
  role: CredentialSetupRole;
  plan: CredentialSetupPlan;
}
export type CredentialSetupAction = 'open-credentials' | 'unlock-storage' | 'review-existing'
  | 'select-existing' | 'recover' | 'confirm-application-history' | 'review-generation';
export interface CredentialSetupGuidance {
  title: string;
  detail: string;
  action: CredentialSetupAction | null;
  actionLabel: string | null;
  ready: boolean;
}
export interface CredentialSetupReviewRequest {
  projectId: string;
  expectedObservationRevision: number;
  role: CredentialSetupRole;
  action: CredentialSetupAction;
}

const plans: readonly string[] = ['unavailable', 'unlock-storage', 'recovery-required', 'reuse-ready',
  'assessment-needed', 'select-existing', 'existing-key-required', 'conflict',
  'confirm-application-history', 'offer-generation'];
const roles: readonly string[] = ['android-upload', 'apple-distribution', 'apple-signing-key'];
const continuity = 'Use your app’s existing signing key. A different key can prevent app updates.';
export const credentialBackupHelp = 'Save the encrypted backup and its recovery code separately. '
  + 'The code is not an account password. You need both to restore on another computer; '
  + 'a restored key still needs to be checked and assigned to your app.';

export function parseCredentialSetupStatus(value: unknown): CredentialSetupStatus | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  const row = value as Record<string, unknown>;
  const expected = ['schemaVersion', 'projectId', 'observationRevision', 'role', 'plan'];
  if (Object.keys(row).length !== expected.length || !expected.every((key) => Object.hasOwn(row, key))
    || row.schemaVersion !== 1 || typeof row.projectId !== 'string'
    || !/^[0-9a-f]{32}$/u.test(row.projectId) || /^0{32}$/u.test(row.projectId)
    || !Number.isInteger(row.observationRevision) || (row.observationRevision as number) < 1
    || (row.observationRevision as number) > 0xffffffff
    || typeof row.role !== 'string' || !roles.includes(row.role)
    || typeof row.plan !== 'string' || !plans.includes(row.plan)) return null;
  return { schemaVersion: 1, projectId: row.projectId,
    observationRevision: row.observationRevision as number,
    role: row.role as CredentialSetupRole, plan: row.plan as CredentialSetupPlan };
}

export function credentialSetupGuidance(status: CredentialSetupStatus | null): CredentialSetupGuidance {
  if (status === null) return { title: 'Check app signing', detail: continuity,
    action: 'open-credentials', actionLabel: 'Set up app signing', ready: false };
  switch (status.plan) {
    case 'reuse-ready': return { title: 'Your saved key is selected',
      detail: 'Your current key is assigned for setup. Signing validation still runs before release.',
      action: null, actionLabel: null, ready: true };
    case 'unlock-storage': return { title: 'Unlock your saved signing keys', detail: continuity,
      action: 'unlock-storage', actionLabel: 'Unlock saved keys', ready: false };
    case 'assessment-needed': return { title: 'Check your saved signing key',
      detail: 'Your choice was saved. Check it again before this app can use it.',
      action: 'review-existing', actionLabel: 'Check saved key', ready: false };
    case 'select-existing': return { title: 'Choose an existing signing key', detail: continuity,
      action: 'select-existing', actionLabel: 'Choose saved key', ready: false };
    case 'existing-key-required': return { title: 'Find your app’s existing key',
      detail: 'This app already has signing history. Import or restore its original key instead of creating another.',
      action: 'open-credentials', actionLabel: 'Find or restore key', ready: false };
    case 'conflict': return { title: 'Check which key belongs to this app',
      detail: 'The saved choice does not match the current app or signing information. Nothing was replaced.',
      action: 'review-existing', actionLabel: 'Review saved choice', ready: false };
    case 'recovery-required': return { title: 'Finish the previous signing setup',
      detail: 'An earlier operation needs attention. Do not create another key or delete the saved files.',
      action: 'recover', actionLabel: 'Review recovery', ready: false };
    case 'confirm-application-history': return { title: 'Has this app been signed before?',
      detail: continuity, action: 'confirm-application-history', actionLabel: 'Review app history', ready: false };
    case 'offer-generation': return { title: status.role === 'android-upload' ? 'Create this new app’s upload key' : 'Prepare this new app’s signing key',
      detail: 'No existing key was found for this confirmed new app. Review the details before creating one.',
      action: 'review-generation', actionLabel: 'Review new key', ready: false };
    case 'unavailable': return { title: 'Signing setup is not available here',
      detail: 'Use the supported native signing setup. No key has been created or changed.',
      action: 'open-credentials', actionLabel: 'View signing options', ready: false };
  }
}

// Explicit button/CLI review only, not an autorun/resume hook. Backend repeats
// currentness and authorization. Even review-generation does NOT create a key.
export function credentialSetupReview(status: CredentialSetupStatus, projectId: string,
  expectedRevision: number): CredentialSetupReviewRequest | null {
  const checked = parseCredentialSetupStatus(status);
  if (checked === null || checked.projectId !== projectId || checked.observationRevision !== expectedRevision) return null;
  const action = credentialSetupGuidance(checked).action;
  return action === null ? null : { projectId, expectedObservationRevision: expectedRevision, role: checked.role, action };
}

export function formatCredentialSetupCli(status: CredentialSetupStatus | null): string {
  const view = credentialSetupGuidance(status);
  return `${view.title}. ${view.detail}${view.actionLabel === null ? '' : ` Next: ${view.actionLabel}.`}`;
}
