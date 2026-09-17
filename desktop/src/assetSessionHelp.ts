import type { CredentialGuide, CredentialGuideField, CredentialKind, HelpContent } from './types.ts';
import type { AssetPreviewSubject, AssetStatus } from './assetSessionTypes.ts';

// The core catalogue remains a static reference, not evidence of native
// availability. Live session help must describe this narrower implemented flow,
// while retaining the core's field requiredness and identifier policy.
const privateValueFormat = 'Enter the original value, at most 4,096 UTF-8 bytes. Do not trim or normalize it. Entry is write-only: never put it in project settings, command arguments or logs. The core reports missing or unsupported values; presence is not credential verification.';
const noRestore = 'Starting a replacement or removal makes affected assignments unavailable. Failure or Cancel may preserve old record bytes, but never restores assignment automatically. Prepare and assign again explicitly; unknown cleanup prevents further use.';
const fieldHelp: Record<string, Partial<CredentialGuideField>> = {
  'android-keystore/file': {
    where: 'Obtain the existing upload-key keystore from its authorized signing-key owner. Select the private original outside registered project folders. The app will not change its contents or permissions, move it, or generate a replacement key.',
    format: 'An original .jks or .keystore file, at most 32 MiB. This importer recognizes only the JKS header; .p12/.pfx are not supported. A filename is not proof of format or key identity.',
    failure: 'A changed, overlapping, unsupported, oversized or insufficiently private source is refused without changing the original. A recognized JKS header does not verify a password, private-key entry, digest or signing identity.',
    suffixes: ['.jks', '.keystore'],
  },
  'android-keystore/storePassword': { format: privateValueFormat, failure: 'A missing value is a missing companion field, not a failed password test. This session accepts the write-only value for assessment and optional in-memory retention; it does not unlock the keystore.' },
  'android-keystore/keyPassword': { format: privateValueFormat, failure: 'Missing input is not a password failure. This session does not test the password or perform signing. No value is displayed back to you.' },
  'android-firebase/file': {
    where: 'In Firebase Console, open Project settings, choose the intended Android app under Your apps, and download google-services.json. Select that private original outside registered project folders. Do not use an exported service-account private key.',
    format: 'An original UTF-8 .json file, at most 4 MiB, within this importer’s document/complexity limits. Decoded duplicate names are refused. The core checks every supported client structure and the configured application ID; CLI parsing rules are unchanged.',
    failure: 'Malformed clients or an application-ID mismatch prevent a usable review. A parser-limit refusal is not proof that the original is malformed. No Firebase service is contacted and the original is never changed.',
  },
  'google-wif/provider': { failure: 'Identifier syntax does not prove provider existence, repository binding or token exchange. This session does not log in, request an identity token or import Google ADC.' },
  'google-wif/serviceAccount': { failure: 'An email with the expected format is not proof of impersonation or Google Play permissions. No account or service is contacted.' },
  'project-read-token/token': { format: privateValueFormat, failure: 'Missing input matters only when selected by core requirements. This session does not fetch source or check token permissions. Never use a Store or administrator credential for this field.' },
};

export function sessionKindHelp(kind: CredentialKind): CredentialKind {
  return { ...kind, fields: kind.fields.map((field) => ({ ...field, ...fieldHelp[`${kind.id}/${field.id}`] })) };
}

const controls: Record<string, Partial<HelpContent>> = {
  project: {
    requiredWhen: 'Before preparing or assigning an input for a project.',
    what: 'The selected native project and its current in-memory configuration draft.',
    format: 'Submit the current project and draft. Submission is not validation: the existing core validates that exact draft during assessment.',
    failure: 'Changing the project or draft invalidates old review and assignment presentation immediately. Prepare again for the new submitted context; no old assignment transfers automatically.',
  },
  platform: {
    requiredWhen: 'Before a context-specific assessment.', what: 'Android, iOS, or project dependency access for this assessment.',
    where: 'Choose the platform in this release-context panel, matching your intended task.',
    format: 'Android and iOS select platform context; Project dependency access selects the separate project-token context. The core alone decides applicability. A context choice does not enable an unsupported importer.',
  },
  stage: {
    requiredWhen: 'Before a context-specific assessment.', what: 'The release stage you are preparing inputs for.',
    where: 'Choose Candidate / internal testing, External testing, or Production preparation in this panel.',
    format: 'This selects assessment context only. Production preparation does not upload, promote or publish a release.',
    failure: 'Changing stage invalidates old context-bound reviews and assignment presentation. No Store operation is started.',
  },
  purpose: {
    requiredWhen: 'Before a context-specific assessment.', what: 'All selected input roles, build/signing roles, or Store-access roles.',
    where: 'Choose the purpose that matches the task you intend to prepare.',
    format: 'The existing core selects the actual requirements for full, signing or store. Choosing a purpose does not run those operations.',
  },
  mode: {
    requiredWhen: 'Explicit consent is required before the app keeps any private session input.',
    what: 'Keep bounded private inputs only in this running application, without persistence.',
    where: 'Use Start session. Only an independently qualified native profile can enable collection.',
    format: 'Session-only memory, at most 32 retained records / 64 MiB. There is no persistent-vault, keyring or plaintext-disk fallback.',
    failure: 'An unavailable importer does not collect input. Quitting or discarding revokes assignments and releases copies only after original work settles; perfect memory erasure is not promised.',
  },
  choose: {
    requiredWhen: 'For a supported file input after submitting the current context.',
    where: 'Click Select file and use the native picker. No manual registration, internal directory copying, path entry or renaming is required.',
    format: 'One private original outside all registered projects on the qualified local filesystem. This first increment supports JKS headers and Android Firebase JSON only.',
  },
  prepare: {
    requiredWhen: 'After file selection and companion entry, or when reviewing a scalar or retained record.',
    where: 'Use Prepare private review, or Review assignment on a retained session record.',
    format: 'Only the existing core evaluates requirements and the captured mechanical observations. Missing companion fields are not failed password tests. Nothing is assigned by preparation.',
  },
  review: {
    requiredWhen: 'Before Keep, Assign or Remove is committed.',
    where: 'Review the exact fixed input kind, target record/revision and submitted context in this panel.',
    format: 'Each action has a single-use review token and the original five-minute ceiling. Navigation and refresh cannot change its target or extend its lifetime.',
    failure: 'A missing original intent, changed context, mismatched target or expired review prevents confirmation. Discard and prepare explicitly; no blind retry.',
  },
  save: {
    requiredWhen: 'Only after explicit review of the exact new or replacement input.',
    what: 'Keep the captured input and supplied fields as one in-memory session record.',
    where: 'Use Keep for this session in the original review panel; review Assign separately afterwards.',
    format: 'One finite in-memory change for the pinned record revision. Nothing is written to a repository or persistent vault, and Keep does not assign or verify the credential.',
    failure: noRestore,
  },
  assign: {
    requiredWhen: 'Only after reviewing the exact retained record revision for the submitted context.',
    where: 'Use Assign to this context after Keep, or Review assignment on an existing session record.',
    format: 'A separate single-use confirmation binds this record to the exact submitted project/draft/platform/stage/purpose. No file read, account check, build or release is started.',
  },
  replace: {
    requiredWhen: 'Only when you explicitly want to change an existing same-kind session record.',
    what: 'Prepare a replacement for the exact selected session record revision.',
    where: 'Choose the consistently numbered existing item under New or replacement copy. Review that same target before keeping.',
    format: 'The original intent survives page navigation. Starting preparation makes old assignments unavailable; a successful replacement retains the record ID and increments its revision.',
    failure: noRestore,
  },
  delete: {
    requiredWhen: 'Only when you explicitly want to remove a retained session copy.',
    what: 'Remove the exact identified in-memory record, never its original file.',
    where: 'Choose Review removal on the record, then confirm its fixed kind, item number and revision.',
    format: 'No source file, account, credential or unrelated record is deleted or revoked. This is not secure memory/disk erasure.',
    failure: noRestore,
  },
  cancel: { requiredWhen: 'While the original session operation is pending.', format: 'Cancellation targets the original operation. Wait for its actual cleanup status; a timeout is not successful cleanup or rollback.', failure: noRestore },
  discard: { requiredWhen: 'When abandoning an unused selection/review or explicitly discarding the session.', where: 'Use Discard review or the confirmed Discard session action.', format: 'Original files stay untouched. Private copies are released only as their original owners settle; there is no complete memory-erasure guarantee.', failure: noRestore },
  lock: { requiredWhen: 'When you want this entire session to become unavailable.', what: 'Revoke all assignments and discard session copies after original pending work settles.', where: 'Use Discard session and confirm the stated data loss.', format: 'No record is saved for a later launch. No credential or signing identity is reset or revoked.', failure: 'Unknown cleanup stays explicit. Keep the original application owner available for late settlement; do not assume its buffers have been erased.' },
};

export function sessionControlHelp(guide: CredentialGuide | null, id: string): HelpContent | null {
  const original = guide?.controls.find((item) => item.id === id);
  const correction = controls[id];
  return original && correction ? { ...original, ...correction } : null;
}

export function sessionTargetLabel(guide: CredentialGuide | null, subject: AssetPreviewSubject, records: AssetStatus['records']): string | null {
  const label = guide?.kinds.find((kind) => kind.id === subject.kind)?.label ?? 'Session input';
  if (subject.change === 'new') return `New ${label.toLocaleLowerCase()} session record`;
  const index = records.findIndex((record) => record.recordId === subject.recordId && record.kind === subject.kind);
  return index >= 0 && subject.recordRevision !== null ? `${label} · item ${index + 1} · revision ${subject.recordRevision}` : null;
}
