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
  'android-keystore/storePassword': { format: privateValueFormat, failure: 'A missing value is a missing companion field, not a failed password test. The private-input flow accepts the write-only value for assessment and separately confirmed storage; it does not unlock the keystore.' },
  'android-keystore/keyPassword': { format: privateValueFormat, failure: 'Missing input is not a password failure. This session does not test the password or perform signing. No value is displayed back to you.' },
  'apple-p12/file': {
    where: 'Ask the authorized Apple Distribution signing-key owner for a P12 export containing the existing certificate and private key, with its password. On a separately admitted Apple-silicon Mac, select the private original outside registered project folders. Do not generate or replace a signing identity just to satisfy this screen.',
    format: 'An original .p12 or .pfx file, at most 32 MiB, with a supported PKCS#12 version-3 envelope. Signed-data authSafe variants have a separate 4 MiB parser ceiling. These are mechanical observations, not password or trust checks.',
    failure: 'A format refusal never changes the original. A recognized envelope does not prove the password, private key, certificate expiry or approved distribution identity. Actual validation belongs to the separately admitted signed export.',
    suffixes: ['.p12', '.pfx'],
  },
  'apple-p12/password': {
    where: 'Use the original password set by the authorized owner when this P12 was exported. Ask that owner if it is unknown; do not paste it into project settings or logs.',
    format: privateValueFormat,
    failure: 'A missing value prevents a usable signing input. Supplied means retained for assessment, not that the P12 was unlocked. Password correctness is checked only by the core signed-export flow.',
  },
  'apple-profile/file': {
    where: 'Obtain the Apple-issued App Store provisioning profile from the authorized developer-account owner. It must cover the saved team, explicit bundle ID and reviewed Apple Distribution certificate. Select its private original outside registered projects on the separately admitted Mac.',
    format: 'An original .mobileprovision file, at most 4 MiB, containing a complete supported DER CMS SignedData envelope. No password is entered for this file. One primary profile is supported; extension/profile mismatches are not guessed.',
    failure: 'CMS format is not proof of Apple authenticity, valid dates, entitlements or team/bundle/signer correspondence. Those checks belong to core signing validation; session assessment cannot authorize a release.',
    suffixes: ['.mobileprovision'],
  },
  'asc-p8/file': {
    where: 'Obtain the original downloaded API private key from its authorized App Store Connect account owner. On an admitted Linux or Apple-silicon Mac session, select the private original outside registered projects; the app does not move, rename, change permissions or generate keys.',
    format: 'An original .p8 file, at most 4 MiB: one unencrypted PRIVATE KEY PEM block with strict 64-column wrapping, or complete DER PKCS#8 version 0. Envelope and named EC/P-256 identifiers only. Encrypted, SEC1-only, version-1, attributes and explicit-curve variants are unsupported.',
    failure: 'A recognized envelope and identifiers do not prove mathematical private-key validity, account ownership, revocation or App Store Connect permissions. No key derivation, signing or Store request occurs. Keep/Save and Assign remain separate reviews.',
    suffixes: ['.p8'],
  },
  'asc-p8/keyId': { format: 'Exactly 10 uppercase ASCII letters or digits, as judged by the core. ' + privateValueFormat },
  'asc-p8/issuerId': { format: 'UUID spelling: 8-4-4-4-12 hexadecimal characters with hyphens, as judged by the core. ' + privateValueFormat },
  'android-firebase/file': {
    where: 'In Firebase Console, open Project settings, choose the intended Android app under Your apps, and download google-services.json. Select that private original outside registered project folders. Do not use an exported service-account private key.',
    format: 'An original UTF-8 .json file, at most 4 MiB, within this importer’s document/complexity limits. Decoded duplicate names are refused. The core checks every supported client structure and the configured application ID; CLI parsing rules are unchanged.',
    failure: 'Malformed clients or an application-ID mismatch prevent a usable review. A parser-limit refusal is not proof that the original is malformed. No Firebase service is contacted and the original is never changed.',
  },
  'ios-firebase/file': {
    where: 'In Firebase Console, open Project settings, choose the intended iOS app under Your apps, and download GoogleService-Info.plist. Select that private original outside registered project folders. Do not use an exported service-account private key.',
    format: 'An original UTF-8 XML 1.0 .plist file, at most 4 MiB. Binary plist is not supported. This importer bounds depth to 32 and applies scalar, key and document-complexity limits; decoded duplicate keys are refused. The core checks the root dictionary and BUNDLE_ID against the submitted iOS bundle ID.',
    failure: 'Malformed XML, missing or nonstring BUNDLE_ID, or a bundle-ID mismatch prevent a usable review. Unsupported variants and parser-limit refusals do not prove the original is malformed. XML format and bundle-ID match do not verify a Firebase account or service. No service is contacted and the original is never changed.',
    suffixes: ['.plist'],
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
    requiredWhen: 'Explicit consent is required before the app keeps any private input.',
    what: 'Choose memory-only inputs for this launch, or an available authenticated encrypted vault for later launches.',
    why: 'Saving, unlocking and assigning are separate decisions. Neither storage mode authorizes a build or release.',
    where: 'Choose Start session or Open encrypted vault in this panel. Only an independently qualified native profile can enable collection.',
    format: 'Memory-only: 32 records / 64 MiB. Encrypted: 128 descriptors / 1 GiB on disk, with bounded private memory and a qualified OS keyring. No vault-password field, plaintext disk or silent mode fallback.',
    failure: 'Use only a trusted operating system, desktop account and original Secret Service session. Profile checks detect observed changes; they are not atomic process protection or protection from a compromised account. Unavailable or denied access fails closed, without replacing a key or weakening OS permissions. Perfect memory/disk erasure is not promised.',
  },
  label: {
    label: 'Optional vault label', requiredness: 'optional', requiredWhen: 'Only when saving a new or replacement encrypted record.',
    what: 'A short nonsecret name to help you recognize this encrypted record.',
    why: 'A chosen label is easier to recognize, but it never proves which account, file or signing identity the record contains.',
    where: 'Choose your own description, such as Android upload key. Leave it empty to use the input kind and item number. No filename is copied automatically.',
    format: 'Optional nonempty text up to 128 UTF-8 bytes, without control characters. It is encrypted on disk and displayed only while its descriptor is unlocked. Unicode may use several bytes per character.',
    failure: 'Overlong or unsupported text prevents preparation. Never put passwords, tokens or private identifiers in labels; a label does not rename or change the original file.',
  },
  initialize: {
    label: 'Initialize encrypted vault', requiredness: 'conditional', requiredWhen: 'Only for a confirmed absent vault, after a separate explicit review.',
    what: 'Create the application’s encrypted private-input vault and its new protected key.',
    why: 'Persistence needs a new, uniquely bound vault and OS keyring entry before the app can save inputs.',
    where: 'Use Review vault initialization, then confirm the original review. The app manages its private location outside registered projects; no folder copying is needed.',
    format: 'Available only when the native service positively reports an uninitialized vault. This creates storage, not a credential, assignment or release.',
    failure: 'Existing, inaccessible or conflicting state is never overwritten or adopted. A partial or uncertain result stays explicit; do not repeat initialization to repair it.',
  },
  unlock: {
    label: 'Unlock encrypted vault', requiredness: 'conditional', requiredWhen: 'Before preparing, saving, removing or assigning encrypted inputs.',
    what: 'Explicitly ask the qualified OS keyring for the existing vault key.',
    why: 'Locked storage cannot expose labels or supply credentials. Unlock authenticates the bounded descriptor listing; it does not assess every stored payload.',
    where: 'Use Unlock vault. If the operating system asks for access, use its normal keyring controls; never enter that password into this app’s credential fields.',
    format: 'No automatic prompt, replacement key, import or recovery is attempted. Saved records still need an explicit Assess and assign step for the current draft.',
    failure: 'Locked, denied, missing and unavailable access have distinct reasons. Interrupted storage may permit read-only labels only, with no mutation or assignment.',
  },
  choose: {
    requiredWhen: 'For a supported file input after submitting the current context.',
    where: 'Click Select file and use the native picker. No manual registration, internal directory copying, path entry or renaming is required.',
    format: 'One private original outside all registered projects on the separately admitted local filesystem. Supported observations are JKS headers, Android Firebase JSON, iOS Firebase XML plist, unencrypted P8 PKCS#8 envelopes, and macOS-only P12 / DER CMS profile envelopes; native availability is a separate gate. P8 envelope/EC-P256 identifiers are not mathematical key, ownership, revocation or Store-access validation. Apple authenticity and password correctness are not format observations. Binary plist is not enabled.',
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
  lock: { requiredWhen: 'When you want this entire session to become unavailable.', what: 'Revoke all assignments and discard session copies after original pending work settles.', where: 'Use Discard session and confirm the stated data loss.', format: 'No record is saved for a later launch. No credential or signing identity is reset or revoked.', failure: 'Unknown cleanup stays explicit. Keep the original application owner available for late settlement; do not assume its buffers have been erased. Once the original work has settled and this session is closed, Close can ask for quit confirmation without reopening credential use.' },
};

const encryptedControls: Record<string, Partial<HelpContent>> = {
  prepare: {
    where: 'Use Prepare private review for new input, or Assess and assign on an existing unlocked encrypted record.',
    format: 'Existing records are freshly read, authenticated and assessed against the submitted draft. Unlocking a label or saving a source snapshot does not perform that step.',
  },
  save: {
    what: 'Save the captured input and supplied fields as one authenticated encrypted record outside your projects.',
    where: 'Use Save encrypted copy in the original review. Then explicitly use Assess and assign on the saved revision.',
    format: 'Saving has separate effect, durability and cleanup results. Saved means not assigned; the stored payload has not yet been checked for use in this session. No source-inherited assignment review follows.',
  },
  assign: {
    where: 'Use Assess and assign on the exact unlocked saved record. Review the fresh assessment, then confirm Assign to this context.',
    format: 'Preparation reads and authenticates the actual stored revision, then the core reassesses it for this draft. Assignment is a separate single-use confirmation; no account check, build or release starts.',
  },
  replace: {
    requiredWhen: 'Only when you explicitly want to replace an existing same-kind encrypted record.',
    what: 'Prepare a replacement for the exact selected encrypted record revision.',
    where: 'Choose the existing kind, item number and revision under New or replacement copy. An optional nonsecret label helps recognition, not identity proof.',
  },
  delete: {
    requiredWhen: 'Only when you explicitly want to remove one encrypted stored copy.',
    what: 'Remove the exact stored record, never its original selected file or OS keyring key.',
    where: 'Choose Review removal on the exact unlocked record and confirm the original review.',
  },
  discard: {
    requiredWhen: 'When abandoning the original operation or unused review.',
    where: 'Use Discard review or Request cancel. Use Lock vault separately to make the whole vault unavailable.',
    format: 'Cancellation is not rollback: an effect may already have happened. Observe effect, durability and cleanup independently; no automatic retry, repair or plaintext fallback occurs.',
  },
  lock: {
    requiredWhen: 'When you want all decrypted vault inputs and assignments to become unavailable.',
    what: 'Revoke assignments and release owned decrypted copies after their original operations settle; preserve encrypted records on disk.',
    where: 'Use Lock vault and confirm. Unlock and reassess stored revisions explicitly before assigning again.',
    format: 'This does not remove the encrypted vault or reset, replace, revoke or export its key. Lock is not a guarantee of perfect memory or disk erasure.',
    failure: 'A pending or unknown original owner stays visible. A storage effect is never relabeled as successful merely because Lock or Cancel was requested.',
  },
};

export function sessionControlHelp(guide: CredentialGuide | null, id: string, storage: 'session' | 'encrypted' = 'session'): HelpContent | null {
  const original = guide?.controls.find((item) => item.id === (id === 'initialize' || id === 'unlock' ? 'mode' : id));
  const correction = controls[id];
  return original && correction ? { ...original, ...correction, ...(storage === 'encrypted' ? encryptedControls[id] : {}) } : null;
}

export function sessionTargetLabel(guide: CredentialGuide | null, subject: AssetPreviewSubject, records: AssetStatus['records'], storage: 'session' | 'encrypted' = 'session'): string | null {
  if (subject.type === 'vault') return 'New encrypted private-input vault';
  const label = guide?.kinds.find((kind) => kind.id === subject.kind)?.label ?? 'Private input';
  if (subject.change === 'new') return `New ${label.toLocaleLowerCase()} ${storage} record`;
  const index = records.findIndex((record) => record.recordId === subject.recordId && record.kind === subject.kind);
  const record = records[index];
  return record && record.revision === subject.recordRevision ? `${label}${record.label ? ` · ${record.label}` : ''} · item ${index + 1} · revision ${subject.recordRevision}` : null;
}
