import { useId } from 'react';
import type { HelpContent } from '../types.ts';
import type { GitHubInputGroupController } from '../githubInputGroupController.ts';
import type { GitHubInputGroupRecord, GitHubInputGroupView } from '../githubInputGroupTypes.ts';
import { GITHUB_INPUT_GROUP_REASON_HELP, githubInputGroupCompleted } from '../githubInputGroupProtocol.ts';
import { sessionKindHelp } from '../assetSessionHelp.ts';
import { Badge, HelpButton, SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';

const HELP: Record<'branch' | 'context' | 'group' | 'environment' | 'apply' | 'access' | 'runners' | 'limit' | 'recovery', HelpContent> = {
  branch: { label: 'Application branch', requiredness: 'required', requiredWhen: 'Before reviewing one GitHub input group.',
    what: 'The branch of your application repository that contains the reviewed release configuration and workflows.',
    why: 'The app checks the exact remote source and input-group-aware toolkit before an upload. Local unsaved changes are not uploaded.',
    where: 'Open the application repository on GitHub and use the Code page’s branch selector.',
    format: 'A branch such as main or release/next, not a URL, commit hash, tag or refs/heads/ prefix.',
    failure: 'Changed source or an older/incompatible workflow is refused. Review workflow changes in this app first.' },
  context: { label: 'Release context', requiredness: 'required', requiredWhen: 'When checking runner safety or selecting assigned private inputs.',
    what: 'The project, release stage, platform and purpose currently submitted in Credentials.',
    why: 'An assignment belongs to that exact context; an input for a different release stage cannot silently replace it.',
    where: 'Use Manage inputs / change release context to open the existing Credentials screen.',
    format: 'Choose the intended stage and platform there, then explicitly review and assign the input.',
    failure: 'Changing context makes earlier assignments and this upload review stale. No private input is automatically reassigned.' },
  group: { label: 'Assigned input group', requiredness: 'required', requiredWhen: 'For each new upload review.',
    what: 'One private input and all its companion fields, such as a signing file and its passwords.',
    why: 'They travel together in one GitHub secret so a partial password/file update is not possible.',
    where: 'Prepare and assign the item in Credentials. Use its native Select file button or guided private fields; no file copying is needed.',
    format: 'Select one complete, currently assigned group. Do not paste private values or secret names into this page.',
    failure: 'Incomplete, stale or unavailable assignments cannot be uploaded. Native signing/account checks remain separate.' },
  environment: { label: 'GitHub release environment', requiredness: 'required', requiredWhen: 'Reviewing the exact upload destination.',
    what: 'A protected, named set of release settings inside the selected application repository.',
    why: 'The release stage determines the exact environment. The app will not create it or weaken its rules.',
    where: 'GitHub repository → Settings → Environments → the mobile environment shown in the review.',
    format: 'This is a read-only destination selected by the core; do not enter a different name.',
    failure: 'Missing access or unverified protection blocks upload. A 404 means missing or inaccessible, not guaranteed absence.' },
  apply: { label: 'Apply one complete group', requiredness: 'required', requiredWhen: 'After reading a fresh upload preview.',
    what: 'One update that adds or replaces the entire displayed input-group secret.',
    why: 'GitHub cannot return the old private value for backup or rollback. Your explicit replacement consent is required.',
    where: 'Check the exact repository, environment and group below, then tick the confirmation and Apply once.',
    format: 'One complete group, one confirmation. Other groups need separate reviews; legacy input names are left untouched.',
    failure: 'A lost response may still mean the update occurred. Never repeat it automatically. No release is started by this action.' },
  access: { label: 'GitHub access for input upload', requiredness: 'conditional', requiredWhen: 'Preparing or applying an input group.',
    what: 'The original GitHub connection’s session-only credential, not a second credential entry.',
    why: 'Review needs read access to the source and environment; Apply additionally needs Environments write.',
    where: 'Review your GitHub App authorization or selected-repository fine-grained token permissions with the repository administrator.',
    format: 'Grant only the documented source/environment read and Environments write access needed for this selected repository.',
    failure: 'Reported repository roles do not prove effective token permissions. Organization approval or SSO may be required; the app never increases access.' },
  runners: { label: 'Runner safety check', requiredness: 'required', requiredWhen: 'Before reviewing or applying a private input group.',
    what: 'A read-only check of who can run the generated release workflows. It uses your existing GitHub connection.',
    why: 'A self-hosted runner labelled ubuntu-24.04 or macos-26 could receive work intended for a GitHub-hosted runner, including work using private inputs. Offline, busy and differently capitalized labels still count.',
    where: 'Repository → Settings → Actions → Runners. For an organization, also ask its administrator to review organization Settings → Actions → Runner groups, including inherited groups, and your connection’s effective Actions/runner visibility.',
    format: 'No value to enter. Use the repository administrator connection, save your project and submit its release context in Credentials, then choose Check runner safety. No branch or selected input group is needed.',
    failure: 'Incomplete access, more than 8 groups or 100 runners per list, or either hosted-label collision blocks the check. Organization checks deliberately cover every visible organization group, not just groups assigned to this repository. Correct access or labels, then explicitly recheck. Observations expire within two minutes, sometimes sooner; the app never renews them automatically.' },
  limit: { label: 'GitHub input size limit', requiredness: 'conditional', requiredWhen: 'Sending a local input group to GitHub.',
    what: 'This channel allows a complete encoded group of at most 48,000 bytes.',
    why: 'GitHub limits individual secrets. A locally valid signing file can be too large after encoding.',
    where: 'The native preview reports whether the assigned complete group fits; you do not need to encode files yourself.',
    format: 'The app handles encoding and encryption privately. Values, original labels and exact private sizes are not displayed.',
    failure: 'Oversized inputs remain usable locally. The original is preserved; nothing is truncated, split, compressed or written into the repository.' },
  recovery: { label: 'Update outcome and recovery', requiredness: 'conditional', requiredWhen: 'An update was interrupted or its response was lost.',
    what: 'GitHub acceptance, local cleanup and current metadata are separate facts.',
    why: 'A secret’s presence or timestamp cannot prove what value was written or that this particular update succeeded.',
    where: 'Read original local Status first. After original settlement, Check current metadata performs only a bounded GitHub read.',
    format: 'Keep the original request record. A deliberate new overwrite needs current inputs, a new preview and new consent.',
    failure: 'Unknown stays unknown without an exact acknowledgement. Restart does not recover private input bytes, and Stop cannot undo an accepted update.' },
};
function resultLabel(row: GitHubInputGroupRecord): string {
  if (githubInputGroupCompleted(row)) return 'GitHub accepted this input group';
  if (row.write.state === 'acknowledged-created' || row.write.state === 'acknowledged-updated') return 'GitHub accepted the update; local completion needs attention';
  if (row.write.state === 'attempted-outcome-unknown') return 'Update outcome unknown — do not retry';
  if (row.write.state === 'explicitly-rejected') return 'GitHub rejected this update';
  return 'No update attempted in this recorded outcome';
}
export function GitHubInputGroup({ state, controller, onHelp, onCredentials, onSettings, compact = false, onShow }: {
  state: GitHubInputGroupView; controller: GitHubInputGroupController; onHelp: (help: HelpContent) => void;
  onCredentials: () => void; onSettings: () => void; compact?: boolean; onShow?: () => void;
}) {
  const branchId = useId(), groupId = useId(), confirmId = useId(), reasonId = useId();
  const options = controller.choices(), kind = controller.selectedKind(), scope = controller.currentScope();
  const prepared = controller.currentPrepared(), status = state.status, op = status?.operation;
  const prepareReason = controller.prepareReason(), applyReason = controller.applyReason(), runnerCheckReason = controller.runnerCheckReason();
  const runner = status?.runner;
  const help = (key: keyof typeof HELP) => <HelpButton content={HELP[key]} onHelp={onHelp} />;
  const controls = <div className="button-row"><button type="button" className="button secondary" disabled={state.mode !== 'native' || state.observing}
    onClick={() => void controller.checkStatus()}>Read original local Status</button>
    <button type="button" className="button secondary" disabled={!controller.canCancel()} onClick={() => controller.cancel()}>Stop original local action</button></div>;
  if (compact && !state.pending && !state.uncertain && !state.cancelling && (!op || op.phase === 'settled')) return null;
  return <section className="card" aria-label="GitHub input-group upload">
    <SectionHeading title="Send an input group to GitHub" description="Review and apply one complete assigned input. No release starts here."><Icon name="key" size={22} /></SectionHeading>
    {compact ? <><p role="status">Original input-group action: {op?.phase ?? 'acknowledgement pending'}.</p>{controls}
      <button type="button" className="button secondary" onClick={onShow}>Show input-group review and recovery</button></> : <>
      <div className="notice notice-info"><Icon name="shield" size={18} /><div>
        <strong>{status?.available ? 'Review first, then apply once' : 'Input upload needs attention'}</strong>
        <p id={reasonId}>{prepareReason ?? 'Prepare reads GitHub and reviews the destination. Apply is a separate, explicit whole-group update.'}</p>
        <p>Your existing native credential session keeps the values private. This page never asks for a password, file path, signing asset or token.</p>
      </div></div>
      <div className="inline-heading"><h3>Inputs for this release context</h3>{help('context')}</div>
      <p className="save-note">{scope ? `${scope.stage === 'candidate' ? 'Candidate' : scope.stage === 'external-testing' ? 'External testing' : 'Production'} · ${scope.platform} · ${scope.purpose === 'full' ? 'All required release inputs' : scope.purpose === 'signing' ? 'Signing inputs' : 'Store inputs'}` : 'No current saved project and credential context.'}</p>
      <div className="button-row"><button type="button" className="button secondary" onClick={onCredentials}>Manage inputs / change release context</button>
        <button type="button" className="button secondary" onClick={onSettings}>Review project settings</button>{help('access')}</div>
      <article className="github-environment" aria-label="Runner safety">
        <div className="inline-heading"><h3>Check runner safety</h3><Badge>Required before upload review</Badge>{help('runners')}</div>
        <p>This reads runner settings using your existing connection. It uploads no input, changes no settings and starts no workflow.</p>
        <button type="button" className="button secondary" disabled={runnerCheckReason !== null} aria-describedby={reasonId + '-runners'}
          onClick={() => controller.checkRunners()}>Check runner safety — read only</button>
        <p id={reasonId + '-runners'} className="save-note">{runnerCheckReason ?? 'No branch or selected input group is needed. Administrator access and effective runner visibility are checked by the native operation.'}</p>
        <p role="status" aria-live="polite">{runner?.result === 'safe' ? 'No conflicting hosted-runner label observed. This is not release readiness or proof that credentials are valid.' : controller.runnerReason()}</p>
        {runner && runner.result !== 'refused' && <dl className="github-facts">
          <div><dt>Scope</dt><dd>{runner.scope === 'organization-wide' ? 'Organization-wide, including inherited groups; a conservative superset of this repository’s runners' : 'This personal repository'}</dd></div>
          <div><dt>Observed inventory</dt><dd>{runner.groupCount} groups · {runner.runnerCount} runners</dd></div>
          <div><dt>Checked at · UTC</dt><dd><time dateTime={runner.checkedAt}>{runner.checkedAt}</time></dd></div>
          <div><dt>Native expiry · display only</dt><dd><time dateTime={runner.expiresAt}>{runner.expiresAt}</time></dd></div>
        </dl>}
        <p className="save-note">The check rejects self-hosted labels ubuntu-24.04 and macos-26 even when runners are offline or busy. It covers at most 8 organization groups and 100 runners per list. A fresh check clears any earlier upload review; it never applies or renews one.</p>
      </article>
      <div className="field-label-row"><label htmlFor={branchId}>Application branch</label><Badge>Required</Badge>{help('branch')}</div>
      <input id={branchId} type="text" value={state.branch} maxLength={200} autoComplete="off" autoCapitalize="none" spellCheck={false}
        placeholder="main or release/next" onChange={(event) => controller.setBranch(event.target.value)} aria-describedby={branchId + '-help'} />
      <p id={branchId + '-help'} className="save-note">Find this on the repository’s GitHub Code page. Local drafts are not uploaded. The native review must match your saved configuration and reviewed workflows.</p>
      <div className="field-label-row"><label htmlFor={groupId}>Assigned input group</label><Badge>Required</Badge>{help('group')}</div>
      <select id={groupId} value={state.assignment?.kind ?? ''} onChange={(event) => controller.setAssignment(options.find((row) => row.assignment.kind === event.target.value)?.assignment ?? null)}
        aria-describedby={groupId + '-help'}><option value="">Choose one assigned group…</option>
        {options.map((row) => <option key={row.assignment.kind} value={row.assignment.kind}>{row.kind.label}</option>)}</select>
      <p id={groupId + '-help'} className="save-note">{options.length ? 'Only current assignments that match saved core requirements are listed. Native validation and platform availability are checked again before upload.' : 'No complete current assignment is available. Open Credentials to select a file or enter companion fields, review it, and explicitly assign it. No terminal or file copying is needed.'}</p>
      {kind && <details><summary>What is included in {kind.label}?</summary><p>The whole group travels together; values and local labels are not displayed.</p>
        {sessionKindHelp(kind).fields.map((field) => <div className="session-field-help" key={field.id}>
          <div className="inline-heading"><strong>{field.label}</strong><HelpButton content={field} onHelp={onHelp} /></div>
          <p>{field.what}</p><p><strong>Find it:</strong> {field.where}</p><p><strong>Format:</strong> {field.format}</p>
        </div>)}</details>}
      <div className="button-row"><button type="button" className="button primary" disabled={prepareReason !== null} aria-describedby={reasonId}
        onClick={() => controller.prepare()}>Review upload — read only</button>{help('limit')}</div>
      {prepared && <article className="github-environment" aria-label="Whole input-group update review">
        <div className="inline-heading"><h3>Review this one complete group</h3>{help('apply')}</div>
        <dl className="github-facts"><div><dt>Application repository</dt><dd>{prepared.target.repository}</dd></div>
          <div><dt>Environment {help('environment')}</dt><dd>{prepared.target.environment}</dd></div>
          <div><dt>Input group</dt><dd>{kind?.label ?? prepared.target.kind}</dd></div>
          <div><dt>Exact GitHub secret name</dt><dd><code>{prepared.target.secretName}</code></dd></div>
          <div><dt>Included fields</dt><dd>{prepared.fields.map((id) => kind?.fields.find((field) => field.id === id)?.label ?? id).join(', ')} — values hidden</dd></div>
          <div><dt>Current metadata</dt><dd>{prepared.metadata.state === 'present' ? 'Present; existing value is unavailable for comparison or backup' : 'Missing or inaccessible; absence is not established'}</dd></div>
          <div><dt>Destination size</dt><dd>Complete group fits the 48,000-byte GitHub envelope limit</dd></div></dl>
        <details><summary>Exact source and destination identities</summary><dl className="github-facts">
          <div><dt>Account / repository / environment IDs</dt><dd><code>{prepared.target.accountId} / {prepared.target.repositoryId} / {prepared.target.environmentId}</code></dd></div>
          <div><dt>Branch / source commit</dt><dd><code>{prepared.target.branch} / {prepared.target.sourceSha}</code></dd></div>
          <div><dt>Toolkit commit / protocol</dt><dd><code>{prepared.target.toolingSha} / {prepared.target.protocol}</code></dd></div>
          <div><dt>Canonical caller / SHA256</dt><dd><code>{prepared.target.callerPath} / {prepared.target.callerSha256}</code></dd></div>
          <div><dt>Configuration SHA256</dt><dd><code>{prepared.target.configSha256}</code></dd></div>
          <div><dt>Native review expiry · display only</dt><dd><time dateTime={prepared.consentExpiresAt}>{prepared.consentExpiresAt}</time></dd></div></dl></details>
        <p>The entire group is added or replaced in one update. The old secret value cannot be recovered by the app. GitHub has no compare-and-swap protection against another authorized writer.</p>
        <p>Existing legacy inputs stay untouched. Only the reviewed group-aware workflow consumes this new group; separate groups and workflow jobs are not one atomic release configuration. This action starts no workflow and publishes nothing.</p>
        {prepared.target.kind === 'apple-operation-commitment' && <p className="review-caution">This is not key generation, rotation, backup or proof that the key matches an earlier release. Retain original keys and versions needed for unfinished releases.</p>}
        <div className="field-label-row"><input id={confirmId} type="checkbox" checked={state.confirmed} onChange={(event) => controller.setConfirmed(event.target.checked)} />
          <label htmlFor={confirmId}>Apply this complete input group to {prepared.target.environment} in {prepared.target.repository}. This may replace its existing value, which the app cannot restore.</label></div>
        <button type="button" className="button primary" disabled={applyReason !== null} onClick={() => controller.apply()}>Apply this group once</button>
        {applyReason && <p className="save-note">{applyReason}</p>}
      </article>}
      {op && <p role="status" aria-live="polite">Original {op.kind}: {op.phase}. {op.reason !== 'none' && GITHUB_INPUT_GROUP_REASON_HELP[op.reason]}</p>}
      {state.uncertain && <p className="review-caution" role="status">The original request or cleanup is uncertain. Read original local Status; do not repeat the update or assume that an idle observation means nothing was sent.</p>}
      {state.error && <p className="review-caution" role="status">{GITHUB_INPUT_GROUP_REASON_HELP[state.error]}</p>}
      <div className="inline-heading"><h3>Original results and recovery</h3>{help('recovery')}</div>
      <button type="button" className="button secondary" disabled={controller.startReason() !== null} onClick={() => controller.loadPending()}>Load this project’s original records — local only</button>
      {!status?.records.length && <p className="save-note">No original record is displayed. This does not prove that no GitHub update exists.</p>}
      {status?.records.map((row) => <article className="github-environment" key={row.originalOperationId}>
        <h4>{row.target.repository} · {row.target.environment} · {row.target.kind}</h4>
        <p><Badge tone={githubInputGroupCompleted(row) ? 'info' : 'warning'}>{resultLabel(row)}</Badge></p>
        <p className="save-note">Original request <code>{row.originalOperationId}</code> · <code>{row.target.secretName}</code>.<br />
          Journal: {row.completion.journal} · cleanup: {row.completion.cleanup} · original finality: {row.completion.finality}.</p>
        {row.reason !== 'none' && <p className="review-caution">{GITHUB_INPUT_GROUP_REASON_HELP[row.reason]}</p>}
        <p className="save-note">Acceptance is not credential correctness or release readiness. After restart, private inputs must be selected and assigned again before a new explicit review.</p>
        <button type="button" className="button secondary" disabled={controller.recordReason(row) !== null} onClick={() => controller.observe(row)}>Check current metadata — read only</button>
        {controller.recordReason(row) && <p className="save-note">{controller.recordReason(row)}</p>}
        {status.observation?.originalOperationId === row.originalOperationId && <p className="save-note">Current metadata: {status.observation.metadata.state}, observed {status.observation.metadata.observedAt}.
          This cannot prove the secret’s value or whether an unknown original update succeeded. Its original outcome is unchanged.</p>}
      </article>)}
      {controls}<p className="save-note">Status reads native state only. Metadata checks are explicit bounded reads, not uploads. Stop requests local cleanup, not rollback. No private values or filenames are stored in this view.</p>
    </>}
  </section>;
}
