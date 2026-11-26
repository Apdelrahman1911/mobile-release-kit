import { useId, useSyncExternalStore } from 'react';
import type { ReactNode } from 'react';
import { IDENTITY_NEW_WARNING, identityValueFits } from '../projectIdentity.ts';
import type { ProjectIdentityController } from '../projectIdentityController.ts';
import type { AgentIdentityProposal } from '../projectIdentityNative.ts';
import { Badge, SectionHeading } from './Common.tsx';

// Root supplies a controller only through the genuine native identity owner.
// A controller without that optional port renders useful, disabled guidance.
// Mounting/typing never invokes a native analysis, build, Store call or write.
export function ProjectIdentityEditor({ controller, onDraftChange, requestedChange, agentAction, delegated = false }: { controller: ProjectIdentityController; onDraftChange?: (value: string) => void; requestedChange?: AgentIdentityProposal['request']['change']; agentAction?: ReactNode; delegated?: boolean }) {
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const id = useId();
  const { analysis, preview, recovery, actions, diagnostic } = state;
  const platform = analysis?.selection.platform ?? state.context?.selection?.platform;
  const label = platform === 'ios' ? 'Bundle ID' : platform === 'android' ? 'Application ID' : 'App ID';
  const changed = preview?.state === 'change';
  const recoveryPrepared = state.reviewCurrent && recovery?.state === 'recoverable';
  const cleanup = recovery?.action !== 'rollback';
  const needsRecovery = state.session?.coreOutcome?.journal === 'recovery_required';
  const newInputValid = platform !== undefined && identityValueFits(state.desiredIdentity, platform);
  const requestMismatch = !!requestedChange && !recovery && (state.intent !== requestedChange.identityIntent ||
    (state.intent === 'preserve' ? analysis?.identity : state.desiredIdentity) !== requestedChange.desiredIdentity);
  return <section className="card" aria-labelledby={`${id}-title`}>
    <div id={`${id}-title`}><SectionHeading title={label} description="This ID connects your app to its store listing. Keep it when updating an existing app.">
      <Badge tone={state.tone === 'success' ? 'info' : state.tone}>{state.busy ? 'Working' : state.result ? 'Finished' : state.reviewCurrent ? 'Review' : 'Project setup'}</Badge>
    </SectionHeading></div>
    <p className="subtle-note">Only the recognized app ID and matching saved setting can change. Source packages and namespaces stay as they are. The built app still needs an identity check before release.</p>
    <div className={`notice notice-${state.tone === 'danger' ? 'danger' : 'info'}`} role={state.tone === 'danger' ? 'alert' : 'status'} aria-live="polite">
      <p>{state.message}</p>
      {diagnostic && <p><strong>Where to look:</strong> <code>{diagnostic.path}:{diagnostic.line}</code></p>}
    </div>

    {requestedChange && <div className="notice notice-info"><div><strong>Immutable CLI proposal</strong>
      <p><code>{requestedChange.desiredIdentity}</code> · {requestedChange.identityIntent === 'new-application' ? 'a separate new app' : 'keep this app'}</p>
      <p>Your ordinary local draft is kept. This proposal cannot be changed through another editor; decline it if it is wrong.</p>
      {analysis && requestMismatch && <p className="review-caution">The original source/continuity check cannot preview this exact proposal. Close it and inspect the saved project; no altered proposal will be substituted.</p>}
    </div></div>}
    {analysis && <div className="field-grid">
      <div className="field"><span className="field-label">Last read {label}</span><code>{analysis.identity ?? 'Not recognized'}</code></div>
      {analysis.configuredIdentity !== analysis.identity && <div className="field"><span className="field-label">ID in saved project settings</span><code>{analysis.configuredIdentity ?? 'Not available'}</code></div>}
    </div>}

    {analysis?.state === 'supported' && !recovery && !preview && state.session?.phase === 'editing' && <fieldset disabled={!state.canEditDraft || delegated}>
      <legend>Which app are you setting up?</legend>
      <label className="checkbox-row"><input type="radio" name={`${id}-intent`} checked={state.intent === 'preserve'} disabled={!!requestedChange}
        onChange={() => controller.setIntent('preserve')} />Keep this app and its current ID</label>
      <label className="checkbox-row"><input type="radio" name={`${id}-intent`} checked={state.intent === 'new-application'} disabled={!state.canChooseNew || !!requestedChange}
        onChange={() => controller.setIntent('new-application')} />Set up a different, new app</label>
      {(analysis.selection.continuity === 'existing' || analysis.identityStatus !== 'unverified') && <p className="field-help">An existing or approved app keeps its ID. This editor cannot turn it into an update under a different ID.</p>}
      {state.intent === 'new-application' && <>
        <label className="field" htmlFor={`${id}-new`}><span className="field-label">New {label}</span>
          <input id={`${id}-new`} type="text" value={state.desiredIdentity} readOnly={!!requestedChange} maxLength={255} autoComplete="off" spellCheck={false}
            placeholder="com.example.myapp" aria-describedby={`${id}-format ${id}-new-warning`}
            onChange={(event) => { const value = event.target.value; if (controller.setDesiredIdentity(value)) onDraftChange?.(value); }} />
        </label>
        <p id={`${id}-format`} className="field-help">Use your chosen ID, with dot-separated parts beginning with a letter. {platform === 'android' ? 'Letters, digits and underscores are allowed.' : 'Letters, digits and hyphens are allowed.'} Spaces are not removed for you.</p>
        {state.desiredIdentity && !newInputValid && <p className="review-caution">Check the ID format before making a preview.</p>}
        <p id={`${id}-new-warning`} className="review-caution">{IDENTITY_NEW_WARNING}</p>
        <label className="checkbox-row"><input type="checkbox" checked={state.newApplicationAcknowledged}
          onChange={(event) => controller.acknowledgeNewApplication(event.target.checked)} />I am setting up a separate app, not updating the existing app.</label>
      </>}
    </fieldset>}

    {agentAction}
    {preview && <div className="review-panel">
      <h3>{changed ? 'Review the ID change' : 'Keep the current ID'}</h3>
      {delegated && <p>The agent owns this delegated preview/start. Follow its original status above; do not Apply it again here.</p>}
      {changed ? <>
        <p><code>{preview.changes[0]?.beforeId}</code> → <code>{preview.changes[0]?.afterId}</code></p>
        <p className="review-caution">{IDENTITY_NEW_WARNING}</p>
        <p>Existing credential checks and release plans will need to be checked again. Reserved version numbers are kept.</p>
        <details><summary>Files in this preview</summary><ul>{preview.changes.map((change, index) =>
          <li key={`${change.path}-${change.line}-${index}`}><code>{change.path}:{change.line}</code> — {change.role === 'saved-identity' ? 'saved project setting' : label}</li>)}</ul></details>
      </> : <p>No project files will change.</p>}
      <label className="checkbox-row"><input type="checkbox" checked={state.reviewAcknowledged} disabled={!state.reviewCurrent || state.busy || delegated}
        onChange={(event) => controller.acknowledgeReview(event.target.checked)} />{changed ? 'I reviewed these IDs and want this exact change.' : 'I reviewed the ID and want to keep it.'}</label>
      <button type="button" className="button primary" disabled={!actions.apply || delegated} onClick={() => controller.apply()}>
        {changed ? `Apply ${label} change` : 'Confirm unchanged ID'}
      </button>
    </div>}

    {recovery && !state.result && <div className="review-panel">
      <h3>Interrupted ID change</h3>
      {recovery.state === 'recoverable' && <>
        <p>{recovery.action === 'committed_cleanup' ? 'The ID change already committed. Recovery keeps it and only finishes private cleanup.' :
          cleanup ? 'This step only finishes the inspected private cleanup. It does not edit current project files.' :
            'Recovery restores the exact original project files. Any conflicting or unfamiliar files are preserved for attention.'}</p>
        {recovery.desiredIdentity && <p>ID from the interrupted change: <code>{recovery.desiredIdentity}</code></p>}
        <details><summary>Recovery details</summary><ul>{recovery.files.map((file) => <li key={file.path}>
          <code>{file.path}</code> — {file.action === 'restore_original' ? 'restore original' : 'preserve'}
        </li>)}</ul><p>Reserved version numbers are kept. Cleanup is limited to the inspected, owned journal.</p></details>
        {recoveryPrepared ? <>
          <label className="checkbox-row"><input type="checkbox" checked={state.reviewAcknowledged} disabled={state.busy}
            onChange={(event) => controller.acknowledgeReview(event.target.checked)} />{cleanup ? 'I reviewed the cleanup. Keep the project files as described.' : 'I reviewed the recovery. Restore the original files as described.'}</label>
          <button type="button" className="button primary" disabled={!actions.recover} onClick={() => controller.recover()}>
            {cleanup ? 'Finish cleanup' : 'Restore original files'}
          </button>
        </> : <button type="button" className="button primary" disabled={!actions.prepareRecovery} onClick={() => controller.prepareRecovery()}>Review recovery</button>}
      </>}
      {recovery.state === 'conflict' && <p className="review-caution">Keep the recovery files. Resolve the reported conflict before trying again; this panel will not overwrite or delete unfamiliar files.</p>}
    </div>}

    <div className="button-row">
      {needsRecovery && !recovery && <button type="button" className="button primary" disabled={!actions.inspectRecovery} onClick={() => controller.inspectRecovery()}>Review interrupted change</button>}
      {(!state.session || state.session.phase === 'final') && !needsRecovery ? <button type="button" className="button primary" disabled={!actions.analyze} onClick={() => controller.analyze()}>Read {label}</button> : null}
      {analysis && !preview && !recovery && state.session?.phase === 'editing' && <button type="button" className="button primary" disabled={!actions.prepare || requestMismatch || delegated} onClick={() => controller.prepare()}>Preview {state.intent === 'new-application' ? 'ID change' : 'unchanged ID'}</button>}
      {actions.discard && <button type="button" className="button secondary" onClick={() => controller.discard()}>Close review</button>}
      {!state.session && !actions.analyze && <button type="button" className="button secondary" disabled={!actions.checkStatus} onClick={() => controller.checkStatus()}>Check status</button>}
      {state.session && !actions.prepare && !actions.apply && !actions.prepareRecovery && !actions.recover && <button type="button" className="button secondary" disabled={!actions.checkStatus} onClick={() => controller.checkStatus()}>Check status</button>}
    </div>
    {!recovery && <details><summary>Interrupted change or technical details</summary>
      <p>If an earlier ID change was interrupted, inspect it before making another change.</p>
      <button type="button" className="button secondary" disabled={!actions.inspectRecovery} onClick={() => controller.inspectRecovery()}>Check for an interrupted change</button>
      {analysis && <><p>Recognized target: <code>{analysis.selection.target}</code></p>
        {analysis.selection.project && <p>Xcode project: <code>{analysis.selection.project}</code></p>}
        <p>Configurations: {analysis.configurations.join(', ') || 'Not recognized'}</p></>}
      <p>This is a literal source check, not proof of the app produced by every build plugin. Computed, generated, shared or ambiguous settings need manual attention at the reported source location.</p>
    </details>}
  </section>;
}
