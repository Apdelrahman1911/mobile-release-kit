import type { ReactNode } from 'react';
import type { IOSArchiveController, IOSArchiveState } from '../iosArchive.ts';
import { isIOSSigningCheckOperation, iosArchiveFindingText, iosArchiveReasonText } from '../iosArchiveProtocol.ts';
import { Badge, ErrorNotice, SectionHeading } from './Common.tsx';

export function IOSSigningInputsResult({ state }: { state: IOSArchiveState }) {
  const op = state.status?.operation;
  if (state.mode !== 'native' || !op || !isIOSSigningCheckOperation(op) || op.phase !== 'terminal' || op.outcome !== 'complete' || !op.result) return null;
  return <section className="offline-report" aria-label="Completed existing iOS signing-input check">
    <div className="inline-heading"><h3>Existing signing inputs checked · {op.context.projectId}</h3><Badge tone="info">Past check</Badge></div>
    <p>Checked at {op.result.checkedAt}. Saved version {op.result.usedVersion.name} · build {op.result.usedVersion.build}.</p>
    <ol className="offline-findings">{op.result.checks.map((row) => <li key={row.check}><Badge tone="neutral">{row.status}</Badge><span>{iosArchiveFindingText[row.check]}</span></li>)}</ol>
    <p>The selected signing inputs passed this local check. Nothing was built, installed, uploaded or assigned. Recheck after changing inputs; this does not mean the app is ready to release.</p>
    {(state.historical || state.integrityFailed || state.nativeBlocked) && <p className="review-caution">These results belong to earlier inputs, not the current selection.</p>}
    <details><summary>What this result does and does not prove</summary>
      <p>The check compared the selected P12/password, its private key and certificate, the authenticated primary App Store profile, saved policy and any required Firebase file. It covers one primary profile and does not check live revocation.</p>
      <p>The existing native owner withheld the result until its required worker, material, private scratch and native lifetimes settled. This historical result is not a current private-key binding, credential assignment or permission to sign. Later signing has its own validation and consent.</p>
    </details>
  </section>;
}

/** A view of the existing app-owned IOSArchive controller, not a second owner. */
export function IOSSigningInputsCheck({ state, controller, controls, modes, projectName, onRefresh, onReadVersion,
  onCredentials, onSettings, onRecovery, refreshReason, versionReason }: {
  state: IOSArchiveState; controller: IOSArchiveController; controls: ReactNode; modes: ReactNode;
  projectName: string | null; onRefresh?: () => void; onReadVersion?: () => void;
  onCredentials?: () => void; onSettings?: () => void; onRecovery?: () => void;
  refreshReason: string | null; versionReason: string | null;
}) {
  const project = state.project, op = state.status?.operation;
  const consent = state.consent?.binding.context.operation === 'ios-signing-inputs-check' ? state.consent : null;
  const prepareReason = controller.prepareReason(), startReason = controller.startReason();
  const phase = op && { 'awaiting-consent': 'Waiting for your approval', starting: 'Starting', running: 'Checking inputs', stopping: 'Stopping and cleaning up', terminal: 'Finished', unknown: 'Needs attention' }[op.phase];
  return <section className="card offline-preflight" aria-label="Check existing iOS signing inputs">
    <SectionHeading title="Check existing iOS signing inputs" description="Check whether your assigned P12, password and App Store profile agree with this saved app."><Badge tone="info">No build or Store call</Badge></SectionHeading>
    {modes}
    <p>Selected saved project: <strong>{projectName ?? 'No project selected'}</strong>{project?.signingInput && <> · Bundle ID <code>{project.signingInput.bundleId}</code></>}.</p>
    <p>Uses your assigned P12/password and primary App Store profile{project?.signingInput?.firebaseRequired ? ', plus the required iOS Firebase file' : ''}. No Xcode project or scheme is needed. It does not run project code, install signing files or contact Apple.</p>
    {project?.dirtyDraft && <p className="review-caution">Save or revert your unsaved edits before checking. This action does neither automatically.</p>}
    {state.signing.issue && <p className="review-caution">{state.signing.issue}</p>}
    {project?.savedVersion && <p>Saved version {project.savedVersion.name} · build {project.savedVersion.build}.</p>}
    <div className="button-row">
      {onRefresh && <button type="button" className="button secondary small" disabled={!project || !!refreshReason || project.snapshotPending} onClick={() => { if (project) controller.snapshotIntent(project.projectId); onRefresh(); }}>Refresh saved configuration</button>}
      {onReadVersion && <button type="button" className="button secondary small" disabled={!project || !!versionReason || project.versionPending} onClick={() => { controller.versionIntent(); onReadVersion(); }}>Read saved version</button>}
      {onCredentials && <button type="button" className="button secondary small" onClick={onCredentials}>Choose signing inputs</button>}
      {onSettings && <button type="button" className="button secondary small" onClick={onSettings}>Review signing settings</button>}
    </div>
    {refreshReason && <p className="save-note">Configuration: {refreshReason}</p>}{versionReason && <p className="save-note">Version: {versionReason}</p>}
    {project?.inputIssue && <p className="review-caution">{project.inputIssue}</p>}
    {!consent && <><button type="button" className="button" disabled={prepareReason !== null} onClick={() => void controller.prepare()}>Review signing-input check</button>{prepareReason && <p className="review-caution">{prepareReason}</p>}</>}
    {consent && <div className="session-review" role="group" aria-label="Approve this signing-input check">
      <h3>Check these existing inputs once?</h3>
      <p>Project {consent.binding.context.projectId}. This review expires in one minute. Changing inputs requires a new review.</p>
      <label className="offline-ack"><input type="checkbox" checked={consent.acknowledged} onChange={(event) => controller.setAcknowledged(consent.operationId, consent.ownerGeneration, event.target.checked)} /><span>Check these selected private inputs once, including temporary local files and their cleanup. Do not build, install signing files, contact a Store or retry automatically.</span></label>
      <button type="button" className="button" disabled={startReason !== null} onClick={() => void controller.start(consent.operationId, consent.ownerGeneration)}>Check existing signing inputs</button>
      {startReason && <p className="review-caution">{startReason}</p>}
    </div>}
    {state.error && <ErrorNotice error={state.error} title="No new signing-input result was confirmed" />}
    {state.originalUnconfirmed && <p className="review-caution">The request has not been confirmed. Use Status or Cancel; do not start it again.</p>}
    {op && <div className="session-progress" role="status"><p>{op.context.projectId} · {phase}.</p><p>{iosArchiveReasonText[op.reason]}</p>
      {!isIOSSigningCheckOperation(op) && <p>An earlier archive or recovery still needs attention. Use its Status and Cancel controls below.</p>}
      {isIOSSigningCheckOperation(op) && op.activity && op.outcome !== 'complete' && <ul>{op.activity.findings.map((row) => <li key={row.check}>{iosArchiveFindingText[row.check]} · {row.status}</li>)}</ul>}
    </div>}
    {controls}
    {onRecovery && <button type="button" className="button secondary small" onClick={onRecovery}>Open local recovery</button>}
    <details><summary>Setup and safety details</summary>
      <p>In Credentials, choose this saved project with iOS · Candidate / internal testing · Build / signing only. Select, assess, keep and separately assign the P12/password and primary App Store profile{project?.signingInput?.firebaseRequired ? ', plus the required iOS Firebase file' : ''}. Format assessment and inventory counts are not this signing check.</p>
      {project?.signingPolicy && <><p>Saved Apple Team ID: <code>{project.signingPolicy.teamId}</code>.</p><p>Distribution certificate SHA-256: <code>{project.signingPolicy.distributionCertificateSha256}</code>.</p></>}
      {state.signing.policy && <ul>{state.signing.policy.assignments.map((row) => <li key={row.kind}>{row.kind} · record revision {row.recordRevision} · context revision {row.contextRevision}</li>)}</ul>}
      <p>The existing iOS owner borrows the exact private inputs, account/project leases and private validation scratch. It never borrows the project-read token or creates certificates, profiles or credential assignments. Original cleanup and native joins must finish before another operation.</p>
      <p>Started checks remain app-owned across pages. Unknown cleanup stays blocked; closing this view or reconnecting cannot reset it. A separately qualified check-only native capability is required; signed-export qualification cannot enable it.</p>
    </details>
    <IOSSigningInputsResult state={state} />
  </section>;
}
