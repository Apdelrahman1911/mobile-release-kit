import type { HelpContent } from '../types.ts';
import type { LifecycleEvidence, LifecycleEvidenceController, LifecycleEvidenceView, EvidenceStage } from '../lifecycleEvidence.ts';
import { documentPaths, evidenceStages, releaseEvidenceHelp, SAVED_EVIDENCE_WARNING, stageLabels } from '../lifecycleEvidence.ts';
import { evidenceHelp, evidenceProblemText } from '../candidateEvidence.ts';
import { Badge, ErrorNotice, HelpButton, SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';

const outcomeLabels = { consistent: 'Documents agree', incomplete: 'Some documents are missing', invalid: 'A document needs attention', inconsistent: 'The documents do not agree' };
const artifactNames: Record<string, string> = {
  'android-aab': 'Android App Bundle', 'android-mapping': 'Android mapping', 'android-native-symbols': 'Android native symbols',
  'ios-ipa': 'iOS package', 'ios-archive': 'iOS archive', 'ios-dsyms': 'iOS debug symbols', 'store-metadata': 'Store metadata', 'validation-report': 'Validation report',
};
const runRoles = ['authorizedBy', 'executedBy', 'producedBy'] as const;
function RecordedRuns({ runs }: { runs: NonNullable<LifecycleEvidence['summary']>['recordedRuns'] }) {
  return <dl className="help-definitions">{runRoles.map((role) => <div key={role}>
    <dt>{role === 'authorizedBy' ? 'Recorded authorization' : role === 'executedBy' ? 'Recorded execution' : 'Recorded production'}</dt>
    <dd>Run <code>{runs[role].runId}</code> · attempt <code>{runs[role].attempt}</code></dd>
  </div>)}</dl>;
}
function EvidenceResult({ value, onHelp }: { value: LifecycleEvidence; onHelp: (help: HelpContent) => void }) {
  const summary = value.summary;
  return <>
    <SectionHeading title={outcomeLabels[value.outcome]} description={`${stageLabels[value.stage]} final folder · local document observation`}><Badge tone={value.outcome === 'consistent' ? 'info' : 'warning'}>Documents only</Badge></SectionHeading>
    <p><strong>Recovery guidance:</strong> {value.guidance.message}</p>
    {summary && <>
      <SectionHeading title="Declared candidate identity" description="Read from the manifest, not compared with your project or the Stores."><HelpButton content={evidenceHelp.summary} onHelp={onHelp} /></SectionHeading>
      <p>{summary.platform === 'android' ? 'Android' : 'iOS'} · <code>{summary.applicationId}</code> · version {summary.version.marketing} / build {summary.version.build}</p>
      <SectionHeading title="Stages recorded in this folder" description="Saved receipt declarations, not authenticated workflow or live Store history." />
      <ol className="plain-list">{value.history.map((row) => <li key={row.stage}><div>
        <strong>{stageLabels[row.stage]}</strong><p>Recorded outcome: <code>{row.recordedOutcome}</code> · recorded readback: <code>{row.recordedReadback}</code></p>
      </div></li>)}</ol>
    </>}
    {value.stage !== 'production-submit' && <p className="subtle-note">Not supplied: {evidenceStages.slice(evidenceStages.indexOf(value.stage) + 1).map((stage) => stageLabels[stage]).join(', ')}. These stages are not assessed.</p>}
    <details><summary>Document status and technical details</summary>
      <p>No artifact bytes, signing, GitHub authenticity, Store state, release readiness or recovery safety are established here. All six assurance flags remain false.</p>
      <ul className="plain-list">{value.documents.map((document) => <li key={document.path}>
        <code>{document.path}</code><Badge tone={document.state === 'valid' ? 'info' : 'warning'}>{document.state === 'valid' ? 'Format + self-digest valid' : document.state === 'missing' ? 'Missing' : 'Invalid'}</Badge>
      </li>)}</ul>
      {summary && <>
        <dl className="help-definitions"><div><dt>Declared source commit</dt><dd><code>{summary.source.commit}</code></dd></div><div><dt>Declared source tree</dt><dd><code>{summary.source.tree}</code></dd></div></dl>
        <SectionHeading title="Declared artifacts" description="No artifact file is opened, measured or hashed by this inspector."><HelpButton content={evidenceHelp.artifacts} onHelp={onHelp} /></SectionHeading>
        <ul className="plain-list">{summary.artifacts.map((artifact) => <li key={artifact.logicalName}><div>
          <strong>{artifactNames[artifact.logicalName]}</strong><p>Declared size: <code>{artifact.declaredBytes}</code> bytes</p><p>Declared SHA-256: <code>{artifact.sha256}</code></p>
        </div></li>)}</ul>
        <SectionHeading title="Manifest-recorded runs" description="These are unauthenticated declarations, not live workflow status."><HelpButton content={evidenceHelp.runs} onHelp={onHelp} /></SectionHeading>
        <RecordedRuns runs={summary.recordedRuns} />
        <SectionHeading title="Canonical document payload digests" description="These are self-integrity digests, not raw-file hashes or signatures."><HelpButton content={evidenceHelp.digests} onHelp={onHelp} /></SectionHeading>
        <dl className="help-definitions">{(['manifest', 'receipt', 'intent'] as const).map((kind) => <div key={kind}><dt>Candidate {kind}</dt><dd><code>{summary.documentPayloadSha256[kind]}</code></dd></div>)}</dl>
        {value.history.map((row) => <div key={row.stage}>
          <h3>{stageLabels[row.stage]} receipt declarations</h3><RecordedRuns runs={row.recordedRuns} />
          <dl className="help-definitions"><div><dt>Receipt payload SHA-256</dt><dd><code>{row.receiptSha256}</code></dd></div>
            <div><dt>Intent payload SHA-256</dt><dd><code>{row.intentSha256}</code></dd></div>
            <div><dt>Previous receipt payload SHA-256</dt><dd>{row.previousReceiptSha256 === null ? 'No predecessor at candidate stage' : <code>{row.previousReceiptSha256}</code>}</dd></div></dl>
        </div>)}
        <p className="subtle-note">Manifest and receipt run roles are kept separate. A recorded operator-authorized outcome does not grant this app recovery authority. Production checks compare repeated candidate document bytes, not the whole evidence inventory.</p>
      </>}
    </details>
  </>;
}
export function ReleaseEvidence({ state, controller, projectName, onHelp }: {
  state: LifecycleEvidenceView; controller: LifecycleEvidenceController; projectName: string | null; onHelp: (help: HelpContent) => void;
}) {
  const status = state.status; const reason = controller.startReason(); const observeReason = controller.observeReason();
  const stage = state.stage ?? 'candidate';
  const active = status !== null && ['choosing', 'observing', 'stopping'].includes(status.phase);
  const stopping = state.cancelling || status?.phase === 'stopping';
  const current = !state.pending && !state.uncertain && !state.integrityFailed ? status?.result : null;
  const canCancel = state.mode === 'native' && !state.integrityFailed && !state.cancelling && status?.operation && (active || status.phase === 'unknown');
  return <>
    <section className="card">
      <SectionHeading title="Saved release evidence" description="Inspect one selected final folder. Choosing evidence never saves or discards a project draft."><HelpButton content={releaseEvidenceHelp} onHelp={onHelp} /></SectionHeading>
      <p className="review-caution"><Icon name="shield" size={16} /> {SAVED_EVIDENCE_WARNING}</p>
      <p>{releaseEvidenceHelp.where}</p>
      <label className="field-label" htmlFor="release-evidence-stage">Evidence stage</label>
      <select id="release-evidence-stage" value={stage} disabled={reason !== null} onChange={(event) => controller.setStage(event.target.value as EvidenceStage)}>
        {evidenceStages.map((value) => <option key={value} value={value}>{stageLabels[value]}</option>)}
      </select>
      <p className="subtle-note">Expected at the top level: {documentPaths[stage].filter((path) => !path.includes('/')).map((path) => <code key={path}>{path} </code>)} · Keep the nested <code>operation/</code> folder.</p>
      <p><strong>Source project:</strong> {projectName ?? 'None selected'} <span className="muted">· unchanged by evidence selection</span></p>
      <p><strong>Evidence folder:</strong> {status?.selection ? `${status.selection.displayName} · ${stageLabels[status.selection.stage]}` : 'Not selected'}</p>
      <div className="button-row">
        <button type="button" className="button secondary" disabled={reason !== null} aria-describedby="evidence-start-reason" onClick={() => void controller.choose()}><Icon name="folder" size={17} />Choose evidence folder</button>
        <button type="button" className="button primary" disabled={observeReason !== null} aria-describedby="evidence-start-reason" onClick={() => void controller.observe()}><Icon name="box" size={17} />Inspect documents</button>
        <button type="button" className="button secondary" disabled={state.mode !== 'native' || state.checking || state.integrityFailed} onClick={() => void controller.check()}>{state.checking ? 'Checking status…' : 'Check operation status'}</button>
        {canCancel && <button type="button" className="button secondary" onClick={() => void controller.cancel()}>Request stop</button>}
      </div>
      <p id="evidence-start-reason" className="subtle-note">{reason ?? observeReason ?? 'Inspect the fixed saved documents when you want a new local observation. Original files stay in place and are read only.'}</p>
      <div role="status" aria-live="polite">
        {stopping ? <p>Stopping; waiting for the original operation to settle. No successful observation is confirmed.</p>
          : active || state.pending ? <p>{status?.phase === 'choosing' || state.pending === 'choose' ? 'Waiting for the native evidence-folder picker…' : 'Checking the selected evidence documents…'}</p> : null}
        {status?.phase === 'cancelled' && <p>Original operation cancelled and settled. No new result was accepted.</p>}
        {status?.problem && status.problem !== 'unavailable' && <p>{evidenceProblemText(status.problem)}</p>}
      </div>
      {state.error && <ErrorNotice error={state.error} title="No current evidence result was accepted" />}
    </section>
    {current && <section className="card"><EvidenceResult value={current} onHelp={onHelp} /></section>}
    {!current && state.stale && <section className="card"><details><summary>Previous observation · stale · {state.stale.selection.displayName}</summary>
      <p className="review-caution">Historical display only. It is not the current selection or observation and cannot authorize any action.</p>
      <EvidenceResult value={state.stale.result} onHelp={onHelp} />
    </details></section>}
    {!current && !state.stale && <section className="card"><SectionHeading title="No current document observation" description="An empty view does not mean a candidate was never released or that recovery is safe. Existing release evidence remains unchanged." /></section>}
  </>;
}
/** Read the SAME controller snapshot; navigation performs no inspection. */
export function ReleaseEvidenceGuidance({ state, onOpenEvidence }: { state: LifecycleEvidenceView; onOpenEvidence: () => void }) {
  const current = !state.pending && !state.uncertain && !state.integrityFailed ? state.status?.result : null;
  return <section className="card">
    <SectionHeading title="Guidance from saved release evidence" description="Shared with Releases and Artifacts. This view does not read any folder automatically." />
    <p className="review-caution">{SAVED_EVIDENCE_WARNING}</p>
    {current ? <><p><strong>{stageLabels[current.stage]} · {state.status?.selection?.displayName}</strong></p><p>{current.guidance.message}</p></>
      : <p>No current saved-document guidance. Project recovery remains unassessed.</p>}
    {!current && state.stale && <details><summary>Previous guidance · stale · {state.stale.selection.displayName}</summary><p>{state.stale.result.guidance.message}</p><p>Not a current recovery assessment.</p></details>}
    <button type="button" className="button secondary" onClick={onOpenEvidence}>Open saved evidence controls</button>
  </section>;
}
