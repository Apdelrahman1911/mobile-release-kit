import type { HelpContent } from '../types.ts';
import type { CandidateEvidence, CandidateEvidenceController, EvidenceView } from '../candidateEvidence.ts';
import { EVIDENCE_ASSURANCE, evidenceHelp, evidenceProblemText } from '../candidateEvidence.ts';
import { Badge, ErrorNotice, HelpButton, PageHeading, SectionHeading } from '../components/Common.tsx';
import { Icon } from '../components/Icon.tsx';

const outcomes = {
  consistent: { title: 'Documents agree', detail: 'Formats, canonical self-digests and candidate bindings agree under the core rules. This is not authenticated provenance or a release approval.' },
  incomplete: { title: 'Some documents are missing', detail: 'A complete candidate summary cannot be shown. Missing local documents do not mean that a release or Store operation never happened.' },
  invalid: { title: 'A document needs attention', detail: 'At least one document is malformed, unsupported, or has an invalid self-digest. Keep the originals; obtain the original complete final evidence rather than editing a digest by hand.' },
  inconsistent: { title: 'The documents do not agree', detail: 'The individual document formats and self-digests are valid, but their candidate bindings do not agree. Do not combine evidence from different candidates.' },
} as const;
const documentNames = { manifest: 'candidate-manifest.json', receipt: 'candidate-receipt.json', intent: 'operation/candidate-operation-intent.json' };
const artifactNames: Record<string, string> = {
  'android-aab': 'Android App Bundle', 'android-mapping': 'Android mapping', 'android-native-symbols': 'Android native symbols',
  'ios-ipa': 'iOS package', 'ios-archive': 'iOS archive', 'ios-dsyms': 'iOS debug symbols', 'store-metadata': 'Store metadata', 'validation-report': 'Validation report',
};

function EvidenceResult({ value, onHelp }: { value: CandidateEvidence; onHelp: (help: HelpContent) => void }) {
  const outcome = outcomes[value.outcome]; const summary = value.summary;
  return <>
    <SectionHeading title={outcome.title} description={outcome.detail}><Badge tone={value.outcome === 'consistent' ? 'info' : 'warning'}>Documents only</Badge></SectionHeading>
    <ul className="plain-list">{value.documents.map((document) => <li key={document.kind}>
      <code>{documentNames[document.kind]}</code>
      <Badge tone={document.state === 'valid' ? 'info' : 'warning'}>{document.state === 'valid' ? 'Format + self-digest valid' : document.state === 'missing' ? 'Missing' : 'Invalid'}</Badge>
    </li>)}</ul>
    {summary && <>
      <SectionHeading title="Declared candidate identity" description="Read from the manifest, not compared with your project or the Stores."><HelpButton content={evidenceHelp.summary} onHelp={onHelp} /></SectionHeading>
      <dl className="help-definitions">
        <div><dt>Platform</dt><dd>{summary.platform === 'android' ? 'Android' : 'iOS'}</dd></div>
        <div><dt>Application ID</dt><dd><code>{summary.applicationId}</code></dd></div>
        <div><dt>Version / build</dt><dd>{summary.version.marketing} / {summary.version.build}</dd></div>
        <div><dt>Source commit</dt><dd><code>{summary.source.commit}</code></dd></div>
        <div><dt>Source tree</dt><dd><code>{summary.source.tree}</code></dd></div>
      </dl>
      <SectionHeading title="Declared artifacts" description="No artifact file is opened, measured or hashed by this inspector."><HelpButton content={evidenceHelp.artifacts} onHelp={onHelp} /></SectionHeading>
      <ul className="plain-list">{summary.artifacts.map((artifact) => <li key={artifact.logicalName}><div>
        <strong>{artifactNames[artifact.logicalName]}</strong><p>Declared size: <code>{artifact.declaredBytes}</code> bytes</p>
        <p>Declared SHA-256: <code>{artifact.sha256}</code></p>
      </div></li>)}</ul>
      <SectionHeading title="Manifest-recorded runs" description="These are unauthenticated declarations, not live workflow status."><HelpButton content={evidenceHelp.runs} onHelp={onHelp} /></SectionHeading>
      <dl className="help-definitions">{(['authorizedBy', 'executedBy', 'producedBy'] as const).map((role) => <div key={role}>
        <dt>Manifest records {role === 'authorizedBy' ? 'authorization' : role === 'executedBy' ? 'execution' : 'production'}</dt>
        <dd>Run <code>{summary.recordedRuns[role].runId}</code> · attempt <code>{summary.recordedRuns[role].attempt}</code></dd>
      </div>)}</dl>
      <SectionHeading title="Canonical document payload digests" description="These are self-integrity digests, not raw-file hashes or signatures."><HelpButton content={evidenceHelp.digests} onHelp={onHelp} /></SectionHeading>
      <dl className="help-definitions">{(['manifest', 'receipt', 'intent'] as const).map((kind) => <div key={kind}>
        <dt>{kind}</dt><dd><code>{summary.documentPayloadSha256[kind]}</code></dd>
      </div>)}</dl>
    </>}
  </>;
}

export function Artifacts({ state, controller, projectName, onHelp }: {
  state: EvidenceView; controller: CandidateEvidenceController; projectName: string | null; onHelp: (help: HelpContent) => void;
}) {
  const status = state.status; const reason = controller.startReason();
  const active = status !== null && ['choosing', 'observing', 'stopping'].includes(status.phase);
  const stopping = state.cancelling || status?.phase === 'stopping';
  const current = !state.pending && !state.uncertain && !state.integrityFailed ? status?.result : null;
  const canCancel = state.mode === 'native' && !state.integrityFailed && !state.cancelling && status?.operation && (active || status.phase === 'unknown');
  return <>
    <PageHeading eyebrow="ARTIFACTS" title="Understand your saved candidate evidence." description="Choose an existing final-evidence folder. The core checks three documents without changing your project, original files or Store state." />
    <div className="notice notice-warning"><Icon name="shield" /><div><strong>{EVIDENCE_ASSURANCE}</strong><p>No artifact bytes, signing, GitHub authenticity, Store state, release readiness or recovery safety are established here.</p></div></div>
    <section className="card">
      <SectionHeading title="Evidence folder" description="Separate from the source project. No files need to be copied or renamed."><HelpButton content={evidenceHelp.folder} onHelp={onHelp} /></SectionHeading>
      <p><strong>Source project:</strong> {projectName ?? 'None selected'} <span className="muted">· unchanged by evidence selection</span></p>
      <p><strong>Evidence folder:</strong> {status?.selection?.displayName ?? 'Not selected'}</p>
      <div className="button-row">
        <button type="button" className="button secondary" disabled={reason !== null} aria-describedby="evidence-start-reason" onClick={() => void controller.choose()}><Icon name="folder" size={17} />Choose evidence folder</button>
        <button type="button" className="button primary" disabled={reason !== null || !status?.selection} aria-describedby="evidence-start-reason" onClick={() => void controller.observe()}><Icon name="box" size={17} />Inspect documents</button>
        <button type="button" className="button secondary" disabled={state.mode !== 'native' || state.checking || state.integrityFailed} onClick={() => void controller.check()}>{state.checking ? 'Checking status…' : 'Check operation status'}</button>
        {canCancel && <button type="button" className="button secondary" onClick={() => void controller.cancel()}>Request stop</button>}
      </div>
      <p id="evidence-start-reason" className="subtle-note">{reason ?? (status?.selection ? 'Ready to inspect the fixed documents. This does not authorize a release or retry.' : 'Choose the retained final-evidence folder to begin. Originals stay in place and are read only.')}</p>
      <div role="status" aria-live="polite">
        {stopping ? <p>Stopping; waiting for the original operation to settle. No successful observation is confirmed.</p>
          : active || state.pending ? <p>{status?.phase === 'choosing' || state.pending === 'choose' ? 'Waiting for the native evidence-folder picker…' : 'Checking the three evidence documents…'}</p> : null}
        {status?.phase === 'cancelled' && <p>Original operation cancelled and settled. No new result was accepted.</p>}
        {status?.problem && status.problem !== 'unavailable' && <p>{evidenceProblemText(status.problem)}</p>}
      </div>
      {state.error && <ErrorNotice error={state.error} title="No current evidence result was accepted" />}
    </section>
    {current && <section className="card"><EvidenceResult value={current} onHelp={onHelp} /></section>}
    {!current && state.stale && <section className="card">
      <details><summary>Previous observation · stale · {state.stale.selection.displayName}</summary>
        <p className="review-caution">Historical display only. It is not the current selection or observation and cannot authorize any action.</p>
        <EvidenceResult value={state.stale.result} onHelp={onHelp} />
      </details>
    </section>}
    {!current && !state.stale && <section className="card"><SectionHeading title="No current document observation" description="An empty view does not mean a candidate was never released or that recovery is safe. Existing release evidence remains unchanged." /></section>}
  </>;
}
