import { diagnosticsAvailabilityText } from '../environmentDiagnosticsController.ts';
import type { EnvironmentDiagnosticsController, EnvironmentDiagnosticsState } from '../environmentDiagnosticsController.ts';
import type { EnvironmentCheckId, EnvironmentCheckReason, EnvironmentDiagnosticsProjection } from '../environmentDiagnosticsTypes.ts';
import { Badge, ErrorNotice, SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';

const labels: Record<EnvironmentCheckId, string> = {
  'developer-selection': 'macOS developer selection', git: 'Git version', java: 'Java runtime version', javac: 'Java compiler version', xcode: 'Xcode version and build',
};
const reasons: Record<EnvironmentCheckReason, string> = {
  'invalid-draft': 'Invalid configuration draft', 'platform-disabled': 'Target disabled in the draft', 'host-mismatch': 'Host does not support this target',
  'unsupported-host': 'Unsupported host profile', 'missing-in-supported-lookup': 'Not found in the supported lookup',
  'unsupported-installation': 'Installation outside the supported policy', 'unselected-installation': 'No unambiguous supported installation selected',
  'full-xcode-not-selected': 'Full Xcode is not selected', stopped: 'Not run before STOP', 'command-incomplete': 'Command did not complete',
  'binding-changed': 'Admitted installation changed', cancelled: 'Cancellation observed', 'timed-out': 'Deadline observed', observed: 'Version / selection observed',
  'nonzero-exit': 'Complete command returned a nonzero exit', 'version-unrecognized': 'Complete output did not match the version format',
  'selection-unrecognized': 'Complete output did not match the selection format',
};
function StateBadges({ row }: { row: EnvironmentDiagnosticsProjection }) {
  return <div className="button-row"><Badge>Phase: {row.phase}</Badge><Badge>Outcome: {row.outcome ?? 'not reported'}</Badge>
    <Badge tone={row.finality === 'settled' ? 'info' : 'warning'}>Native finality: {row.finality}</Badge></div>;
}

export function EnvironmentDiagnostics({ state, controller, compact = false, loading = false, onShow }: {
  state: EnvironmentDiagnosticsState; controller: EnvironmentDiagnosticsController; compact?: boolean; loading?: boolean; onShow?: () => void;
}) {
  const attempt = state.attempt;
  const active = state.status?.active ?? (attempt?.projection?.finality === 'pending' ? attempt.projection : null);
  const unconfirmed = attempt !== null && attempt.projection === null;
  const unknown = state.nativeBlocked || state.integrityFailed || state.generationLost;
  if (compact && !active && !unconfirmed && !unknown && !state.observationIssue) return null;
  const claim = state.cancelClaimed;
  const cancelClaimed = Boolean(active && claim && claim.runId === active.runId && claim.ownerGeneration === active.ownerGeneration);
  const canCancel = state.mode === 'native' && active?.finality === 'pending' && !cancelClaimed;
  const reason = controller.startReason();
  const observation = state.observation;
  const result = observation?.projection.result ?? null;
  return <section className="card" aria-label={compact ? 'Retained build-tool diagnostics owner' : 'Observed build-tool checks'} aria-busy={active?.finality === 'pending'}>
    <SectionHeading title={compact ? 'Build-tool diagnostics owner' : 'Observed build-tool checks'}
      description={compact ? 'The original native run remains owned outside the Environment page.' : 'Separate from expected requirements. Only an explicit check requests local tool-version commands.'} />
    {!compact && <>
      <p>Startup and all work share a <strong>6-second work limit</strong>. The original native owner has a fixed <strong>10-second total finality cutoff</strong> from admission, including cleanup. Each call gets at most 3 seconds within that shared budget. A slow tool may be incomplete or time out; this is not the full CLI doctor.</p>
      <p className="save-note">At most four commands, with 16 KiB aggregate stdout + stderr per command. No builds, Gradle or wrapper commands, project hooks, SDK inventory, repository queries, signing, credential access, installations, license acceptance, report files or network actions are requested. Administratively trusted host tools can still have OS or tool-cache effects; this is not a malware sandbox.</p>
    </>}
    <div className="button-row">
      {!compact && <button type="button" className="button primary" disabled={loading || reason !== null} onClick={() => controller.start()}><Icon name="environment" size={17} />Check build tools</button>}
      <button type="button" className="button secondary" disabled={!canCancel} onClick={() => { if (active) controller.cancel({ runId: active.runId, ownerGeneration: active.ownerGeneration }); }}><Icon name="close" size={17} />{cancelClaimed ? 'Cancel requested' : 'Cancel observed run'}</button>
      <button type="button" className="button secondary" disabled={state.mode !== 'native' || state.readPending} onClick={() => void controller.checkStatus()}><Icon name="refresh" size={17} />{state.readPending ? 'Reading status…' : 'Read native status'}</button>
      {compact && onShow && <button type="button" className="button secondary" onClick={onShow}>Show Environment</button>}
    </div>
    {!compact && <p className="save-note">{reason ?? diagnosticsAvailabilityText.available}</p>}
    {!compact && state.status && <p className="save-note">Native capability: {state.status.capability.reason} · status revision {state.status.statusRevision}. {state.status.capability.available ? 'Availability is not a tool result.' : diagnosticsAvailabilityText[state.status.capability.reason]}</p>}
    {state.mode === 'preview' && <p>Browser design preview — example requirements only. There is no diagnostics fixture, native owner or observed host here.</p>}
    {unconfirmed && <div className="notice notice-warning" role="status"><Icon name="clock" /><div><strong>{attempt.startPending ? 'Start reply pending' : 'Start reply unconfirmed'}</strong><p>A missing reply is neither a refused run nor a completed check. Read native status to recover the original run; no replacement Start or automatic retry is sent.</p></div></div>}
    {attempt?.projection && !attempt.acknowledged && <p className="review-caution">This run was observed in native status, not acknowledged by the Start reply. It is not proof that this call was accepted. Cancel acts only on the displayed native run; changing this view alone will not adopt or cancel an unacknowledged run.</p>}
    {active && <><StateBadges row={active} /><p className="save-note">{active.context.projectId === state.project?.projectId ? 'Selected project' : 'Another original project'} · {active.context.platform === 'ios' ? 'iOS' : 'Android'} / build · original draft {active.context.draftRevision} · baseline {active.context.baselineGeneration} · native reason: {active.reason}.</p>
      {active.phase === 'stopping' && <p role="status">Stopping / settling the original run. A completed core frame or a Cancel reply does not establish native resource settlement.</p>}</>}
    {unknown && <div className="notice notice-warning" role="alert"><Icon name="shield" /><div><strong>Original finality or status integrity is unknown</strong><p>Keep the application open. The native owner and any original resources remain retained. Conflicting work and normal exit cannot be enabled by a UI timer, reconnect, context change or late cleanup. A later resource settlement does not turn this run into success.</p></div></div>}
    {state.observationIssue && <p className="review-caution">Native status is not current. Earlier rows are historical; use Read native status, not another Check build tools request. A missing event listener requires an explicit connection reload.</p>}
    {state.error && <ErrorNotice error={state.error} title="Diagnostics status needs attention" />}
    {!compact && observation && result && <>
      <SectionHeading title={observation.stale ? 'Earlier / stale tool observations' : 'Tool observations from this run'}
        description={`${result.context.platform === 'ios' ? 'iOS' : 'Android'} / build · draft ${result.context.draftRevision} · baseline ${result.context.baselineGeneration} · core host ${result.hostPlatform}`} />
      <StateBadges row={observation.projection} />
      <p className="save-note">Received by this view: {new Date(observation.receivedAt).toLocaleString()} · native status revision {observation.statusRevision} · {observation.provenance === 'acknowledged-start' ? 'acknowledged original Start' : 'native-status observation; Start acknowledgment not established'}. Receipt time is not a native deadline or a fresh probe.</p>
      {observation.stale && <p className="review-caution">These rows belong to an earlier or unconfirmed project, draft, selection, activity or connection context. Returning to the same project does not refresh them.</p>}
      {observation.projection.finality === 'pending' && <p className="review-caution">Core result received; native settlement is still pending. These observations do not free the native slot.</p>}
      <p><strong>Complete means the finite check roster finished, not that every tool matched.</strong> Dependency completeness and release readiness remain unknown.</p>
      <div className="environment-requirements">{result.checks.map((row) => <article className="tool-card" key={row.id}>
        <h3>{labels[row.id]}</h3><div className="button-row"><Badge>{row.state}</Badge><Badge tone={row.assessment === 'mismatch' ? 'warning' : 'neutral'}>{row.assessment}</Badge></div>
        <p>{reasons[row.reason]}</p>
        <dl className="environment-baseline"><dt>Observed version</dt><dd>{row.version ?? 'Not assessed'}{row.build && ` · build ${row.build}`}</dd>
          <dt>{row.baseline.kind === 'workflow-reference' ? 'Workflow reference · not a local compatibility rule' : row.baseline.kind === 'exact-pin' ? 'Expected exact core baseline · not the observation' : 'No local version policy'}</dt>
          <dd>{row.baseline.version ?? 'No version requirement inferred'}{row.baseline.build && ` · build ${row.baseline.build}`}</dd>
          {row.returnCode !== null && <><dt>Complete command exit code</dt><dd>{row.returnCode}</dd></>}
        </dl>
        <details><summary>What this check covers</summary><p>{row.help}</p></details>
      </article>)}</div>
      <p className="save-note">Missing in the fixed supported lookup does not mean globally absent. Custom and per-user installations are outside this slice. A Java runtime/compiler version does not prove project, Gradle, Android SDK or signing compatibility.</p>
      <details><summary>Core resource observations — provisional, not native finality</summary>
        <p>The following immutable core report remains distinct from the native phase, outcome and finality above.</p>
        <dl className="environment-baseline"><dt>Core outcome</dt><dd>{result.outcome}</dd><dt>Commands attempted</dt><dd>{result.commandsAttempted}</dd>
          {Object.entries(result.lifetime).map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{value === null ? 'null' : String(value)}</dd></div>)}
        </dl>
      </details>
      <p className="save-note">Observation basis: {result.assurance.basis}. Project files/code, repository state, SDK completeness, credentials and Store access were not checked. OS/tool-cache effects: {result.assurance.toolCacheEffects}.</p>
    </>}
  </section>;
}
