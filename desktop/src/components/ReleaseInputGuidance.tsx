import { useId } from 'react';
import { RELEASE_INPUT_STAGES, releaseInputGroups, sessionPreparationKind } from '../releaseInputGuidance.ts';
import type { ReleaseInputGuidanceController, ReleaseInputGuidanceState, ReleaseInputPreparationTarget } from '../releaseInputGuidance.ts';
import type { HelpContent } from '../types.ts';
import { Badge, EmptyState, HelpButton, SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';

export function ReleaseInputGuidance({ state, controller, onGuide, onSettings, onHelp }: {
  state: ReleaseInputGuidanceState; controller: ReleaseInputGuidanceController;
  onGuide: (target: ReleaseInputPreparationTarget) => void; onSettings: () => void; onHelp: (help: HelpContent) => void;
}) {
  const stageId = useId(), reason = controller.startReason(), groups = releaseInputGroups(state);
  // A handler retained by an older render cannot reopen retired catalogue help.
  const currentHelp = (help: HelpContent) => { if (controller.getSnapshot() === state) onHelp(help); };
  return <section className="card release-input-guidance">
    <SectionHeading title="Prepare this release’s inputs" description="Full-purpose requirements from your current in-memory draft. This list does not read credentials, check their presence, save configuration, or establish release readiness." />
    <div className="release-input-controls">
      <label htmlFor={stageId}>Preparation stage<select id={stageId} value={state.stage} onChange={(event) => controller.setStage(event.target.value)}>{RELEASE_INPUT_STAGES.map((stage) => <option value={stage.id} key={stage.id}>{stage.label}</option>)}</select></label>
      <button type="button" className="button" disabled={reason !== null} onClick={() => void controller.refresh()}><Icon name="refresh" size={16} />{state.pending ? 'Reading draft requirements…' : 'Show current draft requirements'}</button>
      <button type="button" className="button secondary" onClick={onSettings}>Project settings</button>
    </div>
    <p className="release-input-scope">Stage only filters the core’s full-purpose result; it does not choose signing/store policy or change the draft. {state.project?.dirtyDraft ? 'Unsaved draft changes are included.' : 'This is not a new observation of saved project files.'}</p>
    {state.project?.snapshotFailed && <p className="review-caution" role="status">The project refresh failed. Any newly requested requirements describe only the retained in-memory draft; saved files were not re-observed.</p>}
    {state.project?.sourceChanged && <p className="review-caution">The project observation differs from the retained draft. This list describes the draft, not those saved files.</p>}
    {reason && <p className="review-caution" role="status">{reason}</p>}
    {state.notice && state.notice !== reason && <p className="review-caution" role="status">{state.notice}</p>}
    {state.result?.state === 'format-valid' && !state.pending && groups.length === 0 && <EmptyState compact icon="key" title="No requirements returned for this stage" description="The core returned no rows for this stage of this draft. This does not mean that inputs are present or that a release is ready." />}
    {groups.map((group) => <div className="release-input-group" key={group.platform}>
      <h3>{group.label}</h3><div className="release-input-rows">{group.rows.map((row) => <article className="release-input-row" key={`${row.requirement.name}-${row.requirement.stage}-${row.requirement.platform}`}>
        <div className="credential-row-heading"><div className="inline-heading"><h4>{row.requirement.name}</h4>{row.help && <HelpButton content={row.help} onHelp={currentHelp} />}</div><Badge>Required by this draft; presence not checked.</Badge></div>
        <div className="credential-meta"><span>{row.requirement.kind}</span><span>{row.requirement.environment}</span></div>
        <dl className="asset-guide-definitions"><div><dt>Why required in this draft</dt><dd>{row.requirement.reason}</dd></div>
          {row.help && <><div><dt>What it is</dt><dd>{row.help.what}</dd></div><div><dt>How / where to find it</dt><dd>{row.help.where}</dd></div><div><dt>Expected format</dt><dd>{row.help.format}</dd></div><div><dt>If unavailable or incorrect</dt><dd>{row.help.failure}</dd></div></>}
        </dl>
        {row.file && <p className="release-input-file">Core guide limits: {row.file.maxBytes} bytes maximum{row.file.suffixes.length > 0 ? `; suffixes ${row.file.suffixes.join(', ')}` : ''}. These are format instructions, not a check of your file.</p>}
        {row.requirement.alternatives.length > 0 && <p className="release-input-alternatives">Core-listed alternatives: {row.requirement.alternatives.join(' · ')}. These are alternatives, not extra mandatory inputs.</p>}
        {!row.help && <p className="review-caution">Detailed core guidance is unavailable for this requirement. The returned requirement remains listed; review Project settings or reconnect for compatible help.</p>}
        {row.guideId && <button type="button" className="button small secondary" onClick={() => {
          const target = controller.preparationTarget(state, row.requirement);
          if (target) onGuide(target);
        }}>{sessionPreparationKind(row.guideId) ? 'Open preparation guide' : 'Open reference guide'}</button>}
      </article>)}</div>
    </div>)}
    <p className="release-input-scope">Opening guidance never changes session context or selects, imports, validates, registers, stores or assigns private inputs. Supported guides offer a separate explicit continuation to the existing session controls. Those controls retain their own availability and original status; persistent vault storage and unsupported file pickers remain unavailable.</p>
  </section>;
}
