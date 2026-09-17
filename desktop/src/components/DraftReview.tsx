import { reviewFresh } from '../drafts.ts';
import type { ProjectSession } from '../drafts.ts';
import { valueSummary } from '../preparation.ts';
import type { Catalog, HelpContent } from '../types.ts';
import { Badge, HelpButton, Issues, SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';

export const reviewHelp: HelpContent = {
  label: 'Review draft changes', requiredness: 'optional',
  requiredWhen: 'Available with an in-memory draft and a compatible core preparation capability.',
  what: 'Compare the current draft with its retained JSON baseline and inspect core-derived field context and format validation.',
  why: 'Make intentional choices about conflicts and known-field changes without losing hidden or dependent edits.',
  where: 'Use Review draft changes after editing. Refresh records a separate observation; it does not replace your draft baseline.',
  format: 'A pure JSON comparison. Summaries show known field paths, operations, presence, types and collection counts—not raw values. No baseline means a proposed new configuration, not observed file absence.',
  failure: 'Stale or partial results cannot describe a complete current review. No result is a save plan, file revision, write token, identity approval or release authorization.',
};

interface ReviewProps {
  session: ProjectSession;
  catalog: Catalog;
  onRemoveForbidden: (reviewId: number, paths: string[]) => void;
  onHelp: (help: HelpContent) => void;
}

export function DraftReview({ session, catalog, onRemoveForbidden, onHelp }: ReviewProps) {
  if (!session.review) return null;
  const { result, binding } = session.review;
  const fresh = reviewFresh(session);
  const comparison = result.comparison;
  const conflicts = result.fields.filter((field) => field.state === 'forbidden' && field.present);
  const unknown = result.fields.filter((field) => field.state === 'unknown').length;
  const missing = result.fields.filter((field) => field.state === 'required' && !field.present).length;
  const label = (path: string) => catalog.fields.find((field) => field.path === path)?.label ?? 'Configuration structure';
  return <section className="card draft-review" aria-live="polite">
    <SectionHeading title={fresh ? 'Review the draft, not the filesystem.' : 'This review describes an earlier draft'} description="Nothing was read from or written to project files by this comparison. A review cannot authorize saving.">
      <Badge tone={fresh ? 'info' : 'warning'}>{fresh ? 'Current draft · retained baseline' : 'Review is stale'}</Badge>
    </SectionHeading>
    {!fresh && <div className="notice notice-warning"><Icon name="info" size={18} /><p>Draft or baseline changed after this request. Review again for current field context; removal choices below are disabled.</p></div>}
    <div className="review-basis"><Icon name="shield" size={18} /><div><strong>{comparison.baseProvided ? 'Compared with the retained draft baseline' : 'Proposed new configuration; file existence not checked'}</strong><p>{comparison.baseProvided ? 'The baseline is an earlier JSON observation, not a disk revision. Object key order is ignored; raw bytes, number spelling, formatting, file identity and current disk state are not compared.' : 'A missing comparison base does not mean a configuration file is absent, safe to create or safe to replace.'}</p></div></div>
    {session.sourceChanged && <p className="review-caution">A newer observation differs from this retained baseline. Your draft has not been rebased, merged or discarded.</p>}
    <div className="review-counts" aria-label="Known-field change counts"><span><strong>{comparison.counts.added}</strong> added</span><span><strong>{comparison.counts.changed}</strong> changed</span><span><strong>{comparison.counts.removed}</strong> removed</span><Badge tone={comparison.state === 'partial' ? 'warning' : 'neutral'}>{comparison.state === 'partial' ? 'Partial comparison' : 'Known-field comparison complete'}</Badge></div>
    {comparison.state === 'partial' && <div className="notice notice-warning"><Icon name="info" size={18} /><div><strong>Some data is outside the known-field review</strong><p>{comparison.unreviewedCount} changed unsupported locations are not individually shown. Their names and values are omitted, not discarded from the draft. The listed changes are not a complete review.</p></div></div>}
    {comparison.changes.length > 0 ? <div className="review-table-wrap"><table className="review-table"><caption className="sr-only">Known configuration changes. Raw values are omitted.</caption><thead><tr><th scope="col">Known field</th><th scope="col">Change</th><th scope="col">Before</th><th scope="col">Draft</th></tr></thead><tbody>{comparison.changes.map((change) => <tr key={change.path}><th scope="row"><span>{label(change.path)}</span><code>{change.path}</code></th><td><Badge tone={change.operation === 'remove' ? 'warning' : 'neutral'}>{change.operation}</Badge></td><td>{valueSummary(change.before)}</td><td>{valueSummary(change.after)}</td></tr>)}</tbody></table></div> : <p className="review-empty">{comparison.semanticallyChanged ? 'No changed known fields are listed; review the partial-comparison warning.' : 'No semantic changes were reported. This does not establish identical file bytes or a safe save.'}</p>}
    <div className="review-section-heading"><h3>Core field context</h3><HelpButton content={reviewHelp} onHelp={onHelp} /></div>
    <p className="review-description">{conflicts.length} present fields conflict with their controllers · {missing} required fields are not set · {unknown} field contexts are unknown. Empty values can still fail validation.</p>
    {conflicts.length > 0 && <div className="context-conflicts"><p>Changing a controller did not delete any dependent values. Keep editing, or explicitly unset these listed fields; an undo copy stays in this project’s memory.</p><ul>{conflicts.map((field) => <li key={field.path}><div><strong>{label(field.path)}</strong><code>{field.path}</code><p>{field.reason}</p></div><button className="button small secondary" type="button" disabled={!fresh} onClick={() => onRemoveForbidden(binding.id, [field.path])}>Unset field</button></li>)}</ul>{conflicts.length > 1 && <button className="button secondary" type="button" disabled={!fresh} onClick={() => onRemoveForbidden(binding.id, conflicts.map((field) => field.path))}>Unset all {conflicts.length} listed fields</button>}</div>}
    <details className="context-details"><summary>{fresh ? 'Inspect all field contexts' : 'Inspect earlier field contexts'} ({result.fields.length})</summary><ul>{result.fields.map((field) => <li key={field.path}><div className="context-detail-title"><code>{field.path}</code><Badge tone={field.state === 'forbidden' || field.state === 'unknown' ? 'warning' : 'neutral'}>{field.state}</Badge><span>{field.present ? 'Present' : 'Not set'}</span></div><p>{field.reason}</p></li>)}</ul></details>
    <div className="review-section-heading"><h3>{result.validation.valid ? 'Format-valid only' : 'Format validation needs attention'}</h3><Badge tone={result.validation.valid ? 'info' : 'danger'}>{result.validation.state}</Badge></div>
    <Issues issues={result.validation.issues} />
    <div className="subtle-note"><Icon name="lock" size={15} />Values and commands remain draft text. No native tools, credentials, Git, Store state or release readiness were verified. Save and all mutation actions remain unavailable.</div>
  </section>;
}
