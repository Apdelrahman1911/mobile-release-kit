import { suggestionFresh } from '../drafts.ts';
import type { ProjectSession } from '../drafts.ts';
import type { HelpContent } from '../types.ts';
import { Badge, ErrorNotice, HelpButton, Issues, SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';

const suggestionHelp: HelpContent = {
  label: 'Prepare a suggested draft', requiredness: 'optional',
  requiredWhen: 'Only when this project has no in-memory draft and the core advertises pure suggestions.',
  what: 'Ask the bundled core for a proposed configuration from a small, closed set of static hints and documented defaults.',
  why: 'Provide a starting point without silently initializing files, approving identities or replacing an existing draft.',
  where: 'Prepare a suggestion, inspect its provenance and validation, then explicitly choose Use as an in-memory draft.',
  format: 'Only hinted platforms, singular unambiguous app identifiers, and version-source/key hints are projected. Missing platforms stay disabled and require an explicit decision. Default branches and example identities are not observations.',
  failure: 'Unverified, incomplete or malformed hints cannot establish a real application or Store identity. Suggestions create no files, workflows, metadata or version values. To save a draft, choose Prepare save review when native saving is available, then review and confirm the changes.',
};

interface SuggestionProps {
  session: ProjectSession;
  reason: string | null;
  onSuggest: () => void;
  onAdopt: (requestId: number) => void;
  onHelp: (help: HelpContent) => void;
}

export function DraftSuggestions({ session, reason, onSuggest, onAdopt, onHelp }: SuggestionProps) {
  const suggestion = session.suggestion;
  const fresh = suggestionFresh(session);
  const pending = session.suggestionRequest !== null;
  return <section className="card suggestion-card">
    <SectionHeading title="A starting point, never an automatic setup" description="The core can propose an in-memory configuration. Review its origins before choosing it; no existing file is replaced."><HelpButton content={suggestionHelp} onHelp={onHelp} /></SectionHeading>
    <div className="button-row"><button type="button" className="button secondary" disabled={reason !== null || pending || session.snapshotRequest !== null} onClick={onSuggest} aria-describedby="suggestion-reason"><Icon name={pending ? 'refresh' : 'settings'} className={pending ? 'spin' : ''} size={16} />{pending ? 'Preparing suggestion…' : suggestion ? 'Prepare a new suggestion' : 'Prepare suggested draft'}</button><Badge tone="neutral">No files created</Badge></div>
    <p id="suggestion-reason" className="suggestion-reason">{reason ?? (session.snapshotRequest ? 'Wait for the current static observation to settle.' : session.snapshot ? 'Uses only allowed static hints from the latest retained observation. Identity and discovery remain unverified.' : 'No project observation is available. This request uses no discovered hints and will not invent a platform.')}</p>
    {session.snapshotError && <p className="review-caution">The latest observation attempt failed. Any retained hints are from an earlier observation, not current discovery.</p>}
    {session.suggestionError && <ErrorNotice error={session.suggestionError} title="No new suggestion was prepared" />}
    {suggestion && <div className="suggestion-result" aria-live="polite">
      <div className="review-section-heading"><h3>{fresh ? 'Inspect the proposed defaults and hints' : 'An earlier suggestion is retained'}</h3><Badge tone={fresh ? 'info' : 'warning'}>{fresh ? 'Unverified suggestion' : 'Suggestion is stale'}</Badge></div>
      {!fresh && <p className="review-caution">The draft, baseline or observation changed. Prepare a new suggestion before adopting it.</p>}
      {!suggestion.binding.observedHints && <p className="review-caution">No project observation supplied these hints. Default paths and branches have not been checked against project files or Git.</p>}
      {suggestion.binding.partial && <p className="review-caution">The static observation was partial. A suggestion is not a complete discovery result.</p>}
      {suggestion.binding.omittedStrings > 0 && <p className="review-caution">{suggestion.binding.omittedStrings} unsupported or oversized hint values were omitted, never truncated or replaced with an inferred value. Inspect any core defaults or examples below.</p>}
      {suggestion.result.platformSelectionRequired && <div className="notice notice-warning"><Icon name="info" size={18} /><div><strong>No platform was supplied by the admitted hints</strong><p>Both platforms remain disabled. If you use this draft, explicitly choose your platforms and complete their fields. This is not a valid release configuration yet.</p></div></div>}
      <ul className="provenance-list">{suggestion.result.provenance.map((entry) => <li key={entry.path}><div><code>{entry.path}</code><Badge tone={entry.source === 'hint' ? 'info' : 'warning'}>{entry.source === 'hint' ? 'Unverified hint' : entry.source === 'example' ? 'Example only' : 'Core default'}</Badge></div><p>{entry.reason}</p></li>)}</ul>
      <p className="suggestion-reason">The paths above are configuration field names, not verified file locations. Suggested values become visible in editable controls only after your explicit choice below. Example identifiers must be reviewed and replaced where appropriate.</p>
      <Issues issues={suggestion.result.validation.issues} />
      <div className="suggestion-adopt"><button type="button" className="button primary" disabled={!fresh || pending || session.draft !== null} onClick={() => onAdopt(suggestion.binding.id)}>Use as an in-memory draft</button><span>{suggestion.result.validation.valid ? 'Format-valid only · identity and readiness unverified' : 'Needs correction · nothing initialized'}</span></div>
    </div>}
  </section>;
}
