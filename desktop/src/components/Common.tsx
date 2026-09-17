import { useEffect, useId, useRef } from 'react';
import type { ReactNode } from 'react';
import type { ApiError, HelpContent, Issue } from '../types.ts';
import type { Tone } from '../certainty.ts';
import { Icon } from './Icon.tsx';
import type { IconName } from './Icon.tsx';

export function Badge({ children, tone = 'neutral', dot = false }: { children: ReactNode; tone?: Tone; dot?: boolean }) {
  return <span className={`badge badge-${tone}`}>{dot && <span className="badge-dot" />}{children}</span>;
}

export function HelpButton({ content, onHelp }: { content: HelpContent; onHelp: (help: HelpContent) => void }) {
  return <button type="button" className="help-button" aria-label={`Help: ${content.label}`} onClick={() => onHelp(content)}>?</button>;
}

export function HelpDialog({ content, onClose }: { content: HelpContent | null; onClose: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  useEffect(() => {
    const element = dialog.current;
    if (content && element && !element.open) element.showModal();
    return () => { if (element?.open) element.close(); };
  }, [content]);
  if (!content) return null;
  return <dialog ref={dialog} className="help-dialog" aria-labelledby={titleId} onCancel={onClose} onClick={(event) => { if (event.target === event.currentTarget) onClose(); }}>
    <div className="dialog-content">
      <div className="dialog-heading"><span className="eyebrow">FIELD GUIDE</span><button autoFocus type="button" className="icon-button" aria-label="Close help" onClick={onClose}><Icon name="close" /></button></div>
      <h2 id={titleId}>{content.label}</h2>
      <Badge tone={content.requiredness === 'optional' ? 'neutral' : 'info'}>{content.requiredness}</Badge>
      <dl className="help-definitions">
        <div><dt>What is this?</dt><dd>{content.what}</dd></div>
        <div><dt>Why it matters</dt><dd>{content.why}</dd></div>
        <div><dt>Where to find it</dt><dd>{content.where}</dd></div>
        <div><dt>Expected format</dt><dd>{content.format}</dd></div>
        <div><dt>When it is needed</dt><dd>{content.requiredWhen}</dd></div>
        <div><dt>If it is missing or incorrect</dt><dd>{content.failure}</dd></div>
      </dl>
      <div className="subtle-note"><Icon name="shield" size={16} /><span>Help is local text. Project links, commands, and paths are never opened or executed from this panel.</span></div>
    </div>
  </dialog>;
}

export function ConfirmDialog({ onCancel, onConfirm, blockedReason = null, observationPredatesSave = false }: { onCancel: () => void; onConfirm: () => void; blockedReason?: string | null; observationPredatesSave?: boolean }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  useEffect(() => { const element = dialog.current; element?.showModal(); return () => element?.close(); }, []);
  return <dialog ref={dialog} className="confirm-dialog" aria-labelledby={titleId} onCancel={onCancel}>
    <div className="dialog-content"><h2 id={titleId}>Discard this in-memory draft?</h2><p>This project’s draft, review and retained undo copies will be discarded. Its latest static observation will become the draft and comparison baseline. That observation is not a current file revision. This action does not write files or close a native save session.</p>
      {observationPredatesSave && <p className="review-caution">That observation predates the last settled save check. Cancel and refresh first if you want a newer observation; this action does not fetch one.</p>}
      {blockedReason && <p className="review-caution" role="alert">{blockedReason}</p>}
      <div className="button-row"><button autoFocus className="button secondary" onClick={onCancel}>Keep editing</button><button className="button danger" disabled={blockedReason !== null} onClick={onConfirm}>Discard draft</button></div>
    </div>
  </dialog>;
}

export function ErrorNotice({ error, title = 'The operation was not completed' }: { error: ApiError; title?: string }) {
  return <div className="notice notice-danger" role="alert"><Icon name="info" /><div><strong>{title}</strong><p>{error.message}</p><span className="error-code">{error.code}</span></div></div>;
}

export function Issues({ issues }: { issues: Issue[] }) {
  if (issues.length === 0) return null;
  return <ul className="issues">{issues.map((issue, index) => <li key={`${issue.code}-${index}`}><Badge tone={issue.status === 'INVALID' ? 'danger' : 'warning'}>{issue.status === 'INVALID' ? 'Needs correction' : 'Incomplete'}</Badge><div><strong>{issue.message}</strong><p>{issue.remediation}</p><code>{issue.code}</code></div></li>)}</ul>;
}

export function EmptyState({ icon, title, description, children, compact = false }: { icon: IconName; title: string; description: string; children?: ReactNode; compact?: boolean }) {
  return <div className={`empty-state${compact ? ' compact' : ''}`}><div className="empty-icon"><Icon name={icon} size={27} /></div><h3>{title}</h3><p>{description}</p>{children}</div>;
}

export function DisabledAction({ label, reason, icon }: { label: string; reason: string; icon?: IconName }) {
  const id = useId();
  return <div className="disabled-action"><button type="button" className="button secondary" disabled aria-describedby={id}>{icon && <Icon name={icon} size={17} />}{label}<Icon name="lock" size={14} /></button><p id={id}>{reason}</p></div>;
}

export function PageHeading({ eyebrow, title, description, children }: { eyebrow: string; title: string; description: string; children?: ReactNode }) {
  return <div className="page-heading"><div><span className="eyebrow">{eyebrow}</span><h1>{title}</h1><p>{description}</p></div>{children && <div className="heading-actions">{children}</div>}</div>;
}

export function SectionHeading({ title, description, children }: { title: string; description?: string; children?: ReactNode }) {
  return <div className="section-heading"><div><h2>{title}</h2>{description && <p>{description}</p>}</div>{children}</div>;
}
