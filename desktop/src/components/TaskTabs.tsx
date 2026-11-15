import { useEffect, useId, useState } from 'react';
import type { ReactNode } from 'react';
import { flushSync } from 'react-dom';

export type TaskTab = { id: string; label: string; summary: string; content: ReactNode; attention?: boolean; running?: boolean };

const REVEAL_EVENT = 'mrk-task-tab-reveal';

/** Switch to the tab that holds `element`, then focus and scroll to it. */
export function revealTaskSection(element: HTMLElement | null) {
  const holder = element?.closest<HTMLElement>('[data-task-tab]');
  if (holder) window.dispatchEvent(new CustomEvent(REVEAL_EVENT, { detail: { group: holder.dataset.taskGroup, tab: holder.dataset.taskTab } }));
  element?.focus({ preventScroll: true }); element?.scrollIntoView({ block: 'start' });
}

/**
 * One task at a time. Every panel stays mounted (hidden when inactive), so
 * operation status and controls are never lost by switching tabs.
 */
export function TaskTabs({ label, tabs, initial }: { label: string; tabs: TaskTab[]; initial?: string }) {
  const group = useId();
  const [tab, setTab] = useState(() => initial ?? tabs.find((t) => t.attention)?.id ?? tabs[0]!.id);
  useEffect(() => {
    const reveal = (event: Event) => {
      const detail = (event as CustomEvent<{ group?: string; tab?: string }>).detail;
      if (detail.group === group && detail.tab && tabs.some((t) => t.id === detail.tab)) flushSync(() => setTab(detail.tab!));
    };
    window.addEventListener(REVEAL_EVENT, reveal);
    return () => window.removeEventListener(REVEAL_EVENT, reveal);
  }, [group, tabs]);
  const current = tabs.find((t) => t.id === tab) ?? tabs[0]!;
  const move = (step: number) => {
    const index = tabs.findIndex((t) => t.id === current.id);
    const next = tabs[(index + step + tabs.length) % tabs.length];
    if (!next) return;
    setTab(next.id); document.getElementById(`${group}-${next.id}-tab`)?.focus();
  };
  return <>
    <div className="task-tabs" role="tablist" aria-label={label}>
      {tabs.map((t) => <button key={t.id} type="button" role="tab" id={`${group}-${t.id}-tab`} aria-controls={`${group}-${t.id}`}
        aria-selected={current.id === t.id} tabIndex={current.id === t.id ? 0 : -1} className={`task-tab${current.id === t.id ? ' active' : ''}`}
        onClick={() => setTab(t.id)}
        onKeyDown={(event) => { if (event.key === 'ArrowRight' || event.key === 'ArrowLeft') { event.preventDefault(); move(event.key === 'ArrowRight' ? 1 : -1); } }}>
        <span>{t.label}</span>
        {t.attention ? <span className="task-tab-flag warning">Needs attention</span> : t.running ? <span className="task-tab-flag">Running</span> : null}
      </button>)}
    </div>
    <p className="task-summary">{current.summary}</p>
    {tabs.map((t) => <div key={t.id} role="tabpanel" id={`${group}-${t.id}`} aria-labelledby={`${group}-${t.id}-tab`}
      data-task-tab={t.id} data-task-group={group} hidden={current.id !== t.id} className="release-panel">{t.content}</div>)}
    {tabs.filter((t) => t.attention && t.id !== current.id).map((t) => <div key={t.id} className="notice notice-warning" role="status">
      <div><strong>{t.label} needs your attention</strong>
        <div className="button-row"><button type="button" className="button small secondary" onClick={() => setTab(t.id)}>Open {t.label}</button></div></div></div>)}
  </>;
}
