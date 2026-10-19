import { useId, useState } from 'react';
import type { Page } from '../types.ts';
import { Icon } from './Icon.tsx';
import type { IconName } from './Icon.tsx';

export const workspacePages: Record<Page, { label: string; icon: IconName }> = {
  dashboard: { label: 'Home', icon: 'dashboard' },
  settings: { label: 'Project settings', icon: 'settings' },
  environment: { label: 'Build tools', icon: 'environment' },
  credentials: { label: 'Signing & accounts', icon: 'key' },
  metadata: { label: 'Store listing', icon: 'metadata' },
  github: { label: 'GitHub', icon: 'github' },
  releases: { label: 'Build & release', icon: 'rocket' },
  artifacts: { label: 'Build files', icon: 'box' },
  recovery: { label: 'Recover interrupted work', icon: 'recovery' },
};

const groups = {
  setup: { label: 'Project setup', icon: 'settings', pages: ['settings', 'environment', 'credentials'] },
  more: { label: 'Files & recovery', icon: 'recovery', pages: ['artifacts', 'recovery'] },
} as const;

/** Navigation only: expanding a section never starts an operation or changes a draft. */
export function WorkspaceNavigation({ page, onNavigate }: { page: Page; onNavigate: (page: Page) => void }) {
  const id = useId();
  const [expanded, setExpanded] = useState({ setup: false, more: false });
  const item = (target: Page) => <button type="button" key={target}
    className={`nav-item${target === page ? ' active' : ''}`}
    aria-current={target === page ? 'page' : undefined} onClick={() => onNavigate(target)}>
    <Icon name={workspacePages[target].icon} size={19} /><span>{workspacePages[target].label}</span>
  </button>;
  const group = (key: keyof typeof groups) => {
    const section = groups[key];
    const selected = section.pages.some((target) => target === page);
    // A link from Home, a recovery notice or another view must always reveal
    // its selected navigation item, irrespective of the previous disclosure.
    const open = selected || expanded[key];
    return <div className="nav-disclosure">
      <button type="button" className="nav-item nav-disclosure-toggle" aria-expanded={open}
        aria-controls={`${id}-${key}`} aria-disabled={selected || undefined}
        title={selected ? 'The current section stays open while you use it.' : undefined}
        onClick={() => { if (!selected) setExpanded((previous) => ({ ...previous, [key]: !previous[key] })); }}>
        <Icon name={section.icon} size={19} /><span>{section.label}</span>
        <Icon name={open ? 'down' : 'chevron'} size={14} />
      </button>
      <div id={`${id}-${key}`} className="nav-disclosure-pages" hidden={!open}>
        {section.pages.map(item)}
      </div>
    </div>;
  };
  return <nav aria-label="Workspace navigation">
    <div className="nav-group">{item('dashboard')}{group('setup')}</div>
    <div className="nav-group">
      <span className="nav-group-label">WHEN YOU'RE READY</span>
      {item('releases')}{item('metadata')}{item('github')}
    </div>
    {group('more')}
  </nav>;
}
