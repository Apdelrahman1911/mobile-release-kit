import type { Page } from '../types.ts';
import { Icon } from './Icon.tsx';
import type { IconName } from './Icon.tsx';

export const workspacePages: Record<Page, { label: string; icon: IconName; hint: string }> = {
  dashboard: { label: 'Overview', icon: 'dashboard', hint: 'Where your app stands and what to do next' },
  releases: { label: 'Build & release', icon: 'rocket', hint: 'Build, check and deliver a release' },
  metadata: { label: 'Store listing', icon: 'metadata', hint: 'Store text and images' },
  credentials: { label: 'Signing & accounts', icon: 'key', hint: 'Signing keys and Store accounts' },
  settings: { label: 'Project settings', icon: 'settings', hint: 'App name, IDs and release settings' },
  environment: { label: 'Build tools', icon: 'environment', hint: 'Check the tools on this computer' },
  github: { label: 'GitHub', icon: 'github', hint: 'Repository, workflows and history' },
  artifacts: { label: 'Build files', icon: 'box', hint: 'Inspect a built app package' },
  recovery: { label: 'Recover work', icon: 'recovery', hint: 'Check interrupted tasks safely' },
  automation: { label: 'Automation', icon: 'terminal', hint: 'Let a command-line tool run approved steps' },
};

const sections: { label: string | null; pages: Page[] }[] = [
  { label: null, pages: ['dashboard'] },
  { label: 'Release', pages: ['releases', 'metadata', 'credentials'] },
  { label: 'Project', pages: ['settings', 'environment', 'github'] },
  { label: 'More', pages: ['artifacts', 'recovery', 'automation'] },
];

/** Navigation only: choosing a page never starts an operation or changes a draft. */
export function WorkspaceNavigation({ page, onNavigate, attention = {} }:
  { page: Page; onNavigate: (page: Page) => void; attention?: Partial<Record<Page, boolean>> }) {
  const item = (target: Page) => <button type="button" key={target} title={workspacePages[target].hint}
    className={`nav-item${target === page ? ' active' : ''}`}
    aria-current={target === page ? 'page' : undefined} onClick={() => onNavigate(target)}>
    <Icon name={workspacePages[target].icon} size={18} /><span>{workspacePages[target].label}</span>
    {attention[target] && <span className="nav-attention" role="img" aria-label="needs attention" />}
  </button>;
  return <nav aria-label="Workspace navigation">
    {sections.map((section) => <div className="nav-group" key={section.label ?? 'start'}>
      {section.label && <span className="nav-group-label">{section.label}</span>}
      {section.pages.map(item)}
    </div>)}
  </nav>;
}
