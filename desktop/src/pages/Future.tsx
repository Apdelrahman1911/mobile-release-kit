import type { ReactNode } from 'react';
import type { HelpContent } from '../types.ts';
import type { RetainedEditAttention } from '../drafts.ts';
import { EmptyState, HelpButton, PageHeading, SectionHeading } from '../components/Common.tsx';
import { Icon } from '../components/Icon.tsx';
import { revealTaskSection, TaskTabs } from '../components/TaskTabs.tsx';

export type ReleaseTab = 'check' | 'android' | 'ios' | 'store' | 'github' | 'results';

/** Kept for existing callers: reveal a section inside any task tab. */
export const revealReleaseSection = revealTaskSection;

export function Releases({ rehearsal, offlineChecks, androidBuild, iosArchive, evidence, storeOperations, storeNeedsAttention = false, protectedWorkflows, workflowNeedsAttention = false, running = {}, onOpenGitHub }: { rehearsal?: ReactNode; offlineChecks: ReactNode; androidBuild: ReactNode; iosArchive: ReactNode; evidence: ReactNode; storeOperations?: ReactNode; storeNeedsAttention?: boolean; protectedWorkflows?: ReactNode; workflowNeedsAttention?: boolean; running?: Partial<Record<ReleaseTab, boolean>>; onOpenGitHub: () => void }) {
  return <>
    <PageHeading eyebrow="BUILD & RELEASE" title="Build and release your app" description="Choose what you want to do. Building happens on this computer; anything that reaches a Store or GitHub asks for your approval first." />
    <TaskTabs label="Release tasks" tabs={[
      { id: 'check', label: 'Local checks', running: running.check, summary: 'Run your project’s saved checks on this computer. Nothing is built or published.', content: offlineChecks },
      { id: 'android', label: 'Android build', running: running.android, summary: 'Build an Android App Bundle from your saved settings, then inspect it. Nothing is published.', content: androidBuild },
      { id: 'ios', label: 'iOS build', running: running.ios, summary: 'Archive your iOS app with Xcode, then check it. Signing and export are separate choices.', content: iosArchive },
      { id: 'store', label: 'Store delivery', running: running.store, attention: storeNeedsAttention, summary: 'Check Store access, then prepare, upload or promote a build. Every Store step asks for its own approval.',
        content: <section id="release-store-operations" tabIndex={-1}>{storeOperations}</section> },
      { id: 'github', label: 'GitHub release', attention: workflowNeedsAttention, summary: 'Run a release through your repository’s GitHub workflows instead of this computer.', content: <>
        <section id="release-github-operations" tabIndex={-1}>{protectedWorkflows}</section>
        <section className="card"><EmptyState icon="github" title="See past GitHub releases" description="Open GitHub to connect your project and pick a release run to read. Missing results do not prove that no release happened, and past results do not show what is in the Store now."><button type="button" className="button secondary" onClick={onOpenGitHub}>Open GitHub history</button></EmptyState></section>
      </> },
      { id: 'results', label: 'Results', summary: 'Review saved build results, or continue from an earlier result instead of starting again.', content: <>{evidence}{rehearsal}</> },
    ]} />
  </>;
}

const editAttentionHelp: HelpContent = {
  label: 'Retained file-edit alerts', requiredness: 'conditional',
  what: 'A settings, workflow, public-text, or saved-version save previously reported that its file transaction needs recovery.',
  why: 'Keeping this alert visible prevents a later operation or project switch from hiding that earlier problem.',
  where: 'These alerts come from edit results already observed in this app session. No journal or remote service is inspected by this list.',
  format: 'Nothing to enter here. A loaded project can be opened in its usual editor; text/version editors offer a separate explicit Inspect recovery and frozen confirmation. Navigation itself neither inspects nor repairs files.',
  requiredWhen: 'When an earlier file edit reported recovery was required. Keep the original files and evidence; use the original status controls for an active operation.',
  failure: 'An empty list, changing projects, or restarting the app does not prove that files are clean or a retry is safe. These file-edit alerts are not assessed by project build-input recovery.',
};

export function Recovery({ projectRecovery, attention, choosingProject, onOpenProject, onHelp, evidenceGuidance, onOpenReleases }: {
  projectRecovery: ReactNode;
  evidenceGuidance: ReactNode;
  onOpenReleases?: () => void;
  attention: readonly RetainedEditAttention[];
  choosingProject: boolean;
  onOpenProject: (attention: RetainedEditAttention) => void;
  onHelp: (help: HelpContent) => void;
}) {
  return <>
    <PageHeading eyebrow="RECOVER WORK" title="Check interrupted work safely" description="If a task stopped part-way, find out what actually happened before you try again. Nothing here repeats or undoes a step on its own." />
    {evidenceGuidance}
    {projectRecovery}
    {onOpenReleases && <section className="card"><SectionHeading title="Protected workflow request recovery" description="Reconcile an exact release request or prepare the core’s existing evidence-based same-step recovery. This is separate from local project recovery and does not prove Store state." /><button type="button" className="button secondary" onClick={onOpenReleases}>Open original release requests</button></section>}
    <div className="notice notice-warning"><Icon name="shield" /><div><strong>Other recovery remains unassessed</strong><p>The build-input action above does not recover file edits, signing accounts or Store operations. The retained alerts below are earlier file-edit observations, not a fresh journal inspection or an assessment of current local or remote operations. Use the public-text or saved-version editor’s explicit Inspect recovery only after original native settlement; complete matching journals may then offer one separately confirmed action. This screen does not establish that a project is clean or an operation can safely be retried.</p></div></div>
    <section className="card">
      <SectionHeading title="File-edit alerts from this session" description="Earlier alerts stay visible after unrelated edits. Only a matching successful same-domain recovery can clear that domain’s alert; original active or uncertain operations keep their status controls.">
        <HelpButton content={editAttentionHelp} onHelp={onHelp} />
      </SectionHeading>
      {attention.length === 0
        ? <EmptyState compact icon="recovery" title="No retained file-edit attention observed in this session" description="This is not a clean-state check. Earlier sessions, journals and remote operations have not been assessed." />
        : <ul className="plain-list">{attention.map((item, index) => <li key={`${item.page}:${item.projectId}`}>
          <Icon name="shield" size={17} /><div>
            <strong>{item.projectName ?? 'Project not loaded in this window'}</strong>
            <p>{item.domain}: recovery was required by an earlier edit. Files have not been rechecked.</p>
            {item.page === 'metadata' && <p>This alert does not retain a specific locale or file outcome.</p>}
            <div className="button-row"><button type="button" className="button small secondary"
              disabled={item.projectName === null || choosingProject} aria-describedby={`edit-attention-${index}`}
              onClick={() => onOpenProject(item)}>Open {item.domain.toLowerCase()}</button></div>
            <p id={`edit-attention-${index}`}>{item.projectName === null
              ? 'Navigation is unavailable because the original project is not loaded here. Its alert remains retained.'
              : choosingProject ? 'Finish choosing a project before navigating.'
                : 'Opens the existing editor without discarding drafts. Text/version recovery requires a separate explicit inspection and confirmation; navigation never recovers files.'}</p>
          </div>
        </li>)}</ul>}
    </section>
    <p className="review-caution">Text/version recovery cannot infer missing original context from legacy or incomplete journals. Keep public files, private journal names/contents, original operation details and unsaved drafts. Do not delete or rename controls, force an edit, use generic init --recover, or repeatedly retry a conflict; obtain manual reconciliation assistance.</p>
    <p className="review-caution">Cancelling saved checks or an Android build cannot undo effects already performed by project code. A retained work folder is not a successful artifact or a safe retry. Project admission refusal does not establish a recoverable signing session or distinguish busy ownership from recovery need. Keep the original operation and its status. The build-input flow does not inspect or clean retained artifact folders or signing accounts.</p>
    <section className="card"><SectionHeading title="For other interrupted operations" /><ul className="plain-list"><li><Icon name="shield" size={17} /><span>Do not infer a safe retry from a missing desktop record.</span></li><li><Icon name="box" size={17} /><span>Keep original files, artifacts, and existing release evidence intact.</span></li><li><Icon name="github" size={17} /><span>Check the actual protected workflow or Store operation before considering another mutation.</span></li></ul></section>
  </>;
}
