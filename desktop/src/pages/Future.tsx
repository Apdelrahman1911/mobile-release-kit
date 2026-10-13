import type { ReactNode } from 'react';
import type { AppInfo, HelpContent } from '../types.ts';
import type { RetainedEditAttention } from '../drafts.ts';
import { futureReason } from '../certainty.ts';
import { DisabledAction, EmptyState, HelpButton, PageHeading, SectionHeading } from '../components/Common.tsx';
import { Icon } from '../components/Icon.tsx';

export function Releases({ info, offlineChecks, androidBuild, iosArchive, evidence, protectedWorkflows }: { info: AppInfo | null; offlineChecks: ReactNode; androidBuild: ReactNode; iosArchive: ReactNode; evidence: ReactNode; protectedWorkflows?: ReactNode }) {
  return <>
    <PageHeading eyebrow="RELEASES" title="One candidate. A traceable journey." description="Inspect saved release documents, review local checks, and separately prepare a protected release workflow when its installed runtime is qualified." />
    {protectedWorkflows}
    {evidence}
    {offlineChecks}
    {androidBuild}
    {iosArchive}
    <section className="card"><EmptyState icon="rocket" title="Authenticated release history is not loaded" description="A selected local folder is not authenticated or global history. Missing desktop records do not mean the project has never released."><DisabledAction label="Load authenticated release history" icon="rocket" reason={futureReason(info?.capabilities, 'release.history', 'Remote authenticated artifact history is not implemented. A workflow observation or a selected local folder is not authentication.')} /></EmptyState></section>
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
    <PageHeading eyebrow="RECOVERY" title="An interruption shouldn’t leave you guessing." description="Recovery must know what really happened, preserve original ownership, and never mistake partial success for a clean restart." />
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
