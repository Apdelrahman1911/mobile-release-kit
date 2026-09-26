import type { ReactNode } from 'react';
import type { AppInfo, HelpContent } from '../types.ts';
import type { RetainedEditAttention } from '../drafts.ts';
import { futureReason } from '../certainty.ts';
import { DisabledAction, EmptyState, HelpButton, PageHeading, SectionHeading } from '../components/Common.tsx';
import { Icon } from '../components/Icon.tsx';

export function Releases({ info, offlineChecks, androidBuild, iosArchive, evidence }: { info: AppInfo | null; offlineChecks: ReactNode; androidBuild: ReactNode; iosArchive: ReactNode; evidence: ReactNode }) {
  return <>
    <PageHeading eyebrow="RELEASES" title="One candidate. A traceable journey." description="Inspect saved release documents, then review local checks, Android builds and unsigned iOS archives separately. Protected workflow dispatch is not available here." />
    {evidence}
    {offlineChecks}
    {androidBuild}
    {iosArchive}
    <section className="card"><EmptyState icon="rocket" title="Authenticated release history is not loaded" description="A selected local folder is not authenticated or global history. Missing desktop records do not mean the project has never released."><DisabledAction label="Create release candidate" icon="rocket" reason={futureReason(info?.capabilities, 'release.candidate', 'Protected GitHub dispatch and authenticated release history are not implemented.')} /></EmptyState></section>
  </>;
}

const editAttentionHelp: HelpContent = {
  label: 'Retained file-edit alerts', requiredness: 'conditional',
  what: 'A settings, workflow, public-text, or saved-version save previously reported that its file transaction needs recovery.',
  why: 'Keeping this alert visible prevents a later operation or project switch from hiding that earlier problem.',
  where: 'These alerts come from edit results already observed in this app session. No journal or remote service is inspected by this list.',
  format: 'Nothing to enter. A loaded project can be opened in its usual editor; this does not reopen the original result or repair files.',
  requiredWhen: 'When an earlier file edit reported recovery was required. Keep the original files and evidence; use the original status controls for an active operation.',
  failure: 'An empty list, changing projects, or restarting the app does not prove that files are clean or a retry is safe. These file-edit alerts are not assessed by project build-input recovery.',
};

export function Recovery({ projectRecovery, attention, choosingProject, onOpenProject, onHelp, evidenceGuidance }: {
  projectRecovery: ReactNode;
  evidenceGuidance: ReactNode;
  attention: readonly RetainedEditAttention[];
  choosingProject: boolean;
  onOpenProject: (attention: RetainedEditAttention) => void;
  onHelp: (help: HelpContent) => void;
}) {
  return <>
    <PageHeading eyebrow="RECOVERY" title="An interruption shouldn’t leave you guessing." description="Recovery must know what really happened, preserve original ownership, and never mistake partial success for a clean restart." />
    {evidenceGuidance}
    {projectRecovery}
    <div className="notice notice-warning"><Icon name="shield" /><div><strong>Other recovery remains unassessed</strong><p>The build-input action above does not recover file edits, signing accounts or Store operations. The retained alerts below are earlier file-edit observations, not a fresh journal inspection or an assessment of current local or remote operations. This screen does not establish that a project is clean or an operation can safely be retried.</p></div></div>
    <section className="card">
      <SectionHeading title="File-edit alerts from this session" description="Earlier alerts stay visible even after another edit replaces the latest result. Original active or uncertain operations keep their existing status controls.">
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
                : 'Opens the existing editor without discarding drafts. It does not recover files or reopen the original outcome.'}</p>
          </div>
        </li>)}</ul>}
    </section>
    <p className="review-caution">Cancelling saved checks or an Android build cannot undo effects already performed by project code. A retained work folder is not a successful artifact or a safe retry. Project admission refusal does not establish a recoverable signing session or distinguish busy ownership from recovery need. Keep the original operation and its status. The build-input flow does not inspect or clean retained artifact folders or signing accounts.</p>
    <section className="card"><SectionHeading title="For other interrupted operations" /><ul className="plain-list"><li><Icon name="shield" size={17} /><span>Do not infer a safe retry from a missing desktop record.</span></li><li><Icon name="box" size={17} /><span>Keep original files, artifacts, and existing release evidence intact.</span></li><li><Icon name="github" size={17} /><span>Check the actual protected workflow or Store operation before considering another mutation.</span></li></ul></section>
  </>;
}
