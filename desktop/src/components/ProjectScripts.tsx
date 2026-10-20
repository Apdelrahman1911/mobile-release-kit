import { useId, useState } from 'react';
import { PROJECT_SCRIPT_STAGES, prepareProjectScriptEdit, projectScriptHelp, projectScriptsView,
  projectScriptStageHelp, projectScriptStageLabels, projectScriptStatusHelp } from '../projectScripts.ts';
import type { ProjectScriptContext, ProjectScriptEdit, ProjectScriptStage } from '../projectScripts.ts';
import type { HelpContent } from '../types.ts';
import { HelpButton, SectionHeading } from './Common.tsx';

interface Props { context: ProjectScriptContext; onAdd: (edit: ProjectScriptEdit) => boolean; onHelp: (help: HelpContent) => void }
// Local selections only. Mounting, changing a stage or reading hints never
// starts a process, saves settings or changes a native operation's consent.
export function ProjectScripts({ context, onAdd, onHelp }: Props) {
  const id = useId();
  const [choice, setChoice] = useState<{ context: ProjectScriptContext; candidate: string; stage: ProjectScriptStage | '' } | null>(null);
  const [notice, setNotice] = useState<{ projectId: string; message: string } | null>(null);
  const view = projectScriptsView(context);
  const current = choice?.context.session === context.session && choice?.context.service === context.service &&
    choice?.context.catalog === context.catalog && choice?.context.epoch === context.epoch;
  const candidate = current ? choice!.candidate : '', stage = current ? choice!.stage : '';
  const source = view.discovery?.candidates.find((row) => row.path === candidate);
  const prepared = stage && candidate ? prepareProjectScriptEdit(context, candidate, stage) : null;
  const reason = view.reason ?? prepared?.reason ?? (!candidate ? 'Choose a script you have reviewed.' : !stage ? 'Choose when it should run.' : null);
  const field = stage ? context.catalog?.fields.find((item) => item.path === stage) : undefined;
  const change = (nextCandidate: string, nextStage: ProjectScriptStage | '') => {
    setChoice({ context, candidate: nextCandidate, stage: nextStage });
    setNotice(null);
  };
  return <section className="card form-card" aria-labelledby={`${id}-heading`}>
    <div id={`${id}-heading`}><SectionHeading title="Optional: use an existing project script"
      description="Review the file in your editor, then choose a stage. Adding it here changes only this draft.">
      <HelpButton content={projectScriptHelp} onHelp={onHelp} />
    </SectionHeading></div>
    {view.reason && <p className="toolbar-reason" role="status">{view.reason}</p>}
    {view.discovery && view.discovery.candidates.length === 0 && <p className="subtle-note">No conventional shell scripts were found in this bounded read. Extra scripts are optional. For other paths or layouts, use the command fields in Advanced.</p>}
    {view.discovery && view.discovery.candidates.length > 0 && <>
      <div className="form-grid">
        <label className="field"><span>Existing script</span><select value={candidate} onChange={(event) => change(event.target.value, '')}>
          <option value="">Choose a script…</option>{view.discovery.candidates.map((row) => <option key={row.path} value={row.path}>{row.path}</option>)}
        </select></label>
        <label className="field"><span>When to run it{field && <HelpButton content={field} onHelp={onHelp} />}</span>
          <select value={stage} onChange={(event) => change(candidate, event.target.value as ProjectScriptStage | '')}>
            <option value="">Choose a stage…</option>{PROJECT_SCRIPT_STAGES.map((value) => <option key={value} value={value}>{projectScriptStageLabels[value]}</option>)}
          </select>
        </label>
      </div>
      {source && <p className="context-refresh-note">The name suggests {source.purposeHint === 'prepare' ? 'preparation' : source.purposeHint === 'check' ? 'a check' : 'a build'}, not verified behavior. {projectScriptStatusHelp[source.status]}</p>}
      {stage && <p className="context-refresh-note">{projectScriptStageHelp[stage]}</p>}
      {prepared?.edit && <div className="review-caution"><strong>Add this direct command:</strong> <code>{`./${candidate}`}</code>
        <p>{stage === 'ios.prepareCommand' ? 'Adds an iOS preparation command without replacing one.' : 'Appends one command. Every existing command stays in order.'} No extra arguments, shell wrapper or permissions are added.</p>
      </div>}
      <div className="button-row"><button type="button" className="button secondary" disabled={!prepared?.edit || reason !== null}
        aria-describedby={`${id}-reason`} onClick={() => {
          if (!prepared?.edit || reason !== null || !context.session) return;
          const added = onAdd(prepared.edit);
          setNotice({ projectId: context.session.project.id, message: added ? 'Draft updated. Nothing was saved or run. Review & save… below when ready.' : 'The project or draft changed. Your newer values were kept; choose the script and stage again.' });
        }}>Add to draft</button></div>
      <p id={`${id}-reason`} className="toolbar-reason">{reason ?? 'Use the existing Review & save… action below before this command can become a saved setting. Later execution requires a separate operation approval.'}</p>
    </>}
    {notice?.projectId === context.session?.project.id && <p role="status">{notice?.message}</p>}
  </section>;
}
