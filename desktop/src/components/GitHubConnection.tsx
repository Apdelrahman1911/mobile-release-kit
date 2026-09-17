// Guidance-only mount has an absent native port and null status. No credential
// input, live bridge, remote HTML, URL navigation, avatar or browser fallback.
import { useId } from 'react';
import type { HelpContent } from '../types.ts';
import type { GitHubConnectionHelpEntry, GitHubConnectionViewState, GitHubFact } from '../githubConnectionTypes.ts';
import type { GitHubConnectionController } from '../githubConnectionController.ts';
import { GITHUB_CONNECTION_REASON_HELP } from '../githubConnectionProtocol.ts';
import { Badge, HelpButton, SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';

function helpContent(entry: GitHubConnectionHelpEntry & { requiredness?: 'required' | 'conditional' }): HelpContent {
  return { label: entry.label, requiredness: entry.requiredness ?? 'conditional', requiredWhen: 'Before a separately qualified GitHub connection.',
    what: entry.what, why: entry.why, where: entry.where, format: entry.format, failure: entry.failure };
}
function FactLabel({ fact, retained }: { fact: GitHubFact<unknown>; retained: boolean }) {
  return <p className="save-note"><Badge>{retained && fact.value ? 'stale · retained observation' : fact.state}</Badge>
    {fact.observedAt && <> Observed at <time dateTime={fact.observedAt}>{fact.observedAt}</time>.</>}
    {fact.reason !== 'none' && <> {GITHUB_CONNECTION_REASON_HELP[fact.reason]}</>}</p>;
}

export function GitHubConnection({ state, controller, onHelp }: {
  state: GitHubConnectionViewState; controller: GitHubConnectionController; onHelp: (help: HelpContent) => void;
}) {
  const reasonId = useId(); const repositoryId = useId();
  const status = state.status ?? state.retained;
  const retained = !state.status || state.retirementPending || state.uncertain || state.blocked || state.error !== null;
  const account = status?.account.value; const repository = status?.repository.value; const automation = status?.automation.value;
  return <>
    <section className="card" aria-label="GitHub connection and observations">
      <SectionHeading title="GitHub connection / observations" description="Separate from local workflow files. Account and Actions metadata are not release readiness.">
        <Icon name="github" size={24} />
      </SectionHeading>
      <div className="notice notice-info" role="status"><Icon name="shield" size={18} /><div>
        <strong>Credential entry remains unavailable</strong>
        <p id={reasonId}>This source increment has no token collection or live connection route. Preferred App/device login and the original native owner/TLS profile require separate qualification. No project credential asset is reused.</p>
      </div></div>
      <label htmlFor={repositoryId}>Explicit application repository</label>
      <input id={repositoryId} type="text" disabled value={state.context?.repository ?? ''} placeholder="OWNER/REPO" aria-describedby={reasonId} />
      <p className="save-note">This is not the toolkit repository, a Git remote or an authentication field. Do not paste credentials here.</p>
      {state.helpState !== 'current' && <p className="review-caution" role="status">{state.helpState === 'previous' ? 'Previously loaded help is retained for reading only; it does not enable entry.' : 'Core connection help is unavailable; entry remains disabled.'}</p>}
      {state.help && <div className="button-row" aria-label="Core GitHub connection help">
        {[...state.help.inputs, ...state.help.guidance].map((entry) => <span key={entry.id}>{entry.label} <HelpButton content={helpContent(entry)} onHelp={onHelp} /></span>)}
      </div>}
      {state.error && <p className="review-caution" role="status">{GITHUB_CONNECTION_REASON_HELP[state.error]}</p>}
      {status && <>
        <p className="save-note">{retained ? 'Retained / stale original status' : 'Original native status'} · revision {status.revision}. {status.session ? <>Session <code>{status.session.id}</code>, project <code>{status.session.projectId}</code>, target <code>{status.session.targetRepository}</code>: {status.session.state}.</> : 'No retained native session.'}</p>
        {status.session?.expiresAt && <p className="save-note">Reported expiry <time dateTime={status.session.expiresAt}>{status.session.expiresAt}</time>. Display information only; native deadlines decide admission.</p>}
        <h3>Account</h3><FactLabel fact={status.account} retained={retained} />
        {account && <p><strong>{account.login}</strong> · immutable account ID <code>{account.id}</code></p>}
        <h3>Application repository</h3><FactLabel fact={status.repository} retained={retained} />
        {repository && <dl className="github-facts">
          <div><dt>Repository / immutable ID</dt><dd>{repository.fullName} · <code>{repository.id}</code></dd></div>
          <div><dt>Default branch</dt><dd><code>{repository.defaultBranch}</code></dd></div>
          <div><dt>Visibility / archived</dt><dd>{repository.visibility} / {repository.archived ? 'yes' : 'no'}</dd></div>
          {(['pull', 'push', 'admin'] as const).map((role) => <div key={role}><dt>Reported {role} role</dt><dd>{repository.permissions[role]}</dd></div>)}
        </dl>}
        <p className="save-note">Reported roles are not effective token grants or authorization for any mutation.</p>
        <h3>Actions workflow metadata</h3><FactLabel fact={status.automation} retained={retained} />
        {automation && <div className="review-table-wrap"><table className="review-table">
          <caption>{automation.coverage} bounded coverage; not a Git file or template check</caption>
          <thead><tr><th scope="col">Core workflow ID</th><th scope="col">Presence</th><th scope="col">State</th><th scope="col">Remote ID</th></tr></thead>
          <tbody>{automation.workflows.map((row) => <tr key={row.id}><th scope="row">{row.id}</th><td>{row.presence}</td><td>{row.state}</td><td>{row.remoteId ?? 'not observed'}</td></tr>)}</tbody>
        </table></div>}
        <p className="save-note">Not-listed means only not returned by a complete bounded listing. Repository Actions settings/policy, environments, secrets, variables, protections and runners have not been observed.</p>
      </>}
      <div className="button-row">
        <button type="button" className="button secondary" disabled aria-describedby={reasonId}><Icon name="key" size={17} />Connect · unavailable</button>
        <button type="button" className="button secondary" disabled={state.mode !== 'native' || state.observing} onClick={() => void controller.checkStatus()}><Icon name="refresh" size={17} />Read retained Status</button>
        <button type="button" className="button secondary" disabled={!controller.canRefresh()} onClick={() => controller.refresh()}>Refresh observation</button>
        <button type="button" className="button secondary" disabled={!controller.canDisconnect()} onClick={() => controller.disconnect()}>Disconnect original session</button>
      </div>
      <p className="save-note">Busy rejects new Connect/Refresh, not retained Status or exact-session Disconnect. A lost reply is not permission to retry. Disconnect requests local retirement, not remote revocation, native settlement or credential erasure.</p>
    </section>
    <section className="card" aria-label="Remote GitHub setup unavailable">
      <SectionHeading title="Remote setup — unavailable" description="Local workflow Apply does not push files or grant remote authority."><Icon name="lock" size={22} /></SectionHeading>
      <p>No remote mutations or workflow dispatch. Template compatibility and release readiness remain unknown. The existing core requirements and protected-environment checklist remain manual/unknown and independent of login.</p>
    </section>
  </>;
}
