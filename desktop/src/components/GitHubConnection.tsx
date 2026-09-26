// The advanced input exists only behind the compiled and native-current gates.
// Its value never enters React/controller state, drafts or an async callback.
import { useId, useLayoutEffect, useRef } from 'react';
import type { HelpContent } from '../types.ts';
import type { GitHubConnectionHelpEntry, GitHubConnectionTokenHandoff, GitHubConnectionViewState, GitHubFact } from '../githubConnectionTypes.ts';
import type { GitHubConnectionController } from '../githubConnectionController.ts';
import { GITHUB_CONNECTION_ENTRY_AVAILABLE, GITHUB_CONNECTION_REASON_HELP, connectionRepository, sameConnectionData } from '../githubConnectionProtocol.ts';
import { Badge, HelpButton, SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';

function helpContent(entry: GitHubConnectionHelpEntry & { requiredness?: 'required' | 'conditional' }): HelpContent {
  return { label: entry.label, requiredness: entry.requiredness ?? 'conditional', requiredWhen: 'When connecting GitHub for read-only observations.',
    what: entry.what, why: entry.why, where: entry.where, format: entry.format, failure: entry.failure };
}
function FactLabel({ fact, retained }: { fact: GitHubFact<unknown>; retained: boolean }) {
  return <p className="save-note"><Badge>{retained && fact.value ? 'stale · retained observation' : fact.state}</Badge>
    {fact.observedAt && <> Observed at <time dateTime={fact.observedAt}>{fact.observedAt}</time>.</>}
    {fact.reason !== 'none' && <> {GITHUB_CONNECTION_REASON_HELP[fact.reason]}</>}</p>;
}

export function GitHubConnection({ state, controller, onHelp, repositoryInput, onRepository, projectSelected, handoff, nativeBusyReason = null }: {
  state: GitHubConnectionViewState; controller: GitHubConnectionController; onHelp: (help: HelpContent) => void;
  repositoryInput: string; onRepository: (value: string) => void; projectSelected: boolean;
  handoff: GitHubConnectionTokenHandoff | null;
  nativeBusyReason?: string | null;
}) {
  const reasonId = useId(); const repositoryId = useId(); const tokenId = useId();
  const tokenInput = useRef<HTMLInputElement>(null);
  const clearToken = () => { if (tokenInput.current) tokenInput.current.value = ''; };
  const entryReady = GITHUB_CONNECTION_ENTRY_AVAILABLE && handoff !== null && state.mode === 'native' && projectSelected &&
    state.helpState === 'current' && state.status?.capability.readOnlySessionAvailable === true && controller.canConnect();
  useLayoutEffect(() => {
    clearToken();
    const boundContext = state.context;
    const unlisten = controller.subscribe(() => {
      const next = controller.getSnapshot();
      // This runs synchronously on context/help/service/admission invalidation,
      // not one effect/render later. The captured context contains no secret.
      if (!GITHUB_CONNECTION_ENTRY_AVAILABLE || !handoff || !controller.canConnect() || !sameConnectionData(boundContext, next.context)) clearToken();
    });
    return () => { clearToken(); unlisten(); };
  }, [controller, handoff, state.context]);
  const status = state.status ?? state.retained;
  const retained = !state.status || state.retirementPending || state.uncertain || state.blocked || state.error !== null;
  const account = status?.account.value; const repository = status?.repository.value; const automation = status?.automation.value;
  const repositoryHelp = state.help?.inputs.find((entry) => entry.id === 'repository');
  const tokenHelp = state.help?.inputs.find((entry) => entry.id === 'token');
  return <>
    <section className="card" aria-label="GitHub connection and observations">
      <SectionHeading title="GitHub connection / observations" description="Separate from local workflow files. Account and Actions metadata are not release readiness.">
        <Icon name="github" size={24} />
      </SectionHeading>
      <div className="notice notice-info" role="status"><Icon name="shield" size={18} /><div>
        <strong>{entryReady ? 'Session-only, read-only GitHub connection' : 'Credential entry is not available now'}</strong>
        <p id={reasonId}>{!GITHUB_CONNECTION_ENTRY_AVAILABLE ? 'Advanced token entry is not qualified for this build. Safe Status and original-session retirement do not enable it.' :
          !projectSelected ? 'Select your application project first.' : !state.context ? 'Enter the explicit application repository below.' :
          state.helpState !== 'current' ? 'Reload current core guidance before entering a token.' :
          state.status && !state.status.capability.readOnlySessionAvailable ? GITHUB_CONNECTION_REASON_HELP[state.status.capability.reason] :
          entryReady ? 'Only account, repository and bounded Actions metadata are read. No Store access, repository writes or workflow dispatch.' :
          'An original session or uncertain operation is retained. Read its Status; retire it before making a new connection.'} No GitHub App registration is needed for a session-only token. App/device login remains separately unavailable. No project credential asset is reused.</p>
      </div></div>
      <div className="field-label-row"><label htmlFor={repositoryId}>{repositoryHelp?.label ?? 'Explicit application repository'}</label><Badge>Required for connection</Badge>
        {repositoryHelp && <HelpButton content={helpContent(repositoryHelp)} onHelp={onHelp} />}</div>
      <input id={repositoryId} type="text" disabled={!projectSelected} value={repositoryInput} onChange={(event) => onRepository(event.target.value)}
        placeholder="OWNER/REPO" maxLength={140} autoComplete="off" autoCapitalize="none" spellCheck={false} aria-describedby={`${repositoryId}-help`} />
      <p id={`${repositoryId}-help`} className="save-note">{repositoryHelp?.what ?? 'The GitHub repository containing your mobile application.'} Find OWNER/REPO in its GitHub URL, without https://github.com/ or .git. This is not the toolkit repository and is never guessed from a Git remote. Changing it retires the original connection. Do not paste credentials here.</p>
      {repositoryInput !== '' && !connectionRepository(repositoryInput) && <p className="review-caution" role="status">Use OWNER/REPO, not a URL, path or token. A malformed target cannot start a connection.</p>}
      {entryReady && <form className="github-form" onSubmit={(event) => {
        event.preventDefault();
        try {
          // Recheck before reading the uncontrolled input. connectToken rechecks
          // again after synchronous listeners, before its one direct handoff.
          if (GITHUB_CONNECTION_ENTRY_AVAILABLE && handoff && projectSelected && controller.canConnect() && tokenInput.current)
            controller.connectToken(tokenInput.current.value, handoff);
        } finally { clearToken(); }
      }}>
        <div className="field-label-row"><label htmlFor={tokenId}>{tokenHelp?.label ?? 'Advanced session-only token'}</label><Badge>Required for this connection</Badge>
          {tokenHelp && <HelpButton content={helpContent(tokenHelp)} onHelp={onHelp} />}</div>
        <input ref={tokenInput} id={tokenId} type="password" autoComplete="off" autoCapitalize="none" spellCheck={false} maxLength={4096}
          aria-describedby={`${tokenId}-help`} required />
        <p id={`${tokenId}-help`} className="save-note">{tokenHelp?.what} {tokenHelp?.where} {tokenHelp?.format} Use only the minimum read access described in Help. The value is handed to the native session once, then this field is cleared immediately. It is not saved in project files or an asset vault. Disconnect is local retirement, not remote token revocation.</p>
        <button type="submit" className="button primary"><Icon name="key" size={17} />Connect for read-only observations</button>
      </form>}
      {state.helpState !== 'current' && <p className="review-caution" role="status">{state.helpState === 'previous' ? 'Previously loaded help is retained for reading only; it does not enable entry.' : 'Core connection help is unavailable; entry remains disabled.'}</p>}
      {state.help && <div className="button-row" aria-label="Core GitHub connection help">
        {[...state.help.inputs, ...state.help.guidance].map((entry) => <span key={entry.id}>{entry.label} <HelpButton content={helpContent(entry)} onHelp={onHelp} /></span>)}
      </div>}
      {nativeBusyReason && <p className="review-caution" role="status">{nativeBusyReason} Original Status and Disconnect remain available.</p>}
      {state.error && <p className="review-caution" role="status">{GITHUB_CONNECTION_REASON_HELP[state.error]}</p>}
      {state.uncertain && <p className="review-caution" role="status">The original request has no conclusive acknowledgement. Read retained Status; do not repeat Connect or Refresh. An idle read can arrive before admission and is not proof of refusal.</p>}
      {state.retirementPending && <p className="save-note" role="status">Original retirement is pending. If Connect has not returned its session ID, only its late exact admission can identify what to disconnect; no replacement or sessionless cancellation is sent.</p>}
      {status && <>
        <p className="save-note">{retained ? 'Retained / stale original status' : 'Original native status'} · revision {status.revision}. {status.session ? <>Session <code>{status.session.id}</code>, project <code>{status.session.projectId}</code>, target <code>{status.session.targetRepository}</code>: {status.session.state}.</> : 'No retained native session.'}</p>
        {status.session?.expiresAt && <p className="save-note">Native session ceiling <time dateTime={status.session.expiresAt}>{status.session.expiresAt}</time>. This may be shorter than the token’s lifetime; it is not necessarily observed server expiry. Display information only; native deadlines decide admission.</p>}
        {status.operation && <p className="save-note">Original {status.operation.kind}: {status.operation.phase}. {GITHUB_CONNECTION_REASON_HELP[status.operation.reason]}</p>}
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
        {!entryReady && <button type="button" className="button secondary" disabled aria-describedby={reasonId}><Icon name="key" size={17} />Connect · unavailable</button>}
        <button type="button" className="button secondary" disabled aria-describedby={reasonId}>App/device login · unavailable</button>
        <button type="button" className="button secondary" disabled={!controller.canCheckStatus() || state.observing} onClick={() => void controller.checkStatus()}><Icon name="refresh" size={17} />Read retained Status</button>
        <button type="button" className="button secondary" disabled={!GITHUB_CONNECTION_ENTRY_AVAILABLE || !controller.canRefresh()} onClick={() => { if (GITHUB_CONNECTION_ENTRY_AVAILABLE) controller.refresh(); }}>Refresh observation</button>
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
