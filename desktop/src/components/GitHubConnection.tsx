// The advanced input exists only behind the compiled and native-current gates.
// Its value never enters React/controller state, drafts or an async callback.
import { useId, useLayoutEffect, useRef } from 'react';
import type { ReactNode } from 'react';
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

export function GitHubConnection({ state, controller, onHelp, repositoryInput, onRepository, projectSelected, handoff, nativeBusyReason = null, ghEntry }: {
  state: GitHubConnectionViewState; controller: GitHubConnectionController; onHelp: (help: HelpContent) => void;
  repositoryInput: string; onRepository: (value: string) => void; projectSelected: boolean;
  handoff: GitHubConnectionTokenHandoff | null;
  nativeBusyReason?: string | null; ghEntry?: ReactNode;
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
  const connected = !retained && !state.busy && status?.session?.state === 'connected' &&
    status.account.state === 'observed' && status.repository.state === 'observed';
  return <>
    <section className="card" aria-label="GitHub connection and observations">
      <SectionHeading title="Connect GitHub" description="Check your account and app repository. Connecting does not change files or start a release.">
        <Icon name="github" size={24} />
      </SectionHeading>
      <div className="notice notice-info" role="status"><Icon name="github" size={18} /><div>
        <strong>{connected ? 'Connected for read-only checks' : state.busy ? 'Finishing the original connection task' : retained && account ? 'Previous account check — not a current connection' : 'Not connected'}</strong>
        {account && <p>{connected ? 'Account' : 'Last checked account'}: <strong>{account.login}</strong>{repository && <> · {repository.fullName}</>}</p>}
        <p>A connection is not permission to change repository settings, start a workflow or publish an app. Those tasks have their own review and approval.</p>
      </div></div>
      {nativeBusyReason && <p className="review-caution" role="status">{nativeBusyReason} Check status and Disconnect remain available for the original connection.</p>}
      {state.error && <p className="review-caution" role="status">{GITHUB_CONNECTION_REASON_HELP[state.error]}</p>}
      {status?.operation && status.operation.reason !== 'none' && status.operation.reason !== state.error &&
        <p className="review-caution" role="status">{GITHUB_CONNECTION_REASON_HELP[status.operation.reason]}</p>}
      {state.uncertain && <p className="review-caution" role="status">The original request could not be confirmed. Check its status; do not connect or refresh again. A “not connected” reply alone does not prove the earlier request ended.</p>}
      {state.retirementPending && <p className="save-note" role="status">The original connection is still ending. Keep the app open. Its own result must identify what to disconnect; no replacement connection is started.</p>}
      <div className="field-label-row"><label htmlFor={repositoryId}>Your app’s GitHub repository</label><Badge>Required for connection</Badge>
        {repositoryHelp && <HelpButton content={helpContent(repositoryHelp)} onHelp={onHelp} />}</div>
      <input id={repositoryId} type="text" disabled={!projectSelected} value={repositoryInput} onChange={(event) => onRepository(event.target.value)}
        placeholder="OWNER/REPO" maxLength={140} autoComplete="off" autoCapitalize="none" spellCheck={false} aria-describedby={`${repositoryId}-help`} />
      <p id={`${repositoryId}-help`} className="save-note">Enter OWNER/REPO from your app’s GitHub URL, without https://github.com/ or .git. This is a manual choice, not automatic repository discovery. Changing it ends use of the original connection. Do not paste credentials here.</p>
      {repositoryInput !== '' && !connectionRepository(repositoryInput) && <p className="review-caution" role="status">Use OWNER/REPO, not a URL, path or token. A malformed target cannot start a connection.</p>}
      {ghEntry}
      <details className="progressive-disclosure">
        <summary>Advanced: use a personal access token</summary>
        <p id={reasonId} className="save-note">{!GITHUB_CONNECTION_ENTRY_AVAILABLE ? 'Token entry is unavailable in this build.' :
          !projectSelected ? 'Select your app project first.' : !state.context ? 'Enter your app repository above.' :
          state.helpState !== 'current' ? 'Current connection help is unavailable; token entry stays disabled.' :
          state.status && !state.status.capability.readOnlySessionAvailable ? GITHUB_CONNECTION_REASON_HELP[state.status.capability.reason] :
          entryReady ? 'Use a token limited to your selected repository. It is used for this app session only, not saved in project files.' :
          'Finish or check the original connection before entering a token.'} This option never runs automatically if GitHub CLI fails. No GitHub App registration or project signing key is used.</p>
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
        <p id={`${tokenId}-help`} className="save-note">{tokenHelp?.what} {tokenHelp?.where} {tokenHelp?.format} Use the minimum permissions for your intended actions: the existing read permissions for Connect, plus only the separate Administration permission described below if using repository settings. The value is handed to the native session once, then this field is cleared immediately. It is not saved in project files or an asset vault. Disconnect is local retirement, not remote token revocation.</p>
        <button type="submit" className="button primary"><Icon name="key" size={17} />Connect for read-only observations</button>
      </form>}
        {!entryReady && <button type="button" className="button secondary" disabled aria-describedby={reasonId}><Icon name="key" size={17} />Token connection unavailable</button>}
        <p className="save-note">App/device login is not available. Disconnecting here does not revoke a token on GitHub.</p>
      </details>
      {state.helpState !== 'current' && <p className="review-caution" role="status">{state.helpState === 'previous' ? 'Previously loaded help is retained for reading only; it does not enable entry.' : 'Core connection help is unavailable; entry remains disabled.'}</p>}
      <details className="progressive-disclosure">
        <summary>Connection details, workflow checks &amp; help</summary>
      {state.help && <div className="button-row" aria-label="Core GitHub connection help">
        {[...state.help.inputs, ...state.help.guidance].map((entry) => <span key={entry.id}>{entry.label} <HelpButton content={helpContent(entry)} onHelp={onHelp} /></span>)}
      </div>}
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
      </details>
      <div className="button-row">
        <button type="button" className="button secondary" disabled={!controller.canCheckStatus() || state.observing} onClick={() => void controller.checkStatus()}><Icon name="refresh" size={17} />Check connection status</button>
        <button type="button" className="button secondary" disabled={!GITHUB_CONNECTION_ENTRY_AVAILABLE || !controller.canRefresh()} onClick={() => { if (GITHUB_CONNECTION_ENTRY_AVAILABLE) controller.refresh(); }}>Refresh account &amp; repository check</button>
        <button type="button" className="button secondary" disabled={!controller.canDisconnect()} onClick={() => controller.disconnect()}>Disconnect original connection</button>
      </div>
      <p className="save-note">Check status reads the original task; it does not connect again. Disconnect requests an end to this app’s session, not token revocation on GitHub. Wait for that original task to finish before reconnecting.</p>
    </section>
    <details className="card progressive-disclosure" aria-label="Remote setup limits and permissions">
      <summary>Advanced: permissions for later GitHub tasks</summary>
      <p>Connecting only checks your account and repository. The later tasks below request their own permissions and explicit approval; local workflow files are not pushed by connecting.</p>
      <p>The separate Authenticated release history panel below reads one exact run, attempt, release stage and platform only after you select Start. It uses this original session and clean saved project settings, with Contents and Actions read access for the selected repository. Connect alone does not read History. Local Status and Cancel do not poll GitHub or cancel a remote workflow. Missing native runtime or attestation provider stays unavailable; authenticated retained workflow evidence is not current Store state or permission to promote.</p>
      <p>For repository-setting previews, GitHub requires repository Administration (read). Applying a reviewed change requires Administration (write) for that repository. A successful connection does not prove these permissions. Keep the token limited to the intended repository and permissions. Existing connection read permissions still apply; this is not a request to grant every permission.</p>
      <p>Connecting checks your account and repository without changing them. Repository settings below require a separate preview and confirmation. Connecting alone never changes settings or starts a workflow. The separate nonpublishing preflight panel has its own native qualification, exact caller review and one-use consent. The separate settings panel can review only its fixed environment fields with explicit confirmation. The separate settings card can also preview one supported assigned secret only when its actual native runtime and fixed sealing helper are available. It never accepts raw secret text. Environments/secret permissions are separate from Administration and are checked for that operation; the mapped nonsecret variables have a separate explicit preview showing their desired text and require actual native variable support, not the sealing helper. Unsupported recordless inputs remain unavailable. GitHub acceptance cannot verify a secret value; administrator bypass, complete environment protection and release readiness remain unverified.</p>
    </details>
  </>;
}
