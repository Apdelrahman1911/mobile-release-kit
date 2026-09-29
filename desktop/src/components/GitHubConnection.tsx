// The advanced input exists only behind the compiled and native-current gates.
// Its value never enters React/controller state, drafts or an async callback.
import { useId, useLayoutEffect, useRef, useState } from 'react';
import type { CredentialHelp, HelpContent } from '../types.ts';
import type { ProjectSession } from '../drafts.ts';
import { savedGitHubInputs } from '../githubEnvironmentInputs.ts';
import type { GitHubConnectionHelpEntry, GitHubConnectionTokenHandoff, GitHubConnectionViewState, GitHubFact } from '../githubConnectionTypes.ts';
import type { GitHubConnectionController } from '../githubConnectionController.ts';
import { GITHUB_CONNECTION_ENTRY_AVAILABLE, GITHUB_CONNECTION_REASON_HELP, connectionRepository, sameConnectionData, currentGitHubAuthorization } from '../githubConnectionProtocol.ts';
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

export function GitHubConnection({ state, controller, onHelp, repositoryInput, onRepository, projectSelected, handoff, projectSession, credentialHelp = [], nativeBusyReason = null }: {
  state: GitHubConnectionViewState; controller: GitHubConnectionController; onHelp: (help: HelpContent) => void;
  repositoryInput: string; onRepository: (value: string) => void; projectSelected: boolean;
  handoff: GitHubConnectionTokenHandoff | null; projectSession: ProjectSession | null; credentialHelp?: CredentialHelp[];
  nativeBusyReason?: string | null;
}) {
  const reasonId = useId(); const repositoryId = useId(); const tokenId = useId(); const inputId = useId();
  const [inputKey, setInputKey] = useState('');
  const savedInputs = savedGitHubInputs(projectSession);
  const selectedInput = savedInputs?.inputs.find((row) => `${row.stage}:${row.name}` === inputKey) ?? null;
  const selectedHelp = selectedInput ? credentialHelp.find((row) => row.name === selectedInput.name) : null;
  const tokenInput = useRef<HTMLInputElement>(null);
  const clearToken = () => { if (tokenInput.current) tokenInput.current.value = ''; };
  const entryReady = GITHUB_CONNECTION_ENTRY_AVAILABLE && handoff !== null && state.mode === 'native' && projectSelected &&
    state.helpState === 'current' && state.status?.capability.readOnlySessionAvailable === true && controller.canConnect();
  const deviceReady = GITHUB_CONNECTION_ENTRY_AVAILABLE && state.mode === 'native' && projectSelected &&
    state.helpState === 'current' && controller.canStartDevice();
  const authorization = currentGitHubAuthorization(state);
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
  const authenticationHelp = state.help?.guidance.find((entry) => entry.id === 'authentication');
  const publisherName = state.status?.capability.publisherName;
  const connected = !retained && status?.session?.state === 'connected';
  return <>
    <section className="card" aria-label="GitHub connection and observations">
      <SectionHeading title="Connect your GitHub account" description="Sign in, then check access to your mobile application repository. No release is published here.">
        <Icon name="github" size={24} />
      </SectionHeading>
      <div className="notice notice-info" role="status"><Icon name="shield" size={18} /><div>
        <strong>{connected ? 'GitHub account connected' : authorization ? 'GitHub sign-in is in progress' :
          deviceReady || entryReady ? 'Connect for this app session' : 'Connection needs attention'}</strong>
        <p id={reasonId}>{!projectSelected ? 'Select your application project first.' :
          !state.context ? 'Enter the application repository below.' :
          state.helpState !== 'current' ? 'Reload current connection guidance before signing in.' :
          state.uncertain ? 'Your request may still be running. Read its original Status; cancel only when the original session is identified. Do not start another sign-in.' :
          authorization ? 'Approve the sign-in in your browser. This app waits safely and then checks your account and repository access.' :
          connected ? 'Sign-in is separate from repository access, GitHub setup and release readiness. Review each observation below.' :
          deviceReady ? 'Sign in on GitHub in your system browser. Your GitHub password is never entered in this app.' :
          entryReady ? 'Publisher sign-in is unavailable in this build. The advanced session-only token option is available below.' :
          state.status && !state.status.capability.readOnlySessionAvailable ? GITHUB_CONNECTION_REASON_HELP[state.status.capability.reason] :
          'Finish or disconnect the current session before starting a new connection.'} No repository writes, Store access or workflow dispatch happen here. Credentials are kept only for the current native session, not saved in project files.</p>
      </div></div>
      <div className="field-label-row"><label htmlFor={repositoryId}>{repositoryHelp?.label ?? 'Explicit application repository'}</label><Badge>Required for connection</Badge>
        {repositoryHelp && <HelpButton content={helpContent(repositoryHelp)} onHelp={onHelp} />}</div>
      <input id={repositoryId} type="text" disabled={!projectSelected} value={repositoryInput} onChange={(event) => onRepository(event.target.value)}
        placeholder="OWNER/REPO" maxLength={140} autoComplete="off" autoCapitalize="none" spellCheck={false} aria-describedby={`${repositoryId}-help`} />
      <p id={`${repositoryId}-help`} className="save-note">{repositoryHelp?.what ?? 'The GitHub repository containing your mobile application.'} Find OWNER/REPO in its GitHub URL, without https://github.com/ or .git. This is not the toolkit repository and is never guessed from a Git remote. Changing it retires the original connection. Do not paste credentials here.</p>
      {repositoryInput !== '' && !connectionRepository(repositoryInput) && <p className="review-caution" role="status">Use OWNER/REPO, not a URL, path or token. A malformed target cannot start a connection.</p>}
      <div className="button-row">
        <button type="button" className="button primary" disabled={!deviceReady} aria-describedby={reasonId}
          onClick={() => { if (GITHUB_CONNECTION_ENTRY_AVAILABLE) controller.startDevice(); }}><Icon name="github" size={17} />Sign in with GitHub</button>
        {authenticationHelp && <HelpButton content={helpContent(authenticationHelp)} onHelp={onHelp} />}
      </div>
      {state.status?.capability.deviceLogin === 'publisher-unconfigured' && <p className="save-note">
        The publisher has not configured GitHub App sign-in for this build. You do not need to find or enter a client ID.
        The advanced token option below remains separate and needs no App registration.</p>}
      {state.status?.capability.deviceLogin === 'not-qualified' && <p className="save-note">
        GitHub App sign-in is not available on this installed runtime. Portable UI support is not native verification.</p>}
      {authorization && <div className="notice notice-info" aria-label="GitHub sign-in progress" role="status" aria-live="polite">
        <Icon name="github" size={20} /><div>
          <strong>{authorization.phase === 'requesting-code' ? 'Requesting a sign-in code…' :
            authorization.phase === 'checking-access' ? 'Checking your account and repository access…' :
            authorization.phase === 'slow-down' ? 'Waiting for GitHub — checking less often as requested' : 'Waiting for you to approve on GitHub'}</strong>
          {authorization.userCode !== null && <>
            <p id={reasonId + '-code-label'}>Your one-time GitHub code</p>
            <h3><code dir="ltr" aria-labelledby={reasonId + '-code-label'}>{authorization.userCode}</code></h3>
            <p>Open GitHub, enter this code and check that the application is <strong>{publisherName}</strong> before approving.
              Approve only a sign-in you started. Do not share the code or enter it on another website.</p>
            <button type="button" className="button secondary" disabled={!controller.canOpenDevicePage()} onClick={() => controller.openDevicePage()}>Open GitHub</button>
            <p className="save-note">If the browser does not open, visit <code>https://github.com/login/device</code> yourself.
              Opening the page is not proof that sign-in succeeded.</p>
            {state.browserHandoff === 'opening' && <p className="save-note">The browser handoff has not returned yet. You can still check Status or cancel this sign-in.</p>}
            {state.browserHandoff === 'accepted' && <p className="save-note">The system accepted the browser handoff. Finish approval on GitHub; account access is checked separately.</p>}
            {state.browserHandoff === 'unconfirmed' && <p className="review-caution">The app could not confirm the browser handoff. Use the fixed GitHub address above, or cancel. No new sign-in was started.</p>}
          </>}
          {authorization.expiresAt && <p className="save-note">Code expiry: <time dateTime={authorization.expiresAt}>{authorization.expiresAt}</time>.
            This time is guidance only; the native session controls expiry and stops automatically.</p>}
          <p className="save-note">Cancel does not revoke a GitHub authorization already granted. Session-only sign-in does not save or renew your credential.</p>
        </div>
      </div>}
      {status?.operation?.kind === 'authorize' && status.operation.phase === 'settled' && status.operation.reason !== 'none' &&
        <p className="review-caution" role="status">Sign-in did not complete. {status.operation.reason === 'unauthorized' ?
          'GitHub declined or refused this authorization.' : GITHUB_CONNECTION_REASON_HELP[status.operation.reason]}
          {' '}Disconnect this original session first. After its cleanup is confirmed, you can deliberately start a new sign-in. Refresh cannot repeat a failed sign-in.</p>}
      {entryReady && <details className="github-form"><summary>Advanced: use a session-only token</summary>
        <form className="github-form" onSubmit={(event) => {
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
        <button type="submit" className="button secondary"><Icon name="key" size={17} />Connect with this token</button>
        </form>
      </details>}
      {state.helpState !== 'current' && <p className="review-caution" role="status">{state.helpState === 'previous' ? 'Previously loaded help is retained for reading only; it does not enable entry.' : 'Core connection help is unavailable; entry remains disabled.'}</p>}
      {state.help && <div className="button-row" aria-label="Core GitHub connection help">
        {[...state.help.inputs, ...state.help.guidance].map((entry) => <span key={entry.id}>{entry.label} <HelpButton content={helpContent(entry)} onHelp={onHelp} /></span>)}
      </div>}
      {nativeBusyReason && <p className="review-caution" role="status">{nativeBusyReason} Original Status and Disconnect remain available.</p>}
      {state.error && <p className="review-caution" role="status">{GITHUB_CONNECTION_REASON_HELP[state.error]}</p>}
      {state.uncertain && <p className="review-caution" role="status">The request may still be running and has no conclusive acknowledgement. Read original Status; do not repeat Sign in, Connect, Refresh or the input check. The code and browser action stay hidden while the outcome is uncertain. An idle read can arrive before admission and is not proof of refusal.</p>}
      {state.retirementPending && <p className="save-note" role="status">Original retirement is pending. If sign-in or Connect has not returned its session ID, only its late exact admission can identify what to cancel. A new sign-in stays unavailable until original cleanup is confirmed.</p>}
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
        <p className="save-note">Not-listed means only not returned by a complete bounded listing. Repository Actions settings/policy, protections and runners have not been observed. Environment/input metadata, when requested separately below, is not workflow compatibility or readiness evidence.</p>
      </>}
      <div className="button-row">
        <button type="button" className="button secondary" disabled={!controller.canCheckStatus() || state.observing} onClick={() => void controller.checkStatus()}><Icon name="refresh" size={17} />Read retained Status</button>
        <button type="button" className="button secondary" disabled={!GITHUB_CONNECTION_ENTRY_AVAILABLE || !controller.canRefresh()} onClick={() => { if (GITHUB_CONNECTION_ENTRY_AVAILABLE) controller.refresh(); }}>Refresh observation</button>
        <button type="button" className="button secondary" disabled={!controller.canDisconnect()} onClick={() => controller.disconnect()}>{state.busy === 'authorize' ? 'Cancel sign-in' : 'Disconnect original session'}</button>
      </div>
      <p className="save-note">An active request blocks new Sign in/Connect/Refresh/input checks, not original Status or exact-session Cancel/Disconnect. A lost reply is not permission to retry. Disconnect requests local retirement, not remote revocation, native settlement or credential erasure.</p>
    </section>
    <section className="card" aria-label="GitHub environment input metadata">
      <SectionHeading title="Environment inputs" description="Compare local requirements with one read-only remote metadata observation. Values are never shown."><Icon name="key" size={22} /></SectionHeading>
      <div className="field-label-row"><label htmlFor={inputId}>Input to check</label><Badge>Required for this check</Badge>
        <HelpButton onHelp={onHelp} content={{ label: 'Environment input metadata', requiredness: 'optional',
          requiredWhen: 'When you want to inspect one GitHub environment secret or variable.',
          what: 'An environment is a named group of release settings in your application repository.',
          why: 'This check shows whether GitHub returns metadata for one input named by the core requirements.',
          where: 'In GitHub, open the application repository, then Settings → Environments → the named mobile environment.',
          format: 'Choose an input below. Do not paste a secret, value, URL or local file.',
          failure: 'A not-found response may also mean insufficient access. Metadata cannot prove the value is correct, permissions are sufficient or the release is ready.' }} /></div>
      {savedInputs ? <p className="save-note">Local requirements match the saved configuration snapshot observed at <time dateTime={savedInputs.observedAt}>{savedInputs.observedAt}</time>.
        This is a saved-local observation, not a live filesystem check or proof that GitHub uses the same source/configuration.
        Only environment secret/variable inputs are listed; other preflight requirements remain separate.</p> :
        <p className="review-caution" role="status">Save or reload your configuration, then check it in Project settings. A current core validation must match the saved snapshot before its requirements are shown here.</p>}
      <select id={inputId} value={selectedInput ? inputKey : ''} disabled={!projectSelected || !savedInputs}
        onChange={(event) => setInputKey(event.target.value)} aria-describedby={inputId + '-help'}>
        <option value="">Choose one environment input…</option>
        {savedInputs?.inputs.map((row) => <option key={row.stage + ':' + row.name} value={row.stage + ':' + row.name}>{row.environment} · {row.name}</option>)}
      </select>
      <p id={inputId + '-help'} className="save-note">Select the release environment and input you want to inspect.
        The core chooses the fixed GitHub endpoint and secret/variable type. Your saved requirements and the remote observation are independent; no configuration is applied.</p>
      {selectedInput && <>
        <div className="field-label-row"><strong>{selectedInput.reason}</strong><Badge>{selectedInput.kind} · {selectedInput.platform}</Badge>
          {selectedHelp && <HelpButton onHelp={onHelp} content={{ ...selectedHelp, label: selectedHelp.name }} />}</div>
        <p className="save-note"><code>{selectedInput.name}</code> is expected in <code>{selectedInput.environment}</code> by the saved-local configuration.
          {selectedHelp && <> {selectedHelp.what} {selectedHelp.where}</>}</p>
      </>}
      <button type="button" className="button secondary" disabled={!GITHUB_CONNECTION_ENTRY_AVAILABLE || !projectSelected ||
        !selectedInput || state.context?.projectId !== projectSession?.project.id || !controller.canInspect()}
        onClick={() => { if (GITHUB_CONNECTION_ENTRY_AVAILABLE && selectedInput &&
          controller.getSnapshot().context?.projectId === projectSession?.project.id)
          controller.inspect(selectedInput.stage, selectedInput.name); }}>Check remote metadata — read-only</button>
      {!controller.canInspect() && <p className="save-note">A current connected account and repository observation are required. Finish the original request, reconnect if needed, or refresh its observation. Status and Disconnect remain available.</p>}
      {status?.inputMetadata && <div aria-live="polite">
        <h3>Last requested remote observation</h3>
        <p><code>{status.inputMetadata.selection.stage}</code> · <code>{status.inputMetadata.selection.name}</code></p>
        <h4>Environment metadata</h4><FactLabel fact={status.inputMetadata.environment} retained={retained} />
        {status.inputMetadata.environment.value && <p>{status.inputMetadata.environment.value.name} · environment ID <code>{status.inputMetadata.environment.value.id}</code></p>}
        <h4>Selected input metadata</h4><FactLabel fact={status.inputMetadata.field} retained={retained} />
        {status.inputMetadata.field.value && <dl className="github-facts">
          <div><dt>Input type</dt><dd>{status.inputMetadata.field.value.kind}</dd></div>
          <div><dt>Created</dt><dd><time dateTime={status.inputMetadata.field.value.createdAt}>{status.inputMetadata.field.value.createdAt}</time></dd></div>
          <div><dt>Updated</dt><dd><time dateTime={status.inputMetadata.field.value.updatedAt}>{status.inputMetadata.field.value.updatedAt}</time></dd></div>
        </dl>}
      </div>}
      <p className="save-note">These checks use at most five GET requests for one field. Environment metadata needs Actions read access;
        environment secret/variable metadata needs Environments read access. Reported repository roles do not prove these grants.
        GitHub does not return secret values; variable values are discarded before any UI output. A 404 means not found or inaccessible, not proven absence.
        Metadata never proves credential validity, protection adequacy, caller/configuration equivalence or release readiness. This metadata check cannot write inputs or publish a release. The separate input-group panel needs its own native availability, current assignment and explicit replacement review.</p>
    </section>
    <section className="card" aria-label="Remote GitHub setup unavailable">
      <SectionHeading title="Environment and protection setup — unavailable" description="Local workflow Apply does not push files or grant remote authority."><Icon name="lock" size={22} /></SectionHeading>
      <p>This read-only connection section does not write repository settings or dispatch workflows. The separate nonpublishing preflight panel has its own native qualification, exact caller review and one-use consent. The separate input-group panel applies only its reviewed whole-group secret when its native path is available. It does not create environments, edit protections or configure arbitrary variables. The administrator checklist and release readiness remain unverified.</p>
    </section>
  </>;
}
