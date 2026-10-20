import { useId, useSyncExternalStore } from 'react';
import type { GitHubGhEntryController } from '../githubGhEntryController.ts';
import type { GitHubGhPhase } from '../githubGhEntryProtocol.ts';
import type { GitHubGhAccountsStatus } from '../githubGhAccountsProtocol.ts';
import { GITHUB_CONNECTION_REASON_HELP } from '../githubConnectionProtocol.ts';
import { Icon } from './Icon.tsx';

const phases: Record<GitHubGhPhase, string> = {
  idle: 'No CLI connection request', picking: 'Choose GitHub CLI in the file picker', running: 'Reading the selected local login',
  'checking-identity': 'Checking the account with GitHub', stopping: 'Stopping — waiting for the original request',
  settled: 'CLI request finished', failed: 'CLI request ended without completing', 'cleanup-unknown': 'Original cleanup is unconfirmed',
};
const accountPhases: Record<GitHubGhAccountsStatus['phase'], string> = {
  reading: 'Reading local GitHub account names', stopping: 'Stopping the local account read',
  settled: 'Local account names read', failed: 'Local account names could not be read', 'cleanup-unknown': 'Original cleanup is unconfirmed',
};

// No mount/read/Connect effect. Root retains this controller across navigation;
// a listed name or typed username is never a verified GitHub identity.
export function GitHubGhEntry({ controller, compact = false, originalProjectName, onShow }: {
  controller: GitHubGhEntryController; compact?: boolean; originalProjectName?: string; onShow?: () => void;
}) {
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const input = useId(), reasonId = useId(), accountsId = useId();
  const busy = controller.ownerReason(), reason = controller.startReason(), findReason = controller.findAccountsReason(), original = state.original;
  const accountRead = state.accountsOriginal;
  if (compact && !busy) return null;
  const foreign = !!state.originalProjectId && state.originalProjectId !== state.context?.projectId;
  return <section className={compact ? 'card' : 'github-form'} aria-label="Use a GitHub CLI account">
    {!compact && <>
      <h3>Use a GitHub CLI account</h3>
      <p>Already signed in with GitHub CLI on this Mac? Read its local account names, then choose which account to use. This does not sign in, contact GitHub or switch your CLI’s default account.</p>
      <button type="button" className="button secondary" disabled={findReason !== null} aria-describedby={`${accountsId}-help`}
        onClick={() => controller.findAccounts()}><Icon name="refresh" size={16} />{state.accounts ? 'Read local accounts again' : 'Find local GitHub accounts'}</button>
      <p id={`${accountsId}-help`} className="save-note">{findReason ?? 'Reads names from the supported local GitHub CLI configuration only. Tokens and configuration files stay in the native app.'}</p>
      {state.accounts && <>
        {state.accounts.logins.length > 0 ? <label className="field" htmlFor={accountsId}><span className="field-label">Which GitHub account?</span>
          <select id={accountsId} value={state.selectedAccount ?? ''} disabled={!state.accountsFresh || busy !== null}
            onChange={(event) => controller.chooseAccount(event.target.value)}>
            <option value="">Choose an account…</option>
            {state.accounts.logins.map((login) => <option key={login} value={login}>{login}</option>)}
          </select>
          <span className="field-help">These are local names, not verified accounts. Connecting checks the chosen account and repository with GitHub.</span>
        </label> : <p>No supported account names were listed. This does not prove you are signed out. You can use the manual option below; nothing falls back automatically.</p>}
        {!state.accountsFresh && <p className="save-note">This earlier list cannot be selected. Read local accounts again for the current project.</p>}
      </>}
      {state.manual && <p>Using the username you typed: <strong>{state.login || 'not entered yet'}</strong>. It has not been verified.</p>}
      <button type="button" className="button primary" disabled={reason !== null} aria-describedby={reasonId}
        onClick={() => controller.connect()}><Icon name="github" size={17} />Choose GitHub CLI &amp; connect</button>
      <p id={reasonId} className="save-note">{reason ?? 'Checks this account and repository only. No repository change or workflow starts; the selected path and token stay in the native app.'}</p>
      <details>
        <summary>Enter a username instead (Advanced)</summary>
        <p>Use this if your local account-list format is unsupported. Enter an account already signed in with GitHub CLI. There is no automatic sign-in or fallback to another account.</p>
        <label className="field" htmlFor={input}><span className="field-label">GitHub username already signed in</span>
          <input id={input} type="text" autoComplete="off" autoCapitalize="none" spellCheck={false} maxLength={39}
            value={state.login} disabled={!state.context || busy !== null} onChange={(event) => controller.setLogin(event.target.value)}
            placeholder="your-github-username" aria-describedby={`${input}-help`} />
          <span id={`${input}-help`} className="field-help">Typing chooses the manual route. Your draft is kept if the picker or connection fails; the verified account appears only after GitHub’s own check.</span>
        </label>
        {!state.manual && state.login && <button type="button" className="button secondary small" disabled={busy !== null}
          onClick={() => controller.useManual()}>Use this typed username</button>}
      </details>
    </>}
    {(busy || original && original.phase !== 'idle' || accountRead || state.failure) && <div className={`notice ${state.issue || state.failure ? 'notice-warning' : 'notice-info'}`} role={state.issue ? 'alert' : 'status'}>
      <Icon name="info" /><div>
        <strong>{original ? phases[original.phase] : accountRead ? accountPhases[accountRead.phase] : 'Original GitHub CLI request'}{foreign && ` · ${originalProjectName ?? 'a previously selected project'}`}</strong>
        {original?.selectedLogin && <p>Requested username: <strong>{original.selectedLogin}</strong>. Only GitHub’s own result can confirm the connected account.</p>}
        {busy && <p>{busy}</p>}
        {state.issue && <p>Do not reconnect, repeat the request or switch to a token to bypass this warning. Keep the app open; no cleanup or account approval is inferred.</p>}
        {state.failure && <p>{GITHUB_CONNECTION_REASON_HELP[state.failure]} Your username draft is kept.</p>}
        {state.cancelRequested && <p>Stop was requested. Only the original result can confirm it finished; requesting Stop is not that confirmation.</p>}
        {original?.phase === 'settled' && <p>This confirms the CLI request ended, not that GitHub connected. Use the account and repository result in the connection section.</p>}
        {accountRead?.phase === 'settled' && <p>Names only: no account was authenticated, chosen automatically or connected.</p>}
      </div>
    </div>}
    <div className="button-row">
      <button type="button" className="button secondary small" disabled={!controller.canCheckStatus()} onClick={() => controller.checkStatus()}>
        <Icon name="refresh" size={15} />{busy ? 'Check original CLI status' : 'Check GitHub CLI availability'}</button>
      {(busy || state.cancelRequested) && <button type="button" className="button secondary small" disabled={!controller.canCancel()}
        onClick={() => controller.requestCancel()}>Stop original CLI request</button>}
      {compact && onShow && <button type="button" className="button secondary small" onClick={onShow}>Show GitHub connection</button>}
    </div>
    {!compact && <p className="save-note">Only supported installed GitHub CLI files are accepted. Choosing a file does not install or upgrade it. If this option is unavailable, the separate advanced token option is unchanged; no fallback runs automatically.</p>}
  </section>;
}
