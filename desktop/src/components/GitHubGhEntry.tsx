import { useId, useSyncExternalStore } from 'react';
import type { GitHubGhEntryController } from '../githubGhEntryController.ts';
import type { GitHubGhPhase } from '../githubGhEntryProtocol.ts';
import { GITHUB_CONNECTION_REASON_HELP } from '../githubConnectionProtocol.ts';
import { Icon } from './Icon.tsx';

const phases: Record<GitHubGhPhase, string> = {
  idle: 'No CLI connection request', picking: 'Choose GitHub CLI in the file picker', running: 'Reading the selected local login',
  'checking-identity': 'Checking the account with GitHub', stopping: 'Stopping — waiting for the original request',
  settled: 'CLI request finished', failed: 'CLI request ended without completing', 'cleanup-unknown': 'Original cleanup is unconfirmed',
};

// No mount/read/Connect effect. Root retains this controller across navigation;
// the username is a nonsecret local draft, not an observed/discovered account.
export function GitHubGhEntry({ controller, compact = false, originalProjectName, onShow }: {
  controller: GitHubGhEntryController; compact?: boolean; originalProjectName?: string; onShow?: () => void;
}) {
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const input = useId(), reasonId = useId();
  const busy = controller.ownerReason(), reason = controller.startReason(), original = state.original;
  if (compact && !busy) return null;
  const foreign = !!state.originalProjectId && state.originalProjectId !== state.context?.projectId;
  return <section className={compact ? 'card' : 'github-form'} aria-label="Use a GitHub CLI account">
    {!compact && <>
      <h3>Use a GitHub CLI account</h3>
      <p>Already signed in with GitHub CLI? Enter that username, then choose the installed <code>gh</code> program in the file picker. This app does not discover accounts, sign you in or switch accounts.</p>
      <label className="field" htmlFor={input}><span className="field-label">GitHub username already signed in</span>
        <input id={input} type="text" autoComplete="off" autoCapitalize="none" spellCheck={false} maxLength={39}
          value={state.login} disabled={!state.context || busy !== null} onChange={(event) => controller.setLogin(event.target.value)}
          placeholder="your-github-username" aria-describedby={`${input}-help`} />
        <span id={`${input}-help`} className="field-help">This is your manual choice, not a verified account. The account shown after connecting comes from GitHub’s own check.</span>
      </label>
      <button type="button" className="button primary" disabled={reason !== null} aria-describedby={reasonId}
        onClick={() => controller.connect()}><Icon name="github" size={17} />Choose GitHub CLI &amp; connect</button>
      <p id={reasonId} className="save-note">{reason ?? 'Checks this account and repository only. No repository change or workflow starts; the selected path and token stay in the native app.'}</p>
    </>}
    {(busy || original && original.phase !== 'idle' || state.failure) && <div className={`notice ${state.issue || state.failure ? 'notice-warning' : 'notice-info'}`} role={state.issue ? 'alert' : 'status'}>
      <Icon name="info" /><div>
        <strong>{original ? phases[original.phase] : 'Original GitHub CLI request'}{foreign && ` · ${originalProjectName ?? 'a previously selected project'}`}</strong>
        {original?.selectedLogin && <p>Requested username: <strong>{original.selectedLogin}</strong> · manually entered, not an account-discovery result.</p>}
        {busy && <p>{busy}</p>}
        {state.issue && <p>Do not reconnect, repeat the request or switch to a token to bypass this warning. Keep the app open; no cleanup or account approval is inferred.</p>}
        {state.failure && <p>{GITHUB_CONNECTION_REASON_HELP[state.failure]} Your username draft is kept.</p>}
        {state.cancelRequested && <p>Stop was requested. Only the original result can confirm it finished; requesting Stop is not that confirmation.</p>}
        {original?.phase === 'settled' && <p>This confirms the CLI request ended, not that GitHub connected. Use the account and repository result in the connection section.</p>}
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
