import { useId, useSyncExternalStore } from 'react';
import type { GitHubDeviceConnectionController } from '../githubDeviceConnectionController.ts';
import type { DevicePhase, DeviceReason } from '../githubDeviceConnectionProtocol.ts';
const phases:Record<DevicePhase,string>={idle:'Browser sign-in',starting:'Requesting a device code',pending:'Waiting for your GitHub approval',checking:'Checking the same device code',connecting:'Verifying the GitHub account and repository',stopping:'Stopping the original login',settled:'Browser connection request finished',failed:'Browser connection request ended', 'cleanup-unknown':'Original login cleanup is unconfirmed'};
const reasons:Record<DeviceReason,string>={none:'', 'publisher-unconfigured':'The publisher has not configured its device-enabled GitHub OAuth App. Use the existing GitHub CLI account or token option.',
  'runtime-unavailable':'The installed device sign-in runtime is unavailable.',busy:'Finish the original request first.', 'target-changed':'The original app, repository or connection changed.',
  waiting:'Approval is still pending. Use the same code; wait for GitHub’s interval, then explicitly check again.', 'slow-down':'GitHub requested a longer interval. Keep the same code; do not start another login.',
  denied:'GitHub declined this approval.',expired:'The original login expired.', 'client-refused':'GitHub refused the publisher’s OAuth configuration.', 'response-invalid':'The original response could not be accepted. Do not repeat an unconfirmed login.',
  cancelled:'Local login was stopped. This does not revoke a GitHub grant or token.', 'cleanup-unknown':'Keep this app open. The original login has not confirmed cleanup; do not connect again.'};
// No mount effect, automatic browser, automatic OAuth polling or clipboard.
export function GitHubDeviceConnection({controller,compact=false,onShow}:{controller:GitHubDeviceConnectionController;compact?:boolean;onShow?:()=>void}) {
  const s=useSyncExternalStore(controller.subscribe,controller.getSnapshot,controller.getSnapshot),consent=useId();
  const busy=controller.ownerReason(),original=s.original,reason=controller.startReason(),check=controller.checkReason();
  if(compact&&!busy)return null;
  const code=!s.cancelRequested&&original&&s.context&&original.projectId===s.context.projectId&&original.repository===s.context.repository?original.code:null;
  return <section className={compact?'card':'github-form'} aria-label="Connect to GitHub in your browser">
    {!compact&&<><h3>Connect in your browser for this app session</h3>
      <p>Prefer the existing GitHub CLI account above if you are already signed in. This separate GitHub device flow does not change the CLI’s account, configuration or Keychain.</p>
      <p>GitHub’s <code>repo</code> permission includes private-repository read and write access. MRK still requires its existing separate approval for each action. This flow does not request <code>workflow</code>, admin or gist scope; workflow-file changes can need another credential.</p>
      <label htmlFor={consent}><input id={consent} type="checkbox" checked={s.consent} disabled={!s.fresh||busy!==null}
        onChange={e=>controller.setConsent(e.target.checked)}/> I approve requesting GitHub repo access for this session and this selected project.</label>
      <div className="button-row"><button type="button" className="button primary" disabled={reason!==null} onClick={()=>controller.start()}>Get a GitHub sign-in code</button></div>
      <p className="save-note">{reason??'One explicit request; no token is stored in project files. GitHub and your organization must approve access.'}</p>
    </>}
    {(original?.phase!=='idle'||busy||s.reason)&&<div className="notice notice-info" role="status"><div><strong>{phases[original?.phase??'idle']}</strong>
      {s.reason&&<p>{reasons[s.reason]}</p>}{s.issue&&<p>{busy}</p>}
      {original?.phase==='settled'&&<p>Only the separate account and repository result below confirms a connection. The code or browser request is not proof of sign-in.</p>}
      {s.cancelRequested&&<p>Stop was requested for the original login; waiting for its actual calls to return. A GitHub grant is not revoked by Stop.</p>}
    </div></div>}
    {!compact&&code&&<><p>Enter this code at <code>{code.verificationUri}</code>: <strong><code>{code.userCode}</code></strong></p>
      <p className="save-note">Last native status: at most {code.remainingSeconds}s remain; next check no earlier than {code.checkAfterSeconds}s after that status. Status does not extend the code’s lifetime.</p>
      <div className="button-row"><button type="button" className="button secondary" disabled={!controller.canOpen()} onClick={()=>controller.open()}>Open GitHub</button>
        <button type="button" className="button primary" disabled={check!==null} onClick={()=>controller.check()}>I’ve authorized — connect</button></div>
      <p className="save-note">{check??'Checks once. If GitHub is still waiting, keep the same code and check again after its interval.'}</p>
      {s.browserRequested&&<p>Browser opening was requested, not verified. You can type the fixed address above yourself.</p>}
    </>}
    <div className="button-row"><button type="button" className="button secondary small" disabled={!controller.canRead()} onClick={()=>controller.read()}>{busy?'Check original login status':'Check browser sign-in availability'}</button>
      {(busy||s.cancelRequested)&&<button type="button" className="button secondary small" disabled={!controller.canCancel()} onClick={()=>controller.cancel()}>Stop original login</button>}
      {compact&&onShow&&<button type="button" className="button secondary small" onClick={onShow}>Show GitHub connection</button>}</div>
    {!compact&&<p className="save-note">Status never polls GitHub automatically. Stopping or closing this session does not revoke authorization in GitHub; review Authorized OAuth Apps in GitHub Settings when needed.</p>}
  </section>;
}
