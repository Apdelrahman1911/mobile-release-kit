import { useEffect, useId, useLayoutEffect, useRef } from 'react';
import type { AssetDisplayState } from '../assetSessionTypes.ts';
import type { AssetSessionController } from '../assetSessionController.ts';
import { uploadKeyBaseReason, uploadKeyPlanHelp } from '../credentialUploadKey.ts';

// This is a view of the SAME asset-session controller. Navigation never owns,
// restarts or cancels the native generation operation.
export function CredentialUploadKey({ assets, controller, disabledReason = null }: {
  assets: AssetDisplayState; controller: AssetSessionController; disabledReason?: string | null;
}) {
  const id = useId();
  const committed = useRef<object | null>(null), render = {};
  useLayoutEffect(() => { committed.current = render; return () => { committed.current = null; }; }, [render]);
  const context = assets.status?.context?.platform === 'android' ? assets.status.context.revision : null;
  useEffect(() => {
    // Read-only: never opens the shared store, reserves a key or confirms history.
    if (context !== null) controller.checkUploadKeyStatus();
  }, [context, controller, assets.status?.statusRevision]);
  if (assets.scope.platform !== 'android') return null;
  const view = controller.uploadKeySnapshot();
  const status = view.status;
  const reason = disabledReason ?? uploadKeyBaseReason(assets);
  const current = () => committed.current === render && controller.getSnapshot() === assets;
  const saved = controller.uploadKeySaved(assets);
  const preparing = view.checking || assets.busy === 'prepare-upload-key';
  const active = status?.operation && !['saved', 'recovery-required'].includes(status.operation.phase);
  const canConfirm = !reason && controller.canConfirmUploadKey(assets);
  return <section className="session-context" aria-labelledby={`${id}-title`}>
    <h3 id={`${id}-title`}>Android app signing</h3>
    <p>Use the upload key already used for this app. A different key can prevent app updates. Never delete or replace an existing key to finish setup.</p>
    {status && !active && !saved && <p>{uploadKeyPlanHelp(status.plan)}</p>}
    {!status && <p>Choose your Android project and open its encrypted vault to check signing setup. Checking status never creates a key.</p>}
    {!status?.capability.available && status && <p>Creating a key is unavailable in this build. Existing import and assessment controls are unchanged.</p>}
    {view.error && <p role="alert">{view.error}</p>}
    {view.uncertain && !view.error && <p role="alert">The original setup is not confirmed. Check status and preserve any existing key; do not create another one.</p>}
    {saved && <div role="status">
      <p><strong>Upload key saved.</strong> It is a new, unassigned item in your encrypted vault. It has not been used for signing or checked with Google Play.</p>
      <p>Next, assess and assign this exact item below. Then save an encrypted backup and keep its recovery code in a separate safe place. A saved key is not a completed backup.</p>
    </div>}
    {active && <p role="status">{status.operation!.phase === 'saving' ? 'Saving the new key…' : status.operation!.phase === 'finishing' ? 'Waiting for the original signing action…' : 'Creating the new upload key…'} Keep the app open. Cancelling does not undo an uncertain save.</p>}
    {status?.operation?.phase === 'recovery-required' && <p role="alert">Preserve the original key and files. Check status; do not start another generation or assume cancellation removed them.</p>}
    {canConfirm && <div>
      <label htmlFor={`${id}-new-app`}><input id={`${id}-new-app`} type="checkbox" checked={view.confirmed}
        onChange={(event) => { if (current()) controller.confirmNewUploadKey(assets, event.target.checked); }} />
        This is a new app and I have never used an upload key for it.</label>
      <p>This is your declaration, not a Play Console check. Do not continue for an existing or previously published app.</p>
      <button type="button" className="button" disabled={!view.confirmed} onClick={() => { if (current()) controller.createNewUploadKey(assets); }}>Create and save upload key</button>
    </div>}
    {!canConfirm && !saved && !active && <button type="button" className="button" disabled={!!reason || !status?.capability.available || preparing || view.uncertain || view.attempted}
      onClick={() => { if (current()) controller.prepareUploadKey(assets); }}>{preparing ? 'Checking signing setup…' : 'Set up Android signing'}</button>}
    <button type="button" className="button secondary" disabled={context === null || preparing}
      onClick={() => { if (current()) controller.checkUploadKeyStatus(); }}>Check status</button>
    {reason && <p className="subtle-note">{reason}</p>}
  </section>;
}
