import { localStorePrepareOwnerReason, type LocalStorePrepareController, type LocalStorePrepareState } from '../localStorePrepare.ts';

export function LocalStorePrepare({ state, controller, compact = false, onCredentials, onShow }: {
  state: LocalStorePrepareState; controller: LocalStorePrepareController; compact?: boolean;
  onCredentials: () => void; onShow: () => void;
}) {
  const op = state.status?.operation, retained = localStorePrepareOwnerReason(state), reason = controller.prepareReason();
  const prepared = op?.result?.preparedIntent, ios = state.request?.platform === 'ios';
  if (compact && !retained) return null;
  return <section className="card" aria-label="Prepare local Store release">
    <div className="inline-heading"><h2>Prepare Store release · This Mac</h2>{compact && <button onClick={onShow}>Show preparation</button>}</div>
    {!compact && <>
      <p>Check your already-built Android or iOS candidate against its Store and save a local release plan. Preparation does not upload the app or publish a release.</p>
      <details><summary>Help: what do I need before preparing?</summary>
        <p>Enroll this project, create candidate inputs, then choose the matching platform and Review inputs in Release history. Use the same saved version and unchanged project. The application keeps the bundle in your project; you do not need to copy or register its files.</p>
        <p>In Credentials choose This Mac → the matching platform → Candidate → Store (or Full), then keep and assign the Store credential. Android requires a Google service-account JSON with app access in Play Console. iOS requires an App Store Connect P8, Key ID and Issuer ID with access to the configured app.</p>
        <p>Get Google JSON from Google Cloud Console → IAM &amp; Admin → Service Accounts → Keys. Get the App Store Connect API key from Users and Access → Integrations → App Store Connect API. Keep these private files and identifiers out of Git and GitHub.</p>
        <p>Incorrect credentials, permissions, version or candidate files cause preparation to refuse; they never trigger an automatic release.</p>
      </details>
      {state.request && <p><strong>{state.applicationId}</strong> · Version {state.request.savedVersion.name} · Build {state.request.savedVersion.build} · {ios ? 'TestFlight internal' : 'Play internal testing'}</p>}
      <p><strong>What changes:</strong> {ios ? 'App Store Connect is read to capture a current snapshot; no Store write or upload is requested.' : state.request ? 'Google Play receives a temporary uncommitted edit. The app reads its state and attempts to delete that edit.' : 'Android preparation uses a temporary uncommitted Play edit; iOS preparation only reads App Store Connect.'} The app saves a local snapshot and intent. It does not rebuild, sign, upload, commit a track or publish.</p>
      {!state.request && <button onClick={onCredentials}>Configure local credentials</button>}
      <button disabled={!!reason || state.pending} onClick={() => void controller.prepare()}>Review Store preparation</button>
      {reason && <p className="save-note">{reason}</p>}
    </>}
    {state.consentUntil !== null && <div className="notice">
      <p>{op?.context.platform === 'ios' ? 'Read App Store Connect for this iOS candidate and save a local TestFlight-internal plan. No build is uploaded and no Store release is changed.' : 'Prepare this Android candidate for internal testing, without uploading or publishing. This contacts Google Play and creates a temporary uncommitted edit. Cancellation or a network failure can leave that edit until Google expires it.'}</p>
      <p>Version {op?.context.savedVersion.name} · Build {op?.context.savedVersion.build}. Candidate <code>{op?.context.candidateOperationId}</code>.</p>
      <label><input type="checkbox" checked={state.acknowledged} onChange={event => controller.acknowledge(event.target.checked)} /> I authorize this preparation only, not a release.</label>
      <button disabled={!state.acknowledged || state.pending} onClick={() => void controller.start()}>Prepare local Store intent</button>
    </div>}
    {retained && <div role="status"><p>{op?.phase === 'running' ? 'Preparing the original candidate. This can take up to 20 minutes. Keep the application open until cleanup is confirmed.' : retained}</p><button onClick={() => void controller.cancel()}>Cancel original preparation</button></div>}
    <button disabled={state.mode !== 'native'} onClick={() => void controller.checkStatus()}>Refresh preparation status</button>
    {state.error && <p role="alert">{state.error}</p>}
    {op && <p>{state.historical ? 'Earlier context · ' : ''}{op.phase}{op.reason !== 'none' ? ` · ${op.reason.replaceAll('-', ' ')}` : ''}</p>}
    {op && (op.phase === 'unknown' || op.phase === 'terminal' && op.outcome !== 'complete') && <p className="save-note">Keep the original project, candidate files and Mac Keychain entries. Preparation may have left a pending history checkpoint. Verify existing history before any new attempt; do not delete history or re-enroll to clear a failure.</p>}
    {prepared && <div className="notice">
      <h3>Release intent saved · Not uploaded or published</h3>
      <p>{'bundleId' in prepared ? prepared.bundleId : prepared.applicationId} · Version {prepared.version.name} · Build {prepared.version.build} · {'bundleId' in prepared ? 'TestFlight internal' : 'Play internal testing'}</p>
      {'appStoreAppId' in prepared && <p>App Store app ID: {prepared.appStoreAppId}</p>}
      <p>{'bundleId' in prepared ? 'App Store Connect' : 'Google Play'} state observed at {prepared.observedAt}. Local checkpoint {op?.result?.headSequence}.</p>
      <p>The application retained the snapshot and intent inside your project. No copying or command is needed. This result does not authorize execution, establish earlier build finality, or guarantee that the Store is unchanged.</p>
      {state.historical && <p>This result belongs to an earlier context. It is not a preparation of your current selection.</p>}
      <p>Execution requires separate support, review and explicit consent. This preparation does not enable an iOS upload. Do not treat this saved intent as a completed Store release.</p>
    </div>}
  </section>;
}
