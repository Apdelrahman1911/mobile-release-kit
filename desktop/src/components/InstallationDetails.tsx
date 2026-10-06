import { useEffect, useMemo, useRef, useState } from 'react';
import type { ApiError, AppInfo, DesktopApi, HelpContent } from '../types.ts';
import { installationError, installationLocationHelp, parseInstallationDescription, installationCheckActive, installationCheckHelp,
  INSTALLATION_CHECK_GUIDANCE, installationPreparationActive, installationPreparationHelp, INSTALLATION_PREPARATION_GUIDANCE } from '../installation.ts';
import { InstallationCheckController, InstallationPreparationController, type InstallationCheckApi, type InstallationCheckView,
  type InstallationPreparationApi, type InstallationPreparationView } from '../installationController.ts';
import { Badge, ErrorNotice, HelpButton, SectionHeading } from './Common.tsx';

export function InstallationDetails({ info, api, preview, loading, onHelp }: {
  info: AppInfo | null; api: (Pick<DesktopApi, 'revealInstallation'> & InstallationCheckApi & InstallationPreparationApi) | null;
  preview: boolean; loading: boolean; onHelp: (help: HelpContent) => void;
}) {
  const description = parseInstallationDescription(info?.installation);
  const identity = useMemo(() => ({}), [info, api, preview, loading]);
  const current = useRef(identity); current.current = identity;
  const mounted = useRef(true);
  const running = useRef(false);
  const [pending, setPending] = useState(false);
  const [outcome, setOutcome] = useState<{ identity: object; error: ApiError | null } | null>(null);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const visible = outcome?.identity === identity ? outcome : null;
  const available = !preview && !loading && !!api && description?.revealAvailable === true;
  const reveal = async () => {
    if (!available || !api || running.current) return;
    running.current = true; setPending(true); setOutcome(null);
    const original = identity;
    try {
      await api.revealInstallation();
      if (mounted.current && current.current === original) setOutcome({ identity: original, error: null });
    } catch (error) {
      if (mounted.current && current.current === original) setOutcome({ identity: original, error: installationError(error) });
    } finally {
      running.current = false;
      if (mounted.current) setPending(false);
    }
  };
  return <section className="card" aria-busy={pending} aria-labelledby="installation-location-heading">
    <SectionHeading title="Application installation" />
    <h3 id="installation-location-heading">Where the app lives <HelpButton content={installationLocationHelp} onHelp={onHelp} /></h3>
    {description && !preview ? <>
      <Badge>Location policy · not an installation check</Badge>
      <dl className="environment-baseline"><dt>Expected macOS app location</dt><dd><code>{description.expectedLocation}</code></dd>
        <dt>Bundled runtime release</dt><dd><code>{description.runtimeRelease}</code></dd></dl>
      <p>The standard macOS Installer uses this protected folder. Keep the app here; a moved or copied app cannot use this installed runtime.</p>
      <div className="button-row"><button type="button" className="button secondary" disabled={!available || pending} onClick={() => void reveal()}>{pending ? 'Requesting Finder…' : 'Show in Finder'}</button></div>
      {!available && <p className="save-note">{loading ? 'Wait for the current connection to finish loading.' : 'Finder requests are unavailable in the current native runtime profile.'}</p>}
      <p>To open the installed app manually, use Finder → Go → Go to Folder, enter the location above, then open Mobile Release Kit.</p>
      <p><strong>Fresh installation only.</strong> This engineering installer does not yet repair, update or uninstall an occupied installation. Rerunning it does not replace existing files. Keep any partial-installation evidence; do not delete the protected tree to make a retry pass.</p>
      <p className="save-note">Your projects, signing originals and credential data are separate from this location card. The location description alone does not check files. The separate read-only check below performs no maintenance and does not verify signing, notarization or release readiness.</p>
    </> : <p>{preview ? 'Browser preview cannot observe an installation or request Finder.' : 'Installation location information is not available in this runtime profile. This does not mean the application is missing.'}</p>}
    <InstallationCheckPanel api={api} enabled={!preview && !loading && !!api && description !== null} onHelp={onHelp} />
    <InstallationPreparationPanel api={api} enabled={!preview && !loading && !!api && description !== null} onHelp={onHelp} />
    {visible?.error && <ErrorNotice error={visible.error} title="Finder request not confirmed" />}
    {visible && !visible.error && <p role="status">Finder request sent. Finder visibility is unconfirmed; look for the selected app in Finder. No project or installation files were changed.</p>}
  </section>;
}

function InstallationCheckPanel({ api, enabled, onHelp }: {
  api: InstallationCheckApi | null; enabled: boolean; onHelp: (help: HelpContent) => void;
}) {
  // A separate mounted controller per connection makes old invoke completions
  // inert. Native work remains in the real Document if this view unmounts.
  const identity = useMemo(() => ({}), [api, enabled]);
  const current = useRef<{ identity: object; controller: InstallationCheckController } | null>(null);
  const [rendered, render] = useState<{ identity: object; view: InstallationCheckView } | null>(null);
  useEffect(() => {
    const controller = new InstallationCheckController(api, enabled);
    current.current = { identity, controller };
    controller.attach((view) => render({ identity, view }));
    return () => {
      if (current.current?.controller === controller) current.current = null;
      controller.dispose();
    };
  }, [api, enabled, identity]);
  const controller = current.current?.identity === identity ? current.current.controller : null;
  const view: InstallationCheckView = rendered?.identity === identity ? rendered.view
    : { status: null, error: null, action: null, refreshing: false };
  const status = view.status;
  const active = installationCheckActive(status);
  return <div className="session-progress" aria-busy={active || view.action !== null}>
    <h3>Check installation <HelpButton content={installationCheckHelp} onHelp={onHelp} /></h3>
    <p>Compare the protected app, runtime and installation records without changing files. No project, signing input or Store connection is needed.</p>
    <div className="button-row">
      <button type="button" className="button secondary" disabled={!enabled || !status?.canStart || !!view.action || !!view.error}
        onClick={() => controller?.start()}>{view.action === 'starting' ? 'Starting check…' : 'Check installation'}</button>
      {active && <button type="button" className="button secondary" disabled={!!view.action}
        onClick={() => controller?.cancel()}>{view.action === 'cancelling' ? 'Requesting stop…' : 'Cancel check'}</button>}
      <button type="button" className="button secondary small" disabled={!enabled || view.refreshing}
        onClick={() => void controller?.refresh()}>{view.refreshing ? 'Checking status…' : 'Refresh status'}</button>
    </div>
    {!enabled && <p className="save-note">This check requires the normal installed macOS app, not browser preview or another runtime profile. Unavailable does not mean missing.</p>}
    {status && <div role="status" aria-live="polite">
      <Badge>{status.phase === 'observed' ? 'Read-only correspondence observed' : status.phase.replaceAll('-', ' ')}</Badge>
      <p>{INSTALLATION_CHECK_GUIDANCE[status.reason]}</p>
      {status.phase === 'checking' && <p>Reading the fixed installation. The original check has a 30-second work limit.</p>}
      {status.phase === 'stopping' && <p>Stop requested. Waiting for the original reader and its cleanup; a reply or closed screen does not establish completion.</p>}
      {status.assessment && <p>{status.assessment.files.toLocaleString()} files · {status.assessment.bytes.toLocaleString()} bytes matched their protected inventory. This is not a signing, notarization or release-readiness result.</p>}
      {status.operationId !== null && <p className="save-note">Check #{status.operationId} · Cleanup: {status.settlement}. {status.settlement === 'late-known' ? 'Late cleanup does not restore a successful check or authorize another operation.' : ''}</p>}
      {status.phase === 'not-checked' && status.available && !status.canStart && <p>Wait for the original window and other native operations to be ready before starting.</p>}
    </div>}
    {view.error && <ErrorNotice error={view.error} title="Installation check not confirmed" />}
  </div>;
}

function InstallationPreparationPanel({ api, enabled, onHelp }: {
  api: InstallationPreparationApi | null; enabled: boolean; onHelp: (help: HelpContent) => void;
}) {
  const identity = useMemo(() => ({}), [api, enabled]);
  const current = useRef<{ identity: object; controller: InstallationPreparationController } | null>(null);
  const [rendered, render] = useState<{ identity: object; view: InstallationPreparationView } | null>(null);
  const [confirmation, setConfirmation] = useState<{ identity: object; checked: boolean } | null>(null);
  useEffect(() => {
    const controller = new InstallationPreparationController(api, enabled);
    current.current = { identity, controller };
    controller.attach((view) => render({ identity, view }));
    return () => {
      if (current.current?.controller === controller) current.current = null;
      controller.dispose();
    };
  }, [api, enabled, identity]);
  const controller = current.current?.identity === identity ? current.current.controller : null;
  const view: InstallationPreparationView = rendered?.identity === identity ? rendered.view
    : { status: null, error: null, starting: false, refreshing: false };
  const checked = confirmation?.identity === identity && confirmation.checked;
  const status = view.status;
  const active = installationPreparationActive(status);
  const canConfirm = enabled && status?.canStart === true && !view.starting && !view.refreshing && !view.error;
  return <div className="session-progress" aria-busy={active || view.starting}>
    <h3>Prepare app to quit <HelpButton content={installationPreparationHelp} onHelp={onHelp} /></h3>
    <p>Save your edits and finish or cancel active work first. This stops the installed Android helper, closes new work and then uses the normal Quit flow. It does not delete projects, credentials or installed files, and makes no Store changes.</p>
    <label><input type="checkbox" checked={checked} disabled={!canConfirm}
      onChange={(event) => setConfirmation({ identity, checked: event.currentTarget.checked })} />
      {' '}I want to stop the installed Android helper and prepare this application to quit.</label>
    <div className="button-row">
      <button type="button" className="button secondary" disabled={!canConfirm || !checked}
        onClick={() => { if (controller?.start(checked)) setConfirmation({ identity, checked: false }); }}>
        {view.starting ? 'Starting preparation…' : 'Prepare and quit'}</button>
      <button type="button" className="button secondary small" disabled={!enabled || view.refreshing || view.starting}
        onClick={() => void controller?.refresh()}>{view.refreshing ? 'Checking status…' : 'Refresh preparation status'}</button>
    </div>
    {!enabled && <p className="save-note">Preparation is available only in a supported normal installed macOS app, not browser preview.</p>}
    {status && <div role="status" aria-live="polite">
      <Badge>{status.phase === 'prepared' ? 'Original preparation settled · exit unconfirmed' : status.phase.replaceAll('-', ' ')}</Badge>
      <p>{INSTALLATION_PREPARATION_GUIDANCE[status.reason]}</p>
      {active && <p>Waiting for the original native helper operation and its cleanup. Changing screens does not cancel it or start another request.</p>}
      {status.phase === 'prepared' && <p>The native completion uses the normal Quit flow. If you cancel Quit, new work remains closed; the app does not automatically register the helper again.</p>}
      {status.phase === 'refused' && <p>{status.newWorkClosed
        ? 'New work remains closed because the helper operation started or its effect was uncertain. Do not treat this as successful preparation.'
        : 'The original owner settled an early refusal without starting the helper operation. Refresh and resolve the cause before explicitly trying again.'}</p>}
      {status.operationId && <p className="save-note">Preparation #{status.generation} · {status.newWorkClosed ? 'New work closed' : 'No maintenance closure retained'}. The status is not proof that the app has exited.</p>}
    </div>}
    {view.error && <ErrorNotice error={view.error} title="Preparation not confirmed" />}
    <p className="save-note">Preparing to quit does not enable update, repair, restore or uninstall. The engineering Installer remains fresh-installation-only; keep partial installations and unknown files intact.</p>
  </div>;
}
