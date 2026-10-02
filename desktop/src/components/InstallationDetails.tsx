import { useEffect, useMemo, useRef, useState } from 'react';
import type { ApiError, AppInfo, DesktopApi, HelpContent } from '../types.ts';
import { installationError, installationLocationHelp, parseInstallationDescription } from '../installation.ts';
import { Badge, ErrorNotice, HelpButton, SectionHeading } from './Common.tsx';

export function InstallationDetails({ info, api, preview, loading, onHelp }: {
  info: AppInfo | null; api: Pick<DesktopApi, 'revealInstallation'> | null;
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
      <p className="save-note">Your projects, signing originals and credential data are separate from this location card. It performs no maintenance and does not verify installation integrity, signing, notarization or release readiness.</p>
    </> : <p>{preview ? 'Browser preview cannot observe an installation or request Finder.' : 'Installation location information is not available in this runtime profile. This does not mean the application is missing.'}</p>}
    {visible?.error && <ErrorNotice error={visible.error} title="Finder request not confirmed" />}
    {visible && !visible.error && <p role="status">Finder request sent. Finder visibility is unconfirmed; look for the selected app in Finder. No project or installation files were changed.</p>}
  </section>;
}
