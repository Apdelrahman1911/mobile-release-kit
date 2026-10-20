import type { AndroidToolSourceRole } from '../androidToolSources.ts';
import type { PreparedToolFolders } from '../toolAcquisitionSourcePicker.ts';
import { TOOL_DISCOVERY_HELP } from '../toolSourceDiscovery.ts';

const label = (role: AndroidToolSourceRole) => role === 'jdk' ? 'JDK' : role === 'sdk' ? 'Android SDK' : 'Gradle';

/** Same app-held acquisition and Android controllers. No mount effects, paths,
 * automatic selection/download, extra approval, or replacement of live work. */
export function DiscoveredToolSources({ folders, busy, checkReason, chooseFound, chooseExisting, checkAgain }: {
  folders: PreparedToolFolders; busy: boolean; checkReason: string | null;
  chooseFound(role: AndroidToolSourceRole): void | Promise<void>;
  chooseExisting(role: AndroidToolSourceRole): void | Promise<void>;
  checkAgain(): void | Promise<void>;
}) {
  return <div className="notice notice-info"><div>
    <strong>Found existing tools</strong>
    <p>These folders contain checked matching components. Keep them unchanged. Use the normal folder picker to select them, then check any remaining tools. Nothing has been downloaded or registered.</p>
    <div className="button-row">{folders.roles.map((role) => <button type="button" className="button primary" key={role}
      disabled={busy || folders.waiting} onClick={() => void chooseFound(role)}>Use found {label(role)}…</button>)}</div>
    {folders.waiting && <p role="status">Finish the current folder selection using its original controls below.</p>}
    {folders.incompleteSdk && <p>The found SDK has one matching required package. Selecting it lets the app reuse that package and prepare only the missing part in a separate folder. Other installed packages stay unchanged.</p>}
    <div className="button-row"><button type="button" className="button secondary" disabled={busy || folders.waiting || checkReason !== null}
      onClick={() => void checkAgain()}>Check remaining tools</button></div>
    {checkReason && <p className="save-note">{checkReason}</p>}
    <details><summary>Use another installation &amp; search scope</summary><p>{TOOL_DISCOVERY_HELP}</p>
      <div className="button-row">{(['jdk', 'sdk', 'gradle'] as const).map((role) => <button type="button" className="button secondary" key={role}
        disabled={busy || folders.waiting} onClick={() => void chooseExisting(role)}>Choose another {label(role)}</button>)}</div>
      <p>Choosing a folder is not installation approval. Inspect the selected tools and separately review any protected copy before building. A wrong or unreadable existing installation is never overwritten.</p>
    </details>
  </div></div>;
}
