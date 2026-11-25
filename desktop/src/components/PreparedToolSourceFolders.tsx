import type { AndroidToolSourceRole } from '../androidToolSources.ts';
import type { PreparedToolFolders } from '../toolAcquisitionSourcePicker.ts';

interface Props {
  folders: PreparedToolFolders;
  busy: boolean;
  choosePrepared(role: AndroidToolSourceRole): void | Promise<void>;
  chooseExisting(role: AndroidToolSourceRole): void | Promise<void>;
  openRegistration(): void;
}
/** Controlled only. Mounting neither opens a picker nor downloads/copies tools. */
export function PreparedToolSourceFolders({ folders, busy, choosePrepared, chooseExisting, openRegistration }: Props) {
  return <div className="notice notice-info"><div><strong>Choose the prepared tool folders</strong>
    <p>Open each folder in the native picker and confirm your choice. Then inspect the sources and separately approve a protected copy. Nothing is registered or build-ready yet.</p>
    {folders.waiting && <p role="status">Finish the current folder choice. Its original tool-selection status and cancel controls remain available.</p>}
    <div className="button-row">{folders.roles.map((role) => <button type="button" className="button secondary" key={role}
      disabled={busy || folders.waiting} onClick={() => void choosePrepared(role)}>
      {role === 'jdk' ? 'Choose prepared JDK' : role === 'sdk' ? 'Choose prepared Android SDK' : 'Choose prepared Gradle'}
    </button>)}
      <button type="button" className="button secondary" disabled={busy || folders.waiting} onClick={openRegistration}>Inspect &amp; review selected tools</button>
    </div>
    {folders.incompleteSdk && <><p>The prepared SDK is incomplete. Choose a complete supported SDK you already have, or finish manual SDK setup without replacing working tools.</p>
      <button type="button" className="button secondary" disabled={busy || folders.waiting} onClick={() => void chooseExisting('sdk')}>Choose complete existing Android SDK</button></>}
    <p className="save-note">The starting folder is a convenience, not a check of its current contents. You can choose an existing installation elsewhere; the ordinary inspection and approval steps are unchanged.</p>
  </div></div>;
}
