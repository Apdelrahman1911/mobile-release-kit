import { useState } from 'react';
import { workspaceDiagnostics } from '../workspaceDiagnostics.ts';

export function WorkspaceDiagnosticHistory() {
  const [records, setRecords] = useState(() => workspaceDiagnostics().snapshot());
  return <details className="tech-details"><summary>Local workspace error diagnostics</summary>
    <p>These bounded records contain failure codes and component names. They stay in this app's local storage and contain no raw messages, project data or credentials.</p>
    <button type="button" className="button secondary small" onClick={() => setRecords(workspaceDiagnostics().snapshot())}>Refresh local error records</button>
    {records.length === 0 ? <p>No workspace errors have been recorded in this app's local storage.</p>
      : <pre>{JSON.stringify({ schemaVersion: 1, records }, null, 2)}</pre>}
  </details>;
}
