import { Component } from 'react';
import type { ErrorInfo, ReactNode } from 'react';
import { workspaceDiagnostics, workspaceFailureDescription } from './workspaceDiagnostics.ts';
import type { RecordedFailure, WorkspaceDiagnostics } from './workspaceDiagnostics.ts';

export class WorkspaceBoundary extends Component<{ children: ReactNode; diagnostics?: WorkspaceDiagnostics }, { failed: boolean; record: RecordedFailure | null }> {
  state: { failed: boolean; record: RecordedFailure | null } = { failed: false, record: null };
  static getDerivedStateFromError() { return { failed: true }; }
  componentDidCatch(error: unknown, info: ErrorInfo) {
    const diagnostics = this.props.diagnostics ?? workspaceDiagnostics();
    this.setState({ record: diagnostics.capture(error, 'boundary', info.componentStack) });
  }
  render() {
    if (!this.state.failed) return this.props.children;
    const record = this.state.record;
    return <main className="fatal-error"><h1>Something went wrong showing this screen.</h1>
      <p>Your saved project files are not changed by this screen. Close and reopen the app. If a task was running, check its status after reopening before trying it again.</p>
      {record && <details className="tech-details" open><summary>Error details</summary>
        <p>{workspaceFailureDescription(record.failure)}</p>
        <p>Diagnostic #{record.failure.sequence} · {record.failure.errorType} · {record.failure.category}
          {record.failure.reactCode !== null && ` · React ${record.failure.reactCode}`}</p>
        <p>{record.failure.components.join(' ← ')}</p>
        <p>{record.persisted ? 'A bounded diagnostic record was saved locally for investigation.' : 'Persistent diagnostics are unavailable; keep this diagnostic number before closing.'}</p>
      </details>}
    </main>;
  }
}
