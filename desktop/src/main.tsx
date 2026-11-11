import { Component } from 'react';
import type { ErrorInfo, ReactNode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App.tsx';
import './styles.css';
import { workspaceFatalDiagnostic, type WorkspaceFatalDiagnostic } from './workspaceFatalDiagnostic.ts';

class Boundary extends Component<{ children: ReactNode }, { failed: boolean; diagnostic: WorkspaceFatalDiagnostic | null }> {
  state = { failed: false, diagnostic: null as WorkspaceFatalDiagnostic | null };
  static getDerivedStateFromError() { return { failed: true }; }
  componentDidCatch(error: Error, info: ErrorInfo) {
    // Preserve the first fixed diagnostic; ErrorInfo and raw text never escape.
    if (this.state.diagnostic !== null) return;
    const diagnostic = workspaceFatalDiagnostic(error, info);
    this.setState((state) => state.diagnostic === null ? { diagnostic } : null);
  }
  render() {
    if (this.state.failed) return <main className="fatal-error"><h1>The workspace could not be displayed.</h1><p>No operation is confirmed by this screen. No mock or browser fallback has been enabled. In-memory edits may be unavailable; do not treat a missing status as success.</p>
      <p>{this.state.diagnostic ? <>Diagnostic: <bdi dir="ltr">{this.state.diagnostic.code} · {this.state.diagnostic.category} · component {this.state.diagnostic.component ?? 'unavailable'}{this.state.diagnostic.reactCode !== null ? ` · React code ${this.state.diagnostic.reactCode}` : ''}</bdi></> : 'Diagnostic: unavailable.'}</p></main>;
    return this.props.children;
  }
}

const root = document.getElementById('root');
if (!root) throw new Error('Application root is unavailable.');
createRoot(root).render(<Boundary><App /></Boundary>);
