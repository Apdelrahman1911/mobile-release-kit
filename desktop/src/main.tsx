import { Component } from 'react';
import type { ErrorInfo, ReactNode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App.tsx';
import './theme.css';
import './styles.css';

type Failure = { name: string; message: string; component: string };

class Boundary extends Component<{ children: ReactNode }, { failed: boolean; failure: Failure | null }> {
  state: { failed: boolean; failure: Failure | null } = { failed: false, failure: null };
  static getDerivedStateFromError() { return { failed: true }; }
  componentDidCatch(error: Error, info: ErrorInfo) {
    // Shown only on this screen (never logged to a console): error type, a
    // short message and the nearest components, so the cause can be reported.
    const component = (info.componentStack ?? '').split('\n').map((line) => line.trim()).filter(Boolean).slice(0, 4).join(' ← ');
    this.setState({ failure: { name: error?.name ?? 'Error', message: String(error?.message ?? '').slice(0, 240), component: component.slice(0, 300) } });
  }
  render() {
    if (this.state.failed) return <main className="fatal-error"><h1>Something went wrong showing this screen.</h1>
      <p>Your saved project files are not changed by this. Close and reopen the app. If a task was running, check its status after reopening before trying it again.</p>
      {this.state.failure && <details className="tech-details" open><summary>Error details</summary>
        <p><strong>{this.state.failure.name}</strong>: {this.state.failure.message}</p><p>{this.state.failure.component}</p></details>}</main>;
    return this.props.children;
  }
}

const root = document.getElementById('root');
if (!root) throw new Error('Application root is unavailable.');
createRoot(root).render(<Boundary><App /></Boundary>);
