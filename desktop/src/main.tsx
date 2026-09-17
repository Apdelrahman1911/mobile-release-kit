import { Component } from 'react';
import type { ErrorInfo, ReactNode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App.tsx';
import './styles.css';

class Boundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  componentDidCatch(_error: Error, _info: ErrorInfo) {
    // Do not log project-provided text or bridge rejections to a public console.
  }
  render() {
    if (this.state.failed) return <main className="fatal-error"><h1>The workspace could not be displayed.</h1><p>No operation is confirmed by this screen. No mock or browser fallback has been enabled. In-memory edits may be unavailable; do not treat a missing status as success.</p></main>;
    return this.props.children;
  }
}

const root = document.getElementById('root');
if (!root) throw new Error('Application root is unavailable.');
createRoot(root).render(<Boundary><App /></Boundary>);
