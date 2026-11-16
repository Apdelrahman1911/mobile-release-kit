import { createRoot } from 'react-dom/client';
import { App } from './App.tsx';
import { WorkspaceBoundary } from './workspaceBoundary.tsx';
import { installWorkspaceDiagnostics } from './workspaceDiagnostics.ts';
import './theme.css';
import './styles.css';

const stopDiagnostics = installWorkspaceDiagnostics(window);
if (import.meta.hot) import.meta.hot.dispose(stopDiagnostics);
const root = document.getElementById('root');
if (!root) throw new Error('Application root is unavailable.');
createRoot(root).render(<WorkspaceBoundary><App /></WorkspaceBoundary>);
