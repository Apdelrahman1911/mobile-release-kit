import { useCallback, useEffect, useReducer, useRef, useState } from 'react';
import { desktopApi } from './api.ts';
import { apiError } from './bridge.ts';
import { emptyDraft } from './catalog.ts';
import { methodReason } from './certainty.ts';
import { initialWorkspace, isDirty, workspaceReducer } from './drafts.ts';
import { suggestionHints } from './preparation.ts';
import type { ApiError, AppInfo, Catalog, DesktopApi, HelpContent, JsonValue, Page } from './types.ts';
import { Badge, ConfirmDialog, ErrorNotice, HelpDialog, PageHeading } from './components/Common.tsx';
import { DraftEditor } from './components/DraftEditor.tsx';
import { Icon } from './components/Icon.tsx';
import type { IconName } from './components/Icon.tsx';
import { Dashboard } from './pages/Dashboard.tsx';
import { Environment } from './pages/Environment.tsx';
import { Credentials } from './pages/Credentials.tsx';
import { Metadata } from './pages/Metadata.tsx';
import { Artifacts, GitHub, Recovery, Releases } from './pages/Future.tsx';

const navigation: { id: Page; label: string; icon: IconName; group: 'workspace' | 'release' }[] = [
  { id: 'dashboard', label: 'Dashboard', icon: 'dashboard', group: 'workspace' },
  { id: 'settings', label: 'Project settings', icon: 'settings', group: 'workspace' },
  { id: 'environment', label: 'Environment', icon: 'environment', group: 'workspace' },
  { id: 'credentials', label: 'Credentials', icon: 'key', group: 'workspace' },
  { id: 'metadata', label: 'Metadata', icon: 'metadata', group: 'workspace' },
  { id: 'github', label: 'GitHub', icon: 'github', group: 'release' },
  { id: 'releases', label: 'Releases', icon: 'rocket', group: 'release' },
  { id: 'artifacts', label: 'Artifacts', icon: 'box', group: 'release' },
  { id: 'recovery', label: 'Recovery', icon: 'recovery', group: 'release' },
];

export function App() {
  const [api, setApi] = useState<DesktopApi | null>(null);
  const [info, setInfo] = useState<AppInfo | null>(null);
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  const [loading, setLoading] = useState(true);
  const [bootError, setBootError] = useState<ApiError | null>(null);
  const [catalogError, setCatalogError] = useState<ApiError | null>(null);
  const [choosing, setChoosing] = useState(false);
  const [chooseError, setChooseError] = useState<ApiError | null>(null);
  const [page, setPage] = useState<Page>('dashboard');
  const [help, setHelp] = useState<HelpContent | null>(null);
  const [discardProject, setDiscardProject] = useState<string | null>(null);
  const [workspace, dispatch] = useReducer(workspaceReducer, initialWorkspace);
  const workspaceRef = useRef(workspace);
  workspaceRef.current = workspace;
  const requests = useRef(0);
  const bootGeneration = useRef(0);
  const main = useRef<HTMLElement>(null);
  const mode = api?.mode ?? 'unavailable';
  const preview = mode === 'preview';
  const session = workspace.selectedId ? workspace.projects[workspace.selectedId] ?? null : null;
  const currentNavigation = navigation.find((item) => item.id === page) ?? navigation[0];

  const bootstrap = useCallback(async () => {
    const generation = ++bootGeneration.current;
    setLoading(true);
    setBootError(null);
    setCatalogError(null);
    try {
      const connection = await desktopApi();
      if (generation !== bootGeneration.current) return;
      setApi(connection);
      const appInfo = await connection.appInfo();
      if (generation !== bootGeneration.current) return;
      setInfo(appInfo);
      if (connection.mode === 'preview' || methodReason(appInfo, 'catalog', connection.mode) === null) {
        try {
          const result = await connection.catalog();
          if (generation === bootGeneration.current) setCatalog(result);
        } catch (error) {
          if (generation === bootGeneration.current) { setCatalog(null); setCatalogError(apiError(error)); }
        }
      } else {
        setCatalog(null);
      }
    } catch (error) {
      if (generation === bootGeneration.current) { setInfo(null); setCatalog(null); setBootError(apiError(error)); }
    } finally {
      if (generation === bootGeneration.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void bootstrap();
    return () => { bootGeneration.current += 1; };
  }, [bootstrap]);

  useEffect(() => {
    document.title = `${currentNavigation?.label ?? 'Dashboard'} · Mobile Release Kit${preview ? ' · Browser preview' : ''}`;
  }, [currentNavigation, preview]);

  useEffect(() => {
    const warn = (event: BeforeUnloadEvent) => {
      if (Object.values(workspaceRef.current.projects).some(isDirty)) {
        event.preventDefault();
        event.returnValue = '';
      }
    };
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, []);

  const navigate = (next: Page) => { setPage(next); main.current?.focus({ preventScroll: true }); };
  const refreshReason = methodReason(info, 'project.snapshot', mode);
  const validateReason = methodReason(info, 'config.validate', mode);
  const reviewReason = methodReason(info, 'config.preview', mode);
  const suggestReason = methodReason(info, 'config.suggest', mode);
  const chooseDisabled = loading || choosing || mode === 'unavailable';

  const loadSnapshot = async (projectId: string) => {
    if (!api || (refreshReason !== null && !preview)) return;
    const requestId = ++requests.current;
    dispatch({ type: 'snapshot-start', projectId, requestId });
    try {
      const snapshot = await api.snapshot(projectId);
      dispatch({ type: 'snapshot-done', projectId, requestId, snapshot, observedAt: Date.now() });
    } catch (error) {
      dispatch({ type: 'snapshot-failed', projectId, requestId, error: apiError(error) });
    }
  };

  const chooseProject = async () => {
    if (!api || chooseDisabled) return;
    setChoosing(true);
    setChooseError(null);
    try {
      const project = await api.chooseProject();
      if (!project) return;
      const alreadyLoaded = workspaceRef.current.projects[project.id]?.snapshot;
      dispatch({ type: 'select', project });
      if (!alreadyLoaded) await loadSnapshot(project.id);
    } catch (error) { setChooseError(apiError(error)); }
    finally { setChoosing(false); }
  };

  const validate = async () => {
    if (!api || !session?.draft || validateReason !== null || session.validationRequest || session.reviewRequest) return;
    const projectId = session.project.id;
    const requestId = ++requests.current;
    const revision = session.revision;
    const baselineGeneration = session.baselineGeneration;
    const draft = structuredClone(session.draft);
    dispatch({ type: 'validate-start', projectId, requestId, revision, baselineGeneration });
    try {
      const result = await api.validate(draft);
      dispatch({ type: 'validate-done', projectId, requestId, result });
    } catch (error) { dispatch({ type: 'validate-failed', projectId, requestId, error: apiError(error) }); }
  };

  const review = async () => {
    if (!api || !session?.draft || reviewReason !== null || session.reviewRequest || session.validationRequest) return;
    const projectId = session.project.id;
    const binding = { id: ++requests.current, revision: session.revision, baselineGeneration: session.baselineGeneration };
    const base = structuredClone(session.baseline);
    const draft = structuredClone(session.draft);
    dispatch({ type: 'review-start', projectId, binding });
    try {
      const result = await api.configPreview(base, draft);
      dispatch({ type: 'review-done', projectId, requestId: binding.id, result });
    } catch (error) { dispatch({ type: 'review-failed', projectId, requestId: binding.id, error: apiError(error) }); }
  };

  const suggest = async () => {
    if (!api || !session || session.draft !== null || suggestReason !== null || session.suggestionRequest || session.snapshotRequest) return;
    const projectId = session.project.id;
    const projection = suggestionHints(session.snapshot?.discovery.hints ?? null);
    const binding = {
      id: ++requests.current, revision: session.revision, baselineGeneration: session.baselineGeneration,
      observationGeneration: session.observationGeneration, observedHints: session.snapshot !== null,
      partial: session.snapshot?.discovery.partial ?? false, omittedStrings: projection.omittedStrings,
    };
    dispatch({ type: 'suggest-start', projectId, binding });
    try {
      const result = await api.suggestConfig(projection.hints);
      dispatch({ type: 'suggest-done', projectId, requestId: binding.id, result });
    } catch (error) { dispatch({ type: 'suggest-failed', projectId, requestId: binding.id, error: apiError(error) }); }
  };

  const edit = (path: string, value: JsonValue | undefined) => {
    if (session) dispatch({ type: 'edit', projectId: session.project.id, path, value });
  };

  const editor = (metadataOnly = false) => <DraftEditor
    key={`${session?.project.id ?? 'none'}-${metadataOnly ? 'metadata' : 'settings'}`}
    catalog={catalog} session={session} metadataOnly={metadataOnly} preview={preview}
    validateReason={loading ? 'Engine capabilities are being loaded.' : validateReason}
    reviewReason={loading ? 'Engine capabilities are being loaded.' : reviewReason}
    suggestReason={loading ? 'Engine capabilities are being loaded.' : suggestReason}
    onChoose={() => void chooseProject()} onEdit={edit} onValidate={() => void validate()}
    onReview={() => void review()} onSuggest={() => void suggest()}
    onAdoptSuggestion={(requestId) => { if (session) dispatch({ type: 'adopt-suggestion', projectId: session.project.id, requestId }); }}
    onRemoveForbidden={(reviewId, paths) => { if (session) dispatch({ type: 'remove-forbidden', projectId: session.project.id, reviewId, paths }); }}
    onUndoRemoval={(removalId) => { if (session) dispatch({ type: 'undo-removal', projectId: session.project.id, removalId }); }}
    onForgetRemoval={(removalId) => { if (session) dispatch({ type: 'forget-removal', projectId: session.project.id, removalId }); }}
    onNewDraft={() => { if (session && catalog) dispatch({ type: 'new-draft', projectId: session.project.id, draft: emptyDraft(catalog.schema) }); }}
    onDiscard={() => { if (session) setDiscardProject(session.project.id); }} onHelp={setHelp}
  />;

  return <div className="app-shell">
    <a className="skip-link" href="#main-content">Skip to workspace</a>
    <aside className="sidebar">
      <div className="brand"><span className="brand-mark"><Icon name="box" size={25} /></span><div>Mobile Release Kit<span>THE KIT FOR A CAREFUL LAUNCH</span></div></div>
      <div className="project-switcher"><label htmlFor="project-switch">CURRENT PROJECT</label><div className="project-switcher-control"><span className="project-switch-icon"><Icon name="folder" size={18} /></span><select id="project-switch" aria-label="Switch project; unsaved drafts are retained" value={workspace.selectedId ?? ''} onChange={(event) => dispatch({ type: 'switch', projectId: event.target.value })}><option value="" disabled>{choosing ? 'Opening project…' : 'Choose a project'}</option>{Object.values(workspace.projects).map((entry) => <option key={entry.project.id} value={entry.project.id}>{entry.project.name}{isDirty(entry) ? ' • unsaved' : ''}</option>)}</select><button type="button" className="icon-button" disabled={chooseDisabled} aria-label={preview ? 'Load example project' : 'Open another project folder'} onClick={() => void chooseProject()}><Icon name="plus" size={16} /></button></div></div>
      <nav aria-label="Workspace navigation">{(['workspace', 'release'] as const).map((group) => <div className="nav-group" key={group}><span className="nav-group-label">{group === 'workspace' ? 'WORKSPACE' : 'DELIVERY'}</span>{navigation.filter((entry) => entry.group === group).map((entry) => <button type="button" key={entry.id} className={`nav-item${entry.id === page ? ' active' : ''}`} aria-label={entry.label} aria-current={entry.id === page ? 'page' : undefined} onClick={() => navigate(entry.id)}><Icon name={entry.icon} size={19} /><span>{entry.label}</span>{entry.id === 'releases' && <span className="nav-soon">SOON</span>}</button>)}</div>)}</nav>
      <div className="sidebar-footer"><div className="foundation-label"><span className="local-dot" />Read-only foundation</div><p>Thoughtful preparation.<br />No accidental releases.</p><div className="sidebar-version"><span>DESKTOP {info?.appVersion ?? 'Not loaded'}</span><Icon name="shield" size={14} /></div></div>
    </aside>
    <div className="workspace">
      <header className="topbar"><div className="breadcrumbs"><Icon name="folder" size={16} /><span>{session?.project.name ?? 'Workspace'}</span><Icon name="chevron" size={13} /><strong>{currentNavigation?.label}</strong></div><div className="topbar-status"><span className="no-write-note"><Icon name="lock" size={13} />No writes or release operations</span><Badge tone={preview ? 'warning' : 'neutral'}>{preview ? 'Browser preview' : 'Read-only preparation'}</Badge></div></header>
      {preview && <div className="preview-banner" role="status"><Icon name="environment" size={19} /><div><strong>BROWSER PREVIEW — EXAMPLE DATA ONLY</strong><span>No native bridge, project files, core validation, credentials, or release operations. Never use this view as evidence.</span></div></div>}
      <main id="main-content" tabIndex={-1} ref={main}>
        {loading && <div className="notice notice-info" role="status"><Icon name="refresh" className="spin" size={19} /><span>Loading desktop capabilities and the core field catalogue…</span></div>}
        {bootError && <><ErrorNotice error={bootError} title="The native service is unavailable" /><div className="bridge-retry"><button className="button small secondary" disabled={loading} onClick={() => void bootstrap()}><Icon name="refresh" size={15} />Retry connection</button><span>No browser fallback or mock engine has been enabled.</span></div></>}
        {catalogError && <ErrorNotice error={catalogError} title="The field catalogue could not be loaded" />}
        {chooseError && <ErrorNotice error={chooseError} title="The project could not be selected" />}
        {info?.runtime.state !== 'available' && info && !preview && <div className="notice notice-warning"><Icon name="info" /><div><strong>{info.runtime.state === 'disabled' ? 'The engine is disabled' : 'Bundled engine unavailable'}</strong><p>{info.runtime.reason ?? 'A trusted packaged runtime has not been supplied. The app will not select an ambient Python or a mock engine.'} Folder selection does not establish a project observation.</p></div></div>}
        {page === 'dashboard' && <Dashboard session={session} info={info} preview={preview} chooseDisabled={chooseDisabled} refreshReason={loading ? 'Capabilities are loading.' : refreshReason} onChoose={() => void chooseProject()} onRefresh={() => { if (session) void loadSnapshot(session.project.id); }} onNavigate={navigate} onHelp={setHelp} />}
        {page === 'settings' && <><PageHeading eyebrow="PROJECT SETTINGS" title="A little clarity before the next release." description="Edit a practical, schema-driven draft. The bundled core provides every field, requirement, and validation rule." />{editor()}</>}
        {page === 'environment' && <Environment info={info} preview={preview} onRetry={() => void bootstrap()} loading={loading} />}
        {page === 'credentials' && <Credentials catalog={catalog} onHelp={setHelp} />}
        {page === 'metadata' && <Metadata catalog={catalog}>{editor(true)}</Metadata>}
        {page === 'github' && <GitHub info={info} onNavigate={navigate} />}
        {page === 'releases' && <Releases info={info} />}
        {page === 'artifacts' && <Artifacts info={info} />}
        {page === 'recovery' && <Recovery info={info} />}
        <footer className="workspace-footer"><span><Icon name="shield" size={14} />Configuration is not verification.</span><span>{preview ? 'Illustration only · no engine connected' : 'Read-only desktop foundation · not a completed release product'}</span></footer>
      </main>
    </div>
    <HelpDialog content={help} onClose={() => setHelp(null)} />
    {discardProject && <ConfirmDialog onCancel={() => setDiscardProject(null)} onConfirm={() => { dispatch({ type: 'reset', projectId: discardProject }); setDiscardProject(null); }} />}
  </div>;
}
