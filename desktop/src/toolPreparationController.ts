import { encodeAndroidCatalogRequest } from './androidToolchainCatalogProtocol.ts';
import { encodeToolPreparationRequest, parseToolPreparationPlan, sameToolPreparationCopy, sameToolPreparationDecision } from './toolPreparationProtocol.ts';
import type { SelectAndroidToolchain } from './androidToolchainCatalogTypes.ts';
import type { ToolPreparationActions, ToolPreparationApi, ToolPreparationPlan, ToolPreparationRequest } from './toolPreparationTypes.ts';

export interface ToolPreparationState { plan: ToolPreparationPlan | null; pending: boolean; stale: boolean; error: string | null }
const changed = 'Your project or tools changed. Check again before continuing.';
const unavailable = 'The tool check is unavailable. Use the existing tool controls to check its status.';
function freeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
}
export class ToolPreparationController {
  private generation = 0;
  private disposed = false;
  // Presentation invalidation cannot retire the actual original read or an
  // already-forwarded controller promise. Only its own finally releases this.
  private inFlight = false;
  private selection: Omit<ToolPreparationRequest, 'schemaVersion'> | null = null;
  private state: ToolPreparationState = freeze({ plan: null, pending: false, stale: true, error: null });
  private listeners = new Set<() => void>();
  private readonly api: ToolPreparationApi;
  private readonly actions: ToolPreparationActions;
  constructor(api: ToolPreparationApi, actions: ToolPreparationActions) { this.api = api; this.actions = actions; }
  getSnapshot = (): ToolPreparationState => this.state;
  subscribe = (listener: () => void): (() => void) => { if (!this.disposed) this.listeners.add(listener); return () => this.listeners.delete(listener); };
  private publish(change: Partial<ToolPreparationState>): void {
    this.state = freeze({ ...this.state, ...change }); this.listeners.forEach((listener) => listener());
  }
  select(selection: Omit<ToolPreparationRequest, 'schemaVersion'> | null): void {
    if (this.disposed) return;
    if (selection?.projectId === this.selection?.projectId && selection?.expectedObservationRevision === this.selection?.expectedObservationRevision) return;
    if (selection && !encodeToolPreparationRequest({ schemaVersion: 1, ...selection })) {
      this.generation++; this.selection = null; this.publish({ plan: null, pending: this.inFlight, stale: true, error: unavailable }); return;
    }
    this.generation++; this.selection = selection ? { ...selection } : null;
    this.publish({ plan: null, pending: this.inFlight, stale: true, error: null });
  }
  invalidate(): void { if (this.disposed) return; this.generation++; this.publish({ pending: this.inFlight, stale: true }); }
  dispose(): void { this.disposed = true; this.generation++; this.listeners.clear(); this.selection = null; }
  private async read(generation: number): Promise<ToolPreparationPlan | null> {
    const selected = this.selection;
    if (!selected) return null;
    const plan = parseToolPreparationPlan(await this.api.toolPreparationPlan({ schemaVersion: 1, ...selected }));
    if (generation !== this.generation) return null;
    if (!plan || plan.context.projectId !== selected.projectId || plan.context.observationRevision !== selected.expectedObservationRevision) throw new Error(changed);
    return plan;
  }
  async refresh(): Promise<boolean> {
    if (this.disposed || !this.selection || this.inFlight) return false;
    const generation = this.generation;
    this.inFlight = true;
    this.publish({ pending: true, error: null });
    try {
      const plan = await this.read(generation);
      if (!plan) return false;
      this.publish({ plan, stale: false }); return true;
    } catch {
      if (generation === this.generation) this.publish({ stale: true, error: unavailable });
      return false;
    } finally { this.inFlight = false; if (!this.disposed) this.publish({ pending: false }); }
  }
  async continue(comparison?: SelectAndroidToolchain): Promise<boolean> {
    const previous = this.state.plan;
    if (this.disposed || !previous || this.state.stale || this.inFlight || ['busy', 'unsupported'].includes(previous.state)) return false;
    let selected: SelectAndroidToolchain | null = null;
    if (previous.action === 'choose-registered-copy') {
      const raw = encodeAndroidCatalogRequest('select_android_toolchain', comparison);
      if (!raw) return false;
      selected = JSON.parse(new TextDecoder().decode(raw)) as SelectAndroidToolchain;
      if (!previous.reusable.some((copy) => sameToolPreparationCopy(copy, selected!))) return false;
    }
    const generation = this.generation;
    this.inFlight = true;
    this.publish({ pending: true, error: null });
    try {
      const current = await this.read(generation);
      if (!current) return false;
      if (!sameToolPreparationDecision(previous, current)) { this.publish({ plan: current, stale: true, error: changed }); return false; }
      // These are explicit-click adapters to the existing controllers. Installer
      // registration and copy approval are NEVER performed in this controller.
      switch (current.action) {
        case 'check-project-requirements': this.actions.showProjectRequirements(); break;
        case 'refresh-registered-tools': await this.actions.refreshRegisteredTools(); break;
        case 'choose-registered-copy': await this.actions.chooseRegisteredCopy(structuredClone(selected!)); break;
        case 'use-selected-copy': this.actions.showBuild(); break;
        case 'choose-jdk': await this.actions.chooseSource('jdk'); break;
        case 'choose-sdk': await this.actions.chooseSource('sdk'); break;
        case 'choose-gradle': await this.actions.chooseSource('gradle'); break;
        case 'inspect-sources': case 'review-protected-copy': case 'review-source-problem': this.actions.showSourceInspection(); break;
        case 'check-tool-service': case 'register-tool-service': case 'open-tool-service-settings': this.actions.showToolService(); break;
        case 'reconcile-setup': this.actions.showRecovery(); break;
        case 'check-xcode': case 'inspect-xcode-copy': this.actions.showXcodeChecks(); break;
        case 'install-xcode-manually': this.actions.showXcodeInstructions(); break;
        default: return false;
      }
      if (generation === this.generation) this.publish({ stale: true });
      return true; // Forwarded, NOT installed, settled, or ready.
    } catch {
      if (generation === this.generation) this.publish({ stale: true, error: unavailable });
      return false;
    } finally { this.inFlight = false; if (!this.disposed) this.publish({ pending: false }); }
  }
}
