import type { ApiError, DesktopApi } from './types.ts';
import { installationCheckActive, installationCheckError, parseInstallationStatus, sameInstallationStatus, type InstallationStatus } from './installation.ts';

export type InstallationCheckApi = Pick<DesktopApi, 'installationStatus' | 'inspectInstallation' | 'cancelInstallation'>;
export interface InstallationCheckView {
  status: InstallationStatus | null; error: ApiError | null; action: 'starting' | 'cancelling' | null; refreshing: boolean;
}
// One controller per UI connection. Dispose only removes its own UI timer; it
// never treats unmount or an abandoned invoke as original native cancellation.
export class InstallationCheckController {
  private view: InstallationCheckView = { status: null, error: null, action: null, refreshing: false };
  private listener: ((view: InstallationCheckView) => void) | null = null;
  private disposed = false;
  private started = false;
  private statusPending = false;
  private refreshAgain = false;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private readonly api: InstallationCheckApi | null;
  private readonly enabled: boolean;
  constructor(api: InstallationCheckApi | null, enabled: boolean) { this.api = api; this.enabled = enabled; }
  snapshot(): InstallationCheckView { return this.view; }
  attach(listener: (view: InstallationCheckView) => void): void {
    if (this.disposed || this.started) return;
    this.started = true; this.listener = listener; listener(this.view);
    if (this.enabled && this.api) void this.refresh();
  }
  private update(change: Partial<InstallationCheckView>): void {
    if (this.disposed) return;
    this.view = { ...this.view, ...change }; this.listener?.(this.view);
  }
  private accept(value: unknown): void {
    const next = parseInstallationStatus(value);
    if (!next) throw installationCheckError(null);
    const previous = this.view.status;
    if (previous) {
      if (next.statusRevision < previous.statusRevision) return;
      if (next.statusRevision === previous.statusRevision) {
        if (!sameInstallationStatus(previous, next)) throw installationCheckError(null);
        this.update({ error: null }); return;
      }
      if (previous.operationId !== null && (next.operationId === null || next.operationId < previous.operationId))
        throw installationCheckError(null);
      // A higher transport revision cannot revive the same stopped/failed
      // original. LateKnown is cleanup only, never permission for new work.
      if (previous.phase === 'unknown' && (next.phase !== 'unknown' || next.operationId !== previous.operationId))
        throw installationCheckError(null);
      if (previous.operationId !== null && next.operationId === previous.operationId
        && (previous.phase === 'stopping' && ['checking', 'observed'].includes(next.phase)
          || previous.phase === 'refused' && ['checking', 'observed'].includes(next.phase)))
        throw installationCheckError(null);
    }
    this.update({ status: next, error: null });
  }
  private schedule(): void {
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
    if (!this.disposed && installationCheckActive(this.view.status)) {
      this.timer = setTimeout(() => { this.timer = null; void this.refresh(); }, 500);
    }
  }
  async refresh(): Promise<void> {
    if (this.disposed || !this.enabled || !this.api) return;
    if (this.statusPending) { this.refreshAgain = true; return; }
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null; this.statusPending = true; this.update({ refreshing: true });
    try {
      const status = await this.api.installationStatus();
      if (!this.disposed) this.accept(status);
    } catch (error) { this.update({ error: installationCheckError(error) }); }
    finally {
      this.statusPending = false; this.update({ refreshing: false });
      const again = this.refreshAgain; this.refreshAgain = false;
      if (!this.disposed && again) void this.refresh(); else this.schedule();
    }
  }
  start(): boolean {
    if (this.disposed || !this.enabled || !this.api || this.view.action || this.view.error || !this.view.status?.canStart) return false;
    this.update({ action: 'starting', error: null });
    void Promise.resolve().then(() => {
      if (this.disposed) return null;
      return this.api!.inspectInstallation();
    }).then((status) => {
      if (!this.disposed) this.accept(status);
    }).catch((error: unknown) => { this.update({ error: installationCheckError(error) }); })
      .finally(() => {
        this.update({ action: null });
        // DATA-only reconciliation also covers a lost/malformed acknowledgement.
        // Never automatically issue another Start or Cancel.
        if (!this.disposed) void this.refresh();
      });
    return true;
  }
  cancel(): boolean {
    const status = this.view.status;
    if (this.disposed || !this.enabled || !this.api || this.view.action || !installationCheckActive(status) || status?.operationId == null) return false;
    const originalId = status.operationId;
    this.update({ action: 'cancelling', error: null });
    void Promise.resolve().then(() => {
      if (this.disposed) return null;
      return this.api!.cancelInstallation({ operationId: originalId });
    }).then((reply) => {
      if (!this.disposed) this.accept(reply);
    }).catch((error: unknown) => { this.update({ error: installationCheckError(error) }); })
      .finally(() => { this.update({ action: null }); if (!this.disposed) void this.refresh(); });
    return true;
  }
  dispose(): void {
    this.disposed = true; this.listener = null; this.refreshAgain = false;
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
  }
}
