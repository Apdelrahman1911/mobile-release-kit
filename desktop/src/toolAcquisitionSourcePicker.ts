// A short-lived UI handoff to the EXISTING Android source-picker controller.
// IDs nominate an initial directory only. No path, SourceSnapshot, tool lease,
// registration consent, filesystem access or native qualification lives here.
import { parseAndroidToolSourcesStatus, sameAndroidToolSourceIdentity } from './androidToolSources.ts';
import type { AndroidToolSourceRole, AndroidToolSourcesStatus } from './androidToolSources.ts';
import { parseAndroidToolchainCatalogStatus } from './androidToolchainCatalogProtocol.ts';
import { parseAndroidToolRegistrationStatus } from './androidToolRegistration.ts';
import { foundToolRoles, parseToolSourceDiscovery } from './toolSourceDiscovery.ts';
import { parseToolAcquisitionStatus } from './toolAcquisitionProtocol.ts';
import { parseStagedToolSources } from './toolAcquisitionGuidance.ts';
import type { StagedToolPresentation } from './toolAcquisitionGuidance.ts';
import { sameToolAcquisitionData } from './toolAcquisitionProtocol.ts';
import type { ToolAcquisitionContext, ToolAcquisitionIdentity, ToolAcquisitionOperation } from './toolAcquisitionProtocol.ts';

export interface ToolSourceFolderContext {
  connection: object; context: ToolAcquisitionContext; observation: number;
  draft: unknown; baseline: unknown; snapshot: unknown;
  catalog: unknown; registration: unknown; sources: unknown;
}
export interface PreparedToolFolders {
  roles: readonly AndroidToolSourceRole[]; incompleteSdk: boolean; continuing: boolean; waiting: boolean; existing?: true;
}
function sameSaved(a: ToolSourceFolderContext, b: ToolSourceFolderContext): boolean {
  return a.connection === b.connection && a.observation === b.observation && a.draft === b.draft &&
    a.baseline === b.baseline && a.snapshot === b.snapshot &&
    sameToolAcquisitionData(a.context, b.context);
}
function eligible(operation: ToolAcquisitionOperation | null | undefined, presentation: StagedToolPresentation,
  context: ToolSourceFolderContext): { identity: ToolAcquisitionIdentity; view: PreparedToolFolders } | null {
  if (presentation !== 'current-staged' || operation?.phase !== 'terminal' || operation.outcome !== 'complete' ||
      operation.reason !== 'none' ||
      operation.context.projectId !== context.context.projectId || operation.context.draftRevision !== context.context.draftRevision ||
      operation.context.baselineGeneration !== context.context.baselineGeneration ||
      !sameToolAcquisitionData(operation.context.savedConfig, context.context.savedConfig)) return null;
  if (operation.context.action === 'inspect') {
    // Same strict native status/result coherence as the original controller;
    // no acquisition-shaped result, paths or renderer-added role list.
    const safe = parseToolAcquisitionStatus({schemaVersion:1,statusRevision:0,availability:'available',operation})?.operation;
    const result = safe?.result;
    if (result?.kind !== 'tool-requirements-observation' || result.protectedTools !== 'none-in-supported-catalogue' || !result.components) return null;
    const found = parseToolSourceDiscovery(result.discoveredSources, result.components), roles = foundToolRoles(found);
    if (!roles.length) return null;
    return { identity: { operationId: operation.operationId, ownerGeneration: operation.ownerGeneration },
      view: { roles, incompleteSdk: roles.includes('sdk') && result.components.missing.some((part) => part === 'sdk-platform' || part === 'sdk-build-tools'),
        continuing: false, waiting: false, existing: true } };
  }
  const report = parseStagedToolSources(operation.result);
  if (!report || !report.groups.length || report.operationId !== operation.operationId || !/^[0-9a-f]{32}$/.test(operation.operationId) ||
      !/^[0-9a-f]{32}$/.test(operation.ownerGeneration)) return null;
  return { identity: { operationId: operation.operationId, ownerGeneration: operation.ownerGeneration },
    view: { roles: report.groups.filter((group) => group.allRequiredComponentsStaged && group.next === 'choose-native-source').map((group) => group.group),
      incompleteSdk: report.groups.some((group) => group.group === 'sdk' && !group.allRequiredComponentsStaged), continuing: false, waiting: false } };
}
function usableSources(value: unknown, projectId: string): AndroidToolSourcesStatus | null {
  const sources = parseAndroidToolSourcesStatus(value);
  return sources && ['available', 'busy'].includes(sources.availability) &&
    (sources.projectId === projectId || sources.projectId === null && sources.sourceGeneration === 0) &&
    !['refused', 'cancelled', 'stopping', 'unknown'].includes(sources.phase) ? sources : null;
}
interface Retained {
  context: ToolSourceFolderContext; identity: ToolAcquisitionIdentity; view: PreparedToolFolders;
  sources: AndroidToolSourcesStatus; pending: { pick: PreparedToolSourcePick; claimed: boolean; returned: boolean } | null;
  peerRevision: number; joinedPick: boolean; registrationAvailability: string | null;
}
// Ordinary source admission retires the SAME empty catalogue and increments
// the shared status revision. Its separate relays may precede or follow the
// source reply. This admits only that closed projection, never a new catalogue
// or registration. Native lookup still demands its exact original + epoch.
function peerProjection(retained: Retained, context: ToolSourceFolderContext, sources: AndroidToolSourcesStatus): number | null {
  let revision = retained.peerRevision;
  const withinPick = (next: number): boolean => !!retained.pending?.claimed ||
    retained.pending === null && retained.joinedPick && next <= sources.statusRevision;
  if (retained.context.catalog !== context.catalog) {
    const before = parseAndroidToolchainCatalogStatus(retained.context.catalog), after = parseAndroidToolchainCatalogStatus(context.catalog);
    const empty = (value: NonNullable<typeof before>): boolean => value.catalogGeneration > 0 && value.operationId !== null &&
      value.entries.length === 0 && value.selected === null && ['available', 'busy'].includes(value.availability) &&
      (value.phase === 'ready' && value.reason === 'none' || value.phase === 'refused' && value.reason === 'catalog-changed');
    if (!before || !after || !withinPick(after.statusRevision) || !empty(before) || !empty(after) ||
        before.catalogGeneration !== after.catalogGeneration || before.operationId !== after.operationId ||
        after.statusRevision < before.statusRevision ||
        after.statusRevision === before.statusRevision && !sameToolAcquisitionData(before, after) ||
        before.phase === 'refused' && after.phase !== 'refused') return null;
    revision = Math.max(revision, after.statusRevision);
  }
  if (retained.context.registration !== context.registration) {
    const before = parseAndroidToolRegistrationStatus(retained.context.registration), after = parseAndroidToolRegistrationStatus(context.registration);
    if (!before || !after || !withinPick(after.statusRevision) ||
        ![retained.registrationAvailability, 'busy'].includes(before.availability) ||
        ![retained.registrationAvailability, 'busy'].includes(after.availability) ||
        ['cleanup-unknown', 'document-lost', 'shutdown'].includes(after.availability) ||
        before.phase !== 'idle' || before.operation !== null || before.review !== null || before.report !== null ||
        after.statusRevision < before.statusRevision ||
        after.statusRevision === before.statusRevision && !sameToolAcquisitionData(before, after) ||
        !sameToolAcquisitionData({ ...before, statusRevision: 0, availability: 'available' }, { ...after, statusRevision: 0, availability: 'available' })) return null;
    revision = Math.max(revision, after.statusRevision);
  }
  return revision;
}
function peersSettled(retained: Retained): boolean {
  const catalog = parseAndroidToolchainCatalogStatus(retained.context.catalog);
  const registration = parseAndroidToolRegistrationStatus(retained.context.registration);
  return catalog?.phase === 'refused' && catalog.reason === 'catalog-changed' && catalog.availability === 'available' &&
    (retained.context.registration === null || registration?.availability === retained.registrationAvailability);
}

/** No listener or independent async owner. The app-held tool controller keeps
 * this bounded nomination; the existing Android controller keeps all native
 * picker invokes, status, cancellation and unknown outcomes. */
export class PreparedToolSourceHandoff {
  #retained: Retained | null = null;
  retire(): void { this.#retained = null; }
  sync(context: ToolSourceFolderContext | null): boolean {
    const retained = this.#retained;
    if (!retained) return false;
    if (!context || !sameSaved(retained.context, context)) { this.retire(); return false; }
    const sources = usableSources(context.sources, context.context.projectId), previous = retained.sources, pending = retained.pending, pick = pending?.pick;
    if (!sources || sources.statusRevision < previous.statusRevision) { this.retire(); return false; }
    if (sources.sourceGeneration === previous.sourceGeneration) {
      if (!sameAndroidToolSourceIdentity(sources.operation, previous.operation) ||
          sources.statusRevision === previous.statusRevision && !sameToolAcquisitionData(sources, previous)) { this.retire(); return false; }
    } else if (!pick || !pending?.claimed || sources.sourceGeneration !== pick.before + 1 ||
        sources.operation?.role !== pick.role || sources.projectId !== retained.context.context.projectId ||
        sources.statusRevision <= previous.statusRevision) { this.retire(); return false; }
    if (pick && sources.sourceGeneration !== pick.before && sources.sourceGeneration !== pick.before + 1) { this.retire(); return false; }
    if (previous.phase === 'selected' && sources.sourceGeneration === previous.sourceGeneration && sources.phase !== 'selected' ||
        previous.phase === 'checking' && sources.phase === 'picking') { this.retire(); return false; }
    const peerRevision = peerProjection(retained, context, sources);
    if (peerRevision === null) { this.retire(); return false; }
    retained.peerRevision = peerRevision;
    retained.context = { ...retained.context, catalog: context.catalog, registration: context.registration };
    retained.sources = sources;
    if (pending?.returned && pick && sources.sourceGeneration === pick.before + 1 && sources.phase === 'selected') {
      retained.joinedPick = true;
      if (peerRevision <= sources.statusRevision && peersSettled(retained)) retained.pending = null;
    }
    return true;
  }
  preview(context: ToolSourceFolderContext | null, operation: ToolAcquisitionOperation | null | undefined,
    presentation: StagedToolPresentation): PreparedToolFolders | null {
    if (!context) { this.retire(); return null; }
    if (this.sync(context)) {
      const retained = this.#retained!;
      return { ...retained.view, continuing: true, waiting: retained.pending !== null || retained.peerRevision > retained.sources.statusRevision ||
        retained.joinedPick && !peersSettled(retained) };
    }
    const sources = usableSources(context.sources, context.context.projectId), selected = eligible(operation, presentation, context);
    return sources && selected ? { ...selected.view, waiting: sources.availability !== 'available' || !['idle', 'selected'].includes(sources.phase) } : null;
  }
  // Called only by an explicit prepared-folder click, BEFORE retiring the old
  // acquisition intent. Later picks use this separate handoff, never revive it.
  begin(context: ToolSourceFolderContext | null, operation: ToolAcquisitionOperation | null | undefined,
    presentation: StagedToolPresentation, role: AndroidToolSourceRole,
    current: () => ToolSourceFolderContext | null): PreparedToolSourcePick | null {
    if (!context) return null;
    if (!this.sync(context)) {
      const selected = eligible(operation, presentation, context), sources = usableSources(context.sources, context.context.projectId);
      if (!selected || !sources || sources.availability !== 'available' || !['idle', 'selected'].includes(sources.phase)) return null;
      this.#retained = { context, identity: selected.identity, view: selected.view, sources, pending: null, peerRevision: 0, joinedPick: false,
        registrationAvailability: parseAndroidToolRegistrationStatus(context.registration)?.availability ?? null };
    }
    const retained = this.#retained!;
    if (retained.pending || retained.peerRevision > retained.sources.statusRevision || retained.joinedPick && !peersSettled(retained) ||
        !retained.view.roles.includes(role) || retained.sources.availability !== 'available' ||
        !['idle', 'selected'].includes(retained.sources.phase) || retained.sources.sourceGeneration >= 0xffff_fffe) return null;
    const pick = new PreparedToolSourcePick(this, role, retained.sources.sourceGeneration, current, retained.view.existing === true);
    retained.pending = { pick, claimed: false, returned: false };
    return pick;
  }
  /** Claim checks are synchronous, including after reentrant UI notifications.
   * The native owner independently rematches IDs/epoch/lane and the exact role. */
  claim(pick: PreparedToolSourcePick, projectId: string, role: AndroidToolSourceRole, sourceGeneration: number): ToolAcquisitionIdentity | null {
    if (!this.current(pick) || this.#retained!.pending!.claimed || projectId !== this.#retained!.context.context.projectId ||
        role !== pick.role || sourceGeneration !== pick.before) return null;
    this.#retained!.pending!.claimed = true;
    return { ...this.#retained!.identity };
  }
  current(pick: PreparedToolSourcePick): boolean {
    return this.sync(pick.context()) && this.#retained?.pending?.pick === pick;
  }
  returned(pick: PreparedToolSourcePick): void {
    if (!this.current(pick)) return;
    this.#retained!.pending!.returned = true;
    const sources = this.#retained!.sources;
    // A lost/rejected invoke is not permission to replay or fall back to a
    // plain picker. Its original Android status/cancel controls remain intact.
    if (!this.#retained!.pending!.claimed || sources.sourceGeneration !== pick.before + 1) this.retire();
    else if (sources.phase === 'selected') {
      this.#retained!.joinedPick = true;
      if (this.#retained!.peerRevision <= sources.statusRevision && peersSettled(this.#retained!)) this.#retained!.pending = null;
    }
  }
}

export class PreparedToolSourcePick {
  readonly role: AndroidToolSourceRole;
  readonly before: number;
  readonly origin: 'acquired' | 'discovered';
  readonly #handoff: PreparedToolSourceHandoff;
  readonly #current: () => ToolSourceFolderContext | null;
  constructor(handoff: PreparedToolSourceHandoff, role: AndroidToolSourceRole, before: number,
    current: () => ToolSourceFolderContext | null, existing = false) {
    this.origin = existing ? 'discovered' : 'acquired';
    this.#handoff = handoff; this.role = role; this.before = before; this.#current = current; Object.freeze(this);
  }
  context(): ToolSourceFolderContext | null { try { return this.#current(); } catch { return null; } }
  claim(projectId: string, role: AndroidToolSourceRole, generation: number): ToolAcquisitionIdentity | null {
    return this.#handoff.claim(this, projectId, role, generation);
  }
  stillCurrent(): boolean { return this.#handoff.current(this); }
  joined(): void { this.#handoff.returned(this); }
}
