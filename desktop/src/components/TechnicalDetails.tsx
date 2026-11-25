import { useSyncExternalStore } from 'react';
import type { ReactNode } from 'react';

// A display preference only. It never changes what an operation does or
// what is checked; it only decides whether technical facts start expanded.
const KEY = 'mrk.showTechnicalDetails';
const listeners = new Set<() => void>();
let shown = (() => { try { return globalThis.localStorage?.getItem(KEY) === '1'; } catch { return false; } })();

export const technicalDetailsPreference = {
  get: () => shown,
  subscribe: (listener: () => void) => { listeners.add(listener); return () => { listeners.delete(listener); }; },
  set(next: boolean) {
    shown = next;
    try { globalThis.localStorage?.setItem(KEY, next ? '1' : '0'); } catch { /* preference stays for this session */ }
    listeners.forEach((listener) => listener());
  },
};

export function useShowTechnicalDetails() {
  return useSyncExternalStore(technicalDetailsPreference.subscribe, technicalDetailsPreference.get, technicalDetailsPreference.get);
}

/** Collapsible home for IDs, hashes, paths and other technical facts. */
export function TechnicalDetails({ children, label = 'Technical details' }: { children: ReactNode; label?: string }) {
  const open = useShowTechnicalDetails();
  return <details className="tech-details" open={open} key={open ? 'open' : 'closed'}>
    <summary>{label}</summary>
    <div className="tech-details-body">{children}</div>
  </details>;
}

export function TechnicalDetailsToggle() {
  const open = useShowTechnicalDetails();
  return <label className="tech-toggle">
    <input type="checkbox" checked={open} onChange={(event) => technicalDetailsPreference.set(event.target.checked)} />
    Show technical details
  </label>;
}
