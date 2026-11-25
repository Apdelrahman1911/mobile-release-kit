import { useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { setupDisclosureOpen } from '../setupOverview.ts';

// Keep the original controls mounted once, including drafts and confirmation
// dialogs. Closing a details element is not closing/cancelling a native task.
export function ProgressiveDisclosure({ title, description, children, needsAttention = false, reveal = 0 }: {
  title: string;
  description?: string;
  children: ReactNode;
  needsAttention?: boolean;
  reveal?: number;
}) {
  const details = useRef<HTMLDetailsElement>(null);
  const summary = useRef<HTMLElement>(null);
  const [expanded, setExpanded] = useState(false);
  useEffect(() => {
    if (reveal === 0) return;
    setExpanded(true);
    // Focus follows only an explicit "open this section" click. Background
    // status changes may reveal attention, but never steal keyboard focus.
    summary.current?.focus({ preventScroll: true });
    details.current?.scrollIntoView({ block: 'nearest' });
  }, [reveal]);
  return <details ref={details} className="guided-disclosure" open={setupDisclosureOpen(expanded, needsAttention)}
    onToggle={(event) => {
      const requested = event.currentTarget.open;
      if (!requested && needsAttention) event.currentTarget.open = true;
      else setExpanded(requested);
    }}>
    <summary ref={summary} onClick={(event) => { if (needsAttention) event.preventDefault(); }}>
      {title}{needsAttention && <span className="guided-attention-label">Needs your attention · kept open</span>}
    </summary>
    {description && <p className="guided-disclosure-description">{description}</p>}
    {children}
  </details>;
}
