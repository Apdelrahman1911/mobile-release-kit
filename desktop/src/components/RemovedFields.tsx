import { canUndoRemoval } from '../drafts.ts';
import type { ProjectSession } from '../drafts.ts';
import { SectionHeading } from './Common.tsx';

export function RemovedFields({ session, onUndo, onForget }: { session: ProjectSession; onUndo: (id: number) => void; onForget: (id: number) => void }) {
  if (session.removedFields.length === 0) return null;
  return <section className="card removed-fields">
    <SectionHeading title="Unset fields are still recoverable in memory" description="Undo restores only that field and preserves unrelated edits. Values are not displayed in this summary. Forgetting a copy is explicit; nothing here changes files." />
    <ul>{session.removedFields.map((removal) => {
      const available = canUndoRemoval(session, removal);
      return <li key={removal.id}><div><code>{removal.path}</code><p>{available ? 'An earlier value is retained for this project.' : 'The field or its parent changed later. Automatic undo is blocked to avoid overwriting your edits; the copy remains retained.'}</p></div><div className="button-row"><button type="button" className="button small secondary" disabled={!available} onClick={() => onUndo(removal.id)}>Undo unset</button><button type="button" className="text-button" onClick={() => onForget(removal.id)}>Forget copy</button></div></li>;
    })}</ul>
  </section>;
}
