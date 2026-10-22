import { useSyncExternalStore } from 'react';
import { imageAttemptFinished } from '../metadataImagesController.ts';
import type { MetadataImagesController, MetadataImagesState } from '../metadataImagesController.ts';
export function AgentMetadataImagesPreparation({controller,state}:{controller:MetadataImagesController;state:MetadataImagesState}) {
 const child=controller.preparation, view=useSyncExternalStore(child.subscribe,child.getSnapshot,child.getSnapshot),q=view.status;
 return <details className="advanced-settings"><summary>Advanced: prepare this image selection with the installed CLI</summary>
  <label><input type="checkbox" checked={state.cliPreparation} disabled={state.mode!=='native'||state.callerPending||!imageAttemptFinished(state.attempt)||!!state.editStatus?.active}
   onChange={e=>controller.setCliPreparation(e.target.checked)} /> Enable CLI preparation for the next selection</label>
  <p>Set this before Choose. The same native picker and opened Import are required; the CLI sees only captured item IDs and comparison summaries.
   This smaller review profile supports ten-image batches, but unusually large inventories must use the ordinary editor. It cannot be added to an open selection.</p>
  <p>Keep all replacement choices untouched until the CLI prepares them. Then review the ordinary full preview and give the separate one-use Apply approval below.
   No automatic copy, recovery or Store upload.</p>
  {view.error&&<p className="review-caution" role="status">{view.error}</p>}
  {q&&<><p>Original image preparation: {q.phase}. Prepared is not applied; unknown is not retry permission.</p>
   <pre><code>{`mrk metadata-images-status ${q.origin.projectId} ${q.origin.serviceInstance} ${q.origin.requestId} --json`}</code></pre></>}
  <div className="button-row"><button type="button" disabled={view.pending} onClick={()=>void child.check()}>Check image preparation request</button>
   <button type="button" disabled={!q||q.phase==='final'||q.phase==='transferred'} onClick={()=>child.cancel()}>Stop original preparation request</button></div>
 </details>;
}
