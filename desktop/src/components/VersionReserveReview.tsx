import { useSyncExternalStore } from 'react';
import type { VersionReserveReviewController } from '../versionReserveReviewController.ts';
export function VersionReserveReview({controller}:{controller:VersionReserveReviewController}){
  const state=useSyncExternalStore(controller.subscribe,controller.getSnapshot,controller.getSnapshot),s=state.status;
  return <details><summary>Advanced · CLI version source review</summary>
    <p>With automatic versions selected and existing app read access enabled, <code>version-reserve-review</code> can propose the exact branch and increment. Your choices above are not overwritten. This only reads the saved source and checks the already-held Store inventory; it reserves no number.</p>
    {s&&<><p>Original request <code>{s.origin.requestId}</code>: {s.phase}. {state.unknown?'Outcome unconfirmed; do not repeat.':''}</p>
      <p>CLI proposal: <code>{s.options.reference}</code>, {s.options.increment}, {s.options.newCandidate?'different candidate':'same candidate / retry'}{s.options.futureTag?`, future tag ${s.options.futureTag}`:''}.</p>
      {s.phase==='review-ready'&&<p>Continue with the separate Allow once below, or explicitly reserve these reviewed CLI choices. Counter creation and enrollment remain separate setup steps.</p>}</>}
    <button type="button" className="button secondary" disabled={state.checking} onClick={()=>void controller.check()}>Check CLI source review</button>
    <button type="button" className="button secondary" disabled={!s||state.stopping||s.settlement==='settled'} onClick={()=>void controller.cancel()}>Stop CLI source review</button>
  </details>;
}
