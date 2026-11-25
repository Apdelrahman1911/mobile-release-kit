import { useId } from 'react';
import type { VersionTagSelection } from '../githubVersionTagProtocol.ts';
// Proposal DATA only. Native reads the actual saved source/counter/row/tag.
export function GitHubVersionTagSelection({value,disabled,onChange}:{value:VersionTagSelection;disabled:boolean;onChange:(value:VersionTagSelection)=>void}) {
 const id=useId();
 return <fieldset disabled={disabled}><legend>Existing future-tag reservation</legend>
  <p>Use the candidate and row from the reservation, and the final version-only commit pushed through the existing Git controls. The configured branch must still point to that commit. Review reads the actual tag name and reserved number from the protected counter.</p>
  {([['candidateId','Candidate ID',36],['rowSha256','Reservation row SHA-256',64],['finalCommit','Pushed final commit',40]] as const).map(([field,label,maxLength])=>
   <label className="field" key={field} htmlFor={`${id}-${field}`}>{label}<input id={`${id}-${field}`} spellCheck={false} autoComplete="off" maxLength={maxLength} value={value[field]} onChange={e=>onChange({...value,[field]:e.target.value})}/></label>)}
  <p>No existing tag is moved or adopted. Tag creation may trigger other repository automation; this toolkit’s candidate build remains branch-triggered. A normal release tag or tag-triggered build is not being configured.</p>
 </fieldset>;
}
