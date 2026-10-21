// Only Ready has an explicit wire field. Omitting it preserves legacy Draft
// canonical objects; null/undefined/"draft" must not be normalized into consent.
export type PullRequestCreationMode = 'draft' | 'ready-for-review';
export interface PullRequestModeFields { creationMode?: 'ready-for-review' }
export function validPullRequestMode(v:object):boolean {
  const d=Object.getOwnPropertyDescriptor(v,'creationMode');
  return d===undefined || Object.hasOwn(d,'value')&&d.value==='ready-for-review';
}
export function pullRequestMode(v:PullRequestModeFields):PullRequestCreationMode {
  return v.creationMode==='ready-for-review'?'ready-for-review':'draft';
}
export function pullRequestModeFields(mode:PullRequestCreationMode):PullRequestModeFields {
  if(mode==='draft')return {};
  if(mode==='ready-for-review')return {creationMode:'ready-for-review'};
  throw new Error('Invalid PR creation mode');
}
export function pullRequestModeLabel(v:PullRequestModeFields):string {
  return pullRequestMode(v)==='draft'?'Draft':'Ready for review';
}
