import test from 'node:test';
import assert from 'node:assert/strict';
import { workspaceFatalDiagnostic } from '../src/workspaceFatalDiagnostic.ts';
test('fatal diagnostic redacts all original text and retains only known category and bounded React code', () => {
  const error = new Error('Minified React error #310; /private/project-secret?token=credential');
  assert.deepEqual(workspaceFatalDiagnostic(error), {code:'workspace-render-error',category:'error',reactCode:310,component:null});
  assert(!JSON.stringify(workspaceFatalDiagnostic(error)).includes('private'));
  assert.equal(workspaceFatalDiagnostic(new TypeError('private')).category,'type-error');
  assert.equal(workspaceFatalDiagnostic(new Error('Minified React error #99999; secret')).reactCode,null);
  let reads = 0;
  for (const key of ['message','name','stack']) Object.defineProperty(error,key,{get(){reads++;throw new Error('secret');}});
  assert.equal(workspaceFatalDiagnostic(error).reactCode,null);assert.equal(reads,0);
  assert.deepEqual(workspaceFatalDiagnostic({message:'Minified React error #310; secret'}),{code:'workspace-render-error',category:'unknown',reactCode:null,component:null});
});

test('known component token is extracted without retaining the ErrorInfo stack or invoking getters', () => {
  const info={componentStack:'\n at InstallationDetails (/private/project-secret.tsx:19:2)\n at App (/private/another.tsx:1:2)'};
  const value=workspaceFatalDiagnostic(new TypeError('private message'),info);
  assert.equal(value.component,'InstallationDetails');assert(!JSON.stringify(value).includes('/private'));
  assert.equal(workspaceFatalDiagnostic(new Error('private'),{componentStack:' at SecretUserComponent (/private/user)'}).component,null);
  let reads=0;Object.defineProperty(info,'componentStack',{get(){reads++;throw new Error('secret');}});
  assert.equal(workspaceFatalDiagnostic(new Error('private'),info).component,null);assert.equal(reads,0);
});
