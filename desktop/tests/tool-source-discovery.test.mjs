// Inert public DATA only; no native location read, process or download.
import test from 'node:test';
import assert from 'node:assert/strict';
import { foundToolRoles, parseToolSourceDiscovery, TOOL_DISCOVERY_HELP } from '../src/toolSourceDiscovery.ts';
import { encodeAndroidToolSourcesRequest } from '../src/androidToolSources.ts';
import { toolAcquisitionFailureGuidance } from '../src/toolAcquisitionGuidance.ts';

const parts = { compatible: ['jdk','sdk-platform'], missing:['sdk-build-tools','gradle'] };
const found = () => ({ scope:'fixed-macos-locations-v1', searched:['jdk','sdk','gradle'], present:['jdk','sdk'],
  compatibleComponents:['jdk','sdk-platform'] });
test('fixed source discovery retains partial SDK and genuine absent/present distinctions without paths', () => {
  const view=parseToolSourceDiscovery(found(),parts);
  assert.deepEqual(view,found()); assert.deepEqual(foundToolRoles(view),['jdk','sdk']);
  assert.deepEqual(parseToolSourceDiscovery({...found(),present:['jdk','sdk','gradle']},parts)?.present,['jdk','sdk','gradle']);
  assert.deepEqual(foundToolRoles(parseToolSourceDiscovery({scope:'fixed-macos-locations-v1',searched:['sdk'],present:['sdk'],compatibleComponents:[]},
    {compatible:[],missing:['jdk','sdk-platform','sdk-build-tools','gradle']})),[]);
  assert.match(TOOL_DISCOVERY_HELP,/does not scan/);
  assert.match(TOOL_DISCOVERY_HELP,/Homebrew/);
});
test('discovery refuses unknown paths, duplicate/noncanonical rows, missing parents and mismatched partition', () => {
  for (const patch of [{path:'/private/home/sdk'},{scope:'any-path'},{searched:[]},{searched:['sdk','jdk']},
    {present:['jdk','jdk']},{present:['sdk']},{compatibleComponents:['sdk-platform','jdk']},
    {compatibleComponents:['jdk']},{compatibleComponents:['jdk','sdk-platform','gradle']}])
    assert.equal(parseToolSourceDiscovery({...found(),...patch},parts),null);
  assert.equal(parseToolSourceDiscovery({...found(),searched:['jdk'],present:['jdk','sdk']},parts),null);
  assert.equal(parseToolSourceDiscovery(found(),{compatible:[],missing:['jdk','sdk-platform','sdk-build-tools','gradle']}),null);
});
test('explicit selected components are not offered as unchosen conventional folders', () => {
  const all = {compatible:['jdk','sdk-platform','sdk-build-tools','gradle'],missing:[]};
  const data = {scope:'fixed-macos-locations-v1',searched:['gradle'],present:['gradle'],compatibleComponents:['gradle']};
  assert.deepEqual(foundToolRoles(parseToolSourceDiscovery(data,all)),['gradle']);
  assert.equal(parseToolSourceDiscovery({...data,compatibleComponents:all.compatible},all),null);
});
test('discovered nomination extends only the same choose command and cannot carry paths or both origins', () => {
  const ordinary={schemaVersion:1,sourceGeneration:2,projectId:'inert-project',role:'sdk'};
  const ids={operationId:'a'.repeat(32),ownerGeneration:'b'.repeat(32)};
  const data={...ordinary,discovered:ids};
  const raw=encodeAndroidToolSourcesRequest('choose_android_tool_source',data);
  assert.ok(raw instanceof Uint8Array); assert.deepEqual(JSON.parse(new TextDecoder().decode(raw)),data);
  for(const discovered of [null,undefined,{},'/fixed/sdk',{...ids,path:'/fixed/sdk'}, {...ids,operationId:'https://vendor.invalid/sdk'}])
    assert.equal(encodeAndroidToolSourcesRequest('choose_android_tool_source',{...ordinary,discovered}),null);
  assert.equal(encodeAndroidToolSourcesRequest('choose_android_tool_source',{...data,acquired:ids}),null);
  assert.equal(encodeAndroidToolSourcesRequest('android_tool_sources_status',{schemaVersion:1,discovered:ids}),null);
});
test('source DATA parser and original chooser do not evaluate caller getters', () => {
  let calls=0; const data=found(); Object.defineProperty(data,'present',{enumerable:true,get(){calls++;return ['jdk','sdk'];}});
  assert.equal(parseToolSourceDiscovery(data,parts),null); assert.equal(calls,0);
  const input={schemaVersion:1,sourceGeneration:0,projectId:'p',role:'jdk'};
  Object.defineProperty(input,'discovered',{enumerable:true,get(){calls++;return {};}});
  assert.equal(encodeAndroidToolSourcesRequest('choose_android_tool_source',input),null); assert.equal(calls,0);
});
test('wrong or unreadable source guidance never recommends overwriting or calling it missing', () => {
  assert.match(toolAcquisitionFailureGuidance('existing-tools-incompatible').body,/not been replaced or called missing/);
  assert.match(toolAcquisitionFailureGuidance('existing-tools-unreadable').body,/do not weaken its permissions/);
  assert.match(toolAcquisitionFailureGuidance('unknown').body,/does not authorize a retry/);
});

test('SDKMAN lookup scope preserves legacy observations and keeps fallback paths private', () => {
  const parts = { compatible:['jdk','sdk-platform','gradle'], missing:['sdk-build-tools'] };
  const value = { scope:'fixed-macos-locations-v2', searched:['gradle'], present:['gradle'], compatibleComponents:['gradle'] };
  assert.deepEqual(parseToolSourceDiscovery(value,parts),value);
  assert.deepEqual(foundToolRoles(parseToolSourceDiscovery(value,parts)),['gradle']);
  const old = {...value,scope:'fixed-macos-locations-v1'};
  assert.deepEqual(parseToolSourceDiscovery(old,parts),old); // Never relabel an older search as the new one.
  for (const patch of [{scope:'fixed-macos-locations-v3'},{path:'/Users/inert/.sdkman/candidates/gradle/8.14.5'},
    {present:[]},{compatibleComponents:[]},{searched:['sdkman']},{version:'current'}])
    assert.equal(parseToolSourceDiscovery({...value,...patch},parts),null);
  assert.match(TOOL_DISCOVERY_HELP,/Only if that Gradle folder is absent/);
  assert.match(TOOL_DISCOVERY_HELP,/\.sdkman\/candidates\/gradle\/8\.14\.5/);
  assert.match(TOOL_DISCOVERY_HELP,/other SDKMAN versions/);
  assert.match(TOOL_DISCOVERY_HELP,/ordinary Inspect\/Review\/Register/);
});
