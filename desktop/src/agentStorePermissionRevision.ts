/** MAIN-only comparison DATA for the existing shared Store permission counter.
 * The native Doc owns admission/consumption. CLI Submit and Query do not carry it. */
export function validStorePermissionRevision(value:unknown):value is string {
  return typeof value==='string' && /^(?:0|[1-9][0-9]{0,19})$(?![\s\S])/.test(value) &&
    (value.length<20 || value<='18446744073709551615');
}
export function nextStorePermissionRevision(value:string):string|null {
  return !validStorePermissionRevision(value)||value==='18446744073709551615'?null:(BigInt(value)+1n).toString();
}
