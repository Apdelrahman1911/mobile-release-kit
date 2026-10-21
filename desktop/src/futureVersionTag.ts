// Literal future policy selector only. It is not the checked-out source, a
// number parser, a tag existence observation, or permission to create a tag.
export function futureVersionTag(value: unknown): value is string {
  if (typeof value !== 'string' || !value.startsWith('refs/tags/')) return false;
  const name = value.slice(10), parts = name.split('/');
  return name.length > 0 && name.length <= 200 && /^[A-Za-z0-9]/.test(name) && !/[^A-Za-z0-9._/-]/.test(name) &&
    !name.includes('..') && !name.startsWith('refs/') && parts.length <= 16 &&
    parts.every(p => !!p && !p.startsWith('.') && !p.endsWith('.') && !p.endsWith('.lock'));
}
