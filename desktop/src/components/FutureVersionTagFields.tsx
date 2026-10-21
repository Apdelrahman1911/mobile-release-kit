import type { VersionReserveOptions } from '../versionReserve.ts';

export function FutureVersionTagFields({ id, options, configure }: {
  id: string; options: VersionReserveOptions; configure(options: VersionReserveOptions): unknown;
}) {
  const selected = options.futureTag !== undefined;
  return <>
    <label><input type="checkbox" checked={selected} onChange={e => {
      const { futureTag: _old, ...branch } = options;
      configure(e.target.checked ? { ...branch, futureTag: '' } : branch);
    }} /> Select this version policy for a future tag</label>
    {selected && <>
      <label htmlFor={`${id}-future-tag`}>Future tag · full name</label>
      <input id={`${id}-future-tag`} value={options.futureTag} placeholder="refs/tags/release/next" maxLength={210}
        autoComplete="off" spellCheck={false} onChange={e => configure({ ...options, futureTag: e.target.value })} />
      <p className="save-note">The source and build stay on the checked-out branch. This tag selects the rule; its name does not determine the version number or bypass Store limits. Reserve does not create a tag.</p>
      <p className="save-note">Use v5-capable tooling for every writer and the updated pinned workflow before first use. An existing tag is a conflict. After separately saving, committing and pushing the exact version-only change, review the separate tag binding. Existing tags are never moved.</p>
    </>}
  </>;
}
