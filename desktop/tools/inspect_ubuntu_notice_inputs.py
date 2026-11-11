"""Dependency DATA census only; stop before source inputs/any compiler command."""
import argparse, hashlib, json, os, platform, re, shutil, subprocess, traceback
from pathlib import Path
import prepare_ubuntu_execution as P

class InputsReady(BaseException):
    pass

def inspect(work, commit, tree):
    assert platform.system() == 'Linux' and platform.machine() == 'x86_64'
    original_fetch = P.fetch
    acquisition_env = None
    def fetch(spec, dest, evidence, env):
        nonlocal acquisition_env
        # prepare() has installed pinned Rust/Node and populated locked Cargo/npm
        # dependencies before requesting the first CPython source input.
        if dest.name == 'cpython.archive':
            acquisition_env = env
            raise InputsReady()
        return original_fetch(spec, dest, evidence, env)
    P.fetch = fetch
    try:
        P.prepare(work, commit, tree)
    except InputsReady:
        pass
    else:
        raise AssertionError('Did not stop before source compilation')
    assert acquisition_env is not None
    P.command('apt-build-dependency-closure', ['/usr/bin/apt-cache','depends','--recurse','--installed',
              '--no-recommends','--no-suggests','--no-conflicts','--no-breaks','--no-replaces','--no-enhances',*P.PACKAGES],
              work,work/'evidence',acquisition_env)
    closure_output=(work/'evidence/apt-build-dependency-closure/stdout.log').read_text()
    dependency_packages=sorted({line.split(':',1)[0] for line in closure_output.splitlines()
                               if re.fullmatch(r'[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?',line)})
    assert set(P.PACKAGES)<=set(dependency_packages)
    rows = []
    first = None
    copied = 0
    oversize_dir=work/'oversized-notices';oversize_dir.mkdir()

    roots = [('rust',work/'rust'),('cargo',work/'cargo-home/registry/src'),
             ('npm',P.SOURCE/'desktop/node_modules'),('ubuntu',Path('/usr/share/doc'))]
    for label, root in roots:
        count = 0
        for p in sorted(root.rglob('*')):
            if p.is_file() and not p.is_symlink() and any(x in p.name.lower() for x in ['license','licence','copyright','notice']):
                size = p.stat().st_size
                row = dict(component=label,member=label+'/'+p.relative_to(root).as_posix(),path=str(p),size=size)
                if size < 64 << 20:
                    row['sha256'] = P.sha(p)
                else:
                    row['hashRefusal'] = 'DATA census per-file 64MiB bound'
                if size >= 4 << 20:
                    if label=='ubuntu':
                        role='notice-owner-'+str(len(rows))
                        P.command(role,['/usr/bin/dpkg-query','-S',str(p)],work,work/'evidence',acquisition_env)
                        row['packageOwnership']=(work/'evidence'/role/'stdout.log').read_text().splitlines()
                        row['inBuildPackageClosure']=any(line.split(': ',1)[0].split(':',1)[0] in dependency_packages for line in row['packageOwnership'])
                    if first is None:
                        P.save(work/'notice-first-refusal.json',row)
                        print(json.dumps(dict(firstOriginalRefusal=row)),flush=True)
                    if size<64<<20 and copied+size<64<<20:
                        dest=oversize_dir/row['member'];dest.parent.mkdir(parents=True,exist_ok=True)
                        shutil.copyfile(p,dest);assert P.sha(dest)==row['sha256']
                        copied+=size;row['retainedOriginal']=str(dest.relative_to(work))
                    else:
                        row['retentionRefusal']='Bounded diagnostic evidence ceiling 64MiB; no packaging admission'
                rows.append(row);count += 1
                assert len(rows) < 100000
                if first is None and size >= 4 << 20:
                    first = row
        assert count > 0
    result = dict(schemaVersion=1,sourceCommit=commit,sourceTree=tree,
                  runner=json.loads((work/'runner.json').read_text()),
                  originalLimitBytes=4<<20,firstOriginalRefusal=first,
                  buildDependencyPackages=dependency_packages,retainedNoticeBytes=copied,
                  oversize=[r for r in rows if r['size'] >= 4<<20],
                  selectedFileCount=len(rows),selectedBytes=sum(r['size'] for r in rows),
                  files=rows,compilationPerformed=False,qualified=False)
    P.save(work/'notice-census.json',result)
    print(json.dumps({k:v for k,v in result.items() if k!='files'},indent=2))

if __name__ == '__main__':
    p=argparse.ArgumentParser();p.add_argument('--work',required=True,type=Path);p.add_argument('--commit',required=True);p.add_argument('--tree',required=True);a=p.parse_args()
    try:inspect(a.work,a.commit,a.tree)
    except BaseException:
        if a.work.is_dir():(a.work/'diagnostic-failure.txt').write_text(traceback.format_exc())
        raise
