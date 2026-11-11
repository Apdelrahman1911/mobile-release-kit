"""Lead-authorized disposable Ubuntu VM ONLY. Real dpkg mutations; never cleanup.
Invoke as root with an exact independently reviewed unsigned candidate digest.
Does not qualify execution or exercise GUI actions.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
from ubuntu_candidate_supervisor import run


def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for body in iter(lambda:f.read(1024*1024),b''): h.update(body)
    return h.hexdigest()


def snapshot(root):
    result={}
    if not root.exists(): return result
    for p in [root,*sorted(root.rglob('*'))]:
        s=p.lstat()
        assert not p.is_symlink() and (p.is_file() or p.is_dir())
        result[str(p.relative_to(root))]=dict(identity=[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns],sha256=sha(p) if p.is_file() else None)
    return result


def smoke(deb,digest,work):
    assert os.getuid()==os.geteuid()==0
    assert platform.system()=='Linux' and platform.machine()=='x86_64'
    assert 'VERSION_ID="24.04"\n' in Path('/etc/os-release').read_text()
    assert sha(deb)==digest and work.is_absolute() and not work.exists()
    work.mkdir(mode=0o700)
    root=Path('/var/lib/mobile-release-kit')
    before=snapshot(root)
    (work/'before.json').write_text(json.dumps(before,indent=2)+'\n')
    env=dict(PATH='/usr/bin:/bin',HOME='/root',LANG='C',LC_ALL='C',TZ='UTC',DEBIAN_FRONTEND='noninteractive')
    run([('dependencies-inspect',['/usr/bin/dpkg-deb','-f',str(deb),'Depends'],30)],Path('/'),work,env)
    depends=(work/'dependencies-inspect/stdout.log').read_text().strip()
    names=[]
    for clause in depends.split(', '):
        assert re.fullmatch(r'[a-z0-9][a-z0-9+.-]+(?: \((?:>=|=) [0-9][A-Za-z0-9.+:~\-]*\))?',clause)
        names.append(clause.split(' ')[0])
    run([('apt-update',['/usr/bin/apt-get','update'],300),('dependencies-install',['/usr/bin/apt-get','install','-y','--no-install-recommends',*names],600)],Path('/'),work,env)
    run([('install',['/usr/bin/dpkg','--install',str(deb)],300)],Path('/'),work,env)
    installed=snapshot(root)
    (work/'installed.json').write_text(json.dumps(installed,indent=2)+'\n')
    # Existing objects may include shared parents whose timestamps legitimately
    # change; preserve exact leaves and structural identity of old directories.
    for name,row in before.items():
        assert name in installed
        if row['sha256'] is not None: assert installed[name]==row
        else: assert installed[name]['identity'][:5]==row['identity'][:5]
    for i,command in enumerate([['/usr/sbin/dpkg-reconfigure','-f','noninteractive','mobile-release-kit-desktop'],['/usr/sbin/dpkg-reconfigure','-f','noninteractive','mobile-release-kit-desktop'],['/usr/bin/dpkg','--install',str(deb)]]):
        run([(f'repeat-{i}',command,300)],Path('/'),work,env)
        observed=snapshot(root)
        (work/f'repeat-{i}.json').write_text(json.dumps(observed,indent=2)+'\n')
        assert observed==installed
    # Also invoke the actual maintainer-script configure entry twice explicitly.
    for i in range(2):
        run([(f'postinst-{i}',['/var/lib/dpkg/info/mobile-release-kit-desktop.postinst','configure','0.1.4-1'],300)],Path('/'),work,env)
        assert snapshot(root)==installed
    run([('package-state',['/usr/bin/dpkg-query','-W','-f=${Status} ${Version}\n','mobile-release-kit-desktop'],30)],Path('/'),work,env)
    assert (work/'package-state/stdout.log').read_text()=='install ok installed 0.1.4-1\n'
    (work/'RESULT.json').write_text(json.dumps(dict(installerSha256=digest,installAndRepeatedConfigure=True,qualified=False,signed=False))+'\n')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--deb',type=Path,required=True)
    p.add_argument('--reviewed-deb-sha256',required=True)
    p.add_argument('--work',type=Path,required=True)
    a=p.parse_args(); smoke(a.deb,a.reviewed_deb_sha256,a.work)
