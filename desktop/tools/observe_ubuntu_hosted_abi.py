"""Disposable hosted VM read-only ABI observation; never admits a new kernel."""
import argparse,fcntl,json,os,platform,re,shutil,traceback
from pathlib import Path
import prepare_ubuntu_execution as P

class InputsReady(BaseException):pass

def execute(work,commit,tree):
 # Explicit disposable diagnostic dependency; never part of the product route.
 P.PACKAGES=[*P.PACKAGES,'strace']
 original_fetch=P.fetch;acquired=None
 def fetch(spec,dest,evidence,env):
  nonlocal acquired
  if dest.name=='cpython.archive':acquired=env;raise InputsReady()
  return original_fetch(spec,dest,evidence,env)
 P.fetch=fetch
 try:P.prepare(work,commit,tree)
 except InputsReady:pass
 else:raise AssertionError('Must stop before CPython source acquisition/compilation')
 assert acquired is not None
 e=work/'evidence';release=platform.release()
 P.save(work/'kernel-binding.json',dict(sourceCommit=commit,sourceTree=tree,release=release,productionKernelAdmissionChanged=False,publicationPerformed=False,qualified=False))
 assert release=='7.0.0-1017-azure'
 packages=['linux-image-7.0.0-1017-azure','linux-headers-7.0.0-1017-azure','linux-azure-7.0-headers-7.0.0-1017']
 P.command('kernel-package-versions',['/usr/bin/dpkg-query','-W','-f=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n',*packages],work,e,acquired)
 for line in (e/'kernel-package-versions/stdout.log').read_text().splitlines():
  name,version,arch,status=line.split('\t');assert version=='7.0.0-1017.17~24.04.1' and status=='installed'
 relative=['include/uapi/linux/mount.h','include/uapi/linux/stat.h','include/linux/proc_ns.h','include/uapi/linux/nsfs.h',
           'arch/x86/include/generated/uapi/asm/unistd_64.h','include/generated/uapi/linux/version.h','include/generated/utsrelease.h']
 base=Path('/usr/src');headers=work/'kernel-headers';headers.mkdir();rows=[];originals=[]
 for root in sorted(base.glob('*7.0.0-1017*')):
  for name in relative:
   p=root/name
   if p.is_file():
    resolved=p.resolve(strict=True);assert resolved.is_relative_to(base)
    assert resolved.stat().st_size<2<<20
    dest=headers/root.name/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(resolved,dest)
    r=dict(original=str(p),resolved=str(resolved),**P.row(dest,headers));assert r['sha256']==P.sha(resolved)
    rows.append(r);originals.append(str(p))
 missing=sorted({'mount.h','stat.h','proc_ns.h','nsfs.h','unistd_64.h','utsrelease.h'}-{Path(r['path']).name for r in rows})
 P.save(work/'kernel-header-inventory.json',dict(files=rows,missingRequired=missing))
 assert not missing,'Required installed kernel headers absent: '+repr(missing)
 P.command('kernel-header-package-owners',['/usr/bin/dpkg-query','-S',*sorted({r['resolved'] for r in rows})],work,e,acquired)
 env={**acquired,'CARGO_TARGET_DIR':str(work/'observer-target'),'CARGO_PROFILE_DEV_DEBUG':'0','CARGO_PROFILE_TEST_DEBUG':'0',
      'TMPDIR':str(work/'tmp'),'RAYON_NUM_THREADS':'1','CARGO_BUILD_JOBS':'1','CARGO_INCREMENTAL':'0'}
 Path(env['TMPDIR']).mkdir();cargo=work/'rust/bin/cargo';cwd=P.SOURCE/'desktop/src-tauri'
 args=[str(cargo),'test','--offline','--locked','--jobs','1','--target','x86_64-unknown-linux-gnu','--no-default-features',
       '--features','ubuntu-runtime-publisher','--lib','--no-run']
 with (work/'compiler.lock').open() as owner:
  fcntl.flock(owner,fcntl.LOCK_EX|fcntl.LOCK_NB)
  P.command('publisher-abi-compile',args,cwd,e,env,1800)
  candidates=[p for p in (work/'observer-target/x86_64-unknown-linux-gnu/debug/deps').iterdir()
              if re.fullmatch(r'mobile_release_desktop-[0-9a-f]+',p.name) and p.is_file() and not p.is_symlink() and os.access(p,os.X_OK)]
  assert len(candidates)==1
  compiled=work/'compiled';compiled.mkdir();binary=compiled/'publisher-abi-libtest';shutil.copyfile(candidates[0],binary);os.chmod(binary,0o755)
  P.save(work/'observer-binary.json',P.row(binary))
  P.command('publisher-data-tests',[str(binary),'runtime_publication::','--test-threads=1'],work,e,env,300)
  native_env={**env,'MRK_RUNTIME_PUBLICATION_HELPER_TESTS':'1'}
  P.command('publisher-helper-tests',[str(binary),'runtime_publication::tests::helper_','--ignored','--test-threads=1','--nocapture'],work,e,native_env,300)
  assert P.sha(binary)==P.sha(candidates[0])
  command=['/usr/bin/sudo','-n','/usr/bin/env','-i','PATH=/usr/bin:/bin','HOME=/root','LANG=C','LC_ALL=C',
           'GITHUB_ACTIONS=true','RUNNER_ENVIRONMENT=github-hosted','MRK_UBUNTU_ABI_OBSERVATION=1',
           '/usr/bin/strace','--kill-on-exit','-f','-yy','-s','4096','-e',
           'trace=statx,statmount,openat2,fstat,newfstatat,fstatfs,fgetxattr,read,close,uname,getuid,geteuid,getgid,getegid,getpid,gettid',str(binary),
           '--exact','runtime_publication::platform_native_tests::root_current_hosted_abi_observation',
           '--ignored','--test-threads=1','--nocapture']
  P.command('hosted-root-abi-observation',command,work,e,env,180)
 log=(e/'hosted-root-abi-observation/stdout.log').read_text();assert 'ABI_OBSERVATION_RESULT=' in log
 assert '"productionKernelAccepted":false' in log and '"observations":"Ok(())"' in log and '"settlement":"Ok(())"' in log
 for row in json.loads((work/'source.json').read_text())['sourceFiles']:assert P.sha(P.SOURCE/row['path'])==row['sha256']
 P.save(work/'RESULT.json',dict(sourceCommit=commit,sourceTree=tree,kernel=release,readOnlyNativeObservationPassed=True,
       independentKernelAbiReviewRequired=True,productionKernelAccepted=False,publicationPerformed=False,qualified=False,observer=P.row(binary)))

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--commit',required=True);p.add_argument('--tree',required=True);a=p.parse_args()
 try:execute(a.work,a.commit,a.tree)
 except BaseException:
  if a.work.is_dir():(a.work/'abi-observation-failure.txt').write_text(traceback.format_exc())
  raise
