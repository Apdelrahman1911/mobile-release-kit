"""One artifact-bound installation case per fresh hosted VM. Never repair state."""
import argparse,json,os,shutil
from pathlib import Path
import smoke_ubuntu_candidate as S
from ubuntu_candidate_supervisor import run

def execute(download,case,work):
 assert os.geteuid()==0 and not work.exists()
 assert os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted'
 artifacts=list(download.rglob('mobile-release-kit-desktop_0.1.4-1_amd64.deb'));assert len(artifacts)==1
 originals=list(download.rglob('assembly.json'));assert len(originals)==1
 receipt=json.loads(originals[0].read_text());deb=artifacts[0]
 assert receipt['sha256']==S.sha(deb) and receipt['size']==deb.stat().st_size
 work.mkdir(mode=0o700);shutil.copyfile(deb,work/deb.name);shutil.copyfile(originals[0],work/'assembly.json')
 deb=work/deb.name;root=Path('/var/lib/mobile-release-kit');assert not root.exists()
 if case=='ordinary':S.smoke(deb,receipt['sha256'],work/'ordinary');return
 digest=receipt['runtimeManifestSha256'];parent=root/'versions/x86_64-unknown-linux-gnu'
 if case in ['changed-record','changed-inode','extra-member','record-owner','aliased-record','same-inode-restored']:
  S.smoke(deb,receipt['sha256'],work/'baseline')
  if case=='changed-record':
   p=parent/('.complete-'+digest);os.chmod(p,0o644);p.write_bytes(b'truncated');os.chmod(p,0o444)
  elif case=='changed-inode':
   p=parent/digest/'engine_bootstrap.py';body=p.read_bytes();mode=p.stat().st_mode&0o777
   # Test-only mutation, deliberately inside this disposable VM's owned fixture.
   p.unlink();p.write_bytes(body);os.chmod(p,mode)
  elif case=='record-owner':os.chown(parent/('.complete-'+digest),65534,65534)
  elif case=='aliased-record':os.link(parent/('.complete-'+digest),parent/'alias')
  elif case=='same-inode-restored':
   p=parent/digest/'engine_bootstrap.py';body=p.read_bytes();st=p.stat()
   p.write_bytes(body);os.utime(p,ns=(st.st_atime_ns,st.st_mtime_ns))
  else:(parent/digest/'unrecognized').write_bytes(b'unknown')
  command=['/var/lib/dpkg/info/mobile-release-kit-desktop.postinst','configure','0.1.4-1']
 else:
  parent.mkdir(parents=True,mode=0o755)
  if case in ['unknown-final','unknown-stage']:
   (parent/(digest if case=='unknown-final' else '.publish-'+digest)).mkdir(mode=0o555)
  else:
   assert case in ['pending-record','orphan-record']
   (parent/(('.complete-pending-' if case=='pending-record' else '.complete-')+digest)).write_bytes(b'unowned')
  # Use the same dependency-aware install path; it must fail at the actual postinst.
  before=S.snapshot(root);(work/'before.json').write_text(json.dumps(before,indent=2))
  try:S.smoke(deb,receipt['sha256'],work/'refusal')
  except SystemExit:pass
  else:raise AssertionError('Expected install refusal')
  result=json.loads((work/'refusal/install/original-return.json').read_text())
  assert result['originalReturn']!=0 and result['captureFailure'] is None
  assert b'Runtime publication refused: a staging or published name already exists.' in (work/'refusal/install/stderr.log').read_bytes(), 'Refusal must come from the actual publisher collision'
  assert before==S.snapshot(root)
  (work/'RESULT.json').write_text(json.dumps(dict(case=case,expectedRefusal=True,qualified=False)))
  return
 before=S.snapshot(root);(work/'before.json').write_text(json.dumps(before,indent=2))
 try:run([('refusal',command,300)],Path('/'),work,dict(PATH='/usr/bin:/bin',HOME='/root',LANG='C',LC_ALL='C'))
 except SystemExit:pass
 else:raise AssertionError('Expected postinst refusal')
 result=json.loads((work/'refusal/original-return.json').read_text())
 assert result['originalReturn']!=0 and result['captureFailure'] is None and before==S.snapshot(root)
 (work/'RESULT.json').write_text(json.dumps(dict(case=case,expectedRefusal=True,qualified=False)))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--download',type=Path,required=True);p.add_argument('--case',required=True);p.add_argument('--work',type=Path,required=True);a=p.parse_args();execute(a.download,a.case,a.work)
