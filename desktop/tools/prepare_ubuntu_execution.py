"""Disposable Ubuntu 24.04 candidate constructor; no publication or qualification.
Pinned source inputs, original bounded commands, actual dependency census.
"""
import argparse, fcntl, hashlib, json, os, platform, shutil, subprocess, tarfile, time
from pathlib import Path
from ubuntu_candidate_supervisor import run
import assemble_ubuntu_deb as A
import cpython_static_inputs as I

SOURCE = Path(__file__).resolve().parents[2]
PROFILE = 'ubuntu-candidate-source-runtime-v1'
PACKAGES = ['build-essential','gcc-13','g++-13','pkg-config','dpkg-dev','libgtk-3-dev',
 'libwebkit2gtk-4.1-dev','librsvg2-dev','libayatana-appindicator3-dev','patchelf',
 'perl','m4','autoconf','automake','libtool','curl','ca-certificates','xz-utils','acl']

def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''): h.update(b)
 return h.hexdigest()
def save(p,v):
 with p.open('x') as f: json.dump(v,f,indent=2);f.write('\n')
def row(p,root=None): return dict(path=str(p.relative_to(root) if root else p),size=p.stat().st_size,sha256=sha(p))
def roster(root): return [row(p,root) for p in sorted(root.rglob('*')) if p.is_file() and not p.is_symlink()]
def copy(p,q):
 q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,q)
def fetch(spec,dest,evidence,env):
 run([(dest.name,['/usr/bin/curl','--fail','--location','--proto','=https','--proto-redir','=https','--max-time','180','--max-filesize',str(spec['size']),'-o',str(dest),spec['url']],190)],dest.parent,evidence,env)
 assert dest.stat().st_size==spec['size'] and sha(dest)==spec['sha256']
def unpack(archive,out):
 out.mkdir()
 with tarfile.open(archive) as t:
  members=t.getmembers();assert len(members)<100000 and sum(m.size for m in members)<2<<30
  # Python's data filter rejects escaping links, devices and path traversal.
  t.extractall(out,filter='data')
 roots=list(out.iterdir());assert len(roots)==1 and roots[0].is_dir()
 return roots[0]
def command(role,args,cwd,evidence,env,seconds=600):run([(role,list(map(str,args)),seconds)],cwd,evidence,env)
def git(*args):return subprocess.check_output(['/usr/bin/git','--git-dir='+str(SOURCE/'.git'),'--work-tree='+str(SOURCE),*args],timeout=30).decode().strip()

def prepare(work,commit,tree):
 assert platform.system()=='Linux' and platform.machine()=='x86_64' and os.getuid()!=0
 assert os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted'
 assert os.environ['GITHUB_RUN_ATTEMPT']=='1'
 assert 'VERSION_ID="24.04"' in Path('/etc/os-release').read_text()
 assert work.is_absolute() and not work.exists() and not work.is_relative_to(SOURCE)
 assert git('rev-parse','HEAD')==commit and git('rev-parse','HEAD^{tree}')==tree
 assert not git('status','--porcelain','--untracked-files=no')
 work.mkdir(mode=0o700);e=work/'evidence';e.mkdir();inputs=work/'inputs';inputs.mkdir()
 env=dict(PATH='/usr/bin:/bin',HOME=str(work/'home'),LANG='C.UTF-8',LC_ALL='C.UTF-8',TZ='UTC',CI='true',DEBIAN_FRONTEND='noninteractive',CARGO_BUILD_JOBS='1',CARGO_INCREMENTAL='0',RAYON_NUM_THREADS='1')
 Path(env['HOME']).mkdir();lock=work/'compiler.lock';lock.touch(mode=0o600)
 save(work/'source.json',dict(sourceCommit=commit,sourceTree=tree,sourceFiles=[row(SOURCE/p,SOURCE) for p in git('ls-files','-z').rstrip('\0').split('\0')]))
 command('apt-update',['sudo','apt-get','update'],work,e,env)
 command('apt-install',['sudo','apt-get','install','-y','--no-install-recommends',*PACKAGES],work,e,env,900)
 command('dpkg-inventory',['dpkg-query','-W','-f=${binary:Package}\t${Version}\t${Architecture}\n'],work,e,env)
 command('runner-uname',['uname','-a'],work,e,env)
 save(work/'runner.json',{k:os.environ.get(k) for k in ['ImageOS','ImageVersion','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_SHA','GITHUB_WORKFLOW_SHA']})
 pins=json.loads((SOURCE/'desktop/packaging/debian/ubuntu-execution-inputs.json').read_text())
 for name in ['rust','node']:
  archive=inputs/(name+'.tar.xz');fetch(pins[name],archive,e,env);root=unpack(archive,work/(name+'-distribution'))
  if name=='rust':
   rust=work/'rust';command('rust-install',['sh',root/'install.sh','--prefix='+str(rust),'--disable-ldconfig','--components=rustc,cargo,rust-std-x86_64-unknown-linux-gnu'],work,e,env)
  else: node=root
 env.update(CARGO_HOME=str(work/'cargo-home'),RUSTC=str(rust/'bin/rustc'))
 env['PATH']=str(rust/'bin')+':'+str(node/'bin')+':/usr/bin:/bin'
 command('cargo-fetch',[rust/'bin/cargo','fetch','--locked','--target','x86_64-unknown-linux-gnu'],SOURCE/'desktop/src-tauri',e,env,900)
 command('npm-ci',[node/'bin/node',node/'lib/node_modules/npm/bin/npm-cli.js','ci','--ignore-scripts','--no-audit','--no-fund'],SOURCE/'desktop',e,env,900)
 source_lock=json.loads((SOURCE/'desktop/cpython-source-inputs/source-lock.json').read_text())
 builds={}
 for spec in source_lock['sources']:
  archive=inputs/(spec['id']+'.archive');fetch(dict(url=spec['url'],**spec['archive']),archive,e,env)
  builds[spec['id']]=unpack(archive,work/(spec['id']+'-source'))
 deps=work/'deps';deps.mkdir();config=source_lock['configuration']
 cenv={**env,'CC':'/usr/bin/gcc-13','CXX':'/usr/bin/g++-13','CFLAGS':'-O2 -fPIC','SOURCE_DATE_EPOCH':'1785925789'}
 def flags(key):return [s.replace('/work/deps',str(deps)) for s in config[key]]
 with lock.open() as owner:
  fcntl.flock(owner,fcntl.LOCK_EX|fcntl.LOCK_NB)
  for name,key,program in [('zlib','zlibConfigure','sh'),('libffi','libffiConfigure','sh'),('openssl','opensslConfigure','perl')]:
   root=builds[name];command(name+'-configure',[program,'./Configure' if name=='openssl' else './configure',*flags(key)],root,e,cenv)
   extra=[config['opensslMakeAssignment']] if name=='openssl' else []
   command(name+'-build',['make','-j1',*extra,*(['build_libs'] if name=='openssl' else [])],root,e,cenv,1800)
   command(name+'-install',['make','-j1',*extra,'install_dev' if name=='openssl' else 'install'],root,e,cenv)
  py=builds['cpython'];copy(SOURCE/'desktop/tools/cpython_source_setup.local',py/'Modules/Setup.local')
  cenv.update(CPPFLAGS='-I'+str(deps/'include'),LDFLAGS='-L'+str(deps/'lib'),ZLIB_CFLAGS='-I'+str(deps/'include'),ZLIB_LIBS=str(deps/'lib/libz.a'),LIBFFI_CFLAGS='-I'+str(deps/'include'),LIBFFI_LIBS=str(deps/'lib/libffi.a'))
  for root in [py/'lib',py.parent/'lib']:
   root.mkdir(exist_ok=True)
   for name in I.SOURCE_LIBRARIES:copy(deps/'lib'/name,root/name)
  command('python-configure',['sh','./configure',*flags('pythonConfigure')],py,e,cenv)
  command('builtin-archives',['make','-j1',*config['pythonMakeAssignments'],*I.SOURCE_ARCHIVE_TARGETS],py,e,cenv,900)
  command('python-build',['make','-j1',*config['pythonMakeAssignments'],'python','platform','checksharedmods','build-details.json'],py,e,cenv,1800)
 runtime=work/'runtime';runtime.mkdir()
 copy(py/'python',runtime/'python/bin/python3');os.chmod(runtime/'python/bin/python3',0o755)
 for name in I.SOURCE_LIBRARIES:copy(deps/'lib'/name,runtime/'python/lib'/name)
 for p in sorted((py/'Lib').rglob('*')):
  if p.is_file():
   dest,_=I.source_stdlib_destination(p.relative_to(py/'Lib').as_posix())
   if dest:copy(p,runtime/dest)
 generated=py/(py/'pybuilddir.txt').read_text().strip()
 for name in I.SOURCE_GENERATED_NAMES:copy(generated/name,runtime/'python/lib/python3.14'/name)
 copy(py/'LICENSE',runtime/'python/LICENSE.txt')
 (runtime/'python/lib/python314.zip').write_bytes(b'PK\x05\x06'+b'\0'*18)
 (runtime/'python/lib/python3.14/lib-dynload').mkdir();(runtime/'python/lib/python3.14/lib-dynload/README.mrk').write_text('Static extension modules; source-built validation candidate.\n')
 command('compose-runtime',['/usr/bin/python3','-B',SOURCE/'desktop/tools/prepare_runtime.py','--source',SOURCE,'--runtime-root',runtime,'--target','x86_64-unknown-linux-gnu','--profile','current'],work,e,env)
 A.current_runtime(runtime)
 command('python-runtime-smoke',[runtime/'python/bin/python3','-I','-S','-B','-c','import ssl,ctypes,resource,zlib,pyexpat; print(ssl.OPENSSL_VERSION); print(pyexpat.EXPAT_VERSION)'],work,e,env)
 kit=work/'source-kit';kit.mkdir();notice=kit/'notices';shutil.copytree(SOURCE/'desktop/cpython-source-inputs/conventional-review/notices',notice)
 (notice/'SOURCE-AVAILABILITY.txt').write_text('Exact original component archives are shipped in ../sources. The current recipe and configuration are in ../recipe. Build logs remain in the candidate evidence artifact. No historical runtime is included.\n')
 (notice/'PYTHON-CHANGES.txt').write_text('CPython 3.14.7: no C-source patches. Modules/Setup.local selects static modules; no pip, Tk or test suite. Stdlib projection follows cpython_static_inputs.source_stdlib_destination. OpenSSL 3.5.8 is dynamically linked; zlib and libffi are statically linked. Current application core and bootstraps are composed separately.\n')
 for spec in source_lock['sources']:copy(inputs/(spec['id']+'.archive'),kit/'sources'/(spec['id']+'.archive'))
 for name in ['prepare_ubuntu_execution.py','cpython_source_setup.local','cpython_static_inputs.py','prepare_runtime.py']:copy(SOURCE/'desktop/tools'/name,kit/'recipe'/name)
 save(kit/'recipe/source-lock.json',dict(profile=PROFILE,sources=source_lock['sources'],configuration=config,environment=cenv,sourceCommit=commit,sourceTree=tree))
 (notice/'SUCCESSOR-VERIFICATION-NOTE.txt').write_text('This newly compiled candidate has no historical artifact admission. Build and native test results are recorded separately for this exact commit and run. No publication or qualification is implied.\n')
 (notice/'REBUILD.md').write_text('Use the exact candidate commit and desktop-linux-installer-candidate.yml. recipe/prepare_ubuntu_execution.py records dependency acquisition, source compilation and composition. See recipe/source-lock.json for original input pins and effective environment.\n')
 save(kit/'components.json',dict(profile=PROFILE,sources=source_lock['sources'],configuration=config))
 # Preserve notice bytes without unsafe package path names or expanding the
 # immutable runtime's path/count budget. The tar is DATA documentation only.
 notices=work/'desktop-notices';notices.mkdir();copy(SOURCE/'LICENSE',notices/'PROJECT-LICENSE')
 roots=[('rust',rust),('cargo',work/'cargo-home/registry/src'),('npm',SOURCE/'desktop/node_modules'),('ubuntu',Path('/usr/share/doc'))]
 notice_rows=[]
 with tarfile.open(notices/'dependency-notices.tar','x') as archive:
  for label,root in roots:
   count=0
   for p in sorted(root.rglob('*')):
    if p.is_file() and not p.is_symlink() and any(x in p.name.lower() for x in ['license','licence','copyright','notice']):
     assert p.stat().st_size<4<<20
     name=label+'/'+p.relative_to(root).as_posix()
     archive.add(p,arcname=name,recursive=False);notice_rows.append(dict(component=label,member=name,**row(p)));count+=1
   assert count>0
 assert (notices/'dependency-notices.tar').stat().st_size<60<<20
 save(notices/'notice-origins.json',notice_rows)
 # Actual runner package census plus complete package-owned regular files replaces
 # a caller-invented universal system-library list. Mutable conffiles are recorded too.
 paths=set()
 for listing in Path('/var/lib/dpkg/info').glob('*.list'):
  for line in listing.read_text().splitlines():
   p=Path(line)
   if p.is_file() and p.resolve().parts[1] in ('usr','etc'):
    paths.add(p.resolve())
 for root in [rust,node,work/'cargo-home/registry',SOURCE/'desktop/node_modules']:
  paths.update(p.resolve() for p in root.rglob('*') if p.is_file())
 dependency_files=[row(p) for p in sorted(paths)]
 save(work/'dependency-files.json',dependency_files)
 save(kit/'inventory.json',dict(schemaVersion=1,profile=PROFILE,files=roster(kit)))
 prepared=work/'prepared-files.json';save(prepared,roster(kit));nf=work/'notice-files.json';save(nf,roster(notices))
 staging=dict(runtime=str(runtime),prepared_artifact=str(kit),prepared_files=str(prepared),prepared_files_sha256=sha(prepared),desktop_notices=str(notices),desktop_notice_files=str(nf),desktop_notice_files_sha256=sha(nf),manifest_sha256=sha(runtime/'manifest.json'),protocol_sha256=sha(SOURCE/'src/mobile_release/_desktop_engine.py'),version='0.1.4-1')
 paths={'rustc':rust/'bin/rustc','cargo':rust/'bin/cargo','node':node/'bin/node','npm':node/'lib/node_modules/npm/bin/npm-cli.js'}
 receipt=json.loads((work/'source.json').read_text());receipt.update(schemaVersion=1,version='0.1.4')
 plan=dict(receipt=receipt,staging=staging,tools={k:row(v) for k,v in paths.items()},cargoHome=env['CARGO_HOME'],dependencyFiles=dependency_files)
 A.source_binding(receipt);save(work/'plan.json',plan)
 print(sha(work/'plan.json'))

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--commit',required=True);p.add_argument('--tree',required=True);a=p.parse_args()
 try: prepare(a.work,a.commit,a.tree)
 except BaseException:
  import traceback
  if a.work.is_dir(): (a.work/'failure.txt').write_text(traceback.format_exc())
  raise
