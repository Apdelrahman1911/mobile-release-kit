"""Disposable Windows CI producer: exact source -> runtime -> binaries -> MSI.
No signing/publication/installation. All commands keep original bounded logs.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import urllib.request
import build_windows_transaction as native
import prepare_windows_msi as msi
import prepare_windows_embedded_payload as embedded
from windows_build_command import run_owned
import windows_compiler_evidence as compiler_evidence

def source_asset_admission(source,logs):
 """Observe exact public source asset bytes; never normalize or repair them."""
 rows=[]
 for name,size,pin in ((embedded.GITHUB_CA_SOURCE,embedded.GITHUB_CA_BYTES,embedded.GITHUB_CA_SHA256),
                       (embedded.NOTICE_SOURCE,embedded.NOTICE_BYTES,embedded.NOTICE_SHA256)):
  raw=embedded.runtime_preparation.read_checked(source/name,limit=256*1024)
  actual=hashlib.sha256(raw).hexdigest()
  rows.append({'path':name,'expectedBytes':size,'expectedSha256':pin,'actualBytes':len(raw),
               'actualSha256':actual,'crlfCount':raw.count(b'\r\n'),'lfCount':raw.count(b'\n'),
               'matched':len(raw)==size and actual==pin})
 (logs/'source-asset-bytes.json').write_text(json.dumps({'schema':1,'assets':rows},indent=2)+'\n')
 msi.need(all(row['matched'] for row in rows),'source asset bytes differ; original measurements retained in source-asset-bytes.json')

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('source','source-commit','source-tree','output'):p.add_argument('--'+name,required=True)
 a=p.parse_args();source=Path(a.source).resolve();out=Path(a.output).absolute()
 msi.need(os.name=='nt' and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('GITHUB_REPOSITORY')=='Apdelrahman1911/mobile-release-kit' and os.environ.get('GITHUB_WORKFLOW_SHA')==os.environ.get('GITHUB_SHA')==a.source_commit and os.environ.get('GITHUB_EVENT_NAME')=='push' and os.environ.get('GITHUB_REF')=='refs/heads/verify/desktop-windows-installer-candidate-014' and os.environ.get('GITHUB_RUN_ATTEMPT')=='1','exact disposable Windows source/run admission required')
 msi.need(not out.exists() and out!=source and source not in out.parents,'fresh disjoint output required')
 def git(*args):return subprocess.check_output(['git','-C',str(source),*args],text=True).strip()
 msi.need(git('rev-parse','HEAD')==a.source_commit and git('rev-parse','HEAD^{tree}')==a.source_tree,'reviewed source identity')
 msi.need(not git('status','--porcelain','--untracked-files=no'),'tracked source must be clean')
 out.mkdir();logs=out/'logs';logs.mkdir()
 source_asset_admission(source,logs)
 env=os.environ.copy();msi.need(not any(env.get(key) for key in ('RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','CMAKE_GENERATOR','CXX','CC','CL','_CL_')),'ambient compiler injection refused');env.update(CARGO_BUILD_JOBS='1',CARGO_HOME=str(out/'cargo'),CARGO_TARGET_DIR=str(out/'target'),MSBUILDDISABLENODEREUSE='1',DOTNET_CLI_USE_MSBUILD_SERVER='0',RUSTUP_TOOLCHAIN='1.98.0')
 def run(name,args,cwd=source,timeout=1800):
  return run_owned(name,args,cwd=cwd,env=env,logs=logs,timeout=timeout)
 archive=out/embedded.ZIP_NAME;request=urllib.request.Request(embedded.ZIP_URL,headers={'User-Agent':'MRK-disposable-native-validation/1'})
 with urllib.request.urlopen(request,timeout=60) as incoming,archive.open('xb') as target:
  count=0;h=hashlib.sha256()
  while True:
   chunk=incoming.read(65536)
   if not chunk:break
   count+=len(chunk);msi.need(count<=embedded.ZIP_BYTES,'archive bound');h.update(chunk);target.write(chunk)
 msi.need(count==embedded.ZIP_BYTES and h.hexdigest()==embedded.ZIP_SHA256,'public archive pin')
 runtime=out/'runtime';prepared=embedded.prepare(source,archive,runtime)
 (out/'runtime-prepared.json').write_text(json.dumps(prepared,indent=2)+'\n')
 env.update(MRK_BUNDLED_RUNTIME_MANIFEST_SHA256=prepared['manifestSha256'],MRK_BUNDLED_PROTOCOL_SHA256=prepared['protocolSha256'])
 run('npm-ci',['npm.cmd','ci','--ignore-scripts'],source/'desktop',600)
 run('frontend-build',['npm.cmd','run','build'],source/'desktop',600)
 manifest=str(source/'desktop/src-tauri/Cargo.toml')
 run('shell-typecheck',['cargo','check','--locked','--release','--jobs','1','--target',msi.TARGET,'--manifest-path',manifest,'--no-default-features','--features','desktop-shell,custom-protocol','--bin',msi.SHELL.removesuffix('.exe')])
 run('publisher-data-tests',['cargo','test','--locked','--release','--jobs','1','--target',msi.TARGET,'--manifest-path',manifest,'--no-default-features','--features','windows-runtime-publisher','--lib','--','--nocapture'])
 run('shell-metadata',['cargo','metadata','--locked','--format-version','1','--filter-platform',msi.TARGET,'--manifest-path',manifest,'--no-default-features','--features','desktop-shell,custom-protocol'])
 selected={}
 for role,binary,features in [('publisher',msi.PUBLISHER.removesuffix('.exe'),'windows-runtime-publisher'),('shell',msi.SHELL.removesuffix('.exe'),'desktop-shell,custom-protocol')]:
  run(role+'-compile',['cargo','build','--locked','--release','--jobs','1','--target',msi.TARGET,'--manifest-path',manifest,'--no-default-features','--features',features,'--bin',binary,'--message-format=json-render-diagnostics'])
  selected[role]=compiler_evidence.selected_artifact((logs/(role+'-compile.stdout')).read_bytes(),role=role,source=source,output=out)
 compiler_evidence.retain_normal(source,out,selected['shell'])
 inputs=out/'inputs';inputs.mkdir();shutil.copytree(runtime,inputs/'runtime')
 for role,name in (('shell',msi.SHELL),('publisher',msi.PUBLISHER)):
  original=Path(selected[role]['path']);msi.need(hashlib.sha256(original.read_bytes()).hexdigest()==selected[role]['sha256'],'compiler-selected original changed');shutil.copyfile(original,inputs/name)
 paths=msi.SOURCE_REQUIRED|native.REQUIRED|{'desktop/tools/prepare_windows_transaction_run.py'}
 files={p.relative_to(inputs).as_posix():{'size':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in inputs.rglob('*') if p.is_file()}
 b={'schema':1,'sourceCommit':a.source_commit,'sourceTree':a.source_tree,'version':json.loads((source/'desktop/src-tauri/tauri.conf.json').read_text())['version'],
    'target':msi.TARGET,'manifestSha256':prepared['manifestSha256'],'protocolSha256':prepared['protocolSha256'],
    'sourceFiles':{p:hashlib.sha256((source/p).read_bytes()).hexdigest() for p in sorted(paths)},'files':files}
 binding=out/'binding.json';raw=(json.dumps(b,sort_keys=True,indent=2)+'\n').encode();binding.write_bytes(raw)
 run('native-and-msi',['python',str(source/'desktop/tools/build_windows_transaction.py'),'--source',str(source),'--inputs',str(inputs),'--binding',str(binding),'--binding-sha256',hashlib.sha256(raw).hexdigest(),'--output',str(out/'msi'),'--compile'],timeout=1200)
 # Builds may create ignored outputs, but cannot change any tracked source.
 msi.need(not git('status','--porcelain','--untracked-files=no'),'tracked source changed while building')
if __name__=='__main__':main()
