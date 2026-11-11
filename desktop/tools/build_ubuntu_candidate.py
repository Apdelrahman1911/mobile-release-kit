"""Lead-reviewed disposable Ubuntu candidate execution. Never installs or qualifies.

Requires pre-admitted toolchain/dependencies, current runtime and notices. Offline
Cargo and npm build perform no dependency acquisition. Preserve every failure.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tomllib
import assemble_ubuntu_deb as A
from ubuntu_candidate_supervisor import run


def sha(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for chunk in iter(lambda: f.read(1024*1024), b''): h.update(chunk)
    return h.hexdigest()


def execute(plan, work, lock):
    assert platform.system() == 'Linux' and platform.machine() == 'x86_64'
    assert 'VERSION_ID="24.04"\n' in Path('/etc/os-release').read_text()
    assert os.getuid() == os.geteuid() != 0
    assert work.is_absolute() and not work.exists()
    source = A.S.SOURCE
    assert not work.is_relative_to(source) and not source.is_relative_to(work)
    receipt = plan['receipt']
    A.source_binding(receipt)
    config = plan['staging']
    A.current_runtime(Path(config['runtime']))
    assert sha(Path(config['runtime'])/'manifest.json') == config['manifest_sha256']
    assert sha(source/'src/mobile_release/_desktop_engine.py') == config['protocol_sha256']
    tools = plan['tools']
    assert set(tools) == {'cargo', 'rustc', 'node', 'npm'}
    for row in tools.values():
        p = Path(row['path']); assert p.is_absolute() and sha(p) == row['sha256']
    # This is an explicit read-only dependency admission, not an acquisition step.
    for row in plan['dependencyFiles']:
        assert Path(row['path']).is_absolute() and sha(Path(row['path'])) == row['sha256']
    assert plan['dependencyFiles']
    assert not (source/'desktop/dist').exists()
    work.mkdir(mode=0o700)
    evidence = work/'evidence'; evidence.mkdir(mode=0o700)
    for n in ('home','tmp','compiled'): (work/n).mkdir(mode=0o700)
    env = dict(PATH='/usr/bin:/bin', HOME=str(work/'home'), TMPDIR=str(work/'tmp'),
               LANG='C', LC_ALL='C', TZ='UTC', CI='true', CARGO_BUILD_JOBS='1',
               RAYON_NUM_THREADS='1', CARGO_INCREMENTAL='0', RUSTC=tools['rustc']['path'],
               CARGO_HOME=plan['cargoHome'],
               MRK_BUNDLED_RUNTIME_MANIFEST_SHA256=config['manifest_sha256'],
               MRK_BUNDLED_PROTOCOL_SHA256=config['protocol_sha256'])
    (evidence/'plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    with lock.open('r') as owner:
        fcntl.flock(owner,fcntl.LOCK_EX|fcntl.LOCK_NB)
        node=tools['node']['path']; npm=tools['npm']['path']; cargo=tools['cargo']['path']
        run([('rustc-version',[tools['rustc']['path'],'--version'],15),('cargo-version',[cargo,'--version'],15),('node-version',[node,'--version'],15)],source/'desktop',evidence,env)
        channel=tomllib.loads((source/'desktop/rust-toolchain.toml').read_text())['toolchain']['channel']
        assert (evidence/'rustc-version/stdout.log').read_text().startswith('rustc '+channel+' ')
        # npm is pinned npm-cli.js, run by the pinned node executable.
        env['PATH']=str(Path(cargo).parent)+':'+str(Path(node).parent)+':/usr/bin:/bin'
        run([('frontend',[node,npm,'run','build'],300)],source/'desktop',evidence,env)
        frontend={str(p.relative_to(source/'desktop/dist')):sha(p) for p in sorted((source/'desktop/dist').rglob('*')) if p.is_file()}
        assert 'index.html' in frontend and len(frontend)>1
        (evidence/'frontend.json').write_text(json.dumps(frontend,indent=2)+'\n')
        shared=['--offline','--locked','--jobs','1','--target','x86_64-unknown-linux-gnu','--no-default-features']
        env['CARGO_TARGET_DIR']=str(work/'publisher-target')
        run([('publisher-build',[cargo,'build',*shared,'--release','--features','ubuntu-runtime-publisher','--bin','mrk-runtime-publish'],1800),
             ('publisher-tests',[cargo,'test',*shared,'--features','ubuntu-runtime-publisher','--lib','runtime_publication::','--','--test-threads=1'],1800)],source/'desktop/src-tauri',evidence,env)
        env['MRK_RUNTIME_PUBLICATION_HELPER_TESTS']='1'
        run([('publisher-native-helpers',[cargo,'test',*shared,'--features','ubuntu-runtime-publisher','--lib','runtime_publication::tests::helper_','--','--ignored','--test-threads=1','--nocapture'],1800)],source/'desktop/src-tauri',evidence,env)
        native_log=(evidence/'publisher-native-helpers/stdout.log').read_text()
        assert 'helper_completion_identity_survives_reopen_after_rename ... ok' in native_log
        assert 'helper_completion_same_bytes_replacement_refuses_identity ... ok' in native_log
        del env['MRK_RUNTIME_PUBLICATION_HELPER_TESTS']
        env['CARGO_TARGET_DIR']=str(work/'shell-target')
        run([('shell-build',[cargo,'build',*shared,'--release','--features','desktop-shell,custom-protocol','--bin','mobile-release-kit-desktop'],1800)],source/'desktop/src-tauri',evidence,env)
    for target,name in [('publisher','mrk-runtime-publish'),('shell','mobile-release-kit-desktop')]:
        shutil.copyfile(work/(target+'-target')/'x86_64-unknown-linux-gnu/release'/name,work/'compiled'/name)
    binaries=[dict(path=p.name,size=p.stat().st_size,sha256=sha(p)) for p in sorted((work/'compiled').iterdir())]
    inventory=work/'compiler-files.json'; inventory.write_text(json.dumps(binaries,indent=2)+'\n')
    config.update(compiled=str(work/'compiled'),compiler_files=str(inventory),compiler_files_sha256=sha(inventory))
    receipt.update({k:config[k] for k in ('compiler_files_sha256','prepared_files_sha256','manifest_sha256','protocol_sha256','desktop_notice_files_sha256')})
    receipt.update(frontendFiles=frontend,tools=tools,qualified=False,signed=False)
    A.source_binding(receipt)
    for row in tools.values(): assert sha(Path(row['path']))==row['sha256']
    rp=work/'build-receipt.json'; rp.write_text(json.dumps(receipt,indent=2)+'\n')
    result=A.assemble(config,rp,sha(rp),work/'assembly')
    (work/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--plan',type=Path,required=True)
    p.add_argument('--plan-sha256',required=True)
    p.add_argument('--work',type=Path,required=True)
    p.add_argument('--compiler-lock',type=Path,required=True)
    a=p.parse_args()
    assert sha(a.plan)==a.plan_sha256
    execute(json.loads(a.plan.read_text()),a.work,a.compiler_lock)
