"""Nonshipping Ubuntu assembly; no compile, install, signing, or cleanup.

Config is the existing stage_ubuntu_deb arguments as JSON. Receipt is independently
admitted build evidence binding exact current source, compiler pair, runtime and
notices. A digest of a caller-created receipt is not compiler provenance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import importlib.util
import zipfile
_spec = importlib.util.spec_from_file_location("_ubuntu_stage", Path(__file__).with_name("stage_ubuntu_deb.py"))
S = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(S)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def elf_inputs(roots):
    result = []
    for root in roots:
        for path in S.P.files(root):
            with path.open('rb') as stream:
                magic = stream.read(4)
            if magic == b'\x7fELF':
                S.elf_header(path)
                result.append(path)
    S.D.need(bool(result), 'No final ELF inputs')
    return sorted(result)


def closure_command(paths):
    return ['dpkg-shlibdeps', '-O', '--warnings=7', '-Ldebian/shlibs.local', '-xmobile-release-kit-desktop',
            *['-l' + str(p) for p in sorted({p.parent for p in paths})],
            *['-e' + str(p) for p in paths]]


def closure_output(text):
    lines = text.splitlines()
    S.D.need(len(lines) == 1 and lines[0].startswith('shlibs:Depends='), 'Dependency result differs')
    value = lines[0].split('=', 1)[1]
    S.controls('0.1.4-1', value, 0)
    return value


def current_runtime(runtime):
    """Reject an old M/Q pair even when its own inventory is consistent."""
    S.runtime_records(runtime, digest(runtime / 'manifest.json'),
                      digest(S.SOURCE / 'src/mobile_release/_desktop_engine.py'))
    for name in (*S.P.CURRENT_BOOTSTRAPS, S.P.GITHUB_CA_NAME):
        S.D.need(S.D.read(runtime / name, S.P.MAX_BOOTSTRAP_BYTES if name != S.P.GITHUB_CA_NAME else S.P.MAX_GITHUB_CA_BYTES)
                 == S.P.read_checked(S.SOURCE / 'desktop' / name, limit=S.P.MAX_GITHUB_CA_BYTES), 'Runtime bootstrap/CA differs from current source')
    source = S.SOURCE / 'src/mobile_release'
    expected = {'mobile_release/' + p.relative_to(source).as_posix(): p for p in S.P.files(source)}
    with zipfile.ZipFile(runtime / 'core.zip') as archive:
        members = archive.infolist()
        S.D.need(len(members) == len(expected) and {m.filename for m in members} == set(expected), 'Current core membership differs')
        S.D.need(sum(m.file_size for m in members) <= S.P.MAX_CORE_BYTES, 'Core size exceeds bound')
        for member in members:
            S.D.need(member.file_size == expected[member.filename].stat().st_size, 'Current core size differs')
            S.D.need(archive.read(member) == S.P.read_checked(expected[member.filename], limit=S.P.MAX_CORE_BYTES), 'Current core bytes differ')


def source_binding(receipt):
    git = ['/usr/bin/git', '--git-dir=' + str(S.SOURCE / '.git'), '--work-tree=' + str(S.SOURCE)]
    def read(*args):
        return subprocess.check_output([*git, *args], timeout=30).decode().strip()
    S.D.need(read('rev-parse', 'HEAD') == receipt['sourceCommit']
             and read('rev-parse', 'HEAD^{tree}') == receipt['sourceTree'], 'Current Git identity differs')
    S.D.need(not read('status', '--porcelain', '--untracked-files=no'), 'Tracked source is modified')
    rows = S.D.records(receipt['sourceFiles'])
    tracked = set(read('ls-files', '-z').rstrip('\0').split('\0'))
    S.D.need(set(rows) == tracked, 'Receipt must bind every tracked file exactly')
    for name, row in rows.items():
        S.D.bound(S.SOURCE / name, row)
    return rows


def bounded_command(command, work, role):
    spec = importlib.util.spec_from_file_location('_candidate_owner', Path(__file__).with_name('ubuntu_candidate_supervisor.py'))
    owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owner)
    owner.run([(role, command, 180)], work, work,
              dict(PATH='/usr/bin:/bin', HOME=str(work), LANG='C', LC_ALL='C', TZ='UTC'))
    result = json.loads((work / role / 'original-return.json').read_text())
    return subprocess.CompletedProcess(command, result['originalReturn'],
        (work / role / 'stdout.log').read_text(), (work / role / 'stderr.log').read_text())


def assemble(config, receipt_path, receipt_sha, work):
    S.D.need(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'Ubuntu amd64 required')
    release = Path('/etc/os-release').read_text()
    S.D.need('ID=ubuntu\n' in release and 'VERSION_ID="24.04"\n' in release, 'Ubuntu 24.04 required')
    S.D.need(os.getuid() == os.geteuid() != 0, 'Unprivileged assembly required')
    receipt = S.pinned_json(receipt_path, receipt_sha)
    S.D.need(receipt['schemaVersion'] == 1 and receipt['version'] == '0.1.4', 'Receipt version differs')
    for name in ('sourceCommit', 'sourceTree'):
        S.D.need(len(receipt[name]) == 40 and all(c in '0123456789abcdef' for c in receipt[name]), 'Source identity differs')
    rows = source_binding(receipt)
    S.D.need({'desktop/src-tauri/src/runtime_publication.rs', 'desktop/src-tauri/src/bin/runtime_publish.rs',
              'desktop/src-tauri/src/runtime_publication_completion.rs', 'desktop/src-tauri/src/runtime.rs', 'desktop/src-tauri/build.rs', 'desktop/src-tauri/Cargo.lock',
              'desktop/packaging/debian/postinst', 'desktop/tools/assemble_ubuntu_deb.py'} <= set(rows), 'Incomplete source binding')
    for name, row in rows.items():
        S.D.bound(S.SOURCE / name, row)
    for name in ('compiler_files_sha256', 'prepared_files_sha256', 'manifest_sha256', 'protocol_sha256', 'desktop_notice_files_sha256'):
        S.D.need(config[name] == receipt[name], 'Build receipt binding differs')
    S.D.need(config['version'] == '0.1.4-1', 'Package version differs')
    S.D.need(not work.exists() and work.is_absolute(), 'Fresh absolute assembly directory required')
    parent = work.parent.stat()
    S.D.need(parent.st_uid == os.geteuid() and stat.S_IMODE(parent.st_mode) & 0o077 == 0, 'Private parent required')
    for root in [S.SOURCE, *[Path(config[k]) for k in ('compiled', 'runtime', 'prepared_artifact', 'desktop_notices')]]:
        S.D.need(root.is_absolute() and not work.is_relative_to(root) and not root.is_relative_to(work),
                 'Assembly workspace must be disjoint from inputs and source')
    current_runtime(Path(config['runtime']))
    work.mkdir(mode=0o700)
    (work / 'debian').mkdir()
    (work / 'debian/control').write_text('Source: mobile-release-kit-desktop\nSection: devel\nPriority: optional\nMaintainer: Mobile Release Kit contributors <noreply@github.com>\n\nPackage: mobile-release-kit-desktop\nArchitecture: amd64\nDescription: nonshipping validation assembly\n')
    (work / 'debian/shlibs.local').write_text('libssl 3 mobile-release-kit-desktop (= 0.1.4-1)\nlibcrypto 3 mobile-release-kit-desktop (= 0.1.4-1)\n')
    args = dict(config)
    for key in ('compiled', 'compiler_files', 'runtime', 'prepared_artifact', 'prepared_files', 'desktop_notices', 'desktop_notice_files'):
        args[key] = Path(args[key])
        S.D.need(args[key].is_absolute(), 'Absolute admitted input required')
    paths = elf_inputs([args['compiled'], args['runtime']])
    before = {str(p): digest(p) for p in paths}
    command = closure_command(paths)
    run = bounded_command(command, work, 'dependency-original')
    (work / 'dependency-command.json').write_text(json.dumps(command, indent=2))
    (work / 'dependency.stdout').write_text(run.stdout)
    (work / 'dependency.stderr').write_text(run.stderr)
    S.D.need(run.returncode == 0, 'Dependency analysis failed; originals retained')
    args['depends'] = closure_output(run.stdout)
    args['output'] = work / 'package'
    result = S.stage(argparse.Namespace(**args))
    S.D.need(before == {str(p): digest(p) for p in paths}, 'ELF inputs changed')
    # Normalize only the newly created package archive root, never an installed runtime.
    os.chmod(args['output'], 0o755)
    artifact = work / 'mobile-release-kit-desktop_0.1.4-1_amd64.deb'
    run = bounded_command(['dpkg-deb', '--root-owner-group', '--build', str(args['output']), str(artifact)], work, 'assembly-original')
    (work / 'assembly.stdout').write_text(run.stdout)
    (work / 'assembly.stderr').write_text(run.stderr)
    S.D.need(run.returncode == 0, 'Assembly failed; partial output retained')
    source_binding(receipt)
    current_runtime(Path(config['runtime']))
    result.update(artifact=artifact.name, sha256=digest(artifact), size=artifact.stat().st_size,
                  sourceCommit=receipt['sourceCommit'], sourceTree=receipt['sourceTree'],
                  receiptSha256=receipt_sha, elfInputs=before, depends=args['depends'], signed=False)
    (work / 'assembly.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--receipt-sha256', required=True)
    parser.add_argument('--work', type=Path, required=True)
    a = parser.parse_args()
    print(json.dumps(assemble(json.loads(a.config.read_text()), a.receipt, a.receipt_sha256, a.work), indent=2))
