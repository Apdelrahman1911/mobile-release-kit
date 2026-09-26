"""Bounded public hosted-Python correspondence; never runtime admission."""
import hashlib, json, os, re, stat, sys

# DATA correspondence under the hosted-platform TCB, not interpreter
# startup/stdlib/loader attestation or permission to run the compiler.
PATH = '/usr/bin/python3.12'

METADATA_REF = 'refs/heads/verify/desktop-shell-host-metadata'
SHELL_REF = 'refs/heads/verify/desktop-installed-shell'
ROUTES = ((METADATA_REF, 'host-metadata-only', 'compile'),
          (SHELL_REF, 'compile', 'compile'),
          (SHELL_REF, 'observe', 'compile'),
          ('refs/heads/verify/desktop-installed-github-readonly', 'compile', 'compile'),
          ('refs/heads/verify/desktop-installed-github-readonly', 'observe', 'compile'),
          ('refs/heads/verify/desktop-installed-github-normal-boundaries', 'compile', 'compile'),
          ('refs/heads/verify/desktop-installed-github-normal-boundaries', 'observe', 'compile'))

class Refused(Exception):
    pass

def need(ok, reason):
    if not ok:
        raise Refused(reason)

def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

def observe():
    descriptors, directories, problem = [], [], None
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        for name in ('/', 'usr', 'bin'):
            parent = descriptors[-1] if descriptors else None
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            need(stat.S_ISDIR(before.st_mode), 'directory-type')
            fd = os.open(name, directory_flags, dir_fd=parent)
            descriptors.append(fd)
            wanted = identity(before)
            need(identity(os.fstat(fd)) == wanted, 'directory-open-identity')
            directories.append((name, parent, fd, wanted))
        parent = descriptors[-1]
        before = os.stat('python3.12', dir_fd=parent, follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o755
             and before.st_uid == before.st_gid == 0 and before.st_nlink == 1
             and 0 < before.st_size <= 16 << 20, 'body-metadata')
        fd = os.open('python3.12', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=parent)
        descriptors.append(fd)
        wanted = identity(before)
        need(identity(os.fstat(fd)) == wanted, 'body-open-identity')
        hashed, count = hashlib.sha256(), 0
        while count < before.st_size:
            block = os.read(fd, min(65536, before.st_size - count))
            need(bool(block), 'body-short-read')
            count += len(block)
            hashed.update(block)
        need(count == before.st_size and identity(os.fstat(fd)) == wanted
             and identity(os.stat('python3.12', dir_fd=parent, follow_symlinks=False)) == wanted,
             'body-final-identity')
        for name, parent, fd, wanted in reversed(directories):
            need(identity(os.fstat(fd)) == wanted
                 and identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == wanted,
                 'directory-final-identity')
    except BaseException as error:
        problem = error
    # Attempt every original close once; preserve the first failure.
    # No receipt exists until all four original closes have succeeded.
    for fd in reversed(descriptors):
        try:
            os.close(fd)
        except BaseException:
            if problem is None:
                problem = Refused('descriptor-close')
    if problem is not None:
        raise problem
    return {'path': PATH, 'kind': 'regular', 'size': before.st_size, 'sha256': hashed.hexdigest(),
            'device': before.st_dev, 'inode': before.st_ino, 'mode': stat.S_IMODE(before.st_mode),
            'uid': before.st_uid, 'gid': before.st_gid, 'links': before.st_nlink,
            'mtimeNs': before.st_mtime_ns, 'ctimeNs': before.st_ctime_ns,
            'readBytes': count, 'identityStable': True, 'descriptorsClosed': True}


def context(e):
    ref = e['GITHUB_REF']
    repository = 'Apdelrahman1911/mobile-release-kit'
    need(e['GITHUB_ACTIONS'] == 'true' and e['RUNNER_ENVIRONMENT'] == 'github-hosted'
         and e['RUNNER_OS'] == 'Linux' and e['RUNNER_ARCH'] == 'X64'
         and e['GITHUB_EVENT_NAME'] == 'push' and e['GITHUB_REPOSITORY'] == repository
         and (ref, e['MRK_INSTALLED_SHELL_CASE'], e['GITHUB_JOB']) in ROUTES,
         'provider-route')
    need(re.fullmatch(r'[0-9a-f]{40}', e['GITHUB_SHA']) is not None and e['GITHUB_SHA'] != '0' * 40
         and e['GITHUB_SHA'] == e['GITHUB_WORKFLOW_SHA'] == e['MRK_PUSH_EVENT_AFTER']
         and e['GITHUB_WORKFLOW_REF'] == repository + '/.github/workflows/desktop-ubuntu-publication.yml@' + ref
         and re.fullmatch(r'[1-9][0-9]{0,19}', e['GITHUB_RUN_ID']) is not None
         and re.fullmatch(r'[1-9][0-9]{0,19}', e['GITHUB_RUN_ATTEMPT']) is not None
         and (ref != METADATA_REF or e['GITHUB_RUN_ATTEMPT'] == '1'), 'original-source-run')
    need(e['ImageOS'] == 'ubuntu24'
         and re.fullmatch(r'[0-9]{8}\.[0-9]{1,6}\.[0-9]{1,6}', e['ImageVersion']) is not None,
         'image-identity')
    return {key: e[key] for key in ('GITHUB_REPOSITORY', 'GITHUB_SHA', 'GITHUB_WORKFLOW_SHA',
            'GITHUB_WORKFLOW_REF', 'GITHUB_REF', 'GITHUB_EVENT_NAME', 'GITHUB_RUN_ID',
            'GITHUB_RUN_ATTEMPT', 'RUNNER_ENVIRONMENT', 'ImageOS', 'ImageVersion',
            'GITHUB_JOB', 'MRK_INSTALLED_SHELL_CASE')}


def main():
    try:
        run = context(os.environ)
        uids, gids = os.getresuid(), os.getresgid()
        executable, machine = os.path.realpath(sys.executable), os.uname().machine
        need(sys.platform == 'linux' and machine == 'x86_64' and executable == PATH
             and sys.version_info[:2] == (3, 12)
             and sys.flags.isolated == sys.flags.no_site == sys.flags.dont_write_bytecode == 1
             and uids[0] != 0 and gids[0] != 0 and len(set(uids)) == len(set(gids)) == 1,
             'isolated-nonroot-python')
        body = observe()
        receipt = {'schema': 'mrk-hosted-python-body-data-1', 'scope': 'candidate-only',
                   'trustModel': 'github-hosted-platform-tcb-v1', 'runtimeAdmission': False,
                   'nativeQualification': 'not-established',
                   'run': run,
                   'interpreter': {'executable': executable, 'version': list(sys.version_info[:3]),
                                   'platform': sys.platform, 'machine': machine, 'uid': uids[0], 'gid': gids[0],
                                   'isolated': sys.flags.isolated, 'noSite': sys.flags.no_site,
                                   'dontWriteBytecode': sys.flags.dont_write_bytecode},
                   'body': body}
        line = ('MRK-HOSTED-PYTHON-DATA ' + json.dumps(receipt, sort_keys=True, separators=(',', ':'),
                                                  ensure_ascii=True) + '\n').encode('ascii')
        need(len(line) <= 4096, 'receipt-bound')
        need(sys.stdout.buffer.write(line) == len(line), 'receipt-short-write')
        sys.stdout.buffer.flush()
    except Refused as error:
        print('MRK-HOSTED-PYTHON-REFUSED ' + error.args[0], file=sys.stderr, flush=True)
        raise SystemExit(70)
    except BaseException:
        print('MRK-HOSTED-PYTHON-REFUSED io-or-internal', file=sys.stderr, flush=True)
        raise SystemExit(70)


if __name__ == "__main__":
    main()
