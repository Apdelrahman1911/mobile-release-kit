"""Read-only disposable CI resource observations; no tool admission or repair.

Own open errno is not altool's syscall errno. No resource contents are read.
"""
import contextlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

MAX_ENTRIES = 1000000
MAX_DEPTH = 64
MAX_PATH = 4096
MAX_NAMES = 32 * 1024 * 1024
MAX_MATCHES = 16
CONTROL_LIMIT = 96 * 1024
OUTPUT_LIMIT = 256 * 1024
CONTROL = 'xcode-defaults-observation.json'
FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class Refused(Exception):
    pass


def need(value):
    if not value:
        raise Refused()


def point(state):
    need(time.monotonic() < state['end'])


def identity(row):
    return [row.st_dev, row.st_ino, stat.S_IFMT(row.st_mode)]


def facts(row):
    return dict(uid=row.st_uid, gid=row.st_gid, mode=row.st_mode, links=row.st_nlink,
                flags=getattr(row, 'st_flags', 0), size=row.st_size,
                device=row.st_dev, inode=row.st_ino)


@contextlib.contextmanager
def opened(name, parent, directory, state):
    point(state)
    state['operation'] = 'lstat'
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    need(stat.S_ISDIR(before.st_mode) if directory else stat.S_ISREG(before.st_mode))
    state['operation'] = 'open'
    fd = os.open(name, FLAGS | (os.O_DIRECTORY if directory else 0), dir_fd=parent)
    try:
        state['operation'] = 'fstat'
        held = os.fstat(fd)
        state['operation'] = 'post-lstat'
        need(identity(before) == identity(held) ==
             identity(os.stat(name, dir_fd=parent, follow_symlinks=False)))
        yield fd
        point(state)
        state['operation'] = 'fstat'
        held = os.fstat(fd)
        state['operation'] = 'post-lstat'
        need(identity(before) == identity(held) ==
             identity(os.stat(name, dir_fd=parent, follow_symlinks=False)))
    finally:
        try:
            os.close(fd)
        except OSError:
            state['closeFailures'] += 1


def public_parts(path):
    need(type(path) is str and 0 < len(path.encode('utf-8')) <= MAX_PATH)
    parts = path.split('/')
    need(2 <= len(parts) <= MAX_DEPTH and parts[0] == 'Contents' and parts[-1] == 'Defaults.properties'
         and all(part not in ('', '.', '..') and all(c.isprintable() for c in part) for part in parts))
    return parts


def scan(app, state):
    matches, errors = [], []
    count, queued = [0], [0]
    device = os.fstat(app).st_dev
    def visit(fd, parts):
        point(state)
        need(len(parts) <= MAX_DEPTH and len('/'.join(parts).encode('utf-8')) <= MAX_PATH)
        names = []
        try:
            with os.scandir(fd) as iterator:
                for entry in iterator:
                    point(state)
                    count[0] += 1
                    cost = len(os.fsencode(entry.name)) + 64
                    need(count[0] <= MAX_ENTRIES and queued[0] + cost <= MAX_NAMES)
                    names.append((entry.name, cost)); queued[0] += cost
            while names:
                name, cost = names.pop(); queued[0] -= cost
                point(state)
                row = os.stat(name, dir_fd=fd, follow_symlinks=False)
                need(row.st_dev == device)
                child = parts + [name]
                need(len(child) <= MAX_DEPTH and len('/'.join(child).encode('utf-8')) <= MAX_PATH)
                if stat.S_ISDIR(row.st_mode):
                    try:
                        with opened(name, fd, True, state) as directory:
                            visit(directory, child)
                    except OSError as error:
                        if len(errors) < 16:
                            errors.append(dict(depth=len(child), errno=error.errno))
                        else:
                            raise Refused()
                elif name == 'Defaults.properties' and parts and parts[0] == 'Contents':
                    # No alias traversal even for a matching basename.
                    need(stat.S_ISREG(row.st_mode))
                    path = '/'.join(child); public_parts(path)
                    need(len(matches) < MAX_MATCHES)
                    matches.append(path)
        finally:
            queued[0] -= sum(cost for _, cost in names)
    visit(app, [])
    return sorted(matches), dict(complete=not errors, entries=count[0], errors=errors)


def observe(app, path, state):
    parts = public_parts(path)
    rows = [dict(index=0, **facts(os.fstat(app)))]
    result = dict(path=path, nodes=rows, errno=None, openErrno=None, opened=False)
    def step(fd, index):
        point(state)
        name = parts[index]
        try:
            state['operation'] = 'lstat'
            before = os.stat(name, dir_fd=fd, follow_symlinks=False)
            rows.append(dict(index=index+1, **facts(before)))
            with opened(name, fd, index < len(parts)-1, state) as child:
                if index == len(parts)-1:
                    result['opened'] = True  # Deliberately no read, mmap or content hash.
                else:
                    step(child, index+1)
        except OSError as error:
            result.update(errno=error.errno, openErrno=error.errno if state['operation'] == 'open' else None,
                          failedOperation=state['operation'], failedIndex=index+1)
    step(app, 0)
    return result


def selection(applications, state):
    row = os.stat('Xcode.app', dir_fd=applications, follow_symlinks=False)
    need(row.st_uid in (0, os.getuid()))
    target = None
    name = 'Xcode.app'
    if stat.S_ISLNK(row.st_mode):
        need(row.st_nlink == 1 and 1 <= row.st_size <= 1024)
        target = os.readlink(name, dir_fd=applications)
        name = target[len('/Applications/'):] if target.startswith('/Applications/') else target
        need(name != 'Xcode.app' and len(os.fsencode(name)) <= 255
             and re.fullmatch(r'Xcode[A-Za-z0-9._+-]*\.app', name))
    else:
        need(stat.S_ISDIR(row.st_mode))
    point(state)
    need(identity(row) == identity(os.stat('Xcode.app', dir_fd=applications, follow_symlinks=False)))
    return dict(name=name, alias=identity(row), target=target)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii') + b'\n'


def control_data(value):
    need(type(value) is dict and set(value) == {'schemaVersion', 'selection', 'app', 'paths', 'scanComplete'}
         and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
         and type(value['scanComplete']) is bool and type(value['paths']) is list
         and len(value['paths']) <= MAX_MATCHES)
    for path in value['paths']:
        public_parts(path)
    need(len(set(value['paths'])) == len(value['paths']))
    chosen = value['selection']
    need(type(chosen) is dict and set(chosen) == {'name', 'alias', 'target'})
    need(type(chosen['name']) is str and re.fullmatch(r'Xcode[A-Za-z0-9._+-]*\.app', chosen['name']))
    for row in (value['app'], chosen['alias']):
        need(type(row) is list and len(row) == 3 and all(type(n) is int and n >= 0 for n in row))
    need(chosen['target'] is None or type(chosen['target']) is str and len(chosen['target']) <= 1024)
    return value


def load_control(fd, state):
    with opened(CONTROL, fd, False, state) as original:
        row = os.fstat(original)
        need(row.st_uid == os.getuid() and stat.S_IMODE(row.st_mode) == 0o600
             and row.st_nlink == 1 and 0 < row.st_size <= CONTROL_LIMIT)
        raw = os.read(original, CONTROL_LIMIT+1)
        need(len(raw) == row.st_size)
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result); result[key] = value
        return result
    return control_data(json.loads(raw.decode('utf-8'), object_pairs_hook=pairs))


def save_control(fd, value, state):
    body = encoded(control_data(value)); need(len(body) <= CONTROL_LIMIT)
    original = os.open(CONTROL, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
    try:
        need(os.write(original, body) == len(body))
        row = os.fstat(original)
        need(row.st_uid == os.getuid() and stat.S_IMODE(row.st_mode) == 0o600 and row.st_nlink == 1
             and identity(row) == identity(os.stat(CONTROL, dir_fd=fd, follow_symlinks=False)))
    finally:
        try:
            os.close(original)
        except OSError:
            state['closeFailures'] += 1


def profile(arguments):
    need(arguments in (['before'], ['after']) and sys.platform == 'darwin'
         and os.getuid() == os.geteuid() != 0 and os.getgid() == os.getegid()
         and os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
         and os.environ.get('RUNNER_OS') == 'macOS' and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
         and os.environ.get('GITHUB_REPOSITORY') == 'Apdelrahman1911/mobile-release-kit'
         and os.environ.get('COMPONENT') == 'ios-tools')
    root = Path(os.environ['WORK_ROOT'])
    need(root.is_absolute() and root.parent == Path(os.environ['RUNNER_TEMP'])
         and re.fullmatch(r'mrk-ios-tools\.[A-Za-z0-9]{8}', root.name))
    return arguments[0], root


def main():
    state = dict(end=time.monotonic()+90, closeFailures=0)
    output = dict(scope='ci-xcode-defaults-resource-observation', qualification=False, altoolSyscallErrno=False)
    try:
        phase, work = profile(sys.argv[1:]); output['phase'] = phase
        with opened(str(work), None, True, state) as private:
            row = os.fstat(private)
            need(row.st_uid == os.getuid() and stat.S_IMODE(row.st_mode) == 0o700)
            previous = load_control(private, state) if phase == 'after' else None
            with opened('/', None, True, state) as root:
                with opened('Applications', root, True, state) as applications:
                    chosen = selection(applications, state)
                    with opened(chosen['name'], applications, True, state) as app:
                        app_id = identity(os.fstat(app))
                        if previous is None:
                            paths, census = scan(app, state)
                        else:
                            need(previous['selection'] == chosen and previous['app'] == app_id)
                            paths = previous['paths']; census = dict(complete=previous['scanComplete'], reusedBeforeNomination=True)
                        output.update(selection=chosen['name'], scan=census, observations=[observe(app, path, state) for path in paths])
                        need(selection(applications, state) == chosen)
                        nomination = dict(schemaVersion=1, selection=chosen, app=app_id, paths=paths, scanComplete=census['complete'])
            # All resource originals consumed before writing diagnostic DATA.
            need(state['closeFailures'] == 0)
            if phase == 'before':
                save_control(private, nomination, state)
        need(state['closeFailures'] == 0)
        output.update(originalClosesKnown=True, outcome='observed' if census['complete'] else 'unconfirmed-incomplete-scan')
        body = encoded(output); need(len(body) <= OUTPUT_LIMIT)
        sys.stdout.write(body.decode('ascii'))
        return 0
    except Exception as error:
        failure = dict(scope=output['scope'], qualification=False, outcome='unconfirmed',
                       phase=output.get('phase'), errno=error.errno if isinstance(error, OSError) else None,
                       closeFailures=state['closeFailures'])
        print(encoded(failure).decode('ascii'), end='')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
