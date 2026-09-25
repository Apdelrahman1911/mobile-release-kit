"""One fixed fresh G compile, exact GNOME SESSION batch, and original postchecks.
No acquisition, installation, generic VM, artifact export, DATA2 or normal build.
"""
import hashlib, io, json, os, re, stat, subprocess, sys, tarfile
from pathlib import Path

UID = GID = 61000
PYTHON_PYCACHE = Path("/run/mrk-gnome-python-empty-pycache-v1")
pycache_fds = []
pycache_state = None
PYTHON_ROOT = Path("/run/mrk-gnome-controller-runtime-v2")
PYTHON_EXECUTABLE = str(PYTHON_ROOT / "python/bin/python3")
PYTHON_SEARCH = (str(PYTHON_ROOT / "python/lib/python314.zip"),
                 str(PYTHON_ROOT / "python/lib/python3.14"), str(PYTHON_ROOT / "python/lib/python3.14/lib-dynload"))
CONTROLLER_RUNTIME_SHA256 = "4a413ee3d374b2b8f4609e817f87a0c35f018af3a6e3b945a23655e38e2b2071"
CONTROLLER_SELECTION_SHA256 = "30d3f79676055151ae469d45a3ed62a5cf16e092fa266da2103ff8adda1a2ab1"
runtime_fds = []
runtime_state = None
PYTHON_BUILTINS = ('_abc', '_ast', '_bisect', '_blake2', '_codecs', '_collections', '_contextvars', '_ctypes', '_datetime', '_functools', '_heapq', '_hmac', '_imp', '_io', '_json', '_locale', '_md5', '_opcode', '_operator', '_posixsubprocess', '_random', '_sha1', '_sha2', '_sha3', '_signal', '_socket', '_sre', '_ssl', '_stat', '_string', '_struct', '_suggestions', '_symtable', '_sysconfig', '_thread', '_tokenize', '_tracemalloc', '_types', '_typing', '_warnings', '_weakref', 'atexit', 'binascii', 'builtins', 'errno', 'faulthandler', 'fcntl', 'gc', 'itertools', 'marshal', 'math', 'posix', 'pwd', 'pyexpat', 'resource', 'select', 'sys', 'time', 'unicodedata', 'zlib')
ROOT = Path("/native-fixture-backing")
STAGE = Path("/tmp/native-runtime")
ENV = {"PATH": "/usr/bin:/bin", "HOME": "/tmp", "TMPDIR": "/tmp", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
# bwrap --chdir publishes this one fixed owner PWD; subprocess ENV stays six-key.
OWNER_ENV = {**ENV, "PWD": "/tmp"}
DROP = ["/usr/bin/setpriv", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--"]
TEST = "asset_session::gnome_transport_fixture::real_gnome_session_transport_originals"
PRODUCT_TREE = "4f809afa38b6b814e8c8110df5599cbf5bc97677"
# The expanded carrier tree/index are actual readonly source-binding DATA;
# neither is the old964 product inventory nor a self-referential source literal.
SOURCE_INDEX = TREE = binding = None
CAPS = 0x2001C5
ENTRY = "MRK_GNOME_NATIVE_ENTRY identity=nonroot-exact groups=empty capabilities=empty no_new_privileges=true user_mapping=initial-exact fd_inheritance=stdio-only"
active = []
waits = []
errors = []
input_pins = {}
stage_pins = {}
baseline = None
artifact_fd = None
artifact = None
artifact_before = artifact_after = None
receipt_pin = None
fixture_identity = None
native_accepted = False
control_pins = {}
report = {"schema": "gnome-native-original-result-1", "sourceTree": TREE, "uid": UID, "gid": GID,
          "namespaceProbeAttempted": False, "namespaceProbePassed": False,
          "nativeEnvelopeAttempted": False, "nativeEntryObserved": False,
          "nativeAccepted": False, "dataTestsRun": 0, "persistent": False,
          "installedProvider": False, "gui": False, "nativeQualified": False,
          "waits": waits, "errors": errors}

class Refusal(Exception):
    pass

def need(ok, code):
    if not ok:
        raise Refusal(code)

def emit(name, value):
    print(name + "=" + json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True), flush=True)

def ident(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_uid, s.st_gid,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns]

def read_fd(fd, limit, body=False):
    before = os.fstat(fd)
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size < limit, "regular-original-bound")
    os.lseek(fd, 0, os.SEEK_SET)
    h = hashlib.sha256()
    parts = [] if body else None
    count = 0
    while True:
        value = os.read(fd, 65536)
        if not value:
            break
        count += len(value)
        need(count <= before.st_size, "original-grew")
        h.update(value)
        if body:
            parts.append(value)
    need(count == before.st_size and ident(os.fstat(fd)) == ident(before), "original-read-changed")
    return ident(before), h.hexdigest(), b"".join(parts) if body else None

def data(path, limit, body=False):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        identity, digest, raw = read_fd(fd, limit, body)
        need(identity == ident(path.lstat()), "original-name-changed")
        return identity, digest, raw
    finally:
        os.close(fd)

def original_input(row, after=False):
    identity, digest, _ = data(row["path"], (128 << 20) + 1)
    need(identity[4:6] == [0, 0] and identity[6] == row["bytes"]
         and stat.S_IMODE(identity[2]) == int(row["mode"], 8) and digest == row["sha256"], "admitted-input-mismatch")
    if after:
        need(input_pins[row["path"]] == identity, "admitted-input-identity-changed")
    else:
        need(row["path"] not in input_pins, "duplicate-input")
        input_pins[row["path"]] = identity

def pycache_empty(fd):
    scan, body_failed = None, False
    try:
        scan = os.scandir(fd)
        need(next(scan, None) is None, "pycache-not-empty")
    except BaseException:
        body_failed = True
        raise
    finally:
        if scan is not None:
            try:
                scan.close()
            except BaseException:
                errors.append("pycache-scan-close-unknown")
                if not body_failed:
                    raise Refusal("pycache-scan-close-unknown")


def pycache_namespace_check():
    need(pycache_state is not None and len(pycache_fds) == 3, "pycache-namespace-custody")
    def custody(info):
        return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid]
    def parents():
        for index, expected in enumerate(pycache_state["parents"]):
            actual = os.fstat(pycache_fds[index])
            named = (Path("/").lstat() if index == 0 else
                     os.stat("run", dir_fd=pycache_fds[0], follow_symlinks=False))
            need(stat.S_ISDIR(actual.st_mode) and actual.st_uid == actual.st_gid == 0
                 and not actual.st_mode & 0o022 and custody(actual) == expected == custody(named)
                 and os.fstatvfs(pycache_fds[index]).f_flag & os.ST_RDONLY,
                 "pycache-namespace-parent-original")
    parents()
    fd = pycache_fds[-1]
    before = os.fstat(fd)
    need(stat.S_ISDIR(before.st_mode) and before.st_uid == before.st_gid == 0
         and stat.S_IMODE(before.st_mode) == 0o555 and os.fstatvfs(fd).f_flag & os.ST_RDONLY,
         "pycache-namespace-not-readonly")
    need(ident(before) == pycache_state["identity"] ==
         ident(os.stat(PYTHON_PYCACHE.name, dir_fd=pycache_fds[1], follow_symlinks=False)),
         "pycache-namespace-leaf-original")
    pycache_empty(fd)
    need(ident(os.fstat(fd)) == pycache_state["identity"] ==
         ident(os.stat(PYTHON_PYCACHE.name, dir_fd=pycache_fds[1], follow_symlinks=False)),
         "pycache-namespace-leaf-original")
    parents()


def pycache_namespace_begin(expected):
    global pycache_state
    need(not pycache_fds and pycache_state is None and expected["path"] == str(PYTHON_PYCACHE)
         and expected["entries"] == [], "pycache-namespace-first-original")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    pycache_fds.append(fd)  # main's finally owns every partial acquisition.
    parents = []
    for part in ("run", PYTHON_PYCACHE.name):
        info = os.fstat(fd)
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
             and not info.st_mode & 0o022 and os.fstatvfs(fd).f_flag & os.ST_RDONLY,
             "pycache-namespace-protected-parent")
        parents.append([info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid])
        fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        pycache_fds.append(fd)
    # bwrap's / and /run are synthetic originals, not host ancestor inodes.
    # The narrow readonly bind MUST still expose the first host leaf itself.
    pycache_state = {"parents": parents, "identity": expected["identity"]}
    pycache_namespace_check()
    report["pythonPycacheSameLeaf"] = True


def pycache_namespace_finish():
    close_failed = False
    try:
        if pycache_state is not None:
            pycache_namespace_check()
            report["pythonPycachePostchecked"] = True
    except BaseException as error:
        errors.append("pycache-post:" + error_name(error))
    finally:
        while pycache_fds:
            fd = pycache_fds.pop()
            try:
                os.close(fd)
            except BaseException as error:
                close_failed = True
                errors.append("pycache-close-unknown:" + error_name(error))
        report["pythonPycacheHandlesClosed"] = pycache_state is not None and not close_failed


def runtime_readonly_original(row):
    fd, failed = None, False
    try:
        fd = os.open(row["path"], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        need(ident(os.fstat(fd)) == row["identity"] == ident(Path(row["path"]).lstat())
             and os.fstatvfs(fd).f_flag & os.ST_RDONLY, "controller-runtime-input-not-readonly-original")
    except BaseException:
        failed = True
        raise
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except BaseException as error:
                errors.append("controller-runtime-input-close:" + error_name(error))
                if not failed:
                    raise Refusal("controller-runtime-input-close-unknown")


def runtime_namespace_check():
    need(runtime_state is not None and len(runtime_fds) == 3, "controller-runtime-namespace-custody")
    for index, expected in enumerate(runtime_state["parents"]):
        actual = os.fstat(runtime_fds[index])
        named = Path("/").lstat() if index == 0 else os.stat("run", dir_fd=runtime_fds[0], follow_symlinks=False)
        need([actual.st_dev, actual.st_ino, actual.st_mode, actual.st_uid, actual.st_gid] == expected
             == [named.st_dev, named.st_ino, named.st_mode, named.st_uid, named.st_gid]
             and os.fstatvfs(runtime_fds[index]).f_flag & os.ST_RDONLY,
             "controller-runtime-namespace-parent-original")
    projection = runtime_state["projection"]
    need(ident(os.fstat(runtime_fds[-1])) == projection["rootIdentity"]
         == ident(os.stat(PYTHON_ROOT.name, dir_fd=runtime_fds[1], follow_symlinks=False))
         and os.fstatvfs(runtime_fds[-1]).f_flag & os.ST_RDONLY,
         "controller-runtime-namespace-root-replaced-or-writable")
    for row in projection["directories"]:
        fd, failed = None, False
        try:
            fd = os.open(row["path"], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            actual = os.fstat(fd)
            need(ident(actual) == row["identity"] == ident(Path(row["path"]).lstat())
                 and actual.st_uid == actual.st_gid == 0 and stat.S_IMODE(actual.st_mode) == 0o555
                 and os.fstatvfs(fd).f_flag & os.ST_RDONLY, "controller-runtime-namespace-directory")
            names = sorted(os.listdir(fd))
            need(len(names) <= 700 and names == row["entries"]
                 and ident(os.fstat(fd)) == row["identity"] == ident(Path(row["path"]).lstat()),
                 "controller-runtime-namespace-roster")
        except BaseException:
            failed = True
            raise
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except BaseException as error:
                    errors.append("controller-runtime-directory-close:" + error_name(error))
                    if not failed:
                        raise Refusal("controller-runtime-directory-close-unknown")
    for row in projection["files"]:
        runtime_readonly_original(row)
    # Actual narrow mounts, not merely a clean sys.path or argv assertion.
    zip_row = next(row for row in projection["files"] if row["path"] == PYTHON_SEARCH[0])
    identity, digest, _ = data("/usr/bin/python3.12", 23)
    need(identity == zip_row["identity"] and digest == zip_row["sha256"], "old-python-executable-mask-original")
    runtime_readonly_original({**zip_row, "path": "/usr/bin/python3.12"})
    need(Path("/bin").is_symlink() and os.readlink("/bin") == "usr/bin"
         and Path("/lib").is_symlink() and os.readlink("/lib") == "usr/lib"
         and Path("/usr/bin/python3").is_symlink() and os.readlink("/usr/bin/python3") == "python3.12",
         "old-python-mask-alias-text")
    for name in ("/usr/bin/python3", "/bin/python3", "/bin/python3.12"):
        need(ident(os.stat(name)) == zip_row["identity"], "old-python-alias-not-masked")
    for name in ("/usr/lib/python3.12", "/lib/python3.12"):
        need(ident(Path(name).lstat()) == pycache_state["identity"], "old-python-stdlib-mask-original")
        fd, failed = None, False
        try:
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            need(ident(os.fstat(fd)) == pycache_state["identity"]
                 and os.fstatvfs(fd).f_flag & os.ST_RDONLY, "old-python-stdlib-mask-not-readonly")
            pycache_empty(fd)
        except BaseException:
            failed = True
            raise
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except BaseException as error:
                    errors.append("old-python-mask-close:" + error_name(error))
                    if not failed:
                        raise Refusal("old-python-mask-close-unknown")
    try:
        Path("/usr/lib/python312.zip").lstat()
    except FileNotFoundError:
        pass
    else:
        raise Refusal("old-python-zip-present")


def runtime_namespace_begin(expected, originals):
    global runtime_state
    need(runtime_state is None and not runtime_fds and type(expected) is dict
         and set(expected) == {"catalogueSha256", "originals", "projection", "builtins", "searchPath"}
         and expected["catalogueSha256"] == CONTROLLER_RUNTIME_SHA256
         and expected["builtins"] == list(PYTHON_BUILTINS) and expected["searchPath"] == list(PYTHON_SEARCH),
         "controller-runtime-source-binding")
    pin = expected["originals"]
    need(control_pins["/controller-runtime-originals.json"] == (pin["identity"], pin["sha256"])
         and pin["mode"] == "0o400" and originals["schema"] == "gnome-session-controller-runtime-originals-2"
         and originals["controllerCatalogueSha256"] == CONTROLLER_RUNTIME_SHA256
         and originals["sourceSha"] == binding["sourceSha"]
         and originals["projection"] == expected["projection"]
         and originals["pythonPycache"] == binding["pythonPycache"]
         and originals["readonlyMountRequiredBeforePrivateStartup"] is True,
         "controller-runtime-original-staging")
    projection = expected["projection"]
    need(type(projection["files"]) is list and len(projection["files"]) == 598
         and type(projection["directories"]) is list and len(projection["directories"]) == 53
         and projection["bytes"] == 27303244, "controller-runtime-complete-originals")
    def relative(path):
        name = Path(path).relative_to(PYTHON_ROOT).as_posix()
        need(str(PYTHON_ROOT / name) == path and all(part not in ("", "..") for part in name.split("/")),
             "controller-runtime-original-path")
        return name
    selected = {"files": [{"path": relative(row["path"]), **{key: row[key] for key in ("bytes", "sha256", "mode")}}
                           for row in projection["files"]],
                "directories": sorted([{"path": relative(row["path"]), "mode": row["mode"], "entries": row["entries"]}
                                       for row in projection["directories"]], key=lambda row: row["path"])}
    raw = json.dumps(selected, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
    need(hashlib.sha256(raw).hexdigest() == CONTROLLER_SELECTION_SHA256,
         "controller-runtime-complete-source-projection")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    runtime_fds.append(fd)
    parents = []
    for part in ("run", PYTHON_ROOT.name):
        actual = os.fstat(fd)
        need(stat.S_ISDIR(actual.st_mode) and actual.st_uid == actual.st_gid == 0
             and not actual.st_mode & 0o022 and os.fstatvfs(fd).f_flag & os.ST_RDONLY,
             "controller-runtime-readonly-parent")
        parents.append([actual.st_dev, actual.st_ino, actual.st_mode, actual.st_uid, actual.st_gid])
        fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        runtime_fds.append(fd)
    runtime_state = {"parents": parents, "projection": projection}
    runtime_namespace_check()
    report["controllerRuntimeSameRoot"] = True
    report["oldPythonMasksChecked"] = True


def runtime_namespace_finish():
    close_failed = False
    try:
        if runtime_state is not None:
            runtime_namespace_check()
            need(report.get("controllerRuntimeInputsPrechecked") == report.get("controllerRuntimeInputsPostchecked") == 598,
                 "controller-runtime-original-accounting-incomplete")
            report["controllerRuntimePostchecked"] = True
            report["oldPythonMasksPostchecked"] = True
    except BaseException as error:
        errors.append("controller-runtime-post:" + error_name(error))
    finally:
        while runtime_fds:
            fd = runtime_fds.pop()
            try:
                os.close(fd)
            except BaseException as error:
                close_failed = True
                errors.append("controller-runtime-close-unknown:" + error_name(error))
        report["controllerRuntimeHandlesClosed"] = runtime_state is not None and not close_failed



def owner_identity():
    need(os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0) and os.getgroups() == [], "owner-identity")
    fields = {}
    for line in Path("/proc/self/status").read_text().splitlines():
        key, _, value = line.partition(":")
        need(key not in fields, "owner-status-duplicate")
        fields[key] = value.split()
    need(fields.get("Uid") == fields.get("Gid") == ["0"] * 4
         and fields.get("Groups") == [], "owner-full-credential-state")
    for key in ("CapEff", "CapPrm", "CapBnd"):
        need(len(fields.get(key, [])) == 1 and int(fields[key][0], 16) == CAPS, "owner-capability-set")
    for key in ("CapInh", "CapAmb"):
        need(fields.get(key) == ["0000000000000000"], "owner-inherited-capability")
    need(fields.get("NoNewPrivs") == ["1"], "owner-no-new-privileges")
    for name in ("uid_map", "gid_map"):
        need(Path("/proc/self/" + name).read_text().split() == ["0", "0", "4294967295"], "owner-full-identity-mapping")
    need(dict(os.environ) == OWNER_ENV and os.getcwd() == "/tmp", "owner-environment-cwd")

def network_snapshot_class():
    """One bounded outer proc snapshot; retain only a class, never admission."""
    try:
        raw = bytearray()
        # Proc is a stream, not an admitted regular file with meaningful st_size.
        # At most16KiB+1 bytes, EOF required, original FD closed before return.
        with open("/proc/self/net/dev", "rb", buffering=0) as original:
            while len(raw) <= 16384:
                chunk = original.read(16385 - len(raw))
                if not chunk:
                    break
                raw.extend(chunk)
    except Exception:
        return "unreadable"
    try:
        if len(raw) > 16384 or not raw.endswith(b"\n"):
            return "invalid"
        lines = bytes(raw).split(b"\n")[:-1]
        if len(lines) < 3 or any(len(row) >= 4096 for row in lines):
            return "invalid"
        if [part.split() for part in lines[0].split(b"|")] != [[b"Inter-"], [b"Receive"], [b"Transmit"]]:
            return "invalid"
        if [part.split() for part in lines[1].split(b"|")] != [
            [b"face"], b"bytes packets errs drop fifo frame compressed multicast".split(),
            b"bytes packets errs drop fifo colls carrier compressed".split()]:
            return "invalid"
        names = set()
        for row in lines[2:]:
            prefix, colon, counters = row.partition(b":")
            if colon != b":" or re.fullmatch(rb"[ \t]*[^\x00-\x20\x7f/:]{1,15}", prefix) is None \
                or re.fullmatch(rb"[ \t]*[0-9]+(?:[ \t]+[0-9]+){15}[ \t]*", counters) is None:
                return "invalid"
            name = prefix.lstrip(b" \t")
            if name in names:
                return "invalid"
            names.add(name)
        return "loopback-only" if names == {b"lo"} else "non-loopback"
    except Exception:
        return "invalid"

def process_rows():
    result = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        raw = (entry / "stat").read_bytes()
        need(len(raw) < 16384 and raw.startswith(entry.name.encode() + b" ("), "private-process-stat-shape")
        end = raw.rfind(b") ")
        need(end > 0, "private-process-stat-close")
        values = raw[end + 2:].split()
        need(len(values) >= 20 and values[1].isdigit() and values[19].isdigit(), "private-process-stat-fields")
        result[int(entry.name)] = [int(values[1]), int(values[19])]
    return result

def quiet(first=False):
    global baseline
    rows = process_rows()
    if first:
        ancestors = set()
        current = os.getpid()
        while current:
            need(current in rows and current not in ancestors, "private-owner-ancestry")
            ancestors.add(current)
            current = rows[current][0]
        need(set(rows) == ancestors and 1 in ancestors, "private-initial-cohort")
        baseline = rows
    else:
        need(rows == baseline, "private-cohort-not-retired")
    owner_identity()

def error_name(error):
    return str(error) if isinstance(error, Refusal) else type(error).__name__

def invoke(role, argv, cap):
    """Keep and wait both original handles, including every partial-launch path.
    The ordinary command timeout is independent of outer namespace disposal.
    Unknown descendants are never claimed joined; quiet() refuses them.
    """
    need(re.fullmatch(r"[a-z][a-z0-9-]{0,39}", role) is not None, "fixed-output-role")
    path = Path("/tmp/" + role + ".log")
    fd = None
    original = reader = None
    row = {"role": role, "originalEnvelopeExit": None, "originalReaderExit": None,
           "readerTimedOut": False, "cleanupErrors": []}
    waits.append(row)
    operation_error = None
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        original = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, cwd="/tmp", env=ENV, close_fds=True)
        active.append(original)
        row["originalEnvelopePid"] = original.pid
        reader = subprocess.Popen(DROP + ["/usr/bin/head", "-c", str(cap)], stdin=original.stdout,
                                  stdout=fd, stderr=None, cwd="/tmp", env=ENV, close_fds=True)
        active.append(reader)
        row["originalReaderPid"] = reader.pid
        original.stdout.close()
        os.close(fd)
        fd = None
        row["originalEnvelopeExit"] = original.wait()
        try:
            row["originalReaderExit"] = reader.wait(timeout=10)
        except subprocess.TimeoutExpired:
            row["readerTimedOut"] = True
    except Exception as error:
        operation_error = error_name(error)
        row["operationError"] = operation_error
    finally:
        # No one failed close, signal, or wait is allowed to skip the other
        # retained original. Popen only addresses these exact unreaped children.
        for resource in ([original.stdout] if original is not None and original.stdout is not None else []):
            try:
                resource.close()
            except Exception as error:
                row["cleanupErrors"].append("pipe-close:" + error_name(error))
        if fd is not None:
            try:
                os.close(fd)
            except Exception as error:
                row["cleanupErrors"].append("log-close:" + error_name(error))
        for child, key in ((original, "originalEnvelopeExit"), (reader, "originalReaderExit")):
            if child is None:
                continue
            if child.returncode is None:
                try:
                    child.kill()
                except Exception as error:
                    row["cleanupErrors"].append(key + "-stop:" + error_name(error))
            try:
                row[key] = child.wait(timeout=5)
            except Exception as error:
                row["cleanupErrors"].append(key + "-wait:" + error_name(error))
            if child.returncode is not None and child in active:
                active.remove(child)
    raw = b""
    try:
        identity, digest, raw = data(path, cap + 1, True)
        row.update(logBytes=identity[6], logSha256=digest)
        need(identity[4:6] == [0, 0] and stat.S_IMODE(identity[2]) == 0o600
             and identity[6] < cap, "output-saturated-or-permission")
    except Exception as error:
        row["logError"] = error_name(error)
    emit("GNOME_NATIVE_ORIGINAL_WAIT", row)
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()
    if raw and not raw.endswith(b"\n"):
        print("", flush=True)
    need(operation_error is None and not row["cleanupErrors"] and "logError" not in row,
         "original-" + role + "-lifecycle-failed")
    need(row["originalReaderExit"] == 0 and not row["readerTimedOut"], "original-reader-failed")
    need(type(row["originalEnvelopeExit"]) is int, "original-envelope-unwaited")
    return row["originalEnvelopeExit"], raw

def run_ok(role, argv, cap):
    code, raw = invoke(role, argv, cap)
    need(code == 0, "original-" + role + "-failed")
    return raw

def write_new(path, raw, mode):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as out:
            out.write(raw)
            out.flush()
            os.fsync(fd)
        os.fchmod(fd, mode)
    finally:
        os.close(fd)
    identity, digest, _ = data(path, (128 << 20) + 1)
    need(identity[4:6] == [0, 0] and identity[6] == len(raw) and digest == hashlib.sha256(raw).hexdigest(), "private-stage-write")
    stage_pins[str(path)] = (identity, digest)
    return path

def stage_packages(layout):
    STAGE.mkdir(mode=0o700)
    result = []
    for ordinal, row in enumerate(layout["stagedPackageMembers"]):
        identity, digest, raw = data(row["sourceTar"], 4 << 20, True)
        need(identity[4:6] == [0, 0] and stat.S_IMODE(identity[2]) == 0o600
             and identity[6] == row["tarBytes"] and digest == row["tarSha256"], "package-tar-pin")
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            members = archive.getmembers()
            need(len(members) <= 256, "package-member-count")
            selected = [m for m in members if m.name.removeprefix("./") == row["member"]]
            need(len(selected) == 1 and selected[0].isreg() and selected[0].size == row["bytes"], "package-member-shape")
            stream = archive.extractfile(selected[0])
            need(stream is not None, "package-member-stream")
            with stream:
                body = stream.read(row["bytes"] + 1)
            need(len(body) == row["bytes"] and hashlib.sha256(body).hexdigest() == row["sha256"], "package-member-hash")
        output = write_new(STAGE / ("package-" + str(ordinal)), body, int(row["stagedMode"], 8))
        result.append((str(output), row["nativeDestination"]))
    for name, content in (("passwd", "mrk-gnome-fixture:x:61000:61000:MRK GNOME fixture:/mrk-gnome-fixture/home:/nonexistent\n"),
                          ("group", "mrk-gnome-fixture:x:61000:\n"),
                          ("nsswitch.conf", "passwd: files\ngroup: files\nhosts: files\n"),
                          ("hosts", ""), ("machine-id", "11111111111111111111111111111111\n")):
        output = write_new(STAGE / name, content.encode("ascii"), 0o444)
        result.append((str(output), "/etc/" + name))
    return result

def fixture_layout():
    global fixture_identity
    need(ROOT.is_dir() and not ROOT.is_symlink() and list(ROOT.iterdir()) == [], "fresh-fixture-backing")
    fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        root = os.fstat(fd)
        need(root.st_uid == root.st_gid == 0 and root.st_dev != Path("/tmp").stat().st_dev, "separate-owned-fixture-tmpfs")
        for name in ("home", "run", "data", "config", "control-1", "control-2"):
            os.mkdir(name, mode=0o700, dir_fd=fd)
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            try:
                os.fchmod(child, 0o700)
                os.fchown(child, UID, GID)
                s = os.fstat(child)
                need(s.st_uid == UID and s.st_gid == GID and stat.S_IMODE(s.st_mode) == 0o700, "fixture-child-identity")
            finally:
                os.close(child)
        os.fchmod(fd, 0o700)
        os.fchown(fd, UID, GID)
        root = os.fstat(fd)
        need(root.st_uid == UID and root.st_gid == GID and stat.S_IMODE(root.st_mode) == 0o700, "fixture-root-identity")
        fixture_identity = [root.st_dev, root.st_ino, root.st_uid, root.st_gid, stat.S_IMODE(root.st_mode)]
    finally:
        os.close(fd)

def select_artifact(layout):
    global artifact_fd, artifact, artifact_before, artifact_after, receipt_pin
    identity, digest, raw = data("/tmp/artifact.json", 16384, True)
    need(identity[4:6] == [0, 0] and stat.S_IMODE(identity[2]) == 0o600, "compiler-receipt-owner-mode")
    receipt_pin = (identity, digest)
    receipt = json.loads(raw)
    need(receipt["scope"] == "gnome-transport-libtest-headless-compile-only"
         and receipt["phase"] == "libtest" and receipt["features"] == []
         and receipt["prospectiveTree"] == TREE and receipt["completeSourceFiles"] == binding["completeSourceFiles"]
         and receipt["productTree"] == PRODUCT_TREE and receipt["productFiles"] == 964
         and receipt["sourceIndexSha256"] == SOURCE_INDEX
         and receipt["sourceBindingSha256"] == control_pins["/source-binding.json"][1]
         and receipt["originalIndexStageSha256"] == binding["gitIndexSha256"]
         and receipt["testSupportEnabled"] is True and receipt["nativeQualified"] is False
         and receipt["artifactExecuted"] is False, "compiler-receipt-source")
    artifact = receipt["artifact"]
    need(re.fullmatch(r"/tmp/target/x86_64-unknown-linux-gnu/debug/deps/mobile_release_desktop-[0-9a-f]{16}", artifact["path"]) is not None, "compiler-artifact-path")
    artifact_fd = os.open(artifact["path"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    artifact_before, digest, _ = read_fd(artifact_fd, 128 << 20)
    need(artifact_before == artifact["identity"] == ident(Path(artifact["path"]).lstat())
         and artifact_before[4:6] == [0, 0] and artifact_before[6] == artifact["bytes"]
         and digest == artifact["sha256"] and artifact_before[2] & 0o111, "compiler-artifact-original")
    elf = run_ok("artifact-elf", ["/usr/bin/timeout", "--signal=TERM", "--kill-after=2s", "15s"] + DROP
                 + ["/usr/bin/x86_64-linux-gnu-readelf", "--wide", "--file-header", "--program-headers", "--dynamic", artifact["path"]], 65536)
    text = elf.decode("utf-8", "strict")
    need(text.startswith("ELF Header:") and re.search(r"Class:\s+ELF64\b", text)
         and re.search(r"Data:\s+2's complement, little endian\b", text)
         and re.search(r"Machine:\s+Advanced Micro Devices X86-64\b", text)
         and re.search(r"Type:\s+DYN\b", text) and not re.search(r"(?m)^readelf:", text), "artifact-elf-shape")
    need(re.findall(r"Requesting program interpreter: ([^\]]+)\]", text) == ["/lib64/ld-linux-x86-64.so.2"]
         and "(RPATH)" not in text and "(RUNPATH)" not in text, "artifact-loader-path")
    needed = re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", text)
    admitted = {r["soname"] for r in layout["installedFileMounts"] if r.get("soname")}
    admitted |= {"libgck-1.so.0", "libgcr-base-3.so.1"}
    need(needed and len(needed) == len(set(needed)) and set(needed) <= admitted, "artifact-needed-closure")
    quiet()
    os.fchmod(artifact_fd, 0o555)
    artifact_after, digest, _ = read_fd(artifact_fd, 128 << 20)
    need(digest == artifact["sha256"] and artifact_after[4:6] == [0, 0]
         and stat.S_IMODE(artifact_after[2]) == 0o555
         and all(artifact_before[i] == artifact_after[i] for i in (0, 1, 3, 4, 5, 6, 7))
         and artifact_after == ident(Path(artifact["path"]).lstat()), "artifact-mode-transition")
    report["artifact"] = {"sha256": digest, "bytes": artifact["bytes"], "before": artifact_before,
                          "afterModeTransition": artifact_after, "needed": needed, "sameInode": True,
                          "copiedOrExported": False}

def native_args(layout, staged, probe=False):
    need(type(probe) is bool, "namespace-probe-role")
    # The outer owner already has a mandatory private network namespace. Inherit
    # that isolated network; do not ask this NET_ADMIN-free child to recreate it.
    args = ["/usr/bin/timeout", "--signal=TERM",
            "--kill-after=2s" if probe else "--kill-after=10s", "15s" if probe else "120s",
            "/usr/bin/bwrap", "--unshare-pid", "--die-with-parent",
            "--new-session", "--clearenv"]
    # Only this synthetic inner root and fixed nonsecret runtime parents are
    # traversable by61000. Do not inherit the owner's private077 creation mask.
    # These are NOT host directory mounts, and the whole root is remounted RO.
    args += ["--chmod", "0755", "/"]
    for directory in ("/usr", "/usr/bin", "/usr/lib", "/usr/lib/x86_64-linux-gnu", "/usr/lib64", "/etc"):
        args += ["--perms", "0755", "--dir", directory]
    for row in layout["installedFileMounts"]:
        args += ["--ro-bind", row["path"], row["nativeDestination"]]
    for source, target in staged:
        args += ["--ro-bind", source, target]
    if not probe:
        args += ["--ro-bind", artifact["path"], "/mrk-libtest"]
    entry = Path("/native-entry.sh").read_text()
    tail = ("exec -c /mrk-libtest --ignored --exact --test-threads=1 --color=never "
            "--nocapture " + TEST + "\n")
    need(entry.count(tail) == 1 and entry.endswith(tail), "fixed-native-entry-tail")
    if probe:
        entry = entry[:-len(tail)] + "exit 0\n"
    for link in layout["nativeControlledSymlinks"]:
        args += ["--symlink", link["to"], link["at"]]
    args += ["--bind", str(ROOT), "/mrk-gnome-fixture", "--proc", "/proc", "--dev", "/dev",
             "--remount-ro", "/", "--remount-ro", "/dev", "--chdir", "/",
             "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "LANG", "C", "--setenv", "LC_ALL", "C",
             "--cap-drop", "ALL", "--cap-add", "CAP_SETUID", "--cap-add", "CAP_SETGID", "--cap-add", "CAP_SETPCAP",
             "--", "/usr/bin/setpriv", "--reuid=61000", "--regid=61000", "--clear-groups",
             "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs",
             "--", "/usr/bin/bash", "--noprofile", "--norc", "-c", entry,
             "mrk-gnome-native-entry"]
    return args

def native_launch(layout, staged, probe=False):
    return ["/usr/bin/bash", "--noprofile", "--norc", "-c",
            'set -euo pipefail; ulimit -v 524288; ulimit -t 60; ulimit -n 128; ulimit -c 0; ulimit -f 1024; exec "$@"',
            "mrk-native-limits"] + native_args(layout, staged, probe=probe)

def pristine_fixture():
    """The entry-only probe must not write even a file into the fresh fixture."""
    expected = ["config", "control-1", "control-2", "data", "home", "run"]
    fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        root = os.fstat(fd)
        need([root.st_dev, root.st_ino, root.st_uid, root.st_gid,
              stat.S_IMODE(root.st_mode)] == fixture_identity, "probe-fixture-root")
        need(sorted(os.listdir(fd)) == expected, "probe-fixture-members")
        result = {".": ident(root)}
        for name in expected:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            try:
                before = os.fstat(child)
                need(before.st_uid == UID and before.st_gid == GID
                     and before.st_dev == root.st_dev and stat.S_IMODE(before.st_mode) == 0o700,
                     "probe-fixture-directory")
                need(os.listdir(child) == [] and ident(os.fstat(child)) == ident(before),
                     "probe-fixture-not-pristine")
                result[name] = ident(before)
            finally:
                os.close(child)
        need(ident(os.fstat(fd)) == ident(root), "probe-fixture-root-changed")
        return result
    finally:
        os.close(fd)

def parse_native(raw):
    need(raw.endswith(b"\n") and b"\x1b" not in raw, "native-output-frame")
    lines = [line for line in raw.decode("utf-8", "strict").splitlines() if line]
    need(len(lines) >= 2 and lines.pop(0) == ENTRY and lines.pop(0) == "running 1 test", "native-entry-or-test-count")
    prefix = "test " + TEST + " ... "
    prefix_first = bool(lines and lines[0].startswith(prefix))
    if prefix_first:
        lines[0] = lines[0][len(prefix):]
        if not lines[0]:
            lines.pop(0)
    def take(expected):
        need(bool(lines) and lines.pop(0) == expected, "native-closed-sequence")
    take("MRK_GNOME_SESSION bootstrap=seed verified=true encrypted_opens=3 explicit_closes=3 local_join=true provider_child_matches=true")
    cases = ["existing", "missing", "duplicate", "stop-after-secret", "deadline-after-secret", "owner-loss", "fresh-session-absent"]
    results = ["Ok(())", "Err(MissingKey)", "Err(InvalidReply)", "Err(Interrupted)", "Err(Interrupted)", "Err(OwnerChanged)", "Err(MissingKey)"]
    readers = []
    for case, result in zip(cases, results):
        if case == "fresh-session-absent":
            take("MRK_GNOME_SESSION bootstrap=fresh verified=true encrypted_opens=0 explicit_closes=0 local_join=true provider_child_matches=true")
        polls = [1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1] if case in ("missing", "duplicate", "fresh-session-absent") else (
            [1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1] if case == "owner-loss" else [1] * 11)
        unknown = "true" if case == "owner-loss" else "false"
        candidate = "true" if case == "existing" else "false"
        start = f"MRK_GNOME_SESSION observation={case} result={result} owner_matches=true first_polls={polls} local_reader=Some("
        end = f") local_clean=true candidate_present={candidate} settled_canary={candidate} session_unknown={unknown}"
        need(bool(lines), "native-observation-missing")
        observed = re.fullmatch(re.escape(start) + r"(Returned|RequestedCancellation)" + re.escape(end), lines.pop(0))
        need(observed is not None, "native-observation-differs")
        readers.append(observed.group(1))
        take(f"MRK_GNOME_SESSION case={case} verified=true original_join=true storage_disposed=true first_polls={polls} remote_session_unknown={unknown}")
    children = []
    for ordinal in range(3):
        need(bool(lines), "native-child-result-missing")
        match = re.fullmatch(r"MRK_GNOME_SESSION child=" + str(ordinal)
                            + r" code=(None|Some\(([0-9]{1,3})\)) signal=(None|Some\(([0-9]{1,2})\)) stop_ok=true original_wait=true timely=true", lines.pop(0))
        need(match is not None, "native-child-original-differs")
        code = int(match.group(2)) if match.group(2) is not None else None
        signal = int(match.group(4)) if match.group(4) is not None else None
        need((code is None) != (signal is None) and (code is None or 0 <= code <= 255)
             and (signal is None or 1 <= signal <= 64), "native-child-status-shape")
        children.append({"ordinal": ordinal, "code": code, "signal": signal, "originalWait": True, "timely": True})
    take("MRK_GNOME_SESSION batch=7 verified=true persistent=false installed_provider=false gui=false")
    take("ok" if prefix_first else prefix + "ok")
    need(len(lines) == 1 and re.fullmatch(r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]{1,6} filtered out; finished in [0-9]{1,6}\.[0-9]{2}s", lines[0]) is not None, "native-one-original-test-summary")
    return {"cases": cases, "localReaders": readers, "children": children, "actualLibtestPassed": 1,
            "sessionTransportOnly": True, "persistent": False, "installedProvider": False, "gui": False}

def fixture_post(success):
    root = ROOT.lstat()
    need([root.st_dev, root.st_ino, root.st_uid, root.st_gid, stat.S_IMODE(root.st_mode)] == fixture_identity, "fixture-root-post")
    counts = {"directories": 0, "regular": 0, "sockets": 0, "regularBytes": 0}
    pending = [(ROOT, 0)]
    seen = 0
    while pending:
        directory, depth = pending.pop()
        need(depth <= 8, "fixture-depth-bound")
        for item in os.scandir(directory):
            seen += 1
            need(seen <= 128, "fixture-node-bound")
            s = item.stat(follow_symlinks=False)
            need(s.st_uid == UID and s.st_gid == GID and s.st_dev == root.st_dev
                 and stat.S_IMODE(s.st_mode) & 0o7077 == 0, "fixture-node-permission")
            if stat.S_ISDIR(s.st_mode):
                counts["directories"] += 1
                pending.append((Path(item.path), depth + 1))
            elif stat.S_ISREG(s.st_mode):
                need(s.st_nlink == 1, "fixture-regular-links")
                counts["regular"] += 1
                counts["regularBytes"] += s.st_size
            elif stat.S_ISSOCK(s.st_mode):
                counts["sockets"] += 1
            else:
                raise Refusal("fixture-unadmitted-node-kind")
    need(counts["regularBytes"] < 64 << 20, "fixture-output-total")
    diagnostics = []
    for name in ("bus.stderr", "provider-1.stderr", "provider-2.stderr"):
        p = ROOT / name
        if not p.exists() and not p.is_symlink():
            diagnostics.append({"role": name, "present": False})
            continue
        identity, digest, raw = data(p, (1 << 20) + 1, True)
        need(identity[4:6] == [UID, GID] and stat.S_IMODE(identity[2]) == 0o600 and identity[6] < 1 << 20, "fixture-stderr-shape-bound")
        item = {"role": name, "present": True, "bytes": len(raw), "sha256": digest}
        if not success and raw:
            item["escapedFailureExcerpt"] = raw[:4096].decode("utf-8", "replace")
            item["excerptBytes"] = min(len(raw), 4096)
        diagnostics.append(item)
    report["fixtureOutput"] = counts
    report["diagnostics"] = diagnostics
    emit("GNOME_NATIVE_FIXTURE_DIAGNOSTICS", diagnostics)

def main():
    global native_accepted, artifact_fd, binding, SOURCE_INDEX, TREE
    admitted = False
    rows = []
    python_rows = []
    try:
        need(len(sys.argv) == 1 and sys.executable == PYTHON_EXECUTABLE and sys.version_info[:3] == (3, 14, 7)
             and tuple(sys.path) == PYTHON_SEARCH and tuple(sorted(sys.builtin_module_names)) == PYTHON_BUILTINS
             and sys.prefix == sys.base_prefix == sys.exec_prefix == sys.base_exec_prefix == str(PYTHON_ROOT / "python")
             and sys.implementation.cache_tag == "cpython-314" and sys.flags.optimize == 0
             and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
             and type(sys.pycache_prefix) is str and sys.pycache_prefix == str(PYTHON_PYCACHE),
             "isolated-owner-entry")
        owner_identity()
        quiet(first=True)
        controls = {}
        for name in ("/source-binding.json", "/account-reservation.json", "/runtime-layout.json", "/runtime-inputs.json",
                     "/controller-runtime-originals.json"):
            identity, digest, raw = data(name, 1 << 20, True)
            need(identity[4:6] == [0, 0] and stat.S_IMODE(identity[2]) == 0o400, "control-owner-mode")
            control_pins[name] = (identity, digest)
            controls[name] = json.loads(raw)
        binding = controls["/source-binding.json"]
        need(binding["schema"] == "gnome-session-source-binding-1"
             and re.fullmatch(r"[0-9a-f]{40}", binding["sourceSha"]) is not None
             and binding["sourceSha"] != "0" * 40
             and re.fullmatch(r"[0-9a-f]{40}", binding["fullTree"]) is not None
             and binding["productTree"] == PRODUCT_TREE and binding["productFiles"] == 964
             and 964 < binding["completeSourceFiles"] <= 1024
             and len(binding["sourceFiles"]) == binding["completeSourceFiles"], "hosted-source-binding")
        pycache_namespace_begin(binding["pythonPycache"])
        runtime_namespace_begin(binding["controllerRuntime"], controls["/controller-runtime-originals.json"])
        python_rows = binding["controllerRuntime"]["projection"]["files"]
        admitted = True
        SOURCE_INDEX, TREE = binding["sourceIndexSha256"], binding["fullTree"]
        reservation = controls["/account-reservation.json"]
        need(reservation["schema"] == "gnome-session-host-reservation-1"
             and reservation["sourceBindingSha256"] == control_pins["/source-binding.json"][1]
             and reservation["uid"] == UID and reservation["gid"] == GID
             and reservation["hostAccountCreated"] is True
             and reservation["phases"] == ["before-creation", "after-creation", "before-owner"]
             and reservation["reservation"] == "positive-static-files-and-systemd"
             and reservation["disposition"] == "retained-until-disposable-vm-retirement",
             "hosted-positive-reservation")
        report.update(sourceTree=TREE, sourceSha=binding["sourceSha"],
                      completeSourceFiles=binding["completeSourceFiles"], productTree=PRODUCT_TREE,
                      productFiles=964, sourceBindingSha256=control_pins["/source-binding.json"][1],
                      hostAccountCreated=True, hostReservationChecked=True)
        layout = controls["/runtime-layout.json"]
        rows = controls["/runtime-inputs.json"]
        need(type(rows) is list and 31 <= len(rows) <= 64, "runtime-input-count")
        need(layout["credentials"]["actualNonzeroUid"] == UID
             and layout["credentials"]["actualNonzeroGid"] == GID
             and layout["nativeSelector"] == TEST
             and len(layout["installedFileMounts"]) == 31
             and len(layout["stagedPackageMembers"]) == 3, "fixed-runtime-layout")
        for row in rows:
            original_input(row)
        emit("GNOME_NATIVE_RUNTIME_INPUT_PRE", {"matched": len(rows)})
        report["runtimeInputsPrechecked"] = len(rows)
        for row in python_rows:
            original_input(row)
            need(input_pins[row["path"]] == row["identity"], "controller-runtime-first-original-differs")
            runtime_readonly_original(row)
        report["controllerRuntimeInputsPrechecked"] = len(python_rows)
        report["controllerRuntimeInputsExpected"] = len(python_rows)
        staged = stage_packages(layout)
        fixture_layout()
        pristine = pristine_fixture()
        quiet()
        report["namespaceProbeAttempted"] = True
        outer_network_class = network_snapshot_class()
        code, raw = invoke("namespace-probe", native_launch(layout, staged, probe=True), 65536)
        if code != 0 or raw != (ENTRY + "\n").encode("ascii"):
            try:
                emit("GNOME_NATIVE_NETWORK_SNAPSHOT", {"outerClass": outer_network_class})
            except Exception:
                pass  # Diagnostics cannot replace the original smoke refusal.
        quiet()
        need(pristine_fixture() == pristine, "probe-fixture-changed")
        need(code == 0 and raw == (ENTRY + "\n").encode("ascii"), "namespace-entry-probe-failed")
        report["namespaceProbePassed"] = True
        # Entry-only smoke is not libtest/provider execution or qualification.
        code, _ = invoke("compile", ["/usr/bin/timeout", "--signal=TERM", "--kill-after=10s", "540s"] + DROP
                         + ["/usr/bin/bash", "--noprofile", "--norc", "/compile-only.sh"], 4 << 20)
        quiet()
        need(code == 0, "fresh-headless-compile-failed")
        select_artifact(layout)
        quiet()
        # Staging precedes the smoke/compile. The EUID0 compiler has no caps,
        # but owns these staged files: reauthenticate after its entire cohort
        # retires, BEFORE the native loader can consume any staged runtime.
        for path, (identity, digest) in stage_pins.items():
            actual, current, _ = data(path, (128 << 20) + 1)
            need(actual == identity and current == digest, "staged-original-before-native-changed")
        report["stagedInputsPreNativeChecked"] = len(stage_pins)
        # This means the fixed envelope is about to be attempted, not that a
        # libtest/provider ran. Entry and complete success require actual output.
        report["nativeEnvelopeAttempted"] = True
        code, raw = invoke("native", native_launch(layout, staged), 1 << 20)
        report["nativeEntryObserved"] = raw.startswith((ENTRY + "\n").encode("ascii"))
        quiet()
        report["nestedNamespaceRetired"] = True
        need(code == 0, "original-native-envelope-failed")
        report["nativeEvidence"] = parse_native(raw)
        native_accepted = True
    except Exception as error:
        errors.append("operation:" + error_name(error))
    finally:
        try:
            # The outer launcher independently retires its namespace even if entry
            # was refused. Never start extra helpers under an unadmitted identity.
            if admitted:
                cohort_quiet = False
                try:
                    quiet()
                    cohort_quiet = True
                except Exception as error:
                    errors.append("post-cohort:" + error_name(error))
                if fixture_identity is not None and cohort_quiet:
                    try:
                        fixture_post(native_accepted)
                    except Exception as error:
                        errors.append("fixture-post:" + error_name(error))
                elif fixture_identity is not None:
                    report["fixturePostSkipped"] = "owned cohort not quiet; output remains contained, not verified"
                try:
                    run_ok("source-post", ["/usr/bin/timeout", "--signal=TERM", "--kill-after=5s", "30s"] + DROP
                           + [PYTHON_EXECUTABLE, "-I", "-S", "-B", "-X",
                              "pycache_prefix=/run/mrk-gnome-python-empty-pycache-v1", "/prepare.py", "post"], 65536)
                    report["completeSourceDependencyPostchecked"] = True
                except Exception as error:
                    errors.append("source-post:" + error_name(error))
                post_count = 0
                for row in rows:
                    try:
                        original_input(row, after=True)
                        post_count += 1
                    except Exception as error:
                        errors.append("input-post:" + row.get("path", "invalid-row") + ":" + error_name(error))
                report["runtimeInputsPostchecked"] = post_count
                report["runtimeInputsExpected"] = len(rows)
                python_post_count = 0
                for row in python_rows:
                    try:
                        original_input(row, after=True)
                        runtime_readonly_original(row)
                        python_post_count += 1
                    except Exception as error:
                        errors.append("controller-runtime-input-post:" + row.get("path", "invalid-row") + ":" + error_name(error))
                report["controllerRuntimeInputsPostchecked"] = python_post_count
                report["controllerRuntimeInputsExpected"] = len(python_rows)
                for path, (identity, digest) in {**stage_pins, **control_pins}.items():
                    try:
                        actual, current, _ = data(path, (128 << 20) + 1)
                        need(actual == identity and current == digest, "staged-or-control-original-changed")
                    except Exception as error:
                        errors.append("staged-control-post:" + path + ":" + error_name(error))
                if receipt_pin is not None:
                    try:
                        identity, digest, _ = data("/tmp/artifact.json", 16384)
                        need((identity, digest) == receipt_pin, "compiler-receipt-original-changed")
                        report["artifactReceiptPostchecked"] = True
                    except Exception as error:
                        errors.append("receipt-post:" + error_name(error))
                if artifact_fd is not None:
                    try:
                        current, digest, _ = read_fd(artifact_fd, 128 << 20)
                        expected = artifact_after if artifact_after is not None else artifact_before
                        need(current == expected == ident(Path(artifact["path"]).lstat())
                             and digest == artifact["sha256"], "artifact-post-changed")
                        report["artifactPostchecked"] = True
                    except Exception as error:
                        errors.append("artifact-post:" + error_name(error))
                    finally:
                        try:
                            os.close(artifact_fd)
                        except Exception as error:
                            errors.append("artifact-close:" + error_name(error))
                        artifact_fd = None
                try:
                    quiet()
                    need(not active, "unjoined-retained-original")
                    report["outerPrivateCohortQuiet"] = True
                except Exception as error:
                    errors.append("final-cohort:" + error_name(error))
        finally:
            # Both custody chains span source-post and every postcondition.
            # The leaf is never removed/recreated, even on BaseException.
            try:
                runtime_namespace_finish()
            finally:
                pycache_namespace_finish()
    report["nativeAccepted"] = native_accepted and not errors
    report["passed"] = report["nativeAccepted"]
    report["outerNamespaceRetirementRequired"] = True
    report["hostArtifactsExported"] = False
    emit("GNOME_NATIVE_RESULT", report)
    return 0 if report["passed"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
