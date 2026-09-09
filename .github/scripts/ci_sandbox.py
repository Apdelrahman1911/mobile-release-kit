"""Small, fail-closed execution boundary for disposable GitHub-hosted CI VMs.

This is controller code, not an application API.  Never use it on a shared host.
The root controller supplies fixed commands and immutable inputs.  No receipt,
output string, discovered PID, or previous run grants process ownership.
"""

from __future__ import annotations

import dataclasses
import errno
import grp
import json
import os
from pathlib import Path
import pwd
import resource
import secrets
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time


MiB = 1024 * 1024
CAPTURE_TOTAL = 256 * MiB
DISK_RESERVE = (4 * 1024 + 512) * MiB
JAVA_LIMITS = (
    "-Xms32m -Xmx256m -XX:MaxMetaspaceSize=256m "
    "-XX:CompressedClassSpaceSize=128m -XX:ReservedCodeCacheSize=128m"
)
_ENV_KEYS = frozenset("""
PATH LANG LC_ALL TZ HOME USER LOGNAME TMPDIR TMP TEMP XDG_CONFIG_HOME
XDG_CACHE_HOME CI TERM PYTHONSAFEPATH PYTHONDONTWRITEBYTECODE PYTHONNOUSERSITE
PYTHONUTF8 PYTHONHASHSEED PIP_CONFIG_FILE PIP_NO_INDEX PIP_FIND_LINKS PIP_NO_CACHE_DIR
PIP_DISABLE_PIP_VERSION_CHECK PIP_NO_INPUT PIP_REQUIRE_VIRTUALENV PIP_CACHE_DIR
VIRTUAL_ENV GEM_HOME GEM_PATH GEM_SPEC_CACHE GEMRC BUNDLE_GEMFILE BUNDLE_PATH
BUNDLE_USER_HOME BUNDLE_USER_CACHE BUNDLE_USER_CONFIG BUNDLE_FROZEN
BUNDLE_DEPLOYMENT BUNDLE_DISABLE_SHARED_GEMS BUNDLE_IGNORE_CONFIG BUNDLE_CACHE_PATH
BUNDLE_APP_CONFIG BUNDLE_RETRY BUNDLE_VERSION
GIT_CONFIG_NOSYSTEM GIT_CONFIG_GLOBAL GIT_TERMINAL_PROMPT GIT_ATTR_NOSYSTEM
GIT_CONFIG_COUNT GIT_OPTIONAL_LOCKS
FASTLANE_SKIP_UPDATE_CHECK FASTLANE_HIDE_CHANGELOG FASTLANE_OPT_OUT_USAGE
FASTLANE_SKIP_DOCS FASTLANE_DISABLE_COLORS FASTLANE_SKIP_REPORTING
MOBILE_RELEASE_REQUIRE_RUBY_CONTRACTS MOBILE_RELEASE_TEST_PYTHON
DEVELOPER_DIR JAVA_HOME JAVA_TOOL_OPTIONS
""".split())


class SessionError(RuntimeError):
    """The attempt cannot admit another command or consume mutable outputs."""


class DeadlineExpired(SessionError):
    """The original, never renewed aggregate budget expired."""


_DIAGNOSTIC_OPERATIONS = frozenset({"process-groups-linux", "kernel-groups-library",
                                    "kernel-groups-count", "kernel-groups-fill"})


def _exception_notes(error: BaseException) -> list[dict]:
    """Bounded classes/own-source lines/errno/operation, never messages."""
    notes, pending, seen = [], [error], set()
    while pending and len(notes) < 32:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        lines, tb, inspected = [], current.__traceback__, 0
        while tb is not None and inspected < 64:
            if os.path.basename(tb.tb_frame.f_code.co_filename) == "ci_sandbox.py":
                lines.append(tb.tb_lineno)
            tb, inspected = tb.tb_next, inspected + 1
        name = type(current).__name__
        row = {"exception": name if name.isascii() and name.isidentifier() and len(name) <= 80 else "Exception",
               "lines": sorted(set(lines))[:16]}
        number = current.errno if isinstance(current, OSError) else None
        if type(number) is int and 0 < number < 4096:
            row["errno"] = number
        operation = getattr(current, "_ci_operation", None)
        if isinstance(operation, str) and operation in _DIAGNOSTIC_OPERATIONS:
            row["operation"] = operation
        observation = getattr(current, "_ci_observation", None)
        if observation is not None:
            row["observation"] = observation
        notes.append(row)
        if isinstance(current, BaseExceptionGroup):
            pending.extend(current.exceptions[:32])
        elif current.__cause__ is not None:
            pending.append(current.__cause__)
    return notes


def _child_exception_notes(data: bytes) -> list[dict]:
    """Extract only our bounded diagnostic fields; never publish stderr."""
    notes = []
    for line in data[-16384:].splitlines():
        if not line.startswith(b"MRK_SANDBOX_ERROR="):
            continue
        try:
            rows = json.loads(line[len(b"MRK_SANDBOX_ERROR="):])
        except (ValueError, UnicodeError):
            continue
        if not isinstance(rows, list):
            continue
        for row in rows[:32]:
            if not isinstance(row, dict):
                continue
            name, lines = row.get("exception"), row.get("lines")
            if (isinstance(name, str) and name.isascii() and name.isidentifier() and len(name) <= 80
                    and isinstance(lines, list) and len(lines) <= 16
                    and all(type(n) is int and 0 < n < 1_000_000 for n in lines)):
                note = {"exception": name, "lines": lines}
                number, operation = row.get("errno"), row.get("operation")
                if type(number) is int and 0 < number < 4096:
                    note["errno"] = number
                if isinstance(operation, str) and operation in _DIAGNOSTIC_OPERATIONS:
                    note["operation"] = operation
                notes.append(note)
        if len(notes) >= 32:
            break
    return notes[:32]


def _launcher_error(data: bytes, python: Path, script: Path) -> dict | None:
    """Recognize only exact CPython errors for these two admitted own paths.

    No byte-count guess, arbitrary substring, raw path, or stderr is published.
    Unknown/localized errors remain unclassified, never silently successful.
    """
    for number, message in ((errno.ENOENT, "No such file or directory"),
                            (errno.EACCES, "Permission denied")):
        expected = f"{python}: can't open file '{script}': [Errno {number}] {message}\n".encode()
        if data == expected:
            return {"code": "python-script-open", "errno": number}
    return None


@dataclasses.dataclass(frozen=True)
class CapturedRun:
    stdout: bytes
    stderr: bytes
    returncode: int | None
    waited: bool
    stdout_eof: bool
    stderr_eof: bool
    domain_finality: bool
    timed_out: bool
    cancelled: bool
    duration: float
    primary_error: str | None
    cleanup_errors: tuple[str, ...]
    persisted: tuple[int | None, int | None]

    @property
    def ok(self) -> bool:
        return (self.waited and self.returncode == 0 and self.stdout_eof
                and self.stderr_eof and self.domain_finality
                and not self.timed_out and not self.cancelled
                and self.primary_error is None and not self.cleanup_errors)

    @property
    def status(self) -> int | None:
        return self.returncode

    @property
    def finality(self) -> bool:
        return self.domain_finality


def _under(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _canonical(value: str | Path) -> Path:
    p = Path(value)
    if (not p.is_absolute() or p != p.resolve(strict=True)
            or any(not 32 <= ord(c) < 127 for c in str(p))):
        raise SessionError("noncanonical or absent controller path")
    return p


def _private_file(path: Path, data: bytes, mode: int = 0o600) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    errors = []
    try:
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            if n <= 0:
                raise SessionError("short controller-file write")
            view = view[n:]
        os.fsync(fd)
        os.fchmod(fd, mode)  # Exact immutable/public-bootstrap mode despite umask.
    except BaseException as exc:
        errors.append(exc)
    try:
        os.close(fd)
    except BaseException as exc:
        errors.append(exc)
    if errors:
        raise BaseExceptionGroup("controller file write/close failure", errors)


def _small_command(argv: list[str], seconds: float = 10.0,
                   *, user: int | None = None, group: int | None = None,
                   return_pid: bool = False, expected_code: int = 0,
                   detached: bool = True) -> bytes | tuple[bytes, int]:
    """Bounded, original-parent collection of fixed trusted OS metadata tools."""
    kwargs = {} if user is None else {"user": user, "group": group, "extra_groups": []}
    child = sel = None
    result = [bytearray(), bytearray()]
    eof, waited, code = [False, False], False, None
    cutoff = time.monotonic() + seconds
    errors = []
    try:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, close_fds=True,
                                 env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"},
                                 start_new_session=detached, **kwargs)
        sel = selectors.DefaultSelector()
        for i, stream in enumerate((child.stdout, child.stderr)):
            os.set_blocking(stream.fileno(), False)
            sel.register(stream, selectors.EVENT_READ, i)
        while sel.get_map() or child.poll() is None:
            if time.monotonic() >= cutoff:
                raise SessionError("trusted metadata deadline")
            for key, _ in sel.select(0.05):
                try:
                    chunk = os.read(key.fd, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    eof[key.data] = True
                    sel.unregister(key.fileobj)
                    continue
                result[key.data].extend(chunk)
                if sum(map(len, result)) > 2 * MiB:
                    raise SessionError("trusted metadata output limit")
        code = child.wait(timeout=max(0.01, cutoff - time.monotonic()))
        waited = True
        if code != expected_code or result[1]:
            raise SessionError("trusted metadata tool failed or emitted diagnostics")
    except BaseException as exc:
        errors.append(exc)
    try:
        # This handle has not been reaped by any other owner.  No PID-list kill.
        if child is not None:
            if child.poll() is None:
                child.kill()
            code = child.wait(timeout=2)
            waited = True
    except BaseException as exc:
        errors.append(exc)
    for owned in (sel, child.stdout if child is not None else None,
                  child.stderr if child is not None else None):
        if owned is None:
            continue
        try:
            owned.close()
        except BaseException as exc:
            errors.append(exc)
    if errors:
        failure = BaseExceptionGroup("trusted metadata invocation/cleanup failure", errors)
        failure._ci_observation = {"returncode": code, "waited": waited, "stdout_eof": eof[0],
                                   "stderr_eof": eof[1], "stdout_bytes": len(result[0]),
                                   "stderr_bytes": len(result[1]), "error_count": len(errors),
                                   "exceptions": _child_exception_notes(bytes(result[1]))}
        raise failure
    out = bytes(result[0])
    return (out, child.pid) if return_pid else out


def _nss_absent(uid: int) -> None:
    name = f"mrk-ci-{uid}"
    users, groups = pwd.getpwall(), grp.getgrall()
    if len(users) > 65536 or len(groups) > 65536:
        raise SessionError("NSS inventory limit")
    if any(p.pw_uid == uid or p.pw_gid == uid or p.pw_name == name for p in users):
        raise SessionError("NSS user/primary-group collision")
    if any(g.gr_gid == uid or g.gr_name == name for g in groups):
        raise SessionError("NSS group collision")
    for lookup, value in ((pwd.getpwuid, uid), (pwd.getpwnam, name),
                          (grp.getgrgid, uid), (grp.getgrnam, name)):
        try:
            lookup(value)
        except KeyError:
            continue
        raise SessionError("direct NSS lookup collision")


def _linux_snapshot() -> dict[tuple[int, int], tuple[tuple[int, ...], tuple[int, ...], int]]:
    """Complete bounded process AND thread credentials, including fs IDs."""
    root = Path("/proc")
    pids = sorted(int(p.name) for p in root.iterdir() if p.name.isdecimal())
    if len(pids) > 32768:
        raise SessionError("process census size")
    rows = {}
    for pid in pids:
        task = root / str(pid) / "task"
        tids = sorted(int(p.name) for p in task.iterdir() if p.name.isdecimal())
        if not tids or len(rows) + len(tids) > 131072:
            raise SessionError("thread census size")
        for tid in tids:
            base = task / str(tid)
            before = (base / "stat").read_bytes()
            raw = (base / "status").read_bytes()
            after = (base / "stat").read_bytes()
            if max(len(before), len(raw), len(after)) > 65536:
                raise SessionError("process metadata size")
            # stat field 22 is after the final ')' of the command field.
            births = [s[s.rfind(b")") + 2:].split()[19] for s in (before, after)]
            if births[0] != births[1]:
                raise SessionError("process identity changed during census")
            fields = dict(line.split(b":", 1) for line in raw.splitlines() if b":" in line)
            uids = tuple(int(v) for v in fields[b"Uid"].split())
            gids = tuple(int(v) for v in fields[b"Gid"].split())
            if len(uids) != 4 or len(gids) != 4:
                raise SessionError("incomplete process credentials")
            rows[(pid, tid)] = (uids, gids, int(births[0]))
        if tids != sorted(int(p.name) for p in task.iterdir() if p.name.isdecimal()):
            raise SessionError("thread churn during complete census")
    if pids != sorted(int(p.name) for p in root.iterdir() if p.name.isdecimal()):
        raise SessionError("process churn during complete census")
    return rows


def _mac_snapshot() -> dict[tuple[int, int], tuple[tuple[int, ...], tuple[int, ...], int]]:
    # Unsupported Darwin fields/visibility are a failure, not an invented ABI.
    raw, owned_ps = _small_command(["/bin/ps", "-axo", "pid=,ruid=,uid=,svuid=,rgid=,gid=,svgid=,rss=,stat="],
                                  return_pid=True)
    rows = {}
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) != 9 or not all(s.isdigit() for s in fields[:8]):
            raise SessionError("unsupported/incomplete Darwin process fields")
        pid, ru, eu, su, rg, eg, sg, rss = map(int, fields[:8])
        if pid < 0 or (pid, pid) in rows or not fields[8]:
            raise SessionError("duplicate/invalid Darwin process row")
        if pid == owned_ps:
            continue  # This exact trusted observer was genuinely waited above.
        rows[(pid, pid)] = ((ru, eu, su), (rg, eg, sg), rss * 1024)
    if not rows or len(rows) > 32768:
        raise SessionError("empty/oversized Darwin process census")
    return rows


def _snapshot(platform: str):
    return _linux_snapshot() if platform == "linux" else _mac_snapshot()


def _domain(platform: str, uid: int, *, collision: bool = False) -> set[int]:
    """Two full passes; no missing/truncated/unknown row is silently ignored."""
    occupied = set()
    for _ in range(2):
        for (pid, _), (uids, gids, _) in _snapshot(platform).items():
            if uid in uids or (collision and uid in gids):
                occupied.add(pid)
    return occupied


def _readonly_tree(root: Path) -> None:
    root = _canonical(root)
    for current, dirs, files in os.walk(root, followlinks=False):
        for p in (Path(current), *(Path(current) / n for n in dirs + files)):
            s = p.lstat()
            if stat.S_ISLNK(s.st_mode) or not (stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode)):
                raise SessionError("nonordinary immutable input")
            if s.st_uid != 0 or s.st_mode & 0o022:
                raise SessionError("immutable input is not root-owned/read-only to subject")


class Session:
    """One VM attempt, one reserved numeric identity, one aggregate deadline."""

    def __init__(self, platform: str, root: str | Path, *, python: str | Path,
                 ruby: str | Path, runner_home: str | Path, runner_temp: str | Path,
                 tool_prefixes: tuple[str | Path, ...] | list[str | Path], deadline: float):
        if platform not in {"linux", "darwin"} or sys.platform != platform or os.geteuid() != 0:
            raise SessionError("requires root controller on the selected disposable hosted VM")
        if not isinstance(deadline, (int, float)) or not 0 < deadline - time.monotonic() <= 3300:
            raise SessionError("invalid original aggregate deadline")
        if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
            raise SessionError("another aggregate timer already owns this process")
        self.platform, self.root, self.deadline = platform, _canonical(root), deadline
        self.python, self.ruby = _canonical(python), _canonical(ruby)
        self.runner_home, self.runner_temp = _canonical(runner_home), _canonical(runner_temp)
        self.tool_prefixes = tuple(_canonical(p) for p in tool_prefixes)
        self.source, self.inputs = self.root / "source", self.root / "inputs"
        self.work, self.control, self.bootstrap = (self.root / n for n in ("work", "control", "bootstrap"))
        self.uid = self.gid = 60000 + secrets.randbelow(5000)  # One selection; never retry/adopt.
        self.failure = None
        self.cleanup_errors: list[str] = []
        self.admitted = self.closed = self.cancelled = self._busy = False
        self._admitting = False
        self.domain_finality = False
        self.persisted_bytes = self._run_number = 0
        self.admission_results: list[dict[str, object]] = []
        self._handlers = {}
        self._timer_finished = False
        self._active: subprocess.Popen | None = None
        if self.root.parent != Path("/private/tmp" if platform == "darwin" else "/tmp"):
            raise SessionError("task root must be a fresh canonical direct child of platform tmp")
        parent_state = self.root.parent.stat()
        if parent_state.st_uid != 0 or not parent_state.st_mode & stat.S_ISVTX:
            raise SessionError("platform temporary parent lacks root-owned sticky-directory protection")
        rs = self.root.stat()
        if rs.st_uid != 0 or stat.S_IMODE(rs.st_mode) != 0o755:
            raise SessionError("task root must be root-owned0755")
        if not self.tool_prefixes or len(self.tool_prefixes) > 16:
            raise SessionError("finite trusted runtime prefixes required")
        for p in self.tool_prefixes:
            if _under(self.root, p) or _under(p, self.root) or p == Path("/"):
                raise SessionError("runtime prefix overlaps controller or mutable roots")
        for tool in (self.python, self.ruby):
            if not any(_under(tool, p) for p in self.tool_prefixes):
                raise SessionError("runtime outside admitted tool prefixes")
        # Claim the sole job-wide reservation with create-only ordinary APIs.
        self.reservation = self.root.parent / "mrk-ci-identity-reservation"
        self.reservation.mkdir(mode=0o700)
        self.reservation.chmod(0o700)
        _private_file(self.reservation / "identity.json", json.dumps({"uid": self.uid, "gid": self.gid}).encode())
        for path, mode in ((self.control, 0o700), (self.work, 0o700), (self.bootstrap, 0o755)):
            path.mkdir(mode=mode)
            path.chmod(mode)
        self.entry = self.bootstrap / "ci_sandbox.py"
        _private_file(self.entry, Path(__file__).read_bytes(), 0o444)
        _private_file(self.control / "denied", b"synthetic admission control\n")
        _private_file(self.bootstrap / "readonly", b"synthetic immutable input\n", 0o444)
        self.fixture_controls = self.root / "fixture-controls"
        self.fixture_controls.mkdir(mode=0o755)
        self.fixture_controls.chmod(0o755)
        self.outside_write = self.fixture_controls / "outside-write"
        _private_file(self.outside_write, b"not yet writable by the subject\n")
        self.policy, self.cleanup_policy = self.bootstrap / "subject.sb", self.bootstrap / "cleanup.sb"
        self.write_policy = self.bootstrap / "write-positive.sb"
        if platform == "darwin":
            self._write_policy()
        try:
            for sig in (signal.SIGALRM, signal.SIGINT, signal.SIGTERM):
                self._handlers[sig] = signal.getsignal(sig)
                signal.signal(sig, self._interrupted)
            # The timer is armed once, before data acquisition, and never renewed.
            signal.setitimer(signal.ITIMER_REAL, max(0.001, deadline - time.monotonic()))
            self._guard()
            _readonly_tree(self.source)
        except BaseException as original:
            self._fail("controller initialization failed")
            self.closed = True
            try:
                self.finish()
            except SessionError as cleanup:
                if self.cleanup_errors:
                    raise BaseExceptionGroup("controller initialization and timer cleanup failed", [original, cleanup])
            raise

    def _fail(self, reason: str) -> None:
        if self.failure is None:
            self.failure = reason

    def fail(self, reason: str) -> None:
        """Latch a controller parser/provenance failure; there is no reset API."""
        self._fail(reason)

    def _interrupted(self, signum: int, _frame) -> None:
        if signum == signal.SIGALRM:
            self._fail("original aggregate deadline expired")
            raise DeadlineExpired(self.failure)
        self.cancelled = True
        self._fail("controller cancellation")

    def _guard(self, *, allow_failure: bool = False) -> None:
        if time.monotonic() >= self.deadline:
            self._fail("original aggregate deadline expired")
        if self.closed or (self.failure and not allow_failure):
            raise SessionError(self.failure or "session already closed")

    def _write_policy(self) -> None:
        # JSON ASCII string escaping is also a valid SBPL string literal.
        q = lambda p: json.dumps(str(p), ensure_ascii=True)
        exclusions = "\n  ".join(f"(require-not (subpath {q(p)}))" for p in self.tool_prefixes)
        private = " ".join(f"(subpath {q(p)})" for p in (self.runner_home, self.runner_temp, self.control))
        common = ("(version 1)\n(allow default)\n(deny network*)\n(deny mach-lookup)\n"
                  f"(deny file-read* (require-all (require-any {private})\n  {exclusions}))\n")
        subject = (common + "(deny signal (require-not (target same-sandbox)))\n"
                   f"(deny file-write* (require-all (require-not (subpath {q(self.work)})) "
                   '(require-not (literal "/dev/null"))))\n')
        # Fixed trusted cleanup runs as U.  No same-sandbox rule prevents its
        # kernel-authorized U-only cleanup; it has no network/Mach/write role.
        cleanup = common + '(deny file-write* (require-not (literal "/dev/null")))\n'
        write_positive = (common + f"(deny file-write* (require-all (require-not (literal {q(self.outside_write)})) "
                          '(require-not (literal "/dev/null"))))\n')
        _private_file(self.policy, subject.encode(), 0o444)
        _private_file(self.cleanup_policy, cleanup.encode(), 0o444)
        _private_file(self.write_policy, write_positive.encode(), 0o444)

    def _environment(self, values: dict[str, str]) -> dict[str, str]:
        if not isinstance(values, dict) or set(values) - _ENV_KEYS:
            raise SessionError("unapproved environment key")
        if any(not isinstance(v, str) or "\0" in v or len(v) > 32768 for v in values.values()):
            raise SessionError("invalid environment value")
        fixed = {"HOME": str(self.work / "home"), "USER": f"mrk-ci-{self.uid}",
                 "LOGNAME": f"mrk-ci-{self.uid}", "TMPDIR": str(self.work / "tmp"),
                 "TMP": str(self.work / "tmp"), "TEMP": str(self.work / "tmp"),
                 "XDG_CONFIG_HOME": str(self.work / "config"), "XDG_CACHE_HOME": str(self.work / "cache"),
                 "PYTHONSAFEPATH": "1", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
                 "PIP_CONFIG_FILE": "/dev/null", "PIP_NO_INDEX": "1", "PIP_NO_INPUT": "1",
                 "PIP_NO_CACHE_DIR": "1", "GEMRC": "/dev/null", "BUNDLE_RETRY": "0",
                 "BUNDLE_VERSION": "4.0.16", "BUNDLE_DISABLE_SHARED_GEMS": "1", "BUNDLE_FROZEN": "1",
                 "PIP_DISABLE_PIP_VERSION_CHECK": "1", "GIT_CONFIG_NOSYSTEM": "1",
                 "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0", "BUNDLE_IGNORE_CONFIG": "1",
                 "GIT_ATTR_NOSYSTEM": "1", "GIT_CONFIG_COUNT": "0", "GIT_OPTIONAL_LOCKS": "0"}
        if any(k in values and values[k] != v for k, v in fixed.items()):
            raise SessionError("caller attempted to alter fixed clean-environment boundary")
        if "JAVA_TOOL_OPTIONS" in values and values["JAVA_TOOL_OPTIONS"] != JAVA_LIMITS:
            raise SessionError("only the reviewed literal JVM resource options are admitted")
        result = {"PATH": ":".join([str(self.python.parent), str(self.ruby.parent), "/usr/bin", "/bin", "/usr/sbin", "/sbin"]),
                  "LANG": "C.UTF-8" if self.platform == "linux" else "en_US.UTF-8",
                  "LC_ALL": "C.UTF-8" if self.platform == "linux" else "en_US.UTF-8", "TZ": "UTC", "CI": "true"}
        result.update(values)
        result.update(fixed)
        if "GEM_PATH" in result and ":" in result["GEM_PATH"]:
            raise SessionError("fixed Ruby caller admits one private GEM_PATH, not a search list")
        for key in ("VIRTUAL_ENV", "PIP_CACHE_DIR", "GEM_HOME", "GEM_PATH", "GEM_SPEC_CACHE",
                    "BUNDLE_PATH", "BUNDLE_APP_CONFIG", "BUNDLE_USER_HOME", "BUNDLE_USER_CACHE",
                    "BUNDLE_USER_CONFIG", "MOBILE_RELEASE_TEST_PYTHON"):
            if key in result and (not Path(result[key]).is_absolute() or ".." in Path(result[key]).parts
                                  or not _under(Path(result[key]), self.work)):
                raise SessionError("mutable environment path outside private work")
        for key, wanted in (("PIP_FIND_LINKS", self.inputs / "python"),
                            ("BUNDLE_CACHE_PATH", self.inputs / "gems"),
                            ("BUNDLE_GEMFILE", self.source / "Gemfile")):
            if key in result and result[key] != str(wanted):
                raise SessionError("offline input environment path differs from immutable input")
        for component in result["PATH"].split(":"):
            p = Path(component)
            if not p.is_absolute() or ".." in p.parts or not any(
                _under(p, x) for x in (*self.tool_prefixes, self.work, Path("/usr"), Path("/bin"), Path("/sbin"))
            ):
                raise SessionError("untrusted executable PATH component")
        return result

    def _argv(self, argv: list[str], cpu: int) -> tuple[list[str], dict]:
        entry = [str(self.python), "-I", "-S", "-B", str(self.entry), "--enter", self.platform,
                 str(self.uid), str(self.gid), str(cpu), str(self.policy), *argv]
        if self.platform == "darwin":
            return entry, {"user": self.uid, "group": self.gid, "extra_groups": []}
        cmd = ["/usr/bin/bwrap", "--unshare-pid", "--unshare-net", "--unshare-ipc", "--unshare-uts",
               "--die-with-parent", "--new-session", "--cap-drop", "ALL",
               "--cap-add", "CAP_SETUID", "--cap-add", "CAP_SETGID", "--cap-add", "CAP_SETPCAP"]
        mounted = []
        for p in [Path(n) for n in ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt", "/etc") if Path(n).exists()]:
            if _under(self.root, p) or any(_under(q, p) for q in (self.runner_home, self.runner_temp, self.control)):
                raise SessionError("broad OS bind would expose a private controller root")
            cmd += ["--ro-bind", str(p), str(p)]
            mounted.append(p)
        cmd += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/run", "--tmpfs", "/tmp",
                "--dir", "/dev/shm", "--tmpfs", "/dev/shm"]
        # bubblewrap0.9 bind operations can auto-create ancestors0700.  This is
        # an empty namespace-local directory, NOT a bind of the owner task root;
        # its control/fixture directories remain absent from the subject view.
        cmd += ["--perms", "0755", "--dir", str(self.root)]
        for p in (*self.tool_prefixes, self.source, self.inputs, self.bootstrap):
            if not any(_under(p, existing) for existing in mounted):
                cmd += ["--ro-bind", str(p), str(p)]
                mounted.append(p)
        cmd += ["--bind", str(self.work), str(self.work),
                "--", "/usr/bin/setpriv", "--reuid", str(self.uid), "--regid", str(self.gid),
                "--clear-groups", "--no-new-privs", "--inh-caps=-all", "--ambient-caps=-all",
                "--bounding-set=-all", "--", *entry]
        return cmd, {}

    def _headroom(self) -> None:
        info = os.statvfs(self.root)
        if info.f_bavail * info.f_frsize < DISK_RESERVE:
            raise SessionError("private verification disk headroom exhausted")

    def ensure_idle(self) -> None:
        """Required BEFORE any copy/hash/chmod/delete of task-produced paths."""
        self._guard()
        if self._busy or self._active is not None:
            self._fail("attempted mutable-output access while a producer is owned")
            raise SessionError(self.failure)
        try:
            if _domain(self.platform, self.uid):
                raise SessionError("reserved identity still has a process or zombie")
            self.domain_finality = True
        except BaseException:
            self.domain_finality = False
            self._fail("reserved-identity finality is unknown or false")
            raise
        self._headroom()

    def _cleanup(self) -> list[str]:
        errors = []
        if self.platform == "darwin":
            try:
                # Trusted immutable helper; no project argv/code or root PID kill.
                data = _small_command([str(self.python), "-I", "-S", "-B", str(self.entry),
                                       "--enter", "darwin", str(self.uid), str(self.gid), "10",
                                       str(self.cleanup_policy), str(self.python), "-I", "-S", "-B",
                                       str(self.entry), "--cleanup", str(self.uid)],
                                      6, user=self.uid, group=self.gid)
                if data != b"MRK_CLEANUP_COMPLETE\n":
                    errors.append("trusted numerical cleanup did not complete")
            except BaseException as exc:
                errors.append(f"numerical cleanup {type(exc).__name__}")
        return errors

    def run(self, argv: list[str], *, cwd: str | Path, env: dict[str, str], seconds: float,
            output_limit: int = 8 * MiB, cpu_seconds: int = 180) -> CapturedRun:
        self._guard()
        if not self.admitted:
            raise SessionError("native admission has not completed")
        return self._run(argv, cwd=cwd, env=env, seconds=seconds,
                         output_limit=output_limit, cpu_seconds=cpu_seconds, latch=True)

    def _run(self, argv: list[str], *, cwd: str | Path, env: dict[str, str], seconds: float,
             output_limit: int = 8 * MiB, cpu_seconds: int = 180, latch: bool,
             cancel_after: float | None = None) -> CapturedRun:
        self._guard()
        if self._busy or not isinstance(argv, list) or not argv or not Path(argv[0]).is_absolute():
            raise SessionError("invalid/reentrant fixed command")
        if any(not isinstance(a, str) or "\0" in a for a in argv):
            raise SessionError("invalid fixed command argument")
        cwd = _canonical(cwd)
        if not (_under(cwd, self.work) or _under(cwd, self.source)):
            raise SessionError("command cwd outside source/private work")
        if not 0 < seconds <= 3300 or not 0 < output_limit <= 16 * MiB or not 0 < cpu_seconds <= 300:
            raise SessionError("unbounded command resource request")
        child_env = self._environment(env)
        command, kwargs = self._argv(argv, cpu_seconds)
        self.ensure_idle()
        self._headroom()
        self._busy = True
        self.domain_finality = False
        self._run_number += 1
        start, failure, errors = time.monotonic(), None, []
        cutoff = min(self.deadline, start + seconds)
        outputs, fds, paths, eof, persisted = [bytearray(), bytearray()], [], [], [False, False], [0, 0]
        overflowed = [False, False]
        code = None
        waited = timed_out = cancelled = finality = False
        child = None
        sel = None
        stop_at = None
        terminate_sent = kill_sent = cleanup_done = False
        last_monitor = start

        def fail(message: str) -> None:
            nonlocal failure, stop_at
            if failure is None:
                failure, stop_at = message, time.monotonic()
                if latch:
                    self._fail(message)
            else:
                errors.append(message)

        try:
            sel = selectors.DefaultSelector()
            for suffix in ("stdout", "stderr"):
                p = self.control / f"run-{self._run_number:04d}.{suffix}"
                paths.append(p)
                fds.append(os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600))
            child = subprocess.Popen(command, cwd=cwd, env=child_env, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     close_fds=True, start_new_session=True, **kwargs)
            self._active = child
            for i, stream in enumerate((child.stdout, child.stderr)):
                os.set_blocking(stream.fileno(), False)
                sel.register(stream, selectors.EVENT_READ, i)
            while True:
                now = time.monotonic()
                # A nonzero original wait is latched BEFORE waiting for pipe EOF.
                code = child.poll()
                if code is not None:
                    waited = True
                    if code != 0 and failure is None:
                        fail(f"command exited {code}")
                if now >= cutoff and failure is None:
                    timed_out = True
                    fail("command/original aggregate deadline expired")
                if (self.cancelled or (cancel_after is not None and now - start >= cancel_after)) and failure is None:
                    cancelled = True
                    fail("command cancellation")
                if failure is not None:
                    if code is None and not terminate_sent:
                        child.terminate()
                        terminate_sent = True
                    if code is None and now - stop_at >= 1 and not kill_sent:
                        child.kill()
                        kill_sent = True
                    if code is not None and not cleanup_done:
                        errors.extend(self._cleanup())
                        cleanup_done = True
                    if now - stop_at >= 8:
                        if not all(eof):
                            errors.append("stream EOF unavailable at bounded cleanup cutoff")
                        break
                if code is not None and all(eof):
                    break
                if now - last_monitor >= 0.5 and failure is None:
                    self._headroom()
                    if self.platform == "darwin" and any(
                        self.uid in uids and rss > 2 * 1024 * MiB
                        for uids, _gids, rss in _mac_snapshot().values()
                    ):
                        fail("subject per-process RSS limit exceeded")
                    last_monitor = now
                for key, _ in sel.select(0.05):
                    i = key.data
                    try:
                        size = 65536 if overflowed[i] else min(65536, output_limit - len(outputs[i]) + 1)
                        data = os.read(key.fd, size)
                    except BlockingIOError:
                        continue
                    if not data:
                        eof[i] = True
                        sel.unregister(key.fileobj)
                        continue
                    if overflowed[i]:
                        continue  # Drain bounded failed output to genuine EOF, never persist more.
                    allowed = min(len(data), output_limit - len(outputs[i]), CAPTURE_TOTAL - self.persisted_bytes)
                    piece = data[:max(0, allowed)]
                    outputs[i].extend(piece)
                    view = memoryview(piece)
                    while view:
                        count = os.write(fds[i], view)
                        if count <= 0:
                            raise SessionError("capture write made no progress")
                        persisted[i] += count
                        self.persisted_bytes += count
                        view = view[count:]
                    if allowed != len(data):
                        fail("per-stream or whole-attempt persisted-output limit")
                        overflowed[i] = True
        except BaseException as exc:
            if isinstance(exc, DeadlineExpired):
                timed_out = True
            if isinstance(exc, KeyboardInterrupt):
                cancelled = True
            if getattr(self, "_admitting", False):
                self.admission_results.append({"name": "collector-exception", "ok": False,
                                               "exceptions": _exception_notes(exc)})
            fail(f"collection {type(exc).__name__}")
        finally:
            if child is not None:
                try:
                    if child.poll() is None:
                        child.kill()  # Still-owned original Popen only.
                    code = child.wait(timeout=2)
                    waited = True
                except BaseException as exc:
                    errors.append(f"original child wait {type(exc).__name__}")
                if failure is not None and not cleanup_done:
                    errors.extend(self._cleanup())
                for stream in (child.stdout, child.stderr):
                    try:
                        stream.close()
                    except BaseException as exc:
                        errors.append(f"stream close {type(exc).__name__}")
            try:
                if sel is not None:
                    sel.close()
            except BaseException as exc:
                errors.append(f"selector close {type(exc).__name__}")
            for i, fd in enumerate(fds):
                try:
                    os.fsync(fd)
                except BaseException as exc:
                    errors.append(f"capture fsync {type(exc).__name__}")
                try:
                    actual = os.fstat(fd).st_size
                    # Diagnostic length is actual persisted state, not a forged
                    # successful-write count after an interrupted system call.
                    self.persisted_bytes += actual - persisted[i]
                    persisted[i] = actual
                    if actual != len(outputs[i]):
                        errors.append("capture persisted length differs from returned bytes")
                except BaseException as exc:
                    persisted[i] = None
                    errors.append(f"capture persist {type(exc).__name__}")
                try:
                    os.close(fd)
                except BaseException as exc:
                    errors.append(f"capture close {type(exc).__name__}")
            self._active = child if child is not None and not waited else None
            self._busy = False
            try:
                finality = waited and not _domain(self.platform, self.uid)
                self.domain_finality = finality
                if not finality:
                    errors.append("reserved identity did not reach finality")
            except BaseException as exc:
                self.domain_finality = False
                errors.append(f"reserved identity census {type(exc).__name__}")
            if self.cancelled:
                cancelled = True
                fail("late controller cancellation")
            if time.monotonic() >= cutoff and failure is None:
                timed_out = True
                fail("finality exceeded original command cutoff")
            if not waited or not all(eof):
                fail("original wait or complete stream EOF missing")
            if errors and failure is None:
                fail("late capture/cleanup/finality error")
            if latch and failure is not None:
                self._fail(failure)
                self.cleanup_errors.extend(errors)
        return CapturedRun(bytes(outputs[0]), bytes(outputs[1]), code, waited, *eof,
                           finality, timed_out, cancelled, time.monotonic() - start,
                           failure, tuple(errors), tuple(persisted))

    def admit(self) -> None:
        self._guard()
        if self.admitted or self._busy:
            raise SessionError("duplicate/reentrant native admission")
        self._admitting = True
        try:
            _readonly_tree(self.source)
            _readonly_tree(self.inputs)
            self._headroom()
            raw = _small_command([str(self.python), "-I", "-S", "-B", str(self.entry), "--nss", str(self.uid)])
            if raw != b"MRK_NSS_ABSENT\n" or _domain(self.platform, self.uid, collision=True):
                raise SessionError("numeric identity collision or incomplete admission")
            os.chown(self.work, self.uid, self.gid)
            for name in ("home", "tmp", "config", "cache"):
                p = self.work / name
                p.mkdir(mode=0o700)
                os.chown(p, self.uid, self.gid)
            self._preflight()
            self.ensure_idle()
            self.admitted = True
        except BaseException as exc:
            self.admission_results.append({"name": "native-admission-failure", "ok": False,
                                           "exceptions": _exception_notes(exc)})
            self._fail("native isolation admission failed; no product command permitted")
            raise
        finally:
            self._admitting = False

    def _note_capture(self, name: str, result: CapturedRun) -> dict:
        row = {"name": name, "ok": False, "subject_ok": result.ok,
               "returncode": result.returncode, "waited": result.waited,
               "stdout_eof": result.stdout_eof, "stderr_eof": result.stderr_eof,
               "domain_finality": result.domain_finality, "timed_out": result.timed_out,
               "cancelled": result.cancelled, "persisted": list(result.persisted),
               "error_count": len(result.cleanup_errors) + (result.primary_error is not None),
               "exceptions": _child_exception_notes(result.stderr)}
        launcher_error = _launcher_error(result.stderr, self.python, self.entry)
        if launcher_error is not None:
            row["launcher_error"] = launcher_error
        self.admission_results.append(row)
        return row

    def _preflight(self) -> None:
        listeners, addresses = [], []
        failures = []
        try:
            # This grant is AFTER complete numerical collision admission.  It
            # is a single synthetic UID-owned0600 file, not a group capability.
            os.chown(self.outside_write, self.uid, self.gid)
            positive = self._trusted_entry(self.write_policy, ["--write-control", str(self.outside_write)])
            out = _small_command(positive, 10, user=self.uid, group=self.gid)
            if out != b"MRK_OUTSIDE_WRITE_POSITIVE\n":
                raise SessionError("outside-policy numerical write positive failed")
            self.ensure_idle()
            if self.outside_write.read_bytes() != b"MRK_POSITIVE_WRITE\n":
                raise SessionError("outside-policy positive did not actually persist its write")
            self.admission_results.append({"name": "outside-work-write-positive", "ok": True})
            for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
                for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                    listener = socket.socket(family, kind)
                    listeners.append(listener)
                    listener.settimeout(1)
                    listener.bind((host, 0))
                    address = listener.getsockname()
                    if kind == socket.SOCK_STREAM:
                        listener.listen(8)
                    # Outside-domain positive: these exact owned endpoints work.
                    with socket.socket(family, kind) as positive:
                        positive.settimeout(1)
                        if kind == socket.SOCK_STREAM:
                            positive.connect(address)
                            accepted, _ = listener.accept()
                            accepted.close()
                        else:
                            positive.sendto(b"owned-control", address)
                            if listener.recv(64) != b"owned-control":
                                raise SessionError("outside-domain UDP control failed")
                    addresses.append((int(family), int(kind), host, address[1]))
            data = {"uid": self.uid, "gid": self.gid, "platform": self.platform,
                    "work": str(self.work), "source": str(self.source),
                    "readonly": str(self.bootstrap / "readonly"), "control": str(self.control / "denied"),
                    "outside_write": str(self.outside_write),
                    "runner_home": str(self.runner_home), "runner_temp": str(self.runner_temp),
                    "endpoints": addresses}
            if self.platform == "linux":
                data["host_net"] = os.readlink("/proc/self/ns/net")
                data["host_pid"] = os.readlink("/proc/self/ns/pid")
            base = [str(self.python), "-I", "-S", "-B", str(self.entry)]
            good = self._run([*base, "--probe", json.dumps(data)], cwd=self.work, env={}, seconds=30, latch=False)
            native_note = self._note_capture("native-isolation", good)
            if not good.ok or good.stdout != b"MRK_NATIVE_ISOLATION_OK\n":
                raise SessionError("native credentials/files/FD/network inheritance preflight failed")
            self.ensure_idle()
            # Revoke this synthetic positive grant before any product command.
            # Failed/unknown writers never reach this filesystem postcondition.
            os.chown(self.outside_write, 0, 0)
            self.outside_write.chmod(0o400)
            native_note["ok"] = True
            ruby = self._run([str(self.ruby), "-e", f"abort unless Process.uid == {self.uid} && Process.gid == {self.gid}; puts 'MRK_RUBY_NUMERIC_OK'"],
                             cwd=self.work, env={}, seconds=10, latch=False)
            ruby_note = self._note_capture("ruby-numerical-identity", ruby)
            if not ruby.ok or ruby.stdout != b"MRK_RUBY_NUMERIC_OK\n":
                raise SessionError("Ruby is incompatible with the admitted numerical identity")
            ruby_note["ok"] = True
            if self.platform == "darwin":
                self._signal_preflight()
            cases = (("positive", 0, False), ("nonzero", 7, False),
                     ("missing-footer", 0, False), ("streams", 0, False),
                     ("over-limit", None, False), ("timeout", None, True),
                     ("cancel", None, False), ("held-pipe", None, False))
            for name, expected, timeout in cases:
                result = self._run([*base, "--fixture", name], cwd=self.work, env={},
                                   seconds=0.4 if name in {"timeout", "held-pipe"} else 10,
                                   output_limit=1024, latch=False,
                                   cancel_after=0.15 if name == "cancel" else None)
                capture_note = self._note_capture(name, result)
                basic = result.waited and result.domain_finality and not result.cleanup_errors
                if expected is not None:
                    basic = basic and result.returncode == expected and result.stdout_eof and result.stderr_eof
                if name == "positive":
                    basic = basic and result.ok and result.stdout == b"PASS\n"
                elif name == "nonzero":
                    basic = basic and not result.ok and result.stdout == b"PASS\n"
                elif name == "missing-footer":
                    basic = basic and result.ok and result.stdout != b"PASS\n"
                elif name == "streams":
                    basic = basic and result.ok and result.stdout == b"out\n" and result.stderr == b"err\n"
                elif name == "over-limit":
                    basic = basic and not result.ok and "output limit" in (result.primary_error or "") and result.persisted[0] == 1024
                elif name == "timeout":
                    basic = basic and not result.ok and result.timed_out
                elif name == "cancel":
                    basic = basic and not result.ok and result.cancelled
                elif name == "held-pipe":
                    # Linux may dispose its whole PID namespace on leader exit;
                    # that is genuine outer EOF/finality, not a product cleanup claim.
                    basic = basic and (not result.ok or (self.platform == "linux" and result.stdout_eof and result.stderr_eof))
                if not basic:
                    raise SessionError(f"collector admission case failed: {name}")
                capture_note["ok"] = True
            self._owner_loss_preflight()
        except BaseException as exc:
            failures.append(exc)
        finally:
            for listener in listeners:
                try:
                    listener.close()
                except BaseException as exc:
                    failures.append(exc)
        if failures:
            raise BaseExceptionGroup("native admission and owned listener cleanup failed", failures)

    def _trusted_entry(self, policy: Path, tail: list[str]) -> list[str]:
        return [str(self.python), "-I", "-S", "-B", str(self.entry), "--enter", self.platform,
                str(self.uid), str(self.gid), "10", str(policy), str(self.python), "-I", "-S", "-B",
                str(self.entry), *tail]

    def _signal_preflight(self) -> None:
        """Only these original owned synthetic U processes are signal targets."""
        sentinel = subprocess.Popen(self._trusted_entry(self.cleanup_policy, ["--sentinel"]),
                                    cwd=self.work, env=self._environment({}), user=self.uid,
                                    group=self.gid, extra_groups=[], close_fds=True,
                                    start_new_session=True, stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        errors = []
        try:
            if _ready_line(sentinel.stdout, 5) != b"MRK_SENTINEL_READY\n":
                raise SessionError("owned outside-sandbox signal control did not become ready")
            raw = _small_command(self._trusted_entry(self.policy, ["--signal-case", str(sentinel.pid)]),
                                 10, user=self.uid, group=self.gid)
            if raw != b"MRK_SIGNAL_BOUNDARY_OK\n":
                raise SessionError("native signal boundary did not pass its actual controls")
            out, err = sentinel.communicate(b"q", timeout=2)
            # This fixed trusted sentinel emits at most these two literal lines;
            # no project output is collected using communicate().
            if sentinel.returncode != 0 or out != b"MRK_SENTINEL_CLOSED\n" or err:
                raise SessionError("outside-sandbox sentinel received a signal or failed")
        except BaseException as exc:
            errors.append(exc)
        try:
            if sentinel.poll() is None:
                sentinel.kill()
            sentinel.wait(timeout=2)
        except BaseException as exc:
            errors.append(exc)
        for stream in (sentinel.stdin, sentinel.stdout, sentinel.stderr):
            try:
                stream.close()
            except BaseException as exc:
                errors.append(exc)
        if errors:
            raise BaseExceptionGroup("native signal control/cleanup failure", errors)
        self.ensure_idle()
        self.admission_results.append({"name": "same-UID-native-signal-boundary", "ok": True})

    def _owner_loss_preflight(self) -> None:
        """A deliberately lost synthetic parent is a FAILED separate subject.

        Its child's status is never reconstructed as an original wait.  The
        outside parent genuinely waits the failed owner, then observes bounded
        platform cleanup; no unknown process identity is signalled by root.
        """
        command, kwargs = self._argv([str(self.python), "-I", "-S", "-B", str(self.entry),
                                     "--loss-subject"], 10)
        raw = _small_command([str(self.python), "-I", "-S", "-B", str(self.entry), "--loss-owner",
                              json.dumps({"command": command, "kwargs": kwargs,
                                          "cwd": str(self.work), "env": self._environment({})})],
                             10, expected_code=23)
        fields = raw.split()
        if len(fields) != 2 or fields[0] != b"MRK_OWNER_LOST" or not fields[1].isdigit():
            raise SessionError("lost-owner negative control has no genuine owner observation")
        observed_child = int(fields[1])  # Observation only; never signal authority.
        errors = self._cleanup()
        cutoff = time.monotonic() + 5
        while time.monotonic() < cutoff:
            rows = _snapshot(self.platform)
            if all(pid != observed_child for pid, _ in rows) and not _domain(self.platform, self.uid):
                break
            time.sleep(0.05)
        else:
            errors.append("lost-owner platform cleanup remained unknown or incomplete")
        if errors:
            self.cleanup_errors.extend(errors)
            raise SessionError("lost-owner native admission cleanup failed")
        self.admission_results.append({"name": "supervisor-loss", "ok": True,
                                       "subject_owner_exit": 23, "subject_child_wait": "unavailable",
                                       "outer_domain_finality": True})

    def close(self, *, keep_timer: bool = False) -> None:
        """End command/producer ownership; optionally retain publication budget."""
        if self.closed:
            if not keep_timer:
                self.finish()
            if self.failure:
                raise SessionError(self.failure)
            return
        try:
            self._guard(allow_failure=True)
            if self._active is not None or self._busy:
                self._fail("controller closed with an active producer")
                if self._active is not None:
                    try:
                        if self._active.poll() is None:
                            self._active.kill()
                        self._active.wait(timeout=2)
                        self._active = None
                    except BaseException as exc:
                        self.cleanup_errors.append(f"close original owned child {type(exc).__name__}")
            try:
                self.domain_finality = not self._busy and self._active is None and not _domain(self.platform, self.uid)
                if not self.domain_finality:
                    self.cleanup_errors.append("close did not establish reserved-identity finality")
                    self._fail("close did not establish reserved-identity finality")
            except BaseException as exc:
                self.domain_finality = False
                self.cleanup_errors.append(f"close census {type(exc).__name__}")
                self._fail("close reserved-identity census is unknown")
            # Failed/unknown state is deliberately NOT walked, deleted, adopted
            # or reset.  The reservation survives until this one VM is disposed.
        finally:
            self.closed = True
            if not keep_timer:
                self.finish()
        if self.failure:
            raise SessionError(self.failure)

    def finish(self) -> None:
        """Release owned timer/handlers once, AFTER terminal publication work.

        Each release is attempted independently; no late error or prior failure
        is cleared.  A failed close can still release these controller resources.
        """
        if not self.closed:
            self._fail("terminal close is required before releasing the original timer")
            raise SessionError(self.failure)
        if self._timer_finished:
            if self.failure:
                raise SessionError(self.failure)
            return
        self._timer_finished = True
        errors = []
        try:
            signal.setitimer(signal.ITIMER_REAL, 0)
        except BaseException as exc:
            errors.append(f"aggregate timer release {type(exc).__name__}")
        for sig, previous in self._handlers.items():
            try:
                signal.signal(sig, previous)
            except BaseException as exc:
                errors.append(f"owned signal handler restore {sig} {type(exc).__name__}")
        self.cleanup_errors.extend(errors)
        if errors:
            self._fail("original timer/handler cleanup failed")
        if time.monotonic() >= self.deadline:
            self._fail("original aggregate deadline expired")
        if self.failure:
            raise SessionError(self.failure)


def _limits(platform: str, cpu: int) -> None:
    limits = [(resource.RLIMIT_CORE, 0), (resource.RLIMIT_NOFILE, 1024),
              (resource.RLIMIT_NPROC, 256), (resource.RLIMIT_FSIZE, 512 * MiB),
              (resource.RLIMIT_CPU, cpu)]
    if platform == "linux":
        limits.append((resource.RLIMIT_AS, 4 * 1024 * MiB))
    for which, target in limits:
        _soft, hard = resource.getrlimit(which)
        if hard != resource.RLIM_INFINITY and hard < target:
            raise SessionError("provider resource ceiling is below required profile")
        resource.setrlimit(which, (target, target))
        if resource.getrlimit(which) != (target, target):
            raise SessionError("resource limit did not take effect")


def _write_control(path: Path) -> None:
    expected = Path(__file__).resolve().parent.parent / "fixture-controls" / "outside-write"
    if path != expected or os.getuid() != os.geteuid() or not 60000 <= os.geteuid() < 65000:
        raise SessionError("invalid fixed numerical write control")
    fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    errors = []
    try:
        state = os.fstat(fd)
        if (state.st_uid != os.geteuid() or state.st_nlink != 1
                or not stat.S_ISREG(state.st_mode) or stat.S_IMODE(state.st_mode) != 0o600):
            raise SessionError("synthetic outside-work write control lost its exact DAC state")
        os.ftruncate(fd, 0)
        data = b"MRK_POSITIVE_WRITE\n"
        if os.write(fd, data) != len(data):
            raise SessionError("synthetic outside-work positive write was incomplete")
        os.fsync(fd)
        if os.fstat(fd).st_size != len(data):
            raise SessionError("synthetic outside-work positive persisted length differs")
    except BaseException as exc:
        errors.append(exc)
    try:
        os.close(fd)
    except BaseException as exc:
        errors.append(exc)
    if errors:
        raise BaseExceptionGroup("synthetic write control and close failed", errors)
    print("MRK_OUTSIDE_WRITE_POSITIVE", flush=True)


def _ready_line(stream, seconds: float) -> bytes:
    """Read one bounded fixed trusted-control line; no mutable readiness file."""
    cutoff, data = time.monotonic() + seconds, bytearray()
    with selectors.DefaultSelector() as sel:
        sel.register(stream, selectors.EVENT_READ)
        while time.monotonic() < cutoff:
            if not sel.select(min(0.1, max(0, cutoff - time.monotonic()))):
                continue
            chunk = os.read(stream.fileno(), 256 - len(data))
            if not chunk:
                raise SessionError("owned control stream closed before readiness")
            data.extend(chunk)
            if b"\n" in data:
                return bytes(data)
            if len(data) == 256:
                raise SessionError("owned control line exceeds bound")
    raise SessionError("owned control readiness deadline")


def _signal_subject(target: int) -> None:
    child = subprocess.Popen([sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()),
                              "--signal-target"], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, bufsize=0)
    errors = []
    try:
        if _ready_line(child.stdout, 3) != b"MRK_SIGNAL_READY\n":
            raise SessionError("same-sandbox signal positive did not become ready")
        child.send_signal(signal.SIGUSR1)  # Own original handle, not a discovered PID.
        out, err = child.communicate(timeout=2)
        if child.returncode != 0 or out != b"MRK_SIGNAL_RECEIVED\n" or err:
            raise SessionError("same-sandbox positive signal was not actually delivered")
        try:
            os.kill(target, signal.SIGUSR1)
        except PermissionError:
            pass
        else:
            raise SessionError("signal to owned same-UID outside-sandbox sentinel was allowed")
    except BaseException as exc:
        errors.append(exc)
    try:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=2)
    except BaseException as exc:
        errors.append(exc)
    for stream in (child.stdout, child.stderr):
        try:
            stream.close()
        except BaseException as exc:
            errors.append(exc)
    if errors:
        raise BaseExceptionGroup("native signal subject/cleanup failure", errors)
    print("MRK_SIGNAL_BOUNDARY_OK", flush=True)


def _signal_target(outside: bool) -> None:
    received = []
    signal.signal(signal.SIGUSR1, lambda signum, frame: received.append(signum))
    print("MRK_SENTINEL_READY" if outside else "MRK_SIGNAL_READY", flush=True)
    if outside:
        if os.read(0, 1) != b"q" or received:
            raise SessionError("outside-sandbox control received an unexpected signal or close")
        print("MRK_SENTINEL_CLOSED", flush=True)
    else:
        cutoff = time.monotonic() + 3
        while not received and time.monotonic() < cutoff:
            time.sleep(0.01)
        if received != [signal.SIGUSR1]:
            raise SessionError("same-sandbox control did not receive exactly one owned signal")
        print("MRK_SIGNAL_RECEIVED", flush=True)


def _loss_owner(data: dict) -> None:
    if os.geteuid() != 0:
        raise SessionError("fixed synthetic owner role requires outside subject identity")
    child = subprocess.Popen(data["command"], **data["kwargs"], cwd=data["cwd"], env=data["env"],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True, bufsize=0)
    try:
        if _ready_line(child.stdout, 5) != b"MRK_LOSS_SUBJECT_READY\n":
            raise SessionError("synthetic lost-owner subject did not become ready")
    except BaseException:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=2)
        child.stdout.close()
        raise
    # Deliberately missing child wait; the caller expects 23, NEVER success.
    os.write(1, f"MRK_OWNER_LOST {child.pid}\n".encode("ascii"))
    os._exit(23)


def _process_groups(platform: str) -> list[int]:
    """Observe actual process groups, not Darwin's NSS user-access-group API.

    Modern Darwin CPython os.getgroups() resolves the extended libc alias,
    which queries passwd/directory membership and is not changed by setgroups.
    The public unversioned POSIX getgroups uses gid_t (uint32) and returns the
    kernel list, including its mandatory first effective-GID entry.  No NSS,
    Mach service, named account, runtime discovery, or observation fallback.
    """
    if platform not in {"linux", "darwin"}:
        raise SessionError("unsupported process-group observation platform")
    operation = "process-groups-linux" if platform == "linux" else "kernel-groups-library"
    try:
        if platform == "linux":
            return os.getgroups()
        # Local import: Linux and pure caller setup need not load any library.
        import ctypes
        library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        getgroups = library.getgroups
        getgroups.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint32)]
        getgroups.restype = ctypes.c_int
        operation = "kernel-groups-count"
        ctypes.set_errno(0)
        count = getgroups(0, None)
        if count < 0:
            raise OSError(ctypes.get_errno(), "kernel group-count observation failed")
        if not 1 <= count <= 256:
            raise SessionError("native group-count bound is unsupported")
        groups = (ctypes.c_uint32 * count)()
        operation = "kernel-groups-fill"
        ctypes.set_errno(0)
        filled = getgroups(count, groups)
        if filled < 0:
            raise OSError(ctypes.get_errno(), "kernel group-list observation failed")
        if filled != count:
            raise SessionError("native group count changed during observation")
        return list(groups)
    except BaseException as exc:
        exc._ci_operation = operation
        raise


def _probe_leaf(data: dict) -> None:
    uid, gid = data["uid"], data["gid"]
    if (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (uid, uid, gid, gid):
        raise SessionError("numerical credentials differ")
    # CPython clears groups before setregid/setreuid.  Darwin stores EGID as
    # groups[0], so primary-only[gid] (not []) proves no additional groups.
    if _process_groups(data["platform"]) != ([] if data["platform"] == "linux" else [gid]):
        raise SessionError("process retains unexpected groups")
    # Check before opening any probe descriptors.  No inherited socket or extra FD.
    for fd in range(1024):
        try:
            mode = os.fstat(fd).st_mode
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise
        if fd > 2 or stat.S_ISSOCK(mode):
            raise SessionError("unexpected inherited descriptor")
    if data["platform"] == "linux":
        root = Path(data["work"]).parent
        state = root.stat()
        if (state.st_uid != 0 or stat.S_IMODE(state.st_mode) != 0o755
                or set(os.listdir(root)) != {"source", "inputs", "bootstrap", "work"}):
            raise SessionError("namespace task root has unexpected ownership/mode/topology")
        if os.getresuid() != (uid, uid, uid) or os.getresgid() != (gid, gid, gid):
            raise SessionError("saved numerical credentials differ")
        status = Path("/proc/self/status").read_text()
        fields = dict(s.split(":", 1) for s in status.splitlines() if ":" in s)
        if any(int(fields[n].strip(), 16) for n in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")) or fields["NoNewPrivs"].strip() != "1":
            raise SessionError("capability/no-new-privileges drop failed")
        if any(os.readlink(f"/proc/self/ns/{n}") == data[f"host_{n}"] for n in ("net", "pid")):
            raise SessionError("required namespace was not separated")
    else:
        raw = _small_command(["/bin/ps", "-p", str(os.getpid()), "-o", "ruid=,uid=,svuid=,rgid=,gid=,svgid="])
        if tuple(map(int, raw.split())) != (uid, uid, uid, gid, gid, gid):
            raise SessionError("saved numerical credentials differ")
    try:
        os.setuid(0)
    except PermissionError:
        pass
    else:
        raise SessionError("subject could regain root")
    for target, operation in ((data["control"], "read"), (data["runner_home"], "list"),
                              (data["runner_temp"], "list"), (data["readonly"], "write"),
                              (data["outside_write"], "write"),
                              (str(Path(data["source"]) / "pyproject.toml"), "write")):
        try:
            if operation == "read":
                Path(target).read_bytes()
            elif operation == "list":
                os.listdir(target)
            else:
                fd = os.open(target, os.O_WRONLY)
                os.close(fd)  # Opening alone never modifies golden evidence.
        except OSError as exc:
            allowed = {errno.EACCES, errno.EPERM, errno.EROFS}
            if data["platform"] == "linux":
                allowed.add(errno.ENOENT)  # The outside host path is not mounted.
            if exc.errno in allowed:
                continue
            raise SessionError("protected-file denial had an unknown cause") from exc
        raise SessionError("protected-file boundary ineffective")
    if not (Path(data["source"]) / "pyproject.toml").read_bytes():
        raise SessionError("golden source is unavailable")
    scratch = Path(data["work"]) / f"probe-{os.getpid()}"
    scratch.write_bytes(b"private scratch")
    if scratch.read_bytes() != b"private scratch":
        raise SessionError("private scratch is not usable")
    scratch.unlink()
    # The product legitimately uses local IPC; network denial must not be
    # credited by making its required anonymous local channel unusable.
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        a.settimeout(0.5)
        b.settimeout(0.5)
        a.sendall(b"private-ipc")
        if b.recv(32) != b"private-ipc":
            raise SessionError("required anonymous local IPC failed")
    finally:
        a.close()
        b.close()
    for family, kind, host, port in data["endpoints"]:
        s = None
        try:
            s = socket.socket(family, kind)
            s.settimeout(0.5)
            if kind == socket.SOCK_STREAM:
                s.connect((host, port))
            else:
                s.sendto(b"must-not-escape", (host, port))
        except OSError as exc:
            allowed = {errno.EACCES, errno.EPERM} if data["platform"] == "darwin" else {
                errno.EACCES, errno.EPERM, errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ECONNREFUSED}
            if exc.errno not in allowed:
                raise SessionError("network denial had an unknown cause") from exc
        else:
            raise SessionError("outside-domain networking was permitted")
        finally:
            if s is not None:
                s.close()


def _probe(data: dict, *, grandchild: bool = False) -> None:
    _probe_leaf(data)
    base = [sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve())]
    # Each intermediate is its child's original parent and genuinely waits.
    roles = ("--leaf",) if grandchild else ("--leaf", "--grandchild")
    for role in roles:
        raw = _small_command([*base, role, json.dumps(data)], 10, detached=role == "--grandchild")
        if raw != b"MRK_LEAF_OK\n":
            raise SessionError("fork/exec/detached-grandchild admission failed")
    if not grandchild:
        # Fixed benign root command; stdin is closed, no real password/keychain.
        child = subprocess.Popen(["/usr/bin/sudo", "-n", "-u", "root", "/usr/bin/true"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, close_fds=True)
        try:
            if child.wait(timeout=3) == 0:
                raise SessionError("subject has usable sudo authority")
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=2)
    print("MRK_LEAF_OK" if grandchild else "MRK_NATIVE_ISOLATION_OK", flush=True)


def _cleanup_numeric(uid: int) -> None:
    if uid == 0 or (os.getuid(), os.geteuid()) != (uid, uid):
        raise SessionError("cleanup must run only as the reserved unprivileged identity")
    own = os.getpid()
    cutoff = time.monotonic() + 4
    sent_term = set()
    while time.monotonic() < cutoff:
        targets = _domain("darwin", uid) - {own}
        if not targets:
            print("MRK_CLEANUP_COMPLETE", flush=True)
            return
        for pid in targets:
            if pid <= 1:
                raise SessionError("invalid numerical cleanup target")
            try:
                os.kill(pid, signal.SIGKILL if pid in sent_term else signal.SIGTERM)
            except ProcessLookupError:
                pass
            # A recycled foreign-UID PID yields PermissionError and FAILS.
            sent_term.add(pid)
        time.sleep(0.1)
    raise SessionError("numerical cleanup did not reach finality")


def _fixture(name: str) -> int:
    if name in {"positive", "nonzero"}:
        print("PASS", flush=True)
        return 7 if name == "nonzero" else 0
    if name == "missing-footer":
        return 0
    if name == "streams":
        os.write(1, b"out\n")
        os.write(2, b"err\n")
        return 0
    if name == "over-limit":
        os.write(1, b"x" * 1025)
        return 0
    if name == "held-pipe":
        subprocess.Popen([sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()), "--fixture", "timeout"],
                         close_fds=True, start_new_session=True)
        return 0
    if name in {"timeout", "cancel"}:
        time.sleep(30)
        return 0
    raise SessionError("unknown fixed collector control")


def _main(argv: list[str]) -> int:
    if not argv:
        raise SessionError("this module has only fixed internal entry roles")
    if argv[0] == "--enter" and len(argv) >= 7:
        platform, uid, gid, cpu, policy = argv[1:6]
        if (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (int(uid), int(uid), int(gid), int(gid)):
            raise SessionError("trusted entry did not receive dropped numerical credentials")
        _limits(platform, int(cpu))
        command = argv[6:]
        if platform == "darwin":
            command = ["/usr/bin/sandbox-exec", "-f", policy, *command]
        elif platform != "linux":
            raise SessionError("unsupported platform")
        os.execve(command[0], command, dict(os.environ))
    if argv[0] == "--nss" and len(argv) == 2 and os.geteuid() == 0:
        _nss_absent(int(argv[1]))
        print("MRK_NSS_ABSENT", flush=True)
        return 0
    if argv[0] in {"--probe", "--leaf", "--grandchild"} and len(argv) == 2:
        data = json.loads(argv[1])
        if argv[0] == "--leaf":
            _probe_leaf(data)
            print("MRK_LEAF_OK", flush=True)
        else:
            _probe(data, grandchild=argv[0] == "--grandchild")
        return 0
    if argv[0] == "--cleanup" and len(argv) == 2:
        _cleanup_numeric(int(argv[1]))
        return 0
    if argv[0] == "--fixture" and len(argv) == 2:
        return _fixture(argv[1])
    if argv[0] == "--write-control" and len(argv) == 2:
        _write_control(Path(argv[1]))
        return 0
    if argv == ["--sentinel"] or argv == ["--signal-target"]:
        _signal_target(argv[0] == "--sentinel")
        return 0
    if argv[0] == "--signal-case" and len(argv) == 2:
        _signal_subject(int(argv[1]))
        return 0
    if argv == ["--loss-subject"]:
        print("MRK_LOSS_SUBJECT_READY", flush=True)
        time.sleep(30)
        return 0
    if argv[0] == "--loss-owner" and len(argv) == 2:
        _loss_owner(json.loads(argv[1]))
    raise SessionError("unknown fixed internal entry role")


if __name__ == "__main__":
    try:
        status = _main(sys.argv[1:])
    except BaseException as exc:
        print("MRK_SANDBOX_ERROR=" + json.dumps(_exception_notes(exc), separators=(",", ":")), file=sys.stderr)
        raise SystemExit(1)
    raise SystemExit(status)
