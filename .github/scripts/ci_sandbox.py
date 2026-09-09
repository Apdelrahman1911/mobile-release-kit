"""Small, fail-closed execution boundary for disposable GitHub-hosted CI VMs.

This is controller code, not an application API.  Never use it on a shared host.
The root controller supplies fixed commands and immutable inputs.  No receipt,
output string, discovered PID, or previous run grants process ownership.
"""

from __future__ import annotations

import dataclasses
import errno
import grp
import hashlib
import json
import math
import os
from pathlib import Path
import pwd
import re
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
_HOME_READ_BYTES = b"MRK_SYNTHETIC_HOME_READ\n"
_ANCESTOR_READ_BYTES = b"MRK_SYNTHETIC_ANCESTOR_READ\n"
_HOME_SOCKET_BYTES = b"MRK_SYNTHETIC_HOME_SOCKET\n"
_CENSUS_PASSES = 8
_CENSUS_PAUSE = 0.01
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
MOBILE_RELEASE_TEST_PROCESS_OBSERVER
DEVELOPER_DIR JAVA_HOME JAVA_TOOL_OPTIONS
""".split())


class SessionError(RuntimeError):
    """The attempt cannot admit another command or consume mutable outputs."""


class DeadlineExpired(SessionError):
    """An owning, never renewed absolute budget expired."""


class _CensusUnstable(SessionError):
    """An incomplete Linux pass; only finality may discard it and resnapshot."""


_DIAGNOSTIC_OPERATIONS = frozenset({"process-groups-linux", "kernel-groups-library",
                                    "kernel-groups-count", "kernel-groups-fill",
                                    "mac-original-credentials", "cleanup-batch",
                                    "network-tcp4", "network-udp4", "network-tcp6", "network-udp6"})
_TOOL_DIAGNOSTIC_ROLES = frozenset({"python", "ruby", "sudo", "true", "sandbox-exec", "ps",
                                    "compiler", "linker", "signature-tool", "unspecified"})


def _observer_error_fields(value: object) -> dict | None:
    """Closed diagnostic schema only; no observer result is accepted here."""
    if not isinstance(value, dict) or set(value) != {"code", "errno", "library_close_failed"}:
        return None
    code, number, closed = value["code"], value["errno"], value["library_close_failed"]
    if not isinstance(code, str) or type(closed) is not bool:
        return None
    if code in {"INPUT", "CALLER_IDENTITY", "SELF_QUERY", "SELF_IDENTITY", "QUERY", "SIZE", "GROUP_LIBRARY"}:
        if number is not None or closed:
            return None
    elif code in {"GROUP_SYMBOL", "GROUP_COUNT", "GROUP_BOUND", "GROUP_READ",
                  "GROUP_CHANGED", "GROUP_IDENTITY", "GROUP_CLOSE"}:
        if type(number) is not int or not 0 <= number < 4096:
            return None
        if code not in {"GROUP_COUNT", "GROUP_READ"} and number != 0:
            return None
        if code == "GROUP_CLOSE" and not closed:
            return None
    else:
        return None
    return {"code": code, "errno": number, "library_close_failed": closed}


def _observer_error_note(data: bytes) -> dict | None:
    """Recognize one exact fixed C error line; never publish stdout or a PID."""
    if not isinstance(data, bytes) or len(data) > 128:
        return None
    match = re.fullmatch(rb"MRK_PROCESS_V1 error ([A-Z_]+)(?:_(0|[1-9][0-9]{0,3})(_AND_CLOSE)?)?\n", data)
    if match is None:
        return None
    code = match[1].decode("ascii")
    if code == "GROUP_CLOSE" and match[3] is not None:
        return None
    return _observer_error_fields({"code": code, "errno": None if match[2] is None else int(match[2]),
                                   "library_close_failed": match[3] is not None or code == "GROUP_CLOSE"})


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
                observation = row.get("observation")
                if isinstance(observation, dict):
                    observer_error = _observer_error_fields(observation.get("observer_error"))
                    if observer_error is not None:
                        note["observation"] = {"observer_error": observer_error}
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


def _ruby_launch_error(result: CapturedRun, ruby: Path) -> dict | None:
    """Exact fixed-launch failure diagnosis, never a substitute accepted result."""
    if (result.returncode != 71 or result.stdout or not result.waited
            or not result.stdout_eof or not result.stderr_eof or not result.domain_finality
            or result.timed_out or result.cancelled or result.cleanup_errors
            or result.primary_error != "command exited 71"
            or result.persisted != (0, len(result.stderr))):
        return None
    for number, message in ((errno.EPERM, "Operation not permitted"),
                            (errno.EACCES, "Permission denied"),
                            (errno.ENOENT, "No such file or directory"),
                            (errno.ENOEXEC, "Exec format error"),
                            (errno.ENOMEM, "Cannot allocate memory"),
                            (errno.E2BIG, "Argument list too long"),
                            (errno.ETXTBSY, "Text file busy")):
        expected = f"sandbox-exec: execvp() of '{ruby}' failed: {message}\n".encode()
        if result.stderr == expected:
            return {"operation": "sandbox-execvp", "role": "ruby", "errno": number}
    return None  # No byte-count guess, sandbox_apply guess, or raw stderr.


def _ruby_startup_error(result: CapturedRun, ruby: Path) -> dict | None:
    """Closed tokens from an owned failed capture, not native-cause evidence.

    This never resolves/reads a provider path, runs Ruby again, or changes the
    failed result. Unknown surrounding text is not an understood stack trace.
    """
    if (type(result.returncode) is not int or result.returncode != 1
            or type(result.stdout) is not bytes or result.stdout != b""
            or type(result.stderr) is not bytes or result.waited is not True
            or result.stdout_eof is not True or result.stderr_eof is not True
            or result.domain_finality is not True or result.timed_out is not False
            or result.cancelled is not False or type(result.cleanup_errors) is not tuple or result.cleanup_errors
            or result.primary_error != "command exited 1"
            or type(result.persisted) is not tuple or len(result.persisted) != 2
            or any(type(n) is not int for n in result.persisted)
            or result.persisted != (0, len(result.stderr))):
        return None
    note = {"semantics": "stderr-tokens-only", "classification": "unclassified"}
    data = result.stderr
    if not 0 < len(data) <= 16 * 1024 or not data.endswith(b"\n"):
        return note
    try:
        # The fixed clean locale and admitted paths use this finite grammar;
        # unsupported encodings/formatting remain unclassified, never forwarded.
        raw = data.decode("ascii")
    except UnicodeDecodeError:
        return note
    lines = raw[:-1].split("\n")
    if (not 1 <= len(lines) <= 64 or any(ord(c) < 32 and c not in "\n\t" or ord(c) == 127 for c in raw)
            or any("\t" in line and (index == 0 or not line.startswith("\tfrom ") or "\t" in line[1:])
                   for index, line in enumerate(lines))):
        return note

    # Only these portable Darwin errno values; never infer one from message text
    # or use a Linux-specific number for a differently numbered native error.
    errnos = {"Errno::EPERM": 1, "Errno::ENOENT": 2, "Errno::ENOEXEC": 8,
              "Errno::ENOMEM": 12, "Errno::EACCES": 13, "Errno::ENOTDIR": 20}
    classes = set(errnos) | {"LoadError", "ArgumentError", "RuntimeError", "ThreadError",
                            "SecurityError", "SyntaxError", "NameError", "TypeError", "NoMemoryError"}
    library = ruby.parent.parent / "lib/ruby/3.3.0"  # The workflow's fixed Ruby3.3 provider.
    sources = {str(library / name): role for name, role in (
        ("rubygems.rb", "rubygems"), ("rubygems/defaults.rb", "rubygems-defaults"),
        ("rubygems/path_support.rb", "rubygems-path-support"),
        ("rubygems/core_ext/kernel_require.rb", "rubygems-kernel-require"),
        ("bundled_gems.rb", "bundled-gems"))}
    sources.update({"<internal:gem_prelude>": "gem-prelude", "<internal:prelude>": "ruby-prelude",
                    f"<internal:{library / 'rubygems/core_ext/kernel_require.rb'}>": "rubygems-kernel-require",
                    "-e": "numerical-probe"})

    def fixed_frame(line: str, *, header: bool = False) -> tuple[dict, str] | None:
        for source, role in sources.items():
            prefix = source + ":"
            if not line.startswith(prefix):
                continue
            pattern = r"([1-9][0-9]{0,5})(?::in [`'][^`'\t\n]{1,128}')?"
            if header:
                pattern += r": (.*)"
            match = re.fullmatch(pattern, line[len(prefix):])
            if match is None or role == "numerical-probe" and int(match[1]) != 1:
                return None
            return {"role": role, "line": int(match[1])}, match[2] if header else ""
        return None

    body, frames, bare = lines[0], [], True
    first = fixed_frame(body, header=True)
    if first is not None:
        frames.append(first[0])
        body, bare = first[1], False
    else:
        for prefix in (str(ruby) + ": ", ruby.name + ": "):
            if body.startswith(prefix):
                body, bare = body[len(prefix):], False
                break
    match = re.fullmatch(r"(.+) \(([^()]+)\)", body)
    if match is None or match[2] not in classes:
        return note
    exception, message = match[2], match[1]
    if bare:
        # Ruby can fail before a source frame exists. Admit only this exact
        # native-error spelling, not a class-looking suffix in arbitrary text.
        messages = {"Errno::EPERM": "Operation not permitted", "Errno::ENOENT": "No such file or directory",
                    "Errno::ENOEXEC": "Exec format error", "Errno::ENOMEM": "Cannot allocate memory",
                    "Errno::EACCES": "Permission denied", "Errno::ENOTDIR": "Not a directory"}
        prefix = messages.get(exception, "") + " @ rb_check_realpath_internal - "
        if exception not in messages or not message.startswith(prefix) or not message[len(prefix):]:
            return note
    note.update(classification="recognized", exception=exception, frames=frames)
    if exception in errnos:
        note["errno"] = errnos[exception]
    if re.search(r" @ rb_check_realpath_internal - .+", message):
        note["operation"] = "rb_check_realpath_internal"
    for line in lines[1:]:
        if not line.startswith("\tfrom "):
            continue
        frame = fixed_frame(line[len("\tfrom "):])
        if frame is not None and frame[0] not in frames:
            frames.append(frame[0])
            if len(frames) == 8:
                break
    return note


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


def _remaining(deadline: float) -> float:
    if type(deadline) not in (int, float) or not math.isfinite(deadline):
        raise SessionError("invalid owning absolute deadline")
    left = deadline - time.monotonic()
    if left <= 0:
        raise DeadlineExpired("owning absolute deadline expired")
    return left


def _tool_stat_note(info, uid: int, gid: int, *, role: str) -> dict:
    """One supplied stat observation; POSIX bits are not ACL/sandbox authority."""
    kind = next((name for name, check in (("regular", stat.S_ISREG), ("directory", stat.S_ISDIR),
                                         ("symlink", stat.S_ISLNK), ("fifo", stat.S_ISFIFO),
                                         ("socket", stat.S_ISSOCK), ("character", stat.S_ISCHR),
                                         ("block", stat.S_ISBLK)) if check(info.st_mode)), "other")
    return {"role": role if isinstance(role, str) and role in _TOOL_DIAGNOSTIC_ROLES else "unspecified",
            "kind": kind, "mode": format(stat.S_IMODE(info.st_mode), "04o"),
            "root_owned": info.st_uid == 0, "subject_owned": info.st_uid == uid,
            "subject_group": info.st_gid == gid, "setuid": bool(info.st_mode & stat.S_ISUID),
            "setgid": bool(info.st_mode & stat.S_ISGID), "owner_execute": bool(info.st_mode & 0o100),
            "group_execute": bool(info.st_mode & 0o010), "other_execute": bool(info.st_mode & 0o001)}


def _home_node(info) -> tuple:
    return info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IFMT(info.st_mode)


def _home_paths(home: Path, root: Path) -> tuple[Path, Path]:
    """Only two session-derived synthetic names, never a caller-selected reader."""
    if (not home.is_absolute() or not root.is_absolute() or ".." in home.parts
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", root.name)):
        raise SessionError("invalid fixed HOME fixture binding")
    canary, endpoint = (home / f".{root.name}-home-{suffix}" for suffix in ("read", "socket"))
    if len(os.fsencode(endpoint)) >= 104:
        raise SessionError("fixed HOME socket pathname exceeds native bound")
    return canary, endpoint


def _ruby_ancestor_paths(home: Path, ruby_prefix: Path) -> tuple[Path, ...]:
    """Pure, bounded strict ancestors; native identity checks belong to admission."""
    for path in (home, ruby_prefix):
        if (not path.is_absolute() or ".." in path.parts or path == Path("/")
                or any(not 32 <= ord(c) < 127 for c in str(path)) or len(str(path).encode()) > 4096):
            raise SessionError("invalid fixed Ruby ancestor binding")
    if ruby_prefix == home or not _under(ruby_prefix, home):
        raise SessionError("selected Ruby prefix must lie strictly beneath HOME")
    ancestors, current = [], ruby_prefix.parent
    while True:
        ancestors.append(current)
        if len(ancestors) > 16:
            raise SessionError("selected Ruby ancestor inventory exceeds fixed bound")
        if current == home:
            break
        current = current.parent
    return tuple(reversed(ancestors))


def _ruby_sibling_path(home: Path, ruby_prefix: Path, root: Path) -> Path:
    """One synthetic sibling beneath every literal, outside the Ruby prefix."""
    ancestors = _ruby_ancestor_paths(home, ruby_prefix)
    if (not root.is_absolute() or ".." in root.parts
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", root.name)):
        raise SessionError("invalid fixed Ruby sibling binding")
    sibling = ancestors[-1] / f".{root.name}-ancestor-read"
    if len(str(sibling).encode()) > 4096:
        raise SessionError("fixed Ruby sibling pathname exceeds bound")
    return sibling


def _admit_executable(path: Path, uid: int, gid: int, *, root_owned: bool = False,
                      non_set_id: bool = True, role: str = "unspecified") -> dict:
    """Check a fixed provider/system executable, not a subject-selected tool."""
    try:
        info = path.stat()
    except BaseException as exc:
        exc._ci_observation = {"tool_stat_failure": {
            "role": role if isinstance(role, str) and role in _TOOL_DIAGNOSTIC_ROLES else "unspecified",
            "observed": False}}
        raise  # Original identity, errno and cause; no replacement stat or inode.
    note = _tool_stat_note(info, uid, gid, role=role)
    note["failed_predicates"] = [name for name, failed in (
        ("not-regular", not stat.S_ISREG(info.st_mode)),
        ("no-execute-bit", not info.st_mode & 0o111),
        ("subject-owned", info.st_uid == uid),
        ("world-writable", bool(info.st_mode & 0o002)),
        ("subject-group-writable", info.st_gid == gid and bool(info.st_mode & 0o020)),
        ("root-role-not-root-owned", root_owned and info.st_uid != 0),
        ("root-role-group-or-world-writable", root_owned and bool(info.st_mode & 0o022)),
        ("set-id-forbidden", non_set_id and bool(info.st_mode & (stat.S_ISUID | stat.S_ISGID)))) if failed]
    if (not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111
            or info.st_uid == uid or info.st_mode & 0o002
            or info.st_gid == gid and info.st_mode & 0o020
            or root_owned and (info.st_uid != 0 or info.st_mode & 0o022)
            or non_set_id and info.st_mode & (stat.S_ISUID | stat.S_ISGID)):
        failure = SessionError("fixed executable permission/identity contract failed")
        failure._ci_observation = {"tool": note}
        raise failure
    return note


def _small_command(argv: list[str], seconds: float = 10.0,
                   *, user: int | None = None, group: int | None = None,
                   return_pid: bool = False, expected_code: int = 0,
                   detached: bool = True, deadline: float | None = None) -> bytes | tuple[bytes, int]:
    """Bounded, original-parent collection of fixed trusted OS metadata tools."""
    kwargs = {} if user is None else {"user": user, "group": group, "extra_groups": []}
    child = sel = None
    result = [bytearray(), bytearray()]
    eof, waited, code = [False, False], False, None
    if type(seconds) not in (int, float) or not 0 < seconds <= 3300:
        raise SessionError("invalid trusted metadata time allowance")
    cutoff = time.monotonic() + seconds
    if deadline is not None:
        _remaining(deadline)
        cutoff = min(cutoff, deadline)
    errors = []
    try:
        _remaining(cutoff)
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, close_fds=True,
                                 env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"},
                                 start_new_session=detached, **kwargs)
        _remaining(cutoff)
        sel = selectors.DefaultSelector()
        for i, stream in enumerate((child.stdout, child.stderr)):
            os.set_blocking(stream.fileno(), False)
            sel.register(stream, selectors.EVENT_READ, i)
        while sel.get_map() or child.poll() is None:
            for key, _ in sel.select(min(0.05, _remaining(cutoff))):
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
        code = child.wait(timeout=_remaining(cutoff))
        waited = True
        _remaining(cutoff)
        if code != expected_code or result[1]:
            raise SessionError("trusted metadata tool failed or emitted diagnostics")
    except BaseException as exc:
        errors.append(exc)
    if child is not None:
        try:
            # This handle has no other owner.  No discovered-PID signal.
            if child.poll() is None:
                child.kill()
        except BaseException as exc:
            errors.append(exc)
        try:
            code = child.wait(timeout=max(0.0, min(2, cutoff - time.monotonic())))
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
    try:
        _remaining(cutoff)
    except BaseException as exc:
        errors.append(exc)
    if errors:
        failure = BaseExceptionGroup("trusted metadata invocation/cleanup failure", errors)
        failure._ci_observation = {"returncode": code, "waited": waited, "stdout_eof": eof[0],
                                   "stderr_eof": eof[1], "stdout_bytes": len(result[0]),
                                   "stderr_bytes": len(result[1]), "error_count": len(errors),
                                   "exceptions": _child_exception_notes(bytes(result[1]))}
        observer_error = _observer_error_note(bytes(result[0]))
        if observer_error is not None:
            failure._ci_observation["observer_error"] = observer_error
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


def _linux_snapshot(*, deadline: float | None = None) -> dict[tuple[int, int], tuple[tuple[int, ...], tuple[int, ...], int]]:
    """Complete bounded process AND thread credentials, including fs IDs."""
    if deadline is not None:
        _remaining(deadline)
    root = Path("/proc")
    pids = sorted(int(p.name) for p in root.iterdir() if p.name.isdecimal())
    if len(pids) > 32768:
        raise SessionError("process census size")
    rows = {}
    for pid in pids:
        if deadline is not None:
            _remaining(deadline)
        task = root / str(pid) / "task"
        try:
            tids = sorted(int(p.name) for p in task.iterdir() if p.name.isdecimal())
            if not tids:
                raise _CensusUnstable("enumerated process has no observable threads")
            if len(rows) + len(tids) > 131072:
                raise SessionError("thread census size")
            for tid in tids:
                if deadline is not None:
                    _remaining(deadline)
                base = task / str(tid)
                before = (base / "stat").read_bytes()
                raw = (base / "status").read_bytes()
                after = (base / "stat").read_bytes()
                if max(len(before), len(raw), len(after)) > 65536:
                    raise SessionError("process metadata size")
                # stat field22 follows the final ')' of the command field.
                # Validate BOTH identities and credentials before classifying a
                # difference. Malformed data can never be retried as absence.
                births = []
                for entry in (before, after):
                    marker = entry.rfind(b") ")
                    tail = entry[marker + 2:].split() if marker >= 0 else []
                    if len(tail) <= 19 or not tail[19].isdigit():
                        raise SessionError("malformed process birth metadata")
                    birth = int(tail[19])
                    if birth >= 2**64:
                        raise SessionError("process birth metadata exceeds unsigned64")
                    births.append(birth)
                fields = {}
                for line in raw.splitlines():
                    if b":" not in line:
                        continue
                    key, value = line.split(b":", 1)
                    if key in {b"Uid", b"Gid"}:
                        if key in fields:
                            raise SessionError("duplicate process credentials")
                        fields[key] = value.split()
                if (set(fields) != {b"Uid", b"Gid"}
                        or any(len(values) != 4 or any(not v.isdigit() for v in values)
                               for values in fields.values())):
                    raise SessionError("incomplete or malformed process credentials")
                uids, gids = (tuple(int(v) for v in fields[key]) for key in (b"Uid", b"Gid"))
                if any(value >= 2**32 for values in (uids, gids) for value in values):
                    raise SessionError("process credentials exceed unsigned32")
                if births[0] != births[1]:
                    raise _CensusUnstable("process identity changed during census")
                rows[(pid, tid)] = (uids, gids, births[0])
            if tids != sorted(int(p.name) for p in task.iterdir() if p.name.isdecimal()):
                raise _CensusUnstable("thread churn during complete census")
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                raise
            # Only a path beneath an already enumerated PID/TID may disappear.
            # Root enumeration failures below remain fatal, never empty passes.
            raise _CensusUnstable("enumerated process metadata disappeared") from exc
    if pids != sorted(int(p.name) for p in root.iterdir() if p.name.isdecimal()):
        raise _CensusUnstable("process churn during complete census")
    if deadline is not None:
        _remaining(deadline)
    return rows


def _mac_snapshot(*, deadline: float | None = None) -> dict[tuple[int, int], tuple[tuple[int, ...], tuple[int, ...], int]]:
    # Unsupported Darwin fields/visibility are a failure, not an invented ABI.
    raw, owned_ps = _small_command(["/bin/ps", "-axo", "pid=,ruid=,uid=,svuid=,rgid=,gid=,svgid=,rss=,stat="],
                                  return_pid=True, deadline=deadline)
    rows = {}
    for line in raw.splitlines():
        if deadline is not None:
            _remaining(deadline)
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
    if deadline is not None:
        _remaining(deadline)
    return rows


def _snapshot(platform: str, *, deadline: float | None = None, retry_churn: bool = False):
    if platform != "linux":
        return _mac_snapshot(deadline=deadline)  # Darwin observation is unchanged.
    if not retry_churn:
        return _linux_snapshot(deadline=deadline)
    if deadline is None:
        raise SessionError("finality resnapshot requires its original finite cutoff")
    for attempt in range(_CENSUS_PASSES):
        _remaining(deadline)
        try:
            rows = _linux_snapshot(deadline=deadline)
        except _CensusUnstable:
            if attempt == _CENSUS_PASSES - 1:
                raise
            time.sleep(min(_CENSUS_PAUSE, _remaining(deadline)))
        else:
            _remaining(deadline)
            return rows


def _domain(platform: str, uid: int, *, collision: bool = False, deadline: float | None = None) -> set[int]:
    """Two full passes; no missing/truncated/unknown row is silently ignored."""
    occupied = set()
    for _ in range(2):
        if deadline is not None:
            _remaining(deadline)
        for (pid, _), (uids, gids, _) in _snapshot(platform, deadline=deadline, retry_churn=not collision).items():
            if uid in uids or (collision and uid in gids):
                occupied.add(pid)
    if deadline is not None:
        _remaining(deadline)
    return occupied


def _observe_original_credentials(pid: int, uid: int, gid: int, *, deadline: float) -> None:
    """Root observes its still-unreaped original handle; this is NOT signal authority."""
    try:
        if os.geteuid() != 0 or type(pid) is not int or pid <= 1:
            raise SessionError("original credential observation requires its outside root owner")
        _remaining(deadline)
        row = _mac_snapshot(deadline=deadline).get((pid, pid))
        _remaining(deadline)
        if row is None or row[:2] != ((uid, uid, uid), (gid, gid, gid)):
            raise SessionError("original unreaped child lacks exact real/effective/saved identities")
    except BaseException as exc:
        exc._ci_operation = "mac-original-credentials"
        raise


def _readonly_tree(root: Path) -> None:
    root = _canonical(root)
    for current, dirs, files in os.walk(root, followlinks=False):
        for p in (Path(current), *(Path(current) / n for n in dirs + files)):
            s = p.lstat()
            if stat.S_ISLNK(s.st_mode) or not (stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode)):
                raise SessionError("nonordinary immutable input")
            if s.st_uid != 0 or s.st_mode & 0o022:
                raise SessionError("immutable input is not root-owned/read-only to subject")


def _observer_artifact(path: Path, uid: int, gid: int, *, deadline: float) -> tuple[bytes, int]:
    """Read only AFTER producer finality; never follow/adopt a mutable name."""
    fd = None
    errors, chunks = [], []
    size = 0
    fields = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
                        s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    try:
        _remaining(deadline)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or (before.st_uid, before.st_gid) != (uid, gid)
                or before.st_mode & (stat.S_ISUID | stat.S_ISGID | 0o022)
                or not before.st_mode & 0o111 or not 0 < before.st_size <= 16 * MiB):
            raise SessionError("observer producer artifact identity/mode/size failed")
        while True:
            _remaining(deadline)
            chunk = os.read(fd, min(65536, 16 * MiB - size + 1))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > 16 * MiB:
                raise SessionError("observer producer artifact exceeds fixed bound")
        if fields(before) != fields(os.fstat(fd)) or fields(before) != fields(path.lstat()) or size != before.st_size:
            raise SessionError("observer producer artifact changed during observation")
        _remaining(deadline)
    except BaseException as exc:
        errors.append(exc)
    if fd is not None:
        try:
            os.close(fd)
        except BaseException as exc:
            errors.append(exc)
    try:
        _remaining(deadline)
    except BaseException as exc:
        errors.append(exc)
    if errors:
        raise BaseExceptionGroup("observer artifact observation/close failed", errors)
    return b"".join(chunks), stat.S_IMODE(before.st_mode)


def _observer_toolchain(uid: int, gid: int, *, deadline: float) -> dict:
    """Bind only the selected provider installation; no PATH/config discovery."""
    xcode = _canonical("/Applications/Xcode_26.3.app/Contents/Developer")
    toolchain = _canonical(xcode / "Toolchains/XcodeDefault.xctoolchain")
    sdk = _canonical((xcode / "Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk").resolve(strict=True))

    def checked(path: Path):
        _remaining(deadline)
        info = path.stat()
        if (info.st_uid != 0 or info.st_mode & 0o002
                or info.st_gid == gid and info.st_mode & 0o020
                or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))):
            raise SessionError("selected compiler/SDK is not root-owned and read-only to subject")
        return info

    if not _under(sdk, xcode):
        raise SessionError("selected SDK resolves outside fixed Xcode installation")
    for path in (xcode, *xcode.parents):
        checked(path)
    # Follow only canonical provider links within Xcode, visiting each directory
    # once.  This includes headers/runtime files, not merely the clang pathname.
    pending, visited, count = [toolchain, sdk], set(), 0
    while pending:
        current = pending.pop()
        if current in visited:
            continue
        visited.add(current)
        checked(current)
        for item in current.iterdir():
            count += 1
            if count > 300000:
                raise SessionError("selected compiler/SDK inventory exceeds fixed bound")
            _remaining(deadline)
            target = item.resolve(strict=True)
            if not _under(target, xcode) or item.lstat().st_uid != 0:
                raise SessionError("selected compiler/SDK link escapes provider installation")
            info = checked(target)
            if stat.S_ISDIR(info.st_mode):
                pending.append(target)
    clang, linker = (_canonical((toolchain / "usr/bin" / name).resolve(strict=True)) for name in ("clang", "ld"))
    for role, path in (("compiler", clang), ("linker", linker)):
        if not _under(path, toolchain):
            raise SessionError("compiler/linker resolves outside selected toolchain")
        _admit_executable(path, uid, gid, root_owned=True, role=role)
    _admit_executable(Path("/usr/bin/codesign"), uid, gid, root_owned=True, role="signature-tool")

    def digest(path: Path, maximum: int) -> str:
        before = checked(path)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            raise SessionError("fixed provider file size/type unsupported")
        total, result = 0, hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(65536):
                _remaining(deadline)
                total += len(chunk)
                if total > maximum:
                    raise SessionError("fixed provider digest exceeds bound")
                result.update(chunk)
        after = checked(path)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                or total != before.st_size):
            raise SessionError("fixed provider file changed during binding")
        return result.hexdigest()

    settings = sdk / "SDKSettings.json"
    settings_hash = digest(settings, MiB)
    raw = settings.read_bytes()
    if len(raw) > MiB or hashlib.sha256(raw).hexdigest() != settings_hash:
        raise SessionError("selected SDK settings changed")
    data = json.loads(raw)
    version, canonical = data.get("Version"), data.get("CanonicalName")
    if (not isinstance(version, str) or not re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,3}){1,2}", version)
            or canonical != "macosx" + version):
        raise SessionError("selected SDK identity/version is unsupported")
    _remaining(deadline)
    return {"clang": clang, "linker": linker, "sdk": sdk, "toolchain": toolchain,
            "evidence": {"xcode": "26.3", "clang_sha256": digest(clang, 512 * MiB),
                         "linker_sha256": digest(linker, 512 * MiB), "sdk": canonical,
                         "sdk_settings_sha256": settings_hash, "provider_entries": count}}


def _observer_signature_metadata(stdout: bytes, stderr: bytes, path: Path, arch: str) -> dict:
    """Strict fixed codesign display contract; no failed/empty display inference."""
    if stdout or not 0 < len(stderr) <= 16384 or not stderr.endswith(b"\n"):
        raise SessionError("observer signature display is incomplete")
    text = stderr.decode("ascii", "strict")
    if "\r" in text or "\0" in text or arch not in {"arm64", "x86_64"}:
        raise SessionError("observer signature display format unsupported")
    required = {f"Executable={path}", f"Identifier={path.name}", f"Format=Mach-O thin ({arch})",
                "Signature=adhoc", "TeamIdentifier=not set"}
    ordinary = {"Info.plist=not bound", "Sealed Resources=none", "Internal requirements=none",
                "Internal requirements count=0 size=12", "Hash type=sha256 size=32",
                "Hash choices=sha256", "CMSDigestType=2", "Executable Segment base=0",
                "Executable Segment flags=0x1", "Page size=4096", "Page size=16384"}
    seen, keys, flags = set(), set(), None
    for line in text.splitlines():
        key = ("CodeDirectory" if line.startswith("CodeDirectory ") else
               "Internal requirements" if line.startswith("Internal requirements") else line.split("=", 1)[0])
        if key in keys:
            raise SessionError("duplicate observer signature field")
        keys.add(key)
        seen.add(line)
        if line in required or line in ordinary:
            continue
        match = re.fullmatch(r"CodeDirectory v=([0-9]+) size=([0-9]+) flags=0x([0-9a-f]+)\(([^()]*)\) hashes=([0-9]+)\+([0-9]+) location=embedded", line)
        if match:
            if flags is not None:
                raise SessionError("duplicate observer CodeDirectory")
            flags = int(match[3], 16)
            if (flags not in {2, 0x20002} or match[4] != ("adhoc" if flags == 2 else "adhoc,linker-signed")
                    or not 20001 <= int(match[1]) <= 99999 or not 0 < int(match[2]) <= 16 * MiB
                    or not 0 < int(match[5]) <= 65536 or not 0 <= int(match[6]) <= 32):
                raise SessionError("observer signature has unsupported signing flags/layout")
            continue
        if (re.fullmatch(r"(?:CandidateCDHash sha256|CDHash)=[0-9a-f]{40}", line)
                or re.fullmatch(r"(?:CandidateCDHashFull sha256|CMSDigest)=[0-9a-f]{64}", line)
                or re.fullmatch(r"Executable Segment limit=[0-9]{1,10}", line)):
            continue
        # Authority, nonempty TeamIdentifier, CS platform identifier and every
        # unknown diagnostic/state are deliberately outside this finite grammar.
        failure = SessionError("observer signature display contains unknown or privileged metadata")
        known = {"Executable", "Identifier", "Format", "Signature", "TeamIdentifier", "Authority",
                 "Platform identifier", "Runtime Version", "CodeDirectory", "Internal requirements"}
        failure._ci_observation = {"signature_field": key if key in known else "unclassified"}
        raise failure
    if not required <= seen or flags is None:
        failure = SessionError("observer signature lacks positive ordinary ad-hoc evidence")
        failure._ci_observation = {"signature_fields_missing": sorted(line.split("=", 1)[0] for line in required - seen),
                                   "code_directory_missing": flags is None}
        raise failure
    return {"signature": "adhoc", "flags": flags, "architecture": arch}


def _observer_build_notes(data: bytes, source: Path) -> list[dict]:
    """Only reviewed C source positions/severity, never compiler message text."""
    pattern = re.compile(re.escape(str(source).encode()) + rb":([1-9][0-9]{0,6}):([1-9][0-9]{0,6}): (fatal error|error|warning):")
    notes = []
    for line in data[:65536].splitlines()[:512]:
        match = pattern.match(line)
        if match:
            notes.append({"file": ".github/scripts/ci_process_observer.c", "line": int(match[1]),
                          "column": int(match[2]), "severity": match[3].decode("ascii")})
        elif line.startswith(b"clang: error:"):
            notes.append({"category": "clang-driver"})
        if len(notes) == 16:
            break
    return notes or ([{"category": "unclassified-compiler-diagnostics"}] if data else [])


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
        if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
            raise SessionError("original-parent ownership requires default SIGCHLD disposition")
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
        self.process_observer: Path | None = None
        self._home_state: dict | None = None
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
        if platform == "darwin":
            # Policy publication is exclusive and happens before HOME effects.
            # Bind its one finite metadata allowance now; never rewrite policy.
            self._bind_ruby_ancestors()
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

    def _bind_ruby_ancestors(self) -> None:
        """Canonical selected runtime ancestry, with no subject-writable member."""
        if self.platform != "darwin":
            raise SessionError("Ruby ancestor binding belongs only to the native Mac policy")
        prefix = self.ruby.parent.parent
        if [p for p in self.tool_prefixes if _under(self.ruby, p)] != [prefix]:
            raise SessionError("selected Ruby prefix is missing or ambiguous")
        ancestors = _ruby_ancestor_paths(self.runner_home, prefix)
        _remaining(self.deadline)
        if _canonical(prefix) != prefix:
            raise SessionError("selected Ruby prefix changed its canonical binding")
        states = []
        for path in ancestors:
            _remaining(self.deadline)
            before = path.lstat()
            _remaining(self.deadline)
            _canonical(path)
            _remaining(self.deadline)
            after = path.lstat()
            _remaining(self.deadline)
            mode = stat.S_IMODE(after.st_mode)
            if (not stat.S_ISDIR(after.st_mode) or after.st_uid == self.uid or after.st_gid == self.gid
                    or mode & 0o002 or not mode & 0o001 and not (path == self.runner_home and mode == 0o750)
                    or _home_node(before) != _home_node(after) or stat.S_IMODE(before.st_mode) != mode):
                raise SessionError("selected Ruby ancestor identity/traversal/mode is unsafe")
            states.append(after)
        self.ruby_prefix, self.ruby_ancestors = prefix, ancestors
        self._ruby_ancestor_states = tuple(states)

    def _check_ruby_ancestors(self, *, home_mode: int | None = None) -> None:
        """No policy/runtime ancestry drift; HOME's sole owned mode change is known."""
        if (self.ruby_ancestors != _ruby_ancestor_paths(self.runner_home, self.ruby_prefix)
                or len(self._ruby_ancestor_states) != len(self.ruby_ancestors)):
            raise SessionError("selected Ruby ancestor inventory lost its binding")
        for path, original in zip(self.ruby_ancestors, self._ruby_ancestor_states):
            _remaining(self.deadline)
            _canonical(path)
            _remaining(self.deadline)
            current = path.lstat()
            mode = home_mode if path == self.runner_home and home_mode is not None else stat.S_IMODE(original.st_mode)
            if _home_node(current) != _home_node(original) or stat.S_IMODE(current.st_mode) != mode:
                raise SessionError("selected Ruby ancestor identity/mode drifted")
            _remaining(self.deadline)

    def _write_policy(self) -> None:
        # JSON ASCII string escaping is also a valid SBPL string literal.
        q = lambda p: json.dumps(str(p), ensure_ascii=True)
        exclusions = "\n  ".join(f"(require-not (subpath {q(p)}))" for p in self.tool_prefixes)
        private = " ".join(f"(subpath {q(p)})" for p in (self.runner_home, self.runner_temp, self.control))
        common = ("(version 1)\n(allow default)\n(deny network*)\n(deny mach-lookup)\n"
                  f"(deny file-read* (require-all (require-any {private})\n  {exclusions}))\n")
        metadata = "".join(f"(allow file-read-metadata (literal {q(p)}))\n" for p in self.ruby_ancestors)
        subject = (common + metadata + "(deny signal (require-not (target same-sandbox)))\n"
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
        observer_key = "MOBILE_RELEASE_TEST_PROCESS_OBSERVER"
        observer = getattr(self, "process_observer", None)
        if observer is not None:
            if self.platform != "darwin" or observer != self.bootstrap / "process-observer":
                raise SessionError("process observer selector lost its fixed owner binding")
            fixed[observer_key] = str(observer)
        elif observer_key in values:
            raise SessionError("process observer has not completed native admission")
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
            if _domain(self.platform, self.uid, deadline=self.deadline):
                raise SessionError("reserved identity still has a process or zombie")
            self.domain_finality = True
        except BaseException:
            self.domain_finality = False
            self._fail("reserved-identity finality is unknown or false")
            raise
        self._headroom()

    def _cleanup(self, *, deadline: float | None = None) -> list[str]:
        errors = []
        if self.platform == "darwin":
            try:
                # Root observes only; kernel-authorized signalling stays in U.
                # One cutoff covers all censuses, batches, waits and sleeps.
                cutoff = min(self.deadline, time.monotonic() + 4)
                if deadline is not None:
                    _remaining(deadline)
                    cutoff = min(cutoff, deadline)
                kind = "TERM"
                while True:
                    targets = sorted(_domain("darwin", self.uid, deadline=cutoff))
                    if not targets:
                        break  # Actual root census, not a helper receipt.
                    if len(targets) > 4096:
                        raise SessionError("numerical cleanup batch exceeds fixed bound")
                    data = _small_command([str(self.python), "-I", "-S", "-B", str(self.entry),
                                           "--enter", "darwin", str(self.uid), str(self.gid), "10",
                                           str(self.cleanup_policy), str(self.python), "-I", "-S", "-B",
                                           str(self.entry), "--cleanup-batch", str(self.uid), str(self.gid),
                                           kind, json.dumps(targets), repr(cutoff)],
                                          4, user=self.uid, group=self.gid, deadline=cutoff)
                    if data != b"MRK_CLEANUP_BATCH_ATTEMPTED\n":
                        raise SessionError("trusted numerical cleanup batch lacked its exact result")
                    time.sleep(min(0.1, _remaining(cutoff)))
                    kind = "KILL"
            except BaseException as exc:
                errors.append(f"numerical cleanup {type(exc).__name__}")
                if getattr(self, "_admitting", False):
                    self.admission_results.append({"name": "cleanup-exception", "ok": False,
                                                   "exceptions": _exception_notes(exc)})
        return errors

    def run(self, argv: list[str], *, cwd: str | Path, env: dict[str, str], seconds: float,
            output_limit: int = 8 * MiB, cpu_seconds: int = 180) -> CapturedRun:
        self._guard()
        if not self.admitted:
            raise SessionError("native admission has not completed")
        if self.platform == "darwin" and self.process_observer is None:
            raise SessionError("macOS process observer admission is missing")
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
            if self.platform == "darwin":
                # Keep both strong references and do not poll/wait first.  Even
                # an exited original retains its reserved PID/credentials here.
                _observe_original_credentials(child.pid, self.uid, self.gid, deadline=cutoff)
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
                        errors.extend(self._cleanup(deadline=min(self.deadline, stop_at + 8)))
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
                        for uids, _gids, rss in _mac_snapshot(deadline=cutoff).values()
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
            # A successful command may not buy more metadata time at finality.
            # Failed-command cleanup uses its original stop timestamp, not a
            # fresh allowance; neither path extends the aggregate endpoint.
            final_cutoff = min(self.deadline, stop_at + 8) if stop_at is not None else cutoff
            if child is not None:
                try:
                    if child.poll() is None:
                        child.kill()  # Still-owned original Popen only.
                except BaseException as exc:
                    errors.append(f"original child stop {type(exc).__name__}")
                try:
                    code = child.wait(timeout=max(0.0, min(2, final_cutoff - time.monotonic())))
                    waited = True
                except BaseException as exc:
                    errors.append(f"original child wait {type(exc).__name__}")
                if failure is not None and not cleanup_done:
                    errors.extend(self._cleanup(deadline=final_cutoff))
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
                finality = waited and not _domain(self.platform, self.uid, deadline=final_cutoff)
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
            raw = _small_command([str(self.python), "-I", "-S", "-B", str(self.entry), "--nss", str(self.uid)],
                                 deadline=self.deadline)
            if raw != b"MRK_NSS_ABSENT\n" or _domain(self.platform, self.uid, collision=True, deadline=self.deadline):
                raise SessionError("numeric identity collision or incomplete admission")
            if self.platform == "linux":
                self._prepare_provider_runtime()
            tools = {}
            tools_note = {"name": "fixed-entry-tools", "ok": False, "tools": tools}
            self.admission_results.append(tools_note)
            roles = [("python", self.python, {}),
                     ("sudo", Path("/usr/bin/sudo"), {"root_owned": True, "non_set_id": False}),
                     ("true", Path("/usr/bin/true"), {"root_owned": True})]
            if self.platform == "darwin":
                # Only root's census executes this original system ps.  Record
                # actual image metadata without presuming why sandboxed exec failed.
                roles += [("sandbox-exec", Path("/usr/bin/sandbox-exec"), {"root_owned": True}),
                          ("ps", Path("/bin/ps"), {"root_owned": True, "non_set_id": False})]
            for role, path, options in roles:
                try:
                    tools[role] = _admit_executable(path, self.uid, self.gid, role=role, **options)
                except BaseException as exc:
                    tools_note["failed_role"] = role
                    # Admission's own rejection carries the same successful stat,
                    # never a replacement read or invented metadata on stat error.
                    observation = getattr(exc, "_ci_observation", None)
                    if isinstance(exc, SessionError) and isinstance(observation, dict) and set(observation) == {"tool"}:
                        tools[role] = observation["tool"]
                    raise
            tools_note["ok"] = True
            os.chown(self.work, self.uid, self.gid)
            for name in ("home", "tmp", "config", "cache"):
                p = self.work / name
                p.mkdir(mode=0o700)
                os.chown(p, self.uid, self.gid)
            if self.platform == "darwin":
                self._prepare_home_boundary()
            self._preflight()
            self.ensure_idle()
            if self.platform == "darwin":
                self._admit_process_observer()
                self.ensure_idle()
            self.admitted = True
        except BaseException as exc:
            # Preparation may already have passed its own native controls, but
            # the final outer admission boundary still owns publication.  Keep
            # those subcontrol facts and revoke this attempt's aggregate claim.
            self.admitted = False
            self.process_observer = None
            for row in self.admission_results:
                if row["name"] == "process-observer":
                    row["ok"] = False
            self.admission_results.append({"name": "native-admission-failure", "ok": False,
                                           "exceptions": _exception_notes(exc)})
            self._fail("native isolation admission failed; no product command permitted")
            raise
        finally:
            self._admitting = False

    def _prepare_provider_runtime(self) -> None:
        """Root-only selected Linux provider preparation; no child module import."""
        if self.platform != "linux" or sys.platform != "linux" or os.geteuid() != 0:
            raise SessionError("provider preparation requires the native root owner")
        self.ensure_idle()
        _remaining(self.deadline)
        python_prefix = _canonical(sys.base_prefix)
        ruby_prefix = self.ruby.parent.parent
        remaining = [p for p in self.tool_prefixes if p not in {python_prefix, ruby_prefix}]
        if (python_prefix not in self.tool_prefixes or ruby_prefix not in self.tool_prefixes
                or not _under(self.python, python_prefix) or len(remaining) != 1):
            raise SessionError("selected provider prefix roles are incomplete or ambiguous")
        prefixes = (("python", python_prefix), ("ruby", ruby_prefix), ("jdk", remaining[0]))
        # Only this root admission method loads the immutable provider-only
        # source. The one-file copied bootstrap and every child role stay intact.
        report = {"name": "provider-runtime-permissions", "ok": False}
        self.admission_results.append(report)
        try:
            import importlib.util
            name = "_mrk_ci_provider_runtime"
            if name in sys.modules:
                raise SessionError("provider preparation module already has an owner")
            spec = importlib.util.spec_from_file_location(name, self.source / ".github/scripts/ci_provider_runtime.py")
            if spec is None or spec.loader is None:
                raise SessionError("immutable provider preparation module unavailable")
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            spec.loader.exec_module(module)
            _remaining(self.deadline)
            module.protect_selected_runtimes(prefixes, uid=self.uid, gid=self.gid,
                                            deadline=self.deadline, report=report)
            _remaining(self.deadline)
            if report.get("ok") is not True:
                raise SessionError("selected provider preparation did not complete")
        except BaseException:
            report["ok"] = False  # Preserve module counts, revoke any late aggregate claim.
            raise

    def _check_home_pin(self, mode: int) -> None:
        state = self._home_state
        _remaining(self.deadline)
        pinned = os.fstat(state["pin"])
        _remaining(self.deadline)
        named = self.runner_home.lstat()
        if (state["original"] is None or _home_node(pinned) != _home_node(state["original"])
                or _home_node(named) != _home_node(pinned)
                or stat.S_IMODE(pinned.st_mode) != mode or stat.S_IMODE(named.st_mode) != mode):
            raise SessionError("owned HOME pin/path identity or mode drifted")
        _remaining(self.deadline)

    def _check_ruby_sibling_pin(self, home_mode: int) -> None:
        """Separate parent-FD custody, even when the sibling's parent is HOME."""
        state = self._home_state
        parent = self.ruby_ancestors[-1]
        _remaining(self.deadline)
        _canonical(parent)
        _remaining(self.deadline)
        pinned = os.fstat(state["sibling_pin"])
        _remaining(self.deadline)
        named = parent.lstat()
        mode = home_mode if parent == self.runner_home else state["sibling_parent_mode"]
        if (state["sibling_parent_original"] is None
                or _home_node(pinned) != _home_node(state["sibling_parent_original"])
                or _home_node(named) != _home_node(pinned)
                or stat.S_IMODE(pinned.st_mode) != mode or stat.S_IMODE(named.st_mode) != mode):
            raise SessionError("owned Ruby sibling parent pin/path identity or mode drifted")
        _remaining(self.deadline)

    def _prepare_home_boundary(self) -> None:
        """One disposable-VM HOME search bit; retain all custody before effects."""
        if (self.platform != "darwin" or sys.platform != "darwin" or os.geteuid() != 0
                or self._home_state is not None):
            raise SessionError("invalid or repeated HOME preparation")
        if not _under(self.ruby, self.runner_home):
            raise SessionError("reviewed HOME preparation requires selected Ruby beneath HOME")
        self.ensure_idle()
        self._check_ruby_ancestors()
        canary, endpoint = _home_paths(self.runner_home, self.root)
        sibling = _ruby_sibling_path(self.runner_home, self.ruby_prefix, self.root)
        if any(_under(p, prefix) for p in (canary, endpoint, sibling) for prefix in self.tool_prefixes):
            raise SessionError("synthetic HOME controls overlap a runtime exclusion")
        state = {"pin": None, "original": None, "change_attempted": False, "prepared": False,
                 "expected_mode": None, "canary_fd": None, "canary_name": canary.name,
                 "canary_create_attempted": False, "canary_identity": None, "canary_mode": 0o600,
                 "listener": None, "socket_name": endpoint.name, "socket_bind_attempted": False,
                 "socket_identity": None, "socket_mode": None, "sibling_pin": None,
                 "sibling_parent_original": None, "sibling_parent_mode": None,
                 "sibling_fd": None, "sibling_name": sibling.name, "sibling_create_attempted": False,
                 "sibling_identity": None, "sibling_mode": 0o600, "closed": False}
        self._home_state = state
        note = {"name": "home-search-preparation", "ok": False, "change_attempted": False,
                "change_verified": False}
        self.admission_results.append(note)
        _remaining(self.deadline)
        before = self.runner_home.lstat()
        _remaining(self.deadline)
        state["pin"] = os.open(self.runner_home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        _remaining(self.deadline)
        original = os.fstat(state["pin"])
        state["original"] = original
        _remaining(self.deadline)
        mode = stat.S_IMODE(original.st_mode)
        if (not stat.S_ISDIR(original.st_mode) or original.st_uid == self.uid or original.st_gid == self.gid
                or mode not in {0o750, 0o751, 0o755} or _home_node(before) != _home_node(original)
                or stat.S_IMODE(before.st_mode) != mode):
            raise SessionError("configured HOME does not match the reviewed pinned directory state")
        note["original_mode"] = format(mode, "04o")
        state["expected_mode"] = 0o751 if mode == 0o750 else mode
        self._check_home_pin(mode)
        if mode == 0o750:
            state["change_attempted"] = note["change_attempted"] = True
            os.fchmod(state["pin"], 0o751)
        self._check_home_pin(state["expected_mode"])
        state["prepared"] = True
        note["change_verified"] = state["change_attempted"]
        note["prepared_mode"] = format(state["expected_mode"], "04o")

        # An independent descriptor owns this parent. Never alias HOME's FD or
        # change an ancestor mode to make the new synthetic control usable.
        self._check_ruby_ancestors(home_mode=state["expected_mode"])
        parent = self.ruby_ancestors[-1]
        _remaining(self.deadline)
        before = parent.lstat()
        _remaining(self.deadline)
        state["sibling_pin"] = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        _remaining(self.deadline)
        pinned = os.fstat(state["sibling_pin"])
        state["sibling_parent_original"] = pinned
        state["sibling_parent_mode"] = stat.S_IMODE(pinned.st_mode)
        _remaining(self.deadline)
        expected_parent = self._ruby_ancestor_states[-1]
        expected_mode = state["expected_mode"] if parent == self.runner_home else stat.S_IMODE(expected_parent.st_mode)
        if (not stat.S_ISDIR(pinned.st_mode) or _home_node(pinned) != _home_node(expected_parent)
                or _home_node(before) != _home_node(pinned) or stat.S_IMODE(before.st_mode) != expected_mode
                or state["sibling_parent_mode"] != expected_mode):
            raise SessionError("synthetic Ruby sibling parent lost its admitted identity/mode")
        self._check_ruby_sibling_pin(state["expected_mode"])

        _remaining(self.deadline)
        state["canary_create_attempted"] = True
        state["canary_fd"] = os.open(canary.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                    0o600, dir_fd=state["pin"])
        _remaining(self.deadline)
        created = os.fstat(state["canary_fd"])
        _remaining(self.deadline)
        # Darwin may inherit HOME's ordinary group; preserve it, never adopt U.
        if (not stat.S_ISREG(created.st_mode) or created.st_uid != 0 or created.st_gid == self.gid
                or created.st_nlink != 1 or stat.S_IMODE(created.st_mode) != 0o600 or created.st_size):
            raise SessionError("new synthetic HOME file lacks exclusive creation identity")
        state["canary_identity"] = created
        if os.write(state["canary_fd"], _HOME_READ_BYTES) != len(_HOME_READ_BYTES):
            raise SessionError("synthetic HOME file write was incomplete")
        _remaining(self.deadline)
        os.fsync(state["canary_fd"])
        _remaining(self.deadline)
        state["canary_mode"] = None
        os.fchmod(state["canary_fd"], 0o444)
        _remaining(self.deadline)
        current = os.fstat(state["canary_fd"])
        _remaining(self.deadline)
        if (_home_node(current) != _home_node(created) or current.st_nlink != 1
                or stat.S_IMODE(current.st_mode) != 0o444 or current.st_size != len(_HOME_READ_BYTES)):
            raise SessionError("synthetic HOME file persistence/mode is not verified")
        state["canary_mode"] = 0o444
        self._check_home_pin(state["expected_mode"])

        self._check_ruby_sibling_pin(state["expected_mode"])
        _remaining(self.deadline)
        state["sibling_create_attempted"] = True
        state["sibling_fd"] = os.open(sibling.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     0o600, dir_fd=state["sibling_pin"])
        _remaining(self.deadline)
        created = os.fstat(state["sibling_fd"])
        _remaining(self.deadline)
        if (not stat.S_ISREG(created.st_mode) or created.st_uid != 0 or created.st_gid == self.gid
                or created.st_nlink != 1 or stat.S_IMODE(created.st_mode) != 0o600 or created.st_size):
            raise SessionError("new synthetic Ruby sibling lacks exclusive creation identity")
        state["sibling_identity"] = created
        if os.write(state["sibling_fd"], _ANCESTOR_READ_BYTES) != len(_ANCESTOR_READ_BYTES):
            raise SessionError("synthetic Ruby sibling write was incomplete")
        _remaining(self.deadline)
        os.fsync(state["sibling_fd"])
        _remaining(self.deadline)
        state["sibling_mode"] = None
        os.fchmod(state["sibling_fd"], 0o444)
        _remaining(self.deadline)
        current = os.fstat(state["sibling_fd"])
        _remaining(self.deadline)
        if (_home_node(current) != _home_node(created) or current.st_nlink != 1
                or stat.S_IMODE(current.st_mode) != 0o444 or current.st_size != len(_ANCESTOR_READ_BYTES)):
            raise SessionError("synthetic Ruby sibling persistence/mode is not verified")
        state["sibling_mode"] = 0o444
        self._check_ruby_sibling_pin(state["expected_mode"])

        state["listener"] = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        state["listener"].settimeout(min(2, _remaining(self.deadline)))
        _remaining(self.deadline)
        state["socket_bind_attempted"] = True
        state["listener"].bind(str(endpoint))  # No unlink, adoption or conflict retry.
        _remaining(self.deadline)
        node = os.stat(endpoint.name, dir_fd=state["pin"], follow_symlinks=False)
        _remaining(self.deadline)
        if not stat.S_ISSOCK(node.st_mode) or node.st_uid != 0 or node.st_gid == self.gid or node.st_nlink != 1:
            raise SessionError("new synthetic HOME listener lacks its own node identity")
        state["socket_identity"] = node
        state["socket_mode"] = stat.S_IMODE(node.st_mode)
        self._check_home_pin(state["expected_mode"])
        state["socket_mode"] = None
        os.chmod(endpoint, 0o666, follow_symlinks=False)  # Only this created synthetic socket, never HOME.
        _remaining(self.deadline)
        after = os.stat(endpoint.name, dir_fd=state["pin"], follow_symlinks=False)
        _remaining(self.deadline)
        if _home_node(after) != _home_node(node) or after.st_nlink != 1 or stat.S_IMODE(after.st_mode) != 0o666:
            raise SessionError("synthetic HOME listener node changed")
        state["socket_mode"] = 0o666
        state["listener"].listen(8)
        _remaining(self.deadline)
        _private_file(self.bootstrap / "home-control.json", json.dumps({"home": str(self.runner_home),
                      "ruby_prefix": str(self.ruby_prefix),
                      "uid": self.uid, "gid": self.gid, "deadline": self.deadline}).encode(), 0o444)
        _remaining(self.deadline)
        note["ok"] = True  # Preparation only; genuine mandatory controls still follow.

    def _home_positive_control(self) -> None:
        """Trusted fixed U code outside policy proves DAC is not the negative."""
        state = self._home_state
        if (state is None or not state["prepared"] or state["listener"] is None
                or state["sibling_identity"] is None or state["sibling_mode"] != 0o444):
            raise SessionError("owned HOME controls are not prepared")
        self.ensure_idle()
        self._check_ruby_ancestors(home_mode=state["expected_mode"])
        self._check_home_pin(state["expected_mode"])
        self._check_ruby_sibling_pin(state["expected_mode"])
        raw = _small_command([str(self.python), "-I", "-S", "-B", str(self.entry), "--home-positive"],
                             10, user=self.uid, group=self.gid, deadline=self.deadline)
        if raw != b"MRK_HOME_POSITIVE_OK\n":
            raise SessionError("fixed HOME DAC positive did not complete")
        self.ensure_idle()
        accepted, errors, data = None, [], bytearray()
        try:
            state["listener"].settimeout(min(2, _remaining(self.deadline)))
            accepted, _ = state["listener"].accept()
            while True:
                accepted.settimeout(min(2, _remaining(self.deadline)))
                chunk = accepted.recv(len(_HOME_SOCKET_BYTES) + 1 - len(data))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > len(_HOME_SOCKET_BYTES):
                    raise SessionError("synthetic HOME positive delivery exceeds literal bound")
            if bytes(data) != _HOME_SOCKET_BYTES:
                raise SessionError("synthetic HOME positive delivery was not observed")
        except BaseException as exc:
            errors.append(exc)
        if accepted is not None:
            try:
                accepted.close()
            except BaseException as exc:
                errors.append(exc)
        try:
            _remaining(self.deadline)
        except BaseException as exc:
            errors.append(exc)
        if errors:
            raise BaseExceptionGroup("fixed HOME positive/accepted-connection close failed", errors)
        self.admission_results.append({"name": "home-DAC-and-delivery-positive", "ok": True})

    def _close_home_boundary(self) -> list[BaseException]:
        """Finality-gated exact restore/removal; close every owned handle once."""
        state = getattr(self, "_home_state", None)
        if state is None or state["closed"]:
            return []
        state["closed"] = True
        errors = []
        note = {"name": "home-boundary-finalization", "ok": False, "restored": False,
                "canary_removed": False, "socket_removed": False, "sibling_removed": False,
                "unverified_creation": []}
        self.admission_results.append(note)
        for kind, attempt_key, identity_key in (
                ("canary", "canary_create_attempted", "canary_identity"),
                ("socket", "socket_bind_attempted", "socket_identity"),
                ("sibling", "sibling_create_attempted", "sibling_identity")):
            if state[attempt_key] and state[identity_key] is None:
                note["unverified_creation"].append(kind)
                errors.append(SessionError("synthetic HOME creation after-effect lacks owned identity"))
        eligible = False
        try:
            _remaining(self.deadline)
            if (self._busy or self._active is not None or not self.domain_finality
                    or _domain(self.platform, self.uid, deadline=self.deadline)):
                raise SessionError("HOME restoration has no genuine producer/domain finality")
            if not state["prepared"]:
                raise SessionError("HOME preparation after-effect is not verified")
            self._check_home_pin(state["expected_mode"])
            eligible = True
        except BaseException as exc:
            errors.append(exc)
        if eligible:
            final_mode = state["expected_mode"]
            try:
                if state["change_attempted"]:
                    _remaining(self.deadline)
                    os.fchmod(state["pin"], stat.S_IMODE(state["original"].st_mode))
                    self._check_home_pin(stat.S_IMODE(state["original"].st_mode))
                    final_mode = stat.S_IMODE(state["original"].st_mode)
                    note["restored"] = True
            except BaseException as exc:
                eligible = False  # Uncertain restoration cannot authorize another path mutation.
                errors.append(exc)
        if eligible:
            for kind, identity_key, mode_key, name_key in (
                    ("canary", "canary_identity", "canary_mode", "canary_name"),
                    ("socket", "socket_identity", "socket_mode", "socket_name")):
                if state[identity_key] is None:
                    continue
                try:
                    self._check_home_pin(final_mode)
                    current = os.stat(state[name_key], dir_fd=state["pin"], follow_symlinks=False)
                    _remaining(self.deadline)
                    if (_home_node(current) != _home_node(state[identity_key]) or current.st_nlink != 1
                            or state[mode_key] is None or stat.S_IMODE(current.st_mode) != state[mode_key]):
                        raise SessionError("synthetic HOME node replacement/mode forbids removal")
                    os.unlink(state[name_key], dir_fd=state["pin"])
                    note[kind + "_removed"] = True
                    _remaining(self.deadline)
                except BaseException as exc:
                    errors.append(exc)
            if state["sibling_identity"] is not None:
                try:
                    self._check_home_pin(final_mode)
                    self._check_ruby_sibling_pin(final_mode)
                    current = os.stat(state["sibling_name"], dir_fd=state["sibling_pin"], follow_symlinks=False)
                    _remaining(self.deadline)
                    if (_home_node(current) != _home_node(state["sibling_identity"]) or current.st_nlink != 1
                            or state["sibling_mode"] is None or stat.S_IMODE(current.st_mode) != state["sibling_mode"]):
                        raise SessionError("synthetic Ruby sibling replacement/mode forbids removal")
                    os.unlink(state["sibling_name"], dir_fd=state["sibling_pin"])
                    note["sibling_removed"] = True
                    _remaining(self.deadline)
                except BaseException as exc:
                    errors.append(exc)
        # Local resource closure is always safe, even when no path mutation is.
        for key in ("listener", "sibling_fd", "canary_fd", "sibling_pin", "pin"):
            owned, state[key] = state[key], None
            if owned is None:
                continue
            try:
                owned.close() if key == "listener" else os.close(owned)
            except BaseException as exc:
                errors.append(exc)
        try:
            _remaining(self.deadline)
        except BaseException as exc:
            errors.append(exc)
        note["ok"] = not errors
        if errors:
            note["exceptions"] = _exception_notes(BaseExceptionGroup("HOME owned finalization failed", errors))
        return errors

    def _admit_process_observer(self) -> None:
        """Prepare as U only after base native controls; publish last, once."""
        if self.platform != "darwin" or self.process_observer is not None:
            raise SessionError("duplicate/unsupported process observer preparation")
        self.ensure_idle()
        tools = _observer_toolchain(self.uid, self.gid, deadline=self.deadline)
        arch = os.uname().machine
        if arch not in {"arm64", "x86_64"}:
            raise SessionError("unsupported native observer architecture")
        source = self.source / ".github/scripts/ci_process_observer.c"
        source_bytes = source.read_bytes()
        if not 0 < len(source_bytes) <= 65536:
            raise SessionError("immutable observer C source exceeds fixed bound")
        output, frozen = self.work / "process-observer", self.bootstrap / "process-observer"
        for path in (output, frozen):
            try:
                path.lstat()
            except FileNotFoundError:
                continue
            raise SessionError("observer output would overwrite an existing name")

        def checked_run(name: str, argv: list[str], seconds: int = 15) -> tuple[CapturedRun, dict]:
            result = self._run(argv, cwd=self.work,
                               env={"DEVELOPER_DIR": "/Applications/Xcode_26.3.app/Contents/Developer"},
                               seconds=seconds, cpu_seconds=60, output_limit=65536, latch=False)
            note = self._note_capture(name, result)
            if name == "process-observer-build":
                note["compiler_diagnostics"] = _observer_build_notes(result.stderr, source)
            if not result.ok:
                raise SessionError("observer preparation command lacks genuine successful finality")
            self.ensure_idle()
            _remaining(self.deadline)
            return result, note  # Semantic acceptance belongs to the caller below.

        version, version_note = checked_run("process-observer-compiler", [str(tools["clang"]), "--no-default-config", "--version"])
        version_lines = version.stdout.decode("ascii", "strict").splitlines()
        if (version.stderr or not 1 <= len(version_lines) <= 8
                or not re.fullmatch(r"Apple clang version [A-Za-z0-9 ._()+-]{1,160}", version_lines[0])
                or any(len(line) > 1024 or any(ord(c) < 32 for c in line) for line in version_lines)):
            raise SessionError("selected compiler version evidence is unsupported")
        version_note["ok"] = True
        command = [str(tools["clang"]), "--no-default-config", "-fno-modules", "-std=c11",
                   "-D_DARWIN_C_SOURCE", "-O2", "-Wall", "-Wextra", "-Werror", "-arch", arch,
                   "-isysroot", str(tools["sdk"]), "-B", str(tools["toolchain"] / "usr/bin"),
                   "-Wl,-adhoc_codesign", str(source), "-lproc", "-o", str(output)]
        compiled, build_note = checked_run("process-observer-build", command, 120)
        if compiled.stdout or compiled.stderr:
            raise SessionError("fixed observer compiler emitted unexpected diagnostics")
        # No produced file is opened before the compiler's actual finality.
        binary, producer_mode = _observer_artifact(output, self.uid, self.gid, deadline=self.deadline)
        build_note["ok"] = True
        verified, validity_note = checked_run("process-observer-signature-validity", ["/usr/bin/codesign", "--verify", "--strict", str(output)])
        if verified.stdout or verified.stderr:
            raise SessionError("observer signature verification emitted diagnostics")
        validity_note["ok"] = True
        display, display_note = checked_run("process-observer-signature-display", ["/usr/bin/codesign", "--display", "--verbose=2", str(output)])
        signing = _observer_signature_metadata(display.stdout, display.stderr, output, arch)
        display_note["ok"] = True
        entitlements, entitlement_note = checked_run("process-observer-entitlements", ["/usr/bin/codesign", "--display", "--entitlements", "-", "--xml", str(output)])
        if entitlements.stdout or entitlements.stderr not in (b"", f"Executable={output}\n".encode()):
            raise SessionError("observer has entitlements or unsupported extraction diagnostics")
        entitlement_note["ok"] = True
        # The documented empty display means none only after actual successful
        # strict validation/display, own waits, both EOFs and outside finality.
        self.ensure_idle()
        if _observer_artifact(output, self.uid, self.gid, deadline=self.deadline) != (binary, producer_mode):
            raise SessionError("observer bytes/mode changed across read-only signature validation")
        _remaining(self.deadline)
        _readonly_tree(self.bootstrap)
        _private_file(frozen, binary, 0o555)
        os.chown(frozen, 0, 0)
        frozen_bytes, frozen_mode = _observer_artifact(frozen, 0, 0, deadline=self.deadline)
        if frozen_bytes != binary or frozen_mode != 0o555:
            raise SessionError("observer immutable bootstrap copy differs")
        _readonly_tree(self.bootstrap)
        self._observer_native_controls(frozen)
        self.ensure_idle()
        _remaining(self.deadline)
        self.process_observer = frozen  # No caller-selected or pre-admission path.
        self.admission_results.append({"name": "process-observer", "ok": True,
                                       "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
                                       "binary_sha256": hashlib.sha256(binary).hexdigest(),
                                       "compiler_version": version_lines[0], "tools": tools["evidence"],
                                       "producer_mode": format(producer_mode, "04o"), "mode": "0555",
                                       **signing, "entitlements": "none"})

    def _observer_native_controls(self, candidate: Path) -> None:
        """Root owns only its fixed foreign sentinel; it never runs the reader."""
        if candidate != self.bootstrap / "process-observer":
            raise SessionError("native observer candidate is not the fixed bootstrap file")
        cutoff = min(self.deadline, time.monotonic() + 30)
        sentinel, errors = None, []
        try:
            _remaining(cutoff)
            sentinel = subprocess.Popen([str(self.python), "-I", "-S", "-B", str(self.entry), "--sentinel"],
                                        cwd=self.work, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        close_fds=True, start_new_session=True, bufsize=0)
            if _ready_line(sentinel.stdout, min(5, _remaining(cutoff))) != b"MRK_SENTINEL_READY\n":
                raise SessionError("owned foreign observer control did not become ready")
            _observe_original_credentials(sentinel.pid, 0, os.getgid(), deadline=cutoff)
            probe_cutoff = min(cutoff, time.monotonic() + 20)
            result = self._run([str(self.python), "-I", "-S", "-B", str(self.entry),
                                "--observer-probe", str(candidate), str(sentinel.pid), repr(probe_cutoff)],
                               cwd=self.work, env={}, seconds=_remaining(probe_cutoff), latch=False)
            note = self._note_capture("process-observer-native", result)
            if not result.ok or result.stdout != b"MRK_PROCESS_OBSERVER_OK\n" or result.stderr:
                raise SessionError("native process observer controls failed")
            self.ensure_idle()
            out, err = sentinel.communicate(b"q", timeout=min(2, _remaining(cutoff)))
            if sentinel.returncode != 0 or out != b"MRK_SENTINEL_CLOSED\n" or err:
                raise SessionError("owned foreign observer control did not close genuinely")
            _remaining(cutoff)
        except BaseException as exc:
            errors.append(exc)
        if sentinel is not None:
            try:
                if sentinel.poll() is None:
                    sentinel.kill()  # This original root handle only, never a census PID.
            except BaseException as exc:
                errors.append(exc)
            try:
                if type(sentinel.wait(timeout=max(0.0, min(2, cutoff - time.monotonic())))) is not int:
                    raise SessionError("owned foreign observer control has no original cleanup wait")
            except BaseException as exc:
                errors.append(exc)
            for stream in (sentinel.stdin, sentinel.stdout, sentinel.stderr):
                try:
                    stream.close()
                except BaseException as exc:
                    errors.append(exc)
        try:
            self.ensure_idle()
            _remaining(cutoff)
        except BaseException as exc:
            errors.append(exc)
        if errors:
            raise BaseExceptionGroup("observer native controls/owned foreign cleanup failed", errors)
        note["ok"] = True  # Includes every original wait/EOF/close and final cutoff.

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
        if self.platform == "darwin" and name == "ruby-numerical-identity":
            ruby_error = _ruby_launch_error(result, self.ruby)
            if ruby_error is not None:
                row["launcher_error"] = ruby_error
            startup_error = _ruby_startup_error(result, self.ruby)
            if startup_error is not None:
                row["ruby_startup_error"] = startup_error
        self.admission_results.append(row)
        return row

    def _ruby_path_metadata(self) -> None:
        """Observe the already-canonical provider path; grant no access or launch."""
        row = {"name": "ruby-path-metadata", "ok": False,
               "semantics": "posix-mode-bits-only", "entries": []}
        self.admission_results.append(row)
        _remaining(self.deadline)
        parents = tuple(self.ruby.parents)
        if len(parents) > 32:
            raise SessionError("fixed Ruby ancestor metadata exceeds bound")
        for index, path in enumerate((self.ruby, *parents)):
            row["unobserved_index"] = index
            _remaining(self.deadline)
            info = path.stat()
            row["entries"].append({"index": index, **_tool_stat_note(info, self.uid, self.gid, role="ruby")})
            del row["unobserved_index"]
            _remaining(self.deadline)
        row["ok"] = True

    def _preflight(self) -> None:
        listeners, addresses = [], []
        failures = []
        try:
            if self.platform == "darwin":
                self._home_positive_control()
            # This grant is AFTER complete numerical collision admission.  It
            # is a single synthetic UID-owned0600 file, not a group capability.
            os.chown(self.outside_write, self.uid, self.gid)
            positive = self._trusted_entry(self.write_policy, ["--write-control", str(self.outside_write)])
            out = _small_command(positive, 10, user=self.uid, group=self.gid, deadline=self.deadline)
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
                data["runtime_executables"] = [str(self.python), str(self.ruby)]
            else:
                canary, endpoint = _home_paths(self.runner_home, self.root)
                data["home_canary"], data["home_socket"] = str(canary), str(endpoint)
                data["ruby_prefix"], data["ruby_executable"] = str(self.ruby_prefix), str(self.ruby)
                data["home_sibling"] = str(_ruby_sibling_path(self.runner_home, self.ruby_prefix, self.root))
            base = [str(self.python), "-I", "-S", "-B", str(self.entry)]
            good = self._run([*base, "--probe", json.dumps(data)], cwd=self.work, env={}, seconds=30, latch=False)
            native_note = self._note_capture("native-isolation", good)
            if not good.ok or good.stdout != b"MRK_NATIVE_ISOLATION_OK\n":
                raise SessionError("native credentials/files/FD/network inheritance preflight failed")
            self.ensure_idle()
            _outside_network_empty(listeners, deadline=self.deadline)
            if self.platform == "darwin":
                _home_socket_empty(self._home_state["listener"], deadline=self.deadline)
            # Revoke this synthetic positive grant before any product command.
            # Failed/unknown writers never reach this filesystem postcondition.
            os.chown(self.outside_write, 0, 0)
            self.outside_write.chmod(0o400)
            native_note["ok"] = True
            self._ruby_path_metadata()  # Observation only; the actual probe still decides.
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
                                 10, user=self.uid, group=self.gid, deadline=self.deadline)
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
                             10, expected_code=23, deadline=self.deadline)
        fields = raw.split()
        if len(fields) != 2 or fields[0] != b"MRK_OWNER_LOST" or not fields[1].isdigit():
            raise SessionError("lost-owner negative control has no genuine owner observation")
        observed_child = int(fields[1])  # Observation only; never signal authority.
        errors = self._cleanup()
        # Observation may raise next; never lose earlier independent cleanup
        # diagnostics or copy them again at the ordinary unsuccessful tail.
        self.cleanup_errors.extend(errors)
        cutoff = min(self.deadline, time.monotonic() + 5)
        while time.monotonic() < cutoff:
            rows = _snapshot(self.platform, deadline=cutoff, retry_churn=True)
            if all(pid != observed_child for pid, _ in rows) and not _domain(self.platform, self.uid, deadline=cutoff):
                break
            time.sleep(min(0.05, _remaining(cutoff)))
        else:
            reason = "lost-owner platform cleanup remained unknown or incomplete"
            errors.append(reason)
            self.cleanup_errors.append(reason)
        if errors:
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
                self.domain_finality = (not self._busy and self._active is None
                                        and not _domain(self.platform, self.uid, deadline=self.deadline))
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
            try:
                home_errors = self._close_home_boundary()
                if home_errors:
                    self.cleanup_errors.extend(f"HOME finalization {type(exc).__name__}" for exc in home_errors)
                    self._fail("owned HOME finalization failed")
            except BaseException as exc:
                self.cleanup_errors.append(f"HOME finalization {type(exc).__name__}")
                self._fail("owned HOME finalization failed")
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


def _home_positive() -> None:
    """Fixed unprivileged synthetic HOME controls; no command/path arguments."""
    if (sys.platform != "darwin" or not 60000 <= os.getuid() < 65000
            or os.getuid() != os.geteuid() or os.getgid() != os.getuid() or os.getegid() != os.getgid()):
        raise SessionError("invalid fixed HOME positive role")
    _limits("darwin", 10)
    bootstrap = Path(__file__).resolve().parent
    fds, peer, errors, deadline = [], None, [], None
    try:
        fd = os.open(bootstrap / "home-control.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        fds.append(fd)
        state = os.fstat(fd)
        if (not stat.S_ISREG(state.st_mode) or state.st_uid != 0 or state.st_gid != 0
                or state.st_nlink != 1 or stat.S_IMODE(state.st_mode) != 0o444 or not 0 < state.st_size <= 16384):
            raise SessionError("fixed HOME manifest is not immutable bounded control")
        raw = os.read(fd, 16385)
        if len(raw) != state.st_size or os.read(fd, 1):
            raise SessionError("fixed HOME manifest read is incomplete")
        data = json.loads(raw)
        if (not isinstance(data, dict) or set(data) != {"home", "ruby_prefix", "uid", "gid", "deadline"}
                or type(data["uid"]) is not int or type(data["gid"]) is not int
                or (data["uid"], data["gid"]) != (os.getuid(), os.getgid())
                or not isinstance(data["home"], str) or not isinstance(data["ruby_prefix"], str)
                or _process_groups("darwin") != [os.getgid()]):
            raise SessionError("fixed HOME manifest lacks numerical owner binding")
        deadline = data["deadline"]
        _remaining(deadline)
        home = _canonical(data["home"])
        _remaining(deadline)
        prefix = _canonical(data["ruby_prefix"])
        _remaining(deadline)
        canary, endpoint = _home_paths(home, bootstrap.parent)
        sibling = _ruby_sibling_path(home, prefix, bootstrap.parent)
        for path, expected in ((canary, _HOME_READ_BYTES), (sibling, _ANCESTOR_READ_BYTES)):
            _remaining(deadline)
            named = os.stat(path, follow_symlinks=False)  # Genuine known-name metadata positive.
            _remaining(deadline)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            fds.append(fd)  # Custody precedes every subsequent fallible operation.
            _remaining(deadline)
            state = os.fstat(fd)
            _remaining(deadline)
            if (not stat.S_ISREG(state.st_mode) or state.st_uid != 0 or state.st_gid == os.getgid()
                    or state.st_nlink != 1 or stat.S_IMODE(state.st_mode) != 0o444
                    or state.st_size != len(expected) or _home_node(named) != _home_node(state)
                    or named.st_nlink != 1 or stat.S_IMODE(named.st_mode) != 0o444 or named.st_size != len(expected)):
                raise SessionError("synthetic HOME/sibling file lacks exact DAC-positive state")
            if os.read(fd, len(expected) + 1) != expected or os.read(fd, 1):
                raise SessionError("synthetic HOME/sibling file was not genuinely read")
            _remaining(deadline)
        peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        peer.settimeout(min(2, _remaining(deadline)))
        peer.connect(str(endpoint))
        peer.settimeout(min(2, _remaining(deadline)))
        peer.sendall(_HOME_SOCKET_BYTES)
        _remaining(deadline)
    except BaseException as exc:
        errors.append(exc)
    if peer is not None:
        try:
            peer.close()
        except BaseException as exc:
            errors.append(exc)
    for fd in reversed(fds):
        try:
            os.close(fd)
        except BaseException as exc:
            errors.append(exc)
    if deadline is not None:
        try:
            _remaining(deadline)
        except BaseException as exc:
            errors.append(exc)
    if errors:
        raise BaseExceptionGroup("fixed HOME positive/owned close failed", errors)
    print("MRK_HOME_POSITIVE_OK", flush=True)


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


def _observer_query(observer: Path, pid: int, group: int | None, *, deadline: float,
                    kernel_denied: bool = False) -> str:
    """Fixed native-control parser; arbitrary product or ps text is not accepted."""
    if sys.platform != "darwin" or os.getuid() == 0:
        raise SessionError("native reader may never execute as root or on a substitute platform")
    raw = _small_command([str(observer), str(pid)], 3, expected_code=2 if kernel_denied else 0,
                         deadline=deadline)
    if len(raw) > 512 or not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise SessionError("native observer record size/framing failed")
    if kernel_denied:
        if raw not in {f"MRK_PROCESS_V1 denied {pid} kernel {number}\n".encode()
                       for number in (errno.EPERM, errno.EACCES)}:
            raise SessionError("foreign native observer result is not actual kernel denial")
        _remaining(deadline)
        return "denied"
    if raw == f"MRK_PROCESS_V1 absent {pid}\n".encode():
        _remaining(deadline)
        return "absent"
    fields = raw[:-1].split(b" ")
    if (len(fields) != 13 or fields[:2] != [b"MRK_PROCESS_V1", b"present"]
            or any(not re.fullmatch(rb"0|[1-9][0-9]{0,9}", part) for part in fields[2:12])):
        raise SessionError("native observer record grammar failed")
    observed, pgid, ru, eu, su, rg, eg, sg, status, exiting = map(int, fields[2:12])
    if (observed != pid or not 1 < pgid < 2**31 or group is not None and pgid != group
            or (ru, eu, su) != (os.getuid(),) * 3 or (rg, eg, sg) != (os.getgid(),) * 3
            or not 0 <= status < 2**32 or exiting not in {0, 1}):
        raise SessionError("native observer record identity/status failed")
    wanted = "zombie" if status == 5 else "live" if status in {2, 3, 4} and not exiting else "indeterminate"
    if fields[12] != wanted.encode():
        raise SessionError("native observer record contradicts BSD state")
    _remaining(deadline)
    return wanted


def _observer_control_eof(child, *, deadline: float) -> None:
    """Drain original fixture pipes WITHOUT reaping its deliberately held zombie."""
    sel, errors = None, []
    data = [bytearray(), bytearray()]
    try:
        sel = selectors.DefaultSelector()
        for i, stream in enumerate((child.stdout, child.stderr)):
            os.set_blocking(stream.fileno(), False)
            sel.register(stream, selectors.EVENT_READ, i)
        while sel.get_map():
            for key, _ in sel.select(min(0.05, _remaining(deadline))):
                try:
                    chunk = os.read(key.fd, 512 - len(data[key.data]) + 1)
                except BlockingIOError:
                    continue
                if not chunk:
                    sel.unregister(key.fileobj)  # Actual EOF, not a closed local read end.
                    continue
                data[key.data].extend(chunk)
                if len(data[key.data]) > 512:
                    raise SessionError("observer fixture output exceeds fixed bound")
        if data != [bytearray(b"MRK_OBSERVER_FAMILY_RELEASED\n"), bytearray()]:
            raise SessionError("observer fixture lacks complete release/EOF evidence")
        _remaining(deadline)
    except BaseException as exc:
        errors.append(exc)
    if sel is not None:
        try:
            sel.close()
        except BaseException as exc:
            errors.append(exc)
    try:
        _remaining(deadline)
    except BaseException as exc:
        errors.append(exc)
    if errors:
        raise BaseExceptionGroup("observer fixture EOF/selector cleanup failed", errors)


def _observer_family(deadline: float) -> None:
    """U fixture is its grandchild's original parent and waits before exiting."""
    if sys.platform != "darwin" or os.getuid() == 0 or os.getuid() != os.geteuid():
        raise SessionError("observer family must remain a native unprivileged fixture")
    child, errors = None, []
    try:
        _remaining(deadline)
        child = subprocess.Popen([sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()), "--sentinel"],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 close_fds=True, bufsize=0)
        if _ready_line(child.stdout, min(3, _remaining(deadline))) != b"MRK_SENTINEL_READY\n":
            raise SessionError("owned observer descendant was not genuinely ready")
        print(f"MRK_OBSERVER_FAMILY {child.pid}", flush=True)
        with selectors.DefaultSelector() as sel:
            sel.register(0, selectors.EVENT_READ)
            if not sel.select(_remaining(deadline)) or os.read(0, 1) != b"q":
                raise SessionError("observer family lost its owned release channel")
        out, err = child.communicate(b"q", timeout=min(3, _remaining(deadline)))
        if child.returncode != 0 or out != b"MRK_SENTINEL_CLOSED\n" or err:
            raise SessionError("observer descendant was not actually waited/drained")
    except BaseException as exc:
        errors.append(exc)
    if child is not None:
        try:
            if child.poll() is None:
                child.kill()  # Own original child only.
        except BaseException as exc:
            errors.append(exc)
        try:
            if type(child.wait(timeout=max(0.0, min(2, deadline - time.monotonic())))) is not int:
                raise SessionError("observer descendant has no original cleanup wait")
        except BaseException as exc:
            errors.append(exc)
        for stream in (child.stdin, child.stdout, child.stderr):
            try:
                stream.close()
            except BaseException as exc:
                errors.append(exc)
    try:
        _remaining(deadline)
    except BaseException as exc:
        errors.append(exc)
    if errors:
        raise BaseExceptionGroup("observer descendant original custody/cleanup failed", errors)
    print("MRK_OBSERVER_FAMILY_RELEASED", flush=True)


def _observer_probe(observer: Path, foreign_pid: int, deadline: float) -> None:
    """All reader invocations are U-owned; a printed PID grants no signal route."""
    if (sys.platform != "darwin" or os.getuid() == 0 or os.getuid() != os.geteuid()
            or os.getgid() != os.getegid() or not 1 < foreign_pid < 2**31
            or observer != Path(__file__).resolve().parent / "process-observer"):
        raise SessionError("invalid native observer probe role")
    child, errors = None, []
    try:
        _remaining(deadline)
        child = subprocess.Popen([sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()),
                                  "--observer-family", repr(deadline)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 close_fds=True, start_new_session=True, bufsize=0)
        ready = _ready_line(child.stdout, min(5, _remaining(deadline)))
        match = re.fullmatch(rb"MRK_OBSERVER_FAMILY ([1-9][0-9]{0,9})\n", ready)
        if match is None:
            raise SessionError("observer family has no actual readiness/control evidence")
        descendant = int(match[1])
        if not 1 < descendant < 2**31 or descendant in {child.pid, foreign_pid, os.getpid()}:
            raise SessionError("observer descendant control identity is invalid")
        for pid in (child.pid, descendant):
            while True:
                state = _observer_query(observer, pid, child.pid, deadline=deadline)
                if state == "live":
                    break
                if state != "indeterminate":
                    raise SessionError("observer live control stopped before observation")
                time.sleep(min(0.01, _remaining(deadline)))
        _observer_query(observer, foreign_pid, None, deadline=deadline, kernel_denied=True)
        if os.write(child.stdin.fileno(), b"q") != 1:
            raise SessionError("observer release write was incomplete")
        child.stdin.close()
        _observer_control_eof(child, deadline=deadline)
        # Keep the strong original Popen handle.  Neither pipe EOF nor launching
        # a separate reader polls/waits this child; its zombie PID stays reserved.
        while True:
            state = _observer_query(observer, child.pid, child.pid, deadline=deadline)
            if state == "zombie":
                break
            if state == "absent":
                raise SessionError("owned child disappeared before actual original reap")
            time.sleep(min(0.01, _remaining(deadline)))
        if child.wait(timeout=_remaining(deadline)) != 0:
            raise SessionError("observer original zombie did not yield genuine successful wait")
        if _observer_query(observer, child.pid, child.pid, deadline=deadline) != "absent":
            raise SessionError("observer original child was not absent after actual reap")
        _remaining(deadline)
    except BaseException as exc:
        errors.append(exc)
    if child is not None:
        try:
            if child.poll() is None:
                child.kill()  # Strongly held original fixture, not returned metadata.
        except BaseException as exc:
            errors.append(exc)
        try:
            if type(child.wait(timeout=max(0.0, min(2, deadline - time.monotonic())))) is not int:
                raise SessionError("observer fixture has no original cleanup wait")
        except BaseException as exc:
            errors.append(exc)
        for stream in (child.stdin, child.stdout, child.stderr):
            try:
                stream.close()
            except BaseException as exc:
                errors.append(exc)
    try:
        _remaining(deadline)
    except BaseException as exc:
        errors.append(exc)
    if errors:
        raise BaseExceptionGroup("observer native original-custody/cleanup controls failed", errors)
    print("MRK_PROCESS_OBSERVER_OK", flush=True)


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


def _probe_network(platform: str, endpoints: list) -> None:
    """Probe only owned loopback endpoints; UDP enqueue is not delivery."""
    expected = {(socket.AF_INET, socket.SOCK_STREAM, "127.0.0.1"),
                (socket.AF_INET, socket.SOCK_DGRAM, "127.0.0.1"),
                (socket.AF_INET6, socket.SOCK_STREAM, "::1"),
                (socket.AF_INET6, socket.SOCK_DGRAM, "::1")}
    if (platform not in {"linux", "darwin"} or not isinstance(endpoints, list) or len(endpoints) != 4
            or any(not isinstance(row, (list, tuple)) or len(row) != 4
                   or not isinstance(row[0], int) or not isinstance(row[1], int) or not isinstance(row[2], str)
                   or type(row[3]) is not int or not 0 < row[3] <= 65535 for row in endpoints)
            or {(row[0], row[1], row[2]) for row in endpoints} != expected):
        raise SessionError("incomplete fixed outside network endpoints")
    if platform == "linux":
        interfaces = socket.if_nameindex()
        if (len(interfaces) != 1 or len(interfaces[0]) != 2
                or type(interfaces[0][0]) is not int or interfaces[0][0] <= 0
                or interfaces[0][1] != "lo"):
            raise SessionError("isolated network namespace has unexpected interfaces")
    for family, kind, host, port in endpoints:
        stream = None
        failures = []
        operation = "network-" + ("tcp" if kind == socket.SOCK_STREAM else "udp") + ("4" if family == socket.AF_INET else "6")
        try:
            stream = socket.socket(family, kind)
            stream.settimeout(0.5)
            if kind == socket.SOCK_STREAM:
                stream.connect((host, port))
                raise SessionError("outside-domain TCP connection was permitted")
            sent = stream.sendto(b"must-not-escape", (host, port))
            if platform != "linux" or sent != len(b"must-not-escape"):
                raise SessionError("outside-domain datagram was not denied or fully enqueued locally")
            # Linux's separate stack/loopback can accept this datagram locally.
            # The outside original owner must separately prove no delivery.
        except OSError as exc:
            allowed = {errno.EACCES, errno.EPERM} if platform == "darwin" else {
                errno.EACCES, errno.EPERM, errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ECONNREFUSED}
            if exc.errno not in allowed:
                failures.append(exc)
        except BaseException as exc:
            failures.append(exc)
        if stream is not None:
            try:
                stream.close()
            except BaseException as exc:
                failures.append(exc)
        if failures:
            error = BaseExceptionGroup("fixed network probe/close failed", failures)
            error._ci_operation = operation
            raise error


def _outside_network_empty(listeners: list, *, deadline: float) -> None:
    """Original owner checks all four receivers AFTER wait, EOF and UID finality."""
    expected = {(family, kind) for family in (socket.AF_INET, socket.AF_INET6)
                for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM)}
    if len(listeners) != 4 or {(s.family, s.type) for s in listeners} != expected:
        raise SessionError("incomplete owned outside receiver inventory")
    failures = []
    for listener in listeners:
        accepted = None
        try:
            _remaining(deadline)
            listener.setblocking(False)
            try:
                if listener.type == socket.SOCK_STREAM:
                    accepted, _address = listener.accept()
                else:
                    listener.recv(1)  # A zero-length datagram is also delivery.
                raise SessionError("owned outside receiver observed prohibited delivery")
            except BlockingIOError as exc:
                if exc.errno not in {errno.EAGAIN, errno.EWOULDBLOCK}:
                    raise
        except BaseException as exc:
            failures.append(exc)
        if accepted is not None:
            try:
                accepted.close()
            except BaseException as exc:
                failures.append(exc)
        if failures and isinstance(failures[-1], DeadlineExpired):
            break
    try:
        _remaining(deadline)
    except BaseException as exc:
        failures.append(exc)
    if failures:
        raise BaseExceptionGroup("outside receiver observation/close failed", failures)


def _home_socket_empty(listener, *, deadline: float) -> None:
    """Only the original synthetic HOME listener, after child wait/EOF/finality."""
    if listener.family != socket.AF_UNIX or listener.type != socket.SOCK_STREAM:
        raise SessionError("wrong owned HOME listener type")
    accepted, errors = None, []
    try:
        _remaining(deadline)
        listener.setblocking(False)
        try:
            accepted, _ = listener.accept()
            raise SessionError("synthetic HOME listener observed prohibited delivery")
        except BlockingIOError as exc:
            if exc.errno not in {errno.EAGAIN, errno.EWOULDBLOCK}:
                raise
    except BaseException as exc:
        errors.append(exc)
    if accepted is not None:
        try:
            accepted.close()
        except BaseException as exc:
            errors.append(exc)
    try:
        _remaining(deadline)
    except BaseException as exc:
        errors.append(exc)
    if errors:
        raise BaseExceptionGroup("synthetic HOME non-delivery/accepted close failed", errors)


def _probe_provider_boundaries(data: dict) -> None:
    """Fixed runtime/HOME controls, without generic missing-fixture allowances."""
    if data["platform"] == "linux":
        targets = data["runtime_executables"]
        if not isinstance(targets, list) or len(targets) != 2 or any(not Path(p).is_absolute() for p in targets):
            raise SessionError("incomplete fixed provider writer-control inventory")
        for target in targets:
            fd, errors = None, []
            try:
                fd = os.open(target, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                raise SessionError("selected provider executable is writable by the subject")
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EPERM, errno.EROFS}:
                    errors.append(exc)  # Missing fixture and ETXTBSY are not protection evidence.
            except BaseException as exc:
                errors.append(exc)
            if fd is not None:
                try:
                    os.close(fd)
                except BaseException as exc:
                    errors.append(exc)
            if errors:
                raise BaseExceptionGroup("fixed provider write-open control/close failed", errors)
        return
    if data["platform"] != "darwin":
        raise SessionError("unsupported fixed provider boundary platform")
    home, prefix = Path(data["runner_home"]), Path(data["ruby_prefix"])
    ancestors = _ruby_ancestor_paths(home, prefix)
    ruby = Path(data["ruby_executable"])
    if not ruby.is_absolute() or ".." in ruby.parts or ruby.parent.parent != prefix:
        raise SessionError("Ruby metadata control lost the selected executable binding")
    root = Path(data["work"]).parent
    canary, endpoint = _home_paths(home, root)
    sibling = _ruby_sibling_path(home, prefix, root)
    if (data["home_canary"], data["home_socket"], data["home_sibling"]) != (str(canary), str(endpoint), str(sibling)):
        raise SessionError("HOME boundary controls differ from fixed session names")
    # Each literal must actually permit its one directory inode's metadata.
    # Neither fake Ruby receipts nor successful denied-file opens can stand in
    # for these positives in the original/fork-exec/detached native routes.
    for ancestor in ancestors:
        state = os.stat(ancestor, follow_symlinks=False)
        if (not stat.S_ISDIR(state.st_mode) or state.st_uid == data["uid"] or state.st_gid == data["gid"]
                or state.st_mode & 0o002 or not state.st_mode & 0o001):
            raise SessionError("literal Ruby ancestor metadata/traversal positive failed")
    if ruby.resolve(strict=True) != ruby:
        raise SessionError("selected Ruby path did not resolve strictly under the final policy")
    for target, expected in ((canary, _HOME_READ_BYTES), (sibling, _ANCESTOR_READ_BYTES)):
        for operation in ("read", "metadata"):
            fd, errors = None, []
            try:
                if operation == "read":
                    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
                    os.read(fd, len(expected) + 1)
                else:
                    os.stat(target, follow_symlinks=False)
                raise SessionError("synthetic HOME/sibling known-path access was permitted")
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EPERM}:
                    errors.append(exc)
            except BaseException as exc:
                errors.append(exc)
            if fd is not None:
                try:
                    os.close(fd)
                except BaseException as exc:
                    errors.append(exc)
            if errors:
                raise BaseExceptionGroup("known-path HOME/sibling denial/owned close failed", errors)
    peer, errors = None, []
    try:
        peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        peer.settimeout(0.5)
        try:
            peer.connect(str(endpoint))
            raise SessionError("synthetic HOME pathname socket was reachable")
        except OSError as exc:
            if exc.errno not in {errno.EACCES, errno.EPERM}:
                raise
    except BaseException as exc:
        errors.append(exc)
    if peer is not None:
        try:
            peer.close()
        except BaseException as exc:
            errors.append(exc)
    if errors:
        raise BaseExceptionGroup("HOME named-socket denial/owned close failed", errors)


def _sudo_denial() -> None:
    """Only the pre-admitted fixed noninteractive command is a denial oracle."""
    try:
        child = subprocess.Popen(["/usr/bin/sudo", "-n", "-u", "root", "/usr/bin/true"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, close_fds=True)
    except OSError as exc:
        if exc.errno in {errno.EPERM, errno.EACCES}:
            return  # A real permission denial before an original child exists.
        raise
    failures = []
    try:
        result = child.wait(timeout=3)
        if type(result) is not int or result == 0:
            raise SessionError("subject has usable or unobserved sudo authority")
    except BaseException as exc:
        failures.append(exc)
    try:
        if child.poll() is None:
            child.kill()
    except BaseException as exc:
        failures.append(exc)
    try:
        if type(child.wait(timeout=2)) is not int:
            raise SessionError("fixed sudo denial has no original cleanup wait")
    except BaseException as exc:
        failures.append(exc)
    if failures:
        raise BaseExceptionGroup("fixed sudo denial/cleanup failed", failures)


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
    # Darwin saved IDs were observed by the real root parent on its original,
    # still-unreaped Popen PID.  Fork and the admitted non-set-ID exec chain
    # preserve them; sandboxed ps is not an appropriate metadata dependency.
    try:
        os.setuid(0)
    except PermissionError:
        pass
    else:
        raise SessionError("subject could regain root")
    _probe_provider_boundaries(data)
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
    _probe_network(data["platform"], data["endpoints"])


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
        _sudo_denial()
    print("MRK_LEAF_OK" if grandchild else "MRK_NATIVE_ISOLATION_OK", flush=True)


def _cleanup_numeric(uid: int, gid: int, kind: str, targets: list[int], deadline: float) -> None:
    """Fixed U-only signal batch.  Root, never this helper, observes finality."""
    try:
        _remaining(deadline)
        if (sys.platform != "darwin" or type(uid) is not int or type(gid) is not int
                or not 60000 <= uid < 65000 or gid != uid
                or (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (uid, uid, gid, gid)
                or _process_groups("darwin") != [gid]):
            raise SessionError("cleanup batch lacks its reserved unprivileged credentials")
        if (not isinstance(kind, str) or kind not in {"TERM", "KILL"}
                or not isinstance(targets, list) or not 1 <= len(targets) <= 4096
                or any(type(pid) is not int or not 1 < pid < 2**31 or pid == os.getpid() for pid in targets)
                or len(set(targets)) != len(targets)):
            raise SessionError("invalid fixed numerical cleanup batch")
        signum = signal.SIGTERM if kind == "TERM" else signal.SIGKILL
        for pid in targets:
            _remaining(deadline)
            try:
                os.kill(pid, signum)  # U-only; kernel rechecks even a recycled PID.
            except OSError as exc:
                if exc.errno != errno.ESRCH:
                    raise  # Foreign UID EPERM and unknown errors are failures.
        _remaining(deadline)
        print("MRK_CLEANUP_BATCH_ATTEMPTED", flush=True)
    except BaseException as exc:
        exc._ci_operation = "cleanup-batch"
        raise


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
    if argv[0] == "--cleanup-batch" and len(argv) == 6:
        if len(argv[4]) > 65536:
            raise SessionError("cleanup batch argument exceeds fixed bound")
        _cleanup_numeric(int(argv[1]), int(argv[2]), argv[3], json.loads(argv[4]), float(argv[5]))
        return 0
    if argv[0] == "--fixture" and len(argv) == 2:
        return _fixture(argv[1])
    if argv[0] == "--write-control" and len(argv) == 2:
        _write_control(Path(argv[1]))
        return 0
    if argv == ["--home-positive"]:
        _home_positive()
        return 0
    if argv == ["--sentinel"] or argv == ["--signal-target"]:
        _signal_target(argv[0] == "--sentinel")
        return 0
    if argv[0] == "--observer-probe" and len(argv) == 4:
        _observer_probe(Path(argv[1]), int(argv[2]), float(argv[3]))
        return 0
    if argv[0] == "--observer-family" and len(argv) == 2:
        _observer_family(float(argv[1]))
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
