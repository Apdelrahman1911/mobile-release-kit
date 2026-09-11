"""Real, bounded process-tree fixtures; never imported by production code.

The public transport still receives only gh commands. Its Popen seam launches
this static fixture through the current interpreter to avoid macOS cold-script
execution latency. Session creation, pipes, waits, signals and cleanup are real.
"""
from __future__ import annotations

import json
import math
import os
import re
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from typing import Literal

ARGV = ["gh", "api", "--method", "GET", "fixed"]
OBSERVER_VARIABLE = "MOBILE_RELEASE_TEST_PROCESS_OBSERVER"
# Capture before profile fixtures deliberately insert loader/config canaries.
# Importing a worker/supervisor with no selector is inert: neither observes PIDs.
_PROCESS_OBSERVER = os.environ.get(OBSERVER_VARIABLE)
_PID_MAX, _ID_MAX, _OBSERVATION_LIMIT = 2**31 - 1, 2**32 - 1, 512
ProcessState = Literal["live", "indeterminate", "zombie", "absent"]


def _number(value: bytes, low: int, high: int) -> int:
    if not re.fullmatch(rb"(?:0|[1-9][0-9]{0,9})", value):
        raise AssertionError("noncanonical process observation integer")
    number = int(value)
    if not low <= number <= high:
        raise AssertionError("out-of-range process observation integer")
    return number


def _request(pid: int, group: int | None) -> None:
    if type(pid) is not int or not 2 <= pid <= _PID_MAX:
        raise AssertionError("invalid owned process observation PID")
    if group is not None and (type(group) is not int or not 2 <= group <= _PID_MAX):
        raise AssertionError("invalid owned process observation group")


def _output(stdout: bytes, stderr: bytes, status: int) -> None:
    if (type(stdout) is not bytes or type(stderr) is not bytes or type(status) is not int
            or stderr or len(stdout) > _OBSERVATION_LIMIT):
        raise AssertionError("unsupported process observation output")


def parse_observer(stdout: bytes, stderr: bytes, status: int, pid: int, *,
                   group: int | None = None, uid: int, gid: int) -> ProcessState:
    """Pure parser for the reviewed SDK helper, never fabricated ps output."""
    _request(pid, group)
    _output(stdout, stderr, status)
    if (type(uid) is not int or not 1 <= uid <= _ID_MAX
            or type(gid) is not int or not 0 <= gid <= _ID_MAX):
        raise AssertionError("invalid process observation owner")
    if status != 0:
        raise AssertionError("owned process observer denied or failed")
    if not stdout.endswith(b"\n") or stdout.count(b"\n") != 1 or b"\r" in stdout:
        raise AssertionError("invalid process observer frame")
    fields = stdout[:-1].split(b" ")
    if fields[:2] == [b"MRK_PROCESS_V1", b"absent"] and len(fields) == 3:
        if _number(fields[2], 2, _PID_MAX) != pid:
            raise AssertionError("process observer PID mismatch")
        return "absent"
    if fields[:2] != [b"MRK_PROCESS_V1", b"present"] or len(fields) != 13:
        raise AssertionError("invalid process observer record")
    actual_pid, actual_group = (_number(field, 2, _PID_MAX) for field in fields[2:4])
    ids = tuple(_number(field, 0, _ID_MAX) for field in fields[4:10])
    state, exiting = _number(fields[10], 0, _ID_MAX), _number(fields[11], 0, 1)
    if actual_pid != pid or (group is not None and actual_group != group):
        raise AssertionError("process observer PID/group mismatch")
    if ids != (uid, uid, uid, gid, gid, gid):
        raise AssertionError("process observer credential mismatch")
    # BSD status values defined by the actual SDK sys/proc.h, not Mach states.
    expected = "zombie" if state == 5 else "live" if state in {2, 3, 4} and not exiting else "indeterminate"
    if fields[12] != expected.encode("ascii"):
        raise AssertionError("inconsistent process observer state")
    return expected


def parse_ps(stdout: bytes, stderr: bytes, status: int, pid: int, *,
             group: int | None = None) -> ProcessState:
    """Strict fixed-column system-ps route outside admitted Darwin fixtures."""
    _request(pid, group)
    _output(stdout, stderr, status)
    if status == 1 and stdout == b"":
        return "absent"
    match = re.fullmatch(rb"[ \t]*([0-9]+)[ \t]+([0-9]+)[ \t]+"
                         rb"([RSDTtZXIWUH?][<N]?X?E?V?L?s?l?\+?)[ \t]*\n?", stdout)
    if status != 0 or match is None:
        raise AssertionError("unsupported system process observation")
    actual_pid, actual_group = (_number(field, 2, _PID_MAX) for field in match.group(1, 2))
    if actual_pid != pid or (group is not None and actual_group != group):
        raise AssertionError("system process observation PID/group mismatch")
    state = match[3]
    if state.startswith(b"Z") and b"E" in state:
        raise AssertionError("inconsistent system process observation")
    if state.startswith(b"Z"):
        return "zombie"
    if state[:1] in {b"?", b"H", b"X"} or b"E" in state:
        return "indeterminate"
    return "live"


def _observer_path() -> str | None:
    if _PROCESS_OBSERVER is None:
        if sys.platform == "darwin":
            raise AssertionError("Darwin process observation requires the admitted selector")
        return None
    if (sys.platform != "darwin" or not isinstance(_PROCESS_OBSERVER, str)
            or not 1 <= len(_PROCESS_OBSERVER) <= 4096 or "\0" in _PROCESS_OBSERVER):
        raise AssertionError("invalid process observer selector")
    path = Path(_PROCESS_OBSERVER)
    if (not path.is_absolute() or str(path) != _PROCESS_OBSERVER or ".." in path.parts
            or path.name != "process-observer" or path.parent.name != "bootstrap"
            or path.parent.parent.parent != Path("/private/tmp")
            or not path.parent.parent.name.startswith("mrk-ci-")):
        raise AssertionError("unexpected process observer path")
    try:
        state = path.lstat()
        if (not stat.S_ISREG(state.st_mode) or state.st_uid != 0 or state.st_nlink != 1
                or stat.S_IMODE(state.st_mode) != 0o555):
            raise AssertionError("process observer is not immutable")
        for parent in (path.parent, path.parent.parent):
            state = parent.lstat()
            if (not stat.S_ISDIR(state.st_mode) or state.st_uid != 0
                    or stat.S_IMODE(state.st_mode) != 0o755):
                raise AssertionError("process observer ancestry is not immutable")
        if path.resolve(strict=True) != path:
            raise AssertionError("process observer path is not canonical")
    except OSError:
        raise AssertionError("process observer metadata unavailable") from None
    return str(path)


def observer_environment() -> dict[str, str]:
    """Only the frozen admitted scalar crosses private fixture-driver scrubbing."""
    path = _observer_path()
    return {} if path is None else {OBSERVER_VARIABLE: path}


def _remaining(deadline: float) -> float:
    if not isinstance(deadline, (int, float)) or isinstance(deadline, bool) or not math.isfinite(deadline):
        raise AssertionError("invalid process observation deadline")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise AssertionError("owned process observation deadline expired")
    return remaining


def process_state(pid: int, *, group: int | None = None, deadline: float | None = None) -> ProcessState:
    _request(pid, group)
    cutoff = time.monotonic() + 2 if deadline is None else deadline
    _remaining(cutoff)
    observer = _observer_path()
    argv = ([observer, str(pid)] if observer is not None else
            ["/bin/ps", "-o", "pid=,pgid=,stat=", "-p", str(pid)])
    try:
        # Both fixed tools emit bounded metadata, not arbitrary command output.
        # run owns this direct child, communicates both EOFs, and actually waits.
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                                env={"LANG": "C", "LC_ALL": "C"}, close_fds=True,
                                timeout=min(2, _remaining(cutoff)))
    except (OSError, subprocess.SubprocessError):
        raise AssertionError("owned process observation failed") from None
    _remaining(cutoff)  # Late output cannot satisfy readiness or cleanup.
    if observer is not None:
        return parse_observer(result.stdout, result.stderr, result.returncode, pid,
                              group=group, uid=os.getuid(), gid=os.getgid())
    return parse_ps(result.stdout, result.stderr, result.returncode, pid, group=group)


def assert_live(pid: int, *, deadline: float, group: int | None = None) -> None:
    while True:
        state = process_state(pid, group=group, deadline=deadline)
        if state == "live":
            return
        if state in {"zombie", "absent"}:
            raise AssertionError("owned fixture stopped before readiness")
        time.sleep(min(0.02, _remaining(deadline)))


def record(path: Path, text: str) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(text)
    temporary.replace(path)  # Readers must never see a half-written PID/JSON.


def alive(pid: int, *, group: int | None = None, deadline: float | None = None) -> bool:
    """Known live presence only; false is NOT proof of death or absence."""
    return process_state(pid, group=group, deadline=deadline) == "live"


def assert_dead(pid: int, *, group: int | None = None) -> None:
    deadline = time.monotonic() + 3
    while True:
        if process_state(pid, group=group, deadline=deadline) in {"zombie", "absent"}:
            return
        time.sleep(min(0.02, _remaining(deadline)))


def kill_owned_group(pid: int) -> None:
    # The caller supplies only a group captured from its real start_new_session
    # Popen handle, never a process search, PID of another task, or user input.
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def fixture(root: Path, mode: str, delay: float) -> int:
    time.sleep(delay)
    if mode == "unready":
        time.sleep(30)  # Independent final self-limit, not the test assertion.
        return 0
    record(root / "gh.pid", str(os.getpid()))
    child = os.fork()
    if child == 0:
        (root / "child-ready").touch()
        # Keep the inherited stdout pipe open even when the leader exits.
        # A timed marker alone would not prove the child was killed.
        time.sleep(30)
        os._exit(0)
    record(root / "child.pid", str(child))
    if mode == "timeout":
        return 0
    os.waitpid(child, 0)
    return 0


class ReadinessFailure(AssertionError):
    pass


def driver(root: Path, mode: str, delay: float) -> int:
    from mobile_release import workflow

    real_spawn, real_selector = subprocess.Popen, workflow.selectors.DefaultSelector
    started = time.monotonic()
    launched = []
    observations = {"selectorWaitsAfterLeaderExit": 0, "ready": False}
    child_path = root / "child.pid"

    def ready() -> bool:
        return child_path.is_file() and (root / "child-ready").is_file()

    def spawn(arguments, **options):
        if arguments[0] != "gh":
            return real_spawn(arguments, **options)
        assert arguments == ARGV
        assert options["start_new_session"] is True
        assert options["stdout"] == subprocess.PIPE
        assert options["stderr"] == subprocess.DEVNULL
        assert "PYTHONPATH" not in options["env"]
        process = real_spawn([sys.executable, "-I", str(Path(__file__).resolve()),
                              "fixture", str(root), mode, str(delay)], **options)
        launched.append(process)  # Capture before any fixture/readiness marker.
        record(root / "launcher.pid", str(process.pid))
        if mode == "popen-cancel":
            limit = time.monotonic() + 8
            while not ready() and time.monotonic() < limit and process.poll() is None:
                time.sleep(0.01)
            if not ready():
                raise ReadinessFailure("fixture did not fork before injected cancellation")
            assert_live(int(child_path.read_text()), group=process.pid, deadline=limit)
            observations["ready"] = True
            # The OS child exists, but Transport has not received its handle.
            os.kill(os.getpid(), signal.SIGTERM)
        return process

    class ObservedSelector(real_selector):
        def select(self, timeout=None):
            orphaned_pipe = (bool(launched) and ready() and launched[0].poll() is not None
                             and alive(int(child_path.read_text()), group=launched[0].pid,
                                       deadline=started + 8))
            events = super().select(timeout)  # Real pipe wait, not fake events.
            if orphaned_pipe and not events:
                observations["selectorWaitsAfterLeaderExit"] += 1
                observations["ready"] = True
            return events

    def controlled_clock() -> float:
        limit = 0.2 if mode == "unready" else 8
        if time.monotonic() - started > limit:
            raise ReadinessFailure("independent fixture readiness watchdog expired")
        return 2.0 if observations["selectorWaitsAfterLeaderExit"] else 0.0

    result = None
    try:
        with patch.object(workflow.subprocess, "Popen", side_effect=spawn):
            if mode in {"timeout", "unready"}:
                clock = SimpleNamespace(monotonic=controlled_clock, sleep=time.sleep)
                with patch.object(workflow, "time", clock), patch.object(workflow.selectors, "DefaultSelector", ObservedSelector):
                    try:
                        workflow.Transport().run(ARGV, timeout=1)
                    except workflow.ValidationError as error:
                        assert mode == "timeout" and "timed out" in str(error)
                        result = "timeout"
                    except ReadinessFailure:
                        assert mode == "unready"
                        result = "readiness-failure"
            else:
                try:
                    workflow.Transport().run(ARGV)
                except KeyboardInterrupt:
                    observations["ready"] = ready()
                    result = "cancelled"
        assert result is not None, "Transport unexpectedly succeeded or swallowed cancellation"
        assert len(launched) == 1
        assert_dead(launched[0].pid, group=launched[0].pid)
        if mode == "unready":
            assert not (root / "gh.pid").exists() and not child_path.exists()
        else:
            assert observations["ready"] and child_path.is_file()
            assert_dead(int(child_path.read_text()), group=launched[0].pid)
        if mode == "timeout":
            assert observations["selectorWaitsAfterLeaderExit"] > 0
        # This proof is written BEFORE the harness fallback cleanup below.
        observations.update(result=result, deadBeforeFallback=True,
                            realSeconds=time.monotonic() - started)
        record(root / "observations.json", json.dumps(observations))
        return 130 if result == "cancelled" else 0
    finally:
        for process in launched:
            kill_owned_group(process.pid)
            process.wait(timeout=5)
            if process.stdout is not None:
                process.stdout.close()


def run_case(root: Path, mode: str, *, delay: float = 0) -> dict:
    """Outer real-clock watchdog contains even deliberately broken transports."""
    environment = {"PATH": os.environ["PATH"],
                   "PYTHONPATH": str(Path(__file__).resolve().parents[2] / "src")}
    environment.update(observer_environment())
    process = subprocess.Popen([sys.executable, "-P", str(Path(__file__).resolve()),
                                "driver", str(root), mode, str(delay)], env=environment,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    try:
        if mode == "cancel":
            deadline = time.monotonic() + 10
            while not (root / "child-ready").exists() and time.monotonic() < deadline and process.poll() is None:
                time.sleep(0.01)
            assert (root / "child-ready").exists(), "fixture failed to become ready"
            # The PID may be written just after the child's readiness marker.
            while not (root / "child.pid").exists() and time.monotonic() < deadline and process.poll() is None:
                time.sleep(0.01)
            assert (root / "child.pid").is_file()
            assert_live(int((root / "child.pid").read_text()), deadline=deadline)
            process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=12)
        expected = 130 if mode in {"cancel", "popen-cancel"} else 0
        assert process.returncode == expected, stderr.decode(errors="replace")
        assert stdout == stderr == b"", "fixture emitted unexpected output"
        observed = json.loads((root / "observations.json").read_text())
        assert observed["deadBeforeFallback"] is True
        return observed
    finally:
        try:
            if process.poll() is None:
                process.terminate()  # Let the real Transport clean up first.
                try:
                    process.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    kill_owned_group(process.pid)
                    process.communicate(timeout=5)
        finally:
            try:
                launcher = root / "launcher.pid"
                if launcher.is_file():
                    kill_owned_group(int(launcher.read_text()))
                    assert_dead(int(launcher.read_text()))
                if (root / "child.pid").is_file():
                    assert_dead(int((root / "child.pid").read_text()))
            finally:
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()


if __name__ == "__main__":
    command, directory, selected_mode, seconds = sys.argv[1:]
    function = {"fixture": fixture, "driver": driver}[command]
    raise SystemExit(function(Path(directory), selected_mode, float(seconds)))
