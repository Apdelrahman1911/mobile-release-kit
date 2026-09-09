"""Real private process groups around production profile capture/supervision.

Only the native executable boundary is synthetic. Tests wait for actual readiness,
then prove cleanup before their independent fallback. No real profile/keychain.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if __name__ == "__main__":
    # Test the same package selected by the caller, including an installed wheel
    # outside the checkout. Only the fixture itself comes from the source tree.
    sys.path[:0] = [sys.argv.pop(1), str(ROOT / "tests")]

from workflow.process_fixture import alive, assert_dead, assert_live, observer_environment, record

CANARIES = ("GH_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8", "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD",
            "PYTHONPATH", "PYTHONHOME", "OPENSSL_CONF", "DYLD_INSERT_LIBRARIES")
PARENT_DEATH_MODES = {"marker-parent-death", "committed-parent-death"}
COMPLETION_CANCEL_MODES = {"completion-cancel", "completion-interrupt"}
ACTUAL_SUPERVISOR_MODES = {"success", "custom-handler", "orphan", "supervisor-timeout",
                           "committed-timeout", *COMPLETION_CANCEL_MODES, *PARENT_DEATH_MODES}
BAD_FRAME_MODES = {"partial-marker", "full-zero", "full-failure", "extra-frame", "concatenated-frame"}


def kill_owned_group(pid, *, process=None):
    """Independent fixture fallback, AFTER dangerous-case assertions.

    Reap our own leader when available; macOS zombie-only groups may report EPERM
    until that wait. Never count EPERM or mere signal delivery as absence.
    """
    limit = time.monotonic() + 3
    while True:
        if process is not None:
            process.poll()
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        except PermissionError:
            pass
        if time.monotonic() >= limit:
            raise AssertionError("owned fixture group cleanup could not be confirmed")
        time.sleep(0.01)


def command(role, root, directory, mode, parent=0):
    import mobile_release
    return [sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()),
            str(Path(mobile_release.__file__).resolve().parent.parent),
            role, str(root), str(directory), mode, str(parent)]


def ready(root):
    return (root / "child.pid").is_file() and (root / "child-ready").is_file()


def await_ready(root, process):
    limit = time.monotonic() + 8
    while not ready(root) and time.monotonic() < limit:
        time.sleep(.01)
    assert ready(root), "independent fixture readiness watchdog expired"
    assert_live(int((root / "child.pid").read_text()), deadline=limit)


def fixture(root, directory, mode, parent):
    from mobile_release.ios_profiles import MAX_COMPLETION_BYTES, completion_frame
    record(root / "worker.json", json.dumps({"pid": os.getpid(), "group": os.getpgrp(),
                                             "parent": os.getppid(), "environment": dict(os.environ)}))
    child = os.fork()
    if child == 0:
        if mode != "pipe-timeout":
            descriptor = os.open(os.devnull, os.O_WRONLY)
            os.dup2(descriptor, 1); os.dup2(descriptor, 2); os.close(descriptor)
        (root / "child-ready").touch()
        time.sleep(20)  # Independent self-limit is NOT the cleanup assertion.
        os._exit(0)
    record(root / "child.pid", str(child))
    limit = time.monotonic() + 5
    while not (root / "child-ready").is_file() and time.monotonic() < limit:
        time.sleep(.01)
    assert (root / "child-ready").is_file(), "native fixture child never became ready"
    if mode in {"orphan", "supervisor-timeout", "popen-cancel", "cancel", "register-cancel", "read-failure"}:
        time.sleep(20)
    elif mode == "pipe-timeout":
        return 0
    elif mode == "backpressure":
        (directory / "verified-content.bin").write_bytes(b"v" * (4 * 1024 * 1024))
    elif mode == "overflow":
        sys.stdout.buffer.write(b"v" * (MAX_COMPLETION_BYTES + 1))
        sys.stdout.buffer.flush()
    elif mode == "failure":
        sys.stdout.buffer.write(b"plausible-partial-profile")
        sys.stdout.buffer.flush()
        sys.stderr.write("private-native-canary\n")
        return 1
    elif mode in BAD_FRAME_MODES:
        frame = completion_frame(b"verified-content")
        if mode == "partial-marker":
            frame = frame[:-1]
        elif mode == "extra-frame":
            frame += b"x"
        elif mode == "concatenated-frame":
            frame *= 2
        sys.stdout.buffer.write(frame)
        sys.stdout.buffer.flush()
        if mode not in {"full-zero", "full-failure"}:
            os.killpg(os.getpgrp(), signal.SIGKILL)
        return 0 if mode == "full-zero" else 1
    else:
        (directory / "verified-content.bin").write_bytes(b"verified-content")
    return 0


def supervisor(root, directory, mode, parent):
    from mobile_release import ios_profile_auth as auth
    record(root / "supervisor.pid", str(os.getpid()))
    waits = []
    original_selector = auth.selectors.DefaultSelector
    original_write = os.write
    class ObservedSelector(original_selector):
        def select(self, timeout=None):
            events = super().select(timeout)
            if not events:
                waits.append(True)
                record(root / "backpressure-observed", "true")
            return events

    def clock():
        expired = (mode == "supervisor-timeout" and ready(root)) or bool(waits)
        return 2 if expired else 0

    def at_commit(descriptor, content):
        # Production supervise has just checked its actual parent and deadline.
        # Kill the real original parent either immediately before the terminal
        # write or immediately after it. The parent cannot complete wait/reap
        # before this supervisor exits, so this deterministically removes the
        # delegated cleanup owner at the original review's dangerous handoff.
        if bytes(content) == auth.COMPLETION_MARKER:
            if mode in {"committed-parent-death", *COMPLETION_CANCEL_MODES}:
                count = original_write(descriptor, content)
                assert count == len(content)
            record(root / "completion-interleaving", mode)
            assert os.getpgid(parent) == parent and os.getppid() == parent
            if mode in COMPLETION_CANCEL_MODES:
                os.kill(parent, signal.SIGTERM if mode == "completion-cancel" else signal.SIGINT)
            else:
                os.killpg(parent, signal.SIGKILL)
            if mode in {"committed-parent-death", *COMPLETION_CANCEL_MODES}:
                return count
        return original_write(descriptor, content)

    with ExitStack() as stack:
        stack.enter_context(patch.object(auth, "worker_command", side_effect=lambda selected, path: command("fixture", root, path, mode)))
        if mode in {"supervisor-timeout", "backpressure"}:
            stack.enter_context(patch.object(auth, "time", SimpleNamespace(monotonic=clock, sleep=time.sleep)))
            stack.enter_context(patch.object(auth, "SUPERVISOR_SECONDS", 1))
        if mode == "backpressure":
            stack.enter_context(patch.object(auth.selectors, "DefaultSelector", ObservedSelector))
        if mode in {*PARENT_DEATH_MODES, *COMPLETION_CANCEL_MODES}:
            stack.enter_context(patch.object(auth.os, "write", side_effect=at_commit))
        return auth.supervise(directory, parent)


def driver(root, directory, mode, parent):
    from mobile_release import ios_profiles as profiles
    from mobile_release.errors import ValidationError
    from mobile_release.inspection import InspectionDeadline

    # Inject only after this Python interpreter has started. A DYLD canary in
    # its own launch would test the loader failing, not our production boundary.
    os.environ.update({key: "fictional-private-canary" for key in CANARIES})

    real_spawn, real_command = subprocess.Popen, profiles.worker_command
    real_selector = profiles.selectors.DefaultSelector
    launched, waits, scratches, completed_waits = [], [], [], []
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    if mode == "custom-handler":
        signal.signal(signal.SIGTERM, lambda *args: None)
        previous[signal.SIGTERM] = signal.getsignal(signal.SIGTERM)

    def select_command(selected, path, expected_parent):
        native = real_command(selected, path, expected_parent)
        assert native[:4] == [sys.executable, "-I", "-S", "-B"]
        assert expected_parent == os.getpid()
        assert path.is_dir() and (path.stat().st_mode & 0o777) == 0o700
        assert (path / "cms.der").read_bytes() == b"fictional-profile-canary"
        assert (path / "cms.der").stat().st_mode & 0o777 == 0o600
        scratches.append(path)
        record(root / "scratch-path", str(path))
        return command("supervisor" if mode in ACTUAL_SUPERVISOR_MODES else "fixture", root, path, mode, expected_parent)

    def spawn(arguments, **options):
        process = real_spawn(arguments, **options)
        if str(Path(__file__).resolve()) not in arguments:
            return process
        launched.append(process)
        record(root / "launcher.pid", str(process.pid))
        assert options["start_new_session"] is True
        assert options["stderr"] == subprocess.DEVNULL
        assert not set(CANARIES) & options["env"].keys()
        assert options["env"] == profiles.profile_environment(scratches[-1])
        if mode in {"popen-cancel", "register-cancel", "read-failure"}:
            await_ready(root, process)
        if mode == "popen-cancel":
            os.kill(os.getpid(), signal.SIGTERM)  # Real child exists; handle not yet assigned by production.
        if mode == "committed-timeout":
            original_wait = process.wait
            def wait(*args, **kwargs):
                result = original_wait(*args, **kwargs)
                completed_waits.append(True)
                return result
            process.wait = wait
        return process

    class ObservedSelector(real_selector):
        def register(self, *args, **kwargs):
            if mode == "register-cancel":
                raise KeyboardInterrupt
            if mode == "read-failure":
                raise OSError("private-native-canary")
            return super().register(*args, **kwargs)

        def select(self, timeout=None):
            exited_with_pipe = (ready(root) and launched[0].poll() is not None
                                and alive(int((root / "child.pid").read_text()), group=launched[0].pid))
            result = super().select(timeout)
            if exited_with_pipe and not result:
                waits.append(True)
            return result

    def clock():
        return 2 if waits or completed_waits else 0

    result = None
    try:
        with ExitStack() as stack:
            stack.enter_context(patch.object(profiles, "worker_command", side_effect=select_command))
            stack.enter_context(patch.object(profiles.subprocess, "Popen", side_effect=spawn))
            stack.enter_context(patch.object(profiles, "sys", SimpleNamespace(platform="darwin", executable=sys.executable)))
            stack.enter_context(patch.object(profiles.selectors, "DefaultSelector", ObservedSelector))
            if mode in {"pipe-timeout", "committed-timeout"}:
                stack.enter_context(patch.object(profiles, "CAPTURE_SECONDS", 1))
                stack.enter_context(patch.object(profiles, "time", SimpleNamespace(monotonic=clock, sleep=time.sleep)))
            try:
                output = profiles.authenticate_cms(b"fictional-profile-canary", deadline=InspectionDeadline())
                assert output == b"verified-content" and mode in {"success", "custom-handler"}
                result = "success"
            except ValidationError as error:
                assert mode in {"pipe-timeout", "failure", "overflow", "read-failure", "supervisor-timeout", "committed-timeout", *BAD_FRAME_MODES}, str(error)
                if mode == "committed-timeout":
                    assert completed_waits and "timed out" in str(error)
                assert "private-native-canary" not in str(error)
                result = "rejected"
            except KeyboardInterrupt:
                assert mode in {"popen-cancel", "cancel", "register-cancel", *COMPLETION_CANCEL_MODES}
                result = "cancelled"
        assert result is not None
        assert len(launched) == 1
        assert_dead(launched[0].pid, group=launched[0].pid)
        assert ready(root)
        assert_dead(int((root / "child.pid").read_text()), group=launched[0].pid)
        assert all(not path.exists() for path in scratches)
        assert all(signal.getsignal(sig) == handler for sig, handler in previous.items())
        if mode == "pipe-timeout":
            assert waits, "fixture never exercised the orphaned pipe"
        worker = json.loads((root / "worker.json").read_text())
        assert worker["group"] == launched[0].pid
        if mode in ACTUAL_SUPERVISOR_MODES:
            assert worker["parent"] == launched[0].pid
            assert_dead(worker["pid"], group=launched[0].pid)
        assert not set(CANARIES) & worker["environment"].keys()
        record(root / "result.json", json.dumps({"result": result, "deadBeforeFallback": True,
                                                "scratchRemoved": True, "orphanPipeObserved": bool(waits)}))
        return 0
    finally:
        for process in launched:
            kill_owned_group(process.pid, process=process)
            process.wait(timeout=5)
            if process.stdout is not None:
                process.stdout.close()


def run_case(root: Path, mode: str) -> dict:
    environment = {"PATH": os.environ["PATH"]}
    environment.update(observer_environment())
    process = subprocess.Popen(command("driver", root, root, mode), env=environment,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        if mode in {"cancel", "orphan"}:
            await_ready(root, process)
            if mode == "orphan":
                kill_owned_group(process.pid, process=process)  # Models Ruby terminating its complete validator group.
            else:
                process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=12)
        killed_parent = mode == "orphan" or mode in PARENT_DEATH_MODES
        assert process.returncode == (-signal.SIGKILL if killed_parent else 0), stderr.decode(errors="replace")
        assert not stdout and not stderr
        if killed_parent:
            supervisor_pid = int((root / "supervisor.pid").read_text())
            worker = json.loads((root / "worker.json").read_text())
            assert worker["parent"] == worker["group"] == supervisor_pid
            for pid in (supervisor_pid, worker["pid"], int((root / "child.pid").read_text())):
                assert_dead(pid, group=supervisor_pid)
            scratch = Path((root / "scratch-path").read_text())
            assert scratch.is_dir() and scratch.stat().st_mode & 0o777 == 0o700
            if mode in PARENT_DEATH_MODES:
                assert (root / "completion-interleaving").read_text() == mode
            return {"deadBeforeFallback": True, "hardKillScratchRemainsPrivate": True,
                    "completionInterleavingReached": mode in PARENT_DEATH_MODES}
        return json.loads((root / "result.json").read_text())
    finally:
        kill_owned_group(process.pid, process=process)
        process.wait(timeout=5)
        for stream in (process.stdout, process.stderr):
            stream.close()
        if (root / "launcher.pid").is_file():
            kill_owned_group(int((root / "launcher.pid").read_text()))
        if (root / "child.pid").is_file():
            assert_dead(int((root / "child.pid").read_text()))
        # Explicit owner-only cleanup of exactly the captured hard-kill scratch,
        # not a glob or a claim that the killed application cleaned itself up.
        if (mode == "orphan" or mode in PARENT_DEATH_MODES) and (root / "scratch-path").is_file():
            import shutil
            scratch = Path((root / "scratch-path").read_text())
            assert scratch.name.startswith("mobile-release-profile-auth-") and not scratch.is_symlink()
            if scratch.exists():
                shutil.rmtree(scratch)


def backpressure_case(root: Path) -> dict:
    process = subprocess.Popen(command("supervisor", root, root, "backpressure", os.getpid()),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        # Do NOT consume stdout: prove the supervisor's watchdog survives a full pipe.
        process.wait(timeout=10)
        assert process.returncode == -signal.SIGKILL
        output, errors = process.communicate(timeout=3)
        assert not errors and 0 < len(output) < 4 * 1024 * 1024
        assert (root / "backpressure-observed").is_file()
        assert_dead(int((root / "child.pid").read_text()), group=process.pid)
        assert_dead(json.loads((root / "worker.json").read_text())["pid"], group=process.pid)
        return {"deadBeforeFallback": True, "backpressureObserved": True}
    finally:
        kill_owned_group(process.pid, process=process)
        process.wait(timeout=5)
        for stream in (process.stdout, process.stderr):
            stream.close()


if __name__ == "__main__":
    role, root, directory, mode, parent = sys.argv[1:]
    raise SystemExit({"driver": driver, "fixture": fixture, "supervisor": supervisor}[role](
        Path(root), Path(directory), mode, int(parent)))
