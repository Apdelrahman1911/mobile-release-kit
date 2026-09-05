"""Real default signals and OS resources around the profile parent boundary.

Only the native child is synthetic. Keep exact resources/exception references and
prove cleanup before fallback. The selected package can be an installed wheel.
"""
from __future__ import annotations

import inspect
import json
import os
import selectors
import signal
import subprocess
import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if __name__ == "__main__":
    sys.path[:0] = [sys.argv.pop(1), str(ROOT / "tests")]

import mobile_release
from mobile_release import ios_profiles as profiles
from mobile_release.cancellation import CleanupScope, DefaultCancellation
from mobile_release.errors import ValidationError
from mobile_release.inspection import InspectionDeadline
from workflow.profile_process_fixture import kill_owned_group


def driver(root: Path, mode: str, signum: int) -> dict:
    real_open, real_close, real_read, real_write, real_fstat = os.open, os.close, os.read, os.write, os.fstat
    real_temp, real_spawn, real_selector, real_signal = tempfile.TemporaryDirectory, subprocess.Popen, selectors.DefaultSelector, signal.signal
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    assert previous == {signal.SIGINT: signal.default_int_handler, signal.SIGTERM: signal.SIG_DFL}
    area, phase = mode.split("-", 1)
    target = {"read": profiles.read_profile_bytes, "source": profiles.authenticate_cms,
              "capture": profiles._capture_profile}[area]
    descriptors, scratches, launched, selector_handles, held, scopes = [], [], [], [], [], []
    reached, visits, cleanups = [], [], []
    source = root / "fictional-profile"
    content = b"fictional profile input" * 10
    source.write_bytes(content)
    frame = profiles.completion_frame(b"fictional verified content")
    child_command = [sys.executable, "-I", "-S", "-B", "-c",
                     f"import os,signal; os.write(1,bytes.fromhex({frame.hex()!r})); os.killpg(os.getpgrp(),signal.SIGKILL)"]

    def anchor(function, token):
        lines, first = inspect.getsourcelines(function)
        return next(first + index for index, line in enumerate(lines) if token in line)

    scope_line = anchor(target, "with scope:")
    exit_line = anchor(CleanupScope.__exit__, "if self.claimed:")
    claimed_line = anchor(CleanupScope.__exit__, "try:")
    restore_lines = {"restore-entry": anchor(DefaultCancellation.restore, "self.depth += 1"),
                     "restore-active": anchor(DefaultCancellation.restore, "failed = False")}

    def send(boundary, selected=signum):
        reached.append(boundary)
        os.kill(os.getpid(), selected)

    def remember(descriptor):
        details = real_fstat(descriptor)
        descriptors.append((descriptor, details.st_dev, details.st_ino))

    def matches(descriptor):
        return any(descriptor == item[0] for item in descriptors)

    def opening(path, *args, **kwargs):
        descriptor = real_open(path, *args, **kwargs)
        if str(path) == str(source) or Path(path).name == "cms.der":
            remember(descriptor)
            if phase in {"open", "input-open"} and not reached:
                send(phase)
        return descriptor

    def stating(descriptor):
        result = real_fstat(descriptor)
        if phase == "fstat-failure" and matches(descriptor):
            reached.append(phase)
            raise OSError("private-native-canary")
        if phase == "fstat" and matches(descriptor) and not reached:
            send(phase)
        return result

    def reading(descriptor, count):
        result = real_read(descriptor, count)
        if phase == "read-failure" and matches(descriptor):
            reached.append(phase)
            raise OSError("private-native-canary")
        if phase == "read" and matches(descriptor) and not reached:
            send(phase)
        return result

    def writing(descriptor, data):
        result = real_write(descriptor, data)
        if phase == "input-write-failure" and matches(descriptor):
            reached.append(phase)
            raise OSError("private-native-canary")
        if phase == "input-write" and matches(descriptor) and not reached:
            send(phase)
        return result

    def closing(descriptor):
        result = real_close(descriptor)
        if phase in {"close", "input-close"} and matches(descriptor) and not reached:
            send(phase)
        return result

    def temporary(*args, **kwargs):
        handle = real_temp(*args, dir=root, **kwargs)
        scratches.append(handle)
        original_cleanup = handle.cleanup

        def cleanup():
            if phase == "scratch-cleanup" and not reached:
                send(phase)
            if phase == "scratch-cleanup-unresolved":
                reached.append(phase)
                raise OSError("private-native-canary")
            original_cleanup()
            if phase == "scratch-cleanup-failure":
                reached.append(phase)
                raise OSError("private-native-canary")
        handle.cleanup = cleanup
        if phase == "scratch-create" and not reached:
            send(phase)
        return handle

    def spawn(*args, **kwargs):
        child = real_spawn(*args, **kwargs)
        launched.append(child)
        (root / "native.pid").write_text(str(child.pid))
        return child

    class ObservedSelector(real_selector):
        def __init__(self):
            if phase == "selector-create-failure":
                reached.append(phase)
                raise OSError("private-native-canary")
            super().__init__()
            selector_handles.append(self)
            if phase == "selector-create" and not reached:
                send(phase)

        def register(self, *args, **kwargs):
            result = super().register(*args, **kwargs)
            if phase == "selector-register-failure":
                reached.append(phase)
                raise OSError("private-native-canary")
            if phase == "selector-register" and not reached:
                send(phase)
            return result

        def close(self):
            if phase == "selector-close" and not reached:
                send(phase)
            if phase == "selector-close-unresolved":
                reached.append(phase)
                raise OSError("private-native-canary")
            super().close()
            if phase == "selector-close-failure":
                reached.append(phase)
                raise OSError("private-native-canary")

    def facts():
        open_descriptors = []
        for descriptor, device, inode in descriptors:
            try:
                details = real_fstat(descriptor)
            except OSError:
                continue
            if (details.st_dev, details.st_ino) == (device, inode):
                open_descriptors.append(descriptor)
        open_selectors = []
        for handle in selector_handles:
            try:
                open_selectors.append(handle.fileno())
            except (OSError, ValueError):
                pass
        result = {"boundaryReached": bool(reached), "rawDescriptorsClosed": not open_descriptors,
                  "selectorsClosed": not open_selectors,
                  "scratchRemoved": all(not Path(handle.name).exists() for handle in scratches),
                  "leadersReaped": all(child.returncode is not None for child in launched),
                  "streamsClosed": all(child.stdout.closed for child in launched),
                  "cleanupAttempts": len(cleanups), "mode": mode}
        assert result["rawDescriptorsClosed"]
        assert result["selectorsClosed"] is (phase != "selector-close-unresolved")
        assert result["scratchRemoved"] is (phase != "scratch-cleanup-unresolved")
        assert result["leadersReaped"] and result["streamsClosed"]
        for child in launched:
            try:
                os.killpg(child.pid, 0)
            except ProcessLookupError:
                continue
            raise AssertionError("native group remains before fallback")
        return result

    def change_handler(selected, handler):
        result = real_signal(selected, handler)
        if scopes and handler == previous[selected] and selected in scopes[0].cancellation.previous and not reached:
            if phase == "restore-term" and selected == signal.SIGTERM or phase == "restore-int" and selected == signal.SIGINT:
                send(phase, signal.SIGINT)
            elif phase == "restored-term-fatal" and selected == signal.SIGTERM:
                reached.append(phase)
                state = facts()
                assert state["cleanupAttempts"] == 1
                (root / "fatal-cleanup.json").write_text(json.dumps(state))
                os.kill(os.getpid(), signal.SIGTERM)  # Host default, only AFTER owned resources are gone.
        return result

    def observe(frame, event, arg):
        if event == "call" and scopes and frame.f_code is scopes[0].cleanup.__code__:
            cleanups.append(True)

    def trace(frame, event, arg):
        if event == "line":
            if frame.f_code is target.__code__ and frame.f_lineno == scope_line:
                visits.append(True)
                if not scopes:
                    scopes.append(frame.f_locals["scope"])
                if phase == "cleanup-dispatch" and len(visits) == 2 and not reached:
                    assert not scopes[0].claimed
                    send(phase)
            if scopes and not reached:
                if (phase in {"cleanup-entry", "cleanup-entry-repeat", "cleanup-claimed"}
                        and frame.f_code is CleanupScope.__exit__.__code__ and frame.f_locals["self"] is scopes[0]
                        and frame.f_lineno == (claimed_line if phase == "cleanup-claimed" else exit_line)):
                    if phase == "cleanup-claimed":
                        assert scopes[0].claimed and scopes[0].cancellation.depth == 0
                    send(phase)
                    if phase == "cleanup-entry-repeat":
                        send(phase, signal.SIGTERM if signum == signal.SIGINT else signal.SIGINT)
                if (phase in restore_lines and frame.f_code is DefaultCancellation.restore.__code__
                        and frame.f_locals["self"] is scopes[0].cancellation and frame.f_lineno == restore_lines[phase]):
                    send(phase)
        return trace

    try:
        with ExitStack() as patches:
            for name, implementation in (("open", opening), ("close", closing), ("fstat", stating), ("read", reading), ("write", writing)):
                patches.enter_context(patch.object(profiles.os, name, side_effect=implementation))
            patches.enter_context(patch.object(profiles.tempfile, "TemporaryDirectory", side_effect=temporary))
            patches.enter_context(patch.object(profiles.subprocess, "Popen", side_effect=spawn))
            patches.enter_context(patch.object(profiles.selectors, "DefaultSelector", ObservedSelector))
            patches.enter_context(patch.object(profiles, "worker_command", return_value=child_command))
            patches.enter_context(patch.object(profiles, "sys", SimpleNamespace(platform="darwin", executable=sys.executable)))
            patches.enter_context(patch("mobile_release.cancellation.signal.signal", side_effect=change_handler))
            sys.setprofile(observe)
            sys.settrace(trace)
            try:
                if area == "read":
                    profiles.read_profile_bytes(source)
                elif area == "source":
                    profiles.authenticate_cms(content, deadline=InspectionDeadline())
                else:
                    profiles._capture_profile(root, InspectionDeadline())
                raise AssertionError("cancelled or unresolved-cleanup profile returned success")
            except KeyboardInterrupt as error:
                held.append(error)
                assert not phase.endswith(("-failure", "-unresolved"))
            except ValidationError as error:
                held.append(error)
                expected = {
                    "fstat-failure": "provisioning input could not be read safely",
                    "read-failure": "provisioning input could not be read safely",
                    "input-write-failure": "Apple profile private input could not be prepared safely",
                    "selector-create-failure": "Apple profile authentication could not complete safely",
                    "selector-register-failure": "Apple profile authentication could not complete safely",
                    "selector-close-failure": "selector cleanup could not be confirmed",
                    "selector-close-unresolved": "selector cleanup could not be confirmed",
                    "scratch-cleanup-failure": "private workspace cleanup could not be confirmed",
                    "scratch-cleanup-unresolved": "private workspace cleanup could not be confirmed",
                }
                assert phase in expected and expected[phase] in str(error)
                assert "private-native-canary" not in str(error)
            finally:
                sys.settrace(None)
                sys.setprofile(None)
        result = facts()
        assert reached and len(cleanups) == 1
        assert previous == {sig: signal.getsignal(sig) for sig in previous}
        if area == "source" and phase in {"scratch-create", "input-open", "input-write", "input-close", "input-write-failure"}:
            assert not launched, "pending setup cancellation launched native work"
        result.update(handlersRestored=True, actualProductionOwners=True, checkedBeforeFallback=True,
                      unresolvedCleanupReported=phase.endswith("-unresolved"))
        return result
    finally:
        sys.settrace(None)
        sys.setprofile(None)
        for sig, handler in previous.items():
            real_signal(sig, handler)
        for child in launched:
            kill_owned_group(child.pid, process=child)
            child.wait(timeout=3)
            child.stdout.close()
        for handle in selector_handles:
            real_selector.close(handle)
        for descriptor, device, inode in descriptors:
            try:
                details = real_fstat(descriptor)
                if (details.st_dev, details.st_ino) == (device, inode):
                    real_close(descriptor)
            except OSError:
                pass
        for handle in scratches:
            real_temp.cleanup(handle)
        held.clear()


def run_case(root: Path, mode: str, signum: int = signal.SIGINT) -> dict:
    command = [sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()),
               str(Path(mobile_release.__file__).resolve().parent.parent), str(root), mode, str(int(signum))]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        output, error = process.communicate(timeout=15)
        if mode.endswith("restored-term-fatal"):
            assert process.returncode == -signal.SIGTERM and not output and not error, error.decode(errors="replace")
            result = json.loads((root / "fatal-cleanup.json").read_text())
            result["hostTerminatedAfterCleanup"] = True
            return result
        assert process.returncode == 0 and not error, error.decode(errors="replace")
        return json.loads(output)
    finally:
        kill_owned_group(process.pid, process=process)
        process.wait(timeout=3)
        process.stdout.close(); process.stderr.close()
        if (root / "native.pid").exists():
            kill_owned_group(int((root / "native.pid").read_text()))


if __name__ == "__main__":
    print(json.dumps(driver(Path(sys.argv[1]), sys.argv[2], int(sys.argv[3]))))
