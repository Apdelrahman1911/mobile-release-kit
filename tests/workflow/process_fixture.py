"""Real, bounded process-tree fixtures; never imported by production code.

The public transport still receives only gh commands. Its Popen seam launches
this static fixture through the current interpreter to avoid macOS cold-script
execution latency. Session creation, pipes, waits, signals and cleanup are real.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ARGV = ["gh", "api", "--method", "GET", "fixed"]


def record(path: Path, text: str) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(text)
    temporary.replace(path)  # Readers must never see a half-written PID/JSON.


def alive(pid: int) -> bool:
    """A zombie cannot execute; adopted descendants may await OS reaping."""
    result = subprocess.run(["ps", "-p", str(pid), "-o", "stat="],
                            text=True, capture_output=True, timeout=5)
    state = result.stdout.strip()
    if result.returncode not in {0, 1}:
        raise AssertionError("could not inspect owned fixture process")
    return bool(state) and not state.startswith("Z")


def assert_dead(pid: int) -> None:
    deadline = time.monotonic() + 3
    while alive(pid) and time.monotonic() < deadline:
        time.sleep(0.02)
    if alive(pid):
        raise AssertionError(f"owned fixture process {pid} survived production cleanup")


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
            if not ready() or not alive(int(child_path.read_text())):
                raise ReadinessFailure("fixture did not fork before injected cancellation")
            observations["ready"] = True
            # The OS child exists, but Transport has not received its handle.
            os.kill(os.getpid(), signal.SIGTERM)
        return process

    class ObservedSelector(real_selector):
        def select(self, timeout=None):
            orphaned_pipe = (bool(launched) and ready() and launched[0].poll() is not None
                             and alive(int(child_path.read_text())))
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
        assert_dead(launched[0].pid)
        if mode == "unready":
            assert not (root / "gh.pid").exists() and not child_path.exists()
        else:
            assert observations["ready"] and child_path.is_file()
            assert_dead(int(child_path.read_text()))
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
            assert alive(int((root / "child.pid").read_text()))
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
