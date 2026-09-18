"""Closed hosted Environment fixture, never a product/bootstrap fallback.

Only the reviewed native entry supplies core + one precreated control.json.
This file also contains the two fixed ordinary-owned targets. No arbitrary
argv, runner, resolver, environment enable or lifetime/result constructor exists.
"""
import sys
import time

# Count fixture imports, source checks and preparation in the original child
# allowance. Inert imports by contract tests do not even read this clock.
_ENTRY_STARTED = time.monotonic() if __name__ == "__main__" else None

import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import signal
import stat


CONTROL_LIMIT = 65536
SOURCE_LIMIT = 512 * 1024
READY_MARKER = b"MRK_ENVIRONMENT_TARGET_READY_V1\n"
CAP_STDOUT, CAP_STDERR = 8192, 8193
CASES = frozenset({"L3a", "L3b", "L3c", "L3d", "L4", "L5"})
CONTROL_KEYS = frozenset({"schemaVersion", "case", "runId", "ownerGeneration", "context", "profile",
    "python", "core", "cwd", "projectRoot", "inputManifestSha256", "shimSha256", "observerSha256", "relayIdentity"})
CONTEXT_KEYS = frozenset({"projectId", "draftRevision", "baselineGeneration", "platform", "operation"})
PROFILES = {"linux-gnu-x86_64": ("linux", "x86_64"), "macos-arm64": ("darwin", "arm64")}
_ROOTS = []
_SUBJECT_STARTED = False
_ENGINE_OBSERVATION = None
_PAUSE = signal.pause


class RetainedUnknown(BaseException):
    """Original custody cannot be released by an exception reporter."""


def require(value):
    if not value:
        raise AssertionError("fixed Environment fixture refused")


def hexadecimal(value, width):
    return type(value) is str and len(value) == width and all(c in "0123456789abcdef" for c in value)


def absolute(value):
    return (type(value) is str and value.startswith("/") and len(value) <= 4096
            and all(ord(c) >= 32 and ord(c) != 127 and c != "\\" for c in value)
            and all(part and part not in {".", ".."} for part in value[1:].split("/")))


def _pairs(items):
    result = {}
    for key, value in items:
        require(key not in result)
        result[key] = value
    return result


def _constant(_value):
    raise AssertionError("non-finite fixture DATA")


def parse_control(raw):
    require(type(raw) is bytes and 0 < len(raw) <= CONTROL_LIMIT)
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
    require(type(value) is dict and set(value) == CONTROL_KEYS
            and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
            and type(value["case"]) is str and value["case"] in CASES
            and hexadecimal(value["runId"], 32) and hexadecimal(value["ownerGeneration"], 32)
            and type(value["profile"]) is str and value["profile"] in PROFILES
            and all(absolute(value[key]) for key in ("python", "core", "cwd", "projectRoot"))
            and all(hexadecimal(value[key], 64) for key in ("inputManifestSha256", "shimSha256", "observerSha256")))
    context, identity = value["context"], value["relayIdentity"]
    require(type(context) is dict and set(context) == CONTEXT_KEYS
            and type(context["projectId"]) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", context["projectId"]) is not None
            and all(type(context[key]) is int and 0 <= context[key] < 2**32 - 1 for key in ("draftRevision", "baselineGeneration"))
            and context["platform"] == "android" and context["operation"] == "build"
            and type(identity) is list and len(identity) == 4
            and all(type(part) is int and part >= 0 for part in identity)
            and stat.S_ISREG(identity[3]) and stat.S_IMODE(identity[3]) == 0o600)
    return value


class ReadSlot:
    """One preregistered source/control read and one observed original close."""
    def __init__(self):
        self.fd, self.state = None, "NEW"
        self.identity, self.error = None, None
        self.open, self.read, self.fstat, self.close = os.open, os.read, os.fstat, os.close
        _ROOTS.append(self)

    @staticmethod
    def facts(details):
        return (details.st_dev, details.st_ino, details.st_mode, details.st_uid, details.st_gid,
                details.st_nlink, details.st_size, details.st_mtime_ns, details.st_ctime_ns)

    def content(self, path, limit, *, mode=None):
        require(self.state == "NEW" and absolute(str(path)))
        self.state = "OPENING"
        try:
            self.fd = self.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            self.state = "OPEN"
            details = self.fstat(self.fd)
            self.identity = self.facts(details)
            require(stat.S_ISREG(details.st_mode) and details.st_nlink == 1 and details.st_uid == os.getuid()
                    and 0 <= details.st_size <= limit and stat.S_IMODE(details.st_mode) & 0o022 == 0
                    and (mode is None or stat.S_IMODE(details.st_mode) == mode))
            content = bytearray()
            while len(content) <= limit:
                chunk = self.read(self.fd, min(65536, limit + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
            require(len(content) == details.st_size and self.facts(self.fstat(self.fd)) == self.identity)
            return bytes(content)
        except BaseException as error:
            self.error = error
            raise
        finally:
            if self.state == "OPEN":
                descriptor, self.fd = self.fd, None
                self.state = "UNKNOWN"
                try:
                    self.close(descriptor)
                    self.state = "CLOSED"
                except BaseException as error:
                    if self.error is None:
                        self.error = error
            if self.state != "CLOSED":
                raise RetainedUnknown()


def _runtime_flags():
    require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and sys.version_info[:3] == (3, 14, 7) and os.name == "posix"
            and sys.platform in {"linux", "darwin"} and os.getuid() != 0)


def _admit(core, control_path):
    _runtime_flags()
    require(absolute(core) and absolute(control_path) and absolute(__file__)
            and Path(control_path).name == "control.json")
    value = parse_control(ReadSlot().content(control_path, CONTROL_LIMIT, mode=0o400))
    root = Path(control_path).parent
    details = root.lstat()
    require(stat.S_ISDIR(details.st_mode) and stat.S_IMODE(details.st_mode) == 0o700
            and details.st_uid == os.getuid() and not root.is_symlink()
            and value["relayIdentity"][2] == os.getuid()
            and value["core"] == core and value["python"] == os.path.abspath(sys.executable)
            and value["cwd"] == os.getcwd() and PROFILES[value["profile"]] == (sys.platform, os.uname().machine))
    shim = Path(__file__)
    require(shim.name == "native_desktop_environment.py" and shim.parent.name == "tests")
    observer = shim.parent / "workflow" / "command_bootstrap_fixture.py"
    require(hashlib.sha256(ReadSlot().content(shim, SOURCE_LIMIT)).hexdigest() == value["shimSha256"]
            and hashlib.sha256(ReadSlot().content(observer, SOURCE_LIMIT)).hexdigest() == value["observerSha256"])
    # Native bound the complete Inputs/source/runtime manifest before this fixed
    # spawn. Its supplied digest is an identity, not a newly invented trust root.
    return value, root, observer


def _write_target(descriptor, data):
    remaining = memoryview(data)
    while remaining:
        try:
            count = os.write(descriptor, remaining)
        except BlockingIOError:
            time.sleep(0.01)
            continue
        require(type(count) is int and 0 < count <= len(remaining))
        remaining = remaining[count:]


def _target(kind, started):
    _runtime_flags()
    require(kind in {"--target-active", "--target-cap"})
    if kind == "--target-cap":
        # The marker is INSIDE stdout's8192, not an extra allowance. C's actual
        # source counters, not this intent or an exception string, prove the cap.
        _write_target(1, READY_MARKER + b"x" * (CAP_STDOUT - len(READY_MARKER)))
        _write_target(2, b"y" * CAP_STDERR)
    else:
        _write_target(1, READY_MARKER)
        # Fixed cooperative work only. The unchanged ordinary owner has its
        # earlier integer<=3s bound and original STOP route; no child/trace FD.
        while time.monotonic() < started + 5.0:
            time.sleep(0.01)
    return 0


def _git_path(path, profile):
    if profile == "linux-gnu-x86_64":
        return path == "/usr/bin/git"
    return (path == "/Library/Developer/CommandLineTools/usr/bin/git"
            or re.fullmatch(r"/Applications/Xcode(?:_[A-Za-z0-9_.-]+)?\.app/Contents/Developer/usr/bin/git", path) is not None)


class EngineObservation:
    """Retain the unchanged original engine; never construct a second owner."""
    def __init__(self, engine_type, request_type, guard_type, input_type, service_type, value, started):
        self.engine_type, self.request_type = engine_type, request_type
        self.guard_type, self.input_type, self.service_type = guard_type, input_type, service_type
        self.value, self.started, self.original = value, started, engine_type.__init__
        self.engine = self.request = self.guard = self.source = self.service = None
        self.installed = self.settled_observed = self.stop_attempted = False
        self.errors = []
        _ROOTS.append(self)

        def initialize(actual, original_started):
            require(self.engine is None and type(actual) is self.engine_type)
            self.engine = actual  # Before the one unchanged initializer/effects.
            require(original_started is self.started)
            return self.original(actual, original_started)

        self.initialize = initialize

    def install(self):
        require(not self.installed and self.engine_type.__init__ is self.original)
        self.installed = True
        self.engine_type.__init__ = self.initialize

    def bind(self):
        actual = self.engine
        require(type(actual) is self.engine_type and actual.started is self.started
                and type(actual.request) is self.request_type and type(actual.guard) is self.guard_type
                and type(actual.input) is self.input_type and type(actual.service) is self.service_type)
        request, guard, source, service = actual.request, actual.guard, actual.input, actual.service
        require(source.guard is guard and source.acquired and source.active and source.request_returned
                and service.request is request and service.guard is guard and service.source is source
                and request.run_id == self.value["runId"] and request.owner_generation == self.value["ownerGeneration"]
                and request.context == self.value["context"]
                and request.native == {key: self.value[key] for key in ("profile", "projectRoot", "cwd")})
        if self.request is None:
            self.request, self.guard, self.source, self.service = request, guard, source, service
        require(self.request is request and self.guard is guard and self.source is source and self.service is service)
        return guard, source

    def settled(self):
        guard, source = self.bind()
        verdict = guard.lifetime_ledger.verdict()
        require(verdict.complete and not verdict.fatal and verdict.contained and verdict.cleanup_complete
                and verdict.profile_calls == 0 and guard.handler_state == "RESTORED"
                and guard._environment_source is None and source.closed and source.close_claimed
                and not source.custody_unknown and self.service.lookup.closed
                and all(slot.owned and slot.close_claimed and slot.closed
                        for slot in (self.engine.output, self.engine.error_output)))
        self.settled_observed = True

    def stop(self):
        # A failed initializer may never have created/acquired input. Do not
        # invent that object or acquisition, consult a pathname, or run cleanup.
        actual = self.engine
        source = None if actual is None else getattr(actual, "input", None)
        if self.stop_attempted or type(source) is not self.input_type or not source.acquired:
            return
        self.stop_attempted = True
        try:
            require(source.guard is None or source.guard is getattr(actual, "guard", None))
            source.stop("cancelled")  # Only this retained original input's STOP.
        except BaseException as error:
            self.errors.append(error)

    def restore(self):
        require(self.settled_observed and not self.stop_attempted and not self.errors
                and self.installed and self.engine_type.__init__ is self.initialize)
        self.engine_type.__init__ = self.original


class GitSeam:
    """One fixed redirection after the real DiagnosticsRun/ToolLookup admission."""
    def __init__(self, value, case, original, observation, tool_environment):
        self.value, self.case, self.original = value, case, original
        self.observation, self.tool_environment = observation, tool_environment
        self.guard, self.source, self.error = None, None, None
        self.intercepts, self.other_calls, self.no_next = 0, 0, True
        self.missing_reason = "git-not-admitted"
        _ROOTS.append(self)

    def __call__(self, argv, *, environ, cwd, timeout, capture, text, output_limit, cancellation):
        if self.intercepts:
            self.no_next = False
            raise AssertionError("no command after the fixed intercepted call")
        guard, source = self.observation.bind()
        require(cancellation is guard and guard._environment_source is source
                and source.active and source.request_returned and source.acquired and not source.close_claimed
                and type(argv) is tuple and len(argv) == 2 and all(type(arg) is str for arg in argv)
                and isinstance(cwd, Path) and str(cwd) == self.value["cwd"]
                and type(timeout) is int and 1 <= timeout <= 3 and capture is True and text is False
                and type(output_limit) is int and output_limit == 16384 and type(environ) is dict)
        if self.guard is None:
            self.guard, self.source = guard, source
        require(self.guard is guard and self.source is source)
        is_git = argv[1] == "--version" and _git_path(argv[0], self.value["profile"])
        role = "git" if is_git else "developer-selection" if argv == ("/usr/bin/xcode-select", "-p") else "java"
        # These role environments are identical for Java/javac/Git/selector.
        # The real source-bound call site has already admitted/rechecked the
        # current tool; this check is not a fabricated ToolBinding or resolver.
        require(environ == self.tool_environment(self.value["profile"], role)
                and (argv[1] in {"-p", "-version"} or is_git))
        options = dict(environ=environ, cwd=cwd, timeout=timeout, capture=capture,
                       text=text, output_limit=output_limit, cancellation=guard)
        if not is_git:
            self.other_calls += 1
            require(self.other_calls <= 4)
            return self.original(argv, **options)  # Mac selector never uses the Git observer/nonce.
        guard.check()
        remaining = int(source.work_end - time.monotonic())
        if remaining < 1:
            self.missing_reason = "insufficient-work-margin"
            source.stop("timed-out")
            guard.check()
            raise AssertionError("original STOP did not stop the call")
        options["timeout"] = min(timeout, 3, remaining)
        self.intercepts = 1
        kind = "--target-cap" if self.value["case"] in {"L4", "L5"} else "--target-active"
        target = (self.value["python"], "-I", "-S", "-B", str(Path(__file__)), kind)
        with self.case:
            try:
                self.original(target, **options)  # Unchanged ordinary owner, exact original guard.
            except BaseException as error:
                self.error = error
                raise  # Preserve the actual object and typed original ledger.
            raise AssertionError("fixed incomplete helper unexpectedly returned complete output")


def _settled_facts(value, seam, case, relay, process_error):
    require(seam.intercepts == 1 and seam.no_next and seam.error is not None and case.held_settled
            and case.released and not case.errors and not relay.broken)
    case.require_finality()
    verdict = seam.guard.lifetime_ledger.verdict()
    require(verdict.complete and not verdict.fatal and verdict.contained and verdict.cleanup_complete
            and verdict.command_dispatched is True and verdict.profile_calls == 0
            and seam.guard.handler_state == "RESTORED" and seam.source.closed)
    outcome, rows = case.outcome, case.rows
    require(outcome.original_finality is not None and outcome.run_tool.attempted and outcome.no_target is None
            and outcome.result_integrity == "incomplete")
    capture = rows["C"]["capture"]
    require(capture["failed"] is False and capture["limit"] == 16384
            and all(type(capture[key]) is int and capture[key] >= 0 for key in ("stdout", "stderr")))
    stop_before_work = None
    if value["case"] in {"L4", "L5"}:
        require(isinstance(seam.error, process_error) and seam.error.dispatched is True
                and seam.error.contained is True and seam.error.cleanup_complete is True
                and seam.source.stop_reason == "none" and capture["overflow"] is True
                and capture["stdout"] == CAP_STDOUT and capture["stderr"] == CAP_STDERR)
    else:
        require(capture["stdout"] == len(READY_MARKER) and capture["stderr"] == 0 and capture["overflow"] is False
                and relay.ready_sent and seam.source.stop_reason == "cancelled")
        ready, stopped = rows["C"].get("target_ready"), rows["C"].get("stop_received")
        require(ready is not None and stopped is not None
                and all(type(stopped[key]) is int for key in ("run", "at", "remaining"))
                and stopped["run"] == outcome._engine.ctx.run and ready["run"] == stopped["run"]
                and type(ready["at"]) is int and ready["at"] <= stopped["at"]
                and stopped["remaining"] == stopped["run"] - stopped["at"]
                and 1 <= stopped["remaining"] <= 3_000_000_000)
        stop_before_work = stopped["remaining"]
    reason = seam.source.stop_reason if seam.source.stop_reason != "none" else "command-incomplete"
    # C/A normal return gates + their actual waits and W's actual target bytes
    # prove trace closes. No owner_finish row or CLOEXEC alone supplies them.
    c_close = outcome._engine.wait.status_code in (0, 2) and outcome._engine.wait.status_code == rows["C"]["owner_finish"]["code"]
    a_close = rows["C"]["owner_wait"]["code"] in (0, 2) and rows["C"]["owner_wait"]["code"] == rows["A"]["owner_finish"]["code"]
    w_close = set(rows["W"]) == {"boot"} and outcome._engine.outputs[0].startswith(READY_MARKER)
    return {"intercepts": 1, "readyObserved": relay.ready_sent, "noNextCall": seam.no_next, "reason": reason, "coreCode": 0,
        "commandNonce": outcome.nonce.hex(), "recipeSha256": hashlib.sha256(case.recipe.encode()).hexdigest(),
        "resultIntegrity": outcome.result_integrity, "dispatched": outcome.run_tool.attempted,
        "contained": verdict.contained, "cleanupComplete": verdict.cleanup_complete,
        "cWait": outcome._engine.wait.status_code, "aWait": rows["C"]["owner_wait"]["code"],
        "cFinish": rows["C"]["owner_finish"]["code"], "aFinish": rows["A"]["owner_finish"]["code"],
        "targetWait": {key: rows["A"]["owner_wait"][key] for key in ("kind", "code")},
        "targetMarker": outcome._engine.outputs[0].startswith(READY_MARKER),
        "readersJoined": all(task.joined for task in outcome._engine.ctx.tasks)
            and rows["C"]["owner_io"]["joined"] and rows["A"]["owner_io"]["joined"],
        "traceCloses": {"o": all(slot["state"] == "CLOSED" for slot in case.slots), "c": c_close, "a": a_close, "w": w_close},
        "stopBeforeWorkNs": stop_before_work,
        "capture": {key: capture[key] for key in ("stdout", "stderr", "limit", "overflow")}}


def main():
    global _SUBJECT_STARTED, _ENGINE_OBSERVATION
    started = _ENTRY_STARTED
    require(type(started) is float)
    if len(sys.argv) == 2 and sys.argv[1] in {"--target-active", "--target-cap"}:
        return _target(sys.argv[1], started)
    require(len(sys.argv) == 3)
    value, root, observer_path = _admit(sys.argv[1], sys.argv[2])
    observer = runpy.run_path(str(observer_path))  # Exact native-bound source, before subject effects.
    require(observer["OBSERVE_READY"] == READY_MARKER and observer["OBSERVE_HELD"] == "observe-held")
    relay = observer["ObserveRelay"](str(root / "relay.trace"), tuple(value["relayIdentity"]),
        case=value["case"], run_id=value["runId"], owner_generation=value["ownerGeneration"])
    _ROOTS.extend((observer, relay))
    relay.acquire()
    sys.path.insert(0, value["core"])
    from mobile_release import _command_process as command
    from mobile_release import _desktop_environment_engine as engine
    from mobile_release import environment_diagnostics as service
    from mobile_release._desktop_environment_control import EnvironmentInput
    from mobile_release._desktop_environment_protocol import EnvironmentRequest, context_value
    from mobile_release.cancellation import DefaultCancellation
    from mobile_release.environment_diagnostics_tools import tool_environment
    from mobile_release.owned_process import ProcessError
    require(context_value(value["context"]) == value["context"])
    case = observer["CommandCase"](command, root / "command", "observe-held")
    _ROOTS.extend((case, command, engine, service))
    case.prepare_held(relay)  # All files/readers/recipe before service/lookup admission.
    original = service.run_owned
    observation = EngineObservation(engine._Engine, EnvironmentRequest, DefaultCancellation,
        EnvironmentInput, service.DiagnosticsRun, value, started)
    _ENGINE_OBSERVATION = observation
    observation.install()
    seam = GitSeam(value, case, original, observation, tool_environment)
    service.run_owned = seam
    _SUBJECT_STARTED = True
    code = engine.main(started=started)  # Same actual engine, scope/input/guard/terminal/stdio closes.
    require(code == 0 and not engine._RETAINED and not command._RETAINED and service.run_owned is seam)
    observation.settled()  # Also binds an unexecuted run's actual original request.
    if seam.intercepts == 0:
        case.close_unactivated()
        relay.finish("unexecuted", {"intercepts": 0, "readyObserved": False, "observerClosed": case.held_settled,
            "noNextCall": seam.no_next, "reason": seam.missing_reason, "coreCode": code})
    else:
        facts = _settled_facts(value, seam, case, relay, ProcessError)
        relay.finish("settled", facts)
    require(relay.close_owned())  # This actual return, plus native wait0, is the relay close gate.
    require(all(slot.state == "CLOSED" for slot in _ROOTS if type(slot) is ReadSlot))
    require(service.run_owned is seam)
    observation.restore()  # Both wrappers remain on any unresolved/error tail.
    service.run_owned = original
    relay.release()
    return code


def _stop_before_retention(error):
    _ROOTS.append(error)
    if _ENGINE_OBSERVATION is not None:
        _ENGINE_OBSERVATION.stop()  # Actual STOP before parking, never a new owner.


def retain_originals(error):
    # No new reader/report owner, PID search, cleanup retry or task replacement.
    # The native owner continues its original STOP/joins through H; unresolved
    # originals stay rooted here until the outer hosted timeout disposes the VM.
    # That disposal is deliberately not a successful application receipt.
    _stop_before_retention(error)
    while True:
        try:
            _PAUSE()
        except BaseException:
            pass  # No exception reporter may drop these original retained slots.


if __name__ == "__main__":
    try:
        result = main()
    except RetainedUnknown as error:
        retain_originals(error)
    except BaseException as error:
        if _SUBJECT_STARTED or any(getattr(slot, "state", "CLOSED") not in {"NEW", "CLOSED"} for slot in _ROOTS):
            retain_originals(error)
        result = 78
    raise SystemExit(result)
