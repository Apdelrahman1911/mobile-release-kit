"""Real default signals at exact profile resource owners, including installed wheels.

No selector/Popen facade represents production cleanup. C/K execute the fixed
production helper; V alone is synthetic and inherits only null standard I/O.
Unknown custody survives GC and outer unwinding; this fixture never re-signals a
marker PID or recursively deletes an unresolved product workspace.
"""
from __future__ import annotations

import gc
import inspect
import json
import os
import signal
import stat
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
from mobile_release import _native_process as native
from mobile_release import _profile_process as owner
from mobile_release import ios_profiles as profiles
from mobile_release.cancellation import CleanupScope, DefaultCancellation
from mobile_release.errors import ValidationError
from mobile_release.inspection import InspectionDeadline
from workflow.profile_process_fixture import (
    FixtureDriver, FixtureWorkspace, ProfileBindings, _assert_native_finality,
    assert_fixture_idle,
)
from workflow.process_fixture import observer_environment, record


UNKNOWN_RESOURCE_MODES = frozenset({
    "read-restored-term-fatal",
    "source-restored-term-fatal",
    "capture-restored-term-fatal",
    "read-restore-int",
    "source-restore-int",
    "capture-restore-int",
    "capture-control-close-failure",
    "capture-status-close-failure",
    "capture-payload-close-failure",
    "capture-payload-close-unresolved",
    "source-control-close-failure",
    "source-status-close-failure",
    "source-payload-close-failure",
    "source-payload-close-unresolved",
    "source-scratch-cleanup-failure",
    "source-scratch-cleanup-unresolved",
})


def anchor(function, token):
    lines, first = inspect.getsourcelines(function)
    matches = [first + index for index, line in enumerate(lines) if token in line]
    assert matches, "the fixture no longer binds the actual production boundary"
    return matches[0]


def driver(root: Path, mode: str, signum: int) -> dict:
    assert_fixture_idle()  # Before file, handler, binding or native acquisition.
    real_open, real_close, real_fstat = os.open, os.close, os.fstat
    real_read, real_write, real_mkdtemp, real_signal = os.read, os.write, tempfile.mkdtemp, signal.signal
    real_descriptor_open = profiles._ProfileDescriptor.open
    real_scratch_acquire, real_scratch_cleanup = profiles.ScratchLease.acquire, profiles.ScratchLease.cleanup
    real_capture, real_outer_init, real_pipe = profiles._capture_profile, owner._Outer.__init__, native.Acquisition.pipe
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    assert previous == {signal.SIGINT: signal.default_int_handler, signal.SIGTERM: signal.SIG_DFL}
    area, phase = mode.split("-", 1)
    assert area in {"read", "source", "capture"}
    target = profiles.read_profile_bytes if area == "read" else profiles.authenticate_cms
    source = root / "fictional-profile"
    content = b"fictional-profile-canary"
    source.write_bytes(content)
    source.chmod(0o600)
    scopes, outers, scratches, finalities = [], [], [], []
    profile_records, native_records, opening_handles = {}, {}, []
    raw_close_attempts, lease_close_attempts = {}, {}
    reached, cleanup_calls, visits = [], [], []
    original = SystemExit(37)
    original.__notes__ = object()
    original_notes = original.__notes__
    held_error = None
    pipe_count = 0
    capture_scratch = None
    binding = ProfileBindings(root, "success")

    scope_line = anchor(target, "with scope:")
    private_exit_line = anchor(profiles._ProfileCleanupScope.__exit__, "if self.claimed:")
    base_exit_line = anchor(CleanupScope.__exit__, "if self.claimed:")
    base_claimed_line = anchor(CleanupScope.__exit__, "try:")
    outer_cleanup_entry = anchor(owner._Outer.cleanup, "ctx = self.context")
    outer_cleanup_claimed = anchor(owner._Outer.cleanup, "cutoff = ctx.begin_cleanup()")
    outer_cleanup_dispatch = anchor(owner._Outer.run, "self.cleanup()")
    restore_lines = {"restore-entry": anchor(DefaultCancellation.restore, "self.depth += 1"),
                     "restore-active": anchor(DefaultCancellation.restore, "failed = False")}

    def guard():
        return (outers[0].context.cancellation if area == "capture" and outers else
                scopes[0].cancellation if scopes else None)

    def send(boundary, selected=signum):
        reached.append(boundary)
        os.kill(os.getpid(), selected)  # Own current driver, never a reported PID.

    def profile_open(handle, path, *arguments, **keywords):
        profile_records[id(handle)] = {"lease": handle, "path": str(path), "descriptor": None}
        opening_handles.append(handle)
        try:
            return real_descriptor_open(handle, path, *arguments, **keywords)
        finally:
            assert opening_handles.pop() is handle

    def opening(path, *arguments, **keywords):
        descriptor = real_open(path, *arguments, **keywords)
        if opening_handles:
            handle = opening_handles[-1]
            details = real_fstat(descriptor)
            profile_records[id(handle)].update(descriptor=descriptor, identity=(details.st_dev, details.st_ino))
            subject = Path(path) == source or Path(path).name == "cms.der"
            if subject and phase in {"open", "input-open"} and not reached:
                send(phase)  # Actual FD exists before Python open returns it.
        return descriptor

    def subject_record(descriptor, *, closing=False):
        for item in profile_records.values():
            handle = item["lease"]
            if not (Path(item["path"]) == source or Path(item["path"]).name == "cms.der"):
                continue
            if closing:
                matches = handle.state == "CLOSING" and handle.retired_number == descriptor
            else:
                matches = handle.state == "OWNED" and handle.number == descriptor
            if matches:
                return item
        return None

    def stating(descriptor):
        result = real_fstat(descriptor)
        if subject_record(descriptor) is not None and not reached:
            if phase == "fstat-failure":
                reached.append(phase)
                raise OSError("private-native-canary")
            if phase == "fstat":
                send(phase)
        return result

    def reading(descriptor, count):
        result = real_read(descriptor, count)
        if subject_record(descriptor) is not None:
            if phase == "cleanup-prologue-systemexit" and area == "read" and result == b"":
                raise original
            if not reached and phase == "read-failure":
                reached.append(phase)
                raise OSError("private-native-canary")
            if not reached and phase == "read":
                send(phase)
        return result

    def writing(descriptor, data):
        result = real_write(descriptor, data)
        if subject_record(descriptor) is not None and not reached:
            if phase == "input-write-failure":
                reached.append(phase)
                raise OSError("private-native-canary")
            if phase == "input-write":
                send(phase)
        return result

    def closing(descriptor):
        handles = [item["lease"] for item in profile_records.values()
                   if item["lease"].state == "CLOSING" and item["lease"].retired_number == descriptor]
        assert len(handles) <= 1
        if handles:
            key = id(handles[0])
            raw_close_attempts[key] = raw_close_attempts.get(key, 0) + 1
            assert raw_close_attempts[key] == 1, "profile raw close was replayed"
        item = subject_record(descriptor, closing=True)
        result = real_close(descriptor)
        if item is not None and phase in {"close", "input-close"} and not reached:
            send(phase)
        return result

    def temporary(*arguments, **keywords):
        # TMPDIR already names the explicit controller-owned fixture root.
        path = real_mkdtemp(*arguments, **keywords)
        assert Path(path).parent == root
        if phase == "scratch-create" and not reached:
            send(phase)
        return path

    def acquire(lease):
        path = real_scratch_acquire(lease)
        scratches.append(lease)
        assert path.parent == root and stat.S_IMODE(path.stat().st_mode) == 0o700
        return path

    def cleanup_scratch(lease):
        if phase == "scratch-cleanup" and not reached:
            send(phase)
        if phase == "scratch-cleanup-unresolved" and not reached:
            reached.append(phase)
            raise OSError("private-native-canary")
        result = real_scratch_cleanup(lease)
        if phase == "scratch-cleanup-failure" and not reached:
            reached.append(phase)
            raise OSError("private-native-canary")
        return result

    def capture(directory, deadline, *, cancellation=None, finality=None):
        assert finality is not None
        finalities.append(finality)
        result = real_capture(directory, deadline, cancellation=cancellation, finality=finality)
        if phase == "cleanup-prologue-systemexit" and area == "source":
            raise original
        return result

    def outer_init(instance, *arguments, **keywords):
        real_outer_init(instance, *arguments, **keywords)
        outers.append(instance)

    def pipe(acquisition):
        nonlocal pipe_count
        pair = real_pipe(acquisition)
        if outers and acquisition is outers[0].context.io:
            pipe_count += 1
            for lease in pair:
                remember_native(lease)
            if pipe_count == 3 and phase in {"pipe-create", "pipe-create-failure"} and not reached:
                if phase.endswith("-failure"):
                    reached.append(phase)
                    raise OSError("private-native-canary")
                send(phase)
        return pair

    def remember_native(lease):
        if id(lease) not in native_records and lease.state == "OPEN":
            descriptor = lease.fileno()
            details = real_fstat(descriptor)
            native_records[id(lease)] = {"lease": lease, "descriptor": descriptor,
                                         "identity": (details.st_dev, details.st_ino)}

    def target_lease(lease):
        channel = binding.channel_objects.get("c_to_o")
        if channel is not None:
            return ((phase.startswith("control-close") and lease is channel.writer)
                    or (phase.startswith("status-close") and lease is channel.reader)
                    or (phase.startswith("payload-close") and lease is binding.payload_reader))
        return False

    def observe_native(role, event, evidence):
        if role == "outer" and event == "payload_reader_registered":
            remember_native(evidence["lease"])
            if phase in {"payload-register", "payload-register-failure"} and not reached:
                if phase.endswith("-failure"):
                    reached.append(phase)
                    raise OSError("private-native-canary")
                send(phase)

    binding.on_event = observe_native

    def facts():
        assert len(outers) <= 1
        context = outers[0].context if outers else None
        if outers:
            assert {id(task) for task in context.tasks} == set(binding.tasks), "actual creator inventory differs"
            inventory = (*context.io.leases, *(lease for task in context.tasks for lease in task.acquisition.leases))
            for lease in inventory:
                if lease.state != "NEW":
                    remember_native(lease)
                    assert id(lease) in native_records, "actual acquisition escaped the lease inventory"
        for item in profile_records.values():
            handle = item["lease"]
            assert handle.state in {"UNACQUIRED", "CLOSED"}
            if item["descriptor"] is not None:
                assert raw_close_attempts.get(id(handle)) == 1
        for item in native_records.values():
            assert lease_close_attempts.get(id(item["lease"])) == 1
        raw_closed = all(item["lease"].settled for item in profile_records.values())
        leases_closed = all(item["lease"].state == "CLOSED" for item in native_records.values())
        assert leases_closed == (not phase.endswith("close-unresolved"))
        # Actual state is cross-checked against the original OS object, not just
        # an attempted-close event or a recycled descriptor number.
        for item in (*profile_records.values(), *native_records.values()):
            if item["descriptor"] is None:
                continue
            closed = item["lease"].state == "CLOSED"
            try:
                details = real_fstat(item["descriptor"])
            except OSError:
                assert closed
            else:
                same = (details.st_dev, details.st_ino) == item["identity"]
                assert not (closed and same), "close completion retained its original OS descriptor"
                if not closed:
                    assert same, "UNKNOWN lease lost the original fixture-owned descriptor"
        children = [task.acquisition.child for task in context.tasks if task.acquisition.child is not None] if context else []
        no_producer_attempt = False
        if children:
            assert context.child_acquisition.child is children[0] and len(children) == 1
            _assert_native_finality(root)
        elif context is not None:
            acquisition = context.child_acquisition
            assert (acquisition.attempted is False and acquisition.child is None
                    and acquisition.launch_retired and acquisition.settled and not acquisition.cleanup_unknown
                    and context.launch_closed), "missing child publication is NOT positive no-attempt evidence"
            assert not binding.children
            for task in context.tasks:
                assert task.acquisition is acquisition and task.launch_retired and task.joined and task.body_done
                assert task.actual is not None and not task.actual.is_alive()
                assert binding.join_witnesses.get(id(task.actual)) == id(task)
            no_producer_attempt = True
        else:
            # The capture wrapper registers entry before calling any owner.
            # An absent _Outer by itself could also mean lost initialization.
            assert not finalities and not binding.tasks and not binding.children
            no_producer_attempt = True
        paths = [lease.path for lease in scratches if lease.path is not None]
        retained_paths = [path for path in paths if path.exists()]
        assert all(path.is_dir() and stat.S_IMODE(path.stat().st_mode) == 0o700 for path in retained_paths)
        actual_finalities = []
        for finality in (*finalities, *(lease._finality for lease in scratches),
                         *(scope._scratch._finality for scope in scopes if scope._scratch is not None)):
            if not any(finality is existing for existing in actual_finalities):
                actual_finalities.append(finality)
        assert len(actual_finalities) <= 1, "resource fixture attempted another producer case"
        return {"boundaryReached": bool(reached), "rawDescriptorsClosed": raw_closed,
                "leasesClosed": leases_closed, "nativeWaitsConfirmed": bool(children),
                "noProducerAttempt": no_producer_attempt, "scratchRemoved": not retained_paths,
                "scratchRetained": bool(retained_paths), "cleanupAttempts": len(cleanup_calls),
                "checkedBeforeFallback": True, "mode": mode,
                "producerFinalities": [item.state for item in actual_finalities],
                "producerCleanupAllowed": all(item.cleanup_allowed for item in actual_finalities)}

    def change_handler(selected, handler):
        result = real_signal(selected, handler)
        active = guard()
        if (active is not None and selected in previous and handler == previous[selected]
                and selected in active.previous and not reached):
            if ((phase == "restore-term" and selected == signal.SIGTERM)
                    or (phase == "restore-int" and selected == signal.SIGINT)):
                send(phase, signal.SIGINT)
            elif phase == "restored-term-fatal" and selected == signal.SIGTERM:
                reached.append(phase)
                state = facts()
                assert state["cleanupAttempts"] == 1
                state.update(hostTerminatedAfterCleanup=True, retainedCustody=True,
                             handlersRestored=False, noRetainedState=False)
                record(root / "resource-result.json", json.dumps(state))
                os.kill(os.getpid(), signal.SIGTERM)  # Real host default, after owned process/FD cleanup.
        return result

    def observe(frame, event, arg):
        if event != "call":
            return
        if area == "capture":
            if outers and frame.f_code is owner._Outer.cleanup.__code__ and frame.f_locals["self"] is outers[0]:
                if not getattr(outers[0], "cleanup_claimed", False):
                    cleanup_calls.append(True)
        elif scopes and frame.f_code is profiles._ProfileCleanupScope._cleanup_all.__code__ and frame.f_locals["self"] is scopes[0]:
            cleanup_calls.append(True)

    def trace(frame, event, arg):
        if event != "line":
            return trace
        if area != "capture" and frame.f_code is target.__code__ and frame.f_lineno == scope_line:
            visits.append(True)
            if not scopes:
                scopes.append(frame.f_locals["scope"])
            if phase == "cleanup-dispatch" and len(visits) == 2 and not reached:
                assert not scopes[0].claimed
                send(phase)
        if reached:
            return trace
        if area != "capture" and scopes:
            scope = scopes[0]
            if (phase == "cleanup-prologue-systemexit" and frame.f_code is profiles._ProfileCleanupScope.__exit__.__code__
                    and frame.f_locals["self"] is scope and frame.f_lineno == private_exit_line):
                assert frame.f_locals["error"] is original and scope._primary_error is None
                assert not scope.claimed and scope.cancellation.depth == 0
                send(phase)  # Before the incoming SystemExit has been assigned.
            elif (phase in {"cleanup-entry", "cleanup-entry-repeat", "cleanup-claimed"}
                    and frame.f_code is CleanupScope.__exit__.__code__ and frame.f_locals["self"] is scope
                    and frame.f_lineno == (base_claimed_line if phase == "cleanup-claimed" else base_exit_line)):
                if phase == "cleanup-claimed":
                    assert scope.claimed
                send(phase)
                if phase == "cleanup-entry-repeat":
                    send(phase, signal.SIGTERM if signum == signal.SIGINT else signal.SIGINT)
        elif area == "capture" and outers:
            if ((phase in {"cleanup-entry", "cleanup-entry-repeat", "cleanup-claimed"}
                 and frame.f_code is owner._Outer.cleanup.__code__ and frame.f_locals["self"] is outers[0]
                 and frame.f_lineno == (outer_cleanup_claimed if phase == "cleanup-claimed" else outer_cleanup_entry))
                    or (phase == "cleanup-dispatch" and frame.f_code is owner._Outer.run.__code__
                        and frame.f_locals["self"] is outers[0] and frame.f_lineno == outer_cleanup_dispatch)):
                send(phase)
                if phase == "cleanup-entry-repeat":
                    send(phase, signal.SIGTERM if signum == signal.SIGINT else signal.SIGINT)
        if (not reached and phase in restore_lines and frame.f_code is DefaultCancellation.restore.__code__
                and frame.f_locals["self"] is guard() and frame.f_lineno == restore_lines[phase]):
            send(phase)
        return trace

    with ExitStack() as patches:
        # Bind owner os.read to the real resource wrapper, so its EOF oracle
        # still sees an actual b"" returned by the real read after any injection.
        patches.enter_context(patch.object(profiles.os, "read", reading))
        patches.enter_context(binding)
        bound_close = native.FDLease.close
        def close_lease(lease):
            remember_native(lease)
            if lease.state == "OPEN":
                key = id(lease)
                lease_close_attempts[key] = lease_close_attempts.get(key, 0) + 1
                assert lease_close_attempts[key] == 1, "native lease close was replayed"
            chosen = target_lease(lease) and not reached
            if chosen and phase.endswith("-unresolved"):
                reached.append(phase)
                raise OSError("private-native-canary")
            result = bound_close(lease)
            if chosen:
                if phase.endswith("-failure"):
                    reached.append(phase)
                    raise OSError("private-native-canary")
                send(phase)
            return result
        # ProfileBindings was constructed before the read patch; explicitly use
        # this bounded real-read wrapper, not a synthetic EOF-producing callback.
        binding._real_read = reading
        for obj, name, implementation in (
            (profiles._ProfileDescriptor, "open", profile_open), (profiles.os, "open", opening),
            (profiles.os, "close", closing), (profiles.os, "fstat", stating), (profiles.os, "write", writing),
            (profiles.tempfile, "mkdtemp", temporary), (profiles.ScratchLease, "acquire", acquire),
            (profiles.ScratchLease, "cleanup", cleanup_scratch), (profiles, "_capture_profile", capture),
            (owner._Outer, "__init__", outer_init), (native.Acquisition, "pipe", pipe),
            (native.FDLease, "close", close_lease), (signal, "signal", change_handler),
        ):
            patches.enter_context(patch.object(obj, name, implementation))
        patches.enter_context(patch.object(profiles, "sys", SimpleNamespace(platform="darwin", executable=sys.executable)))
        patches.enter_context(patch.object(owner, "SUPERVISOR_SECONDS", 5))
        patches.enter_context(patch.object(owner, "CAPTURE_SECONDS", 8))
        if area == "capture":
            finality = owner.CaptureFinality()
            capture_scratch = profiles.ScratchLease(finality)
            directory = capture_scratch.acquire()
            (directory / "cms.der").write_bytes(content)
            (directory / "cms.der").chmod(0o600)
        sys.setprofile(observe)
        sys.settrace(trace)
        try:
            if area == "read":
                profiles.read_profile_bytes(source)
            elif area == "source":
                profiles.authenticate_cms(content, deadline=InspectionDeadline())
            else:
                profiles._capture_profile(directory, InspectionDeadline(), finality=finality)
        except (KeyboardInterrupt, SystemExit, ValidationError) as error:
            held_error = error
        finally:
            sys.settrace(None)
            sys.setprofile(None)
        assert reached and held_error is not None, "cancelled or unresolved profile returned success"
        if phase == "cleanup-prologue-systemexit":
            assert held_error is original and original.code == 37 and original.__notes__ is original_notes
        elif phase.endswith(("-failure", "-unresolved")):
            assert isinstance(held_error, ValidationError)
            assert "private-native-canary" not in str(held_error)
        else:
            assert isinstance(held_error, KeyboardInterrupt)
        assert {sig: signal.getsignal(sig) for sig in previous} == previous
        if capture_scratch is not None:
            try:
                capture_scratch.cleanup()
            except ValidationError:
                assert finality.state == "UNKNOWN" and capture_scratch.path.is_dir()
        result = facts()
        assert len(cleanup_calls) == 1
        result.update(handlersRestored=True, originalIdentityPreserved=held_error is original)
        # Settled product records remove themselves. Even an unfinished record
        # without a published UNKNOWN flag must veto a healthy next case.
        retained = (bool(profiles._PROFILE_SCRATCH_LEASES)
                    or bool(profiles._PROFILE_RESOURCE_SCOPES) or bool(owner._CUSTODY)
                    or any(state not in {"NO_PRODUCERS", "FINALIZED"}
                           for state in result["producerFinalities"]))
        retained_paths = [lease.path for lease in scratches if lease.path is not None and lease.path.exists()]
        if phase == "restore-int":
            # The actual saved INT handler ran before its setter returned to
            # production. Observed restored handlers/closed FDs do not replace
            # that lost restoration completion or retire the retained owner.
            assert mode in UNKNOWN_RESOURCE_MODES and retained
            assert result["handlersRestored"] and result["rawDescriptorsClosed"] and result["leasesClosed"]
            assert result["noProducerAttempt"] == (area == "read")
            assert result["nativeWaitsConfirmed"] == (area != "read")
            if area == "read":
                assert len(scopes) == 1 and scopes[0].retained
                assert not outers and not scratches and result["producerFinalities"] == []
                assert result["producerCleanupAllowed"] and result["scratchRemoved"] and not result["scratchRetained"]
            elif area == "source":
                assert len(scopes) == 1 and scopes[0].retained
                assert result["producerFinalities"] == ["FINALIZED"]
                assert result["producerCleanupAllowed"] and result["scratchRemoved"] and not result["scratchRetained"]
            else:
                assert not scopes and len(scratches) == 1 and scratches[0].retained
                assert result["producerFinalities"] == ["UNKNOWN"]
                assert not result["producerCleanupAllowed"] and not result["scratchRemoved"] and result["scratchRetained"]
        if mode in UNKNOWN_RESOURCE_MODES:
            assert retained, "intentional real-resource uncertainty lost its product custody"
            scope_ids = {id(item) for item in profiles._PROFILE_RESOURCE_SCOPES if item.retained}
            scratch_ids = {id(item) for item in profiles._PROFILE_SCRATCH_LEASES}
            retained_scratch_ids = {id(item) for item in profiles._PROFILE_SCRATCH_LEASES if item.retained}
            # authenticate_cms checks these actual retained profile records
            # before constructing cancellation/scope owners. Native _CUSTODY
            # alone is not that entry veto and cannot admit this later probe.
            assert scope_ids or retained_scratch_ids, "missing actual retained profile entry veto"
            capture_ids = {id(item) for item in owner._CUSTODY if item.state == "UNKNOWN"}
            del held_error
            # Drop fixture references, then prove the actual product registries
            # still prevent reuse before any new acquisition or creator starts.
            scopes.clear(); scratches.clear(); finalities.clear()
            outers.clear(); profile_records.clear(); native_records.clear()
            capture_scratch = finality = None
            binding.release_fixture_references()
            gc.collect()
            assert all(path.is_dir() for path in retained_paths), "outer unwind/GC deleted retained scratch"
            surviving_scope_ids = {id(item) for item in profiles._PROFILE_RESOURCE_SCOPES if item.retained}
            surviving_scratch_ids = {id(item) for item in profiles._PROFILE_SCRATCH_LEASES if item.retained}
            assert scope_ids <= surviving_scope_ids and retained_scratch_ids <= surviving_scratch_ids
            assert (scope_ids & surviving_scope_ids) or (retained_scratch_ids & surviving_scratch_ids)
            assert scratch_ids <= {id(item) for item in profiles._PROFILE_SCRATCH_LEASES}
            assert capture_ids <= {id(item) for item in owner._CUSTODY if item.state == "UNKNOWN"}
            with patch.object(profiles, "_profile_cancellation", side_effect=AssertionError("retained custody admitted another cancellation owner")) as cancellation_probe, patch.object(profiles.tempfile, "mkdtemp", side_effect=AssertionError("retained custody admitted scratch")) as scratch_probe, patch.object(native, "create", side_effect=AssertionError("retained custody admitted native child")) as child_probe:
                try:
                    try:
                        profiles.authenticate_cms(content, deadline=InspectionDeadline())
                    except ValidationError:
                        pass
                    else:
                        raise AssertionError("retained ownership did not veto reuse")
                finally:
                    # Check every veto even if an unexpected error escapes or
                    # a later wrapper sanitizes an attempted acquisition.
                    assert (cancellation_probe.call_count, scratch_probe.call_count, child_probe.call_count) == (0, 0, 0)
            result.update(retainedAfterGC=True, reuseRefused=True)
        else:
            # These 78 ordinary rows may not pass through the poison branch.
            # Their genuine native receipts (or positive no-attempt inventory)
            # must agree with actual product finality and empty real registries.
            assert not retained and not retained_paths, "healthy resource case retained actual custody"
            assert all(not scope.retained for scope in scopes)
            assert all(lease.state == "REMOVED" for lease in scratches)
            if result["noProducerAttempt"]:
                assert not result["nativeWaitsConfirmed"]
                assert all(state == "NO_PRODUCERS" for state in result["producerFinalities"])
            else:
                assert result["nativeWaitsConfirmed"]
                assert result["producerFinalities"] == ["FINALIZED"]
            assert result["producerCleanupAllowed"]
            assert result["rawDescriptorsClosed"] and result["leasesClosed"]
            assert result["scratchRemoved"] and not result["scratchRetained"]
        result["retainedCustody"] = retained
        result["noRetainedState"] = not retained
    if mode not in UNKNOWN_RESOURCE_MODES:
        # Check the shared latch only AFTER the actual binding restoration;
        # an active ProfileBindings context is itself still owned custody.
        assert_fixture_idle()
    return result


def run_case(workspace: FixtureWorkspace, mode: str, signum: int = signal.SIGINT) -> dict:
    assert_fixture_idle()
    root = workspace.path
    command = [sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()),
               str(Path(mobile_release.__file__).resolve().parent.parent), str(root), mode, str(int(signum))]
    environment = {"PATH": os.environ["PATH"], "TMPDIR": str(root), "TMP": str(root), "TEMP": str(root)}
    environment.update(observer_environment())
    try:
        with FixtureDriver(command, env=environment) as controller:
            output, error = controller.finish(timeout=15)
            expected = -signal.SIGTERM if mode.endswith("restored-term-fatal") else 0
            assert controller.process.returncode == expected and controller.receipt is not None, "profile resource fixture failed"
            assert not output and not error, "profile resource fixture emitted unexpected output"
        result = json.loads((root / "resource-result.json").read_text())
        if result.get("retainedCustody") or result.get("scratchRetained"):
            # A genuine wait/EOF for our driver does not dispose the original
            # Session domain or recover the nested product's UNKNOWN resources.
            workspace.retain()
        assert result["mode"] == mode
        if mode in UNKNOWN_RESOURCE_MODES:
            workspace.retain()  # Latch before a caller's subTest can catch failure.
            assert result["retainedCustody"] is True and result["noRetainedState"] is False
        else:
            assert result["retainedCustody"] is False and result["noRetainedState"] is True
            assert result["scratchRetained"] is False and result["scratchRemoved"] is True
            assert result["handlersRestored"] is True
            assert result["rawDescriptorsClosed"] is True and result["leasesClosed"] is True
            assert result["producerCleanupAllowed"] is True
            if result["noProducerAttempt"] is True:
                assert result["nativeWaitsConfirmed"] is False
                assert all(state == "NO_PRODUCERS" for state in result["producerFinalities"])
            else:
                assert result["nativeWaitsConfirmed"] is True
                assert result["producerFinalities"] == ["FINALIZED"]
            workspace.allow_removal()
        return result
    except BaseException:
        workspace.retain()
        raise


if __name__ == "__main__":
    root = Path(sys.argv[1])
    record(root / "resource-result.json", json.dumps(driver(root, sys.argv[2], int(sys.argv[3]))))
