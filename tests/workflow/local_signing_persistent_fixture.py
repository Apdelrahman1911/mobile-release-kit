"""Warm, sequential crash workers; real journals, independently persisted fake native IO.

No native signing tool, account home, credential or Store is accessed. Crash cuts
use os._exit, never fabricated journals or an exception that runs Python cleanup.
"""
from __future__ import annotations

import collections
import copy
import gzip
import hashlib
import json
import os
import re
import select
import signal
import stat
import sys
import termios
import threading
import time
import traceback
import tty
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if __name__ == "__main__":
    raise SystemExit("Use the fixed verify_ci matrix phase; raw fixture execution is not admitted.")

from mobile_release import credentials, local_signing as signing
from mobile_release.errors import CredentialError
from unit.ios_entitlement_helpers import profile
from unit.local_signing_helpers import fictional_signing_profile
from unit.local_signing_persistent import (
    PROFILE, UUID, OwnerResolutionRefused, PersistentSigningModel, ResourceOracle, facts, initialize, write_json,
)
from workflow.local_signing_matrix_contract import (
    SHARDS, digest, event_fact, logical_case_id, package_manifest, definitions_manifest, shard_for, strict_json,
)
from workflow.local_signing_workload import recovery_timeout, worker_timeout

CRASH = 73
WORKER_ERROR = 91
IO_OPERATIONS = ("open", "write", "fsync", "replace", "unlink", "rmdir", "mkdir", "link", "close", "dup")
PRODUCTION = {"mobile_release.local_signing", "mobile_release.credentials", "mobile_release.ios_profiles",
              "mobile_release.cancellation"}
PHASE_DEADLINE = None
_CASE_CUSTODY = {}
# Separate from A/W/G custody: an expected O73 can leave its original C
# finishing an authorized account/fence tail outside G. This is a retention
# debt, never a receipt or permission to start/recover an UNKNOWN case.
_CASE_RECOVERY_DEBT = {}


def _directory_identity(root):
    value = root.lstat()
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid


def require_fresh_recovery(root: Path):
    """Before a selected O-loss launch, retain the exact original case root."""
    key, identity = str(root), _directory_identity(root)
    assert key not in _CASE_CUSTODY or _CASE_CUSTODY[key] is not None, "prior case custody remains unknown"
    assert key not in _CASE_CUSTODY or _CASE_CUSTODY[key] == identity, "prior case directory changed"
    assert key not in _CASE_RECOVERY_DEBT or _CASE_RECOVERY_DEBT[key] == identity, "recovery-debt directory changed"
    _CASE_RECOVERY_DEBT[key] = identity


def run_worker(root: Path, name: str, task, *, timeout: float = 20, expect=0) -> dict:
    from workflow.local_signing_case_owner import run_worker as owned_worker
    identity = _directory_identity(root)
    assert str(root) not in _CASE_CUSTODY or _CASE_CUSTODY[str(root)] is not None, "prior case custody remains unknown"
    assert str(root) not in _CASE_CUSTODY or _CASE_CUSTODY[str(root)] == identity, "prior case directory changed"
    assert str(root) not in _CASE_RECOVERY_DEBT or _CASE_RECOVERY_DEBT[str(root)] == identity, "recovery-debt directory changed"
    _CASE_CUSTODY[str(root)] = None  # Unknown is absorbing until this original returns.
    result = owned_worker(root, name, task, timeout=timeout, expect=expect,
                          deadline=PHASE_DEADLINE, write_json=write_json)
    assert _directory_identity(root) == identity, "case directory changed during original worker"
    _CASE_CUSTODY[str(root)] = identity
    return result


def read_fixture_file(path: Path, *, limit: int, empty=False):
    """Bound one actual no-follow inode read; a lost close never means success."""
    descriptor = None
    primary = close_error = None
    try:
        before = path.lstat()
        assert stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid(), "invalid fixture evidence inode"
        assert (0 if empty else 1) <= before.st_size <= limit, "fixture evidence byte bound"
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        expected = Trace._file_state(before)
        assert Trace._file_state(os.fstat(descriptor)) == expected, "fixture evidence changed before read"
        content = bytearray()
        while len(content) <= before.st_size:
            block = os.read(descriptor, min(65536, before.st_size + 1 - len(content)))
            if not block:
                break
            content.extend(block)
        assert len(content) == before.st_size, "fixture evidence truncated or grew"
        assert Trace._file_state(os.fstat(descriptor)) == Trace._file_state(path.lstat()) == expected, \
            "fixture evidence changed during read"
    except BaseException as error:
        primary = error
    finally:
        closing, descriptor = descriptor, None
        if closing is not None:
            try:
                os.close(closing)
            except BaseException as error:
                close_error = error
    if primary is not None:
        if close_error is not None:
            primary._fixture_read_close_errors = (close_error,)
            primary.add_note("fixture evidence original close is independently unknown")
        raise primary
    if close_error is not None:
        raise AssertionError("fixture evidence original close is unknown") from close_error
    return bytes(content), before


def read_case_json(root: Path, name: str):
    assert type(name) is str and re.fullmatch(r"[A-Za-z0-9_-]+", name), "nonliteral case result name"
    content, details = read_fixture_file(root / (name + ".json"), limit=8 * 1024 * 1024)
    assert stat.S_IMODE(details.st_mode) == 0o600 and details.st_nlink == 1, "case output metadata differs"
    return strict_json(content.decode("utf-8"))


def snapshot(root: Path) -> dict:
    model = json.loads((root / "observed-native.json").read_bytes())
    lease = root / "home" / signing.LEASE_DIRECTORY
    sessions = sorted(lease.glob("session-*")) if lease.exists() else []
    assert len(sessions) <= 1
    controls, fences = {}, {}
    if sessions:
        for path in sessions[0].iterdir():
            if path.name in signing.CONTROLS | signing.FENCE_CONTROLS:
                content, details = read_fixture_file(path, limit=(signing.FENCE_LIMIT if path.name in signing.FENCE_CONTROLS
                                                                 else signing.CONTROL_LIMIT), empty=True)
                try:
                    value = json.loads(content)
                except ValueError:
                    value = {"incompleteHex": content.hex()}
                observation = {"facts": {"device": details.st_dev, "inode": details.st_ino,
                    "mode": stat.S_IMODE(details.st_mode), "size": details.st_size,
                    "sha256": hashlib.sha256(content).hexdigest()}, "value": value}
                if path.name in signing.FENCE_CONTROLS:
                    observation["metadata"] = {"uid": details.st_uid, "gid": details.st_gid, "links": details.st_nlink}
                    fences[path.name] = observation
                else:
                    controls[path.name] = observation
    profiles = root / "home/Library/MobileDevice/Provisioning Profiles"
    return {"preferences": model["preferences"], "original": model["original"], "keychain": model["keychain"],
            "session": sessions[0].name[8:] if sessions else None, "controls": controls, "fences": fences,
            "nativeDirectory": bool(sessions and (sessions[0] / "keychain").exists()),
            "native": {str(path.relative_to(root)): facts(path) for session in sessions
                       for path in (session / "keychain").glob("*")},
            "profile": {str(path.relative_to(root)): facts(path) for path in profiles.iterdir()},
            "ownedRemaining": ResourceOracle(root).owned_remaining(),
            "nativeCalls": model["calls"]}


def uncertainty(root: Path, observed: dict) -> dict:
    """Read-only independent comparison; never a cleanup/adoption authority."""
    controls = observed["controls"]
    state = controls.get("state.json", {}).get("value")
    intent = controls.get("intent.json", {}).get("value")
    if "completed.json" in controls:
        terminal = controls["completed.json"]["value"]
        state, intent = terminal["state"], terminal["intent"]
    unknown = {}
    if state is None:
        assert not observed["native"] and not observed["ownedRemaining"], "resources preceded committed authority"
        return unknown
    for relative, actual in observed["native"].items():
        recorded = state["native"].get(Path(relative).name)
        if recorded != {key: actual[key] for key in ("device", "inode")}:
            unknown[relative] = actual
    record, info = state["profile"], intent["profile"]
    for filename, identity in ((info["stage"], record["stageIdentity"]),
                               (info["uuid"] + ".mobileprovision", record["ownedIdentity"] or
                                (record["stageIdentity"] if record["phase"] == "link-intent" else None))):
        relative = "home/Library/MobileDevice/Provisioning Profiles/" + filename
        actual = observed["profile"].get(relative)
        if actual is None or relative in ResourceOracle(root).read()["sentinels"]:
            continue
        if (identity != {key: actual[key] for key in ("device", "inode")}
                or actual.get("sha256") != info["sha256"]):
            unknown[relative] = actual
    return unknown


class Trace:
    def __init__(self, root: Path, name: str, target=None, *, inventory=False, after_effect=None):
        self.root, self.name, self.target, self.inventory = root, name, target, inventory
        self.phase = "setup"
        self.events, self.lines = [], set()
        self.occurrences = collections.Counter()
        self.descriptors = {}
        self.oracle = ResourceOracle(root)
        self.after_effect = after_effect
        self._fence_session = None
        self._fence_event = None
        self._fence_evidence = None
        self.session_token = None

    def normalize(self, value):
        value = str(value).replace(str(self.root), "<ROOT>")
        return re.sub(r"(session-|\.mobile-release-profile-)[0-9a-f]{32}", r"\1<TOKEN>", value)

    def begin(self, operation, slot, origin, details):
        prefix = str(self.root / "home" / signing.LEASE_DIRECTORY) + "/session-"
        if str(slot).startswith(prefix):
            token = str(slot)[len(prefix):].split("/", 1)[0]
            assert re.fullmatch(r"[0-9a-f]{32}", token), "invalid actual session observation"
            assert self.session_token in {None, token}, "trace changed original signing session"
            self.session_token = token
        key = (operation, self.normalize(slot), origin, self.phase)
        self.occurrences[key] += 1
        event = {"index": len(self.events) + 1, "operation": operation, "slot": key[1], "origin": origin,
                 "phase": self.phase, "occurrence": self.occurrences[key], "details": details}
        self.events.append(event)
        if self.target is not None and event["index"] == self.target["event"]["index"]:
            expected = {key: value for key, value in self.target["event"].items() if key not in ("succeeded", "error")}
            assert event == expected, {"traceMismatch": event, "expected": expected}
            if self.target["edge"] == "before":
                self.cut(event, "before")
        return event

    def partial(self, event):
        return self.target is not None and self.target["event"]["index"] == event["index"] and self.target["edge"] == "partial"

    def end(self, event, *, succeeded, error=None):
        event["succeeded"] = succeeded
        if error is not None:
            event["error"] = error
        if self.after_effect is not None:
            self.after_effect(event)
        if self.target is not None and event["index"] == self.target["event"]["index"] and self.target["edge"] == "after":
            assert event == self.target["event"], {"effectMismatch": event, "expected": self.target}
            self.cut(event, "after")

    def cut(self, event, edge):
        record = {"event": event, "edge": edge, "snapshot": snapshot(self.root), "sessionToken": self.session_token}
        if event["operation"].startswith("command-fence/"):
            assert self._fence_evidence is not None, "missing actual original-C observation"
            record["originalCFenceObservation"] = self._fence_evidence
        write_json(self.root / (self.name + "-cut.json"), record)
        os._exit(CRASH)

    @staticmethod
    def _file_state(value):
        return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                value.st_uid, value.st_gid, value.st_size, value.st_mtime_ns, value.st_ctime_ns)

    def _observe_fence_policy(self, session):
        from mobile_release._command_process import FenceObservationPolicy
        assert self._fence_event is None, "previous observed fence did not finish"
        self._fence_session = (session, session.fd, dict(session.identity), os.getpid())
        return FenceObservationPolicy.TRACE_V1

    def _fence_namespace(self):
        assert self._fence_session is not None, "unbound C fence observation"
        session, descriptor, identity, owner = self._fence_session
        assert owner == os.getpid() == session.pid and not session.closed and session.fd == descriptor
        opened = os.fstat(descriptor)
        named = session.path.lstat()
        assert stat.S_ISDIR(opened.st_mode) and stat.S_IMODE(opened.st_mode) == 0o700
        assert opened.st_uid == os.getuid()
        assert {"device": opened.st_dev, "inode": opened.st_ino} == identity == session.identity
        assert (named.st_dev, named.st_ino, named.st_mode, named.st_uid, named.st_gid) == (
            opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid, opened.st_gid)
        return session, descriptor

    def _fence_prefix(self, observation):
        """One bounded, original-inode read while C holds its unACKed checkpoint."""
        session, directory = self._fence_namespace()
        pending, final = "command-final.pending", "command-final.json"
        def final_absent():
            try:
                os.stat(final, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                return
            raise AssertionError("final fence already exists at genuine prefix edge")
        final_absent()
        before = os.stat(pending, dir_fd=directory, follow_symlinks=False)
        creation = (before.st_dev, before.st_ino, before.st_uid, before.st_gid, before.st_mode, before.st_nlink)
        assert observation.identity_state == 1 and creation == observation.creation_identity
        assert stat.S_ISREG(before.st_mode) and before.st_mode == stat.S_IFREG | 0o600
        assert before.st_uid == os.getuid() and before.st_nlink == 1 and before.st_size == observation.written
        descriptor = None  # Original read slot is retired before its only close.
        primary = close_error = None
        try:
            descriptor = os.open(pending, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                 dir_fd=directory)
            opened = os.fstat(descriptor)
            expected = self._file_state(before)
            assert self._file_state(opened) == expected, "pending original inode changed before prefix read"
            content = bytearray()
            while len(content) <= observation.written:
                part = os.read(descriptor, observation.written + 1 - len(content))
                if not part:
                    break
                content.extend(part)
            assert len(content) == observation.written and bytes(content) == observation.operand[:observation.written]
            assert self._file_state(os.fstat(descriptor)) == expected
            assert self._file_state(os.stat(pending, dir_fd=directory, follow_symlinks=False)) == expected
            final_absent()
            assert self._fence_namespace() == (session, directory)
        except BaseException as error:
            primary = error
        finally:
            closing, descriptor = descriptor, None
            if closing is not None:
                try:
                    os.close(closing)
                except BaseException as error:
                    close_error = error
        if primary is not None:
            if close_error is not None:
                primary._fence_prefix_close_errors = (close_error,)
                primary.add_note("original C-prefix read close is independently unknown")
            raise primary
        if close_error is not None:
            raise AssertionError("original C-prefix read close is unknown") from close_error
        return {"actualReadHex": bytes(content).hex(), "originalFileState": list(expected),
                "finalAbsentBeforeAndAfter": True, "originalReadClosed": True}

    def _observe_fence(self, observation):
        from mobile_release._command_process import FenceObservation, FenceOperation, FenceEdge, FenceEventOutcome
        assert type(observation) is FenceObservation
        session, _directory = self._fence_namespace()
        operation = session.state["inflight"]
        assert operation is not None and operation["nonce"] == observation.nonce.hex()
        assert operation["sequence"] == observation.command_sequence
        self._fence_evidence = {
            "nonce": observation.nonce.hex(), "commandSequence": observation.command_sequence,
            "ordinal": observation.ordinal, "operation": observation.operation.name,
            "edge": observation.edge.name, "outcome": observation.outcome.name,
            "written": observation.written, "total": observation.total, "syncFlags": observation.sync_flags,
            "creationIdentity": list(observation.creation_identity) if observation.creation_identity else None,
            "operandHex": observation.operand.hex(), "originalWorker": True,
        }
        if observation.edge is FenceEdge.BEFORE:
            assert self._fence_event is None
            filename = ("command-final.json" if observation.operation is FenceOperation.FINAL_LINK else
                        "" if observation.operation is FenceOperation.DIRECTORY_FSYNC else "command-final.pending")
            # Raw nonce/identity/count evidence never enters logical identity or
            # event equality. The engine validates its frozen finite automaton.
            self._fence_event = self.begin("command-fence/" + observation.operation.name,
                                           session.path / filename, "original-custodian", {})
        elif observation.edge is FenceEdge.PARTIAL:
            assert self._fence_event is not None and observation.operation is FenceOperation.PENDING_WRITE
            self._fence_evidence.update(self._fence_prefix(observation))
            if self.partial(self._fence_event):
                self.cut(self._fence_event, "partial")  # Original O dies73 without ACK; C may finish after OEOF.
        else:
            assert observation.edge is FenceEdge.AFTER and self._fence_event is not None
            event, self._fence_event = self._fence_event, None
            self.end(event, succeeded=observation.outcome is FenceEventOutcome.OK,
                     error=None if observation.outcome is FenceEventOutcome.OK else observation.outcome.name)

    def result(self):
        assert self.target is None, {"selectedCutNotReached": self.target}
        return {"events": self.events, "lines": sorted(self.lines), "snapshot": snapshot(self.root),
                "sessionToken": self.session_token}

    def origin(self, frame):
        while frame is not None:
            module = frame.f_globals.get("__name__", "")
            if module in {"mobile_release._command_process", "mobile_release._native_process", "mobile_release.owned_process"}:
                return None  # Separate original owner/command tests, not caller IO.
            if module in PRODUCTION:
                return module + ":" + frame.f_code.co_name
            if module.startswith(("unit.", "workflow.")) or module == __name__:
                return None  # Never classify oracle/model/test logging as production IO.
            frame = frame.f_back
        return None

    def path(self, value, directory=None):
        if isinstance(value, int):
            return self.descriptors.get(value, "unmapped-descriptor")
        path = Path(value)
        if not path.is_absolute() and directory is not None:
            path = Path(self.descriptors[directory]) / path
        return str(path)

    def record_profile(self, path):
        path = Path(path)
        if (path.parent == self.root / "home/Library/MobileDevice/Provisioning Profiles"
                and (path.name.startswith(".mobile-release-profile-") or path.name == UUID + ".mobileprovision")
                and path.exists()):
            self.oracle.record(path, "profile")

    def wrapper(self, operation, actual):
        def invoke(*args, **kwargs):
            origin = self.origin(sys._getframe(1))
            if origin is None:
                return actual(*args, **kwargs)
            directory = kwargs.get("dir_fd", kwargs.get("src_dir_fd"))
            slot = self.path(args[0], directory)
            details = {}
            if operation == "open":
                details["flags"] = args[1]
            if operation in {"link", "replace"}:
                destination = self.path(args[1], kwargs.get("dst_dir_fd"))
                details["destination"] = self.normalize(destination)
            event = self.begin(operation, slot, origin, details)
            if self.partial(event):
                assert operation == "write" and len(args[1]) > 1
                count = actual(args[0], args[1][:max(1, len(args[1]) // 2)])
                assert 0 < count < len(args[1])
                self.record_profile(slot)
                self.cut(event, "partial")
            try:
                result = actual(*args, **kwargs)
            except BaseException as error:
                self.end(event, succeeded=False, error=type(error).__name__)
                raise
            if operation in {"open", "dup"}:
                self.descriptors[result] = slot
            if operation == "close":
                self.descriptors.pop(args[0], None)
            if operation in {"open", "write"}:
                self.record_profile(slot)
            elif operation in {"link", "replace"}:
                self.record_profile(destination)
            self.end(event, succeeded=True)
            return result
        return invoke

    def fdopen(self, actual):
        def opening(fd, *args, **kwargs):
            origin = self.origin(sys._getframe(1))
            stream = actual(fd, *args, **kwargs)
            if origin is None or not stream.writable():
                return stream
            trace, slot = self, self.path(fd)
            class Buffered:
                def __enter__(self): return self
                def __exit__(self, *unused): self.close()
                def fileno(self): return stream.fileno()
                def write(self, content):
                    event = trace.begin("buffer.write", slot, origin, {})
                    if trace.partial(event):
                        prefix = content[:max(1, len(content) // 2)]
                        assert stream.write(prefix) == len(prefix)
                        stream.flush()  # Real on-disk prefix, not merely a buffered write.
                        assert Path(slot).read_bytes() == prefix and len(prefix) < len(content)
                        trace.record_profile(slot)
                        trace.cut(event, "partial")
                    result = stream.write(content)
                    trace.record_profile(slot)
                    trace.end(event, succeeded=True)
                    return result
                def flush(self):
                    event = trace.begin("buffer.flush", slot, origin, {})
                    stream.flush()
                    trace.record_profile(slot)
                    trace.end(event, succeeded=True)
                def close(self):
                    event = trace.begin("buffer.close", slot, origin, {})
                    stream.close()
                    trace.record_profile(slot)
                    trace.end(event, succeeded=True)
            return Buffered()
        return opening

    def _trace_lines(self, frame, event, _arg):
        module = frame.f_globals.get("__name__")
        if module not in PRODUCTION:
            return None  # No per-line callbacks for nonproduction call frames.
        if event == "line":
            self.lines.add(module + ":" + frame.f_code.co_name + ":" + str(frame.f_lineno))
        return self._trace_lines

    @contextmanager
    def installed(self):
        with ExitStack() as patches:
            from mobile_release import _command_process
            from workflow import local_signing_case_owner as case_owner
            trace = self
            patches.enter_context(patch.object(signing.SigningSession, "_fence_observation_policy",
                                                new=lambda session: trace._observe_fence_policy(session)))
            patches.enter_context(patch.object(_command_process, "_fence_trace_checkpoint", new=self._observe_fence))
            if case_owner.ADAPTER_DIAGNOSTIC_CONTEXT is not None:
                patches.enter_context(patch.object(_command_process._Context, "record",
                    new=case_owner.adapter_command_recorder(_command_process._Context.record)))
            for name in IO_OPERATIONS:
                patches.enter_context(patch.object(os, name, new=self.wrapper(name, getattr(os, name))))
            patches.enter_context(patch.object(os, "fdopen", new=self.fdopen(os.fdopen)))
            previous_trace = sys.gettrace()
            if self.inventory:
                sys.settrace(self._trace_lines)
            try:
                yield
            finally:
                if self.inventory:
                    sys.settrace(previous_trace)


def original_flow(root: Path, trace: Trace, *, auto_add=False):
    model = PersistentSigningModel(root, trace=trace, auto_add=auto_add)
    with patch.object(credentials, "_authenticated_signing_profile", new=fictional_signing_profile), \
         patch.object(credentials, "_run_private", new=model), trace.installed():
        with signing.local_signing_lease(home=root / "home") as lease:
            with credentials._temporary_apple_signing_environment(
                    p12=root / "private/p12", password="fictional", profile=root / "private/profile",
                    directory=root / "private", lease=lease):
                trace.phase = "build"
                lease.active.run(["build"], kind="build")
                trace.phase = "cleanup"
    ResourceOracle(root).assert_sentinels()
    assert not ResourceOracle(root).owned_remaining()
    assert model.state["preferences"] == model.state["original"]
    assert_positive_postconditions(root, expected_preferences=model.state["original"])
    return trace.result()


def assert_pending(root):
    assert signing.signing_status(home=root / "home")["status"] == "pending"
    try:
        with signing.local_signing_lease(home=root / "home"):
            raise AssertionError("pending resources admitted a new signing task")
    except signing.SigningPending:
        pass


def assert_positive_postconditions(root, *, expected_preferences):
    """Actual task assertions, never inferred from a later output file."""
    observed = snapshot(root)
    ResourceOracle(root).assert_sentinels()
    assert observed["preferences"] == expected_preferences, "positive recovery changed expected preferences"
    assert not observed["ownedRemaining"] and not observed["native"] and not observed["session"] and not observed["fences"], \
        "positive recovery retained a signing resource"
    assert signing.signing_status(home=root / "home")["status"] == "idle"
    with signing.local_signing_lease(home=root / "home"):
        pass  # Newly acquired and released actual normal admission.
    return observed


def original_session_token(root):
    """Retained original acquisition data routes public ABS; it grants nothing."""
    tokens = set()
    for name in ("seed-cut", "original-cut", "recovery-cut", "inventory", "recovery-inventory"):
        path = root / (name + ".json")
        if path.exists():
            record = read_case_json(root, name)
            token = record.get("sessionToken")
            if token is not None:
                assert type(token) is str and re.fullmatch(r"[0-9a-f]{32}", token)
                tokens.add(token)
    assert len(tokens) == 1, "absent recovery requires the retained actual original session token"
    return tokens.pop()


def assert_original_return(result, *, expected=0):
    """Check DATA only in the immediate continuation of the actual owner call."""
    assert type(result) is dict and type(result.get("exit")) is int and result["exit"] == expected, \
        "missing original case return"
    for name in ("originalAnchorWait", "originalWorkerWait", "originalStatusEOF", "groupAbsentBeforeAnchorWait"):
        assert result.get(name) is True, "incomplete original case return"
    assert result.get("deadlineTest") is False and result.get("runDeadlineExpired") is False


def pin_case_context(root):
    from workflow.local_signing_matrix_contract import before_deadline
    before_deadline(PHASE_DEADLINE)
    package = Path(signing.__file__).resolve().parent
    return (_directory_identity(root), PHASE_DEADLINE, package,
            package_manifest(package, deadline=PHASE_DEADLINE), definitions_manifest(ROOT, deadline=PHASE_DEADLINE))


def check_phase_context(context):
    from workflow.local_signing_matrix_contract import before_deadline
    _identity, deadline, package, source, definitions = context
    assert PHASE_DEADLINE == deadline, "original phase endpoint changed"
    before_deadline(deadline)
    assert package_manifest(package, deadline=deadline) == source and definitions_manifest(ROOT, deadline=deadline) == definitions, \
        "case source or definitions changed"
    before_deadline(deadline)


def check_case_context(root, context):
    assert _directory_identity(root) == context[0], "original case root changed"
    check_phase_context(context)


FOCUSED_OWNER_VARIANTS = frozenset({"profile-inplace-edit", "terminal-profile-reappeared",
                                    "terminal-native-reappeared", "foreign-native-db"})


@contextmanager
def _focused_parent(root, relative):
    """Pin only this case's no-follow directory chain for a finite owner action."""
    path = Path(relative)
    assert not path.is_absolute() and path.parts and all(part not in {".", ".."} for part in path.parts)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    with ExitStack() as handles:
        descriptor = os.open(root, flags)
        handles.callback(os.close, descriptor)
        chain, parents = [], {}
        def bind(fd, parent, name, key):
            value = os.fstat(fd)
            identity = [value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid]
            assert stat.S_ISDIR(value.st_mode) and value.st_uid == os.getuid()
            assert not stat.S_IMODE(value.st_mode) & 0o022, "fixture parent is writable by another account"
            named = root.lstat() if parent is None else os.stat(name, dir_fd=parent, follow_symlinks=False)
            assert [named.st_dev, named.st_ino, named.st_mode, named.st_uid, named.st_gid] == identity
            chain.append((fd, parent, name, identity))
            parents[key] = identity
        bind(descriptor, None, None, ".")
        for index, part in enumerate(path.parts[:-1], 1):
            child = os.open(part, flags, dir_fd=descriptor)
            handles.callback(os.close, child)
            bind(child, descriptor, part, "/".join(path.parts[:index]))
            descriptor = child
        yield descriptor, parents
        for fd, parent, name, identity in chain:
            value = root.lstat() if parent is None else os.stat(name, dir_fd=parent, follow_symlinks=False)
            assert [value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid] == identity, \
                "fixture directory changed during owner action"
            actual = os.fstat(fd)
            assert [actual.st_dev, actual.st_ino, actual.st_mode, actual.st_uid, actual.st_gid] == identity


def _focused_file(parent, name):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
    try:
        before = os.fstat(descriptor)
        assert stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
        assert stat.S_IMODE(before.st_mode) == 0o600 and 1 <= before.st_nlink <= 2
        assert 0 < before.st_size <= 1024 * 1024, "fixture resource byte bound"
        data = bytearray()
        while len(data) <= before.st_size:
            block = os.read(descriptor, min(65536, before.st_size + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        after = os.fstat(descriptor)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size")
        identity = [getattr(before, key) for key in fields]
        assert len(data) == before.st_size
        assert [getattr(after, key) for key in fields] == [getattr(named, key) for key in fields] == identity
        return {"identity": identity, "sha256": hashlib.sha256(data).hexdigest()}
    finally:
        os.close(descriptor)


def focused_receipt(root, path):
    relative = path.relative_to(root).as_posix()
    with _focused_parent(root, relative) as (parent, parents):
        return {"parents": parents, "file": _focused_file(parent, path.name)}


def focused_owner_plan(root, variant, receipts):
    """Data bound after the negative assertion; edited-file receipts predate it."""
    assert variant in FOCUSED_OWNER_VARIANTS
    identity = _directory_identity(root)
    assert _CASE_CUSTODY.get(str(root)) == _CASE_RECOVERY_DEBT.get(str(root)) == identity
    model = PersistentSigningModel(root, recovery=True)
    destination = "home/Library/MobileDevice/Provisioning Profiles/" + UUID + ".mobileprovision"
    target = (Path(model.state["keychain"]).relative_to(root).as_posix()
              if variant in {"terminal-native-reappeared", "foreign-native-db"} else destination)
    expected = {target, "retained-fictional-profile"} if variant == "terminal-profile-reappeared" else {target}
    assert set(receipts) == expected, "incomplete finite fixture-edit receipt inventory"
    oracle = model.oracle.read()
    paths = set().union(*(set(oracle[key]) for key in ("sentinels", "native", "profile", "foreignChanges"))) | expected
    expected_preferences = copy.deepcopy(model.state["original"])
    if variant == "foreign-native-db":
        expected_preferences = copy.deepcopy(model.state["preferences"])
        if expected_preferences["default"] == str(root / target):
            expected_preferences["default"] = model.state["original"]["default"]
        expected_preferences["search"] = [item for item in expected_preferences["search"] if item != str(root / target)]
    return {"variant": variant, "identity": identity, "target": target, "receipts": receipts,
            "preferences": copy.deepcopy(model.state["preferences"]), "oracle": oracle,
            "expectedPreferences": expected_preferences,
            "resources": {path: facts(root / path) for path in paths}}


def resolve_focused_fixture(root, model, plan):
    """Exactly four independently authored edits, called only by locked TTY."""
    variant = plan["variant"]
    assert variant in FOCUSED_OWNER_VARIANTS
    assert _directory_identity(root) == plan["identity"]
    assert model.state["preferences"] == plan["preferences"], "fixture preference receipt changed"
    assert model.oracle.read() == plan["oracle"], "fixture oracle receipt changed"
    model.oracle.assert_sentinels()
    assert {path: facts(root / path) for path in plan["resources"]} == plan["resources"], "fixture resource inventory changed"
    for relative, receipt in plan["receipts"].items():
        assert focused_receipt(root, root / relative) == receipt, "fixture edit receipt changed"
    target = plan["target"]
    expected_target = (Path(model.state["keychain"]).relative_to(root).as_posix()
        if variant in {"terminal-native-reappeared", "foreign-native-db"} else
        "home/Library/MobileDevice/Provisioning Profiles/" + UUID + ".mobileprovision")
    expected_receipts = {target, "retained-fictional-profile"} if variant == "terminal-profile-reappeared" else {target}
    assert target == expected_target and set(plan["receipts"]) == expected_receipts
    receipt = plan["receipts"][target]
    if variant == "terminal-profile-reappeared":
        retained = plan["receipts"]["retained-fictional-profile"]["file"]
        assert receipt["file"] == retained and retained["identity"][5] == 2
    if variant == "foreign-native-db":
        assert model.state["keychain"] == str(root / target) and Path(target).name == signing.DB_NAME
        assert receipt["file"]["identity"][5] == 1, "foreign fixture DB has unexpected links"
        assert plan["oracle"].get("fixtureForeignDbArchive") is None
        archive = root / "fixture-owner-archive"
        assert not os.path.lexists(archive), "fixture archive collision"
        # Compute only removal of this exact DB's references; all unrelated
        # preferences remain byte-for-byte ordered as independently observed.
        preferences = copy.deepcopy(model.state["preferences"])
        if preferences["default"] == str(root / target):
            preferences["default"] = model.state["original"]["default"]
        preferences["search"] = [item for item in preferences["search"] if item != str(root / target)]
        with _focused_parent(root, target) as (parent, parents), \
                _focused_parent(root, "fixture-owner-archive") as (case, _case_parents):
            assert {"parents": parents, "file": _focused_file(parent, Path(target).name)} == receipt
            os.mkdir("fixture-owner-archive", mode=0o700, dir_fd=case)
            archive_fd = os.open("fixture-owner-archive", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 dir_fd=case)
            try:
                # link is exclusive; never replace an existing archive pathname.
                os.link(Path(target).name, "foreign-native.keychain-db", src_dir_fd=parent,
                        dst_dir_fd=archive_fd, follow_symlinks=False)
                linked = copy.deepcopy(receipt["file"])
                linked["identity"][5] += 1
                assert _focused_file(parent, Path(target).name) == linked
                assert _focused_file(archive_fd, "foreign-native.keychain-db") == linked
                os.unlink(Path(target).name, dir_fd=parent)
                assert _focused_file(archive_fd, "foreign-native.keychain-db") == receipt["file"]
            finally:
                os.close(archive_fd)
        model.oracle.record_fixture_foreign_db_archive(root / target, archive / "foreign-native.keychain-db")
        model.state["preferences"] = preferences
        model.save()
    else:
        with _focused_parent(root, target) as (parent, parents):
            assert {"parents": parents, "file": _focused_file(parent, Path(target).name)} == receipt
            os.unlink(Path(target).name, dir_fd=parent)
        if variant == "terminal-profile-reappeared":
            retained = copy.deepcopy(plan["receipts"]["retained-fictional-profile"])
            retained["file"]["identity"][5] -= 1
            assert focused_receipt(root, root / "retained-fictional-profile") == retained
    model.oracle.assert_sentinels()
    assert facts(root / target) is None


def settle_focused_fixture(root, plan, *, report=False):
    # The parent's prior A/W/G and pending debt are checked BEFORE run_worker
    # installs its absorbing UNKNOWN slot; the child inherits that UNKNOWN.
    assert _CASE_CUSTODY.get(str(root)) == _CASE_RECOVERY_DEBT.get(str(root)) == plan["identity"] == _directory_identity(root)
    context = pin_case_context(root)
    assert not (root / "focused-fixture-owner.json").exists(), "focused owner output already exists"
    expected_status = "recovered-with-conflict" if plan["variant"] == "foreign-native-db" else "recovered"
    def task():
        from workflow import local_signing_case_owner as case_owner
        assert _directory_identity(root) == plan["identity"]
        assert type(case_owner.CASE_DEADLINE) is float
        while signing.signing_status(home=root / "home")["status"] == "busy":
            time.sleep(min(.002, case_owner.remaining(case_owner.CASE_DEADLINE)))
        case_owner.remaining(case_owner.CASE_DEADLINE)
        model = PersistentSigningModel(root, recovery=True)
        status = signing.signing_status(home=root / "home")
        assert status["status"] == "pending", "focused negative case unexpectedly disappeared"
        trace = Trace(root, "focused-fixture-owner")
        input_observations = []
        with owner_tty(root, status["session"], model, trace, "fixture/" + plan["variant"],
                       focused_owner=plan, input_observations=input_observations) as (input_stream, output_stream):
            result = signing.recover_signing(status["session"], signing.CONFIRMATION, home=root / "home", runner=model,
                manual=True, input_stream=input_stream, output_stream=output_stream)
        assert result["status"] == expected_status
        assert len(trace.events) == 1 and trace.events[0]["operation"] == "manual/input"
        assert trace.events[0]["details"] == {"action": "fixture/" + plan["variant"]}
        assert trace.events[0]["succeeded"] is True, "genuine fixture-owner callback did not complete"
        assert input_observations == [{"eventIndex": trace.events[0]["index"], "action": "fixture/" + plan["variant"],
                                       "read": {"kind": "recheck", "characters": len(status["session"]) + 9}}]
        assert model.state["preferences"] == plan["expectedPreferences"], "manual recovery changed unrelated preferences"
        after = assert_positive_postconditions(root, expected_preferences=plan["expectedPreferences"])
        return {"result": result, "preferences": model.state["preferences"], "manualFixtureAction": True,
                "events": trace.events, "inputObservations": input_observations,
                "after": after, "idleAndRenewedAdmission": True}
    original = run_worker(root, "focused-fixture-owner", task, timeout=worker_timeout("focused-owner"))
    assert_original_return(original)
    value = read_case_json(root, "focused-fixture-owner")
    assert value["manualFixtureAction"] is True and value["preferences"] == plan["expectedPreferences"] \
        and value["result"]["status"] == expected_status and value["idleAndRenewedAdmission"] is True
    check_case_context(root, context)
    assert _CASE_CUSTODY.get(str(root)) == _CASE_RECOVERY_DEBT.get(str(root)) == plan["identity"] == _directory_identity(root)
    # Same fixed child completed all checks AND its actual original owner
    # returned. No second automatic absent worker, file-based permit or retry.
    del _CASE_RECOVERY_DEBT[str(root)]
    if report:
        return {"preferences": value["preferences"], "original": original, "observation": value}
    return value["preferences"]


def _focused_controls(root, token):
    """Observe every journal/fence control, including absence, around owner IO."""
    lease = root / "home" / signing.LEASE_DIRECTORY
    session = lease / ("session-" + token)
    result = {"lease": _directory_identity(lease), "session": _directory_identity(session), "files": {}}
    for name in sorted(signing.CONTROLS | signing.FENCE_CONTROLS):
        path = session / name
        try:
            value = path.lstat()
        except FileNotFoundError:
            result["files"][name] = None
        else:
            assert stat.S_ISREG(value.st_mode) and value.st_uid == os.getuid()
            result["files"][name] = {"facts": facts(path), "identity": [value.st_dev, value.st_ino,
                value.st_mode, value.st_uid, value.st_gid, value.st_nlink]}
    return result


_OWNER_TTY_ENV = "MRK_CI_PRIVATE_PTY"
_OWNER_TTY_STATE = {"active": False, "broken": False, "pair": None, "binding": None}


def _owner_tty_original():
    """Admit only the original ordinary entry's inherited Darwin capability."""
    assert not _OWNER_TTY_STATE["broken"], "private terminal custody is uncertain"
    raw = os.environ.get(_OWNER_TTY_ENV)
    assert type(raw) is str and 0 < len(raw) <= 1024, "missing original private terminal"
    assert _OWNER_TTY_STATE["binding"] in (None, raw), "original terminal binding was replaced"
    data = json.loads(raw)
    assert type(data) is dict and set(data) == {"version", "uid", "gid", "pair"}, "private terminal schema"
    assert type(data["version"]) is int and data["version"] == 1, "private terminal version"
    assert type(data["uid"]) is int and type(data["gid"]) is int \
        and 60000 <= data["uid"] < 65000 and data["gid"] == data["uid"], "private terminal numerical identity"
    assert (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) == (data["uid"],) * 4, "private terminal credentials"
    assert type(data["pair"]) is list and len(data["pair"]) == 2, "private terminal pair shape"
    assert json.dumps(data, sort_keys=True, separators=(",", ":")) == raw, "private terminal canonical binding"
    pair = []
    for item in data["pair"]:
        assert type(item) is list and len(item) == 2 and type(item[0]) is int \
            and 2 < item[0] < 1024 and item[0] not in pair, "private terminal descriptor slot"
        assert type(item[1]) is list and len(item[1]) == 6 \
            and all(type(value) is int and 0 <= value < 2 ** 64 for value in item[1]), "private terminal identity shape"
        info = os.fstat(item[0])
        assert [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_rdev] == item[1] \
            and stat.S_ISCHR(info.st_mode) and os.isatty(item[0]), "original terminal descriptor changed"
        pair.append(item[0])
    slave = os.fstat(pair[1])
    assert slave.st_uid == data["uid"] and stat.S_IMODE(slave.st_mode) == 0o600 \
        and re.fullmatch(r"/dev/ttys[0-9]{1,6}", os.ttyname(pair[1])), "private owned slave changed"
    pair = tuple(pair)
    assert _OWNER_TTY_STATE["pair"] in (None, pair), "original terminal pair was replaced"
    for fd in pair:
        os.set_inheritable(fd, False)  # Fork survives, unrelated exec does not.
    _OWNER_TTY_STATE.update(pair=pair, binding=raw)
    return pair


# Real ordinary fixture admission occurs at import, before model commands can
# run. No pair is allocated here and Linux/no-capability native roles are inert.
if sys.platform == "darwin" and _OWNER_TTY_ENV in os.environ:
    _owner_tty_original()


@contextmanager
def owner_tty(root, token, model, trace, action, *, focused_owner=None, input_observations=None):
    assert input_observations is None or type(input_observations) is list and not input_observations
    private = sys.platform == "darwin"
    if private:
        assert not _OWNER_TTY_STATE["active"] and not _OWNER_TTY_STATE["broken"], "private terminal is busy or uncertain"
        _OWNER_TTY_STATE["active"] = True
    base, copies, streams = None, [None, None], [None, None]
    primary, cleanup, yielded = None, [], False
    try:
        if private:
            original = _owner_tty_original()
            base = [None, None]
            base[0] = os.dup(original[0])
            base[1] = os.dup(original[1])
        else:
            base = os.openpty()  # Own the entire returned pair before setup.
        master, slave = base
        tty.setraw(slave)
        attributes = termios.tcgetattr(slave)
        attributes[3] |= termios.ICANON  # Real canonical EOF on an empty input line.
        termios.tcsetattr(slave, termios.TCSANOW, attributes)
        termios.tcflush(slave, termios.TCIOFLUSH)  # No state crosses serialized contexts.
        os.set_blocking(master, False)
        os.set_blocking(slave, True)
        copies[0] = os.dup(slave)
        streams[0] = os.fdopen(copies[0], "r", closefd=False)
        copies[1] = os.dup(slave)
        streams[1] = os.fdopen(copies[1], "w", closefd=False)
        read_stream, write_stream = streams
        class OwnerOutput:
            def isatty(self): return write_stream.isatty()
            def drain(self):
                while True:
                    try:
                        assert os.read(master, 4096), "fictional terminal disconnected"
                    except BlockingIOError:
                        return
            def write(self, text):
                # Real peer reads avoid Darwin's small PTY queue deadlock.
                for offset in range(0, len(text), 64):
                    write_stream.write(text[offset:offset + 64])
                    write_stream.flush()
                    self.drain()
                return len(text)
            def flush(self):
                write_stream.flush()
                self.drain()
        class OwnerInput:
            def isatty(self): return read_stream.isatty()
            def readline(self, bound):
                assert signing.signing_status(home=root / "home")["status"] == "busy"
                event = trace.begin("manual/input", "tty", "owner", {"action": action})
                observed = {"eventIndex": event["index"], "action": action}
                if input_observations is not None:
                    input_observations.append(observed)
                if action == "resolve":
                    model.oracle.resolve_owned(model)
                elif action in {"fixture/" + variant for variant in FOCUSED_OWNER_VARIANTS}:
                    assert focused_owner is not None and action == "fixture/" + focused_owner["variant"]
                    controls = _focused_controls(root, token)
                    try:
                        resolve_focused_fixture(root, model, focused_owner)
                    finally:
                        assert _focused_controls(root, token) == controls, "fixture owner changed production controls"
                if action == "cancel":
                    os.kill(os.getpid(), signal.SIGINT)
                    raise AssertionError("default manual cancellation was ignored")
                response = "wrong\n" if action == "wrong" else f"recheck {token}\n"
                os.write(master, attributes[6][termios.VEOF] if action == "eof" else response.encode())
                actual = read_stream.readline(bound)
                if input_observations is not None:
                    expected = "" if action == "eof" else response
                    assert actual == expected, "fictional terminal read differs from the selected input"
                    observed["read"] = {"kind": "eof" if actual == "" else "wrong" if actual == "wrong\n" else "recheck",
                                        "characters": len(actual)}
                trace.end(event, succeeded=True)
                return actual
        yielded = True
        yield OwnerInput(), OwnerOutput()
    except BaseException as error:
        primary = error
        if private and not yielded:
            _OWNER_TTY_STATE["broken"] = True
    # Streams never own their raw FD. Retire all exact slots independently;
    # a failing close never prevents another close or authorizes a retry.
    for index, stream in enumerate(streams):
        streams[index] = None
        if stream is not None:
            try:
                stream.close()
            except BaseException as error:
                cleanup.append(error)
    closing, copies = copies, None
    for fd in (*reversed(closing), *reversed(base or ())):
        if fd is not None:
            try:
                os.close(fd)
            except BaseException as error:
                cleanup.append(error)
    if private:
        _OWNER_TTY_STATE["active"] = False
        if cleanup:
            _OWNER_TTY_STATE["broken"] = True
    if cleanup:
        raise BaseExceptionGroup("fictional terminal operation and independent cleanup failed",
                                 ([primary] if primary is not None else []) + cleanup)
    if primary is not None:
        raise primary


def recovery_flow(root: Path, trace: Trace, *, manual="none", expected_preferences=None,
                  original_token=None, expected_status=None):
    from workflow import local_signing_case_owner as case_owner
    # An O-loss cut is not C death. Its original command custodian may still
    # finish the independently authorized fence/account tail outside case G.
    # Wait only for production exclusion, never a PID or a guessed wait. This
    # untraced rendezvous is not a reached-cut event or publication receipt.
    assert type(case_owner.CASE_DEADLINE) is float, "recovery requires original case deadline"
    case_owner.adapter_progress("recovery-check")
    observed_busy = False
    while signing.signing_status(home=root / "home")["status"] == "busy":
        if not observed_busy:
            observed_busy = True
            case_owner.adapter_progress("recovery-busy")
        case_owner.remaining(case_owner.CASE_DEADLINE)
        time.sleep(min(.002, case_owner.remaining(case_owner.CASE_DEADLINE)))
    case_owner.adapter_progress("recovery-ready")
    case_owner.remaining(case_owner.CASE_DEADLINE)
    before = snapshot(root)
    token = before["session"] if before["session"] is not None else (
        original_session_token(root) if original_token is None else original_token)
    assert type(token) is str and re.fullmatch(r"[0-9a-f]{32}", token), "missing original recovery token"
    assert original_token in {None, token}, "recovery token differs from original acquisition"
    trace.session_token = token
    unknown = uncertainty(root, before)
    model = PersistentSigningModel(root, trace=trace, recovery=True)
    trace.phase = "recovery"
    result, refused = None, None
    with trace.installed():
        initial = signing.signing_status(home=root / "home")
        try:
            assert initial["status"] in {"idle", "pending"}
            assert initial.get("session", token) == token
            if manual == "none":
                result = signing.recover_signing(token, signing.CONFIRMATION,
                                                home=root / "home", runner=model)
            else:
                with owner_tty(root, token, model, trace, manual) as (input_stream, output_stream):
                    result = signing.recover_signing(token, signing.CONFIRMATION,
                                                    home=root / "home", runner=model, manual=True,
                                                    input_stream=input_stream, output_stream=output_stream)
        except CredentialError as error:
            refused = str(error)
    after = snapshot(root)
    model.oracle.assert_sentinels()
    if refused is not None:
        # Only independent unknown resources justify a refused base-matrix cut.
        # A typed exception or a reassuring message alone is never acceptance.
        assert unknown, {"unexplainedRecoveryRefusal": refused, "before": before, "after": after}
        assert any(text in refused for text in ("unknown native staging", "native transaction identity is unknown",
                   "unproven profile stage", "owned profile bytes changed", "private profile stage was replaced")), refused
        assert_pending(root)
        assert all(facts(root / path) == identity for path, identity in unknown.items()), "unknown resource was adopted/deleted"
        assert before["controls"].get("intent.json") == after["controls"].get("intent.json"), "refusal changed immutable intent"
        assert expected_status in {None, "refused-unknown-resource"}, "unexpected declared positive recovery refusal"
    else:
        assert result["status"] in {"absent", "recovered", "recovered-with-conflict"}, result
        assert expected_status in {None, result["status"]}, "recovery status differs from finite case declaration"
        assert result["session"] == token
        if initial["status"] == "idle":
            assert result == {"status": "absent", "session": token}, "public absent recovery was not executed"
        expected_preferences = after["original"] if expected_preferences is None else expected_preferences
        assert_positive_postconditions(root, expected_preferences=expected_preferences)
    if expected_status is not None:
        manual_events = [event for event in trace.events if event["operation"] == "manual/input"]
        assert len(manual_events) == (0 if manual == "none" else 1), "declared manual branch was not executed"
        assert all(event["details"] == {"action": manual} and event.get("succeeded") is True for event in manual_events)
    output = trace.result()
    output.update(initial=initial, before=before, after=after, unknown=unknown, result=result, refused=refused)
    if expected_status is not None:
        output["expectedStatus"] = expected_status
        output["idleAndRenewedAdmission"] = refused is None
    return output


def recover_final(root: Path, *, expected_preferences=None) -> dict:
    run_worker(root, "final-automatic", lambda: recovery_flow(
        root, Trace(root, "final-automatic"), expected_preferences=expected_preferences),
        timeout=worker_timeout("automatic-recovery"))
    automatic = json.loads((root / "final-automatic.json").read_bytes())
    if automatic["refused"] is None:
        outcome = {"automatic": automatic["result"]["status"], "manual": None}
    else:
        run_worker(root, "final-no-resolution", lambda: recovery_flow(
            root, Trace(root, "final-no-resolution"), manual="observe", expected_preferences=expected_preferences),
            timeout=worker_timeout("manual-recovery"))
        unresolved = json.loads((root / "final-no-resolution.json").read_bytes())
        assert unresolved["refused"] is not None
        run_worker(root, "final-owner-resolution", lambda: recovery_flow(
            root, Trace(root, "final-owner-resolution"), manual="resolve", expected_preferences=expected_preferences),
            timeout=worker_timeout("manual-recovery"))
        resolved = json.loads((root / "final-owner-resolution.json").read_bytes())
        assert resolved["refused"] is None
        outcome = {"automatic": "refused-unknown-resource", "manual": resolved["result"]["status"]}
    # Only this original fresh recovery path reaches here: recovery_flow has
    # obtained real account exclusion, checked idle and renewed lease admission;
    # run_worker has also settled its actual A/W/G. Exceptions never clear debt.
    assert (outcome["manual"] or outcome["automatic"]) in {"absent", "recovered", "recovered-with-conflict"}
    key = str(root)
    if key in _CASE_RECOVERY_DEBT:
        assert _CASE_RECOVERY_DEBT[key] == _CASE_CUSTODY.get(key) == _directory_identity(root), "unconfirmed recovery-debt settlement"
        del _CASE_RECOVERY_DEBT[key]
    return outcome


def edges(event):
    result = ["before", "after"]
    if event["operation"] in {"write", "buffer.write", "command-fence/PENDING_WRITE"} or event["operation"].startswith("native-effect/write/"):
        result.append("partial")
    return result


def remove_case(root: Path):
    # Called ONLY after exact worker wait + group-absence proof and after copying
    # required evidence. Never a stale recovery-journal PID deletion authority.
    import shutil
    assert str(root) not in _CASE_RECOVERY_DEBT, "original C recovery debt remains; retain case directory"
    assert _CASE_CUSTODY.get(str(root)) == _directory_identity(root), "unconfirmed or replaced case directory"
    assert shutil.rmtree.avoids_symlink_attacks, "descriptor-relative fixture removal unavailable"
    shutil.rmtree(root)
    _CASE_CUSTODY.pop(str(root))


def inventory_original(root: Path):
    initialize(root)
    run_worker(root, "inventory", lambda: original_flow(root, Trace(root, "inventory", inventory=True)),
               timeout=worker_timeout("persistent-original"))
    return json.loads((root / "inventory.json").read_bytes())


def seeds(inventory):
    """Select actual original-flow edges, never synthesize a recovery journal."""
    events = inventory["events"]
    result = {}
    def select(name, operation, *, suffix=None, phase=None, edge="after", occurrence=0, destination=None):
        matches = [event for event in events if event["operation"] == operation
                   and (suffix is None or event["slot"].endswith(suffix))
                   and (phase is None or event["phase"] == phase)
                   and (destination is None or event["details"].get("destination", "").endswith(destination))]
        assert matches and occurrence < len(matches), {"missingSeedBoundary": name}
        result[name] = {"event": matches[occurrence], "edge": edge}
    select("empty-session", "mkdir", suffix="session-<TOKEN>")
    select("empty-native-directory", "mkdir", suffix="/keychain")
    select("intent-pending-empty", "write", suffix="/intent.pending", edge="before")
    select("intent-pending-partial", "write", suffix="/intent.pending", edge="partial")
    select("intent-committed", "replace", destination="/intent.json")
    select("initial-state-pending", "write", suffix="/state.pending", edge="partial")
    select("profile-unrecorded-stage", "open", suffix=".mobile-release-profile-<TOKEN>")
    select("profile-partial-bytes", "buffer.write", edge="partial")
    select("profile-complete-link", "link")
    select("native-unrecorded-create", "native-effect/create/" + signing.DB_NAME)
    select("native-transaction-stage", "native-effect/create/native-atomic-stage")
    select("native-unrecorded-inode", "native-effect/replace/" + signing.DB_NAME)
    select("active-before-build", "open", phase="build", edge="before")
    select("active-build-handed-off", "native/build", edge="before")
    select("active-build-result", "native/build")
    select("active-known-pending", "write", suffix="/state.pending", phase="build", edge="partial")
    select("active-build-pending", "write", suffix="/state.pending", phase="build", occurrence=2, edge="partial")
    select("active-after-build", "open", phase="cleanup", edge="before")
    select("default-restored", "native-effect/preference/default", phase="cleanup")
    select("search-restored", "native-effect/preference/search", phase="cleanup")
    select("terminal-pending-empty", "write", suffix="/completed.pending", edge="before")
    select("terminal-pending-partial", "write", suffix="/completed.pending", edge="partial")
    select("completed", "replace", destination="/completed.json")
    select("completed-without-state", "unlink", suffix="/state.json")
    select("completed-without-native-directory", "rmdir", suffix="/keychain")
    select("completed-only", "unlink", suffix="/intent.json")
    select("final-empty", "unlink", suffix="/completed.json")
    select("final-absent", "rmdir", suffix="session-<TOKEN>")
    return result


def seed_case(root, target, *, borrowed=False, auto_add=False, after_effect=None):
    initialize(root, borrowed=borrowed)
    require_fresh_recovery(root)
    run_worker(root, "seed", lambda: original_flow(root, Trace(root, "seed", target, after_effect=after_effect),
                                                 auto_add=auto_add), timeout=worker_timeout("persistent-original"), expect=CRASH)
    return json.loads((root / "seed-cut.json").read_bytes())


def recovery_inventory(root, original):
    groups = {}
    for name, target in seeds(original).items():
        for manual in ("none", "observe", "resolve"):
            case = root / "case"
            case.mkdir(mode=0o700)
            cut = seed_case(case, target)
            unknown = uncertainty(case, cut["snapshot"])
            if manual != "none" and not unknown:
                # A/W/G settlement alone does not settle a separately grouped
                # command custodian. Re-enter real fresh recovery (including
                # its bounded original-hold exclusion) before disposal even
                # when this particular manual branch is inapplicable.
                recover_final(case)
                remove_case(case)
                continue  # Explicitly inapplicable: no refused resources, thus no TTY branch.
            group = name + "/" + manual
            run_worker(case, "recovery-inventory", lambda: recovery_flow(
                case, Trace(case, "recovery-inventory", inventory=True), manual=manual), timeout=recovery_timeout(manual))
            result = json.loads((case / "recovery-inventory.json").read_bytes())
            # Identical IO/line traces do not establish semantic equivalence of
            # starting/intermediate authority, resource or inflight state.
            # Replay EVERY explicit seed/manual state; no equivalences assumed.
            groups[group] = {"seed": name, "target": target, "manual": manual, "cut": cut, "inventory": result}
            recover_final(case)
            remove_case(case)
    # Evidence must contain actual successful removal, not just a failed read of
    # every pending slot; these are three distinct production cleanup branches.
    all_records = list(groups.values())
    removed = {Path(event["slot"]).name for record in all_records for event in record["inventory"]["events"]
               if event["operation"] == "unlink" and event["succeeded"]}
    assert {"intent.pending", "state.pending", "completed.pending"} <= removed, removed
    assert any(record["manual"] == "resolve" for record in groups.values())
    assert any(record["manual"] == "observe" for record in groups.values())
    return {"groups": groups, "equivalences": {}, "equivalencePolicy": "none; every seed/manual state is replayed",
            "actualPendingSlotsRemoved": sorted(removed)}


def append_evidence(root, target, outcome, case, *, seed=None, case_id=None):
    results = {}
    for name in ("seed-cut", "original-cut", "recovery-cut", "final-automatic", "final-no-resolution", "final-owner-resolution"):
        path = case / (name + ".json")
        if path.exists():
            value = json.loads(path.read_bytes())
            # Preserve complete actual before/after/resource/authority facts, not
            # megabytes of repeated non-selected trace events for each replay.
            results[name] = {key: item for key, item in value.items() if key not in ("events", "lines")}
    with gzip.open(root / "results.jsonl.gz", "at", compresslevel=1) as output:
        output.write(json.dumps({"caseId": case_id, "seed": seed, "target": target, "outcome": outcome, "results": results}) + "\n")


def matrix_cases(original, recovery):
    """Full logical inventory; index is retained only for exact local dispatch."""
    records = {}
    groups = {"original": {"inventory": original, "target": None, "manual": "none"}, **recovery["groups"]}
    for group, record in groups.items():
        for event in record["inventory"]["events"]:
            for edge in edges(event):
                case_id = logical_case_id(group, event, edge)
                assert case_id not in records, "duplicate logical crash case"
                records[case_id] = {"group": group, "target": {"event": event, "edge": edge},
                                    "seed": record["target"], "manual": record["manual"]}
    assert all(any(shard_for(case_id) == shard for case_id in records) for shard in range(SHARDS)), "empty partition"
    return dict(sorted(records.items()))


def matrix_inventory_digest(cases, original, recovery):
    # Assignment excludes effect flags; equality does NOT. Include the actual
    # seed selector and visited branches, independent of hash-set read order.
    normalized = []
    for case_id, record in cases.items():
        seed = record["seed"]
        normalized.append({"id": case_id, "event": event_fact(record["target"]["event"]),
                           "seed": {"event": event_fact(seed["event"]), "edge": seed["edge"]} if seed else None})
    return digest({"cases": normalized, "originalLines": original["lines"],
                   "recoveryLines": {name: record["inventory"]["lines"] for name, record in recovery["groups"].items()}})


def replay_shard(root, original, recovery, shard):
    assert type(shard) is int and 0 <= shard < SHARDS, "invalid shard"
    cases = matrix_cases(original, recovery)
    expected = [case_id for case_id in cases if shard_for(case_id) == shard]
    actual, counts = [], collections.Counter()
    package = Path(signing.__file__).resolve().parent
    before_package, before_definitions = package_manifest(package), definitions_manifest(ROOT)
    for case_id in expected:
        record = cases[case_id]
        case = root / "case"
        case.mkdir(mode=0o700)
        if record["seed"] is None:
            initialize(case)
            require_fresh_recovery(case)
            run_worker(case, "original", lambda: original_flow(case, Trace(case, "original", record["target"])),
                       timeout=worker_timeout("persistent-original"), expect=CRASH)
        else:
            seed_case(case, record["seed"])
            run_worker(case, "recovery", lambda: recovery_flow(
                case, Trace(case, "recovery", record["target"]), manual=record["manual"]),
                timeout=recovery_timeout(record["manual"]), expect=CRASH)
        outcome = recover_final(case)
        append_evidence(root, record["target"], outcome, case, seed=record["group"], case_id=case_id)
        remove_case(case)
        actual.append(case_id)  # Only after actual cut, final recovery, evidence and exact cleanup.
        counts[record["group"]] += 1
        counts[record["target"]["edge"]] += 1
        counts[outcome["automatic"]] += 1
        if outcome["manual"]:
            counts["manual/" + outcome["manual"]] += 1
    assert actual == expected and actual, "incomplete assigned execution"
    assert package_manifest(package) == before_package and definitions_manifest(ROOT) == before_definitions, "source changed during execution"
    return {"shard": shard, "scope": "partial; one of sixteen required shards", "expectedCaseIds": list(cases),
            "executedCaseIds": actual, "inventorySha256": matrix_inventory_digest(cases, original, recovery),
            "packageSha256": digest(before_package), "definitionsSha256": digest(before_definitions),
            "counts": dict(counts), "productionRoot": str(package), "recoveryGroups": sorted(recovery["groups"]),
            "allExactChildrenReapedAndGroupsAbsent": True, "allCasePathsRemoved": True}


def replay_recovery_group(root, group, record):
    counts = collections.Counter()
    for event in record["inventory"]["events"]:
        for edge in edges(event):
            case = root / "case"
            case.mkdir(mode=0o700)
            seed_case(case, record["target"])
            target = {"event": event, "edge": edge}
            run_worker(case, "recovery", lambda: recovery_flow(
                case, Trace(case, "recovery", target), manual=record["manual"]),
                timeout=recovery_timeout(record["manual"]), expect=CRASH)
            outcome = recover_final(case)
            counts[edge] += 1
            counts[outcome["automatic"]] += 1
            if outcome["manual"]:
                counts["manual/" + outcome["manual"]] += 1
            append_evidence(root, target, outcome, case, seed=group)
            remove_case(case)
    return dict(counts)


def assert_refusal_manual_evidence(trace, input_observations, manual, error):
    """Validate observed branch data; this grants no recovery or process custody."""
    assert manual in {"none", "resolve", "wrong", "eof", "cancel"}
    events = [event for event in trace.events if event["operation"] == "manual/input"]
    assert len(events) == len(input_observations) == (0 if manual == "none" else 1), \
        "declared focused manual branch was not executed exactly once"
    if manual == "none":
        assert isinstance(error, CredentialError), "automatic refusal did not retain its actual failure"
        return
    event, observation = events[0], input_observations[0]
    assert event["origin"] == "owner" and event["slot"] == "tty" and event["details"] == {"action": manual}
    assert observation.get("eventIndex") == event["index"] and observation.get("action") == manual
    if manual in {"wrong", "eof"}:
        assert isinstance(error, CredentialError) and event.get("succeeded") is True
        assert observation.get("read") == {"kind": manual, "characters": 6 if manual == "wrong" else 0}, \
            "focused refusal lacks its actual wrong/EOF terminal read"
    else:
        expected = KeyboardInterrupt if manual == "cancel" else OwnerResolutionRefused
        assert type(error) is expected, "focused interruption/owner refusal did not retain its original failure"
        assert event.get("succeeded") is None and "read" not in observation, \
            "failed focused owner input was falsely completed"


def refusal_case(root, *, message, preserved, manual="none", terminal=False, preserve_preferences=False):
    assert manual in {"none", "resolve", "wrong", "eof", "cancel"}
    before = snapshot(root)
    model = PersistentSigningModel(root, recovery=True)
    trace = Trace(root, "focused-refusal")
    token = before["session"]
    input_observations, caught = [], None
    try:
        if manual == "none":
            signing.recover_signing(token, signing.CONFIRMATION, home=root / "home", runner=model)
        else:
            with owner_tty(root, token, model, trace, manual,
                           input_observations=input_observations) as (input_stream, output_stream):
                signing.recover_signing(token, signing.CONFIRMATION, home=root / "home", runner=model, manual=True,
                                        input_stream=input_stream, output_stream=output_stream)
    except CredentialError as error:
        assert message in str(error), str(error)
        caught, error_text = error, str(error)
    except KeyboardInterrupt as error:
        assert manual == "cancel"
        caught, error_text = error, "actual default cancellation"
    except OwnerResolutionRefused as error:
        assert manual == "resolve" and message in str(error)
        caught, error_text = error, str(error)
    else:
        raise AssertionError("unresolved/conflicting resource was accepted")
    assert_refusal_manual_evidence(trace, input_observations, manual, caught)
    after = snapshot(root)
    for name, original in preserved.items():
        assert facts(root / name) == original, "recovery changed the explicitly unproven resource"
    assert before["controls"]["intent.json"] == after["controls"]["intent.json"], "immutable authority changed"
    if preserve_preferences:
        assert before["preferences"] == after["preferences"]
        assert all(not call["mutation"] for call in after["nativeCalls"][len(before["nativeCalls"]):])
    if terminal:
        assert before["controls"] == after["controls"]
        assert before["preferences"] == after["preferences"]
        assert all(not call["mutation"] for call in after["nativeCalls"][len(before["nativeCalls"]):])
    ResourceOracle(root).assert_sentinels()
    assert_pending(root)
    return {"before": before, "after": after, "error": error_text, "caughtType": type(caught).__name__,
            "events": trace.events, "inputObservations": input_observations,
            "resourcesPreserved": True, "freshAdmission": "pending"}


def focused_cases(root, inventory):
    """Foreign edits and terminal conflicts are not the base matrix's manual fallback."""
    results = {}
    selected = seeds(inventory)
    for variant in ("foreign-default", "reordered-search", "deleted-search", "foreign-profile",
                    "profile-inplace-edit", "native-unknown-stage", "foreign-native-db", "terminal-profile-reappeared",
                    "terminal-native-reappeared", "manual-wrong", "manual-eof", "manual-cancel"):
        case = root / "case"
        case.mkdir(mode=0o700)
        destination = case / "home/Library/MobileDevice/Provisioning Profiles" / (UUID + ".mobileprovision")
        target = selected["active-after-build"]
        if variant.startswith("manual-"):
            target = selected["profile-unrecorded-stage"]
        elif variant.startswith("terminal-"):
            target = selected["completed"]

        def keep_profile(event):
            if variant == "terminal-profile-reappeared" and event["operation"] == "link" and event["succeeded"]:
                os.link(destination, case / "retained-fictional-profile")
        seed_case(case, target, after_effect=keep_profile)
        receipts = {}
        model = PersistentSigningModel(case)
        expected = copy.deepcopy(model.state["original"])
        if variant in {"foreign-default", "reordered-search", "deleted-search"}:
            foreign = case / "home/foreign.keychain-db"
            foreign.write_bytes(b"unrelated fictional keychain"); foreign.chmod(0o600)
            model.oracle.record_foreign(foreign, None)
            if variant == "foreign-default":
                model.state["preferences"]["default"] = str(foreign)
                expected["default"] = str(foreign)
            elif variant == "reordered-search":
                model.state["preferences"]["search"] = [expected["search"][1], model.state["keychain"],
                                                        expected["search"][0], str(foreign)]
                expected["search"] = [expected["search"][1], expected["search"][0], str(foreign)]
            else:
                model.state["preferences"]["search"] = []
                expected["search"] = []
            model.save()
        elif variant == "foreign-profile":
            before = facts(destination)
            foreign = case / "foreign-profile"
            foreign.write_bytes(b"unrelated replacement profile"); foreign.chmod(0o600)
            foreign.replace(destination)
            assert facts(destination)["inode"] != before["inode"]
            model.oracle.record_foreign(destination, before)
        elif variant == "profile-inplace-edit":
            before = facts(destination)
            destination.write_bytes(b"changed in place, not the originally authenticated bytes")
            assert facts(destination)["inode"] == before["inode"]
        elif variant == "native-unknown-stage":
            stage = Path(model.state["keychain"]).parent / "unknown-transaction-stage"
            stage.write_bytes(b"independently observed fictional native staging"); stage.chmod(0o600)
            model.oracle.record(stage, "native")
        elif variant == "foreign-native-db":
            database = Path(model.state["keychain"])
            before = facts(database)
            replacement = case / "foreign-native-database"
            replacement.write_bytes(b"independent foreign replacement keychain")
            replacement.chmod(0o600)
            replacement.replace(database)
            assert facts(database)["inode"] != before["inode"]
            model.oracle.record_foreign(database, before)
            assert str(database) == model.state["preferences"]["default"]
            assert str(database) in model.state["preferences"]["search"]
        elif variant == "terminal-profile-reappeared":
            assert not destination.exists()
            os.link(case / "retained-fictional-profile", destination)
        elif variant == "terminal-native-reappeared":
            path = Path(model.state["keychain"])
            assert not path.exists()
            path.write_bytes(b"new unexplained native state after completion"); path.chmod(0o600)

        if variant in FOCUSED_OWNER_VARIANTS:
            edited = (Path(model.state["keychain"])
                      if variant in {"terminal-native-reappeared", "foreign-native-db"} else destination)
            receipts[edited.relative_to(case).as_posix()] = focused_receipt(case, edited)
            if variant == "terminal-profile-reappeared":
                receipts["retained-fictional-profile"] = focused_receipt(case, case / "retained-fictional-profile")

        if variant in {"foreign-default", "reordered-search", "deleted-search", "foreign-profile"}:
            run_worker(case, "focused", lambda: recovery_flow(case, Trace(case, "focused"), expected_preferences=expected),
                       timeout=worker_timeout("automatic-recovery"))
            result = json.loads((case / "focused.json").read_bytes())
            assert result["result"]["status"] == "recovered-with-conflict"
        elif variant == "native-unknown-stage":
            result = recover_final(case)
            assert result == {"automatic": "refused-unknown-resource", "manual": "recovered-with-conflict"}
        elif variant == "foreign-native-db":
            preserved = {str(database.relative_to(case)): facts(database)}
            result = {}
            for mode, message in (("none", "native transaction identity is unknown"),
                                  ("resolve", "owner cannot identify an intervening replacement/edit")):
                run_worker(case, "focused-" + mode, lambda: refusal_case(
                    case, message=message, preserved=preserved, manual=mode, preserve_preferences=True),
                    timeout=worker_timeout("focused-refusal"))
                result[mode] = json.loads((case / ("focused-" + mode + ".json")).read_bytes())
        else:
            preserved = {}
            manual, terminal = "none", variant.startswith("terminal-")
            if variant == "profile-inplace-edit":
                message = "owned profile bytes changed"
                preserved[str(destination.relative_to(case))] = facts(destination)
            elif variant == "terminal-profile-reappeared":
                message = "previously cleaned profile resource reappeared"
                preserved[str(destination.relative_to(case))] = facts(destination)
            elif variant == "terminal-native-reappeared":
                message = "terminal session has new native resources/references"
                path = Path(model.state["keychain"])
                preserved[str(path.relative_to(case))] = facts(path)
            else:
                manual = variant.removeprefix("manual-")
                message = "manual recheck cancelled or incorrect"
                preserved = ResourceOracle(case).owned_remaining()
            run_worker(case, "focused", lambda: refusal_case(case, message=message, preserved=preserved,
                                                              manual=manual, terminal=terminal),
                       timeout=worker_timeout("focused-refusal"))
            result = json.loads((case / "focused.json").read_bytes())
        results[variant] = result
        # Preserve the original negative/conflict independently BEFORE owner
        # work; subsequent success never rewrites it as a passing recovery.
        write_json(root / "focused-evidence.json", results)
        if variant in FOCUSED_OWNER_VARIANTS:
            plan = focused_owner_plan(case, variant, receipts)
            expected = settle_focused_fixture(case, plan)
        if str(case) in _CASE_RECOVERY_DEBT:
            recover_final(case, expected_preferences=expected)
        remove_case(case)

    for variant in ("auto-add", "borrowed-profile"):
        case = root / "case"
        case.mkdir(mode=0o700)
        initialize(case, borrowed=variant == "borrowed-profile")
        run_worker(case, "focused-inventory", lambda: original_flow(
            case, Trace(case, "focused-inventory", inventory=True), auto_add=variant == "auto-add"),
            timeout=worker_timeout("persistent-original"))
        alternate = json.loads((case / "focused-inventory.json").read_bytes())
        remove_case(case)
        case.mkdir(mode=0o700)
        target = seeds(alternate)["active-after-build"] if variant == "auto-add" else {
            "event": next(event for event in alternate["events"] if event["phase"] == "cleanup"), "edge": "before"}
        seed_case(case, target, borrowed=variant == "borrowed-profile", auto_add=variant == "auto-add")
        result = recover_final(case)
        assert result == {"automatic": "recovered", "manual": None}
        results[variant] = result
        write_json(root / "focused-evidence.json", results)
        remove_case(case)
        if variant == "auto-add":
            target = {"event": next(event for event in alternate["events"]
                                    if event["operation"] == "native-effect/create-search-add"), "edge": "after"}
            case.mkdir(mode=0o700)
            seed_case(case, target, auto_add=True)
            result = recover_final(case)
            assert result["automatic"] == "refused-unknown-resource" and result["manual"] is not None
            results["auto-add-ambiguous-create"] = result
            write_json(root / "focused-evidence.json", results)
            remove_case(case)
    write_json(root / "focused-evidence.json", results)
    return {"cases": sorted(results), "count": len(results), "allExactChildrenReapedAndGroupsAbsent": True}


def main(root: Path, mode: str):
    started = time.monotonic()
    assert Path(signing.__file__).resolve().parent.parent == Path(sys.path[0]).resolve(), "wrong production import root"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if mode.startswith("harness-"):
        def blocked():
            write_json(root / "case-live.json", {"pid": os.getpid()})
            time.sleep(30)
        if mode == "harness-deadline":
            return run_worker(root, "deadline", blocked, timeout=.2, expect=-signal.SIGKILL)
        assert mode == "harness-parent-loss"
        return run_worker(root, "parent-loss", blocked, timeout=20)
    inventory_root = root / "inventory"
    inventory_root.mkdir(mode=0o700)
    inventory = inventory_original(inventory_root)
    write_json(root / "original-inventory.json", inventory)
    remove_case(inventory_root)
    if mode == "inventory":
        return {"count": len(inventory["events"]), "cuts": sum(len(edges(event)) for event in inventory["events"]),
                "productionRoot": str(Path(signing.__file__).resolve().parent), "elapsed": time.monotonic() - started}
    if mode == "focused":
        return focused_cases(root, inventory)
    if mode.startswith("shard/"):
        value = mode.removeprefix("shard/")
        assert value.isdecimal() and str(int(value)) == value and 0 <= int(value) < SHARDS, "invalid shard selection"
        recovery = recovery_inventory(root, inventory)
        write_json(root / "recovery-inventory.json", recovery)
        result = replay_shard(root, inventory, recovery, int(value))
        result["elapsed"] = time.monotonic() - started
        write_json(root / "matrix-result.json", result)
        return {key: value for key, value in result.items() if key not in ("expectedCaseIds", "executedCaseIds")}
    if mode.startswith("recovery"):
        recovery = recovery_inventory(root, inventory)
        write_json(root / "recovery-inventory.json", recovery)
        counts = {group: sum(len(edges(event)) for event in record["inventory"]["events"])
                  for group, record in recovery["groups"].items()}
        if mode == "recovery-inventory":
            return {"groups": counts, "equivalentGroups": len(recovery["equivalences"]),
                    "cuts": sum(counts.values()), "elapsed": time.monotonic() - started}
        if mode == "recovery":
            selected = recovery["groups"]
        else:
            assert mode.startswith("recovery/"), "unknown recovery mode"
            group = mode.removeprefix("recovery/")
            assert group in recovery["groups"], "requested recovery group is not an inventoried representative"
            selected = {group: recovery["groups"][group]}
        return {"groups": {group: replay_recovery_group(root, group, record) for group, record in selected.items()},
                "elapsed": time.monotonic() - started}
    assert mode == "original", "unknown persistent matrix group"
    counts = collections.Counter()
    for event in inventory["events"]:
        for edge in edges(event):
            case = root / "case"
            case.mkdir(mode=0o700)
            initialize(case)
            require_fresh_recovery(case)
            target = {"event": event, "edge": edge}
            run_worker(case, "original", lambda: original_flow(case, Trace(case, "original", target)),
                       timeout=worker_timeout("persistent-original"), expect=CRASH)
            outcome = recover_final(case)
            counts[edge] += 1
            counts[event["operation"]] += 1
            counts[outcome["automatic"]] += 1
            if outcome["manual"]:
                counts["manual/" + outcome["manual"]] += 1
            append_evidence(root, target, outcome, case)
            remove_case(case)
    return {"counts": dict(counts), "elapsed": time.monotonic() - started, "productionRoot": str(Path(signing.__file__).resolve().parent),
            "allExactChildrenReapedAndGroupsAbsent": True, "allCasePathsRemoved": True}
