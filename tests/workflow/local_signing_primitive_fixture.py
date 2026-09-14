"""Real filesystem algorithms, not signing-command or recovery receipts.

Only the fixed matrix executor calls these helpers in its disposable owner.
Every case uses the existing original case-worker custody.  No component may
dispatch a command, mint a command outcome, or claim to recover a signing run.
"""
from __future__ import annotations

import copy
import errno
import hashlib
import json
import os
import stat
import sys
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mobile_release import credentials, local_signing as signing
from mobile_release.errors import CredentialError
from mobile_release.owned_process import ProcessError
from workflow import local_signing_persistent_fixture as fixture


COMPONENT_NAMES = (
    "writer-intent-first", "writer-state-first", "writer-state-replace", "writer-completed-first",
    "remover-intent-json", "remover-state-json", "remover-completed-json",
    "remover-intent-pending", "remover-state-pending", "remover-completed-pending",
    "reader-private", "reader-profile", "installer-owned", "installer-borrowed",
    "writer-failures", "reader-failures", "remover-failures",
)
_OLD = {"fixtureAlgorithmData": "old", "generation": 1}
_NEW = {"fixtureAlgorithmData": "new", "generation": 2}
_READ_BYTES = b"fictional bounded reader data\n" * 2500
_EXTRA_IO = ("read", "stat", "fstat")
_IO = frozenset((*fixture.IO_OPERATIONS, *_EXTRA_IO,
                 "buffer.open", "buffer.read", "buffer.write", "buffer.flush", "buffer.close"))
_WRITER_OPS = frozenset({"open", "write", "fsync", "close", "stat", "fstat", "replace"})
_READER_OPS = frozenset({"open", "read", "close", "stat", "fstat"})
_INSTALLER_COMMON = frozenset({"open", "close", "stat", "fstat", "fsync", "mkdir",
                               "buffer.open", "buffer.read", "buffer.close"})
_ALGORITHM_OPERATIONS = {
    "writer-intent-first": _WRITER_OPS,
    "writer-state-first": _WRITER_OPS,
    "writer-state-replace": _WRITER_OPS | {"read"},
    "writer-completed-first": _WRITER_OPS,
    **{name: _READER_OPS | {"unlink", "fsync"} for name in COMPONENT_NAMES if name.startswith("remover-")
       and name != "remover-failures"},
    "reader-private": _READER_OPS,
    "reader-profile": _READER_OPS,
    "installer-owned": _INSTALLER_COMMON | {"buffer.write", "buffer.flush", "link", "unlink"},
    "installer-borrowed": _INSTALLER_COMMON,
}
_WRITER_FAILURES = (
    "short-write", "zero-write", "oversized-write", "partial-write-error",
    "pending-intent", "pending-state", "pending-completed", "immutable-intent", "immutable-completed",
    "stage-replaced", "target-replaced", "file-sync-before", "file-sync-after",
    "directory-sync-before", "directory-sync-after", "close-after",
)
_READER_FAILURES = ("read-before", "read-after", "reader-name-changed", "reader-close-after")
_REMOVER_FAILURES = ("unlink-before", "unlink-after", "remove-sync-before", "remove-sync-after")
_FOREIGN = b"fictional independent replacement\n"


def _forbid_command(*_args, **_kwargs):
    raise AssertionError("filesystem component attempted a native/signing command")


def _identities(root: Path) -> dict:
    home = root / "home"
    result = {}
    for path in [home, *sorted(home.rglob("*"))]:
        details = path.lstat()
        relative = fixture.Trace.normalize(SimpleNamespace(root=root), path.relative_to(root))
        result[relative] = [details.st_dev, details.st_ino]
    return result


def _identity_key(details):
    return str(details.st_dev) + ":" + str(details.st_ino)


def _physical(root: Path, initial: dict | None = None, generations: dict | None = None) -> dict:
    """Independent bounded readback; never a production cleanup capability."""
    home = root / "home"
    rows, aliases = {}, {}
    paths = [home, *sorted(home.rglob("*"))]
    assert len(paths) <= 256, "component fixture acquired unexpected entries"
    for path in paths:
        details = path.lstat()
        relative = fixture.Trace.normalize(SimpleNamespace(root=root), path.relative_to(root))
        row = {"type": stat.S_IFMT(details.st_mode), "mode": stat.S_IMODE(details.st_mode),
               "links": details.st_nlink}
        if initial is not None:
            row["initialAliases"] = sorted(name for name, value in initial.items()
                                           if value == [details.st_dev, details.st_ino])
            if generations is not None and not row["initialAliases"]:
                assert _identity_key(details) in generations, "unobserved algorithm creation/replacement"
                row["createdBy"] = generations[_identity_key(details)]
        if stat.S_ISREG(details.st_mode):
            assert details.st_size <= 4 * 1024**2
            content = path.read_bytes()
            assert len(content) == details.st_size
            row.update(size=len(content), sha256=hashlib.sha256(content).hexdigest())
            aliases.setdefault((details.st_dev, details.st_ino), []).append(relative)
        elif stat.S_ISLNK(details.st_mode):
            row["target"] = os.readlink(path).replace(str(root), "<ROOT>")
        else:
            assert stat.S_ISDIR(details.st_mode), "unexpected component special file"
        assert relative not in rows
        rows[relative] = row
    for paths in aliases.values():
        for name in paths:
            rows[name]["aliases"] = sorted(paths)
    return rows


def _no_native(root: Path, trace=None) -> None:
    native = json.loads((root / "observed-native.json").read_bytes())
    assert not native["calls"] and native["keychain"] is None and native["revisions"] == 0
    assert native["preferences"] == native["original"]
    fixture.ResourceOracle(root).assert_sentinels()
    if trace is not None:
        assert trace._fence_session is None and trace._fence_event is None and trace._fence_evidence is None


def _event_key(event: dict) -> dict:
    return {key: value for key, value in event.items() if key not in {"succeeded", "error"}}


class ComponentTrace(fixture.Trace):
    """Observe only the selected algorithm; retain the original FD/path map."""

    def __init__(self, root: Path, name: str, selection=None, *, observe_states=True):
        super().__init__(root, name)
        self.selection, self.active = selection, False
        self.focus, self.states, self.partial_fact = [], {}, None
        self.initial, self.observe_states = None, observe_states
        self.generations = {}
        self.phase = "component"

    def begin(self, operation, slot, origin, details):
        event = super().begin(operation, slot, origin, details)
        if self.active:
            assert operation in _IO, "unclassified algorithm operation"
            assert slot != "unmapped-descriptor", "algorithm descriptor provenance is missing"
            self.focus.append(event["index"])
            if self.observe_states:
                self.states[event["index"]] = {"before": _physical(self.root, self.initial, self.generations)}
            if self.selected(event, "before"):
                self.cut(event, "before")
        return event

    def end(self, event, *, succeeded, error=None):
        super().end(event, succeeded=succeeded, error=error)
        if self.active:
            if self.observe_states:
                assert event["index"] in self.states
                self.states[event["index"]]["after"] = _physical(self.root, self.initial, self.generations)
            if self.selected(event, "after"):
                assert event == self.selection["event"], "algorithm after-effect differs"
                self.cut(event, "after")

    def selected(self, event, edge):
        if self.selection is None or event["index"] != self.selection["event"]["index"]:
            return False
        assert _event_key(event) == _event_key(self.selection["event"]), "algorithm event drift"
        return self.selection["edge"] == edge

    def partial(self, event):
        return self.selected(event, "partial")

    def cut(self, event, edge):
        assert self.active and self.selected(event, edge), "unselected component cut"
        _no_native(self.root, self)
        fixture.write_json(self.root / (self.name + "-cut.json"), {
            "event": event, "edge": edge, "physical": _physical(self.root, self.initial, self.generations),
            "initial": self.initial, "generations": self.generations, "atCutIdentities": _identities(self.root),
            "partial": self.partial_fact, "nativeCommands": 0,
        })
        os._exit(fixture.CRASH)

    def wrapper(self, operation, actual):
        # One wrapper frame only: nesting Trace.wrapper behind another fixture
        # wrapper would make Trace.origin correctly reject its own fixture frame
        # and silently lose the real write observations.
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
                prefix = bytes(args[1][:max(1, len(args[1]) // 2)])
                count = actual(args[0], prefix)
                assert type(count) is int and 0 < count <= len(prefix) < len(args[1])
                self.partial_fact = {"slot": self.normalize(slot), "requested": len(args[1]),
                                     "prefixHex": prefix[:count].hex()}
                self.record_profile(slot)
                self.cut(event, "partial")
            try:
                result = self.perform(event, actual, args, kwargs)
            except BaseException as error:
                self.end(event, succeeded=False, error=type(error).__name__)
                raise
            if operation in {"open", "dup"}:
                self.descriptors[result] = slot
                if operation == "open" and args[1] & os.O_CREAT and args[1] & os.O_EXCL:
                    created = os.fstat(result)  # Actual returned FD, never a pathname adoption.
                    self.generations[_identity_key(created)] = {"operation": "open", "event": event["index"]}
            elif operation == "mkdir":
                created = os.stat(args[0], dir_fd=kwargs.get("dir_fd"), follow_symlinks=False)
                self.generations[_identity_key(created)] = {"operation": "mkdir", "event": event["index"]}
            elif operation == "close":
                self.descriptors.pop(args[0], None)
            if operation in {"open", "write"}:
                self.record_profile(slot)
            elif operation in {"link", "replace"}:
                self.record_profile(destination)
            self.end(event, succeeded=True)
            return result
        return invoke

    def perform(self, event, actual, args, kwargs):
        return actual(*args, **kwargs)

    def fdopen(self, actual):
        def opening(fd, *args, **kwargs):
            origin = self.origin(sys._getframe(1))
            if origin is None:
                return actual(fd, *args, **kwargs)
            slot = self.path(fd)
            event = self.begin("buffer.open", slot, origin, {"mode": args[0] if args else kwargs.get("mode", "r"),
                                                          "closefd": kwargs.get("closefd", True)})
            try:
                stream = actual(fd, *args, **kwargs)
            except BaseException as error:
                self.end(event, succeeded=False, error=type(error).__name__)
                raise
            self.end(event, succeeded=True)
            trace = self

            class Buffer:
                def __enter__(self):
                    stream.__enter__()
                    return self

                def __exit__(self, *unused):
                    self.close()

                def fileno(self):
                    return stream.fileno()

                def _call(self, operation, function, *values):
                    item = trace.begin(operation, slot, origin, {})
                    try:
                        result = function(*values)
                    except BaseException as error:
                        trace.end(item, succeeded=False, error=type(error).__name__)
                        raise
                    trace.end(item, succeeded=True)
                    return result

                def read(self, size=-1):
                    return self._call("buffer.read", stream.read, size)

                def write(self, content):
                    item = trace.begin("buffer.write", slot, origin, {})
                    if trace.partial(item):
                        prefix = content[:max(1, len(content) // 2)]
                        assert 0 < len(prefix) < len(content)
                        assert stream.write(prefix) == len(prefix)
                        stream.flush()
                        assert Path(slot).read_bytes() == prefix
                        trace.record_profile(slot)
                        trace.partial_fact = {"slot": trace.normalize(slot), "requested": len(content),
                                              "prefixHex": prefix.hex()}
                        trace.cut(item, "partial")
                    try:
                        result = stream.write(content)
                    except BaseException as error:
                        trace.end(item, succeeded=False, error=type(error).__name__)
                        raise
                    trace.record_profile(slot)
                    trace.end(item, succeeded=True)
                    return result

                def flush(self):
                    return self._call("buffer.flush", stream.flush)

                def close(self):
                    return self._call("buffer.close", stream.close)
            return Buffer()
        return opening

    @contextmanager
    def installed(self):
        with ExitStack() as stack:
            # The normal Trace owns acquisition provenance throughout, even
            # before the component's selected algorithm interval begins.
            stack.enter_context(super().installed())
            for name in _EXTRA_IO:
                stack.enter_context(patch.object(os, name, new=self.wrapper(name, getattr(os, name))))
            stack.enter_context(patch.object(signing.SigningSession, "_call", new=_forbid_command))
            stack.enter_context(patch.object(signing.SigningSession, "_new_scope", new=_forbid_command))
            stack.enter_context(patch.object(credentials, "_run_private", new=_forbid_command))
            stack.enter_context(patch.object(credentials, "run_owned", new=_forbid_command))
            stack.enter_context(patch.object(signing, "run_owned", new=_forbid_command))
            yield


def _flow(root: Path, name: str, trace: ComponentTrace) -> dict:
    phases = []
    with trace.installed(), signing.local_signing_lease(home=root / "home") as lease:
        session = lease.session()
        session.open(create=True)
        if name.startswith("writer-"):
            slot = name.split("-")[1] + ".json"
            if name == "writer-state-replace":
                session._write(slot, _OLD)
            action = lambda: session._write(slot, _NEW, immutable=slot != "state.json")
        elif name.startswith("remover-"):
            _kind, stem, suffix = name.split("-")
            slot = stem + "." + suffix
            fixture.write_json(session.path / slot, _OLD)
            action = lambda: session._remove_control(slot)
        elif name.startswith("reader-"):
            path = session.path / "reader.fixture"
            path.write_bytes(_READ_BYTES)
            path.chmod(0o600 if name == "reader-private" else 0o640)

            def action():
                content, _details = signing._read_regular(session.fd, path.name, len(_READ_BYTES),
                    private=name == "reader-private", cancellation=lease.cancellation)
                assert content == _READ_BYTES
        else:
            assert name in {"installer-owned", "installer-borrowed"}

            def action():
                with credentials._temporary_profile_installation(
                    fixture.PROFILE, fixture.UUID, root / "home", cancellation=lease.cancellation,
                    observer=lambda phase, **_values: phases.append(phase),
                ):
                    destination = root / "home/Library/MobileDevice/Provisioning Profiles" / (fixture.UUID + ".mobileprovision")
                    assert destination.read_bytes() == fixture.PROFILE
        trace.initial = _identities(root)
        trace.active = True
        try:
            action()
        finally:
            trace.active = False
        if name.startswith("installer-"):
            expected = (["inspected", "reused", "resolved"] if name.endswith("borrowed") else
                        ["inspected", "stage-intent", "stage-created", "link-intent", "linked", "stage-removed", "resolved"])
            assert phases == expected, "installer algorithm phases changed"
        _no_native(root, trace)
    assert trace.selection is None, "component selected cut was not reached"
    events = [event for event in trace.events if event["index"] in trace.focus]
    operations = {event["operation"] for event in events}
    assert operations == _ALGORITHM_OPERATIONS[name], {"component": name, "actualOperations": sorted(operations)}
    # Optional missing control reads and already-created profile directories
    # have real, handled OS errors in a healthy algorithm; inventory them rather
    # than pretending they succeeded or cutting them out of the witness set.
    assert all(event.get("succeeded") is True and "error" not in event or
               event.get("succeeded") is False and
               ((event["operation"] in {"open", "stat"} and event.get("error") == "FileNotFoundError") or
                (event["operation"] == "mkdir" and event.get("error") == "FileExistsError")) for event in events)
    return {"events": events, "states": trace.states, "initial": trace.initial, "generations": trace.generations,
            "nativeCommands": 0, "phases": phases}


def _new_case(root: Path, name: str, *, borrowed=False) -> Path:
    path = root / name
    path.mkdir(mode=0o700)
    fixture.initialize(path, borrowed=borrowed)
    return path


def _assert_cut(root: Path, name: str, selected: dict, inventory: dict) -> dict:
    actual = json.loads((root / "cut-cut.json").read_bytes())
    assert actual["nativeCommands"] == 0 and actual["edge"] == selected["edge"]
    assert _event_key(actual["event"]) == _event_key(selected["event"])
    assert _identities(root) == actual["atCutIdentities"], "component inode changed after the original cut"
    physical = _physical(root, actual["initial"], actual["generations"])
    assert physical == actual["physical"], "component state changed after original worker exit"
    if selected["edge"] == "partial":
        fact = actual["partial"]
        assert type(fact) is dict and set(fact) == {"slot", "requested", "prefixHex"}
        prefix = bytes.fromhex(fact["prefixHex"])
        assert 0 < len(prefix) < fact["requested"]
        operand = (json.dumps(_NEW, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii") \
            if name.startswith("writer-") else fixture.PROFILE
        assert fact["requested"] == len(operand) and prefix == operand[:len(prefix)]
        relative = fact["slot"].removeprefix("<ROOT>/")
        assert fact["slot"] == selected["event"]["slot"] and relative != fact["slot"]
        row = physical[relative]
        assert row["size"] == len(prefix) and row["sha256"] == hashlib.sha256(prefix).hexdigest()
        expected = copy.deepcopy(inventory["states"][str(selected["event"]["index"])]["before"])
        expected[relative].update(size=len(prefix), sha256=hashlib.sha256(prefix).hexdigest())
        assert physical == expected, "partial write changed unrelated fixture state"
    else:
        assert physical == inventory["states"][str(selected["event"]["index"])][selected["edge"]], \
            "component actual persisted before/after state differs"
    _no_native(root)
    return {"event": fixture.event_fact(actual["event"]), "edge": selected["edge"],
            "physicalSha256": fixture.digest(physical), "nativeCommands": 0}


def _crash_component(root: Path, name: str) -> dict:
    borrowed = name == "installer-borrowed"
    healthy = _new_case(root, "inventory", borrowed=borrowed)
    fixture.run_worker(healthy, "inventory", lambda: _flow(healthy, name, ComponentTrace(healthy, "inventory")), timeout=20)
    inventory = json.loads((healthy / "inventory.json").read_bytes())
    fixture.remove_case(healthy)
    records = []
    for event in inventory["events"]:
        for edge in fixture.edges(event):
            path = _new_case(root, "cut", borrowed=borrowed)
            selected = {"event": event, "edge": edge}
            fixture.run_worker(path, "cut", lambda: _flow(path, name, ComponentTrace(path, "cut", selected)),
                               timeout=20, expect=fixture.CRASH)
            records.append(_assert_cut(path, name, selected, inventory))
            fixture.remove_case(path)
    expected = sum(len(fixture.edges(event)) for event in inventory["events"])
    assert len(records) == expected and expected > 0
    fixture.write_json(root / "component-evidence.json", records)
    return {"component": name, "algorithmEvents": len(inventory["events"]), "actualCuts": len(records),
            "resultsSha256": fixture.digest(records), "nativeCommands": 0,
            "allExactChildrenReapedAndGroupsAbsent": True, "allCasePathsRemoved": True}


def run_component(root: Path, name: str) -> dict:
    assert name in COMPONENT_NAMES, "unknown fixed filesystem component"
    if name.endswith("failures"):
        return _failure_component(root, name)
    return _crash_component(root, name)


class FailureTrace(ComponentTrace):
    """One real IO perturbation, never an owner/result/recovery replacement."""

    def __init__(self, root: Path, variant: str, target: Path, stage: Path, replacement: Path):
        super().__init__(root, "failure", observe_states=False)
        self.variant, self.target_path, self.stage, self.replacement = variant, target, stage, replacement
        self.faults, self.close_requests = [], []
        self.error = OSError(errno.EIO, "fictional one-effect filesystem failure")

    def perform(self, event, actual, args, kwargs):
        if not self.active:
            return actual(*args, **kwargs)
        operation, slot, variant = event["operation"], event["slot"], self.variant
        stage, target = self.normalize(self.stage), self.normalize(self.target_path)
        directory = self.normalize(self.target_path.parent)
        if operation == "close" and slot in {stage, target}:
            self.close_requests.append(slot)
        if self.faults:
            return actual(*args, **kwargs)
        selected = (
            operation == "write" and slot == stage and variant in {
                "short-write", "zero-write", "oversized-write", "partial-write-error"}
            or operation == "fsync" and slot == stage and variant in {"file-sync-before", "file-sync-after"}
            or operation == "fsync" and slot == directory and variant in {
                "directory-sync-before", "directory-sync-after", "remove-sync-before", "remove-sync-after"}
            or operation == "close" and slot == stage and variant in {"stage-replaced", "target-replaced", "close-after"}
            or operation == "read" and slot == target and variant in {"read-before", "read-after", "reader-name-changed"}
            or operation == "close" and slot == target and variant == "reader-close-after"
            or operation == "unlink" and slot == target and variant in {"unlink-before", "unlink-after"}
        )
        if not selected:
            return actual(*args, **kwargs)
        fact = {"variant": variant, "event": _event_key(event), "effectCompleted": False}
        self.faults.append(fact)  # Absorbing before attempting the one effect.
        if variant == "zero-write":
            return 0
        if variant == "oversized-write":
            return len(args[1]) + 1
        if variant in {"short-write", "partial-write-error"}:
            prefix = bytes(args[1][:max(1, len(args[1]) // 2)])
            count = actual(args[0], prefix)
            assert type(count) is int and 0 < count <= len(prefix) < len(args[1])
            fact.update(effectCompleted=True, written=count, prefixHex=prefix[:count].hex())
            if variant == "short-write":
                return count
            raise self.error
        if variant.endswith("-before"):
            raise self.error
        result = actual(*args, **kwargs)
        fact["effectCompleted"] = True
        if variant in {"stage-replaced", "target-replaced", "reader-name-changed"}:
            destination = self.stage if variant == "stage-replaced" else self.target_path
            replacement_identity = self.replacement.stat()
            self.generations[_identity_key(replacement_identity)] = {"fixtureReplacement": variant}
            self.replacement.replace(destination)  # Independent fixture edit, not production IO.
            fact["replacement"] = fixture.facts(destination)
            return result
        raise self.error


def _control_bytes(value):
    # Independent expected bytes: do not read the production writer's result
    # and promote it into its own success oracle.
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")


def _failure_task(root: Path, family: str, variant: str) -> dict:
    session = trace = observed = None
    outer = None
    target_name = (variant.removeprefix("pending-") + ".json" if variant.startswith("pending-") else
                   variant.removeprefix("immutable-") + ".json" if variant.startswith("immutable-") else
                   "reader.fixture" if family == "reader-failures" else "state.json")
    replacement = root / "replacement.data"
    replacement.write_bytes(_FOREIGN)
    replacement.chmod(0o600)
    report = None
    try:
        # Install tracing before lease/session acquisition so every original
        # descriptor has a real pathname. Never assign an invented descriptor.
        trace = FailureTrace(root, variant, Path("unset"), Path("unset"), replacement)
        with trace.installed(), signing.local_signing_lease(home=root / "home") as lease:
            session = lease.session()
            session.open(create=True)
            trace.target_path = target = session.path / target_name
            trace.stage = stage = session.path / (target_name.removesuffix(".json") + ".pending")
            if family == "reader-failures":
                target.write_bytes(_READ_BYTES)
                target.chmod(0o600)
            else:
                session._write(target_name, _OLD)
            if variant.startswith("pending-"):
                stage.write_bytes(_FOREIGN)
                stage.chmod(0o600)
            original_controls = copy.deepcopy(session._committed_controls)
            trace.initial = _identities(root)
            trace.active = True
            try:
                if family == "writer-failures":
                    session._write(target_name, _NEW, immutable=variant.startswith("immutable-"))
                elif family == "reader-failures":
                    signing._read_regular(session.fd, target_name, len(_READ_BYTES), private=True,
                                          cancellation=lease.cancellation)
                else:
                    assert family == "remover-failures"
                    session._remove_control(target_name)
            except BaseException as error:
                observed = error
            finally:
                trace.active = False
            if variant == "short-write":
                assert observed is None and not session.journal_failed
                assert target.read_bytes() == _control_bytes(_NEW) and not stage.exists()
                assert session._committed_controls == {target_name: _control_bytes(_NEW)}
                writes = [event for event in trace.events if event["index"] in trace.focus and event["operation"] == "write"]
                assert len(writes) >= 2 and all(event["succeeded"] is True for event in writes)
            else:
                assert observed is not None, "one-effect algorithm error was silently accepted"
                if variant in {"close-after", "reader-close-after"}:
                    assert isinstance(observed, ProcessError) and observed.fatal
                elif variant.endswith("-before") or variant.endswith("-after") or variant == "partial-write-error":
                    assert observed is trace.error, "algorithm replaced the original IO error"
                else:
                    assert isinstance(observed, (CredentialError, FileExistsError))
                assert session._committed_controls == original_controls, "failed operation published a committed control"
                if family != "reader-failures":
                    assert session.journal_failed, "failed control operation did not latch"
                    before_retry = _physical(root, trace.initial, trace.generations)
                    retry = None
                    try:
                        session._write(target_name, _NEW)
                    except CredentialError as error:
                        retry = error
                    assert retry is not None and session.journal_failed, "same-session failed write was retried"
                    assert _physical(root, trace.initial, trace.generations) == before_retry, "rejected retry changed the filesystem"
                if family == "writer-failures":
                    target_content = _FOREIGN if variant == "target-replaced" else \
                        _control_bytes(_NEW if variant.startswith("directory-sync-") else _OLD)
                    assert target.read_bytes() == target_content
                    if variant.startswith(("immutable-", "directory-sync-")):
                        assert not stage.exists()
                    else:
                        expected_stage = (_FOREIGN if variant.startswith("pending-") or variant == "stage-replaced" else
                                          b"" if variant in {"zero-write", "oversized-write"} else
                                          bytes.fromhex(trace.faults[0]["prefixHex"]) if variant == "partial-write-error" else
                                          _control_bytes(_NEW))
                        assert stage.read_bytes() == expected_stage, "incorrect persisted failure prefix/generation"
                elif family == "reader-failures":
                    assert not session.journal_failed
                    assert target.read_bytes() == (_FOREIGN if variant == "reader-name-changed" else _READ_BYTES)
                else:
                    assert target.read_bytes() == _control_bytes(_OLD) if variant == "unlink-before" else not target.exists()
            if variant.startswith(("pending-", "immutable-")):
                assert not trace.faults
                if variant.startswith("pending-"):
                    assert any(event.get("error") == "FileExistsError" and event["slot"] == trace.normalize(stage)
                               for event in trace.events if event["index"] in trace.focus)
                else:
                    assert not any(event["operation"] in {"write", "replace"} or
                                   event["operation"] == "open" and event["slot"] == trace.normalize(stage)
                                   for event in trace.events if event["index"] in trace.focus)
            else:
                assert len(trace.faults) == 1, "original one-effect seam was not reached exactly once"
            if variant in {"close-after", "reader-close-after"}:
                closed_slot = trace.normalize(stage if variant == "close-after" else target)
                assert trace.close_requests.count(closed_slot) == 1, "ambiguous close was retried"
            if variant in {"stage-replaced", "target-replaced", "reader-name-changed"}:
                replacement_target = stage if variant == "stage-replaced" else target
                assert fixture.facts(replacement_target) == trace.faults[0]["replacement"], \
                    "independent replacement identity/bytes were not preserved"
            _no_native(root, trace)
            report = {"variant": variant, "originalError": type(observed).__name__ if observed is not None else None,
                      "journalFailed": session.journal_failed, "faults": trace.faults,
                      "initial": trace.initial, "generations": trace.generations,
                      "retainedIdentities": _identities(root),
                      "physical": _physical(root, trace.initial, trace.generations), "nativeCommands": 0}
            # Keep fatal cleanup facts on their real guard through its actual
            # exit. Do not clear its ledger merely to return a success object.
            if variant in {"close-after", "reader-close-after"}:
                raise observed
    except BaseException as error:
        outer = error
    if variant in {"close-after", "reader-close-after"}:
        assert isinstance(outer, ProcessError) and outer.fatal, "lease exit lost the actual fatal close"
    elif outer is not None:
        raise outer
    assert report is not None and session.closed, "algorithm fixture did not complete its owned unwind"
    assert _identities(root) == report["retainedIdentities"], "lease exit changed retained algorithm identities"
    assert _physical(root, report["initial"], report["generations"]) == report["physical"], \
        "lease exit changed retained algorithm state"
    _no_native(root, trace)
    return report


def _failure_component(root: Path, name: str) -> dict:
    variants = {"writer-failures": _WRITER_FAILURES, "reader-failures": _READER_FAILURES,
                "remover-failures": _REMOVER_FAILURES}[name]
    records = []
    for variant in variants:
        path = _new_case(root, "failure")
        fixture.run_worker(path, "failure", lambda: _failure_task(path, name, variant), timeout=20)
        observed = json.loads((path / "failure.json").read_bytes())
        assert observed["variant"] == variant and observed["nativeCommands"] == 0
        assert _identities(path) == observed["retainedIdentities"], "failure identity changed after original wait"
        assert _physical(path, observed["initial"], observed["generations"]) == observed["physical"], \
            "failure state changed after original wait"
        _no_native(path)
        records.append(observed)
        fixture.remove_case(path)
    assert [record["variant"] for record in records] == list(variants)
    fixture.write_json(root / "component-evidence.json", records)
    return {"component": name, "actualFailureCases": len(records), "resultsSha256": fixture.digest(records),
            "nativeCommands": 0, "allExactChildrenReapedAndGroupsAbsent": True, "allCasePathsRemoved": True}


if __name__ == "__main__":
    raise SystemExit("Use the reviewed fixed matrix owner, not raw fixture execution.")
