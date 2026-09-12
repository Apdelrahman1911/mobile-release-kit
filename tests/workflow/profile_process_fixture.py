"""Real private process groups around production profile capture/supervision.

Only the native executable boundary is synthetic. Tests wait for actual readiness,
then prove cleanup before their independent fallback. No real profile/keychain.
"""
from __future__ import annotations

import json
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
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

from workflow.process_fixture import assert_live, observer_environment, process_state, record

CANARIES = ("GH_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8", "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD",
            "PYTHONPATH", "PYTHONHOME", "OPENSSL_CONF", "DYLD_INSERT_LIBRARIES")
PARENT_DEATH_MODES = {"marker-parent-death", "committed-parent-death"}
COMPLETION_CANCEL_MODES = {"completion-cancel", "completion-interrupt"}
BAD_FRAME_MODES = {"full-zero", "full-failure"}
PAYLOAD_MUTATION_MODES = {"overflow", "partial-marker", "extra-frame", "concatenated-frame"}
UNKNOWN_PROFILE_MODES = {*BAD_FRAME_MODES, *PARENT_DEATH_MODES, "orphan",
                         "payload-writer-close-failure", "payload-reader-close-failure", "payload-reader-close-unresolved"}

_DRIVER_FAILURE_MODES = frozenset({"failure", "read-failure", "partial-write-failure", "overflow",
                                   "partial-marker", "extra-frame", "concatenated-frame"})
_DRIVER_FAILURE_FILES = (
    "tests/workflow/profile_process_fixture.py", "tests/workflow/process_fixture.py",
    "src/mobile_release/_profile_process.py", "src/mobile_release/_native_process.py",
    "src/mobile_release/ios_profiles.py", "src/mobile_release/inspection.py", "src/mobile_release/errors.py",
)
_DRIVER_EXCEPTION_CATEGORIES = {
    name.encode("ascii"): category
    for category, names in (
        ("assertion-error", ("AssertionError",)),
        ("os-error", ("OSError", "BlockingIOError", "ChildProcessError", "ConnectionError", "BrokenPipeError",
                      "ConnectionAbortedError", "ConnectionRefusedError", "ConnectionResetError", "FileExistsError",
                      "FileNotFoundError", "InterruptedError", "IsADirectoryError", "NotADirectoryError",
                      "PermissionError", "ProcessLookupError", "TimeoutError")),
        ("value-error", ("ValueError", "UnicodeError", "UnicodeDecodeError", "UnicodeEncodeError", "UnicodeTranslateError")),
        ("type-error", ("TypeError",)),
        ("memory-error", ("MemoryError",)),
        ("exception", ("Exception", "RuntimeError", "RecursionError", "NotImplementedError", "SystemError",
                       "EOFError", "AttributeError", "ImportError", "ModuleNotFoundError", "LookupError",
                       "IndexError", "KeyError", "NameError", "UnboundLocalError", "StopIteration", "StopAsyncIteration",
                       "ArithmeticError", "FloatingPointError", "OverflowError", "ZeroDivisionError", "BufferError",
                       "ReferenceError", "SyntaxError", "IndentationError", "TabError", "ExceptionGroup")),
        ("base-exception", ("BaseException", "SystemExit", "KeyboardInterrupt", "GeneratorExit", "BaseExceptionGroup")),
    )
    for name in names
}


_RETAINED_WORKSPACES = []
_UNKNOWN_DRIVERS = []
_BINDING_CUSTODY = []
_DRIVER_CUSTODY = []
_FIXTURE_ADVERSE = []


def retain_fixture_custody(owner):
    """Sticky actual-object custody until disposal of the original Session."""
    if not any(item is owner for item in _FIXTURE_ADVERSE):
        _FIXTURE_ADVERSE.append(owner)


def assert_fixture_idle():
    """Guard before acquisition; a current active workspace is not a reset.

    Inspect only already-imported product modules. Pure observer contracts must
    not import/initialize a native owner merely to check this fixture latch.
    """
    for item in (*_UNKNOWN_DRIVERS, *_DRIVER_CUSTODY, *_BINDING_CUSTODY):
        retain_fixture_custody(item)
    for workspace in _RETAINED_WORKSPACES:
        if workspace.retained or workspace._closed:
            retain_fixture_custody(workspace)
    for module_name, names in (("mobile_release.ios_profiles", ("_PROFILE_SCRATCH_LEASES", "_PROFILE_RESOURCE_SCOPES")),
                               ("mobile_release._profile_process", ("_CUSTODY",))):
        module = sys.modules.get(module_name)
        if module is not None:
            for name in names:
                # Every remaining record matters, including an unfinished
                # acquisition which has not yet published UNKNOWN.
                for item in getattr(module, name, ()):
                    retain_fixture_custody(item)
    assert not _FIXTURE_ADVERSE, "retained fixture domain requires original Session disposal before another case"


def _report_driver_failure(mode, returncode, stderr):
    """Optional bounded observations, only after the rejected driver's cleanup.

    This examines already-captured bytes, not private files or live processes.
    Unknown text stays unknown; neither these observations nor a successful
    write establish nested product finality or the initiating failure's cause.
    """
    try:
        if (type(mode) is not str or mode not in _DRIVER_FAILURE_MODES
                or type(returncode) is not int or not -255 <= returncode <= 255 or returncode == 0
                or type(stderr) is not bytes):
            return
        tail = stderr[-65536:]
        if len(stderr) > 65536:
            # The first retained line may be partial: never interpret it.
            tail = tail.partition(b"\n")[2]
        lines = tail.splitlines()
        header = next((index for index in range(len(lines) - 1, -1, -1)
                       if lines[index] == b"Traceback (most recent call last):"), None)
        category, locations = "unknown", []
        suffixes = [(name.encode("ascii"), name) for name in _DRIVER_FAILURE_FILES]
        suffixes += [(name[4:].encode("ascii"), name) for name in _DRIVER_FAILURE_FILES if name.startswith("src/")]
        if header is not None:
            for line in lines[header + 1:]:
                frame = re.fullmatch(rb'  File "([^"\r\n]+)", line ([1-9][0-9]{0,5})(?:, in [^\r\n]+)?', line)
                if frame is not None:
                    path, number = frame.groups()
                    for suffix, name in suffixes:
                        if path == suffix or path.endswith(b"/" + suffix):
                            locations.append({"file": name, "line": int(number)})
                            locations = locations[-4:]
                            break
                elif line and not line.startswith((b" ", b"\t")):
                    token = re.fullmatch(rb"([A-Za-z_][A-Za-z0-9_.]{0,127})(?::[^\r\n]*)?", line)
                    if token is not None:
                        category = _DRIVER_EXCEPTION_CATEGORIES.get(token[1], "unknown")
                    # Only this last traceback's terminal token counts. Later
                    # multiline messages must not replace an unknown category.
                    break
        record = {"schema": 1, "mode": mode, "returncode": returncode,
                  "category": category, "locations": locations}
        # Verbosity-two unittest leaves its progress line open during the body.
        # Delimit the marker in the SAME write; the bound includes both newlines.
        line = "\nMRK_PROFILE_FIXTURE_FAILURE=" + json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n"
        if len(line) <= 2048:  # The rebuilt line is ASCII, so chars == bytes.
            # Ordinary existing captured stderr, not a new nonblocking transport.
            # Driver close accounting already ran; the original Session owns its
            # unchanged cutoff. No explicit flush, retry or descriptor mutation.
            sys.stderr.write(line)
    except BaseException:
        # This optional failure-only side effect cannot replace the assertion
        # which the caller is already re-raising. Never wrap acquisition/cleanup.
        pass


class FixtureWorkspace:
    """An explicit test root, never an automatic UNKNOWN-scratch finalizer."""

    def __init__(self, prefix="mrk-profile-process-"):
        assert_fixture_idle()
        if _RETAINED_WORKSPACES:
            for workspace in _RETAINED_WORKSPACES:
                workspace.retain()
            raise AssertionError("another fixture workspace still owns resources")
        self.path = self._identity = None
        self.removal_allowed = False
        self._closed = False
        self.retained = False
        # Root before mkdtemp: a lost return is not permission to try another
        # root, nor evidence that this acquisition created nothing.
        _RETAINED_WORKSPACES.append(self)
        try:
            self.path = Path(tempfile.mkdtemp(prefix=prefix))
            details = self.path.lstat()
            assert stat.S_ISDIR(details.st_mode) and stat.S_IMODE(details.st_mode) == 0o700
            self._identity = details.st_dev, details.st_ino, details.st_uid
        except BaseException:
            self.retain()
            raise

    def retain(self):
        self.retained = True
        self.removal_allowed = False
        retain_fixture_custody(self)

    def allow_removal(self):
        # Only positively checked fixture accounting may permit this; actual
        # owner receipts/EOFs/joins, not an output payload, establish finality.
        assert_fixture_idle()
        assert not self.retained and not self._closed
        self.removal_allowed = True

    def __enter__(self):
        assert_fixture_idle()
        assert not self._closed and not self.retained
        return self

    def __exit__(self, kind, value, traceback):
        if self._closed:
            return False
        if not self.removal_allowed or kind is not None:
            self._closed = True
            self.retain()
            return False
        try:
            assert_fixture_idle()
            self._closed = True  # Retire before any removal attempt.
            self.removal_allowed = False
            details = self.path.lstat()
            assert stat.S_ISDIR(details.st_mode) and not self.path.is_symlink()
            assert (details.st_dev, details.st_ino, details.st_uid) == self._identity
            shutil.rmtree(self.path)
            _RETAINED_WORKSPACES.remove(self)
        except BaseException:
            self._closed = True
            self.retain()
            raise
        return False


class FixtureDriver:
    """Exclusive top-level fixture wait/signal custody, not a production waiter.

    No poll/communicate/Popen.wait is used: even its ECHILD fallback would not
    be a genuine receipt. All group requests retire before the first exact
    waitpid. Child IDs read from fixture files are observations, never targets.
    Unresolved production children are left to the reviewed disposable owner;
    this controller never guesses their IDs or deletes their retained scratch.
    """

    def __init__(self, argv, *, env=None):
        assert_fixture_idle()
        self.process = None
        self.requests_retired = False
        self.wait_unknown = False
        self.receipt = None
        self._signals = set()
        self._finish_cutoff = None
        self.selector = None
        self.stream_states = {name: "UNACQUIRED" for name in ("stdout", "stderr")}
        self.stream_eof = {name: False for name in ("stdout", "stderr")}
        _DRIVER_CUSTODY.append(self)
        try:
            from mobile_release._native_process import assert_child_waitability

            assert_child_waitability()
            self.process = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL,
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                            start_new_session=True, close_fds=True)
            self.stream_states = {name: "OPEN" for name in ("stdout", "stderr")}
        except BaseException:
            # __exit__ will not run after partial construction. Root the
            # original process/streams even when publication is incomplete.
            self._retain_unknown()
            raise

    def _retain_unknown(self):
        self.requests_retired = self.wait_unknown = True
        if not any(item is self for item in _UNKNOWN_DRIVERS):
            _UNKNOWN_DRIVERS.append(self)
        retain_fixture_custody(self)

    def request_signal(self, signum):
        assert self.process is not None and self.receipt is None
        assert not self.requests_retired and not self.wait_unknown
        assert signum in {signal.SIGINT, signal.SIGTERM, signal.SIGKILL}
        assert signum not in self._signals, "fixture numeric signal retry"
        self._signals.add(signum)
        # Popen returned after establishing this private group; nobody has
        # consumed its leader. Do not call Popen.send_signal's implicit poll.
        try:
            os.killpg(self.process.pid, signum)
        except ProcessLookupError:
            # ESRCH retires further numeric requests, but is not our wait.
            self.requests_retired = True

    def _wait(self, timeout=3, *, cutoff=None):
        if self.receipt is not None:
            return self.receipt
        assert not self.wait_unknown
        self.requests_retired = True
        if cutoff is None:
            cutoff = self._finish_cutoff if self._finish_cutoff is not None else time.monotonic() + timeout
        elif self._finish_cutoff is not None:
            cutoff = min(cutoff, self._finish_cutoff)
        try:
            while True:
                assert time.monotonic() < cutoff, "fixture exact wait exceeded its original cutoff"
                result = os.waitpid(self.process.pid, os.WNOHANG)
                assert (type(result) is tuple and len(result) == 2
                        and type(result[0]) is int and type(result[1]) is int), "fixture wait publication is unknown"
                pid, status = result
                if pid == self.process.pid:
                    assert os.WIFEXITED(status) or os.WIFSIGNALED(status), "fixture wait was not a terminal receipt"
                    self.receipt = result
                    self.process.returncode = os.waitstatus_to_exitcode(status)
                    assert time.monotonic() < cutoff, "fixture terminal wait returned after its original cutoff"
                    return self.receipt
                assert pid == 0 and status == 0, "fixture exact wait publication is unknown"
                remaining = cutoff - time.monotonic()
                assert remaining > 0, "fixture exact wait did not settle"
                # Only this genuine pid0 return permits another consuming
                # poll of the SAME child under the SAME absolute cutoff.
                time.sleep(min(.01, remaining))
        except BaseException:
            self._retain_unknown()
            raise

    def finish(self, timeout=15, *, on_tick=None):
        assert self._finish_cutoff is None, "fixture finish cannot renew its deadline"
        self._finish_cutoff = cutoff = time.monotonic() + timeout
        output = {"stdout": bytearray(), "stderr": bytearray()}
        try:
            self.selector = selectors.DefaultSelector()
            with self.selector as selector:
                for name in output:
                    stream = getattr(self.process, name)
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, name)
                while selector.get_map():
                    remaining = cutoff - time.monotonic()
                    assert remaining > 0, "independent profile fixture deadline expired"
                    if on_tick is not None:
                        on_tick(self)
                    for key, _ in selector.select(min(.05, remaining)):
                        try:
                            chunk = os.read(key.fd, 65536)
                        except BlockingIOError:
                            continue
                        if chunk:
                            output[key.data].extend(chunk)
                            assert len(output[key.data]) <= 1024 * 1024, "fixture output exceeded its bound"
                        else:
                            assert chunk == b"", "fixture stream EOF was not actually read"
                            self.stream_eof[key.data] = True
                            selector.unregister(key.fileobj)
                assert all(self.stream_eof.values()), "fixture driver lacks both original stream EOFs"
                # EOF is NOT a child receipt. Retire the numeric signal route
                # before the first consuming wait, then use only this original
                # waitpid. No new observer may follow nested product UNKNOWN.
                self.requests_retired = True
                self._wait(cutoff=cutoff)
            return bytes(output["stdout"]), bytes(output["stderr"])
        except BaseException:
            self._retain_unknown()
            raise

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        errors = []
        if self.receipt is None and not self.requests_retired and not self.wait_unknown:
            try:
                if self._finish_cutoff is None:
                    self._finish_cutoff = time.monotonic() + 3
                assert time.monotonic() < self._finish_cutoff
                if signal.SIGKILL not in self._signals:
                    self.request_signal(signal.SIGKILL)
                self._wait(cutoff=self._finish_cutoff)
            except BaseException as error:
                errors.append(error)
                self._retain_unknown()
        for name in ("stdout", "stderr"):
            if self.stream_states[name] == "OPEN":
                self.stream_states[name] = "CLOSE_IN_FLIGHT"
                try:
                    getattr(self.process, name).close()
                except BaseException as error:
                    self.stream_states[name] = "UNKNOWN"
                    errors.append(error)
                else:
                    self.stream_states[name] = "CLOSED"
        unresolved = (self.wait_unknown or self.receipt is None
                      or not all(self.stream_eof.get(name) is True for name in ("stdout", "stderr"))
                      or any(state != "CLOSED" for state in self.stream_states.values()))
        if unresolved and not any(item is self for item in _UNKNOWN_DRIVERS):
            # A real process receipt plus closes does NOT establish missing
            # stream EOFs or settle an ambiguous close. Keep actual objects
            # rooted so neither GC nor another case can repair the uncertainty.
            _UNKNOWN_DRIVERS.append(self)
        if unresolved or errors:
            retain_fixture_custody(self)
        elif any(item is self for item in _DRIVER_CUSTODY):
            _DRIVER_CUSTODY.remove(self)
        if (errors or unresolved) and kind is None:
            raise AssertionError("fixture controller cleanup is unresolved") from None
        return False



def command(role, root, directory, mode, *arguments):
    import mobile_release
    return (sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()),
            str(Path(mobile_release.__file__).resolve().parent.parent),
            role, str(root), str(directory), mode, *(str(value) for value in arguments))


def ready(root):
    return (root / "child.pid").is_file() and (root / "child-ready").is_file()


def events(root):
    result = []
    for role in ("outer", "custodian", "keeper"):
        path = root / (role + ".events")
        if path.exists():
            raw = path.read_bytes()
            assert len(raw) <= 1024 * 1024, "fixture event inventory exceeded its bound"
            for line in raw.splitlines():
                # One O_APPEND write per bounded event. A concurrent last
                # partial record is not evidence and is never used as authority.
                try:
                    item = json.loads(line)
                except (ValueError, UnicodeError):
                    continue
                assert type(item) is dict and item["role"] == role
                result.append(item)
    return result


def selected(items, role, event):
    return [item for item in items if item["role"] == role and item["event"] == event]


def _receipt(receipt):
    return {"state": "reaped", "pid": receipt.pid, "status_kind": receipt.status_kind,
            "status_code": receipt.status_code}


class ProfileBindings:
    """Actual owner instrumentation; events observe, never confer authority.

    C/K run the real fixed helper_main and reconstruct the same sole synthetic
    V command. The malformed-helper controls are explicitly separate negative
    peers; they are never counted as production-helper success evidence.
    """

    def __init__(self, root, mode, role="outer", *, on_event=None):
        import threading
        from mobile_release import _profile_process as owner
        from mobile_release import _native_process as native
        self.root, self.mode, self.role = root, mode, role
        self.owner, self.native, self.on_event = owner, native, on_event
        self.stack = ExitStack()
        self.patch_state = "NEW"
        self._patch_slots = []
        self._patch_errors = []
        self.lock = threading.Lock()
        self.children, self.tasks, self.leases = {}, {}, {}
        self.close_attempts = {}
        self.wait_witnesses = {}
        self.join_witnesses = {}
        self.channels = {}
        self.channel_objects = {}
        self.map_evidence = None
        self.payload_reader = self.payload_writer = None
        self.payload_fd = None
        self.payload_eof = False
        self.payload_bytes_read = 0
        self.payload_parser_rejected = False
        self.payload_overflow_veto = False
        self.raw_eofs = set()
        self.group = None
        self.absent = set()
        self.run_deadline_ns = None
        self.deadline = None
        self.orphan_observed = self.zombie_observed = False
        self.commit_withheld = False
        self._observing = False
        self._injected = set()
        self._sequence = 0
        self._real_read, self._real_write, self._real_killpg = os.read, os.write, os.killpg
        self._real_fstat = os.fstat

    def _install_patch(self, patcher):
        slot = {"patcher": patcher, "state": "ENTERING"}
        self._patch_slots.append(slot)
        # Publish restoration BEFORE entering a patch which may change a target
        # and then lose its return. Callback dispatch is independently one-shot.
        self.stack.callback(self._restore_patch, slot)
        patcher.__enter__()
        slot["state"] = "INSTALLED"

    def _restore_patch(self, slot):
        if slot["state"] not in {"ENTERING", "INSTALLED"}:
            return
        slot["state"] = "RESTORING"
        try:
            slot["patcher"].__exit__(None, None, None)
        except BaseException as error:
            slot["state"] = "UNKNOWN"
            self._patch_errors.append(error)
        else:
            slot["state"] = "RESTORED"

    def _restore_patches(self):
        if self.patch_state in {"CLOSED", "UNKNOWN"}:
            return
        self.patch_state = "RESTORING"
        try:
            self.stack.close()
        except BaseException as error:
            self._patch_errors.append(error)
        self.patch_state = ("UNKNOWN" if self._patch_errors
                            or any(slot["state"] != "RESTORED" for slot in self._patch_slots) else "CLOSED")
        if self.patch_state == "CLOSED":
            _BINDING_CUSTODY[:] = [item for item in _BINDING_CUSTODY if item is not self]

    def descriptor_evidence(self, descriptor):
        import fcntl
        details = self._real_fstat(descriptor)
        return {"device": details.st_dev, "inode": details.st_ino,
                "type": stat.S_IFMT(details.st_mode), "rdev": details.st_rdev,
                "access": fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE}

    def child_for(self, role):
        # Cancellation may lose _spawn's handoff event, never the preregistered
        # actual acquisition. Only a real child object can bind a later wait.
        children = [task.acquisition.child for task in self.tasks.values()
                    if task.child_role == role and task.acquisition.child is not None]
        if role in self.children:
            children.append(self.children[role])
        assert children and all(child is children[0] for child in children)
        return children[0]

    def release_fixture_references(self):
        # Called only after the independent receipt/EOF/join assertions. Do not
        # let observer-held objects impersonate the product's strong GC roots.
        self.children.clear(); self.tasks.clear(); self.leases.clear()
        self.channels.clear(); self.channel_objects.clear()
        self.wait_witnesses.clear(); self.join_witnesses.clear()
        self.payload_reader = self.payload_writer = self.group = None

    def log(self, event, **fields):
        with self.lock:
            self._sequence += 1
            assert self._sequence <= 2048, "unbounded fixture event stream"
            row = {"role": self.role, "event": event, "pid": os.getpid(),
                   "sequence": self._sequence, "time_ns": time.monotonic_ns(), **fields}
            data = json.dumps(row, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            assert len(data) <= 8192
            descriptor = os.open(self.root / (self.role + ".events"), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                assert self._real_write(descriptor, data) == len(data)
            finally:
                os.close(descriptor)

    def remember(self, lease):
        if id(lease) not in self.leases:
            descriptor = lease.fileno()
            details = self._real_fstat(descriptor)
            self.leases[id(lease)] = (lease, descriptor, (details.st_dev, details.st_ino))
        return self.leases[id(lease)][1]

    def assert_local_leases(self, context, *, unresolved=None):
        inventory = (*context.io.leases, *(lease for task in context.tasks for lease in task.acquisition.leases))
        for lease in inventory:
            if lease.state == "NEW":
                continue  # A resource-free slot is not a claimed successful close.
            assert id(lease) in self.leases, "an acquired lease escaped the actual close inventory"
            assert self.close_attempts.get(id(lease)) == 1
            assert lease.state == ("OPEN" if lease is unresolved else "CLOSED")
            _lease, descriptor, identity = self.leases[id(lease)]
            try:
                details = self._real_fstat(descriptor)
            except OSError:
                assert lease.state == "CLOSED"
            else:
                same = (details.st_dev, details.st_ino) == identity
                assert same if lease is unresolved else not same
        self.log("local_leases_accounted", count=len(inventory), unresolved=unresolved is not None)

    def tick(self):
        if self.role != "outer" or self._observing:
            return
        self._observing = True
        try:
            if self.mode == "before-run-cancel" and (self.root / "keeper-published").exists() and "cancel" not in self._injected:
                self._injected.add("cancel")
                record(self.root / "keeper-release", "cancel before RUN")
                os.kill(os.getpid(), signal.SIGTERM)
            if self.mode == "zombie" and (self.root / "validator-published").exists() and not self.zombie_observed:
                publication = json.loads((self.root / "validator-published").read_text())
                limit = time.monotonic() + 1
                state = process_state(publication["pid"], group=publication["group"], deadline=limit)
                assert state != "absent", "absence was substituted for an unreaped validator zombie"
                if state == "zombie":
                    self.zombie_observed = True
                    self.log("actual_validator_zombie", validator_pid=publication["pid"])
                    record(self.root / "zombie-observed", "actual unreaped zombie")
            if (self.mode == "pipe-timeout" and not self.orphan_observed and ready(self.root)
                    and (self.root / "group-held").exists() and (self.root / "validator-reaped").exists()
                    and self.payload_reader is not None and self.payload_reader.state == "OPEN"):
                worker = json.loads((self.root / "worker.json").read_text())
                descendant = int((self.root / "child.pid").read_text())
                assert_live(descendant, group=worker["group"], deadline=time.monotonic() + 1)
                import select
                readable, _, _ = select.select((self.payload_reader.fileno(),), (), (), 0)
                if not readable:
                    # C, never V, owns this still-open payload writer. No read,
                    # wait or signal is stolen from any production owner.
                    self.orphan_observed = True
                    self.log("exited_validator_live_descendant_without_payload_eof", descendant=descendant)
        finally:
            self._observing = False

    def observe(self, role, event, **evidence):
        assert role == self.role
        fields = {}
        if event == "map_validated":
            mapping = evidence["fd_roles"]
            assert set(mapping) == set(range(8))
            assert all(mapping[index] == index for index in range(3))
            null = os.stat(os.devnull)
            fields["fd_roles"] = {}
            for number in range(8):
                actual = self.descriptor_evidence(number)
                fields["fd_roles"][str(number)] = actual
                access = os.O_RDONLY if number in (0, 3, 5) else os.O_WRONLY
                assert actual["access"] == access
                is_pipe = number in (3, 4) or (role == "custodian" and number == 6)
                assert actual["type"] == (stat.S_IFIFO if is_pipe else stat.S_IFCHR)
                if not is_pipe:
                    assert actual["rdev"] == null.st_rdev
            for number in range(3, 8):
                lease = mapping[number]
                assert self.remember(lease) == number
            self.map_evidence = fields["fd_roles"]
            if role == "custodian":
                self.payload_writer = mapping[6]
        elif event == "payload_reader_registered":
            self.payload_reader = evidence["lease"]
            self.payload_fd = self.remember(self.payload_reader)
            fields["descriptor"] = self.payload_fd
            fields["identity"] = self.descriptor_evidence(self.payload_fd)
        elif event.startswith("task_"):
            task = evidence["task"]
            self.tasks[id(task)] = task
            fields.update(task=id(task), child_role=task.child_role)
            if event == "task_granted" and role in {"custodian", "keeper"}:
                assert self.map_evidence is not None, "child grant preceded production helper map validation"
                if role == "custodian":
                    assert len(task.spec.fd_sources) == 8
                    assert all(lease is not self.payload_writer for lease in task.spec.fd_sources)
                else:
                    assert len(task.spec.fd_sources) == 3
                    assert all(self.descriptor_evidence(lease.fileno())["type"] == stat.S_IFCHR
                               for lease in task.spec.fd_sources)
            if event == "task_joined":
                assert task.joined and task.body_done and task.actual is not None
                assert not task.actual.is_alive(), "a live creator was called joined"
                assert self.join_witnesses.get(id(task.actual)) == id(task), "join flags lacked the original Thread.join return"
                if role == "outer" and task.child_role == "custodian" and task.acquisition.child is not None:
                    acquisition = task.acquisition
                    child = acquisition.child
                    assert acquisition.attempted and acquisition.settled and not acquisition.cleanup_unknown
                    assert task.launch_retired and acquisition.launch_retired
                    assert child.receipt is None and not child.numeric_retired
                    assert len(task.spec.fd_sources) == 8
                    source = task.spec.fd_sources[6]
                    assert source is not self.payload_reader and source.state == "OPEN"
                    # Snapshot the SAME original writer which native creation
                    # mapped to C6, after the genuine creator join and before
                    # O closes sources. child_published may be lost on cancel.
                    descriptor = self.remember(source)
                    identity = self.descriptor_evidence(descriptor)
                    assert identity["type"] == stat.S_IFIFO and identity["access"] == os.O_WRONLY
                    fields.update(child_pid=child.pid, payload_source_lease=id(source),
                                  payload_source_descriptor=descriptor, payload_source_identity=identity)
        elif event == "child_published":
            child, acquisition = evidence["child"], evidence["acquisition"]
            child_role = evidence["child_role"]
            assert acquisition.child is child and acquisition.settled
            assert child.receipt is None and not child.numeric_retired
            self.children[child_role] = child
            fields.update(child_role=child_role, child_pid=child.pid)
            if child_role == "keeper":
                record(self.root / "keeper-published", str(child.pid))
            elif child_role == "validator":
                record(self.root / "validator-published", json.dumps({"pid": child.pid, "group": os.getpgrp()}))
        elif event in {"validator_reaped", "keeper_reaped", "custodian_reaped"}:
            child_role = event.removesuffix("_reaped")
            child, receipt = self.child_for(child_role), evidence["receipt"]
            assert child.receipt is receipt and child.wait_state == "REAPED" and child.numeric_retired
            assert self.wait_witnesses.get(id(child)) is receipt, "receipt flags lacked the original Child.poll_wait return"
            fields["receipt"] = _receipt(receipt)
            if event == "keeper_reaped":
                assert self.group is not None and self.group.retired
                assert self.group.absent and self.group.id in self.absent
            if event == "validator_reaped":
                record(self.root / "validator-reaped", json.dumps(fields["receipt"]))
            if event == "custodian_reaped" and self.mode == "committed-timeout":
                assert self.deadline is not None
                self.deadline._expires_at = time.monotonic() - 1
        elif event in {"reserved", "group_request", "group_retired"} and role == "custodian":
            group = evidence["group"]
            assert group.keeper is self.child_for("keeper") and group.id == group.keeper.pid
            self.group = group
            fields["group"] = group.id
            if event == "group_request":
                assert not group.retired and not group.keeper.numeric_retired
                fields["signum"] = int(evidence["signum"])
            elif event == "group_retired":
                assert group.retired and group.absent is evidence["absent"]
                if group.absent:
                    assert group.id in self.absent, "group absence lacked an actual ESRCH observation"
                fields["absent"] = group.absent
        elif event in {"group_request", "group_retired"} and role == "keeper":
            keeper = evidence["group"]
            assert keeper.group_id == os.getpid() and keeper.group_id != keeper.context.parent_pid
            self.group = keeper
            fields["group"] = keeper.group_id
            if event == "group_request":
                assert not keeper.group_retired
                fields["signum"] = int(evidence["signum"])
            else:
                assert keeper.group_retired and keeper.group_absent is evidence["absent"]
                fields["absent"] = keeper.group_absent
        elif event in {"descriptor_closed", "payload_closed"}:
            lease = evidence["lease"]
            assert lease.state == "CLOSED", "an attempted close was reported as completed"
            fields["lease"] = id(lease)
            if id(lease) in self.leases:
                fields["descriptor"] = self.leases[id(lease)][1]
        elif event == "payload_eof":
            assert evidence["lease"] is self.payload_reader and id(self.payload_reader) in self.raw_eofs
            self.payload_eof = True
            fields["descriptor"] = self.payload_fd
        elif event in {"status_eof", "control_eof"}:
            edge = evidence["edge"]
            assert edge in self.channels and id(self.channels[edge]) in self.raw_eofs
            fields["edge"] = edge
        elif event in {"payload_write", "payload_before_marker", "payload_marker_written"}:
            assert role == "custodian" and self.payload_writer is not None
            assert evidence["descriptor"] == self.remember(self.payload_writer) == 6
            fields["descriptor"] = 6
            if "count" in evidence:
                assert type(evidence["count"]) is int and evidence["count"] > 0
                fields["count"] = evidence["count"]
        if "frame" in evidence:
            fields["frame"] = evidence["frame"]
        if "edge" in evidence:
            fields["edge"] = evidence["edge"]
        self.log(event, **fields)
        if self.on_event is not None:
            self.on_event(role, event, evidence)
        if role == "outer":
            if event == "child_published" and self.mode == "before-admit-cancel":
                os.kill(os.getpid(), signal.SIGTERM)
            if event == "payload_reader_registered" and self.mode == "payload-register-cancel":
                raise KeyboardInterrupt
        if role == "custodian" and event == "child_published" and self.mode == "before-run-cancel":
            while not (self.root / "keeper-release").exists() and time.monotonic_ns() < self.run_deadline_ns:
                time.sleep(.005)
        if role == "keeper" and event == "child_published" and self.mode == "zombie":
            while not (self.root / "zombie-observed").exists() and time.monotonic_ns() < self.run_deadline_ns:
                time.sleep(.005)
            assert (self.root / "zombie-observed").exists(), "zombie observation watchdog expired before a production wait"
        if role == "custodian" and event == "group_request" and self.mode == "pipe-timeout" and "group-held" not in self._injected:
            self._injected.add("group-held")
            record(self.root / "group-held", "C holds payload while descendant cleanup waits")
            while time.monotonic_ns() < self.run_deadline_ns:
                time.sleep(.005)
        completion_event = "payload_before_marker" if self.mode == "marker-parent-death" else "payload_marker_written"
        if (role == "custodian" and event == completion_event
                and self.mode in {*PARENT_DEATH_MODES, *COMPLETION_CANCEL_MODES}):
            record(self.root / "completion-interleaving", self.mode)
            while not (self.root / "completion-signal-delivered").exists() and time.monotonic_ns() < self.run_deadline_ns:
                time.sleep(.005)
            assert (self.root / "completion-signal-delivered").exists(), "outer fixture signal watchdog expired"

    def __enter__(self):
        assert self.patch_state == "NEW", "fixture bindings cannot be entered twice"
        assert not _BINDING_CUSTODY, "unrestored fixture bindings veto another installation"
        _BINDING_CUSTODY.append(self)
        self.patch_state = "INSTALLING"
        try:
            self._enter_patches()
        except BaseException:
            # __exit__ is not called when __enter__ loses its return. The
            # preregistered callbacks include that partially entered patch.
            self._restore_patches()
            raise
        self.patch_state = "ACTIVE"
        return self

    def _enter_patches(self):
        from mobile_release import ios_profiles as profiles
        owner, native = self.owner, self.native
        original_helper, original_worker = owner.helper_argv, owner._worker_argv
        original_channel_init, original_send = owner._Channel.__init__, owner._Channel.send
        original_create, original_close = native.create, native.FDLease.close
        original_wait, original_join = native.Child.poll_wait, owner.threading.Thread.join
        original_frame, original_parser = profiles.completion_frame, profiles.completed_content
        original_read_payload = owner._Outer.read_payload
        completion_marker = profiles.COMPLETION_MARKER

        def helper_argv(role, *, parent_context, deadlines):
            original = original_helper(role, parent_context=parent_context, deadlines=deadlines)
            assert original[:5] == (sys.executable, "-I", "-S", "-B", "-c")
            assert tuple(original[-5:]) == (role, str(parent_context["parent_pid"]), str(parent_context["session_id"]),
                                            str(deadlines["run_deadline_ns"]), str(deadlines["hard_cleanup_deadline_ns"]))
            self.run_deadline_ns = deadlines["run_deadline_ns"]
            if self.role == "outer":
                record(self.root / "deadlines.json", json.dumps(deadlines))
            peer = "bad-helper" if role == "custodian" and self.mode in BAD_FRAME_MODES else "helper"
            return command(peer, self.root, self.root, self.mode, *original[-5:])

        def worker_argv(directory, deadline_ns):
            original = original_worker(directory, deadline_ns)
            assert original[:5] == (sys.executable, "-I", "-S", "-B", "-c")
            assert original[-3:] == ("--worker", str(directory), str(deadline_ns))
            assert directory.parent == self.root and directory.is_dir()
            assert stat.S_IMODE(directory.stat().st_mode) == 0o700
            assert (directory / "cms.der").read_bytes() == b"fictional-profile-canary"
            assert stat.S_IMODE((directory / "cms.der").stat().st_mode) == 0o600
            record(self.root / "scratch-path", str(directory))
            return command("validator", self.root, directory, self.mode, deadline_ns)

        def channel_init(channel, context, reader, writer, incoming, outgoing):
            original_channel_init(channel, context, reader, writer, incoming, outgoing)
            self.channels[incoming] = reader
            self.channel_objects[incoming] = channel
            self.remember(reader)
            self.remember(writer)

        def send(channel, kind, **fields):
            if self.role == "outer" and channel.outgoing == "o_to_c" and kind == "COMMIT":
                assert self.payload_eof and id(self.payload_reader) in self.raw_eofs, "COMMIT preceded real payload EOF"
                self.log("commit_requested_after_real_eof")
                if self.mode == "withhold-commit":
                    assert not self.commit_withheld, "success COMMIT was retried"
                    self.commit_withheld = True
                    self.log("commit_withheld")
                    return
            return original_send(channel, kind, **fields)

        def create(acquisition, spec):
            child = original_create(acquisition, spec)
            assert acquisition.child is child and child.receipt is None
            slots = [task for task in self.tasks.values() if task.acquisition is acquisition]
            assert len(slots) == 1
            self.children[slots[0].child_role] = child
            if self.role == "outer" and self.mode == "spawn-return-cancel":
                assert acquisition.child is child and child.receipt is None
                self.log("native_return_before_python_handoff", child_pid=child.pid)
                os.kill(os.getpid(), signal.SIGTERM)
            return child

        def poll_wait(child):
            # Observe the original consuming operation's return, not just
            # flags exposed later by a role event. Never add another wait.
            assert child.numeric_retired and child.wait_state in {"OWNED", "POLLABLE"}, "original wait entry was not retired and pollable"
            if self.role == "custodian":
                group = self.group
                # Gate EVERY original poll, including one which returns pid0.
                # Post-reap event order cannot prove this first-entry property;
                # a missing group is not positive evidence of no routing grant.
                assert (group is not None and group.keeper is child and group.id == child.pid
                        and group.retired), "keeper poll preceded its exact group retirement"
            receipt = original_wait(child)
            if receipt is not None:
                previous = self.wait_witnesses.get(id(child))
                assert previous is None or previous is receipt
                self.wait_witnesses[id(child)] = receipt
                if previous is None:
                    self.log("original_wait_return", receipt=_receipt(receipt))
            return receipt

        def join(thread, *arguments, **keywords):
            result = original_join(thread, *arguments, **keywords)
            slots = [task for task in self.tasks.values() if task.actual is thread]
            if slots and not thread.is_alive():
                assert len(slots) == 1
                task = slots[0]
                previous = self.join_witnesses.get(id(thread))
                assert previous is None or previous == id(task)
                self.join_witnesses[id(thread)] = id(task)
                if previous is None:
                    self.log("original_join_return", task=id(task), thread=id(thread), child_role=task.child_role)
            return result

        def read(descriptor, count):
            self.tick()
            is_payload = (self.role == "outer" and self.payload_reader is not None
                          and self.payload_reader.state == "OPEN" and descriptor == self.payload_reader.fileno())
            if is_payload:
                if self.mode == "read-failure" and ready(self.root) and "read-failure" not in self._injected:
                    self._injected.add("read-failure")
                    raise OSError("private-native-canary")
                if (self.mode == "backpressure" and self.run_deadline_ns is not None
                        and time.monotonic_ns() < self.run_deadline_ns):
                    raise BlockingIOError
            result = self._real_read(descriptor, count)
            if is_payload:
                self.payload_bytes_read += len(result)
            if result == b"":
                # Bind read(0) to the exact still-OPEN lease, not a recyclable
                # integer retained from an unrelated earlier endpoint.
                for lease in (*self.channels.values(), self.payload_reader):
                    if lease is not None and lease.state == "OPEN" and lease.fileno() == descriptor:
                        self.raw_eofs.add(id(lease))
            return result

        def read_payload(outer):
            result = original_read_payload(outer)
            if self.mode == "overflow" and outer.overflow:
                assert outer.payload is self.payload_reader
                assert self.payload_bytes_read > profiles.MAX_COMPLETION_BYTES
                assert type(outer.context.primary) is profiles.ValidationError
                assert str(outer.context.primary) == "authenticated profile content exceeds its safety bound"
                if not self.payload_overflow_veto:
                    self.payload_overflow_veto = True
                    self.log("actual_payload_overflow_veto", bytes_read=self.payload_bytes_read)
            return result

        def completion_frame(content):
            frame = original_frame(content)
            assert self.role == "custodian" and self.mode in PAYLOAD_MUTATION_MODES
            if self.mode == "overflow":
                frame = (frame[:-len(completion_marker)]
                         + b"x" * (profiles.MAX_COMPLETION_BYTES + 1 - len(frame)) + completion_marker)
                assert len(frame) == profiles.MAX_COMPLETION_BYTES + 1
            elif self.mode == "concatenated-frame":
                frame *= 2
            # partial/extra marker modes change the ONE C-local constant used
            # by both the real frame builder and the real split writer. Merely
            # truncating a returned frame would have its marker repaired by C.
            elif self.mode == "partial-marker":
                assert frame.endswith(completion_marker[:-1]) and not frame.endswith(completion_marker)
            else:
                assert self.mode == "extra-frame" and frame.endswith(completion_marker + b"x")
            self.log("payload_frame_mutated", mode=self.mode, count=len(frame))
            return frame

        def completed_content(frame):
            assert self.role == "outer" and self.payload_eof
            assert self.payload_reader is not None and id(self.payload_reader) in self.raw_eofs
            if self.mode in PAYLOAD_MUTATION_MODES - {"overflow"}:
                canonical = original_frame(b"verified-content")
                expected = {"partial-marker": canonical[:-1], "extra-frame": canonical + b"x",
                            "concatenated-frame": canonical * 2}[self.mode]
                assert frame == expected, "C did not emit the intended malformed payload bytes"
            try:
                return original_parser(frame)
            except profiles.ValidationError as error:
                if self.mode in PAYLOAD_MUTATION_MODES - {"overflow"}:
                    assert not self.payload_parser_rejected
                    assert str(error) == profiles.AUTHENTICATION_ERROR + "; missing or malformed private completion frame"
                    self.payload_parser_rejected = True
                    self.log("actual_payload_parser_rejected", mode=self.mode, count=len(frame))
                raise

        def write(descriptor, content):
            if self.role == "custodian" and self.payload_writer is not None and descriptor == 6:
                if self.mode == "short-write":
                    return self._real_write(descriptor, content[:7])
                if self.mode == "partial-write-failure":
                    if "partial-write" in self._injected:
                        raise OSError("private-native-canary")
                    self._injected.add("partial-write")
                    return self._real_write(descriptor, content[:7])
            return self._real_write(descriptor, content)

        def killpg(group_id, signum):
            group = self.group
            assert group is not None
            if self.role == "custodian":
                assert group.id == group_id == group.keeper.pid
                assert not group.retired and not group.keeper.numeric_retired, "stale group mutation vetoed before syscall"
            else:
                assert self.role == "keeper" and group.group_id == group_id == os.getpid()
                assert not group.group_retired and group_id != group.context.parent_pid
            try:
                return self._real_killpg(group_id, signum)
            except ProcessLookupError:
                self.absent.add(group_id)
                self.log("actual_group_esrch", group=group_id, signum=int(signum))
                raise

        def close(lease):
            if lease.state == "OPEN":
                self.remember(lease)
                self.close_attempts[id(lease)] = self.close_attempts.get(id(lease), 0) + 1
                assert self.close_attempts[id(lease)] == 1, "native descriptor close was replayed"
            target = ((self.role == "custodian" and lease is self.payload_writer and self.mode == "payload-writer-close-failure")
                      or (self.role == "outer" and lease is self.payload_reader
                          and self.mode in {"payload-reader-close-failure", "payload-reader-close-unresolved"}))
            if target and "close" not in self._injected:
                self._injected.add("close")
                if self.mode != "payload-reader-close-unresolved":
                    original_close(lease)
                    assert lease.state == "CLOSED"
                self.log("injected_close_failure", completed=lease.state == "CLOSED")
                raise OSError("private-native-canary")
            return original_close(lease)

        for obj, name, implementation in ((owner, "helper_argv", helper_argv), (owner, "_worker_argv", worker_argv),
                                           (owner, "_role_event", self.observe), (owner._Channel, "__init__", channel_init),
                                           (owner._Channel, "send", send), (native, "create", create),
                                           (native.Child, "poll_wait", poll_wait), (owner.threading.Thread, "join", join),
                                           (native.FDLease, "close", close), (owner.os, "read", read),
                                           (owner.os, "write", write), (owner.os, "killpg", killpg)):
            self._install_patch(patch.object(obj, name, implementation))
        if self.role == "outer":
            self._install_patch(patch.object(profiles, "completed_content", completed_content))
            self._install_patch(patch.object(owner._Outer, "read_payload", read_payload))
        if self.role == "custodian" and self.mode in PAYLOAD_MUTATION_MODES:
            if self.mode in {"partial-marker", "extra-frame"}:
                marker = completion_marker[:-1] if self.mode == "partial-marker" else completion_marker + b"x"
                self._install_patch(patch.object(profiles, "COMPLETION_MARKER", marker))
            self._install_patch(patch.object(profiles, "completion_frame", completion_frame))
        if self.role == "outer" and self.mode in {"supervisor-timeout", "pipe-timeout", "backpressure", "withhold-commit", *BAD_FRAME_MODES}:
            self._install_patch(patch.object(owner, "SUPERVISOR_SECONDS", 3))
        elif self.role == "outer" and self.mode in PAYLOAD_MUTATION_MODES:
            self._install_patch(patch.object(owner, "SUPERVISOR_SECONDS", 6))

    def __exit__(self, kind, value, traceback):
        self._restore_patches()
        if self.patch_state != "CLOSED" and kind is None:
            raise AssertionError("fixture patch restoration is unresolved") from None
        return False


def validator(root, directory, mode, deadline_ns):
    # The real V boundary has only null stdio. Neither V nor its child may keep
    # C's completion writer or any control/status endpoint alive.
    import errno
    import fcntl
    null = os.stat(os.devnull)
    for descriptor in range(3):
        details = os.fstat(descriptor)
        assert stat.S_ISCHR(details.st_mode) and details.st_rdev == null.st_rdev
        assert fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE == (os.O_RDONLY if descriptor == 0 else os.O_WRONLY)
    for descriptor in range(3, 8):
        try:
            os.fstat(descriptor)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            raise AssertionError("validator inherited a forbidden helper descriptor")
    record(root / "worker.json", json.dumps({"pid": os.getpid(), "group": os.getpgrp(),
                                             "parent": os.getppid(), "environment": dict(os.environ),
                                             "forbiddenEndpointsAbsent": True}))
    child = os.fork()
    if child == 0:
        # Publish the actual inherited G membership BEFORE readiness or any
        # injected parent loss. Later G-absence proof needs no new observer.
        record(root / "child.json", json.dumps({"pid": os.getpid(), "group": os.getpgrp(), "parent": os.getppid()}))
        (root / "child-ready").touch()
        time.sleep(20)  # A strict self-limit is not the cleanup oracle (<12s).
        os._exit(0)
    record(root / "child.pid", str(child))
    limit = time.monotonic() + 3
    while not (root / "child-ready").exists() and time.monotonic() < limit:
        time.sleep(.005)
    assert (root / "child-ready").exists()
    if mode in {"orphan", "cancel", "supervisor-timeout"}:
        time.sleep(20)
    if mode == "pipe-timeout":
        while time.monotonic_ns() < deadline_ns - 500_000_000:
            time.sleep(.005)
    if mode == "failure":
        os.write(2, b"private-native-canary\n")  # Real native stderr is null.
        return 1
    content = b"v" * (4 * 1024 * 1024) if mode == "backpressure" else b"verified-content"
    with (directory / "verified-content.bin").open("xb") as output:
        output.write(content)
    return 0


def helper(root, mode, arguments):
    from mobile_release import _profile_process as owner
    role, _parent, _session, cutoff, _hard = arguments
    with ProfileBindings(root, mode, role) as binding:
        binding.run_deadline_ns = int(cutoff)
        result = owner.helper_main(list(arguments))
        contexts = [context for context in owner._HELPER_CUSTODY if context.role == role]
        assert len(contexts) == 1
        binding.assert_local_leases(contexts[0])
        return result


def bad_helper(root, mode, arguments):
    """Bounded malformed C peer; NOT a production-helper positive control."""
    from mobile_release.ios_profiles import completion_frame
    assert mode in BAD_FRAME_MODES
    frame = completion_frame(b"verified-content")
    cutoff = int(arguments[-2])
    os.set_blocking(6, False)
    view = memoryview(frame)
    try:
        while view and time.monotonic_ns() < cutoff:
            try:
                count = os.write(6, view[:65536])
            except BlockingIOError:
                time.sleep(.005)
                continue
            assert count > 0
            view = view[count:]
    except BrokenPipeError:
        pass
    finally:
        os.close(6)  # Exactly the test peer's inherited, O-owned map role.
    return 1 if mode == "full-failure" else 0


def _assert_helper_maps(items, *, keeper_required):
    maps = {}
    for role in ("custodian", "keeper"):
        observed = selected(items, role, "map_validated")
        if role == "keeper" and not keeper_required:
            assert not observed
            continue
        assert len(observed) == 1, "actual production helper map was not validated"
        maps[role] = observed[0]["fd_roles"]
        grants = selected(items, role, "task_granted")
        assert all(observed[0]["sequence"] < grant["sequence"] for grant in grants)
    readers = selected(items, "outer", "payload_reader_registered")
    assert len(readers) == 1
    reader = readers[0]["identity"]
    assert reader["type"] == stat.S_IFIFO and reader["access"] == os.O_RDONLY
    payload = maps["custodian"]["6"]
    assert payload["type"] == stat.S_IFIFO and payload["access"] == os.O_WRONLY
    sources = [item for item in selected(items, "outer", "task_joined")
               if item["child_role"] == "custodian" and "payload_source_identity" in item]
    assert len(sources) == 1
    source = sources[0]
    assert selected(items, "custodian", "map_validated")[0]["pid"] == source["child_pid"]
    # Compare duplication of one actual write endpoint, not opposite pipe ends:
    # XNU hashes the endpoint into st_ino. Reader metadata is not a peer token;
    # the existing actual payload reads/EOF remain independent evidence.
    assert payload == source["payload_source_identity"]
    closes = [item for item in selected(items, "outer", "descriptor_closed")
              if item["lease"] == source["payload_source_lease"]]
    assert len(closes) == 1 and source["sequence"] < closes[0]["sequence"]
    if keeper_required:
        for descriptor in ("6", "7"):
            unused = maps["keeper"][descriptor]
            assert unused["type"] == stat.S_IFCHR and unused["access"] == os.O_WRONLY
            assert (unused["device"], unused["inode"]) != (payload["device"], payload["inode"])


def _assert_original_witnesses(items):
    for role in ("outer", "custodian", "keeper"):
        published = selected(items, role, "task_published")
        joined = selected(items, role, "task_joined")
        originals = selected(items, role, "original_join_return")
        assert ({item["task"] for item in published} == {item["task"] for item in joined}
                == {item["task"] for item in originals})
        for item in joined:
            witnesses = [entry for entry in originals if entry["task"] == item["task"]]
            assert len(witnesses) == 1 and witnesses[0]["sequence"] < item["sequence"]
        waits = [item for item in items if item["role"] == role
                 and item["event"] in {"custodian_reaped", "keeper_reaped", "validator_reaped"}]
        original_waits = selected(items, role, "original_wait_return")
        assert len(waits) == len(original_waits)
        for item in waits:
            witnesses = [entry for entry in original_waits if entry["receipt"] == item["receipt"]]
            assert len(witnesses) == 1 and witnesses[0]["sequence"] < item["sequence"]


def _assert_worker_group_absent(root, items, *, require_ready=False):
    """Original K/V waits plus pinned-G absence, never a substitute C wait."""
    k_waits = selected(items, "custodian", "keeper_reaped")
    v_waits = selected(items, "keeper", "validator_reaped")
    assert len(k_waits) == len(v_waits) == 1
    group = k_waits[0]["receipt"]["pid"]
    retired = selected(items, "custodian", "group_retired")
    absent = selected(items, "custodian", "actual_group_esrch")
    assert len(retired) == 1 and retired[0]["absent"] and absent
    assert retired[0]["group"] == group and all(item["group"] == group for item in absent)
    assert absent[-1]["sequence"] < retired[0]["sequence"] < k_waits[0]["sequence"]
    admitted = ready(root)
    assert admitted or not require_ready, "parent-loss fixture never admitted its real descendant"
    if admitted:
        worker = json.loads((root / "worker.json").read_text())
        descendant = json.loads((root / "child.json").read_text())
        assert worker["group"] == worker["parent"] == group
        assert worker["pid"] == v_waits[0]["receipt"]["pid"]
        assert worker["forbiddenEndpointsAbsent"]
        assert not set(CANARIES) & worker["environment"].keys()
        assert set(descendant) == {"pid", "group", "parent"}
        assert all(type(value) is int and value > 1 for value in descendant.values())
        assert descendant["pid"] == int((root / "child.pid").read_text())
        assert descendant["pid"] not in {worker["pid"], group}
        assert descendant["parent"] == worker["pid"] and descendant["group"] == group
        # V's fixed child never leaves its inherited G. C's actual ESRCH was
        # observed while K was still unreaped, then permanently retired G
        # before the original K wait. This proves that admitted descendant is
        # no longer in G without launching a post-UNKNOWN process observer.


def _assert_native_finality(root, *, allow_no_validator=False):
    items = events(root)
    c_waits = selected(items, "outer", "custodian_reaped")
    assert len(c_waits) == 1, "missing actual O wait of C"
    assert selected(items, "outer", "status_eof"), "C status EOF was not actually read"
    _assert_original_witnesses(items)
    k_waits = selected(items, "custodian", "keeper_reaped")
    v_waits = selected(items, "keeper", "validator_reaped")
    if allow_no_validator:
        finals = [item["frame"] for item in selected(items, "custodian", "frame_sent")
                  if item["frame"]["type"] == "FINAL"]
        assert len(finals) == 1 and finals[0]["outcome"] == "failed"
        assert c_waits[0]["receipt"]["status_kind"] == "exit" and c_waits[0]["receipt"]["status_code"] == 2
        assert finals[0]["validator"] == {"state": "not_attempted"} and not v_waits
        if finals[0]["keeper"] == {"state": "not_attempted"}:
            assert not k_waits and finals[0]["group"] == {"state": "not_created"}
            _assert_helper_maps(items, keeper_required=False)
        else:
            assert len(k_waits) == 1 and finals[0]["keeper"] == k_waits[0]["receipt"]
            _assert_helper_maps(items, keeper_required=True)
        return items
    assert len(k_waits) == len(v_waits) == 1
    for role in ("custodian", "keeper"):
        assert len(selected(items, role, "local_leases_accounted")) == 1
    _assert_helper_maps(items, keeper_required=True)
    _assert_worker_group_absent(root, items)
    return items


def driver(root, mode):
    assert_fixture_idle()
    import gc
    from mobile_release import ios_profiles as profiles
    from mobile_release import _profile_process as owner
    from mobile_release.errors import ValidationError
    from mobile_release.inspection import InspectionDeadline

    os.environ.update({key: "fictional-private-canary" for key in CANARIES})
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    if mode == "custom-handler":
        signal.signal(signal.SIGTERM, lambda *_: None)
        previous[signal.SIGTERM] = signal.getsignal(signal.SIGTERM)
    finalities, scratches = [], []
    original_capture, original_acquire = owner.capture_profile, profiles.ScratchLease.acquire
    deadline = InspectionDeadline()
    def capture(directory, clock, *, cancellation=None, finality):
        finalities.append(finality)
        return original_capture(directory, clock, cancellation=cancellation, finality=finality)
    def acquire(lease):
        path = original_acquire(lease)
        scratches.append(path)
        assert path.parent == root
        record(root / "scratch-path", str(path))
        return path
    result = None
    with ProfileBindings(root, mode) as binding, patch.object(profiles, "sys", SimpleNamespace(platform="darwin", executable=sys.executable)), patch.object(owner, "capture_profile", capture), patch.object(profiles.ScratchLease, "acquire", acquire):
        binding.deadline = deadline
        try:
            output = profiles.authenticate_cms(b"fictional-profile-canary", deadline=deadline)
            assert mode in {"success", "custom-handler", "short-write", "zombie", "commit-after-eof"}
            assert output == b"verified-content"
            result = "success"
        except KeyboardInterrupt:
            assert mode in {"spawn-return-cancel", "payload-register-cancel", "before-admit-cancel", "before-run-cancel", "cancel", *COMPLETION_CANCEL_MODES}
            result = "cancelled"
        except ValidationError as error:
            assert mode in {"pipe-timeout", "supervisor-timeout", "backpressure", "committed-timeout", "withhold-commit", "failure", "read-failure", "partial-write-failure", "payload-writer-close-failure", "payload-reader-close-failure", "payload-reader-close-unresolved", *BAD_FRAME_MODES, *PAYLOAD_MUTATION_MODES}
            assert "private-native-canary" not in str(error)
            result = "rejected"
    assert result is not None
    assert all(signal.getsignal(sig) == handler for sig, handler in previous.items())
    assert len(finalities) == 1 and len(scratches) == 1
    finality = finalities.pop()
    final_state = finality.state
    assert finality._owner is not None
    if final_state == "UNKNOWN":
        # Latch the admitted fixture domain, not another fixture reference to
        # finality: the GC check below must still prove PRODUCT registry roots.
        retain_fixture_custody(root)
    if mode in UNKNOWN_PROFILE_MODES:
        assert final_state == "UNKNOWN", "poison fixture did not retain its actual uncertainty"
    else:
        expected = "NO_PRODUCERS" if mode == "payload-register-cancel" else "FINALIZED"
        assert final_state == expected, "healthy profile case retained unfinished product custody"
    binding.assert_local_leases(finality._owner, unresolved=binding.payload_reader
                                if mode == "payload-reader-close-unresolved" else None)
    if mode in BAD_FRAME_MODES:
        items = events(root)
        assert len(selected(items, "outer", "custodian_reaped")) == 1
        assert not (root / "worker.json").exists()
        assert final_state == "UNKNOWN", "missing terminal accounting fabricated no-K finality"
    elif mode in {"payload-register-cancel", "spawn-return-cancel", "before-admit-cancel", "before-run-cancel"}:
        items = events(root)
        if mode == "payload-register-cancel":
            assert not selected(items, "outer", "child_published")
            context = finality._owner
            acquisition = context.child_acquisition
            assert {id(task) for task in context.tasks} == set(binding.tasks)
            assert (acquisition.attempted is False and acquisition.child is None
                    and acquisition.launch_retired and acquisition.settled and not acquisition.cleanup_unknown
                    and context.launch_closed), "missing C publication is NOT positive no-attempt evidence"
            assert not binding.children
            for task in context.tasks:
                assert task.acquisition is acquisition and task.launch_retired and task.joined and task.body_done
                assert task.actual is not None and not task.actual.is_alive()
                assert binding.join_witnesses.get(id(task.actual)) == id(task)
            assert final_state == "NO_PRODUCERS"
        else:
            items = _assert_native_finality(root, allow_no_validator=True)
    else:
        items = _assert_native_finality(root)
    if mode in {"payload-writer-close-failure", "payload-reader-close-failure", "payload-reader-close-unresolved"}:
        assert final_state == "UNKNOWN" and result == "rejected"
    retained = final_state == "UNKNOWN"
    reuse_refused = False
    if retained:
        assert all(path.is_dir() and stat.S_IMODE(path.stat().st_mode) == 0o700 for path in scratches)
        retained_id = id(finality)
        del finality
        binding.release_fixture_references()
        gc.collect()
        assert any(id(item) == retained_id and item.state == "UNKNOWN" for item in owner._CUSTODY)
        assert all(path.is_dir() for path in scratches), "GC deleted UNKNOWN scratch"
        with patch.object(profiles.tempfile, "mkdtemp", side_effect=AssertionError("UNKNOWN admitted another workspace")), patch.object(owner.native, "create", side_effect=AssertionError("UNKNOWN admitted another child")):
            try:
                profiles.authenticate_cms(b"fictional-profile-canary", deadline=InspectionDeadline())
            except ValidationError:
                reuse_refused = True
        assert reuse_refused
    else:
        assert final_state in {"NO_PRODUCERS", "FINALIZED"}
        assert all(not path.exists() for path in scratches)
        assert not profiles._PROFILE_SCRATCH_LEASES and not profiles._PROFILE_RESOURCE_SCOPES
        assert not owner._CUSTODY and binding.patch_state == "CLOSED"
        assert_fixture_idle()
    commits = [item for item in selected(items, "outer", "frame_sent") if item["frame"]["type"] == "COMMIT"]
    eof = selected(items, "outer", "payload_eof")
    if final_state == "FINALIZED":
        finals = [item["frame"] for item in selected(items, "outer", "final_received")]
        assert len(finals) == 1 and finals[0]["cleanup"] == "confirmed"
        receipt = selected(items, "outer", "custodian_reaped")[0]["receipt"]
        assert receipt["status_kind"] == "exit"
        assert receipt["status_code"] == (2 if finals[0]["outcome"] == "failed" else 0)
        keeper = finals[0]["keeper"]
        if keeper["state"] == "reaped":
            assert keeper["status_kind"] == "exit" and keeper["status_code"] in (0, 2)
            released = [item["frame"] for item in selected(items, "keeper", "frame_sent")
                        if item["frame"]["type"] == "RELEASED"]
            assert len(released) == 1 and released[0]["validator"] == finals[0]["validator"]
            assert any(item["edge"] == "k_to_c" for item in selected(items, "custodian", "status_eof"))
            if keeper["status_code"] == 2:
                assert finals[0]["outcome"] == "failed"
    if mode in PAYLOAD_MUTATION_MODES:
        assert result == "rejected" and final_state == "FINALIZED"
        mutations = selected(items, "custodian", "payload_frame_mutated")
        assert len(mutations) == 1 and mutations[0]["mode"] == mode
        assert len(eof) == 1 and not commits
        assert not selected(items, "custodian", "commit_received")
        assert binding.payload_overflow_veto == (mode == "overflow")
        assert binding.payload_parser_rejected == (mode != "overflow")
        if mode == "overflow":
            assert len(selected(items, "outer", "actual_payload_overflow_veto")) == 1
        else:
            rejected = selected(items, "outer", "actual_payload_parser_rejected")
            assert len(rejected) == 1 and eof[0]["sequence"] < rejected[0]["sequence"]
    if result == "success":
        assert len(commits) == len(eof) == 1 and eof[0]["sequence"] < commits[0]["sequence"]
        payload_closes = selected(items, "custodian", "payload_closed")
        received = selected(items, "custodian", "commit_received")
        assert len(payload_closes) == len(received) == 1
        assert payload_closes[0]["sequence"] < received[0]["sequence"]
        # A post-close observer may run after O has already observed EOF. Do
        # not infer cross-process operation order from delayed log timestamps.
        finals = [item["frame"] for item in selected(items, "custodian", "frame_sent") if item["frame"]["type"] == "FINAL"]
        assert len(finals) == 1 and finals[0]["outcome"] == "ok"
    if mode == "withhold-commit":
        assert binding.commit_withheld and eof and not commits
        assert not selected(items, "custodian", "commit_received")
        assert all(item["frame"]["outcome"] != "ok" for item in selected(items, "custodian", "frame_sent") if item["frame"]["type"] == "FINAL")
    if mode == "pipe-timeout":
        assert binding.orphan_observed
    if mode == "zombie":
        assert binding.zombie_observed
    partial_bytes = sum(item["count"] for item in selected(items, "custodian", "payload_write"))
    if mode == "backpressure":
        assert 0 < partial_bytes < 4 * 1024 * 1024
    result_record = {"result": result, "deadBeforeFallback": True, "scratchRemoved": not retained,
                     "scratchRetained": retained, "retainedAfterGC": retained,
                     "domainDisposalRequired": retained, "noRetainedCustody": not retained,
                     "reuseRefused": reuse_refused, "finality": final_state,
                     "orphanPipeObserved": binding.orphan_observed, "zombieObserved": binding.zombie_observed,
                     "realEOFAheadOfCommit": bool(eof) and (not commits or eof[0]["sequence"] < commits[0]["sequence"]),
                     "commitWithheld": binding.commit_withheld, "backpressureObserved": mode == "backpressure" and partial_bytes > 0,
                     "syntheticMalformedHelper": mode in BAD_FRAME_MODES,
                     "payloadParserRejected": binding.payload_parser_rejected,
                     "payloadOverflowVeto": binding.payload_overflow_veto}
    record(root / "result.json", json.dumps(result_record))
    return 0


def run_case(workspace: FixtureWorkspace, mode: str) -> dict:
    assert_fixture_idle()
    root = workspace.path
    environment = {"PATH": os.environ["PATH"], "TMPDIR": str(root), "TMP": str(root), "TEMP": str(root)}
    environment.update(observer_environment())
    signalled = []
    def tick(controller):
        selected_signal = None
        if mode in {"cancel", "orphan"} and ready(root):
            selected_signal = signal.SIGKILL if mode == "orphan" else signal.SIGTERM
        elif mode in {*PARENT_DEATH_MODES, *COMPLETION_CANCEL_MODES} and (root / "completion-interleaving").exists():
            selected_signal = (signal.SIGINT if mode == "completion-interrupt" else
                               signal.SIGTERM if mode == "completion-cancel" else signal.SIGKILL)
        if selected_signal is not None and not signalled:
            if selected_signal == signal.SIGKILL:
                # The original O-to-C waiter is about to be lost. Its own
                # driver's later receipt cannot repair that missing custody.
                workspace.retain()
            controller.request_signal(selected_signal)
            signalled.append(selected_signal)
            record(root / "completion-signal-delivered", str(int(selected_signal)))
    started = time.monotonic()
    driver_failure = None
    try:
        with FixtureDriver(command("driver", root, root, mode), env=environment) as controller:
            stdout, stderr = controller.finish(timeout=12, on_tick=tick)
            killed_parent = mode == "orphan" or mode in PARENT_DEATH_MODES
            if controller.process.returncode != (-signal.SIGKILL if killed_parent else 0):
                driver_failure = (controller.process.returncode, stderr)
            assert controller.process.returncode == (-signal.SIGKILL if killed_parent else 0), "profile fixture driver failed"
            assert not stdout and not stderr, "profile fixture emitted unexpected output"
            assert controller.receipt is not None
    except AssertionError:
        # The original __exit__ and close/UNKNOWN accounting precede optional
        # output. Acquisition/finish/other assertions simply re-raise unchanged.
        if driver_failure is not None:
            _report_driver_failure(mode, *driver_failure)
        raise
    try:
        if killed_parent:
            workspace.retain()
            # Reporting of existing witnesses only. This cutoff belongs to
            # the original case, not a renewed post-loss observer capture.
            cutoff = min(started + 12, controller._finish_cutoff)
            while time.monotonic() < cutoff:
                items = events(root)
                publications = selected(items, "outer", "child_published")
                if (publications and selected(items, "custodian", "keeper_reaped")
                        and selected(items, "keeper", "validator_reaped")
                        and selected(items, "custodian", "group_retired")
                        and selected(items, "custodian", "local_leases_accounted")
                        and selected(items, "keeper", "local_leases_accounted")):
                    break
                time.sleep(.01)
            else:
                raise AssertionError("independent keeper/validator cleanup lacked its original witnesses")
            _assert_original_witnesses(items)
            _assert_helper_maps(items, keeper_required=True)
            _assert_worker_group_absent(root, items, require_ready=True)
            scratch = Path((root / "scratch-path").read_text())
            assert scratch.parent == root and scratch.is_dir() and stat.S_IMODE(scratch.stat().st_mode) == 0o700
            assert not selected(items, "outer", "custodian_reaped"), "dead O fabricated a wait receipt"
            assert not selected(items, "outer", "original_wait_return"), "dead O fabricated its original C wait"
            observed = time.monotonic()
            assert observed < cutoff, "hard-loss fixture proof exceeded its original cutoff"
            # K/V/G evidence proves the admitted worker group, NOT cessation
            # of C. Missing original O-to-C custody stays explicitly UNKNOWN
            # until the delivered Session disposes its original domain.
            return {"workerGroupAbsent": True, "custodianWaitMissing": True,
                    "finality": "UNKNOWN", "domainDisposalRequired": True,
                    "hardKillScratchRemainsPrivate": True,
                    "completionInterleavingReached": mode in PARENT_DEATH_MODES,
                    "scratchRetained": True, "elapsed": observed - started}
        result = json.loads((root / "result.json").read_text())
        if result["finality"] == "UNKNOWN" or result["scratchRetained"]:
            workspace.retain()
        result["elapsed"] = time.monotonic() - started
        assert result["elapsed"] < 12, "fixture reached a worker self-timeout instead of cleanup"
        if mode in UNKNOWN_PROFILE_MODES:
            assert result["finality"] == "UNKNOWN" and result["scratchRetained"] and result["domainDisposalRequired"]
            assert result["retainedAfterGC"] and result["reuseRefused"] and not result["noRetainedCustody"]
        else:
            expected = "NO_PRODUCERS" if mode == "payload-register-cancel" else "FINALIZED"
            assert result["finality"] == expected and result["noRetainedCustody"]
            assert not result["scratchRetained"] and not result["domainDisposalRequired"] and result["scratchRemoved"]
            workspace.allow_removal()
        return result
    except BaseException:
        workspace.retain()
        raise


def backpressure_case(workspace: FixtureWorkspace) -> dict:
    return run_case(workspace, "backpressure")


if __name__ == "__main__":
    role, root, directory, mode, *arguments = sys.argv[1:]
    root, directory = Path(root), Path(directory)
    if role == "driver":
        status = driver(root, mode)
    elif role == "validator":
        status = validator(root, directory, mode, int(arguments[0]))
    elif role == "helper":
        status = helper(root, mode, arguments)
    elif role == "bad-helper":
        status = bad_helper(root, mode, arguments)
    else:
        raise AssertionError("unknown fixed profile fixture role")
    raise SystemExit(status)
