"""Original Store-lane files, checked terminal reader and refusal-only fence.

Private preparation: callers/entrypoint are not activated by importing this
module. Only the original fixed writer's 0/75 outcome can bind terminal output.
No cleanup from a pathname, copied JSON, stale PID or marker absence exists.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
import time
import unicodedata
from pathlib import Path
from typing import Mapping

from . import _store_lane_contract as wire
from ._store_lane_evidence import (
    StoreLaneCallEvidence, StoreLaneEvidenceError, StoreLaneResourceBinding,
    StoreLaneTerminal,
)
from .cancellation import DefaultCancellation
from .owned_process import preserve_lifetime_error


_RETAINED: list[object] = []
_AUTHORITY_KEYS = frozenset(("attempt", "callerPath", "event", "headSha", "ref",
    "reusableCommit", "reusablePath", "reusableRepository", "runId", "workflow"))


def _identity(value: os.stat_result, *, directory: bool) -> wire.Identity:
    wire.need((stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode)))
    return wire.Identity(value.st_dev, value.st_ino, value.st_uid, value.st_gid,
                         stat.S_IMODE(value.st_mode))


def _revision(value: os.stat_result) -> tuple[int, int, int, int]:
    return value.st_size, value.st_mtime_ns, value.st_ctime_ns, value.st_nlink


class _Owner:
    def __init__(self, record: StoreLaneCallEvidence, cancellation: DefaultCancellation) -> None:
        wire.need(type(record) is StoreLaneCallEvidence)
        record._origin(cancellation)
        self.record, self.guard = record, cancellation
        self.pid, self.thread = os.getpid(), threading.current_thread()
        self.slots: list[_FD] = []
        self.creations: list[_Creation] = []
        self.removals: set[tuple[int, str]] = set()
        self.primary: BaseException | None = None
        self.errors: list[BaseException] = []
        self.failed = False

    def origin(self) -> None:
        # A copied/forked owner must not touch the original guard or FD slots.
        if self.pid != os.getpid() or self.thread is not threading.current_thread():
            raise StoreLaneEvidenceError()
        self.record._origin(self.guard)

    def remember(self, error: BaseException, *, unknown: bool = True) -> None:
        self.origin()
        if self.primary is None:
            self.primary = error
        elif error is not self.primary and len(self.errors) < 8 and not any(x is error for x in self.errors):
            self.errors.append(error)
        # Retain a known original primary on the composite record before a
        # later reader/close error can arrive. An ordinary primary does not
        # make otherwise settled consumers live again or abort the guard.
        self.record._remember(error)
        if unknown:
            self.failed = True
            if not any(owner is self for owner in _RETAINED):
                _RETAINED.append(self)
            self.record.record_failure(error)

    def raise_failure(self) -> None:
        if isinstance(self.primary, (KeyboardInterrupt, SystemExit)):
            raise self.primary
        error = StoreLaneEvidenceError(attempted=self.record._attempted)
        for previous in (self.primary, *self.errors):
            preserve_lifetime_error(error, previous=previous, contained=False)
        raise error from None

    def close_handles(self) -> None:
        self.origin()
        # Independent original closes still run after another close failed.
        for slot in reversed(self.slots):
            try:
                slot.close()
            except BaseException as error:
                self.remember(error)

    def handles_closed(self) -> bool:
        return all(slot.state == "CLOSED" for slot in self.slots)


class _FD:
    def __init__(self, owner: _Owner) -> None:
        self.owner, self.number, self.state = owner, None, "NEW"
        owner.slots.append(self)

    def open(self, name: str, flags: int, *, parent: int | None = None) -> int:
        self.owner.origin()
        wire.need(self.state == "NEW")
        try:
            with self.owner.guard.deferred(check_on_exit=False):
                self.state = "ATTEMPTED"
                self.number = os.open(name, flags | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                                      0o600, dir_fd=parent)
                wire.need(type(self.number) is int and self.number >= 0)
                self.state = "OPEN"
        except BaseException as error:
            # A positively returned original descriptor still gets its one
            # close, even if a later check/deferral exit raised.
            self.state = "OPEN" if type(self.number) is int and self.number >= 0 else "UNKNOWN"
            self.owner.remember(error)
            raise
        return self.number

    def close(self) -> None:
        self.owner.origin()
        if self.state in ("NEW", "CLOSED"):
            self.state = "CLOSED"
            return
        if self.state != "OPEN":
            # UNKNOWN is never a numeric-FD retry route.
            self.owner.remember(StoreLaneEvidenceError(attempted=self.owner.record._attempted))
            return
        try:
            with self.owner.guard.deferred(check_on_exit=False):
                self.state = "CLOSING"  # Retire before the actual single close.
                number, self.number = self.number, None
                os.close(number)
                self.state = "CLOSED"
        except BaseException as error:
            self.state = "UNKNOWN"
            self.owner.remember(error)


class _Directory:
    def __init__(self, owner: _Owner, name: str, parent: _Directory | None,
                 *, private: bool = False) -> None:
        self.owner, self.name, self.parent = owner, name, parent
        self.slot = _FD(owner)
        number = self.slot.open(name, os.O_RDONLY | os.O_DIRECTORY,
                                parent=None if parent is None else parent.fd)
        self.identity = _identity(os.fstat(number), directory=True)
        if private:
            wire.need(self.identity.uid == os.geteuid() and self.identity.mode == 0o700
                      and parent is not None and self.identity.device == parent.identity.device)
        self.check()

    @property
    def fd(self) -> int:
        wire.need(self.slot.state == "OPEN" and type(self.slot.number) is int)
        return self.slot.number

    def check(self) -> None:
        self.owner.origin()
        if self.parent is not None:
            self.parent.check()
        wire.need(_identity(os.fstat(self.fd), directory=True) == self.identity
                  and _identity(os.stat(self.name, dir_fd=None if self.parent is None else self.parent.fd,
                                        follow_symlinks=False), directory=True) == self.identity)

    def names(self, *, limit: int = 64) -> set[str]:
        self.check()
        values = os.listdir(self.fd)
        wire.need(len(values) <= limit and all(type(x) is str and len(os.fsencode(x)) <= 512 for x in values))
        self.check()
        return set(values)


def _path_directory(owner: _Owner, path: Path) -> _Directory:
    wire.need(isinstance(path, Path) and wire.absolute(str(path)))
    current = _Directory(owner, path.anchor, None)
    for name in path.parts[1:]:
        current = _Directory(owner, name, current)
    return current


def _private_child(owner: _Owner, parent: _Directory, name: str, *, exclusive: bool) -> _Directory:
    parent.check()
    # On case-folding native filesystems, a foreign alias is still a collision,
    # never an excuse to adopt a differently spelled reserved namespace.
    key = unicodedata.normalize("NFC", name).casefold()
    names = parent.names(limit=4096)
    wire.need(all(unicodedata.normalize("NFC", value).casefold() != key or value == name for value in names))
    if name in names:
        wire.need(not exclusive)
        return _Directory(owner, name, parent, private=True)
    creation = _Creation(owner, parent, name)  # Reservation precedes mkdir.
    creation.create()
    child = _Directory(owner, name, parent, private=True)
    creation.directory = child
    parent.check()
    return child


class _Creation:
    def __init__(self, owner: _Owner, parent: _Directory, name: str) -> None:
        self.owner, self.parent, self.name = owner, parent, name
        self.state, self.directory = "NEW", None
        owner.creations.append(self)

    def create(self) -> None:
        self.owner.origin()
        wire.need(self.state == "NEW")
        try:
            with self.owner.guard.deferred(check_on_exit=False):
                self.state = "ATTEMPTED"
                os.mkdir(self.name, 0o700, dir_fd=self.parent.fd)
                self.state = "CREATED"
        except BaseException as error:
            self.state = "UNKNOWN"
            self.owner.remember(error)
            raise


def _store_directory(owner: _Owner, app_root: Path) -> _Directory:
    app = _path_directory(owner, app_root)
    private = _private_child(owner, app, ".mobile-release", exclusive=False)
    return _private_child(owner, private, "store", exclusive=False)


def _read(owner: _Owner, directory: _Directory, name: str, *, limit: int,
          links: int, expected: wire.Identity | None = None) -> tuple[bytes, wire.Identity]:
    directory.check()
    slot = _FD(owner)
    data = bytearray()
    try:
        number = slot.open(name, os.O_RDONLY, parent=directory.fd)
        before = os.fstat(number)
        identity = _identity(before, directory=False)
        wire.need(identity.uid == os.geteuid() and identity.mode == 0o600
                  and before.st_nlink == links and 0 < before.st_size <= limit
                  and (expected is None or identity == expected))
        while len(data) <= limit:
            block = os.read(number, min(65_536, limit + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        after = os.fstat(number)
        entry = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
        wire.need(len(data) == before.st_size and len(data) <= limit
                  and _identity(after, directory=False) == identity
                  and _identity(entry, directory=False) == identity
                  and _revision(after) == _revision(before) == _revision(entry))
        directory.check()
    except BaseException as error:
        # Record before finally, so an independent close failure cannot replace
        # the first original read/interruption object.
        owner.remember(error)
        raise
    finally:
        slot.close()
    wire.need(slot.state == "CLOSED" and not owner.failed)
    return bytes(data), identity


def _remove(owner: _Owner, directory: _Directory, name: str, *, identity: wire.Identity,
            directory_entry: bool, links: int | None = None) -> None:
    directory.check()
    original = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
    wire.need(_identity(original, directory=directory_entry) == identity
              and (directory_entry or original.st_nlink == links))
    operation = (id(directory), name)
    wire.need(operation not in owner.removals)
    with owner.guard.deferred(check_on_exit=False):
        owner.removals.add(operation)  # No retry after a lost removal return.
        if directory_entry:
            os.rmdir(name, dir_fd=directory.fd)
        else:
            os.unlink(name, dir_fd=directory.fd)
    directory.check()
    try:
        os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise StoreLaneEvidenceError(attempted=owner.record._attempted)


class StoreLaneFiles(_Owner):
    """One fixed original namespace/reader, not an output adoption API."""

    def __init__(self, record: StoreLaneCallEvidence, cancellation: DefaultCancellation,
                 *, app_root: Path, mode: str, shell_home: bool = False) -> None:
        super().__init__(record, cancellation)
        wire.need(type(mode) is str and mode in ("prepare", "execute") and type(shell_home) is bool
                  and isinstance(app_root, Path) and wire.absolute(str(app_root)))
        self.app_root, self.mode, self.shell_home = app_root, mode, shell_home
        self.root_path: Path | None = None
        self.root: _Directory | None = None
        self.directories: dict[str, _Directory] = {}
        self.created: list[_Directory] = []
        self.timing: wire.Timing | None = None
        self.environment: tuple[tuple[str, str], ...] | None = None
        self.phase = "NEW"
        self.inventory: tuple[wire.Entry, ...] = ()
        self.terminal: StoreLaneTerminal | None = None
        self.original_outcome = None
        self.terminal_identity: wire.Identity | None = None
        self._document_bytes: bytes | None = None
        self._publication_consumed = False
        self._cleanup_complete = False
        self.bindings = {role: record.bind_resource(role, self, cancellation=cancellation)
                         for role in ("runner", "tmp", "terminal")}

    def acquire(self) -> None:
        self.origin()
        wire.need(self.phase == "NEW" and not self.failed)
        self.phase = "ACQUIRING"
        try:
            self.guard.check()
            expected_root = self.app_root / ".mobile-release/store/lane-private-v1" / self.record._nonce.hex()
            wire.need(wire.absolute(str(expected_root)))
            store = _store_directory(self, self.app_root)
            parent = _private_child(self, store, "lane-private-v1", exclusive=False)
            root = _private_child(self, parent, self.record._nonce.hex(), exclusive=True)
            self.root = root
            self.created.append(root)
            self.root_path = expected_root
            self.directories["root"] = root
            for role in ("runner", "tmp"):
                child = _private_child(self, root, role, exclusive=True)
                self.directories[role] = child; self.created.append(child)
            if self.shell_home:
                parent = root
                for role, name in (("home", "home"), ("shell-parent", ".appstoreconnect"),
                                   ("shell-keys", "private_keys")):
                    child = _private_child(self, parent, name, exclusive=True)
                    self.directories[role] = child; self.created.append(child)
                    parent = child
            wire.need(root.names() == ({"runner", "tmp", "home"} if self.shell_home else {"runner", "tmp"}))
            self.phase = "ACQUIRED"
            self.guard.check()
        except BaseException as error:
            self.remember(error)
            self.close_handles()
            self.raise_failure()

    @property
    def cwd(self) -> Path:
        self.origin()
        wire.need(self.root_path is not None and self.phase != "NEW")
        return self.root_path / "runner"

    def prepare_environment(self, environment: Mapping[str, str]) -> dict[str, str]:
        self.origin()
        wire.need(self.phase == "ACQUIRED" and not self.failed and self.environment is None)
        try:
            self.guard.check()
            assert self.root is not None and self.root_path is not None
            self.root.check()
            result = dict(environment)
            wire.need(all(type(k) is str and type(v) is str for k, v in result.items())
                      and result.get("MOBILE_RELEASE_OPERATION") == self.record._lane
                      and result.get("MOBILE_RELEASE_STORE_RECEIPT_PATH") == self.record._output
                      and result.get("MOBILE_RELEASE_STORE_MODE") == self.mode
                      and result.get(wire.PREFIX + "NONCE", self.record._nonce.hex()) == self.record._nonce.hex()
                      and all(not key.startswith(wire.PREFIX) or key == wire.PREFIX + "NONCE" for key in result)
                      and not Path(self.record._output).is_relative_to(self.root_path))
            # Retire admission before clock/encoding can fail; no renewed hour.
            self.phase = "SEALING"
            label = wire.clock_label()
            run = time.monotonic_ns() + wire.RUN_NS
            self.timing = wire.Timing(label, run, run + wire.CLEANUP_NS)
            wire.need(self.timing.hard <= wire.MAX_TIME)
            result.update({
                wire.PREFIX + "NONCE": self.record._nonce.hex(),
                wire.PREFIX + "ROOT": str(self.root_path),
                wire.PREFIX + "ROOT_ID": f"{self.root.identity.device}:{self.root.identity.inode}",
                wire.PREFIX + "CLOCK": label,
                wire.PREFIX + "RUN_DEADLINE_NS": str(self.timing.run),
                wire.PREFIX + "HARD_DEADLINE_NS": str(self.timing.hard),
                "TMPDIR": str(self.root_path / "tmp"), "TMP": str(self.root_path / "tmp"),
                "TEMP": str(self.root_path / "tmp"),
            })
            if self.shell_home:
                # The caller admits its concrete toolchain before this private
                # shell-HOME selection; ambient key directories are never used.
                result["HOME"] = str(self.root_path / "home")
            self.environment = tuple(sorted(result.items()))
            self.phase = "PREPARED"
            return result
        except BaseException as error:
            self.remember(error)
            self.raise_failure()

    def _matches_command(self, record: StoreLaneCallEvidence, cwd: Path,
                         environment: Mapping[str, str]) -> bool:
        self.origin()
        matched = (record is self.record and self.phase == "PREPARED" and not self.failed
                   and self.timing is not None and self.environment == tuple(sorted(environment.items()))
                   and cwd == self.cwd)
        if matched:
            try:
                self._check_inventory()  # Includes both absent terminal names.
            except BaseException as error:
                self.remember(error)
                self.raise_failure()
        return matched

    def _receipt_closed_for(self, record: StoreLaneCallEvidence) -> bool:
        self.origin()
        return (record is self.record and self.phase == "DISPOSED" and not self.failed
                and self._cleanup_complete and self.handles_closed())

    def _accepts_terminal(self, record: StoreLaneCallEvidence, binding: StoreLaneResourceBinding,
                          terminal: StoreLaneTerminal, outcome: object) -> bool:
        self.origin()
        accepted = (record is self.record and binding is self.bindings["terminal"]
                    and terminal is self.terminal and outcome is self.original_outcome
                    and self.phase == "OBSERVED" and not self.failed and not self._publication_consumed)
        if accepted:
            self._publication_consumed = True
        return accepted

    def _observe_inventory(self, entries: tuple[wire.Entry, ...]) -> None:
        pending = list(entries)
        while pending:
            progress = False
            for entry in tuple(pending):
                if entry.parent not in self.directories:
                    continue
                parent = self.directories[entry.parent]
                parent.check()
                value = os.stat(entry.name, dir_fd=parent.fd, follow_symlinks=False)
                wire.need(_identity(value, directory=entry.kind == "directory") == entry.identity
                          and (entry.kind == "directory" or value.st_nlink == 1))
                if entry.kind == "directory":
                    child = _Directory(self, entry.name, parent, private=True)
                    wire.need(child.identity == entry.identity)
                    self.directories[entry.role] = child
                pending.remove(entry); progress = True
            wire.need(progress)
        self.inventory = entries
        self._check_inventory()

    def _check_inventory(self) -> None:
        expected = {role: set() for role in self.directories}
        expected["root"] = {"runner", "tmp"} | ({"home"} if self.shell_home else set())
        if self.terminal_identity is not None:
            expected["root"].update(("terminal.part", "terminal.json"))
        if self.shell_home:
            expected["home"].add(".appstoreconnect")
            expected["shell-parent"].add("private_keys")
        for entry in self.inventory:
            expected[entry.parent].add(entry.name)
        for role, directory in self.directories.items():
            wire.need(directory.names() == expected[role])

    def read_terminal(self, *, primary: BaseException | None = None) -> StoreLaneTerminal | None:
        self.origin()
        wire.need(self.phase == "PREPARED" and not self.failed)
        if primary is not None:
            self.remember(primary, unknown=False)
        self.phase = "READING"
        try:
            outcome = self.record._outcome()
            wire.need(outcome is not None)
            if outcome.no_target is not None:
                self.phase = "NO_TARGET"
                self._check_inventory()
                return None
            wire.need(outcome.result_integrity == "complete" and outcome.termination == "normal-exit"
                      and type(outcome.returncode) is int and outcome.returncode in (wire.SUCCESS, wire.SETTLED_FAILURE))
            assert self.root is not None and self.timing is not None
            left, identity = _read(self, self.root, "terminal.part", limit=wire.MAX_FRAME, links=2)
            right, other = _read(self, self.root, "terminal.json", limit=wire.MAX_FRAME, links=2, expected=identity)
            wire.need(left == right and identity == other)
            value = wire.decode_terminal(left, lane=self.record._lane, mode=self.mode,
                output=self.record._output, nonce=self.record._nonce, timing=self.timing,
                code=outcome.returncode, device=self.root.identity.device, uid=os.geteuid(),
                shell_home=self.shell_home,
                app_id=dict(self.environment).get("MOBILE_RELEASE_ASC_APP_ID"),
                key_id=dict(self.environment).get("MOBILE_RELEASE_ASC_KEY_ID"))
            wire.need(value.identity == identity)
            self.terminal_identity = identity
            self._observe_inventory(value.inventory)
            data = None
            if value.document is not None:
                output = Path(self.record._output)
                original_slots = len(self.slots)
                try:
                    directory = _path_directory(self, output.parent)
                    data, found = _read(self, directory, output.name, limit=wire.MAX_DOCUMENT,
                                         links=1, expected=value.document.identity)
                    wire.need(len(data) == value.document.size
                              and hashlib.sha256(data).digest() == value.document.sha256)
                except BaseException as error:
                    self.remember(error)
                    raise
                finally:
                    # Reader-only directory descriptors retire independently,
                    # including a partial parent walk or rejected output.
                    for slot in reversed(self.slots[original_slots:]):
                        slot.close()
                wire.need(not self.failed)
            self.terminal = StoreLaneTerminal(self.bindings["terminal"], 1, self.record._nonce,
                self.record._lane, self.record._output, True, True, True,
                None if value.document is None else value.document.sha256)
            self.original_outcome = outcome
            self.phase = "OBSERVED"
            self.record.publish_terminal(self.bindings["terminal"], owner=self,
                                          terminal=self.terminal, cancellation=self.guard)
            self._document_bytes = data
            return self.terminal
        except BaseException as error:
            self.remember(error)
            self.close_handles()
            self.raise_failure()

    def checked_document(self) -> bytes:
        """Exact bytes read and closed here; not independent receipt authority.

        Callers parse these bytes rather than reopening an output pathname, and
        still require the original record's final receipt gate after cleanup.
        """
        self.origin()
        wire.need(not self.failed and self.terminal is not None
                  and self.record._terminal is self.terminal
                  and type(self._document_bytes) is bytes
                  and self.phase in ("OBSERVED", "DISPOSED"))
        return self._document_bytes

    def dispose(self) -> None:
        self.origin()
        admitted = False
        try:
            wire.need(not self.failed and self.phase in ("ACQUIRED", "PREPARED", "NO_TARGET", "OBSERVED")
                      and self.guard.lifetime_ledger.verdict().contained
                      and all(self.record.dependents_settled_for(binding, owner=self, cancellation=self.guard)
                              for binding in self.bindings.values()))
            self._check_inventory()
            admitted = True
            self.phase = "DISPOSING"
            # Parents are a closed acyclic role grammar; remove leaves first.
            pending = list(self.inventory)
            while pending:
                leaves = [entry for entry in pending if not any(x.parent == entry.role for x in pending)]
                wire.need(bool(leaves))
                for entry in leaves:
                    try:
                        if entry.kind == "directory":
                            wire.need(not self.directories[entry.role].names())
                        _remove(self, self.directories[entry.parent], entry.name,
                                identity=entry.identity, directory_entry=entry.kind == "directory", links=1)
                    except BaseException as error:
                        self.remember(error)
                    # A failed child's actual surviving name prevents parent
                    # rmdir; independent sibling cleanup still proceeds.
                    pending.remove(entry)
            if self.terminal_identity is not None:
                assert self.root is not None
                try:
                    for name, links in (("terminal.json", 2), ("terminal.part", 1)):
                        _remove(self, self.root, name, identity=self.terminal_identity,
                                directory_entry=False, links=links)
                except BaseException as error:
                    self.remember(error)
            for directory in reversed(self.created):
                try:
                    wire.need(not directory.names() and directory.parent is not None)
                    _remove(self, directory.parent, directory.name,
                            identity=directory.identity, directory_entry=True)
                except BaseException as error:
                    self.remember(error)
        except BaseException as error:
            self.remember(error)
        finally:
            self.close_handles()
        if admitted and not self.failed and self.handles_closed():
            self._cleanup_complete = True
            self.phase = "DISPOSED"
        if self.failed:
            self.raise_failure()

    def close(self, *, primary: BaseException | None = None) -> None:
        self.origin()
        if primary is not None:
            self.remember(primary, unknown=False)
        self.close_handles()
        if self.failed:
            self.raise_failure()


def execution_attempt_key(intent_sha256: bytes, executed_by: Mapping[str, object], lane: str) -> str:
    """Refusal lookup only. The caller must already validate actual authority."""
    from ._command_process import _STORE_LANES

    wire.need(type(intent_sha256) is bytes and len(intent_sha256) == 32
              and type(executed_by) is dict and executed_by.keys() == _AUTHORITY_KEYS
              and all(type(x) in (str, int) for x in executed_by.values())
              and type(lane) is str and lane in _STORE_LANES)
    authority = json.dumps(executed_by, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True, allow_nan=False).encode("ascii")
    encoded = lane.encode("ascii")
    wire.need(len(authority) <= 16_384 and len(encoded) < 256)
    return hashlib.sha256(b"mrk-store-attempt-v1\0" + intent_sha256
        + len(authority).to_bytes(4, "big") + authority + bytes((len(encoded),)) + encoded).hexdigest()


class StoreLaneAttempt(_Owner):
    """Original-only pending-marker removal; no process or receipt authority."""

    def __init__(self, record: StoreLaneCallEvidence, cancellation: DefaultCancellation,
                 *, app_root: Path, mode: str, intent_sha256: bytes | None = None,
                 executed_by: Mapping[str, object] | None = None) -> None:
        super().__init__(record, cancellation)
        wire.need(type(mode) is str and mode in ("prepare", "execute")
                  and isinstance(app_root, Path) and wire.absolute(str(app_root)))
        self.key = (execution_attempt_key(intent_sha256, executed_by, record._lane)
                    if mode == "execute" else record._nonce.hex())
        self.app_root, self.mode = app_root, mode
        self.name = self.key + ".pending"
        self.directory: _Directory | None = None
        self.identity: wire.Identity | None = None
        self.content = (json.dumps({"version": 1, "key": self.key,
            "nonce": record._nonce.hex(), "lane": record._lane, "mode": mode,
            "output": record._output}, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
        wire.need(len(self.content) <= 8192)  # Serialize before any acquisition.
        self.phase = "NEW"
        record._bind_attempt(self, cancellation=cancellation)

    def acquire(self) -> None:
        self.origin()
        wire.need(self.phase == "NEW" and not self.record._attempted)
        self.phase = "ACQUIRING"
        writer = _FD(self)
        try:
            self.guard.check()
            store = _store_directory(self, self.app_root)
            self.directory = _private_child(self, store, "lane-attempts-v1", exclusive=False)
            number = writer.open(self.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                                 parent=self.directory.fd)
            initial = os.fstat(number)
            self.identity = _identity(initial, directory=False)
            wire.need(self.identity.mode == 0o600 and self.identity.uid == os.geteuid()
                      and self.identity.device == self.directory.identity.device and initial.st_nlink == 1)
            view = memoryview(self.content)
            while view:
                written = os.write(number, view)
                wire.need(type(written) is int and 0 < written <= len(view))
                view = view[written:]
            os.fsync(number)
            wire.need(_identity(os.fstat(number), directory=False) == self.identity)
            writer.close()
            wire.need(writer.state == "CLOSED" and not self.failed)
            observed, identity = _read(self, self.directory, self.name, limit=8192,
                                        links=1, expected=self.identity)
            wire.need(observed == self.content and identity == self.identity)
            os.fsync(self.directory.fd)
            self.phase = "PENDING"
            self.guard.check()
        except BaseException as error:
            self.remember(error)
            writer.close()
            self.close_handles()
            self.raise_failure()

    def require_absent(self) -> None:
        """A refusal probe only; an absent marker is never positive evidence."""
        self.origin()
        wire.need(self.phase == "NEW")
        self.phase = "PROBING"
        try:
            store = _store_directory(self, self.app_root)
            directory = _private_child(self, store, "lane-attempts-v1", exclusive=False)
            directory.check()
            try:
                os.stat(self.name, dir_fd=directory.fd, follow_symlinks=False)
            except FileNotFoundError:
                self.phase = "ABSENT"
            else:
                raise StoreLaneEvidenceError(attempted=False)
        except BaseException as error:
            self.remember(error)
        finally:
            self.close_handles()
        if self.failed:
            self.raise_failure()

    def _admitted_for(self, record: StoreLaneCallEvidence, files: StoreLaneFiles) -> bool:
        self.origin()
        ready = (record is self.record and record._pending_attempt is self
                 and type(files) is StoreLaneFiles and files.record is record
                 and files.app_root == self.app_root and files.mode == self.mode
                 and self.phase == "PENDING" and not self.failed
                 and self.directory is not None and self.identity is not None
                 and self.content is not None)
        if ready:
            try:
                observed, identity = _read(self, self.directory, self.name, limit=8192,
                                           links=1, expected=self.identity)
                wire.need(observed == self.content and identity == self.identity)
            except BaseException as error:
                self.remember(error)
                self.raise_failure()
        return ready

    def _receipt_closed_for(self, record: StoreLaneCallEvidence) -> bool:
        self.origin()
        return (record is self.record and record._pending_attempt is self
                and self.phase == "RETIRED" and not self.failed and self.handles_closed())

    def retire(self) -> None:
        self.origin()
        try:
            wire.need(self.phase == "PENDING" and not self.failed and self.directory is not None
                      and self.identity is not None and self.content is not None
                      and self.record.verdict(cancellation=self.guard).dependents_settled
                      and self.guard.lifetime_ledger.verdict().contained)
            observed, identity = _read(self, self.directory, self.name, limit=8192,
                                        links=1, expected=self.identity)
            wire.need(observed == self.content and identity == self.identity)
            self.phase = "RETIRING"
            _remove(self, self.directory, self.name, identity=self.identity,
                    directory_entry=False, links=1)
            os.fsync(self.directory.fd)
        except BaseException as error:
            self.remember(error)
        finally:
            self.close_handles()
        if self.failed:
            self.raise_failure()
        wire.need(self.handles_closed())
        self.phase = "RETIRED"

    def close(self, *, primary: BaseException | None = None) -> None:
        self.origin()
        if primary is not None:
            self.remember(primary, unknown=False)
        self.close_handles()
        if self.failed:
            self.raise_failure()
