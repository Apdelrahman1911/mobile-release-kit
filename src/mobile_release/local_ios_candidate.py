"""Original signed iOS artifact retention; neither a candidate nor Store authority.

The exact producer registers this scope before running and offers its original
archive/IPA before closing. No path, inventory, report or successful subprocess
can construct a joined handoff. Ordinary archive/recovery never opts in.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import threading
import time

from .build_inputs import _Directory, _FD, _directory, _file
from .cancellation import CleanupScope
from .config import MAX_CONFIG_BYTES, MAX_VERSION_BYTES
from .errors import ValidationError
from .ios_artifacts import MAX_DEPTH, MAX_FILES, MAX_FILE_BYTES, CHUNK, _File, _attributes

MAX_HANDOFF_FDS = 96
MAX_OWNED_FDS = 256
MAX_CONTROL_BYTES = 32 * 1024 * 1024
READ_CHUNK = 64 * 1024
READS = 3  # Capture and at most two complete subsequent reads of each artifact.
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK


class LocalIOSCandidateError(ValidationError):
    pass


def _need(value):
    if not value:
        raise LocalIOSCandidateError("Original local iOS build inputs are unavailable")


@dataclass(eq=False)
class _Original:
    slot: _FD
    parent: int
    name: str
    relative: str | None
    identity: tuple | None = None


def _producer_slots(operation):
    """Actual Python originals, counted by slot identity, not numeric FD reuse."""
    files = operation.files
    rows = [held.slot for held in files.held]
    for directory in (files.developer, files.sdk, files.system_directory, files.namespace):
        if directory is not None:
            rows.extend(directory.slots)
    project = operation.invocation._original_project
    _need(project is not None and project is operation.invocation.project_owner)
    rows.extend(project.directory.slots)
    rows.append(project.meta)
    # The account lease remains open around this cut even though its signing
    # session/material consumers closed. Its original home and locked hold are
    # two separate resources, never credited as part of session closure.
    lease = operation.signing.lease
    lease.assert_owner()
    _need(lease.locked and type(lease.home_fd) is int and type(lease.fd) is int
          and lease._hold_slot.state == "OPEN")
    # Signing/snapshot closure is separately required before using this census.
    _need(all(iterator.close_state == "CLOSED" for iterator in files.iterators))
    unique = {id(slot): slot for slot in rows}
    return 2 + sum(slot.close_state != "CLOSED" for slot in unique.values())


class LocalIOSBuildHandoff:
    def __init__(self, run):
        from .desktop_ios_archive import IOSArchiveRun
        from .ios_archive_operation import IOSArchiveOperation
        _need(type(run) is IOSArchiveRun and type(run.operation) is IOSArchiveOperation
              and run.source.signed and not run.source.recovery and run.operation.signing is not None
              and not run._run_claimed and not run._close_claimed and run.primary is None
              and getattr(run, "_local_handoff", None) is None)
        run.operation.owner()
        self.run, self.guard = run, run.guard
        self.pid, self.thread = os.getpid(), threading.current_thread()
        self.failed = self.closed = self.captured = self.producer_joined = False
        self._candidate_owner = None
        self._capturing = self._walking = self._reading = False
        self.parent = self.archive = self.export = self.ipa = None
        self.originals, self.iterators = [], []
        self._bindings = {}
        self._inventory = self._ipa_inventory = None
        self._config = self._version = self._result = None
        self._tree_reads = self._ipa_reads = self._ipa_read_bytes = 0
        self._scan_entries = self._scan_names = 0
        self._entry_limit = self._name_limit = self._fd_quote = 0
        self.control_quote = self.owned_fd_quote = 0
        run._local_handoff = self

    def _owner(self):
        _need(self.pid == os.getpid() and self.thread is threading.current_thread()
              and self.run._local_handoff is self)

    def _fail(self):
        self._owner()
        self.failed = True

    def _poison(self, error):
        self.failed = True
        self.guard._abort(error)

    def _point(self):
        self._owner()
        try:
            _need(not self.closed and not self.failed)
            self.guard.check()
            _need(time.monotonic() < self.run.source.work_end)
        except BaseException as error:
            self._poison(error)
            raise

    # Existing _tree consumes a deadline's check only. This is the SAME original
    # endpoint, not a recreated inspection owner or a renewed native timeout.
    def check(self):
        self._point()

    def _live(self):
        return ((0 if self.parent is None else sum(s.close_state != "CLOSED" for s in self.parent.slots))
                + sum(row.slot.close_state != "CLOSED" for row in self.originals)
                + len(self.iterators))

    def _preopen(self):
        self._point()
        _need(self._live() < self._fd_quote <= MAX_HANDOFF_FDS)

    def _open(self, parent, name, flags, relative=None):
        self._preopen()
        row = _Original(_FD(self.guard), parent, name, relative)
        self.originals.append(row)  # Receiver BEFORE the one original open.
        number = row.slot.open(name, flags, dir_fd=parent)
        value = os.fstat(number)
        _need((stat.S_ISDIR(value.st_mode) if flags & os.O_DIRECTORY else stat.S_ISREG(value.st_mode))
              and (flags & os.O_DIRECTORY or value.st_size <= MAX_FILE_BYTES))
        row.identity = _attributes(value)
        self._check_row(row)
        return row

    def _check_row(self, row):
        _need(row in self.originals and row.slot.close_state == "NOT_ATTEMPTED"
              and row.slot.number is not None and row.identity is not None
              and _attributes(os.fstat(row.slot.number)) == row.identity
              and _attributes(os.stat(row.name, dir_fd=row.parent, follow_symlinks=False)) == row.identity)

    def _close_row(self, row):
        try:
            row.slot.close()
            _need(row.slot.close_state == "CLOSED" and row.slot.number is None)
        except BaseException as error:
            self._poison(error)
            raise
        # Retain permanent row objects; retired traversal slots no longer retain
        # a live original. Their initial stat is in the bounded binding table.
        if row not in (self.archive, self.export, self.ipa):
            self.originals.remove(row)

    def _post(self):
        self._point()
        _need(self.parent is not None and all(row is not None for row in (self.archive, self.export, self.ipa)))
        self.parent.check()
        for row in (self.archive, self.export, self.ipa):
            self._check_row(row)

    def _capture(self, run):
        try:
            self._capture_original(run)
        except BaseException as error:
            self._poison(error)
            raise

    def _capture_original(self, run):
        from .ios_archive_operation import OriginalIOSArchive, OriginalIOSIPA
        from ._desktop_ios_archive_protocol import SIGNED_SCOPE, SIGNED_LIMITATIONS, RESPONSE_LIMIT, _encode
        self._point()
        _need(run is self.run and run._run_claimed and not run._close_claimed and run.primary is None
              and not self.captured and self.parent is None)
        op, signing = run.operation, run.operation.signing
        op.checkpoint()
        archive, ipa = op.artifact(), op.ipa()
        _need(type(archive) is OriginalIOSArchive and type(ipa) is OriginalIOSIPA
              and archive.operation is op and ipa.operation is op and op.inputs is not None
              and not op.close_claimed and op.commands_settled() and op.snapshot_closed()
              and op.files.work_disposition() == "removed" and signing.inputs_closed()
              and signing.session is not None and signing.session.closed and signing.session._disposal_complete
              and signing.session.fd is None and signing.session.native_fd is None
              and signing.lease.active is None)
        archive.check(); ipa.check(); op.check_inputs()
        inventory, ipa_inventory = archive.inventory, ipa.inventory
        _need(type(inventory) is dict and 0 < len(inventory) <= MAX_FILES and type(ipa_inventory) is _File
              and 0 < ipa_inventory.size <= MAX_FILE_BYTES)
        # Quote BEFORE copying/encoding/scanning. Includes old/new dicts, _Paths,
        # per-directory stat/sorted rows, bindings and one shared CHUNK buffer.
        count, names, size = len(inventory), 0, 0
        for name, item in inventory.items():
            self._point()
            _need(type(name) is str and 0 < len(name) <= 2048 and (item is None or type(item) is _File))
            names += len(name.encode("utf-8"))
            size += 0 if item is None else item.size
            _need(names <= MAX_CONTROL_BYTES and 0 <= size <= 8 * 1024**3)
        saved = op.inputs.saved
        config, version = saved.configuration.raw, saved.version_raw
        _need(type(config) is bytes and 0 < len(config) <= MAX_CONFIG_BYTES
              and type(version) is bytes and 0 < len(version) <= MAX_VERSION_BYTES)
        self.control_quote = 2048 * count + 12 * names + len(config) + len(version) + 2 * RESPONSE_LIMIT + CHUNK
        _need(self.control_quote <= MAX_CONTROL_BYTES)
        candidate = run._candidate
        _need(type(candidate) is dict and candidate["scope"] == SIGNED_SCOPE
              and candidate["limitations"] == list(SIGNED_LIMITATIONS)
              and candidate["entries"] == count and candidate["bytes"] == size
              and candidate["ipaBytes"] == ipa_inventory.size and candidate["pairing"] == run.pairing
              and saved.configuration.symbols_policy != "required")
        for body, key in ((config, "usedConfig"), (version, "usedVersion")):
            _need((len(body), hashlib.sha256(body).hexdigest()) ==
                  (candidate[key]["bytes"], candidate[key]["sha256"]))
        result = _encode(candidate)
        _need(len(result) <= RESPONSE_LIMIT)
        path = op.files.namespace.path
        _need(path.is_absolute() and candidate["archive"] == str(archive.path.relative_to(op.root))
              and candidate["ipa"] == str(ipa.path.relative_to(op.root)))
        # One shared namespace ancestry, three permanent roots, at most depth+1
        # child descriptors and one iterator. Alias allowance counted upfront.
        ancestry = len(path.parts) + 2
        self._fd_quote = ancestry + 3 + MAX_DEPTH + 2
        self.owned_fd_quote = _producer_slots(op) + self._fd_quote + 8
        _need(self._fd_quote <= MAX_HANDOFF_FDS and self.owned_fd_quote <= MAX_OWNED_FDS)
        op.charge("local-ios-handoff-fds", self._fd_quote, MAX_HANDOFF_FDS)
        op.charge("local-ios-handoff-control", self.control_quote, MAX_CONTROL_BYTES)
        self._entry_limit, self._name_limit = count, names
        self._inventory, self._ipa_inventory = dict(inventory), ipa_inventory
        self._config, self._version, self._result = config, version, result
        self.parent = _Directory(path, self.guard, system_root_aliases=True)
        self.parent.acquire()
        _need(len(self.parent.slots) <= ancestry and _directory(os.fstat(self.parent.fd)) ==
              _directory(os.fstat(op.files.namespace.fd)))
        self.archive = self._open(self.parent.fd, archive.original.name, _READ | os.O_DIRECTORY, "")
        self.export = self._open(self.parent.fd, ipa.directory.name, _READ | os.O_DIRECTORY)
        self.ipa = self._open(self.export.slot.number, ipa.original.name, _READ)
        for retained, original in ((self.archive, archive.original), (self.export, ipa.directory), (self.ipa, ipa.original)):
            _need(retained.identity == _attributes(os.fstat(original.slot.number)))
        self._capturing = True
        try:
            self._scan()
            for _ in self._blocks():
                pass
            archive.check(); ipa.check(); op.check_inputs(); op.checkpoint()
            self._post()
            self.captured = True
        finally:
            self._capturing = False

    @contextmanager
    def descriptor(self, path, flags, *, parent=None):
        self._point()
        _need(self._walking and flags in {_READ, _READ | os.O_DIRECTORY})
        if parent is None:
            _need(Path(path) == self.parent.path / self.archive.name and flags & os.O_DIRECTORY)
            self._post()
            yield self.archive.slot.number
            self._post()
            return
        ancestors = [row for row in self.originals if row.slot.number == parent and row.relative is not None]
        _need(len(ancestors) == 1 and type(path) is str and path not in {"", ".", ".."} and "/" not in path)
        ancestor = ancestors[0]
        self._check_row(ancestor)
        relative = f"{ancestor.relative}/{path}" if ancestor.relative else path
        _need(relative in self._inventory and (self._inventory[relative] is None) == bool(flags & os.O_DIRECTORY))
        row = None
        try:
            row = self._open(parent, path, flags, relative)
            if self._capturing:
                _need(relative not in self._bindings)
                self._bindings[relative] = row.identity
            else:
                _need(self._bindings.get(relative) == row.identity)
            yield row.slot.number
            self._point(); self._check_row(row); self._check_row(ancestor)
        finally:
            if row is not None:
                self._close_row(row)

    @contextmanager
    def entries(self, number):
        self._preopen()
        _need(self._walking and any(row.slot.number == number and row.relative is not None for row in self.originals))
        # Scandir is itself an original FD owner. Ambiguous acquisition/close
        # keeps this pre-registered row; no cleanup retries an unknown call.
        row = [None, "NEW"]
        self.iterators.append(row)
        try:
            row[1] = "ACQUIRING"
            row[0] = os.scandir(number)
            row[1] = "OPEN"
            def selected():
                for entry in row[0]:
                    self._point()
                    self._scan_entries += 1
                    self._scan_names += len(entry.name.encode("utf-8"))
                    _need(self._scan_entries <= self._entry_limit and self._scan_names <= self._name_limit)
                    yield entry
            yield selected()
        except BaseException as error:
            self._poison(error)
            raise
        finally:
            if row[1] == "OPEN":
                try:
                    row[1] = "CLOSING"
                    _need(row[0].close() is None)
                    row[1] = "CLOSED"
                    self.iterators.remove(row)
                except BaseException as error:
                    self._poison(error)
                    raise
            elif row[1] != "CLOSED":
                self._poison(LocalIOSCandidateError("Original local iOS scan did not close"))

    def copy_file(self, number, target, budget):
        from .ios_artifacts import _copy_file
        _need(target is None and self._walking and budget.deadline is self)
        rows = [row for row in self.originals if row.slot.number == number and row.relative is not None]
        _need(len(rows) == 1)
        row = rows[0]
        self._check_row(row)
        result = _copy_file(number, None, budget)  # SAME shared bounded read/hash implementation.
        self._check_row(row)
        return result

    def _scan(self):
        from .ios_artifacts import _tree
        self._post()
        _need(not self._walking and not self._reading and (self._capturing or self.producer_joined or self._candidate_ready())
              and self._tree_reads < READS)
        self._tree_reads += 1  # Failed/abandoned attempts are never refunded.
        self._scan_entries = self._scan_names = 0
        self._walking = True
        try:
            observed = _tree(self.parent.path / self.archive.name, deadline=self, owner=self)
            _need(observed == self._inventory and self._scan_entries == self._entry_limit
                  and len(self._bindings) == self._entry_limit)
            self._post()
            return observed
        except BaseException as error:
            self._poison(error)
            raise
        finally:
            self._walking = False

    def _blocks(self):
        self._post()
        _need(not self._reading and not self._walking and (self._capturing or self.producer_joined or self._candidate_ready())
              and self._ipa_reads < READS)
        self._ipa_reads += 1
        self._reading = True
        complete = False
        try:
            count, digest = 0, hashlib.sha256()
            while count < self._ipa_inventory.size:
                self._point()
                amount = min(READ_CHUNK, self._ipa_inventory.size - count)
                self._ipa_read_bytes += amount
                _need(self._ipa_read_bytes <= READS * self._ipa_inventory.size)
                body = os.pread(self.ipa.slot.number, amount, count)
                _need(len(body) == amount)
                count += amount; digest.update(body)
                yield body
            _need(not os.pread(self.ipa.slot.number, 1, count) and digest.hexdigest() == self._ipa_inventory.sha256)
            self._post()
            complete = True
        except BaseException as error:
            self._poison(error)
            raise
        finally:
            self._reading = False
            if not complete:
                self._poison(LocalIOSCandidateError("Original local iOS read was not consumed"))

    def _terminal(self, run, terminal):
        from ._desktop_ios_archive_protocol import _encode, SIGNED_CLOSE_FIELDS
        self._owner()
        _need(run is self.run)
        if self.failed or terminal["outcome"] != "complete":
            self.failed = True
            return
        try:
            self._point()
            verdict = self.guard.lifetime_ledger.verdict()
            _need(self.captured and not self._walking and not self._reading and run.primary is None
                  and run._close_claimed and run.operation.closed() and run.source.closed
                  and self.guard.handler_state == "RESTORED" and verdict.complete and verdict.cleanup_complete
                  and verdict.contained and not verdict.fatal and all(terminal["lifetime"][key] for key in SIGNED_CLOSE_FIELDS)
                  and _encode(terminal["result"]) == self._result)
            self._post()
            self.producer_joined = True
        except BaseException as error:
            self._poison(error)
            raise

    def observation(self):
        self._point()
        _need(self.producer_joined and not self._reading and not self._walking)
        try:
            self._post()
            return {"origin": "local-desktop", "scope": "retained-ios-build-inputs", "producerCoreSettled": True,
                    "outerTransportFinality": "not-established", "sourceProvenance": "not-established",
                    "freshness": "not-established", "storeAuthorized": False, "candidatePrepared": False,
                    "inspection": json.loads(self._result)}
        except BaseException as error:
            self._poison(error)
            raise

    def saved_inputs(self):
        self.observation()
        return self._config, self._version

    def archive_inventory(self):
        self.observation()
        return self._scan()  # Fresh bounded DATA, never archive path/descriptor authority.

    @contextmanager
    def ipa_blocks(self):
        self.observation()
        iterator = self._blocks()
        before = self._ipa_reads
        try:
            yield iterator
        finally:
            iterator.close()
            if self._ipa_reads != before + 1:
                self._poison(LocalIOSCandidateError("Original local iOS read was not consumed"))
        _need(not self.failed)

    def _candidate_ready(self):
        from .local_ios_candidate_create import IOSCandidateCreateRun
        owner = self._candidate_owner
        return (type(owner) is IOSCandidateCreateRun and owner.run is self.run
                and self.run._candidate_inputs is owner and owner.composition.handoff is self
                and owner.build_settled and not self.producer_joined)

    def _candidate_check(self, owner):
        _need(owner is self._candidate_owner and self._candidate_ready()
              and not owner.closed and not self._reading and not self._walking)
        self._post()

    def _candidate_inventory(self, owner):
        self._candidate_check(owner)
        return self._scan()

    def _candidate_blocks(self, owner):
        self._candidate_check(owner)
        yield from self._blocks()

    def _candidate_close(self, owner):
        from .local_ios_candidate_create import IOSCandidateCreateRun
        _need(type(owner) is IOSCandidateCreateRun and self._candidate_owner is owner
              and owner.run is self.run and owner.composition.handoff is self and owner.closing)
        self._close()

    def _close(self):
        self._owner()
        if self.closed:
            _need(not self.iterators and all(row.slot.close_state == "CLOSED" for row in self.originals)
                  and (self.parent is None or all(s.close_state == "CLOSED" for s in self.parent.slots)))
            return
        self.closed = True
        if self._reading or self._walking or not self.producer_joined and not self._candidate_ready():
            self.failed = True
        first = None
        for row in reversed(tuple(self.originals)):
            try:
                self._close_row(row)
            except BaseException as error:
                first = first or error
        if self.parent is not None:
            try:
                self.parent.close()
                _need(all(s.close_state == "CLOSED" for s in self.parent.slots))
            except BaseException as error:
                self._poison(error); first = first or error
        if self.iterators:
            error = LocalIOSCandidateError("Original local iOS scan closure is unknown")
            self._poison(error); first = first or error
        if first is not None:
            raise first

    def _fork_close(self):
        # Original _FDs are also fork registered; no parent finality is minted.
        for scan in self.iterators:
            if scan[1] == "OPEN":
                scan[1] = "CLOSING"
                scan[0].close()
                scan[1] = "CLOSED"
        for row in reversed(self.originals):
            row.slot.close()
        if self.parent is not None:
            self.parent.fork_close()


@contextmanager
def retain_ios_build_inputs(run):
    handoff = LocalIOSBuildHandoff(run)
    scope = CleanupScope(handoff.guard, handoff._close, owns_cancellation=False,
                         fork_cleanup=handoff._fork_close, first_primary=True)
    try:
        try:
            with scope:
                yield handoff
        finally:
            scope.__exit__(*sys.exc_info())
    except BaseException:
        handoff.failed = True
        raise
