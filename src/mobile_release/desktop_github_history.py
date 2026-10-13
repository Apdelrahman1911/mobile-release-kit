"""Fixed History original context, owned reads and existing gh transport adapter.

No renderer callback, alternate verifier, Store path or ambient provider is accepted.
The private engine/native original must bind before any filesystem/process effect.
"""
from __future__ import annotations

import hashlib
import math
import os
import stat
import sys
import threading
import time
import zipfile
from contextlib import contextmanager
from pathlib import Path

from ._desktop_github_history_control import HistoryInput
from ._desktop_github_history_protocol import HistoryRequest, CONFIG_RELATIVE, PROVIDER_RELATIVE, require
from .build_inputs import _FD, _Directory, _file, _directory, _fd_cleanup
from .cancellation import DefaultCancellation
from .errors import ValidationError
from .github_history import HistoryBudget, GIB, MIB, _decode_json


class HistoryRefused(ValidationError):
    def __init__(self, reason: str):
        from .github_history import REFUSED, UNAVAILABLE
        require(reason in REFUSED | UNAVAILABLE)
        self.reason = reason
        super().__init__("History observation was not confirmed")


def _wire_identity(value, directory=False):
    result = {"device": str(value.st_dev), "inode": str(value.st_ino), "mode": value.st_mode,
              "uid": value.st_uid, "gid": value.st_gid}
    if not directory:
        ms, mn = divmod(value.st_mtime_ns, 1_000_000_000)
        cs, cn = divmod(value.st_ctime_ns, 1_000_000_000)
        result.update(nlink=str(value.st_nlink), bytes=str(value.st_size), mtimeSeconds=str(ms),
                      mtimeNanos=mn, ctimeSeconds=str(cs), ctimeNanos=cn, flags=getattr(value, "st_flags", 0))
    return result


class _Reader:
    """Only a borrowed original; _fd_cleanup, not this wrapper, consumes its FD."""
    def __init__(self, operation, slot, size, check):
        self.operation, self.slot, self.size = operation, slot, size
        self.check = check
        self.position = 0

    def fileno(self):
        require(self.slot.number is not None)
        return self.slot.number

    def seekable(self):
        return True

    def tell(self):
        return self.position

    def seek(self, offset, whence=os.SEEK_SET):
        self.operation.checkpoint()
        require(type(offset) is int and whence in (os.SEEK_SET, os.SEEK_CUR, os.SEEK_END))
        position = offset + (self.position if whence == os.SEEK_CUR else self.size if whence == os.SEEK_END else 0)
        require(0 <= position <= self.size)
        returned = os.lseek(self.fileno(), position, os.SEEK_SET)
        require(returned == position)
        self.position = returned
        self.operation.checkpoint()
        return returned

    def read(self, amount=-1):
        from .workflow import MAX_ZIP_DIRECTORY
        self.operation.checkpoint()
        require(type(amount) is int and amount >= -1)
        wanted = self.size - self.position if amount == -1 else min(amount, self.size - self.position)
        require(wanted <= max(MAX_ZIP_DIRECTORY, MIB))
        result = bytearray()
        while len(result) < wanted:
            self.operation.checkpoint()
            part = os.read(self.fileno(), min(65536, wanted - len(result)))
            require(bool(part))
            result.extend(part)
            self.position += len(part)
        self.operation.checkpoint()
        return bytes(result)


class HistoryOperation:
    def __init__(self, request: HistoryRequest, source: HistoryInput, guard: DefaultCancellation, runtime_dir: str):
        require(type(request) is HistoryRequest and type(source) is HistoryInput
                and type(guard) is DefaultCancellation and source.guard is guard
                and source.initial is request and source.request_returned and not source.ready_sent
                and guard._github_history_source is source and threading.current_thread() is threading.main_thread())
        self.request, self.source, self.guard = request, source, guard
        self.pid, self.thread = os.getpid(), threading.current_thread()
        self.budget = source.budget
        self.root = Path(request.native["projectRoot"])
        self.work = Path(request.native["workRoot"])
        self.provider = Path(runtime_dir) / PROVIDER_RELATIVE
        require(type(runtime_dir) is str and Path(runtime_dir).is_absolute())
        self.slots, self.live = [], set()
        self.directories, self.sources, self.created = [], [], []
        self.current_child = None
        self.child_count = 0
        self.dispatched = False
        self.unknown = self.cleaning = self.closed = False
        self.iterators = self.child_reserved = 0
        self.iterator_records = []
        self.token = None
        self.capture_total = 0
        self.command_capture = None
        self.optional_active = False
        self.final_observation = None
        self.identity_complete = False
        self.parsed = {}
        self.config = None
        self._download_size = None
        self._output_record = self._output_parent = None
        source.bind_operation(self)

    def require_owner(self, cancellation=None):
        require(type(self) is HistoryOperation and self.pid == os.getpid()
                and self.thread is threading.current_thread() and self.thread is threading.main_thread()
                and self.source.operation is self and self.source.guard is self.guard
                and (cancellation is None or cancellation is self.guard))
        self.guard._check_owner()

    def checkpoint(self):
        self.require_owner()
        raw = time.clock_gettime_ns(self.source.raw_clock)
        if self.cleaning:
            require(time.monotonic() < self.cleanup_end() and raw < self.source.raw_hard_end)
            self.guard._poll_edit_stop()
        else:
            self.guard.check()
            if raw >= self.source.raw_work_end or time.monotonic() >= self.source.work_end:
                self.source.stop("timed-out")
                self.guard.check()
        require(not self.unknown and not self.guard.lifetime_ledger.fatal)

    def cleanup_end(self):
        self.require_owner()
        first = self.source.first_failure
        return min(self.source.hard_end, self.source.work_end + 10,
                   math.inf if first is None else first + 10)

    def _unknown(self, error):
        self.unknown = True
        self.source.failure_observed()
        self.guard._abort(error)

    def register_descriptor(self, slot):
        self.checkpoint()
        require(type(slot) is _FD and slot.guard is self.guard and slot not in self.live)
        self.budget.check_descriptors(self.request.native["parentDescriptorReservation"],
            len(self.live) + self.iterators + self.child_reserved + 3, 1)
        self.budget.claim_originals(1)
        self.slots.append(slot)  # Retain before the actual acquisition.
        self.live.add(slot)

    def retired_descriptor(self, slot):
        self.require_owner()
        require(slot in self.live and slot.close_state == "CLOSED" and slot.number is None)
        self.live.remove(slot)

    def _directory(self, path, *, retain=False):
        self.checkpoint()
        require(type(path) is Path or isinstance(path, Path))
        require(path.is_absolute() and len(path.parts) <= 64
                and len(str(path).encode("utf-8")) <= 4096 and ".." not in path.parts)
        owner = _Directory(path, self.guard, system_root_aliases=True)
        if retain:
            self.directories.append(owner)
        try:
            owner.acquire()
            if path.is_relative_to(self.work):
                if retain and path == self.work:
                    require(_wire_identity(os.fstat(owner.fd), True) == self.request.native["workIdentity"])
                else:
                    self._check_work_directory(owner)
            self.checkpoint()
            return owner
        except BaseException:
            owner.close()
            raise

    def _allowed(self, path):
        path = Path(path)
        require(path.is_absolute() and ".." not in path.parts)
        require(path == self.root / CONFIG_RELATIVE or path == self.provider or path.is_relative_to(self.work))
        return path

    def _created_original(self, path, directory):
        row = next((r for r in self.created if r["path"] == path and r["state"] != "retired"), None)
        require(row is not None and row["state"] == "owned" and row["directory"] is directory)
        return row["identity"]

    def _check_work_directory(self, parent):
        """Bind a fresh chain to retained work and every known-created ancestor.

        No per-node original is reopened into authority: the fresh descriptors
        must equal the immutable identities captured by our actual creates.
        Directory mtime/ctime are not stable during our own child effects.
        """
        try:
            work = next((d for d in self.directories if d.lexical_path == self.work), None)
            require(work is not None and parent.lexical_path.is_relative_to(self.work))
            work.check()
            parent.check()
            parts = parent.lexical_path.relative_to(self.work).parts
            prefix = len(work.bindings)
            require(len(parent.bindings) == prefix + len(parts)
                    and [(name, identity) for _, name, identity in parent.bindings[:prefix]]
                    == [(name, identity) for _, name, identity in work.bindings]
                    and parent.alias == work.alias)
            current = self.work
            for slot, part in zip(parent.slots[prefix:], parts):
                current /= part
                require(_wire_identity(os.fstat(slot.number), True) == self._created_original(current, True))
        except BaseException as error:
            self._unknown(error)
            raise

    def _read_original(self, path, parent):
        """Return only the exact already-admitted or completed output identity."""
        try:
            record = next((r for r in self.sources if r[0].lexical_path / r[1] == path), None)
            if record is not None:
                original_parent, name, original_slot, identity = record
                original_parent.check()
                parent.check()
                require([(name, value) for _, name, value in parent.bindings]
                        == [(name, value) for _, name, value in original_parent.bindings]
                        and parent.alias == original_parent.alias
                        and original_slot.number is not None
                        and _wire_identity(os.fstat(original_slot.number)) == identity
                        and _wire_identity(os.stat(name, dir_fd=original_parent.fd, follow_symlinks=False)) == identity)
                return identity
            require(path.is_relative_to(self.work))
            self._check_work_directory(parent)
            return self._created_original(path, False)
        except BaseException as error:
            self._unknown(error)
            raise

    @contextmanager
    def reader(self, path, maximum=GIB):
        path = self._allowed(path)
        parent = self._directory(path.parent)
        slot = _FD(self.guard)
        try:
            with _fd_cleanup(slot):
                number = slot.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent.fd)
                observed = os.fstat(number)
                require(stat.S_ISREG(observed.st_mode) and observed.st_nlink == 1 and 0 <= observed.st_size <= maximum)
                identity = self._read_original(path, parent)
                def check_original():
                    self.checkpoint()
                    try:
                        require(self._read_original(path, parent) == identity
                                and _wire_identity(os.fstat(number)) == identity
                                and _wire_identity(os.stat(path.name, dir_fd=parent.fd, follow_symlinks=False)) == identity)
                        parent.check()
                    except BaseException as error:
                        self._unknown(error)
                        raise
                check_original()  # BEFORE any bytes or metadata reach a caller.
                try:
                    yield _Reader(self, slot, observed.st_size, check_original)
                finally:
                    # Parser failure alone is not failed custody; every actual
                    # read still has a same-original POST and consuming close.
                    check_original()
        finally:
            parent.close()

    def file_stat(self, path):
        with self.reader(path) as reader:
            return os.fstat(reader.fileno())

    def file_sha(self, path):
        digest = hashlib.sha256()
        with self.reader(path) as reader:
            while reader.position < reader.size:
                digest.update(reader.read(min(65536, reader.size - reader.position)))
        return digest.hexdigest()

    def read_json(self, path, maximum=MIB):
        with self.reader(path, min(maximum, MIB)) as reader:
            # Prospective decode quote before allocating actual complete input.
            self.budget.reserve_decode(reader.size)
            raw = reader.read(reader.size)
        value = self.decode(raw, preclaimed=True)
        require(type(value) is dict and len(self.parsed) < 128)
        self.parsed[id(value)] = (value, hashlib.sha256(raw).hexdigest())
        return value

    def decode(self, raw, *, preclaimed=False):
        self.checkpoint()
        # _decode_json owns its own claim; preclaimed reads use the same claim
        # through a reserved-decode operation, never a separate reset budget.
        if preclaimed:
            return self.budget.decode_reserved(raw)
        return _decode_json(raw, self.budget)

    def load(self, loader, path):
        from . import provenance as p
        require(loader in (p.load_operation_intent, p.load_candidate_manifest, p.load_release_receipt, p.load_store_receipt))
        value = self.read_json(path)
        if loader is p.load_operation_intent:
            p.validate_operation_intent(value)
        elif loader is p.load_candidate_manifest:
            p.validate_evidence_document(value)
            require(value.get("documentType") == "candidate-manifest")
        elif loader is p.load_release_receipt:
            p.validate_evidence_document(value)
            require(value.get("documentType") == "store-receipt")
        else:
            p._validate_json_value(value)
        return value

    def source_post(self):
        self.checkpoint()
        for directory in self.directories:
            directory.check()
        for parent, name, slot, identity in self.sources:
            require(slot.number is not None and _wire_identity(os.fstat(slot.number)) == identity
                    and _wire_identity(os.stat(name, dir_fd=parent.fd, follow_symlinks=False)) == identity)
        self.checkpoint()

    def admit(self):
        from .config import ReleaseConfig
        from .darwin_memory import sampled_free_bytes, DarwinMemoryCleanupUnknown, DarwinMemoryUnavailable
        require(not self.sources and not self.directories and self.config is None)
        root = self._directory(self.root, retain=True)
        require(_wire_identity(os.fstat(root.fd), True) == self.request.native["rootIdentity"])
        work = self._directory(self.work, retain=True)
        require(_wire_identity(os.fstat(work.fd), True) == self.request.native["workIdentity"])
        require(self.names(work.fd, 0) == [])
        for path, expected, digest, maximum, protected in (
            (self.root / CONFIG_RELATIVE, self.request.native["configIdentity"], self.request.context.config_sha256, 512 * 1024, False),
            (self.provider, self.request.native["provider"]["identity"], self.request.native["provider"]["sha256"], 128 * MIB, True)):
            parent = self._directory(path.parent, retain=True)
            if protected:
                for ancestor in parent.slots:
                    identity = os.fstat(ancestor.number)
                    require(identity.st_uid == 0 and identity.st_gid == 0 and identity.st_mode & 0o022 == 0)
            slot = _FD(self.guard)
            # Retain the cell before open, including an interrupted return.
            record = (parent, path.name, slot, expected)
            self.sources.append(record)
            number = slot.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent.fd)
            require(_wire_identity(os.fstat(number)) == expected and int(expected["bytes"]) <= maximum)
            actual = self.file_sha(path)
            require(actual == digest)
        raw = None
        with self.reader(self.root / CONFIG_RELATIVE, 512 * 1024) as reader:
            self.budget.reserve_decode(reader.size)
            raw = reader.read(reader.size)
        data = self.decode(raw, preclaimed=True)
        # Reuse the actual configuration schema; no version/build/tool command.
        from .config import _validate_config
        _validate_config(data)
        self.config = ReleaseConfig(self.root / CONFIG_RELATIVE, self.root, data)
        if not self.config.platform_enabled(self.request.context.selection.platform):
            raise HistoryRefused("platform-disabled")
        try:
            free = sampled_free_bytes(check=self.checkpoint)
        except DarwinMemoryCleanupUnknown as error:
            self._unknown(error)
            raise
        except DarwinMemoryUnavailable:
            raise HistoryRefused("resources-unavailable") from None
        if free < 4 * GIB:
            raise HistoryRefused("resources-unavailable")
        disk = os.fstatvfs(work.fd)
        require(disk.f_bavail >= 0 and disk.f_frsize > 0)
        if disk.f_bavail * disk.f_frsize < 5 * GIB:
            raise HistoryRefused("resources-unavailable")
        # Fixed19 is a prospective ceiling, not 19 fabricated executions.
        self.budget.reserve_verifiers()
        for name in ("home", "cache", "tmp"):
            self.ensure_directory(self.work / name)
        self.source_post()

    def _close_iterator(self, record):
        self.require_owner()
        if record["state"] == "CLOSED":
            return
        require(record["state"] == "OPEN" and record["value"] is not None)
        record["state"] = "ATTEMPTED_CLOSE"
        try:
            record["value"].close()
            record["state"] = "CLOSED"
            self.iterators -= 1
        except BaseException as error:
            record["state"] = "UNKNOWN"
            self._unknown(error)
            raise

    def names(self, number, maximum):
        self.checkpoint()
        require(type(maximum) is int and 0 <= maximum <= 128)
        self.budget.check_descriptors(self.request.native["parentDescriptorReservation"],
            len(self.live) + self.iterators + self.child_reserved + 3, 1)
        self.budget.claim_originals(1)
        record = {"state": "NEW", "value": None}
        self.iterator_records.append(record)
        self.iterators += 1
        try:
            record["state"] = "ATTEMPTED_OPEN"
            record["value"] = os.scandir(number)
            record["state"] = "OPEN"
            names = []
            for entry in record["value"]:
                self.checkpoint()
                require(len(names) < maximum and type(entry.name) is str and entry.name not in names
                        and len(entry.name.encode("utf-8")) <= 255 and entry.name not in (".", ".."))
                names.append(entry.name)
            return sorted(names)
        except BaseException as error:
            self.source.failure_observed()
            if record["state"] != "OPEN":
                self._unknown(error)
            raise
        finally:
            if record["state"] == "OPEN":
                self._close_iterator(record)
            # Uncertain originals stay strongly retained; no destructor/close
            # replay is counted as known cleanup or returned capacity.

    def files(self, root, maximum):
        root = self._allowed(root)
        require(root.is_relative_to(self.work))
        files, directories, folded = {}, set(), set()
        total = 0
        pending = [(root, "", 0, None)]
        while pending:
            path, relative, depth, expected = pending.pop()
            require(depth <= 16 and len(files) + len(directories) <= 2048)
            held = self._directory(path)
            try:
                before = _directory(os.fstat(held.fd))
                require(expected is None or before == expected)
                names = self.names(held.fd, 128)
                for name in names:
                    self.checkpoint()
                    child = name if not relative else relative + "/" + name
                    require(len(child.encode("utf-8")) <= 512 and child.casefold() not in folded)
                    folded.add(child.casefold())
                    observed = os.stat(name, dir_fd=held.fd, follow_symlinks=False)
                    require(_wire_identity(observed, stat.S_ISDIR(observed.st_mode))
                            == self._created_original(path / name, stat.S_ISDIR(observed.st_mode)))
                    if stat.S_ISDIR(observed.st_mode):
                        require(child not in directories and len(directories) < 2048)
                        directories.add(child)
                        pending.append((path / name, child, depth + 1, _directory(observed)))
                    else:
                        require(stat.S_ISREG(observed.st_mode) and observed.st_nlink == 1 and len(files) < 128)
                        total += observed.st_size
                        require(0 <= observed.st_size <= GIB and total <= maximum)
                        files[child] = path / name
                require(self.names(held.fd, 128) == names and _directory(os.fstat(held.fd)) == before)
                held.check()
            finally:
                held.close()
        return files, directories

    @contextmanager
    def zip_file(self, archive):
        from .workflow import _validate_zip_source
        with self.reader(archive) as source:
            count = _validate_zip_source(source)
            source.check()  # Same original, before stdlib's directory allocation.
            source.seek(0)
            with zipfile.ZipFile(source) as stream:
                yield stream, count

    def pause(self, duration):
        require(type(duration) in (int, float) and 0 <= duration <= 2)
        end = min(self.source.work_end, time.monotonic() + duration)
        while time.monotonic() < end:
            self.checkpoint()
            time.sleep(min(0.05, max(0.0, end - time.monotonic())))

    def command(self, arguments, output, maximum, timeout):
        self.checkpoint()
        require(self.source.go_returned and type(self.token) is str and self.current_child is None
                and self.command_capture is None and self.config is not None)
        require(type(timeout) is int and timeout > 0 and arguments[0] == "gh" and len(arguments) <= 32)
        args = list(arguments)
        env = {"HOME": str(self.work / "home"), "GH_CONFIG_DIR": str(self.work / "home"),
               "XDG_CONFIG_HOME": str(self.work / "home"), "XDG_CACHE_HOME": str(self.work / "cache"),
               "TMPDIR": str(self.work / "tmp"), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
               "GH_TOKEN": self.token, "GH_HOST": "github.com", "GH_PROMPT_DISABLED": "1",
               "GH_NO_UPDATE_NOTIFIER": "1", "GH_NO_EXTENSION_UPDATE_NOTIFIER": "1", "NO_COLOR": "1",
               "MRK_HISTORY_PROVIDER_V1": "1", "MRK_HISTORY_CACHE_DIR": str(self.work / "cache")}
        if args[1:3] == ["attestation", "verify"]:
            require(output is None and len(args) == 23 and Path(args[3]).is_relative_to(self.work))
            self.budget.claim_verifier()
            maximum = MIB
        else:
            require(args[1:6] == ["api", "--hostname", "github.com", "--method", "GET"])
            env["MRK_HISTORY_API_KIND"] = "archive" if output is not None else "json"
            if output is not None:
                require(output == self.work / "download.zip" and self._download_size is not None)
                env["MRK_HISTORY_ARCHIVE_BYTES"] = str(self._download_size)
                maximum = self._download_size
            else:
                maximum = MIB
        if args[1:3] != ["attestation", "verify"]:
            self.budget.claim_call()
        self.command_capture = 0 if output is None else -1
        if output is None:
            self.budget.claim_capture(0, MIB)
        timeout = min(120, timeout, self.source.remaining_timeout(120))
        # Floor before child startup; native original end and parent's exact
        # deadline also remain authoritative if startup consumes this interval.
        env["MRK_HISTORY_REMAINING_MS"] = str(max(1, min(120000, int((self.source.work_end - time.monotonic()) * 1000))))
        args[0] = str(self.provider)
        self.source_post()
        return args, env, maximum, timeout

    def bind_child(self, child):
        from .workflow import _TransportProcess
        self.checkpoint()
        require(type(child) is _TransportProcess and child.guard is self.guard
                and child.history is self and self.current_child is None)
        self.budget.check_descriptors(self.request.native["parentDescriptorReservation"], len(self.live) + self.iterators + 3, 8)
        self.budget.claim_originals(8)  # Fixed pipe/error-pipe/selector/child-original precharge.
        self.child_reserved = 8
        self.current_child = child
        self.child_count += 1

    def capture_block(self, size, capture):
        self.checkpoint()
        require(type(size) is int and 0 <= size <= 65536 and self.current_child is not None)
        if capture:
            require(type(self.command_capture) is int and self.command_capture >= 0 and self.command_capture + size <= MIB)
            self.budget.claim_capture(size, MIB)
            self.command_capture += size
        else:
            require(self.command_capture == -1)

    def finish_child(self, child):
        self.require_owner()
        require(self.current_child is child)
        if not child.settled():
            self._unknown(ValidationError("History provider original did not settle"))
            return
        self.dispatched = self.dispatched or child.spawn_state != "NEW"
        self.current_child = None
        self.child_reserved = 0
        self.command_capture = None

    def _record(self, path, directory):
        self.checkpoint()
        path = self._allowed(path)
        require(path != self.work and path.is_relative_to(self.work) and len(self.created) < 4096
                and not any(row["path"] == path and row["state"] != "retired" for row in self.created))
        self.budget.claim_originals(1)
        row = {"path": path, "directory": directory, "state": "new", "identity": None}
        self.created.append(row)
        return row

    def ensure_directory(self, path):
        path = self._allowed(path)
        require(path.is_relative_to(self.work))
        current = self.work
        for part in path.relative_to(self.work).parts:
            current = current / part
            existing = next((r for r in self.created if r["path"] == current and r["state"] != "retired"), None)
            if existing is not None:
                require(existing["directory"] and existing["state"] == "owned")
                continue
            parent = self._directory(current.parent)
            row = self._record(current, True)
            try:
                with self.guard.deferred(check_on_exit=False):
                    row["state"] = "attempted"
                    os.mkdir(current.name, 0o700, dir_fd=parent.fd)
                    row["identity"] = _wire_identity(os.stat(current.name, dir_fd=parent.fd, follow_symlinks=False), True)
                    require(stat.S_IMODE(row["identity"]["mode"]) == 0o700 and row["identity"]["uid"] == os.getuid())
                    row["state"] = "owned"
                parent.check()
            except BaseException as error:
                # Preserve ambiguous create; never unlink an unbound name.
                if row["state"] != "owned":
                    self._unknown(error)
                raise
            finally:
                parent.close()

    def open_output(self, slot, path):
        require(type(slot) is _FD and slot.guard is self.guard)
        parent = self._directory(path.parent)
        row = self._record(path, False)
        try:
            row["state"] = "attempted"
            slot.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent.fd)
            row["identity"] = _wire_identity(os.fstat(slot.number))
            require(stat.S_IMODE(row["identity"]["mode"]) == 0o600)
            row["state"] = "writing"
            self._output_record = row
            self._output_parent = parent
        except BaseException as error:
            parent.close()
            if row["state"] != "writing":
                self._unknown(error)
            raise

    def finish_output(self, slot):
        row, parent = self._output_record, self._output_parent
        require(row["state"] == "writing" and slot.number is not None)
        actual = _wire_identity(os.fstat(slot.number))
        require(all(actual[k] == row["identity"][k] for k in ("device", "inode", "mode", "uid", "gid", "nlink")))
        require(_wire_identity(os.stat(row["path"].name, dir_fd=parent.fd, follow_symlinks=False)) == actual)
        row["identity"], row["state"] = actual, "owned"
        parent.check()
        parent.close()
        self._output_record = self._output_parent = None

    def write_file(self, path, blocks):
        slot = _FD(self.guard)
        with _fd_cleanup(slot):
            self.open_output(slot, path)
            try:
                for block in blocks:
                    self.checkpoint()
                    require(type(block) is bytes and len(block) <= MIB)
                    view = memoryview(block)
                    while view:
                        self.checkpoint()
                        written = os.write(slot.number, view)
                        require(type(written) is int and 0 < written <= len(view))
                        view = view[written:]
                os.fsync(slot.number)
            finally:
                self.finish_output(slot)

    def retire(self, paths):
        wanted = set(paths)
        for row in reversed(self.created):
            if row["path"] not in wanted or row["state"] == "retired":
                continue
            self.checkpoint()
            if row["state"] == "new":
                row["state"] = "retired"  # No filesystem effect was entered.
                continue
            require(row["state"] == "owned")
            parent = self._directory(row["path"].parent)
            try:
                observed = os.stat(row["path"].name, dir_fd=parent.fd, follow_symlinks=False)
                identity = _wire_identity(observed, row["directory"])
                require(identity == row["identity"])
                with self.guard.deferred(check_on_exit=False):
                    row["state"] = "retiring"
                    if row["directory"]:
                        os.rmdir(row["path"].name, dir_fd=parent.fd)
                    else:
                        os.unlink(row["path"].name, dir_fd=parent.fd)
                    row["state"] = "retired"
                parent.check()
            except BaseException as error:
                self._unknown(error)
                raise
            finally:
                parent.close()

    @contextmanager
    def comparison(self):
        self.checkpoint()
        require(not self.optional_active)
        self.optional_active = True
        path = self.work / "comparison"
        self.ensure_directory(path)
        try:
            yield str(path)
        except BaseException:
            self.source.failure_observed()
            raise
        finally:
            # If work stopped, final cleanup owns these exact existing records;
            # never acquire a new scope/clock or erase a pending comparison.
            if sys.exc_info()[0] is None:
                self.retire([row["path"] for row in self.created if row["path"].is_relative_to(path)])
                self.optional_active = False

    def download(self, github, artifact, destination):
        from .workflow import _extract_zip
        self.checkpoint()
        size = artifact["size_in_bytes"]
        require(type(size) is int and 0 < size <= GIB and self._download_size is None)
        self.budget.claim_download(size)
        self.ensure_directory(destination)
        archive = self.work / "download.zip"
        self._download_size = size
        try:
            github.transport.run(["gh", "api", "--hostname", "github.com", "--method", "GET",
                github._path(f"actions/artifacts/{artifact['id']}/zip")], output=archive,
                maximum=size, timeout=120, cancellation=self.guard, history=self)
            require(self.file_stat(archive).st_size == size and "sha256:" + self.file_sha(archive) == artifact["digest"])
            _extract_zip(archive, destination, GIB, cancellation=self.guard, history=self)
        except BaseException:
            self.source.failure_observed()
            raise
        finally:
            self._download_size = None
            if sys.exc_info()[0] is None:
                self.retire([archive])
        return destination

    def capture_final(self, root, stage, artifact, proof, intent, receipt, candidate):
        self.checkpoint()
        selected = self.request.context.selection
        require(self.final_observation is None and stage == selected.stage
                and proof["producer"]["runId"] == selected.run_id
                and proof["producer"]["attempt"] == selected.attempt)
        def digest(value):
            record = self.parsed.get(id(value))
            require(record is not None and record[0] is value)
            return record[1]
        self.final_observation = {
            "artifactId": str(artifact["id"]), "artifactSha256": artifact["digest"][7:],
            "artifactName": artifact["name"], "producerJobId": proof["jobId"],
            "producedBy": receipt["producedBy"], "authorizedBy": intent["authorizedBy"],
            "candidateSource": intent["candidateSource"], "operationSource": intent["operationSource"],
            "version": {"name": intent["version"]["marketing"], "build": intent["version"]["build"]},
            "applicationId": intent["application"]["id"], "outcome": receipt["outcome"],
            "candidateManifestSha256": digest(candidate), "operationIntentSha256": digest(intent),
            "receiptSha256": digest(receipt), "provenanceSha256": digest(proof)}

    def authenticated_identity(self, github, kind):
        require(kind in ("account", "repository"))
        self.budget.claim_auth_read()
        endpoint = "user" if kind == "account" else "repos/" + self.request.context.repository
        raw = github.transport.run(["gh", "api", "--hostname", "github.com", "--method", "GET",
            "-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: 2022-11-28", endpoint],
            cancellation=self.guard, history=self)
        value = self.decode(raw)
        require(type(value) is dict and type(value.get("id")) is int and value["id"] > 0)
        expected = self.request.context.account_id if kind == "account" else self.request.context.repository_id
        if str(value["id"]) != expected or kind == "repository" and value.get("full_name") != self.request.context.repository:
            raise HistoryRefused("target-changed")

    def run(self, token):
        from .workflow import GitHub
        self.checkpoint()
        require(self.source.go_returned and type(token) is str and self.token is None)
        self.token = token
        github = GitHub(self.request.context.verifier_context(), cancellation=self.guard, history=self)
        self.authenticated_identity(github, "account")
        self.authenticated_identity(github, "repository")
        pending = None
        try:
            self._observe(github)
        except HistoryRefused as error:
            pending = error
        # Both positive and delivered known-negative observations bind the
        # SAME actual identities after all their work. Unknown/timeout failures
        # do not start more calls and cannot be promoted into a DATA negative.
        self.authenticated_identity(github, "repository")
        self.authenticated_identity(github, "account")
        self.source_post()
        self.identity_complete = True
        self.token = None
        if pending is not None:
            raise pending
        return self.final_observation

    def _observe(self, github):
        from .workflow import Verifier, artifact_name
        selected = self.request.context.selection
        # Observe this exact historical attempt, never latest/current-job policy.
        observed = github.json(github._path(f"actions/runs/{selected.run_id}/attempts/{selected.attempt}"))
        require(type(observed) is dict and type(observed.get("id")) is int and str(observed["id"]) == selected.run_id
                and type(observed.get("run_attempt")) is int and observed["run_attempt"] == selected.attempt)
        name = artifact_name(selected.stage, selected.platform, "evidence")
        rows = github.pages(f"actions/runs/{selected.run_id}/artifacts", "artifacts")
        matched = [row for row in rows if row.get("name") == name]
        require(len(matched) <= 1)
        if not matched:
            raise HistoryRefused("artifact-missing")
        require(type(matched[0].get("expired")) is bool)
        if matched[0]["expired"]:
            raise HistoryRefused("artifact-expired")
        # Reuse the same actual list snapshot and existing service schema.
        github._artifacts[selected.run_id] = rows
        artifact = github.artifact(selected.run_id, name)
        require(artifact is not None)
        root = github.download(artifact, self.work / "primary")
        Verifier(github, allow_current=False).final(root, selected.stage, artifact=artifact)
        require(self.final_observation is not None)

    def cleanup(self):
        self.require_owner()
        if self.closed:
            return
        self.cleaning = True
        self.token = None
        first = None
        def action(call):
            nonlocal first
            try:
                call()
            except BaseException as error:
                if first is None:
                    first = error
                self._unknown(error)
        # An unresolved actual child is never reconstructed or replaced.
        if self.current_child is not None:
            child = self.current_child
            action(child.cleanup)
            action(child.release_settled)
            if child.settled():
                self.dispatched = self.dispatched or child.spawn_state != "NEW"
                self.current_child, self.child_reserved, self.command_capture = None, 0, None
        if not self.unknown:
            action(self.source_post)
        if not self.unknown:
            action(lambda: self.retire([row["path"] for row in self.created]))
        # Only source descriptors/handles have independent close authority even
        # after a namespace/retirement failure; no retry of consuming unknowns.
        if self._output_parent is not None:
            action(self._output_parent.close)
            self._output_parent = None
        for record in self.iterator_records:
            if record["state"] == "OPEN":
                action(lambda record=record: self._close_iterator(record))
        for slot in reversed(self.slots):
            if slot.close_state == "NOT_ATTEMPTED":
                action(slot.close)
        for directory in reversed(self.directories):
            action(directory.close)
        self.closed = not self.unknown and not self.live and self.iterators == 0 and self.current_child is None
        require(self.closed)
        if first is not None:
            raise first
