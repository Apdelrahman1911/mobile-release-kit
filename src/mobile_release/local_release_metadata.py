"""Original bounded local metadata snapshot, not candidate or Store authority.

Opt in before source acquisition. The unchanged original scratch owns the ZIP;
this reader only binds its bytes to the held source's selected committed rows.
Candidate composition retains these originals through its last source POST.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import resource
import stat
import sys
import threading

from .build_inputs import FiniteScratch, _name_key
from .cancellation import CleanupScope, _mark_fork_unsafe
from .checked_files import _Reader, _Node, _directory_identity, _file_identity
from ._desktop_preflight_budget import _Iterator
from .errors import ValidationError
from .metadata import (ALLOWED_SUFFIXES, MAX_ARCHIVE_SIZE, MAX_FILE_COUNT,
                       MAX_FILE_SIZE, PLATFORM_METADATA_ROOTS)

MAX_ROWS_BYTES = 2 << 20
MAX_DIRECTORIES = 96
MAX_DEPTH = 32
MAX_FDS = 256


class LocalMetadataError(ValidationError):
    def __init__(self):
        super().__init__("Original local metadata snapshot is unavailable")


def _need(value):
    if not value:
        raise LocalMetadataError()


class LocalMetadataSource:
    """One optional same-source selection; no arbitrary reader/roster callback."""

    def __init__(self, source, *, platform="android"):
        from .local_release_source import LocalSourceObservation, _relative
        _need(type(source) is LocalSourceObservation and not source.active
              and not source.closed and source.calls == 0 and not source.readers
              and getattr(source, "_metadata_owner", None) is None)
        source._owner()
        _need(platform in {"android", "ios"})
        if platform == "ios":
            from .local_ios_candidate_source import IOSCandidateComposition
            _need(type(source._composition) is IOSCandidateComposition and source._composition.source is source)
        self.platform = platform
        self.source, self.guard = source, source.guard
        self.pid, self.thread = os.getpid(), threading.current_thread()
        self.relative = _relative(source.config.section("metadata").get("root", "release/store"))
        self.root = source.root / self.relative
        self.selected = tuple(self.root / part for part in PLATFORM_METADATA_ROOTS[self.platform])
        self.rows = None
        self.directories, self.children, self.bindings = {}, {}, {}
        self.absent = []
        self.reader = self.leaf = None
        self.iterators = []
        self.scratch = self.reservation = self.composition = None
        self.final_post = False
        self.failed = self.closed = self.active = self.used = False
        self.counters = {}
        source._metadata_owner = self  # Before original capture; no files opened.

    def owner(self):
        _need(self.pid == os.getpid() and self.thread is threading.current_thread()
              and getattr(self.source, "_metadata_owner", None) is self)

    def check(self):
        self.owner()
        _need(not self.failed and not self.closed)
        self.source._owner()  # Original endpoint and cancellation, never reset.

    def charge(self, name, amount, limit):
        self.check()
        old = self.counters.get(name, 0)
        _need(type(amount) is int and 0 <= amount and old <= limit - amount)
        self.counters[name] = old + amount

    def _accept_tracked(self, source, tracked):
        self.check()
        _need(source is self.source and self.rows is None and not source.active
              and source.observed is None and source.calls == 6)
        prefixes = tuple((self.relative + "/" + part + "/").encode("utf-8")
                         for part in PLATFORM_METADATA_ROOTS[self.platform])
        rows = {}
        for index, (name, (mode, blob)) in enumerate(tracked.items()):
            if index % 64 == 0:
                self.check()
            if not name.startswith(prefixes):
                continue
            self.charge("rows", 1, MAX_FILE_COUNT)
            self.charge("row-bytes", 4 * len(name) + 512, MAX_ROWS_BYTES)
            path = self.source.root / name.decode("utf-8", "strict")
            relative = path.relative_to(self.root)
            _need(mode == b"100644" and len(relative.parts) <= MAX_DEPTH
                  and not any(ord(char) < 32 for char in relative.as_posix()))
            if path.name != ".gitkeep":
                _need(not any(part.startswith(".") for part in relative.parts)
                      and path.suffix.lower() in ALLOWED_SUFFIXES)
            rows[path] = blob
        # These are the only permissible selected-tree directories. Reject
        # empty/untracked additions rather than guessing which ones to ignore.
        planned = set()
        for path in (self.root, *rows):
            parent = path if path == self.root else path.parent
            while parent != self.source.root:
                if parent not in planned:
                    self.charge("directory-rows", 1, MAX_DIRECTORIES)
                    self.charge("row-bytes", 4 * len(os.fsencode(parent)) + 256, MAX_ROWS_BYTES)
                    planned.add(parent)
                parent = parent.parent
        self.rows, self.planned = rows, tuple(sorted(planned, key=lambda p: (len(p.parts), p)))

    def _scratch_new(self, scratch):
        self.check()
        _need(self.source.active and self.rows is not None and self.reservation is None
              and type(scratch) is FiniteScratch and scratch.cancellation is self.guard
              and scratch.layout == "store-metadata" and not scratch.created
              and not scratch.active and not scratch.claimed and not scratch.parent.slots
              and scratch._local_metadata_owner is None)

    def _reserve(self, scratch, total, directories):
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        _need(total <= MAX_FDS and (soft == resource.RLIM_INFINITY or soft >= MAX_FDS))
        row_bytes = self.counters.get("row-bytes", 0)
        zip_bound = MAX_ARCHIVE_SIZE + 2 * row_bytes + 512 * len(self.rows) + 65536
        _need(zip_bound <= scratch._spec("metadata").limit)
        # Four composed censuses (initial, publication, seventh and eighth Git
        # POST), including excluded .gitkeep rows. Quote before build, not ZIP.
        passes = 4 if self.composition is not None else 3
        # Selected root entry + root iterator exhaustion; each selected
        # directory adds its own exhaustion attempt as well as child entries.
        count, census = 2, 2048
        count += sum(any(path == root or root in path.parents for root in self.selected)
                     for path in self.planned)
        for path in (*self.planned, *self.rows):
            if any(path.parent == root or root in path.parent.parents for root in self.selected):
                count += 1
                census += 8 * len(path.name.encode("utf-8")) + 128
        _need(passes * count <= 50_000 and passes * census <= 8 * MAX_ROWS_BYTES)
        self.reservation = {"ownedDescriptors": total, "directories": directories,
            "zipBytes": zip_bound,
            "assemblyBytes": 2 * zip_bound + 2 * MAX_FILE_SIZE + 4 * row_bytes + (1 << 20)}
        self.scratch = scratch
        scratch._local_metadata_owner = self
        return dict(self.reservation)

    def reserve(self, scratch):
        """Standalone original source phase; ordinary scratch APIs unchanged."""
        self._scratch_new(scratch)
        _need(self.platform == "android" and getattr(self.source, "_composition", None) is None
              and getattr(self.guard, "_android_build_source", None) is None)
        project = self.source.project
        _need(scratch.parent.path == self.source.root / ".mobile-release"
              and project.meta.number is not None)
        source_fds = sum(len(reader.descriptors) for reader in self.source.readers)
        directories = sum(path not in self.source.directories for path in self.planned)
        scratch_fds = len(scratch.parent.path.parts) + 3
        total = len(project.directory.slots) + 1 + source_fds + directories + scratch_fds + 2 + 20 + 8
        return self._reserve(scratch, total, directories)

    def _reserve_composed(self, composition, scratch):
        from .local_release_candidate import LocalAndroidCandidateComposition, metadata_fd_quote
        self._scratch_new(scratch)
        _need(type(composition) is LocalAndroidCandidateComposition
              and self.source._composition is composition and composition.source is self.source
              and composition.metadata is self and composition.metadata_scratch is scratch)
        composition._owner()
        op = composition.run.operation
        _need(op.guard is self.guard and op.root == self.source.root
              and op.inputs is not None and all(state == "new" for state in op._roles.values())
              and scratch.parent.path == op.root / ".mobile-release" / "desktop-android-build" / op.operation_id)
        directories = sum(path not in self.source.directories for path in self.planned)
        quote = metadata_fd_quote(composition.quote, directories=directories,
                                  scratch_depth=len(scratch.parent.path.parts))
        self.composition = composition
        reservation = self._reserve(scratch, quote["total"], directories)
        composition.quote = quote
        return reservation

    def _reserve_ios(self, composition, scratch):
        from .local_ios_candidate_source import IOSCandidateComposition
        self._scratch_new(scratch)
        _need(type(composition) is IOSCandidateComposition and self.platform == "ios"
              and self.source._composition is composition and composition.source is self.source
              and composition.metadata is self and composition.metadata_scratch is scratch
              and scratch.parent.path == self.source.root / ".mobile-release")
        composition._owner()
        directories = sum(path not in self.source.directories for path in self.planned)
        self.composition = composition
        quote = composition.metadata_quote(directories, scratch)
        return self._reserve(scratch, quote, directories)

    def _scratch_parent(self, scratch):
        """After original parent acquire, BEFORE any scratch mkdir/publication."""
        self.check()
        _need(scratch is self.scratch and scratch._local_metadata_owner is self
              and self.source.active and self.reservation is not None)
        if self.composition is None or self.platform == "ios":
            if self.composition is not None:
                self.composition._metadata_cut()
            number = self.source.project.meta.number
        else:
            composition = self.composition
            composition._metadata_cut()
            files = composition.run.operation.files
            files._namespace_metadata()
            namespace = files.namespace
            from .build_inputs import _StoreNamespace
            _need(type(namespace) is _StoreNamespace and namespace is files._namespace_owner
                  and namespace.android_operation is composition.run.operation
                  and namespace.path == scratch.parent.path and not namespace.claimed)
            number = namespace.slots[-1].number
        _need(number is not None)
        scratch.parent.check()
        _need(_directory_identity(os.fstat(scratch.parent.fd)) == _directory_identity(os.fstat(number)))

    def _source_post(self, source):
        if self.composition is None:
            return
        self.check()
        _need(source is self.source and self.used and not self.final_post
              and source.calls == 8 and self.composition.metadata_snapshot is not None)
        try:
            self._post()  # Actual eighth original Git returned; no later native seam.
            self.scratch.require(self.composition.metadata_snapshot)
            self.final_post = True
        except BaseException:
            self.failed = True
            raise

    def _archive_close(self):
        # Composed readers belong to the original source scope and close after
        # its eighth-query POST, not at the provisional ZIP return.
        if self.composition is None:
            self._close()

    def _directory(self, path):
        parent = self.directories[path.parent]
        borrowed = self.source.directories.get(path)
        if borrowed is not None:
            _need(borrowed.parent is parent.slot)
            self.reader.nodes.append(borrowed)  # Check original name/FD, never own its close.
            self.directories[path] = borrowed
            return
        self.charge("held-directories", 1, self.reservation["directories"])
        info = self.reader._stat(parent.slot, path.name)
        _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
              and not info.st_mode & 0o022)
        slot = self.reader._open(path.name, parent=parent.slot, directory=True)
        node = _Node(slot, parent.slot, path.name, path, info, True)
        self.reader.nodes.append(node)  # Original fallback before fallible POST.
        self.directories[path] = node
        self.reader.terminal()

    def _names(self, node):
        self.charge("iterators", 1, 4 * (MAX_DIRECTORIES + 1))
        original = _Iterator(self)
        self.iterators.append(original)
        names, keys = set(), set()
        try:
            original.acquire(self.reader._number(node.slot))
            for entry in original:
                name = entry.name
                _need(type(name) is str and 0 < len(name) <= 255)
                self.charge("census-bytes", 8 * len(name.encode("utf-8")) + 128, 8 * MAX_ROWS_BYTES)
                key = _name_key(name)
                _need(name not in names and key not in keys and len(names) < MAX_FILE_COUNT + MAX_DIRECTORIES)
                names.add(name); keys.add(key)
            return names
        finally:
            # Original single consuming close, including acquisition UNKNOWN.
            original.close()

    def _post(self):
        self.check()
        self.source._unchanged()
        self.reader.terminal()
        root_names = self._names(self.directories[self.root])
        for selected in self.selected:
            matches = {name for name in root_names if _name_key(name) == _name_key(selected.name)}
            _need(matches == ({selected.name} if selected in self.directories else set()))
        for path, expected in self.children.items():
            _need(self._names(self.directories[path]) == expected)
        for path, identity in self.bindings.items():
            parent = self.directories[path.parent]
            _need(_file_identity(self.reader._stat(parent.slot, path.name)) == identity)
        for parent, name in self.absent:
            try:
                self.reader._stat(parent.slot, name)
            except FileNotFoundError:
                pass
            else:
                raise LocalMetadataError()
        self.reader.terminal()

    def _acquire(self):
        self.reader = _Reader(self.guard)
        # Borrow actual held ancestry. This reader closes only its OWN slots.
        self.reader.root = self.source.readers[0].root
        self.reader.nodes.extend(node for node in self.source.readers[0].nodes
            if node.directory and (node.canonical == self.source.root
                                   or node.canonical in self.source.root.parents))
        self.directories[self.source.root] = self.source.directories[self.source.root]
        for path in self.planned:
            self._directory(path)
        # Census only the selected Android subtree, not unrelated iOS/review.
        selected_dirs = {path for path in self.planned if any(path == root or root in path.parents for root in self.selected)}
        for path in selected_dirs:
            self.children[path] = {child.name for child in (*self.planned, *self.rows)
                                   if child.parent == path}
        # Metadata root's Android entry is checked as a selected name, without
        # claiming authority over unrelated platform names.
        root_node = self.directories[self.root]
        for selected in self.selected:
            if selected not in self.directories:
                try:
                    self.reader._stat(root_node.slot, selected.name)
                except FileNotFoundError:
                    self.absent.append((root_node, selected.name))
                else:
                    raise LocalMetadataError()
        self._post()
        # Initial, pre-native and final post-native census use the same known
        # roster. Reserve those passes before ZIP publication, not a cap rise.
        passes = 4 if self.composition is not None else 3
        _need(passes * self.counters.get("advances", 0) <= 50_000
              and passes * self.counters.get("census-bytes", 0) <= 8 * MAX_ROWS_BYTES)
        # Admission totals include excluded .gitkeep payload, not just ZIP rows.
        total = 0
        for path in self.rows:
            info = self.reader._stat(self.directories[path.parent].slot, path.name)
            _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                  and info.st_nlink == 1 and info.st_mode & 0o400
                  and not info.st_mode & 0o7133 and 0 <= info.st_size <= MAX_FILE_SIZE)
            total += info.st_size
            _need(total <= MAX_ARCHIVE_SIZE)
            self.bindings[path] = _file_identity(info)
        self.active = True

    def _read(self, path):
        self.check()
        _need(self.active and path in self.rows and path not in self.read_paths)
        self.reader.terminal()  # Includes borrowed directory originals, not source-file hashes.
        self.read_paths.add(path)
        parent = self.directories[path.parent]
        reader = _Reader(self.guard)
        self.leaf = reader  # Root receiver before any original open.
        reader.root = self.reader.root
        info = reader._stat(parent.slot, path.name)
        _need(_file_identity(info) == self.bindings[path])
        try:
            slot = reader._open(path.name, parent=parent.slot, directory=False)
            node = _Node(slot, parent.slot, path.name, path, info, False)
            reader.nodes.append(node)
            reader.terminal()
            body = reader.read(node)
            reader.terminal()
            actual = hashlib.sha1(b"blob " + str(len(body)).encode("ascii") + b"\0" + body).hexdigest().encode("ascii")
            _need(actual == self.rows[path])
        finally:
            reader.close()
            reader.assert_closed()
        self.leaf = None
        self.reader.terminal()
        self.check()
        return body  # Only after the original positive consuming close.

    def _close(self):
        self.owner()
        if self.closed:
            return
        self.closed = True
        first = None
        for action in ([self.leaf.close] if self.leaf is not None else []) + [
                iterator.close for iterator in reversed(self.iterators) if iterator.close_state == "new"] + ([self.reader.close] if self.reader is not None else []):
            try:
                action()
            except BaseException as error:
                if first is None:
                    first = error
        for reader in (self.leaf, self.reader):
            if reader is not None:
                try:
                    reader.assert_closed()
                except BaseException as error:
                    if first is None:
                        first = error
        if any(iterator.close_state != "closed" for iterator in self.iterators):
            first = first or LocalMetadataError()
        if first is not None:
            self.failed = True
            raise first

    def _fork_close(self):
        if self.pid == os.getpid():
            return
        # Child copies only; never call the parent's guard or retry unknown
        # iterator consumption. No live iterator reaches the fixed Git call.
        for iterator in self.iterators:
            if iterator.close_state == "closed":
                continue
            if iterator.state != "open" or iterator.close_state != "new":
                _mark_fork_unsafe()
                continue
            iterator.close_state = "unknown"
            try:
                iterator.value.close()
                iterator.close_state = "closed"
            except BaseException:
                _mark_fork_unsafe()
        for reader in (self.leaf, self.reader):
            if reader is not None:
                reader.after_fork_child()

    @contextmanager
    def _archive(self, scratch, root, platform):
        self.check()
        _need(scratch is self.scratch and self.reservation is not None and not self.used
              and type(scratch) is FiniteScratch and scratch.layout == "store-metadata"
              and scratch.cancellation is self.guard and root == self.root and platform == self.platform
              and self.source.active and scratch.active and not scratch.claimed)
        self._scratch_parent(scratch)
        self.used = True
        self.read_paths = set()
        scope = CleanupScope(self.guard, self._archive_close, owns_cancellation=False,
            fork_cleanup=self._fork_close,
            first_primary=True)
        try:
            try:
                with scope:
                    self._acquire()
                    for path in self.rows:
                        if path.name == ".gitkeep":
                            self._read(path)
                    yield tuple(sorted(path for path in self.rows if path.name != ".gitkeep"))
                    _need(self.read_paths == set(self.rows))
                    self._post()  # AFTER original _publish, before token escapes.
                    self.source.check()
                    self._post()  # Last native status may have overlapped selected-tree change.
            finally:
                scope.__exit__(*sys.exc_info())
            self.guard.check()
        except BaseException:
            self.failed = True
            raise
