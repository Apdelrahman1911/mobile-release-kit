"""Read an anchored iOS candidate in place; no build, Store or signing claim."""
from __future__ import annotations
from contextlib import contextmanager
import os
from pathlib import Path
import stat
from uuid import UUID
from .build_inputs import _FD, _attempt_all
from .checked_files import _Node, _Policy
from .local_candidate_bundle import CandidateBundleReview, CandidateBundleError, MANIFEST, MANIFEST_BYTES, need
from .local_ios_candidate_bundle import manifest_data, summary_data, archive_digest
from .ios_artifacts import MAX_DEPTH, MAX_FILE_BYTES, CHUNK, _tree, _copy_file

CONTROL_BYTES = 32 * 1024 * 1024
READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
            getattr(value, 'st_flags', 0))


class IOSCandidateBundleReview(CandidateBundleReview):
    def __init__(self, owner, **binding):
        from .local_release_history import LocalHistoryRun
        from .local_store_prepare import LocalStorePrepareRun
        need(owner.request.context.get('platform') == 'ios' and
             (type(owner) is LocalHistoryRun and owner.request.context['action'] in {'review-inputs','review-prepared'}
              or type(owner) is LocalStorePrepareRun and owner.request.context['operation']=='local-store-prepare'))
        super().__init__(owner, **binding)
        self.archive = self.export = None
        self.roots = {}; self.tree_slots = []; self.tree_iterators = []
        self.bindings = {}; self.walking = False; self.tree_reads = 0
        self.seen = self.names = 0; self.base_fds = 0

    def check(self):
        self.point()  # SAME original work clock and source lease, never 900s renewal.

    def poison(self, error):
        self.failed = True; self.owner.guard._abort(error)

    def preopen(self):
        self.point()
        need(self.base_fds + len(self.reader.descriptors) + len(self.tree_slots)
             + len(self.tree_iterators) + 1 <= 256)

    def node(self, parent, name, *, directory=False, maximum=None, private=False):
        self.preopen(); before = self.reader._stat(parent.slot, name)
        self.shape(before, directory=directory, maximum=maximum, private=private)
        slot = self.reader._open(name, parent=parent.slot, directory=directory)
        node = _Node(slot, parent.slot, name, parent.canonical / name, before, directory)
        self.reader.nodes.append(node); self.point()
        need(identity(before) == identity(os.fstat(self.reader._number(slot))))
        return node

    def shape(self, value, *, directory=False, maximum=None, private=False):
        parent = os.fstat(self.reader._number(self.parent))
        need((stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode))
             and value.st_uid == os.getuid() == os.geteuid() == parent.st_uid
             and value.st_gid == os.getgid() == os.getegid() == parent.st_gid
             and value.st_dev == parent.st_dev and not getattr(value, 'st_flags', 0)
             and (directory or value.st_nlink == 1)
             and (maximum is None or 0 <= value.st_size <= maximum))
        if private: need(stat.S_IMODE(value.st_mode) == (0o700 if directory else 0o600))
        else: need(value.st_mode & 0o7022 == 0)

    def roster(self, node, expected):
        self.point(); need(self.iterator is None and self.scan_state in {'new', 'closed'})
        self.preopen(); self.scan_state = 'acquiring'
        try:
            self.iterator = os.scandir(self.reader._number(node.slot)); self.scan_state = 'open'
            names = []
            for entry in self.iterator:
                self.point(); need(len(names) < len(expected)); names.append(entry.name)
            need(len(names) == len(expected) and set(names) == set(expected))
        finally:
            if self.iterator is not None:
                original, self.iterator = self.iterator, None; self.scan_state = 'closing'
                try: need(original.close() is None)
                except BaseException as error:
                    self.scan_state = 'unknown'; self.poison(error); raise
                self.scan_state = 'closed'
            elif self.scan_state == 'acquiring':
                self.scan_state = 'unknown'; self.poison(CandidateBundleError())
        self.point()

    def _scan(self):
        parent = next(n for n in self.reader.nodes if n.directory and n.slot is self.parent)
        self.roster(parent, {'archive.xcarchive', 'export', MANIFEST, 'store-metadata.zip', 'validation-report.json'})
        self.roster(self.export, {self.value['files'][0]['fileName'][7:]})
        for node in (self.archive, self.export):
            need(identity(os.fstat(self.reader._number(node.slot))) == self.roots[node.name])

    def acquire(self):
        self.point(); root = self.owner.root
        from .local_store_prepare import LocalStorePrepareRun
        self.base_fds = (self.owner.quote['tree_base'] if type(self.owner) is LocalStorePrepareRun else
            len(root.parts) + 1 + len(Path(self.owner.request.native['home']).parts) + 5 + 6)
        # Root walk, manifest/archive/export/three file originals, max64
        # nested directories plus one leaf and iterator, all coexist.
        need(self.base_fds + len(root.parts) + 3 + 1 + 6 + MAX_DEPTH + 2 <= 256)
        path = root / '.mobile-release/desktop-ios-archive' / UUID(self.operation_id).hex / MANIFEST
        self.manifest = self.reader.acquire(path, _Policy(False, 1, MANIFEST_BYTES), None)
        self.parent = self.manifest.parent
        ancestors = [n for n in self.reader.nodes if n.directory]
        need(len(ancestors) >= 3)
        for node in ancestors[-3:]: self.shape(node.observed, directory=True, private=True)
        self._shape(self.manifest, MANIFEST_BYTES)
        raw = self._hash(self.manifest, self.expected, capture=True)
        self.value = manifest_data(raw, operation_id=self.operation_id, enrollment=self.enrollment, pending=self.pending)
        need(2048 * self.value['archive']['entries'] + 2 * CHUNK <= CONTROL_BYTES)
        parent = next(n for n in self.reader.nodes if n.directory and n.slot is self.parent)
        self.archive = self.node(parent, 'archive.xcarchive', directory=True)
        self.export = self.node(parent, 'export', directory=True)
        self.roots = {n.name: identity(n.observed) for n in (self.archive, self.export)}
        self._scan()
        for index, row in enumerate(self.value['files']):
            node = self.node(self.export if index == 0 else parent,
                row['fileName'][7:] if index == 0 else row['fileName'],
                maximum=(4 << 30, 512 << 20, 65536)[index], private=index != 0)
            self.members.append(node); need(node.observed.st_size == row['bytes'])
            self._hash(node, row['sha256'])
        self.tree(); self._scan(); return self

    def row(self, number):
        if number == self.reader._number(self.archive.slot): return ('', self.archive.observed)
        values = [v for v in self.tree_slots if v[0].number == number]
        need(len(values) == 1); return values[0][1], values[0][2]

    @contextmanager
    def descriptor(self, path, flags, *, parent=None):
        self.point(); need(self.walking)
        if parent is None:
            need(path == self.archive.canonical and flags == READ | os.O_DIRECTORY)
            yield self.reader._number(self.archive.slot)
            self.point(); return
        relative, _ = self.row(parent)
        need(type(path) is str and '/' not in path and '\\' not in path and path not in {'', '.', '..'})
        relative = f'{relative}/{path}' if relative else path
        self.preopen(); slot = _FD(self.owner.guard); row = [slot, relative, None]
        self.tree_slots.append(row)
        try:
            number = slot.open(path, flags, dir_fd=parent); observed = os.fstat(number); row[2] = observed
            self.shape(observed, directory=bool(flags & os.O_DIRECTORY), maximum=None if flags & os.O_DIRECTORY else MAX_FILE_BYTES)
            need(identity(observed) == identity(os.stat(path, dir_fd=parent, follow_symlinks=False)))
            if self.tree_reads == 1:
                need(relative not in self.bindings); self.bindings[relative] = identity(observed)
            else: need(self.bindings.get(relative) == identity(observed))
            yield number
            self.point(); need(identity(os.fstat(number)) == identity(observed)
                == identity(os.stat(path, dir_fd=parent, follow_symlinks=False)))
        except BaseException as error:
            self.poison(error); raise
        finally:
            try:
                slot.close(); need(slot.close_state == 'CLOSED'); self.tree_slots.remove(row)
            except BaseException as error:
                self.poison(error); raise

    @contextmanager
    def entries(self, number):
        self.point(); need(self.walking); prefix, _ = self.row(number); self.preopen()
        row = [None, 'ACQUIRING']; self.tree_iterators.append(row)
        try:
            row[0] = os.scandir(number); row[1] = 'OPEN'
            def selected():
                for entry in row[0]:
                    self.point(); relative = f'{prefix}/{entry.name}' if prefix else entry.name
                    self.seen += 1; self.names += len(relative.encode('utf-8'))
                    need(self.seen <= self.value['archive']['entries']
                         and 2048 * self.seen + 12 * self.names + 2 * CHUNK <= CONTROL_BYTES)
                    yield entry
            yield selected()
        except BaseException as error:
            self.poison(error); raise
        finally:
            if row[1] == 'OPEN':
                row[1] = 'CLOSING'
                try: need(row[0].close() is None)
                except BaseException as error:
                    row[1] = 'UNKNOWN'; self.poison(error); raise
                row[1] = 'CLOSED'; self.tree_iterators.remove(row)
            elif row[1] != 'CLOSED': self.poison(CandidateBundleError())

    def copy_file(self, number, target, budget):
        self.point(); need(self.walking and target is None and budget.deadline is self)
        _, observed = self.row(number)
        need(budget.size + observed.st_size <= self.value['archive']['bytes'])
        return _copy_file(number, None, budget)

    def tree(self):
        self.point(); need(not self.walking and self.tree_reads < 2)
        self.tree_reads += 1; self.walking = True; self.seen = self.names = 0
        try:
            inventory = _tree(self.archive.canonical, deadline=self, owner=self)
            need(self.seen == len(inventory) == self.value['archive']['entries']
                 and sum(v.size for v in inventory.values() if v is not None) == self.value['archive']['bytes']
                 and archive_digest(inventory) == self.value['archive']['sha256'])
            self._scan()
        except BaseException as error:
            self.poison(error); raise
        finally: self.walking = False

    def finish(self):
        self.point(); need(len(self.members) == 3 and self.tree_reads == 1)
        self._hash(self.manifest, self.expected)
        for node, row in zip(self.members, self.value['files']): self._hash(node, row['sha256'])
        self.tree(); self._scan(); value = self.value
        summary = summary_data({'operationId': self.operation_id, 'candidateSha256': self.expected,
            'sourceCommit': value['sourceCommit'], 'sourceTree': value['sourceTree'], 'bundleId': value['bundleId'],
            'version': {k: value['savedVersion'][k] for k in ('name', 'build')},
            'files': [dict(row) for row in value['files']], 'archive': dict(value['archive']),
            'observation': 'current-bundle-only', 'priorCreateFinality': 'not-established'})
        self.close(); need(self.tree_closed())
        # No future traversal is allowed after these actual consuming closes.
        # Retire only the now-unused name/stat table before prepared JSON reads.
        self.bindings.clear()
        return summary

    def tree_closed(self):
        return not self.tree_slots and not self.tree_iterators and not self.walking

    def close(self):
        actions = [row[0].close for row in self.tree_slots if row[0].close_state == 'NOT_ATTEMPTED']
        actions.append(super().close)
        try: _attempt_all(self.owner.guard, actions)
        finally:
            self.tree_slots = [row for row in self.tree_slots if row[0].close_state != 'CLOSED']
        need(self.tree_closed())
