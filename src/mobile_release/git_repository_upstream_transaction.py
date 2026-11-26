"""Set-upstream facet of the original local config/index transaction.

Stock Git only edits its original private copy. The native Candidate job, not
this Python facet, creates the reviewed missing directories after durable CAS.
Its bounded ACK compares the exact final directory roster before config moves.
No native mkdir authority, remote transport or cleanup-by-path is provided here.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from . import git_repository_local as local
from . import git_repository_read as read
from . import git_repository_rename as rename
from . import git_repository_upstream as upstream
from . import git_service as core
from ._desktop_git_read_protocol import identity as full_identity


def core_identity(value):
    return (value[0], value[1], value[2], value[6], value[7], value[8])


def stable_directory(before, after):
    return before[:5] == after[:5]


def directory_digest(intent, before, after):
    # Array grammar, UTF-8 and integer identities are shared with native.
    # ACK already binds request/intent; include candidate bytes here as well.
    w = intent.working
    value = ["mrk-git-upstream-directories/1",
             [intent.expected_revision, intent.expected_reference_revision, intent.expected_ref,
              intent.expected_head, intent.expected_index, intent.original_config, intent.candidate_config,
              intent.remote, intent.repository, list(intent.missing_directories), intent.config_changed,
              [list(w["root"]), w["locks"], w["scratch"], w["scratchIdentity"], w["indexIdentity"]]],
             [[p.name, list(p.identity), list(p.names)] for p in before],
             [[p.name, list(p.identity), list(p.names)] for p in after]]
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class ConfigReturned:
    original: core._Stamp
    successor: core._Stamp


class Handoff:
    def __init__(self, repository, plan, original):
        self.repository, self.plan, self.original = repository, plan, original
        self.operation_id = core._text(original.operation_id, 128)
        self.entered = self.acknowledged = False
        self.intent = None

    def check_current(self, root, action, revision):
        core._need((root, action, revision) == (self.repository.root, upstream.KIND,
                   self.plan._snapshot.public.revision), "authorization")
        self.original.check_current(root, action, revision)

    def record_intent(self, intent):
        t = self.repository._transaction
        core._need(not self.entered and type(intent) is upstream.UpstreamIntent and type(t) is UpstreamTransaction
                   and t.owner is self and t.intent is intent, "authorization")
        self.entered, self.intent = True, intent
        self.original.record_intent(intent)
        # The original worker validates the native hash while handling that
        # exact ACK, BEFORE it reports candidate_returned/source POST.
        core._need(t.directory_returned and t.directory_sha256 is not None, "authorization")
        t.check_original()
        t.session.guard_current()
        self.acknowledged = True

    def publication_ready(self):
        t = self.repository._transaction
        core._need(self.acknowledged and self.intent is t.intent and t.directory_returned, "authorization")


class UpstreamTransaction(local._LocalTransaction):
    def __init__(self, session, original, plan, owner):
        super().__init__(session, original, plan, owner)
        self.intent = self.exec_view = self.candidate = self.command_entered = None
        self.command_returned = []
        self.config_returned = None
        self.directory_returned = self.config_attempted = self.closed = False
        self.directory_sha256 = None
        self.directory_closes = []
        self.parents = plan._controls.parents
        self.working = None
        self.locked = self.closing = False

    def working_originals(self):
        git = self.session.git_dir
        rows = []
        if self.config_lock.fd is not None and not self.config_lock.closed:
            rows.append((self.config_lock.path, self.config_lock.fd))
        rows.extend((p, fd) for p, fd, _ in self.locks)
        identities = {}
        for path, fd in rows:
            held, named = full_identity(os.fstat(fd)), full_identity(path.lstat())
            core._need(held == named and held[3] == os.getuid() and held[5] == 1
                       and stat.S_ISREG(held[2]) and not held[2] & 0o7022, "stale-observation")
            identities[path.name] = held
        if not self.locked:
            return identities
        core._need(set(identities) == {"config.lock", "index.lock", "HEAD.lock"}
                   and all(v[6] == 0 and stat.S_IMODE(v[2]) == 0o600 for v in identities.values()), "authorization")
        core._need(self.scratch is not None and self.index == self.scratch / "index"
                   and self.scratch.parent == git and re.fullmatch(r"mrk-git-[a-z0-9_]{8}", self.scratch.name)
                   and self.scratch_files == {self.index: core._identity(self.index.lstat())}, "authorization")
        scratch = upstream.directory(self.scratch)
        stamp, raw = rename.regular(self.index, 1024 * 1024)
        core._need(tuple(self.session.names(self.scratch)) == ("index",) and raw == self.original.index_bytes
                   and stat.S_IMODE(scratch[2]) == 0o700, "stale-observation")
        return {"root": upstream.directory(git), "locks": [list(identities[n]) for n in ("config.lock", "index.lock", "HEAD.lock")],
                "scratch": self.scratch.name, "scratchIdentity": list(scratch),
                "indexIdentity": list(full_identity(self.index.lstat()))}

    def _root_names(self, original):
        names = set(original)
        if not self.config_lock.closed and self.config_lock.fd is not None and self.config_returned is None:
            names.add("config.lock")
        names.update(path.name for path, _, _ in self.locks)
        if self.scratch is not None and (not self.closed or self.retained):
            names.add(self.scratch.name)
        return names

    def check_controls(self):
        # During acquisition only the original transaction's already-returned
        # locks/scratch may explain the root change. No arbitrary recensus.
        for row in self.parents:
            path = self.session.git_dir / row.name
            current, names = upstream.directory(path), tuple(self.session.names(path))
            expected = self._root_names(row.names) if row.name == "." and not self.directory_returned else set(row.names)
            if row.name == "." and self.directory_returned:
                expected = set(row.names)
                if self.config_returned is not None or self.config_lock.closed:
                    expected.discard("config.lock")
                if self.closed:
                    expected -= {"index.lock", "HEAD.lock"}
                    if not self.retained:
                        expected.discard(self.scratch.name)
            root_transition = row.name == "." and (not self.locked or self.closing or self.config_returned is not None)
            core._need(names == tuple(sorted(expected)) and
                       (stable_directory(row.identity, current) if root_transition else current == row.identity),
                       "stale-observation")
        for name, stamp in self.plan._controls.leaves:
            core._need(core._read(self.session.git_dir / name, 128 * 1024)[0] == stamp, "stale-observation")

    def expected_inventory(self, inventory):
        dirs = dict(inventory.directories)
        if self.directory_returned:
            for p in self.parents:
                if p.name == "refs" or p.name.startswith("refs/"):
                    dirs[p.name] = core_identity(p.identity)
        files = list(inventory.files)
        if self.config_returned is not None:
            files = [(n, self.config_returned.successor, self.candidate) if n == "config" else (n, s, raw)
                     for n, s, raw in files]
        return read._ReferenceInventory(tuple(sorted(dirs.items())), tuple(files), inventory.forbidden, inventory.pack)

    def check_original(self):
        if not self.closed and self.config_returned is None:
            self.config_lock.check()
        for path, fd, original in self.locks:
            core._need(core._identity(path.lstat()) == original == core._identity(os.fstat(fd)), "stale-observation")
        core._need(core._read(self.session.git_dir / "index", 1024 * 1024)[0] == self.original.index_stamp,
                   "stale-observation")
        self.session.check_original()
        for path, stamp in self.original.metadata.items():
            expected = self.config_returned.successor if self.config_returned is not None and path.name == "config" else stamp
            core._need(core._read(path, 65536)[0] == expected, "stale-observation")
        core._need(self.session.operation_markers() == self.original.operations, "stale-observation")
        self.session.guard_current()

    def acquire(self):
        super().acquire()
        self.locked = True
        self.working = self.working_originals()
        self.parents = tuple(upstream.Parent(p.name, tuple(self.working["root"]) if p.name == "." else p.identity,
                                            tuple(sorted(self._root_names(p.names))) if p.name == "." else p.names)
                             for p in self.parents)
        self.check_original()
        self.exec_view = self.session.exec_view = core._FrozenGitDirectory.__new__(core._FrozenGitDirectory)
        core._FrozenGitDirectory.__init__(self.exec_view)
        frozen = self.session.frozen
        for path in sorted(frozen.directories, key=lambda p: len(p.parts)):
            destination = self.exec_view.root / path.relative_to(frozen.root)
            if destination not in self.exec_view.directories:
                destination.mkdir(mode=0o700)
                self.exec_view.directories[destination] = core._identity(destination.lstat())[:2]
        for path in frozen.files:
            name = path.relative_to(frozen.root).as_posix()
            if name != read._CONFIG_FILE:
                self.exec_view.write(name, core._read(path, 65536)[1])
        self.exec_view.write("upstream-config", self.plan._controls.raw)
        self.check_execution()

    def check_execution(self):
        core._need(self.exec_view is not None and not self.exec_view.unknown, "recovery-required")
        for path, identity in self.exec_view.directories.items():
            current = core._identity(path.lstat())
            names = {p.name for p in (*self.exec_view.files, *self.exec_view.directories) if p != path and p.parent == path}
            core._need(current[:2] == identity and stat.S_ISDIR(current[2]) and set(self.session.names(path)) == names
                       and core._identity(path.lstat()) == current, "stale-observation")
        for path, stamp in self.exec_view.files.items():
            core._need(core._read(path, 65536)[0] == stamp, "stale-observation")
        core._need(core._read(self.index, 1024 * 1024)[1] == self.original.index_bytes, "stale-observation")

    def admit_command(self, args, identity):
        core._need(self.command_entered is None and identity is None, "authorization")
        prefix = ["config", "--file", str(self.exec_view.root / "upstream-config"), "--no-includes"]
        position, additions = len(self.command_returned), self.plan._controls.additions
        expected = [*prefix, "--add", *additions[position]] if position < len(additions) else [*prefix, "--null", "--list"]
        core._need(args == expected and position <= len(additions), "authorization")
        self.check_original()
        self.check_execution()
        self.command_entered = position

    def command_did_return(self, args, result):
        position = self.command_entered
        core._need(position == len(self.command_returned) and position is not None and result.returncode == 0
                   and tuple(args) == self.session.execution_command[0], "recovery-required")
        additions = self.plan._controls.additions
        path = self.exec_view.root / "upstream-config"
        stamp, raw = rename.regular(path, upstream.MAX_CONFIG)
        if position < len(additions):
            expected = upstream.append_config(self.plan._controls.raw, additions[:position + 1])
            core._need(raw == expected and result.stdout == b"", "response-invalid")
            self.exec_view.files[path] = stamp  # Only this exact returned private config successor.
        else:
            core._need(read._configuration(result.stdout) == upstream.configured(self.original.config, additions)
                       and raw == upstream.append_config(self.plan._controls.raw, additions), "response-invalid")
            self.candidate = raw
        self.command_returned.append(position)
        self.command_entered = None
        self.check_execution()

    def prepare_candidate(self):
        prefix = ["config", "--file", str(self.exec_view.root / "upstream-config"), "--no-includes"]
        for key, value in self.plan._controls.additions:
            self.session.execute_private([*prefix, "--add", key, value])
        self.session.execute_private([*prefix, "--null", "--list"])
        p, c = self.plan, self.plan._controls
        core._need(self.working == self.working_originals() and self.candidate is not None, "stale-observation")
        self.intent = upstream.UpstreamIntent(p._snapshot.public.revision, p.reference_revision,
            p._snapshot.public.branch, p._snapshot.public.head, p._snapshot.index_stamp.digest,
            c.config.digest, core._digest(self.candidate), p.remote, p.repository, c.missing,
            self.working, bool(c.additions))
        self.check_original()

    def accept_directory_ack(self, digest):
        """Comparison called ONLY by the same worker's original ACK parser."""
        core._need(self.owner.entered and not self.directory_returned and self.intent is self.owner.intent
                   and type(digest) is str and re.fullmatch("[0-9a-f]{64}", digest), "authorization")
        before = {p.name: p for p in self.parents}
        after = []
        all_paths = upstream.parent_paths("refs/remotes/" + self.plan.remote + "/" + self.intent.expected_ref[11:])
        for name in all_paths:
            current = upstream.directory(self.session.git_dir / name)
            names = tuple(self.session.names(self.session.git_dir / name))
            children = {Path(v).name for v in self.intent.missing_directories if Path(v).parent.as_posix() == name}
            if name in before:
                prior = before[name]
                core._need(names == tuple(sorted(set(prior.names) | children))
                           and (stable_directory(prior.identity, current) if children else prior.identity == current),
                           "stale-observation")
            else:
                core._need(name in self.intent.missing_directories and names == tuple(sorted(children))
                           and current[0] == before["."].identity[0] and current[3:5] == before["."].identity[3:5]
                           and stat.S_IMODE(current[2]) == 0o700, "stale-observation")
            core._need(upstream.directory(self.session.git_dir / name) == current, "stale-observation")
            after.append(upstream.Parent(name, current, names))
        core._need(directory_digest(self.intent, self.plan._controls.parents, after) == digest, "stale-observation")
        # Retain exact final DATA only after the same native ACK comparison.
        self.parents, self.directory_sha256, self.directory_returned = tuple(after), digest, True
        self.check_original()

    def publish_config(self):
        self.owner.publication_ready()
        self.check_original()
        if not self.intent.config_changed:
            return
        core._need(not self.config_attempted and self.config_returned is None, "already-used")
        self.config_attempted = True  # Before any write/replace can lose return.
        fd, path = self.config_lock.fd, self.config_lock.path
        offset = 0
        while offset < len(self.candidate):
            count = os.write(fd, self.candidate[offset:])
            core._need(count > 0, "recovery-required")
            offset += count
        # Only the new owned replacement adopts the reviewed original mode.
        os.fchmod(fd, stat.S_IMODE(self.plan._controls.config.identity[2]))
        os.fsync(fd)
        self.config_lock.identity = core._identity(os.fstat(fd))
        self.check_original()
        before = upstream.directory(path.parent)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            core._need(full_identity(os.fstat(parent)) == before, "stale-observation")
            os.replace(path.name, "config", src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
            current = upstream.directory(path.parent)
            core._need(stable_directory(before, current) and full_identity(os.fstat(parent)) == current, "recovery-required")
        finally:
            self.directory_closes.append(parent)
            os.close(parent)
            self.directory_closes.pop()
        after, raw = rename.regular(self.session.git_dir / "config", upstream.MAX_CONFIG)
        core._need(raw == self.candidate and after.identity == core._identity(os.fstat(fd))
                   and full_identity(os.fstat(fd))[3:5] == self.working["root"][3:5], "recovery-required")
        self.config_returned = ConfigReturned(self.plan._controls.config, after)
        self.session.frozen.write(read._CONFIG_FILE, self.candidate)
        self.session.config = upstream.configured(self.original.config, self.plan._controls.additions)
        self.check_original()

    def close(self, *, preserve_scratch=False):
        if self.command_entered is not None or self.directory_closes or (self.config_attempted and self.config_returned is None):
            self.retained = self.session.repository._unknown = True
            return False
        # A sent Candidate without a returned directory ACK might have created
        # parents. No cleanup/retry can pretend the old absence is still true.
        if self.owner.entered and not self.directory_returned:
            self.retained = self.session.repository._unknown = True
            return False
        self.closing = True
        good = True
        if self.exec_view is not None and not preserve_scratch:
            self.check_execution()
            good = self.exec_view.close()
        if self.config_returned is not None:
            self.config_lock.close_claimed = self.config_lock.unknown = True
            os.close(self.config_lock.fd)
            self.config_lock.closed, self.config_lock.unknown = True, False
        good = super().close(preserve_scratch=preserve_scratch) and good
        self.closed = True
        self.retained |= preserve_scratch or not good
        if good:
            self.check_controls()
        return good
