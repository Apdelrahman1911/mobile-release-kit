"""Fixed metadata facet of the existing local Git index transaction.

No original command runs `branch -m`: stock Git touches only the already-owned
private execution view. Both real ref locks stay held through original closure.
The public row ACK precedes every original metadata publication. There is no
rollback, target overwrite, dropped old FD or retry after a possibly sent step.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat

from . import git_repository_rename as rename
from . import git_repository_local as local
from . import git_repository_read as read
from . import git_service as core
from .init_transaction import _rename_function


class RefLocks:
    """Portable fixture/core originals; installed callers borrow SourceBook.

    The exact two normal ref locks are not supplied to Git. Their same parent
    transition is compared, not treated as a license to reset ref inventory.
    """
    def __init__(self, root, source, target):
        core._need(core._ref(source) and core._ref(target) and source != target
                   and source.rsplit("/", 1)[0] == target.rsplit("/", 1)[0], "invalid-input")
        self.git, self.source, self.target = root / ".git", source, target
        self.parent = (self.git / source).parent
        self.paths = tuple(self.git / (value + ".lock") for value in (source, target))
        self.locks = tuple(local._ConfigLock(path) for path in self.paths)
        self.parent_before = self.parent_current = None
        self.unknown = self.closed = False

    def acquire(self):
        core._need(self.parent_before is None, "already-used")
        self.parent_before = rename.directory(self.parent)
        for lock in self.locks:
            lock.acquire()
        self.parent_current = rename.directory(self.parent)
        core._need(self.parent_current[:3] == self.parent_before[:3]
                   and self.parent_current[6:] == self.parent_before[6:], "stale-observation")
        self.check()

    def check(self):
        core._need(not self.unknown and not self.closed and self.parent_current is not None, "recovery-required")
        for lock in self.locks:
            lock.check()
        core._need(rename.directory(self.parent) == self.parent_current, "stale-observation")

    def comparison(self, inventory):
        core._need(self.parent_before is not None and self.parent_current is not None, "authorization")
        name = self.source.rsplit("/", 1)[0]
        rows = []
        for path, identity in inventory.directories:
            if path == name:
                core._need(identity in (self.parent_before[:6], self.parent_current[:6]), "stale-observation")
                identity = self.parent_before[:6]
            rows.append((path, identity))
        return read._ReferenceInventory(tuple(rows), inventory.files, inventory.forbidden, inventory.pack)

    def moved(self, receipt):
        core._need(type(receipt) is Returned and receipt.step == "ref" and receipt.parent is not None,
                   "authorization")
        current = rename.directory(self.parent)
        core._need(current == receipt.parent and current[:3] == self.parent_current[:3]
                   and current[6:] == self.parent_current[6:], "recovery-required")
        self.parent_current = current
        self.check()

    def close(self):
        if self.closed:
            return not self.unknown
        self.check()
        for lock in reversed(self.locks):
            lock.check()
            lock.close_claimed = lock.unknown = self.unknown = True
            os.unlink(lock.path)
            current = rename.directory(self.parent)
            core._need(current[:3] == self.parent_current[:3] and current[6:] == self.parent_current[6:]
                       and core._read(lock.path, 1, regular=False)[0].kind == "absent"
                       and rename.directory(self.parent) == current, "recovery-required")
            self.parent_current = current
            os.close(lock.fd)
            lock.closed, lock.unknown, self.unknown = True, False, False
        self.closed = True
        return True


class BorrowedRefLocks:
    """Only compares two native original locks; has no close/unlink route."""
    def __init__(self, root, source, target, identities, parent_before, parent_current):
        core._need(core._ref(source) and core._ref(target) and source != target
                   and source.rsplit("/", 1)[0] == target.rsplit("/", 1)[0]
                   and len(identities) == 2, "invalid-input")
        self.git, self.source, self.target = root / ".git", source, target
        self.paths = tuple(self.git / (value + ".lock") for value in (source, target))
        self.parent = self.paths[0].parent
        self.identities = identities
        self.parent_before, self.parent_current = parent_before, parent_current

    def check(self):
        for path, expected in zip(self.paths, self.identities):
            stamp, raw = core._read(path, 1)
            info = path.lstat()
            core._need(stamp.kind == "file" and not raw and stamp.identity == expected
                       and core._identity(info) == expected and info.st_uid == os.getuid()
                       and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600, "stale-observation")
        core._need(rename.directory(self.parent) == self.parent_current, "stale-observation")

    comparison = RefLocks.comparison
    moved = RefLocks.moved


@dataclass(frozen=True, slots=True, repr=False)
class Returned:
    step: str
    original: core._Stamp
    successor: core._Stamp
    parent: tuple | None = None


class Handoff:
    def __init__(self, repository, plan, original):
        self.repository, self.plan, self.original = repository, plan, original
        self.operation_id = core._text(original.operation_id, 128)
        self.entered = self.acknowledged = False
        self.intent = None

    def check_current(self, root, action, revision):
        core._need((root, action, revision) == (self.repository.root, "branch-rename", self.plan._snapshot.public.revision),
                   "authorization")
        self.original.check_current(root, action, revision)

    def record_intent(self, intent):
        transaction = self.repository._transaction
        core._need(not self.entered and type(intent) is rename.RenameIntent and transaction is not None
                   and transaction.owner is self and transaction.intent is intent, "authorization")
        self.entered, self.intent = True, intent
        self.original.record_intent(intent)
        transaction.session.guard_current()
        self.acknowledged = True

    def publication_ready(self):
        core._need(self.acknowledged and self.intent is self.repository._transaction.intent, "authorization")


class RenameTransaction(local._LocalTransaction):
    def __init__(self, session, original, plan, owner):
        super().__init__(session, original, plan, owner)
        self.intent = None
        self.exec_view = None
        self.command_entered = None
        self.command_returned = set()
        self.returns = []
        self.attempted = []
        self.directory_closes = []
        self.log_locks = {}
        self.log_parents = {name: (identity, names) for name, identity, names in plan._controls.parents}
        self.candidates = {}
        self.exclusive_rename = None
        self.closed = False

    def _done(self):
        return {row.step: row for row in self.returns}

    def expected_inventory(self, inventory):
        rows = {name: (stamp, raw) for name, stamp, raw in inventory.files}
        done = self._done()
        if "ref" in done:
            rows.pop(self.plan.source)
            rows[self.plan.target] = done["ref"].successor, (self.plan._snapshot.public.head + "\n").encode("ascii")
        for step, name in (("head", "HEAD"), ("config", "config")):
            if step in done:
                rows[name] = done[step].successor, self.candidates[name]
        return read._ReferenceInventory(inventory.directories, tuple((n, *v) for n, v in sorted(rows.items())),
                                        inventory.forbidden, inventory.pack)

    def check_controls(self):
        done = self._done()
        original = self.plan._controls
        old_log, new_log = "logs/" + self.plan.source, "logs/" + self.plan.target
        expected = {name: stamp for name, stamp, _ in original.files if name.startswith("logs/")}
        expected[new_log] = done["new-log"].successor if "new-log" in done else core._ABSENT
        if "old-log" in done:
            expected[old_log] = core._ABSENT
        if "head-log" in done:
            expected["logs/HEAD"] = done["head-log"].successor
        for name, stamp in expected.items():
            core._need(core._read(self.session.git_dir / name, 65536)[0] == stamp, "stale-observation")
        for parent, (identity, names) in self.log_parents.items():
            current_names = set(self.session.names(self.session.git_dir / parent))
            extra = {lock.path.name for step, lock in self.log_locks.items()
                     if lock.path.parent == self.session.git_dir / parent and step not in done and not lock.closed}
            expected_names = set(names) | extra
            if "new-log" in done and str(Path(new_log).parent) == parent:
                expected_names.add(Path(new_log).name)
            if "old-log" in done and str(Path(old_log).parent) == parent:
                expected_names.remove(Path(old_log).name)
            core._need(rename.directory(self.session.git_dir / parent) == identity
                       and current_names == expected_names, "stale-observation")

    def check_original(self):
        done = self._done()
        if not self.closed:
            if "config" not in done:
                self.config_lock.check()
            for path, fd, identity in self.locks:
                step = "head" if path.name == "HEAD.lock" else None
                destination = self.session.git_dir / "HEAD" if step in done else path
                core._need(core._identity(destination.lstat())[:2] == identity[:2]
                           == core._identity(os.fstat(fd))[:2], "stale-observation")
        core._need(core._read(self.session.git_dir / "index", rename.MAX_INDEX)[0] == self.original.index_stamp,
                   "stale-observation")
        self.session.check_original()
        for path, stamp in self.original.metadata.items():
            step = "head" if path == self.session.git_dir / "HEAD" else "config" if path == self.session.git_dir / "config" else None
            core._need(core._read(path, 65536)[0] == (done[step].successor if step in done else stamp), "stale-observation")
        core._need(self.session.operation_markers() == self.original.operations, "stale-observation")
        self.session.guard_current()

    def _log_parent_after(self, name):
        parent = str(Path(name).parent)
        if parent not in self.log_parents:
            return
        before, names = self.log_parents[parent]
        after = rename.directory(self.session.git_dir / parent)
        core._need(after[:3] == before[:3] and after[6:] == before[6:], "recovery-required")
        self.log_parents[parent] = after, names

    def acquire(self):
        self.session.ref_locks.check()
        # Bind the existing no-replace syscall before any candidate/publication.
        self.exclusive_rename = _rename_function()
        super().acquire()
        if self.plan._controls.logging:
            for step, name in (("new-log", "logs/" + self.plan.target), ("head-log", "logs/HEAD")):
                lock = local._ConfigLock(self.session.git_dir / (name + ".lock"))
                self.log_locks[step] = lock  # Original route retained before open.
                lock.acquire()
                self._log_parent_after(name)
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
            name = str(path.relative_to(frozen.root))
            if name != read._CONFIG_FILE:
                self.exec_view.write(name, core._read(path, 65536)[1])
        for name in ("logs", "logs/refs", *[str(p) for p in reversed(Path("logs/" + self.plan.source).parents)
                                          if str(p) not in (".", "logs", "logs/refs")]):
            destination = self.exec_view.root / name
            if destination not in self.exec_view.directories:
                destination.mkdir(mode=0o700)
                self.exec_view.directories[destination] = core._identity(destination.lstat())[:2]
        for name, stamp, raw in self.plan._controls.files:
            if name.startswith("logs/") and stamp.kind == "file":
                self.exec_view.write(name, raw)
        self.exec_view.write("rename-config", self.plan._controls.file("config")[1])
        # Keep stock log policy explicit in the private execution context.
        stamp, config = core._read(self.exec_view.root / "config", 65536)
        log_value = b"true" if self.plan._controls.logging else b"false"
        self.exec_view.write("config", config + b"[core]\nlogAllRefUpdates=" + log_value + b"\n")
        self.check_execution()

    def check_execution(self):
        core._need(self.exec_view is not None and not self.exec_view.unknown, "recovery-required")
        for path, identity in self.exec_view.directories.items():
            before = core._identity(path.lstat())
            core._need(before[:2] == identity and stat.S_ISDIR(before[2]), "stale-observation")
            expected = {p.name for p in (*self.exec_view.files, *self.exec_view.directories) if p != path and p.parent == path}
            core._need(set(self.session.names(path)) == expected and core._identity(path.lstat()) == before,
                       "stale-observation")
        for path, expected in self.exec_view.files.items():
            core._need(core._read(path, 65536)[0] == expected, "stale-observation")
        core._need(core._read(self.index, rename.MAX_INDEX)[1] == self.original.index_bytes, "stale-observation")

    def admit_command(self, args, identity):
        core._need(self.command_entered is None and self.exec_view is not None, "already-used")
        if args == ["branch", "-m", "--", self.plan.old_name, self.plan.name]:
            step = "branch"
            core._need(not self.command_returned and identity is self.plan._controls.identity, "authorization")
        elif args == ["config", "--file", str(self.exec_view.root / "rename-config"), "--no-includes",
                      "--rename-section", "branch." + self.plan.old_name, "branch." + self.plan.name]:
            step = "config"
            core._need(self.command_returned == {"branch"} and identity is None
                       and self.plan._controls.config_candidate is not None, "authorization")
        elif args == ["config", "--file", str(self.exec_view.root / "rename-config"), "--no-includes", "--null", "--list"]:
            step = "verify"
            expected = {"branch", "config"} if self.plan._controls.config_candidate is not None else {"branch"}
            core._need(self.command_returned == expected and identity is None, "authorization")
        else:
            raise core.GitError("invalid-input")
        self.check_original()
        self.check_execution()
        self.command_entered = step

    def _adopt_private(self, name, raw):
        stamp, actual = core._read(self.exec_view.root / name, 65536)
        core._need(stamp.kind == "file" and actual == raw, "recovery-required")
        self.exec_view.files[self.exec_view.root / name] = stamp

    def _absent_private(self, name):
        path = self.exec_view.root / name
        core._need(path in self.exec_view.files and core._read(path, 65536)[0].kind == "absent", "recovery-required")
        del self.exec_view.files[path]

    def _log_candidate(self, name, original):
        stamp, raw = core._read(self.exec_view.root / name, 65536)
        if not self.plan._controls.logging:
            core._need(stamp.kind == "absent", "recovery-required")
            return b""
        core._need(stamp.kind == "file" and len(raw) <= rename.MAX_LOG and raw.startswith(original), "recovery-required")
        identity = self.plan._controls.identity
        prefix = (self.plan._snapshot.public.head + " " + self.plan._snapshot.public.head + " "
                  + identity.name + " <" + identity.email + "> ").encode("utf-8")
        message = ("Branch: renamed " + self.plan.source + " to " + self.plan.target).encode("ascii")
        tail = raw[len(original):]
        core._need(re.fullmatch(re.escape(prefix) + rb"[0-9]{1,12} [+-][0-9]{4}\t" + re.escape(message) + rb"\n", tail)
                   is not None and len(tail) <= 2048, "recovery-required")
        self._adopt_private(name, raw)
        return raw

    def command_did_return(self, args, result):
        step = self.command_entered
        core._need(step is not None and step not in self.command_returned and result.returncode == 0
                   and self.session.execution_command is not None
                   and tuple(args) == self.session.execution_command[0], "recovery-required")
        if step == "branch":
            self._absent_private(self.plan.source)
            self._adopt_private(self.plan.target, (self.plan._snapshot.public.head + "\n").encode("ascii"))
            self.candidates["HEAD"] = ("ref: " + self.plan.target + "\n").encode("ascii")
            self._adopt_private("HEAD", self.candidates["HEAD"])
            old_log, new_log = "logs/" + self.plan.source, "logs/" + self.plan.target
            if self.plan._controls.logging:
                self._absent_private(old_log)
            self.candidates[new_log] = self._log_candidate(new_log, self.plan._controls.file(old_log)[1])
            self.candidates["logs/HEAD"] = self._log_candidate("logs/HEAD", self.plan._controls.file("logs/HEAD")[1])
            # Stock branch also renames its private tracking section. Accept
            # only this exact bounded change; never refresh the whole view.
            old_config = self.exec_view.files[self.exec_view.root / "config"]
            raw_before = self.private_config_before
            # The original read facet deliberately emits one safe subsection
            # per tracking key. These generated repeated headers are NOT the
            # user's config (whose duplicate sections were refused at capture).
            before_header = ('[branch "' + self.plan.old_name + '"]\n').encode("ascii")
            after_header = ('[branch "' + self.plan.name + '"]\n').encode("ascii")
            self._adopt_private("config", raw_before.replace(before_header, after_header))
            core._need(old_config.kind == "file" and result.stdout == b"", "response-invalid")
        elif step == "config":
            self._adopt_private("rename-config", self.plan._controls.config_candidate)
            core._need(result.stdout == b"", "response-invalid")
        else:
            expected = rename.renamed_config(self.original.config, self.plan.old_name, self.plan.name)
            core._need(read._configuration(result.stdout) == expected, "recovery-required")
            self.candidates["config"] = core._read(self.exec_view.root / "rename-config", rename.MAX_CONFIG)[1]
        self.command_returned.add(step)
        self.command_entered = None
        self.check_execution()

    def prepare_candidates(self):
        self.private_config_before = core._read(self.exec_view.root / "config", 65536)[1]
        self.session.execute_private(["branch", "-m", "--", self.plan.old_name, self.plan.name], identity=self.plan._controls.identity)
        config = str(self.exec_view.root / "rename-config")
        if self.plan._controls.config_candidate is not None:
            self.session.execute_private(["config", "--file", config, "--no-includes", "--rename-section",
                                          "branch." + self.plan.old_name, "branch." + self.plan.name])
        self.session.execute_private(["config", "--file", config, "--no-includes", "--null", "--list"])
        plan, controls = self.plan, self.plan._controls
        old_log, new_log = "logs/" + plan.source, "logs/" + plan.target
        self.intent = rename.RenameIntent(plan._snapshot.public.revision, plan.reference_revision, plan.source,
            plan._snapshot.public.head, plan._snapshot.index_stamp.digest, plan.target,
            controls.file("config")[0].digest, core._digest(self.candidates["config"]),
            controls.file(old_log)[0].digest, core._digest(self.candidates[new_log]) if controls.logging else core._ABSENT.digest,
            controls.file("logs/HEAD")[0].digest, core._digest(self.candidates["logs/HEAD"]) if controls.logging else core._ABSENT.digest,
            controls.config_candidate is not None, controls.logging)
        self.check_original()

    def _directory_call(self, path, call):
        before = rename.directory(path)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            core._need((*core._identity(os.fstat(fd)), os.fstat(fd).st_uid, os.fstat(fd).st_gid) == before,
                       "stale-observation")
            call(fd)
            os.fsync(fd)
            after = rename.directory(path)
            core._need(after[:3] == before[:3] and after[6:] == before[6:]
                       and (*core._identity(os.fstat(fd)), os.fstat(fd).st_uid, os.fstat(fd).st_gid) == after,
                       "recovery-required")
        finally:
            self.directory_closes.append(fd)
            os.close(fd)
            self.directory_closes.pop()

    def publish(self, step):
        core._need(step == rename.steps(self.plan)[len(self.returns)] and step not in self.attempted, "already-used")
        self.owner.publication_ready()
        self.check_original()
        git, plan = self.session.git_dir, self.plan
        self.attempted.append(step)  # Before write/unlink/rename can lose return.
        if step == "ref":
            before, raw = plan._controls.file(plan.source)
            core._need(core._read(git / plan.source, 65) == (before, raw)
                       and core._read(git / plan.target, 65, regular=False)[0].kind == "absent", "stale-observation")
            self._directory_call((git / plan.source).parent,
                lambda fd: self.exclusive_rename(fd, Path(plan.source).name, fd, Path(plan.target).name))
            after, actual = rename.regular(git / plan.target, 65)
            core._need(actual == raw and after.identity[:5] == before.identity[:5]
                       and core._read(git / plan.source, 65, regular=False)[0].kind == "absent", "recovery-required")
            receipt = Returned(step, before, after, rename.directory((git / plan.source).parent))
            self.session.ref_locks.moved(receipt)
        elif step == "old-log":
            name = "logs/" + plan.source
            before, raw = plan._controls.file(name)
            core._need(core._read(git / name, 65536) == (before, raw)
                       and "new-log" in self._done(), "stale-observation")
            self._directory_call((git / name).parent, lambda fd: os.unlink(Path(name).name, dir_fd=fd))
            core._need(core._read(git / name, 65536, regular=False)[0].kind == "absent", "recovery-required")
            receipt = Returned(step, before, core._ABSENT)
            self._log_parent_after(name)
        else:
            name = {"new-log": "logs/" + plan.target, "head-log": "logs/HEAD", "head": "HEAD", "config": "config"}[step]
            before = (core._ABSENT if step == "new-log" else
                      self.original.metadata[git / "HEAD"] if step == "head" else plan._controls.file(name)[0])
            if step in self.log_locks:
                lock = self.log_locks[step]
                path, fd = lock.path, lock.fd
            elif step == "config":
                lock = self.config_lock
                path, fd = lock.path, lock.fd
            else:
                lock = None
                path, fd, _ = next(row for row in self.locks if row[0].name == "HEAD.lock")
            raw = self.candidates[name]
            offset = 0
            while offset < len(raw):
                count = os.write(fd, raw[offset:])
                core._need(count > 0, "recovery-required")
                offset += count
            mode = stat.S_IMODE(before.identity[2]) if before.kind == "file" else stat.S_IMODE(plan._controls.file("logs/" + plan.source)[0].identity[2])
            os.fchmod(fd, mode)
            os.fsync(fd)
            if lock is not None:
                lock.identity = core._identity(os.fstat(fd))
            self.check_original()
            core._need(core._read(git / name, 65536, regular=False)[0] == before, "stale-observation")
            if before.kind == "absent":
                self._directory_call(path.parent, lambda parent: self.exclusive_rename(parent, path.name, parent, Path(name).name))
            else:
                self._directory_call(path.parent, lambda parent: os.replace(path.name, Path(name).name, src_dir_fd=parent, dst_dir_fd=parent))
            after, actual = rename.regular(git / name, 65536)
            core._need(actual == raw and after.identity == core._identity(os.fstat(fd)), "recovery-required")
            receipt = Returned(step, before, after)
            self._log_parent_after(name)
        self.returns.append(receipt)
        self._publish_private_comparison(receipt)
        self.check_original()

    def _publish_private_comparison(self, receipt):
        frozen = self.session.frozen
        if receipt.step == "ref":
            old = frozen.root / self.plan.source
            core._need(core._read(old, 65)[0] == frozen.files[old], "stale-observation")
            del frozen.files[old]
            os.unlink(old)
            frozen.write(self.plan.target, (self.plan._snapshot.public.head + "\n").encode("ascii"))
        elif receipt.step == "head":
            frozen.write("HEAD", self.candidates["HEAD"])
            self.session.head_bytes = self.candidates["HEAD"]
            self.session._resolved_head = None
        elif receipt.step == "config":
            frozen.write(read._CONFIG_FILE, self.candidates["config"])
            self.session.config = rename.renamed_config(self.original.config, self.plan.old_name, self.plan.name)

    def close(self, *, preserve_scratch=False):
        if self.attempted != [row.step for row in self.returns] or self.command_entered is not None or self.directory_closes:
            self.retained = self.session.repository._unknown = True
            return False
        good = True
        if self.exec_view is not None and not preserve_scratch:
            self.check_execution()
            good = self.exec_view.close()
        done = self._done()
        # Published routes close their exact original FD; never unlink the
        # named successor. Unpublished locks use the original sole close path.
        if "head" in done:
            row = next(row for row in self.locks if row[0].name == "HEAD.lock")
            self.locks.remove(row)
            self.uncertain_closes.append(row)
            os.close(row[1])
            self.uncertain_closes.pop()
        for step, lock in self.log_locks.items():
            if step in done:
                lock.close_claimed = lock.unknown = True
                os.close(lock.fd)
                lock.closed, lock.unknown = True, False
            else:
                good = lock.close() and good
                self._log_parent_after(str(lock.path.relative_to(self.session.git_dir)).removesuffix(".lock"))
        if "config" in done:
            self.config_lock.close_claimed = self.config_lock.unknown = True
            os.close(self.config_lock.fd)
            self.config_lock.closed, self.config_lock.unknown = True, False
        good = super().close(preserve_scratch=preserve_scratch) and good
        self.closed = True
        self.retained |= preserve_scratch or not good
        return good
