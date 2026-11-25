"""Fixed isolated stock-Git fetch and exact candidate publication.

This is a GitLocal transaction facet, not another journal/process owner. The
sole network command still needs the original GitRemote map-v2/W limit and
private channel. Its returned transcript/pack is never native finality. The
native candidate job owns the original keep marker before ACK; Python only
compares it and NEVER opens, removes, or closes that native keep descriptor.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
import os
from pathlib import Path
import re
import stat
import tempfile
import time

from . import git_repository_fetch as fetch
from . import git_repository_local as local
from . import git_repository_read as read
from . import git_service as core

FILE_LIMIT = 32 * 1024 * 1024
STAGING_RESERVE = 80 * 1024 * 1024
META_LIMIT = 64 * 1024
_METADATA = ("HEAD", "config", "exec/git", "exec/git-remote-mrk")
_DIRECTORIES = ("objects", "objects/info", "objects/pack", "refs", "refs/heads", "exec")
_PACK = re.compile(r"pack-([a-f0-9]{40})\.pack\Z", re.ASCII)


@dataclass(frozen=True, slots=True, repr=False)
class Launch:
    """Native-held code paths only; these values are NOT source admission."""
    python: Path
    bootstrap: Path
    core: Path
    runtime: Path

    def __post_init__(self):
        for path in (self.python, self.bootstrap, self.core, self.runtime):
            core._need(type(path) is type(Path()) and path.is_absolute()
                       and all(part not in (".", "..") for part in path.parts)
                       and 1 <= len(os.fsencode(path)) <= 4096
                       and not any(ord(char) < 32 or ord(char) == 127 for char in str(path)), "invalid-input")


def _quote(path: Path) -> bytes:
    # Constant exec syntax; no caller-provided shell expressions, PATH lookup,
    # credential, environment assignment or interpolation is admitted.
    return b"'" + os.fsencode(path).replace(b"'", b"'\\''") + b"'"


def _full(info):
    return (*core._identity(info), info.st_uid, info.st_gid, info.st_nlink)


class _File:
    """Two bounded content-file descriptors, retained before their first read."""
    def __init__(self, path: Path, session):
        self.path, self.session = path, session
        self.fd = None
        self.identity = None
        self.sha256 = None
        self.entered = self.close_claimed = self.closed = self.unknown = False
        self.linked = self.removed = False
        self.original_path = None

    def capture(self):
        core._need(not self.entered, "already-used")
        self.entered = True
        try:
            before = self.path.lstat()
            fetch.require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1
                          and stat.S_IMODE(before.st_mode) in (0o400, 0o444, 0o600, 0o644)
                          and 0 < before.st_size <= FILE_LIMIT, "fetch-output")
        except BaseException:
            self.closed = True  # No open was entered; no descriptor route exists.
            raise
        try:
            self.fd = os.open(self.path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            self.closed = True  # Returned failed open, not an unknown FD.
            raise
        except BaseException:
            self.unknown = True
            raise
        self.identity = _full(before)
        self.check()
        count, digest = 0, hashlib.sha256()
        while True:
            self.session.guard_current()
            block = os.read(self.fd, min(32768, self.identity[3] + 1 - count))
            if not block:
                break
            count += len(block)
            fetch.require(count <= self.identity[3], "fetch-output")
            digest.update(block)
        fetch.require(count == self.identity[3], "fetch-output")
        self.sha256 = digest.hexdigest()
        os.fsync(self.fd)  # Private validated contents durable before candidate ACK/link.
        self.check()

    def check(self):
        core._need(self.entered and self.fd is not None and self.identity is not None
                   and not self.closed and not self.close_claimed and not self.unknown, "recovery-required")
        core._need(_full(os.fstat(self.fd)) == self.identity, "stale-observation")
        if not self.removed:
            core._need(_full(self.path.lstat()) == self.identity, "stale-observation")
        if self.original_path is not None:
            core._need(_full(self.original_path.lstat()) == self.identity, "stale-observation")

    def _after_link_count(self, count):
        before, after = self.identity, _full(os.fstat(self.fd))
        # Only the exact positive owned link/unlink may change ctime/nlink.
        # File contents/mode/owner/size/mtime and original descriptor stay exact.
        core._need(after[:5] == before[:5] and after[6:8] == before[6:8]
                   and after[8] == count, "recovery-required")
        self.identity = after
        self.check()

    def close(self):
        if self.closed:
            return not self.unknown
        if self.fd is None or self.close_claimed:
            self.unknown = self.entered
            return not self.unknown
        self.close_claimed = self.unknown = True
        fd, self.fd = self.fd, None  # Retire this sole route before close.
        os.close(fd)
        self.closed, self.unknown = True, False
        return True


@dataclass(frozen=True, slots=True, repr=False)
class BorrowedKeep:
    """Comparison DATA from the SAME native candidate-ACK job, not its lease.

    The original SourceBook retains descriptor+parent through source POST,
    runtime/management settlement and its own one-attempt unlink/close. An equal
    instance without that actual owner cannot admit publication or retirement.
    """
    pack_oid: str
    review_digest: str
    identity: tuple[int, ...]
    parent_before: tuple[int, ...]
    parent_after: tuple[int, ...]

    def __post_init__(self):
        core._need(type(self.pack_oid) is str and fetch._OID.fullmatch(self.pack_oid) is not None
                   and type(self.review_digest) is str and core._REVISION.fullmatch(self.review_digest) is not None,
                   "invalid-input")
        for row, length in ((self.identity, 9), (self.parent_before, 8), (self.parent_after, 8)):
            core._need(type(row) is tuple and len(row) == length and all(type(v) is int and v >= 0 for v in row),
                       "invalid-input")
        core._need(stat.S_ISREG(self.identity[2]) and stat.S_IMODE(self.identity[2]) == 0o600
                   and self.identity[6] == os.getuid() and self.identity[8] == 1
                   and self.parent_before[:3] == self.parent_after[:3]
                   and self.parent_before[6:] == self.parent_after[6:], "invalid-input")

    @property
    def name(self):
        return "pack-" + self.pack_oid + ".keep"

    @property
    def body(self):
        return b"mrk-git-fetch/1 " + self.review_digest.encode("ascii") + b"\n"

    def check(self, parent: Path):
        # Native durability/creation is checked by the original job, never
        # inferred from this name/readback. No operation here consumes its FD.
        core._need(self.identity[3] == len(self.body) and _full((parent / self.name).lstat()) == self.identity,
                   "stale-observation")
        stamp, raw = core._read(parent / self.name, 256)
        core._need(stamp.identity == self.identity[:6] and raw == self.body, "stale-observation")


class _View(core._FrozenGitDirectory):
    """One finite same-filesystem bare view, no original ODB or third spool."""
    def __init__(self, transaction):
        self.tx = transaction
        self.root = None
        self.directories, self.files = {}, {}
        self.contents = []
        self.pack_dir_fd = None
        self.pack_dir_close_claimed = False
        self.unknown = False
        self.output_oid = None
        self.output_entered = self.output_returned = False
        self.closed = False
        session, plan = transaction.session, transaction.plan
        self.root = Path(tempfile.mkdtemp(prefix="mrk-git-fetch-", dir=session.git_dir))
        fetch.require(stat.S_IMODE(self.root.lstat().st_mode) == 0o700)
        self.directories[self.root] = core._identity(self.root.lstat())[:2]
        fetch.require(self.root.lstat().st_dev == (session.git_dir / "objects/pack").lstat().st_dev)
        for name in _DIRECTORIES:
            path = self.root / name
            path.mkdir(mode=0o700)
            self.directories[path] = core._identity(path.lstat())[:2]
        launch = session.repository.launch
        git_script = b"#!/bin/sh\nexec " + _quote(session.repository.git_executable) + b' "$@"\n'
        helper_script = (b"#!/bin/sh\nexec " + _quote(launch.python) + b" -I -S -B " + _quote(launch.bootstrap)
                         + b" " + _quote(launch.core) + b" " + _quote(launch.runtime) + b' "$@"\n')
        self.write("HEAD", b"ref: " + fetch.PRIVATE_REF.encode("ascii") + b"\n")
        self.write("config", (b"[core]\nbare = true\nrepositoryFormatVersion = 0\nlogAllRefUpdates = false\n"
            b"hooksPath = /dev/null\nfsmonitor = false\nuntrackedCache = false\nattributesFile = /dev/null\n"
            b"excludesFile = /dev/null\n[protocol]\nversion = 2\nallow = never\n[protocol \"mrk\"]\nallow = always\n"
            b"[pack]\nthreads = 1\nwriteReverseIndex = false\nindexVersion = 2\n[fetch]\nfsckObjects = true\n"
            b"writeCommitGraph = false\n[transfer]\nfsckObjects = true\n[maintenance]\nauto = false\n[gc]\nauto = 0\n"
            b"[remote " + read._quoted(plan.remote.encode("ascii")) + b"]\nurl = "
            + read._quoted(("mrk::https://github.com/" + plan.target.repository + ".git").encode("ascii")) + b"\n"))
        self.write("exec/git", git_script)
        self.write("exec/git-remote-mrk", helper_script)
        for name in ("exec/git", "exec/git-remote-mrk"):
            path = self.root / name
            os.chmod(path, 0o700)
            self.files[path] = core._read(path, META_LIMIT)[0]
        core._need(sum(stamp.identity[3] for stamp in self.files.values()) <= META_LIMIT, "limit")
        self.pack_dir_fd = os.open(self.root / "objects/pack", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.check()

    def check(self, *, outputs=False):
        core._need(not self.unknown and not self.closed and self.root in self.directories, "recovery-required")
        session = self.tx.session
        known = set(self.files) | {row.path for row in self.contents if not row.removed}
        for path, identity in self.directories.items():
            before = core._identity(path.lstat())
            core._need(before[:2] == identity and stat.S_ISDIR(before[2]) and not before[2] & 0o77, "stale-observation")
            expected = {p.name for p in (*self.directories, *known) if p != path and p.parent == path}
            names = set(session.names(path))
            if outputs and path in (self.root / "objects/pack", self.root / "refs/heads"):
                pass  # The exact two output directories are checked below.
            else:
                core._need(names == expected, "stale-observation")
            core._need(core._identity(path.lstat()) == before, "stale-observation")
        for path, stamp in self.files.items():
            core._need(core._read(path, META_LIMIT)[0] == stamp, "stale-observation")
        for row in self.contents:
            row.check()
        core._need(self.pack_dir_fd is not None and core._identity(os.fstat(self.pack_dir_fd))[:2]
                   == self.directories[self.root / "objects/pack"], "stale-observation")

    def command(self, role: str):
        plan, session = self.tx.plan, self.tx.session
        env = {"PATH": str(self.root / "exec"), "GIT_EXEC_PATH": str(self.root / "exec"), "HOME": str(self.root),
               "XDG_CONFIG_HOME": str(self.root), "LANG": "C", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
               "GIT_CONFIG_SYSTEM": os.devnull, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0",
               "GIT_ATTR_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1",
               "GIT_LITERAL_PATHSPECS": "1", "GIT_ALLOW_PROTOCOL": "mrk", "GIT_PROTOCOL_FROM_USER": "0",
               "GIT_PAGER": "cat"}
        # No OBJECT_DIRECTORY/alternate, original index, ambient auth/proxy,
        # curl/default CA, trace, user hooks or arbitrary executable search.
        roles = {
            "metadata": ["ls-remote", "--exit-code", "--refs", plan.remote, plan.target.selected.reference],
            "fetch": ["fetch", "--keep", "--no-tags", "--no-recurse-submodules", "--no-write-fetch-head",
                      "--no-auto-maintenance", "--no-write-commit-graph", "--jobs=1", "--refmap=", plan.remote,
                      plan.target.selected.reference + ":" + fetch.PRIVATE_REF],
            "resolve": ["rev-parse", "--verify", "--end-of-options", fetch.PRIVATE_REF + "^{commit}"],
            "fsck": ["fsck", "--full", "--strict", "--no-reflogs", "--no-progress", "--no-dangling",
                     plan.target.selected.oid],
            "tree": ["ls-tree", "-r", "-z", "--full-tree", plan.target.selected.oid],
        }
        if role == "verify":
            core._need(self.output_oid is not None, "authorization")
            args = ["verify-pack", str(self.root / "objects/pack" / ("pack-" + self.output_oid + ".idx"))]
        else:
            core._need(role in roles, "invalid-input")
            args = roles[role]
        argv = [str(session.repository.git_executable), "--no-pager", "--no-replace-objects",
                "--git-dir=" + str(self.root), *args]
        return argv, env

    def capture_outputs(self):
        core._need(self.output_entered and self.output_returned and not self.contents and self.output_oid is None,
                   "authorization")
        self.check(outputs=True)
        session = self.tx.session
        names = session.names(self.root / "objects/pack")
        packs = [name for name in names if _PACK.fullmatch(name)]
        fetch.require(len(packs) == 1, "fetch-output")
        oid = _PACK.fullmatch(packs[0])[1]
        expected = {"pack-" + oid + ".pack", "pack-" + oid + ".idx"}
        keep = "pack-" + oid + ".keep"
        fetch.require(set(names) in (expected, expected | {keep}), "fetch-output")
        fetch.require(session.names(self.root / "refs/heads") == ("mrk-fetch",), "fetch-output")
        ref_path = self.root / fetch.PRIVATE_REF
        stamp, raw = core._read(ref_path, 128)
        fetch.require(stamp.kind == "file" and raw == (self.tx.plan.target.selected.oid + "\n").encode("ascii"),
                      "fetch-target-changed")
        self.files[ref_path] = stamp
        if keep in names:
            path = self.root / "objects/pack" / keep
            stamp, _ = core._read(path, 2048)
            fetch.require(stamp.kind == "file", "fetch-output")
            self.files[path] = stamp  # This private marker does NOT protect original objects.
        self.output_oid = oid
        for suffix in ("pack", "idx"):
            item = _File(self.root / "objects/pack" / ("pack-" + oid + "." + suffix), session)
            self.contents.append(item)  # Retain before open/read/close can fail.
            item.capture()
        fetch.require(self.contents[0].identity[:2] != self.contents[1].identity[:2], "fetch-output")
        core._need(sum(row.identity[3] for row in self.contents) + sum(row.identity[3] for row in self.files.values())
                   <= 2 * FILE_LIMIT + META_LIMIT < STAGING_RESERVE, "limit")
        self.check()

    def close(self, *, preserve=False):
        if self.closed:
            return not self.unknown
        if self.unknown:
            return False
        good = True
        # A failed/unknown command's outputs are not adopted for deletion by a
        # filename pattern. Preserve the finite staging root for manual audit.
        if not preserve:
            self.check()
            for item in self.contents:
                item.check()
                self.unknown = True
                os.unlink(item.path)
                item.removed = True
                if item.linked:
                    item._after_link_count(1)
                self.unknown = False
            for path in tuple(self.files):
                core._need(core._read(path, META_LIMIT)[0] == self.files[path], "stale-observation")
                del self.files[path]
                self.unknown = True
                os.unlink(path)
                self.unknown = False
        for item in self.contents:
            good = item.close() and good
        if self.pack_dir_fd is not None and not self.pack_dir_close_claimed:
            fd, self.pack_dir_fd = self.pack_dir_fd, None
            self.pack_dir_close_claimed = self.unknown = True
            os.close(fd)
            self.unknown = False
        if not preserve:
            for path in sorted(self.directories, key=lambda p: len(p.parts), reverse=True):
                core._need(core._identity(path.lstat())[:2] == self.directories[path] and not self.tx.session.names(path),
                           "stale-observation")
                del self.directories[path]
                self.unknown = True
                os.rmdir(path)
                self.unknown = False
        self.closed = good
        return good


@dataclass(frozen=True, slots=True, repr=False)
class Publication:
    """Known positive prefix only. NOT SourceBook/runtime/Store finality.

    No matching name or failed/unknown child can manufacture a ref successor.
    Partially linked validated objects may be retained after a known STOP; the
    original native SourceBook still rematches exactly this operation's inputs.
    """
    intent: fetch.FetchIntent
    ref: local._RefSuccessor | None
    pack: tuple[int, ...] | None
    index: tuple[int, ...] | None
    keep: BorrowedKeep
    log: core._Stamp | None
    log_parent: tuple[int, ...] | None
    phase: str


class FetchTransaction(local._LocalTransaction):
    def __init__(self, session, original, plan, owner, review_digest):
        super().__init__(session, original, plan, owner)
        self.review_digest = review_digest
        self.view = self.intent = self.keep = self.publication = None
        self.pack_parent = None
        self.pack_fd = None
        self.pack_close_claimed = False
        self.ack_entered = self.acknowledged = self.cas_entered = self.cas_returned = False
        self.phase = "not-published"
        self.unknown = False
        self.linked = []
        self.private_roles = []
        self.ref_files = []
        self.ref_parent_fd = None
        self.ref_parent_close_claimed = False
        self.log_parent_fd = None
        self.log_parent_close_claimed = False

    def metadata(self):
        """The same finite view, with no object producer or original locks.

        This is only the explicit Prepare ls-remote, before a reviewed OID
        exists. It never enables this transaction's download/publication path.
        """
        core._need(self.view is None and self.owner is None and self.plan.target.selected.oid is None
                   and not self.private_roles, "authorization")
        self.session.guard_current(); self.session.check_original()
        self.view = _View.__new__(_View)
        _View.__init__(self.view, self)
        self.private_roles.append("metadata")
        argv, environment = self.view.command("metadata")
        remaining = self.session.deadline - time.monotonic()
        self.session.calls += 1
        core._need(self.session.calls <= core.MAX_CALLS and remaining >= 1, "deadline")
        result = self.session.repository._remote(argv, cwd=self.view.root, environ=environment,
            capture=True, text=False, timeout=min(45, math.floor(remaining)), output_limit=256 * 1024,
            cancellation=self.session.repository.cancellation, execution_scope=None)
        core._need(result.args == argv and type(result.returncode) is int and type(result.stdout) is bytes
                   and type(result.stderr) is bytes and len(result.stdout) + len(result.stderr) <= 256 * 1024,
                   "response-invalid")
        fetch.require(result.returncode == 0, "fetch-target-changed")
        selected = self.plan.target.selected.reference.encode("ascii")
        matched = re.fullmatch(rb"([a-f0-9]{40})\t" + re.escape(selected) + rb"\n", result.stdout)
        fetch.require(matched is not None, "fetch-target-changed")
        oid = matched[1].decode("ascii")
        fetch.Selection(self.plan.target.selected.reference, oid)
        self.view.check()  # Neither ref nor object output is allowed in Prepare.
        self.session.check_original(); self.session.guard_current()
        return oid

    def acquire(self):
        super().acquire()
        core._need(callable(self.session.repository._remote), "authorization")
        # Same-filesystem bounded staging; the outer native reservation and
        # genuine W limit/source nomination remain prerequisites, not inferred
        # from this filesystem observation or a config flag.
        self.view = _View.__new__(_View)
        _View.__init__(self.view, self)
        path = self.session.git_dir / "objects/pack"
        self.pack_parent = fetch._directory(path)
        self.pack_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        core._need(_full(os.fstat(self.pack_fd))[:8] == self.pack_parent, "stale-observation")
        self.check_original()

    def check_original(self):
        super().check_original()
        if self.pack_fd is not None:
            parent = self.session.git_dir / "objects/pack"
            core._need(_full(os.fstat(self.pack_fd))[:8] == self.pack_parent
                       and fetch._directory(parent) == self.pack_parent, "stale-observation")
        if self.keep is not None:
            self.keep.check(self.session.git_dir / "objects/pack")
        for item in self.linked:
            item.check()

    def normalized_inventory(self, inventory):
        if self.keep is None:
            return inventory
        core._need(self.acknowledged and self.intent is not None, "authorization")
        self.keep.check(self.session.git_dir / "objects/pack")
        pack = dict(inventory.pack)
        expected = {self.keep.name: self.keep.identity[:6]}
        expected.update({row.path.name: row.identity[:6] for row in self.linked})
        for name, identity in expected.items():
            core._need(pack.pop(name, None) == identity, "stale-observation")
        directories = []
        for name, identity in inventory.directories:
            if name == "objects/pack":
                core._need(identity == self.pack_parent[:6], "stale-observation")
                identity = self.keep.parent_before[:6]
            directories.append((name, identity))
        return read._ReferenceInventory(tuple(directories), inventory.files, inventory.forbidden, tuple(sorted(pack.items())))

    def _command(self, role: str):
        self.check_original()
        core._need(self.view is not None and role not in self.private_roles, "already-used")
        allowed = ("fetch", "resolve", "verify", "fsck", "tree")
        core._need(role == allowed[len(self.private_roles)], "invalid-input")
        self.view.check()
        self.private_roles.append(role)  # Before the actual original send.
        argv, environment = self.view.command(role)
        self.session.calls += 1
        remaining = self.session.deadline - time.monotonic()
        core._need(self.session.calls <= core.MAX_CALLS and remaining >= 1, "deadline")
        limit = core.MAX_GIT_BYTES if role == "tree" else 256 * 1024
        if role == "fetch":
            self.view.output_entered = True
            runner, timeout = self.session.repository._remote, min(45, math.floor(remaining))
        else:
            runner, timeout = self.session.repository._run, min(10, math.floor(remaining))
        result = runner(argv, cwd=self.view.root, environ=environment, capture=True, text=False, timeout=timeout,
                        output_limit=limit, cancellation=self.session.repository.cancellation, execution_scope=None)
        core._need(result.args == argv and type(result.returncode) is int and type(result.stdout) is bytes
                   and type(result.stderr) is bytes and len(result.stdout) + len(result.stderr) <= limit, "response-invalid")
        core._need(result.returncode == 0, "command-failed")
        if role == "fetch":
            # The real fixed worker returns ONLY after its C/A/W and private
            # channel all-copy EOF/closes. CompletedProcess DATA alone from an
            # arbitrary caller does not supply that installed authority.
            self.view.output_returned = True
        else:
            self.view.check()
        self.check_original()
        return result.stdout

    def download(self):
        self._command("fetch")
        self.view.capture_outputs()

    def validate_candidate(self):
        oid = core._oid(self._command("resolve"))
        fetch.require(oid == self.plan.target.selected.oid, "fetch-target-changed")
        self._command("verify")
        self._command("fsck")
        rows = core._nul(self._command("tree"))
        core._need(len(rows) <= core.MAX_ENTRIES, "limit")
        seen = set()
        for row in rows:
            header, separator, path = row.partition(b"\t")
            fields = header.split(b" ")
            fetch.require(separator == b"\t" and len(fields) == 3
                          and fields[0] in (b"100644", b"100755", b"120000") and fields[1] == b"blob")
            fetch.require(fetch._OID.fullmatch(core._oid(fields[2])) is not None)
            name = core._decode_path(path)
            fetch.require(name not in seen and len(name.split("/")) <= read.MAX_REF_DEPTH)
            fetch.require(name.split("/")[-1] not in (".gitmodules", ".gitattributes", ".lfsconfig"))
            seen.add(name)
        self.view.check(); self.check_original()
        pack, index = self.view.contents
        before = self.plan._snapshot
        self.intent = fetch.FetchIntent(self.review_digest, before.public.revision, self.plan.reference_revision,
            before.public.branch, before.public.head, before.index_stamp.digest, self.plan.target_ref,
            self.plan.expected_target, self.plan.target.selected.oid, self.view.output_oid,
            pack.sha256, pack.identity[3], index.sha256, index.identity[3])

    def handoff(self):
        core._need(self.intent is not None and not self.ack_entered, "authorization")
        self.check_original(); self.view.check()
        self.ack_entered = True
        # SAME durable row is amended before the native original creates its
        # O_EXCL keep marker and ACKs. Lost ACK retains that original; no retry.
        keep = self.owner.record_intent(self.intent)
        core._need(type(keep) is BorrowedKeep and keep.pack_oid == self.intent.pack_oid
                   and keep.review_digest == self.review_digest and keep.parent_before == self.pack_parent,
                   "authorization")
        keep.check(self.session.git_dir / "objects/pack")
        self.keep, self.pack_parent, self.acknowledged = keep, keep.parent_after, True
        self.check_original(); self.view.check()

    def publication_ready(self, **_):
        core._need(self.acknowledged and self.intent is not None and self.keep is not None and not self.retained
                   and not self.unknown, "authorization")
        # Native ACK never suppresses a later STOP/currentness check.
        self.owner.check_current(self.session.root, "fetch", self.original.public.revision)
        self.config_lock.check()
        self.keep.check(self.session.git_dir / "objects/pack")
    def sync_ref(self, target, stamp):
        # A positive stock CAS is followed by exact file+directory durability;
        # retain these new original routes before a syscall can lose return.
        core._need(self.cas_entered and not self.cas_returned and not self.ref_files, "authorization")
        path = self.session.git_dir / target
        row = _File(path, self.session)
        self.ref_files.append(row)
        row.capture()
        core._need(row.identity[:6] == stamp.identity and row.sha256 == stamp.digest, "recovery-required")
        self.ref_parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        core._need(core._identity(os.fstat(self.ref_parent_fd)) == core._identity(path.parent.lstat()), "stale-observation")
        os.fsync(self.ref_parent_fd)
        row.check()

    def sync_log(self, stamp):
        log = self.plan._logging
        core._need(self.cas_entered and not self.cas_returned and len(self.ref_files) == 1, "authorization")
        if stamp is None or stamp.kind == "absent" or stamp == log.original:
            return
        row = _File(log.path, self.session)
        self.ref_files.append(row)
        row.capture()
        core._need(row.identity[:6] == stamp.identity and row.sha256 == stamp.digest, "recovery-required")
        self.log_parent_fd = os.open(log.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        core._need(_full(os.fstat(self.log_parent_fd))[:8] == self.session.fetch_log_parent, "stale-observation")
        os.fsync(self.log_parent_fd)
        row.check()

    def publish(self):
        self.publication_ready(); self.check_original(); self.view.check()
        parent = self.session.git_dir / "objects/pack"
        for item in self.view.contents:
            self.check_original(); self.publication_ready(); self.view.check()
            core._need(core._read(parent / item.path.name, 1, regular=False)[0].kind == "absent", "stale-observation")
            self.phase = "pack-link-entered" if not self.linked else "index-link-entered"
            self.unknown = True  # A lost link return cannot be a no-attempt.
            os.link(item.path.name, item.path.name, src_dir_fd=self.view.pack_dir_fd,
                    dst_dir_fd=self.pack_fd, follow_symlinks=False)
            item.original_path = parent / item.path.name
            item.linked = True
            item._after_link_count(2)
            self.linked.append(item)
            self.pack_parent = fetch._directory(parent)
            core._need(self.pack_parent[:3] == self.keep.parent_after[:3]
                       and self.pack_parent[6:] == self.keep.parent_after[6:], "recovery-required")
            os.fsync(self.pack_fd)
            self.check_original()
            self.phase = "pack-linked" if len(self.linked) == 1 else "objects-linked"
            self.unknown = False  # Only after exact positive postchecks+fsync.
        self.check_original(); self.publication_ready()
        # Stock Git needs its own HEAD/ref lock. Keep the original index/config
        # locks; never hold a custom selected-ref lock around update-ref.
        self.release_head_lock()
        self.check_original(); self.publication_ready()
        self.phase, self.cas_entered = "ref-send-entered", True
        self.session.git(["update-ref", "--no-deref", "-m", fetch.REF_MESSAGE, self.plan.target_ref,
                          self.plan.target.selected.oid, self.plan.expected_target or "0" * 40], limit=1024)
        core._need(self.cas_returned and self.phase == "ref-published", "recovery-required")
        self.check_original()

    def diagnostics(self):
        """Bounded relative recovery DATA; never a cleanup or retry authority."""
        names = []
        if self.retained and self.view is not None and self.view.root is not None:
            names.append(self.view.root.name)
        if self.keep is not None and (self.retained or self.phase != "ref-published"):
            names.append("objects/pack/" + self.keep.name)
        if self.retained:
            names.extend("objects/pack/" + row.path.name for row in self.linked)
        core._need(len(names) <= 5 and len(set(names)) == len(names), "recovery-required")
        return self.phase, tuple(sorted(names))

    def close(self, *, preserve_scratch=False):
        good = True
        unknown = self.unknown
        if self.view is not None:
            good = self.view.close(preserve=preserve_scratch or unknown) and good
            unknown |= self.view.unknown or any(row.unknown for row in self.view.contents)
        for row in self.ref_files:
            good = row.close() and good
            unknown |= row.unknown
        for fd_name, flag_name in (("ref_parent_fd", "ref_parent_close_claimed"),
                                  ("log_parent_fd", "log_parent_close_claimed"), ("pack_fd", "pack_close_claimed")):
            fd = getattr(self, fd_name)
            if fd is None or getattr(self, flag_name):
                continue
            if fd_name == "pack_fd" and not preserve_scratch and not unknown:
                core._need(fetch._directory(self.session.git_dir / "objects/pack") == self.pack_parent, "stale-observation")
            setattr(self, flag_name, True)
            setattr(self, fd_name, None)  # Retire the exact route before close.
            self.unknown = True
            os.close(fd)
            self.unknown = unknown
        good = super().close(preserve_scratch=False) and good
        self.unknown |= unknown
        if good and self.linked and self.acknowledged and not self.unknown:
            core._need(self.keep is not None and self.intent is not None, "recovery-required")
            if self.cas_returned:
                core._need(self.session.successor is not None, "recovery-required")
            self.publication = Publication(self.intent, self.session.successor if self.cas_returned else None,
                self.linked[0].identity, self.linked[1].identity if len(self.linked) == 2 else None, self.keep,
                self.session.fetch_log_successor if self.cas_returned else None,
                self.session.fetch_log_parent if self.cas_returned else None, self.phase)
        self.retained |= preserve_scratch or not good or self.unknown
        # The native keep is deliberately NOT retired here. Its SourceBook
        # owns source/runtime joins, final keep unlink/parent check and last FD.
        return good
