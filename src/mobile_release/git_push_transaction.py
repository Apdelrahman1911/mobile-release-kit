"""Fixed private stock-Push view on the existing GitLocal transaction owner.

No original ref/index/worktree is published. The private hook and body/HTTP
exchange still require the SAME actual GitRemote channel, candidate ACK, C/A/W
and native joins. A callback supplied by an inert test cannot qualify that path.
Unknown output/close stays retained; no retry, filesystem repair or rollback.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import os
from pathlib import Path
import stat
import tempfile
import time

from . import git_repository_local as local
from . import git_repository_push as push
from . import git_repository_read as read
from . import git_service as core
from . import git_push_body as body
from . import git_push_wire as wire
from . import _git_push_private_protocol as private


META_LIMIT = 64 * 1024
STAGING_RESERVE = 80 * 1024 * 1024  # One body <=32MiB plus existing private metadata; no Fetch pack+idx.


@dataclass(frozen=True, slots=True, repr=False)
class Launch:
    """Only original native-held code paths; never path-based admission."""
    python: Path
    bootstrap: Path
    core: Path
    runtime: Path
    context: private.Clock | None = None

    def __post_init__(self):
        for path in (self.python, self.bootstrap, self.core, self.runtime):
            core._need(type(path) is type(Path()) and path.is_absolute()
                       and all(part not in (".", "..") for part in path.parts)
                       and 1 <= len(os.fsencode(path)) <= 4096
                       and not any(ord(c) < 32 or ord(c) == 127 for c in str(path)), "invalid-input")
        core._need(self.context is None or type(self.context) is private.Clock, "invalid-input")


def _quote(path):
    return b"'" + os.fsencode(path).replace(b"'", b"'\\''") + b"'"


def url(plan):
    return "mrk::https://github.com/" + plan.target.repository + ".git"


def hook_line(selected):
    core._need(type(selected) is wire.Selection, "invalid-input")
    return (selected.local_ref + " " + selected.new_oid + " " + selected.remote_ref
            + " " + selected.old_oid + "\n").encode("ascii")


def _digest_valid(value):
    return type(value) is str and core._REVISION.fullmatch(value) is not None


@dataclass(frozen=True, slots=True, repr=False)
class Returned:
    """DATA reported by the actual private channel, not a constructor of joins.

    The fixed worker must publish this on its SAME retained transaction before
    checking later source/close errors; a plain successful Git exit is not it.
    Native finality is deliberately absent from this value.
    """
    mode: str
    selected: wire.Selection
    advertisement_sha256: str
    body: wire.BodyDigest | None
    status: wire.Status | None
    after_sha256: str | None

    def __post_init__(self):
        core._need(self.mode in ("review", "apply") and type(self.selected) is wire.Selection
                   and _digest_valid(self.advertisement_sha256), "response-invalid")
        if self.mode == "review":
            core._need(self.body is self.status is self.after_sha256 is None, "response-invalid")
        else:
            core._need(type(self.body) is wire.BodyDigest and type(self.status) is wire.Status
                       and _digest_valid(self.after_sha256)
                       and self.status.outcome == "ok"
                       and (self.status.reference, self.status.old_oid, self.status.new_oid)
                       == (self.selected.remote_ref, self.selected.old_oid, self.selected.new_oid), "response-invalid")


class _View(core._FrozenGitDirectory):
    """Finite private metadata and ONE body inode, no original ref mapping."""
    def __init__(self, transaction):
        self.tx = transaction
        self.root = None
        self.directories, self.files = {}, {}
        self.unknown = self.closed = self.retained = False
        self.body_initial = self.body_current = None
        self.body_removed = self.body_remove_entered = False
        session, plan = transaction.session, transaction.plan
        self.root = Path(tempfile.mkdtemp(prefix="mrk-git-push-", dir=transaction.scratch or session.git_dir))
        info = self.root.lstat()
        core._need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700, "recovery-required")
        self.directories[self.root] = core._identity(info)[:2]
        branch = plan.target.selected.local_ref
        names = {"objects", "objects/info", "objects/pack", "refs", "refs/heads", "exec", "hooks"}
        names.update("/".join(branch.split("/")[:end]) for end in range(3, len(branch.split("/"))))
        for name in sorted(names, key=lambda value: (value.count("/"), value)):
            path = self.root / name
            path.mkdir(mode=0o700)
            self.directories[path] = core._identity(path.lstat())[:2]
        launch = session.repository.launch
        core._need(type(launch.context) is private.Clock, "authorization")
        prefix = (b"#!/bin/sh\nexec " + _quote(launch.python) + b" -I -S -B " + _quote(launch.bootstrap)
                  + b" " + _quote(launch.core) + b" " + _quote(launch.runtime))
        self.write("HEAD", ("ref: " + branch + "\n").encode("ascii"))
        self.write(branch, (plan.target.selected.new_oid + "\n").encode("ascii"))
        self.write("config", b"[core]\nbare = true\nrepositoryFormatVersion = 0\nlogAllRefUpdates = false\n"
                   b"fsmonitor = false\nuntrackedCache = false\nattributesFile = /dev/null\n"
                   b"excludesFile = /dev/null\ncommitGraph = false\nhooksPath = "
                   + read._quoted(os.fsencode(self.root / "hooks"))
                   + b"\n[protocol]\nversion = 0\nallow = never\n[protocol \"mrk\"]\nallow = always\n"
                   b"[push]\nnegotiate = false\nfollowTags = false\ngpgSign = false\nrecurseSubmodules = no\n"
                   b"useForceIfIncludes = false\n[pack]\nthreads = 1\nuseBitmaps = false\n"
                   b"[commit]\ngpgSign = false\n[tag]\ngpgSign = false\n[maintenance]\nauto = false\n[gc]\nauto = 0\n")
        self.write("exec/git", b"#!/bin/sh\nexec " + _quote(session.repository.git_executable) + b' "$@"\n')
        self.write("exec/git-remote-mrk", prefix + b' push-helper "$@"\n')
        hook_context = " ".join((self.tx.mode, launch.context.digest, self.tx.review_digest,
                                 str(launch.context.work_end_ns), str(launch.context.hard_end_ns)))
        self.write("hooks/pre-push", prefix + b" push-hook " + hook_context.encode("ascii") + b' "$@"\n')
        for name in ("exec/git", "exec/git-remote-mrk", "hooks/pre-push"):
            path = self.root / name
            os.chmod(path, 0o700)
            self.files[path] = core._read(path, META_LIMIT)[0]
        if transaction.mode == "apply":
            # Existing finite write owns its open/close before GO. Helper's
            # TWO later real leases rematch this exact initial inode/parent;
            # they never adopt a newly found name or reopen after sealing.
            self.write(body.NAME, b"")
            path = self.root / body.NAME
            self.body_initial = self.body_current = body._stamp(path.lstat())
            del self.files[path]  # Pack bytes are never read by _FrozenGitDirectory's metadata codec.
        core._need(sum(stamp.identity[3] for stamp in self.files.values()) <= META_LIMIT, "limit")
        self.check()

    def check(self):
        core._need(not self.unknown and not self.closed and self.root in self.directories, "recovery-required")
        known = set(self.files)
        if self.body_initial is not None and not self.body_removed:
            known.add(self.root / body.NAME)
            core._need(body._stamp((self.root / body.NAME).lstat()) == self.body_current, "stale-observation")
        for path, original in self.directories.items():
            info = path.lstat()
            identity = core._identity(info)
            core._need(identity[:2] == original and stat.S_ISDIR(identity[2])
                       and stat.S_IMODE(identity[2]) == 0o700 and info.st_uid == os.getuid(), "stale-observation")
            expected = {p.name for p in (*self.directories, *known) if p != path and p.parent == path}
            core._need(set(self.tx.session.names(path)) == expected and core._identity(path.lstat()) == identity,
                       "stale-observation")
        for path, stamp in self.files.items():
            core._need(core._read(path, META_LIMIT)[0] == stamp, "stale-observation")

    def accept_body(self, digest, stamp):
        core._need(type(digest) is wire.BodyDigest and body._identity(stamp)
                   and self.body_initial is not None and self.body_current == self.body_initial
                   and not self.body_remove_entered, "authorization")
        core._need(stamp[:3] == self.body_initial[:3] and stamp[6:] == self.body_initial[6:]
                   and stamp[3] == digest.body_bytes and 32 < digest.body_bytes <= wire.MAX_BODY
                   and _digest_valid(digest.body_sha256) and push._OID.fullmatch(digest.pack_sha1) is not None,
                   "response-invalid")
        # Returned helper DATA comes only through the same channel. Preserve
        # that original positive comparison even if the following rematch/STOP
        # refuses the send; it is not a native settlement or retry permission.
        self.body_current = stamp
        self.check()

    def command(self):
        session, plan = self.tx.session, self.tx.plan
        environment = {"PATH": str(self.root / "exec"), "GIT_EXEC_PATH": str(self.root / "exec"),
            "HOME": str(self.root), "XDG_CONFIG_HOME": str(self.root), "LANG": "C", "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": os.devnull, "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0", "GIT_ATTR_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1", "GIT_LITERAL_PATHSPECS": "1",
            "GIT_ALLOW_PROTOCOL": "mrk", "GIT_PROTOCOL_FROM_USER": "0", "GIT_PAGER": "cat",
            "GIT_OBJECT_DIRECTORY": str(session.git_dir / "objects")}
        if self.tx.index is not None:
            environment["GIT_INDEX_FILE"] = str(self.tx.index)
        args = ["push", "--porcelain", "--no-progress", "--no-thin", "--recurse-submodules=no"]
        if self.tx.mode == "review":
            args += ["--dry-run"]
        selected = plan.target.selected
        args += [url(plan), selected.local_ref + ":" + selected.remote_ref]
        return [str(session.repository.git_executable), "--no-pager", "--no-replace-objects",
                "--git-dir=" + str(self.root), *args], environment

    def close(self, *, preserve=False):
        if self.closed:
            return not self.unknown
        if preserve or self.unknown:
            self.retained = True
            return not self.unknown  # No unlink/adoption of partial or unknown body.
        try:
            self.check()
            if self.body_initial is not None:
                core._need(not self.body_remove_entered and self.tx.complete, "recovery-required")
                self.body_remove_entered = True
                os.unlink(self.root / body.NAME)
                self.body_removed = True
            good = super().close()
            self.closed = good
            return good
        except BaseException:
            self.unknown = self.retained = True
            raise


class PushTransaction(local._LocalTransaction):
    def __init__(self, session, original, plan, owner, review_digest, mode):
        core._need(mode in ("review", "apply") and type(plan) is push.PushPlan
                   and (owner is None) == (mode == "review"), "invalid-input")
        super().__init__(session, original, plan, owner)
        self.mode, self.review_digest = mode, review_digest
        self.view = self.intent = self.body_digest = self.receipt = self.remote_status = None
        self.running = self.entered = self.complete = self.unknown = False
        self.hook_entered = self.hook_returned = self.ack_entered = self.acknowledged = False
        self.send_entered = self.send_consumed = False

    def prepare_view(self):
        core._need(self.view is None and not self.entered, "already-used")
        self.session.check_original(); self.session.guard_current()
        self.view = _View.__new__(_View)
        _View.__init__(self.view, self)

    def acquire(self):
        core._need(self.mode == "apply", "authorization")
        super().acquire()  # Same original config/index/HEAD locks and private index copy.
        self.prepare_view()
        self.check_original()

    def check_original(self):
        if self.mode == "apply":
            super().check_original()
        else:
            self.session.check_original()
            core._IndexTransaction.check_original(self)
            self.session.guard_current()
        core._need(all(self.session.selected_stamp(name)[0] == stamp
                       for name, stamp in self.original.file_stamps.items()), "stale-observation")

    def hook(self, raw, remote, location):
        """Only the retained original private-channel hook request calls this.

        The fixed hook cannot select another intent. Review checks but never
        arms; Apply retains the exact intent BEFORE the original durable handoff.
        """
        core._need(self.running and self.entered and not self.hook_entered and self.view is not None,
                   "authorization")
        core._need(raw == hook_line(self.plan.target.selected) and remote == location == url(self.plan),
                   "authorization")
        self.hook_entered = True
        self.check_original(); self.view.check()
        if self.mode == "apply":
            self.intent = push.PushIntent.from_plan(self.plan, self.review_digest)
            self.ack_entered = True
            # Actual native caller owns/joins the original candidate CAS. A
            # fake test delegate or equal serialized value supplies no grant.
            self.owner.record_intent(self.intent)
            self.check_original(); self.view.check()
            self.acknowledged = True
        self.hook_returned = True

    def consume_send(self, digest, stamp):
        core._need(self.mode == "apply" and self.running and self.entered and self.hook_returned
                   and self.acknowledged and self.intent is not None and not self.send_entered,
                   "authorization")
        self.send_entered = True  # A lost original send-point reply never permits another request.
        self.body_digest = digest
        self.view.accept_body(digest, stamp)
        self.check_original(); self.view.check()
        self.send_consumed = True

    def observe_status(self, value):
        """Keep a genuine bounded response even if later IO/native checks fail."""
        core._need(self.mode == "apply" and self.running and self.send_consumed and self.remote_status is None
                   and type(value) is wire.Status, "authorization")
        selected = self.plan.target.selected
        core._need((value.reference, value.old_oid, value.new_oid)
                   == (selected.remote_ref, selected.old_oid, selected.new_oid), "response-invalid")
        self.remote_status = value

    def observe_return(self, value):
        core._need(self.running and self.entered and self.receipt is None and type(value) is Returned
                   and value.mode == self.mode and value.selected == self.plan.target.selected
                   and self.hook_returned, "authorization")
        if self.mode == "apply":
            core._need(self.send_consumed and value.body == self.body_digest
                       and value.status == self.remote_status, "authorization")
        self.receipt = value

    def run(self):
        core._need(not self.entered and self.view is not None and callable(self.session.repository._remote), "authorization")
        self.check_original(); self.view.check()
        argv, environment = self.view.command()
        remaining = self.session.deadline - time.monotonic()
        self.session.calls += 1
        core._need(self.session.calls <= core.MAX_CALLS and remaining >= 1, "deadline")
        self.entered = self.running = True
        try:
            result = self.session.repository._remote(argv, cwd=self.view.root, environ=environment,
                capture=True, text=False, timeout=min(45, math.floor(remaining)), output_limit=256 * 1024,
                cancellation=self.session.repository.cancellation, execution_scope=None)
            core._need(result.args == argv and type(result.returncode) is int and type(result.stdout) is bytes
                       and type(result.stderr) is bytes and len(result.stdout) + len(result.stderr) <= 256 * 1024,
                       "response-invalid")
            push.require(result.returncode == 0, "push-remote-refused")
            # Git0/porcelain is never an alternative to the same private
            # helper/channel return. No output text becomes an operation grant.
            core._need(self.receipt is not None and self.hook_returned, "recovery-required")
            self.view.check(); self.check_original()
            self.complete = True
        finally:
            self.running = False

    def close(self, *, preserve_scratch=False):
        known = self.unknown
        good = True
        first = None
        try:
            if self.view is not None:
                good = self.view.close(preserve=preserve_scratch or known)
                known |= self.view.unknown
        except BaseException as error:
            first, known, good = error, True, False
        try:
            # Always retire the original lock routes when actual process
            # lifetime is known. Retained private output does not hold a lock
            # forever, nor does closing a descriptor settle a remote mutation.
            good = super().close(preserve_scratch=preserve_scratch or known) and good
        except BaseException as error:
            known, good = True, False
            if first is None:
                first = error
        self.unknown |= known
        self.retained |= preserve_scratch or not good or known or self.view is not None and self.view.retained
        if first is not None:
            raise first
        return good

    def diagnostics(self):
        paths = ()
        if self.retained and self.view is not None and self.view.root is not None:
            paths = (str(self.view.root.relative_to(self.session.git_dir)),)
        phase = ("remote-returned" if self.receipt is not None else "send-consumed" if self.send_consumed
                 else "send-entered" if self.send_entered else "candidate-acknowledged" if self.acknowledged
                 else "candidate-entered" if self.ack_entered else "not-sent")
        return phase, paths
