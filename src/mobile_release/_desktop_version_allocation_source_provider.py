"""Closed SOURCE-only CLT Git binding, not a native provider nomination.

The installed parent retains its own original SourceBook and supplies these
snapshots. This child supplements that custody with the SAME checked reader
and invocation; it cannot accept an executable path, grant a GitRead ticket,
change the ordinary LocalSource default, or create a command executor.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
import sys

from . import _desktop_version_allocation_source_protocol as wire
from . import version_policy as policy
from .cancellation import CleanupScope
from .checked_files import _Reader, _Policy, _directory_identity, _file_identity

KIND = "macos-clt-git/1"
TOOL_PATH = Path("/Library/Developer/CommandLineTools/usr/bin/git")
TOOL_LIMIT = 128 * 1024 * 1024
TOOL_FDS = 7
STREAM_CHUNK = 32768
HELD_SOURCE_FDS = 96 + TOOL_FDS
assert len(TOOL_PATH.parts) == TOOL_FDS


@dataclass(frozen=True, slots=True, repr=False)
class Snapshot:
    identity: tuple[int, ...]
    sha256: str

    def value(self):
        return {"identity": list(self.identity), "sha256": self.sha256}


def _directory(value, uid):
    wire.require(type(value) is list and len(value) == 5)
    fields = tuple(policy._integer(v, (1 << (64 if i < 2 else 32)) - 1) for i, v in enumerate(value))
    wire.require(fields[0] > 0 and fields[1] > 0 and stat.S_ISDIR(fields[2])
                 and fields[3] == uid and not fields[2] & 0o7022)
    return fields


def _snapshot(value, uid, maximum, *, executable=False):
    row = policy._object(value, {"identity", "sha256"})
    identity = row["identity"]
    wire.require(type(identity) is list and len(identity) == 9)
    fields = tuple(policy._integer(v, (1 << (64 if i < 2 or i in {5, 6} else 32)) - 1)
                   if i < 7 else policy._integer(v, (1 << 63) - 1, -(1 << 63))
                   for i, v in enumerate(identity))
    wire.require(fields[0] > 0 and fields[1] > 0 and stat.S_ISREG(fields[2])
                 and fields[3] == uid and fields[5] == 1 and 0 < fields[6] <= maximum
                 and not fields[2] & 0o7022 and (not executable or fields[2] & 0o111))
    return Snapshot(fields, policy._match(row["sha256"], policy._DIGEST))


@dataclass(frozen=True, slots=True, repr=False)
class Provider:
    uid: int
    gid: int
    root: Path
    directories: tuple[tuple[int, ...], ...]
    tool: Snapshot
    files: tuple[Snapshot, ...]

    @classmethod
    def parse(cls, value, request):
        wire.require(type(request) is wire.SourceRequest)
        row = policy._object(value, {"kind", "native"})
        wire.require(row["kind"] == KIND)
        native = policy._object(row["native"], {"uid", "gid", "root", "directories", "tool", "files"})
        uid = policy._integer(native["uid"], (1 << 32) - 1)
        gid = policy._integer(native["gid"], (1 << 32) - 1)
        wire.require(native["root"] == str(request.root))
        directories = policy._object(native["directories"], {"root", "git", "objects"})
        directories = tuple(_directory(directories[name], uid) for name in ("root", "git", "objects"))
        wire.require(directories[0] == request.identity)
        files = policy._object(native["files"], {"HEAD", "config", "index"})
        # LocalSource is deliberately stricter than GitRead: an actual index,
        # HEAD <=1KiB and index <=2MiB. Do not inherit its broader read limits.
        snapshots = tuple(_snapshot(files[name], uid, maximum)
                          for name, maximum in (("HEAD", 1024), ("config", 65536), ("index", 2 << 20)))
        return cls(uid, gid, request.root, directories, _snapshot(native["tool"], 0, TOOL_LIMIT, executable=True), snapshots)

    def value(self):
        return {"kind": KIND, "native": {"uid": self.uid, "gid": self.gid, "root": str(self.root),
            "directories": {name: list(value) for name, value in zip(("root", "git", "objects"), self.directories)},
            "tool": self.tool.value(),
            "files": {name: value.value() for name, value in zip(("HEAD", "config", "index"), self.files)}}}


class HeldProvider:
    def __init__(self, operation, selection):
        from .version_allocation_source import AllocationSourceRun
        wire.require(type(operation) is AllocationSourceRun and type(selection) is Provider
                     and operation.input.operation is operation and operation.selected is None
                     and type(operation.input.dialogue.initial) is wire.Initial
                     and operation.input.dialogue.initial.provider is selection
                     and Provider.parse(selection.value(), operation.request) == selection)
        wire.require((os.getuid(), os.geteuid(), os.getgid(), os.getegid()) ==
                     (selection.uid, selection.uid, selection.gid, selection.gid))
        self.operation, self.selection = operation, selection
        self.reader = _Reader(operation.guard)  # Retained BEFORE an open can fail.
        self.node = None
        self.started = self.close_claimed = self.final_checked = False
        self.close_error = None

    def _owner(self):
        run = self.operation
        run._owner()
        wire.require(run.provider is self and run.input.dialogue.initial.provider is self.selection
                     and not self.close_claimed and not run.failed and not run.close_claimed)
        run.checkpoint()
        wire.require((os.getuid(), os.geteuid(), os.getgid(), os.getegid()) ==
                     (self.selection.uid, self.selection.uid, self.selection.gid, self.selection.gid))

    def _tool(self, *, hash_file):
        self._owner()
        wire.require(self.started and self.node is not None and self.node.canonical == TOOL_PATH
                     and len(self.reader.descriptors) == TOOL_FDS and len(self.reader.nodes) == TOOL_FDS
                     and not self.reader.aliases)
        # The fixed executable's complete path is system owned. A user-writable
        # prefix cannot gain pathname-exec authority from a leaf hash alone.
        for node in self.reader.nodes:
            wire.require(node.observed.st_uid == 0 and not node.observed.st_mode & 0o7022
                         and not getattr(node.observed, "st_flags", 0))
        self.reader.terminal()
        wire.require(_file_identity(self.node.observed) == self.selection.tool.identity)
        if hash_file:
            fd = self.reader._number(self.node.slot)
            os.lseek(fd, 0, os.SEEK_SET)
            count, digest = 0, hashlib.sha256()
            while True:
                self._owner()
                block = os.read(fd, min(STREAM_CHUNK, self.selection.tool.identity[6] + 1 - count))
                self._owner()
                if not block:
                    break
                count += len(block)
                wire.require(count <= self.selection.tool.identity[6])
                digest.update(block)
            wire.require(count == self.selection.tool.identity[6] and digest.hexdigest() == self.selection.tool.sha256)
            self.reader.terminal()

    def source_matches(self, observation):
        run = self.operation
        self._tool(hash_file=False)
        wire.require(observation is run.observation and observation._composition is run
                     and observation.invocation is run.invocation and observation.root == self.selection.root
                     and not observation.closed)
        observation._unchanged()
        for relative, expected in zip(("", ".git", ".git/objects"), self.selection.directories):
            node = observation.directories.get(run.root / relative)
            wire.require(node is not None and _directory_identity(node.observed) == expected)
        for relative, expected in zip((".git/HEAD", ".git/config", ".git/index"), self.selection.files):
            matches = [(reader, node, raw) for reader, node, raw in observation.files
                       if node.canonical == run.root / relative]
            wire.require(len(matches) == 1)
            reader, node, raw = matches[0]
            wire.require(reader in observation.readers and _file_identity(node.observed) == expected.identity
                         and len(raw) == expected.identity[6] and hashlib.sha256(raw).hexdigest() == expected.sha256)
        wire.require(observation.descriptor_quote() <= 96
                     and observation.held + len(self.reader.descriptors) <= HELD_SOURCE_FDS)

    def executable(self, observation):
        self.source_matches(observation)
        return str(TOOL_PATH)  # No caller path, environment override or PATH search.

    def command_returned(self, observation):
        self.source_matches(observation)
        if self.operation.phase == "final":
            wire.require(not self.final_checked)
            self._tool(hash_file=True)
            self.final_checked = True

    def close(self):
        if self.close_claimed:
            self.reader.assert_closed()
            if self.close_error is not None:
                raise self.close_error
            return
        self.close_claimed = True
        try:
            self.reader.close()
            self.reader.assert_closed()
        except BaseException as error:
            self.close_error = error
            self.operation.guard._abort(error)
            raise

    def originals_closed(self):
        self.reader.assert_closed()
        return (not self.started or self.close_claimed) and self.close_error is None

    @contextmanager
    def hold(self):
        self._owner()
        wire.require(not self.started)
        scope = CleanupScope(self.operation.guard, self.close, owns_cancellation=False,
                             fork_cleanup=self.reader.after_fork_child, first_primary=True)
        try:
            with scope:
                self.started = True
                self.node = self.reader.acquire(TOOL_PATH, _Policy(False, 1, TOOL_LIMIT), None)
                self._tool(hash_file=True)
                yield
                wire.require(self.final_checked)
                self._tool(hash_file=False)
        finally:
            scope.__exit__(*sys.exc_info())
        wire.require(self.originals_closed())
