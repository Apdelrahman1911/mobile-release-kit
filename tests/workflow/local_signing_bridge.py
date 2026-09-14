"""Fixed, credential-free model transport; never a command/fence authority.

Both FIFO endpoints are opened after target exec. No socket, inherited account
descriptor, O_RDWR endpoint or dummy writer can conceal original peer loss.
"""
from __future__ import annotations

import json
import math
import os
import select
import stat
import time
from pathlib import Path

VERSION = 1
NAMES = ("events.fifo", "acks.fifo")
MAX_FRAME = 65536
MAX_FRAMES = 512
MAX_BYTES = 2 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise AssertionError("model bridge: " + message)


def remaining(deadline):
    require(type(deadline) is float and math.isfinite(deadline), "invalid original cutoff")
    value = deadline - time.monotonic()
    require(value > 0, "original cutoff expired")
    return value


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate frame key")
        result[key] = value
    return result


def decode(data):
    require(type(data) is bytes and 0 < len(data) <= MAX_FRAME, "invalid frame bytes")
    return json.loads(data.decode("ascii"), object_pairs_hook=_pairs,
                      parse_constant=lambda _: require(False, "nonfinite frame"))


def result_policy(value=None):
    """Finite target behavior, never a fabricated caller outcome or callback."""
    if value is None:
        value = {"returncode": 0, "perform_effect": True, "stdout": None, "stderr": ""}
    require(type(value) is dict and set(value) == {"returncode", "perform_effect", "stdout", "stderr"},
            "fixed model result policy fields")
    require(type(value["returncode"]) is int and 0 <= value["returncode"] <= 255
            and type(value["perform_effect"]) is bool
            and (value["stdout"] is None or type(value["stdout"]) is str and len(value["stdout"].encode("utf-8")) <= 8192)
            and type(value["stderr"]) is str and len(value["stderr"].encode("utf-8")) <= 8192,
            "fixed model result policy values")
    require(value["perform_effect"] or value["returncode"] != 0, "omitted effect cannot be a successful model command")
    return dict(value)


class Namespace:
    """Preregistered original directory/node slots; no finalizer or close retry."""

    def __init__(self, path, binding=None, *, create=False):
        self.path = Path(path)
        self.directory = None
        self.descriptors = {}
        self.close_errors = []
        self.binding = binding
        self.created = create
        try:
            if create:
                self.path.mkdir(mode=0o700)
            before = self.path.lstat()
            require(stat.S_ISDIR(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o700
                    and before.st_uid == os.getuid(), "private directory required")
            self.directory = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            require(identity(os.fstat(self.directory)) == identity(before), "directory changed during open")
            if create:
                for name in NAMES:
                    os.mkfifo(name, 0o600, dir_fd=self.directory)
                self.binding = {"directory": list(identity(os.fstat(self.directory))), "nodes": {}}
                for name in NAMES:
                    self.binding["nodes"][name] = list(identity(os.stat(name, dir_fd=self.directory, follow_symlinks=False)))
            self.validate()
        except BaseException:
            self.close()
            raise

    def validate(self):
        require(type(self.binding) is dict and set(self.binding) == {"directory", "nodes"}, "binding fields")
        require(type(self.binding["nodes"]) is dict and set(self.binding["nodes"]) == set(NAMES), "node inventory")
        require(all(type(value) is list and len(value) == 6 and all(type(item) is int for item in value)
                    for value in (self.binding["directory"], *self.binding["nodes"].values())), "binding identities")
        require(list(identity(os.fstat(self.directory))) == self.binding["directory"]
                and list(identity(self.path.lstat())) == self.binding["directory"], "original directory mismatch")
        require(set(os.listdir(self.directory)) == set(NAMES), "unexpected namespace entry")
        for name in NAMES:
            info = os.stat(name, dir_fd=self.directory, follow_symlinks=False)
            require(stat.S_ISFIFO(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
                    and info.st_uid == os.getuid() and info.st_nlink == 1
                    and list(identity(info)) == self.binding["nodes"][name], "original FIFO mismatch")

    def open(self, name, flags, deadline):
        require(name in NAMES and name not in self.descriptors, "duplicate or unknown node")
        remaining(deadline)
        self.validate()
        # Set the slot before post-open validation; any failure retains one
        # actual close attempt rather than reopening a pathname or raw FD.
        descriptor = os.open(name, flags | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=self.directory)
        self.descriptors[name] = descriptor
        require(list(identity(os.fstat(descriptor))) == self.binding["nodes"][name], "opened FIFO changed")
        self.validate()
        return descriptor

    def close_node(self, name):
        descriptor = self.descriptors.pop(name, None)
        if descriptor is not None:
            try:
                os.close(descriptor)
            except BaseException as error:
                self.close_errors.append(error)

    def close(self):
        for name in tuple(self.descriptors):
            self.close_node(name)
        descriptor, self.directory = self.directory, None
        if descriptor is not None:
            try:
                os.close(descriptor)
            except BaseException as error:
                self.close_errors.append(error)
        return not self.close_errors

    def remove(self):
        require(self.created and self.directory is not None and not self.descriptors and not self.close_errors,
                "namespace has unresolved original custody")
        self.validate()
        for name in NAMES:
            info = os.stat(name, dir_fd=self.directory, follow_symlinks=False)
            require(list(identity(info)) == self.binding["nodes"][name], "replacement FIFO preserved")
            os.unlink(name, dir_fd=self.directory)
        before = identity(os.fstat(self.directory))
        require(identity(self.path.lstat()) == before and not os.listdir(self.directory), "directory changed before removal")
        os.rmdir(self.path)
        require(self.close(), "namespace close failed")


class Channel:
    def __init__(self, descriptor, deadline, *, stop=None):
        self.descriptor, self.deadline = descriptor, deadline
        self.stop = stop
        self.buffer = bytearray()
        self.bytes = self.frames = 0
        self.established = False
        self.eof = False

    def check(self):
        require(self.stop is None or not self.stop.is_set(), "original service retired")
        return remaining(self.deadline)

    def _charge(self, count):
        self.bytes += count
        require(self.bytes <= MAX_BYTES, "channel byte bound")

    def send(self, value):
        data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
        require(0 < len(data) <= MAX_FRAME and self.frames < MAX_FRAMES, "send frame bound")
        self.frames += 1  # Attempt is retired even if the first write fails.
        data = len(data).to_bytes(4, "big") + data
        offset = 0
        while offset < len(data):
            self.check()
            _, writable, _ = select.select([], [self.descriptor], [], min(.02, remaining(self.deadline)))
            if not writable:
                continue
            count = os.write(self.descriptor, data[offset:])
            require(type(count) is int and 0 < count <= len(data) - offset, "incomplete frame write")
            self._charge(count)
            offset += count
        self.check()

    def receive(self):
        while True:
            self.check()
            if len(self.buffer) >= 4:
                size = int.from_bytes(self.buffer[:4], "big")
                require(0 < size <= MAX_FRAME, "advertised frame bound")
                if len(self.buffer) >= size + 4:
                    require(self.frames < MAX_FRAMES, "receive frame bound")
                    self.frames += 1
                    data = bytes(self.buffer[4:4 + size])
                    del self.buffer[:4 + size]
                    value = decode(data)
                    self.check()  # Decode cannot extend original peer/clock authority.
                    return value
            readable, _, _ = select.select([self.descriptor], [], [], min(.02, remaining(self.deadline)))
            if not readable:
                continue
            data = os.read(self.descriptor, min(4096, MAX_FRAME + 4 - len(self.buffer)))
            if not data:
                require(not self.established, "original peer EOF")
                # An unopened FIFO has no writer. This is not admission and
                # cannot authorize an effect or refresh the original cutoff.
                time.sleep(min(.002, remaining(self.deadline)))
                continue
            self._charge(len(data))
            self.buffer.extend(data)

    def require_eof(self):
        require(self.established and not self.buffer, "unconsumed peer frames")
        while True:
            self.check()
            ready, _, _ = select.select([self.descriptor], [], [], min(.02, remaining(self.deadline)))
            if ready:
                value = os.read(self.descriptor, 1)
                require(value == b"", "extra peer bytes after final ACK")
                self.eof = True
                return


class RemoteTrace:
    """Target requests observations; only original worker executes Trace.cut."""

    def __init__(self, events, acks):
        self.events, self.acks = events, acks
        self.sequence = 0
        self.last_event_index = 0
        self.occurrences = {}

    def request(self, kind, value):
        self.sequence += 1
        self.events.send({"version": VERSION, "sequence": self.sequence, "kind": kind, "value": value})
        result = self.acks.receive()
        require(type(result) is dict and set(result) == {"version", "sequence", "kind", "value"}
                and type(result["version"]) is int and result["version"] == VERSION
                and type(result["sequence"]) is int and result["sequence"] == self.sequence
                and result["kind"] == kind + "-ACK", "wrong or replayed ACK")
        require(kind not in {"END", "DONE"} or result["value"] is None, "invalid terminal ACK value")
        return result["value"]

    def begin(self, operation, slot, origin, details):
        require(type(operation) is str and operation.startswith(("native/", "native-effect/"))
                and len(operation) <= 256 and slot == "native" and origin == "model"
                and type(details) is dict and not details, "unmodeled BEGIN request")
        event = self.request("BEGIN", {"operation": operation, "slot": slot, "origin": origin, "details": details})
        require(type(event) is dict and set(event) == {"index", "operation", "slot", "origin", "phase", "occurrence", "details"}
                and type(event["index"]) is int and self.last_event_index < event["index"] <= 1_000_000
                and type(event["occurrence"]) is int and 1 <= event["occurrence"] <= 1_000_000
                and type(event["phase"]) is str and event["phase"] in {"setup", "build", "cleanup", "recovery"}
                and event["operation"] == operation and event["slot"] == slot and event["origin"] == origin
                and type(event["details"]) is dict and event["details"] == details, "invalid BEGIN ACK event")
        key = (operation, event["phase"])
        require(key not in self.occurrences or event["occurrence"] == self.occurrences[key] + 1,
                "replayed BEGIN ACK occurrence")
        self.last_event_index = event["index"]
        self.occurrences[key] = event["occurrence"]
        return event

    def partial(self, event):
        value = self.request("PARTIAL", event)
        require(type(value) is bool, "invalid partial decision")
        return value

    def end(self, event, *, succeeded, error=None):
        self.request("END", {"event": event, "succeeded": succeeded, "error": error})

    def cut(self, event, edge):
        self.request("CUT", {"event": event, "edge": edge})
        raise AssertionError("selected original-worker crash returned an ACK")
