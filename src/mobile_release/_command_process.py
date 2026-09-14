"""Private original-child command lifecycle and bounded byte transport.

Only the fixed C/A/W entries use this protocol.  A nonce, descriptor number,
serialized status or diagnostic observation is not an ownership capability.
Importing the module does not acquire a resource or start a worker.
"""
from __future__ import annotations

import errno
import hashlib
import json
import math
import os
import select
import signal
import stat
import struct
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any

from . import _native_process as native
from . import cancellation as cancellation_state
from .cancellation import CleanupScope, DefaultCancellation, cancellation_owner
from .owned_process import (
    OUTPUT_LIMIT, PRIVATE_OUTPUT_LIMIT, REQUEST_LIMIT, ProcessCleanupError,
    ProcessError, ProcessOutcomeUnknown, _json, _valid_request, preserve_lifetime_error,
)

NANOSECOND = 1_000_000_000
CLEANUP_NS = 3 * NANOSECOND
CHUNK = 65_536
SCALAR_LIMIT = 1024
SCALAR_COUNT = 16
PID_LIMIT = (1 << 31) - 1
INTEGER_LIMIT = (1 << 63) - 1
ERROR = "owned command protocol or original ownership is incomplete"
TIMEOUT = "owned command exceeded its original deadline"
_KEY = object()
_RETAINED: list[Any] = []


def _require(condition: bool, message: str = ERROR) -> None:
    if not condition:
        raise ProcessError(message)


def _integer(value: Any, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high


def _nonce(value: Any) -> bool:
    return type(value) is bytes and len(value) == 16


def _u64(value: int) -> bytes:
    _require(_integer(value, 0, (1 << 64) - 1))
    return value.to_bytes(8, "big")


def _u128(value: int) -> bytes:
    _require(_integer(value, 0, (1 << 128) - 1))
    return value.to_bytes(16, "big")


@dataclass(frozen=True, slots=True)
class Manifest:
    nonce: bytes
    capture: bool
    search: bool
    json_size: int
    limit: int
    host_envelope: int
    argc: int
    envc: int
    dirc: int
    argument_bytes: int
    cwd_bytes: int
    environment_bytes: int
    directory_bytes: int
    record_bytes: int
    digest: bytes

    def validate(self) -> None:
        _require(sys.maxsize == INTEGER_LIMIT and _nonce(self.nonce))
        _require(type(self.capture) is bool and type(self.search) is bool)
        _require(_integer(self.json_size, 1, REQUEST_LIMIT)
                 and _integer(self.limit, 1, OUTPUT_LIMIT)
                 and _integer(self.host_envelope, 1, INTEGER_LIMIT))
        _require(_integer(self.argc, 1, 4096)
                 and _integer(self.envc, 0, self.host_envelope // 3)
                 and _integer(self.dirc, 1 if self.search else 0, INTEGER_LIMIT)
                 and (self.search or self.dirc == 0))
        _require(_integer(self.argument_bytes, 1, self.argc * INTEGER_LIMIT)
                 and _integer(self.cwd_bytes, 1, INTEGER_LIMIT)
                 and _integer(self.environment_bytes, 0, self.host_envelope)
                 and _integer(self.directory_bytes, 0, self.dirc * INTEGER_LIMIT))
        expected = (32 + 8 * self.argc + 14 * self.envc + 8 * self.dirc
                    + self.argument_bytes + self.cwd_bytes
                    + self.environment_bytes + self.directory_bytes)
        _require(type(self.record_bytes) is int and self.record_bytes == expected
                 and 0 < expected < 1 << 127
                 and type(self.digest) is bytes and len(self.digest) == 32)

    def encode(self) -> bytes:
        self.validate()
        result = (bytes((1, int(self.capture) | (int(self.search) << 1))) + self.nonce
                  + struct.pack(">II", self.json_size, self.limit)
                  + b"".join(_u64(value) for value in
                             (self.host_envelope, self.argc, self.envc, self.dirc))
                  + _u128(self.argument_bytes) + _u64(self.cwd_bytes)
                  + _u64(self.environment_bytes) + _u128(self.directory_bytes)
                  + _u128(self.record_bytes) + self.digest)
        _require(len(result) == 154)
        return result

    @classmethod
    def decode(cls, content: bytes) -> Manifest:
        _require(type(content) is bytes and len(content) == 154
                 and content[0] == 1 and content[1] & ~3 == 0)
        offset = 18

        def number(width: int) -> int:
            nonlocal offset
            value = int.from_bytes(content[offset:offset + width], "big")
            offset += width
            return value

        j, limit = number(4), number(4)
        host, n, m, d = (number(8) for _ in range(4))
        a, c, e, directories, size = number(16), number(8), number(8), number(16), number(16)
        result = cls(content[2:18], bool(content[1] & 1), bool(content[1] & 2),
                     j, limit, host, n, m, d, a, c, e, directories, size, content[offset:])
        result.validate()
        return result


@dataclass(frozen=True, slots=True)
class FrozenCommand:
    args: tuple[str, ...]
    argv: tuple[bytes, ...]
    cwd: bytes
    environment: tuple[tuple[bytes, bytes], ...]
    directories: tuple[bytes, ...]
    manifest: Manifest

    def pieces(self) -> Iterator[bytes]:
        """No B-sized staging record and no expanded executable candidates."""
        yield _u64(len(self.argv))
        for arg in self.argv:
            yield _u64(len(arg))
            yield arg
        yield _u64(len(self.cwd))
        yield self.cwd
        yield _u64(len(self.environment))
        for key, value in self.environment:
            yield _u64(len(key))
            yield _u64(len(value))
            yield key
            yield value
        yield _u64(len(self.directories))
        for directory in self.directories:
            yield _u64(len(directory))
            yield directory

    def chunks(self) -> Iterator[bytes]:
        pending = bytearray()
        for piece in self.pieces():
            remaining = memoryview(piece)
            while remaining:
                take = min(CHUNK - len(pending), len(remaining))
                pending.extend(remaining[:take])
                remaining = remaining[take:]
                if len(pending) == CHUNK:
                    yield bytes(pending)
                    pending.clear()
        if pending:
            yield bytes(pending)


def _freeze_command(argv: Sequence[str], *, environ: Mapping[str, str] | None,
                    cwd: Path | None, capture: bool, output_limit: int,
                    nonce: bytes) -> FrozenCommand:
    _require(_nonce(nonce))
    arguments = []
    for value in argv:
        _require(len(arguments) < 4096)
        arguments.append(value)
    request = {"argv": arguments, "cwd": str(Path.cwd() if cwd is None else cwd.absolute()),
               "capture": capture, "limit": output_limit}
    _valid_request(request)
    # Preserve the exact canonical JSON admission predicate, without ever
    # joining a caller's potentially enormous repeated-reference argv vector.
    # ensure_ascii makes each emitted character exactly one encoded byte. An
    # individual argument was already bounded above; stop at the first excess
    # fragment rather than encoding/allocating the rest of the document.
    canonical_size = 0
    encoder = json.JSONEncoder(ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)
    for fragment in encoder.iterencode(request):
        canonical_size += len(fragment)
        _require(canonical_size <= REQUEST_LIMIT)
    environment = dict(os.environ if environ is None else environ)
    _require(all(type(key) is str and type(value) is str for key, value in environment.items()))
    host = os.sysconf("SC_ARG_MAX")
    _require(sys.maxsize == INTEGER_LIMIT and _integer(host, 1, INTEGER_LIMIT),
             "owned command host argument envelope is unavailable")

    def encode(value: str, *, nonempty: bool = False) -> bytes:
        raw = os.fsencode(value)
        _require(type(raw) is bytes and b"\0" not in raw and len(raw) <= INTEGER_LIMIT
                 and (bool(raw) or not nonempty))
        return raw

    args = tuple(encode(value, nonempty=index == 0) for index, value in enumerate(arguments))
    working = encode(request["cwd"], nonempty=True)
    _require(os.path.isabs(working))
    pairs, keys = [], set()
    env_size = 0
    for key, value in environment.items():
        name, data = encode(key, nonempty=True), encode(value)
        _require(b"=" not in name and name not in keys)
        keys.add(name)
        env_size += len(name) + len(data) + 2
        _require(env_size <= host)
        pairs.append((name, data))
    search = b"/" not in args[0]
    directories = tuple(encode(value) for value in os.get_exec_path(environment)) if search else ()
    a, c, d = sum(map(len, args)), len(working), sum(map(len, directories))
    size = 32 + 8 * len(args) + 14 * len(pairs) + 8 * len(directories) + a + c + env_size + d
    temporary = Manifest(nonce, capture, search, canonical_size, output_limit, host,
                         len(args), len(pairs), len(directories), a, c, env_size, d, size, bytes(32))
    frozen = FrozenCommand(tuple(arguments), args, working, tuple(pairs), directories, temporary)
    digest, actual = hashlib.sha256(), 0
    for piece in frozen.pieces():
        digest.update(piece)
        actual += len(piece)
    _require(actual == size)
    manifest = Manifest(nonce, capture, search, canonical_size, output_limit, host,
                        len(args), len(pairs), len(directories), a, c, env_size, d, size, digest.digest())
    manifest.validate()
    return FrozenCommand(frozen.args, args, working, tuple(pairs), directories, manifest)


class NativeRecordDecoder:
    """Grow required W fields from received bytes, never advertised lengths."""
    def __init__(self, manifest: Manifest) -> None:
        manifest.validate()
        self.manifest = manifest
        self.argv: list[bytes] = []
        self.cwd = b""
        self.environment: dict[bytes, bytes] = {}
        self.directories: list[bytes] = []
        self.poisoned = self.complete = False
        self.received = 0
        self.digest = hashlib.sha256()
        self.buffer = bytearray()
        self.parser = self._fields()
        self.need = next(self.parser)

    def _fields(self):
        m = self.manifest
        _require(int.from_bytes((yield 8), "big") == m.argc)
        total = 0
        for index in range(m.argc):
            count = int.from_bytes((yield 8), "big")
            _require(count <= INTEGER_LIMIT and count <= m.argument_bytes - total
                     and (count > 0 or index != 0))
            value = yield count
            _require(b"\0" not in value)
            self.argv.append(value)
            total += count
        _require(total == m.argument_bytes and (b"/" not in self.argv[0]) == m.search)
        _require(int.from_bytes((yield 8), "big") == m.cwd_bytes)
        self.cwd = yield m.cwd_bytes
        _require(b"\0" not in self.cwd and os.path.isabs(self.cwd))
        _require(int.from_bytes((yield 8), "big") == m.envc)
        total = 0
        for _ in range(m.envc):
            key_size = int.from_bytes((yield 8), "big")
            value_size = int.from_bytes((yield 8), "big")
            _require(0 < key_size <= INTEGER_LIMIT and value_size <= INTEGER_LIMIT
                     and key_size + value_size + 2 <= m.environment_bytes - total)
            key, value = (yield key_size), (yield value_size)
            _require(b"\0" not in key and b"=" not in key and key not in self.environment
                     and b"\0" not in value)
            self.environment[key] = value
            total += key_size + value_size + 2
        _require(total == m.environment_bytes)
        _require(int.from_bytes((yield 8), "big") == m.dirc)
        total = 0
        for _ in range(m.dirc):
            count = int.from_bytes((yield 8), "big")
            _require(count <= INTEGER_LIMIT and count <= m.directory_bytes - total)
            value = yield count
            _require(b"\0" not in value)
            self.directories.append(value)
            total += count
        _require(total == m.directory_bytes)

    def feed(self, content: bytes) -> None:
        try:
            _require(not self.poisoned and not self.complete and type(content) is bytes
                     and 0 < len(content) <= CHUNK)
            _require(self.received + len(content) <= self.manifest.record_bytes)
            self.received += len(content)
            self.digest.update(content)
            offset = 0
            while offset < len(content) or self.need == 0:
                take = min(self.need - len(self.buffer), len(content) - offset)
                self.buffer.extend(content[offset:offset + take])
                offset += take
                if len(self.buffer) != self.need:
                    break
                field = bytes(self.buffer)
                self.buffer.clear()
                try:
                    self.need = self.parser.send(field)
                except StopIteration:
                    _require(offset == len(content)
                             and self.received == self.manifest.record_bytes
                             and self.digest.digest() == self.manifest.digest)
                    self.complete = True
                    break
        except BaseException:
            self.poisoned = True
            raise

    def finish(self) -> None:
        try:
            _require(self.complete and not self.poisoned and not self.buffer)
        except BaseException:
            self.poisoned = True
            raise


class FenceObservationPolicy(IntEnum):
    OFF = 0
    TRACE_V1 = 1


class FenceOperation(IntEnum):
    PENDING_CREATE = 1
    PENDING_WRITE = 2
    DATA_FSYNC = 3
    PENDING_CLOSE = 4
    FINAL_LINK = 5
    DIRECTORY_FSYNC = 6


class FenceEdge(IntEnum):
    BEFORE = 0
    PARTIAL = 1
    AFTER = 2


class FenceEventOutcome(IntEnum):
    PENDING = 0
    OK = 1
    ERROR = 2
    UNKNOWN = 3


@dataclass(frozen=True, slots=True)
class FenceObservation:
    nonce: bytes
    command_sequence: int
    ordinal: int
    operation: FenceOperation
    edge: FenceEdge
    outcome: FenceEventOutcome
    written: int
    total: int
    sync_flags: int
    identity_state: int
    creation_identity: tuple[int, int, int, int, int, int] | None
    operand: bytes = b""

    def encode(self) -> bytes:
        _require(_nonce(self.nonce) and _integer(self.command_sequence, 1, INTEGER_LIMIT)
                 and _integer(self.ordinal, 1, 13)
                 and type(self.operation) is FenceOperation and type(self.edge) is FenceEdge
                 and type(self.outcome) is FenceEventOutcome
                 and _integer(self.total, 2, 4096) and _integer(self.written, 0, self.total)
                 and _integer(self.sync_flags, 0, 3) and _integer(self.identity_state, 0, 2)
                 and type(self.operand) is bytes)
        identity = (0, 0, 0, 0, 0, 0) if self.creation_identity is None else self.creation_identity
        _require(type(identity) is tuple and len(identity) == 6)
        if self.identity_state == 1:
            _require(self.creation_identity is not None
                     and _integer(identity[0], 0, (1 << 64) - 1)
                     and _integer(identity[1], 1, (1 << 64) - 1)
                     and all(_integer(value, 0, (1 << 32) - 1) for value in identity[2:])
                     and identity[4] == stat.S_IFREG | 0o600 and identity[5] == 1)
        else:
            _require(self.creation_identity is None and identity == (0,) * 6)
        if self.edge is FenceEdge.PARTIAL:
            _require(self.operation is FenceOperation.PENDING_WRITE
                     and self.outcome is FenceEventOutcome.OK and self.identity_state == 1
                     and len(self.operand) == self.total // 2
                     and 0 < self.written <= len(self.operand) < self.total and self.sync_flags == 0)
        else:
            _require(not self.operand)
        _require((self.edge is FenceEdge.BEFORE) == (self.outcome is FenceEventOutcome.PENDING))
        return (bytes((1,)) + self.nonce + _u64(self.command_sequence)
                + struct.pack(">BBBBHHBBQQIIIIH", self.ordinal, int(self.operation),
                              int(self.edge), int(self.outcome), self.written, self.total,
                              self.sync_flags, self.identity_state, *identity, len(self.operand))
                + self.operand)

    @classmethod
    def decode(cls, content: bytes) -> FenceObservation:
        _require(type(content) is bytes and 69 <= len(content) <= 2117 and content[0] == 1)
        values = struct.unpack(">BBBBHHBBQQIIIIH", content[25:69])
        ordinal, op, edge, outcome, written, total, flags, state, *identity_and_length = values
        identity, length = tuple(identity_and_length[:-1]), identity_and_length[-1]
        _require(len(content) == 69 + length)
        try:
            result = cls(content[1:17], int.from_bytes(content[17:25], "big"), ordinal,
                         FenceOperation(op), FenceEdge(edge), FenceEventOutcome(outcome),
                         written, total, flags, state, identity if state == 1 else None, content[69:])
        except ValueError:
            raise ProcessError(ERROR) from None
        _require((state == 1 or identity == (0,) * 6) and result.encode() == content)
        return result

    def ack(self) -> bytes:
        return (bytes((1,)) + self.nonce + _u64(self.command_sequence)
                + bytes((self.ordinal, int(self.operation), int(self.edge))))


def _fence_trace_checkpoint(event: FenceObservation) -> None:
    """Fixed O-local test seam. OFF never calls this; no hook crosses IPC."""


class FenceObservationDecoder:
    def __init__(self, nonce: bytes, sequence: int, *, uid: int) -> None:
        self.nonce, self.sequence, self.uid = nonce, sequence, uid
        self.ordinal = 0
        self.operation = 1
        self.edge = FenceEdge.BEFORE
        self.identity: tuple[int, ...] | None = None
        self.total: int | None = None
        self.written = self.sync_flags = 0
        self.poisoned = self.finished = False

    def accept(self, content: bytes) -> FenceObservation:
        try:
            _require(not self.poisoned and not self.finished)
            event = FenceObservation.decode(content)
            failed = event.outcome in (FenceEventOutcome.ERROR, FenceEventOutcome.UNKNOWN)
            _require(event.nonce == self.nonce and event.command_sequence == self.sequence
                     and event.ordinal == self.ordinal + 1
                     and int(event.operation) == self.operation
                     and (event.edge == self.edge or failed and self.edge is FenceEdge.PARTIAL
                          and event.edge is FenceEdge.AFTER))
            if self.total is None:
                self.total = event.total
            _require(event.total == self.total and event.written >= self.written
                     and event.sync_flags & self.sync_flags == self.sync_flags)
            if failed:
                _require(event.edge is FenceEdge.AFTER
                         and event.sync_flags == self.sync_flags)
            elif event.edge is FenceEdge.BEFORE:
                _require(event.written == self.written and event.sync_flags == self.sync_flags)
            elif event.edge is FenceEdge.PARTIAL:
                _require(self.operation == 2)
            else:
                expected_written = event.total if self.operation >= 2 else 0
                expected_flags = 3 if self.operation == 6 else (1 if self.operation >= 3 else 0)
                _require(event.written == expected_written and event.sync_flags == expected_flags)
            if self.operation == 1 and event.edge is FenceEdge.BEFORE:
                _require(event.identity_state == 0)
            elif not failed:
                _require(event.identity_state == 1 and event.creation_identity is not None
                         and event.creation_identity[2] == self.uid)
                if self.identity is None:
                    _require(self.operation == 1 and event.edge is FenceEdge.AFTER)
                    self.identity = event.creation_identity
                _require(event.creation_identity == self.identity)
            elif event.identity_state == 1:
                _require(event.creation_identity == self.identity)
            else:
                _require(event.identity_state == 2 or self.operation == 1 and event.identity_state == 0)
            self.ordinal += 1
            self.written, self.sync_flags = event.written, event.sync_flags
            if failed:
                self.finished = True
            elif event.edge is FenceEdge.BEFORE:
                self.edge = FenceEdge.PARTIAL if self.operation == 2 else FenceEdge.AFTER
            elif event.edge is FenceEdge.PARTIAL:
                self.edge = FenceEdge.AFTER
            else:
                self.operation += 1
                self.edge = FenceEdge.BEFORE
                self.finished = self.operation == 7
            return event
        except BaseException:
            self.poisoned = True
            raise


class AccountExecutionSource:
    def __init__(self, lease: Any, locked_source: Any, authorization: Any, *, _key: object) -> None:
        _require(_key is _KEY)
        self._lease, self._locked_source, self._authorization = lease, locked_source, authorization
        self._pid, self._thread = os.getpid(), threading.current_thread()
        self._check()

    def _check(self) -> None:
        _require(os.getpid() == self._pid and threading.current_thread() is self._thread)
        self._lease._admit_execution(self._authorization)
        self._locked_source._check()

    def new_scope(self) -> AccountExecutionScope:
        self._check()
        return AccountExecutionScope(self, os.urandom(16), _key=_KEY)


class CommandOutcomeSlot:
    def __init__(self, scope: AccountExecutionScope | None, nonce: bytes, *, _key: object) -> None:
        _require(_key is _KEY and _nonce(nonce))
        self._scope, self._nonce = scope, nonce
        self._engine: Any = None
        self._value: OriginalCommandOutcome | None = None

    def read(self) -> OriginalCommandOutcome | None:
        return self._value

    def _bind(self, engine: Any) -> None:
        _require(self._engine is None and engine.nonce == self._nonce)
        self._engine = engine

    def _publish(self, engine: Any, outcome: OriginalCommandOutcome) -> None:
        _require(self._engine is engine and self._value is None
                 and outcome._engine is engine and outcome.nonce == self._nonce)
        self._value = outcome


class AccountExecutionScope:
    def __init__(self, source: AccountExecutionSource, nonce: bytes, *, _key: object) -> None:
        _require(_key is _KEY)
        self._source, self.nonce = source, nonce
        self._outcome = CommandOutcomeSlot(self, nonce, _key=_KEY)
        self._used = False
        self._binding: JournalledCommandBinding | None = None

    @property
    def outcome(self) -> CommandOutcomeSlot:
        return self._outcome

    def _consume(self, engine: Any, binding: JournalledCommandBinding | None) -> None:
        self._source._check()
        _require(not self._used and self._binding is binding)
        self._used = True
        self._outcome._bind(engine)


def _issue_account_execution_source(lease: Any, locked_source: Any, *, authorization: Any = None) -> AccountExecutionSource:
    lease._admit_execution(authorization)
    _require(locked_source._lease is lease)
    return AccountExecutionSource(lease, locked_source, authorization, _key=_KEY)


@dataclass(frozen=True, slots=True)
class RouteHistory:
    attempted: bool
    retired: bool


class OriginalCommandFinality:
    def __init__(self, engine: Any, *, _key: object) -> None:
        _require(_key is _KEY and engine.original_finality())
        self._engine = engine


class NoTargetProof:
    def __init__(self, engine: Any, tag: str, *, _key: object) -> None:
        _require(_key is _KEY and tag in ("NO_W_CREATION", "CLOSED_BEFORE_RUN", "EXEC_REJECTED"))
        self._engine, self.kind = engine, tag


@dataclass(frozen=True, slots=True)
class OriginalCommandOutcome:
    _engine: Any
    nonce: bytes
    create_w: RouteHistory
    run_tool: RouteHistory
    no_target: NoTargetProof | None
    termination: str
    returncode: int | None
    result_integrity: str
    original_finality: OriginalCommandFinality | None

    def matches(self, scope: AccountExecutionScope, binding: JournalledCommandBinding | None = None) -> bool:
        return (type(scope) is AccountExecutionScope and scope.outcome.read() is self
                and scope.outcome._engine is self._engine and scope.nonce == self.nonce
                and scope._binding is binding)

    def require_binding(self, binding: JournalledCommandBinding) -> None:
        _require(type(binding) is JournalledCommandBinding
                 and binding._scope.outcome._engine is self._engine
                 and binding._scope.nonce == self.nonce
                 and self.original_finality is not None
                 and self.original_finality._engine is self._engine
                 and self.result_integrity == "complete")

    @property
    def execution_unknown(self) -> bool:
        return self.no_target is None and self.termination == "signal-wait"


class OriginalCommandReservation:
    def __init__(self, engine: Any, *, _key: object) -> None:
        _require(_key is _KEY and engine.prepared_reservation())
        self._engine = engine
        self.nonce = engine.nonce


class CreatePermit:
    def __init__(self, reservation: OriginalCommandReservation, *, _key: object) -> None:
        _require(_key is _KEY)
        self._reservation = reservation
        self._used = False

    def _consume(self, engine: Any) -> None:
        _require(not self._used and self._reservation._engine is engine
                 and engine.prepared_reservation())
        self._used = True


class JournalledCommandBinding:
    def __init__(self, scope: AccountExecutionScope, session: Any, arm: Callable[..., None],
                 fence_binding: bytes, observation_policy: FenceObservationPolicy, *, _key: object) -> None:
        _require(_key is _KEY and not scope._used and scope._binding is None
                 and session.lease is scope._source._lease and callable(arm)
                 and getattr(arm, "__self__", None) is session
                 and type(fence_binding) is bytes
                 and type(observation_policy) is FenceObservationPolicy)
        self._scope, self._session, self._arm = scope, session, arm
        self.fence_binding = fence_binding
        self._fence_observation = observation_policy
        self._arm_attempted = self._arm_retired = False
        self._arming_reservation: OriginalCommandReservation | None = None
        self._fields = _fence_fields(fence_binding)
        _require(self._fields["nonce"] == scope.nonce.hex())
        scope._binding = self

    @property
    def fence_observation(self) -> FenceObservationPolicy:
        return self._fence_observation

    def validate_reservation(self, reservation: OriginalCommandReservation) -> None:
        self._scope._source._check()
        _require(self._arm_attempted and not self._arm_retired
                 and self._arming_reservation is reservation
                 and type(reservation) is OriginalCommandReservation
                 and reservation._engine is self._scope.outcome._engine
                 and reservation.nonce == self._scope.nonce
                 and reservation._engine.prepared_reservation())

    def arm_command(self, reservation: OriginalCommandReservation) -> CreatePermit:
        self._scope._source._check()
        _require(type(reservation) is OriginalCommandReservation
                 and reservation._engine is self._scope.outcome._engine
                 and reservation.nonce == self._scope.nonce
                 and not self._arm_attempted and not self._arm_retired
                 and reservation._engine.prepared_reservation())
        self._arm_attempted = True
        self._arming_reservation = reservation
        try:
            self.validate_reservation(reservation)
            _require(self._arm(reservation) is None)
            self._scope._source._check()
            _require(not self._arm_retired and reservation._engine.prepared_reservation())
            return CreatePermit(reservation, _key=_KEY)
        except BaseException:
            self._arm_retired = True
            raise
        finally:
            self._arming_reservation = None


def _issue_journal_binding(scope: AccountExecutionScope, *, session: Any, arm: Callable[..., None],
                           fence_binding: bytes,
                           observation_policy: FenceObservationPolicy = FenceObservationPolicy.OFF) -> JournalledCommandBinding:
    _require(type(scope) is AccountExecutionScope)
    scope._source._check()
    session.assert_owner()
    return JournalledCommandBinding(scope, session, arm, fence_binding, observation_policy, _key=_KEY)


def _fence_fields(content: bytes) -> dict[str, Any]:
    from .owned_process import _parse
    _require(type(content) is bytes and 0 < len(content) <= 4096)
    result = _parse(content)
    names = {"version", "role", "uid", "homeIdentity", "leaseIdentity", "sessionIdentity",
             "sessionToken", "intentSha256", "sequence", "nonce", "kind"}
    _require(set(result) == names and result["version"] == 2
             and result["role"] == "command-custodian"
             and _integer(result["uid"], 0, (1 << 32) - 1)
             and _integer(result["sequence"], 1, INTEGER_LIMIT))
    for name in ("homeIdentity", "leaseIdentity", "sessionIdentity"):
        identity = result[name]
        _require(type(identity) is dict and set(identity) == {"device", "inode"}
                 and _integer(identity["device"], 0, (1 << 64) - 1)
                 and _integer(identity["inode"], 1, (1 << 64) - 1))
    for name, length in (("sessionToken", 32), ("nonce", 32), ("intentSha256", 64)):
        value = result[name]
        _require(type(value) is str and len(value) == length and all(c in "0123456789abcdef" for c in value))
    _require(result["kind"] in {"create", "settings", "unlock", "import", "partition", "build",
                                 "observe", "search", "default", "delete", "extract"})
    _require(_json(result) == content)
    return result


# Command-local lifecycle.  These roles deliberately do not depend on the
# profile executor's private state machine or its scratch/validator policy.
POLL = 0.01
HELPER_OK, HELPER_FAILED, HELPER_UNKNOWN = 0, 2, 70


class Tag(IntEnum):
    CONFIG = 1
    HELLO = 2
    PREPARED = 3
    CREATE_W = 4
    READY = 5
    RUN_TOOL = 6
    EXEC_ARMED = 7
    EXEC_REJECTED = 8
    WORK_DONE = 9
    GROUP_DONE = 10
    TERMINAL = 11
    STOP = 12
    FENCE_BINDING = 13
    PRODUCERS_SEALED = 14
    MANIFEST = 0x20
    DATA = 0x21
    FENCE_EVENT = 0x30
    FENCE_ACK = 0x31


def _command_event(role: str, event: str, **facts: Any) -> None:
    """Fixed local regression seam; neither its arguments nor return grant work."""


def _scalar(nonce: bytes, **fields: Any) -> bytes:
    result = _json({"v": 1, "nonce": nonce.hex(), **fields})
    _require(len(result) <= SCALAR_LIMIT)
    return result


def _scalar_fields(content: bytes, nonce: bytes, names: set[str]) -> dict[str, Any]:
    from .owned_process import _parse
    result = _parse(content)
    _require(set(result) == names | {"v", "nonce"} and result["v"] == 1
             and type(result["v"]) is int and result["nonce"] == nonce.hex()
             and _json(result) == content)
    return result


@dataclass(slots=True)
class _Route:
    tag: Tag
    queued: bool = False
    attempted: bool = False
    retired: bool = False

    def queue(self) -> None:
        _require(not self.queued and not self.attempted and not self.retired)
        self.queued = True

    def attempt(self) -> None:
        _require(self.queued and not self.retired)
        self.attempted = True  # BEFORE every first possible consuming write.

    def retire(self) -> None:
        self.retired = True
        self.queued = False


class _Context:
    def __init__(self, role: str, nonce: bytes, run: int, hard: int, *,
                 guard: DefaultCancellation | None = None, parent: int | None = None,
                 suppress_cancel: bool = False) -> None:
        _require(role in ("O", "C", "A", "W") and _nonce(nonce)
                 and _integer(run, 1, INTEGER_LIMIT) and run < hard <= run + CLEANUP_NS)
        self.role, self.nonce, self.run, self.hard = role, nonce, run, hard
        self.pid, self.owner = os.getpid(), threading.current_thread()
        self.guard, self.parent, self.suppress_cancel = guard, parent, suppress_cancel
        self.lock = threading.Lock()
        self.primary: BaseException | None = None
        self.secondary: list[BaseException] = []
        self.first_interruption: BaseException | None = None
        self.failure_cutoff: int | None = None
        self.cleanup_cutoff: int | None = None
        self.stopped = self.launch_retired = self.cleanup_unknown = self.exited = False
        self.error_epoch = self.signal_epoch = 0
        self.exit_armed = False
        self.acquisitions: list[native.Acquisition] = []
        self.tasks: list[_TaskSlot] = []
        self.closed: set[int] = set()
        self.routes: list[_Route] = []
        self.retained: list[Any] = []
        # UNKNOWN original custody can outlive the local CleanupScope. The
        # shared weak registry follows this rooted context too; it never owns
        # or cleans a parent's resources in the original process.
        cancellation_state._FORK_RESOURCES.add(self)
        self.child_acquisition = self.acquisition()

    def after_fork_child(self) -> None:
        if os.getpid() == self.pid:
            return
        self.launch_retired = self.stopped = self.cleanup_unknown = True
        for route in self.routes:
            route.retire()
        for acquisition in self.acquisitions:
            acquisition._relinquish_inherited()

    def origin(self) -> None:
        if os.getpid() != self.pid:
            # A raw fork never invokes a parent callback, inherited mutex,
            # native wait or signalling route. Close only positively owned
            # inherited descriptor copies, never LOCK_UN the parent's OFD.
            self.after_fork_child()
            raise ProcessCleanupError("inherited command ownership cannot authorize work", contained=False)

    def owner_check(self) -> None:
        self.origin()
        _require(threading.current_thread() is self.owner)

    def acquisition(self) -> native.Acquisition:
        result = native.Acquisition(failure_recorder=self.record)
        self.acquisitions.append(result)
        return result

    def start_io(self) -> native.Acquisition:
        result = self.acquisition()
        result.grant(self.owner, self.check)
        return result

    def record(self, error: BaseException, *, unknown: bool = False) -> None:
        self.origin()  # Before the common lock or an inherited recorder.
        with self.lock:
            if self.primary is None:
                self.primary = error
            elif error is not self.primary and len(self.secondary) < SCALAR_COUNT:
                if not any(item is error for item in self.secondary):
                    self.secondary.append(error)
            if self.first_interruption is None and isinstance(error, (KeyboardInterrupt, SystemExit)):
                self.first_interruption = error
            self.error_epoch += 1
            self.stopped = True
            self.cleanup_unknown |= unknown
            if self.failure_cutoff is None:
                # An unavailable clock cannot renew the first failure's grace.
                # Latch a fail-closed endpoint before observing that clock.
                self.failure_cutoff = 0
                try:
                    self.failure_cutoff = min(self.hard, time.monotonic_ns() + CLEANUP_NS)
                except BaseException as diagnostic:
                    self.cleanup_unknown = True
                    if len(self.secondary) < SCALAR_COUNT:
                        self.secondary.append(diagnostic)
            if self.cleanup_cutoff is not None:
                self.cleanup_cutoff = min(self.cleanup_cutoff, self.failure_cutoff)
        try:
            self.retire_launch()
        except BaseException as diagnostic:
            self.cleanup_unknown = self.launch_retired = self.stopped = True
            if len(self.secondary) < SCALAR_COUNT:
                self.secondary.append(diagnostic)

    def retire_launch(self) -> None:
        self.origin()
        self.launch_retired = True
        self.child_acquisition.close_launch()
        for route in self.routes:
            route.retire()
        # Close every grant before an Event wakeup can itself fail/interrupt.
        for task in self.tasks:
            task.launch, task.retired = False, True
        for task in self.tasks:
            task.retire()

    def begin_cleanup(self) -> int:
        self.owner_check()
        if self.cleanup_cutoff is None:
            self.cleanup_cutoff = min(self.hard, time.monotonic_ns() + CLEANUP_NS)
        return self.cutoff()

    def cutoff(self) -> int:
        return min(self.hard, self.hard if self.failure_cutoff is None else self.failure_cutoff,
                   self.hard if self.cleanup_cutoff is None else self.cleanup_cutoff)

    def parent_lost(self) -> bool:
        self.origin()
        return self.parent is not None and os.getppid() != self.parent

    def check(self) -> None:
        self.owner_check()
        if self.primary is not None:
            raise self.primary
        if self.guard is not None:
            _require(self.guard.pid == self.pid and self.guard.owner_thread is self.owner)
            if not self.suppress_cancel:
                self.guard.check()
            else:
                _require(not self.guard.lifetime_ledger.fatal and self.guard.handler_state != "UNKNOWN")
        _require(not self.stopped and not self.parent_lost())
        _require(time.monotonic_ns() < self.run, TIMEOUT)

    def helper_signal(self, _signum: int, _frame: Any) -> None:
        if os.getpid() != self.pid:
            return
        if self.exit_armed:
            os._exit(HELPER_UNKNOWN)
        self.signal_epoch += 1
        self.stopped = True  # Latch only; never throw inside the W guard tail.

    def check_tail(self) -> None:
        self.owner_check()
        _require(time.monotonic_ns() < self.cutoff(), TIMEOUT)

    def close(self, lease: native.FDLease) -> None:
        self.owner_check()
        if id(lease) in self.closed:
            return
        self.closed.add(id(lease))  # Retirement before a possibly consuming call.
        try:
            lease.close()
            _command_event(self.role, "descriptor_closed", lease=lease)
        except BaseException as error:
            self.record(error, unknown=True)

    def close_io(self, acquisition: native.Acquisition, *, except_leases: tuple[Any, ...] = ()) -> None:
        excluded = {id(lease) for lease in except_leases}
        # No forwarded original is closed while an unsettled creator still
        # borrows it. Its root and borrower are not manually cleared.
        for task in self.tasks:
            if not task.joined:
                excluded.update(id(lease) for lease in task.spec.fd_sources)
        for lease in reversed(acquisition.leases):
            if id(lease) not in excluded:
                self.close(lease)
        acquisition.close_launch()

    def settled(self, acquisitions: tuple[native.Acquisition, ...] | None = None,
                *, except_leases: tuple[Any, ...] = ()) -> bool:
        self.owner_check()
        chosen = tuple(self.acquisitions) if acquisitions is None else acquisitions
        excluded = {id(value) for value in except_leases}
        return (all(item.settled and not item.cleanup_unknown for item in chosen)
                and all(lease.state in ("NEW", "CLOSED") or id(lease) in excluded
                        for item in chosen for lease in item.leases)
                and all(task.joined and task.acquisition.settled and not task.acquisition.cleanup_unknown
                        for task in self.tasks if task.acquisition in chosen))

    def cleanup_tasks(self, pump: Callable[[], None]) -> None:
        self.retire_launch()
        while any(not task.joined for task in self.tasks) and time.monotonic_ns() < self.cutoff():
            for task in self.tasks:
                task.join_once(self.cutoff())
            try:
                pump()
            except BaseException as error:
                self.record(error)
            _pause(self.cutoff())
        if any(not task.joined for task in self.tasks):
            self.cleanup_unknown = True


class _CreatorStopView:
    def __init__(self, task: _TaskSlot, grant: object) -> None:
        self.task, self.grant = task, grant
        self.creator, self.owner, self.pid = task.actual, task.context.owner, task.context.pid
        self.guard = task.context.guard

    def check(self) -> None:
        task, ctx = self.task, self.task.context
        ctx.origin()
        _require(self.pid == os.getpid() and threading.current_thread() is self.creator
                 and self.creator is task.actual is task.returned is task.constructed
                 and task.grant_identity is self.grant and task.stop_view is self
                 and task.launch and not task.retired and not task.joined and not task.body_done
                 and not ctx.launch_retired and not task.acquisition.launch_retired
                 and ctx.owner is self.owner and self.owner.is_alive())
        if ctx.primary is not None:
            raise ctx.primary
        if self.guard is not None:
            _require(ctx.guard is self.guard and self.guard.pid == self.pid
                     and self.guard.owner_thread is self.owner)
            # Read-only stop view. No owner-only guard.check/source callback is
            # executed by the native creator thread.
            _require(ctx.suppress_cancel or not self.guard.cancelled)
        _require(not ctx.stopped and not ctx.parent_lost())
        _require(time.monotonic_ns() < ctx.run, TIMEOUT)


class _TaskSlot:
    def __init__(self, context: _Context, spec: native.SpawnSpec) -> None:
        self.context, self.spec, self.acquisition = context, spec, context.child_acquisition
        self.actual: threading.Thread | None = None
        self.returned: threading.Thread | None = None
        self.constructed: threading.Thread | None = None
        self.start_attempted = self.body_done = self.joined = self.launch = self.retired = False
        self.event = threading.Event()
        self.grant_identity: object | None = None
        self.stop_view: _CreatorStopView | None = None
        self.error: BaseException | None = None
        self.result: native.Child | None = None

    def retire(self) -> None:
        self.context.origin()
        self.launch, self.retired = False, True
        self.acquisition.close_launch()
        self.event.set()

    def _record(self, error: BaseException) -> None:
        if self.error is None:
            self.error = error
        try:
            self.context.record(error)
        except BaseException:
            # No automatic threading.excepthook may emit application payloads.
            # These rooted fallback slots cannot authorize further execution.
            self.context.cleanup_unknown = self.context.stopped = self.context.launch_retired = True
            if self.context.failure_cutoff is None:
                self.context.failure_cutoff = 0
            if self.context.primary is None:
                self.context.primary = error
        self.launch, self.retired = False, True

    def _body(self) -> None:
        try:
            self.context.origin()
            self.actual = threading.current_thread()
            _command_event(self.context.role, "creator_published", task=self)
            while not self.event.wait(POLL):
                if (self.retired or self.context.launch_retired or self.context.stopped
                        or not self.context.owner.is_alive() or time.monotonic_ns() >= self.context.run):
                    self.retire()
                    return
            if not self.launch or self.retired:
                return
            _require(self.stop_view is not None)
            self.stop_view.check()
            self.result = native.create(self.acquisition, self.spec)
        except BaseException as error:
            self._record(error)
        finally:
            self.body_done = True

    def start(self) -> None:
        self.context.check()
        try:
            self.constructed = threading.Thread(target=self._body, name="mrk-command-creator", daemon=False)
            self.start_attempted = True
            self.constructed.start()
            self.returned = self.constructed
        except BaseException as error:
            self._record(error)
            self.retire()
            raise

    def grant(self) -> bool:
        self.context.check()
        if self.actual is None:
            return False
        _require(self.actual is self.returned is self.constructed and not self.retired
                 and self.grant_identity is None)
        self.grant_identity = object()
        self.stop_view = _CreatorStopView(self, self.grant_identity)
        self.launch = True
        self.acquisition.grant(self.actual, self.stop_view.check)
        self.event.set()
        return True

    def join_once(self, cutoff: int) -> bool:
        self.context.owner_check()
        if self.joined:
            return True
        if not self.start_attempted:
            # The actual start effect was never entered, not merely no Thread
            # publication. There can be no creator/native attempt in this arm.
            _require(self.retired and not self.acquisition.attempted and self.actual is None)
            self.joined = True
            return True
        thread = self.actual or self.returned
        if thread is None or thread is threading.current_thread():
            return False
        left = (min(cutoff, self.context.cutoff()) - time.monotonic_ns()) / NANOSECOND
        if left <= 0:
            return False
        try:
            thread.join(min(POLL, left))
            if not thread.is_alive():
                _require(self.body_done and (self.actual is thread or
                         self.actual is None and self.returned is self.constructed is thread))
                self.joined = True
                self.retire()
                _command_event(self.context.role, "creator_joined", task=self)
                return True
        except BaseException as error:
            self.context.record(error, unknown=True)
        return False


def _pause(cutoff: int, *, readers: tuple[native.FDLease, ...] = (),
           writers: tuple[native.FDLease, ...] = ()) -> None:
    left = (cutoff - time.monotonic_ns()) / NANOSECOND
    if left <= 0:
        return
    if not readers and not writers:
        time.sleep(min(POLL, left))
        return
    # Readiness is only a hint to repeat the original checked nonblocking IO.
    # poll owns no descriptor and, unlike select, has no FD_SETSIZE boundary.
    # Never infer EOF, a complete frame, or producer settlement from its events.
    readiness = select.poll()
    masks: dict[int, int] = {}
    for leases, mask in ((readers, select.POLLIN), (writers, select.POLLOUT)):
        for lease in leases:
            descriptor = lease.fileno()
            masks[descriptor] = masks.get(descriptor, 0) | mask
    for descriptor, mask in masks.items():
        readiness.register(descriptor, mask)
    left = (cutoff - time.monotonic_ns()) / NANOSECOND
    if left > 0:
        readiness.poll(int(min(POLL, left) * 1000))


class _Wire:
    """One original reader/writer pair, bounded finite frames, no writer thread."""
    def __init__(self, context: _Context, reader: native.FDLease, writer: native.FDLease,
                 *, diagnostics: bool = False) -> None:
        self.ctx, self.reader, self.writer = context, reader, writer
        self.diagnostics = diagnostics
        self.buffer = bytearray()
        self.header: tuple[Tag, int] | None = None
        self.poisoned = self.eof = self.write_failed = self.write_in_flight = False
        self.sent_scalars = self.read_scalars = self.sent_diagnostics = self.read_diagnostics = 0
        self.sent_bytes = self.read_bytes = 0
        self.out: bytes | None = None
        self.out_tag: Tag | None = None
        self.out_offset = 0
        self.out_route: _Route | None = None
        self.send_manifest: Manifest | None = None
        self.read_manifest: Manifest | None = None
        self.send_data = self.read_data = 0
        self.expected_manifest: Manifest | None = None
        self.sent: list[Tag] = []
        os.set_blocking(reader.fileno(), False)
        os.set_blocking(writer.fileno(), False)

    def _shape(self, tag: Tag, size: int, *, outgoing: bool, payload: bytes | None = None) -> None:
        _require(0 <= size <= CHUNK)
        manifest = self.send_manifest if outgoing else self.read_manifest
        count = self.send_data if outgoing else self.read_data
        if tag is Tag.DATA:
            _require(manifest is not None and count < manifest.record_bytes
                     and size == min(CHUNK, manifest.record_bytes - count))
        elif tag is Tag.MANIFEST:
            _require(size == 154 and manifest is None)
        elif tag in (Tag.FENCE_EVENT, Tag.FENCE_ACK):
            _require(self.diagnostics and (69 <= size <= 2117 if tag is Tag.FENCE_EVENT else size == 28))
        else:
            _require(0 < size <= SCALAR_LIMIT)
        if manifest is not None and count < manifest.record_bytes:
            _require(tag is Tag.DATA)  # No scalar interleaving inside the record.
        if payload is not None and tag is Tag.MANIFEST:
            decoded = Manifest.decode(payload)
            _require(self.expected_manifest is not None and decoded == self.expected_manifest)
            if outgoing:
                self.send_manifest = decoded
            else:
                self.read_manifest = decoded
        if tag is Tag.DATA:
            if outgoing:
                self.send_data += size
            elif payload is not None:
                self.read_data += size

    def queue(self, tag: Tag, payload: bytes, route: _Route | None = None) -> None:
        self.ctx.owner_check()
        _require(type(tag) is Tag and type(payload) is bytes and self.out is None
                 and not self.write_failed and self.writer.state == "OPEN")
        self._shape(tag, len(payload), outgoing=True, payload=payload)
        if tag in (Tag.FENCE_EVENT, Tag.FENCE_ACK):
            self.sent_diagnostics += 1
            _require(self.sent_diagnostics <= 13)
        elif tag is not Tag.DATA:
            self.sent_scalars += 1
            _require(self.sent_scalars <= SCALAR_COUNT)
        if route is not None:
            _require(route.tag is tag and route in self.ctx.routes)
            route.queue()
        self.out = bytes((int(tag),)) + len(payload).to_bytes(4, "big") + payload
        self.out_tag, self.out_offset, self.out_route = tag, 0, route

    def flush(self) -> bool:
        self.ctx.owner_check()
        if self.out is None:
            return True
        if self.out_route is not None and self.out_route.retired:
            # A possibly partial frame cannot be replaced by another command.
            self.write_failed = self.out_offset != 0
            self.out = None
            self.ctx.close(self.writer)
            return False
        try:
            if self.out_route is not None:
                self.out_route.attempt()
            self.write_in_flight = True
            count = os.write(self.writer.fileno(), self.out[self.out_offset:self.out_offset + CHUNK])
            self.write_in_flight = False
            _require(_integer(count, 1, min(CHUNK, len(self.out) - self.out_offset)))
            self.out_offset += count
            self.sent_bytes += count
            if self.out_offset == len(self.out):
                assert self.out_tag is not None
                self.sent.append(self.out_tag)
                self.out = None
                self.out_route = None
                return True
        except BlockingIOError:
            self.write_in_flight = False  # Genuine no-progress return; same frame.
        except BaseException as error:
            self.write_failed = True
            self.ctx.record(error)
            raise
        return False

    def read(self) -> tuple[Tag, bytes] | None:
        self.ctx.owner_check()
        _require(not self.poisoned)
        if self.eof:
            return None
        try:
            needed = (5 if self.header is None else 5 + self.header[1]) - len(self.buffer)
            if needed:
                try:
                    chunk = os.read(self.reader.fileno(), min(CHUNK, needed))
                except BlockingIOError:
                    return None
                if not chunk:
                    self.eof = True
                    _require(not self.buffer, "owned command ended with an incomplete frame")
                    return None
                self.buffer.extend(chunk)
                self.read_bytes += len(chunk)
            if self.header is None and len(self.buffer) == 5:
                try:
                    tag = Tag(self.buffer[0])
                except ValueError:
                    raise ProcessError(ERROR) from None
                size = int.from_bytes(self.buffer[1:5], "big")
                self._shape(tag, size, outgoing=False)
                self.header = tag, size
                # At most one header and one bounded body read per turn. Avoid
                # paying a polling interval for an already available payload.
                if size:
                    return self.read()
            if self.header is None or len(self.buffer) != 5 + self.header[1]:
                return None
            tag, size = self.header
            body = bytes(self.buffer[5:])
            self._shape(tag, size, outgoing=False, payload=body)
            if tag in (Tag.FENCE_EVENT, Tag.FENCE_ACK):
                self.read_diagnostics += 1
                _require(self.read_diagnostics <= 13)
            elif tag is not Tag.DATA:
                self.read_scalars += 1
                _require(self.read_scalars <= SCALAR_COUNT)
            self.header = None
            self.buffer.clear()
            return tag, body
        except BaseException as error:
            self.poisoned = True
            self.ctx.record(error)
            raise

    def drain_to_eof(self) -> bool:
        """Poison is not EOF. Use only the still-open original reader."""
        self.ctx.owner_check()
        if self.eof:
            return True
        _require(self.reader.state == "OPEN")
        manifest = self.expected_manifest
        budget = SCALAR_COUNT * (5 + SCALAR_LIMIT) + (3439 if self.diagnostics else 0)
        if manifest is not None:
            budget += manifest.record_bytes + 5 * ((manifest.record_bytes + CHUNK - 1) // CHUNK)
        _require(self.read_bytes < budget)
        try:
            chunk = os.read(self.reader.fileno(), min(CHUNK, budget - self.read_bytes))
        except BlockingIOError:
            return False
        self.read_bytes += len(chunk)
        self.eof = not chunk
        return self.eof

    def close_writer(self) -> None:
        if self.out is not None:
            self.write_failed = True
            if self.out_route is not None:
                self.out_route.retire()
            self.out = None
        self.ctx.close(self.writer)


def _flush(wire: _Wire, pump: Callable[[], None], *, normal: bool = True) -> None:
    while wire.out is not None:
        if normal:
            wire.ctx.check()
        else:
            wire.ctx.check_tail()
        wire.flush()
        pump()
        if wire.out is not None:
            _pause(wire.ctx.run if normal else wire.ctx.cutoff(), writers=(wire.writer,))
    _require(not wire.write_failed)


def _send(wire: _Wire, tag: Tag, body: bytes, pump: Callable[[], None], *,
          route: _Route | None = None, normal: bool = True) -> None:
    wire.queue(tag, body, route)
    _flush(wire, pump, normal=normal)


def _receive(wire: _Wire, expected: Tag, pump: Callable[[], None], *, normal: bool = True) -> bytes:
    while True:
        if normal:
            wire.ctx.check()
        else:
            wire.ctx.check_tail()
        frame = wire.read()
        if frame is not None:
            tag, body = frame
            try:
                if tag is Tag.STOP:
                    value = _scalar_fields(body, wire.ctx.nonce, {"cutoff"})
                    _require(_integer(value["cutoff"], 1, wire.ctx.hard))
                else:
                    _require(tag is expected)
            except BaseException as error:
                wire.poisoned = True
                wire.ctx.record(error)
                raise
            if tag is Tag.STOP:
                wire.ctx.record(ProcessError(ERROR))
                wire.ctx.failure_cutoff = min(wire.ctx.cutoff(), value["cutoff"])
                raise wire.ctx.primary  # type: ignore[misc]
            return body
        _require(not wire.eof)
        pump()
        _pause(wire.ctx.run if normal else wire.ctx.cutoff(), readers=(wire.reader,))


def _spawn(context: _Context, spec: native.SpawnSpec, pump: Callable[[], None]) -> native.Child:
    context.check()
    _require(not context.tasks and not context.launch_retired)
    task = _TaskSlot(context, spec)
    context.tasks.append(task)  # Before Thread construction or its start effect.
    task.start()
    granted = False
    while True:
        pump()
        context.check()
        if not granted:
            granted = task.grant()
        if granted and task.join_once(context.run):
            if task.error is not None:
                raise task.error
            child = task.acquisition.child
            _require(child is not None and child is task.result and task.acquisition.settled
                     and not task.acquisition.cleanup_unknown)
            _command_event(context.role, "child_published", child=child)
            return child
        _pause(context.run)


_BOOTSTRAP = r'''
import os, signal, sys
_self = os.getpid()
_raise, _kill, _park, _sig = signal.raise_signal, os.kill, signal.pause, signal.SIGKILL
_role = sys.argv[2]
if _role == "W":
    _enter, _stage = True, 0
    while True:
        try:
            if _enter:
                _enter = False
                sys.path.insert(0, sys.argv[1])
                from mobile_release._command_process import helper_main
                helper_main(sys.argv[2:], None)
            if _stage == 0:
                _stage = 1
                _raise(_sig)
            if _stage == 1:
                _stage = 2
                _kill(_self, _sig)
            _park()
        except BaseException:
            _enter = False
else:
    _policy = None
    if _role == "C":
        _policy = 0
        for _bit, _number in enumerate((signal.SIGINT, signal.SIGTERM, signal.SIGCHLD)):
            _old = signal.getsignal(_number)
            if _old == signal.SIG_IGN:
                _policy |= 1 << _bit
            elif not (_old == signal.SIG_DFL or _number == signal.SIGINT and _old is signal.default_int_handler):
                raise SystemExit(70)
        if _policy & 4:
            raise SystemExit(70)
    sys.path.insert(0, sys.argv[1])
    from mobile_release._command_process import helper_main
    raise SystemExit(helper_main(sys.argv[2:], _policy))
'''


def _command_spec(context: _Context, role: str,
                  sources: tuple[native.FDLease, ...]) -> native.SpawnSpec:
    context.check()
    _require(role in ("C", "A", "W") and {"O": "C", "C": "A", "A": "W"}.get(context.role) == role
             and len(sources) == 8)
    executable = os.path.abspath(sys.executable)
    module_root = str(Path(__file__).resolve().parent.parent)
    hold = sources[5].account_binding
    account = "-" if hold is None else ",".join(str(value) for value in (hold.uid, *hold.identity))
    _require(role != "W" or account == "-")
    argv = (executable, "-I", "-S", "-B", "-c", _BOOTSTRAP, module_root, role,
            str(context.pid), str(os.getsid(0)), str(os.getpgrp()),
            str(context.run), str(context.hard), context.nonce.hex(), account, "1")
    environment = (("PATH", os.defpath), ("LC_ALL", "C"), ("LANG", "C"))
    permit = native._issue_command_map(
        context.child_acquisition, role=role, command_nonce=context.nonce,
        executable=executable, argv=argv, env=environment, fd_sources=sources,
    )
    return native.SpawnSpec(executable, argv, environment, sources, command_map=permit)


def _nulls(io: native.Acquisition) -> tuple[native.FDLease, native.FDLease, native.FDLease]:
    return io.open_null(writable=False), io.open_null(writable=True), io.open_null(writable=True)


def _bootstrap_map(context: _Context, bootstrap: native.CommandBootstrapMap,
                   relay: native.Acquisition, account: native.Acquisition) -> dict[int, native.FDLease]:
    # This method is entered only by the fixed loader's original map. Descriptor
    # type/direction validation is additional evidence, never OFD provenance.
    for fd, access in ((0, os.O_RDONLY), (1, os.O_WRONLY), (2, os.O_WRONLY)):
        info, null = os.fstat(fd), os.stat("/dev/null")
        _require(stat.S_ISCHR(info.st_mode) and info.st_rdev == null.st_rdev)
        os.set_inheritable(fd, True)  # Target DEVNULL stdio survives W's exec.
    result = {
        3: relay.adopt_fd(3, access=os.O_RDONLY, kind="pipe"),
        4: relay.adopt_fd(4, access=os.O_WRONLY, kind="pipe"),
        6: relay.adopt_fd(6, access=os.O_WRONLY, kind="pipe"),
        7: relay.adopt_fd(7, access=os.O_WRONLY, kind="pipe"),
    }
    if bootstrap.account_binding is not None:
        result[5] = account.adopt_account_hold(bootstrap, binding=bootstrap.account_binding)
    else:
        result[5] = account.adopt_fd(5, access=os.O_RDONLY, kind="null")
    return result


def _hello(context: _Context) -> bytes:
    return _scalar(context.nonce, role=context.role, pid=context.pid,
                   parent=os.getppid(), session=os.getsid(0), group=os.getpgrp(), map=1)


def _admit_hello(context: _Context, child: native.Child, content: bytes, role: str,
                 session: int, group: int) -> None:
    value = _scalar_fields(content, context.nonce, {"role", "pid", "parent", "session", "group", "map"})
    _require(child is context.child_acquisition.child and child.wait_state == "OWNED"
             and not child.numeric_retired and value["role"] == role and value["pid"] == child.pid
             and all(_integer(value[key], 1, PID_LIMIT) for key in ("pid", "parent", "session", "group"))
             and type(value["map"]) is int and value["map"] == 1
             and value["parent"] == context.pid and value["session"] == session and value["group"] == group
             and os.getsid(child.pid) == session and os.getpgid(child.pid) == group)


class _AnchorGroup:
    """C's G reservation is pinned by its original, deliberately unpolled A."""
    def __init__(self, context: _Context, anchor: native.Child) -> None:
        self.context, self.anchor = context, anchor
        self.group, self.retired, self.absent = anchor.pid, False, False
        self.kill_attempted = False

    def check(self) -> None:
        self.context.owner_check()
        _require(not self.retired and self.anchor is self.context.child_acquisition.child
                 and self.anchor.wait_state == "OWNED" and not self.anchor.numeric_retired
                 and self.group == self.anchor.pid)

    def terminate(self) -> None:
        self.check()
        self.kill_attempted = True
        try:
            os.killpg(self.group, signal.SIGKILL)
        except ProcessLookupError:
            self.absent = True

    def probe(self) -> bool:
        self.check()
        if self.absent:
            return True
        try:
            os.killpg(self.group, 0)
        except ProcessLookupError:
            self.absent = True
        except PermissionError:
            # A Darwin zombie-only group can report EPERM before A's own W
            # wait. It is not absence and supplies no terminal receipt.
            pass
        return self.absent

    def retire(self) -> None:
        self.retired = True


class _SelfGroup:
    """A's own living PID pins G independently of W's retired numeric routes."""
    def __init__(self, context: _Context, session: int) -> None:
        _require(context.role == "A" and os.getpgrp() == context.pid and os.getsid(0) == session)
        self.context, self.session, self.group = context, session, context.pid
        self.retired = False

    def terminate(self) -> None:
        self.context.owner_check()
        _require(not self.retired and os.getpid() == self.group and os.getsid(0) == self.session)
        # A moves to H before admitting W RUN. While still in G, W can only be
        # an inert bootstrap; the same original group kill is a bounded failing
        # exit and can never emit a clean settlement.
        try:
            os.killpg(self.group, signal.SIGKILL)
        except ProcessLookupError:
            pass


def _receipt(receipt: native.WaitReceipt | None) -> dict[str, Any] | None:
    if receipt is None:
        return None
    return {"kind": receipt.status_kind, "code": receipt.status_code}


def _valid_receipt(value: Any) -> bool:
    return (type(value) is dict and set(value) == {"kind", "code"}
            and ((value["kind"] == "exit" and _integer(value["code"], 0, 255))
                 or (value["kind"] == "signal" and _integer(value["code"], 1, signal.NSIG - 1))))


def _wait_original(context: _Context, child: native.Child, pump: Callable[[], None]) -> native.WaitReceipt | None:
    # All caller-owned numeric routes MUST be permanently retired first. A
    # genuine pid0 permits another original wait, never another signal/probe.
    child.retire_numeric()
    while time.monotonic_ns() < context.cutoff():
        try:
            receipt = child.poll_wait()
            if receipt is not None:
                _command_event(context.role, "child_waited", child=child, receipt=receipt)
                return receipt
        except BaseException as error:
            context.record(error, unknown=True)
            return None
        try:
            pump()
        except BaseException as error:
            context.record(error)
        _pause(context.cutoff())
    context.cleanup_unknown = True
    return None


def _input_loss(context: _Context, wire: _Wire) -> None:
    context.owner_check()
    if wire.eof or context.parent_lost():
        raise ProcessError("owned command original parent ended")


def _check_stop(context: _Context, wire: _Wire) -> None:
    frame = wire.read()
    if frame is not None:
        tag, body = frame
        _require(tag is Tag.STOP)
        fields = _scalar_fields(body, context.nonce, {"cutoff"})
        _require(_integer(fields["cutoff"], 1, context.hard))
        error = ProcessError(ERROR)
        context.record(error)
        context.failure_cutoff = min(context.cutoff(), fields["cutoff"])
        raise error
    _input_loss(context, wire)


def _config(content: bytes, context: _Context, *, custodian: bool) -> tuple[Manifest, int, bool, FenceObservationPolicy]:
    fields = _scalar_fields(content, context.nonce, {"manifest", "signals", "fence", "trace"})
    _require(type(fields["manifest"]) is str and len(fields["manifest"]) == 308
             and _integer(fields["signals"], 0, 3) and type(fields["fence"]) is bool
             and _integer(fields["trace"], 0, 1)
             and (custodian or not fields["fence"] and fields["trace"] == 0)
             and (fields["fence"] or fields["trace"] == 0))
    manifest = Manifest.decode(bytes.fromhex(fields["manifest"]))
    _require(manifest.nonce == context.nonce)
    return manifest, fields["signals"], fields["fence"], FenceObservationPolicy(fields["trace"])


def _config_bytes(context: _Context, manifest: Manifest, policy: int,
                  *, fence: bool = False, trace: FenceObservationPolicy = FenceObservationPolicy.OFF) -> bytes:
    return _scalar(context.nonce, manifest=manifest.encode().hex(), signals=policy, fence=fence, trace=int(trace))


@dataclass(slots=True)
class _FileEffect:
    operation: str
    state: str = "PREPARED"
    result: Any = None


class _FileSlot:
    """Command account-tail FD: original publication, then exactly one close."""
    def __init__(self, writer: FenceWriter) -> None:
        self.writer, self.fd, self.state = writer, None, "NEW"
        writer.files.append(self)

    def open(self, name: str, flags: int, *, parent: int, mode: int = 0o600) -> int:
        _require(self.state == "NEW")
        self.state = "OPENING"
        try:
            value = self.writer.effect("open", os.open, name, flags, mode, dir_fd=parent)
            _require(_integer(value, 0, PID_LIMIT))
            self.fd, self.state = value, "OPEN"
            return value
        except BaseException:
            self.state = "UNKNOWN"
            raise

    def fileno(self) -> int:
        self.writer.ctx.owner_check()
        _require(self.state == "OPEN" and self.fd is not None)
        return self.fd

    def close(self) -> None:
        if self.state in ("NEW", "CLOSED"):
            return
        _require(self.state == "OPEN" and self.fd is not None)
        fd, self.fd, self.state = self.fd, None, "CLOSING"
        try:
            _require(self.writer.effect("close", os.close, fd) is None)
            self.state = "CLOSED"
        except BaseException:
            self.state = "UNKNOWN"
            self.writer.ctx.cleanup_unknown = True
            raise


def _metadata(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
            info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class DescendantsSettled:
    def __init__(self, custodian: _Custodian, *, _key: object) -> None:
        _require(_key is _KEY and custodian._producer_settled())
        self._custodian, self._nonce = custodian, custodian.ctx.nonce


class _FenceObserver:
    def __init__(self, writer: FenceWriter, wire: _Wire, *, _key: object) -> None:
        _require(_key is _KEY and writer.policy is FenceObservationPolicy.TRACE_V1)
        self.writer, self.wire = writer, wire
        self.ordinal = 0
        self.retired = self.delivery_possible = self.acknowledged = self.owner_loss = False
        self.outstanding: FenceObservation | None = None

    def _loss(self) -> bool:
        if not self.owner_loss and (self.wire.eof or self.writer.ctx.parent_lost()):
            self.owner_loss = self.retired = True
            self.writer.ctx.record(ProcessError("owned command original observer ended"))
        return self.owner_loss

    def _hold_after_retirement(self) -> None:
        ctx = self.writer.ctx
        while self.delivery_possible and not self.acknowledged and not self._loss():
            # Parser poison/local close/EAGAIN is never an EOF observation. Once
            # retired, even a late matching ACK cannot release this checkpoint.
            ctx.check_tail()
            if self.wire.reader.state == "OPEN":
                try:
                    self.wire.drain_to_eof()
                except BaseException as error:
                    ctx.record(error)
                    # No replaced/reopened reader or repeated failed raw read.
                    ctx.close(self.wire.reader)
            _pause(ctx.cutoff())

    def checkpoint(self, operation: FenceOperation, edge: FenceEdge,
                   outcome: FenceEventOutcome, *, written: int, total: int,
                   sync_flags: int, operand: bytes = b"") -> None:
        ctx = self.writer.ctx
        ctx.check_tail()
        if self.retired:
            self._hold_after_retirement()
            return
        _require(self.outstanding is None or self.acknowledged)
        if self._loss():
            return
        self.ordinal += 1
        identity = None if self.writer.observation_identity_unavailable else self.writer.creation_identity
        state = 1 if identity is not None else (0 if operation is FenceOperation.PENDING_CREATE
                                             and edge is FenceEdge.BEFORE else 2)
        event = FenceObservation(ctx.nonce, self.writer.fields["sequence"], self.ordinal,
                                 operation, edge, outcome, written, total, sync_flags,
                                 state, identity, operand)
        self.outstanding = event
        self.delivery_possible = self.acknowledged = False
        try:
            self.wire.queue(Tag.FENCE_EVENT, event.encode())
            while self.wire.out is not None:
                ctx.check_tail()
                self.delivery_possible = True  # BEFORE the possible event send.
                self.wire.flush()
                if self._loss():
                    self._hold_after_retirement()
                    return
                if self.wire.out is not None:
                    _pause(ctx.cutoff(), writers=(self.wire.writer,))
            while True:
                ctx.check_tail()
                frame = self.wire.read()
                if frame is not None:
                    _require(frame[0] is Tag.FENCE_ACK and frame[1] == event.ack())
                    self.acknowledged = True
                    return
                if self._loss():
                    return
                _pause(ctx.cutoff(), readers=(self.wire.reader,))
        except BaseException as error:
            ctx.record(error)
            self.retired = True
            self.wire.close_writer()
            self._hold_after_retirement()


class FenceWriter:
    """Original C-only, one-use publication from its already sealed producers."""
    def __init__(self, custodian: _Custodian, content: bytes, policy: FenceObservationPolicy,
                 *, _key: object) -> None:
        _require(_key is _KEY and custodian.ctx.role == "C")
        self.custodian, self.ctx, self.fields = custodian, custodian.ctx, _fence_fields(content)
        self.policy = policy
        self.hold = custodian.mapping[5]
        hold = self.hold.account_binding
        _require(hold is not None and hold.command_nonce == self.ctx.nonce
                 and hold.uid == self.fields["uid"]
                 and hold.identity == tuple(self.fields["leaseIdentity"][key] for key in ("device", "inode"))
                 and self.fields["nonce"] == self.ctx.nonce.hex())
        self.files: list[_FileSlot] = []
        self.effects: list[_FileEffect] = []
        self.home, self.session, self.pending = _FileSlot(self), _FileSlot(self), _FileSlot(self)
        self.intent_metadata: tuple[int, ...] | None = None
        self.creation_identity: tuple[int, int, int, int, int, int] | None = None
        self.observation_identity_unavailable = False
        self.attempted = self.complete = self.retired = False
        self.written = self.sync_flags = 0
        self.content = b""
        self.observer: _FenceObserver | None = None

    def effect(self, name: str, function: Callable[..., Any], *args: Any,
               mutating: bool = True, **kwargs: Any) -> Any:
        self.ctx.owner_check()
        _require(not self.retired and len(self.effects) < 16384)
        effect = _FileEffect(name)
        self.effects.append(effect)
        effect.state = "IN_FLIGHT"
        try:
            effect.result = function(*args, **kwargs)
            effect.state = "RETURNED"
            return effect.result
        except BaseException as error:
            effect.state = "UNKNOWN"
            self.ctx.record(error, unknown=mutating)
            raise

    def _directory(self, details: os.stat_result, identity: dict[str, int], *, private: bool) -> None:
        _require(stat.S_ISDIR(details.st_mode) and details.st_uid == self.fields["uid"] == os.getuid()
                 and (details.st_dev, details.st_ino) == (identity["device"], identity["inode"])
                 and (stat.S_IMODE(details.st_mode) == 0o700 if private else not details.st_mode & 0o7022))

    def namespace(self) -> None:
        _require(not self.retired and self.hold.state == "OPEN")
        self._directory(self.effect("hold_stat", os.fstat, self.hold.fileno(), mutating=False),
                        self.fields["leaseIdentity"], private=True)
        self._directory(self.effect("home_stat", os.fstat, self.home.fileno(), mutating=False),
                        self.fields["homeIdentity"], private=False)
        self._directory(self.effect("lease_name", os.stat, ".mobile-release-signing",
                                    dir_fd=self.home.fileno(), follow_symlinks=False, mutating=False),
                        self.fields["leaseIdentity"], private=True)
        self._directory(self.effect("session_stat", os.fstat, self.session.fileno(), mutating=False),
                        self.fields["sessionIdentity"], private=True)
        self._directory(self.effect("session_name", os.stat, "session-" + self.fields["sessionToken"],
                                    dir_fd=self.hold.fileno(), follow_symlinks=False, mutating=False),
                        self.fields["sessionIdentity"], private=True)
        if self.intent_metadata is not None:
            info = self.effect("intent_name", os.stat, "intent.json", dir_fd=self.session.fileno(),
                               follow_symlinks=False, mutating=False)
            _require(_metadata(info) == self.intent_metadata)

    def prepare(self) -> None:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        self.home.open("..", flags, parent=self.hold.fileno())
        self.session.open("session-" + self.fields["sessionToken"], flags, parent=self.hold.fileno())
        self.namespace()
        intent = _FileSlot(self)
        before = self.effect("intent_before", os.stat, "intent.json", dir_fd=self.session.fileno(),
                             follow_symlinks=False, mutating=False)
        _require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o600
                 and before.st_uid == self.fields["uid"] and before.st_nlink == 1
                 and 0 < before.st_size <= 512 * 1024)
        intent.open("intent.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                    parent=self.session.fileno())
        _require(_metadata(self.effect("intent_opened", os.fstat, intent.fileno(), mutating=False)) == _metadata(before))
        digest, remaining = hashlib.sha256(), before.st_size
        while remaining:
            chunk = self.effect("intent_read", os.read, intent.fileno(), min(CHUNK, remaining), mutating=False)
            _require(type(chunk) is bytes and 0 < len(chunk) <= remaining)
            digest.update(chunk)
            remaining -= len(chunk)
        _require(self.effect("intent_eof", os.read, intent.fileno(), 1, mutating=False) == b"")
        _require(_metadata(self.effect("intent_after", os.fstat, intent.fileno(), mutating=False)) == _metadata(before)
                 and digest.hexdigest() == self.fields["intentSha256"])
        intent.close()
        self.intent_metadata = _metadata(before)
        self.namespace()
        self.absent("command-final.pending")
        self.absent("command-final.json")

    def absent(self, name: str) -> None:
        # Genuine ENOENT is expected here, so it is not fed into the common
        # failure latch. No wildcard cleanup or foreign-file adoption exists.
        self.ctx.owner_check()
        try:
            os.stat(name, dir_fd=self.session.fileno(), follow_symlinks=False)
        except FileNotFoundError:
            return
        raise ProcessError("owned command fence name already exists")

    def _pending_identity(self, details: os.stat_result, *, links: int, size: int) -> None:
        identity = self.creation_identity
        _require(identity is not None and (details.st_dev, details.st_ino, details.st_uid,
                 details.st_gid, details.st_mode, 1) == identity
                 and details.st_nlink == links and details.st_size == size)

    def _checkpoint(self, operation: FenceOperation, edge: FenceEdge,
                    outcome: FenceEventOutcome, operand: bytes = b"") -> None:
        if self.observer is not None:
            self.observer.checkpoint(operation, edge, outcome, written=self.written,
                                     total=len(self.content), sync_flags=self.sync_flags, operand=operand)

    def _operation(self, operation: FenceOperation, body: Callable[[], None]) -> None:
        self.ctx.check_tail()
        self.namespace()
        self._checkpoint(operation, FenceEdge.BEFORE, FenceEventOutcome.PENDING)
        self.ctx.check_tail()
        try:
            body()
        except BaseException as error:
            self.ctx.record(error)
            try:
                self._checkpoint(operation, FenceEdge.AFTER, FenceEventOutcome.UNKNOWN)
            except BaseException as diagnostic:
                self.ctx.record(diagnostic)
            raise
        self._checkpoint(operation, FenceEdge.AFTER, FenceEventOutcome.OK)

    def publish(self, seal: DescendantsSettled) -> None:
        _require(type(seal) is DescendantsSettled and seal._custodian is self.custodian
                 and seal._nonce == self.ctx.nonce and self.custodian.seal is seal
                 and not self.attempted and not self.retired)
        self.attempted = True
        self.content = _json({**self.fields, "outcome": "producer-settled" if
                             self.custodian.run_route.attempted else "never-dispatched"})
        _require(1 < len(self.content) <= 4096)
        if self.policy is FenceObservationPolicy.TRACE_V1:
            self.observer = _FenceObserver(self, self.custodian.upstream, _key=_KEY)

        def create() -> None:
            self.absent("command-final.pending")
            self.absent("command-final.json")
            self.pending.open("command-final.pending", os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                              os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, parent=self.session.fileno())
            info = self.effect("pending_identity", os.fstat, self.pending.fileno(), mutating=False)
            identity = (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_nlink)
            _require(stat.S_ISREG(info.st_mode) and info.st_mode == stat.S_IFREG | 0o600
                     and info.st_uid == self.fields["uid"] and info.st_nlink == 1 and info.st_size == 0
                     and _integer(info.st_dev, 0, (1 << 64) - 1) and _integer(info.st_ino, 1, (1 << 64) - 1)
                     and all(_integer(value, 0, (1 << 32) - 1) for value in identity[2:]))
            self.creation_identity = identity

        def write() -> None:
            if self.observer is not None:
                operand = self.content[:len(self.content) // 2]
                count = self.effect("pending_prefix", os.write, self.pending.fileno(), operand)
                _require(_integer(count, 1, len(operand)))
                self.written = count
                try:
                    current = self.effect("pending_prefix_identity", os.fstat, self.pending.fileno(), mutating=False)
                    self._pending_identity(current, links=1, size=count)
                except BaseException:
                    # Preserve creation history for custody, but do not label
                    # failed current PARTIAL revalidation as BOUND evidence.
                    self.observation_identity_unavailable = True
                    raise
                self._checkpoint(FenceOperation.PENDING_WRITE, FenceEdge.PARTIAL, FenceEventOutcome.OK, operand)
            while self.written < len(self.content):
                self.ctx.check_tail()
                count = self.effect("pending_write", os.write, self.pending.fileno(), self.content[self.written:])
                _require(_integer(count, 1, len(self.content) - self.written))
                self.written += count
            self._pending_identity(self.effect("pending_written_identity", os.fstat, self.pending.fileno(), mutating=False),
                                   links=1, size=len(self.content))

        def data_sync() -> None:
            _require(self.effect("pending_fsync", os.fsync, self.pending.fileno()) is None)
            self.sync_flags |= 1

        def link() -> None:
            self.namespace()
            self._pending_identity(self.effect("pending_name", os.stat, "command-final.pending",
                                    dir_fd=self.session.fileno(), follow_symlinks=False, mutating=False),
                                   links=1, size=len(self.content))
            self.absent("command-final.json")
            _require(self.effect("final_link", os.link, "command-final.pending", "command-final.json",
                                 src_dir_fd=self.session.fileno(), dst_dir_fd=self.session.fileno(),
                                 follow_symlinks=False) is None)
            for name in ("command-final.pending", "command-final.json"):
                self._pending_identity(self.effect("fence_pair", os.stat, name, dir_fd=self.session.fileno(),
                                                   follow_symlinks=False, mutating=False),
                                       links=2, size=len(self.content))

        def directory_sync() -> None:
            _require(self.effect("fence_directory_fsync", os.fsync, self.session.fileno()) is None)
            self.sync_flags |= 2

        for operation, body in ((FenceOperation.PENDING_CREATE, create), (FenceOperation.PENDING_WRITE, write),
                                (FenceOperation.DATA_FSYNC, data_sync), (FenceOperation.PENDING_CLOSE, self.pending.close),
                                (FenceOperation.FINAL_LINK, link), (FenceOperation.DIRECTORY_FSYNC, directory_sync)):
            self._operation(operation, body)
        self.complete = True

    def close(self) -> bool:
        # At a held observer edge, this is called only after genuine O loss or
        # original cutoff failure, never to advance successful publication.
        for slot in reversed(self.files):
            if slot.state == "OPEN":
                try:
                    slot.close()
                except BaseException as error:
                    self.ctx.record(error, unknown=True)
        self.retired = True  # No account callback remains after this boundary.
        return all(slot.state in ("NEW", "CLOSED") for slot in self.files)


def _settlement_fields(content: bytes, context: _Context) -> dict[str, Any]:
    fields = _scalar_fields(content, context.nonce,
                            {"create", "run", "no_child", "moved", "wait", "armed", "rejected", "producer", "result"})
    _require(all(type(fields[name]) is bool for name in
                 ("create", "run", "no_child", "moved", "armed", "producer", "result"))
             and (fields["wait"] is None or _valid_receipt(fields["wait"]))
             and not (fields["no_child"] and fields["wait"] is not None)
             and (not fields["run"] or fields["create"])
             and (not fields["armed"] or fields["run"]))
    rejection = fields["rejected"]
    if rejection is not None:
        _require(type(rejection) is dict and set(rejection) == {"stage", "errno"}
                 and rejection["stage"] in ("stdio", "cwd", "signals", "exec")
                 and _integer(rejection["errno"], 1, 4095) and fields["armed"])
    if fields["producer"]:
        _require(fields["moved"] and (fields["no_child"] or fields["wait"] is not None))
        if fields["no_child"]:
            _require(not fields["run"] and not fields["armed"] and rejection is None)
        elif fields["wait"]["kind"] == "exit":
            _require(fields["run"] and fields["armed"] and rejection is None)
        if rejection is not None:
            _require(fields["wait"] is not None and fields["wait"]["kind"] == "signal")
    if fields["result"]:
        _require(fields["producer"] and (not fields["run"] or fields["armed"]))
    return fields


def _terminal_code(context: _Context, wire: _Wire, epoch: tuple[int, int], *,
                   allowed: bool) -> int:
    context.owner_check()
    # A helper-local signal is latched without throwing inside cleanup/W's
    # guard tail. A later epoch snapshot must not erase that earlier stop into
    # an ordinary success, even when the independently authorized tail settles.
    intended = HELPER_FAILED if context.primary is not None or context.stopped else HELPER_OK
    # This monotonic arm protects the saved return through the minimal loader's
    # integer exit handoff. A later executed helper signal cannot preserve it.
    context.exit_armed = True
    if (not allowed or context.cleanup_unknown or not context.settled()
            or Tag.TERMINAL not in wire.sent or wire.out is not None
            or wire.write_failed or wire.write_in_flight or wire.writer.state != "CLOSED"
            or time.monotonic_ns() >= context.cutoff()
            or epoch != (context.error_epoch, context.signal_epoch)):
        return HELPER_UNKNOWN
    return intended


class _Worker:
    def __init__(self, context: _Context, bootstrap: native.CommandBootstrapMap) -> None:
        self.ctx = context
        self.io, self.account = context.start_io(), context.start_io()
        self.mapping = _bootstrap_map(context, bootstrap, self.io, self.account)
        _require(bootstrap.account_binding is None and self.mapping[5].account_binding is None)
        self.upstream = _Wire(context, self.mapping[3], self.mapping[4])
        self.exec_retired = self.reject_attempted = False
        self.effects: list[_FileEffect] = []

    def _setup(self, operation: str, function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        effect = _FileEffect(operation)
        self.effects.append(effect)
        effect.state = "IN_FLIGHT"
        try:
            effect.result = function(*args, **kwargs)
            effect.state = "RETURNED"
            return effect.result
        except BaseException:
            effect.state = "UNKNOWN"
            raise

    def _reject(self, stage: str, number: int) -> None:
        self.exec_retired = True  # There is no exec site on the report/tail path.
        _require(not self.reject_attempted and stage in ("stdio", "cwd", "signals", "exec")
                 and _integer(number, 1, 4095))
        payload = _scalar(self.ctx.nonce, stage=stage, errno=number)
        self.upstream.queue(Tag.EXEC_REJECTED, payload)
        frame = self.upstream.out
        _require(frame is not None and len(frame) <= 512)
        self.reject_attempted = True
        self.upstream.write_in_flight = True
        # Exactly ONE nonblocking syscall, not the ordinary suffix write loop.
        # A complete receiver frame can survive a lost local return, but no
        # incomplete/zero/error return authorizes another write or normal exit.
        count = os.write(self.mapping[4].fileno(), frame)
        self.upstream.write_in_flight = False
        _require(type(count) is int and count == len(frame))
        self.upstream.sent_bytes += count
        self.upstream.sent.append(Tag.EXEC_REJECTED)
        self.upstream.out = None

    def run(self) -> None:
        ctx, wire = self.ctx, self.upstream
        _send(wire, Tag.HELLO, _hello(ctx), lambda: None)
        manifest, policy, _, _ = _config(_receive(wire, Tag.CONFIG, lambda: None), ctx, custodian=False)
        wire.expected_manifest = manifest
        _require(Manifest.decode(_receive(wire, Tag.MANIFEST, lambda: None)) == manifest)
        decoded = NativeRecordDecoder(manifest)
        while wire.read_data < manifest.record_bytes:
            decoded.feed(_receive(wire, Tag.DATA, lambda: None))
        decoded.finish()
        ctx.check()
        _send(wire, Tag.READY, _scalar(ctx.nonce), lambda: None)
        _scalar_fields(_receive(wire, Tag.RUN_TOOL, lambda: None), ctx.nonce, set())
        ctx.check()
        _send(wire, Tag.EXEC_ARMED, _scalar(ctx.nonce), lambda: None)
        # The complete marker is a necessary pre-exec gate, not evidence that
        # an image subsequently ran. The enclosing loader never exits normally
        # if any of these setup/exec/report operations returns or raises.
        stage = "stdio"
        try:
            ctx.check()
            if manifest.capture:
                _require(self._setup("stdout_dup", os.dup2, self.mapping[6].fileno(), 1, inheritable=True) == 1)
                _require(self._setup("stderr_dup", os.dup2, self.mapping[7].fileno(), 2, inheritable=True) == 2)
            for fd in (0, 1, 2):
                _require(self._setup("stdio_inheritance", os.set_inheritable, fd, True) is None)
            stage = "cwd"
            _require(self._setup("cwd", os.chdir, decoded.cwd) is None)
            stage = "signals"
            for bit, signum in enumerate((signal.SIGINT, signal.SIGTERM, signal.SIGCHLD)):
                self._setup("target_disposition", signal.signal, signum,
                            signal.SIG_IGN if policy & (1 << bit) else signal.SIG_DFL)
            for name in ("SIGPIPE", "SIGXFZ", "SIGXFSZ"):
                if hasattr(signal, name):
                    self._setup("target_default", signal.signal, getattr(signal, name), signal.SIG_DFL)
            # Deliberately no pthread_sigmask, umask or shell/PATH preflight.
            ctx.check()
        except OSError as error:
            self._reject(stage, error.errno)
            return
        argv = tuple(decoded.argv)
        first_error = None
        final_error = errno.ENOENT
        directories = decoded.directories if manifest.search else [None]
        for directory in directories:
            ctx.check()
            _require(not self.exec_retired)
            candidate = argv[0] if directory is None or directory == b"" else directory + b"/" + argv[0]
            effect = _FileEffect("exec")
            self.effects.append(effect)
            effect.state = "IN_FLIGHT"
            try:
                # Byte-only exec: O already froze filesystem encoding, env and
                # PATH splitting. Never re-encode using the helper's locale.
                value = os.execve(candidate, argv, decoded.environment)
            except OSError as error:
                _require(_integer(error.errno, 1, 4095))
                effect.result, effect.state = error.errno, "REJECTED"
                final_error = error.errno
                if error.errno not in (errno.ENOENT, errno.ENOTDIR) and first_error is None:
                    first_error = error.errno
                continue
            effect.result, effect.state = value, "RETURNED"
            # execve cannot return normally; do not invent an errno or a target
            # result from an unexpected return/publication failure.
            raise ProcessError(ERROR)
        self._reject("exec", final_error if first_error is None else first_error)


class _Anchor:
    def __init__(self, context: _Context, bootstrap: native.CommandBootstrapMap) -> None:
        self.ctx, self.session = context, os.getsid(0)
        self.relay, self.account, self.producer = context.start_io(), context.start_io(), context.start_io()
        self.mapping = _bootstrap_map(context, bootstrap, self.relay, self.account)
        self.upstream = _Wire(context, self.mapping[3], self.mapping[4])
        self.group = _SelfGroup(context, self.session)
        self.child: native.Child | None = None
        self.downstream: _Wire | None = None
        self.create_route, self.run_route = _Route(Tag.CREATE_W), _Route(Tag.RUN_TOOL)
        context.routes.extend((self.create_route, self.run_route))
        self.moved = self.armed = self.worker_ready = self.worker_protocol_failed = False
        self.rejection: dict[str, Any] | None = None
        self.wait: native.WaitReceipt | None = None
        self.no_child = False
        self.work_done: bytes | None = None
        self.group_done = False

    def _parent(self) -> None:
        _input_loss(self.ctx, self.upstream)

    def _worker_frames(self) -> None:
        wire = self.downstream
        if wire is None:
            return
        if wire.poisoned:
            self.worker_protocol_failed = True
            if not wire.eof:
                wire.drain_to_eof()
            return
        frame = wire.read()
        if frame is None:
            return
        try:
            self._worker_frame(*frame)
        except BaseException as error:
            self.worker_protocol_failed = wire.poisoned = True
            self.ctx.record(error)
            raise

    def _worker_frame(self, tag: Tag, body: bytes) -> None:
        if tag is Tag.EXEC_ARMED:
            _require(self.run_route.attempted and self.worker_ready and not self.armed and self.rejection is None)
            _scalar_fields(body, self.ctx.nonce, set())
            self.armed = True
        elif tag is Tag.EXEC_REJECTED:
            _require(self.armed and self.rejection is None)
            value = _scalar_fields(body, self.ctx.nonce, {"stage", "errno"})
            _require(value["stage"] in ("stdio", "cwd", "signals", "exec") and _integer(value["errno"], 1, 4095))
            self.rejection = {"stage": value["stage"], "errno": value["errno"]}
        else:
            self.worker_protocol_failed = True
            raise ProcessError(ERROR)

    def _move(self) -> None:
        _require(not self.moved and os.getsid(0) == self.session and os.getpgrp() == self.ctx.pid)
        # The calling process is the actual A, not a stored/reconstructed PID.
        os.setpgid(0, self.session)
        _require(os.getsid(0) == self.session and os.getpgrp() == self.session)
        self.moved = True
        _command_event("A", "anchor_moved", context=self.ctx)

    def _prepare_worker(self, manifest: Manifest, policy: int) -> None:
        ctx = self.ctx
        nulls = _nulls(self.producer)
        incoming, command_writer = self.producer.pipe()
        status_reader, outgoing = self.producer.pipe()
        null_hold = self.producer.open_null(writable=False)
        sources = (*nulls, incoming, outgoing, null_hold, self.mapping[6], self.mapping[7])
        spec = _command_spec(ctx, "W", sources)
        # Publish the original control pair before any creator can exist. An
        # interrupted creation/return therefore still has an EOF withdrawal
        # route; cleanup need not wait a child still waiting for CONFIG.
        self.downstream = _Wire(ctx, status_reader, command_writer)
        self.downstream.expected_manifest = manifest
        self.create_route.queue()
        self.create_route.attempt()  # Original CREATE_W consumption before start.
        self.child = _spawn(ctx, spec, self._parent)
        for lease in (*nulls, incoming, outgoing, null_hold, self.mapping[6], self.mapping[7]):
            ctx.close(lease)
        hello = _receive(self.downstream, Tag.HELLO, self._parent)
        _admit_hello(ctx, self.child, hello, "W", self.session, ctx.pid)
        self._move()  # Only after real creator settlement AND W's private map.
        _send(self.downstream, Tag.CONFIG, _config_bytes(ctx, manifest, policy), self._parent)

    def body(self) -> None:
        ctx, parent = self.ctx, self.upstream
        _send(parent, Tag.HELLO, _hello(ctx), lambda: None)
        manifest, policy, _, _ = _config(_receive(parent, Tag.CONFIG, lambda: None), ctx, custodian=False)
        parent.expected_manifest = manifest
        _send(parent, Tag.PREPARED, _scalar(ctx.nonce), lambda: None)
        _scalar_fields(_receive(parent, Tag.CREATE_W, lambda: None), ctx.nonce, set())
        self._prepare_worker(manifest, policy)
        assert self.downstream is not None and self.child is not None
        content = _receive(parent, Tag.MANIFEST, self._parent)
        _send(self.downstream, Tag.MANIFEST, content, self._parent)
        digest = hashlib.sha256()
        while parent.read_data < manifest.record_bytes:
            content = _receive(parent, Tag.DATA, self._parent)
            digest.update(content)
            _send(self.downstream, Tag.DATA, content, self._parent)
        _require(digest.digest() == manifest.digest)
        _scalar_fields(_receive(self.downstream, Tag.READY, self._parent), ctx.nonce, set())
        self.worker_ready = True
        _send(parent, Tag.READY, _scalar(ctx.nonce, moved=True), self._parent)
        _scalar_fields(_receive(parent, Tag.RUN_TOOL, self._parent), ctx.nonce, set())
        _send(self.downstream, Tag.RUN_TOOL, _scalar(ctx.nonce), self._parent, route=self.run_route)
        # W numeric signal/probe authority is retired BEFORE the very first
        # potentially consuming wait, including a genuine pid0 poll.
        self.child.retire_numeric()
        while self.wait is None or not self.downstream.eof:
            ctx.check()
            self._worker_frames()
            if self.wait is None:
                self.wait = self.child.poll_wait()
            _check_stop(ctx, parent)
            _pause(ctx.run)
        _require(self.armed and not self.worker_protocol_failed and not self.downstream.poisoned)

    def _local_producers(self) -> bool:
        wire = self.downstream
        return (self.moved and (self.no_child or self.wait is not None and wire is not None and wire.eof
                and wire.reader.state == "CLOSED" and wire.writer.state == "CLOSED")
                and self.ctx.settled((self.producer, self.ctx.child_acquisition))
                and all(self.mapping[fd].state == "CLOSED" for fd in (6, 7)))

    def finish(self) -> int:
        ctx, parent = self.ctx, self.upstream
        ctx.begin_cleanup()
        ctx.retire_launch()
        ctx.cleanup_tasks(lambda: None)
        self.child = ctx.child_acquisition.child
        if self.child is None:
            self.no_child = (not ctx.child_acquisition.attempted and not ctx.child_acquisition.cleanup_unknown
                             and all(task.joined for task in ctx.tasks))
            if self.no_child and not self.moved:
                self._move()  # Genuine closed no-child branch, never UNKNOWN.
        wire = self.downstream
        if wire is not None:
            wire.close_writer()
        if self.child is not None:
            if not self.moved:
                # No positive W-map/group handshake: cannot pretend A moved.
                # Self-group termination is the bounded failing disposition.
                self.group.terminate()
                return HELPER_UNKNOWN
            if ctx.primary is not None:
                self.group.terminate()
            if self.wait is None:
                self.wait = _wait_original(ctx, self.child, self._worker_frames)
            if wire is not None:
                while not wire.eof and time.monotonic_ns() < ctx.cutoff():
                    try:
                        self._worker_frames()
                    except BaseException as error:
                        self.worker_protocol_failed = True
                        ctx.record(error)
                        if wire.poisoned and wire.reader.state != "OPEN":
                            break
                    _pause(ctx.cutoff())
                ctx.close(wire.reader)
        for fd in (6, 7):
            if all(task.joined for task in ctx.tasks):
                ctx.close(self.mapping[fd])
        ctx.close_io(self.producer)
        producer = self._local_producers()
        result = (producer and not self.worker_protocol_failed
                  and (not self.run_route.attempted or self.armed)
                  and (wire is None or not wire.poisoned))
        self.work_done = _scalar(ctx.nonce, create=self.create_route.attempted, run=self.run_route.attempted,
                                 no_child=self.no_child, moved=self.moved, wait=_receipt(self.wait),
                                 armed=self.armed, rejected=self.rejection, producer=producer, result=result)
        _settlement_fields(self.work_done, ctx)
        if producer and not parent.eof and not ctx.parent_lost():
            try:
                _send(parent, Tag.WORK_DONE, self.work_done, lambda: None, normal=False)
                body = _receive(parent, Tag.GROUP_DONE, lambda: None, normal=False)
                _scalar_fields(body, ctx.nonce, set())
                self.group_done = True
            except BaseException as error:
                ctx.record(error)
        self.group.retired = True
        allowed = producer and self.group_done
        epoch = (ctx.error_epoch, ctx.signal_epoch)
        if allowed:
            try:
                _send(parent, Tag.TERMINAL, self.work_done, lambda: None, normal=False)
            except BaseException as error:
                ctx.record(error)
        parent.close_writer()
        ctx.close_io(self.relay)
        # Hold closes last, only after every preceding raw/native slot is known.
        if ctx.settled((self.relay, self.producer, ctx.child_acquisition)) and not ctx.cleanup_unknown:
            ctx.close_io(self.account)
        else:
            ctx.cleanup_unknown = True
        return _terminal_code(ctx, parent, epoch, allowed=allowed)

    def run(self) -> int:
        try:
            self.body()
        except BaseException as error:
            self.ctx.record(error)
        try:
            return self.finish()
        except BaseException as error:
            self.ctx.record(error, unknown=True)
            # Never issue another creator/wait/close pass from an exception
            # reporter. The helper's unchanged cutoff/parent owns any debt.
            return HELPER_UNKNOWN


class _Custodian:
    def __init__(self, context: _Context, bootstrap: native.CommandBootstrapMap, policy: int) -> None:
        _require(_integer(policy, 0, 3))
        self.ctx, self.policy = context, policy
        self.relay, self.account, self.producer = context.start_io(), context.start_io(), context.start_io()
        self.mapping = _bootstrap_map(context, bootstrap, self.relay, self.account)
        self.upstream = _Wire(context, self.mapping[3], self.mapping[4], diagnostics=True)
        self.downstream: _Wire | None = None
        self.child: native.Child | None = None
        self.group: _AnchorGroup | None = None
        self.create_route, self.run_route = _Route(Tag.CREATE_W), _Route(Tag.RUN_TOOL)
        context.routes.extend((self.create_route, self.run_route))
        self.manifest: Manifest | None = None
        self.writer: FenceWriter | None = None
        self.writer_prepared = False
        self.source_readers: list[native.FDLease] = []
        self.source_eof = [False, False]
        self.source_failed = self.output_overflow = self.anchor_protocol_failed = False
        self.output = [bytearray(), bytearray()]
        self.source_counts = [0, 0]
        self.anchor_work: dict[str, Any] | None = None
        self.anchor_terminal: dict[str, Any] | None = None
        self.wait: native.WaitReceipt | None = None
        self.group_done_sent = False
        self.seal: DescendantsSettled | None = None

    def _source_io(self) -> None:
        limit = self.manifest.limit if self.manifest is not None else PRIVATE_OUTPUT_LIMIT
        for index, reader in enumerate(self.source_readers):
            if self.source_eof[index] or reader.state != "OPEN":
                continue
            try:
                chunk = os.read(reader.fileno(), CHUNK)
            except BlockingIOError:
                continue
            except BaseException as error:
                self.source_failed = True
                self.ctx.record(error)
                # A failed source read is not repaired by a different reader or
                # by O's relay EOF. Retain the original slot, fail the seal.
                self.ctx.close(reader)
                continue
            if not chunk:
                self.source_eof[index] = True
                continue
            self.source_counts[index] += len(chunk)
            _require(self.source_counts[index] <= INTEGER_LIMIT)
            left = max(0, limit - sum(map(len, self.output)))
            self.output[index].extend(chunk[:left])
            if sum(self.source_counts) > limit and not self.output_overflow:
                self.output_overflow = True
                self.ctx.record(ProcessError("owned command output exceeds its bound"))

    def _parent(self) -> None:
        self._source_io()
        _input_loss(self.ctx, self.upstream)

    def _anchor_frames(self) -> None:
        wire = self.downstream
        if wire is None:
            return
        if wire.poisoned:
            self.anchor_protocol_failed = True
            if not wire.eof:
                wire.drain_to_eof()
            return
        frame = wire.read()
        if frame is None:
            return
        try:
            self._anchor_frame(*frame)
        except BaseException as error:
            self.anchor_protocol_failed = wire.poisoned = True
            self.ctx.record(error)
            raise

    def _anchor_frame(self, tag: Tag, body: bytes) -> None:
        if tag is Tag.WORK_DONE:
            _require(self.anchor_work is None and not self.group_done_sent)
            value = _settlement_fields(body, self.ctx)
            _require((not value["create"] or self.create_route.attempted)
                     and (not value["run"] or self.run_route.attempted))
            self.anchor_work = value
        elif tag is Tag.TERMINAL:
            _require(self.group_done_sent and self.group is not None and self.group.retired
                     and self.anchor_work is not None and self.anchor_terminal is None)
            self.anchor_terminal = _settlement_fields(body, self.ctx)
            _require(self.anchor_terminal == self.anchor_work)
        else:
            self.anchor_protocol_failed = True
            raise ProcessError(ERROR)

    def _pump(self) -> None:
        self._source_io()
        self._anchor_frames()

    def body(self) -> None:
        ctx, parent = self.ctx, self.upstream
        _send(parent, Tag.HELLO, _hello(ctx), lambda: None)
        manifest, placeholder, journalled, trace = _config(_receive(parent, Tag.CONFIG, lambda: None), ctx, custodian=True)
        _require(placeholder == 0)
        self.manifest = parent.expected_manifest = manifest
        if journalled:
            content = _receive(parent, Tag.FENCE_BINDING, lambda: None)
            self.writer = FenceWriter(self, content, trace, _key=_KEY)
            self.writer.prepare()
            self.writer_prepared = True
        else:
            _require(trace is FenceObservationPolicy.OFF)
        nulls = _nulls(self.producer)
        child_input, writer = self.producer.pipe()
        reader, child_status = self.producer.pipe()
        stdout, child_stdout = self.producer.pipe()
        stderr, child_stderr = self.producer.pipe()
        self.source_readers = [stdout, stderr]
        for source in self.source_readers:
            os.set_blocking(source.fileno(), False)
        sources = (*nulls, child_input, child_status, self.mapping[5], child_stdout, child_stderr)
        self.downstream = _Wire(ctx, reader, writer)
        self.downstream.expected_manifest = manifest
        self.child = _spawn(ctx, _command_spec(ctx, "A", sources), self._parent)
        self.group = _AnchorGroup(ctx, self.child)
        for lease in (*nulls, child_input, child_status, child_stdout, child_stderr):
            ctx.close(lease)
        hello = _receive(self.downstream, Tag.HELLO, self._parent)
        _admit_hello(ctx, self.child, hello, "A", ctx.pid, self.child.pid)
        _send(self.downstream, Tag.CONFIG, _config_bytes(ctx, manifest, self.policy), self._parent)
        _scalar_fields(_receive(self.downstream, Tag.PREPARED, self._parent), ctx.nonce, set())
        _send(parent, Tag.PREPARED, _scalar(ctx.nonce, group=self.child.pid, signals=self.policy), self._parent)
        _scalar_fields(_receive(parent, Tag.CREATE_W, self._parent), ctx.nonce, set())
        _send(self.downstream, Tag.CREATE_W, _scalar(ctx.nonce), self._parent, route=self.create_route)
        content = _receive(parent, Tag.MANIFEST, self._parent)
        _send(self.downstream, Tag.MANIFEST, content, self._parent)
        digest = hashlib.sha256()
        while parent.read_data < manifest.record_bytes:
            content = _receive(parent, Tag.DATA, self._parent)
            digest.update(content)
            _send(self.downstream, Tag.DATA, content, self._parent)
        _require(digest.digest() == manifest.digest)
        ready = _scalar_fields(_receive(self.downstream, Tag.READY, self._parent), ctx.nonce, {"moved"})
        _require(ready["moved"] is True and self.child.wait_state == "OWNED" and not self.child.numeric_retired
                 and os.getsid(self.child.pid) == ctx.pid and os.getpgid(self.child.pid) == ctx.pid)
        _send(parent, Tag.READY, _scalar(ctx.nonce), self._parent)
        _scalar_fields(_receive(parent, Tag.RUN_TOOL, self._parent), ctx.nonce, set())
        _send(self.downstream, Tag.RUN_TOOL, _scalar(ctx.nonce), self._parent, route=self.run_route)
        while self.anchor_work is None:
            ctx.check()
            self._pump()
            _check_stop(ctx, parent)
            _require(not self.downstream.eof or self.anchor_work is not None)
            _pause(ctx.run)

    def _stop_anchor(self) -> None:
        wire = self.downstream
        if wire is None or wire.writer.state != "OPEN":
            return
        if self.anchor_work is not None:
            return
        try:
            if wire.out is not None or wire.write_failed:
                wire.close_writer()
                return
            _send(wire, Tag.STOP, _scalar(self.ctx.nonce, cutoff=self.ctx.cutoff()), self._source_io, normal=False)
        except BaseException as error:
            self.ctx.record(error)
            wire.close_writer()

    def _producer_settled(self) -> bool:
        ctx, wire, group = self.ctx, self.downstream, self.group
        return (self.child is not None and self.child is ctx.child_acquisition.child
                and self.wait is not None and self.wait is self.child.receipt
                and self.wait.status_kind == "exit" and self.wait.status_code in (HELPER_OK, HELPER_FAILED)
                and group is not None and group.absent and group.retired
                and wire is not None and wire.eof and wire.reader.state == wire.writer.state == "CLOSED"
                and self.anchor_work is not None and self.anchor_work["producer"]
                and self.anchor_terminal == self.anchor_work and not self.anchor_protocol_failed
                and len(self.source_readers) == 2 and all(self.source_eof) and not self.source_failed
                and self.create_route.retired and self.run_route.retired
                and ctx.settled((self.producer, ctx.child_acquisition)))

    def seal_descendants(self) -> DescendantsSettled:
        self.ctx.owner_check()
        _require(self.seal is None and self._producer_settled())
        self.seal = DescendantsSettled(self, _key=_KEY)
        return self.seal

    def _settle_producers(self) -> None:
        ctx = self.ctx
        ctx.begin_cleanup()
        ctx.retire_launch()
        ctx.cleanup_tasks(self._source_io)
        self.child = ctx.child_acquisition.child
        if self.child is None:
            return  # No guessed PID or external child's receipt.
        if self.group is None:
            self.group = _AnchorGroup(ctx, self.child)
        wire = self.downstream
        self._stop_anchor()
        # Give the real A its original chance to settle W and move out of G.
        # Killing G immediately after STOP would kill a prepared, no-W A before
        # it can produce the genuine no-child settlement needed by late ARMED.
        while (wire is not None and not wire.eof and self.anchor_work is None
               and time.monotonic_ns() < ctx.cutoff() - 50_000_000):
            try:
                self._pump()
            except BaseException as error:
                self.anchor_protocol_failed = True
                ctx.record(error)
                if wire.poisoned:
                    break
            _pause(ctx.cutoff())
        try:
            self.group.terminate()
            while not self.group.probe() and time.monotonic_ns() < ctx.cutoff():
                try:
                    self._pump()
                except BaseException as error:
                    self.anchor_protocol_failed = True
                    ctx.record(error)
                _pause(ctx.cutoff())
        except BaseException as error:
            ctx.record(error, unknown=True)
        finally:
            self.group.retire()  # Permanently BEFORE any original A wait.
        if (self.group.absent and self.anchor_work is not None and self.anchor_work["producer"]
                and wire is not None and not self.anchor_protocol_failed and wire.writer.state == "OPEN"):
            try:
                _send(wire, Tag.GROUP_DONE, _scalar(ctx.nonce), self._source_io, normal=False)
                self.group_done_sent = True
                while not wire.eof and time.monotonic_ns() < ctx.cutoff():
                    self._pump()
                    _pause(ctx.cutoff())
            except BaseException as error:
                self.anchor_protocol_failed = True
                ctx.record(error)
        if self.anchor_terminal is None and self.child.wait_state == "OWNED" and not self.child.numeric_retired:
            # The exact original A remains reserved here. No route survives its
            # first consuming wait, including on malformed/early-EOF branches.
            try:
                os.kill(self.child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except BaseException as error:
                ctx.record(error, unknown=True)
        self.child.retire_numeric()
        self.wait = _wait_original(ctx, self.child, self._pump)
        while not all(self.source_eof) and time.monotonic_ns() < ctx.cutoff():
            self._source_io()
            if self.source_failed:
                break
            _pause(ctx.cutoff())
        if wire is not None:
            wire.close_writer()
            ctx.close(wire.reader)
        ctx.close_io(self.producer)

    def _relay_output(self) -> bool:
        complete = True
        for index, descriptor in enumerate((self.mapping[6], self.mapping[7])):
            try:
                os.set_blocking(descriptor.fileno(), False)
                offset = 0
                while offset < len(self.output[index]):
                    self.ctx.check_tail()
                    try:
                        count = os.write(descriptor.fileno(), self.output[index][offset:offset + CHUNK])
                    except BlockingIOError:
                        _pause(self.ctx.cutoff())
                        continue
                    _require(_integer(count, 1, min(CHUNK, len(self.output[index]) - offset)))
                    offset += count
            except BaseException as error:
                self.ctx.record(error)
                complete = False
            finally:
                self.ctx.close(descriptor)
        return complete

    def finish(self) -> int:
        ctx, parent = self.ctx, self.upstream
        self._settle_producers()
        producer = self._producer_settled()
        if producer:
            seal = self.seal_descendants()
            try:
                _send(parent, Tag.PRODUCERS_SEALED, _scalar(ctx.nonce), lambda: None, normal=False)
            except BaseException as error:
                ctx.record(error)
            if self.writer is not None and self.writer_prepared:
                try:
                    self.writer.publish(seal)
                except BaseException as error:
                    ctx.record(error)
        fs_settled = True if self.writer is None else self.writer.close()
        relay = self._relay_output()
        anchor = self.anchor_work
        valid = (producer and anchor is not None and anchor["result"] and not self.output_overflow
                 and self.wait is not None and self.wait.status_code == HELPER_OK
                 and not self.source_failed and relay)
        if not valid and ctx.primary is None:
            ctx.record(ProcessError(ERROR))
        # Bind the result before serialization/publication: a stop already
        # latched cannot produce success, and a later signal invalidates this
        # original epoch rather than inheriting an already-built success frame.
        epoch = (ctx.error_epoch, ctx.signal_epoch)
        valid = valid and ctx.primary is None and not ctx.stopped
        no_target = None
        if producer and anchor is not None:
            if anchor["no_child"]:
                no_target = "NO_W_CREATION"
            elif not anchor["run"]:
                no_target = "CLOSED_BEFORE_RUN"
            elif anchor["rejected"] is not None and anchor["result"]:
                no_target = "EXEC_REJECTED"
        terminal = _scalar(ctx.nonce, create=self.create_route.attempted, run=self.run_route.attempted,
                            no_target=no_target, wait=None if anchor is None else anchor["wait"],
                            producer=producer, result=valid, stdout=len(self.output[0]), stderr=len(self.output[1]),
                            fence=None if self.writer is None else self.writer.complete)
        try:
            _send(parent, Tag.TERMINAL, terminal, lambda: None, normal=False)
        except BaseException as error:
            ctx.record(error)
        parent.close_writer()
        ctx.close_io(self.relay)
        if (fs_settled and not ctx.cleanup_unknown
                and ctx.settled((self.relay, self.producer, ctx.child_acquisition))):
            ctx.close_io(self.account)  # Original account hold is always last.
        else:
            ctx.cleanup_unknown = True
        return _terminal_code(ctx, parent, epoch, allowed=producer and fs_settled)

    def run(self) -> int:
        try:
            self.body()
        except BaseException as error:
            self.ctx.record(error)
        try:
            return self.finish()
        except BaseException as error:
            self.ctx.record(error, unknown=True)
            return HELPER_UNKNOWN


def helper_main(argv: list[str], policy: int | None) -> int:
    """Only the fixed loader calls this; W's loader guards this entire call."""
    context: _Context | None = None
    try:
        _require(type(argv) is list and len(argv) == 9 and argv[0] in ("C", "A", "W")
                 and argv[8] == "1")
        role = argv[0]
        parent, session, group, run, hard = (int(value) for value in argv[1:6])
        _require(all(_integer(value, 1, PID_LIMIT) for value in (parent, session, group))
                 and all(str(value) == encoded for value, encoded in zip((parent, session, group, run, hard), argv[1:6]))
                 and len(argv[6]) == 32 and all(char in "0123456789abcdef" for char in argv[6]))
        nonce = bytes.fromhex(argv[6])
        account = None if argv[7] == "-" else tuple(int(value) for value in argv[7].split(","))
        _require(account is None or len(account) == 3 and all(type(value) is int for value in account))
        _require(os.getppid() == parent and os.getsid(0) == session and os.getpgrp() == group
                 and time.monotonic_ns() < run and hard - run == CLEANUP_NS)
        if role == "C":
            _require(_integer(policy, 0, 3))
            os.setsid()
            _require(os.getsid(0) == os.getpgrp() == os.getpid())
        elif role == "A":
            _require(policy is None and session == group == parent)
            os.setpgid(0, 0)
            _require(os.getsid(0) == session and os.getpgrp() == os.getpid())
        else:
            _require(policy is None and account is None and group == parent)
        context = _Context(role, nonce, run, hard, parent=parent)
        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, context.helper_signal)
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        bootstrap = native._issue_command_bootstrap(role=role, command_nonce=nonce,
                    parent_pid=parent, parent_session=session, parent_group=group, account_binding=account)
        if role == "W":
            _Worker(context, bootstrap).run()
            return HELPER_UNKNOWN  # Only into the loader's non-returning tail.
        owner = _Custodian(context, bootstrap, policy) if role == "C" else _Anchor(context, bootstrap)
        return owner.run()
    except BaseException as error:
        if context is not None:
            try:
                context.record(error, unknown=True)
            except BaseException:
                pass
        return HELPER_UNKNOWN


class _Outer:
    def __init__(self, guard: DefaultCancellation, owns: bool, timeout: int,
                 scope: AccountExecutionScope | None, binding: JournalledCommandBinding | None,
                 *, suppress_cancel: bool) -> None:
        self.nonce = os.urandom(16) if scope is None else scope.nonce
        now = time.monotonic_ns()
        self.ctx = _Context("O", self.nonce, now + timeout * NANOSECOND,
                            now + timeout * NANOSECOND + CLEANUP_NS,
                            guard=guard, suppress_cancel=suppress_cancel)
        self.guard, self.owns, self.scope, self.binding = guard, owns, scope, binding
        self.slot = CommandOutcomeSlot(None, self.nonce, _key=_KEY) if scope is None else scope.outcome
        if scope is None:
            _require(binding is None)
            self.slot._bind(self)
        else:
            _require(scope._source._lease.cancellation is guard)
            scope._consume(self, binding)
        guard.lifetime_ledger._bind_command(self.slot)
        self.create_route, self.run_route = _Route(Tag.CREATE_W), _Route(Tag.RUN_TOOL)
        self.ctx.routes.extend((self.create_route, self.run_route))
        self.io: native.Acquisition | None = None
        self.wire: _Wire | None = None
        self.child: native.Child | None = None
        self.wait: native.WaitReceipt | None = None
        self.frozen: FrozenCommand | None = None
        self.outputs = [bytearray(), bytearray()]
        self.readers: list[native.FDLease] = []
        self.output_eof = [False, False]
        self.output_failed = self.protocol_failed = False
        self.hello: bytes | None = None
        self.prepared: dict[str, Any] | None = None
        self.ready = self.sealed = False
        self.terminal: dict[str, Any] | None = None
        self.phase = "NEW"
        self.handlers_complete = self.local_cleanup_complete = self.cleanup_entered = False
        self.decoded: tuple[str, str] | None = None
        self.observation: FenceObservationDecoder | None = None
        if binding is not None and binding.fence_observation is FenceObservationPolicy.TRACE_V1:
            self.observation = FenceObservationDecoder(self.nonce, binding._fields["sequence"], uid=binding._fields["uid"])

    def prepared_reservation(self) -> bool:
        self.ctx.check()
        return (self.phase == "PREPARED" and self.prepared is not None and self.child is not None
                and self.child is self.ctx.child_acquisition.child and self.child.wait_state == "OWNED"
                and not self.child.numeric_retired and not self.ctx.launch_retired
                and all(task.joined for task in self.ctx.tasks) and self.ctx.child_acquisition.settled
                and not self.ctx.child_acquisition.cleanup_unknown and self.wire is not None
                and not self.wire.eof and not self.wire.poisoned and not self.sealed
                and not self.create_route.attempted and not self.create_route.retired
                and not self.run_route.attempted and not self.run_route.retired)

    def _read_outputs(self) -> None:
        limit = self.frozen.manifest.limit if self.frozen is not None else PRIVATE_OUTPUT_LIMIT
        for index, reader in enumerate(self.readers):
            if self.output_eof[index] or reader.state != "OPEN":
                continue
            try:
                chunk = os.read(reader.fileno(), CHUNK)
            except BlockingIOError:
                continue
            except BaseException as error:
                self.output_failed = True
                self.ctx.record(error)
                self.ctx.close(reader)
                continue
            if not chunk:
                self.output_eof[index] = True
                continue
            self.outputs[index].extend(chunk)
            if sum(map(len, self.outputs)) > limit:
                self.output_failed = True
                self.ctx.close(reader)
                raise ProcessError("owned command output exceeds its bound")

    def _terminal(self, content: bytes) -> dict[str, Any]:
        fields = _scalar_fields(content, self.nonce,
                                {"create", "run", "no_target", "wait", "producer", "result", "stdout", "stderr", "fence"})
        _require(all(type(fields[name]) is bool for name in ("create", "run", "producer", "result"))
                 and fields["no_target"] in (None, "NO_W_CREATION", "CLOSED_BEFORE_RUN", "EXEC_REJECTED")
                 and (fields["wait"] is None or _valid_receipt(fields["wait"]))
                 and all(_integer(fields[name], 0, OUTPUT_LIMIT) for name in ("stdout", "stderr"))
                 and (fields["fence"] is None if self.binding is None else type(fields["fence"]) is bool)
                 and (not fields["run"] or fields["create"])
                 and (not fields["create"] or self.create_route.attempted and self.prepared is not None)
                 and (not fields["run"] or self.run_route.attempted and self.ready)
                 and (not fields["producer"] or self.sealed)
                 and (fields["no_target"] is None or fields["producer"])
                 and (not fields["producer"] or fields["run"] or fields["no_target"] is not None)
                 and (fields["fence"] is not True or fields["producer"])
                 and (not fields["result"] or fields["producer"] and fields["wait"] is not None
                      and fields["run"] and self.ready
                      and (self.binding is None or fields["fence"] is True)))
        _require(self.frozen is not None
                 and fields["stdout"] + fields["stderr"] <= self.frozen.manifest.limit
                 and (self.frozen.manifest.capture or fields["stdout"] == fields["stderr"] == 0))
        if fields["no_target"] == "NO_W_CREATION":
            _require(fields["wait"] is None and not fields["run"])
        elif fields["no_target"] in ("CLOSED_BEFORE_RUN", "EXEC_REJECTED"):
            _require(fields["wait"] is not None and fields["wait"]["kind"] == "signal")
            if fields["no_target"] == "EXEC_REJECTED":
                _require(fields["run"])
        return fields

    def _pump(self) -> None:
        self.ctx.owner_check()
        self._read_outputs()
        wire = self.wire
        if wire is None:
            return
        if wire.poisoned:
            self.protocol_failed = True
            if not wire.eof and wire.reader.state == "OPEN":
                wire.drain_to_eof()
            return
        frame = wire.read()
        if frame is None:
            return
        try:
            self._frame(*frame)
        except BaseException as error:
            self.protocol_failed = wire.poisoned = True
            self.ctx.record(error)
            raise

    def _frame(self, tag: Tag, content: bytes) -> None:
        wire = self.wire
        assert wire is not None
        if tag is Tag.HELLO:
            _require(self.phase == "STARTING" and self.hello is None and self.child is not None)
            _admit_hello(self.ctx, self.child, content, "C", self.child.pid, self.child.pid)
            self.hello = content
        elif tag is Tag.PREPARED:
            _require(self.phase == "PREPARING" and self.prepared is None)
            value = _scalar_fields(content, self.nonce, {"group", "signals"})
            _require(_integer(value["group"], 1, PID_LIMIT) and _integer(value["signals"], 0, 3))
            self.prepared = value
        elif tag is Tag.READY:
            _require(self.phase in ("TRANSFER", "WAIT_READY") and self.create_route.attempted
                     and not self.ready and not self.sealed)
            _scalar_fields(content, self.nonce, set())
            self.ready = True
        elif tag is Tag.PRODUCERS_SEALED:
            _require(self.hello is not None and not self.sealed and self.terminal is None)
            _scalar_fields(content, self.nonce, set())
            self.sealed = True
            self.ctx.retire_launch()
        elif tag is Tag.FENCE_EVENT:
            _require(self.sealed and self.terminal is None and self.observation is not None
                     and self.ctx.primary is None and not self.protocol_failed)
            self.ctx.check()
            event = self.observation.accept(content)
            _fence_trace_checkpoint(event)
            self.ctx.check()
            _send(wire, Tag.FENCE_ACK, event.ack(), self._read_outputs)
        elif tag is Tag.TERMINAL:
            _require(self.hello is not None and self.terminal is None)
            self.terminal = self._terminal(content)
        else:
            self.protocol_failed = True
            raise ProcessError(ERROR)

    def _until(self, predicate: Callable[[], bool]) -> None:
        while not predicate():
            self.ctx.check()
            self._pump()
            _require(self.wire is not None and (not self.wire.eof or predicate()))
            self.ctx.check()
            if not predicate():
                readers = tuple(reader for reader, eof in (
                    (self.wire.reader, self.wire.eof), *zip(self.readers, self.output_eof))
                    if not eof and reader.state == "OPEN")
                _pause(self.ctx.run, readers=readers)

    def body(self, argv: Sequence[str], environ: Mapping[str, str] | None, cwd: Path | None,
             capture: bool, output_limit: int, on_start: Callable[[int], None] | None) -> None:
        ctx = self.ctx
        ctx.check()
        self.frozen = _freeze_command(argv, environ=environ, cwd=cwd, capture=capture,
                                      output_limit=output_limit, nonce=self.nonce)
        if self.binding is not None:
            _require(len(self.binding.fence_binding) <= SCALAR_LIMIT)
        self.io = ctx.start_io()
        nulls = _nulls(self.io)
        child_input, input_writer = self.io.pipe()
        status_reader, child_status = self.io.pipe()
        stdout, child_stdout = self.io.pipe()
        stderr, child_stderr = self.io.pipe()
        self.readers = [stdout, stderr]
        for reader in self.readers:
            os.set_blocking(reader.fileno(), False)
        hold = (self.io.open_null(writable=False) if self.scope is None else
                self.io.export_account_hold(self.scope._source._locked_source, command_nonce=self.nonce))
        sources = (*nulls, child_input, child_status, hold, child_stdout, child_stderr)
        self.wire = _Wire(ctx, status_reader, input_writer, diagnostics=self.observation is not None)
        self.wire.expected_manifest = self.frozen.manifest
        self.child = _spawn(ctx, _command_spec(ctx, "C", sources), lambda: None)
        for lease in (*nulls, child_input, child_status, hold, child_stdout, child_stderr):
            ctx.close(lease)
        self.phase = "STARTING"
        self._until(lambda: self.hello is not None)
        self.phase = "PREPARING"
        _send(self.wire, Tag.CONFIG, _config_bytes(ctx, self.frozen.manifest, 0,
              fence=self.binding is not None,
              trace=FenceObservationPolicy.OFF if self.binding is None else self.binding.fence_observation), self._pump)
        if self.binding is not None:
            _send(self.wire, Tag.FENCE_BINDING, self.binding.fence_binding, self._pump)
        self._until(lambda: self.prepared is not None)
        self.phase = "PREPARED"
        if on_start is not None:
            assert self.prepared is not None
            on_start(self.prepared["group"])  # Diagnostic only; never an arm capability.
        ctx.check()
        reservation = OriginalCommandReservation(self, _key=_KEY)
        permit = (CreatePermit(reservation, _key=_KEY) if self.binding is None else
                  self.binding.arm_command(reservation))
        permit._consume(self)
        ctx.check()
        self.phase = "TRANSFER"
        _send(self.wire, Tag.CREATE_W, _scalar(self.nonce), self._pump, route=self.create_route)
        _send(self.wire, Tag.MANIFEST, self.frozen.manifest.encode(), self._pump)
        for chunk in self.frozen.chunks():
            _send(self.wire, Tag.DATA, chunk, self._pump)
        self.phase = "WAIT_READY"
        self._until(lambda: self.ready)
        ctx.check()
        _require(not self.sealed and not self.run_route.retired)
        self.phase = "RUNNING"
        _send(self.wire, Tag.RUN_TOOL, _scalar(self.nonce), self._pump, route=self.run_route)
        self._until(lambda: self.terminal is not None and self.wire.eof and all(self.output_eof))
        _require(not self.protocol_failed and not self.output_failed)

    def _safe_pump(self) -> None:
        try:
            self._pump()
        except BaseException as error:
            self.ctx.record(error)
            self.protocol_failed = True
            if self.wire is not None and self.wire.writer.state == "OPEN":
                self.wire.close_writer()

    def cleanup(self) -> None:
        ctx = self.ctx
        ctx.owner_check()
        _require(not self.cleanup_entered)
        self.cleanup_entered = True
        ctx.begin_cleanup()
        ctx.retire_launch()
        ctx.cleanup_tasks(self._safe_pump)
        self.child = ctx.child_acquisition.child
        wire = self.wire
        if wire is not None and self.terminal is None and wire.writer.state == "OPEN":
            try:
                if wire.out is None and not wire.write_failed:
                    _send(wire, Tag.STOP, _scalar(self.nonce, cutoff=ctx.cutoff()), self._safe_pump, normal=False)
            except BaseException as error:
                ctx.record(error)
            finally:
                # Withdrawal is actual original EOF, including after a partial
                # DATA/grant. No replacement control stream or send retry.
                wire.close_writer()
        if wire is not None:
            while (not wire.eof or not all(self.output_eof)) and time.monotonic_ns() < ctx.cutoff():
                self._safe_pump()
                if (wire.reader.state != "OPEN" and not wire.eof
                        or any(reader.state != "OPEN" and not self.output_eof[index]
                               for index, reader in enumerate(self.readers))):
                    break
                _pause(ctx.cutoff())
        if self.child is not None:
            # O has no G route. C's independent owner protocol settled that
            # group; no post-wait PID/PGID query is used to recreate authority.
            self.child.retire_numeric()
            self.wait = _wait_original(ctx, self.child, self._safe_pump)
        for acquisition in ctx.acquisitions:
            if acquisition is not ctx.child_acquisition:
                ctx.close_io(acquisition)
        self.local_cleanup_complete = not ctx.cleanup_unknown and ctx.settled()
        if not self.local_cleanup_complete:
            _RETAINED.append(self)

    def original_finality(self) -> bool:
        ctx = self.ctx
        ctx.owner_check()
        if not self.handlers_complete or not self.local_cleanup_complete or ctx.cleanup_unknown:
            return False
        if self.child is None:
            return (not ctx.child_acquisition.attempted and not ctx.child_acquisition.cleanup_unknown
                    and all(task.joined for task in ctx.tasks) and not self.create_route.attempted
                    and not self.run_route.attempted and self.create_route.retired and self.run_route.retired)
        terminal, wire = self.terminal, self.wire
        return (self.wait is not None and self.wait is self.child.receipt and self.wait.status_kind == "exit"
                and self.wait.status_code in (HELPER_OK, HELPER_FAILED)
                and terminal is not None and terminal["producer"] and self.sealed
                and wire is not None and wire.eof and not wire.poisoned and not self.protocol_failed
                and len(self.readers) == 2 and all(self.output_eof) and not self.output_failed
                and len(self.outputs[0]) == terminal["stdout"] and len(self.outputs[1]) == terminal["stderr"])

    def publish(self) -> OriginalCommandOutcome:
        final = self.original_finality()
        tag = ("NO_W_CREATION" if final and self.child is None else
               self.terminal["no_target"] if final and self.terminal is not None else None)
        # Complete protocol evidence can positively establish that no target
        # existed; it need not invent a target result. This original proof is
        # useful after pre-native validation/callback failure. A created C still
        # needs its admitted terminal/fence and exact zero stream counts, while
        # the no-C/no-grant branch has no fence publication obligation at all.
        no_target_complete = (final and tag is not None and not any(self.outputs)
                              and (self.child is None or self.terminal is not None
                                   and (self.binding is None or self.terminal["fence"] is True)))
        complete = (no_target_complete or final and self.wait is not None
                    and self.wait.status_code == HELPER_OK and self.terminal is not None
                    and self.terminal["result"])
        if complete:
            try:
                self.decoded = self.outputs[0].decode("utf-8"), self.outputs[1].decode("utf-8")
            except UnicodeError as error:
                self.ctx.record(error)
                complete = False
        observed = None if self.terminal is None else self.terminal["wait"]
        code = None
        termination = "unavailable"
        if final and observed is not None:
            termination = "normal-exit" if observed["kind"] == "exit" else "signal-wait"
            code = observed["code"] if observed["kind"] == "exit" else -observed["code"]
        outcome = OriginalCommandOutcome(
            self, self.nonce, RouteHistory(self.create_route.attempted, self.create_route.retired),
            RouteHistory(self.run_route.attempted, self.run_route.retired),
            None if tag is None else NoTargetProof(self, tag, _key=_KEY),
            termination, code, "complete" if complete else "incomplete",
            OriginalCommandFinality(self, _key=_KEY) if final else None,
        )
        self.slot._publish(self, outcome)
        self.guard.lifetime_ledger._finish_command(self.slot,
                dispatched=False if tag is not None else self.run_route.attempted,
                contained=final, cleanup_complete=final)
        if not final and self not in _RETAINED:
            _RETAINED.append(self)
        self.phase = "CLOSED" if final else "UNKNOWN"
        return outcome


def run_command(argv: Sequence[str], *, environ: Mapping[str, str] | None, cwd: Path | None,
                timeout: int, capture: bool, output_limit: int,
                cancellation: DefaultCancellation | None, on_start: Callable[[int], None] | None,
                cleanup: bool, execution_scope: AccountExecutionScope | None,
                journal_binding: JournalledCommandBinding | None) -> subprocess.CompletedProcess[str]:
    _require(os.name == "posix" and sys.platform in ("linux", "darwin")
             and _integer(timeout, 1, 86400) and type(cleanup) is bool
             and (on_start is None or callable(on_start))
             and (execution_scope is None or type(execution_scope) is AccountExecutionScope)
             and (journal_binding is None or type(journal_binding) is JournalledCommandBinding)
             and (journal_binding is None or execution_scope is not None))
    if execution_scope is not None:
        # A legitimate account source carries its actual cancellation owner,
        # including worker/custom-signal paths with zero installed handlers.
        # Ambient handler discovery alone cannot recover that owner. Admit the
        # source on its original thread and reject an explicit disagreement
        # before consuming its one-use scope or binding any command ledger.
        execution_scope._source._check()
        original_guard = execution_scope._source._lease.cancellation
        _require(type(original_guard) is DefaultCancellation
                 and original_guard.pid == os.getpid()
                 and original_guard.owner_thread is threading.current_thread()
                 and (cancellation is None or cancellation is original_guard))
        cancellation = original_guard
    guard, owns = cancellation_owner(cancellation, ProcessCleanupError,
                                     "owned command cancellation handlers could not be restored")
    suppress = cleanup and guard.cancelled and guard.depth > 0
    engine = _Outer(guard, owns, timeout, execution_scope, journal_binding, suppress_cancel=suppress)

    def fork_relinquish() -> None:
        if engine.ctx.pid != os.getpid():
            for acquisition in engine.ctx.acquisitions:
                acquisition._relinquish_inherited()
            engine.ctx.launch_retired = engine.ctx.stopped = engine.ctx.cleanup_unknown = True

    scope = CleanupScope(guard, engine.cleanup, owns_cancellation=owns,
                         fork_cleanup=fork_relinquish, first_primary=True)
    try:
        try:
            with scope:
                if owns:
                    guard.install()
                    guard.activate()
                try:
                    engine.body(argv, environ, cwd, capture, output_limit, on_start)
                except BaseException as error:
                    engine.ctx.record(error)
                    raise
        finally:
            scope.__exit__(*sys.exc_info())
    except BaseException as error:
        engine.ctx.record(error)
    engine.ctx.origin()
    if scope._cleanup_errors:
        for error in scope._cleanup_errors:
            engine.ctx.record(error, unknown=True)
    try:
        if owns:
            engine.handlers_complete = guard.handler_state == "RESTORED"
        else:
            guard._borrowable()
            engine.handlers_complete = True
    except BaseException as error:
        engine.ctx.record(error, unknown=True)
    outcome = engine.publish()
    final = outcome.original_finality is not None
    dispatched = outcome.no_target is None and outcome.run_tool.attempted
    primary = engine.ctx.primary
    if primary is not None:
        if isinstance(primary, ProcessError):
            # Current no-target/finality is not authority to erase earlier
            # callback/cause-chain dispatch or lifetime debt. Merge only in the
            # conservative direction and retain the original typed object.
            preserve_lifetime_error(primary, dispatched=dispatched, contained=final)
            primary.cleanup_complete = primary.cleanup_complete and final
            raise primary
        if isinstance(primary, (KeyboardInterrupt, SystemExit)):
            # Keep the exact original object. The actual guard's monotonic
            # ledger carries fatality; a new ProcessInterrupted would erase it.
            raise primary
        error = (ProcessError("owned command failed, timed out, or produced incomplete output",
                              dispatched=dispatched, contained=final, cleanup_complete=final)
                 if final else ProcessCleanupError("owned command cleanup could not be confirmed",
                                                   dispatched=dispatched, contained=False))
        preserve_lifetime_error(error, previous=primary, dispatched=dispatched, contained=final)
        raise error from None
    if not final:
        raise ProcessCleanupError("owned command cleanup could not be confirmed", dispatched=dispatched, contained=False)
    if outcome.no_target is not None:
        raise ProcessError("owned command executable could not be started" if outcome.no_target.kind == "EXEC_REJECTED"
                           else "owned command was stopped before execution", dispatched=False)
    if outcome.result_integrity != "complete" or outcome.returncode is None or engine.decoded is None:
        raise ProcessError("owned command produced incomplete output", dispatched=dispatched)
    assert engine.frozen is not None
    return subprocess.CompletedProcess(list(engine.frozen.args), outcome.returncode, *engine.decoded)
