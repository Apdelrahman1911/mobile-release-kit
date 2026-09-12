"""Private, exact-child-owned provisioning-profile process boundary.

The caller must preserve exclusive waiting and the original child's waitability
from BEFORE native creation through its genuine terminal receipt.  A cooperating
caller may wait its own different children; a catch-all reaper, SIGCHLD=SIG_IGN or
SA_NOCLDWAIT is not compatible with this boundary.  We inspect, never reset, the
caller's SIGCHLD policy.  Fixed helpers reset only their own policy.

O owns C; C owns K; K owns V.  K moves out of G=its original PID before READY.
C never waits K while any request to G remains possible.  All private messages
are evidence over installed pipes, not new authority to signal a reported PID.
There are no import-time acquisitions, finalizers, implicit reapers or retries of
an ambiguous numeric identity.  UNKNOWN custody deliberately survives unwind.
"""
from __future__ import annotations

import json
import math
import os
import select
import signal
import stat
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import _native_process as native
from .cancellation import DefaultCancellation
from .errors import ValidationError
from .inspection import InspectionDeadline

NANOSECOND = 1_000_000_000
CAPTURE_SECONDS = 30
SUPERVISOR_SECONDS = 25
NATIVE_SECONDS = 20
CLEANUP_SECONDS = 3
CONFIG_LIMIT = 128 * 1024
FRAME_LIMIT = 1024
FRAME_COUNT = 16
PID_LIMIT = (1 << 31) - 1
TIME_LIMIT = (1 << 63) - 1
POLL_SECONDS = 0.01
HELPER_SETTLED = 0
HELPER_UNKNOWN = 1
HELPER_FAILED = 2
ERROR = "Apple profile authentication could not complete safely; no upload is authorized"
TIMEOUT = "Apple profile authentication timed out; no decode-only fallback is permitted"
CLEANUP_ERROR = "Apple profile worker cleanup could not be confirmed; end this process before retrying"
PROTOCOL_ERROR = "Apple profile private process protocol is invalid; no upload is authorized"
HELPER_BOOTSTRAP = (
    "import sys; sys.path.insert(0, sys.argv.pop(1)); "
    "from mobile_release._profile_process import helper_main; raise SystemExit(helper_main())"
)
WORKER_BOOTSTRAP = (
    "import sys; sys.path.insert(0, sys.argv.pop(1)); "
    "from mobile_release.ios_profile_auth import main; raise SystemExit(main())"
)
ROLES = frozenset(("custodian", "keeper"))
REASONS = frozenset(("cancelled", "deadline", "parent_lost", "protocol", "io", "creation", "lifecycle"))
EDGES = {
    "o_to_c": frozenset(("CONFIG", "ADMIT", "RUN", "COMMIT", "CANCEL")),
    "c_to_o": frozenset(("HELLO", "RESERVED", "READY", "STATUS", "QUIESCING", "FINAL")),
    "c_to_k": frozenset(("CONFIG", "RUN", "CANCEL", "GROUP_RETIRED", "RELEASE")),
    "k_to_c": frozenset(("HELLO", "MOVED", "STATUS", "RELEASED")),
}
FIELDS = {
    "CONFIG": {"role", "cwd", "validator_argv", "validator_env", "run_deadline_ns",
               "hard_cleanup_deadline_ns", "max_output_bytes", "capture_kind"},
    "HELLO": {"pid", "ppid", "sid", "pgid", "fd_map_version"},
    "ADMIT": set(), "RUN": set(), "COMMIT": set(), "RELEASE": set(), "QUIESCING": set(),
    "RESERVED": {"keeper_pid", "group_id", "session_id"},
    "MOVED": {"validator_pid", "group_id", "keeper_pgid"},
    "READY": {"validator_pid", "group_id", "keeper_pgid"},
    "STATUS": {"validator_pid", "status_kind", "status_code"},
    "CANCEL": {"reason_code", "cleanup_deadline_ns"},
    "GROUP_RETIRED": {"group_id", "absent"},
    "RELEASED": {"validator"},
    "FINAL": {"outcome", "cleanup", "keeper", "validator", "group"},
}


def _require(condition: bool, message: str = PROTOCOL_ERROR) -> None:
    if not condition:
        raise ValidationError(message)


def _failure_reason(error: BaseException, default: str = "lifecycle") -> str:
    # Do not call a foreign exception's __str__ while collecting its first error.
    return ("deadline" if type(error) is ValidationError and len(error.args) == 1
            and type(error.args[0]) is str and error.args[0] == TIMEOUT else default)


def _integer(value: Any, maximum: int, minimum: int = 1) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _string(value: Any, *, maximum: int = 8192, empty: bool = False) -> bool:
    if type(value) is not str or "\0" in value or (not value and not empty):
        return False
    try:
        return len(value.encode("utf-8", "strict")) <= maximum
    except UnicodeError:
        return False


def _status(kind: Any, code: Any) -> bool:
    return (type(kind) is str and ((kind == "exit" and _integer(code, 255, 0))
                                  or (kind == "signal" and _integer(code, signal.NSIG - 1))))


def _child_record(record: Any) -> None:
    _require(type(record) is dict and type(record.get("state")) is str)
    if record["state"] in ("not_attempted", "unknown"):
        _require(set(record) == {"state"})
    else:
        _require(record["state"] == "reaped" and set(record) == {"state", "pid", "status_kind", "status_code"})
        _require(_integer(record["pid"], PID_LIMIT) and _status(record["status_kind"], record["status_code"]))


def _group_record(record: Any) -> None:
    _require(type(record) is dict and type(record.get("state")) is str)
    if record["state"] in ("not_created", "unknown"):
        _require(set(record) == {"state"})
    else:
        _require(record["state"] == "retired" and set(record) == {"state", "id", "absent"})
        _require(_integer(record["id"], PID_LIMIT) and type(record["absent"]) is bool)


def _normal(record: dict[str, Any], *, success: bool = True) -> bool:
    return (record["state"] == "reaped" and record["status_kind"] == "exit"
            and (record["status_code"] == 0 if success else record["status_code"] != 0))


def _terminal_fields(frame: dict[str, Any]) -> None:
    keeper, validator, group = (frame[name] for name in ("keeper", "validator", "group"))
    _child_record(keeper); _child_record(validator); _group_record(group)
    _require(type(frame["outcome"]) is str and frame["outcome"] in ("ok", "rejected", "failed")
             and type(frame["cleanup"]) is str and frame["cleanup"] in ("confirmed", "unknown"))
    if keeper["state"] == "not_attempted":
        _require(validator == {"state": "not_attempted"} and group == {"state": "not_created"}
                 and frame["outcome"] == "failed")
    if group["state"] == "not_created":
        _require(validator == {"state": "not_attempted"} and frame["outcome"] == "failed")
    unknown = ("unknown" in (keeper["state"], validator["state"], group["state"])
               or (group["state"] == "retired" and not group["absent"]))
    if unknown or frame["cleanup"] == "unknown":
        _require(frame["outcome"] == "failed" and frame["cleanup"] == "unknown")
    if frame["cleanup"] == "confirmed" and keeper["state"] == "reaped":
        _require(keeper["status_kind"] == "exit"
                 and keeper["status_code"] in (HELPER_SETTLED, HELPER_FAILED))
    if group["state"] == "retired" and keeper["state"] == "reaped":
        _require(group["id"] == keeper["pid"])
    if keeper["state"] == validator["state"] == "reaped":
        _require(keeper["pid"] != validator["pid"])
    if frame["outcome"] in ("ok", "rejected"):
        _require(_normal(keeper) and group["state"] == "retired" and group["absent"]
                 and frame["cleanup"] == "confirmed")
        _require(_normal(validator, success=frame["outcome"] == "ok"))


def _validate_frame(frame: Any) -> None:
    _require(type(frame) is dict and type(frame.get("type")) is str and frame["type"] in FIELDS)
    kind = frame["type"]
    _require(type(frame.get("v")) is int and frame["v"] == 1 and set(frame) == FIELDS[kind] | {"v", "type"})
    if kind == "CONFIG":
        _require(type(frame["role"]) is str and frame["role"] in ROLES
                 and type(frame["capture_kind"]) is str and frame["capture_kind"] in ("profile", "native"))
        _require(_string(frame["cwd"]) and os.path.isabs(frame["cwd"]))
        argv, env = frame["validator_argv"], frame["validator_env"]
        _require(type(argv) is list and 0 < len(argv) <= 64 and all(_string(item) for item in argv))
        _require(os.path.isabs(argv[0]) and sum(len(item.encode()) for item in argv) <= 64 * 1024)
        _require(type(env) is dict and len(env) <= 64)
        _require(all(_string(key) and "=" not in key and _string(value, empty=True) for key, value in env.items()))
        _require(sum(len(key.encode()) + len(value.encode()) + 1 for key, value in env.items()) <= 64 * 1024)
        _require(_integer(frame["run_deadline_ns"], TIME_LIMIT)
                 and _integer(frame["hard_cleanup_deadline_ns"], TIME_LIMIT)
                 and frame["run_deadline_ns"] <= frame["hard_cleanup_deadline_ns"])
        _require(_integer(frame["max_output_bytes"], 5 * 1024 * 1024))
    elif kind == "HELLO":
        _require(all(_integer(frame[name], PID_LIMIT) for name in ("pid", "ppid", "sid", "pgid")))
        _require(type(frame["fd_map_version"]) is int and frame["fd_map_version"] == 1)
    elif kind in ("RESERVED", "MOVED", "READY"):
        _require(all(_integer(frame[name], PID_LIMIT) for name in FIELDS[kind]))
    elif kind == "STATUS":
        _require(_integer(frame["validator_pid"], PID_LIMIT) and _status(frame["status_kind"], frame["status_code"]))
    elif kind == "CANCEL":
        _require(type(frame["reason_code"]) is str and frame["reason_code"] in REASONS
                 and _integer(frame["cleanup_deadline_ns"], TIME_LIMIT))
    elif kind == "GROUP_RETIRED":
        _require(_integer(frame["group_id"], PID_LIMIT) and type(frame["absent"]) is bool)
    elif kind == "RELEASED":
        _child_record(frame["validator"])
    elif kind == "FINAL":
        _terminal_fields(frame)


class _Direction:
    def __init__(self, edge: str) -> None:
        _require(type(edge) is str and edge in EDGES)
        self.edge = edge
        self.seen: set[str] = set()
        self.terminal = False

    def accept(self, frame: dict[str, Any]) -> None:
        _validate_frame(frame)
        kind = frame["type"]
        _require(not self.terminal and kind in EDGES[self.edge] and kind not in self.seen and len(self.seen) < FRAME_COUNT)
        if self.edge == "c_to_o":
            _require("QUIESCING" not in self.seen or kind == "FINAL")
        if kind == "CONFIG":
            _require(not self.seen and frame["role"] == ("custodian" if self.edge == "o_to_c" else "keeper"))
        elif kind in ("ADMIT", "RUN", "COMMIT"):
            needed = {"ADMIT": "CONFIG", "RUN": "ADMIT" if self.edge == "o_to_c" else "CONFIG", "COMMIT": "RUN"}[kind]
            _require(needed in self.seen and "CANCEL" not in self.seen)
            _require(not self.seen & {"GROUP_RETIRED", "RELEASE"})
        elif kind in ("RESERVED", "READY", "MOVED", "STATUS"):
            needed = {"RESERVED": "HELLO", "READY": "RESERVED", "MOVED": "HELLO",
                      "STATUS": "READY" if self.edge == "c_to_o" else "MOVED"}[kind]
            _require(needed in self.seen)
        elif kind == "HELLO":
            _require(not self.seen)
        elif kind == "RELEASE":
            _require("GROUP_RETIRED" in self.seen)
        elif kind == "FINAL":
            _require("QUIESCING" in self.seen)
            if frame["outcome"] in ("ok", "rejected"):
                _require("STATUS" in self.seen)
        if kind in ("FINAL", "RELEASED"):
            self.terminal = True
        self.seen.add(kind)


class Protocol:
    @staticmethod
    def encode(frame: dict[str, Any]) -> bytes:
        _validate_frame(frame)
        try:
            payload = json.dumps(frame, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")
        except (TypeError, ValueError, UnicodeError):
            raise ValidationError(PROTOCOL_ERROR) from None
        _require(0 < len(payload) <= (CONFIG_LIMIT if frame["type"] == "CONFIG" else FRAME_LIMIT))
        return len(payload).to_bytes(4, "big") + payload


class Decoder:
    """Bounded incremental framing; EOF and genuine process status stay separate."""
    def __init__(self, edge: str) -> None:
        self.direction = _Direction(edge)
        self.pending = bytearray()
        self.length: int | None = None
        self.ended = False
        self.failed = False

    def feed(self, content: bytes) -> list[dict[str, Any]]:
        _require(not self.failed)
        try:
            return self._feed(content)
        except BaseException:
            # A rejected header/phase cannot leave a reusable oversized length
            # or partially accepted parser state for the next draining turn.
            self.failed = True
            self.pending.clear()
            self.length = None
            raise

    def _feed(self, content: bytes) -> list[dict[str, Any]]:
        _require(type(content) is bytes and not self.ended)
        frames: list[dict[str, Any]] = []
        view = memoryview(content)
        while view:
            needed = (4 if self.length is None else self.length) - len(self.pending)
            count = min(needed, len(view))
            self.pending.extend(view[:count]); view = view[count:]
            if self.length is None and len(self.pending) == 4:
                self.length = int.from_bytes(self.pending, "big")
                self.pending.clear()
                first_config = self.direction.edge in ("o_to_c", "c_to_k") and not self.direction.seen
                _require(0 < self.length <= (CONFIG_LIMIT if first_config else FRAME_LIMIT))
            elif self.length is not None and len(self.pending) == self.length:
                def pairs(items):
                    result = {}
                    for key, value in items:
                        _require(key not in result)
                        result[key] = value
                    return result
                try:
                    frame = json.loads(self.pending.decode("utf-8", "strict"), object_pairs_hook=pairs,
                                       parse_constant=lambda _: (_ for _ in ()).throw(ValidationError(PROTOCOL_ERROR)))
                except (ValueError, UnicodeError, RecursionError):
                    raise ValidationError(PROTOCOL_ERROR) from None
                _validate_frame(frame)
                _require(self.length <= (CONFIG_LIMIT if frame["type"] == "CONFIG" else FRAME_LIMIT))
                self.direction.accept(frame)
                frames.append(frame)
                self.pending.clear(); self.length = None
        return frames

    def eof(self) -> None:
        _require(not self.failed)
        try:
            _require(not self.ended and not self.pending and self.length is None)
            self.ended = True
        except BaseException:
            self.failed = True
            self.pending.clear()
            self.length = None
            raise


_CUSTODY: list[CaptureFinality] = []
_CUSTODY_LOCK = threading.Lock()


class CaptureFinality:
    """Read-only producer verdict for the exact outer ScratchLease.

    bind_scratch binds custody, not an assertion about acquisition or cleanup.
    Only the real capture owner calls the private state transitions below.
    """
    def __init__(self) -> None:
        self._state = "NO_PRODUCERS"
        self._scratch: object | None = None
        self._owner: _Context | None = None
        self._begun = False

    @property
    def state(self) -> str:
        # An exceptional tail cannot leave a discarded ACTIVE owner reusable.
        # This read never manufactures finality; only _finish can do that.
        if self._state == "ACTIVE" and self._owner is not None and self._owner.exited:
            return "UNKNOWN"
        return self._state

    @property
    def cleanup_allowed(self) -> bool:
        return self.state in ("NO_PRODUCERS", "FINALIZED")

    def bind_scratch(self, lease: object) -> None:
        _require(not self._begun and self._scratch is None and lease is not None, CLEANUP_ERROR)
        self._scratch = lease

    def _begin(self, owner: _Context) -> None:
        with _CUSTODY_LOCK:
            _require(not self._begun and self._state == "NO_PRODUCERS"
                     and not any(item.state == "UNKNOWN" for item in _CUSTODY), CLEANUP_ERROR)
            self._owner = owner
            self._begun = True
            self._state = "ACTIVE"
            _CUSTODY.append(self)

    def _unknown(self) -> None:
        self._state = "UNKNOWN"
        with _CUSTODY_LOCK:
            if self not in _CUSTODY:
                _CUSTODY.append(self)

    def _finish(self, *, no_producers: bool = False) -> None:
        _require(self._begun and self._state == "ACTIVE", CLEANUP_ERROR)
        self._state = "NO_PRODUCERS" if no_producers else "FINALIZED"
        with _CUSTODY_LOCK:
            if self in _CUSTODY:
                _CUSTODY.remove(self)


def _role_event(role: str, event: str, **evidence: Any) -> None:
    """Private no-op observation seam; it never supplies lifecycle authority.

    Credential-free fixtures may observe/mutate the actual called operation.
    There is no callback argument, environment switch, CLI hook or event pipe.
    """


@dataclass(frozen=True)
class _Deadlines:
    capture: int
    run: int
    native: int
    hard: int
    outer_hard: int

    @classmethod
    def from_inspection(cls, deadline: InspectionDeadline) -> _Deadlines:
        endpoint = deadline.expires_at
        _require(type(endpoint) in (int, float) and math.isfinite(endpoint) and endpoint > 0, TIMEOUT)
        now = time.monotonic_ns()
        # Floor the EXACT represented endpoint. Multiplying a large float first
        # can round upward by nanoseconds before floor sees it, extending shared
        # admission. Integer-ratio conversion never adds that extra rounding.
        numerator, denominator = endpoint.as_integer_ratio() if type(endpoint) is float else (endpoint, 1)
        shared = numerator * NANOSECOND // denominator
        capture = min(shared, now + CAPTURE_SECONDS * NANOSECOND)
        run = min(capture, now + SUPERVISOR_SECONDS * NANOSECOND)
        native_cutoff = min(run, now + NATIVE_SECONDS * NANOSECOND)
        hard = min(shared, run + CLEANUP_SECONDS * NANOSECOND)
        _require(now < native_cutoff and _integer(hard, TIME_LIMIT), TIMEOUT)
        return cls(capture, run, native_cutoff, hard, min(shared, capture + CLEANUP_SECONDS * NANOSECOND))


def _module_root() -> str:
    return str(Path(__file__).resolve().parent.parent)


def _interpreter() -> str:
    _require(_string(sys.executable) and os.path.isabs(sys.executable), ERROR)
    return sys.executable


def helper_argv(role: str, *, parent_context: dict[str, int], deadlines: dict[str, int]) -> tuple[str, ...]:
    _require(type(role) is str and role in ROLES and type(parent_context) is dict
             and set(parent_context) == {"parent_pid", "session_id"} and type(deadlines) is dict
             and set(deadlines) == {"run_deadline_ns", "hard_cleanup_deadline_ns"})
    _require(all(_integer(value, PID_LIMIT) for value in parent_context.values())
             and all(_integer(value, TIME_LIMIT) for value in deadlines.values())
             and deadlines["run_deadline_ns"] <= deadlines["hard_cleanup_deadline_ns"])
    return (_interpreter(), "-I", "-S", "-B", "-c", HELPER_BOOTSTRAP, _module_root(), role,
            str(parent_context["parent_pid"]), str(parent_context["session_id"]),
            str(deadlines["run_deadline_ns"]), str(deadlines["hard_cleanup_deadline_ns"]))


def _worker_argv(directory: Path, deadline_ns: int) -> tuple[str, ...]:
    _require(_integer(deadline_ns, TIME_LIMIT) and directory.is_absolute())
    return (_interpreter(), "-I", "-S", "-B", "-c", WORKER_BOOTSTRAP, _module_root(),
            "--worker", str(directory), str(deadline_ns))


def _configuration(directory: Path, deadlines: _Deadlines, role: str) -> dict[str, Any]:
    from .ios_profiles import MAX_COMPLETION_BYTES, profile_environment
    frame = {"v": 1, "type": "CONFIG", "role": role, "cwd": str(directory),
             "validator_argv": list(_worker_argv(directory, deadlines.native)),
             "validator_env": profile_environment(directory), "run_deadline_ns": deadlines.run,
             "hard_cleanup_deadline_ns": deadlines.hard, "max_output_bytes": MAX_COMPLETION_BYTES,
             "capture_kind": "profile"}
    _validate_frame(frame)
    return frame


class _Context:
    def __init__(self, role: str, run: int, hard: int, *, cancellation: DefaultCancellation | None = None,
                 parent_pid: int | None = None) -> None:
        self.role, self.run, self.hard = role, run, hard
        self.cancellation, self.parent_pid = cancellation, parent_pid
        self.owner = threading.current_thread()
        # Bind before ANY native operation, including IO setup and transient
        # teardown. The first caught leaf error enters this very same lock now,
        # not a delayed creator-return handoff which a later signal could beat.
        self.io = native.Acquisition(failure_recorder=lambda error: self.record(error, "io"))
        self.child_acquisition = native.Acquisition(failure_recorder=lambda error: self.record(error, "creation"))
        self.launch_closed = False
        self.tasks: list[TaskSlot] = []
        self.closed: set[int] = set()
        self.lifetime: list[Any] = []
        self.primary: BaseException | None = None
        self.interruption: BaseException | None = None
        self.secondary: list[BaseException] = []
        self.cleanup_errors: list[str] = []
        self.cleanup_unknown = False
        self.reason = "lifecycle"
        self.cleanup_limit: int | None = None
        self.failure_limit: int | None = None
        self.cancelled = False
        self.exited = False
        self.lock = threading.Lock()
        self.observed_interruptions: set[int] = set()
        self.emergency_primary: BaseException | None = None
        self.emergency_secondary: BaseException | None = None
        self.error_epoch = 0
        self.signal_epoch = 0
        self._helper_offer: tuple[int, tuple[int, int], int, _Channel, str] | None = None
        self._helper_terminal_armed = False

    def record(self, error: BaseException, reason: str = "lifecycle", *, cleanup: bool = False) -> None:
        # The actual recording boundary, not exception-class priority or an
        # inferred timestamp, decides which already-observed error was first.
        with self.lock:
            if isinstance(error, (KeyboardInterrupt, SystemExit)) and self.interruption is None:
                self.interruption = error
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                self.observed_interruptions.add(id(error))
            if self.primary is None:
                self.primary, self.reason = error, reason
            elif (error is not self.primary and not any(item is error for item in self.secondary)
                  and len(self.secondary) < FRAME_COUNT):
                self.secondary.append(error)
            self.error_epoch += 1
            if cleanup:
                self.cleanup_unknown = True
                if len(self.cleanup_errors) < FRAME_COUNT:
                    self.cleanup_errors.append(reason)
            self.cancelled = True
            if self.failure_limit is None:
                self.failure_limit = min(self.hard, time.monotonic_ns() + CLEANUP_SECONDS * NANOSECOND)
            self.cleanup_limit = min(self.cleanup_limit or self.failure_limit, self.failure_limit)
        try:
            self.retire_launch()
        except BaseException as retirement_error:
            self.contain_target_error(error, retirement_error)

    def contain_target_error(self, error: BaseException, recording_error: BaseException | None = None) -> None:
        """Last, nonthrowing task boundary; never call an automatic reporter.

        The ordinary shared recorder is attempted first by the caller. If that
        machinery itself failed, use the SAME lock, never a private timestamp or
        class-priority override. Any collector/retirement uncertainty is rooted
        UNKNOWN. Pure fallback slots preserve evidence even if diagnostics fail.
        """
        self.cleanup_unknown = self.cancelled = self.launch_closed = True
        try:
            with self.lock:
                if self.primary is None:
                    self.primary, self.reason = error, "creation"
                self.error_epoch += 1
                for candidate in (error, recording_error):
                    if candidate is None:
                        continue
                    if isinstance(candidate, (KeyboardInterrupt, SystemExit)) and self.interruption is None:
                        self.interruption = candidate
                    if (candidate is not self.primary and not any(item is candidate for item in self.secondary)
                            and len(self.secondary) < FRAME_COUNT):
                        self.secondary.append(candidate)
                if self.failure_limit is None:
                    self.failure_limit = min(self.hard, time.monotonic_ns() + CLEANUP_SECONDS * NANOSECOND)
                self.cleanup_limit = min(self.cleanup_limit or self.failure_limit, self.failure_limit)
        except BaseException as final_error:
            if self.emergency_secondary is None:
                self.emergency_secondary = final_error
        finally:
            if self.emergency_primary is None:
                self.emergency_primary = error
            if recording_error is not None and self.emergency_secondary is None:
                self.emergency_secondary = recording_error
        try:
            self.child_acquisition.close_launch()
        except BaseException as final_error:
            if self.emergency_secondary is None:
                self.emergency_secondary = final_error

    def collect_native(self) -> None:
        # The synchronous leaf recorder already owns first-error ordering. This
        # reconciliation also retains a later swallowed *actual* interruption;
        # it never backdates, synthesizes or gives its class blanket priority.
        for acquisition in (self.io, self.child_acquisition):
            interruption = acquisition.interruption
            if interruption is not None and id(interruption) not in self.observed_interruptions:
                self.record(interruption, "creation")
            if acquisition.cleanup_unknown:
                if not self.cleanup_unknown:
                    self.record(ValidationError(CLEANUP_ERROR), "creation", cleanup=True)
                self.cleanup_unknown = True

    def retire_launch(self) -> None:
        self.launch_closed = True
        self.child_acquisition.close_launch()
        for task in tuple(self.tasks):
            task.close_launch()

    def begin_cleanup(self) -> int:
        if self.cleanup_limit is None:
            self.cleanup_limit = min(self.hard, time.monotonic_ns() + CLEANUP_SECONDS * NANOSECOND)
        return self.cleanup_limit

    def cleanup_cutoff(self, original: int) -> int:
        return min(original, self.cleanup_limit or original, self.failure_limit or original)

    def control_cutoff(self, original: int) -> int:
        # A success-ready C may have completed descendant cleanup long before a
        # later withheld-COMMIT failure. Its failure report gets the ONE actual
        # first-failure grace, not a reopened numeric descendant-cleanup loop.
        return min(original, self.failure_limit or original, self.hard)

    def offer_terminal(self, intended: int, epoch: tuple[int, int], cutoff: int,
                       channel: _Channel, kind: str) -> tuple[int, tuple[int, int], int, _Channel, str]:
        # Preserve the original pre-offer proof exactly once. Neither the tail
        # nor the interpreter handoff may replace it with a fresher epoch/time.
        _require(self._helper_offer is None and not self._helper_terminal_armed, CLEANUP_ERROR)
        offer = intended, epoch, cutoff, channel, kind
        self._helper_offer = offer
        return offer

    def helper_handoff(self, saved: int) -> int:
        try:
            offer = self._helper_offer
            if (type(saved) is not int or saved not in (HELPER_SETTLED, HELPER_FAILED)
                    or offer is None or saved != offer[0] or self._helper_terminal_armed):
                return HELPER_UNKNOWN
            # Called only AFTER owner.run returns a positively settled code. From
            # this monotonic arm through interpreter exit, an executed helper-local
            # handler cannot let a saved 0/2 survive. Pre-arm callbacks instead change
            # the SAME original proof rechecked below. No disposition/mask swap.
            self._helper_terminal_armed = True
            checked = self.terminal_code(*offer)
            return saved if type(checked) is int and checked == saved else HELPER_UNKNOWN
        except BaseException:
            # Resources already settled before this handoff. Any proof-read,
            # arm or final-check failure is UNKNOWN without a second cleanup pass.
            return HELPER_UNKNOWN

    def helper_signal(self, _signum: int, _frame: Any) -> None:
        if self._helper_terminal_armed:
            # Only our own helper exits, only with the fixed unconfirmed code.
            # No locks, diagnostics, exception injection or cleanup in this arm.
            os._exit(HELPER_UNKNOWN)
            return
        self.signal_epoch += 1
        self.cancelled = True

    def observe_helper_latches(self) -> None:
        if self.primary is None:
            try:
                self.check()
            except BaseException as error:
                self.record(error, _failure_reason(error))

    def terminal_code(self, intended: int, epoch: tuple[int, int], cutoff: int, channel: _Channel, kind: str) -> int:
        # 1 is also the interpreter's ordinary unexpected-exception exit: it
        # can NEVER masquerade as a positively settled lifecycle failure (2).
        if (intended not in (HELPER_SETTLED, HELPER_FAILED)
                or not self.resources_confirmed() or kind not in channel.sent or channel.write_failed or channel.write_in_flight
                or not channel.writer_closed or time.monotonic_ns() >= self.control_cutoff(cutoff)
                or self.parent_pid is not None and os.getppid() != self.parent_pid):
            return HELPER_UNKNOWN
        # Check the epochs LAST too: a signal/error observed inside any of the
        # real tail resource/clock/parent gates above still invalidates the offer.
        return intended if epoch == (self.error_epoch, self.signal_epoch) else HELPER_UNKNOWN

    def cancel_frame(self, frame: dict[str, Any]) -> BaseException:
        _require(frame["cleanup_deadline_ns"] <= self.hard)
        error = ValidationError(TIMEOUT if frame["reason_code"] == "deadline" else ERROR)
        self.record(error, frame["reason_code"])
        self.cleanup_limit = min(self.begin_cleanup(), frame["cleanup_deadline_ns"])
        self.failure_limit = min(self.failure_limit or self.hard, frame["cleanup_deadline_ns"])
        return error

    def check(self) -> None:
        if self.primary is not None:
            raise self.primary
        if self.cancellation is not None:
            self.cancellation.check()
        if self.parent_pid is not None and os.getppid() != self.parent_pid:
            raise ValidationError(ERROR)
        if self.cancelled:
            raise ValidationError(ERROR)
        if time.monotonic_ns() >= self.run:
            raise ValidationError(TIMEOUT)

    def start_io(self) -> None:
        self.io.grant(self.owner, self.check)

    def close(self, lease: Any) -> None:
        if id(lease) in self.closed:
            return
        # Publication of retirement precedes even a potentially consuming close.
        self.closed.add(id(lease))
        try:
            lease.close()
            _role_event(self.role, "descriptor_closed", lease=lease)
        except BaseException as error:
            self.record(error, "io", cleanup=True)

    def close_all(self, *, exclude: tuple[Any, ...] = ()) -> None:
        protected = {id(lease) for lease in (*self.lifetime, *exclude)}
        for task in self.tasks:
            if not task.joined:
                protected.update(id(lease) for lease in task.spec.fd_sources)
        for lease in reversed(self.io.leases):
            if id(lease) not in protected:
                self.close(lease)
        self.io.close_launch()

    def resources_confirmed(self, *, exclude: tuple[Any, ...] = ()) -> bool:
        protected = {id(lease) for lease in (*self.lifetime, *exclude)}
        return (not self.cleanup_unknown and self.io.settled and not self.io.cleanup_unknown
                and self.child_acquisition.settled and not self.child_acquisition.cleanup_unknown
                and all(id(lease) in protected or id(lease) in self.closed for lease in self.io.leases)
                and all(task.joined and task.acquisition.settled and not task.acquisition.cleanup_unknown
                        for task in self.tasks))


class TaskSlot:
    """Prepublished, initially closed creator; a late return is never a grant."""
    def __init__(self, context: _Context, spec: Any, child_role: str) -> None:
        self.context, self.spec, self.child_role = context, spec, child_role
        self.acquisition = context.child_acquisition
        self.actual: threading.Thread | None = None
        self.returned: threading.Thread | None = None
        self.constructed: threading.Thread | None = None
        self.started = False
        self.joined = False
        self.body_done = False
        self.launch = False
        self.launch_retired = False
        self.error: BaseException | None = None
        self.result: Any = None
        self.published = threading.Event()
        self.granted = threading.Event()

    def close_launch(self) -> None:
        self.launch_retired = True
        self.launch = False
        self.acquisition.close_launch()
        self.granted.set()

    def _check(self) -> None:
        _require(self.launch and not self.launch_retired and self.context.owner.is_alive(), ERROR)
        self.context.check()

    def _contained_error(self, error: BaseException) -> None:
        try:
            self.context.record(error, "creation")
        except BaseException as recording_error:
            self.context.contain_target_error(error, recording_error)
        finally:
            if self.error is None:
                self.error = error
            self.launch_retired, self.launch = True, False
        try:
            self.close_launch()
        except BaseException as retirement_error:
            self.context.contain_target_error(error, retirement_error)

    def _body(self) -> None:
        # This is the complete Thread target, including setup, publication,
        # diagnostics and tail. No exception from those paths can reach Python's
        # automatic threading.excepthook or expose its private exception chain.
        try:
            self._owned_body()
        except BaseException as error:
            try:
                self._contained_error(error)
            except BaseException as last_error:
                # Last-resort pure slots are already owned by the published
                # context/task. They cannot authorize success or a new launch.
                self.error = self.error if self.error is not None else error
                self.launch_retired, self.launch = True, False
                self.context.cleanup_unknown = self.context.cancelled = self.context.launch_closed = True
                if self.context.emergency_primary is None:
                    self.context.emergency_primary = self.error
                if self.context.emergency_secondary is None:
                    self.context.emergency_secondary = last_error
        finally:
            self.body_done = True

    def _owned_body(self) -> None:
        try:
            self.actual = threading.current_thread()
            self.published.set()
            _role_event(self.context.role, "task_published", task=self)
            while not self.granted.wait(POLL_SECONDS):
                if (self.launch_retired or self.context.launch_closed or self.context.cancelled
                        or not self.context.owner.is_alive()
                        or time.monotonic_ns() >= self.context.run):
                    self.close_launch()
                    return
            if not self.launch or self.launch_retired:
                return
            self._check()
            self.result = native.create(self.acquisition, self.spec)
        except BaseException as error:
            self._contained_error(error)
        finally:
            try:
                self.context.collect_native()
            except BaseException as error:
                self._contained_error(error)
                self.context.cleanup_unknown = True

    def start(self) -> None:
        # This slot already belongs to the context before Thread.start can create
        # a task.  No native/FD acquisition can precede actual-ref reconciliation.
        try:
            self.constructed = threading.Thread(target=self._body, name="mrk-profile-creator", daemon=False)
            self.constructed.start()
            self.started = True
            self.returned = self.constructed
        except BaseException as error:
            self.context.record(error, "creation")
            self.close_launch()
            raise

    def reconcile_and_grant(self) -> bool:
        if self.actual is None:
            return False
        _require(self.returned is self.actual and self.actual is self.constructed, ERROR)
        self.context.check()
        _require(not self.launch_retired, ERROR)
        self.launch = True
        self.acquisition.grant(self.actual, self._check)
        _role_event(self.context.role, "task_granted", task=self)
        self.granted.set()
        return True

    def join_once(self, deadline_ns: int) -> bool:
        if self.joined:
            return True
        # A lost Thread.start return can still reconcile the actual self-published
        # reference.  An empty slot or an unstarted Thread is not a joined task.
        thread = self.actual if self.actual is not None else self.returned
        if thread is None or thread is threading.current_thread():
            return False
        remaining = (self.context.cleanup_cutoff(deadline_ns) - time.monotonic_ns()) / NANOSECOND
        if remaining <= 0:
            return False
        try:
            thread.join(min(POLL_SECONDS, remaining))
            if not thread.is_alive():
                # Admission needs self-publication AND normal-return identity.
                # Physical settlement may instead join the genuine normally
                # returned original thread whose target failed before publishing.
                _require(self.body_done and (self.actual is thread or
                         (self.actual is None and self.returned is thread and self.constructed is thread)), CLEANUP_ERROR)
                self.joined = True
                self.close_launch()
                _role_event(self.context.role, "task_joined", task=self)
                return True
        except BaseException as error:
            self.context.record(error, "lifecycle", cleanup=True)
        return False


def _spawn(context: _Context, argv: tuple[str, ...], environment: dict[str, str], sources: tuple[Any, ...],
           child_role: str, pump: Callable[[], None]) -> Any:
    context.check()
    _require(not context.launch_closed and not context.tasks, ERROR)
    spec = native.SpawnSpec(executable=argv[0], argv=argv, env=tuple(environment.items()), fd_sources=sources)
    task = TaskSlot(context, spec, child_role)
    context.tasks.append(task)
    task.start()
    granted = False
    while True:
        pump()
        context.check()
        if not granted:
            granted = task.reconcile_and_grant()
        if granted and task.join_once(context.run):
            if task.error is not None:
                raise task.error
            child = task.acquisition.child
            _require(child is not None and task.acquisition.settled and not task.acquisition.cleanup_unknown, CLEANUP_ERROR)
            _role_event(context.role, "child_published", child=child, acquisition=task.acquisition, child_role=child_role)
            return child
        _pause(context.run)


def _pause(deadline_ns: int, channels: tuple[_Channel, ...] = (), extra_read: tuple[Any, ...] = ()) -> None:
    timeout = min(POLL_SECONDS, max(0, (deadline_ns - time.monotonic_ns()) / NANOSECOND))
    if timeout <= 0:
        return
    readers = [channel.reader.fileno() for channel in channels if not channel.eof and not channel.reader_closed]
    readers.extend(lease.fileno() for lease in extra_read)
    writers = [channel.writer.fileno() for channel in channels if channel.pending and not channel.writer_closed]
    if readers or writers:
        select.select(readers, writers, (), timeout)
    else:
        time.sleep(timeout)


class _Channel:
    def __init__(self, context: _Context, reader: Any, writer: Any, incoming: str, outgoing: str) -> None:
        self.context, self.reader, self.writer = context, reader, writer
        self.incoming, self.outgoing = incoming, outgoing
        self.decoder = Decoder(incoming)
        self.encoder = _Direction(outgoing)
        self.pending: list[tuple[dict[str, Any], memoryview]] = []
        self.write_limits: dict[str, int] = {}
        self.write_attempted: set[str] = set()
        self.sent: set[str] = set()
        self.write_failed = False
        self.write_in_flight = False
        self.frames: list[dict[str, Any]] = []
        self.eof = False
        self.reader_closed = False
        self.writer_closed = False
        for lease in (reader, writer):
            os.set_blocking(lease.fileno(), False)

    def send(self, kind: str, **fields: Any) -> None:
        _require(not self.writer_closed)
        frame = {"v": 1, "type": kind, **fields}
        packet = Protocol.encode(frame)
        self.encoder.accept(frame)
        if kind in ("CANCEL", "GROUP_RETIRED", "RELEASE"):
            self.write_limits[kind] = self.context.cleanup_cutoff(self.context.hard)
        else:
            self.write_limits[kind] = self.context.failure_limit or self.context.run
        self.pending.append((frame, memoryview(packet)))

    def send_frame(self, frame: dict[str, Any]) -> None:
        self.send(frame["type"], **{key: value for key, value in frame.items() if key not in ("v", "type")})

    def _unknown_write(self, error: BaseException) -> None:
        try:
            self.context.record(error, "io", cleanup=True)
        except BaseException as recording_error:
            self.context.contain_target_error(error, recording_error)
        finally:
            self.write_failed = True
            self.pending.clear()
            self.close_writer()

    def flush(self, *, deadline_ns: int | None = None) -> None:
        if self.writer_closed:
            return
        if self.write_in_flight or self.write_failed:
            # A previous call/publication/collector escaped without positive
            # completion. Neither an old offset nor an empty queue is proof that
            # its bytes were not consumed; permanently retire this writer.
            error = ValidationError(CLEANUP_ERROR)
            self._unknown_write(error)
            raise error
        # One bounded write per owner turn prevents a writable peer from starving
        # deadline, cancellation or independent status work.
        if self.pending:
            frame, content = self.pending[0]
            kind = frame["type"]
            limit = self.context.control_cutoff(self.write_limits[kind])
            if kind in ("CANCEL", "GROUP_RETIRED", "RELEASE"):
                limit = self.context.cleanup_cutoff(limit)
            if deadline_ns is not None:
                limit = min(limit, deadline_ns)
            try:
                _require(time.monotonic_ns() < limit, TIMEOUT)
                if kind in ("ADMIT", "RUN", "COMMIT", "RESERVED", "MOVED", "READY") or (
                        kind == "FINAL" and frame["outcome"] == "ok"):
                    self.context.check()
                    if kind in ("ADMIT", "RUN", "COMMIT"):
                        _require(not self.context.launch_closed, ERROR)
            except BaseException as error:
                # Never send a queued grant after local cancellation/retirement.
                # Closing even a wholly unsent grant is conservative; a partial
                # grant MUST not be completed to authorize late child work.
                try:
                    self.context.record(error, _failure_reason(error))
                except BaseException as recording_error:
                    self.context.contain_target_error(error, recording_error)
                finally:
                    self.pending.clear()
                    self.close_writer()
                raise
            # Publication of IN_FLIGHT precedes the syscall AND every result
            # mutation. Even interruption of the exception handler leaves an
            # absorbing pre-syscall veto for any later safe-pump retry.
            self.write_in_flight = True
            try:
                descriptor, block = self.writer.fileno(), content[:64 * 1024]
                self.write_attempted.add(kind)
                try:
                    count = os.write(descriptor, block)
                except BlockingIOError:
                    self.write_in_flight = False
                    return  # Only the actual write's would-block is retryable.
                _require(type(count) is int and 0 < count <= min(len(content), 64 * 1024))
                if count == len(content):
                    self.pending.pop(0)
                    self.sent.add(kind)
                    _role_event(self.context.role, "frame_sent", edge=self.outgoing, frame=frame)
                else:
                    self.pending[0] = (frame, content[count:])
                # Do not clear until both the exact offset/positive-full-write
                # publication and the complete observation tail have finished.
                self.write_in_flight = False
            except BaseException as error:
                self._unknown_write(error)
                raise

    def read(self) -> None:
        if self.eof or self.reader_closed:
            return
        try:
            content = os.read(self.reader.fileno(), 64 * 1024)
        except BlockingIOError:
            return
        if content:
            self.frames.extend(self.decoder.feed(content))
        else:
            self.eof = True
            self.decoder.eof()
            _role_event(self.context.role, "status_eof" if self.incoming in ("c_to_o", "k_to_c") else "control_eof",
                        edge=self.incoming)

    def pump(self) -> None:
        self.flush()
        self.read()

    def take(self) -> list[dict[str, Any]]:
        frames, self.frames = self.frames, []
        return frames

    def close_writer(self) -> None:
        if not self.writer_closed:
            self.writer_closed = True
            self.context.close(self.writer)

    def close_reader(self) -> None:
        if not self.reader_closed:
            self.reader_closed = True
            self.context.close(self.reader)


class _GroupReservation:
    """G routing backed by C's original, deliberately unreaped K child."""
    def __init__(self, context: _Context, keeper: Any) -> None:
        self.context, self.keeper = context, keeper
        self._id = keeper.pid
        self._retired = False
        self._absent = False

    @property
    def id(self) -> int:
        return self._id

    @property
    def retired(self) -> bool:
        return self._retired

    @property
    def absent(self) -> bool:
        return self._absent

    def _check(self) -> None:
        _require(not self.retired and not self.keeper.numeric_retired
                 and _integer(self.id, PID_LIMIT) and self.keeper.pid == self.id, CLEANUP_ERROR)
        _require(time.monotonic_ns() < self.context.cleanup_cutoff(self.context.hard), CLEANUP_ERROR)

    def request(self, signum: int) -> bool:
        _require(type(signum) is int and signum in (0, signal.SIGKILL), CLEANUP_ERROR)
        self._check()
        _role_event(self.context.role, "group_request", group=self, signum=signum)
        self._check()  # An observer/mutation cannot bypass the pre-syscall veto.
        try:
            os.killpg(self.id, signum)
            return True
        except ProcessLookupError:
            self.retire(absent=True)
            return False
        except PermissionError:
            return True  # Presence/EPERM is never evidence of absence.

    def retire(self, *, absent: bool) -> None:
        if self.retired:
            _require(not absent or self.absent, CLEANUP_ERROR)
            return
        _require(type(absent) is bool, CLEANUP_ERROR)
        self._retired, self._absent = True, absent
        _role_event(self.context.role, "group_retired", group=self, absent=absent)


def _receipt_record(receipt: Any) -> dict[str, Any]:
    record = {"state": "reaped", "pid": receipt.pid, "status_kind": receipt.status_kind,
              "status_code": receipt.status_code}
    _child_record(record)
    return record


def _task_child_record(context: _Context) -> dict[str, Any]:
    task = context.tasks[0] if context.tasks else None
    acq = context.child_acquisition
    if acq.child is not None and acq.child.receipt is not None:
        return _receipt_record(acq.child.receipt)
    if (not acq.attempted and acq.launch_retired and context.launch_closed
            and (task is None or (task.launch_retired and task.joined))
            and acq.settled and not acq.cleanup_unknown):
        return {"state": "not_attempted"}
    return {"state": "unknown"}


def _wait_child(context: _Context, child: Any, deadline_ns: int, pump: Callable[[], None], event: str,
                *, phase: str, single_turn: bool = False) -> Any | None:
    # No direct numeric request exists after this boundary, even if the first
    # WNOHANG call consumes status and its publication is subsequently lost.
    def stopped() -> bool:
        _require(child.wait_state in ("OWNED", "POLLABLE", "REAPED")
                 and context.child_acquisition.settled and not context.child_acquisition.cleanup_unknown,
                 CLEANUP_ERROR)
        if child.wait_state == "REAPED":
            _require(child.receipt is not None, CLEANUP_ERROR)
        now = time.monotonic_ns()
        cutoff = context.cleanup_cutoff(context.hard if phase == "WORK" else deadline_ns)
        if now >= cutoff:
            context.record(ValidationError(CLEANUP_ERROR), "deadline", cleanup=True)
            return True
        if phase == "WORK":
            # Only positively unambiguous custody permits an ordinary operation
            # stop. No native/publication/observer exception enters this branch.
            if context.primary is not None:
                return True  # The actual already-recorded cancellation/error.
            if context.cancelled:
                context.record(ValidationError(ERROR), "cancelled")
                return True
            if now >= min(deadline_ns, context.run):
                context.record(ValidationError(TIMEOUT), "deadline")
                return True
        return False

    try:
        _require(phase in ("WORK", "CLEANUP") and (phase != "WORK" or context.role == "keeper"), CLEANUP_ERROR)
        _require(type(single_turn) is bool
                 and (not single_turn or phase == "CLEANUP" and context.role == "keeper"), CLEANUP_ERROR)
        child.retire_numeric()
        while not stopped():
            receipt = child.poll_wait()
            if receipt is not None:
                _require(child.wait_state == "REAPED" and child.receipt is receipt, CLEANUP_ERROR)
                _role_event(context.role, event, receipt=receipt)
                if phase == "WORK" and stopped():
                    return None  # Actual late receipt remains cleanup accounting.
                return receipt
            _require(child.wait_state == "POLLABLE", CLEANUP_ERROR)
            if single_turn:
                # K must keep servicing parent controls/fallback while V is
                # pending. This actual pid0 return grants only a later poll of
                # the same child, never settlement or a renewed wait budget.
                return None
            if phase == "WORK" and stopped():
                return None
            pump()
            if phase == "WORK" and stopped():
                return None
            _pause(context.cleanup_cutoff(deadline_ns))
    except BaseException as error:
        context.record(error, "lifecycle", cleanup=True)
    return None


def _settle_tasks(context: _Context, pump: Callable[[], None]) -> None:
    for task in context.tasks:
        try:
            task.close_launch()
        except BaseException as error:
            context.record(error, "creation", cleanup=True)
    if all(task.joined and task.acquisition.settled and not task.acquisition.cleanup_unknown for task in context.tasks):
        context.collect_native()
        return
    deadline_ns = context.begin_cleanup()
    while time.monotonic_ns() < context.cleanup_cutoff(deadline_ns) and any(not task.joined for task in context.tasks):
        for task in context.tasks:
            task.join_once(context.cleanup_cutoff(deadline_ns))
        try:
            pump()
        except BaseException as error:
            context.record(error, "io", cleanup=True)
        _pause(context.cleanup_cutoff(deadline_ns))
    for task in context.tasks:
        if not task.joined or not task.acquisition.settled or task.acquisition.cleanup_unknown:
            context.record(ValidationError(CLEANUP_ERROR), "creation", cleanup=True)
    context.collect_native()


def _validate_configuration(frame: dict[str, Any], context: _Context) -> Path:
    from .ios_profiles import MAX_COMPLETION_BYTES, profile_environment
    _require(frame["role"] == context.role and frame["capture_kind"] == "profile"
             and frame["run_deadline_ns"] == context.run
             and frame["hard_cleanup_deadline_ns"] == context.hard
             and frame["max_output_bytes"] == MAX_COMPLETION_BYTES)
    directory = Path(frame["cwd"])
    metadata = directory.lstat()
    _require(stat.S_ISDIR(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o700)
    arguments = frame["validator_argv"]
    try:
        cutoff = int(arguments[-1])
    except (ValueError, TypeError):
        raise ValidationError(PROTOCOL_ERROR) from None
    _require(str(cutoff) == arguments[-1] and _integer(cutoff, context.run)
             and tuple(arguments) == _worker_argv(directory, cutoff)
             and frame["validator_env"] == profile_environment(directory))
    # Child-local only; no caller/global cwd mutation and no shell command.
    os.chdir(directory)
    return directory


def _helper_map(context: _Context) -> dict[int, Any]:
    import fcntl
    null = os.stat(os.devnull)
    for descriptor, access in ((0, os.O_RDONLY), (1, os.O_WRONLY), (2, os.O_WRONLY)):
        metadata = os.fstat(descriptor)
        _require(stat.S_ISCHR(metadata.st_mode) and metadata.st_rdev == null.st_rdev
                 and fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE == access)
        os.set_inheritable(descriptor, False)
    # Standard wrappers are interpreter-owned for the helper lifetime. Validate
    # them, but do not adopt them into a raw-close inventory. A genuine helper
    # exit, not a claimed pre-FINAL close, accounts the remaining descriptor table.
    roles = {3: (os.O_RDONLY, "pipe"), 4: (os.O_WRONLY, "pipe"), 5: (os.O_RDONLY, "null"),
             6: (os.O_WRONLY, "pipe" if context.role == "custodian" else "null"),
             7: (os.O_WRONLY, "null")}
    result: dict[int, Any] = {}
    pipes: set[tuple[int, int]] = set()
    for descriptor, (access, kind) in roles.items():
        lease = context.io.adopt_fd(descriptor, access=access, kind=kind)
        result[descriptor] = lease
        if kind == "pipe":
            metadata = os.fstat(lease.fileno())
            identity = (metadata.st_dev, metadata.st_ino)
            _require(identity not in pipes)
            pipes.add(identity)
    _role_event(context.role, "map_validated", fd_roles={0: 0, 1: 1, 2: 2, **result})
    return result


def _hello() -> dict[str, Any]:
    return {"v": 1, "type": "HELLO", "pid": os.getpid(), "ppid": os.getppid(),
            "sid": os.getsid(0), "pgid": os.getpgrp(), "fd_map_version": 1}


def _status_frame(receipt: Any) -> dict[str, Any]:
    return {"v": 1, "type": "STATUS", "validator_pid": receipt.pid,
            "status_kind": receipt.status_kind, "status_code": receipt.status_code}


def _status_record(frame: dict[str, Any]) -> dict[str, Any]:
    return {"state": "reaped", "pid": frame["validator_pid"],
            "status_kind": frame["status_kind"], "status_code": frame["status_code"]}


def _flush_until(channel: _Channel, deadline_ns: int, pump: Callable[[], None], *, cleanup_bound: bool = True) -> None:
    def current() -> int:
        return (channel.context.cleanup_cutoff(deadline_ns) if cleanup_bound
                else channel.context.control_cutoff(deadline_ns))
    while channel.pending and time.monotonic_ns() < current():
        pump()
        channel.flush(deadline_ns=current())
        _pause(current(), (channel,))
    _require(not channel.pending and not channel.write_failed and not channel.write_in_flight, CLEANUP_ERROR)


class _Custodian:
    def __init__(self, context: _Context, descriptors: dict[int, Any]) -> None:
        self.context, self.descriptors = context, descriptors
        self.outer = _Channel(context, descriptors[3], descriptors[4], "o_to_c", "c_to_o")
        self.payload = descriptors[6]
        os.set_blocking(self.payload.fileno(), False)
        self.config: dict[str, Any] | None = None
        self.directory: Path | None = None
        self.admitted = self.run_granted = self.run_sent = False
        self.ready = self.payload_closed = self.committed = False
        self.reserved = self.release_sent = self.routes_retired = False
        self.outer_eof_seen = self.keeper_eof_seen = False
        self.outer_retiring = False
        self.keeper: Any = None
        self.group: _GroupReservation | None = None
        self.keeper_channel: _Channel | None = None
        self.keeper_hello: dict[str, Any] | None = None
        self.moved: dict[str, Any] | None = None
        self.validator: dict[str, Any] | None = None
        self.released: dict[str, Any] | None = None
        self.released_after_request = False
        self.keeper_receipt: Any = None
        self.cleanup_claimed = False

    def pump_outer(self) -> None:
        ctx = self.context
        if ctx.cancelled and ctx.primary is None:
            ctx.record(ValidationError(ERROR), "cancelled")
        if ctx.parent_pid is not None and os.getppid() != ctx.parent_pid and ctx.primary is None:
            ctx.record(ValidationError(ERROR), "parent_lost")
        self.outer.pump()
        for frame in self.outer.take():
            kind = frame["type"]
            if kind == "CANCEL":
                ctx.cancel_frame(frame)
            elif self.outer_retiring:
                # The decoder still enforces every frame and ordering rule.
                # Retired routes consume late positive controls, never install
                # their CONFIG or turn their bytes into a new work grant.
                continue
            elif kind == "CONFIG":
                self.directory = _validate_configuration(frame, ctx)
                self.config = frame
            elif kind == "ADMIT":
                _require(self.config is not None and not self.admitted and "HELLO" in self.outer.sent)
                ctx.check(); self.admitted = True
            elif kind == "RUN":
                _require(self.reserved and not self.run_granted and "RESERVED" in self.outer.sent)
                ctx.check(); self.run_granted = True
            elif kind == "COMMIT":
                _require(self.payload_closed and self.keeper_receipt is not None and self.validator is not None
                         and self.ready and "STATUS" in self.outer.sent and _normal(self.validator)
                         and self.keeper_receipt.status_kind == "exit" and self.keeper_receipt.status_code == HELPER_SETTLED
                         and self.group is not None and self.group.absent)
                ctx.check(); self.committed = True
                _role_event(ctx.role, "commit_received", frame=frame)
        if self.outer.eof and not self.outer_eof_seen:
            self.outer_eof_seen = True
            if not (self.outer_retiring and "QUIESCING" in self.outer.sent
                    and not self.outer.pending and not self.outer.write_failed and not self.outer.write_in_flight
                    and self.outer.decoder.ended and not self.outer.decoder.failed):
                # An earlier clean EOF remains a lifecycle failure, including
                # ordinary O cleanup after CANCEL. It can still prove stopped
                # input later; it never becomes an assertion of parent liveness.
                ctx.record(ValidationError(ERROR), "parent_lost")

    def pump_keeper(self) -> None:
        channel, ctx = self.keeper_channel, self.context
        if channel is None:
            return
        channel.pump()
        self.run_sent = "RUN" in channel.sent
        self.release_sent = "RELEASE" in channel.sent
        if self.keeper is None:
            # Parsing is bounded, but an unpublished spawn cannot admit HELLO.
            return
        for frame in channel.take():
            kind = frame["type"]
            if kind == "HELLO":
                _require(not self.routes_retired and not self.keeper.numeric_retired
                         and frame["pid"] == self.keeper.pid and frame["ppid"] == os.getpid()
                         and frame["sid"] == os.getpid() and frame["pgid"] == self.keeper.pid)
                _require(os.getsid(self.keeper.pid) == os.getpid() and os.getpgid(self.keeper.pid) == self.keeper.pid)
                self.keeper_hello = frame
                self.group = _GroupReservation(ctx, self.keeper)
                _role_event(ctx.role, "hello", frame=frame)
            elif kind == "MOVED":
                _require(self.run_sent and self.group is not None and not self.routes_retired
                         and not self.keeper.numeric_retired and frame["group_id"] == self.group.id
                         and frame["validator_pid"] not in (self.keeper.pid, os.getpid(), ctx.parent_pid)
                         and frame["keeper_pgid"] == os.getpid()
                         and os.getpgid(self.keeper.pid) == os.getpid() and os.getsid(self.keeper.pid) == os.getpid())
                self.moved = frame
                _role_event(ctx.role, "moved", frame=frame)
                if ctx.primary is None:
                    ctx.check()
                    self.outer.send("READY", **{key: frame[key] for key in FIELDS["READY"]})
                    self.ready = True
                    _role_event(ctx.role, "ready", frame=frame)
            elif kind == "STATUS":
                _require(self.moved is not None and frame["validator_pid"] == self.moved["validator_pid"])
                self.validator = _status_record(frame)
                if self.ready:
                    self.outer.send_frame(frame)
            else:
                _require(kind == "RELEASED")
                candidate = frame["validator"]
                if self.validator is not None:
                    _require(candidate == self.validator)
                if self.moved is not None:
                    _require(candidate["state"] != "not_attempted")
                    if candidate["state"] == "reaped":
                        _require(candidate["pid"] == self.moved["validator_pid"])
                if "RUN" not in channel.write_attempted:
                    _require(candidate["state"] == "not_attempted")
                if candidate["state"] == "reaped":
                    _require(candidate["pid"] not in (self.keeper.pid, os.getpid(), ctx.parent_pid))
                # An invalid candidate must not replace already known real V
                # evidence when failure cleanup later constructs its terminal.
                self.released = candidate
                self.released_after_request = self.release_sent
                if not self.release_sent:
                    ctx.record(ValidationError(ERROR), "lifecycle")
        if channel.eof and not self.keeper_eof_seen:
            self.keeper_eof_seen = True
            if self.released is None:
                ctx.record(ValidationError(CLEANUP_ERROR), "lifecycle", cleanup=True)

    def pump(self) -> None:
        self.pump_outer()
        self.pump_keeper()

    def safe_pump(self) -> None:
        for method in (self.pump_outer, self.pump_keeper):
            try:
                method()
            except BaseException as error:
                self.context.record(error, "protocol", cleanup=True)

    def work(self) -> None:
        ctx = self.context
        self.outer.send_frame(_hello())
        while not self.admitted:
            self.pump_outer(); ctx.check(); _pause(ctx.run, (self.outer,))
        assert self.config is not None
        control_read, control_write = ctx.io.pipe()
        status_read, status_write = ctx.io.pipe()
        self.keeper_channel = _Channel(ctx, status_read, control_write, "k_to_c", "c_to_k")
        command = helper_argv("keeper", parent_context={"parent_pid": os.getpid(), "session_id": os.getsid(0)},
                              deadlines={"run_deadline_ns": ctx.run, "hard_cleanup_deadline_ns": ctx.hard})
        # C's payload fd6 is deliberately NOT in this map. K/V cannot hold EOF.
        sources = (self.descriptors[5], self.descriptors[7], self.descriptors[7], control_read, status_write,
                   self.descriptors[5], self.descriptors[7], self.descriptors[7])
        self.keeper = _spawn(ctx, command, self.config["validator_env"], sources, "keeper", self.pump)
        ctx.close(control_read); ctx.close(status_write)
        ctx.close(self.descriptors[5]); ctx.close(self.descriptors[7])
        configuration = {**self.config, "role": "keeper"}
        self.keeper_channel.send_frame(configuration)
        while self.keeper_hello is None:
            self.pump(); ctx.check(); _pause(ctx.run, (self.outer, self.keeper_channel))
        ctx.check()
        assert self.group is not None
        self.outer.send("RESERVED", keeper_pid=self.keeper.pid, group_id=self.group.id, session_id=os.getpid())
        self.reserved = True
        _role_event(ctx.role, "reserved", group=self.group, keeper=self.keeper)
        while not self.run_granted:
            self.pump(); ctx.check(); _pause(ctx.run, (self.outer, self.keeper_channel))
        ctx.check()
        self.keeper_channel.send("RUN")
        while self.validator is None:
            self.pump(); ctx.check(); _pause(ctx.run, (self.outer, self.keeper_channel))

    def cleanup_descendants(self) -> None:
        ctx = self.context
        _require(not self.cleanup_claimed, CLEANUP_ERROR)
        self.cleanup_claimed = True
        ctx.retire_launch()
        cutoff = ctx.begin_cleanup()
        _settle_tasks(ctx, self.safe_pump)
        if self.keeper is None:
            self.keeper = ctx.child_acquisition.child
        channel = self.keeper_channel
        # A lost spawn return does not justify retaining C's own unused writer
        # copies until the EOF those copies would prevent. Still-running task
        # sources remain protected by close_all, not guessed safe to close.
        keep = (self.outer.reader, self.outer.writer, self.payload)
        if channel is not None:
            keep += (channel.reader, channel.writer)
        ctx.close_all(exclude=keep)
        self.safe_pump()
        if self.keeper is not None and channel is not None:
            if ctx.primary is not None and "CANCEL" not in channel.encoder.seen:
                try:
                    channel.send("CANCEL", reason_code=ctx.reason, cleanup_deadline_ns=ctx.cleanup_cutoff(cutoff))
                except BaseException as error:
                    ctx.record(error, "protocol", cleanup=True)
            while self.group is None and not channel.eof and time.monotonic_ns() < ctx.cleanup_cutoff(cutoff):
                self.safe_pump(); _pause(ctx.cleanup_cutoff(cutoff), (self.outer, channel))
            group = self.group
            if group is not None:
                try:
                    while not group.retired and time.monotonic_ns() < ctx.cleanup_cutoff(cutoff):
                        self.safe_pump()
                        group._check()
                        # Clean pre-RUN cancellation lets K move out of an empty
                        # G without fabricating MOVED/V. Do not kill its receipt.
                        if "RUN" not in channel.write_attempted and os.getpgid(self.keeper.pid) == group.id and not channel.eof:
                            _pause(ctx.cleanup_cutoff(cutoff), (self.outer, channel)); continue
                        if group.request(0):
                            group.request(int(signal.SIGKILL))
                        _pause(ctx.cleanup_cutoff(cutoff), (self.outer, channel))
                except BaseException as error:
                    ctx.record(error, "lifecycle", cleanup=True)
                finally:
                    if not group.retired:
                        group.retire(absent=False)
                if not group.absent:
                    ctx.record(ValidationError(CLEANUP_ERROR), "lifecycle", cleanup=True)
            # No later HELLO, cleanup exception or poll can reopen G routing.
            self.routes_retired = True
            try:
                if self.released is None:
                    channel.send("GROUP_RETIRED", group_id=self.keeper.pid, absent=group is not None and group.absent)
                    channel.send("RELEASE")
                    _flush_until(channel, cutoff, self.safe_pump)
                    self.release_sent = "RELEASE" in channel.sent
                else:
                    # A positively settled FAILED keeper can report before C's
                    # release request. Its actual status2 is checked below; do
                    # not write into its already retired control reader.
                    channel.close_writer()
            except BaseException as error:
                ctx.record(error, "protocol", cleanup=True)
                channel.close_writer()
            self.keeper_receipt = _wait_child(ctx, self.keeper, cutoff, self.safe_pump, "keeper_reaped", phase="CLEANUP")
            while not channel.eof and time.monotonic_ns() < ctx.cleanup_cutoff(cutoff):
                self.safe_pump(); _pause(ctx.cleanup_cutoff(cutoff), (channel,))
            if not channel.eof or self.released is None:
                ctx.record(ValidationError(CLEANUP_ERROR), "lifecycle", cleanup=True)
            channel.close_reader(); channel.close_writer()
        elif self.keeper is not None:
            self.routes_retired = True
            self.keeper_receipt = _wait_child(ctx, self.keeper, cutoff, self.safe_pump, "keeper_reaped", phase="CLEANUP")
            ctx.record(ValidationError(CLEANUP_ERROR), "lifecycle", cleanup=True)
        ctx.close_all(exclude=(self.outer.reader, self.outer.writer, self.payload))

    def retire_routes(self) -> None:
        # Even an interrupted cleanup dispatch permanently relinquishes the
        # entire numeric route before any final report or helper unwinding.
        self.routes_retired = True
        if self.group is not None and not self.group.retired:
            self.group.retire(absent=False)

    def write_payload(self) -> None:
        from .ios_profiles import COMPLETION_MARKER, completion_frame, read_profile_bytes
        ctx = self.context
        assert self.directory is not None
        ctx.check()
        frame = completion_frame(read_profile_bytes(self.directory / "verified-content.bin"))
        ctx.check()
        for marker, part in ((False, frame[:-len(COMPLETION_MARKER)]), (True, COMPLETION_MARKER)):
            content = memoryview(part)
            if marker:
                _role_event(ctx.role, "payload_before_marker", descriptor=self.payload.fileno())
            while content:
                self.pump_outer(); ctx.check()
                try:
                    count = os.write(self.payload.fileno(), content[:64 * 1024])
                except BlockingIOError:
                    _pause(ctx.run, (self.outer,)); continue
                _require(type(count) is int and 0 < count <= min(len(content), 64 * 1024), ERROR)
                _role_event(ctx.role, "payload_write", descriptor=self.payload.fileno(), count=count)
                content = content[count:]
            if marker:
                _role_event(ctx.role, "payload_marker_written", descriptor=self.payload.fileno())
        ctx.check()

    def retire_outer_control(self) -> bool:
        ctx, channel = self.context, self.outer
        stopped = False

        def failed(error: BaseException) -> None:
            try:
                ctx.record(error, _failure_reason(error), cleanup=True)
            except BaseException as recording_error:
                ctx.contain_target_error(error, recording_error)

        try:
            _require(not self.outer_retiring and not channel.reader_closed
                     and id(channel.reader) not in ctx.closed, CLEANUP_ERROR)
            # A settled failed K can outlive run without a C-local failure.
            # Observe ordinary stops before this one retirement bound is fixed;
            # expiry after a healthy sample must never reopen the wait.
            ctx.observe_helper_latches()
            cutoff = ctx.run if ctx.primary is None else (ctx.failure_limit or ctx.hard)
            # Retire dispatch before notifying O or consuming another control.
            # This phase cannot reopen descendant cleanup or renew its own bound.
            self.outer_retiring = True
            _require(time.monotonic_ns() < ctx.control_cutoff(cutoff), TIMEOUT)
            channel.send("QUIESCING")
            while True:
                _require(time.monotonic_ns() < ctx.control_cutoff(cutoff), TIMEOUT)
                _require(ctx.parent_pid is None or os.getppid() == ctx.parent_pid, CLEANUP_ERROR)
                self.pump_outer()
                _require(not channel.write_failed and not channel.write_in_flight
                         and not channel.decoder.failed and not channel.reader_closed, CLEANUP_ERROR)
                if channel.eof:
                    # read() publishes eof before Decoder.eof() can reject a
                    # trailing partial frame. Only completed framing is proof.
                    _require(channel.decoder.ended, CLEANUP_ERROR)
                    if "QUIESCING" in channel.sent and not channel.pending:
                        stopped = True
                        break
                _require(not channel.writer_closed, CLEANUP_ERROR)
                _pause(ctx.control_cutoff(cutoff), (channel,))
        except BaseException as error:
            failed(error)
        # One actual close/accounting attempt follows both success and failure.
        # A lost write/read/close never starts a second retirement wait.
        try:
            channel.close_reader()
        except BaseException as error:
            stopped = False
            failed(error)
        if stopped:
            try:
                _require(channel.eof and channel.decoder.ended and not channel.decoder.failed
                         and "QUIESCING" in channel.sent and not channel.pending
                         and not channel.write_failed and not channel.write_in_flight
                         and channel.reader_closed and id(channel.reader) in ctx.closed
                         and not channel.reader.unknown and not ctx.cleanup_unknown, CLEANUP_ERROR)
                _require(time.monotonic_ns() < ctx.control_cutoff(cutoff), TIMEOUT)
                _require(ctx.parent_pid is None or os.getppid() == ctx.parent_pid, CLEANUP_ERROR)
            except BaseException as error:
                stopped = False
                failed(error)
        return stopped

    def run(self) -> int:
        ctx = self.context
        try:
            self.work()
        except BaseException as error:
            ctx.record(error, _failure_reason(error))
        try:
            self.cleanup_descendants()
        except BaseException as error:
            ctx.record(error, "lifecycle", cleanup=True)
        finally:
            self.retire_routes()
        keeper = _task_child_record(ctx)
        validator = (self.released if self.released is not None else
                     self.validator if self.validator is not None else {"state": "unknown"})
        if keeper["state"] == "not_attempted":
            validator = {"state": "not_attempted"}
            group = {"state": "not_created"}
        elif self.group is not None and self.group.retired:
            group = {"state": "retired", "id": self.group.id, "absent": self.group.retired and self.group.absent}
        else:
            group = {"state": "unknown"}
        keeper_settled = (keeper["state"] == "not_attempted" or
                          keeper["state"] == "reaped" and keeper["status_kind"] == "exit"
                          and keeper["status_code"] in (HELPER_SETTLED, HELPER_FAILED)
                          and (keeper["status_code"] == HELPER_FAILED or self.released_after_request)
                          and self.released is not None and self.keeper_channel is not None
                          and self.keeper_channel.eof)
        successful = (ctx.primary is None and self.ready and self.validator == validator and _normal(validator)
                      and keeper_settled and _normal(keeper) and group["state"] == "retired" and group["absent"]
                      and ctx.resources_confirmed(exclude=(self.outer.reader, self.outer.writer, self.payload)))
        if successful:
            try:
                self.write_payload()
            except BaseException as error:
                ctx.record(error, "io")
        ctx.close(self.payload)
        self.payload_closed = id(self.payload) in ctx.closed and not self.payload.unknown
        if self.payload_closed:
            try:
                _role_event(ctx.role, "payload_closed", lease=self.payload)
            except BaseException as error:
                ctx.record(error, "io", cleanup=True)
        if successful and ctx.primary is None:
            try:
                # Cleanup, content write and the ACTUAL writer close precede
                # this success-only request. Withholding COMMIT cannot trap EOF.
                while not self.committed:
                    self.pump_outer(); ctx.check(); _pause(ctx.run, (self.outer,))
                self.pump_outer(); ctx.check()
            except BaseException as error:
                ctx.record(error, "lifecycle")
        input_retired = self.retire_outer_control()
        ctx.close_all(exclude=(self.outer.writer,))
        ctx.observe_helper_latches()
        epoch = ctx.error_epoch, ctx.signal_epoch
        confirmed = (input_retired and ctx.resources_confirmed(exclude=(self.outer.writer,))
                     and keeper_settled
                     and "unknown" not in (keeper["state"], validator["state"], group["state"])
                     and (group["state"] != "retired" or group["absent"]))
        outcome = "failed"
        if confirmed and ctx.primary is None and not ctx.cancelled:
            if successful and self.committed:
                outcome = "ok"
            elif self.ready and _normal(validator, success=False) and _normal(keeper):
                outcome = "rejected"
        final = {"v": 1, "type": "FINAL", "outcome": outcome,
                 "cleanup": "confirmed" if confirmed else "unknown", "keeper": keeper,
                 "validator": validator, "group": group}
        cutoff = ctx.run if ctx.primary is None else (ctx.failure_limit or ctx.hard)
        intended = (HELPER_FAILED if outcome == "failed" else HELPER_SETTLED) if confirmed else HELPER_UNKNOWN
        offer = ctx.offer_terminal(intended, epoch, cutoff, self.outer, "FINAL")
        try:
            self.outer.send_frame(final)
            _flush_until(self.outer, cutoff, lambda: None, cleanup_bound=False)
        except BaseException as error:
            ctx.record(error, "io", cleanup=True)
        self.outer.close_writer()
        return ctx.terminal_code(*offer)


class _Keeper:
    def __init__(self, context: _Context, descriptors: dict[int, Any]) -> None:
        self.context, self.descriptors = context, descriptors
        self.channel = _Channel(context, descriptors[3], descriptors[4], "c_to_k", "k_to_c")
        self.group_id = os.getpid()
        self.config: dict[str, Any] | None = None
        self.directory: Path | None = None
        self.run_granted = self.moved = self.released = False
        self.group_retired = self.group_absent = False
        self.eof_seen = False
        self.parent_cancellation: BaseException | None = None
        self.validator: Any = None
        self.receipt: Any = None

    def pump(self) -> None:
        ctx = self.context
        if ctx.cancelled and ctx.primary is None:
            ctx.record(ValidationError(ERROR), "cancelled")
        if os.getppid() != ctx.parent_pid and ctx.primary is None:
            ctx.record(ValidationError(ERROR), "parent_lost")
        self.channel.pump()
        for frame in self.channel.take():
            kind = frame["type"]
            if kind == "CONFIG":
                self.directory = _validate_configuration(frame, ctx)
                self.config = frame
            elif kind == "RUN":
                _require(self.config is not None and not self.run_granted and not self.group_retired
                         and "HELLO" in self.channel.sent)
                ctx.check(); self.run_granted = True
            elif kind == "CANCEL":
                self.parent_cancellation = ctx.cancel_frame(frame)
            elif kind == "GROUP_RETIRED":
                _require(frame["group_id"] == self.group_id and not self.group_retired)
                self.group_retired, self.group_absent = True, frame["absent"]
                _role_event(ctx.role, "group_retired", group=self, absent=self.group_absent)
                if not self.group_absent:
                    ctx.record(ValidationError(CLEANUP_ERROR), "lifecycle", cleanup=True)
            else:
                _require(kind == "RELEASE" and self.group_retired and not self.released)
                self.released = True
        if self.channel.eof and not self.eof_seen:
            self.eof_seen = True
            ctx.record(ValidationError(ERROR), "parent_lost")

    def safe_pump(self) -> None:
        try:
            self.pump()
        except BaseException as error:
            self.context.record(error, "protocol", cleanup=True)

    def move_out(self, *, positive: bool) -> None:
        ctx = self.context
        _require(os.getpid() == self.group_id and os.getsid(0) == ctx.parent_pid
                 and os.getpgrp() == self.group_id and os.getppid() == ctx.parent_pid, ERROR)
        # A pending/unknown V creation can still inherit our CURRENT group. Only
        # a genuinely published call or proved no-attempt permits this move.
        if positive:
            _require(self.validator is not None and ctx.child_acquisition.child is self.validator)
            ctx.check()
        else:
            _require(_task_child_record(ctx)["state"] == "not_attempted" or self.validator is not None, CLEANUP_ERROR)
            _require(time.monotonic_ns() < ctx.cleanup_cutoff(ctx.hard), CLEANUP_ERROR)
        os.setpgid(0, ctx.parent_pid)
        _require(os.getpgrp() == ctx.parent_pid and os.getsid(0) == ctx.parent_pid, ERROR)
        self.moved = True
        if positive:
            assert self.validator is not None
            ctx.check()
            frame = {"v": 1, "type": "MOVED", "validator_pid": self.validator.pid,
                     "group_id": self.group_id, "keeper_pgid": os.getpgrp()}
            self.channel.send_frame(frame)
            _role_event(ctx.role, "moved", frame=frame)
        else:
            _role_event(ctx.role, "empty_group_moved", group_id=self.group_id, keeper_pgid=os.getpgrp())

    def work(self) -> None:
        ctx = self.context
        self.channel.send_frame(_hello())
        while not self.run_granted:
            self.pump(); ctx.check(); _pause(ctx.run, (self.channel,))
        assert self.config is not None
        ctx.check()
        self.validator = _spawn(ctx, tuple(self.config["validator_argv"]), self.config["validator_env"],
                                (self.descriptors[5], self.descriptors[6], self.descriptors[7]), "validator", self.pump)
        # The actual V creation was in G. These now-unused application copies do
        # not survive merely because a later release/COMMIT has not arrived.
        for descriptor in (5, 6, 7):
            ctx.close(self.descriptors[descriptor])
        self.move_out(positive=True)
        self.receipt = _wait_child(ctx, self.validator, ctx.run, self.pump, "validator_reaped", phase="WORK")
        if self.receipt is None:
            if ctx.primary is not None:
                raise ctx.primary  # Preserve the exact cooperative parent CANCEL.
            raise ValidationError(CLEANUP_ERROR)
        ctx.check()  # A late receipt accounts for cleanup, never a late STATUS.
        self.channel.send_frame(_status_frame(self.receipt))

    def fallback_group(self) -> None:
        """Own-pinned EOF/deadline fallback, never the C group we joined."""
        ctx = self.context
        if self.group_retired:
            return
        cutoff = ctx.begin_cleanup()
        if not self.moved:
            try:
                self.move_out(positive=False)
            except BaseException as error:
                ctx.record(error, "lifecycle", cleanup=True)
        while not self.group_retired and time.monotonic_ns() < ctx.cleanup_cutoff(cutoff):
            self.safe_pump()
            if self.group_retired:
                break
            _require(os.getpid() == self.group_id and self.group_id != ctx.parent_pid, CLEANUP_ERROR)
            try:
                # Live self identity pins G even when C is gone. If movement was
                # impossible this may kill THIS keeper too; it is failure, never
                # a success-status oracle or a request to the joined C group.
                _role_event(ctx.role, "group_request", group=self, signum=signal.SIGKILL)
                _require(not self.group_retired and os.getpid() == self.group_id
                         and time.monotonic_ns() < ctx.cleanup_cutoff(cutoff), CLEANUP_ERROR)
                os.killpg(self.group_id, signal.SIGKILL)
            except ProcessLookupError:
                self.group_retired, self.group_absent = True, True
                _role_event(ctx.role, "group_retired", group=self, absent=True)
            except PermissionError:
                pass
            if (self.validator is not None and self.validator.receipt is None and self.validator.wait_state != "UNKNOWN"
                    and time.monotonic_ns() < ctx.cleanup_cutoff(cutoff)):
                # Numeric V authority retires before this FIRST poll as on the
                # ordinary path. A receipt may account failure, never fake READY.
                self.validator.retire_numeric()
                try:
                    receipt = self.validator.poll_wait()
                    if receipt is not None:
                        self.receipt = receipt
                        _role_event(ctx.role, "validator_reaped", receipt=receipt)
                except BaseException as error:
                    ctx.record(error, "lifecycle", cleanup=True)
            _pause(ctx.cleanup_cutoff(cutoff), (self.channel,))
        if not self.group_retired:
            self.group_retired, self.group_absent = True, False
            _role_event(ctx.role, "group_retired", group=self, absent=False)
            ctx.record(ValidationError(CLEANUP_ERROR), "lifecycle", cleanup=True)

    def run(self) -> int:
        ctx = self.context
        try:
            self.work()
        except BaseException as error:
            ctx.record(error, "lifecycle")
        ctx.retire_launch()
        _settle_tasks(ctx, self.safe_pump)
        if self.validator is None:
            self.validator = ctx.child_acquisition.child
        if not self.moved and (self.validator is not None or _task_child_record(ctx)["state"] == "not_attempted"):
            try:
                self.move_out(positive=False)
            except BaseException as error:
                ctx.record(error, "lifecycle", cleanup=True)
        try:
            while not self.released:
                self.safe_pump()
                cutoff = ctx.cleanup_cutoff(ctx.failure_limit or ctx.run)
                if self.eof_seen or os.getppid() != ctx.parent_pid or time.monotonic_ns() >= cutoff:
                    if ctx.primary is None:
                        ctx.record(ValidationError(TIMEOUT), "deadline")
                    self.fallback_group()
                    break
                if (not self.released and self.validator is not None and self.validator.receipt is None
                        and self.validator.wait_state in ("OWNED", "POLLABLE")):
                    # C cannot retire G while a killed V remains an unreaped
                    # group member. Reap V concurrently with waiting RELEASE,
                    # but never block parent-loss fallback behind a live V.
                    receipt = _wait_child(ctx, self.validator, cutoff, self.safe_pump,
                                          "validator_reaped", phase="CLEANUP", single_turn=True)
                    if receipt is not None:
                        self.receipt = receipt
                _pause(ctx.cleanup_cutoff(cutoff), (self.channel,))
            if self.validator is not None and self.validator.receipt is None and self.validator.wait_state != "UNKNOWN":
                self.receipt = _wait_child(ctx, self.validator, ctx.failure_limit or ctx.hard,
                                           self.safe_pump, "validator_reaped", phase="CLEANUP")
        except BaseException as error:
            ctx.record(error, "lifecycle", cleanup=True)
        ctx.close_all(exclude=(self.channel.reader, self.channel.writer))
        self.channel.close_reader()
        validator = _task_child_record(ctx)
        if not self.group_retired:
            self.group_retired, self.group_absent = True, False
            ctx.record(ValidationError(CLEANUP_ERROR), "lifecycle", cleanup=True)
        ctx.observe_helper_latches()
        epoch = ctx.error_epoch, ctx.signal_epoch
        settled = (self.group_retired and self.group_absent and validator["state"] != "unknown"
                   and ctx.resources_confirmed(exclude=(self.channel.writer,)))
        # A clean cooperative parent CANCEL can settle the requested protocol.
        # Its exact error object cannot erase a preceding or later local error,
        # nor an independently latched helper signal, into a fictitious K0.
        cooperative = (ctx.signal_epoch == 0 and (ctx.primary is None or
                       ctx.primary is self.parent_cancellation and not ctx.secondary))
        intended = (HELPER_SETTLED if self.released and cooperative
                    else HELPER_FAILED) if settled else HELPER_UNKNOWN
        cutoff = ctx.failure_limit or ctx.run
        offer = ctx.offer_terminal(intended, epoch, cutoff, self.channel, "RELEASED")
        try:
            # A real pre-READY V receipt may be carried here for accounting. It
            # is not promoted into a successful STATUS in a phase that never ran.
            self.channel.send("RELEASED", validator=validator)
            _flush_until(self.channel, cutoff, lambda: None, cleanup_bound=False)
        except BaseException as error:
            ctx.record(error, "io", cleanup=True)
        self.channel.close_writer()
        return ctx.terminal_code(*offer)


_HELPER_CUSTODY: list[_Context] = []


def helper_main(argv: list[str] | None = None) -> int:
    """Fixed C/K bootstrap. Arguments cannot select a program, FD or timeout reset."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    context: _Context | None = None
    owner: _Custodian | _Keeper | None = None
    try:
        _require(len(arguments) == 5 and type(arguments[0]) is str and arguments[0] in ROLES)
        role = arguments[0]
        _require(all(type(value) is str and value.isascii() and value.isdecimal() and len(value) <= 19
                     for value in arguments[1:]))
        values = tuple(int(value) for value in arguments[1:])
        _require(all(str(value) == raw for value, raw in zip(values, arguments[1:])))
        parent, inherited_session, run, hard = values
        _require(_integer(parent, PID_LIMIT, 2) and _integer(inherited_session, PID_LIMIT)
                 and _integer(run, TIME_LIMIT) and run <= hard <= min(TIME_LIMIT, run + CLEANUP_SECONDS * NANOSECOND))
        _require(os.getppid() == parent and os.getsid(0) == inherited_session and time.monotonic_ns() < run)
        if role == "keeper":
            _require(inherited_session == parent and os.getpgrp() == parent)
        context = _Context(role, run, hard, parent_pid=parent)
        _HELPER_CUSTODY.append(context)
        context.start_io()
        descriptors = _helper_map(context)
        os.umask(0o077)
        if role == "custodian":
            os.setsid()
            _require(os.getsid(0) == os.getpid() and os.getpgrp() == os.getpid())
        else:
            os.setpgid(0, 0)
            _require(os.getsid(0) == parent and os.getpgrp() == os.getpid())
        # Helper-local resets never modify an outer caller's handler/policy.
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        native.assert_child_waitability()

        # The same handler remains installed through exit. Its terminal-only arm
        # is enabled solely after owner.run has positively settled all resources.
        signal.signal(signal.SIGINT, context.helper_signal)
        signal.signal(signal.SIGTERM, context.helper_signal)
        owner = _Custodian(context, descriptors) if role == "custodian" else _Keeper(context, descriptors)
        saved = owner.run()
    except BaseException as error:
        if context is not None:
            context.record(error, "lifecycle", cleanup=True)
            try:
                if isinstance(owner, _Custodian):
                    if not owner.cleanup_claimed:
                        owner.cleanup_descendants()
                    owner.retire_routes()
                elif isinstance(owner, _Keeper):
                    context.retire_launch()
                    _settle_tasks(context, owner.safe_pump)
                    if owner.validator is None:
                        owner.validator = context.child_acquisition.child
                    owner.fallback_group()
            except BaseException as cleanup_error:
                context.record(cleanup_error, "lifecycle", cleanup=True)
            finally:
                if isinstance(owner, _Custodian):
                    try:
                        owner.retire_routes()
                    except BaseException as cleanup_error:
                        context.record(cleanup_error, "lifecycle", cleanup=True)
                context.close_all()
        # Nothing from a profile, path, native stderr or helper exception logs.
        return 1
    # Once owner.run returned, no handoff lookup/call/arm error may re-enter the
    # lifecycle rescue above, even if the monotonic arm was already published.
    try:
        return context.helper_handoff(saved)
    except BaseException:
        return HELPER_UNKNOWN


class _Outer:
    def __init__(self, context: _Context, directory: Path, deadlines: _Deadlines) -> None:
        self.context, self.directory, self.deadlines = context, directory, deadlines
        self.channel: _Channel | None = None
        self.payload: Any = None
        self.child: Any = None
        self.hello: dict[str, Any] | None = None
        self.reserved: dict[str, Any] | None = None
        self.ready: dict[str, Any] | None = None
        self.status: dict[str, Any] | None = None
        self.final: dict[str, Any] | None = None
        self.output = bytearray()
        self.payload_eof = self.overflow = False
        self.committed = self.status_eof_seen = False
        self.commit_requested = False
        self.control_retiring = False
        self.content: bytes | None = None
        self.receipt: Any = None
        self.confirmed = self.no_producers = False
        self.cleanup_claimed = False

    def read_payload(self) -> None:
        from .ios_profiles import MAX_COMPLETION_BYTES
        if self.payload is None or self.payload_eof or id(self.payload) in self.context.closed:
            return
        try:
            content = os.read(self.payload.fileno(), 64 * 1024)
        except BlockingIOError:
            return
        if not content:
            self.payload_eof = True
            _role_event("outer", "payload_eof", lease=self.payload)
        elif not self.overflow:
            self.output.extend(content)
            if len(self.output) > MAX_COMPLETION_BYTES:
                self.overflow = True
                self.output.clear()
                self.context.record(ValidationError("authenticated profile content exceeds its safety bound"), "io")

    def retire_control_writer(self) -> None:
        channel, ctx = self.channel, self.context
        if not self.control_retiring or channel is None or channel.writer_closed:
            return
        if ctx.primary is not None and "CANCEL" not in channel.encoder.seen:
            # record() already fixed the first failure bound. Do not replace an
            # existing CANCEL packet, offset or deadline, or start another grace.
            channel.send("CANCEL", reason_code=ctx.reason,
                         cleanup_deadline_ns=min(ctx.cleanup_cutoff(ctx.hard), self.deadlines.hard))
        # CONFIG and an existing CANCEL may drain. A queued/partial grant instead
        # hits flush's live retirement veto; never finish it to reach a later
        # CANCEL, or pretend that discarded trailing bytes were delivered.
        channel.flush()
        if not channel.pending and not channel.write_failed and not channel.write_in_flight:
            channel.close_writer()

    def process_frames(self) -> None:
        channel, ctx = self.channel, self.context
        if channel is None or self.child is None:
            return
        self.committed = "COMMIT" in channel.sent
        for frame in channel.take():
            kind = frame["type"]
            if kind == "HELLO":
                _require(frame["pid"] == self.child.pid and frame["ppid"] == os.getpid()
                         and frame["sid"] == self.child.pid and frame["pgid"] == self.child.pid
                         and self.child.pid != os.getpid())
                self.hello = frame
                _role_event("outer", "hello", frame=frame)
            elif kind == "RESERVED":
                _require(self.hello is not None and "ADMIT" in channel.sent
                         and frame["keeper_pid"] == frame["group_id"]
                         and frame["session_id"] == self.child.pid
                         and frame["keeper_pid"] not in (os.getpid(), self.child.pid))
                self.reserved = frame
            elif kind == "READY":
                _require(self.reserved is not None and "RUN" in channel.sent
                         and frame["group_id"] == self.reserved["group_id"]
                         and frame["keeper_pgid"] == self.child.pid
                         and frame["validator_pid"] not in (os.getpid(), self.child.pid, self.reserved["keeper_pid"]))
                self.ready = frame
                _role_event("outer", "ready", frame=frame)
            elif kind == "STATUS":
                _require(self.ready is not None and frame["validator_pid"] == self.ready["validator_pid"])
                self.status = frame
            elif kind == "QUIESCING":
                _require(not self.control_retiring)
                self.control_retiring = True
                ctx.retire_launch()
            else:
                _require(kind == "FINAL" and self.control_retiring)
                keeper, validator, group = (frame[name] for name in ("keeper", "validator", "group"))
                if "ADMIT" not in channel.write_attempted:
                    _require(keeper["state"] == "not_attempted" and validator["state"] == "not_attempted"
                             and group["state"] == "not_created")
                if "RUN" not in channel.write_attempted:
                    _require(validator["state"] == "not_attempted")
                if keeper["state"] == "reaped":
                    _require(keeper["pid"] not in (os.getpid(), self.child.pid))
                if validator["state"] == "reaped":
                    forbidden = (os.getpid(), self.child.pid)
                    if keeper["state"] == "reaped":
                        forbidden += (keeper["pid"],)
                    _require(validator["pid"] not in forbidden)
                if self.reserved is not None:
                    _require(keeper["state"] != "not_attempted" and group["state"] != "not_created")
                    if keeper["state"] == "reaped":
                        _require(keeper["pid"] == self.reserved["keeper_pid"])
                    if group["state"] == "retired":
                        _require(group["id"] == self.reserved["group_id"])
                if self.status is not None:
                    _require(frame["validator"] == _status_record(self.status))
                elif self.ready is not None:
                    _require(frame["validator"]["state"] != "not_attempted")
                    if frame["validator"]["state"] == "reaped":
                        _require(frame["validator"]["pid"] == self.ready["validator_pid"])
                if frame["outcome"] == "ok":
                    _require(self.committed and self.content is not None and self.payload_eof
                             and self.status is not None and _normal(_status_record(self.status)))
                self.final = frame
                _role_event("outer", "final_received", frame=frame)
        if channel.eof and not self.status_eof_seen:
            self.status_eof_seen = True
            if self.final is None:
                ctx.record(ValidationError(CLEANUP_ERROR), "protocol", cleanup=True)
        self.retire_control_writer()

    def pump(self) -> None:
        if self.channel is not None:
            self.channel.pump()
        self.read_payload()
        self.process_frames()

    def safe_pump(self) -> None:
        # Independent sources continue draining even after a malformed peer or a
        # failed data read. Neither path can turn a partial result into success.
        if self.channel is not None:
            try:
                self.channel.pump()
                self.process_frames()
            except BaseException as error:
                self.context.record(error, "protocol", cleanup=True)
        try:
            self.read_payload()
        except BaseException as error:
            self.context.record(error, "io", cleanup=True)

    def work(self) -> None:
        from .ios_profiles import AUTHENTICATION_ERROR, completed_content, profile_environment
        ctx = self.context
        metadata = self.directory.lstat()
        _require(self.directory.is_absolute() and stat.S_ISDIR(metadata.st_mode)
                 and stat.S_IMODE(metadata.st_mode) == 0o700, ERROR)
        null_read = ctx.io.open_null(writable=False)
        null_write = ctx.io.open_null(writable=True)
        control_read, control_write = ctx.io.pipe()
        status_read, status_write = ctx.io.pipe()
        payload_read, payload_write = ctx.io.pipe()
        self.channel = _Channel(ctx, status_read, control_write, "c_to_o", "o_to_c")
        self.payload = payload_read
        os.set_blocking(payload_read.fileno(), False)
        _role_event("outer", "payload_reader_registered", lease=payload_read)
        command = helper_argv("custodian", parent_context={"parent_pid": os.getpid(), "session_id": os.getsid(0)},
                              deadlines={"run_deadline_ns": self.deadlines.run,
                                         "hard_cleanup_deadline_ns": self.deadlines.hard})
        sources = (null_read, null_write, null_write, control_read, status_write, null_read, payload_write, null_write)
        self.child = _spawn(ctx, command, profile_environment(self.directory), sources, "custodian", self.pump)
        for lease in (control_read, status_write, payload_write, null_read, null_write):
            ctx.close(lease)
        self.channel.send_frame(_configuration(self.directory, self.deadlines, "custodian"))
        while (self.hello is None or self.control_retiring) and self.final is None:
            self.pump(); ctx.check(); _pause(ctx.run, (self.channel,), (self.payload,))
        if self.final is not None:
            raise ValidationError(AUTHENTICATION_ERROR)
        ctx.check()
        if not self.control_retiring:
            self.channel.send("ADMIT")
        while (self.reserved is None or self.control_retiring) and self.final is None:
            self.pump(); ctx.check(); _pause(ctx.run, (self.channel,), (self.payload,))
        if self.final is not None:
            raise ValidationError(AUTHENTICATION_ERROR)
        ctx.check()
        if not self.control_retiring:
            self.channel.send("RUN")
        while self.final is None:
            self.pump(); ctx.check()
            if (not self.control_retiring and not self.commit_requested and self.ready is not None and self.status is not None
                    and _normal(_status_record(self.status)) and self.payload_eof):
                self.content = completed_content(bytes(self.output))
                ctx.check()
                if not self.control_retiring:
                    self.channel.send("COMMIT")
                    self.commit_requested = True
            _pause(ctx.run, (self.channel,), () if self.payload_eof else (self.payload,))
        if self.final["outcome"] != "ok":
            raise ValidationError(AUTHENTICATION_ERROR)
        while not self.channel.eof or not self.payload_eof:
            self.pump(); ctx.check()
            _pause(ctx.run, (self.channel,), () if self.payload_eof else (self.payload,))
        ctx.check()

    def cleanup(self) -> None:
        ctx = self.context
        _require(not self.cleanup_claimed, CLEANUP_ERROR)
        self.cleanup_claimed = True
        ctx.retire_launch()
        cutoff = ctx.begin_cleanup()
        channel = self.channel
        if channel is not None and self.final is None and not channel.writer_closed:
            try:
                if "CANCEL" not in channel.encoder.seen:
                    channel.send("CANCEL", reason_code=ctx.reason,
                                 cleanup_deadline_ns=min(ctx.cleanup_cutoff(cutoff), self.deadlines.hard))
                _flush_until(channel, cutoff, self.safe_pump)
            except BaseException as error:
                ctx.record(error, "io", cleanup=True)
        if channel is not None:
            channel.close_writer()  # Late unpublished C gets EOF, never ADMIT.
        _settle_tasks(ctx, self.safe_pump)
        if self.child is None:
            self.child = ctx.child_acquisition.child
        keep = (self.payload,) if self.payload is not None else ()
        if channel is not None:
            keep += (channel.reader, channel.writer)
        ctx.close_all(exclude=keep)
        self.safe_pump()
        if self.child is not None:
            self.receipt = _wait_child(ctx, self.child, cutoff, self.safe_pump, "custodian_reaped", phase="CLEANUP")
            while (channel is not None and (not channel.eof or not self.payload_eof)
                   and time.monotonic_ns() < ctx.cleanup_cutoff(cutoff)):
                self.safe_pump()
                _pause(ctx.cleanup_cutoff(cutoff), (channel,), () if self.payload is None or self.payload_eof else (self.payload,))
        if channel is not None:
            channel.close_reader()
        if self.payload is not None:
            ctx.close(self.payload)
        ctx.close_all()
        record = _task_child_record(ctx)
        self.no_producers = record["state"] == "not_attempted"
        self.confirmed = (ctx.resources_confirmed() and
                          (self.no_producers or
                           (self.receipt is not None and self.receipt.status_kind == "exit"
                            and self.control_retiring and self.final is not None and self.final["cleanup"] == "confirmed"
                            and self.receipt.status_code == (HELPER_FAILED if self.final["outcome"] == "failed" else HELPER_SETTLED)
                            and channel is not None and channel.eof and self.payload_eof)))

    def run(self) -> bytes | None:
        try:
            self.work()
        except BaseException as error:
            self.context.record(error, _failure_reason(error))
        try:
            self.cleanup()
        except BaseException as error:
            self.context.record(error, "lifecycle", cleanup=True)
            self.context.close_all()
            self.confirmed = False
        return self.content


def _public_error(error: BaseException) -> BaseException:
    from .ios_profiles import AUTHENTICATION_ERROR
    if isinstance(error, (KeyboardInterrupt, SystemExit)):
        return error
    safe = {ERROR, TIMEOUT, CLEANUP_ERROR, PROTOCOL_ERROR, AUTHENTICATION_ERROR,
            "authenticated profile content exceeds its safety bound",
            "iOS artifact inspection exceeded its shared time bound; no new authorization is permitted",
            "Apple profile cancellation handlers could not be restored; no upload is authorized"}
    if (type(error) is ValidationError and len(error.args) == 1
            and type(error.args[0]) is str and error.args[0] in safe):
        return error
    return ValidationError(ERROR)


def capture_profile(directory: Path, deadline: InspectionDeadline, *, cancellation: DefaultCancellation | None = None,
                    finality: CaptureFinality) -> bytes:
    """Capture only the fixed profile worker under a shared, nonrenewed deadline.

    Exclusive exact-child ownership and continuing waitability are prerequisites,
    including the public libc creation/error/publication interval. No cooperating
    caller may install automatic disposal or steal this capture's child status.
    A borrowed cancellation guard remains installed through outer scratch cleanup.
    """
    from .ios_profiles import _profile_cancellation, _require_profile_scratch_available
    _require_profile_scratch_available()
    _require(type(finality) is CaptureFinality and isinstance(directory, Path), CLEANUP_ERROR)
    owns_guard = cancellation is None
    guard = _profile_cancellation() if cancellation is None else cancellation
    context: _Context | None = None
    owner: _Outer | None = None
    primary: BaseException | None = None
    result: bytes | None = None
    # Defer only this guard's default-signal exception injection throughout the
    # owned operation. Explicit loop checks remain live while native creation is
    # in its actual separate task. Thus entering a cleanup/finality frame cannot
    # itself lose the only dispatch to required closes, joins or restoration.
    # Custom handlers and non-main callers are never replaced.
    with guard.deferred(check_on_exit=False):
        try:
            if owns_guard:
                guard.install()
                guard.activate()
            deadline.check()
            guard.check()
            deadlines = _Deadlines.from_inspection(deadline)
            context = _Context("outer", deadlines.capture, deadlines.outer_hard, cancellation=guard)
            finality._begin(context)
            context.start_io()
            owner = _Outer(context, directory, deadlines)
            result = owner.run()
        except BaseException as error:
            if context is not None:
                try:
                    context.record(error, _failure_reason(error))
                except BaseException as recording_error:
                    context.contain_target_error(error, recording_error)
            primary = error
        finally:
            # Every independent obligation is attempted even if another dispatch
            # raises. Numeric cleanup is claimed once; joins/close-once slots
            # retain their original endpoint and never infer a missing receipt.
            try:
                if context is not None:
                    try:
                        if owner is not None and not owner.cleanup_claimed:
                            owner.cleanup()
                    except BaseException as error:
                        context.record(error, "lifecycle", cleanup=True)
                    try:
                        context.retire_launch()
                        _settle_tasks(context, owner.safe_pump if owner is not None else lambda: None)
                    except BaseException as error:
                        context.record(error, "creation", cleanup=True)
                    try:
                        context.close_all()
                    except BaseException as error:
                        context.record(error, "io", cleanup=True)
                    try:
                        context.collect_native()
                    except BaseException as error:
                        context.record(error, "creation", cleanup=True)
            finally:
                if context is not None:
                    # ACTIVE with an exited owner reads UNKNOWN even if a later
                    # custom interruption skips explicit finality publication.
                    context.exited = True
                if owns_guard:
                    try:
                        guard.restore()
                    except BaseException as error:
                        if context is not None:
                            context.record(error, "lifecycle", cleanup=True)
                        elif primary is None:
                            primary = error
            if context is not None and finality._owner is context and finality._begun:
                try:
                    no_producers = _task_child_record(context)["state"] == "not_attempted"
                    confirmed = (context.resources_confirmed() and not context.cleanup_unknown
                                 and (owner.confirmed if owner is not None else no_producers))
                    if confirmed:
                        finality._finish(no_producers=no_producers)
                    else:
                        finality._unknown()
                except BaseException as error:
                    context.record(error, "lifecycle", cleanup=True)
                    finality._unknown()
        if context is not None:
            primary = context.primary if context.primary is not None else primary
        # No required resource/publication work follows this acceptance gate.
        # Do not create a cancellation exception to mask an earlier active error.
        if primary is None:
            try:
                deadline.check()
                guard.check()
                if context is not None:
                    context.check()  # Cleanup grace never extends capture acceptance.
                _require(context is not None and owner is not None and owner.confirmed
                         and context.resources_confirmed() and finality.state == "FINALIZED"
                         and type(result) is bytes and owner.final is not None
                         and owner.final["outcome"] == "ok", CLEANUP_ERROR)
            except BaseException as error:
                if context is not None:
                    try:
                        context.record(error, _failure_reason(error))
                    except BaseException as recording_error:
                        context.contain_target_error(error, recording_error)
                    primary = context.primary if context.primary is not None else error
                else:
                    primary = error
        if primary is not None:
            raise _public_error(primary) from None
        assert result is not None
        return result


if __name__ == "__main__":
    raise SystemExit(helper_main())
