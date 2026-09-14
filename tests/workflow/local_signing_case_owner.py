"""Original-fork lifetime owner for warm, sequential signing-matrix cases.

L retains its original anchor A unpolled. A creates W in G=A.pid, then moves
outside G before RUN. G is retired before L's first A wait, including waitpid0;
diagnostic PID files never authorize a signal, wait, cleanup or next case.
"""
from __future__ import annotations

import json
import math
import mmap
import os
from pathlib import Path
import select
import signal
import struct
from subprocess import CompletedProcess
import threading
import time
import traceback

from workflow.local_signing_matrix_contract import (
    ADAPTER_PROGRESS_CASES, ADAPTER_PROGRESS_OWNER_STAGES, ADAPTER_PROGRESS_SERVICE_STAGES,
    ADAPTER_PROGRESS_MAX, adapter_command_first, adapter_target_result, emit_adapter_failure,
)

WORKER_ERROR = 91
MAX_RECORD = 4096
CASE_DEADLINE = None  # Set only in the actual original case worker before RUN.
ADAPTER_DIAGNOSTIC_CONTEXT = None  # Immutable finite4 context; disabled in every other scope.
ADAPTER_CASE_FAILURE = None  # Existing scalar observations only, not a custody receipt.
ADAPTER_CASE_PROGRESS = None  # Separate context-bound, post-settlement optional DATA.
_ADAPTER_WORKER_DIAGNOSTIC = None
_ADAPTER_PROGRESS_WRITER = None
_RETAINED_ADAPTER_PROGRESS = []  # Ambiguous original close; no retry or later-case adoption.


class _AdapterProgress:
    """Two fixed single-writer slots; never a control or finality channel.

    The launcher alone owns its mapping close. W's exact main thread writes
    offset0; its exact already-existing model service writes offset64. A single
    post-settlement page copy is NOT an atomic observation across both slots.
    """
    record = struct.Struct("!12I")
    sequence = struct.Struct("!I")

    def __init__(self, context, name, started, launcher):
        self.context, self.name, self.started, self.launcher = context, name, started, launcher
        self.case = ADAPTER_PROGRESS_CASES.index(name) + 1
        self.mapping = None  # Assigned separately, inside the launcher's protected lifetime.
        self.close_claimed = False
        self.worker = self.main = self.service = None
        self.service_command, self.joined = None, True
        self.command = self.completed = self.total = self.maximum = 0
        self.command_started, self.returned = None, False
        self.sequences, self.disabled = [0, 0], [False, False]

    def bind_worker(self):
        global _ADAPTER_PROGRESS_WRITER
        if self.mapping is not None and threading.current_thread() is threading.main_thread():
            self.worker, self.main = os.getpid(), threading.main_thread()
            _ADAPTER_PROGRESS_WRITER = self

    def disable(self, role):
        self.disabled[role] = True
        try:
            # Odd is unavailable; this never resets a publication sequence.
            self.mapping[role * 64:role * 64 + 4] = self.sequence.pack(ADAPTER_PROGRESS_MAX)
        except Exception:
            pass  # A failed write can leave only an older best-effort observation.

    def publish(self, role, stage, command, now):
        if self.disabled[role]:
            return
        try:
            self.sequences[role] += 2
            number, offset = self.sequences[role], role * 64
            # Invalidate BEFORE payload construction/writes. SIGKILL may leave
            # odd or mismatched fields; readers reject them without retrying.
            self.mapping[offset:offset + 4] = self.sequence.pack(min(number - 1, ADAPTER_PROGRESS_MAX))
            elapsed = (now - self.started) * 1000
            if not math.isfinite(elapsed) or not 0 <= elapsed <= ADAPTER_PROGRESS_MAX:
                self.disabled[role] = True
                return
            values = (1, role + 1, self.worker, self.case, command, stage, int(elapsed),
                      self.completed if role == 0 else 0, self.total if role == 0 else 0,
                      self.maximum if role == 0 else 0)
            if number > ADAPTER_PROGRESS_MAX - 1 or any(type(value) is not int or not 0 <= value <= ADAPTER_PROGRESS_MAX
                                                      for value in values):
                self.disabled[role] = True
                return
            data = self.record.pack(number, *values, number)
            self.mapping[offset + 4:offset + self.record.size] = data[4:]
            self.mapping[offset:offset + 4] = data[:4]  # Matching positive even publication, last.
        except Exception:
            self.disable(role)

    def observe(self, stage, command, service):
        if os.getpid() != self.worker or ADAPTER_DIAGNOSTIC_CONTEXT is not self.context:
            return None
        current = threading.current_thread()
        if stage in ADAPTER_PROGRESS_SERVICE_STAGES:
            if (current is self.service and type(command) is int and command == self.service_command
                    and not self.joined):
                self.publish(1, ADAPTER_PROGRESS_SERVICE_STAGES.index(stage) + 1, command, time.monotonic())
            return None
        if current is not self.main:
            return None
        if stage == "bind-service":
            if (type(command) is int and command == self.command and command > 0 and self.service is None
                    and isinstance(service, threading.Thread) and service is not self.main):
                self.service, self.service_command, self.joined = service, command, False
            return None
        now = time.monotonic()
        if stage == "begin":
            if command is not None or service is not None or not self.joined or self.disabled[0]:
                return None
            self.command += 1
            self.command_started, self.returned = now, False
            self.service, self.service_command = None, None
        elif stage in {"run-owned", "target-return", "service-joined", "model-return"}:
            if type(command) is not int or command != self.command or command <= 0:
                return None
            if stage == "service-joined":
                if service is not self.service or service is None:
                    return None
                self.joined = True  # Called only after the original join is confirmed.
            elif stage == "model-return":
                if not self.joined or self.returned:
                    return None
                self.returned = True  # Accounting is once, after the actual final-success gate.
                duration = (now - self.command_started) * 1000
                if not math.isfinite(duration) or not 0 <= duration <= ADAPTER_PROGRESS_MAX:
                    self.disable(0)
                    return None
                duration = int(duration)
                self.completed += 1
                self.total += duration
                self.maximum = max(self.maximum, duration)
        elif stage not in ADAPTER_PROGRESS_OWNER_STAGES or command is not None or service is not None:
            return None
        self.publish(0, ADAPTER_PROGRESS_OWNER_STAGES.index(stage) + 1, self.command, now)
        return self.command if stage == "begin" and not self.disabled[0] else None

    def snapshot(self, worker):
        if self.mapping is None or os.getpid() != self.launcher or ADAPTER_DIAGNOSTIC_CONTEXT is not self.context:
            return None
        try:
            raw = self.mapping[:]  # Exactly one page copy, only after original settlement.
            if type(raw) is not bytes or len(raw) != 4096 or type(worker) is not int or worker <= 0:
                return None
            records = []
            for role, stages in enumerate((ADAPTER_PROGRESS_OWNER_STAGES, ADAPTER_PROGRESS_SERVICE_STAGES)):
                values = self.record.unpack(raw[role * 64:role * 64 + self.record.size])
                first, version, actual_role, pid, case, command, stage, elapsed, completed, total, maximum, last = values
                if (not 0 < first == last <= ADAPTER_PROGRESS_MAX - 1 or first % 2 or version != 1
                        or actual_role != role + 1 or pid != worker or case != self.case
                        or not 1 <= stage <= len(stages) or any(value > ADAPTER_PROGRESS_MAX for value in values)
                        or completed > command or maximum > total or not completed and (total or maximum)
                        or role == 1 and (not command or completed or total or maximum)):
                    records.append(None)
                    continue
                record = {"stage": stages[stage - 1], "elapsedMs": elapsed, "command": command}
                if role == 0:
                    if (record["stage"] in {"begin", "run-owned", "target-return", "service-joined", "model-return"}
                            and not command or record["stage"] == "model-return" and not completed):
                        records.append(None)
                        continue
                    record.update(completed=completed, totalMs=total, maxMs=maximum)
                records.append(record)
            owner, service = records
            if owner is None or service is not None and service["command"] != owner["command"]:
                service = None  # A prior service EOF never describes the next command.
            return {"case": self.name, "owner": owner, "service": service}
        except Exception:
            return None

    def close(self, cleanup_errors):
        if self.mapping is None or self.close_claimed or os.getpid() != self.launcher:
            return
        self.close_claimed = True  # One original close attempt, including interruption.
        try:
            self.mapping.close()
        except BaseException as error:
            _RETAINED_ADAPTER_PROGRESS.append(self)
            cleanup_errors.append(error)


def adapter_progress(stage, *, command=None, service=None):
    """Finite hooks only; ordinary telemetry errors cannot replace task work."""
    page = _ADAPTER_PROGRESS_WRITER
    if page is not None:
        try:
            return page.observe(stage, command, service)
        except Exception:
            pass
    return None


def adapter_command_recorder(actual):
    """Observe the first original O primary AFTER its unchanged recorder."""
    slot = _ADAPTER_WORKER_DIAGNOSTIC
    if slot is None:
        return actual

    def recorded(context, error, **kwargs):
        result = actual(context, error, **kwargs)  # Exactly once; an original raise propagates unchanged.
        try:
            if (os.getpid() != slot["pid"] or context.pid != slot["pid"] or context.role != "O"
                    or context.primary is not error or not slot["lock"].acquire(blocking=False)):
                return result
            try:
                if slot["claimed"]:
                    return result
                slot["claimed"] = True  # Absorbing BEFORE projection; failures cannot rearm it.
            finally:
                slot["lock"].release()
            slot["first"] = adapter_command_first(slot["context"], error)
        except BaseException:
            pass  # Optional, bounded in-memory DATA; no IO or failure replacement.
        return result

    return recorded


def adapter_case_failure(context):
    value = ADAPTER_CASE_FAILURE
    return value[1] if value is not None and value[0] is context else None


def adapter_case_progress(context):
    value = ADAPTER_CASE_PROGRESS
    return value[1] if value is not None and value[0] is context else None


def observe_adapter_target_result(result):
    """Optional original normal-return DATA, called only after primary latched."""
    slot = _ADAPTER_WORKER_DIAGNOSTIC
    if slot is None:
        return
    try:
        if (os.getpid() != slot["pid"] or threading.current_thread() is not slot["thread"]
                or ADAPTER_DIAGNOSTIC_CONTEXT is not slot["context"] or type(result) is not CompletedProcess
                or not slot["lock"].acquire(blocking=False)):
            return
        try:
            if slot["target_claimed"]:
                return
            slot["target_claimed"] = True  # Absorbing even if projection fails or is unavailable.
        finally:
            slot["lock"].release()
        slot["target"] = adapter_target_result(slot["context"], result.returncode, result.stderr)
    except BaseException:
        pass  # Never retain the result/raw streams or change the original primary.


def require(condition, message):
    if not condition:
        raise AssertionError("case owner: " + message)


def remaining(deadline):
    value = deadline - time.monotonic()
    require(value > 0, "original case endpoint expired")
    return value


def terminal_record(line):
    require(type(line) is bytes and 0 < len(line) <= MAX_RECORD, "anchor terminal frame invalid")
    kind, separator, raw = line.partition(b" ")
    require(separator and kind in {b"SETTLED", b"EXPIRED"}, "anchor settlement invalid")
    try:
        code = int(raw)
    except ValueError:
        raise AssertionError("case owner: anchor terminal status invalid") from None
    require(str(code).encode("ascii") == raw and -128 <= code <= 255, "anchor terminal status invalid")
    return kind == b"EXPIRED", code


class Handles:
    def __init__(self):
        self.values = {}
        self.errors = []

    def pipe(self, name):
        require(name + "r" not in self.values and name + "w" not in self.values, "duplicate pipe slot")
        read, write = os.pipe()
        self.values[name + "r"], self.values[name + "w"] = read, write
        os.set_blocking(read, False)
        os.set_blocking(write, False)

    def close(self, name):
        descriptor = self.values.pop(name, None)
        if descriptor is not None:
            try:
                os.close(descriptor)
            except BaseException as error:
                self.errors.append(error)

    def close_except(self, keep=()):
        for name in tuple(self.values):
            if name not in keep:
                self.close(name)

    def get(self, name):
        require(name in self.values, "retired original descriptor")
        return self.values[name]


class OriginalWait:
    """Only constructed immediately around the actual original fork result."""
    def __init__(self):
        self.attempted = False
        self.pid = None
        self.retired = False
        self.status = None
        self.unknown = False

    def fork(self):
        require(not self.attempted, "fork slot consumed")
        self.attempted = True
        try:
            result = os.fork()
            self.pid = result  # Publish before shape/branch checks.
            require(type(result) is int and result >= 0, "invalid original fork result")
            return result
        except BaseException:
            self.unknown = True
            raise

    def wait(self):
        require(type(self.pid) is int and self.pid > 0 and not self.unknown, "no original wait custody")
        if self.status is not None:
            return self.status
        self.retired = True  # Never rearm numeric routes after a zero return.
        try:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            require(type(pid) is int and pid in (0, self.pid), "wrong original wait result")
            if pid:
                self.status = status
            return self.status
        except BaseException:
            self.unknown = True
            raise


def send(descriptor, data, deadline):
    require(type(data) is bytes and 0 < len(data) <= MAX_RECORD, "bounded record required")
    offset = 0
    while offset < len(data):
        remaining(deadline)
        _, ready, _ = select.select([], [descriptor], [], min(.01, remaining(deadline)))
        if ready:
            count = os.write(descriptor, data[offset:])
            require(type(count) is int and 0 < count <= len(data) - offset, "record write unknown")
            offset += count


def receive(descriptor, buffer, deadline):
    """One bounded original stream, including its genuine EOF observation."""
    remaining(deadline)
    ready, _, _ = select.select([descriptor], [], [], min(.01, remaining(deadline)))
    if not ready:
        return None
    data = os.read(descriptor, MAX_RECORD + 1 - len(buffer))
    if not data:
        return False
    buffer.extend(data)
    require(len(buffer) <= MAX_RECORD, "record exceeds bound")
    return True


def absent(group, *, route_live):
    require(route_live, "retired group observation")
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


def _worker(handles, parent, group, root, name, task, deadline, write_json, *, hard=None, progress=None):
    global CASE_DEADLINE, _ADAPTER_WORKER_DIAGNOSTIC, _ADAPTER_PROGRESS_WRITER
    code = WORKER_ERROR
    try:
        handles.close_except(("w-runr", "w-statew"))
        require(not handles.errors and os.getppid() == parent and os.getpgrp() == group, "worker original group setup")
        send(handles.get("w-statew"), b"READY\n", deadline)
        message = bytearray()
        while b"\n" not in message:
            require(os.getppid() == parent, "worker lost original anchor")
            require(receive(handles.get("w-runr"), message, deadline) is not False, "worker RUN EOF")
        require(bytes(message) == b"RUN\n", "worker RUN invalid")
        handles.close("w-runr")
        require(not handles.errors, "worker setup close failed")
        remaining(deadline)
        CASE_DEADLINE = deadline
        _ADAPTER_WORKER_DIAGNOSTIC = None
        _ADAPTER_PROGRESS_WRITER = None
        if ADAPTER_DIAGNOSTIC_CONTEXT is not None:
            try:
                _ADAPTER_WORKER_DIAGNOSTIC = {"context": ADAPTER_DIAGNOSTIC_CONTEXT, "pid": os.getpid(),
                                            "lock": threading.Lock(), "claimed": False, "first": None,
                                            "reserved": 16, "thread": threading.current_thread(),
                                            "target_claimed": False, "target": None}  # Before task.
            except Exception:
                pass  # An unavailable diagnostic slot never prevents the original task.
        if progress is not None:
            try:
                progress.bind_worker()
            except Exception:
                pass
        adapter_progress("task-entered")
        value = task()
        adapter_progress("task-returned")
        remaining(deadline)
        write_json(root / (name + ".json"), value)
        adapter_progress("result-write-returned")
        remaining(deadline)
        code = 0
    except BaseException as error:
        try:
            emit_adapter_failure(ADAPTER_DIAGNOSTIC_CONTEXT, "worker", "error",
                                 (type(error), error, BaseException.__dict__["__traceback__"].__get__(error, BaseException)),
                                 deadline=hard if hard is not None else deadline,
                                 command_first=_ADAPTER_WORKER_DIAGNOSTIC["first"] if _ADAPTER_WORKER_DIAGNOSTIC else None,
                                 command_reserved=_ADAPTER_WORKER_DIAGNOSTIC["reserved"] if _ADAPTER_WORKER_DIAGNOSTIC else 0,
                                 target_result=_ADAPTER_WORKER_DIAGNOSTIC["target"] if _ADAPTER_WORKER_DIAGNOSTIC else None)
        except BaseException:
            pass
        try:
            write_json(root / (name + "-error.json"), {"traceback": traceback.format_exc()})
        except BaseException:
            pass
    finally:
        handles.close_except()
        if handles.errors:
            code = WORKER_ERROR
        os._exit(code)


def _anchor(handles, launcher, home_group, root, name, task, run_deadline, hard, write_json, *, progress=None):
    code, moved, live_group, loss = WORKER_ERROR, False, True, False
    child = OriginalWait()
    own = os.getpid()
    try:
        handles.close_except(("l-controlr", "a-statew"))
        require(not handles.errors and os.getppid() == launcher, "anchor original owner missing")
        os.setpgid(0, 0)
        require(os.getpgrp() == own and os.getsid(0) != own, "anchor must not be a session leader")
        handles.pipe("w-run")
        handles.pipe("w-state")
        if child.fork() == 0:
            _worker(handles, own, own, root, name, task, run_deadline, write_json, hard=hard, progress=progress)
        handles.close("w-runr")
        handles.close("w-statew")
        worker_data, owner_data = bytearray(), bytearray()
        while b"\n" not in worker_data:
            require(os.getppid() == launcher, "anchor owner lost before worker admission")
            require(receive(handles.get("w-stater"), worker_data, run_deadline) is not False, "worker missing original readiness")
        require(bytes(worker_data) == b"READY\n" and os.getpgid(child.pid) == own, "wrong original worker group")
        os.setpgid(0, home_group)
        moved = True
        require(os.getpgrp() == home_group and os.getpgrp() != own and not handles.errors, "anchor move not confirmed")
        send(handles.get("a-statew"), b"ARMED " + str(child.pid).encode("ascii") + b"\n", run_deadline)
        while b"\n" not in owner_data:
            require(os.getppid() == launcher, "launcher disappeared before RUN")
            require(receive(handles.get("l-controlr"), owner_data, run_deadline) is not False, "launcher RUN EOF")
        require(bytes(owner_data) == b"RUN\n", "launcher RUN invalid")
        owner_data.clear()
        send(handles.get("w-runw"), b"RUN\n", run_deadline)
        handles.close("w-runw")
        stopped = False
        expired = False
        worker_eof = False
        while child.status is None or not worker_eof:
            remaining(hard)
            loss = loss or os.getppid() != launcher
            ready, _, _ = select.select([handles.get("l-controlr")], [], [], 0)
            if ready:
                value = os.read(handles.get("l-controlr"), MAX_RECORD)
                require(value in (b"", b"STOP\n"), "unexpected original launcher control")
                loss = True
            expired = expired or time.monotonic() >= run_deadline
            if (loss or expired) and not stopped:
                # A's own still-live PID reserves its former G while A is
                # outside it. This is independent of W's retired wait routes.
                try:
                    os.killpg(own, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                stopped = True
            if child.status is None:
                child.wait()
            if not worker_eof:
                value = receive(handles.get("w-stater"), worker_data, hard)
                worker_eof = value is False
                require(bytes(worker_data) == b"READY\n", "unexpected worker status bytes")
        while not absent(own, route_live=live_group):
            remaining(hard)
            if not stopped:
                os.killpg(own, signal.SIGKILL)
                stopped = True
            time.sleep(min(.002, remaining(hard)))
        live_group = False
        handles.close("w-stater")
        require(not handles.errors, "anchor original producer descriptors unresolved")
        if not loss:
            expired = expired or time.monotonic() >= run_deadline
            send(handles.get("a-statew"), (b"EXPIRED " if expired else b"SETTLED ") +
                 str(os.waitstatus_to_exitcode(child.status)).encode("ascii") + b"\n", hard)
            owner_data.clear()
            while b"\n" not in owner_data:
                if os.getppid() != launcher or receive(handles.get("l-controlr"), owner_data, hard) is False:
                    loss = True
                    break
            require(loss or bytes(owner_data) == b"RELEASE\n", "anchor release invalid")
        code = 0
    except BaseException:
        # Revoke the original barrier first. A child that never received RUN
        # can only fail/exit; it cannot use a later cleanup grace to begin work.
        handles.close("w-runw")
        if not moved:
            try:
                remaining(hard)
                # This is A moving *itself* for cleanup, not a route derived
                # from a status PID or an attempted/consumed child wait.
                os.setpgid(0, home_group)
                moved = os.getpgrp() == home_group and home_group != own
            except BaseException:
                pass
        # No guessed post-wait child route. If still outside G, only A's own
        # original reservation can contain it within the same original tail.
        if moved and live_group:
            try:
                os.killpg(own, signal.SIGKILL)
            except BaseException:
                pass
        if moved and not child.unknown and child.pid:
            try:
                while child.status is None:
                    remaining(hard)
                    child.wait()
                    time.sleep(min(.002, remaining(hard)))
            except BaseException:
                pass
    finally:
        handles.close_except()
        if handles.errors:
            code = WORKER_ERROR
        os._exit(code)


def run_worker(root: Path, name: str, task, *, timeout=20, expect=0, deadline=None, write_json):
    global ADAPTER_CASE_FAILURE, ADAPTER_CASE_PROGRESS
    ADAPTER_CASE_FAILURE = None
    ADAPTER_CASE_PROGRESS = None
    require(threading.active_count() == 1, "warm launcher must be single threaded")
    require(type(timeout) in (int, float) and not isinstance(timeout, bool) and math.isfinite(timeout) and timeout > 0,
            "bounded timeout required")
    require(deadline is None or type(deadline) is float and math.isfinite(deadline),
            "finite original caller endpoint required")
    require(type(expect) is int and expect in {0, 73, -signal.SIGKILL}, "finite expected case status required")
    started = time.monotonic()
    hard = min(started + timeout + 5, deadline if deadline is not None else math.inf)
    require(math.isfinite(hard), "finite original hard endpoint required")
    run_deadline = min(started + timeout, hard)
    remaining(run_deadline)  # An expired caller endpoint admits no pipe or fork.
    owner, home_group = os.getpid(), os.getpgrp()
    handles, anchor = Handles(), OriginalWait()
    group_live, armed, settled, eof = True, False, False, False
    worker_pid = worker_code = anchor_code = None
    observed_expiry = anchor_expired = False
    primary = None
    cleanup_errors = []
    progress = observed_progress = None
    try:
        if ADAPTER_DIAGNOSTIC_CONTEXT is not None and type(name) is str and name in ADAPTER_PROGRESS_CASES:
            try:
                progress = _AdapterProgress(ADAPTER_DIAGNOSTIC_CONTEXT, name, started, owner)
                progress.mapping = mmap.mmap(-1, 4096)  # Anonymous, shared by the original fork only.
            except Exception:
                pass
        handles.pipe("l-control")
        handles.pipe("a-state")
        if anchor.fork() == 0:
            _anchor(handles, owner, home_group, root, name, task, run_deadline, hard, write_json, progress=progress)
        handles.close("l-controlr")
        handles.close("a-statew")
        require(not handles.errors, "launcher setup close unresolved")
        data = bytearray()
        while not settled:
            result = receive(handles.get("a-stater"), data, hard if armed else run_deadline)
            observed_expiry = observed_expiry or time.monotonic() >= run_deadline
            require(result is not False, "anchor did not provide original settlement")
            while b"\n" in data:
                line, _, suffix = data.partition(b"\n")
                data[:] = suffix
                line = bytes(line)  # Freeze this exact completed original frame before parsing.
                if not armed:
                    require(line.startswith(b"ARMED ") and line[6:].isdigit(), "anchor readiness invalid")
                    worker_pid = int(line[6:])
                    require(worker_pid > 0 and worker_pid != anchor.pid and not anchor.retired,
                            "anchor original worker binding invalid")
                    armed = True
                    write_json(root / "last-worker.json", {"pid": worker_pid, "anchor": anchor.pid, "diagnosticOnly": True})
                    send(handles.get("l-controlw"), b"RUN\n", run_deadline)
                else:
                    require(not settled, "duplicate anchor settlement")
                    anchor_expired, worker_code = terminal_record(line)
                    settled = True
        require(not data and absent(anchor.pid, route_live=group_live) and not anchor.retired,
                "original pinned group not empty before anchor wait")
        group_live = False  # Irreversible BEFORE the first consuming A wait.
        send(handles.get("l-controlw"), b"RELEASE\n", hard)
        handles.close("l-controlw")
        while anchor.status is None or not eof:
            remaining(hard)
            if anchor.status is None:
                anchor.wait()
            if not eof:
                eof = receive(handles.get("a-stater"), data, hard) is False
                require(not data, "unexpected post-settlement anchor data")
        anchor_code = os.waitstatus_to_exitcode(anchor.status)  # The existing original conversion, exactly once.
        require(anchor_code == 0 and worker_code == expect,
                f"case {name} expected {expect}, observed {worker_code}")
        observed_expiry = observed_expiry or time.monotonic() >= run_deadline
        require((anchor_expired and worker_code == -signal.SIGKILL) if expect == -signal.SIGKILL else
                (not anchor_expired and not observed_expiry), "original run deadline cannot become late success")
    except BaseException as error:
        primary = error
    finally:
        handles.close("l-controlw")  # Genuine EOF makes original A stop.
        if os.getpid() == owner and anchor.pid and not anchor.unknown and anchor.status is None:
            try:
                if group_live:
                    # Original A remains entirely unpolled. Failure cannot
                    # reuse a diagnostic worker PID or rearm a waited anchor.
                    require(not anchor.retired, "anchor route already retired")
                    if armed:
                        try:
                            os.killpg(anchor.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    while not absent(anchor.pid, route_live=group_live):
                        remaining(hard)
                        time.sleep(min(.002, remaining(hard)))
                    group_live = False
                while anchor.status is None:
                    remaining(hard)
                    anchor.wait()
                    time.sleep(min(.002, remaining(hard)))
            except BaseException as error:
                cleanup_errors.append(error)
        handles.close_except()
        cleanup_errors.extend(handles.errors)
        if os.getpid() != owner:
            os._exit(WORKER_ERROR)
        if progress is not None:
            try:
                if (settled and worker_code is not None and anchor.status is not None and not anchor.unknown
                        and anchor_code is not None and not group_live and eof):
                    observed_progress = progress.snapshot(worker_pid)
            except BaseException as error:
                if primary is None:
                    primary = error
                else:
                    cleanup_errors.append(error)  # Cancellation cannot replace an already-latched primary.
            finally:
                progress.close(cleanup_errors)
    try:
        if primary is not None:
            primary._case_cleanup_errors = tuple(cleanup_errors)
            if cleanup_errors:
                primary.add_note("independent case cleanup errors: " + ",".join(type(error).__name__ for error in cleanup_errors))
            raise primary
        if cleanup_errors:
            raise BaseExceptionGroup("original case cleanup is unconfirmed", cleanup_errors)
        require(anchor.status is not None and not anchor.unknown and not group_live and settled and eof,
                "original case custody incomplete")
        remaining(hard)
        if expect != -signal.SIGKILL:
            remaining(run_deadline)
    except BaseException:
        try:
            if ADAPTER_DIAGNOSTIC_CONTEXT is not None:
                # Only original variables after failure/cleanup. No new wait,
                # census, filesystem read, expiry inference or finality claim.
                ADAPTER_CASE_FAILURE = (ADAPTER_DIAGNOSTIC_CONTEXT,
                                       (expect, worker_code, anchor_code, settled, anchor_expired if settled else None))
                if observed_progress is not None and progress.context is ADAPTER_DIAGNOSTIC_CONTEXT:
                    ADAPTER_CASE_PROGRESS = (ADAPTER_DIAGNOSTIC_CONTEXT, observed_progress)
        except BaseException:
            pass
        raise
    return {"pid": worker_pid, "anchor": anchor.pid, "exit": worker_code,
            "originalAnchorWait": True, "originalWorkerWait": True,
            "originalStatusEOF": True, "groupAbsentBeforeAnchorWait": True,
            "deadlineTest": expect == -signal.SIGKILL, "runDeadlineExpired": anchor_expired or observed_expiry,
            "elapsed": time.monotonic() - started}
