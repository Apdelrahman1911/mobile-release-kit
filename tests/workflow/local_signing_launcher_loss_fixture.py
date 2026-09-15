"""One genuine L loss, observed through the unchanged original L/A/W owner.

The retained extra control writer makes EOF unavailable as the reason A stops W.
Events are bounded observations, not substitutes for L's now-missing A wait.
Only the existing disposable Session may retire this intentional-UNKNOWN case.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
if __name__ == "__main__":
    sys.path[:0] = [sys.argv.pop(1), str(ROOT / "tests")]

from workflow import local_signing_case_owner as owner

FRAME = b"STARTED\n"
MAX_EVENTS, MAX_EVENT_BYTES = 24, 512
_FIELDS = {
    ("L", "run_sent"): ("before_deadline",),
    ("L", "readiness"): ("exact_frame", "eof", "readiness_closed", "anchor_wait_attempted", "before_deadline"),
    ("A", "held_writer"): ("launcher", "home_group"),
    ("A", "worker_run"): ("worker", "group"),
    ("A", "parent_loss"): ("launcher", "observed_parent", "held_writer", "before_deadline"),
    ("A", "control_route"): ("route",),
    ("A", "group_signal"): ("group", "signal", "outside", "before_deadline"),
    ("A", "worker_wait"): ("worker", "exitcode", "terminal"),
    ("A", "worker_eof"): ("worker",),
    ("A", "group_absent"): ("group", "reserved", "outside", "before_deadline"),
    ("A", "exit_attempt"): ("exitAttemptCode", "original_group_retired", "production_handles_closed",
                               "extra_writer_closed", "readiness_closed", "before_deadline"),
    ("W", "inherited_writer_closed"): ("anchor", "group"),
    ("W", "started"): ("anchor", "before_deadline"),
}
_REQUIRED = frozenset(_FIELDS) - {("A", "control_route")}


def require(condition, message):
    if not condition:
        raise AssertionError("launcher-loss fixture: " + message)


def _descriptor_identity(details):
    return details.st_dev, details.st_ino, details.st_mode, details.st_rdev


def validate_events(stdout, stderr, launcher):
    """Pure already-captured bytes only; never a post-loss process/FS probe."""
    require(type(launcher) is int and launcher > 1, "original launcher binding")
    require(type(stdout) is bytes and type(stderr) is bytes and not stderr,
            "original captures contain unexpected output")
    require(0 < len(stdout) <= MAX_EVENTS * MAX_EVENT_BYTES and stdout.endswith(b"\n"), "bounded complete events")
    lines = stdout.splitlines(keepends=True)
    require(len(lines) <= MAX_EVENTS, "event count")
    records, positions = {}, {}
    for index, line in enumerate(lines):
        require(0 < len(line) <= MAX_EVENT_BYTES and line.endswith(b"\n"), "atomic event size")
        try:
            row = json.loads(line)
            canonical = json.dumps(row, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"
        except (ValueError, UnicodeError, TypeError):
            raise AssertionError("launcher-loss fixture: malformed event") from None
        require(type(row) is dict and canonical == line, "canonical event")
        key = row.get("role"), row.get("event")
        require(all(type(value) is str for value in key) and key in _REQUIRED and key not in records,
                "missing/duplicate/unexpected lifecycle event")
        require(set(row) == {"role", "event", "pid", *_FIELDS[key]}
                and type(row["pid"]) is int and 1 < row["pid"] < 2**31, "event shape")
        records[key], positions[key] = row, index
    require(set(records) == _REQUIRED, "incomplete original lifecycle observations")
    anchor = records["A", "held_writer"]["pid"]
    worker = records["W", "inherited_writer_closed"]["pid"]
    require(len({launcher, anchor, worker}) == 3, "original role identities overlap")
    identities = {"L": launcher, "A": anchor, "W": worker}
    for (role, _event), row in records.items():
        require(row["pid"] == identities[role], "role changed original identity")
        for field in ("before_deadline", "exact_frame", "eof", "readiness_closed", "held_writer", "outside",
                      "terminal", "reserved", "original_group_retired", "production_handles_closed", "extra_writer_closed"):
            if field in row:
                require(row[field] is True, "missing positive " + field)
        for field in ("launcher", "home_group", "worker", "group", "anchor", "observed_parent", "signal",
                      "exitcode", "exitAttemptCode"):
            if field in row:
                require(type(row[field]) is int, "nonintegral " + field)
    require(records["A", "held_writer"]["launcher"] == records["A", "held_writer"]["home_group"] == launcher,
            "original launcher/group binding")
    require(records["W", "inherited_writer_closed"]["anchor"] ==
            records["W", "inherited_writer_closed"]["group"] == records["W", "started"]["anchor"] == anchor,
            "original worker binding")
    require(all(records["A", event]["worker"] == worker for event in ("worker_run", "worker_wait", "worker_eof"))
            and all(records["A", event]["group"] == anchor for event in ("worker_run", "group_signal", "group_absent")),
            "original reserved group or worker changed")
    loss = records["A", "parent_loss"]
    require(loss["launcher"] == launcher and 0 < loss["observed_parent"] != launcher, "not actual parent loss")
    require(records["A", "group_signal"]["signal"] == signal.SIGKILL
            and records["A", "worker_wait"]["exitcode"] == -signal.SIGKILL, "worker did not have original killed wait")
    require(records["A", "exit_attempt"]["exitAttemptCode"] == 0
            and records["L", "readiness"]["anchor_wait_attempted"] is False, "missing wait cannot become finality")

    def precedes(role, first, second):
        require(positions[role, first] < positions[role, second], "original role event order")

    precedes("L", "run_sent", "readiness")
    precedes("W", "inherited_writer_closed", "started")
    for first, second in (("held_writer", "worker_run"), ("worker_run", "parent_loss"),
                          ("parent_loss", "group_signal"), ("group_absent", "exit_attempt")):
        precedes("A", first, second)
    # Actual wait and actual EOF can arrive in either order, but both precede
    # retirement while A still reserves G. No cross-process clock ordering.
    for event in ("worker_wait", "worker_eof"):
        precedes("A", "group_signal", event)
        precedes("A", event, "group_absent")
    return {"finality": "UNKNOWN", "originalAnchorWait": False, "anchorExitAttemptCode": 0,
            "originalWorkerWait": True, "originalWorkerStatusEOF": True,
            "groupAbsentWhileReserved": True, "domainDisposalRequired": True}


class _ObservedOS:
    """Only the case-owner module sees this pass-through observation proxy."""
    def __init__(self, observation):
        self.observation = observation

    def __getattr__(self, name):
        return getattr(os, name)

    def getppid(self):
        value = os.getppid()
        state = self.observation
        if state.role == "A" and state.ran and value != state.launcher and not state.lost:
            state.lost = True
            require(state.held is not None and _descriptor_identity(os.fstat(state.held)) == state.held_identity,
                    "actual control writer lost before parent observation")
            state.emit("parent_loss", launcher=state.launcher, observed_parent=value,
                       held_writer=True, before_deadline=time.monotonic() < state.deadline)
        return value

    def read(self, descriptor, count):
        value = os.read(descriptor, count)
        state = self.observation
        if state.role == "A" and state.ran and descriptor == state.handles.values.get("l-controlr"):
            state.emit("control_route", route="eof" if value == b"" else "stop" if value == b"STOP\n" else "unexpected")
        return value

    def killpg(self, group, signum):
        value = os.killpg(group, signum)
        state = self.observation
        if signum:
            require(state.role == "A" and state.lost and state.ran and group == os.getpid()
                    and signum == signal.SIGKILL and not state.group_absent, "not original loss containment")
            state.emit("group_signal", group=group, signal=int(signum), outside=os.getpgrp() == state.home_group != group,
                       before_deadline=time.monotonic() < state.deadline)
        return value

    def _exit(self, code):
        # Instrumentation must NEVER unwind out of the child boundary, replace
        # the original requested status, or keep A alive because a witness failed.
        try:
            if self.observation.role == "A":
                original = sys._getframe(1)
                require(original.f_code is self.observation.real_anchor.__code__, "not the original anchor exit call")
                retired = original.f_locals.get("live_group") is False
                del original
                self.observation.anchor_exit(code, original_group_retired=retired)
        finally:
            self.observation.real_exit(code)


class _Observation:
    def __init__(self):
        self.real_exit = os._exit
        self.real_close = owner.Handles.close
        self.real_send, self.real_receive = owner.send, owner.receive
        self.real_wait, self.real_absent = owner.OriginalWait.wait, owner.absent
        self.real_anchor, self.real_worker = owner._anchor, owner._worker
        self.role, self.handles, self.held = "L", None, None
        self.held_identity = self.launcher = self.home_group = self.worker = None
        self.deadline = self.hard = None
        self.ran = self.lost = self.group_absent = self.duplicate_attempted = self.launcher_waited = False
        self.worker_slot = None
        self.events = set()
        self.readiness = owner.Handles()
        self.readiness.pipe("started")

    def emit(self, event, **fields):
        key = self.role, event
        require(key in _FIELDS and set(fields) == set(_FIELDS[key]) and key not in self.events, "event inventory")
        require(len(self.events) < MAX_EVENTS and time.monotonic() < self.hard, "original event bound")
        self.events.add(key)
        raw = json.dumps({"role": self.role, "event": event, "pid": os.getpid(), **fields},
                         sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"
        require(len(raw) <= MAX_EVENT_BYTES, "atomic event bound")
        require(os.write(1, raw) == len(raw), "original event write incomplete")

    def close(self, handles, name):
        if self.role == "A" and handles is self.handles and name == "l-controlw" and not self.duplicate_attempted:
            self.duplicate_attempted = True
            try:
                original = handles.get(name)
                self.held = os.dup(original)
                self.held_identity = _descriptor_identity(os.fstat(original))
                require(_descriptor_identity(os.fstat(self.held)) == self.held_identity,
                        "extra writer is not the actual original duplicate")
                self.emit("held_writer", launcher=self.launcher, home_group=self.home_group)
            finally:
                self.real_close(handles, name)  # Never inhibit the original close.
        else:
            self.real_close(handles, name)
        if self.role == "L" and name == "l-controlr":
            self.handles = handles

    def anchor(self, handles, launcher, home_group, root, name, task, deadline, hard, write_json, *, progress=None,
               matrix_context=None):
        try:
            self.role, self.handles = "A", handles
            self.launcher, self.home_group, self.deadline, self.hard = launcher, home_group, deadline, hard
            self.readiness.close("startedr")
            require(not self.readiness.errors, "anchor readiness reader close")
            self.real_anchor(handles, launcher, home_group, root, name, task, deadline, hard, write_json,
                             progress=progress, matrix_context=matrix_context)
        finally:
            # Includes instrumentation failures before entering the real owner.
            # Never fall into the copied launcher branch or its cleanup.
            self.real_exit(owner.WORKER_ERROR)

    def worker_entry(self, handles, parent, group, root, name, task, deadline, write_json, *, hard=None, progress=None,
                     matrix_context=None):
        try:
            self.role, self.handles, self.deadline = "W", handles, deadline
            require(self.held is not None, "worker did not inherit original duplicate")
            descriptor, self.held = self.held, None
            os.close(descriptor)
            self.emit("inherited_writer_closed", anchor=parent, group=group)
            self.real_worker(handles, parent, group, root, name, task, deadline, write_json,
                             hard=hard, progress=progress, matrix_context=matrix_context)
        finally:
            # A W setup/witness failure must self-exit, never enter A's copied
            # parent branch and accidentally use its wait/group ownership.
            self.real_exit(owner.WORKER_ERROR)

    def send(self, descriptor, data, deadline):
        if self.role == "A" and data.startswith(b"ARMED "):
            require(descriptor == self.handles.get("a-statew") and data.endswith(b"\n"), "original ARMED binding")
            self.worker = int(data[6:-1])
            require(data == b"ARMED " + str(self.worker).encode("ascii") + b"\n" and self.worker > 1,
                    "original ARMED worker")
            self.readiness.close("startedw")
            require(not self.readiness.values and not self.readiness.errors, "anchor readiness writer close")
        self.real_send(descriptor, data, deadline)
        if self.role == "A" and data == b"RUN\n":
            require(descriptor == self.handles.get("w-runw"), "original W RUN binding")
            self.ran = True
            self.emit("worker_run", worker=self.worker, group=os.getpid())
        elif self.role == "L" and data == b"RUN\n":
            require(descriptor == self.handles.get("l-controlw"), "original L RUN binding")
            self.deadline, self.hard = deadline, deadline
            self.emit("run_sent", before_deadline=time.monotonic() < deadline)
            self.readiness.close("startedw")
            require(not self.readiness.errors, "launcher readiness writer close")
            received = bytearray()
            while self.real_receive(self.readiness.get("startedr"), received, deadline) is not False:
                require(len(received) <= len(FRAME), "worker readiness frame overflow")
            require(bytes(received) == FRAME, "worker readiness frame/EOF missing")
            self.readiness.close("startedr")
            require(not self.readiness.values and not self.readiness.errors, "launcher readiness close")
            self.emit("readiness", exact_frame=True, eof=True, readiness_closed=True,
                      anchor_wait_attempted=self.launcher_waited, before_deadline=time.monotonic() < deadline)
            self.real_exit(73)  # Actual L death, never a numeric L/group signal.

    def receive(self, descriptor, buffer, deadline):
        value = self.real_receive(descriptor, buffer, deadline)
        if self.role == "A" and self.ran and descriptor == self.handles.values.get("w-stater") and value is False:
            self.emit("worker_eof", worker=self.worker)
        return value

    def wait(self, slot):
        if self.role == "L":
            self.launcher_waited = True
            # A pre-RUN failure may have no event cutoff yet. Observation must
            # not prevent/replace the original wait or its original error.
            return self.real_wait(slot)
        elif self.role == "A":
            if self.worker_slot is None:
                self.worker_slot = slot
            require(self.worker_slot is slot and slot.pid == self.worker, "actual original worker wait slot")
        value = self.real_wait(slot)
        if self.role == "A" and value is not None:
            self.emit("worker_wait", worker=slot.pid, exitcode=os.waitstatus_to_exitcode(value),
                      terminal=os.WIFEXITED(value) or os.WIFSIGNALED(value))
        return value

    def absent(self, group, *, route_live):
        value = self.real_absent(group, route_live=route_live)
        if self.role == "A" and value:
            require(self.lost and group == os.getpid() and route_live and not self.group_absent,
                    "original reserved group absence")
            self.group_absent = True
            self.emit("group_absent", group=group, reserved=True, outside=os.getpgrp() == self.home_group != group,
                      before_deadline=time.monotonic() < self.deadline)
        return value

    def anchor_exit(self, code, *, original_group_retired):
        try:
            closed = self.handles is not None and not self.handles.values and not self.handles.errors
            require(self.held is not None and self.lost and self.group_absent, "incomplete anchor loss cleanup")
        finally:
            descriptor, self.held = self.held, None
            if descriptor is not None:
                os.close(descriptor)  # One original duplicate close, no retry.
        self.emit("exit_attempt", exitAttemptCode=code, original_group_retired=original_group_retired,
                  production_handles_closed=closed, extra_writer_closed=True,
                  readiness_closed=not self.readiness.values and not self.readiness.errors,
                  before_deadline=time.monotonic() < self.deadline)

    def task(self):
        # Invoked only by the actual W after production's exact RUN admission.
        self.real_send(self.readiness.get("startedw"), FRAME, self.deadline)
        self.emit("started", anchor=os.getppid(), before_deadline=time.monotonic() < self.deadline)
        self.readiness.close("startedw")
        require(not self.readiness.values and not self.readiness.errors, "worker readiness close")
        time.sleep(30)  # Longer than the unchanged case20, hard25, and P12.
        raise AssertionError("launcher-loss worker escaped original containment")

    def install(self):
        owner.os = _ObservedOS(self)
        observation = self
        owner.Handles.close = lambda handles, name: observation.close(handles, name)
        owner.OriginalWait.wait = lambda slot: observation.wait(slot)
        owner.send, owner.receive, owner.absent = self.send, self.receive, self.absent
        owner._anchor, owner._worker = self.anchor, self.worker_entry


def main():
    require(len(sys.argv) == 2, "fixed root argument required")
    root = Path(sys.argv[1])
    require(os.getpid() == os.getpgrp() == os.getsid(0), "original driver private session")
    os.set_blocking(1, False)  # Before either fork; one <=PIPE_BUF write/event.
    observation = _Observation()
    observation.install()
    owner.run_worker(root, "launcher-loss", observation.task, timeout=20,
                     write_json=lambda path, value: path.write_text(json.dumps(value)))
    raise AssertionError("original launcher did not actually exit")


if __name__ == "__main__":
    main()
