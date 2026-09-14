"""Optional bounded matrix failure DATA; never custody, coverage or a receipt.

The original phase prebinds source filenames before fixture/product work. This
module never resolves paths, reads source/evidence, starts work or grants time.
"""
from __future__ import annotations

import json
import math
import os
import re
import sys
import threading
import time
import types
from subprocess import CompletedProcess


PREFIX = "MRK_SIGNING_MATRIX_FAILURE="
WORKER_PREFIX = "MRK_SIGNING_MATRIX_WORKER_FAILURE="
STAGES = ("admission", "helper", "typed-result", "persist", "cleanup", "postconditions", "publication")
SEMANTIC_STEPS = ("healthy", "seed", "recovery", "semantic-main", "semantic-resolution")
PUBLIC_FILE = re.compile(r"(?:tests|\.github/scripts|src/mobile_release)/(?:[A-Za-z_][A-Za-z0-9_-]*/)*[A-Za-z_][A-Za-z0-9_-]*\.py\Z")
CASE_ID = re.compile(r"[0-9a-f]{64}\Z")
REPORTED_FRAME = re.compile(r'  File "([^"\r\n]+)", line ([1-9][0-9]{0,5}), in ([^\r\n]{1,256})\Z')
_PROFILE_CAPTURE = "_mrk_matrix_original_profile_capture"
_CASE_CAPTURE = "_mrk_matrix_original_case_capture"
CURRENT = None
CURRENT_WORKER = None


def _require(value):
    if not value:
        raise ValueError("matrix diagnostic unavailable")


def _before(context):
    _require(time.monotonic() < context.deadline)


class Phase:
    """One invocation: semantic L48/W16; delegated G L0/W64; four locations."""

    def __init__(self, phase, deadline, operating_system, shard, identifiers, regression_ids, source_map,
                 child_bindings=()):
        _require(type(phase) is str and phase in {"source", "wheel"}
                 and type(deadline) is float and math.isfinite(deadline)
                 and type(operating_system) is str and operating_system in {"ubuntu-24.04", "macos-26"}
                 and type(shard) is int and 0 <= shard < 16)
        _require(type(identifiers) is tuple and 0 < len(identifiers) <= 512
                 and all(type(value) is str and CASE_ID.fullmatch(value) for value in identifiers)
                 and len(set(identifiers)) == len(identifiers)
                 and type(regression_ids) is tuple and len(set(regression_ids)) == len(regression_ids)
                 and all(type(value) is str and value in identifiers for value in regression_ids))
        _require(type(source_map) is tuple and 0 < len(source_map) <= 512
                 and all(type(pair) is tuple and len(pair) == 2
                         and type(pair[0]) is str and 0 < len(pair[0]) <= 4096
                         and type(pair[1]) is str and len(pair[1]) <= 256 and PUBLIC_FILE.fullmatch(pair[1])
                         for pair in source_map)
                 and len({pair[0] for pair in source_map}) == len(source_map)
                 and len({pair[1] for pair in source_map}) == len(source_map))
        _require(type(child_bindings) is tuple and len(child_bindings) <= len(identifiers)
                 and all(type(row) is tuple and len(row) == 3
                         and type(row[0]) is str and row[0] in identifiers
                         and type(row[1]) is str and row[1] in {"profile-signal", "semantic-worker"}
                         and type(row[2]) is tuple and row[2] and len(set(row[2])) == len(row[2])
                         and all(type(value) is str and 0 < len(value) <= 64 for value in row[2])
                         and ((row[0] in regression_ids and len(row[2]) == 1) if row[1] == "profile-signal"
                              else row[0] not in regression_ids and all(value in SEMANTIC_STEPS for value in row[2]))
                         for row in child_bindings)
                 and len({row[0] for row in child_bindings}) == len(child_bindings))
        self.phase, self.deadline = phase, deadline
        self.identifiers, self.regression_ids, self.source_map = identifiers, regression_ids, source_map
        self.child_bindings = child_bindings
        self.pid, self.thread = os.getpid(), threading.current_thread()
        self.case_id, self.stage = None, "admission"
        # Reserve W's16 once, BEFORE any fork. Neither another step nor an
        # unavailable callback can renew the remaining parent budget.
        self.g_seen, self.g_failure, self.child, self.budget = False, None, None, [48]
        self.emitted, self.available = False, True
        _before(self)


def _owned(context):
    return (type(context) is Phase and context.available and context.pid == os.getpid()
            and context.thread is threading.current_thread())


def _selectors(context, role):
    return next((values for identifier, actual_role, values in context.child_bindings
                 if identifier == context.case_id and actual_role == role), ())


def _worker_role(context, step):
    if step == "regression" and context.case_id in context.regression_ids:
        return "regression-worker"
    if step in _selectors(context, "semantic-worker"):
        return "semantic-worker"
    return None


def _g_context():
    worker = CURRENT_WORKER
    if (type(worker) is Worker and worker.context is CURRENT and worker.role == "regression-worker"
            and worker.pid == os.getpid() and worker.pid != worker.context.pid
            and worker.thread is threading.current_thread() and not worker.emitted):
        return worker
    return None


def _attributes(error):
    return BaseException.__dict__["__dict__"].__get__(error, BaseException)


def attach_profile_capture(error, result, mode):
    """Private original-result retention AFTER its assertion, never publication."""
    context = _g_context()
    try:
        _require(context is not None and context.stage == "helper" and not context.g_seen
                 and type(error) is AssertionError and type(result) is CompletedProcess
                 and type(mode) is str and mode in _selectors(context, "profile-signal"))
        _before(context)
        attributes = _attributes(error)
        if _PROFILE_CAPTURE not in attributes:
            attributes[_PROFILE_CAPTURE] = (context, context.case_id, mode, result)
    except BaseException:
        pass  # The caller bare-reraises the same already-created assertion.


def _profile_child(context, exception):
    retained = _attributes(exception).pop(_PROFILE_CAPTURE, None)
    if retained is None:
        return None
    _require(type(retained) is tuple and len(retained) == 4
             and retained[0] is context and retained[1] == context.case_id
             and retained[2] in _selectors(context, "profile-signal"))
    result = retained[3]
    _require(type(result) is CompletedProcess and type(result.returncode) is int
             and -128 <= result.returncode <= 255 and result.returncode != 0
             and type(result.stdout) is str and len(result.stdout) <= 65536
             and type(result.stderr) is str and len(result.stderr) <= 65536)
    # run_owned's strict UTF-8 decode makes these the actual captured lengths;
    # no replacement decoding, formatted assertion or filesystem read.
    stdout_bytes, stderr_bytes = len(result.stdout.encode("utf-8")), len(result.stderr.encode("utf-8"))
    _require(stdout_bytes <= 65536 and stderr_bytes <= 65536 and context.budget[0] >= 32)
    context.budget[0] -= 32  # Reserve before any optional text scan, never renew.
    value = {"role": "profile-signal", "returncode": result.returncode,
             "stdoutBytes": stdout_bytes, "stderrBytes": stderr_bytes,
             "stderrKind": "unavailable" if result.stderr else "empty", "locations": []}
    if stderr_bytes > 8192 or not result.stderr.endswith("\n"):
        return value
    lines = result.stderr.split("\n", 32)
    if lines[-1] == "":
        lines.pop()
    if len(lines) > 32 or not lines or lines[0] != "Traceback (most recent call last):":
        return value
    locations = []
    for line in lines:  # Every physical line, not only allowlisted frames.
        _before(context)
        if not line.startswith("  File "):
            continue
        match = REPORTED_FRAME.fullmatch(line)
        if match is None:
            return value
        filename, number, _function = match.groups()
        public = next((relative for actual, relative in context.source_map if filename == actual), None)
        if public is not None:
            locations.append({"file": public, "line": int(number)})
            locations = locations[-2:]
    if locations:
        value.update(stderrKind="stderr-reported", locations=locations)
    return value


class Worker:
    """Pre-fork immutable bindings plus one W-local optional emission latch."""

    def __init__(self, context, step, deadline):
        self.context, self.case_id, self.step = context, context.case_id, step
        self.role = _worker_role(context, step)
        self.phase, self.source_map = context.phase, context.source_map
        self.child_bindings, self.regression_ids = context.child_bindings, context.regression_ids
        self.stage = "helper"
        self.deadline = min(context.deadline, deadline)
        self.pid = self.thread = None
        self.emitted = False
        self.g_seen, self.g_failure, self.child, self.budget = False, None, None, [64]


def prepare_worker(step, deadline):
    context = CURRENT
    try:
        _require(_owned(context) and context.stage == "helper" and not context.emitted
                 and type(step) is str and _worker_role(context, step) is not None
                 and type(deadline) is float and math.isfinite(deadline))
        _before(context)
        return Worker(context, step, deadline)
    except BaseException:
        return None


def enter_worker(worker):
    global CURRENT_WORKER
    try:
        _require(type(worker) is Worker and worker.context is CURRENT and worker.pid is None
                 and worker.role is not None and worker.role == _worker_role(worker.context, worker.step)
                 and os.getpid() != worker.context.pid and threading.current_thread() is threading.main_thread())
        _before(worker)
        worker.pid, worker.thread = os.getpid(), threading.current_thread()
        CURRENT_WORKER = worker  # W-local diagnostics only; inherited Phase custody is unchanged.
    except BaseException:
        pass


def attach_case_capture(error, worker, observed):
    """Only original launcher locals AFTER failure and original cleanup."""
    try:
        context = CURRENT
        _require(_owned(context) and type(worker) is Worker and worker.context is context
                 and worker.case_id == context.case_id and context.stage == "helper"
                 and worker.role is not None and worker.role == _worker_role(context, worker.step))
        _before(context)
        attributes = _attributes(error)
        if _CASE_CAPTURE not in attributes:
            attributes[_CASE_CAPTURE] = (worker, observed)
    except BaseException:
        pass


def _case_child(context, exception):
    retained = _attributes(exception).pop(_CASE_CAPTURE, None)
    if retained is None:
        return None
    _require(type(retained) is tuple and len(retained) == 2)
    worker, observed = retained
    _require(type(worker) is Worker and worker.context is context and worker.case_id == context.case_id
             and worker.role is not None and worker.role == _worker_role(context, worker.step)
             and type(observed) is tuple and len(observed) == 5)
    expected, child, anchor, parsed, expired = observed
    _require(type(expected) is int and expected in {0, 73, -9}
             and (worker.role != "regression-worker" or expected == 0)
             and all(value is None or type(value) is int and -128 <= value <= 255 for value in (child, anchor))
             and type(parsed) is bool and (child is not None) == parsed
             and (type(expired) is bool if parsed else expired is None))
    return {"role": worker.role, "step": worker.step, "expectedExit": expected,
            "workerExit": child, "anchorExit": anchor, "terminalParsed": parsed, "anchorExpired": expired}


def emit_worker(worker, error):
    """Original W exception DATA via existing stderr, not its launcher's memory."""
    if type(worker) is not Worker or worker.emitted:
        return None
    worker.emitted = True
    try:
        _require(worker.context is CURRENT and worker.pid == os.getpid()
                 and worker.thread is threading.current_thread() and worker.pid != worker.context.pid
                 and worker.case_id == worker.context.case_id
                 and worker.role is not None and worker.role == _worker_role(worker.context, worker.step))
        _before(worker)
        exception, frame = _actual(error)
        if worker.role == "regression-worker":
            original, child = worker.g_failure, worker.child
            maximum = 4 - (len(original["locations"]) if original is not None else 0) \
                - (len(child["locations"]) if child is not None else 0)
            _require(maximum >= 0 and worker.budget[0] >= 16)
            worker.budget[0] -= 16  # Reserve fixed outer16; unavailable inner work never renews it.
            record = {"schema": 2, "phase": worker.phase, "caseId": worker.case_id, "step": worker.step,
                      "role": worker.role, "category": _category(exception),
                      "locations": _locations(frame, worker.source_map, [16], maximum),
                      "originalGFailure": original, "child": child}
        else:
            record = {"schema": 1, "phase": worker.phase, "caseId": worker.case_id, "step": worker.step,
                      "category": _category(exception), "locations": _locations(frame, worker.source_map, [16], 2)}
        data = WORKER_PREFIX + json.dumps(record, sort_keys=True, separators=(",", ":"),
                                          ensure_ascii=True, allow_nan=False) + "\n"
        _require(len(data.encode("ascii")) <= (1536 if worker.role == "regression-worker" else 768))
        _before(worker)
        _require(sys.stderr.write(data) == len(data))
        sys.stderr.flush()
        _before(worker)
        return record
    except BaseException:
        return None


def mark(stage, case_id=None):
    """Advance optional DATA immediately before an existing original action."""
    context = CURRENT
    if not _owned(context):
        return
    try:
        _require(type(stage) is str and stage in STAGES
                 and (case_id is None or type(case_id) is str and case_id in context.identifiers)
                 and (stage not in {"helper", "typed-result", "cleanup"} or case_id is not None)
                 and (stage not in {"admission", "postconditions", "publication"} or case_id is None))
        context.stage, context.case_id = stage, case_id
    except BaseException:
        context.available = False  # Never publish a stale/foreign case or change the original action.


def _actual(error):
    _require(type(error) is tuple and len(error) == 3 and isinstance(error[1], BaseException)
             and error[0] is type(error[1])
             and error[2] is BaseException.__dict__["__traceback__"].__get__(error[1], BaseException))
    return error[1], error[2]


def _category(error):
    return next(name for kind, name in (
        (OSError, "os-error"), (AssertionError, "assertion-error"), (ValueError, "value-error"),
        (TypeError, "type-error"), (MemoryError, "memory-error"), (Exception, "exception"),
        (BaseException, "base-exception")) if issubclass(type(error), kind))


def _locations(frame, source_map, budget, maximum):
    locations = []
    if maximum == 0:
        return locations  # [-0:] is the entire list, not a zero-location bound.
    while type(frame) is types.TracebackType and budget[0] > 0:
        budget[0] -= 1  # Includes every unallowlisted raw frame; no source/linecache lookup.
        filename, line = frame.tb_frame.f_code.co_filename, frame.tb_lineno
        public = next((relative for actual, relative in source_map if filename == actual), None)
        if public is not None and type(line) is int and 0 < line < 1_000_000:
            locations.append({"file": public, "line": line})
            locations = locations[-maximum:]
        frame = frame.tb_next
    return locations


def original_g_failure(error):
    """Only the winning original result callback may offer its actual tuple."""
    context = _g_context()
    if context is None or context.g_seen:
        return
    context.g_seen = True  # First remains first even with no tuple or a projection exception.
    context.budget[0] -= 16  # Reserve BEFORE projection; never renew visits after optional failure.
    try:
        _require(context.stage == "helper" and context.case_id in context.regression_ids)
        _before(context)
        exception, frame = _actual(error)
        value = {"category": _category(exception),
                 "locations": _locations(frame, context.source_map, [16], 2)}
        _before(context)
        context.g_failure = value  # Bounded DATA only; no exception/traceback retention.
        try:
            context.child = _profile_child(context, exception)
        except BaseException:
            pass  # A child projection cannot discard the actual parent failure.
    except BaseException:
        pass


def emit(context, error):
    """One best-effort marker; the outer wrapper still bare-reraises its cause."""
    if not _owned(context) or context.emitted:
        return None
    context.emitted = True  # A failing writer/projector cannot cause a duplicate attempt.
    try:
        _before(context)
        exception, frame = _actual(error)
        original = context.g_failure
        _require(original is None or context.stage == "helper" and context.case_id in context.regression_ids)
        child = context.child
        if child is None and context.stage == "helper":
            try:
                child = _case_child(context, exception)
            except BaseException:
                pass
        # W may already have emitted even if the optional launcher attachment
        # failed. Its reserved bytes/locations never return to the parent.
        semantic = bool(_selectors(context, "semantic-worker"))
        regression = context.stage == "helper" and context.case_id in context.regression_ids
        _require(original is None)  # G tracebacks belong to its original W, never to warm L.
        maximum = 0 if regression else 2 if semantic else 4
        record = {"schema": 2, "phase": context.phase, "caseId": context.case_id, "stage": context.stage,
                  "category": _category(exception),
                  "locations": _locations(frame, context.source_map, context.budget, maximum),
                  "originalGFailure": original, "child": child}
        data = PREFIX + json.dumps(record, sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=True, allow_nan=False) + "\n"
        _require(len(data.encode("ascii")) <= (512 if regression else 1280 if semantic else 2048))
        _before(context)
        _require(sys.stderr.write(data) == len(data))
        sys.stderr.flush()
        _before(context)
        return record
    except BaseException:
        return None
