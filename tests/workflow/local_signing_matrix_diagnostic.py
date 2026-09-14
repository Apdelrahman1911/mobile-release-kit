"""Optional bounded matrix failure DATA; never custody, coverage or a receipt.

The original phase prebinds source filenames before fixture/product work. This
module never resolves paths, reads source/evidence, starts work or grants time.
"""
from __future__ import annotations

import json
import math
import re
import sys
import time
import types


PREFIX = "MRK_SIGNING_MATRIX_FAILURE="
STAGES = ("admission", "helper", "typed-result", "persist", "cleanup", "postconditions", "publication")
PUBLIC_FILE = re.compile(r"(?:tests|\.github/scripts|src/mobile_release)/(?:[A-Za-z_][A-Za-z0-9_-]*/)*[A-Za-z_][A-Za-z0-9_-]*\.py\Z")
CASE_ID = re.compile(r"[0-9a-f]{64}\Z")
CURRENT = None


def _require(value):
    if not value:
        raise ValueError("matrix diagnostic unavailable")


def _before(context):
    _require(time.monotonic() < context.deadline)


class Phase:
    """One original invocation and a shared64-visit/four-location budget."""

    def __init__(self, phase, deadline, operating_system, shard, identifiers, regression_ids, source_map):
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
        self.phase, self.deadline = phase, deadline
        self.identifiers, self.regression_ids, self.source_map = identifiers, regression_ids, source_map
        self.case_id, self.stage = None, "admission"
        self.g_seen, self.g_failure, self.budget = False, None, [64]
        self.emitted, self.available = False, True
        _before(self)


def mark(stage, case_id=None):
    """Advance optional DATA immediately before an existing original action."""
    context = CURRENT
    if type(context) is not Phase or not context.available:
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
    context = CURRENT
    if type(context) is not Phase or not context.available or context.g_seen:
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
    except BaseException:
        pass


def emit(context, error):
    """One best-effort marker; the outer wrapper still bare-reraises its cause."""
    if type(context) is not Phase or not context.available or context.emitted:
        return None
    context.emitted = True  # A failing writer/projector cannot cause a duplicate attempt.
    try:
        _before(context)
        exception, frame = _actual(error)
        original = context.g_failure
        _require(original is None or context.stage == "helper" and context.case_id in context.regression_ids)
        maximum = 4 - (len(original["locations"]) if original is not None else 0)
        record = {"schema": 1, "phase": context.phase, "caseId": context.case_id, "stage": context.stage,
                  "category": _category(exception),
                  "locations": _locations(frame, context.source_map, context.budget, maximum),
                  "originalGFailure": original}
        data = PREFIX + json.dumps(record, sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=True, allow_nan=False) + "\n"
        _require(len(data.encode("ascii")) <= 2048)
        _before(context)
        _require(sys.stderr.write(data) == len(data))
        sys.stderr.flush()
        _before(context)
        return record
    except BaseException:
        return None
