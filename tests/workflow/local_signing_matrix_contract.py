"""Strict test-execution records. These are NOT release attestations or authority."""
from __future__ import annotations

import hashlib
import ast
import gzip
import io
import importlib.util
import json
import math
import os
import re
import stat
import sys
import time
import types
from itertools import islice
from pathlib import Path

SHARDS = 48
OPERATING_SYSTEMS = ("ubuntu-24.04", "macos-26")
MAX_CASES = 100_000
MAX_PROOF_BYTES = 8 * 1024 * 1024
MAX_PROOFS = 512
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_RESULTS_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_RESULTS = 256 * 1024 * 1024
HEX = re.compile(r"[0-9a-f]{64}\Z")
ARTIFACT = re.compile(r"local-signing-matrix-proof-(ubuntu-24\.04|macos-26)-(0|[1-9][0-9]?)-attempt-([1-9][0-9]{0,5})\Z")
ADAPTER_TEST_IDS = tuple(
    "unit.test_local_signing_persistent.PersistentSigningTests." + name for name in (
        "test_one_real_model_command_bridge_finishes_before_success",
        "test_actual_case_wait_eof_barrier_crash_and_deadline_settle_before_return",
        "test_original_c_prefix_cut_uses_real_fence_and_fresh_recovery",
        "test_genuine_model_inventory_active_build_pending_contrast",
    )
) + (
    "workflow.test_command_account_lifecycle.CommandAccountLifecycleTests."
    "test_prepared_no_target_original_fence_and_same_lease_cleanup",
)
ADAPTER_TEST_DEFINITIONS = (
    ("tests/unit/test_local_signing_persistent.py", "PersistentSigningTests", ADAPTER_TEST_IDS[:4]),
    ("tests/workflow/test_command_account_lifecycle.py", "CommandAccountLifecycleTests", ADAPTER_TEST_IDS[4:]),
)
ADAPTER_TEST_FILES = {identifier: filename for filename, _class, identifiers in ADAPTER_TEST_DEFINITIONS
                      for identifier in identifiers}
ADAPTER_PARENT_MODULES = frozenset({
    "mobile_release", "mobile_release.local_signing", "mobile_release.owned_process",
    "mobile_release._native_process",
})
ADAPTER_ORIGIN_MODULES = {
    "parent": ADAPTER_PARENT_MODULES,
    "commandWorker": ADAPTER_PARENT_MODULES | {"mobile_release._command_process"},
}
ADAPTER_FAILURE_PREFIX = "MRK_SIGNING_ADAPTER_FAILURE="
ADAPTER_FAILURE_MAX_BYTES = 2048
ADAPTER_FAILURE_CATEGORIES = (
    "none", "os-error", "assertion-error", "value-error", "type-error", "memory-error", "exception", "base-exception",
)
ADAPTER_PROGRESS_MAX = (1 << 31) - 1
ADAPTER_PROGRESS_CASES = (
    "healthy", "crash", "deadline", "query", "seed", "inventory",
    "final-automatic", "final-no-resolution", "final-owner-resolution",
    "semantic-main", "semantic-resolution",
)
ADAPTER_PROGRESS_OWNER_STAGES = (
    "task-entered", "task-returned", "result-write-returned", "recovery-check", "recovery-busy", "recovery-ready",
    "begin", "run-owned", "target-return", "service-joined", "model-return",
)
ADAPTER_PROGRESS_SERVICE_STAGES = ("HELLO", "BEGIN", "EFFECT", "END", "DONE", "EOF")
ADAPTER_TARGET_FRAME = re.compile(r'  File "([^"\r\n]+)", line ([1-9][0-9]{0,5}), in ([^\r\n]{1,256})\Z')
ADAPTER_FAILURE_TEST_FILES = (
    "tests/unit/test_local_signing_persistent.py", "tests/unit/local_signing_persistent.py",
    "tests/unit/local_signing_helpers.py", "tests/unit/ios_entitlement_helpers.py",
    "tests/workflow/local_signing_persistent_fixture.py", "tests/workflow/local_signing_case_owner.py",
    "tests/workflow/local_signing_bridge.py", "tests/workflow/local_signing_model_target.py",
    "tests/workflow/local_signing_semantic_fixture.py", "tests/workflow/local_signing_semantic_catalog.py",
    "tests/workflow/local_signing_workload.py",
    "tests/workflow/test_command_account_lifecycle.py", "tests/workflow/command_account_lifecycle_fixture.py",
    "tests/workflow/command_bootstrap_fixture.py", "tests/workflow/command_fence_failure_fixture.py",
    "tests/workflow/profile_process_fixture.py",
)
ADAPTER_PHASE_FAILURE_PREFIX = "MRK_SIGNING_ADAPTER_PHASE_FAILURE="
ADAPTER_PHASE_FAILURE_STAGES = (
    "admission", "imports", "inventory", "suite", "postconditions", "origins", "publication",
)
ADAPTER_PHASE_FAILURE_FILES = (
    "tests/workflow/run_local_signing_matrix.py", "tests/workflow/local_signing_matrix_contract.py",
)


def require(condition, message):
    if not condition:
        raise ValueError("signing matrix: " + message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def before_deadline(deadline):
    if deadline is not None:
        require(type(deadline) is float and math.isfinite(deadline) and time.monotonic() < deadline,
                "original matrix cutoff expired")


def _adapter_context(context):
    phase, identifier, source_map = context  # Immutable, prepared BEFORE dispatch.
    require(phase in {"source", "wheel"} and identifier in ADAPTER_TEST_IDS, "adapter diagnostic context")
    require(type(context) is tuple and type(source_map) is tuple and 0 < len(source_map) <= 512
            and all(type(pair) is tuple and len(pair) == 2 and type(pair[0]) is str and type(pair[1]) is str
                    and (pair[1] in ADAPTER_FAILURE_TEST_FILES or re.fullmatch(
                        r"src/mobile_release/(?:[A-Za-z_][A-Za-z0-9_]*/)*[A-Za-z_][A-Za-z0-9_]*\.py", pair[1]))
                    for pair in source_map), "adapter diagnostic filename map")
    return phase, identifier, source_map


def _adapter_category(exception):
    return next((name for kind, name in (
        (OSError, "os-error"), (AssertionError, "assertion-error"), (ValueError, "value-error"),
        (TypeError, "type-error"), (MemoryError, "memory-error"), (Exception, "exception"),
        (BaseException, "base-exception")) if issubclass(type(exception), kind)), "base-exception")


def _adapter_locations(frame, source_map, budget, maximum):
    locations = []
    while type(frame) is types.TracebackType and budget[0] > 0:
        budget[0] -= 1  # Shared raw-frame visits, including unallowlisted frames.
        filename, line = frame.tb_frame.f_code.co_filename, frame.tb_lineno
        public = next((relative for actual, relative in source_map if filename == actual), None)
        if public is not None and type(line) is int and 0 < line < 1_000_000:
            locations.append({"file": public, "line": line})
            locations = locations[-maximum:]
        frame = frame.tb_next
    return locations


def _adapter_exception_data(exception, name):
    # Bypass subclass attributes/properties. These are Python's actual links,
    # not a claim that a related exception was the first or underlying cause.
    return BaseException.__dict__[name].__get__(exception, BaseException)


def adapter_command_first(context, exception):
    """Small in-memory-only observation; never retain an exception/context."""
    _phase, _identifier, source_map = _adapter_context(context)
    require(isinstance(exception, BaseException), "adapter original command exception")
    budget = [16]  # Leave at least 48 of the shared 64 visits for the later root.
    locations = _adapter_locations(_adapter_exception_data(exception, "__traceback__"), source_map, budget, 2)
    return (_adapter_category(exception), tuple((row["file"], row["line"]) for row in locations), 16 - budget[0])


def adapter_target_result(context, returncode, stderr):
    """Captured target stderr DATA only; not an actual traceback/cause/receipt."""
    _phase, _identifier, source_map = _adapter_context(context)
    require(type(returncode) is int and -128 <= returncode <= 255, "adapter original target status")
    unavailable = (returncode, "unavailable", ())
    if type(stderr) is not str or len(stderr) > 8192:
        return unavailable
    try:
        if len(stderr.encode("utf-8")) > 8192:
            return unavailable
    except UnicodeError:
        return unavailable
    if not stderr:
        return returncode, "empty", ()
    lines = stderr.split("\n")
    if lines[-1] == "":
        lines.pop()  # A final newline terminates a physical line; it is not another one.
    if len(lines) > 64 or lines[0] != "Traceback (most recent call last):":
        return unavailable
    locations = []
    for line in lines[1:]:
        if not line.startswith("  File "):
            continue  # Never copy a function, source line, exception name or message.
        match = ADAPTER_TARGET_FRAME.fullmatch(line)
        if match is None:
            return unavailable
        filename, number, _function = match.groups()
        public = next((relative for actual, relative in source_map if filename == actual), None)
        if public is not None:
            locations.append((public, int(number)))
            locations = locations[-2:]
    return (returncode, "traceback-frames", tuple(locations)) if locations else unavailable


def _adapter_progress_record(value):
    require(type(value) is dict and set(value) == {"case", "owner", "service"}
            and type(value["case"]) is str and value["case"] in ADAPTER_PROGRESS_CASES, "adapter progress case")
    owner, service = value["owner"], value["service"]
    for record, stages, fields in ((owner, ADAPTER_PROGRESS_OWNER_STAGES,
                                   {"command", "elapsedMs", "completed", "totalMs", "maxMs"}),
                                  (service, ADAPTER_PROGRESS_SERVICE_STAGES, {"command", "elapsedMs"})):
        if record is not None:
            require(type(record) is dict and set(record) == fields | {"stage"}
                    and type(record["stage"]) is str and record["stage"] in stages
                    and all(type(record[key]) is int and 0 <= record[key] <= ADAPTER_PROGRESS_MAX for key in fields),
                    "adapter progress scalar record")
    if owner is not None:
        require(owner["completed"] <= owner["command"] and owner["maxMs"] <= owner["totalMs"]
                and (owner["completed"] > 0 or owner["maxMs"] == owner["totalMs"] == 0)
                and (owner["stage"] not in {"begin", "run-owned", "target-return", "service-joined", "model-return"}
                     or owner["command"] > 0)
                and (owner["stage"] != "model-return" or owner["completed"] > 0), "adapter progress owner fields")
    if service is not None:
        require(owner is not None and service["command"] > 0 and service["command"] == owner["command"],
                "adapter progress original service generation")
    return {"case": value["case"], "owner": dict(owner) if owner is not None else None,
            "service": dict(service) if service is not None else None}


def adapter_failure_record(context, layer, outcome, error, *, deadline, command_first=None, command_reserved=0,
                           case=None, target_result=None, progress=None):
    """Actual root and bounded Python links; no message/source/linecache reads."""
    before_deadline(deadline)
    phase, identifier, source_map = _adapter_context(context)
    require(layer in {"worker", "unittest"}
            and outcome in {"error", "failure", "expected-failure", "unexpected-success", "skip"},
            "adapter diagnostic context")
    require(type(command_reserved) is int and command_reserved in {0, 16}
            and (layer == "worker" or command_reserved == 0), "adapter original command reserved budget")
    # The original worker reserves 16 BEFORE task execution, not when a row
    # becomes visible. Missing/in-flight/failed/later callbacks cannot renew it.
    budget, related = [64 - command_reserved], []
    if command_first is not None:
        require(layer == "worker" and command_reserved == 16 and type(command_first) is tuple and len(command_first) == 3,
                "adapter original command observation")
        category, frames, visited = command_first
        require(category in ADAPTER_FAILURE_CATEGORIES[1:] and type(frames) is tuple and len(frames) <= 2
                and type(visited) is int and 0 <= visited <= 16
                and all(type(row) is tuple and len(row) == 2 and type(row[0]) is str
                        and row[0] in {public for _actual, public in source_map}
                        and type(row[1]) is int and 0 < row[1] < 1_000_000 for row in frames),
                "adapter original command observation fields")
        related.append({"via": ["command-first"], "category": category,
                        "locations": [{"file": filename, "line": line} for filename, line in frames]})
    category, locations = "none", []
    if error is not None:
        require(type(error) is tuple and len(error) == 3 and isinstance(error[1], BaseException),
                "adapter actual exception tuple")
        exception = error[1]
        category = _adapter_category(exception)
        locations = _adapter_locations(error[2], source_map, budget, 4)
        pending, seen = [(exception, ())], {id(exception)}
        while pending and len(related) < 3:
            current, route = pending.pop(0)
            for name in ("cause", "context"):
                linked = _adapter_exception_data(current, "__" + name + "__")
                if linked is None or id(linked) in seen:
                    continue
                if len(seen) == 8:
                    break
                seen.add(id(linked))
                via = (*route, name)
                related.append({"via": list(via), "category": _adapter_category(linked),
                    "locations": _adapter_locations(_adapter_exception_data(linked, "__traceback__"), source_map, budget, 2)})
                pending.append((linked, via))
                if len(related) == 3:
                    break
    record = {"schema": 1, "phase": phase, "testId": identifier, "layer": layer,
              "outcome": outcome, "category": category, "locations": locations}
    if related:
        record["related"] = related
    if case is not None:
        require(layer == "unittest" and type(case) is tuple and len(case) == 5, "adapter case observation")
        expected, worker, anchor, parsed, expired = case
        require(type(expected) is int and expected in {0, 73, -9}
                and all(value is None or type(value) is int and -128 <= value <= 255 for value in (worker, anchor))
                and type(parsed) is bool and (worker is not None) == parsed
                and (type(expired) is bool if parsed else expired is None), "adapter case observation fields")
        record["case"] = {"expectedExit": expected, "workerExit": worker, "anchorExit": anchor,
                          "terminalParsed": parsed, "anchorExpired": expired}
    if target_result is not None:
        require(layer == "worker" and type(target_result) is tuple and len(target_result) == 3,
                "adapter original target observation")
        code, kind, frames = target_result
        require(type(code) is int and -128 <= code <= 255 and type(kind) is str
                and kind in {"empty", "traceback-frames", "unavailable"}
                and type(frames) is tuple and len(frames) <= 2 and bool(frames) == (kind == "traceback-frames")
                and all(type(row) is tuple and len(row) == 2 and type(row[0]) is str
                        and row[0] in {public for _actual, public in source_map}
                        and type(row[1]) is int and 0 < row[1] < 1_000_000 for row in frames),
                "adapter original target observation fields")
        record["targetResult"] = {"returncode": code, "stderrKind": kind,
                                  "locations": [{"file": filename, "line": line} for filename, line in frames]}
    if progress is not None:
        require(layer == "unittest" and outcome in {"error", "failure", "expected-failure"}, "adapter progress failure layer")
        record["progress"] = _adapter_progress_record(progress)
    if "progress" in record and len(ADAPTER_FAILURE_PREFIX) + len(canonical(record)) + 1 > ADAPTER_FAILURE_MAX_BYTES:
        del record["progress"]  # New progress is discarded BEFORE any prior optional observation.
    if "targetResult" in record and len(ADAPTER_FAILURE_PREFIX) + len(canonical(record)) + 1 > ADAPTER_FAILURE_MAX_BYTES:
        del record["targetResult"]
    # Preserve the original root observation before optional related details.
    while record.get("related") and len(ADAPTER_FAILURE_PREFIX) + len(canonical(record)) + 1 > ADAPTER_FAILURE_MAX_BYTES:
        record["related"].pop()
        if not record["related"]:
            del record["related"]
    before_deadline(deadline)
    return record


def emit_adapter_failure(context, layer, outcome, error, *, deadline, command_first=None, command_reserved=0,
                         case=None, target_result=None, progress=None):
    """Optional stderr DATA only; a diagnostic error cannot replace its cause."""
    if context is None:
        return None
    try:
        record = adapter_failure_record(context, layer, outcome, error, deadline=deadline,
                                        command_first=command_first, command_reserved=command_reserved,
                                        case=case, target_result=target_result, progress=progress)
        data = ADAPTER_FAILURE_PREFIX + canonical(record).decode("ascii") + "\n"
        require(len(data.encode("ascii")) <= ADAPTER_FAILURE_MAX_BYTES, "adapter diagnostic byte bound")
        before_deadline(deadline)
        sys.stderr.write(data)
        sys.stderr.flush()
        before_deadline(deadline)
        return record
    except BaseException:
        return None  # Original test/worker failure is already irreversibly latched.


def _adapter_phase_context(context):
    require(type(context) is tuple and len(context) == 3, "adapter phase diagnostic context")
    phase, deadline, source_map = context
    require(type(phase) is str and phase in {"source", "wheel"}
            and type(deadline) is float and math.isfinite(deadline), "adapter phase diagnostic binding")
    require(type(source_map) is tuple and len(source_map) == 2
            and all(type(pair) is tuple and len(pair) == 2
                    and type(pair[0]) is str and 0 < len(pair[0]) <= 4096
                    and type(pair[1]) is str for pair in source_map)
            and tuple(pair[1] for pair in source_map) == ADAPTER_PHASE_FAILURE_FILES
            and source_map[0][0] != source_map[1][0], "adapter phase diagnostic filename map")
    before_deadline(deadline)
    return phase, deadline, source_map


def adapter_phase_failure_record(context, stage, error):
    """One actual escaping phase exception; no test identity or resource proof."""
    phase, deadline, source_map = _adapter_phase_context(context)
    require(type(stage) is str and stage in ADAPTER_PHASE_FAILURE_STAGES, "adapter phase diagnostic stage")
    require(type(error) is tuple and len(error) == 3 and isinstance(error[1], BaseException)
            and error[0] is type(error[1])
            and error[2] is _adapter_exception_data(error[1], "__traceback__"), "adapter phase actual exception")
    locations = _adapter_locations(error[2], source_map, [64], 4)
    record = {"schema": 1, "phase": phase, "stage": stage,
              "category": _adapter_category(error[1]), "locations": locations}
    before_deadline(deadline)
    return record


def emit_adapter_phase_failure(context, stage, error):
    """Best-effort existing stderr only; the wrapper re-raises its original."""
    if context is None:
        return None
    try:
        record = adapter_phase_failure_record(context, stage, error)
        data = ADAPTER_PHASE_FAILURE_PREFIX + canonical(record).decode("ascii") + "\n"
        require(len(data.encode("ascii")) <= ADAPTER_FAILURE_MAX_BYTES, "adapter phase diagnostic byte bound")
        before_deadline(context[1])
        sys.stderr.write(data)
        sys.stderr.flush()
        before_deadline(context[1])
        return record
    except BaseException:
        return None  # No observation can replace the already escaping exception.


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


_LAYERED_CATALOG = None


def layered_catalog():
    """Exact pure source authority, also usable outside the workflow package."""
    global _LAYERED_CATALOG
    path = Path(__file__).resolve().with_name("local_signing_layered_catalog.py")
    require(path.is_file() and not path.is_symlink(), "layered source catalog missing")
    name = "_mrk_layered_" + hashlib.sha256(str(path).encode()).hexdigest()
    # A matching filename is only DATA. Reuse only this loader's original
    # object, never a pre-existing alias supplied by another import/consumer.
    require(name not in sys.modules, "layered source catalog alias occupied")
    if _LAYERED_CATALOG is not None:
        require(Path(_LAYERED_CATALOG.__file__) == path, "layered source catalog origin differs")
        return _LAYERED_CATALOG
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, "layered source catalog loader missing")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
        require(sys.modules.get(name) is module, "layered source catalog binding changed")
    finally:
        if sys.modules.get(name) is module:
            del sys.modules[name]
    _LAYERED_CATALOG = module
    return module


def diagnostic_child_bindings(operating_system, shard, *, deadline=None):
    """Prelaunch DATA from the actual selected catalog, never reported selectors."""
    catalog, result = layered_catalog(), []
    for identifier in catalog.shard_ids(operating_system, shard):
        before_deadline(deadline)
        item = catalog.case(identifier, operating_system)
        if item.kind == "regression":
            original = catalog.REGRESSION.case(item.name)
            if original.helper == "profile-signal":
                result.append((identifier, "profile-signal", (original.variant,)))
        elif item.kind == "semantic":
            original = catalog.SEMANTIC.case(item.name)
            if original.kind == "healthy":
                steps = ("healthy",)
            elif original.kind in {"seed", "command", "native-prefix", "recovery"}:
                steps = ("seed",) + (("recovery",) if original.kind == "recovery" else ()) + ("semantic-main",)
                if original.resolution is not None:
                    steps += ("semantic-resolution",)
            else:
                continue  # Focused helpers retain the original outer diagnostic.
            result.append((identifier, "semantic-worker", steps))
    return tuple(result)


def shard_for(case_id):
    require(type(case_id) is str and HEX.fullmatch(case_id), "invalid logical case ID")
    return int(hashlib.sha256(case_id.encode("ascii")).hexdigest(), 16) % SHARDS


def logical_case_id(group, event, edge):
    """No global event index, temporary path, PID or inode enters assignment."""
    require(edge in ("before", "after", "partial"), "invalid crash edge")
    return digest({"group": group, "operation": event["operation"], "slot": event["slot"],
                   "destination": event["details"].get("destination"), "origin": event["origin"],
                   "phase": event["phase"], "occurrence": event["occurrence"], "edge": edge})


def event_fact(event):
    # Flags, failed effects and error types stay in the complete inventory hash;
    # excluding them from stable assignment must not hide behavioral drift.
    return {key: value for key, value in event.items() if key != "index"}


def validate_ids(value, label):
    require(type(value) is list and 0 < len(value) <= MAX_CASES, label + " must be nonempty and bounded")
    require(all(type(item) is str and HEX.fullmatch(item) for item in value), label + " has an invalid ID")
    require(value == sorted(value) and len(set(value)) == len(value), label + " contains duplicates or is not canonical")
    return value


def package_manifest(package, *, deadline=None):
    before_deadline(deadline)
    require(package.is_dir() and (package / "__init__.py").is_file(), "package root is missing")
    result = {}
    for path in sorted(package.rglob("*")):
        before_deadline(deadline)
        if "__pycache__" in path.parts:
            continue
        require(not path.is_symlink(), "package contains a symlink")
        if path.is_file():
            result[path.relative_to(package).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            require(path.is_dir(), "package contains a special file")
    require("local_signing.py" in result and "owned_process.py" in result, "required production files are absent")
    return result


def definitions_manifest(root, *, deadline=None):
    # Bind Python definitions AND native fixture sources (not merely their
    # loader). A stale C signal probe may not reuse current-source evidence.
    # Generated objects/caches are not source definitions.
    paths = (sorted(path for path in (root / "tests").rglob("*") if path.suffix in {".py", ".c", ".h"})
             + sorted(path for path in (root / ".github/scripts").rglob("*")
                      if path.is_file() and "__pycache__" not in path.parts)
             + [root / ".github/workflows/ci.yml", root / "pyproject.toml"])
    require(len(paths) > 10, "test definition inventory is incomplete")
    require(all(path.is_file() and not path.is_symlink() for path in paths), "invalid test definition file")
    result = {}
    for path in paths:
        before_deadline(deadline)
        result[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    before_deadline(deadline)
    return result


def adapter_test_ids(root, *, deadline=None):
    """Closed five-method/two-definition-file smoke; not full matrix coverage."""
    before_deadline(deadline)
    for filename, class_name, identifiers in ADAPTER_TEST_DEFINITIONS:
        before_deadline(deadline)
        path = root / filename
        require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 1024**2,
                "adapter test definition missing or oversized")
        tree = ast.parse(path.read_bytes(), filename=str(path))
        classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name]
        require(len(classes) == 1, "adapter class inventory")
        methods = [node.name for node in classes[0].body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
        require(all(methods.count(identifier.rsplit(".", 1)[1]) == 1 for identifier in identifiers),
                "adapter literal method missing or duplicated")
    before_deadline(deadline)
    return ADAPTER_TEST_IDS


def adapter_scope_from_metadata(metadata, operating_system):
    # Separate schema/role. Never accept these records in matrix reducers.
    require(type(metadata) is dict and set(metadata) == {"kind", "repository", "commit", "runId", "attempt", "job"},
            "adapter explicit scope fields")
    require(metadata["kind"] == "github" and metadata["job"] == "test-signing-adapter"
            and operating_system in OPERATING_SYSTEMS, "adapter scope role/OS")
    require(type(metadata["repository"]) is str and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", metadata["repository"]),
            "adapter repository")
    require(type(metadata["commit"]) is str and re.fullmatch(r"[0-9a-f]{40}", metadata["commit"]), "adapter commit")
    require(type(metadata["runId"]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", metadata["runId"]), "adapter run")
    require(type(metadata["attempt"]) is int and 1 <= metadata["attempt"] <= 999999, "adapter attempt")
    return {"schema": "mrk-signing-adapter-scope-v1", **metadata, "os": operating_system}


def validate_adapter_origins(origins, role):
    """Closed role-local DATA; a parent import cannot stand in for its worker."""
    require(type(role) is str and role in ADAPTER_ORIGIN_MODULES, "adapter origin role")
    require(type(origins) is dict and 1 <= len(origins) <= 100
            and ADAPTER_ORIGIN_MODULES[role] <= set(origins), "adapter actual loaded modules missing: " + role)
    for name, relative in origins.items():
        require(type(name) is str and re.fullmatch(r"mobile_release(?:\.[A-Za-z_][A-Za-z0-9_]*)*", name)
                and type(relative) is str, "adapter loaded origin fields")
        expected = {"__init__.py"} if name == "mobile_release" else {
            "/".join(name.split(".")[1:]) + ".py",
            "/".join([*name.split(".")[1:], "__init__.py"]),
        }
        require(relative in expected, "adapter loaded origin escaped package")
    return origins


def actual_adapter_origins(package, role, *, deadline=None):
    """Observe existing imports only, without loading unused production modules."""
    before_deadline(deadline)
    require(package.is_absolute() and package.resolve(strict=True) == package and package.is_dir(),
            "adapter actual package root")
    origins = {}
    for name, module in tuple(sys.modules.items()):
        before_deadline(deadline)
        if type(name) is str and (name == "mobile_release" or name.startswith("mobile_release.")):
            origin = getattr(module, "__file__", None)
            require(type(origin) is str, "adapter actual loaded origin missing")
            path = Path(origin)
            require(path.is_absolute() and path.resolve(strict=True) == path and path.is_file()
                    and path.is_relative_to(package), "adapter actual import escaped package")
            origins[name] = path.relative_to(package).as_posix()
            require(len(origins) <= 100, "adapter actual import count")
    validate_adapter_origins(origins, role)
    before_deadline(deadline)
    return origins


def validate_adapter_record(record, scope, phase, package):
    require(type(record) is dict and set(record) == {"schema", "phase", "scope", "status", "productionRoot",
            "startedIds", "successfulIds", "testsRun", "origins", "casePathsRemoved"}, "adapter record fields")
    require(record["schema"] == "mrk-signing-adapter-phase-v2" and record["status"] == "adapter-only"
            and type(record["scope"]) is dict and canonical(record["scope"]) == canonical(scope)
            and record["phase"] == phase
            and record["productionRoot"] == str(package), "adapter record binding")
    require(record["startedIds"] == list(ADAPTER_TEST_IDS) == record["successfulIds"]
            and type(record["testsRun"]) is int and record["testsRun"] == len(ADAPTER_TEST_IDS)
            and record["casePathsRemoved"] is True, "adapter actual successful IDs or retained cases")
    origins = record["origins"]
    require(type(origins) is dict and set(origins) == set(ADAPTER_ORIGIN_MODULES), "adapter origin roles missing")
    for role, values in origins.items():
        validate_adapter_origins(values, role)


def scope_from_metadata(metadata, operating_system, *, producer):
    """Explicit finite workflow channel, independent of the clean child env.

    This is test accounting, not Store/release authority. A missing CI field
    cannot select local mode, and a reducer cannot impersonate a producer job.
    """
    require(type(metadata) is dict and set(metadata) == {"kind", "repository", "commit", "runId", "attempt", "job"},
            "invalid explicit scope fields")
    require(operating_system in OPERATING_SYSTEMS and type(producer) is bool, "invalid scope role/OS")
    require(metadata["kind"] in {"local", "github"}, "invalid scope kind")
    require(type(metadata["attempt"]) is int and 1 <= metadata["attempt"] <= 999999, "invalid attempt scope")
    if metadata["kind"] == "local":
        require(metadata == {"kind": "local", "repository": None, "commit": None, "runId": None,
                             "attempt": 1, "job": "local"}, "invalid local scope")
        return {**metadata, "os": operating_system}
    require(type(metadata["repository"]) is str and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", metadata["repository"]),
            "invalid repository scope")
    require(type(metadata["commit"]) is str and re.fullmatch(r"[0-9a-f]{40}", metadata["commit"]), "invalid commit scope")
    require(type(metadata["runId"]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", metadata["runId"]), "invalid run scope")
    require(metadata["job"] == ("test-signing-matrix" if producer else "test"), "unexpected workflow job")
    return {**metadata, "job": "test-signing-matrix", "os": operating_system}


def scope_from_environment(environment, operating_system, *, producer):
    require(operating_system in OPERATING_SYSTEMS, "unsupported operating system")
    if environment.get("GITHUB_ACTIONS") != "true":
        return {"kind": "local", "repository": None, "commit": None, "runId": None,
                "attempt": 1, "job": "local", "os": operating_system}
    repository = environment.get("GITHUB_REPOSITORY", "")
    commit = environment.get("GITHUB_SHA", "")
    run_id = environment.get("GITHUB_RUN_ID", "")
    attempt = environment.get("GITHUB_RUN_ATTEMPT", "")
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository), "invalid repository scope")
    require(re.fullmatch(r"[0-9a-f]{40}", commit), "invalid commit scope")
    require(re.fullmatch(r"[1-9][0-9]{0,19}", run_id), "invalid run scope")
    require(re.fullmatch(r"[1-9][0-9]{0,5}", attempt), "invalid attempt scope")
    expected_job = "test-signing-matrix" if producer else "test"
    require(environment.get("GITHUB_JOB") == expected_job, "unexpected workflow job")
    return {"kind": "github", "repository": repository, "commit": commit, "runId": run_id,
            "attempt": int(attempt), "job": "test-signing-matrix", "os": operating_system}


def artifact_name(scope, shard):
    require(type(shard) is int and 0 <= shard < SHARDS, "invalid shard")
    return f"local-signing-matrix-proof-{scope['os']}-{shard}-attempt-{scope['attempt']}"


def _object(value, keys, label):
    require(type(value) is dict and set(value) == set(keys), "invalid " + label + " fields")


def _hash(value, label):
    require(type(value) is str and HEX.fullmatch(value), "invalid " + label + " hash")


def validate_phase(run, expected, shard, package_sha, definitions_sha, mode, *, operating_system):
    """Independently source-bound phase contract; producer IDs are not authority."""
    require(mode in {"source", "wheel"} and type(shard) is int and 0 <= shard < SHARDS, "invalid phase selection")
    catalog = layered_catalog()
    validate_ids(expected, "expected cases")
    require(expected == list(catalog.expected_ids(operating_system)), "expected cases differ from source catalog")
    selected = list(catalog.shard_ids(operating_system, shard))
    _object(run, ("executedCaseIds", "catalogSha256", "packageSha256", "definitionsSha256",
                  "resultsSha256", "coverage", "allExactChildrenReapedAndGroupsAbsent", "allCasePathsRemoved"), mode)
    validate_ids(run["executedCaseIds"], mode + " executed cases")
    require(run["executedCaseIds"] == selected, mode + " has omitted, extra or incorrectly assigned cases")
    for key in ("catalogSha256", "packageSha256", "definitionsSha256", "resultsSha256"):
        _hash(run[key], mode + " " + key)
    require(run["catalogSha256"] == digest(catalog.definition(operating_system)), "phase source catalog differs")
    require(run["packageSha256"] == package_sha, "production package differs from aggregate checkout")
    require(run["definitionsSha256"] == definitions_sha, "test definitions differ from aggregate checkout")
    require(canonical(run["coverage"]) == canonical(catalog.coverage(operating_system, selected)),
            "phase kind/variant/contribution coverage differs")
    require(run["allExactChildrenReapedAndGroupsAbsent"] is True and run["allCasePathsRemoved"] is True,
            "unconfirmed worker/fixture cleanup")


def validate_proof(proof, name, expected_scope, package_sha, definitions_sha):
    _object(proof, ("schemaVersion", "scope", "shard", "expectedCaseIds", "expectedSha256",
                    "catalogSha256", "source", "wheel"), "proof")
    require(type(proof["schemaVersion"]) is int and proof["schemaVersion"] == 2, "unsupported proof version")
    scope = proof["scope"]
    _object(scope, ("kind", "repository", "commit", "runId", "attempt", "job", "os"), "scope")
    require(type(scope["attempt"]) is int and 1 <= scope["attempt"] <= expected_scope["attempt"], "invalid producing attempt")
    require(scope["os"] in OPERATING_SYSTEMS, "invalid producer OS")
    for key in ("kind", "repository", "commit", "runId", "job"):
        require(scope[key] == expected_scope[key] and type(scope[key]) is type(expected_scope[key]), "wrong " + key + " scope")
    shard = proof["shard"]
    require(type(shard) is int and 0 <= shard < SHARDS, "invalid producing shard")
    require(type(name) is str and ARTIFACT.fullmatch(name) and name == artifact_name(scope, shard), "artifact identity disagrees with proof")
    expected = validate_ids(proof["expectedCaseIds"], "expected cases")
    catalog = layered_catalog()
    require(expected == list(catalog.expected_ids(scope["os"])), "expected cases differ from source catalog")
    _hash(proof["expectedSha256"], "expected cases")
    _hash(proof["catalogSha256"], "source catalog")
    require(proof["expectedSha256"] == digest(expected), "expected case digest differs")
    require(proof["catalogSha256"] == digest(catalog.definition(scope["os"])), "source catalog digest differs")
    for mode in ("source", "wheel"):
        validate_phase(proof[mode], expected, shard, package_sha, definitions_sha, mode, operating_system=scope["os"])
    return proof


def reconcile(candidates, expected_scope, package_sha, definitions_sha, *, operating_systems=OPERATING_SYSTEMS):
    """Validate ALL attempts before selecting latest complete cells; no fallback."""
    require(tuple(operating_systems) in (OPERATING_SYSTEMS, ("ubuntu-24.04",), ("macos-26",)), "invalid required OS set")
    catalog = layered_catalog()
    expected_by_os = {system: list(catalog.expected_ids(system)) for system in operating_systems}
    latest, seen, names = {}, set(), set()
    count = 0
    for name, proof in candidates:
        count += 1
        require(count <= MAX_PROOFS, "excessive execution proofs")
        require(name not in names, "duplicate proof artifact")
        names.add(name)
        validate_proof(proof, name, expected_scope, package_sha, definitions_sha)
        scope = proof["scope"]
        operating_system = scope["os"]
        require(operating_system in operating_systems, "unexpected OS proof")
        key = (operating_system, proof["shard"])
        identity = (*key, scope["attempt"])
        require(identity not in seen, "duplicate OS/shard/attempt proof")
        seen.add(identity)
        if key not in latest or scope["attempt"] > latest[key]["scope"]["attempt"]:
            latest[key] = {**proof, "expectedCaseIds": expected_by_os[operating_system]}
    require(count > 0, "missing execution proofs")
    required = {(system, shard) for system in operating_systems for shard in range(SHARDS)}
    require(set(latest) == required, "incomplete OS/shard product")
    results = {}
    for operating_system in operating_systems:
        results[operating_system] = {}
        obligations = catalog.REGRESSION.obligations(operating_system)
        required_parts = sorted(part for parts in obligations.values() for part in parts)
        for mode in ("source", "wheel"):
            union, parts = set(), set()
            for shard in range(SHARDS):
                row = latest[(operating_system, shard)][mode]
                actual = row["executedCaseIds"]
                contribution = row["coverage"]["regressionParts"]
                require(not union.intersection(actual), "executed shard sets overlap")
                require(not parts.intersection(contribution), "regression contribution sets overlap")
                union.update(actual)
                parts.update(contribution)
            require(sorted(union) == expected_by_os[operating_system], "actual execution union omits expected cases")
            require(sorted(parts) == required_parts, "original regression obligations incomplete")
            results[operating_system][mode] = {
                "cases": len(union), "caseIdsSha256": digest(sorted(union)),
                "coverage": catalog.coverage(operating_system, sorted(union)),
                "originalRegressionMethods": len(obligations),
                "originalRegressionParts": len(parts),
            }
    return {"schema": "mrk-signing-layered-reduction-v2", "status": "complete", "scope": expected_scope,
            "shards": SHARDS, "operatingSystems": results,
            "packageSha256": package_sha, "definitionsSha256": definitions_sha,
            "producingAttempts": {f"{system}/{shard}": latest[(system, shard)]["scope"]["attempt"]
                                  for system, shard in sorted(required)}}


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def strict_json(content):
    return json.loads(content, object_pairs_hook=_unique_pairs,
                      parse_constant=lambda _: require(False, "non-finite JSON number"))


def validate_original_c_prefix(observation):
    """Read-only event DATA, never a completion or filesystem authority."""
    _object(observation, ("nonce", "commandSequence", "ordinal", "operation", "edge", "outcome", "written", "total",
        "syncFlags", "creationIdentity", "operandHex", "originalWorker", "actualReadHex", "originalFileState",
        "finalAbsentBeforeAndAfter", "originalReadClosed"), "original-C prefix")
    require(observation["originalWorker"] is True and observation["originalReadClosed"] is True
            and observation["finalAbsentBeforeAndAfter"] is True and observation["operation"] == "PENDING_WRITE"
            and observation["edge"] == "PARTIAL" and observation["outcome"] == "OK", "original-C prefix event")
    require(type(observation["nonce"]) is str and re.fullmatch(r"[0-9a-f]{32}", observation["nonce"])
            and type(observation["commandSequence"]) is int and 1 <= observation["commandSequence"] < 1 << 63
            and type(observation["ordinal"]) is int and 1 <= observation["ordinal"] <= 13, "original-C prefix generation")
    written, total = observation["written"], observation["total"]
    require(type(written) is int and type(total) is int and 2 <= total <= 4096 and 0 < written <= total // 2
            and type(observation["syncFlags"]) is int and observation["syncFlags"] == 0, "original-C prefix lengths")
    actual, operand = observation["actualReadHex"], observation["operandHex"]
    require(type(actual) is str and type(operand) is str
            and len(actual) == 2 * written and len(operand) == 2 * (total // 2)
            and re.fullmatch(r"[0-9a-f]+", actual) and re.fullmatch(r"[0-9a-f]+", operand)
            and actual == operand[:2 * written], "actual original-C prefix comparison missing")
    creation, opened = observation["creationIdentity"], observation["originalFileState"]
    require(type(creation) is list and len(creation) == 6 and all(type(value) is int for value in creation)
            and type(opened) is list and len(opened) == 9 and all(type(value) is int for value in opened),
            "original-C prefix inode fields")
    require(0 <= opened[0] < 1 << 64 and 0 < opened[1] < 1 << 64
            and opened[2] == stat.S_IFREG | 0o600 and opened[3] == 1
            and all(0 <= value < 1 << 32 for value in opened[4:6]) and opened[6] == written
            and creation == [opened[index] for index in (0, 1, 4, 5, 2, 3)], "original-C prefix inode binding")


def _original_case_return(value, expected):
    require(type(value) is dict and type(value.get("exit")) is int and value["exit"] == expected,
            "original case return missing")
    require(all(value.get(name) is True for name in
                ("originalAnchorWait", "originalWorkerWait", "originalStatusEOF", "groupAbsentBeforeAnchorWait"))
            and value.get("deadlineTest") is False and value.get("runDeadlineExpired") is False,
            "incomplete or late original case return")


def _primitive_record(item, observation, evidence):
    name = item.name.removeprefix("A/")
    failures = layered_catalog().PRIMITIVE_FAILURES.get(name)
    keys = {"component", "resultsSha256", "nativeCommands",
            "allExactChildrenReapedAndGroupsAbsent", "allCasePathsRemoved"}
    keys |= {"actualFailureCases"} if failures is not None else {"algorithmEvents", "actualCuts"}
    _object(observation, keys, "primitive observation")
    require(observation["component"] == name and type(observation["nativeCommands"]) is int
            and observation["nativeCommands"] == 0
            and observation["allExactChildrenReapedAndGroupsAbsent"] is True
            and observation["allCasePathsRemoved"] is True, "primitive native/cleanup observation")
    require(set(evidence) == {"component-evidence.json"}, "primitive evidence inventory")
    rows = evidence["component-evidence.json"]
    require(type(rows) is list and 0 < len(rows) <= 10000 and all(type(row) is dict for row in rows),
            "primitive evidence rows")
    require(observation["resultsSha256"] == digest(rows), "primitive evidence digest")
    require(all(type(row.get("nativeCommands")) is int and row["nativeCommands"] == 0 for row in rows),
            "primitive attempted native commands")
    if failures is not None:
        require(type(observation["actualFailureCases"]) is int and observation["actualFailureCases"] == len(failures)
                and [row.get("variant") for row in rows] == list(failures), "primitive failure union")
        for row in rows:
            _object(row, ("variant", "originalError", "journalFailed", "faults", "initial", "generations",
                          "retainedIdentities", "physical", "nativeCommands"), "primitive failure observation")
            variant = row["variant"]
            expected_error = (None if variant == "short-write" else "ProcessCleanupError" if variant == "close-after"
                else "ProcessError" if variant == "reader-close-after" else "OSError" if variant.endswith(("-before", "-after"))
                or variant == "partial-write-error" else "FileExistsError" if variant.startswith("pending-")
                else "CredentialError")
            require(row["originalError"] == expected_error
                    and row["journalFailed"] is (name != "reader-failures" and variant != "short-write"),
                    "primitive failure outcome/latch differs")
            for key in ("initial", "retainedIdentities"):
                require(type(row[key]) is dict and 0 < len(row[key]) <= 256
                        and all(type(path) is str and 0 < len(path) <= 4096 and type(identity) is list
                                and len(identity) == 2 and all(type(value) is int for value in identity)
                                and identity[0] >= 0 and identity[1] > 0 for path, identity in row[key].items()),
                        "primitive original identity observations missing")
            require(type(row["generations"]) is dict and len(row["generations"]) <= 256
                    and all(type(key) is str and re.fullmatch(r"[0-9]+:[0-9]+", key)
                            and type(value) is dict and bool(value) for key, value in row["generations"].items())
                    and type(row["physical"]) is dict and set(row["physical"]) == set(row["retainedIdentities"]),
                    "primitive retained generation/physical observations missing")
            for physical in row["physical"].values():
                require(type(physical) is dict and type(physical.get("type")) is int
                        and physical["type"] in {stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK}
                        and type(physical.get("mode")) is int and 0 <= physical["mode"] <= 0o7777
                        and type(physical.get("links")) is int and physical["links"] > 0
                        and type(physical.get("initialAliases")) is list
                        and len(physical["initialAliases"]) <= 256
                        and all(type(alias) is str for alias in physical["initialAliases"]),
                        "primitive physical observation fields")
                if physical["type"] == stat.S_IFREG:
                    require(type(physical.get("size")) is int and 0 <= physical["size"] <= 4 * 1024**2,
                            "primitive retained file size")
                    _hash(physical.get("sha256"), "primitive retained bytes")
            faults = row["faults"]
            no_fault = variant.startswith(("pending-", "immutable-"))
            require(type(faults) is list and len(faults) == (0 if no_fault else 1), "primitive actual fault count differs")
            if no_fault:
                continue
            fault = faults[0]
            prefix = variant in {"short-write", "partial-write-error"}
            replacement = variant in {"stage-replaced", "target-replaced", "reader-name-changed"}
            _object(fault, {"variant", "event", "effectCompleted"} | ({"written", "prefixHex"} if prefix else set())
                    | ({"replacement"} if replacement else set()), "primitive actual fault")
            require(fault["variant"] == variant
                    and fault["effectCompleted"] is (not variant.endswith("-before")
                        and variant not in {"zero-write", "oversized-write"}), "primitive original fault effect differs")
            event = fault["event"]
            _object(event, ("index", "operation", "slot", "origin", "phase", "occurrence", "details"), "primitive fault event")
            operation = ("write" if variant in {"short-write", "zero-write", "oversized-write", "partial-write-error"}
                         else "fsync" if "sync-" in variant else "unlink" if variant.startswith("unlink-")
                         else "read" if variant in {"read-before", "read-after", "reader-name-changed"} else "close")
            require(event["operation"] == operation and event["phase"] == "component"
                    and type(event["index"]) is int and event["index"] > 0
                    and type(event["occurrence"]) is int and event["occurrence"] > 0
                    and type(event["slot"]) is str and bool(event["slot"])
                    and type(event["origin"]) is str and bool(event["origin"]) and type(event["details"]) is dict,
                    "primitive original fault route differs")
            if prefix:
                require(type(fault["written"]) is int and 0 < fault["written"] <= 65536
                        and type(fault["prefixHex"]) is str and len(fault["prefixHex"]) == 2 * fault["written"]
                        and re.fullmatch(r"[0-9a-f]+", fault["prefixHex"]), "primitive actual write prefix missing")
            if replacement:
                replaced = fault["replacement"]
                _object(replaced, ("device", "inode", "mode", "size", "sha256"), "primitive replacement facts")
                require(type(replaced["device"]) is int and replaced["device"] >= 0
                        and type(replaced["inode"]) is int and replaced["inode"] > 0
                        and type(replaced["mode"]) is int and replaced["mode"] == 0o600
                        and type(replaced["size"]) is int and 0 <= replaced["size"] <= 4 * 1024**2
                        and row["generations"].get(str(replaced["device"]) + ":" + str(replaced["inode"]))
                            == {"fixtureReplacement": variant}, "primitive replacement generation differs")
                _hash(replaced["sha256"], "primitive replacement bytes")
    else:
        require(type(observation["actualCuts"]) is int and observation["actualCuts"] == len(rows)
                and type(observation["algorithmEvents"]) is int and observation["algorithmEvents"] > 0,
                "primitive dynamic cut count")
        groups = {}
        for row in rows:
            _object(row, ("event", "edge", "physicalSha256", "nativeCommands"), "primitive cut")
            event = row["event"]
            require(type(event) is dict and type(event.get("operation")) is str
                    and row["edge"] in {"before", "after", "partial"}, "primitive reached operation")
            _hash(row["physicalSha256"], "primitive physical state")
            key = canonical({name: value for name, value in event.items() if name not in {"succeeded", "error"}})
            edges = groups.setdefault(key, [])
            require(row["edge"] not in edges, "primitive duplicate reached cut")
            edges.append(row["edge"])
        require(len(groups) == observation["algorithmEvents"], "primitive operation inventory differs")
        for event, actual in groups.items():
            operation = strict_json(event)["operation"]
            expected = {"before", "after"}
            if operation in {"write", "buffer.write"}:
                expected.add("partial")
            require(set(actual) == expected, "primitive omitted operation edge")


def _semantic_cut(observation, selector):
    require(type(observation) is dict and type(observation.get("event")) is dict
            and type(observation["event"].get("details")) is dict
            and type(observation["event"].get("occurrence")) is int
            and canonical(observation.get("selector")) == canonical(selector.record())
            and selector.routes(observation["event"]) and observation.get("edge") == selector.edge,
            "semantic actual selected cut differs")
    context = observation.get("context")
    require(type(context) is dict and all(key in context and type(context[key]) is type(value)
                                        and context[key] == value for key, value in selector.context),
            "semantic actual live context differs")


def _semantic_clean_snapshot(value):
    require(type(value) is dict and value.get("session") is None and "session" in value
            and all(type(value.get(key)) is dict and not value[key]
                    for key in ("controls", "fences", "native", "ownedRemaining"))
            and value.get("nativeDirectory") is False and type(value.get("preferences")) is dict,
            "semantic final snapshot retains or omits resource state")


def _semantic_recovery(step, token, *, manual, expected):
    _object(step, ("name", "manual", "expected", "original", "observation"), "semantic recovery step")
    value = step["observation"]
    require(step["manual"] == manual and step["expected"] == expected
            and value.get("sessionToken") == token and value.get("expectedStatus") == expected
            and type(value.get("unknown")) is dict and type(value.get("before")) is dict
            and type(value.get("after")) is dict, "semantic actual recovery route differs")
    if expected == "refused-unknown-resource":
        require(type(value.get("refused")) is str and bool(value["refused"])
                and value.get("result") is None and "result" in value and bool(value["unknown"])
                and value.get("idleAndRenewedAdmission") is False
                and value["before"].get("session") == value["after"].get("session") == token,
                "semantic actual refusal/pending state differs")
    else:
        require(value.get("refused") is None and "refused" in value
                and value.get("idleAndRenewedAdmission") is True, "semantic actual positive recovery missing")
        _object(value.get("result"), ("status", "session"), "semantic actual recovery result")
        require(value["result"] == {"status": expected, "session": token}, "semantic actual recovery outcome differs")
        _semantic_clean_snapshot(value["after"])
        _semantic_clean_snapshot(value.get("snapshot"))
    events = value.get("events")
    require(type(events) is list and len(events) <= MAX_CASES and all(type(event) is dict for event in events),
            "semantic recovery events missing")
    inputs = [event for event in events if event.get("operation") == "manual/input"]
    require(len(inputs) == (0 if manual == "none" else 1)
            and all(event.get("details") == {"action": manual} and event.get("origin") == "owner"
                    and event.get("slot") == "tty" and event.get("succeeded") is True for event in inputs),
            "semantic actual manual recovery differs")


def _semantic_focused_refusal(step, token, *, manual, preserve_preferences=False):
    _object(step, ("name", "manual", "original", "observation"), "focused refusal step")
    value = step["observation"]
    require(step["manual"] == manual and value.get("resourcesPreserved") is True
            and value.get("freshAdmission") == "pending" and type(value.get("error")) is str and bool(value["error"])
            and type(value.get("before")) is dict and type(value.get("after")) is dict
            and value["before"].get("session") == value["after"].get("session") == token,
            "focused actual refusal/preservation missing")
    if preserve_preferences:
        require(type(value["before"].get("preferences")) is dict
                and value["before"]["preferences"] == value["after"].get("preferences"),
                "focused refusal changed preserved preferences")
    events, inputs = value.get("events"), value.get("inputObservations")
    require(type(events) is list and type(inputs) is list and len(events) == len(inputs) == (manual != "none")
            and all(type(event) is dict for event in events) and all(type(row) is dict for row in inputs),
            "focused actual manual refusal observations missing")
    expected_error = {"none": "CredentialError", "wrong": "CredentialError", "eof": "CredentialError",
                      "cancel": "KeyboardInterrupt", "resolve": "OwnerResolutionRefused"}[manual]
    require(value.get("caughtType") == expected_error, "focused original refusal outcome differs")
    if events:
        event, observed = events[0], inputs[0]
        require(event.get("operation") == "manual/input" and event.get("origin") == "owner"
                and event.get("slot") == "tty" and event.get("details") == {"action": manual}
                and type(event.get("index")) is int and event["index"] > 0
                and type(observed.get("eventIndex")) is int and observed["eventIndex"] == event["index"]
                and observed.get("action") == manual,
                "focused actual input route differs")
        if manual in {"wrong", "eof"}:
            require(event.get("succeeded") is True and canonical(observed.get("read")) == canonical({
                "kind": manual, "characters": 6 if manual == "wrong" else 0}), "focused actual terminal read differs")
        else:
            require(event.get("succeeded") is None and "read" not in observed, "focused failed input was completed")


def _semantic_fixture_owner(step, token, *, variant, expected):
    _object(step, ("name", "original", "observation"), "focused fixture-owner step")
    value = step["observation"]
    require(value.get("manualFixtureAction") is True and value.get("idleAndRenewedAdmission") is True
            and value.get("result") == {"status": expected, "session": token}, "focused original owner recovery missing")
    _semantic_clean_snapshot(value.get("after"))
    require(type(value.get("preferences")) is dict and value["preferences"] == value["after"]["preferences"],
            "focused owner preferences differ")
    events, inputs = value.get("events"), value.get("inputObservations")
    require(type(events) is list and len(events) == 1 and type(events[0]) is dict
            and type(inputs) is list and len(inputs) == 1, "focused actual owner input missing")
    event, action = events[0], "fixture/" + variant
    require(event.get("operation") == "manual/input" and event.get("origin") == "owner"
            and event.get("slot") == "tty" and event.get("details") == {"action": action}
            and type(event.get("index")) is int and event["index"] > 0 and event.get("succeeded") is True
            and canonical(inputs[0]) == canonical({"eventIndex": event["index"], "action": action,
                "read": {"kind": "recheck", "characters": len(token) + 9}}), "focused actual owner completion differs")


def _semantic_focused(source, variant, steps, token):
    """Closed existing F routes, not an adaptive recovery or permission engine."""
    require(variant in source.FOCUSED_VARIANTS, "unknown focused variant")
    seed = (source.native("native-effect/create-search-add", operationKind="create", operationPhase="ARMED")
            if variant == "auto-add-ambiguous-create" else source.SEEDS[
                "profile-unrecorded-stage" if variant.startswith("manual-") else
                "completed" if variant.startswith("terminal-") else "active-after-build"])
    _semantic_cut(steps[0]["observation"], seed)
    direct = {"foreign-default": source.CONFLICT, "reordered-search": source.CONFLICT,
              "deleted-search": source.CONFLICT, "foreign-profile": source.CONFLICT,
              "auto-add-active": source.RECOVERED, "borrowed-profile": source.RECOVERED}
    owner = {"profile-inplace-edit": source.RECOVERED, "terminal-profile-reappeared": source.RECOVERED,
             "terminal-native-reappeared": source.RECOVERED, "foreign-native-db": source.CONFLICT}
    if variant in direct:
        names, negatives = ["seed", "focused-main"], []
    elif variant == "foreign-native-db":
        names, negatives = ["seed", "focused-none", "focused-resolve", "focused-fixture-owner"], [
            ("negative-none", 1), ("negative-resolve", 2)]
    else:
        names = ["seed", "focused-refusal", "focused-fixture-owner" if variant in owner else "focused-resolution"]
        negatives = [("negative", 1)]
    require([step["name"] for step in steps] == names, "focused lifecycle steps differ")
    if variant in direct:
        _semantic_recovery(steps[1], token, manual="none", expected=direct[variant])
    elif variant in {"native-unknown-stage", "auto-add-ambiguous-create"}:
        _semantic_recovery(steps[1], token, manual="none", expected=source.REFUSED)
        _semantic_recovery(steps[2], token, manual="resolve",
                           expected=source.CONFLICT if variant == "native-unknown-stage" else source.RECOVERED)
    elif variant == "foreign-native-db":
        for step, mode in zip(steps[1:3], ("none", "resolve")):
            _semantic_focused_refusal(step, token, manual=mode, preserve_preferences=True)
    else:
        _semantic_focused_refusal(steps[1], token,
            manual=variant.removeprefix("manual-") if variant.startswith("manual-") else "none",
            preserve_preferences=variant.startswith("terminal-"))
        if variant.startswith("manual-"):
            _semantic_recovery(steps[2], token, manual="resolve", expected=source.RECOVERED)
    if variant in owner:
        _semantic_fixture_owner(steps[-1], token, variant=variant, expected=owner[variant])
    return [(suffix, steps[index]) for suffix, index in negatives]


def _semantic_healthy(value, source):
    """Bounded finalized H data; original fixture owns detailed native predicates."""
    contexts = value.get("healthyContexts")
    _object(contexts, ("commands", "checkpoints", "effects"), "healthy context inventory")
    commands, checkpoints, effects = (contexts[key] for key in ("commands", "checkpoints", "effects"))
    require(all(type(rows) is list and len(rows) == count and all(type(row) is dict for row in rows)
                for rows, count in ((commands, 50), (checkpoints, 11), (effects, 7))), "healthy context union incomplete")
    snapshot, events = value.get("snapshot"), value.get("events")
    _semantic_clean_snapshot(snapshot)
    require(type(snapshot.get("original")) is dict and snapshot["preferences"] == snapshot["original"],
            "healthy final preferences differ")
    calls = snapshot.get("nativeCalls")
    require(type(calls) is list and len(calls) == 50 and all(type(row) is dict for row in calls)
            and type(events) is list and 0 < len(events) <= MAX_CASES and all(type(row) is dict for row in events),
            "healthy original command/event observations missing")
    for ordinal, (command, call) in enumerate(zip(commands, calls), 1):
        _object(call, ("command", "mutation", "recovery"), "healthy original command")
        require(type(call["command"]) is str and bool(call["command"]) and type(call["mutation"]) is bool
                and call["recovery"] is False and type(command.get("ordinal")) is int
                and command["ordinal"] == ordinal and command.get("command") == call["command"]
                and command.get("mutation") is call["mutation"]
                and command.get("phase") == ("setup" if ordinal < 27 else "build" if ordinal == 27 else "cleanup"),
                "healthy original command context differs")
    positions, revisions, intents = [], [], []
    for ordinal, (row, completed) in enumerate(zip(checkpoints, (14, 16, 19, 21, 24, 26, 27, 34, 39, 44, 46)), 1):
        require(type(row.get("ordinal")) is int and row["ordinal"] == ordinal
                and row.get("caller") in {"activate", "remember_preferences", "cleanup_native", "cleanup_profile"}
                and type(row.get("completedModelCalls")) is int and row["completedModelCalls"] == completed
                and type(row.get("eventPosition")) is int and 0 <= row["eventPosition"] < len(events),
                "healthy checkpoint return context differs")
        state = row.get("state")
        require(type(state) is dict and "inflight" in state and state["inflight"] is None
                and state.get("conflict") is False and type(state.get("revision")) is int and state["revision"] > 0,
                "healthy checkpoint state missing or unsettled")
        _hash(row.get("intentSha256"), "healthy original intent")
        require(row.get("stateSha256") == hashlib.sha256(canonical(state) + b"\n").hexdigest(),
                "healthy checkpoint bytes differ")
        positions.append(row["eventPosition"])
        revisions.append(state["revision"])
        intents.append(row["intentSha256"])
    require(positions == sorted(set(positions)) and revisions == sorted(set(revisions)) and len(set(intents)) == 1,
            "healthy checkpoint order or original intent differs")
    for row, operation in zip(effects, ("extract", "extract", "extract", "preference/search", "preference/default",
                                        "preference/default", "preference/search")):
        require(row.get("operation") == operation and type(row.get("eventIndex")) is int
                and 1 <= row["eventIndex"] <= len(events) and type(row.get("commandOrdinal")) is int
                and 1 <= row["commandOrdinal"] <= 50 and type(row.get("occurrence")) is int
                and row["occurrence"] > 0 and row.get("phase") == commands[row["commandOrdinal"] - 1]["phase"]
                and type(row.get("beforePreferences")) is dict and type(row.get("afterPreferences")) is dict,
                "healthy effect context missing")
        event = events[row["eventIndex"] - 1]
        require(type(event.get("index")) is int and event["index"] == row["eventIndex"]
                and event.get("operation") == "native-effect/" + operation and event.get("phase") == row["phase"]
                and type(event.get("occurrence")) is int and event["occurrence"] == row["occurrence"]
                and event.get("origin") == "model" and event.get("slot") == "native"
                and event.get("details") == {} and event.get("succeeded") is True and "error" not in event,
                "healthy actual effect did not complete")
    publication = [event for event in events if event.get("operation") == "replace"
                   and event.get("slot") == source.SESSION + "/completed.pending"
                   and event.get("origin") == source.LOCAL + "_write"]
    require(len(publication) == 1 and type(publication[0].get("index")) is int
            and positions[-1] < publication[0]["index"] <= len(events) and publication[0].get("succeeded") is True,
            "healthy actual terminal publication missing or early")


def _semantic_native_prefix(cut, source, name, token):
    payload = source.NATIVE_PREFIX_CONTENT[name]
    proof = cut.get("physicalWrite")
    _object(proof, ("name", "bytes", "intendedBytes", "sha256", "intendedSha256", "facts", "properPrefix", "revisionAtCut"),
            "native prefix observation")
    filename = source.NATIVE_PREFIXES[name].operation.removeprefix("native-effect/write/")
    revision, ordinal = (1, 4) if name == "transaction-stage" else (0, 3)
    require(proof["name"] == filename and type(proof["bytes"]) is int and 0 < proof["bytes"] < len(payload)
            and type(proof["intendedBytes"]) is int and proof["intendedBytes"] == len(payload)
            and proof["properPrefix"] is True and type(proof["revisionAtCut"]) is int and proof["revisionAtCut"] == revision
            and proof["sha256"] == hashlib.sha256(payload[:proof["bytes"]]).hexdigest()
            and proof["intendedSha256"] == hashlib.sha256(payload).hexdigest(), "native actual source prefix differs")
    facts = proof["facts"]
    _object(facts, ("device", "inode", "mode", "size", "sha256"), "native prefix file facts")
    require(type(facts["device"]) is int and facts["device"] >= 0 and type(facts["inode"]) is int and facts["inode"] > 0
            and type(facts["mode"]) is int and facts["mode"] == 0o600
            and type(facts["size"]) is int and facts["size"] == proof["bytes"] and facts["sha256"] == proof["sha256"],
            "native actual prefix file differs")
    snapshot = cut.get("snapshot")
    relative = source.KEYCHAIN.removeprefix("<ROOT>/").replace("<TOKEN>", token) + "/" + filename
    require(type(snapshot) is dict and snapshot.get("session") == token and type(snapshot.get("native")) is dict
            and canonical(snapshot["native"].get(relative)) == canonical(facts)
            and cut["context"].get("recoveryAttempt") is False, "native prefix snapshot is not its original file")
    command = "set-keychain-settings" if ordinal == 4 else "create-keychain"
    require(canonical(cut.get("originalCommand")) == canonical({"command": command, "ordinal": ordinal,
        "keychain": source.KEYCHAIN + "/" + source.DB_NAME, "revisionBefore": 0}), "native original command binding differs")
    calls = snapshot.get("nativeCalls")
    require(type(calls) is list and len(calls) == ordinal and type(calls[-1]) is dict
            and canonical(calls[-1]) == canonical({"command": command, "mutation": True, "recovery": False}),
            "native prefix original model call missing")


def _semantic_record(item, observation, evidence, parts):
    name = item.name
    _object(observation, ("caseId", "status", "evidence", "caseRemoved", "originalWorkersSettled",
                          "regressionContributions"), "semantic observation")
    stem = "semantic-" + digest(name)
    complete_name = stem + "-complete.json"
    require(observation["caseId"] == name and observation["status"] == "semantic-subset-case"
            and observation["evidence"] == complete_name and observation["caseRemoved"] is True
            and observation["originalWorkersSettled"] is True
            and canonical(observation["regressionContributions"]) == canonical(parts), "semantic observation binding")
    require(complete_name in evidence, "semantic complete evidence missing")
    complete = evidence[complete_name]
    _object(complete, ("schema", "case", "steps", "negativeEvidence"), "semantic complete evidence")
    specification = json.loads(item.specification)
    require(complete["schema"] == "mrk-signing-semantic-case-v1"
            and canonical(complete["case"]) == canonical(specification), "semantic case specification changed")
    steps = complete["steps"]
    require(type(steps) is list and 0 < len(steps) <= 8 and all(type(step) is dict for step in steps)
            and all(type(step.get("name")) is str for step in steps)
            and len({step["name"] for step in steps}) == len(steps), "semantic step inventory")
    for step in steps:
        require({"name", "original", "observation"} <= set(step) and type(step["observation"]) is dict,
                "semantic original observation missing")
        _original_case_return(step["original"], 73 if step["name"] in {"seed", "recovery-cut"} else 0)
        if step["name"] in {"seed", "recovery-cut", "healthy"}:
            _object(step, ("name", "original", "observation"), "semantic original step")
    kind, source = specification["kind"], layered_catalog().SEMANTIC
    token = steps[0]["observation"].get("sessionToken")
    require(type(token) is str and re.fullmatch(r"[0-9a-f]{32}", token), "semantic original session token missing")
    negative_steps = []
    if kind == "focused":
        negative_steps = _semantic_focused(source, specification["variant"], steps, token)
    else:
        names = ["healthy"] if kind == "healthy" else [
            "seed", *(("recovery-cut",) if kind == "recovery" else ()), "semantic-main",
            *(("semantic-resolution",) if specification["resolution"] is not None else ()),
        ]
        require([step["name"] for step in steps] == names, "semantic lifecycle steps differ")
        if kind == "healthy":
            _semantic_healthy(steps[0]["observation"], source)
        else:
            cut = steps[1 if kind == "recovery" else 0]["observation"]
            require(cut.get("sessionToken") == token, "semantic selected session differs from its original seed")
            _semantic_cut(cut, source.case(name).selector)
            if kind == "recovery":
                initial = source.QUERY_DEBT_SEED if specification["seed"] == "query-settled-partial" else source.SEEDS[specification["seed"]]
                _semantic_cut(steps[0]["observation"], initial)
            if kind == "command" and specification["selector"]["operation"].startswith("command-fence/"):
                fence = cut.get("originalCFenceObservation")
                require(type(fence) is dict and fence.get("originalWorker") is True
                        and fence.get("operation") == specification["selector"]["operation"].removeprefix("command-fence/")
                        and fence.get("edge") == specification["selector"]["edge"].upper(), "actual original-C cut missing")
                if specification["selector"]["edge"] == "partial":
                    validate_original_c_prefix(fence)
            if kind == "native-prefix":
                _semantic_native_prefix(cut, source, specification["seed"], token)
            main = steps[-2] if specification["resolution"] is not None else steps[-1]
            _semantic_recovery(main, token, manual=specification["manual"] if kind == "seed" else "none",
                               expected=specification["expected"])
            if specification["resolution"] is not None:
                negative_steps = [("negative", main)]
                _semantic_recovery(steps[-1], token, manual="resolve", expected=specification["resolution"])
    negative = complete["negativeEvidence"]
    expected_negative = [(stem + "-" + suffix + ".json", step) for suffix, step in negative_steps]
    require(type(negative) is list and negative == [filename for filename, _step in expected_negative],
            "semantic source-required negative evidence names differ")
    required = {complete_name, *negative}
    for filename, step in expected_negative:
        require(filename in evidence and canonical(evidence[filename]) == canonical(step),
                "semantic negative evidence lost")
    if parts:
        alias_name = stem + "-regression.json"
        required.add(alias_name)
        require(alias_name in evidence, "semantic regression contribution evidence missing")
        expected_alias = {"schema": "mrk-signing-semantic-contribution-v1", "semantic": name,
                          "contributions": parts, "evidenceSha256": digest(complete)}
        require(canonical(evidence[alias_name]) == canonical(expected_alias), "semantic regression predicates not bound")
    require(set(evidence) == required, "semantic evidence inventory differs")


def validate_layered_record(record, operating_system):
    """Validate typed original observations as DATA, never as live resource custody."""
    _object(record, ("schemaVersion", "caseId", "kind", "name", "observation", "evidence", "regressionParts"),
            "layered actual result")
    require(type(record["schemaVersion"]) is int and record["schemaVersion"] == 2, "unsupported actual result version")
    catalog = layered_catalog()
    item = catalog.case(record["caseId"], operating_system)
    require(record["kind"] == item.kind and record["name"] == item.name, "cross-kind or renamed actual result")
    parts = list(catalog.regression_parts(item, operating_system))
    require(canonical(record["regressionParts"]) == canonical(parts), "missing or extra regression contribution")
    observation, evidence = record["observation"], record["evidence"]
    require(type(observation) is dict and type(evidence) is dict and 0 < len(evidence) <= 5,
            "missing bounded original evidence")
    if item.kind == "primitive":
        _primitive_record(item, observation, evidence)
    elif item.kind == "semantic":
        _semantic_record(item, observation, evidence, parts)
    else:
        _object(observation, ("caseId", "status", "evidence", "caseRemoved", "originalWorkersSettled"),
                "regression observation")
        filename = "regression-" + digest(item.name) + ".json"
        require(observation["caseId"] == item.name and observation["status"] == "regression-case"
                and observation["evidence"] == filename and observation["caseRemoved"] is True
                and observation["originalWorkersSettled"] is True and set(evidence) == {filename},
                "regression original completion missing")
        specification = json.loads(item.specification)
        expected = {"schema": "mrk-signing-regression-case-v1", "case": specification,
                    "originalTestcaseCompleted": True, "typedVariant": specification["helper"] != "whole",
                    "testsRun": 1, "setupBodyTeardownCleanupsReturned": True,
                    "originalWorkersSettled": True, "caseRemoved": True}
        require(canonical(evidence[filename]) == canonical(expected), "regression testcase lifecycle differs")
    return item.identifier


def validate_actual_results(content, expected, *, operating_system, deadline=None):
    """Only original finalized bytes; exact source-defined kinds/variant union."""
    before_deadline(deadline)
    validate_ids(expected, "actual assigned cases")
    require(set(expected) <= set(layered_catalog().expected_ids(operating_system)), "unknown assigned source cases")
    require(type(content) is bytes and 0 < len(content) <= MAX_RESULTS_BYTES, "actual result compressed bound")
    actual, expanded = [], 0
    with gzip.GzipFile(fileobj=io.BytesIO(content), mode="rb") as stream:
        while True:
            before_deadline(deadline)
            line = stream.readline(2 * 1024 * 1024 + 1)
            if not line:
                break
            expanded += len(line)
            require(expanded <= MAX_EXPANDED_RESULTS and len(line) <= 2 * 1024 * 1024
                    and line.endswith(b"\n"), "oversized/incomplete actual result")
            record = strict_json(line.decode("utf-8"))
            actual.append(validate_layered_record(record, operating_system))
            require(len(actual) <= len(expected), "extra actual executions")
    require(actual == expected, "actual layered executions omit, duplicate or reorder assigned cases")
    before_deadline(deadline)
    return hashlib.sha256(content).hexdigest()


def read_proof(path):
    require(path.is_file() and not path.is_symlink(), "proof must be a regular file")
    require(0 < path.stat().st_size <= MAX_PROOF_BYTES, "proof exceeds size bound")
    with path.open("rb") as stream:
        content = stream.read(MAX_PROOF_BYTES + 1)
    require(len(content) <= MAX_PROOF_BYTES, "proof grew beyond size bound")
    return strict_json(content.decode("utf-8"))


def proof_paths(root):
    require(root.is_dir() and not root.is_symlink(), "proof directory missing or symlinked")
    # Python 3.11 Path.iterdir uses eager listdir, even when wrapped in islice.
    # Bound the actual directory scan, and release its handle before validation.
    with os.scandir(root) as entries:
        directories = [Path(entry.path) for entry in islice(entries, MAX_PROOFS + 1)]
    require(0 < len(directories) <= MAX_PROOFS, "missing or excessive proof artifacts")
    total = 0
    for directory in sorted(directories):
        require(ARTIFACT.fullmatch(directory.name) and directory.is_dir() and not directory.is_symlink(), "unexpected artifact directory")
        with os.scandir(directory) as entries:
            names = [entry.name for entry in islice(entries, 2)]
        require(names == ["proof.json"], "artifact has missing or extra files")
        path = directory / "proof.json"
        require(path.is_file() and not path.is_symlink(), "non-regular proof")
        total += path.stat().st_size
        require(total <= MAX_TOTAL_BYTES, "aggregate proof bytes exceed bound")
        yield directory.name, path
