"""Strict test-execution records. These are NOT release attestations or authority."""
from __future__ import annotations

import hashlib
import ast
import gzip
import io
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

SHARDS = 16
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
)
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


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


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
    """Closed four-method preparation check; not full matrix coverage."""
    before_deadline(deadline)
    path = root / "tests/unit/test_local_signing_persistent.py"
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 1024**2,
            "adapter test definition missing or oversized")
    tree = ast.parse(path.read_bytes(), filename=str(path))
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "PersistentSigningTests"]
    require(len(classes) == 1, "adapter class inventory")
    methods = [node.name for node in classes[0].body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    require(all(methods.count(identifier.rsplit(".", 1)[1]) == 1 for identifier in ADAPTER_TEST_IDS),
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


def validate_adapter_record(record, scope, phase, package):
    require(type(record) is dict and set(record) == {"schema", "phase", "scope", "status", "productionRoot",
            "startedIds", "successfulIds", "testsRun", "origins", "casePathsRemoved"}, "adapter record fields")
    require(record["schema"] == "mrk-signing-adapter-phase-v1" and record["status"] == "adapter-only"
            and type(record["scope"]) is dict and canonical(record["scope"]) == canonical(scope)
            and record["phase"] == phase
            and record["productionRoot"] == str(package), "adapter record binding")
    require(record["startedIds"] == list(ADAPTER_TEST_IDS) == record["successfulIds"]
            and type(record["testsRun"]) is int and record["testsRun"] == len(ADAPTER_TEST_IDS)
            and record["casePathsRemoved"] is True, "adapter actual successful IDs or retained cases")
    origins = record["origins"]
    require(type(origins) is dict and 1 <= len(origins) <= 100
            and {"mobile_release", "mobile_release.local_signing", "mobile_release.owned_process",
                 "mobile_release._command_process", "mobile_release._native_process"} <= set(origins),
            "adapter actual loaded modules missing")
    for name, relative in origins.items():
        require(type(name) is str and re.fullmatch(r"mobile_release(?:\.[A-Za-z_][A-Za-z0-9_]*)*", name)
                and type(relative) is str and relative in {
                    "/".join(name.split(".")[1:]) + ".py",
                    "/".join([*name.split(".")[1:], "__init__.py"]),
                }, "adapter loaded origin escaped package")


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


def validate_phase(run, expected, shard, package_sha, definitions_sha, mode):
    """The same per-phase contract before wheel dispatch and in the reducer."""
    require(mode in {"source", "wheel"} and type(shard) is int and 0 <= shard < SHARDS, "invalid phase selection")
    validate_ids(expected, "expected cases")
    selected = [case for case in expected if shard_for(case) == shard]
    require(selected, "empty shard")
    _object(run, ("executedCaseIds", "inventorySha256", "packageSha256", "definitionsSha256",
                  "resultsSha256", "allExactChildrenReapedAndGroupsAbsent", "allCasePathsRemoved"), mode)
    validate_ids(run["executedCaseIds"], mode + " executed cases")
    require(run["executedCaseIds"] == selected, mode + " has omitted, extra or incorrectly assigned cases")
    for key in ("inventorySha256", "packageSha256", "definitionsSha256", "resultsSha256"):
        _hash(run[key], mode + " " + key)
    require(run["packageSha256"] == package_sha, "production package differs from aggregate checkout")
    require(run["definitionsSha256"] == definitions_sha, "test definitions differ from aggregate checkout")
    require(run["allExactChildrenReapedAndGroupsAbsent"] is True and run["allCasePathsRemoved"] is True,
            "unconfirmed worker/fixture cleanup")


def validate_proof(proof, name, expected_scope, package_sha, definitions_sha):
    _object(proof, ("schemaVersion", "scope", "shard", "expectedCaseIds", "expectedSha256", "source", "wheel"), "proof")
    require(type(proof["schemaVersion"]) is int and proof["schemaVersion"] == 1, "unsupported proof version")
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
    _hash(proof["expectedSha256"], "expected cases")
    require(proof["expectedSha256"] == digest(expected), "expected case digest differs")
    for mode in ("source", "wheel"):
        validate_phase(proof[mode], expected, shard, package_sha, definitions_sha, mode)
    require(proof["source"]["inventorySha256"] == proof["wheel"]["inventorySha256"], "source/wheel inventory drift")
    return proof


def reconcile(candidates, expected_scope, package_sha, definitions_sha, *, operating_systems=OPERATING_SYSTEMS):
    """Validate ALL attempts before selecting latest complete cells; no fallback."""
    require(tuple(operating_systems) in (OPERATING_SYSTEMS, ("ubuntu-24.04",), ("macos-26",)), "invalid required OS set")
    expected_by_os, inventory_by_os, latest, seen, names = {}, {}, {}, set(), set()
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
        expected = proof["expectedCaseIds"]
        inventory = proof["source"]["inventorySha256"]
        require(expected_by_os.setdefault(operating_system, expected) == expected, "cross-cell expected inventory differs")
        require(inventory_by_os.setdefault(operating_system, inventory) == inventory, "cross-cell effect inventory differs")
        if key not in latest or scope["attempt"] > latest[key]["scope"]["attempt"]:
            # Share the agreed immutable expected list instead of retaining a
            # separate large copy for every selected cell/older run attempt.
            latest[key] = {**proof, "expectedCaseIds": expected_by_os[operating_system]}
    require(count > 0, "missing execution proofs")
    required = {(system, shard) for system in operating_systems for shard in range(SHARDS)}
    require(set(latest) == required, "incomplete OS/shard product")
    results = {}
    for operating_system in operating_systems:
        results[operating_system] = {}
        for mode in ("source", "wheel"):
            union = set()
            for shard in range(SHARDS):
                actual = latest[(operating_system, shard)][mode]["executedCaseIds"]
                require(not union.intersection(actual), "executed shard sets overlap")
                union.update(actual)
            require(sorted(union) == expected_by_os[operating_system], "actual execution union omits expected cases")
            results[operating_system][mode] = {"cases": len(union), "caseIdsSha256": digest(sorted(union))}
    return {"status": "complete", "scope": expected_scope, "shards": SHARDS, "operatingSystems": results,
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


def validate_actual_results(content, expected, *, deadline=None):
    """Finalized bytes only; reconcile reached cuts, not requested IDs or PIDs."""
    before_deadline(deadline)
    validate_ids(expected, "actual assigned cases")
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
            require(type(record) is dict and {"caseId", "seed", "outcome", "results"} <= set(record), "actual result fields")
            group = record["seed"]
            require(type(group) is str and type(record["results"]) is dict, "actual result group")
            cut_name = "original-cut" if group == "original" else "recovery-cut"
            require(cut_name in record["results"], "actual reached cut missing")
            cut = record["results"][cut_name]
            case_id = logical_case_id(group, cut["event"], cut["edge"])
            require(record["caseId"] == case_id, "result ID disagrees with the actual reached crash cut")
            actual.append(case_id)
            require(len(actual) <= len(expected), "extra actual executions")
            require("final-automatic" in record["results"], "final recovery was not observed")
            require(type(record["outcome"]) is dict and "manual" in record["outcome"], "actual recovery outcome missing")
            if record["outcome"]["manual"] is not None:
                require({"final-no-resolution", "final-owner-resolution"} <= set(record["results"]),
                        "manual recheck observations missing")
            if cut["event"]["operation"].startswith("command-fence/"):
                observation = cut.get("originalCFenceObservation")
                require(type(observation) is dict and observation.get("originalWorker") is True
                        and observation.get("operation") == cut["event"]["operation"].removeprefix("command-fence/")
                        and observation.get("edge") == cut["edge"].upper(), "actual original-C cut evidence missing")
                if cut["edge"] == "partial":
                    validate_original_c_prefix(observation)
    require(actual == expected, "actual crash executions omit, duplicate or reorder assigned cases")
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
