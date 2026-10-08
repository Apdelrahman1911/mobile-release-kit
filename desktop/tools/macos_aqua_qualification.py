#!/usr/bin/env python3
"""Fixed, source-bound installed Mac Aqua scopes; never a general runner.

Importing this module loads only stdlib DATA/parsers. The native main alone
admits the hosted user/source, prepares exclusive synthetic fixtures, and loads
the pinned current-source run_owned. No Store, release, alternate command or cleanup
controller is provided. Unknown invocation finality preserves the fixtures.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
from dataclasses import dataclass
import hashlib
from importlib.machinery import ModuleSpec
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from types import FunctionType, ModuleType

# Fixed synthetic literals only. The reviewed project producer body is kept
# unchanged inside a module-level diagnostic try; no historical runner is imported.
RECOVERY_CASE = "project-recovery-pending"
IOS_ACCOUNT_CASE = "ios-recovery-pending"
IOS_ACCOUNT_LOCK_NAME = ".fl" + hashlib.sha1(b"signing.keychain-db", usedforsecurity=False).hexdigest()[:8].upper()
RECOVERY_FILES = {"project/.gitignore": b".mobile-release/\n", "project/unrelated.txt": b"unrelated synthetic file; preserve\n",
                  "project/google-services.json": b"synthetic original Android input\n",
                  "project/GoogleService-Info.plist": b"synthetic original iOS input\n"}
RECOVERY_FOREIGN = b"synthetic foreign iOS input; preserve\n"
RECOVERY_LIMITATIONS = ["build-inputs-only-not-store-or-account-recovery", "recorded-quiescence-not-new-worker-proof",
                       "foreign-changes-preserved", "cancellation-does-not-undo-completed-cleanup", "project-and-release-readiness-not-assessed"]
RECOVERY_JOINS = tuple(("inspectionJoined acquisitionJoined attempted childWaitedSuccess stdinClosed stdoutEofClosed stderrEofClosed ioJoined "
                       "coreLifetimeSettled runtimeLedgerSettled runtimeSettlementJoined driverJoined managerJoined observerJoined watchdogJoined retiredBeforeCutoff").split())


def _expected_recovery_report():
    """Inert comparison DATA only, never used to manufacture an observation."""
    observation = {"status": "pending", "session": "e" * 32, "roles": ["android-services", "ios-services"], "quiescence": "original"}
    originals, prepared = [], []
    for i, action in enumerate(("inspect", "recover")):
        operation, generation = ("a" if i == 0 else "c") * 32, ("b" if i == 0 else "d") * 32
        context = {"projectId": "inert-recovery-parser", "draftRevision": 1, "baselineGeneration": 1,
                   "action": action, "review": None if i == 0 else dict(observation)}
        prep = {"operationId": operation, "ownerGeneration": generation, "context": context, "phase": "awaiting-consent",
                "intentUsable": True, "outcome": None, "reason": "none", "result": None, "effect": None}
        prepared.append(prep)
        result = {"schemaVersion": 1, "scope": "project-build-inputs-only", "action": action,
                  "observation": dict(observation) if i == 0 else None,
                  "recoveredSession": None if i == 0 else observation["session"], "limitations": RECOVERY_LIMITATIONS}
        facts = {key: True for key in RECOVERY_JOINS}
        facts.update(domain="project-recovery", id=operation, generation=generation, noChild=False, activeRetained=False, resourceUnknown=False)
        originals.append({"facts": facts, "projection": {**prep, "phase": "terminal", "intentUsable": False,
            "outcome": "complete", "result": result, "effect": "inspection" if i == 0 else "recovery-attempted"},
            "accepted": True, "coreTerminal": True, "coreFatal": False, "reviewMinted": i == 0})
    return {"schemaVersion": 1, "scope": "project-build-input-recovery-native-observation-v1", "case": RECOVERY_CASE,
            "ordinaryProfileAvailableBeforeAdmission": True, "originals": originals, "prepared": prepared,
            "requests": [1] * 4, "replies": [1] * 4, "statusCallsReturned": 0,
            "freshUncheckedReview": True, "explicitAcknowledgement": True, "exactSessionReviewed": True, "finalVisible": True,
            "workMs": 120000, "hardMs": 130000, "observationMs": 315000, "outerInvocationMs": 325000,
            "commandDispatches": 0, "profileCalls": 0, "signedModesActivated": False, "shippingBinaryQualified": False}


def _recovery_report(value):
    expected = _expected_recovery_report()
    try:
        need(type(value) is dict and type(value["originals"]) is list and len(value["originals"]) == 2
             and type(value["prepared"]) is list and len(value["prepared"]) == 2, "recovery-original-pair")
        ids, generations = [], []
        context = value["prepared"][0]["context"]
        need(type(context["projectId"]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", context["projectId"])
             and all(type(context[key]) is int and 0 <= context[key] < 2**32-1 for key in ("draftRevision", "baselineGeneration")), "recovery-context")
        session = value["originals"][0]["projection"]["result"]["observation"]["session"]
        need(type(session) is str and re.fullmatch(r"[0-9a-f]{32}", session), "recovery-session")
        for i in range(2):
            original, prep = expected["originals"][i], expected["prepared"][i]
            operation, generation = value["prepared"][i]["operationId"], value["prepared"][i]["ownerGeneration"]
            need(all(type(token) is str and re.fullmatch(r"[0-9a-f]{32}", token) for token in (operation, generation)), "recovery-original-identity")
            ids.append(operation); generations.append(generation)
            prep.update(operationId=operation, ownerGeneration=generation)
            for key in ("projectId", "draftRevision", "baselineGeneration"):
                prep["context"][key] = context[key]
            original["facts"].update(id=operation, generation=generation)
            original["projection"].update(operationId=operation, ownerGeneration=generation)
            if i == 0:
                original["projection"]["result"]["observation"]["session"] = session
            else:
                prep["context"]["review"]["session"] = session
                original["projection"]["result"]["recoveredSession"] = session
        need(ids[0] != ids[1] and generations[0] != generations[1], "recovery-original-reused")
        calls = value["statusCallsReturned"]
        need(type(calls) is int and 0 <= calls <= 96, "recovery-status-calls")
        expected["statusCallsReturned"] = calls
    except (KeyError, TypeError, IndexError) as error:
        raise Refused("recovery-report-shape") from error
    _exact(value, expected, ("projectRecovery",))
    return value


# A failure record describes one returned precursor, never app success/finality.
IOS_ACCOUNT_FAILURE_REASONS = ('duplicate-private-key', 'native-account-entry', 'entry-bounds', 'original-clock', 'state-route', 'private-comparison-binding', 'native-account-user', 'original-work-expired', 'original-finality-expired', 'descriptor-not-original', 'descriptor-limit', 'descriptor-inheritance', 'baseline-original-changed', 'directory-route', 'directory-original', 'baseline-not-eligible', 'baseline-path', 'baseline-member-original', 'baseline-member-substitution', 'command-owner', 'fixed-native-command', 'original-account-command-source', 'command-deadline', 'native-original-return', 'native-original-finality', 'private-comparison-file', 'private-comparison-original', 'private-account-binding', 'profile-destination-occupied', 'pending-boundary-unsettled', 'private-comparison-bound', 'persistent-lease-substitution', 'native-baseline-not-restored', 'pending-session-remains', 'account-original-close', 'account-close-state', 'producer-original-finality', 'pending-origin', 'readback-only', 'receipt-bound', 'original-operation-failed')
# Role0 is the original producer literal; other fixed role IDs name
# src/mobile_release/<name>.py in the run's exact source, never an observed path.
PRECURSOR_FAILURE_SOURCE_ROLES = ('producer-literal', 'build_inputs', 'local_signing', 'init_transaction', 'checked_files', 'cancellation', 'owned_process', '_command_process', '_native_process', '_lifetime_evidence', '_profile_callers', 'errors')
PRECURSOR_FAILURE_CATEGORIES = ('none', 'refused', 'runtime', 'os', 'permission', 'missing', 'exists', 'timeout', 'blocked', 'broken-pipe', 'child-process', 'is-directory', 'not-directory', 'connection', 'connection-aborted', 'connection-refused', 'connection-reset', 'os-interrupted', 'process-missing', 'value', 'type', 'key', 'attribute', 'import', 'import-missing', 'assertion', 'interrupted', 'exit', 'not-implemented', 'recursion', 'index', 'overflow', 'memory', 'build-input', 'build-input-busy', 'build-input-root-changed', 'build-input-manual', 'desktop-recovery-refused', 'private-publication', 'signing-busy', 'signing-pending', 'init-conflict', 'init-operation-failure', 'init-interrupted', 'process', 'process-cleanup', 'process-outcome-unknown', 'process-interrupted', 'native-process', 'mobile-release', 'configuration', 'validation', 'credential', 'mutation-guard', 'store-operation', 'other')
PRECURSOR_FAILURE_OS_CATEGORIES = ('os', 'permission', 'missing', 'exists', 'timeout', 'blocked', 'broken-pipe', 'child-process', 'is-directory', 'not-directory', 'connection', 'connection-aborted', 'connection-refused', 'connection-reset', 'os-interrupted', 'process-missing')
PRECURSOR_FAILURE_LIMIT = 2048


def _precursor_spec(kind):
    need(type(kind) is str and kind in ("project-recovery-producer", "ios-account-produce", "ios-account-observe"),
         "precursor-diagnostic-kind")
    project = kind == "project-recovery-producer"
    return (SHELL_RECOVERY_PRODUCER if project else IOS_ACCOUNT_CORE_PROGRAM,
            b"MRK_PROJECT_RECOVERY_FIXTURE_FAILURE=" if project else b"MRK_IOS_ACCOUNT_FIXTURE_FAILURE=",
            ("fixture-check-failed", "original-operation-failed") if project else IOS_ACCOUNT_FAILURE_REASONS,
            16*1024 if kind == "ios-account-produce" else 2048)


def _precursor_exception_graph(value, kind, program):
    graph = value["exceptionGraph"]
    need(type(graph) is dict and set(graph) == {"raised", "caught", "nodes", "complete", "boundRoles"}
         and type(graph["raised"]) is int and graph["raised"] == 0
         and type(graph["complete"]) is bool, "precursor-diagnostic-graph")
    nodes, roles, caught = graph["nodes"], graph["boundRoles"], graph["caught"]
    need(type(nodes) is list and 1 <= len(nodes) <= 4
         and type(roles) is list and 1 <= len(roles) <= len(PRECURSOR_FAILURE_SOURCE_ROLES)
         and all(type(role) is int and 0 <= role < len(PRECURSOR_FAILURE_SOURCE_ROLES) for role in roles)
         and roles == sorted(set(roles)) and roles[0] == 0, "precursor-diagnostic-roles")
    # Both actual roots were reserved before cause/context expansion. A distinct
    # project caught object cannot be displaced by a long outer failure chain.
    need(caught is None or type(caught) is int and caught in (0, 1) and caught < len(nodes),
         "precursor-diagnostic-caught-root")
    need(kind == "project-recovery-producer" or caught is None, "precursor-diagnostic-caught-root")
    omitted = False
    for node in nodes:
        need(type(node) is dict and set(node) == {"category", "errno", "sites", "tracebackLinksSeen",
             "tracebackComplete", "unmappedFrames", "sitesTruncated", "cause", "context", "suppressed"},
             "precursor-diagnostic-node")
        need(type(node["category"]) is str and node["category"] in PRECURSOR_FAILURE_CATEGORIES
             and node["category"] != "none", "precursor-diagnostic-node-category")
        number = node["errno"]
        need(number is None or type(number) is int and 0 <= number <= 4095
             and node["category"] in PRECURSOR_FAILURE_OS_CATEGORIES, "precursor-diagnostic-errno")
        sites, links, unmapped = node["sites"], node["tracebackLinksSeen"], node["unmappedFrames"]
        need(type(sites) is list and len(sites) <= 8
             and type(links) is int and 0 <= links <= 32
             and type(unmapped) is int and 0 <= unmapped <= links
             and type(node["tracebackComplete"]) is bool and type(node["sitesTruncated"]) is bool
             and type(node["suppressed"]) is bool, "precursor-diagnostic-node-bounds")
        for site in sites:
            need(type(site) is list and len(site) == 2 and type(site[0]) is int and site[0] in roles
                 and type(site[1]) is int and 1 <= site[1] <= 1_000_000
                 and (site[0] != 0 or site[1] <= len(program.splitlines())), "precursor-diagnostic-node-site")
        need(node["tracebackComplete"] or links == 32, "precursor-diagnostic-node-cutoff")
        need((len(sites) == 8 and links > len(sites) + unmapped) if node["sitesTruncated"]
             else links == len(sites) + unmapped, "precursor-diagnostic-node-counts")
        for key in ("cause", "context"):
            edge = node[key]
            need(edge is None or type(edge) is int and -1 <= edge < len(nodes), "precursor-diagnostic-edge")
            omitted = omitted or edge == -1
    need(graph["complete"] == (not omitted), "precursor-diagnostic-graph-cutoff")
    reachable = {0} if caught is None else {0, caught}
    for _ in nodes:
        for index in tuple(reachable):
            for key in ("cause", "context"):
                edge = nodes[index][key]
                if edge is not None and edge >= 0:
                    reachable.add(edge)
    need(len(reachable) == len(nodes), "precursor-diagnostic-unreachable-node")
    need(value["exceptionCategory"] == nodes[0]["category"]
         and value["tracebackLinksSeen"] == nodes[0]["tracebackLinksSeen"]
         and (not value["sourceSitesComplete"] or nodes[0]["tracebackComplete"]),
         "precursor-diagnostic-raised-binding")
    if kind == "project-recovery-producer":
        need(value["caughtExceptionCategory"] == ("none" if caught is None else nodes[caught]["category"]),
             "precursor-diagnostic-caught-binding")


def _precursor_child_failure(stderr, kind):
    program, marker, reasons, _ = _precursor_spec(kind)
    if (type(stderr) is not bytes or not 0 < len(stderr) <= PRECURSOR_FAILURE_LIMIT or not stderr.startswith(marker)
            or not stderr.endswith(b"\n") or b"\n" in stderr[:-1]):
        return None
    try:
        value = json.loads(stderr[len(marker):-1], object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(Refused("precursor-diagnostic-json")))
        expected = {"schemaVersion", "reason", "exceptionCategory", "sourceSites", "tracebackLinksSeen", "sourceSitesComplete", "exceptionGraph"}
        if kind == "project-recovery-producer":
            expected.add("caughtExceptionCategory")
        need(type(value) is dict and set(value) == expected and type(value["schemaVersion"]) is int
             and value["schemaVersion"] == 2, "precursor-diagnostic-schema")
        need(type(value["reason"]) is str and value["reason"] in reasons
             and type(value["exceptionCategory"]) is str and value["exceptionCategory"] in PRECURSOR_FAILURE_CATEGORIES
             and value["exceptionCategory"] != "none", "precursor-diagnostic-enum")
        need(type(value["sourceSites"]) is list and len(value["sourceSites"]) <= 4
             and all(type(site) is int and 1 <= site <= len(program.splitlines()) for site in value["sourceSites"])
             and type(value["tracebackLinksSeen"]) is int and len(value["sourceSites"]) <= value["tracebackLinksSeen"] <= 32
             and type(value["sourceSitesComplete"]) is bool, "precursor-diagnostic-sites")
        if kind == "project-recovery-producer":
            need(type(value["caughtExceptionCategory"]) is str and value["caughtExceptionCategory"] in PRECURSOR_FAILURE_CATEGORIES,
                 "precursor-diagnostic-caught")
        _precursor_exception_graph(value, kind, program)
        canonical = json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
        need(stderr == marker + canonical + b"\n", "precursor-diagnostic-record")
        return value
    except (Refused, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        return None  # Malformed detail cannot authorize anything or export private bytes.


def _precursor_diagnostic(result, kind):
    """Only called after the original CompletedProcess admission and time gate."""
    _, _, _, limit = _precursor_spec(kind)
    need(type(result) is subprocess.CompletedProcess and type(result.returncode) is int
         and -(2**31) <= result.returncode < 2**31 and type(result.stdout) is bytes and type(result.stderr) is bytes
         and len(result.stdout) + len(result.stderr) <= limit, "precursor-diagnostic-contract")
    value = {"kind": kind, "returncode": result.returncode, "stdoutBytes": len(result.stdout), "stderrBytes": len(result.stderr),
             "envelope": {"zeroReturncode": result.returncode == 0, "emptyStderr": result.stderr == b"",
                          "stdoutNonemptyWithinLimit": 0 < len(result.stdout) <= limit,
                          "stdoutFinalNewline": result.stdout.endswith(b"\n"), "stdoutSingleLine": b"\n" not in result.stdout[:-1]}}
    # A normal success receipt (especially private account JSON) is never decoded
    # as failure detail. Only the fixed nonzero footer can supply a closed record.
    detail = _precursor_child_failure(result.stderr, kind) if result.returncode == 1 else None
    if detail is not None:
        value["childFailure"] = detail
    return value


def recovery_producer_result(result):
    need(result.returncode == 0 and result.stderr == b"" and result.stdout.endswith(b"\n")
         and b"\n" not in result.stdout[:-1] and 0 < len(result.stdout) <= 2048, "recovery-producer-failed")
    value = json.loads(result.stdout, object_pairs_hook=_pairs, parse_constant=lambda _: (_ for _ in ()).throw(Refused("recovery-producer-json")))
    expected = {"schemaVersion": 1, "scope": "real-core-project-recovery-fixture-v1", "case": RECOVERY_CASE,
                "materializationOutcome": "expected-cleanup-failure", "coreFatal": True, "commands": 0, "profileCalls": 0,
                "attemptedDescriptors": None, "neverOpenedDescriptors": None, "attemptedDescriptorsClosed": True,
                "handlersRestored": True, "invocationReleased": True, "originalQuiescenceRecorded": True,
                "retirementInterceptions": 0, "observersRestored": True,
                "restored": {"android-services": True, "ios-services": False}, "followupCoreOrFilesystemOperation": False}
    need(type(value) is dict and value.keys() == expected.keys(), "recovery-producer-shape")
    counts = [value[key] for key in ("attemptedDescriptors", "neverOpenedDescriptors")]
    need(all(type(n) is int and 0 <= n <= 2048 for n in counts) and 0 < counts[0] <= sum(counts) <= 2048, "recovery-producer-descriptors")
    expected.update(attemptedDescriptors=counts[0], neverOpenedDescriptors=counts[1])
    _exact(value, expected)
    return value


def produce_pending_recovery(fixtures, run_owned, uid, username):
    """Exactly one already-admitted installed interpreter call, then DATA.

    Unknown/foreign return retains the original custody and forbids scans,
    moves, closing fixtures, app entry and another call. Semantic refusal with
    a genuine returned command permits closing, never a recovery dispatch.
    """
    need(fixtures.cases == (RECOVERY_CASE,) and not fixtures.inflight and not fixtures.recovery_produced, "recovery-producer-reused")
    executable, core = fixtures.recovery_runtime_paths()
    state = fixtures.path / "state" / RECOVERY_CASE
    argv = [executable, "-I", "-S", "-B", "-c", SHELL_RECOVERY_PRODUCER, core, str(fixtures.path / RECOVERY_CASE / "project"), RECOVERY_CASE]
    fixtures.precursor_diagnostic = None
    fixtures.case, fixtures.stage, fixtures.inflight, fixtures.last_returned = RECOVERY_CASE, "recovery-producer", True, False
    # The original callable's actual CompletedProcess is the only return edge.
    result = run_owned(argv, environ=app_environment(state, uid, username), cwd=state,
                       timeout=30, capture=True, text=False, output_limit=2048)
    need(type(result) is subprocess.CompletedProcess and type(result.args) is list and len(result.args) == len(argv)
         and all(type(arg) is str for arg in result.args) and result.args == argv and type(result.returncode) is int
         and type(result.stdout) is bytes and type(result.stderr) is bytes and len(result.stdout) + len(result.stderr) <= 2048,
         "recovery-producer-return-contract")
    fixtures.inflight, fixtures.last_returned, fixtures.stage = False, True, "recovery-generated"
    try:
        attestation = recovery_producer_result(result)
    except BaseException:
        try:
            fixtures.precursor_diagnostic = _precursor_diagnostic(result, "project-recovery-producer")
        except BaseException:
            pass  # Diagnostics cannot replace the identical original semantic refusal.
        raise
    fixtures.accept_recovery_producer(attestation)


def _preserve_recovery_conflict_exclusive(project):
    """One fixed Darwin renameatx_np(RENAME_EXCL), never replace or retry.

    Caller holds the original private project descriptor and has validated the
    known-return producer inventory. A destination collision remains untouched.
    """
    need(sys.platform == "darwin" and type(project) is int and project >= 0, "recovery-rename-platform")
    import ctypes  # Native-only; importing this DATA module does not load it.
    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    rename = library.renameatx_np
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(project, b"GoogleService-Info.plist", project, b"saved-foreign-ios", 0x4) != 0:
        raise OSError(ctypes.get_errno(), "recovery exclusive preservation refused")


def _recovery_kind(path):
    if path in (".", "project", "project/.mobile-release", "project/.mobile-release/build-inputs", "project/.mobile-release/build-inputs/scratch"):
        return "directory"
    if path in RECOVERY_FILES or path in ("project/saved-foreign-ios", "project/.mobile-release/build-inputs-complete.json"):
        return "file"
    if re.fullmatch(r"project/\.mobile-release/build-inputs/(?:header\.json|intent\.json|checkpoint-(?:0[0-9]{2}|1[01][0-9]|12[0-7])\.json|(?:backup|stage|retired)-[01])", path):
        return "file"
    raise Refused("recovery-fixture-member")


def _recovery_inventory_data(rows, uid, gid):
    need(type(rows) is dict and 6 <= len(rows) <= 160, "recovery-inventory-count")
    seen, total = set(), 0
    device = rows["."].identity[0]
    for name, row in rows.items():
        need(type(name) is str and type(row) is Node, "recovery-inventory-shape")
        kind = _recovery_kind(name)
        identity = row.identity
        need(type(identity) is tuple and len(identity) == 9 and all(type(n) is int and 0 <= n < 2**64 for n in identity)
             and identity[0] == device and identity[1] > 0 and identity[:2] not in seen and identity[3:5] == (uid, gid)
             and identity[2] == (stat.S_IFDIR | 0o700 if kind == "directory" else stat.S_IFREG | 0o600), "recovery-inventory-identity")
        seen.add(identity[:2])
        if kind == "directory":
            need(row.sha256 is None and type(row.entries) is tuple and len(row.entries) <= 136 and identity[5] >= 1
                 and identity[6] <= 1024*1024, "recovery-inventory-directory")
            expected = tuple(sorted(p.rsplit("/", 1)[-1] for p in rows if p != "." and str(Path(p).parent) == name))
            need(row.entries == expected, "recovery-inventory-roster")
        else:
            need(identity[5] == 1 and 0 < identity[6] <= 256*1024 and row.entries is None
                 and type(row.sha256) is str and re.fullmatch(r"[0-9a-f]{64}", row.sha256), "recovery-inventory-file")
            total += identity[6]
        if name != ".":
            parent = str(Path(name).parent)
            need(parent in rows and rows[parent].sha256 is None, "recovery-inventory-parent")
    need(total <= 136*256*1024, "recovery-inventory-bytes")
    checkpoints = sorted(name for name in rows if "/checkpoint-" in name)
    need(checkpoints == [f"project/.mobile-release/build-inputs/checkpoint-{i:03}.json" for i in range(len(checkpoints))], "recovery-checkpoint-sequence")
    return rows


def _recovery_bytes(row, body):
    need(row.identity[6] == len(body) and row.sha256 == digest(body), "recovery-fixture-content")


def _recovery_moved(original, current):
    need(original.identity[:8] == current.identity[:8] and original.sha256 == current.sha256, "recovery-original-move")


def _recovery_generated(initial, generated, uid, gid):
    _recovery_inventory_data(initial, uid, gid); _recovery_inventory_data(generated, uid, gid)
    static = {".", "project", *RECOVERY_FILES}
    pending = "project/.mobile-release/build-inputs"
    controls = {name for name in generated if "/checkpoint-" in name}
    need(set(initial) == static and controls and set(generated) == static | {"project/.mobile-release", pending,
         pending+"/header.json", pending+"/intent.json", pending+"/backup-1"} | controls, "recovery-generated-roster")
    for path, body in RECOVERY_FILES.items():
        _recovery_bytes(initial[path], body)
    for name in ("project/.gitignore", "project/unrelated.txt"):
        need(generated[name] == initial[name], "recovery-generated-unrelated")
    for name in (".", "project"):
        need(generated[name].identity[:5] == initial[name].identity[:5], "recovery-generated-ancestry")
    _recovery_moved(initial["project/google-services.json"], generated["project/google-services.json"])
    _recovery_moved(initial["project/GoogleService-Info.plist"], generated[pending+"/backup-1"])
    _recovery_bytes(generated["project/GoogleService-Info.plist"], RECOVERY_FOREIGN)


def _recovery_before(generated, before, uid, gid):
    _recovery_inventory_data(before, uid, gid)
    moved, saved = "project/GoogleService-Info.plist", "project/saved-foreign-ios"
    need(set(before) == set(generated) - {moved} | {saved}, "recovery-preservation-roster")
    _recovery_moved(generated[moved], before[saved])
    need(all(before[name] == row for name, row in generated.items() if name not in (moved, "project"))
         and before["project"].identity[:5] == generated["project"].identity[:5], "recovery-preservation-unrelated")


def _recovery_final(initial, generated, before, after, uid, gid):
    _recovery_generated(initial, generated, uid, gid); _recovery_before(generated, before, uid, gid)
    _recovery_inventory_data(after, uid, gid)
    need(set(after) == {".", "project", *RECOVERY_FILES, "project/.mobile-release", "project/saved-foreign-ios"}, "recovery-final-roster")
    for name in ("project/.gitignore", "project/unrelated.txt", "project/google-services.json", "project/saved-foreign-ios"):
        need(after[name] == before[name], "recovery-final-preservation")
    for name in (".", "project", "project/.mobile-release"):
        need(after[name].identity[:5] == before[name].identity[:5], "recovery-final-ancestry")
    _recovery_moved(initial["project/GoogleService-Info.plist"], after["project/GoogleService-Info.plist"])
    return {"fixture": "real-core-project-recovery-v1", "case": RECOVERY_CASE, "realCoreGenerated": True,
            "originalTargetsRestored": True, "metadataRetired": True, "foreignPreserved": True, "privateContentsExported": False,
            "inventories": [{"stage": stage, "nodes": len(rows), "sha256": digest(_recovery_inventory_bytes(rows))}
                            for stage, rows in zip(("initial", "generated", "before", "after"), (initial, generated, before, after))]}


def _recovery_inventory_bytes(rows):
    raw = json.dumps({name: {"identity": row.identity, "sha256": row.sha256, "entries": row.entries} for name, row in sorted(rows.items())},
                     sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    need(len(raw) <= 128*1024, "recovery-inventory-data-limit")
    return raw

SHELL_RECOVERY_PRODUCER = r'''try:
    import errno, json, os, sys, threading
    from pathlib import Path, PurePosixPath
    def need(ok):
        if not ok: raise RuntimeError("fixed recovery fixture refused")
    need(len(sys.argv)==4 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode)
    core, raw_root, case=sys.argv[1:]
    need(case in ("project-recovery-pending","project-recovery-cancel","project-recovery-cleanup-only","project-recovery-partial"))
    root=Path(raw_root)
    need(root.is_absolute() and root.name=="project" and root.parent.name==case and Path(core).is_absolute())
    need(threading.current_thread() is threading.main_thread() and threading.active_count()==1)
    sys.path.insert(0, core)
    from mobile_release import build_inputs as inputs
    from mobile_release.owned_process import ProcessError
    need(inputs.__file__.startswith(core+"/") and inputs._ENV_OWNER is None and not inputs._ENV_TAINTED)
    original_init=inputs._FD.__init__
    original_retire=inputs._retire_terminal
    slots=[]
    retirement_calls=[]
    def observed_init(self, guard):
        original_init(self, guard)
        need(len(slots)<2048)
        slots.append(self)
    def retirement_stop(project, terminal, binding):
        need(case=="project-recovery-cleanup-only" and not retirement_calls)
        need(project is invocation._original_project and terminal["quiescence"]=="original")
        retirement_calls.append(True)
        raise OSError(errno.EIO,"fixed synthetic metadata retirement interruption")
    def foreign(original, name, content):
        slot=inputs._FD(original.cancellation)
        with inputs._fd_cleanup(slot):
            fd=slot.open(root/name, os.O_WRONLY|os.O_TRUNC|os.O_NOFOLLOW)
            need(os.write(fd,content)==len(content))
            os.fsync(fd)
    invocation=original=None
    caught=None
    inputs._FD.__init__=observed_init
    if case=="project-recovery-cleanup-only": inputs._retire_terminal=retirement_stop
    try:
        try:
            with inputs.invocation_custody(root,mode="build") as invocation:
                with invocation.project(signing_lease=None):
                    with invocation.materialization(signing_lease=None) as original:
                        original.replace_all((
                            inputs.TargetReplacement("android-services",PurePosixPath("google-services.json"),b"synthetic temporary Android input\n"),
                            inputs.TargetReplacement("ios-services",PurePosixPath("GoogleService-Info.plist"),b"synthetic temporary iOS input\n"),
                        ))
                        if case=="project-recovery-partial":
                            foreign(original,"google-services.json",b"synthetic foreign Android input; preserve\n")
                        if case!="project-recovery-cleanup-only":
                            foreign(original,"GoogleService-Info.plist",b"synthetic foreign iOS input; preserve\n")
        except BaseException as error:
            caught=error
    finally:
        inputs._FD.__init__=original_init
        inputs._retire_terminal=original_retire
    # NO core operation or filesystem access below: inspect the original retained
    # objects and emit bounded closed DATA to the original stdout only.
    need(type(caught) is ProcessError and invocation is not None and original is not None
         and caught.dispatched is False and caught.contained is True and caught.cleanup_complete is False)
    guard=invocation.cancellation
    ledger=guard._ledger
    project=invocation._original_project
    attempted=[slot for slot in slots if slot.open_state!="NEW"]
    never_opened=[slot for slot in slots if slot.open_state=="NEW"]
    need(0<len(attempted)<=2048 and len(attempted)+len(never_opened)==len(slots))
    need(all(slot.guard is guard and slot.open_state in ("OPEN","NO_EFFECT") and slot.close_state=="CLOSED" and slot.number is None for slot in attempted))
    need(all(slot.guard is guard and slot.number is None and slot.close_state in ("NOT_ATTEMPTED","CLOSED") for slot in never_opened))
    need(guard._restoration=="RESTORED" and ledger._fatal and ledger._command is None and ledger._profile is None
         and ledger._commands==ledger._profile_calls==0 and ledger._command_dispatched is False and ledger._profile_dispatched is False
         and ledger._profile_contained is True and ledger._command_contained is True)
    need(invocation.claimed and not invocation.active and not invocation.reserved and not invocation.frames
         and invocation.child is None and invocation.project_owner is None and invocation.store_namespace is None
         and invocation.reservation_state=="RELEASED" and invocation.lock_result is None and inputs._ENV_OWNER is None and not inputs._ENV_TAINTED)
    need(project is not None and project.claimed and original.claimed and original.quiescence=="original" and not original.failed)
    need(inputs._FD.__init__ is original_init and inputs._retire_terminal is original_retire)
    need(len(retirement_calls)==int(case=="project-recovery-cleanup-only"))
    primary=ledger._primary
    if case=="project-recovery-cleanup-only":
        need(type(primary) is OSError and primary.errno==errno.EIO and primary.args==(errno.EIO,"fixed synthetic metadata retirement interruption"))
    else:
        need(type(primary) is inputs.BuildInputError and primary.args==("build inputs: intervening target must be preserved",))
    restored={row["role"]:row["restored"] for row in original.records}
    expected={"android-services":case!="project-recovery-partial","ios-services":case=="project-recovery-cleanup-only"}
    need(restored==expected and all(type(x) is bool for x in restored.values()))
    report={"schemaVersion":1,"scope":"real-core-project-recovery-fixture-v1","case":case,
        "materializationOutcome":"expected-cleanup-failure","coreFatal":True,"commands":0,"profileCalls":0,
        "attemptedDescriptors":len(attempted),"neverOpenedDescriptors":len(never_opened),
        "attemptedDescriptorsClosed":True,"handlersRestored":True,"invocationReleased":True,
        "originalQuiescenceRecorded":True,"retirementInterceptions":len(retirement_calls),"observersRestored":True,
        "restored":restored,"followupCoreOrFilesystemOperation":False}
    raw=json.dumps(report,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")+b"\n"
    need(len(raw)<=2048)
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()
except BaseException as _failure_error:
    try:
        # Retained exceptions and loaded namespaces only: no import, filesystem,
        # native query, replay, cleanup or arbitrary exception formatting here.
        _failure_globals = globals()
        _failure_core = None
        if (type(sys.argv) is list and 1 < len(sys.argv) <= 8 and type(sys.argv[1]) is str
                and 0 < len(sys.argv[1]) <= 512 and sys.argv[1].startswith("/")):
            _failure_core = sys.argv[1]
        _failure_namespaces = [(0, _failure_globals, "<string>")]
        _failure_types = [(RuntimeError, 'runtime'), (OSError, 'os'), (PermissionError, 'permission'), (FileNotFoundError, 'missing'), (FileExistsError, 'exists'), (TimeoutError, 'timeout'), (BlockingIOError, 'blocked'), (BrokenPipeError, 'broken-pipe'), (ChildProcessError, 'child-process'), (IsADirectoryError, 'is-directory'), (NotADirectoryError, 'not-directory'), (ConnectionError, 'connection'), (ConnectionAbortedError, 'connection-aborted'), (ConnectionRefusedError, 'connection-refused'), (ConnectionResetError, 'connection-reset'), (InterruptedError, 'os-interrupted'), (ProcessLookupError, 'process-missing'), (ValueError, 'value'), (TypeError, 'type'), (KeyError, 'key'), (AttributeError, 'attribute'), (ImportError, 'import'), (ModuleNotFoundError, 'import-missing'), (AssertionError, 'assertion'), (KeyboardInterrupt, 'interrupted'), (SystemExit, 'exit'), (NotImplementedError, 'not-implemented'), (RecursionError, 'recursion'), (IndexError, 'index'), (OverflowError, 'overflow'), (MemoryError, 'memory')]
        _failure_os_types = (OSError, PermissionError, FileNotFoundError, FileExistsError, TimeoutError, BlockingIOError, BrokenPipeError, ChildProcessError, IsADirectoryError, NotADirectoryError, ConnectionError, ConnectionAbortedError, ConnectionRefusedError, ConnectionResetError, InterruptedError, ProcessLookupError,)
        _failure_refused = _failure_globals.get("Refused")
        if type(_failure_refused) is type:
            _failure_types.append((_failure_refused, "refused"))
        # IDs match PRECURSOR_FAILURE_SOURCE_ROLES in the original outer reader.
        _failure_roles = ((1, 'build_inputs', (('BuildInputError', 'build-input'), ('BuildInputBusy', 'build-input-busy'), ('BuildInputRootChanged', 'build-input-root-changed'), ('BuildInputManualRecoveryRequired', 'build-input-manual'), ('_DesktopRecoveryRefused', 'desktop-recovery-refused'), ('_PrivatePublicationError', 'private-publication'))), (2, 'local_signing', (('SigningBusy', 'signing-busy'), ('SigningPending', 'signing-pending'))), (3, 'init_transaction', (('InitConflict', 'init-conflict'), ('InitOperationFailure', 'init-operation-failure'), ('InitInterrupted', 'init-interrupted'))), (4, 'checked_files', ()), (5, 'cancellation', ()), (6, 'owned_process', (('ProcessError', 'process'), ('ProcessCleanupError', 'process-cleanup'), ('ProcessOutcomeUnknown', 'process-outcome-unknown'), ('ProcessInterrupted', 'process-interrupted'))), (7, '_command_process', ()), (8, '_native_process', (('NativeProcessError', 'native-process'),)), (9, '_lifetime_evidence', ()), (10, '_profile_callers', ()), (11, 'errors', (('MobileReleaseError', 'mobile-release'), ('ConfigurationError', 'configuration'), ('ValidationError', 'validation'), ('CredentialError', 'credential'), ('MutationGuardError', 'mutation-guard'), ('StoreOperationError', 'store-operation'))))
        if _failure_core is not None and type(sys.modules) is dict:
            for _failure_role, _failure_name, _failure_classes in _failure_roles:
                _failure_full_name = "mobile_release." + _failure_name
                _failure_module = sys.modules.get(_failure_full_name)
                if type(_failure_module) is not type(sys):
                    continue
                _failure_namespace = _failure_module.__dict__
                _failure_filename = _failure_core + "/mobile_release/" + _failure_name + ".py"
                if (type(_failure_namespace.get("__name__")) is not str
                        or _failure_namespace["__name__"] != _failure_full_name
                        or type(_failure_namespace.get("__file__")) is not str
                        or _failure_namespace["__file__"] != _failure_filename):
                    continue
                _failure_namespaces.append((_failure_role, _failure_namespace, _failure_filename))
                for _failure_class_name, _failure_label in _failure_classes:
                    _failure_class = _failure_namespace.get(_failure_class_name)
                    if type(_failure_class) is type:
                        _failure_types.append((_failure_class, _failure_label))
        def _failure_category(error):
            if error is None: return "none"
            for expected, category in _failure_types:
                if type(error) is expected: return category
            return "other"
        _failure_args = BaseException.args.__get__(_failure_error)
        _failure_reason = "original-operation-failed"
        if (type(_failure_error) is RuntimeError and type(_failure_args) is tuple and len(_failure_args) == 1
                and type(_failure_args[0]) is str and _failure_args[0] == "fixed recovery fixture refused"):
            _failure_reason = "fixture-check-failed"
        _failure_objects, _failure_nodes = [], []
        def _failure_add(error):
            if error is None: return None
            for index, original in enumerate(_failure_objects):
                if original is error: return index
            if len(_failure_objects) == 4: return -1
            _failure_objects.append(error)
            return len(_failure_objects) - 1
        _failure_raised = _failure_add(_failure_error)
        _failure_caught = _failure_add(_failure_globals.get("caught"))
        _failure_complete = True
        _failure_sites, _failure_own_omitted = [], False
        _failure_index = 0
        while _failure_index < len(_failure_objects):
            _failure_original = _failure_objects[_failure_index]
            _failure_cause = _failure_add(BaseException.__cause__.__get__(_failure_original))
            _failure_context = _failure_add(BaseException.__context__.__get__(_failure_original))
            _failure_complete = _failure_complete and _failure_cause != -1 and _failure_context != -1
            _failure_tb = BaseException.__traceback__.__get__(_failure_original)
            _failure_node_sites, _failure_links, _failure_unmapped, _failure_truncated = [], 0, 0, False
            while _failure_tb is not None and _failure_links < 32:
                _failure_links += 1
                _failure_frame, _failure_line = _failure_tb.tb_frame, _failure_tb.tb_lineno
                _failure_frame_role = None
                for _failure_role, _failure_namespace, _failure_filename in _failure_namespaces:
                    if (_failure_frame.f_globals is _failure_namespace
                            and _failure_frame.f_code.co_filename == _failure_filename):
                        _failure_frame_role = _failure_role
                        break
                _failure_line_ok = (type(_failure_line) is int and 1 <= _failure_line <= 1_000_000
                    and (_failure_frame_role != 0 or _failure_line <= 207))
                # Legacy cap4 is independent of the graph's first8 mixed sites.
                if _failure_index == 0 and _failure_frame_role == 0:
                    if _failure_line_ok and len(_failure_sites) < 4:
                        _failure_sites.append(_failure_line)
                    else:
                        _failure_own_omitted = True
                if _failure_frame_role is None or not _failure_line_ok:
                    _failure_unmapped += 1
                elif len(_failure_node_sites) < 8:
                    _failure_node_sites.append([_failure_frame_role, _failure_line])
                else:
                    _failure_truncated = True
                _failure_tb = _failure_tb.tb_next
            _failure_errno = None
            if any(type(_failure_original) is expected for expected in _failure_os_types):
                _failure_number = OSError.errno.__get__(_failure_original)
                if type(_failure_number) is int and 0 <= _failure_number <= 4095:
                    _failure_errno = _failure_number
            _failure_nodes.append({"category": _failure_category(_failure_original), "errno": _failure_errno,
                "sites": _failure_node_sites, "tracebackLinksSeen": _failure_links,
                "tracebackComplete": _failure_tb is None, "unmappedFrames": _failure_unmapped,
                "sitesTruncated": _failure_truncated, "cause": _failure_cause, "context": _failure_context,
                "suppressed": BaseException.__suppress_context__.__get__(_failure_original)})
            _failure_index += 1
        _failure_detail = {"schemaVersion":2, "reason":_failure_reason,
            "exceptionCategory":_failure_nodes[0]["category"], "sourceSites":_failure_sites,
            "tracebackLinksSeen":_failure_nodes[0]["tracebackLinksSeen"],
            "sourceSitesComplete":_failure_nodes[0]["tracebackComplete"] and not _failure_own_omitted,
            "exceptionGraph":{"raised":_failure_raised, "caught":_failure_caught, "nodes":_failure_nodes,
                "complete":_failure_complete, "boundRoles":[role for role, _, _ in _failure_namespaces]}}
        _failure_detail["caughtExceptionCategory"] = "none" if _failure_caught is None else _failure_nodes[_failure_caught]["category"]
        _failure_raw = "MRK_PROJECT_RECOVERY_FIXTURE_FAILURE=" + json.dumps(_failure_detail,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False) + "\n"
        if len(_failure_raw.encode("ascii")) <= 2048:
            sys.stderr.write(_failure_raw)
            sys.stderr.flush()
    except BaseException:
        pass  # Even diagnostic reduction/emission failure must not expose a raw traceback.
    raise SystemExit(1) from None
'''

IOS_ACCOUNT_CORE_PROGRAM = r'''
import hashlib, json, os, re, stat, subprocess, sys, time
from pathlib import Path
class Refused(Exception): pass
def need(ok, label):
    if not ok: raise Refused(label)
def pairs(items):
    out={}
    for key,value in items:
        need(key not in out,"duplicate-private-key");out[key]=value
    return out
def encoded(value): return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode("ascii")
def ident(info): return [info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink]
def main():
    need(len(sys.argv)==7 and sys.platform=="darwin","native-account-entry")
    core,mode,state,work,final,expected_sha=sys.argv[1:]
    need(mode in ("produce","observe") and re.fullmatch(r"[1-9][0-9]{1,19}",work) and re.fullmatch(r"[1-9][0-9]{1,19}",final),"entry-bounds")
    work,final=int(work),int(final)
    need(final-work==25_000_000_000 and time.monotonic_ns()<work<final<2**63,"original-clock")
    need(re.fullmatch(r"/private/tmp/mrk-macos-aqua-[0-9a-f]{40}-[1-9][0-9]{0,19}-[1-9][0-9]{0,19}/state/ios-recovery-pending",state)
         and os.getcwd()==state,"state-route")
    need(expected_sha=="-" if mode=="produce" else re.fullmatch(r"[0-9a-f]{64}",expected_sha),"private-comparison-binding")
    sys.path.insert(0,core)
    from mobile_release import local_signing as signing
    from mobile_release.owned_process import run_owned, ProcessCleanupError
    from mobile_release.cancellation import DefaultCancellation, CleanupScope
    from mobile_release._command_process import OriginalCommandOutcome, OriginalCommandFinality
    uid,gid=os.getuid(),os.getgid()
    need(uid>0 and uid==os.geteuid() and gid==os.getegid(),"native-account-user")
    os.umask(0o077)
    guard=DefaultCancellation(ProcessCleanupError,"fixture original close is unconfirmed")
    fds=[];held=[];parents={};calls=[];closed=0;close_error=None;session=None;lease=None;private=None
    def timely(): need(time.monotonic_ns()<work,"original-work-expired")
    def final_time(): need(time.monotonic_ns()<final,"original-finality-expired")
    def close_one(fd):
        nonlocal closed,close_error
        need(fd in fds,"descriptor-not-original")
        fds.remove(fd)
        try:
            with guard.deferred(check_on_exit=False): os.close(fd)
        except BaseException as error:
            if close_error is None:close_error=error
            raise
        closed+=1
    def close_owned():
        for fd in tuple(reversed(fds)):
            try:close_one(fd)
            except BaseException:pass
        if close_error is not None:raise close_error
    def opening(name,parent=None,directory=False):
        timely();need(len(fds)<32,"descriptor-limit")
        flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC|(os.O_DIRECTORY if directory else 0)
        with guard.deferred():
            fd=os.open(name,flags,dir_fd=parent);fds.append(fd)
        need(not os.get_inheritable(fd),"descriptor-inheritance");return fd
    def check_held():
        timely()
        for parent,name,fd,before,directory in held:
            current=ident(os.fstat(fd));named=ident(os.stat(name,dir_fd=parent,follow_symlinks=False))
            n=5 if directory else 6
            need(current[:n]==before[:n] and named[:n]==before[:n],"baseline-original-changed")
    def directory(path):
        path=Path(path)
        need(path.is_absolute() and len(str(path).encode())<=512 and len(path.parts)-1<=8
             and all(p not in (".","..") and len(p.encode())<=255 for p in path.parts[1:]),"directory-route")
        if str(path) in parents:return parents[str(path)]
        parent=None if path==Path("/") else directory(path.parent)
        name="/" if parent is None else path.name
        fd=opening(name,parent,True);info=ident(os.fstat(fd))
        need(info==ident(os.stat(name,dir_fd=parent,follow_symlinks=False)) and stat.S_ISDIR(info[2])
             and info[3] in (0,uid) and (info[2]&0o7022==0 or str(path)=="/private/tmp" and info[2]==stat.S_IFDIR|0o1777 and info[3]==0),"directory-original")
        held.append((parent,name,fd,info,True));parents[str(path)]=fd;return fd
    def native_baseline(home,baseline,expected=None):
        need(type(baseline) is dict and set(baseline)=={"default","search"} and type(baseline["search"]) is list
             and 1<=len(baseline["search"])<=8 and type(baseline["default"]) is str
             and baseline["default"] in baseline["search"] and len(set(baseline["search"]))==len(baseline["search"]),"baseline-not-eligible")
        members=[];seen=set();root=home/"Library/Keychains"
        for raw in baseline["search"]:
            timely();need(type(raw) is str and "\x00" not in raw and "\\" not in raw and len(raw.encode())<=512,"baseline-path")
            path=Path(raw)
            need(path.is_absolute() and str(path)==raw and path.is_relative_to(root) and path!=root
                 and len(path.parts)-1<=8 and all(p not in (".","..") and 0<len(p.encode())<=255 for p in path.parts[1:]),"baseline-path")
            parent=directory(path.parent);fd=opening(path.name,parent);before=ident(os.fstat(fd))
            need(before==ident(os.stat(path.name,dir_fd=parent,follow_symlinks=False)) and stat.S_ISREG(before[2])
                 and before[3]==uid and before[5]==1 and before[2]&0o7022==0 and before[0]==os.fstat(directory(home)).st_dev
                 and tuple(before[:2]) not in seen,"baseline-member-original")
            seen.add(tuple(before[:2]));held.append((parent,path.name,fd,before,False));members.append({"path":raw,"identity":before})
        need(expected is None or members==expected,"baseline-member-substitution")
        check_held();return members
    def original_runner(argv,**options):
        timely();need(session is not None and lease is not None and len(calls)<64,"command-owner")
        allowed=[["/usr/bin/security",name,"-d","user"] for name in ("default-keychain","list-keychains")]
        if mode=="produce":
            allowed.extend([["/usr/bin/security",name,"-d","user","-s",str(session.keychain)] for name in ("default-keychain","list-keychains")])
            allowed.append(["/usr/bin/security","create-keychain","-p","MRK-disposable-empty-keychain",str(session.keychain)])
        need(type(argv) is list and argv in allowed and options.get("cancellation") is guard,"fixed-native-command")
        scope=options.get("execution_scope");binding=options.get("journal_binding")
        need(scope is not None and scope._source._lease is lease,"original-account-command-source")
        # Remaining allowance is always derived from the original pre-entry T.
        # Reserve the unchanged core's3s command cleanup plus2s scheduling margin.
        timeout=min(options["timeout"],(work-time.monotonic_ns())//1_000_000_000-5)
        need(type(timeout) is int and 1<=timeout<=30,"command-deadline")
        options["timeout"]=timeout;options["output_limit"]=16*1024
        row=[scope,binding,None];calls.append(row)
        result=run_owned(argv,**options);row[2]=result
        timely()
        need(type(result) is subprocess.CompletedProcess and result.args==argv and type(result.returncode) is int
             and result.returncode==0 and type(result.stdout) is str and result.stderr=="","native-original-return")
        return result
    def command_finality():
        for scope,binding,result in calls:
            outcome=scope.outcome.read()
            need(result is not None and type(outcome) is OriginalCommandOutcome and outcome.matches(scope,binding)
                 and type(outcome.original_finality) is OriginalCommandFinality
                 and outcome.original_finality._engine is outcome._engine and outcome.create_w.retired and outcome.run_tool.retired
                 and outcome.result_integrity=="complete" and outcome.termination=="normal-exit" and outcome.returncode==0
                 and not outcome.execution_unknown and outcome.no_target is None,"native-original-finality")
    scope=CleanupScope(guard,close_owned,owns_cancellation=True,first_primary=True)
    try:
        try:
            with scope:
                guard.install();guard.activate();timely()
                home=signing.account_home();directory(home);state_fd=directory(state)
                if mode=="observe":
                    fd=opening("account-baseline.json",state_fd)
                    before=os.fstat(fd)
                    need(stat.S_ISREG(before.st_mode) and before.st_uid==uid and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600
                         and 0<before.st_size<=12*1024,"private-comparison-file")
                    body=os.read(fd,12*1024+1)
                    need(len(body)==before.st_size and hashlib.sha256(body).hexdigest()==expected_sha
                         and ident(os.fstat(fd))==ident(before) and ident(os.stat("account-baseline.json",dir_fd=state_fd,follow_symlinks=False))==ident(before),"private-comparison-original")
                    private=json.loads(body,object_pairs_hook=pairs)
                    need(type(private) is dict and set(private)=={"home","homeIdentity","leaseIdentity","sessionIdentity","nativeIdentity","token","baseline","members","controls","native"}
                         and private["home"]==str(home) and ident(os.fstat(directory(home)))[:5]==private["homeIdentity"],"private-account-binding")
                    native_baseline(home,private["baseline"],private["members"])
                with signing.local_signing_lease(cancellation=guard) as original_lease:
                    lease=original_lease;session=lease.session();session.bind_runner(original_runner)
                    if mode=="produce":
                        session.open(create=True)
                        # An uninstalled canary for ownership bookkeeping only,
                        # never a claim of Apple profile/certificate validity.
                        session.prepare(b"MRK empty-account recovery bookkeeping; not an Apple profile\n","D91B5701-B147-4B82-A33A-760E5C110006")
                        timely();need(session.intent["profile"]["before"] is None,"profile-destination-occupied")
                        members=native_baseline(home,session.intent["baseline"])
                        session.run(["security","create-keychain","-p","MRK-disposable-empty-keychain",str(session.keychain)],kind="create")
                        session.activate();timely();command_finality();check_held()
                        need(not session.unresolved and not session.journal_failed and session.state["inflight"] is None
                             and session.completed is None and session.state["profile"]["phase"]=="not-started"
                             and session.inventory()==session.state["native"] and signing.DB_NAME in session.state["native"]
                             and signing._names(session.fd)=={"keychain","intent.json","state.json"},"pending-boundary-unsettled")
                        controls={name:{"bytes":len(session._committed_controls[name]),"sha256":hashlib.sha256(session._committed_controls[name]).hexdigest()}
                                  for name in ("intent.json","state.json")}
                        private={"home":str(home),"homeIdentity":ident(os.fstat(lease.home_fd))[:5],"leaseIdentity":ident(os.fstat(lease.fd))[:5],
                            "sessionIdentity":ident(os.fstat(session.fd))[:5],"nativeIdentity":ident(os.fstat(session.native_fd))[:5],
                            "token":session.token,"baseline":session.intent["baseline"],"members":members,"controls":controls,"native":session.state["native"]}
                        need(len(encoded(private))<=12*1024,"private-comparison-bound")
                        # Deliberately stop here. This exact normal context
                        # closes descriptors/lease, not native cleanup or finish.
                    else:
                        need(ident(os.fstat(lease.fd))[:5]==private["leaseIdentity"],"persistent-lease-substitution")
                        need(session.observe(journal=False)==private["baseline"],"native-baseline-not-restored")
                        need(not signing._names(lease.fd),"pending-session-remains")
                        command_finality();check_held();timely()
                need(session.closed and session.fd is None and session.native_fd is None and lease.active is None
                     and lease.fd is None and lease.home_fd is None and not lease.locked,"account-original-close")
                need(not session._disposal_complete and not session.unresolved and not session.journal_failed,"account-close-state")
                command_finality();check_held();final_time()
        finally:scope.__exit__(*sys.exc_info())
    except BaseException:
        raise
    final_time();ledger=guard.lifetime_ledger
    need(guard.handler_state=="RESTORED" and not ledger.fatal and ledger._command is None and ledger._profile is None
         and ledger._profile_calls==0 and ledger._commands==len(calls) and not fds and close_error is None and closed>0,"producer-original-finality")
    if mode=="produce":
        # The original lease records deliberate unfinished-session revocation.
        need(lease._normal_execution_revoked and not session._disposal_complete and 3<=len(calls)<=64,"pending-origin")
    else:need(len(calls)==2 and not session._open_attempted,"readback-only")
    report={"schemaVersion":1,"scope":"real-core-pending-account-fixture-v1" if mode=="produce" else "real-core-account-baseline-readback-v1",
        "case":"ios-recovery-pending","commands":len(calls),"profileCalls":0,"commandFinalities":True,"leaseClosed":True,"sessionClosed":True,
        "handlersRestored":True,"fixtureDescriptorsClosed":True,"originalDeadlineMet":True,"keychainContentsRead":False}
    if mode=="produce":report.update(pendingLeft=True,private=private)
    else:report.update(pendingAbsent=True,baselinePreferencesMatched=True,baselineMemberIdentitiesMatched=True)
    raw=encoded(report)+b"\n";need(len(raw)<=16*1024 if mode=="produce" else len(raw)<=2048,"receipt-bound")
    final_time();sys.stdout.buffer.write(raw);sys.stdout.buffer.flush()
try:main()
except BaseException as _failure_error:
    try:
        # Retained exceptions and loaded namespaces only: no import, filesystem,
        # native query, replay, cleanup or arbitrary exception formatting here.
        _failure_globals = globals()
        _failure_core = None
        if (type(sys.argv) is list and 1 < len(sys.argv) <= 8 and type(sys.argv[1]) is str
                and 0 < len(sys.argv[1]) <= 512 and sys.argv[1].startswith("/")):
            _failure_core = sys.argv[1]
        _failure_namespaces = [(0, _failure_globals, "<string>")]
        _failure_types = [(RuntimeError, 'runtime'), (OSError, 'os'), (PermissionError, 'permission'), (FileNotFoundError, 'missing'), (FileExistsError, 'exists'), (TimeoutError, 'timeout'), (BlockingIOError, 'blocked'), (BrokenPipeError, 'broken-pipe'), (ChildProcessError, 'child-process'), (IsADirectoryError, 'is-directory'), (NotADirectoryError, 'not-directory'), (ConnectionError, 'connection'), (ConnectionAbortedError, 'connection-aborted'), (ConnectionRefusedError, 'connection-refused'), (ConnectionResetError, 'connection-reset'), (InterruptedError, 'os-interrupted'), (ProcessLookupError, 'process-missing'), (ValueError, 'value'), (TypeError, 'type'), (KeyError, 'key'), (AttributeError, 'attribute'), (ImportError, 'import'), (ModuleNotFoundError, 'import-missing'), (AssertionError, 'assertion'), (KeyboardInterrupt, 'interrupted'), (SystemExit, 'exit'), (NotImplementedError, 'not-implemented'), (RecursionError, 'recursion'), (IndexError, 'index'), (OverflowError, 'overflow'), (MemoryError, 'memory')]
        _failure_os_types = (OSError, PermissionError, FileNotFoundError, FileExistsError, TimeoutError, BlockingIOError, BrokenPipeError, ChildProcessError, IsADirectoryError, NotADirectoryError, ConnectionError, ConnectionAbortedError, ConnectionRefusedError, ConnectionResetError, InterruptedError, ProcessLookupError,)
        _failure_refused = _failure_globals.get("Refused")
        if type(_failure_refused) is type:
            _failure_types.append((_failure_refused, "refused"))
        # IDs match PRECURSOR_FAILURE_SOURCE_ROLES in the original outer reader.
        _failure_roles = ((1, 'build_inputs', (('BuildInputError', 'build-input'), ('BuildInputBusy', 'build-input-busy'), ('BuildInputRootChanged', 'build-input-root-changed'), ('BuildInputManualRecoveryRequired', 'build-input-manual'), ('_DesktopRecoveryRefused', 'desktop-recovery-refused'), ('_PrivatePublicationError', 'private-publication'))), (2, 'local_signing', (('SigningBusy', 'signing-busy'), ('SigningPending', 'signing-pending'))), (3, 'init_transaction', (('InitConflict', 'init-conflict'), ('InitOperationFailure', 'init-operation-failure'), ('InitInterrupted', 'init-interrupted'))), (4, 'checked_files', ()), (5, 'cancellation', ()), (6, 'owned_process', (('ProcessError', 'process'), ('ProcessCleanupError', 'process-cleanup'), ('ProcessOutcomeUnknown', 'process-outcome-unknown'), ('ProcessInterrupted', 'process-interrupted'))), (7, '_command_process', ()), (8, '_native_process', (('NativeProcessError', 'native-process'),)), (9, '_lifetime_evidence', ()), (10, '_profile_callers', ()), (11, 'errors', (('MobileReleaseError', 'mobile-release'), ('ConfigurationError', 'configuration'), ('ValidationError', 'validation'), ('CredentialError', 'credential'), ('MutationGuardError', 'mutation-guard'), ('StoreOperationError', 'store-operation'))))
        if _failure_core is not None and type(sys.modules) is dict:
            for _failure_role, _failure_name, _failure_classes in _failure_roles:
                _failure_full_name = "mobile_release." + _failure_name
                _failure_module = sys.modules.get(_failure_full_name)
                if type(_failure_module) is not type(sys):
                    continue
                _failure_namespace = _failure_module.__dict__
                _failure_filename = _failure_core + "/mobile_release/" + _failure_name + ".py"
                if (type(_failure_namespace.get("__name__")) is not str
                        or _failure_namespace["__name__"] != _failure_full_name
                        or type(_failure_namespace.get("__file__")) is not str
                        or _failure_namespace["__file__"] != _failure_filename):
                    continue
                _failure_namespaces.append((_failure_role, _failure_namespace, _failure_filename))
                for _failure_class_name, _failure_label in _failure_classes:
                    _failure_class = _failure_namespace.get(_failure_class_name)
                    if type(_failure_class) is type:
                        _failure_types.append((_failure_class, _failure_label))
        def _failure_category(error):
            if error is None: return "none"
            for expected, category in _failure_types:
                if type(error) is expected: return category
            return "other"
        _failure_args = BaseException.args.__get__(_failure_error)
        _failure_reason = "original-operation-failed"
        if (type(_failure_error) is Refused and type(_failure_args) is tuple and len(_failure_args) == 1
                and type(_failure_args[0]) is str and _failure_args[0] in ('duplicate-private-key', 'native-account-entry', 'entry-bounds', 'original-clock', 'state-route', 'private-comparison-binding', 'native-account-user', 'original-work-expired', 'original-finality-expired', 'descriptor-not-original', 'descriptor-limit', 'descriptor-inheritance', 'baseline-original-changed', 'directory-route', 'directory-original', 'baseline-not-eligible', 'baseline-path', 'baseline-member-original', 'baseline-member-substitution', 'command-owner', 'fixed-native-command', 'original-account-command-source', 'command-deadline', 'native-original-return', 'native-original-finality', 'private-comparison-file', 'private-comparison-original', 'private-account-binding', 'profile-destination-occupied', 'pending-boundary-unsettled', 'private-comparison-bound', 'persistent-lease-substitution', 'native-baseline-not-restored', 'pending-session-remains', 'account-original-close', 'account-close-state', 'producer-original-finality', 'pending-origin', 'readback-only', 'receipt-bound', 'original-operation-failed')):
            _failure_reason = _failure_args[0]
        _failure_objects, _failure_nodes = [], []
        def _failure_add(error):
            if error is None: return None
            for index, original in enumerate(_failure_objects):
                if original is error: return index
            if len(_failure_objects) == 4: return -1
            _failure_objects.append(error)
            return len(_failure_objects) - 1
        _failure_raised = _failure_add(_failure_error)
        _failure_caught = None
        _failure_complete = True
        _failure_sites, _failure_own_omitted = [], False
        _failure_index = 0
        while _failure_index < len(_failure_objects):
            _failure_original = _failure_objects[_failure_index]
            _failure_cause = _failure_add(BaseException.__cause__.__get__(_failure_original))
            _failure_context = _failure_add(BaseException.__context__.__get__(_failure_original))
            _failure_complete = _failure_complete and _failure_cause != -1 and _failure_context != -1
            _failure_tb = BaseException.__traceback__.__get__(_failure_original)
            _failure_node_sites, _failure_links, _failure_unmapped, _failure_truncated = [], 0, 0, False
            while _failure_tb is not None and _failure_links < 32:
                _failure_links += 1
                _failure_frame, _failure_line = _failure_tb.tb_frame, _failure_tb.tb_lineno
                _failure_frame_role = None
                for _failure_role, _failure_namespace, _failure_filename in _failure_namespaces:
                    if (_failure_frame.f_globals is _failure_namespace
                            and _failure_frame.f_code.co_filename == _failure_filename):
                        _failure_frame_role = _failure_role
                        break
                _failure_line_ok = (type(_failure_line) is int and 1 <= _failure_line <= 1_000_000
                    and (_failure_frame_role != 0 or _failure_line <= 299))
                # Legacy cap4 is independent of the graph's first8 mixed sites.
                if _failure_index == 0 and _failure_frame_role == 0:
                    if _failure_line_ok and len(_failure_sites) < 4:
                        _failure_sites.append(_failure_line)
                    else:
                        _failure_own_omitted = True
                if _failure_frame_role is None or not _failure_line_ok:
                    _failure_unmapped += 1
                elif len(_failure_node_sites) < 8:
                    _failure_node_sites.append([_failure_frame_role, _failure_line])
                else:
                    _failure_truncated = True
                _failure_tb = _failure_tb.tb_next
            _failure_errno = None
            if any(type(_failure_original) is expected for expected in _failure_os_types):
                _failure_number = OSError.errno.__get__(_failure_original)
                if type(_failure_number) is int and 0 <= _failure_number <= 4095:
                    _failure_errno = _failure_number
            _failure_nodes.append({"category": _failure_category(_failure_original), "errno": _failure_errno,
                "sites": _failure_node_sites, "tracebackLinksSeen": _failure_links,
                "tracebackComplete": _failure_tb is None, "unmappedFrames": _failure_unmapped,
                "sitesTruncated": _failure_truncated, "cause": _failure_cause, "context": _failure_context,
                "suppressed": BaseException.__suppress_context__.__get__(_failure_original)})
            _failure_index += 1
        _failure_detail = {"schemaVersion":2, "reason":_failure_reason,
            "exceptionCategory":_failure_nodes[0]["category"], "sourceSites":_failure_sites,
            "tracebackLinksSeen":_failure_nodes[0]["tracebackLinksSeen"],
            "sourceSitesComplete":_failure_nodes[0]["tracebackComplete"] and not _failure_own_omitted,
            "exceptionGraph":{"raised":_failure_raised, "caught":_failure_caught, "nodes":_failure_nodes,
                "complete":_failure_complete, "boundRoles":[role for role, _, _ in _failure_namespaces]}}

        _failure_raw = "MRK_IOS_ACCOUNT_FIXTURE_FAILURE=" + json.dumps(_failure_detail,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False) + "\n"
        if len(_failure_raw.encode("ascii")) <= 2048:
            sys.stderr.write(_failure_raw)
            sys.stderr.flush()
    except BaseException:
        pass  # Even diagnostic reduction/emission failure must not expose a raw traceback.
    raise SystemExit(1) from None
'''


CASES = ("first-save", "noop-stale", "picker-loss", "save-loss")
IOS_CASES = ("ios-toolchain-prerequisite", "ios-version-stale", "ios-unsigned-archive", "ios-cancel", "ios-finality")
IOS_SIGNED_CASES = ("ios-signed-refusal", "ios-signed-cancel")
IOS_SESSION_CASES = ("ios-signing-inputs", *IOS_SIGNED_CASES)
IOS_INPUT_IDS = {"ios-signing-inputs": (2, 4, 6, 8, 9, 10, 11),
                 "ios-signed-refusal": (2, 7), "ios-signed-cancel": (2, 7)}
ANDROID_INPUT_CASE = "android-inputs"
SESSION_CASES = IOS_SESSION_CASES + (ANDROID_INPUT_CASE,)
INPUT_IDS = {**IOS_INPUT_IDS, ANDROID_INPUT_CASE: (2, 7, 12, 14, 15, 16, 17)}
FILE_NATIVE_PANELS = {case: {f"Session(Native({index}))": identifier for index, identifier in enumerate(ids)}
                      for case, ids in INPUT_IDS.items()}
IOS_CURRENT_CASES = IOS_CASES + ("ios-signing-inputs", *IOS_SIGNED_CASES, "ios-recovery-empty")
IOS_OPERATION_CASES = IOS_CASES + IOS_SIGNED_CASES + ("ios-recovery-empty", IOS_ACCOUNT_CASE)
PROJECT_FIELDS_CASE = "project-fields"
# Fixed no-hook projects. No arbitrary project or configured program enters this
# opt-in observation; arbitrary offline preflight remains potentially effectful.
LOCAL_CHECK_SCOPE = "doctor-preflight2"
LOCAL_CHECK_CASES = ("local-tool-observations", "local-saved-offline")
LOCAL_CHECK_IDS = (("developer-selection", "git", "java", "javac"), ("developer-selection", "git", "xcode"))
LOCAL_CHECK_STATUSES = ("PASS", "FAIL", "MISSING", "BLOCKED", "INVALID", "SKIP", "MANUAL", "CONFIGURED", "NOT_APPLICABLE")
LOCAL_CHECK_LIMITATIONS = ("saved-inputs-not-atomic", "project-code-effects-possible", "not-network-isolated", "core-builds-disabled",
                          "artifact-validation-not-requested", "toolkit-signing-credentials-store-not-requested", "release-readiness-not-assessed")
LOCAL_CHECK_FINDINGS = ("version-source", "platform-selection", "android-module", "android-gradle-wrapper", "android-debug-identity",
                       "workspace-private-output", "android-artifact", "preflight-early-exit", "configuration-policy", "metadata-policy",
                       "configured-project-check", "core-lifecycle", "other-core-finding")
LOCAL_CHECK_NOT_RUN = ("invalid-draft", "platform-disabled", "host-mismatch", "unsupported-host", "missing-in-supported-lookup",
                       "unsupported-installation", "unselected-installation", "full-xcode-not-selected", "stopped")


def local_check_fixture_data(case):
    need(type(case) is str and case in LOCAL_CHECK_CASES, "fixture-case")
    files = {".gitignore": IGNORE_PREFIX + IGNORE_RULES, "app/build.gradle.kts": SOURCE, "keep.txt": KEEP,
             "release/mobile-release.json": local_edit_config("local-metadata-text") if case == LOCAL_CHECK_CASES[0] else CONFIG,
             "version.properties": VERSION}
    return files, {".": (0o700, (".gitignore", "app", "keep.txt", "release", "version.properties")),
                   "app": (0o700, ("build.gradle.kts",)), "release": (0o700, ("mobile-release.json",))}


def _local_checks_base(case):
    files, _ = local_check_fixture_data(case)
    return {"schemaVersion": 1, "case": case, "tools": [], "offline": None, "sameOriginalNativeTerminals": True,
            "exactFixtureReadback": True, "fixture": {"files": 5, "directories": 3, "sha256": {p: digest(b) for p, b in files.items()}},
            "releaseReadiness": "not-assessed", "physicalDropdownGestureTested": False}


def _local_checks_report(value, case):
    """Admit only actual returned finite facts; no generated terminal fallback."""
    label = "local-checks-report"
    target = _local_checks_base(case)
    need(type(value) is dict and value.keys() == target.keys(), label)
    def token(v):
        return type(v) is str and re.fullmatch(r"[0-9a-f]{32}", v) is not None
    def integer(v, maximum=2**32 - 2, minimum=0):
        return type(v) is int and minimum <= v <= maximum
    def version(v):
        return type(v) is str and re.fullmatch(r"[0-9][A-Za-z0-9._+\-]{0,63}", v) is not None
    def build(v):
        return type(v) is str and re.fullmatch(r"[0-9]{1,3}[A-Z][0-9]{1,6}[a-z]?", v) is not None
    def context(row, platform, operation, saved=False):
        need(type(row) is dict and set(row) == {"projectId", "draftRevision", "baselineGeneration", "platform", "operation"} | ({"savedConfig"} if saved else set()), label)
        need(type(row["projectId"]) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", row["projectId"])
             and integer(row["draftRevision"]) and integer(row["baselineGeneration"])
             and row["platform"] == platform and row["operation"] == operation, label)
        if saved:
            _exact(row["savedConfig"], {"bytes": len(CONFIG), "sha256": digest(CONFIG)})
    def tool_row(row, role):
        need(type(row) is dict and set(row) == {"id", "state", "reason", "version", "build", "returnCode", "baseline", "assessment"} and row["id"] == role, label)
        baseline = row["baseline"]
        need(type(baseline) is dict and set(baseline) == {"kind", "version", "build"}, label)
        if role in ("java", "javac"):
            need(baseline["kind"] == "workflow-reference" and version(baseline["version"]) and baseline["build"] is None, label)
        elif role == "xcode":
            need(baseline["kind"] == "exact-pin" and version(baseline["version"]) and build(baseline["build"]), label)
        else:
            _exact(baseline, {"kind": "no-local-policy", "version": None, "build": None})
        empty = row["version"] is None and row["build"] is None and row["assessment"] == "not-assessed"
        if row["state"] == "not-run":
            need(row["reason"] in LOCAL_CHECK_NOT_RUN and (row["reason"] != "full-xcode-not-selected" or role == "xcode") and empty and row["returnCode"] is None, label)
            return
        need(row["state"] == "completed" and row["reason"] in ("observed", "nonzero-exit", "version-unrecognized", "selection-unrecognized")
             and integer(row["returnCode"], 2**31 - 1, -(2**31)) and (row["reason"] == "nonzero-exit") == (row["returnCode"] != 0), label)
        if row["reason"] != "observed":
            need(empty and (row["reason"] == "selection-unrecognized") == (role == "developer-selection" and row["reason"] != "nonzero-exit"), label)
        elif role == "developer-selection":
            need(empty, label)
        elif role == "xcode":
            need(version(row["version"]) and build(row["build"])
                 and row["assessment"] == ("match" if row["version"] == baseline["version"] and row["build"] == baseline["build"] else "mismatch"), label)
        else:
            need(version(row["version"]) and row["build"] is None and row["assessment"] == "no-local-policy", label)
    if case == LOCAL_CHECK_CASES[0]:
        rows = value["tools"]
        need(type(rows) is list and len(rows) == 2 and value["offline"] is None, label)
        for index, row in enumerate(rows):
            need(type(row) is dict and set(row) == {"runId", "ownerGeneration", "context", "statusRevision", "phase", "finality", "outcome", "commandsAttempted", "checks", "sameOriginal", "rendered", "staleAfterContextChange"}, label)
            context(row["context"], ("android", "ios")[index], "build")
            need(token(row["runId"]) and token(row["ownerGeneration"]) and integer(row["statusRevision"], minimum=1)
                 and row["phase"] == "settled" and row["finality"] == "settled" and row["outcome"] == "complete"
                 and row["sameOriginal"] is True and row["rendered"] is True and row["staleAfterContextChange"] is (index == 0), label)
            checks = row["checks"]
            need(type(checks) is list and len(checks) == len(LOCAL_CHECK_IDS[index]), label)
            for check, role in zip(checks, LOCAL_CHECK_IDS[index]):
                tool_row(check, role)
            need(integer(row["commandsAttempted"], 4, 1) and row["commandsAttempted"] == sum(c["state"] == "completed" for c in checks)
                 and any(c["id"] != "developer-selection" and c["reason"] == "observed" and c["returnCode"] == 0 and version(c["version"]) for c in checks), label)
        first, second = rows
        need(first["runId"] != second["runId"] and first["ownerGeneration"] != second["ownerGeneration"]
             and first["statusRevision"] < second["statusRevision"]
             and {**first["context"], "platform": "ios"} == second["context"], label)
        target["tools"] = rows
    else:
        need(value["tools"] == [] and type(value["tools"]) is list, label)
        row = value["offline"]
        need(type(row) is dict and set(row) == {"operationId", "ownerGeneration", "context", "statusRevision", "phase", "outcome", "result", "sameOriginal", "dirtyDraftObserved", "explicitConsent", "startArrivalObserved", "startArrivalLate", "rendered", "draftDiscardedThroughUi"}, label)
        context(row["context"], "android", "offline-preflight", True)
        need(token(row["operationId"]) and token(row["ownerGeneration"]) and integer(row["statusRevision"], minimum=1)
             and row["phase"] == "terminal" and row["outcome"] == "complete" and row["startArrivalLate"] is False
             and all(row[k] is True for k in ("sameOriginal", "dirtyDraftObserved", "explicitConsent", "startArrivalObserved", "rendered", "draftDiscardedThroughUi")), label)
        result = row["result"]
        need(type(result) is dict and set(result) == {"schemaVersion", "scope", "usedConfig", "findings", "summary", "limitations"}, label)
        _exact(result["schemaVersion"], 1)
        _exact(result["scope"], "saved-offline-android-no-core-build")
        _exact(result["usedConfig"], {"bytes": len(CONFIG), "sha256": digest(CONFIG)})
        _exact(result["limitations"], list(LOCAL_CHECK_LIMITATIONS))
        summary, findings = result["summary"], result["findings"]
        need(type(summary) is dict and set(summary) == {"total", "shown", "omitted", "counts"}
             and all(integer(summary[k], 4096) for k in ("total", "shown", "omitted"))
             and summary["shown"] == min(summary["total"], 128) and summary["omitted"] == summary["total"] - summary["shown"]
             and type(summary["counts"]) is dict and set(summary["counts"]) == set(LOCAL_CHECK_STATUSES)
             and all(integer(n, 4096) for n in summary["counts"].values()) and sum(summary["counts"].values()) == summary["total"]
             and type(findings) is list and len(findings) == summary["shown"], label)
        shown = dict.fromkeys(LOCAL_CHECK_STATUSES, 0)
        for index, finding in enumerate(findings):
            need(type(finding) is dict and set(finding) == {"ordinal", "check", "status", "message", "projectCheckIndex"}
                 and integer(finding["ordinal"], 127) and finding["ordinal"] == index and finding["check"] in LOCAL_CHECK_FINDINGS
                 and finding["message"] == finding["check"] and finding["status"] in LOCAL_CHECK_STATUSES
                 and finding["projectCheckIndex"] is None and finding["check"] != "configured-project-check", label)
            shown[finding["status"]] += 1
        need(all(shown[k] <= summary["counts"][k] and (summary["omitted"] != 0 or shown[k] == summary["counts"][k]) for k in shown), label)
        need(all(any(f["check"] == k and f["status"] == v for f in findings) for k, v in
                 (("android-gradle-wrapper", "MISSING"), ("version-source", "PASS"), ("workspace-private-output", "PASS"))), label)
        target["offline"] = row
    _exact(value, target, ("localChecks",))
    return value


LOCAL_EDITS_SCOPE = "local-edits3"
LOCAL_EDIT_CASES = ("local-metadata-text", "local-release-version", "local-github-apply")
INSTALLATION_INSPECTION_CASE = "installation-inspection"
VAULT_HELPER_SCOPE = "vault-helper-shipping"
VAULT_HELPER_CASES = ("vault-helper-roundtrip", "vault-helper-stop-before-go", "vault-helper-stop-after-add")
PROJECT_FIELD_CHOICES = (
    ("version.source", "version-source", "inputs/VERSION", None),
    ("ios.project", "ios-project", "ios/Example.xcodeproj", None),
    ("ios.workspace", "ios-workspace", "ios/Example.xcworkspace", None),
    ("metadata.root", "metadata-root", "metadata", None),
    ("version.source", "version-source", None, None),
    ("metadata.root", "metadata-root", None, None),
    ("version.source", "version-source", None, "project_path_unsafe"),
    ("version.source", "version-source", None, "project_path_unsafe"),
    ("version.source", "version-source", None, "project_path_unsafe"),
    ("ios.workspace", "ios-workspace", None, "project_path_changed"),
)
PROJECT_FIELD_PANELS = {f"ProjectFields(Native({i}))": (i + 2, choice[1])
                        for i, choice in enumerate(PROJECT_FIELD_CHOICES)}
ALL_CASES = CASES + IOS_CURRENT_CASES + (PROJECT_FIELDS_CASE, ANDROID_INPUT_CASE) + VAULT_HELPER_CASES + (INSTALLATION_INSPECTION_CASE, RECOVERY_CASE, IOS_ACCOUNT_CASE,) + LOCAL_EDIT_CASES + LOCAL_CHECK_CASES
EXECUTABLE = "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app/Contents/Helpers/MobileReleaseKitPayload.app/Contents/MacOS/mobile-release-kit-desktop"
REPOSITORY = "Apdelrahman1911/mobile-release-kit"
REF = "refs/heads/verify/desktop-macos-aqua"
WORKFLOW = REPOSITORY + "/.github/workflows/desktop-macos-aqua.yml@" + REF
MARKER = b"MRK_MACOS_AQUA_RESULT="
OUTPUT_LIMIT = 2 * 1024 * 1024
JSON_LIMIT = 16383
PROJECT_FIELDS_JSON_LIMIT = 32767  # Four bounded original selection histories; no other case grows.
FAILURE_CONTEXT_LIMIT = 8192
TRACEBACK_LIMIT = 64
SCOPE = "programmatic genuine controls; no Store, release, distribution or physical-device evidence"
FAILURE_STEPS = frozenset((
    "Bootstrap Environment ReadEnvironment Dashboard ChooseCancel CancelProject CancelSettled ReadCancelled "
    "ChooseProject OpenProject ProjectSettled Snapshot Settings Suggest Suggestion Adopt Draft "
    "Validate Validation Preview Previewed RequirementsPage LoadRequirements Requirements GitHubPage "
    "GitHubRepository GitHubSha GitHubPropose GitHubProposal ReturnSettings KeepReviewing KeptReview "
    "ReadbackPage Refresh Readback SavedSettings ChangeDraft ChangedDraft MutateIgnore CloseCancel "
    "QuitCancel QuitCancelled RetainedReview Close Quit Exit PickerPending Reload Lost"
).split()) | frozenset(f"{name}({number})" for name in (
    "Prepare", "Review", "OpenConfirmation", "Confirmation", "Acknowledge", "Acknowledged", "Apply", "Applied") for number in (0, 1))
FAILURE_STEPS |= frozenset(f"Checks({name})" for name in (
    "Navigate ToolsSelect ToolsStale EditBranch EditedBranch Releases Prepare Intent Acknowledge Acknowledged Run OfflineWait OfflineRead Settings Discard ConfirmDiscard Discarded"
).split()) | frozenset(f"Checks({name}({i}))" for name in ("ToolsStart", "ToolsWait", "ToolsRead") for i in (0, 1))

FAILURE_STEPS |= frozenset(f"LocalEdits({name})" for name in (
    "Navigate Name Build CloseReview Closed Repository Pin Propose Proposal Mutate Done"
).split()) | frozenset(f"LocalEdits({name}({number}))" for name in (
    "Context Loaded Load Inputs Validate Validated Open Opened Prepare OpenText Review Confirm Confirmation "
    "Check Checked Type Typed Apply Result Refresh Readback"
).split() for number in range(3)) | frozenset(
    f"LocalEdits(Fill({round_number}, {field}))" for round_number, field in ((0, 1), (0, 2), (1, 0), (1, 4)))
FAILURE_STEPS |= frozenset(f"Ios({name})" for name in (
    "Navigate SignedMode ReadVersion VersionRead Prepare Review Acknowledge Acknowledged MutateVersion Start Running Cancel Hold ReleaseHold Final "
    "AccountPrepare AccountReview AccountAcknowledge AccountAcknowledged AccountStart AccountRunning AccountFinal"
).split())
FAILURE_STEPS |= frozenset(f"Session({name})" for name in (
    "Navigate Platform Purpose Open Ready ChangeStage StageChanged Archive LockPage Lock ConfirmLock Locked Done"
).split()) | frozenset(f"Session({name}({number}))" for name in (
    "Kind Choose Native Chosen Fields Prepare Prepared Keep Kept Reassess Reassessed Bind Bound"
).split() for number in range(7)) | frozenset(
    f"Session({name}({number}, {kept}))" for name in ("Discard", "Discarded")
    for number in range(7) for kept in ("true", "false"))
FAILURE_STEPS |= frozenset(f"ProjectFields({name}({i}))" for name in (
    "Navigate Section Browse Native Chosen Read").split() for i in range(10)) | frozenset(
    f"ProjectFields({name})" for name in ("PreviewPage Preview Previewed Done").split())
FAILURE_STEPS |= frozenset(f"Vault({name})" for name in (
    "Open Opened Prepare Prepared Initialize Initialized Lock Locked Reopen Reopened Unlock Unlocked Relock Relocked"
).split())
FAILURE_STEPS |= frozenset(f"Installation({name})" for name in (
    "StartCancelled WaitFirstRead Cancel WaitCancelled StartMatching WaitMatching"
).split())
FAILURE_STEPS |= frozenset(f"Recovery({name})" for name in ("Navigate Ready Inspect WaitInspect ReadInspect Review ReadReview Acknowledge ReadChecked Start WaitRecover ReadFinal").split())
FAILURE_REASONS = frozenset((
    "observer-invariant observer-deadline observer-record-unavailable observer-data-check "
    "dom-dispatch-refused dom-pending-custody dom-callback-size dom-callback-json "
    "dom-callback-object dom-callback-state picker-unexpected-result dom-evaluation-budget dom-project-chooser-data "
    "native-wrong-thread native-step native-pending-custody native-original-id native-kind native-not-started "
    "native-ineligible native-action-attempted native-action-returned native-callback-returned "
    "native-response-present native-selection-present native-close-attempted native-closed "
    "native-attachment-lost native-preaction-history native-dismissed native-duplicate-action "
    "native-ax-not-trusted native-ax-trust native-default-binding native-default-input native-default-custody native-default-deadline "
    "cancel-unexpected-project cancel-duplicate-result adapter-wrong-thread adapter-book-borrow "
    "adapter-original-call adapter-original-owner adapter-original-binding adapter-missing-facts "
    "adapter-missing-panel adapter-ineligible adapter-native-observation adapter-native-action "
    "asset_invalid_request asset_closed asset_unqualified asset_unsupported_platform "
    "asset_unsupported_filesystem asset_unsupported_format asset_busy asset_source_refused "
    "asset_source_changed asset_material_limit asset_parser_limit asset_project_overlap "
    "asset_exclusion_unconfirmed asset_capacity assessment_context_stale asset_user_cancelled "
    "asset_review_expired asset_deadline asset_document_lost asset_shutdown asset_cleanup_unknown "
    "project-result-shape project-result-order project-result-path project-result-name project-result-id "
    "snapshot-request-order snapshot-request-project "
    "snapshot-error-runtime snapshot-error-protocol snapshot-error-invalid snapshot-error-shutdown "
    "snapshot-error-timeout snapshot-error-cleanup snapshot-error-busy snapshot-error-unavailable "
    "snapshot-error-project snapshot-error-limit snapshot-error-io snapshot-error-engine snapshot-error-other "
    "snapshot-value-root snapshot-value-scope snapshot-config-path snapshot-value-assurance "
    "snapshot-value-issues snapshot-hints-android snapshot-hints-version snapshot-discovery-state "
    "snapshot-config-state snapshot-config-data snapshot-config-content snapshot-config-issues "
    "snapshot-return-order snapshot-return-project "
    "project-witness-identity project-witness-response project-witness-selection project-witness-callback "
    "edit-status-schema edit-status-generation edit-status-owner edit-status-projection "
    "relay-join-contract exit-edit-status exit-finality-contract observer-report-unavailable "
    "project-result-path-app-child project-result-path-descendant project-result-path-ancestor "
    "project-result-path-sibling project-result-path-tmp-spelling project-result-path-data-spelling "
    "native-completion-custody native-completion-data native-completion-unknown native-completion-selection "
    "ios-original-witness ios-request-contract ios-status-contract ios-version-contract "
    "ios-finality-contract ios-fixture-contract ios-dom-contract "
    "recovery-original-contract recovery-request-contract recovery-result-contract recovery-dom-contract recovery-fixture-contract "
    "local-edits-original-contract local-edits-dom-contract local-edits-fixture-contract "
    "local-checks-original-contract local-checks-dom-contract local-checks-fixture-contract local-checks-unexpected-cancel local-checks-start-arrival "
    "session-request-contract session-result-contract session-original-contract session-dom-contract "
    "project-fields-request-contract project-fields-result-contract project-fields-original-contract "
    "project-fields-fixture-contract project-fields-dom-contract "
    "vault-request-contract vault-result-contract vault-original-contract vault-finality-contract "
    "installation-request-contract installation-status-contract installation-first-read-contract "
    "installation-original-contract installation-finality-contract "
    "bootstrap-attach-thread bootstrap-attach-duplicate bootstrap-window-result "
    "bootstrap-navigation-untrusted bootstrap-navigation-unattached bootstrap-navigation-order "
    "bootstrap-load-untrusted bootstrap-load-unattached bootstrap-load-reload-order "
    "bootstrap-load-start-order bootstrap-load-finish-before-start bootstrap-load-finish-duplicate "
    "bootstrap-info-methods-shape bootstrap-info-actions-shape bootstrap-info-runtime-state "
    "bootstrap-info-runtime-mode bootstrap-info-runtime-reason bootstrap-info-app-name "
    "bootstrap-info-app-version bootstrap-info-project-selection bootstrap-info-project-reason "
    "bootstrap-info-project-fields bootstrap-info-method-count bootstrap-info-action-count "
    "bootstrap-info-available-count bootstrap-info-required-method bootstrap-info-method-availability "
    "bootstrap-info-action-availability bootstrap-info-duplicate bootstrap-info-reload "
    "bootstrap-catalog-info-order bootstrap-catalog-duplicate bootstrap-catalog-result "
    "bootstrap-catalog-fields bootstrap-catalog-field-count bootstrap-catalog-version-help "
    "bootstrap-catalog-reload bootstrap-close-request bootstrap-tick-main-thread"
).split())
BOOTSTRAP_FAILURE_REASONS = frozenset(reason for reason in FAILURE_REASONS if reason.startswith("bootstrap-"))
PROJECT_SELECTION_CUSTODY = frozenset(("bound-original-data", "unavailable-original-data", "inconsistent-original-data"))
PROJECT_SELECTION_OBJECTS = frozenset(("fixture-root-all5", "captured-app-all5", "captured-release-all5",
                                     "captured-object-metadata-changed", "different-object", "unavailable"))
PROJECT_SELECTION_LOCATIONS = frozenset(("current-project", "current-app", "current-release", "other-case",
                                       "case-cwd", "case-home", "case-tmp", "namespace-other", "outside-namespace", "unavailable"))
# Only when saved native/registry/returned paths agree can the unchanged
# lexical failure reason constrain the selected-location axis this tightly.
PROJECT_SELECTION_BOUND_LOCATIONS = {
    "project-result-path": frozenset(("other-case", "case-cwd", "case-home", "case-tmp", "namespace-other", "outside-namespace")),
    "project-result-path-app-child": frozenset(("current-app",)),
    "project-result-path-descendant": frozenset(("current-release", "namespace-other")),
    "project-result-path-ancestor": frozenset(("namespace-other", "outside-namespace")),
    "project-result-path-sibling": frozenset(("other-case", "namespace-other")),
    "project-result-path-tmp-spelling": frozenset(("outside-namespace",)),
    "project-result-path-data-spelling": frozenset(("outside-namespace",)),
}
NATIVE_STEPS = frozenset("CancelProject OpenProject QuitCancel Quit PickerPending".split())
# Closed same-origin action DATA, not a panel query or an action/finality permit.
NATIVE_ACTION_STEPS = {
    "CancelProject": ("project-cancel", "project", (1,), 1),
    "QuitCancel": ("quit-cancel", "quit", (3,), 8),
    "Quit": ("quit-confirm", "quit", (2, 4), 16),
}
# site: (original native-return error, permitted action mask, can catch ObjC).
# None denotes an exception-only site. Keep aligned with the native decoder.
NATIVE_ACTION_SITES = {
    "main-thread": ("invalid-input", 63, False), "state-pointer": ("invalid-input", 63, False),
    "action-code": ("invalid-input", 63, False), "directory-argument": ("invalid-input", 63, False),
    "original-unknown": ("io", 63, False), "not-started": ("permission-denied", 63, False),
    "window-absent": ("permission-denied", 63, False), "parent-absent": ("permission-denied", 63, False),
    "completion-absent": ("permission-denied", 63, False), "responded": ("permission-denied", 63, False),
    "callback-active": ("permission-denied", 63, False), "close-attempted": ("permission-denied", 63, False),
    "closed": ("permission-denied", 63, False), "action-attempted": ("permission-denied", 63, False),
    "panel-kind": ("permission-denied", 63, False), "attachment": ("would-block", 63, True),
    "directory-already-bound": ("permission-denied", 2, False), "directory-path": ("invalid-input", 2, False),
    "directory-text": ("invalid-input", 2, True), "directory-url": ("invalid-input", 2, True),
    "directory-set": ("none", 2, True), "directory-unbound": ("permission-denied", 4, False),
    "directory-not-returned": ("permission-denied", 4, False), "directory-ready": ("would-block", 4, True),
    "alert-buttons": (None, 24, True), "alert-absent": ("permission-denied", 24, False),
    "button-count": ("permission-denied", 24, True), "button-index": (None, 24, True),
    "button-window": ("permission-denied", 24, True), "button-enabled": ("would-block", 24, True),
    "button-hidden": ("would-block", 24, True), "project-cancel": ("none", 1, True),
    "project-open": ("none", 4, True), "quit-cancel": ("none", 8, True), "quit-confirm": ("none", 16, True),
    "file-cancel": ("none", 32, True),
}
ACCESSIBILITY_CONTROL_LIMIT_SITES = frozenset((
    "control-title-limit control-child-count-limit control-child-copy-limit control-node-limit control-depth-limit"
).split())
ACCESSIBILITY_SITES = frozenset((
    "entry application windows parent-identifier sheet topology control-projection button control-recheck "
    "initial-original-proof original-proof admission press cleanup"
).split()) | ACCESSIBILITY_CONTROL_LIMIT_SITES
ACCESSIBILITY_SELECTION_SITES = frozenset((
    "selection-parent-proof selection-projection selection-recheck selection-settable selection-write selection-readback"
).split())
ACCESSIBILITY_SITES |= ACCESSIBILITY_SELECTION_SITES
ACCESSIBILITY_SELECTION_LIMITS = ("label-length", "child-count", "child-copy-count", "queue-capacity", "depth",
                                  "ax-call-budget", "cf-slot-budget")
ACCESSIBILITY_SELECTION_CHECKS = ("completeProjection", "uniqueEntry", "originalLabelChainRechecked",
                                  "attributeSettable", "singletonOriginalEntryReadback")
ACCESSIBILITY_CONTROL_ROLES = ("not-read", "Sheet", "Group", "SplitGroup", "Button",
                               "Browser", "Table", "Outline", "ScrollArea", "opaque")
ACCESSIBILITY_SELECTION_ROLES = ACCESSIBILITY_CONTROL_ROLES + ("Column", "List", "Row", "Cell", "Image", "StaticText", "TextField")
ACCESSIBILITY_ERRORS = frozenset((
    "none wrong-thread invalid-input ineligible unsupported ambiguous malformed limit deadline custody "
    "invalid-element cannot-complete ax-other changed objc-exception cleanup-unknown"
).split())
# Closed first actual AX-fault labels. No values, object identities or inferred causes.
ACCESSIBILITY_AX_FAILURE_OPERATIONS = (
    "set-messaging-timeout", "copy-attribute-value", "get-attribute-value-count", "copy-attribute-values",
    "copy-action-names", "is-attribute-settable", "set-attribute-value", "perform-action",
    "copy-multiple-attribute-values",
)
ACCESSIBILITY_AX_FAILURE_ATTRIBUTES = (
    None, "Parent", "Role", "Identifier", "Title", "Value", "Enabled",
    "Windows", "Children", "Rows", "SelectedChildren", "SelectedRows",
)
ACCESSIBILITY_AX_FAILURE_PAIRS = frozenset(
    (ACCESSIBILITY_AX_FAILURE_OPERATIONS[operation - 1], ACCESSIBILITY_AX_FAILURE_ATTRIBUTES[attribute])
    for operation, attributes in (
        (1, (0,)), (2, range(1, 7)), (3, range(7, 12)), (4, range(7, 12)),
        (5, (0,)), (6, (10, 11)), (7, (10, 11)), (8, (0,)), (9, (0,)),
    )
    for attribute in attributes
)
ACCESSIBILITY_BINDING_CLASSES = frozenset(("nil", "match", "different", "type-invalid"))
ACCESSIBILITY_BINDING_SITES = frozenset((
    "objects", "parent-tag", "parent-set", "parent-get", "prompt-set", "prompt-get", "complete",
    "initial-directory-url", "initial-directory-set", "initial-temporary-close",
    "file-name-set", "file-name-get",
))
ACCESSIBILITY_PANEL_CLASSES = frozenset((
    "nil", "type-invalid", "empty", "byte-limit", "nul", "encoding-invalid", "valid", "match", "different",
))
ACCESSIBILITY_PROOF_CHECKS = (
    "eligible", "attached", "directory", "parentIdentifier", "panelIdentifier", "parentSingleton",
    "noNestedSheet", "nativeChild", "nativeParent", "nativeRole", "stableIdentifier", "finalEligibility",
)
ACCESSIBILITY_PROOF_SITES = frozenset((
    "objects attachment directory parent-identifier panel-identifier parent-sheets panel-sheets "
    "panel-attached-sheet native-children native-parent native-role stable-identifier final-eligibility complete"
).split())
ACCESSIBILITY_BUTTON_CHECKS = (
    "parentBound", "sheetBound", "completeControlProjection", "uniquePromptButton",
    "enabled", "pressAdvertised", "sameOriginalControlPathRechecked",
)
SOURCE = (b'plugins { id("com.android.application") }\n'
          b'android { defaultConfig { applicationId = "org.example.mrk.observed" } }\n')
VERSION = b"VERSION_NAME=1.2.3\nBUILD_NUMBER=7\n"
KEEP = b"MRK_MACOS_AQUA_KEEP\n"
IGNORE_PREFIX = b"# MRK Mac Aqua user ignore\nuser-output/\n"
IGNORE_RULES = (b".mobile-release/\n.mobile-release-init-prepare/\n.mobile-release-init/\n"
                b".mobile-release-init-cleanup/\n.mobile-release-metadata-text-prepare/\n"
                b".mobile-release-metadata-text/\n.mobile-release-metadata-text-cleanup/\n"
                b".mobile-release-version-prepare/\n.mobile-release-version/\n.mobile-release-version-cleanup/\n"
                b".mobile-release-metadata-images-prepare/\n.mobile-release-metadata-images/\n.mobile-release-metadata-images-cleanup/\n")
STALE = b"# MRK Mac Aqua stale base\n"
# Literal public fixture DATA, not another core configuration serializer.
CONFIG = b'''{
  "android": {
    "applicationId": "org.example.mrk.observed",
    "enabled": true,
    "identityStatus": "unverified"
  },
  "ios": {
    "enabled": false
  },
  "metadata": {
    "androidLocales": [
      "en-US"
    ],
    "iosLocales": [],
    "root": "release/store"
  },
  "projectChecks": {
    "androidArtifact": [],
    "iosArtifact": [],
    "preflight": []
  },
  "schemaVersion": 1,
  "services": {
    "androidFirebase": "disabled",
    "iosFirebase": "disabled"
  },
  "source": {
    "candidateBranch": "main",
    "productionBranch": "main"
  },
  "version": {
    "buildKey": "BUILD_NUMBER",
    "nameKey": "VERSION_NAME",
    "source": "version.properties"
  }
}
'''

# Fixed credential-free iOS fixture bytes, mirrored by the native observer.
IOS_CONFIG = b'''{
  "android": {
    "enabled": false
  },
  "ios": {
    "archiveConfiguration": "Release",
    "bundleId": "org.example.mrk.observed",
    "enabled": true,
    "identityStatus": "unverified",
    "project": "ios/MRKObserved.xcodeproj",
    "scheme": "MRKObserved",
    "symbols": {
      "policy": "required",
      "uploadCommand": [
        "/usr/bin/false"
      ]
    }
  },
  "metadata": {
    "androidLocales": [],
    "iosLocales": [
      "en-US"
    ],
    "root": "release/store"
  },
  "projectChecks": {
    "androidArtifact": [],
    "iosArtifact": [],
    "preflight": []
  },
  "schemaVersion": 1,
  "services": {
    "androidFirebase": "disabled",
    "iosFirebase": "disabled"
  },
  "source": {
    "candidateBranch": "main",
    "productionBranch": "main"
  },
  "version": {
    "buildKey": "BUILD_NUMBER",
    "nameKey": "VERSION_NAME",
    "source": "version.properties"
  }
}
'''
IOS_CONFIG_PREREQUISITE = b'''{
  "android": {
    "enabled": false
  },
  "ios": {
    "archiveConfiguration": "Release",
    "bundleId": "org.example.mrk.observed",
    "enabled": true,
    "identityStatus": "unverified",
    "prepareCommand": [
      "/usr/bin/false"
    ],
    "project": "ios/MRKObserved.xcodeproj",
    "scheme": "MRKObserved",
    "symbols": {
      "policy": "required",
      "uploadCommand": [
        "/usr/bin/false"
      ]
    }
  },
  "metadata": {
    "androidLocales": [],
    "iosLocales": [
      "en-US"
    ],
    "root": "release/store"
  },
  "projectChecks": {
    "androidArtifact": [],
    "iosArtifact": [],
    "preflight": []
  },
  "schemaVersion": 1,
  "services": {
    "androidFirebase": "disabled",
    "iosFirebase": "disabled"
  },
  "source": {
    "candidateBranch": "main",
    "productionBranch": "main"
  },
  "version": {
    "buildKey": "BUILD_NUMBER",
    "nameKey": "VERSION_NAME",
    "source": "version.properties"
  }
}
'''
IOS_CONFIG_CANCEL = b'''{
  "android": {
    "enabled": false
  },
  "ios": {
    "archiveConfiguration": "Release",
    "bundleId": "org.example.mrk.observed",
    "enabled": true,
    "identityStatus": "unverified",
    "prepareCommand": [
      "/bin/sleep",
      "30"
    ],
    "project": "ios/MRKObserved.xcodeproj",
    "scheme": "MRKObserved",
    "symbols": {
      "policy": "required",
      "uploadCommand": [
        "/usr/bin/false"
      ]
    }
  },
  "metadata": {
    "androidLocales": [],
    "iosLocales": [
      "en-US"
    ],
    "root": "release/store"
  },
  "projectChecks": {
    "androidArtifact": [],
    "iosArtifact": [],
    "preflight": []
  },
  "schemaVersion": 1,
  "services": {
    "androidFirebase": "disabled",
    "iosFirebase": "disabled"
  },
  "source": {
    "candidateBranch": "main",
    "productionBranch": "main"
  },
  "version": {
    "buildKey": "BUILD_NUMBER",
    "nameKey": "VERSION_NAME",
    "source": "version.properties"
  }
}
'''
# Fixed mechanical inputs, not valid Apple signing material or trust evidence.
# Same signature-less DER structures as credential_apple.rs's reviewed fixtures.
IOS_SYNTHETIC_P12 = bytes.fromhex(
    "3030020103302b06092a864886f70d010701a01e041c"
    "707269766174652d656e76656c6f70652d6f6e6c792d63616e617279")
IOS_SYNTHETIC_PROFILE = bytes.fromhex(
    "304306092a864886f70d010702a03630340201013100302b06092a864886f70d010701a01e041c"
    "707269766174652d656e76656c6f70652d6f6e6c792d63616e6172793100")
IOS_SYNTHETIC_FIREBASE = b'''<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>BUNDLE_ID</key><string>org.example.mrk.observed</string></dict></plist>
'''
IOS_CONFIG_SIGNED = b'''{
  "android": {"enabled": false},
  "ios": {
    "archiveConfiguration": "Release",
    "bundleId": "org.example.mrk.observed",
    "distributionCertificateSha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "enabled": true,
    "identityStatus": "unverified",
    "project": "ios/MRKObserved.xcodeproj",
    "scheme": "MRKObserved",
    "symbols": {"policy": "retain"},
    "teamId": "INERT12345"
  },
  "metadata": {"androidLocales": [], "iosLocales": ["en-US"], "root": "release/store"},
  "projectChecks": {"androidArtifact": [], "iosArtifact": [], "preflight": []},
  "schemaVersion": 1,
  "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
  "source": {"candidateBranch": "main", "productionBranch": "main"},
  "version": {"buildKey": "BUILD_NUMBER", "nameKey": "VERSION_NAME", "source": "version.properties"}
}
'''
IOS_CONFIG_INPUTS = IOS_CONFIG_SIGNED.replace(b'"iosFirebase": "disabled"', b'"iosFirebase": "required"')

IOS_PROJECT = b'''// !$*UTF8*$!
{
 archiveVersion = 1;
 classes = {};
 objectVersion = 56;
 objects = {
  000000000000000000000001 = {isa = PBXProject; attributes = {BuildIndependentTargetsInParallel = YES; LastUpgradeCheck = 1500;}; buildConfigurationList = 000000000000000000000002; compatibilityVersion = "Xcode 14.0"; developmentRegion = en; hasScannedForEncodings = 0; knownRegions = (en, Base); mainGroup = 000000000000000000000003; productRefGroup = 000000000000000000000004; projectDirPath = ""; projectRoot = ""; targets = (000000000000000000000005);};
  000000000000000000000002 = {isa = XCConfigurationList; buildConfigurations = (000000000000000000000006); defaultConfigurationIsVisible = 0; defaultConfigurationName = Release;};
  000000000000000000000003 = {isa = PBXGroup; children = (000000000000000000000007, 000000000000000000000004, 000000000000000000000008); sourceTree = "<group>";};
  000000000000000000000004 = {isa = PBXGroup; children = (000000000000000000000009); name = Products; sourceTree = "<group>";};
  000000000000000000000005 = {isa = PBXNativeTarget; buildConfigurationList = 00000000000000000000000A; buildPhases = (00000000000000000000000B, 00000000000000000000000C, 00000000000000000000000D); buildRules = (); dependencies = (); name = MRKObserved; productName = MRKObserved; productReference = 000000000000000000000009; productType = "com.apple.product-type.application";};
  000000000000000000000006 = {isa = XCBuildConfiguration; buildSettings = {CLANG_ENABLE_OBJC_ARC = YES; SDKROOT = iphoneos;}; name = Release;};
  000000000000000000000007 = {isa = PBXGroup; children = (00000000000000000000000E, 00000000000000000000000F); path = MRKObserved; sourceTree = "<group>";};
  000000000000000000000008 = {isa = PBXGroup; children = (000000000000000000000010); name = Frameworks; sourceTree = "<group>";};
  000000000000000000000009 = {isa = PBXFileReference; explicitFileType = wrapper.application; includeInIndex = 0; path = MRKObserved.app; sourceTree = BUILT_PRODUCTS_DIR;};
  00000000000000000000000A = {isa = XCConfigurationList; buildConfigurations = (000000000000000000000011); defaultConfigurationIsVisible = 0; defaultConfigurationName = Release;};
  00000000000000000000000B = {isa = PBXSourcesBuildPhase; buildActionMask = 2147483647; files = (000000000000000000000012); runOnlyForDeploymentPostprocessing = 0;};
  00000000000000000000000C = {isa = PBXFrameworksBuildPhase; buildActionMask = 2147483647; files = (000000000000000000000013); runOnlyForDeploymentPostprocessing = 0;};
  00000000000000000000000D = {isa = PBXResourcesBuildPhase; buildActionMask = 2147483647; files = (); runOnlyForDeploymentPostprocessing = 0;};
  00000000000000000000000E = {isa = PBXFileReference; lastKnownFileType = sourcecode.c.objc; path = main.m; sourceTree = "<group>";};
  00000000000000000000000F = {isa = PBXFileReference; lastKnownFileType = text.plist.xml; path = Info.plist; sourceTree = "<group>";};
  000000000000000000000010 = {isa = PBXFileReference; lastKnownFileType = wrapper.framework; name = UIKit.framework; path = System/Library/Frameworks/UIKit.framework; sourceTree = SDKROOT;};
  000000000000000000000011 = {isa = XCBuildConfiguration; buildSettings = {
   ARCHS = arm64;
   CODE_SIGNING_ALLOWED = NO;
   CODE_SIGNING_REQUIRED = NO;
   DEBUG_INFORMATION_FORMAT = "dwarf-with-dsym";
   GCC_GENERATE_DEBUGGING_SYMBOLS = YES;
   INFOPLIST_FILE = MRKObserved/Info.plist;
   IPHONEOS_DEPLOYMENT_TARGET = 15.0;
   PRODUCT_BUNDLE_IDENTIFIER = org.example.mrk.observed;
   PRODUCT_NAME = MRKObserved;
   SKIP_INSTALL = NO;
   STRIP_INSTALLED_PRODUCT = NO;
   SUPPORTED_PLATFORMS = iphoneos;
   TARGETED_DEVICE_FAMILY = "1,2";
  }; name = Release;};
  000000000000000000000012 = {isa = PBXBuildFile; fileRef = 00000000000000000000000E;};
  000000000000000000000013 = {isa = PBXBuildFile; fileRef = 000000000000000000000010;};
 };
 rootObject = 000000000000000000000001;
}
'''
IOS_SCHEME = b'''<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion="1500" version="1.3">
 <BuildAction parallelizeBuildables="NO" buildImplicitDependencies="NO"><BuildActionEntries>
  <BuildActionEntry buildForTesting="NO" buildForRunning="YES" buildForProfiling="YES" buildForArchiving="YES" buildForAnalyzing="YES">
   <BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="000000000000000000000005" BuildableName="MRKObserved.app" BlueprintName="MRKObserved" ReferencedContainer="container:MRKObserved.xcodeproj"/>
  </BuildActionEntry>
 </BuildActionEntries></BuildAction>
 <ArchiveAction buildConfiguration="Release" revealArchiveInOrganizer="NO"/>
</Scheme>
'''
IOS_MAIN = b'''#import <UIKit/UIKit.h>
@interface MRKObservedDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end
@implementation MRKObservedDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController = [[UIViewController alloc] init];
    self.window.rootViewController.view.backgroundColor = UIColor.systemBackgroundColor;
    [self.window makeKeyAndVisible];
    return YES;
}
@end
int main(int argc, char *argv[]) {
    @autoreleasepool { return UIApplicationMain(argc, argv, nil, NSStringFromClass(MRKObservedDelegate.class)); }
}
'''
IOS_PLIST = b'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
 <key>CFBundleDevelopmentRegion</key><string>en</string>
 <key>CFBundleExecutable</key><string>$(EXECUTABLE_NAME)</string>
 <key>CFBundleIdentifier</key><string>$(PRODUCT_BUNDLE_IDENTIFIER)</string>
 <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
 <key>CFBundleName</key><string>$(PRODUCT_NAME)</string>
 <key>CFBundlePackageType</key><string>APPL</string>
 <key>CFBundleShortVersionString</key><string>$(MARKETING_VERSION)</string>
 <key>CFBundleVersion</key><string>$(CURRENT_PROJECT_VERSION)</string>
 <key>LSRequiresIPhoneOS</key><true/>
 <key>UILaunchScreen</key><dict/>
 <key>UISupportedInterfaceOrientations</key><array><string>UIInterfaceOrientationPortrait</string></array>
</dict></plist>
'''
IOS_WORKSPACE = b'''<?xml version="1.0" encoding="UTF-8"?>
<Workspace version="1.0"><FileRef location="self:"/></Workspace>
'''

OWNER_PINS = {
    "owned_process.py": "0c7c87c7eaf27629be2eb33c195a956b6c40b7b5883214a08e15f255ac4939b8",
    "_command_process.py": "30781e5b264fbcdb4c09028829e0606095a79e5c7a194556484f5ca8b2bfad69",
    "_native_process.py": "70c380adde3c2bc06a0985761f0f877355bb56ef09ad506440da93fd4e4ba3b4",
    "cancellation.py": "5f469444f42b5ad6a69ecce8161a7d83e67303c92a221a31f88c079f4ff29d35",
}


class Refused(Exception):
    """A fixed public diagnostic label, never an OS/path/child transcript."""


def need(condition, label):
    if not condition:
        raise Refused(label)


def digest(body):
    return hashlib.sha256(body).hexdigest()


ARM_TARGET = "aarch64-apple-darwin"
INTEL_TARGET = "x86_64-apple-darwin"


def target_data(target):
    need(type(target) is str and target in (ARM_TARGET, INTEL_TARGET), "native-target")
    intel = target == INTEL_TARGET
    return {"machine": "x86_64" if intel else "arm64", "runner": "X64" if intel else "ARM64",
            "releaseInput": "build-release-intel.json" if intel else "build-release.json",
            "sourceLock": "source-lock-intel.json" if intel else "source-lock.json",
            "releasePrefix": "macos26-x86_64-" if intel else "macos26-arm64-",
            "platform": "macOS26-x86_64" if intel else "macOS26-arm64",
            "cargo": "/Users/runner/.rustup/toolchains/stable-" + target + "/bin/cargo",
            "toolchain": "1.98.0" if intel else "1.98.1"}


@dataclass(frozen=True)
class Binding:
    source: str
    run: str
    attempt: str
    target: str = ARM_TARGET

    def checked(self):
        target_data(self.target)
        need(type(self.source) is str and re.fullmatch(r"[0-9a-f]{40}", self.source), "source-binding")
        need(all(type(v) is str and re.fullmatch(r"[1-9][0-9]{0,19}", v) for v in (self.run, self.attempt)), "run-binding")
        return self

    def root(self, *, project_fields=False, vault_helper=False, installation_inspection=False, recovery=False, local_edits=False, local_checks=False):
        self.checked()
        flags = (project_fields, vault_helper, installation_inspection, recovery, local_edits, local_checks)
        need(all(type(flag) is bool for flag in flags) and sum(flags) <= 1, "scope-not-supported")
        suffix = ("-project-fields" if project_fields else "-vault-helper" if vault_helper
                  else "-installation-inspection" if installation_inspection else "-project-recovery" if recovery else "-local-edits" if local_edits else "-doctor-preflight" if local_checks else "")
        return Path("/private/tmp") / f"mrk-macos-aqua-{self.source}-{self.run}-{self.attempt}{suffix}"

    def public(self):
        return {"sourceCommit": self.source, "runId": self.run, "runAttempt": self.attempt}


def _expected_identity_proof():
    # Literal successful DATA shape, never a substitute for a native receipt.
    return {"returned": True, "attempted": True, "checks": dict.fromkeys(ACCESSIBILITY_PROOF_CHECKS, True),
            "parent": "match", "panel": "match", "children": 1, "originals": "one", "site": "complete", "error": "none"}


def _expected_prompt_button():
    # A literal parser fixture, not observed AX counts or a native receipt.
    return {"checks": dict.fromkeys(ACCESSIBILITY_BUTTON_CHECKS, True), "calls": 48,
            "initialNodesExamined": 2, "recheckNodesExamined": 2, "lastRole": "Button", "lastDepth": 1,
            "cfSlots": 32, "cfSlotsRetired": 32, "cleanupReturned": True, "axError": 0, "axFailure": None}


def _expected_completion_selection(case):
    # Literal parser DATA only. Browsing/Press never supplies this witness.
    return {"mechanism": "original-ok-singleton-selection-v1", "case": case,
            "id": 2 if case == "first-save" else 1, "kind": "project",
            "pollReturned": True, "pollResult": "responded", "timely": True,
            "facts": {"callbackEntered": True, "urlsReadEntered": True, "urlsReadReturned": True,
                      "callbackReturned": True, "duplicate": False, "nativeUnknown": False,
                      "response": "accept", "selection": "match"}}


def selected_cases(scope=None):
    need(scope in (None, "ios-unsigned-archive", "ios-current-synthetic", PROJECT_FIELDS_CASE, ANDROID_INPUT_CASE, VAULT_HELPER_SCOPE, INSTALLATION_INSPECTION_CASE, RECOVERY_CASE, IOS_ACCOUNT_CASE, LOCAL_EDITS_SCOPE, LOCAL_CHECK_SCOPE), "scope-not-supported")
    if scope == LOCAL_CHECK_SCOPE:
        return LOCAL_CHECK_CASES
    if scope == LOCAL_EDITS_SCOPE:
        return LOCAL_EDIT_CASES
    if scope == VAULT_HELPER_SCOPE:
        return VAULT_HELPER_CASES
    if scope in (PROJECT_FIELDS_CASE, ANDROID_INPUT_CASE, INSTALLATION_INSPECTION_CASE, RECOVERY_CASE, IOS_ACCOUNT_CASE):
        return (scope,)
    if scope == "ios-current-synthetic":
        return IOS_CURRENT_CASES
    return IOS_CASES if scope == "ios-unsigned-archive" else CASES


def argument_scope(argv):
    # Closed scopes only; no executable/path/env/timeout passthrough.
    need(type(argv) is list and (argv == [] or argv == ["--scope", "ios-unsigned-archive"]
                               or argv == ["--scope", "ios-current-synthetic"]
                               or argv == ["--scope", PROJECT_FIELDS_CASE]
                               or argv == ["--scope", ANDROID_INPUT_CASE]
                               or argv == ["--scope", VAULT_HELPER_SCOPE]
                               or argv == ["--scope", INSTALLATION_INSPECTION_CASE]
                               or argv == ["--scope", RECOVERY_CASE]
                               or argv == ["--scope", IOS_ACCOUNT_CASE]
                               or argv == ["--scope", LOCAL_EDITS_SCOPE]
                               or argv == ["--scope", LOCAL_CHECK_SCOPE]), "arguments-not-supported")
    return argv[1] if argv else None


def entry_arguments(argv):
    # The fixed host target follows, never precedes/interleaves, the old scope.
    need(type(argv) is list and all(type(value) is str for value in argv), "arguments-not-supported")
    target = ARM_TARGET
    if len(argv) >= 2 and argv[-2] == "--target":
        target = argv[-1]
        target_data(target)
        argv = argv[:-2]
    return argument_scope(argv), target


def case_timeout(case):
    need(type(case) is str and case in ALL_CASES, "case-binding")
    if case in LOCAL_CHECK_CASES:
        return (105, 1875)[LOCAL_CHECK_CASES.index(case)]
    if case in LOCAL_EDIT_CASES:
        return (135, 105, 195)[LOCAL_EDIT_CASES.index(case)]
    return 525 if case == IOS_ACCOUNT_CASE else 95 if case == INSTALLATION_INSPECTION_CASE else 325 if case in IOS_OPERATION_CASES or case == RECOVERY_CASE else 135 if case in VAULT_HELPER_CASES else 60


def ios_config(case):
    need(case in IOS_CURRENT_CASES and case != "ios-recovery-empty", "ios-case")
    if case in IOS_SIGNED_CASES:
        return IOS_CONFIG_SIGNED
    if case == "ios-signing-inputs":
        return IOS_CONFIG_INPUTS
    return IOS_CONFIG_PREREQUISITE if case == IOS_CASES[0] else IOS_CONFIG_CANCEL if case == "ios-cancel" else IOS_CONFIG


def _ios_version_observation(case):
    return {"schemaVersion": 2, "source": "version.properties", "version": {"name": "1.2.3", "build": 7},
            "observationScope": "single-request-non-atomic",
            "assurance": {"basis": "static-text", "projectCodeExecuted": False, "toolsProbed": False,
                          "credentialsRead": False, "gitObserved": False, "storeContacted": False,
                          "writesPerformed": False, "releaseReadiness": "unknown"},
            "savedConfig": {"bytes": len(ios_config(case)), "sha256": digest(ios_config(case))},
            "savedVersion": {"bytes": len(VERSION), "sha256": digest(VERSION)}}


def _expected_signing_inputs(case):
    """Literal parser-test DATA; never substitutes for original native inputs."""
    need(case in SESSION_CASES, "signing-inputs-case")
    signed, android = case in IOS_SIGNED_CASES, case == ANDROID_INPUT_CASE
    roles = ("p12", "profile") if signed else (("keystore", "firebase", "firebase-mismatch", "overlap", "link", "public", "cancel")
            if android else ("p12", "profile", "firebase", "overlap", "link", "public", "cancel"))
    ids = INPUT_IDS[case]
    rows = []
    for index, (role, operation) in enumerate(zip(roles, ids)):
        keep = (signed or android) and index < 2
        if android:
            assessment = None if index >= 3 else {
                "state": ("configured", "format-valid", "invalid")[index],
                "identity": ("not-applicable", "match", "mismatch")[index],
                "fieldScopes": list((("jks-header", "value-admission", "value-admission", "identifier-format", "value-admission"),
                                     ("json-document", "firebase-shape", "application-identity"),
                                     ("json-document", "firebase-shape", "application-identity"))[index]),
                "fieldOutcomes": list((("asserted-pass", "passed", "passed", "passed", "passed"),
                                       ("asserted-pass", "passed", "passed"), ("asserted-pass", "passed", "failed"))[index]),
                "issues": ["identity-mismatch"] if index == 2 else []}
            kind = "android-firebase" if index in (1, 2) else "android-keystore"
        else:
            assessment = None if index >= 3 else {
                "state": "format-valid" if index == 2 else "configured",
                "identity": "match" if index == 2 else "not-applicable",
                "fieldScopes": list((("pfx-envelope", "value-admission"), ("cms-signed-data-envelope",),
                                     ("plist-document", "firebase-shape", "application-identity"))[index])}
            kind = "apple-profile" if index == 1 else "ios-firebase" if index == 2 else "apple-p12"
        rows.append({"role": role, "kind": kind, "operationId": operation,
                     "nativeResponse": "decline" if index == 6 else "accept",
                     "exactNativeSelection": None if index == 6 else True,
                     "source": "captured" if index < 3 else "pending" if index == 6 else "refused",
                     "reason": "none" if index < 3 else "project-overlap" if index == 3
                         else "user-cancelled" if index == 6 else "source-refused",
                     "originalWorkerAndNativeSettled": True,
                     "openIdentityMatched": None if index == 6 else True,
                     "openInputJoined": None if index == 6 else True,
                     "assessment": assessment, "recordId": ("d" if index == 0 else "e") * 32 if keep else None,
                     "keptRevision": 1 if keep else None, "assignedContextRevision": 1 if keep else None})
    value = {"schemaVersion": 2, "oneUseOriginalDocumentRegistration": True,
             "selection": "ordinary-installed-macos-session", "mode": "session",
             "context": {"platform": "android" if android else "ios", "stage": "production" if android else "candidate",
                         "purpose": "full" if android else "signing"}, "rows": rows,
             "originalOperations": 18 if android else 12, "allOriginalsSettled": True, "memorySessionLocked": True,
             "originalProjectAndQuitSettled": True, "observationMs": 315000 if signed else 45000,
             "outerInvocationMs": 325000 if signed else 60000}
    if android:
        value["contextTransition"] = {"previous": {"platform": "android", "stage": "candidate", "purpose": "full"},
            "current": {"platform": "android", "stage": "production", "purpose": "full"},
            "previousRevision": 1, "currentRevision": 2, "preservedRecords": 2, "assignmentsUnavailable": 2,
            "oldPreviewRetired": True, "oldSelectionRetired": True, "originalsSettled": True}
    return value


def _signing_inputs(value, case):
    need(type(value) is dict, "signing-inputs-report")
    expected = _expected_signing_inputs(case)
    if case in IOS_SIGNED_CASES or case == ANDROID_INPUT_CASE:
        try:
            rows = value["rows"]
            need(type(rows) is list and len(rows) == (7 if case == ANDROID_INPUT_CASE else 2), "signing-inputs-rows")
            ids = [row["recordId"] for row in rows[:2]]
            need(all(type(v) is str and re.fullmatch(r"[0-9a-f]{32}", v) for v in ids)
                 and len(set(ids)) == 2, "signing-inputs-records")
            for expected_row, record_id in zip(expected["rows"][:2], ids):
                expected_row["recordId"] = record_id
        except (KeyError, TypeError, AttributeError) as error:
            raise Refused("signing-inputs-shape") from error
    _exact(value, expected, ("signingInputs",))
    return value


def _signing_policy_from_inputs(value):
    return {"teamId": "INERT12345", "distributionCertificateSha256": "c" * 64,
            "assignments": [{"kind": row["kind"], "recordId": row["recordId"],
                             "recordRevision": row["keptRevision"], "contextRevision": row["assignedContextRevision"]}
                            for row in value["rows"]]}


IOS_LIMITATIONS = ["saved-inputs-not-atomic", "project-build-code-is-trusted", "not-network-isolated",
                  "unsigned-archive-not-an-ipa", "signing-and-profile-not-validated", "ipa-correspondence-not-validated",
                  "source-provenance-not-authenticated", "store-operation-not-requested", "release-readiness-not-assessed",
                  "retained-location-not-current-file-authority", "core-terminal-requires-original-native-finality"]


def _expected_ios_report(case):
    if case == IOS_ACCOUNT_CASE:
        return _expected_ios_pending_report()
    """Literal parser-test DATA, never a native receipt or a success producer."""
    if case in IOS_SIGNED_CASES or case == "ios-recovery-empty":
        return _expected_ios_account_report(case)
    need(case in IOS_CASES, "ios-report-case")
    version = _ios_version_observation(case)
    stale, cancel = case == "ios-version-stale", case == "ios-cancel"
    complete = case in ("ios-unsigned-archive", "ios-finality")
    operation, generation = "a" * 32, "b" * 32
    context = {"projectId": "inert-ios-parser", "draftRevision": 1, "baselineGeneration": 1,
               "savedConfig": version["savedConfig"], "savedVersion": {"source": "version.properties", "name": "1.2.3", "build": 7,
                   **version["savedVersion"]}, "platform": "ios", "operation": "ios-unsigned-archive"}
    facts = {key: True for key in (
        "inspectionJoined acquisitionJoined attempted childWaitedSuccess stdinClosed stdoutEofClosed stderrEofClosed ioJoined "
        "coreLifetimeSettled runtimeLedgerSettled toolsLedgerSettled nativeSettlementJoined nativeIntegrity "
        "driverJoined managerJoined observerJoined watchdogJoined retiredBeforeCutoff"
    ).split()}
    facts.update(operationId=operation, ownerGeneration=generation, activeRetained=False, resourceUnknown=False,
                 workMs=300000, hardMs=310000)
    no = {"outcome": "not-dispatched", "exitCode": None}
    zero = {"outcome": "exited", "exitCode": 0}
    commands = {"xcode-version": dict(no if stale else zero), "ios-sdk": dict(no if stale else zero),
                "archive": dict(zero if complete else no),
                "prepare": dict(no) if stale else {"outcome": "not-configured", "exitCode": None} if complete
                    else {"outcome": "unknown", "exitCode": None} if cancel else {"outcome": "exited", "exitCode": 1}}
    selection = None if stale else {"containerKind": "project", "container": "ios/MRKObserved.xcodeproj",
        "scheme": "MRKObserved", "configuration": "Release", "bundleId": "org.example.mrk.observed",
        "symbolsPolicy": "required", "preparationConfigured": not complete}
    result = None if not complete else {"schemaVersion": 1, "scope": "local-unsigned-ios-archive-observation",
        "usedConfig": context["savedConfig"], "usedVersion": context["savedVersion"],
        "archive": f".mobile-release/desktop-ios-archive/{operation}/archive.xcarchive",
        "entries": 16, "bytes": 4096, "limitations": list(IOS_LIMITATIONS)}
    terminal = {"schemaVersion": 1, "context": context,
        "outcome": "complete" if complete else "refused" if stale else "cancelled" if cancel else "failed",
        "reason": "none" if complete else "saved-version-changed" if stale else "cancelled" if cancel else "command-failed",
        "activity": {"stage": "disposing-work" if complete else "accepted" if stale else "preparing", "selection": selection,
                     "commands": commands, "findings": [{"check": "archive-identity", "status": "PASS"},
                         {"check": "archive-dsym", "status": "PASS"}] if complete else []},
        "disposition": {"snapshot": "removed" if complete else "not-created", "work": "not-created" if stale else "removed",
                        "output": "retained-local-result" if complete else "not-created" if stale else "retained-incomplete",
                        "relativeDirectory": None if stale else f".mobile-release/desktop-ios-archive/{operation}"},
        "result": result,
        "lifetime": {"complete": True, "fatal": False, "contained": True, "commandDispatched": not stale,
                     "commands": 0 if stale else 3, "profileCalls": 0, "stopObserved": "cancelled" if cancel else "none",
                     **dict.fromkeys(("inputClosed", "handlersRestored", "invocationClosed", "snapshotClosed", "filesClosed", "namespaceClosed"), True)}}
    held_facts = {**facts, "observerJoined": False, "watchdogJoined": False, "retiredBeforeCutoff": False, "activeRetained": True}
    return {"protocol": "mrk-ios-archive/1", "savedVersionObservation": version, "context": context,
            "prepareRequestedOnce": True, "prepareReturned": True, "reviewVisible": True, "acknowledged": True,
            "startRequestedOnce": True, "startReturned": True, "statusCallsReturned": 1,
            "staleVersionWriterReturnedAndClosed": stale,
            "original": {"facts": facts, "terminal": terminal}, "finalResultVisible": True,
            "prerequisiteOnly": case == "ios-toolchain-prerequisite",
            "cancel": {"requestedOnce": True, "returned": True, "stageAtClick": "preparing",
                       "prepareOutcome": commands["prepare"], "activeCommandKillClaimed": False} if cancel else None,
            "hold": {"original": {"facts": held_facts, "terminal": terminal}, "publicSuccessHidden": True,
                     "conflictingUiBlocked": True, "environmentDiagnosticsBlocked": True, "originalReleasedOnce": True} if case == "ios-finality" else None,
            "workMs": 300000, "hardMs": 310000, "observationMs": 315000, "outerInvocationMs": 325000}


def _expected_ios_account_report(case):
    """Closed synthetic refusal/recovery DATA, not successful signing evidence."""
    expected = _expected_ios_report("ios-toolchain-prerequisite")
    recovery, cancel = case == "ios-recovery-empty", case == "ios-signed-cancel"
    expected.update(protocol="mrk-ios-archive/3" if recovery else "mrk-ios-archive/2",
                    savedVersionObservation=None if recovery else _ios_version_observation(case),
                    prerequisiteOnly=False, workMs=120000, cleanupMs=240000, hardMs=250000)
    facts = expected["original"]["facts"]
    facts.update(workMs=120000, cleanupMs=240000, hardMs=250000, materialLoanPresent=False, materialLoanRetired=True)
    context = {"projectId": "inert-ios-parser", "platform": "ios", "operation": "ios-local-recovery",
               "recovery": {"action": "inspect"}} if recovery else {
        **expected["context"], "operation": "ios-signed-export", "savedConfig": expected["savedVersionObservation"]["savedConfig"],
        "signing": _signing_policy_from_inputs(_expected_signing_inputs(case))}
    expected["context"] = context
    lifetime = {**expected["original"]["terminal"]["lifetime"], "commandDispatched": not (recovery or cancel),
                "commands": 0 if recovery or cancel else 3, "profileCalls": 0 if recovery or cancel else 1,
                "stopObserved": "cancelled" if cancel else "none",
                "signingClosed": True, "buildInputsClosed": True, "materialRetired": True}
    if recovery:
        terminal = {"schemaVersion": 1, "context": context, "outcome": "complete", "reason": "none",
                    "activity": {"stage": "disposing-work"}, "lifetime": lifetime,
                    "report": {"schemaVersion": 1, "scope": "local-ios-recovery",
                               "account": {"status": "idle", "session": None, "next": "none"},
                               "project": {"status": "idle", "session": None, "next": "none"},
                               "limitations": ["local-recovery-only", "manual-recovery-not-supported",
                                               "user-confirmation-is-not-worker-finality", "no-store-operation"]}}
        expected["recoveryActions"] = {"idleRowsVisible": True, "ordinaryButtonsDisabled": True,
                                       "foreignMutationAttempted": False, "recoveryMutationClaimed": False}
    else:
        no = {"outcome": "not-dispatched", "exitCode": None}
        zero = {"outcome": "exited", "exitCode": 0}
        terminal = {"schemaVersion": 1, "context": context,
                    "outcome": "cancelled" if cancel else "failed", "reason": "cancelled" if cancel else "signing-validation-failed",
                    "activity": {"stage": "inputs-bound" if cancel else "validating-signing",
                                 "selection": {"containerKind": "project", "container": "ios/MRKObserved.xcodeproj",
                                               "scheme": "MRKObserved", "configuration": "Release",
                                               "bundleId": "org.example.mrk.observed", "symbolsPolicy": "retain",
                                               "preparationConfigured": False},
                                 "commands": {"xcode-version": dict(no if cancel else zero), "ios-sdk": dict(no if cancel else zero),
                                              "prepare": {"outcome": "not-configured", "exitCode": None},
                                              "archive": dict(no), "export": dict(no)},
                                 "findings": [] if cancel else [{"check": "profile-material", "status": "INVALID"}]},
                    "disposition": {"snapshot": "not-created", "work": "not-created" if cancel else "removed",
                                    "output": "not-created" if cancel else "retained-incomplete",
                                    "relativeDirectory": None if cancel else f".mobile-release/desktop-ios-archive/{facts['operationId']}"},
                    "result": None, "lifetime": lifetime}
        if cancel:
            expected["cancel"] = {"requestedOnce": True, "returned": True, "stageAtClick": "inputs-bound",
                                  "trigger": "original-inputs-bound", "boundary": {"stage": "inputs-bound",
                                      "operationId": facts["operationId"], "ownerGeneration": facts["ownerGeneration"], "originalTypedFrame": True},
                                  "activeCommandKillClaimed": False}
        else:
            held = {**facts, "observerJoined": False, "watchdogJoined": False, "retiredBeforeCutoff": False,
                    "activeRetained": True, "materialLoanPresent": True, "materialLoanRetired": False}
            expected["hold"] = {"original": {"facts": held, "terminal": terminal}, "publicSuccessHidden": True,
                                "conflictingUiBlocked": True, "environmentDiagnosticsBlocked": True, "originalReleasedOnce": True}
    expected["original"]["terminal"] = terminal
    return expected


def _expected_ios_pending_report():
    """Inert exact comparison DATA; never native observation/finality."""
    originals, prepared = [], []
    token = "e" * 32
    for i, action in enumerate(("inspect", "account")):
        base = _expected_ios_account_report("ios-recovery-empty")
        original = base["original"]
        operation, generation = ("a" if i == 0 else "c") * 32, ("b" if i == 0 else "d") * 32
        context = {"projectId": "inert-ios-parser", "platform": "ios", "operation": "ios-local-recovery",
                   "recovery": {"action": action, **({"session": token} if i else {})}}
        original["facts"].update(operationId=operation, ownerGeneration=generation)
        original["terminal"]["context"] = context
        original["terminal"]["report"]["account"] = {"status": "recovered" if i else "pending", "session": token,
                                                    "next": "none" if i else "ordinary"}
        if i:
            original["terminal"]["report"]["project"] = None
            original["terminal"]["lifetime"].update(commands=17, commandDispatched=True)
        prepared.append({"operationId": operation, "ownerGeneration": generation, "context": context,
                         "phase": "awaiting-consent", "intentUsable": True, "outcome": None, "reason": "none",
                         "stage": None, "activity": None, "report": None})
        originals.append(original)
    return {"protocol": "mrk-ios-archive/3", "scope": "native-account-recovery-original-pair-v1", "case": IOS_ACCOUNT_CASE,
            "prepared": prepared, "originals": originals, "requests": [1, 1, 1, 1], "replies": [1, 1, 1, 1],
            "statusCallsReturned": 0, "freshUncheckedReviews": True, "explicitAcknowledgements": True,
            "exactInspectedSession": True, "bothFinalResultsVisible": True, "projectRecoveryRequested": False,
            "archiveOrExportRequested": False, "workMs": 120000, "cleanupMs": 240000, "hardMs": 250000,
            "observationMs": 515000, "outerInvocationMs": 525000, "shippingBinaryQualified": False}


def _ios_pending_report(value):
    expected = _expected_ios_pending_report()
    try:
        need(type(value) is dict and type(value["originals"]) is list and len(value["originals"]) == 2
             and type(value["prepared"]) is list and len(value["prepared"]) == 2, "ios-account-original-pair")
        project = value["prepared"][0]["context"]["projectId"]
        token = value["originals"][0]["terminal"]["report"]["account"]["session"]
        need(type(project) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", project)
             and type(token) is str and re.fullmatch(r"[0-9a-f]{32}", token), "ios-account-session")
        ids, generations = [], []
        for i in range(2):
            operation, generation = value["prepared"][i]["operationId"], value["prepared"][i]["ownerGeneration"]
            need(all(type(v) is str and re.fullmatch(r"[0-9a-f]{32}", v) for v in (operation, generation)), "ios-account-original-id")
            ids.append(operation); generations.append(generation)
            expected["prepared"][i].update(operationId=operation, ownerGeneration=generation)
            expected["prepared"][i]["context"]["projectId"] = project
            expected["originals"][i]["facts"].update(operationId=operation, ownerGeneration=generation)
            expected["originals"][i]["terminal"]["report"]["account"]["session"] = token
            if i:
                expected["prepared"][i]["context"]["recovery"]["session"] = token
        need(ids[0] != ids[1] and generations[0] != generations[1], "ios-account-original-reused")
        calls = value["statusCallsReturned"]
        count = value["originals"][1]["terminal"]["lifetime"]["commands"]
        need(type(calls) is int and 0 <= calls <= 128 and type(count) is int and 1 <= count <= 32, "ios-account-command-count")
        expected["statusCallsReturned"] = calls
        expected["originals"][1]["terminal"]["lifetime"]["commands"] = count
    except (KeyError, TypeError, IndexError) as error:
        raise Refused("ios-account-pair-shape") from error
    _exact(value, expected, ("iosArchive",))
    return value


def _ios_account_private(value, uid, home):
    """Private bounded producer DATA; paths cannot select another account."""
    need(type(uid) is int and uid > 0 and type(home) is str and home.startswith("/")
         and type(value) is dict and set(value) == {"home", "homeIdentity", "leaseIdentity", "sessionIdentity", "nativeIdentity",
             "token", "baseline", "members", "controls", "native"} and value["home"] == home, "ios-account-private-shape")
    need(len(json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")) <= 12*1024,
         "ios-account-private-bound")
    need(type(value["token"]) is str and re.fullmatch(r"[0-9a-f]{32}", value["token"]), "ios-account-private-token")
    def identity(row, size):
        need(type(row) is list and len(row) == size and all(type(n) is int and 0 <= n < 2**64 for n in row)
             and row[0] > 0 and row[1] > 0, "ios-account-private-identity")
    for key in ("homeIdentity", "leaseIdentity", "sessionIdentity", "nativeIdentity"):
        row = value[key]; identity(row, 5)
        need(stat.S_ISDIR(row[2]) and row[3] == uid and row[2] & 0o7022 == 0
             and (key == "homeIdentity" or row[2] == stat.S_IFDIR | 0o700)
             and row[0] == value["homeIdentity"][0], "ios-account-private-directory")
    baseline, members = value["baseline"], value["members"]
    need(type(baseline) is dict and set(baseline) == {"default", "search"} and type(baseline["search"]) is list
         and 1 <= len(baseline["search"]) <= 8 and type(members) is list and len(members) == len(baseline["search"])
         and type(baseline["default"]) is str and baseline["default"] in baseline["search"], "ios-account-private-baseline")
    names, identities = set(), set()
    root = Path(home) / "Library/Keychains"
    for raw, row in zip(baseline["search"], members):
        need(type(raw) is str and "\x00" not in raw and "\\" not in raw and len(raw.encode("utf-8")) <= 512, "ios-account-private-path")
        path = Path(raw)
        need(path.is_absolute() and str(path) == raw and path.is_relative_to(root) and path != root
             and len(path.parts)-1 <= 8 and all(part not in (".", "..") and 0 < len(part.encode()) <= 255 for part in path.parts[1:])
             and raw not in names and type(row) is dict and set(row) == {"path", "identity"} and row["path"] == raw, "ios-account-private-path")
        identity(row["identity"], 6); original = row["identity"]
        need(stat.S_ISREG(original[2]) and original[3] == uid and original[5] == 1 and original[2] & 0o7022 == 0
             and original[0] == value["homeIdentity"][0] and tuple(original[:2]) not in identities, "ios-account-private-member")
        names.add(raw); identities.add(tuple(original[:2]))
    controls = value["controls"]
    need(type(controls) is dict and set(controls) == {"intent.json", "state.json"}, "ios-account-private-controls")
    for row in controls.values():
        need(type(row) is dict and set(row) == {"bytes", "sha256"} and type(row["bytes"]) is int and 0 < row["bytes"] <= 512*1024
             and type(row["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]), "ios-account-private-control")
    native = value["native"]
    need(type(native) is dict and "signing.keychain-db" in native and set(native) <= {"signing.keychain-db", IOS_ACCOUNT_LOCK_NAME},
         "ios-account-private-native")
    for row in native.values():
        need(type(row) is dict and set(row) == {"device", "inode"}
             and all(type(n) is int and 0 < n < 2**64 for n in row.values()) and row["device"] == value["homeIdentity"][0]
             and (row["device"], row["inode"]) not in identities, "ios-account-private-native-identity")
        identities.add((row["device"], row["inode"]))
    return value


def _ios_account_child_result(result, mode, uid=None, home=None):
    limit = 16*1024 if mode == "produce" else 2048
    need(mode in ("produce", "observe") and type(result) is subprocess.CompletedProcess
         and type(result.returncode) is int and result.returncode == 0 and result.stderr == b"" and type(result.stdout) is bytes
         and 0 < len(result.stdout) <= limit and result.stdout.endswith(b"\n") and b"\n" not in result.stdout[:-1], "ios-account-child-failed")
    try:
        value = json.loads(result.stdout, object_pairs_hook=_pairs, parse_constant=lambda _: (_ for _ in ()).throw(Refused("ios-account-json")))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Refused("ios-account-json") from error
    expected = {"schemaVersion": 1, "scope": "real-core-pending-account-fixture-v1" if mode == "produce" else "real-core-account-baseline-readback-v1",
                "case": IOS_ACCOUNT_CASE, "commands": 2, "profileCalls": 0, "commandFinalities": True,
                "leaseClosed": True, "sessionClosed": True, "handlersRestored": True, "fixtureDescriptorsClosed": True,
                "originalDeadlineMet": True, "keychainContentsRead": False}
    if mode == "produce":
        need(type(value) is dict and type(value.get("commands")) is int and 3 <= value["commands"] <= 64, "ios-account-producer-command-count")
        expected.update(commands=value["commands"], pendingLeft=True, private=_ios_account_private(value.get("private"), uid, home))
    else:
        expected.update(pendingAbsent=True, baselinePreferencesMatched=True, baselineMemberIdentitiesMatched=True)
    _exact(value, expected)
    return value


def _account_environment(state, uid, username):
    value = app_environment(state, uid, username)
    # The native core itself selects/verifies pwd's real account home. A fake
    # Aqua HOME must never redirect or conflict with account admission.
    del value["HOME"]
    return value


def _run_ios_account_child(fixtures, run_owned, uid, username, mode):
    import time
    need(fixtures.cases == (IOS_ACCOUNT_CASE,) and not fixtures.inflight and mode in ("produce", "observe")
         and (not fixtures.account_produced if mode == "produce" else fixtures.account_produced and fixtures.account_app_returned
              and not fixtures.account_readback), "ios-account-child-order")
    need(not fixtures.account_attempts[mode], "ios-account-child-reused")
    fixtures.account_attempts[mode] = True
    executable, core = fixtures.recovery_runtime_paths()
    if mode == "observe":
        fixtures._account_current(after=True)
    state = fixtures.path / "state" / IOS_ACCOUNT_CASE
    start = time.monotonic_ns()
    work = start + (150 if mode == "produce" else 60)*1_000_000_000
    final = work + 25*1_000_000_000
    argv = [executable, "-I", "-S", "-B", "-c", IOS_ACCOUNT_CORE_PROGRAM, core, mode, str(state), str(work), str(final),
            "-" if mode == "produce" else fixtures.account_private_sha]
    fixtures.precursor_diagnostic = None
    fixtures.case, fixtures.stage, fixtures.inflight, fixtures.last_returned = IOS_ACCOUNT_CASE, "account-" + mode, True, False
    limit = 16*1024 if mode == "produce" else 2048
    result = run_owned(argv, environ=_account_environment(state, uid, username), cwd=state,
                       timeout=180 if mode == "produce" else 90, capture=True, text=False, output_limit=limit)
    need(type(result) is subprocess.CompletedProcess and type(result.args) is list and result.args == argv
         and all(type(arg) is str for arg in result.args) and type(result.returncode) is int
         and type(result.stdout) is bytes and type(result.stderr) is bytes and len(result.stdout)+len(result.stderr) <= limit,
         "ios-account-child-return-contract")
    fixtures.inflight, fixtures.last_returned = False, True
    need(time.monotonic_ns() < final, "ios-account-child-finality-late")
    try:
        value = _ios_account_child_result(result, mode, uid, fixtures.account_home)
    except BaseException:
        try:
            fixtures.precursor_diagnostic = _precursor_diagnostic(result, "ios-account-" + mode)
        except BaseException:
            pass  # Retain the original refusal and all unchanged time/adoption gates.
        raise
    if mode == "produce":
        fixtures.accept_account_producer(value)
    else:
        fixtures._account_current(after=True)
        fixtures.account_readback = True
        fixtures.account_readback_attestation = value
    need(time.monotonic_ns() < final, "ios-account-child-finality-late")
    return value


def _ios_account_facts(value, expected, case, operation, generation):
    """Admit actual bounded varying counters; never accept unknown finality."""
    terminal, out = value["original"]["terminal"], expected["original"]["terminal"]
    lifetime = terminal["lifetime"]
    recovery, cancel = case == "ios-recovery-empty", case == "ios-signed-cancel"
    count, profiles, dispatched = lifetime["commands"], lifetime["profileCalls"], lifetime["commandDispatched"]
    need(type(count) is int and 0 <= count <= (32 if recovery else 4096)
         and type(profiles) is int and 0 <= profiles <= (0 if recovery else 1024)
         and type(dispatched) is bool and (count > 0 if dispatched else count <= 1), "ios-account-command-accounting")
    if recovery:
        out["lifetime"].update(commands=count, profileCalls=profiles, commandDispatched=dispatched)
        return
    policy = value["context"]["signing"]
    need(type(policy) is dict and type(policy.get("assignments")) is list and len(policy["assignments"]) == 2,
         "ios-signing-policy")
    ids = [row["recordId"] for row in policy["assignments"]]
    need(all(type(v) is str and re.fullmatch(r"[0-9a-f]{32}", v) for v in ids) and len(set(ids)) == 2, "ios-signing-records")
    for row, record_id in zip(expected["context"]["signing"]["assignments"], ids):
        row["recordId"] = record_id
    if cancel:
        stages = ("inputs-bound", "checking-xcode", "validating-signing")
        stage = terminal["activity"]["stage"]
        need(stage in stages, "ios-signed-cancel-stage")
        out["activity"]["stage"] = stage
        clicked = value["cancel"]["stageAtClick"]
        need(clicked in stages and stages.index(clicked) <= stages.index(stage), "ios-signed-cancel-click")
        expected["cancel"]["stageAtClick"] = clicked
        expected["cancel"]["boundary"].update(operationId=operation, ownerGeneration=generation)
        for role in ("xcode-version", "ios-sdk"):
            command = terminal["activity"]["commands"][role]
            need(type(command) is dict and set(command) == {"outcome", "exitCode"}
                 and ((command["outcome"] in ("not-dispatched", "unknown") and command["exitCode"] is None)
                      or (command["outcome"] == "exited" and type(command["exitCode"]) is int and 0 <= command["exitCode"] <= 255)),
                 "ios-signed-cancel-command")
            out["activity"]["commands"][role] = dict(command)
        output, work = terminal["disposition"]["output"], terminal["disposition"]["work"]
        need(output in ("not-created", "retained-incomplete") and work in ("not-created", "removed")
             and (output != "not-created" or work == "not-created"), "ios-signed-cancel-output")
        out["disposition"].update(output=output, work=work,
            relativeDirectory=None if output == "not-created" else f".mobile-release/desktop-ios-archive/{operation}")
        # If cancellation raced with the material checker, retain its exact
        # known-invalid synthetic-profile finding, never an artifact check.
        findings = terminal["activity"]["findings"]
        need(findings in ([], [{"check": "profile-material", "status": "INVALID"}]), "ios-signed-cancel-findings")
        no = {"outcome": "not-dispatched", "exitCode": None}
        zero = {"outcome": "exited", "exitCode": 0}
        xcode, sdk = (out["activity"]["commands"][role] for role in ("xcode-version", "ios-sdk"))
        # Actual stage progression supplies prerequisites, not exact lifetime
        # command totals. A clicked UI stage may lag, but never lead, terminal.
        need(sdk == no or xcode == zero, "ios-signed-cancel-role-order")
        if stage == "inputs-bound":
            need(xcode == sdk == no, "ios-signed-cancel-before-xcode")
        if stage != "validating-signing":
            need(profiles == 0 and not findings, "ios-signed-cancel-before-validation")
        else:
            need(xcode == sdk == zero, "ios-signed-cancel-xcode-prerequisite")
        need(not findings or profiles >= 1, "ios-signed-cancel-profile-accounting")
        out["activity"]["findings"] = findings
    else:
        need(dispatched and count >= 2 and profiles >= 1, "ios-signing-validation-accounting")
    commands = out["activity"]["commands"].values()
    need(sum(command["outcome"] == "exited" for command in commands) <= count
         and (dispatched or all(command["outcome"] in ("not-dispatched", "not-configured") for command in commands)),
         "ios-signed-command-dispatch")
    out["lifetime"].update(commands=count, profileCalls=profiles, commandDispatched=dispatched)


def _ios_report(value, case):
    """Closed independent DATA parser. Only bounded actual varying facts vary."""
    if case == IOS_ACCOUNT_CASE:
        return _ios_pending_report(value)
    need(type(value) is dict and case in IOS_OPERATION_CASES, "ios-report")
    expected = _expected_ios_report(case)
    try:
        facts, context, terminal = value["original"]["facts"], value["context"], value["original"]["terminal"]
        operation, generation = facts["operationId"], facts["ownerGeneration"]
        need(all(type(v) is str and re.fullmatch(r"[0-9a-f]{32}", v) for v in (operation, generation)), "ios-original-identity")
        need(type(context["projectId"]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", context["projectId"]), "ios-project-identity")
        for name in (() if case == "ios-recovery-empty" else ("draftRevision", "baselineGeneration")):
            need(type(context[name]) is int and 0 <= context[name] < 2**32 - 1, "ios-context-generation")
            expected["context"][name] = context[name]
        expected["context"]["projectId"] = context["projectId"]
        for snapshot in (expected["original"], *([expected["hold"]["original"]] if expected["hold"] else [])):
            snapshot["facts"].update(operationId=operation, ownerGeneration=generation)
        need(type(value["statusCallsReturned"]) is int and 0 <= value["statusCallsReturned"] <= 64, "ios-status-calls")
        expected["statusCallsReturned"] = value["statusCallsReturned"]
        out = expected["original"]["terminal"]
        if case != "ios-recovery-empty" and out["disposition"]["relativeDirectory"] is not None:
            out["disposition"]["relativeDirectory"] = f".mobile-release/desktop-ios-archive/{operation}"
        if case in ("ios-unsigned-archive", "ios-finality"):
            result = terminal["result"]
            need(type(result["entries"]) is int and 1 <= result["entries"] <= 1024
                 and type(result["bytes"]) is int and 1 <= result["bytes"] <= 128 * 1024 * 1024, "ios-fixture-archive-budget")
            out["result"].update(archive=f".mobile-release/desktop-ios-archive/{operation}/archive.xcarchive",
                                  entries=result["entries"], bytes=result["bytes"])
        if case == "ios-cancel":
            prepare = terminal["activity"]["commands"]["prepare"]
            # Preparing may precede dispatch. A stopped original may also settle
            # without a usable exit result: command-result Unknown is NOT native
            # lifetime/custody Unknown. All exact original finality gates remain.
            need(type(prepare) is dict and set(prepare) == {"outcome", "exitCode"}
                 and ((prepare["outcome"] in ("not-dispatched", "unknown") and prepare["exitCode"] is None)
                      or (prepare["outcome"] == "exited" and type(prepare["exitCode"]) is int
                          and 0 <= prepare["exitCode"] <= 255)), "ios-cancel-prepare")
            count = terminal["lifetime"]["commands"]
            need(type(count) is int and count in ((2, 3) if prepare["outcome"] == "not-dispatched" else (3,)), "ios-cancel-command-count")
            out["activity"]["commands"]["prepare"] = dict(prepare)
            out["lifetime"]["commands"] = count
            expected["cancel"]["prepareOutcome"] = dict(prepare)
        if case in IOS_SIGNED_CASES or case == "ios-recovery-empty":
            _ios_account_facts(value, expected, case, operation, generation)
        _exact(value, expected, ("iosArchive",))
    except (KeyError, TypeError, AttributeError) as error:
        raise Refused("ios-report-shape") from error
    return value


def _expected_project_fields():
    """Closed comparison DATA, never the producer of a qualification receipt."""
    rows = []
    for i, (field, kind, relative, error) in enumerate(PROJECT_FIELD_CHOICES):
        accepted = i not in (4, 5)
        facts = 511 | 4096 | ((512 | 1024) if accepted else 0)
        rows.append({"operationId": i + 2, "field": field, "kind": kind,
            "nativeResponse": "accept" if accepted else "decline",
            "initialRootAndOptions": {"result": "ok", "facts": facts,
                "fileFilter": {"facts": 23, "allowedTypes": "unrestricted", "allowsOther": False} if kind == "version-source" else None},
            "nameFieldPreparation": {"returned": True, "result": "ok", "facts": 31} if accepted and kind == "version-source" else None,
            "laterSyntheticNavigation": accepted, "exactNativeSelection": True if accepted else None,
            "sourceBookStarted": accepted and i != 6, "originalSourceChildGuiAndCoordinatorSettled": True,
            "relativePath": relative, "errorCode": error, "draftObserved": True})
    return {"schemaVersion": 2, "oneUseOriginalDocumentRegistration": True, "normalProfileAvailable": True,
        "selection": "original-bound-installed-macos-project-fields", "rows": rows, "originalOperations": 12,
        "allOriginalsSettled": True, "completeDraftAndBaselineMatched": True,
        "previewValidation": "invalid-retained-ios-fields", "fixtureMutationsRestored": True,
        "shippingProfileEnabledByThisReceipt": False, "panelAttachments": [True] * 10, "controlReturns": [True] * 10,
        "acceptedOpenHistories": [{"operationId": identifier,
            "kind": "project" if identifier == 1 else PROJECT_FIELD_CHOICES[identifier - 2][1],
            "originalInputSucceeded": True, "originalBarrierRetired": True,
            "originalBindingMatched": True, "originalCompletionMatched": True}
            for identifier in (1, 2, 3, 4, 5, 8, 9, 10, 11)]}


def _expected_vault_original(kind, *, negative=False):
    """Literal parser-test DATA only; never native evidence or an omitted receipt default."""
    before = kind == "before-go"
    added = kind in ("initialize", "after-add") and not negative
    lookup = kind == "lookup"
    consumed = kind in ("initialize", "lookup") and not negative
    failed = before or kind == "after-add" or negative
    return {"go": not before, "requestSent": not before, "writeAttempted": not before,
        "stopAttempted": False, "stopSent": False, "notice": negative, "terminal": not before,
        "successfulAddTerminal": added, "terminalSuccess": not (before or negative),
        "outputFailed": False, "stderrSeen": False,
        "authSettled": None if before else True, "filesystemSettled": None if before else True,
        "nativeInputClosed": None if before else True,
        "addOutcome": None if before or lookup else "locked" if negative else "added",
        "addSettled": None if before or lookup else True,
        "lookupSettled": None if before or negative else True, "addEffect": int(added),
        "addItemCallsAbsent": None if before or lookup else negative,
        "addPrerequisiteRefused": None if before or lookup else negative,
        "nativeCandidateConsumed": None if before or negative else True,
        "tryWaitEntered": True, "tryWaitReturned": True, "waitEntered": False,
        "exitObserved": True, "exitSuccess": not (before or negative),
        "waitFailed": False, "killAttempted": False, "killFailed": False,
        "stdoutEof": True, "stderrEof": True, "pipeClosed": [True, True, True], "helperSlotsSettled": True,
        "helperGateAcquired": True, "helperGateSpawnEntered": True, "helperGatePostchecked": True,
        "helperGateClosed": True, "helperGateUnknown": False,
        "driverReturned": True, "driverBeforeCleanup": True, "blockingChildJoined": True,
        "resourcesSettled": True, "allocationsReleased": True,
        "firstFailure": "locked" if negative else "interrupted" if failed else None,
        "cleanupContracted": failed, "cleanupUnknown": False,
        "applicationCandidateConstructed": consumed, "applicationCandidateTaken": consumed,
        "applicationCallbackReturned": consumed}


def _expected_vault_helper(case, *, negative=False):
    """Finite DATA fixture. parse_result requires and checks the actual native member first."""
    need(case in VAULT_HELPER_CASES and type(negative) is bool
         and not (negative and case == VAULT_HELPER_CASES[1]), "vault-helper-case")
    roundtrip = case == VAULT_HELPER_CASES[0] and not negative
    kind = "before-go" if case == VAULT_HELPER_CASES[1] else "after-add" if case == VAULT_HELPER_CASES[2] else "initialize"
    # Exact enabled candidate source. The mechanism is still the selected
    # helper journey, not ordinary persistent-credential UI acceptance.
    return {"mechanism": "original-document-shipping-helper-v1", "normalPersistenceEnabled": True,
        "execution": "not-executed-provider-prerequisite" if negative else "executed",
        "testResult": "not-executed" if negative else "positive" if roundtrip else "expected-stop",
        "checkpoint": ("none", "before-helper-go", "successful-add-terminal-before-application-candidate")[VAULT_HELPER_CASES.index(case)],
        "checkpointObserved": not negative and not roundtrip,
        "nativeLookupMayAlreadyHaveConsumed": case == VAULT_HELPER_CASES[2],
        "openedEmpty": True, "previewConsumedOnce": True, "initialized": roundtrip, "locked": True,
        "reopened": roundtrip, "unlocked": roundtrip, "relocked": roundtrip,
        "initializeHelper": _expected_vault_original(kind, negative=negative),
        "lookupHelper": _expected_vault_original("lookup") if roundtrip else None,
        "storage": {"reservation": [True, True], "header": [roundtrip, roundtrip], "durability": [True, roundtrip]},
        "originalCount": 7 if roundtrip else 5, "allOriginalsSettled": True, "finalDocumentEmpty": True,
        "syntheticKeychainRowRetirement": "disposable-hosted-account-only", "physicalMacEvidence": False}


def _vault_helper_original(value, kind, *, negative=False):
    label = "vault-helper-original"
    need(type(value) is dict, label)
    expected = _expected_vault_original(kind, negative=negative)
    # Original same-slot STOP is mandatory for the two checkpoint cases. A
    # transport STOP is neither invented nor needed once the decoded terminal
    # has positively retired the helper's input; preserve actual observations.
    for field in ("stopAttempted", "stopSent"):
        need(type(value.get(field)) is bool, label)
    need(value["stopSent"] == value["stopAttempted"] and
         (not value["stopAttempted"] or kind == "after-add" or negative), label)
    expected.update(stopAttempted=value["stopAttempted"], stopSent=value["stopSent"])
    if negative:
        need(type(value.get("notice")) is bool, label)
        need(type(value.get("addOutcome")) is str and value["addOutcome"] in (
            "missing", "locked", "interaction-required", "authentication-failed", "unavailable", "unsupported", "native-failure"), label)
        need(type(value.get("firstFailure")) is str and value["firstFailure"] in (
            "missing-key", "locked", "denied", "unsupported-provider", "unavailable"), label)
        expected.update(notice=value["notice"], addOutcome=value["addOutcome"], firstFailure=value["firstFailure"])
    _exact(value, expected)
    return value


def _vault_helper_report(value, case):
    label = "vault-helper-report"
    need(case in VAULT_HELPER_CASES and type(value) is dict, label)
    execution = value.get("execution")
    need(type(execution) is str and execution in ("executed", "not-executed-provider-prerequisite"), label)
    negative = execution != "executed"
    expected = _expected_vault_helper(case, negative=negative)
    kind = "before-go" if case == VAULT_HELPER_CASES[1] else "after-add" if case == VAULT_HELPER_CASES[2] else "initialize"
    expected["initializeHelper"] = _vault_helper_original(value.get("initializeHelper"), kind, negative=negative)
    if case == VAULT_HELPER_CASES[0] and not negative:
        expected["lookupHelper"] = _vault_helper_original(value.get("lookupHelper"), "lookup")
    _exact(value, expected)
    return value


def vault_fixture_path(binding, home, case):
    """Closed path DATA. The native owner alone supplies getpwuid's real home."""
    binding.checked()
    need(type(home) is str and 1 < len(home.encode("utf-8")) <= 2048
         and home.startswith("/") and "\x00" not in home and "\\" not in home
         and all(part and part not in (".", "..") for part in home.split("/")[1:])
         and len(home.split("/")) <= 64 and case in VAULT_HELPER_CASES, "vault-native-home")
    return (Path(home) / "Library" / "Application Support" /
            f"mrk-macos-aqua-vault-{binding.source}-{binding.run}-{binding.attempt}" / case / "dev.mobile-release-kit.desktop")


def _expected_installation_report():
    # Literal parser-test DATA only, never an observed read or a missing-receipt
    # replacement. _installation_report requires every actual field separately.
    def row(identifier, revision, final_revision, cancelled):
        start = {"schemaVersion": 1, "statusRevision": revision, "available": True, "canStart": False,
                 "operationId": identifier, "phase": "checking", "reason": "none", "settlement": "pending", "assessment": None}
        status = {**start, "statusRevision": final_revision, "canStart": True,
                  "phase": "refused" if cancelled else "observed", "reason": "cancelled" if cancelled else "none",
                  "settlement": "known", "assessment": None if cancelled else {
                      "files": 3, "bytes": 19, "assurance": "read-only-correspondence", "maintenance": "unavailable"}}
        return {"start": start, "firstRead": {"verifiedFiles": 1, "verifiedBytes": 7},
                "cancelRequestedOnce": cancelled, "cancelReturned": cancelled, "status": status,
                "originals": {"normalCoordinatorJoined": True, "normalChildJoined": True, "nativeSettled": True,
                              "storageDisposed": True, "resourcesSettled": True, "stopped": cancelled}}
    return {"mechanism": "original-document-ordinary-installation-v1", "recordKind": "ordinary",
            "projectSelected": False, "firstReadCancellationBoundary": "completed-file-read-before-exact-original-stop",
            "cancelled": row(1, 1, 3, True), "matching": row(2, 4, 5, False),
            "normalQuit": {"operationId": 3, "inspectionId": 2, "noProjectFinality": True},
            "limits": {"readOnly": True, "maintenance": "unavailable", "network": "not-part-of-this-operation",
                       "credentials": "not-part-of-this-operation"}}


def _installation_report(value):
    """Closed actual returned facts; no expected file/byte/revision fallback."""
    label = "installation-inspection-report"
    expected = _expected_installation_report()
    need(type(value) is dict and set(value) == set(expected), label)
    revisions = []
    for name in ("cancelled", "matching"):
        actual, target = value[name], expected[name]
        need(type(actual) is dict and set(actual) == set(target), label)
        first = actual["firstRead"]
        need(type(first) is dict and set(first) == {"verifiedFiles", "verifiedBytes"}, label)
        need(type(first["verifiedFiles"]) is int and 1 <= first["verifiedFiles"] <= 2048
             and type(first["verifiedBytes"]) is int and 1 <= first["verifiedBytes"] <= 512 * 1024 * 1024, label)
        target["firstRead"] = first
        for kind in ("start", "status"):
            status = actual[kind]
            need(type(status) is dict and set(status) == set(target[kind]), label)
            revision = status["statusRevision"]
            need(type(revision) is int and 0 < revision < 2**32 - 1, label)
            revisions.append(revision)
            target[kind]["statusRevision"] = revision
        if name == "matching":
            assessment = actual["status"]["assessment"]
            need(type(assessment) is dict and set(assessment) == {"files", "bytes", "assurance", "maintenance"}, label)
            need(type(assessment["files"]) is int and 1 <= assessment["files"] <= 2048
                 and type(assessment["bytes"]) is int and 1 <= assessment["bytes"] <= 512 * 1024 * 1024
                 and first["verifiedFiles"] <= assessment["files"] and first["verifiedBytes"] <= assessment["bytes"], label)
            target["status"]["assessment"].update(files=assessment["files"], bytes=assessment["bytes"])
    need(all(left < right for left, right in zip(revisions, revisions[1:])), label)
    _exact(value, expected, ("installationInspection",))
    return value


def expected_result(binding, case):
    binding.checked()
    need(case in ALL_CASES, "case-binding")
    if case == INSTALLATION_INSPECTION_CASE:
        value = expected_result(binding, "picker-loss")
        value.update(case=case, installationInspection=_expected_installation_report())
        value["native"]["panelAttachments"] = [False, True, False, False]
        value["reload"] = dict.fromkeys(value["reload"], False)
        return value
    if case in IOS_CURRENT_CASES or case in (PROJECT_FIELDS_CASE, ANDROID_INPUT_CASE, RECOVERY_CASE, IOS_ACCOUNT_CASE) or case in VAULT_HELPER_CASES or case in LOCAL_EDIT_CASES or case in LOCAL_CHECK_CASES:
        value = expected_result(binding, "noop-stale")
        value.update(case=case, saveSessions=[], staleMarkerWriterReturnedAndClosed=False)
        if case in LOCAL_CHECK_CASES:
            value["localChecks"] = _local_checks_base(case)  # Shape DATA only; actual report required below.
        if case in LOCAL_EDIT_CASES:
            value["localEdits"] = _expected_local_edits(case)
        if case in IOS_OPERATION_CASES:
            value["iosArchive"] = _expected_ios_report(case)
        if case in SESSION_CASES:
            value["signingInputs"] = _expected_signing_inputs(case)
        if case == RECOVERY_CASE:
            value["projectRecovery"] = _expected_recovery_report()
        if case == PROJECT_FIELDS_CASE:
            value["projectFields"] = _expected_project_fields()
        if case in VAULT_HELPER_CASES:
            value["vaultHelper"] = _expected_vault_helper(case)
        value["native"]["projectOpenBinding"]["case"] = case
        value["native"]["projectCompletionSelection"]["case"] = case
        if case == PROJECT_FIELDS_CASE:
            # Comparison/test DATA only. Actual success parsing below requires
            # each original returned report; these defaults never fill a gap.
            for row in value["projectFields"]["acceptedOpenHistories"]:
                if row["kind"] != "version-source":
                    continue
                identifier = row["operationId"]
                parent = {**_expected_identity_proof(), "purpose": "selection-parent"}
                row["selectionInput"] = {**value["native"]["projectOpenInput"],
                    "mechanism": "accessibility-version-source-selection-press-v8",
                    "id": identifier, "step": _field_open_step(case, identifier),
                    "initialOriginalProof": _expected_identity_proof(), "originalProof": _expected_identity_proof(),
                    "promptChecks": {"initial": True, "final": True}, "promptButton": _expected_prompt_button(),
                    "selectionParentProof": parent, "selectionParentPrompt": True,
                    "selection": {"checks": dict.fromkeys(ACCESSIBILITY_SELECTION_CHECKS, True),
                        "attempted": True, "returned": True, "selected": True, "nodes": 12, "matches": 1,
                        "attribute": "SelectedRows", "lastRole": "StaticText", "depth": 4, "limit": None,
                        "contentReadiness": {"sample": 1, "callsBefore": 0, "cfBefore": 0, "wait": 0, "pending": []},
                        "projectionDiagnostic": None,
                        "projectionSummary": {"tableRoles": 1, "outlineRoles": 0, "listRoles": 0, "entryRoots": 2,
                            "titlePresent": 0, "titleAbsent": 2, "valuePresent": 2, "outsideEntryRoleMask": 0,
                            "fixtureLabelMask": 1, "expectedLabelRelations": 1, "expectedLabelRoleMask": 1 << 15}}}
                row["selectionInput"]["promptButton"].update(calls=221, cfSlots=120, cfSlotsRetired=120)
                row["selectionBinding"] = {**value["native"]["projectOpenBinding"],
                    "mechanism": "selection-parent-original-sheet-v3", "id": identifier, "kind": "version-source",
                    "configuration": dict(value["native"]["projectOpenBinding"]["configuration"]),
                    "binding": {**_expected_identity_proof(), "purpose": "selection-parent"}}
                row["selectionCompletion"] = {**_expected_completion_selection(case), "id": identifier, "kind": "version-source"}
        return value
    first, stale, lost = case == "first-save", case == "noop-stale", case in ("picker-loss", "save-loss")
    initial_ignore, saved_ignore = len(IGNORE_PREFIX), len(IGNORE_PREFIX + IGNORE_RULES)
    plans = {
        "create": [("release/mobile-release.json", "create", None, 684), (".gitignore", "append", initial_ignore, saved_ignore)],
        "preserve": [("release/mobile-release.json", "preserve", 684, 684), (".gitignore", "preserve", saved_ignore, saved_ignore)],
        "replace": [("release/mobile-release.json", "replace", 684, 690), (".gitignore", "preserve", saved_ignore, saved_ignore)],
    }
    rows = {
        "first-save": [(1, 1, "create", 2, True, "committed", "clean", "none", "none"),
                       (1, 2, "preserve", 0, False, "not_started", "not_created", "cancelled", "shutdown")],
        "noop-stale": [(1, 1, "preserve", 1, True, "unchanged", "not_created", "none", "none"),
                       (2, 1, "replace", 1, True, "not_started", "not_created", "stale_revision", "none")],
        "picker-loss": [],
        "save-loss": [(1, 1, "create", 0, False, "not_started", "not_created", "cancelled", "window_lost")],
    }
    sessions = []
    for draft, baseline, plan, confirmations, applied, effect, journal, reason, native in rows[case]:
        sessions.append({"draftRevision": draft, "baselineGeneration": baseline,
            "files": [dict(zip(("path", "action", "beforeBytes", "afterBytes"), row)) for row in plans[plan]],
            "createReleaseDirectory": plan == "create", "reviewMatched": True, "confirmationsOpened": confirmations,
            "acknowledged": applied, "apply": applied,
            "outcome": {"effect": effect, "journal": journal, "resources": "settled", "reason": reason},
            "nativeReason": native, "nativeFinality": "settled", "writerFrames": 3 if applied else 2,
            "stdoutFrames": 3, "originalsJoined": True})
    return {"schemaVersion": 1, **binding.public(), "case": case, "instrumentedEngineeringApp": True,
        "shippingBinaryQualified": False, "distributionQualified": False, "methods": "fourteen-passive-with-session-assessment", "actionsAvailable": False,
        "native": {"projectCancelSettled": first, "selectedPathMatched": case != "picker-loss",
            "originalWindow": {"mechanism": "passive-original-window-callback-v1", "accessorReturned": True,
                "nativeReturned": True, "result": "ok", "admitted": True,
                "state": {"applicationPresent": True, "active": True, "mainPresent": True,
                    "originalMain": True, "ordinaryWindow": True, "noAttachedSheet": True}},
            "panelAttachments": [True, True, first, first],
            "controlReturns": [first, case != "picker-loss", first, True],
            "accessibilityTrustedWithoutPrompt": True,
            "projectOpenInput": None if case == "picker-loss" else {
                "mechanism": "accessibility-preconfigured-original-press-v5", "step": "OpenProject", "id": 2 if first else 1,
                "prepared": True, "requested": True, "dispatchAttempted": True, "state": "retired",
                "bodyEntered": True, "nativeEntered": True, "bodyReturned": True, "receiptJoined": True,
                "workerRegistered": True, "workerJoined": True, "rechecksSettled": True,
                "barrierRetired": True, "expired": False, "timely": True, "custodyKnown": True,
                "attempted": True, "pressReturned": True, "triggered": True,
                "initialOriginalProof": _expected_identity_proof(), "originalProof": _expected_identity_proof(),
                "promptChecks": {"initial": True, "final": True},
                "promptButton": _expected_prompt_button(), "site": "press", "error": "none"},
            "projectOpenBinding": None if case == "picker-loss" else {
                "mechanism": "preconfigured-original-sheet-v2", "case": case, "id": 2 if first else 1, "kind": "project",
                "start": {"returned": True, "result": "ok"},
                "configuration": {"attempted": True, "parentSetterEntered": True, "parentSetterReturned": True,
                    "promptSetterEntered": True, "promptSetterReturned": True,
                    "initialDirectorySetterEntered": True, "initialDirectorySetterReturned": True,
                    "parent": "match", "prompt": "match", "site": "complete", "error": "none"},
                "binding": _expected_identity_proof()},
            "projectCompletionSelection": None if case == "picker-loss" else _expected_completion_selection(case),
            "quitCancelKeptOriginalReview": first, "originalDocumentAndQuitSettled": True},
        "saveSessions": sessions, "freshCoreReadback": first, "syntheticFileReadback": True,
        "staleMarkerWriterReturnedAndClosed": stale,
        "reload": {"requested": lost, "dispatchReturned": lost, "navigationDenied": lost, "secondStarted": False,
            "originalLossSettled": lost, "webProcessCrashTested": False},
        "originalRelayJoined": True, "actualExit": True, "scope": SCOPE}


def _pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, "duplicate-result-key")
        result[key] = value
    return result


# Public schema vocabulary only. Unknown future keys lose diagnostic detail,
# never validation. Neither report values nor unexpected keys enter this set.
RESULT_LOCATION_KEYS = frozenset((
    "accessibility accessibilityTrustedWithoutPrompt accessorReturned acknowledged action actionsAvailable active actualExit admitted "
    "afterBytes applicationPresent apply attempted axError axFailure barrierRetired baselineGeneration beforeBytes binding "
    "bodyEntered bodyReturned callbackEntered callbackReturned calls case cfSlots cfSlotsRetired checks children "
    "cleanupReturned configuration confirmationsOpened controlReturns createReleaseDirectory custodyKnown "
    "dispatchAttempted dispatchReturned distributionQualified draftRevision duplicate effect error expired facts files "
    "final freshCoreReadback id initial initialDirectorySetterEntered initialDirectorySetterReturned initialNodesExamined "
    "initialOriginalProof instrumentedEngineeringApp journal kind lastDepth lastRole mainPresent mechanism methods "
    "native nativeEntered nativeFinality nativeReason nativeReturned nativeUnknown navigationDenied noAttachedSheet "
    "ordinaryWindow originalDocumentAndQuitSettled originalLossSettled originalMain originalProof originalRelayJoined "
    "originalWindow originals originalsJoined outcome panel panelAttachments parent parentSetterEntered parentSetterReturned "
    "path pollResult pollReturned prepared pressReturned pressDiagnostic acknowledgment installedAllowanceNs lastPermitToReturnAdmissionNs "
    "projectCancelSettled projectCompletionSelection projectOpenBinding "
    "projectOpenInput prompt promptButton promptChecks promptSetterEntered promptSetterReturned quitCancelKeptOriginalReview "
    "reason receiptJoined recheckNodesExamined rechecksSettled reload requested resources response result returned reviewMatched "
    "runAttempt runId saveSessions schemaVersion scope secondStarted selectedPathMatched selection shippingBinaryQualified "
    "site sourceCommit staleMarkerWriterReturnedAndClosed start state stdoutFrames step syntheticFileReadback timely triggered "
    "urlsReadEntered urlsReadReturned webProcessCrashTested workerJoined workerRegistered writerFrames"
).split()) | frozenset(ACCESSIBILITY_PROOF_CHECKS) | frozenset(ACCESSIBILITY_BUTTON_CHECKS)
RESULT_LOCATION_KEYS |= frozenset((
    "iosArchive protocol savedVersionObservation context prepareRequestedOnce prepareReturned reviewVisible "
    "startRequestedOnce startReturned statusCallsReturned staleVersionWriterReturnedAndClosed original terminal "
    "finalResultVisible prerequisiteOnly cancel requestedOnce stageAtClick prepareOutcome activeCommandKillClaimed "
    "hold publicSuccessHidden conflictingUiBlocked environmentDiagnosticsBlocked originalReleasedOnce "
    "workMs hardMs observationMs outerInvocationMs operationId ownerGeneration inspectionJoined acquisitionJoined "
    "childWaitedSuccess stdinClosed stdoutEofClosed stderrEofClosed ioJoined coreLifetimeSettled runtimeLedgerSettled "
    "toolsLedgerSettled nativeSettlementJoined nativeIntegrity driverJoined managerJoined observerJoined watchdogJoined "
    "retiredBeforeCutoff activeRetained resourceUnknown source version name build observationScope assurance basis "
    "projectCodeExecuted toolsProbed credentialsRead gitObserved storeContacted writesPerformed releaseReadiness "
    "savedConfig savedVersion bytes sha256 projectId platform operation activity commands xcode-version ios-sdk "
    "prepare archive exitCode containerKind container scheme bundleId symbolsPolicy preparationConfigured findings "
    "check status disposition snapshot work output relativeDirectory usedConfig usedVersion entries limitations "
    "lifetime complete fatal contained commandDispatched profileCalls stopObserved inputClosed handlersRestored "
    "invocationClosed snapshotClosed filesClosed namespaceClosed requests replies freshUncheckedReviews explicitAcknowledgements "
    "exactInspectedSession bothFinalResultsVisible projectRecoveryRequested archiveOrExportRequested"
).split())
RESULT_LOCATION_KEYS |= frozenset((
    "projectFields normalProfileAvailable field initialRootAndOptions nameFieldPreparation laterSyntheticNavigation "
    "sourceBookStarted originalSourceChildGuiAndCoordinatorSettled relativePath errorCode draftObserved "
    "completeDraftAndBaselineMatched previewValidation fixtureMutationsRestored shippingProfileEnabledByThisReceipt "
    "acceptedOpenHistories originalInputSucceeded originalBarrierRetired originalBindingMatched originalCompletionMatched "
    "selectionInput selectionBinding selectionCompletion selectionParentProof selectionParentPrompt purpose "
    "completeProjection uniqueEntry originalLabelChainRechecked attributeSettable singletonOriginalEntryReadback "
    "nodes matches attribute depth selected contentReadiness sample callsBefore cfBefore wait pending "
    "fileFilter allowedTypes allowsOther"
).split())
RESULT_LOCATION_KEYS |= frozenset((
    "signingInputs oneUseOriginalDocumentRegistration mode rows role nativeResponse exactNativeSelection "
    "originalWorkerAndNativeSettled openIdentityMatched openInputJoined assessment identity fieldScopes "
    "recordId keptRevision assignedContextRevision originalOperations allOriginalsSettled memorySessionLocked "
    "originalProjectAndQuitSettled signing teamId distributionCertificateSha256 assignments recordRevision "
    "contextRevision purpose cleanupMs materialLoanPresent materialLoanRetired trigger boundary originalTypedFrame "
    "signingClosed buildInputsClosed materialRetired export recovery recoveryActions idleRowsVisible "
    "ordinaryButtonsDisabled foreignMutationAttempted recoveryMutationClaimed report account project session next "
    "contextTransition previous current previousRevision currentRevision preservedRecords assignmentsUnavailable "
    "oldPreviewRetired oldSelectionRetired originalsSettled fieldOutcomes issues"
).split())


RESULT_LOCATION_KEYS |= frozenset((
    "installationInspection recordKind projectSelected firstReadCancellationBoundary cancelled matching normalQuit "
    "inspectionId noProjectFinality limits readOnly maintenance network credentials firstRead verifiedFiles verifiedBytes "
    "cancelRequestedOnce cancelReturned statusRevision available canStart phase settlement normalCoordinatorJoined "
    "normalChildJoined nativeSettled storageDisposed resourcesSettled stopped"
).split())


RESULT_LOCATION_KEYS |= frozenset(("projectRecovery ordinaryProfileAvailableBeforeAdmission prepared projection noChild runtimeSettlementJoined coreTerminal coreFatal reviewMinted intentUsable action review observation recoveredSession roles quiescence requests replies freshUncheckedReview explicitAcknowledgement exactSessionReviewed commandDispatches signedModesActivated").split())

RESULT_LOCATION_KEYS |= frozenset((
    "localEdits domain sameOriginalSessions originalFinalities visibleReviewAndResult passiveReadbacks fixture directories "
    "completedOriginals staleAppendReturnedAndClosed sessions apply close fileReadback controlIntegrationOnly "
    "physicalDropdownGestureQualified imagesDoctorVaultRestartQualified"
).split())


RESULT_LOCATION_KEYS |= frozenset(("localChecks tools offline sameOriginalNativeTerminals exactFixtureReadback releaseReadiness physicalDropdownGestureTested runId context platform operation draftRevision baselineGeneration checks commandsAttempted state reason version build returnCode baseline kind assessment sameOriginal rendered staleAfterContextChange dirtyDraftObserved explicitConsent startArrivalObserved startArrivalLate draftDiscardedThroughUi usedConfig findings summary limitations total shown omitted counts ordinal check message projectCheckIndex savedConfig").split())


def _result_location(parts):
    if type(parts) is not tuple or not 1 <= len(parts) <= 12 or type(parts[0]) is not str:
        return None
    result = ""
    for part in parts:
        if type(part) is str and part in RESULT_LOCATION_KEYS:
            result += ("." if result else "") + part
        elif type(part) is int and 0 <= part < 64:
            result += f"[{part}]"
        else:
            return None
    return result if len(result) <= 256 else None


def _result_need(condition, label, location):
    if not condition:
        error = Refused(label)
        try:
            error.result_location = location
        except BaseException:
            pass  # Diagnostic attachment cannot replace the original refusal.
        raise error


def _exact(actual, expected, location=()):
    # Python's True == 1 (and 1.0 == 1) must not accept substituted evidence.
    _result_need(type(actual) is type(expected), "result-type", location)
    if type(expected) is dict:
        _result_need(actual.keys() == expected.keys(), "result-keys", location)
        for key in expected:
            _exact(actual[key], expected[key], location + (key,))
    elif type(expected) is list:
        _result_need(len(actual) == len(expected), "result-count", location)
        for index, (left, right) in enumerate(zip(actual, expected)):
            _exact(left, right, location + (index,))
    else:
        _result_need(actual == expected, "result-value", location)


def parse_result(stdout, stderr, binding, case):
    need(type(stdout) is bytes and type(stderr) is bytes and len(stdout) + len(stderr) <= OUTPUT_LIMIT, "result-capture")
    need(not any(token in stream for stream in (stdout, stderr)
                 for token in (b"MRK_MACOS_AQUA_FAILURE", b"MRK_MACOS_AQUA=")), "inner-failure-marker")
    need(stdout.count(MARKER) == 1 and MARKER not in stderr, "result-marker-count")
    lines = stdout.split(b"\n")
    records = [line[len(MARKER):] for line in lines[:-1] if line.startswith(MARKER)]
    record_limit = PROJECT_FIELDS_JSON_LIMIT if case == PROJECT_FIELDS_CASE else JSON_LIMIT
    need(len(records) == 1 and 0 < len(records[0]) <= record_limit and b"\r" not in records[0], "result-record")
    try:
        value = json.loads(records[0].decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(Refused("result-constant")))
    except (ValueError, RecursionError, UnicodeError) as error:
        raise Refused("result-json") from error
    expected = expected_result(binding, case)
    if case in LOCAL_CHECK_CASES:
        need(type(value) is dict and "localChecks" in value, "local-checks-report")
        expected["localChecks"] = _local_checks_report(value["localChecks"], case)
    if case == RECOVERY_CASE:
        need(type(value) is dict and "projectRecovery" in value, "recovery-report")
        expected["projectRecovery"] = _recovery_report(value["projectRecovery"])
    if case == INSTALLATION_INSPECTION_CASE:
        need(type(value) is dict and "installationInspection" in value, "installation-inspection-report")
        expected["installationInspection"] = _installation_report(value["installationInspection"])
    if case == PROJECT_FIELDS_CASE:
        _project_field_selection_histories(value, expected)
    if case in VAULT_HELPER_CASES:
        need(type(value) is dict and "vaultHelper" in value, "vault-helper-report")
        expected["vaultHelper"] = _vault_helper_report(value["vaultHelper"], case)
    if case in IOS_OPERATION_CASES:
        need(type(value) is dict and "iosArchive" in value, "ios-report")
        expected["iosArchive"] = _ios_report(value["iosArchive"], case)
    if case in SESSION_CASES:
        need(type(value) is dict and "signingInputs" in value, "signing-inputs-report")
        expected["signingInputs"] = _signing_inputs(value["signingInputs"], case)
        if case in IOS_SIGNED_CASES:
            _exact(value["iosArchive"]["context"]["signing"], _signing_policy_from_inputs(value["signingInputs"]),
                   ("iosArchive", "context", "signing"))
    if case not in ("picker-loss", INSTALLATION_INSPECTION_CASE):
        need(type(value) is dict and type(value.get("native")) is dict, "native-object")
        identity = _accessibility_binding_context(value["native"].get("projectOpenBinding"), case)
        need(identity is not None and identity["start"]["result"] == "ok" and identity["binding"] is not None
             and identity["binding"]["attempted"] and identity["binding"]["error"] == "none",
             "project-open-binding")
        # Original preparation and exact semantic action/return/receipt are
        # separate mandatory proofs; child counts remain actual native DATA.
        expected["native"]["projectOpenBinding"] = identity
        input_data = _accessibility_context(value["native"].get("projectOpenInput"), None, None,
                                            expected_id=identity["id"])
        need(input_data is not None and _accessibility_succeeded(input_data),
             "project-open-input")
        expected["native"]["projectOpenInput"] = input_data
        # A genuine original Press is input success only. The actual original
        # OK callback must independently return one exact, ordinary-path-agreeing
        # selection before any unchanged project/Save/finality gate may pass.
        completion = _completion_selection_context(value["native"].get("projectCompletionSelection"), case)
        need(completion is not None and _completion_selection_succeeded(completion),
             "project-completion-selection")
        expected["native"]["projectCompletionSelection"] = completion
    if case in ("picker-loss", "save-loss"):
        need(type(value) is dict and type(value.get("reload")) is dict, "reload-object")
        reload = value["reload"]
        denied, started = reload.get("navigationDenied"), reload.get("secondStarted")
        need(type(denied) is bool and type(started) is bool and (denied or started), "reload-loss-route")
        expected["reload"]["navigationDenied"], expected["reload"]["secondStarted"] = denied, started
    _exact(value, expected)
    return value


def _failure_row(stdout, stderr, marker, limit):
    """One complete row; count malformed/embedded/partial candidates too."""
    if type(stdout) is not bytes or type(stderr) is not bytes or len(stdout) + len(stderr) > OUTPUT_LIMIT:
        return None
    if sum(stream.count(marker) for stream in (stdout, stderr)) != 1:
        return None
    prefix = marker + b"="
    stream = stdout if marker in stdout else stderr
    start = stream.index(marker)
    if (start != 0 and stream[start - 1] != 10) or not stream.startswith(prefix, start):
        return None
    start += len(prefix)
    end = stream.find(b"\n", start)
    if not 0 < end - start <= limit:
        return None
    row = stream[start:end]
    return None if b"\r" in row else row


def failure_step(stdout, stderr):
    # Finite Rust Step labels only; never publish arbitrary child log text.
    row = _failure_row(stdout, stderr, b"MRK_MACOS_AQUA_FAILURE_STEP", 40)
    if row is None:
        return None
    try:
        label = row.decode("ascii")
    except UnicodeError:
        return None
    return label if label in FAILURE_STEPS else None


def failure_reason(stdout, stderr):
    """Optional closed DATA only; malformed/partial output never grants success."""
    row = _failure_row(stdout, stderr, b"MRK_MACOS_AQUA_FAILURE_REASON", 48)
    if row is None:
        return None
    try:
        label = row.decode("ascii")
    except UnicodeError:
        return None
    return label if label in FAILURE_REASONS else None


def _file_native_panels(case):
    return FILE_NATIVE_PANELS.get(case, {}) if type(case) is str else {}


def _file_open_step(case, identifier):
    # The seventh File panel is genuine Cancel, never an armed Open original.
    return next((step for step, original in _file_native_panels(case).items()
                 if original == identifier and step != "Session(Native(6))"), None)


def _field_native_panels(case):
    return PROJECT_FIELD_PANELS if case == PROJECT_FIELDS_CASE else {}


def _field_open_step(case, identifier):
    return next((step for step, (original, _) in _field_native_panels(case).items()
                 if original == identifier and original not in (6, 7)), None)


def _open_sample_kind(case, identifier, *, allow_files=False):
    if type(case) is not str or case not in ALL_CASES or case in ("picker-loss", INSTALLATION_INSPECTION_CASE) or type(identifier) is not int:
        return None
    if identifier == (2 if case == "first-save" else 1):
        return "project"
    if allow_files and _field_open_step(case, identifier) is not None:
        return PROJECT_FIELD_CHOICES[identifier - 2][1]
    return "file" if allow_files and _file_open_step(case, identifier) is not None else None


def _native_action_context(value, native, panel, *, case=None):
    # Missing/malformed new DATA loses only this diagnostic. Never replace the
    # existing context, first error, original return or unknown-finality facts.
    if value is None:
        return None
    try:
        need(type(value) is dict and set(value) == {"step", "id", "action", "domain", "site", "error"}, "native-action-data")
        need(all(type(value[key]) is str for key in ("step", "action", "domain", "site", "error"))
             and type(value["id"]) is int, "native-action-data")
        spec = NATIVE_ACTION_STEPS.get(value["step"])
        if case == INSTALLATION_INSPECTION_CASE:
            spec = ("quit-confirm", "quit", (3,), 16) if value["step"] == "Quit" else None
        elif value["step"] == "Quit" and type(case) is str and (case in SESSION_CASES or case == PROJECT_FIELDS_CASE):
            spec = ("quit-confirm", "quit", (18 if case == ANDROID_INPUT_CASE else 12,), 16)
        elif value["step"] == "Quit" and case in VAULT_HELPER_CASES:
            spec = ("quit-confirm", "quit", (5, 7) if case == VAULT_HELPER_CASES[0] else (5,), 16)
        elif value["step"] == "Session(Native(6))" and case in ("ios-signing-inputs", ANDROID_INPUT_CASE):
            spec = ("file-cancel", "file", (INPUT_IDS[case][6],), 32)
        elif value["step"] == "ProjectFields(Native(4))" and case == PROJECT_FIELDS_CASE:
            spec = ("file-cancel", "version-source", (6,), 32)
        elif value["step"] == "ProjectFields(Native(5))" and case == PROJECT_FIELDS_CASE:
            spec = ("project-cancel", "metadata-root", (7,), 1)
        need(spec is not None and value["action"] == spec[0] and value["id"] in spec[2], "native-action-data")
        need(native is not None and native["entered"] and native["returned"] and native["step"] == value["step"]
             and panel is not None and panel["step"] == value["step"] and panel["id"] == value["id"]
             and panel["kind"] == spec[1], "native-action-data")
        domain, site, error = value["domain"], value["site"], value["error"]
        if domain == "rust-precondition":
            need(site == "original-usability" and error == "other", "native-action-data")
        else:
            rule = NATIVE_ACTION_SITES.get(site)
            need(rule is not None and rule[1] & spec[3], "native-action-data")
            need(domain == "native-return" and error == rule[0] and error not in (None, "none", "would-block")
                 or domain == "objc-exception" and rule[2] and error == "io", "native-action-data")
        return value
    except (Refused, TypeError, ValueError):
        return None


def _accessibility_native_proof(value, *, selection_parent=False):
    """Validate the closed DATA copied after one actual native body return."""
    label = "accessibility-native-proof"
    extra = {"purpose"} if selection_parent else set()
    need(type(value) is dict and set(value) == {
        "returned", "attempted", "checks", "parent", "panel", "children", "originals", "site", "error", *extra}, label)
    need(not selection_parent or value["purpose"] == "selection-parent", label)
    need(value["returned"] is True and type(value["attempted"]) is bool, label)
    checks = value["checks"]
    need(type(checks) is dict and set(checks) == set(ACCESSIBILITY_PROOF_CHECKS)
         and all(v is None or type(v) is bool for v in checks.values()), label)
    for field, allowed in (("parent", ACCESSIBILITY_BINDING_CLASSES), ("panel", ACCESSIBILITY_PANEL_CLASSES),
                           ("originals", {"zero", "one", "multiple"})):
        need(value[field] is None or type(value[field]) is str and value[field] in allowed, label)
    children, site, error = value["children"], value["site"], value["error"]
    need(children is None or type(children) is int and 0 <= children <= 17, label)
    need(type(site) is str and site in ACCESSIBILITY_PROOF_SITES
         and type(error) is str and error in ACCESSIBILITY_ERRORS, label)
    if not value["attempted"]:
        need(all(v is None for v in checks.values())
             and all(value[key] is None for key in ("parent", "panel", "children", "originals"))
             and (site, error) == ("objects", "custody"), label)
    else:
        # Preserve the earlier successful first-value observation separately
        # from the later failed stability check. Only this exact returned
        # negative frame permits a final class different from valid/match.
        stable_failure = (site == "stable-identifier" and error == "changed"
            and all(checks[key] is True for key in ACCESSIBILITY_PROOF_CHECKS[:10])
            and checks["stableIdentifier"] is False and checks["finalEligibility"] is None
            and value["panel"] in ACCESSIBILITY_PANEL_CLASSES - {"valid", "match"})
        need(checks["eligible"] is not None
             and (checks["parentIdentifier"] is not True or value["parent"] == "match")
             and (checks["panelIdentifier"] is not True or value["panel"] in ("valid", "match") or stable_failure)
             and (checks["nativeChild"] is not True or type(children) is int and 1 <= children <= 16
                  and value["originals"] == "one")
             and (checks["stableIdentifier"] is not True or value["panel"] == "match"), label)
        need((site == "complete") == (error == "none"), label)
        if error == "none":
            need(all(v is True for v in checks.values()) and value["parent"] == value["panel"] == "match"
                 and type(children) is int and 1 <= children <= 16 and value["originals"] == "one", label)
    return value


def _accessibility_press_diagnostic(value):
    """Negative DATA: no AX success acknowledgment, actual effect unknown."""
    label = "accessibility-press-diagnostic"
    need(type(value) is dict and set(value) == {
        "acknowledgment", "effect", "installedAllowanceNs", "lastPermitToReturnAdmissionNs"}, label)
    need(type(value["acknowledgment"]) is str and value["acknowledgment"] == "not-acknowledged"
         and type(value["effect"]) is str and value["effect"] == "unknown", label)
    for key, minimum, maximum, digits in (
        ("installedAllowanceNs", 1, 100000000, 9),
        ("lastPermitToReturnAdmissionNs", 0, 18446744073709551615, 20),
    ):
        scalar = value[key]
        if scalar is None and key == "lastPermitToReturnAdmissionNs":
            continue
        need(type(scalar) is str and 1 <= len(scalar) <= digits and scalar.isascii()
             and scalar.isdecimal() and (scalar == "0" or scalar[0] != "0")
             and minimum <= int(scalar) <= maximum, label)
    return value


def _accessibility_ax_failure(value, ax_error):
    """First actual AX status metadata only; absent iff the original AX error is zero."""
    label = "accessibility-ax-failure"
    need(type(ax_error) is int and (ax_error == 0 or -25214 <= ax_error <= -25200), label)
    if ax_error == 0:
        need(value is None, label)
        return None
    need(type(value) is dict and set(value) == {"operation", "attribute"}, label)
    need(type(value["operation"]) is str and (value["attribute"] is None or type(value["attribute"]) is str)
         and (value["operation"], value["attribute"]) in ACCESSIBILITY_AX_FAILURE_PAIRS, label)
    return value


ACCESSIBILITY_SELECT_NODES = 256
ACCESSIBILITY_SELECT_CALLS = 3072
ACCESSIBILITY_SELECT_CF = 1024
ACCESSIBILITY_SELECT_SAMPLES = 8


def _accessibility_prompt_button(value, *, selecting=False, content=False):
    """Bounded AX/CF DATA; selecting comes from the validated original context."""
    label = "accessibility-prompt-button"
    need(type(selecting) is bool and type(content) is bool, label)
    calls, slots = (ACCESSIBILITY_SELECT_CALLS, ACCESSIBILITY_SELECT_CF) if selecting else (512, 256)
    need(not content or selecting, label)
    if content:
        calls *= ACCESSIBILITY_SELECT_SAMPLES
        slots *= ACCESSIBILITY_SELECT_SAMPLES
    need(type(value) is dict and set(value) == {"checks", "calls", "initialNodesExamined", "recheckNodesExamined",
                                               "lastRole", "lastDepth", "cfSlots", "cfSlotsRetired", "cleanupReturned", "axError", "axFailure"}, label)
    checks = value["checks"]
    need(type(checks) is dict and set(checks) == set(ACCESSIBILITY_BUTTON_CHECKS)
         and all(type(v) is bool for v in checks.values()), label)
    ordered = tuple(checks[key] for key in ACCESSIBILITY_BUTTON_CHECKS)
    need(all(not flag or all(ordered[:index]) for index, flag in enumerate(ordered)), label)
    for key, maximum in (("calls", calls), ("initialNodesExamined", 16), ("recheckNodesExamined", 16), ("lastDepth", 8), ("cfSlots", slots)):
        need(type(value[key]) is int and 0 <= value[key] <= maximum, label)
    need(type(value["lastRole"]) is str and value["lastRole"] in ACCESSIBILITY_CONTROL_ROLES, label)
    need(type(value["cfSlotsRetired"]) is int and 0 <= value["cfSlotsRetired"] <= value["cfSlots"]
         and type(value["cleanupReturned"]) is bool, label)
    need(not value["cleanupReturned"] or value["cfSlotsRetired"] == value["cfSlots"], label)
    need(type(value["axError"]) is int and (value["axError"] == 0 or -25214 <= value["axError"] <= -25200), label)
    _accessibility_ax_failure(value["axFailure"], value["axError"])
    need(not (any(ordered) or value["lastRole"] != "not-read") or value["calls"] > 0 and value["cfSlots"] > 0, label)
    initial, recheck, depth = value["initialNodesExamined"], value["recheckNodesExamined"], value["lastDepth"]
    need(initial == 0 or checks["parentBound"] and checks["sheetBound"], label)
    need(not checks["completeControlProjection"] or initial >= 1, label)
    need(recheck == 0 or all(ordered[:6]), label)
    need(depth <= max(initial, recheck), label)
    need(not checks["sameOriginalControlPathRechecked"] or recheck >= 1 and value["lastRole"] == "Button"
         and 1 <= depth <= min(initial, recheck), label)
    return value


def _selection_succeeded(value):
    return (value is not None and value["limit"] is None and all(value["checks"].values()) and value["attempted"] is True
            and value["returned"] is True and value["selected"] is True and value["matches"] == 1
            and 1 <= value["nodes"] < ACCESSIBILITY_SELECT_NODES and value["attribute"] in ("SelectedRows", "SelectedChildren")
            and value["lastRole"] != "not-read" and 1 <= value["depth"] <= min(8, value["nodes"]))


def _accessibility_selection_limit(value, selection, button, site, error):
    """Closed first-refusal scalars from existing calls; never a new observation."""
    label = "accessibility-selection-limit"
    if value is None:
        need(not (site in ACCESSIBILITY_SELECTION_SITES - {"selection-parent-proof"} and error == "limit"), label)
        return value
    need(type(value) is dict and set(value) == {"predicate", "observed", "cap", "queued", "children"}, label)
    predicate, count, cap, queued, children = (value[key] for key in ("predicate", "observed", "cap", "queued", "children"))
    need(type(predicate) is str and predicate in ACCESSIBILITY_SELECTION_LIMITS, label)
    need(type(count) is int and -(1 << 63) <= count < (1 << 63)
         and type(cap) is int and 1 <= cap <= ACCESSIBILITY_SELECT_CALLS, label)
    need(error == "limit" and site in ("selection-projection", "selection-recheck", "selection-settable", "selection-readback")
         and button is not None and button["axError"] == 0, label)
    projection = site == "selection-projection"
    if projection:
        need(type(queued) is int and 1 <= queued <= ACCESSIBILITY_SELECT_NODES and queued > selection["nodes"]
             and not any(selection["checks"].values()), label)
    else:
        need(queued is None, label)
    need(children is None or type(children) is int and 1 <= children <= 32, label)
    role = selection["lastRole"]
    child_cap = (32 if role in ("Table", "Outline", "List") else
                 16 if role in ("Sheet", "Group", "SplitGroup", "Browser", "ScrollArea", "Column", "Row", "Cell") else 0)
    if predicate == "label-length":
        valid = (projection and cap == 512 and count > 512 and children is None and selection["nodes"] > 0
                 and selection["depth"] > 0 and role in ("Group", "Row", "Cell", "Image", "StaticText", "TextField"))
    elif predicate in ("child-count", "child-copy-count"):
        valid = ((projection and child_cap != 0 and cap == child_cap or site == "selection-readback" and cap == 32)
                 and children is None and (count > cap or predicate == "child-copy-count" and count < 0))
    elif predicate == "queue-capacity":
        valid = (projection and cap == ACCESSIBILITY_SELECT_NODES and count == queued and child_cap != 0 and children is not None
                 and children <= child_cap and children > ACCESSIBILITY_SELECT_NODES - queued and selection["depth"] < 8)
    elif predicate == "depth":
        valid = (projection and cap == 8 and count == 8 and selection["depth"] == 8
                 and child_cap != 0 and children is not None and children <= child_cap)
    elif predicate == "ax-call-budget":
        current = selection.get("contentReadiness")
        before = current["callsBefore"] if current is not None else 0
        valid = (cap == ACCESSIBILITY_SELECT_CALLS and count == button["calls"] - before
                 and ACCESSIBILITY_SELECT_CALLS - 1 <= count <= ACCESSIBILITY_SELECT_CALLS and children is None)
    else:
        current = selection.get("contentReadiness")
        before = current["cfBefore"] if current is not None else 0
        valid = cap == ACCESSIBILITY_SELECT_CF and count == button["cfSlots"] - before == ACCESSIBILITY_SELECT_CF and children is None
    need(valid, label)
    return value


def _accessibility_selection_projection_summary(value, selection, site):
    """Closed existing-roster scalars only; fixed label relations never authorize selection."""
    label = "accessibility-selection-data"
    if value is None:
        need(not any(selection["checks"].values()) and not selection["attempted"] and not selection["returned"]
             and selection["selected"] is None and selection["nodes"] == selection["matches"] == selection["depth"] == 0
             and selection["attribute"] == selection["lastRole"] == "not-read" and selection["limit"] is None
             and site not in ACCESSIBILITY_SELECTION_SITES - {"selection-parent-proof"}, label)
        return None
    counts = ("tableRoles", "outlineRoles", "listRoles", "entryRoots", "titlePresent", "titleAbsent", "valuePresent")
    masks = {"outsideEntryRoleMask": 0x1c210, "fixtureLabelMask": 31,
             "expectedLabelRelations": 7, "expectedLabelRoleMask": 0x1f004}
    need(type(value) is dict and set(value) == {*counts, *masks}, label)
    need(all(type(value[key]) is int and 0 <= value[key] <= selection["nodes"] for key in counts), label)
    need(all(type(value[key]) is int and value[key] >= 0 and value[key] & ~allowed == 0
             for key, allowed in masks.items()), label)
    roles = sum(value[key] for key in counts[:3])
    labels = sum(value[key] for key in counts[4:])
    mask = value["outsideEntryRoleMask"]
    present = value["titlePresent"] + value["valuePresent"]
    need(roles <= selection["nodes"] and labels <= selection["nodes"]
         and (value["entryRoots"] == 0 or roles > 0) and (labels == 0 or value["entryRoots"] > 0)
         and selection["matches"] <= value["entryRoots"]
         and selection["matches"] <= value["titlePresent"] + value["valuePresent"]
         and (mask == 0 or selection["nodes"] > 0)
         and value["fixtureLabelMask"].bit_count() <= present
         and value["expectedLabelRoleMask"].bit_count() <= present
         and (value["expectedLabelRelations"] == 0) == (value["expectedLabelRoleMask"] == 0)
         and bool(value["expectedLabelRelations"] & 1) == (selection["matches"] != 0), label)
    return value


def _accessibility_content_readiness(value, selection, button, site, error):
    """Eight bounded original samples, not another owner or an action-retry receipt."""
    label = "accessibility-selection-data"
    if value is None:
        need(button["calls"] == button["cfSlots"] == 0, label)
        return None
    need(type(value) is dict and set(value) == {"sample", "callsBefore", "cfBefore", "wait", "pending"}, label)
    need(all(type(value[key]) is int for key in ("sample", "callsBefore", "cfBefore", "wait"))
         and 1 <= value["sample"] <= ACCESSIBILITY_SELECT_SAMPLES and 0 <= value["wait"] <= 3, label)
    history = value["pending"]
    need(type(history) is list and len(history) == value["sample"] - 1, label)
    calls, slots = 0, 0
    for index, row in enumerate(history):
        need(type(row) is list and len(row) == 16 and all(type(v) is int and 0 <= v <= (1 << 32) - 1 for v in row), label)
        (ordinal, before, after, cf_before, cf_after, nodes, depth, role, entries, mask,
         relations, checks, matches, flags, sample_error, wait) = row
        need(ordinal == index + 1 and before == calls and cf_before == slots
             and 0 < after - before <= ACCESSIBILITY_SELECT_CALLS and 0 < cf_after - cf_before <= ACCESSIBILITY_SELECT_CF
             and 1 <= nodes < ACCESSIBILITY_SELECT_NODES and 1 <= depth <= min(nodes, 8)
             and 1 <= role <= 16 and entries <= nodes and mask <= 31 and mask.bit_count() <= nodes
             and relations <= 6 and not relations & 1 and (entries != 0 or mask == relations == 0)
             and checks == 1 and matches == flags == sample_error == 0 and wait == 2, label)
        calls, slots = after, cf_after
    need(value["callsBefore"] == calls and value["cfBefore"] == slots
         and 0 <= button["calls"] - calls <= ACCESSIBILITY_SELECT_CALLS
         and 0 <= button["cfSlots"] - slots <= ACCESSIBILITY_SELECT_CF
         and button["calls"] <= ACCESSIBILITY_SELECT_SAMPLES * ACCESSIBILITY_SELECT_CALLS
         and button["cfSlots"] <= ACCESSIBILITY_SELECT_SAMPLES * ACCESSIBILITY_SELECT_CF, label)
    if value["wait"]:
        need(value["sample"] < ACCESSIBILITY_SELECT_SAMPLES and site == "selection-projection"
             and error not in (None, "none") and button["axError"] == 0
             and selection["checks"] == dict(zip(ACCESSIBILITY_SELECTION_CHECKS, (True, False, False, False, False)))
             and selection["matches"] == 0 and not selection["attempted"] and not selection["returned"]
             and selection["selected"] is None and (value["wait"] != 3 or error == "ax-other"), label)
    return value


def _accessibility_selection_projection_diagnostic(value, selection, button, error):
    """First-zero finite projection DATA, not atomic presentation or selection authority."""
    label = "accessibility-selection-data"
    if value is None:
        return None  # Unentered is indeterminate, never proof that a label was absent.
    fields = {"version", "state", "normalFixtureMask", "callsBefore", "callsAfter", "cfBefore", "cfAfter",
              "eligibleFrontiers", "attemptedFrontiers", "addedNodes", "maxDepth", "alternateValueMask",
              "frontierLabelMask", "outsideFieldMask", "alternateRoleMask", "frontierRoleMask",
              "unavailable", "omissions", "duplicates", "nonStringValues"}
    need(type(value) is dict and set(value) == fields, label)
    need(all(type(value[key]) is int and 0 <= value[key] < (1 << 32) for key in fields - {"state"}), label)
    need(value["version"] == 1 and type(value["state"]) is str
         and value["state"] in ("entered", "returned-complete", "returned-incomplete"), label)
    calls, slots = value["callsAfter"] - value["callsBefore"], value["cfAfter"] - value["cfBefore"]
    eligible, attempted, added = value["eligibleFrontiers"], value["attemptedFrontiers"], value["addedNodes"]
    need(0 < value["callsBefore"] <= value["callsAfter"] <= ACCESSIBILITY_SELECT_CALLS and 0 <= calls <= 1024
         and 0 < value["cfBefore"] <= value["cfAfter"] <= ACCESSIBILITY_SELECT_CF and 0 <= slots <= 512
         and eligible < ACCESSIBILITY_SELECT_NODES and attempted <= min(64, eligible) and added <= 64
         and value["maxDepth"] <= 8 and (added == 0) == (value["maxDepth"] == 0), label)
    for key, allowed in (("normalFixtureMask", 31), ("alternateValueMask", 31), ("frontierLabelMask", 31),
                         ("outsideFieldMask", 31), ("alternateRoleMask", 0x7004), ("frontierRoleMask", 0x1f014),
                         ("unavailable", 63), ("omissions", 1023)):
        need(value[key] & ~allowed == 0, label)
    need((value["alternateValueMask"] == 0) == (value["alternateRoleMask"] == 0)
         and (value["frontierLabelMask"] == 0) == (value["frontierRoleMask"] == 0)
         and value["duplicates"] <= 32 * (attempted + added) and value["nonStringValues"] <= slots
         and 2 * added <= slots and (added == 0 or attempted > 0)
         and value["alternateValueMask"].bit_count() <= slots and value["outsideFieldMask"].bit_count() <= slots
         and value["alternateRoleMask"].bit_count() <= slots
         and value["frontierLabelMask"].bit_count() <= 2 * added and value["frontierRoleMask"].bit_count() <= added, label)
    content = selection["contentReadiness"]
    need(content is not None, label)
    if content["sample"] == 1:
        need(selection["checks"] == dict(zip(ACCESSIBILITY_SELECTION_CHECKS, (True, False, False, False, False)))
             and selection["matches"] == 0 and not selection["attempted"] and not selection["returned"]
             and selection["selected"] is None and selection["projectionSummary"] is not None, label)
        first_nodes, first_mask = selection["nodes"], selection["projectionSummary"]["fixtureLabelMask"]
        first_calls, first_cf = button["calls"], button["cfSlots"]
    else:
        first = content["pending"][0]  # Already validated complete; never use the last partial sample.
        first_nodes, first_mask, first_calls, first_cf = first[5], first[9], first[2], first[4]
        need(value["state"] != "entered", label)
    need(1 <= first_nodes < ACCESSIBILITY_SELECT_NODES and value["normalFixtureMask"] == first_mask
         and value["callsAfter"] == first_calls and value["cfAfter"] == first_cf
         and eligible <= first_nodes and first_nodes + 1 + added <= ACCESSIBILITY_SELECT_NODES, label)
    incomplete = value["unavailable"] or value["omissions"] or value["nonStringValues"] or attempted != eligible
    if value["state"] == "entered":
        need(error not in (None, "none"), label)
    elif value["state"] == "returned-complete":
        need(not incomplete, label)
    else:
        need(incomplete or error not in (None, "none"), label)
    # VERSION alone outside the entry grammar can be the prefilled name field.
    # Even a new sibling route is non-atomic relative to the original census;
    # compare later unchanged normal samples, never infer an action permit.
    return value


def _accessibility_selection(value, button, site, error, *, content=False):
    """Actual selector scalars, never a filename, URL, or substitute Open proof."""
    label = "accessibility-selection-data"
    need(type(value) is dict and set(value) == {"checks", "attempted", "returned", "selected",
         "nodes", "matches", "attribute", "lastRole", "depth", "limit", "projectionSummary", *({"contentReadiness", "projectionDiagnostic"} if content else set())}, label)
    checks = value["checks"]
    need(type(checks) is dict and set(checks) == set(ACCESSIBILITY_SELECTION_CHECKS)
         and all(type(v) is bool for v in checks.values()), label)
    ordered = tuple(checks[key] for key in ACCESSIBILITY_SELECTION_CHECKS)
    need(all(not flag or all(ordered[:index]) for index, flag in enumerate(ordered)), label)
    need(all(type(value[key]) is bool for key in ("attempted", "returned"))
         and (value["selected"] is None or type(value["selected"]) is bool), label)
    for key, limit in (("nodes", ACCESSIBILITY_SELECT_NODES - 1), ("matches", 2), ("depth", 8)):
        need(type(value[key]) is int and 0 <= value[key] <= limit, label)
    need(value["depth"] <= value["nodes"] and type(value["lastRole"]) is str
         and value["lastRole"] in ACCESSIBILITY_SELECTION_ROLES
         and type(value["attribute"]) is str and value["attribute"] in ("not-read", "SelectedRows", "SelectedChildren"), label)
    need(value["matches"] <= value["nodes"]
         and (not checks["completeProjection"] or value["nodes"] > 0 and value["depth"] > 0 and value["lastRole"] != "not-read"), label)
    need((value["attribute"] != "not-read") == checks["originalLabelChainRechecked"]
         and (not checks["uniqueEntry"] or value["matches"] == 1 and value["nodes"] > 0), label)
    need(not value["returned"] or value["attempted"], label)
    need((value["selected"] is not None) == value["returned"], label)
    need(not value["attempted"] or checks["attributeSettable"], label)
    need(not checks["singletonOriginalEntryReadback"] or value["selected"] is True, label)
    need(value["selected"] is not False or button is not None and button["axError"] != 0, label)
    if content:
        _accessibility_content_readiness(value["contentReadiness"], value, button, site, error)
    _accessibility_selection_limit(value["limit"], value, button, site, error)
    _accessibility_selection_projection_summary(value["projectionSummary"], value, site)
    if content:
        _accessibility_selection_projection_diagnostic(value["projectionDiagnostic"], value, button, error)
    return value


def _accessibility_succeeded(value):
    # A matching receipt alone never means that its input thread has joined.
    field = PROJECT_FIELD_PANELS.get(value["step"])
    selecting = field is not None and field[1] == "version-source"
    selected = (value.get("mechanism") == "accessibility-version-source-selection-press-v8"
        and _selection_succeeded(value.get("selection"))
        and value["selection"].get("contentReadiness") is not None and value["selection"]["contentReadiness"]["wait"] == 0
        and value.get("selectionParentPrompt") is True
        and value.get("selectionParentProof") is not None
        and value["selectionParentProof"].get("purpose") == "selection-parent"
        and value["selectionParentProof"]["error"] == "none")
    return ((selected if selecting else value["mechanism"] == "accessibility-preconfigured-original-press-v5")
            and all(value[key] is True for key in ("prepared", "requested", "dispatchAttempted", "bodyEntered", "nativeEntered",
             "bodyReturned", "receiptJoined", "workerRegistered", "workerJoined", "rechecksSettled", "barrierRetired",
             "timely", "custodyKnown", "attempted", "pressReturned", "triggered"))
            and value["expired"] is False and value["state"] == "retired" and value["site"] == "press" and value["error"] == "none"
            and all(value[key] is not None and "purpose" not in value[key] and value[key]["error"] == "none"
                    for key in ("initialOriginalProof", "originalProof"))
            and all(value["promptChecks"][key] is True for key in ("initial", "final"))
            and value["promptButton"] is not None and all(value["promptButton"]["checks"].values())
            and value["promptButton"]["cleanupReturned"] is True and value["promptButton"]["axError"] == 0
            and value["promptButton"]["axFailure"] is None
            and value["promptButton"]["cfSlotsRetired"] == value["promptButton"]["cfSlots"])


def _accessibility_context(value, native, panel, *, expected_id=None, case=None, field_history=False, historical=False,
                           allow_press_diagnostic=False):
    if value is None:
        return None
    label = "accessibility-data"
    try:
        flags = ("prepared", "requested", "dispatchAttempted", "bodyReturned", "receiptJoined", "barrierRetired", "expired",
                 "workerRegistered", "workerJoined")
        observed = ("bodyEntered", "nativeEntered", "attempted", "pressReturned", "triggered", "timely", "custodyKnown", "rechecksSettled")
        need(type(value) is dict and type(value.get("id")) is int, label)
        field_step = _field_open_step(case, value["id"]) if expected_id is None or field_history else None
        version_source = field_step is not None and PROJECT_FIELD_PANELS[field_step][1] == "version-source"
        content = version_source and value.get("mechanism") == "accessibility-version-source-selection-press-v8"
        selecting = content or historical and version_source and value.get("mechanism") == "accessibility-version-source-selection-press-v7"
        mechanism = "accessibility-version-source-selection-press-v8" if version_source else "accessibility-preconfigured-original-press-v5"
        need(value.get("mechanism") == mechanism or historical and version_source
             and value.get("mechanism") in ("accessibility-preconfigured-original-press-v5", "accessibility-version-source-selection-press-v7"), label)
        extra = {"selectionParentProof", "selectionParentPrompt", "selection"} if selecting else set()
        diagnostic_fields = {"pressDiagnostic"} if "pressDiagnostic" in value else set()
        need(not diagnostic_fields or allow_press_diagnostic is True and expected_id is None
             and not field_history and value["mechanism"] == mechanism, label)
        need(set(value) == {"mechanism", "step", "id", "state", "site", "error",
             "initialOriginalProof", "originalProof", "promptChecks", "promptButton", *flags, *observed, *extra, *diagnostic_fields}, label)
        need(not field_history or expected_id is not None and selecting, label)
        # The actual File OpenInput projection retains its historical
        # OpenProject label. Only failure DATA with an exact case/ID/native
        # panel binding may describe File; Project success callers stay closed.
        file_step = _file_open_step(case, value["id"]) if expected_id is None else None
        need(value["step"] == (field_step or "OpenProject")
             and (value["id"] in (1, 2) or file_step is not None or field_step is not None), label)
        if expected_id is not None:
            need(value["id"] == expected_id, label)
        elif field_step is not None:
            need(native is not None and native["step"] == field_step and native["entered"] and native["returned"]
                 and panel is not None and panel["step"] == field_step and panel["id"] == value["id"]
                 and panel["kind"] == PROJECT_FIELD_PANELS[field_step][1], label)
        elif file_step is not None:
            need(native is not None and native["step"] == file_step and native["entered"] and native["returned"]
                 and panel is not None and panel["step"] == file_step and panel["kind"] == "file"
                 and panel["id"] == value["id"], label)
        else:
            need(native is not None, label)
            if native["step"] == "OpenProject":
                need(native["entered"] and native["returned"] and panel is not None and panel["step"] == "OpenProject"
                     and panel["kind"] == "project" and panel["id"] == value["id"], label)
        need(all(type(value[key]) is bool for key in flags)
             and all(value[key] is None or type(value[key]) is bool for key in observed), label)
        state, site, error = value["state"], value["site"], value["error"]
        need(type(state) is str and state in ("prepared", "requested", "queued", "entered", "returned", "joined", "retired", "unknown"), label)
        need(site is None or type(site) is str and site in ACCESSIBILITY_SITES
             and (selecting or site not in ACCESSIBILITY_SELECTION_SITES), label)
        need(error is None or type(error) is str and error in ACCESSIBILITY_ERRORS, label)
        need((site is None) == (error is None), label)
        need(not value["requested"] or value["prepared"], label)
        need(not value["dispatchAttempted"] or value["requested"] and value["workerRegistered"], label)
        need(not value["workerJoined"] or value["workerRegistered"], label)
        need(value["bodyEntered"] is not True or value["dispatchAttempted"], label)
        need(value["nativeEntered"] is not True or value["bodyEntered"] is True, label)
        need(not value["bodyReturned"] or value["bodyEntered"] is True, label)
        need(not value["receiptJoined"] or value["bodyReturned"] and value["workerJoined"]
             and value["rechecksSettled"] is True, label)
        no_entry = (not value["dispatchAttempted"] and value["bodyEntered"] is False
                    and not value["bodyReturned"] and value["nativeEntered"] is False)
        need(not value["barrierRetired"] or value["prepared"] and (value["receiptJoined"] or no_entry)
             and value["rechecksSettled"] is not False
             and (not value["workerRegistered"] or value["workerJoined"] and value["rechecksSettled"] is True), label)
        # Phase is current custody; monotonic facts cannot be erased by Unknown.
        if state == "unknown":
            need(value["custodyKnown"] is False, label)
        elif state == "retired":
            need(value["barrierRetired"] and value["custodyKnown"] is True, label)
        else:
            need(not value["barrierRetired"], label)
            ordinal = ("prepared", "requested", "queued", "entered", "returned", "joined").index(state)
            need(value["requested"] == (ordinal >= 1) and value["dispatchAttempted"] == (ordinal >= 2)
                 and value["bodyReturned"] == (ordinal >= 4) and value["receiptJoined"] == (ordinal >= 5), label)
            need(value["bodyEntered"] is True if ordinal >= 3 else value["bodyEntered"] in (None, False), label)
            if ordinal < 4:
                need(value["custodyKnown"] is not True, label)
            elif ordinal == 4:
                need(value["custodyKnown"] is not False, label)
            else:
                need(value["custodyKnown"] is True, label)
        need(not value["expired"] or value["timely"] is not True, label)
        need(value["attempted"] is not True or value["nativeEntered"] is True and value["bodyReturned"], label)
        need(value["pressReturned"] is not True or value["attempted"] is True, label)
        need((value["triggered"] is not None) == (value["pressReturned"] is True), label)
        need(error not in ("custody", "objc-exception", "cleanup-unknown") or value["custodyKnown"] is not True, label)
        proofs = (value["initialOriginalProof"], value["originalProof"])
        prompt = value["promptChecks"]
        need(type(prompt) is dict and set(prompt) == {"initial", "final"}
             and all(item is None or type(item) is bool for item in prompt.values()), label)
        for index, (proof, name) in enumerate(zip(proofs, ("initial", "final"))):
            if proof is not None:
                need(value["bodyReturned"] and value["nativeEntered"] is True, label)
                _accessibility_native_proof(proof)
                need(index == 0 or proofs[0] is not None and proofs[0]["error"] == "none" and prompt["initial"] is True, label)
            if prompt[name] is not None:
                need(proof is not None and proof["error"] == "none", label)
        parent, parent_prompt, selection = None, None, None
        if selecting:
            parent, parent_prompt, selection = (value[key] for key in ("selectionParentProof", "selectionParentPrompt", "selection"))
            need(parent_prompt is None or type(parent_prompt) is bool, label)
            if parent is not None:
                need(value["bodyReturned"] and value["nativeEntered"] is True, label)
                _accessibility_native_proof(parent, selection_parent=True)
            need(parent_prompt is None or parent is not None and parent["error"] == "none", label)
        parent_ready = parent is not None and parent["error"] == "none" and parent_prompt is True
        full_ready = proofs[0] is not None and proofs[0]["error"] == "none" and prompt["initial"] is True
        button = value["promptButton"]
        if button is not None:
            need(value["bodyReturned"] and value["nativeEntered"] is True, label)
            _accessibility_prompt_button(button, selecting=selecting, content=content)
            need(button["calls"] == 0 or (parent_ready if selecting else full_ready), label)
            need(button["initialNodesExamined"] == 0 and not button["checks"]["completeControlProjection"] or full_ready, label)
            need(button["cleanupReturned"] or value["custodyKnown"] is not True
                 and not value["receiptJoined"] and not value["barrierRetired"], label)
        selector_ready = False
        if selecting:
            need((selection is None) == (button is None), label)
            if selection is not None:
                need(value["bodyReturned"] and value["nativeEntered"] is True, label)
                _accessibility_selection(selection, button, site, error, content=content)
                selector_ready = _selection_succeeded(selection)
                started = (any(selection["checks"].values()) or selection["nodes"] != 0 or selection["matches"] != 0
                    or selection["lastRole"] != "not-read" or selection["depth"] != 0
                    or selection["attempted"] or selection["returned"] or selection["selected"] is not None or selection["limit"] is not None
                    or selection["projectionSummary"] is not None)
                need(not started or parent_ready and button["calls"] > 0 and button["cfSlots"] > 0
                     and button["checks"]["parentBound"] and button["checks"]["sheetBound"], label)
                need(not any(button["checks"][key] for key in ACCESSIBILITY_BUTTON_CHECKS[2:]) or selector_ready, label)
                completed = sum(selection["checks"].values())
                if site in ACCESSIBILITY_SELECTION_SITES:
                    need(proofs == (None, None) and prompt == {"initial": None, "final": None}, label)
                    if site == "selection-parent-proof":
                        need(not started and button["calls"] == 0 and button["cfSlots"] == 0
                             and not any(button["checks"].values()), label)
                    else:
                        need(tuple(button["checks"][key] for key in ACCESSIBILITY_BUTTON_CHECKS)
                             == (True, True, False, False, False, False, False), label)
                    if site == "selection-projection":
                        need(completed in (0, 1, 2) and not selection["attempted"], label)
                    elif site == "selection-recheck":
                        need(completed == 2 and not selection["attempted"], label)
                    elif site == "selection-settable":
                        need(completed in (3, 4) and not selection["attempted"], label)
                    elif site == "selection-write":
                        need(completed == 4 and selection["attempted"], label)
                    elif site == "selection-readback":
                        need(completed in (4, 5) and selection["selected"] is True, label)
            need(proofs[0] is None or parent_ready and selector_ready, label)
            if value["nativeEntered"] is not True or not value["bodyReturned"]:
                need(parent is None and parent_prompt is None and selection is None, label)
        need(proofs[1] is None or button is not None and all(button["checks"].values()), label)
        ready = (all(p is not None and p["error"] == "none" for p in proofs)
                 and prompt == {"initial": True, "final": True} and button is not None and all(button["checks"].values())
                 and (not selecting or parent_ready and selector_ready))
        need(value["attempted"] is not True or ready and site in ("press", "cleanup"), label)
        if value["nativeEntered"] is False:
            need(all(p is None for p in proofs) and all(p is None for p in prompt.values()) and button is None
                 and value["attempted"] is False and value["pressReturned"] is False and value["triggered"] is None, label)
        elif value["nativeEntered"] is None:
            need(all(p is None for p in proofs) and all(p is None for p in prompt.values()) and button is None
                 and value["attempted"] is None and value["pressReturned"] is None and value["triggered"] is None, label)
        else:
            need(value["bodyReturned"], label)
        if not value["bodyReturned"]:
            need(all(p is None for p in proofs) and all(p is None for p in prompt.values()) and button is None
                 and value["triggered"] is None, label)
        if value["triggered"] is False:
            need(button is not None and button["axError"] != 0 and error not in (None, "none"), label)
        elif value["triggered"] is True:
            need(button is not None and button["axError"] == 0, label)
        if error == "none":
            need(site == "press" and value["attempted"] is True and value["pressReturned"] is True
                 and value["triggered"] is True and ready and button["axError"] == 0 and button["cleanupReturned"], label)
        if error == "cannot-complete":
            need(button is not None and button["axError"] == -25204, label)
        if diagnostic_fields:
            kind = _open_sample_kind(case, value["id"], allow_files=True)
            native_step = field_step or file_step or "OpenProject"
            need(kind is not None and native == {"step": native_step, "entered": True, "returned": True}
                 and panel is not None and panel["step"] == native_step and panel["id"] == value["id"]
                 and panel["kind"] == kind and value["bodyEntered"] is True and value["nativeEntered"] is True
                 and value["bodyReturned"] and value["attempted"] is True and value["pressReturned"] is True
                 and value["triggered"] is False and button is not None and button["axError"] == -25204
                 and button["axFailure"] == {"operation": "perform-action", "attribute": None}, label)
            _accessibility_press_diagnostic(value["pressDiagnostic"])
        if error == "invalid-element":
            need(button is not None and button["axError"] == -25202, label)
        if site in ("control-projection", "button", "control-recheck"):
            need(button is not None, label)
            completed = sum(button["checks"].values())
            need((site == "control-projection" and completed in (2, 3) and button["recheckNodesExamined"] == 0)
                 or (site == "button" and completed in (4, 5, 6) and button["recheckNodesExamined"] == 0)
                 or (site == "control-recheck" and completed == 6 and button["lastDepth"] <= button["recheckNodesExamined"]), label)
        if site in ACCESSIBILITY_CONTROL_LIMIT_SITES:
            # Count/Copy can fail at the root or after deeper nodes began.
            # Preserve both actual counters and current role/depth even through
            # late/Unknown cleanup; no local diagnostic can supply proof.
            need(error == "limit" and button is not None and button["axError"] == 0
                 and button["calls"] > 0 and button["cfSlots"] > 0
                 and proofs[0] is not None and proofs[0]["error"] == "none" and proofs[1] is None
                 and prompt == {"initial": True, "final": None} and value["attempted"] is False
                 and value["pressReturned"] is False and value["triggered"] is None, label)
            ordered = tuple(button["checks"][key] for key in ACCESSIBILITY_BUTTON_CHECKS)
            initial = ordered == (True, True, False, False, False, False, False)
            recheck = ordered == (True, True, True, True, True, True, False)
            need(initial and button["recheckNodesExamined"] == 0 or recheck and button["initialNodesExamined"] >= 1, label)
            examined = button["initialNodesExamined"] if initial else button["recheckNodesExamined"]
            depth, role = button["lastDepth"], button["lastRole"]
            node = 1 <= depth <= 8 and examined >= depth
            container = role in ("Group", "SplitGroup") and node
            need((site == "control-title-limit" and role == "Button" and node)
                 or (site in ("control-child-count-limit", "control-child-copy-limit")
                     and (container or role == "Sheet" and depth == 0 and examined == 0))
                 or (site == "control-node-limit" and container and depth < 8)
                 or (site == "control-depth-limit" and container and depth == 8), label)
        for name, proof in (("selection-parent-proof", parent), ("initial-original-proof", proofs[0]), ("original-proof", proofs[1])):
            if site == name and proof is not None and proof["error"] != "none":
                need(proof["error"] == error, label)
        return value
    except (Refused, KeyError, TypeError, ValueError):
        return None


def _accessibility_binding_context(value, case, *, allow_files=False, historical=False):
    """Closed original-return DATA; never a permission, action or finality fact."""
    if value is None:
        return None
    try:
        label = "accessibility-binding-data"
        need(type(case) is str and case in ALL_CASES and case != "picker-loss", label)
        need(type(value) is dict and set(value) == {
            "mechanism", "case", "id", "kind", "start", "configuration", "binding"}, label)
        kind = _open_sample_kind(case, value["id"], allow_files=allow_files)
        selecting = kind == "version-source" and value["mechanism"] == "selection-parent-original-sheet-v3"
        mechanism = "selection-parent-original-sheet-v3" if kind == "version-source" else "preconfigured-original-sheet-v2"
        need((value["mechanism"] == mechanism or historical and kind == "version-source"
              and value["mechanism"] == "preconfigured-original-sheet-v2") and value["case"] == case
             and kind is not None and value["kind"] == kind, label)
        start, configured, bound = value["start"], value["configuration"], value["binding"]
        need(type(start) is dict and set(start) == {"returned", "result"} and start["returned"] is True
             and type(start["result"]) is str
             and start["result"] in ("ok", "permission-denied", "io", "invalid-input", "already", "other"), label)
        flags = ("parentSetterEntered", "parentSetterReturned", "promptSetterEntered", "promptSetterReturned",
                 "initialDirectorySetterEntered", "initialDirectorySetterReturned")
        file_flags = ("fileNameSetterEntered", "fileNameSetterReturned") if kind == "file" else ()
        need(type(configured) is dict and set(configured) == {"attempted", *flags, *file_flags, "parent", "prompt", "site", "error"}
             and all(type(configured[key]) is bool for key in ("attempted", *flags, *file_flags)), label)
        parent, prompt, site, error = (configured[key] for key in ("parent", "prompt", "site", "error"))
        need(parent is None or type(parent) is str and parent in ACCESSIBILITY_BINDING_CLASSES, label)
        need(prompt is None or type(prompt) is str and prompt in ACCESSIBILITY_BINDING_CLASSES, label)
        need(site is None or type(site) is str and site in ACCESSIBILITY_BINDING_SITES, label)
        need(error is None or type(error) is str and error in ACCESSIBILITY_ERRORS, label)
        bits = tuple(configured[key] for key in flags)
        file_bits = tuple(configured[key] for key in file_flags)
        all_bits = bits + file_bits
        need(all(not flag or all(all_bits[:index]) for index, flag in enumerate(all_bits)), label)
        if kind == "file":
            need(configured["attempted"] and (site in ("file-name-set", "file-name-get", "complete")
                 or file_bits == (False, False)), label)
        if not configured["attempted"]:
            need(not any(bits) and parent is prompt is site is error is None and start["result"] != "ok", label)
        else:
            need(start["result"] in ("ok", "io") and site is not None and error is not None, label)
            if site in ("objects", "parent-tag"):
                need(not any(bits) and parent is prompt is None
                     and error in (("ineligible",) if site == "objects" else ("invalid-input", "objc-exception")), label)
            elif site == "parent-set":
                need(bits == (True, False, False, False, False, False) and parent is prompt is None and error == "objc-exception", label)
            elif site == "parent-get":
                need(bits == (True, True, False, False, False, False) and parent is prompt is None and error == "objc-exception", label)
            elif site == "prompt-set":
                need(bits == (True, True, True, False, False, False) and parent is not None and prompt is None and error == "objc-exception", label)
            elif site == "prompt-get":
                need(bits == (True, True, True, True, False, False) and parent is not None
                     and (prompt is None and error == "objc-exception" or prompt is not None and prompt != "match" and error == "changed"), label)
            elif site == "initial-directory-url":
                need(bits == (True, True, True, True, False, False) and parent is not None and prompt == "match"
                     and error in ("invalid-input", "objc-exception"), label)
            elif site == "initial-directory-set":
                need(bits == (True, True, True, True, True, False) and parent is not None and prompt == "match"
                     and error == "objc-exception", label)
            elif site == "initial-temporary-close":
                need(kind in ("version-source", "ios-project", "ios-workspace", "metadata-root")
                     and bits in ((True, True, True, True, False, False), (True, True, True, True, True, False),
                                  (True, True, True, True, True, True))
                     and parent is not None and prompt == "match" and error == "cleanup-unknown", label)
            elif site == "file-name-set":
                need(kind == "file" and all(bits) and file_bits == (True, False) and parent is not None
                     and prompt == "match" and error == "objc-exception", label)
            elif site == "file-name-get":
                need(kind == "file" and all(bits) and file_bits == (True, True) and parent is not None
                     and prompt == "match" and error in ("changed", "objc-exception"), label)
            else:
                need(site == "complete" and all(all_bits) and parent is not None and prompt == "match" and error == "none", label)
            if start["result"] == "ok":
                need(site == "complete" and error == "none", label)
        if bound is not None:
            need(start["result"] == "ok", label)
            _accessibility_native_proof(bound, selection_parent=selecting)
        return value
    except (Refused, KeyError, TypeError, ValueError):
        return None


def _completion_selection_context(value, case, *, allow_files=False):
    """Saved same-original poll DATA, including returned errors, never a join."""
    if value is None:
        return None
    try:
        label = "completion-selection-data"
        need(type(case) is str and case in ALL_CASES and case != "picker-loss", label)
        need(type(value) is dict and set(value) == {
            "mechanism", "case", "id", "kind", "pollReturned", "pollResult", "timely", "facts"}, label)
        kind = _open_sample_kind(case, value["id"], allow_files=allow_files)
        need(value["mechanism"] == "original-ok-singleton-selection-v1" and value["case"] == case
             and kind is not None and value["kind"] == kind and value["pollReturned"] is True
             and type(value["timely"]) is bool and type(value["pollResult"]) is str
             and value["pollResult"] in ("showing", "responded", "closed", "error", "invalid-return"), label)
        facts = value["facts"]
        if facts is not None:
            flags = ("callbackEntered", "urlsReadEntered", "urlsReadReturned", "callbackReturned", "duplicate", "nativeUnknown")
            need(type(facts) is dict and set(facts) == {*flags, "response", "selection"}
                 and all(type(facts[key]) is bool for key in flags), label)
            response, selection = facts["response"], facts["selection"]
            need(response is None or type(response) is str and response in ("accept", "decline", "other"), label)
            need(selection is None or type(selection) is str and selection in (
                "empty", "malformed", "multiple", "different", "ordinary-path-disagreement", "match"), label)
            if not facts["callbackEntered"]:
                need(not any(facts[key] for key in flags[:-1]) and response is selection is None, label)
            need(not facts["urlsReadEntered"] or response == "accept", label)
            need(not facts["urlsReadReturned"] or facts["urlsReadEntered"], label)
            need(selection is None or facts["urlsReadReturned"], label)
            need(not facts["duplicate"] or facts["nativeUnknown"], label)
            if not facts["nativeUnknown"]:
                need(facts["callbackEntered"] and facts["callbackReturned"] and response is not None, label)
                if response == "accept":
                    need(facts["urlsReadReturned"] and selection is not None, label)
                else:
                    need(not facts["urlsReadEntered"] and selection is None, label)
        return value
    except (Refused, KeyError, TypeError, ValueError):
        return None


def _completion_selection_succeeded(value):
    # Unknown/late/unavailable DATA may explain a failure but never resolve it.
    # This predicate receives only a closed, case/id-bound decoded sample.
    if value is None or value["pollResult"] != "responded" or value["timely"] is not True:
        return False
    facts = value["facts"]
    return (facts is not None and all(facts[key] is True for key in (
                "callbackEntered", "urlsReadEntered", "urlsReadReturned", "callbackReturned"))
            and facts["duplicate"] is False and facts["nativeUnknown"] is False
            and facts["response"] == "accept" and facts["selection"] == "match")


def _project_field_selection_histories(value, expected):
    label = "project-fields-selection-history"
    need(type(value) is dict and type(value.get("projectFields")) is dict, label)
    rows = value["projectFields"].get("rows")
    expected_rows = expected["projectFields"]["rows"]
    need(type(rows) is list and len(rows) == len(expected_rows), label)
    for actual, original in zip(rows, expected_rows):
        need(type(actual) is dict and type(actual.get("initialRootAndOptions")) is dict
             and "fileFilter" in actual["initialRootAndOptions"], label)
        observed = actual["initialRootAndOptions"]["fileFilter"]
        if original["kind"] == "version-source":
            _file_filter_context(observed, complete=True)
        else:
            need(observed is None, label)
        original["initialRootAndOptions"]["fileFilter"] = observed
    histories = value["projectFields"].get("acceptedOpenHistories")
    originals = expected["projectFields"]["acceptedOpenHistories"]
    need(type(histories) is list and len(histories) == len(originals), label)
    for actual, original in zip(histories, originals):
        need(type(actual) is dict and type(actual.get("operationId")) is int
             and actual["operationId"] == original["operationId"] and actual.get("kind") == original["kind"], label)
        if original["kind"] != "version-source":
            continue
        identifier = original["operationId"]
        action = _accessibility_context(actual.get("selectionInput"), None, None,
            expected_id=identifier, case=PROJECT_FIELDS_CASE, field_history=True)
        need(action is not None and _accessibility_succeeded(action), label)
        binding = _accessibility_binding_context(actual.get("selectionBinding"), PROJECT_FIELDS_CASE, allow_files=True)
        need(binding is not None and binding["id"] == identifier and binding["kind"] == "version-source"
             and binding["start"]["result"] == "ok" and binding["binding"] is not None
             and binding["binding"]["attempted"] and binding["binding"]["error"] == "none", label)
        completion = _completion_selection_context(actual.get("selectionCompletion"), PROJECT_FIELDS_CASE, allow_files=True)
        need(completion is not None and completion["id"] == identifier and completion["kind"] == "version-source"
             and _completion_selection_succeeded(completion), label)
        original.update(selectionInput=action, selectionBinding=binding, selectionCompletion=completion)


def _original_window_context(value):
    if value is None:
        return None  # No returned sample, not a nil/inactive native observation.
    label = "original-window-context"
    need(type(value) is dict and set(value) == {"mechanism", "accessorReturned", "nativeReturned",
                                               "result", "admitted", "state"}, label)
    need(type(value["mechanism"]) is str and value["mechanism"] == "passive-original-window-callback-v1"
         and type(value["accessorReturned"]) is bool and value["accessorReturned"]
         and type(value["nativeReturned"]) is bool and type(value["admitted"]) is bool
         and type(value["result"]) is str
         and value["result"] in ("ok", "accessor-error", "entry-refused", "native-error", "invalid-return"), label)
    need(value["nativeReturned"] == (value["result"] != "accessor-error"), label)
    state = value["state"]
    if value["result"] != "ok":
        need(state is None and not value["admitted"], label)
    else:
        need(type(state) is dict and set(state) == {"applicationPresent", "active", "mainPresent",
                                                  "originalMain", "ordinaryWindow", "noAttachedSheet"}
             and all(type(fact) is bool for fact in state.values()), label)
        need(state["applicationPresent"] or not any(state.values()), label)
        need(state["mainPresent"] or not any(state[key] for key in
             ("originalMain", "ordinaryWindow", "noAttachedSheet")), label)
        # A positive read returned after failure/expiry can be truthful DATA
        # with admitted=False; it still cannot satisfy successful case evidence.
        need(not value["admitted"] or all(state.values()), label)
    return value


def _project_selection_context(value, source, step, reason, case):
    """Saved relational DATA, never a path, fresh identity or native receipt."""
    label = "project-selection-context"
    need(type(value) is dict and set(value) == {"custody", "recordedObject", "lexicalLocation"}
         and all(type(part) is str for part in value.values()), label)
    custody, recorded, location = value["custody"], value["recordedObject"], value["lexicalLocation"]
    need(custody in PROJECT_SELECTION_CUSTODY and recorded in PROJECT_SELECTION_OBJECTS
         and location in PROJECT_SELECTION_LOCATIONS, label)
    need(source == "record" and step in ("OpenProject", "ProjectSettled")
         and reason in PROJECT_SELECTION_BOUND_LOCATIONS
         and (case is None or type(case) is str and case in ("first-save", "noop-stale", "save-loss")), label)
    if custody == "bound-original-data":
        need(recorded != "unavailable" and location in PROJECT_SELECTION_BOUND_LOCATIONS[reason], label)
    elif custody == "unavailable-original-data":
        need(recorded == "unavailable" or location == "unavailable", label)
    need(location != "current-project" or custody == "inconsistent-original-data", label)
    # Only noop-stale captured a release directory before this original return.
    need(recorded != "captured-release-all5" or case is None or case == "noop-stale", label)
    return value


def _file_filter_context(value, *, complete=False):
    label = "project-field-preparation-data"
    if value is None:
        need(not complete, label)
        return None
    need(type(value) is dict and set(value) == {"facts", "allowedTypes", "allowsOther"}, label)
    flags = value["facts"]
    need(type(flags) is int and flags in (1, 3, 7, 11, 23, 27, 55, 59), label)
    expected_types = "unrestricted" if flags & 4 else "restricted" if flags & 8 else None
    expected_other = bool(flags & 32) if flags & 16 else None
    need(value["allowedTypes"] == expected_types and value["allowsOther"] is expected_other
         and (not complete or flags in (23, 27, 55, 59)), label)
    return value


def _field_preparation_context(value, case, step):
    if value is None:
        return None
    try:
        need(case == PROJECT_FIELDS_CASE and type(value) is dict
             and set(value) in ({"operationId", "kind", "returned", "result", "facts"},
                                {"operationId", "kind", "returned", "result", "facts", "nameFieldPreparation"},
                                {"operationId", "kind", "returned", "result", "facts", "nameFieldPreparation", "fileFilter"}),
             "project-field-preparation-data")
        identifier = value["operationId"]
        need(type(identifier) is int and 2 <= identifier <= 11
             and value["kind"] == PROJECT_FIELD_CHOICES[identifier - 2][1] and value["returned"] is True
             and step in (f"ProjectFields(Native({identifier - 2}))", f"ProjectFields(Chosen({identifier - 2}))")
             and type(value["result"]) is str and value["result"] in (
                 "ok", "permission-denied", "io", "invalid-input", "would-block", "already", "invalid-return"),
             "project-field-preparation-data")
        flags = value["facts"]
        need(flags is None or type(flags) is int and 0 <= flags <= 8191
             and (flags == 0 or flags & 257 == 257) and (not flags & 512 or flags & 511 == 511)
             and (not flags & 1024 or flags & 512) and (not flags & 2048 or flags & 1024)
             and (value["result"] != "would-block" or flags == 0), "project-field-preparation-data")
        if "fileFilter" in value:
            if value["kind"] == "version-source":
                _file_filter_context(value["fileFilter"])
                need(value["fileFilter"] is None or flags is not None and flags & 511 == 511, "project-field-preparation-data")
            else:
                need(value["fileFilter"] is None, "project-field-preparation-data")
        if "nameFieldPreparation" in value:
            # The new shape retains navigation and name as distinct returns.
            # Historical five-key8191 frames stay historical; never relabel one.
            need(flags is None or not flags & 2048, "project-field-preparation-data")
            name = value["nameFieldPreparation"]
            if name is not None:
                need(value["kind"] == "version-source" and identifier != 6
                     and value["result"] == "ok" and flags == 6143
                     and type(name) is dict and set(name) == {"returned", "result", "facts"}
                     and name["returned"] is True and type(name["result"]) is str
                     and name["result"] in ("ok", "permission-denied", "io", "invalid-input",
                                            "would-block", "already", "invalid-return"),
                     "project-field-preparation-data")
                name_flags = name["facts"]
                need(name_flags is None or type(name_flags) is int and 0 <= name_flags <= 31
                     and (name_flags == 0 or name_flags & 1)
                     and (not name_flags & 4 or name_flags & 3 == 3)
                     and (not name_flags & 8 or name_flags & 4), "project-field-preparation-data")
                need(name["result"] != "would-block" or name_flags is None, "project-field-preparation-data")
        return value
    except (Refused, KeyError, TypeError):
        return None  # Diagnostic loss cannot become success or replace failure.


DOM_CHOOSER_REASONS = frozenset((
    "none loading selection-pending offline-preflight android-build ios-archive project-recovery "
    "github-preflight github-release project-path version-edit metadata-images shutdown native-selection other"
).split())


def _dom_failure_context(value, source):
    # Only the current Record's retained original callback DATA. This optional
    # field has no authority to settle a callback, native call, or invocation.
    need(source == "record" and type(value) is dict
         and set(value) == {"evaluations", "lastProjectChooser"}, "failure-context")
    count = value["evaluations"]
    need(type(count) is int and 0 <= count <= 160, "failure-context")
    sample = value["lastProjectChooser"]
    if sample is None:
        return value
    need(type(sample) is dict and set(sample) == {
        "step", "sequence", "dashboardSelected", "buttonDisabled", "reason"}, "failure-context")
    need(type(sample["step"]) is str and sample["step"] in ("ChooseCancel", "ChooseProject")
         and type(sample["sequence"]) is int and 1 <= sample["sequence"] <= count
         and type(sample["dashboardSelected"]) is bool
         and (sample["buttonDisabled"] is None or type(sample["buttonDisabled"]) is bool)
         and type(sample["reason"]) is str and sample["reason"] in DOM_CHOOSER_REASONS, "failure-context")
    need((sample["dashboardSelected"] or sample["buttonDisabled"] is None and sample["reason"] == "none")
         and (sample["buttonDisabled"] is not False or sample["reason"] == "none"), "failure-context")
    return value


def _bootstrap_failure_context(value, source, step, reason):
    # Only these nested facts were retained by the first CAS winner while
    # holding the original Record guard. No other context becomes first-time
    # DATA, and unavailable facts are never filled from later Record snapshots.
    flags = {"attached", "initialNavigation", "started", "loaded", "info", "catalog", "capability",
             "reloadRequested", "reloadNavigation", "lossSeen"}
    need(source == "record" and step in FAILURE_STEPS and reason in BOOTSTRAP_FAILURE_REASONS
         and type(value) is dict and set(value) == flags | {"source", "step", "methods", "originalWindowAdmitted"}
         and value["source"] == "first-failure-record"
         and type(value["step"]) is str and value["step"] in FAILURE_STEPS
         and all(type(value[key]) is bool for key in flags), "failure-context")
    count, admitted = value["methods"], value["originalWindowAdmitted"]
    need(type(count) is int and 0 <= count <= 64 and (admitted is None or type(admitted) is bool)
         and (14 <= count if value["info"] else count == 0)
         and (not value["loaded"] or value["started"])
         and (not value["catalog"] or value["info"])
         and (not value["reloadNavigation"] or value["reloadRequested"] and value["loaded"])
         and (not value["lossSeen"] or value["reloadRequested"] and value["loaded"]), "failure-context")
    return value


def _vault_original_failure_data(value):
    """Closed partial original facts, deliberately NOT helper-success validation."""
    flags = {"go", "requestSent", "writeAttempted", "stopAttempted", "stopSent", "notice", "terminal",
             "successfulAddTerminal", "terminalSuccess", "outputFailed", "stderrSeen", "tryWaitEntered",
             "tryWaitReturned", "waitEntered", "exitObserved", "waitFailed", "killAttempted", "killFailed",
             "stdoutEof", "stderrEof", "helperSlotsSettled", "driverReturned", "driverBeforeCleanup",
             "helperGateAcquired", "helperGateSpawnEntered", "helperGatePostchecked", "helperGateClosed", "helperGateUnknown",
             "blockingChildJoined", "resourcesSettled", "allocationsReleased", "cleanupContracted", "cleanupUnknown",
             "applicationCandidateConstructed", "applicationCandidateTaken", "applicationCallbackReturned"}
    nullable = {"authSettled", "filesystemSettled", "nativeInputClosed", "addSettled", "lookupSettled",
                "addItemCallsAbsent", "addPrerequisiteRefused", "nativeCandidateConsumed", "exitSuccess"}
    need(type(value) is dict and set(value) == flags | nullable | {"addEffect", "addOutcome", "firstFailure", "pipeClosed"}
         and all(type(value[k]) is bool for k in flags)
         and all(value[k] is None or type(value[k]) is bool for k in nullable), "failure-context")
    need(type(value["addEffect"]) is int and 0 <= value["addEffect"] < 2**32
         and type(value["pipeClosed"]) is list and len(value["pipeClosed"]) == 3
         and all(type(v) is bool for v in value["pipeClosed"]), "failure-context")
    outcomes = {"pending", "added", "candidate", "missing", "duplicate", "locked", "interaction-required",
                "authentication-failed", "user-canceled", "unavailable", "unsupported", "invalid-input", "invalid-result",
                "allocation", "stopped", "custody-unknown", "native-failure", "native-exception"}
    problems = {"interrupted", "cleanup-unknown", "capacity", "locked", "missing-key", "denied", "unsupported-provider",
                "unavailable", "invalid-input", "identity-mismatch", "crypto", "protocol"}
    for key, vocabulary in (("addOutcome", outcomes), ("firstFailure", problems)):
        need(value[key] is None or type(value[key]) is str and value[key] in vocabulary, "failure-context")
    # Do not invent consistency/finality out of a partial native observation.
    # The unchanged successful-result parser separately requires real joins,
    # EOF/close/terminal evidence and original application consumption.
    return value


def _vault_failure_context(value, source, step, reason, case):
    need(source == "record" and case in VAULT_HELPER_CASES and reason == "vault-finality-contract"
         and type(step) is str and step in FAILURE_STEPS and step.startswith("Vault(")
         and type(value) is dict and set(value) == {"source", "step", "observationOnly", "snapshot"}
         and value["source"] == "first-original-vault-snapshot" and value["step"] == step
         and value["observationOnly"] is True, "failure-context")
    snapshot = value["snapshot"]
    flags = {"unknown", "originalsSettled", "empty", "documentUnknown", "exhausted", "lostObserved", "originalBound",
             "keyPresent", "initializePreview", "previewConsumed"}
    fields = {"originals", "operationId", "operationPhase", "operationReason", "operationSettlement",
              "state", "storage", "initialize", "lookup", "initializeTransport", "lookupTransport"}
    need(type(snapshot) is dict and set(snapshot) == flags | fields
         and all(type(snapshot[k]) is bool for k in flags) and snapshot["unknown"]
         and snapshot["unknown"] == (snapshot["documentUnknown"] or snapshot["exhausted"] or snapshot["lostObserved"] or not snapshot["originalBound"])
         and type(snapshot["originals"]) is int and 0 <= snapshot["originals"] <= (7 if case == VAULT_HELPER_CASES[0] else 5), "failure-context")
    phases = {"idle", "admitting", "picking", "capturing", "selected", "assessing", "preview", "mutating", "stopping", "unknown"}
    reasons = {"none", "closed", "unqualified", "unsupported-platform", "unsupported-filesystem", "unsupported-format",
               "invalid-request", "busy", "source-refused", "source-changed", "material-limit", "parser-limit", "project-overlap",
               "exclusion-unconfirmed", "capacity", "context-stale", "user-cancelled", "review-expired", "deadline", "document-lost",
               "shutdown", "cleanup-unknown", "vault-uninitialized", "vault-key-missing", "vault-keyring-locked", "vault-keyring-denied",
               "vault-keyring-unavailable", "vault-provider-unsupported", "vault-corrupt", "vault-interrupted", "vault-durability-unknown"}
    for key, vocabulary in (("operationPhase", phases), ("operationReason", reasons),
                             ("operationSettlement", {"pending", "known", "unknown", "late-known"}),
                             ("state", {"uninitialized", "locked", "unlocked", "initializing", "mutating", "interrupted", "unknown"})):
        need(snapshot[key] is None or type(snapshot[key]) is str and snapshot[key] in vocabulary, "failure-context")
    identifier = snapshot["operationId"]
    operation_fields = (snapshot[k] for k in ("operationPhase", "operationReason", "operationSettlement"))
    need((identifier is None and all(v is None for v in operation_fields))
         or (type(identifier) is int and 1 <= identifier <= snapshot["originals"] and all(v is not None for v in operation_fields)), "failure-context")
    storage = snapshot["storage"]
    if storage is not None:
        need(type(storage) is dict and set(storage) == {"reservation", "header", "durability"}
             and all(type(v) is list and len(v) == 2 and all(type(b) is bool for b in v) for v in storage.values()), "failure-context")
    for key in ("initialize", "lookup"):
        if snapshot[key] is not None:
            _vault_original_failure_data(snapshot[key])
        transport = snapshot[key + "Transport"]
        if transport is not None:
            need(type(transport) is dict and set(transport) == {"exitCode", "exitSignal", "responseBytes"}, "failure-context")
            code, signal, count = (transport[k] for k in ("exitCode", "exitSignal", "responseBytes"))
            need((code is None or type(code) is int and 0 <= code <= 255)
                 and (signal is None or type(signal) is int and 1 <= signal <= 127)
                 and (code is None or signal is None)
                 and type(count) is int and 0 <= count <= 16385, "failure-context")
            # Returned process facts do not establish native terminal/finality.
    return value


def failure_context(stdout, stderr, case=None):
    row = _failure_row(stdout, stderr, b"MRK_MACOS_AQUA_FAILURE_CONTEXT", FAILURE_CONTEXT_LIMIT)
    if row is None:
        return None
    try:
        value = json.loads(row.decode("ascii"), object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(Refused("failure-context")))
        need(type(value) is dict and set(value) - {"accessibilityBinding", "snapshotSource", "originalWindow", "projectSelection", "completionSelection", "projectFieldPreparation", "dom", "bootstrap", "vault", "inputBodyAdmission"} in (
            {"pending", "nativeHandler", "lastPanel"},
            {"pending", "nativeHandler", "lastPanel", "nativeAction"},
            {"pending", "nativeHandler", "lastPanel", "nativeAction", "accessibility"}), "failure-context")
        if "snapshotSource" in value:
            need(type(value["snapshotSource"]) is str and value["snapshotSource"] in ("record", "prearm-open-progress", "prearm-open-return"), "failure-context")
        returned_input = value.get("snapshotSource") == "prearm-open-return"
        need(("inputBodyAdmission" in value) == returned_input, "failure-context")
        if returned_input:
            need(value["inputBodyAdmission"] is None or type(value["inputBodyAdmission"]) is bool, "failure-context")
        if "dom" in value:
            value["dom"] = _dom_failure_context(value["dom"], value.get("snapshotSource"))
        if "bootstrap" in value:
            value["bootstrap"] = _bootstrap_failure_context(value["bootstrap"], value.get("snapshotSource"),
                                                            failure_step(stdout, stderr), failure_reason(stdout, stderr))
        if "vault" in value:
            value["vault"] = _vault_failure_context(value["vault"], value.get("snapshotSource"),
                                                    failure_step(stdout, stderr), failure_reason(stdout, stderr), case)
        if "originalWindow" in value:
            value["originalWindow"] = _original_window_context(value["originalWindow"])
        if "projectSelection" in value:
            value["projectSelection"] = _project_selection_context(value["projectSelection"], value.get("snapshotSource"),
                failure_step(stdout, stderr), failure_reason(stdout, stderr), case)
        if "completionSelection" in value:
            # Only the saved original Record can carry this post-poll sample.
            # No native handler/Press receipt is invented to fill missing DATA.
            value["completionSelection"] = (_completion_selection_context(value["completionSelection"], case, allow_files=True)
                                             if value.get("snapshotSource") == "record" else None)
        if "projectFieldPreparation" in value:
            value["projectFieldPreparation"] = _field_preparation_context(value["projectFieldPreparation"], case, failure_step(stdout, stderr))
        pending, native, panel = value["pending"], value["nativeHandler"], value["lastPanel"]
        file_panels, field_panels = _file_native_panels(case), _field_native_panels(case)
        native_steps = {"Quit"} if case == INSTALLATION_INSPECTION_CASE else NATIVE_STEPS | file_panels.keys() | field_panels.keys()
        if pending is not None:
            need(type(pending) is dict and set(pending) == {"kind", "step"}
                 and type(pending["kind"]) is str, "failure-context")
            kind, step = pending["kind"], pending["step"]
            allowed = {"dom": FAILURE_STEPS, "native": native_steps,
                       "accessibility": {"OpenProject"} | {step for step, (identifier, _) in field_panels.items() if identifier not in (6, 7)},
                       "close": {"Close", "CloseCancel"}}
            need(kind in ("reload", "failure-close") and step is None
                 or kind in allowed and type(step) is str and step in allowed[kind], "failure-context")
        if native is not None:
            need(type(native) is dict and set(native) == {"step", "entered", "returned"}
                 and type(native["step"]) is str and native["step"] in native_steps
                 and type(native["entered"]) is bool and type(native["returned"]) is bool
                 and (not native["returned"] or native["entered"]), "failure-context")
        if panel is not None:
            panel_keys = {"step", "id", "kind", "parentPresent", "panelPresent",
                          "parentReferencesPanel", "panelReferencesParent", "panelVisible"}
            readiness_keys = {"directoryBound", "directoryReturned", "directoryReady", "directoryReadiness", "waitLocation"}
            # Historical frames remain historical: accept either the old exact
            # shape or the complete new sample, never synthesize missing values.
            need(type(panel) is dict and set(panel) in (panel_keys, panel_keys | readiness_keys)
                 and native is not None and native["entered"] and panel["step"] == native["step"]
                 and type(panel["id"]) is int and type(panel["kind"]) is str
                 and type(panel["parentPresent"]) is bool and type(panel["panelPresent"]) is bool, "failure-context")
            if case == INSTALLATION_INSPECTION_CASE:
                need((panel["step"], panel["id"], panel["kind"]) == ("Quit", 3, "quit"), "failure-context")
            elif panel["kind"] in {choice[1] for choice in PROJECT_FIELD_CHOICES} or panel["step"] in field_panels:
                need(panel["step"] in field_panels and (panel["id"], panel["kind"]) == field_panels[panel["step"]], "failure-context")
            elif panel["kind"] == "file" or panel["step"] in file_panels:
                need(panel["kind"] == "file" and panel["step"] in file_panels
                     and panel["id"] == file_panels[panel["step"]], "failure-context")
            elif panel["step"] == "Quit" and type(case) is str and (case in SESSION_CASES or case == PROJECT_FIELDS_CASE):
                need(panel["kind"] == "quit" and panel["id"] == (18 if case == ANDROID_INPUT_CASE else 12), "failure-context")
            else:
                need(1 <= panel["id"] <= 4 and panel["kind"] in ("project", "quit"), "failure-context")
            both = panel["parentPresent"] and panel["panelPresent"]
            need(all(type(panel[key]) is bool if both else panel[key] is None
                     for key in ("parentReferencesPanel", "panelReferencesParent"))
                 and (type(panel["panelVisible"]) is bool if panel["panelPresent"] else panel["panelVisible"] is None),
                 "failure-context")
            if "directoryReadiness" in panel:
                # Current VersionSource checks actual selection. Retain the old
                # filename token as historical failure DATA, not qualification.
                readiness = panel["directoryReadiness"]
                need(all(type(panel[key]) is bool for key in ("directoryBound", "directoryReturned", "directoryReady"))
                     and type(readiness) is str
                     and readiness in {"not-ready", "directory-not-matched", "filename-not-matched", "selection-not-matched", "ready"}
                     and panel["directoryReady"] == (readiness == "ready")
                     and (readiness == "not-ready" or panel["directoryBound"] and panel["directoryReturned"] and panel["panelPresent"])
                     and (readiness != "filename-not-matched" or panel["kind"] in ("file", "version-source"))
                     and (readiness != "selection-not-matched" or panel["kind"] == "version-source")
                     and (panel["kind"] != "quit" or readiness == "not-ready"), "failure-context")
                wait = panel["waitLocation"]
                need(wait is None or type(wait) is str and wait == "open-directory-readiness", "failure-context")
                if wait is not None:
                    open_step = _field_open_step(case, panel["id"]) or _file_open_step(case, panel["id"])
                    need(value.get("snapshotSource") == "record" and native["returned"]
                         and (panel["step"] == open_step or panel["step"] == "OpenProject" and panel["kind"] == "project")
                         and not all(panel[key] for key in ("directoryBound", "directoryReturned", "directoryReady")),
                         "failure-context")
        if "nativeAction" in value:
            value["nativeAction"] = _native_action_context(value["nativeAction"], native, panel, case=case)
        if "accessibility" in value:
            value["accessibility"] = _accessibility_context(value["accessibility"], native, panel, case=case, historical=True,
                                                          allow_press_diagnostic=True)
        if value.get("snapshotSource") == "prearm-open-progress":
            sample = value.get("accessibility")
            field_step = _field_open_step(case, sample["id"]) if sample is not None else None
            native_step = field_step or (_file_open_step(case, sample["id"]) if sample is not None else None) or "OpenProject"
            # The fixed pre-arm original fields are historical, while only the
            # one atomic progress/expiry sample was refreshed at the deadline.
            need(pending == {"kind": "accessibility", "step": field_step or "OpenProject"}
                 and "projectSelection" not in value and "completionSelection" not in value
                 and native == {"step": native_step, "entered": True, "returned": True}
                 and sample is not None and sample["prepared"] and sample["requested"]
                 and sample["expired"] and sample["timely"] is False
                 and all(sample[key] is None for key in ("nativeEntered", "attempted", "pressReturned", "triggered",
                      "initialOriginalProof", "originalProof", "promptButton", "site", "error"))
                 and sample["promptChecks"] == {"initial": None, "final": None}, "failure-context")
        if "accessibilityBinding" in value:
            # Early start failure legitimately has no nativeHandler/lastPanel
            # or Press sample. Bind to the known case, not to invented actions.
            value["accessibilityBinding"] = _accessibility_binding_context(value["accessibilityBinding"], case, allow_files=True, historical=True)
        if returned_input:
            # Historical pre-arm binding + positively received original body DATA.
            # Neither body admission nor native cleanup establishes worker finality.
            sample, binding = value.get("accessibility"), value.get("accessibilityBinding")
            field_step = _field_open_step(case, sample["id"]) if sample is not None else None
            need(case == "project-fields" and field_step is not None
                 and failure_step(stdout, stderr) == field_step and failure_reason(stdout, stderr) == "native-default-input"
                 and pending == {"kind": "accessibility", "step": field_step}
                 and native == {"step": field_step, "entered": True, "returned": True}
                 and not set(value).intersection(("dom", "bootstrap", "vault", "projectSelection", "completionSelection"))
                 and panel is not None and panel["kind"] == "version-source"
                 and sample is not None and sample["mechanism"] == "accessibility-version-source-selection-press-v8"
                 and sample["prepared"] and sample["requested"] and sample["workerRegistered"]
                 and sample["dispatchAttempted"] and sample["bodyEntered"] is True and sample["bodyReturned"]
                 and sample["nativeEntered"] is True and sample["state"] in ("returned", "unknown")
                 and not sample["receiptJoined"] and not sample["barrierRetired"] and sample["rechecksSettled"] is None
                 and sample["timely"] is (False if sample["expired"] else None)
                 and sample["promptButton"] is not None and sample["site"] is not None and sample["error"] is not None
                 and (value["inputBodyAdmission"] is not None or sample["custodyKnown"] is False)
                 and (sample["error"] != "none" or value["inputBodyAdmission"] is not True)
                 and binding is not None and binding["case"] == case and binding["id"] == sample["id"]
                 and binding["kind"] == "version-source" and binding["mechanism"] == "selection-parent-original-sheet-v3"
                 and binding["start"] == {"returned": True, "result": "ok"}
                 and binding["configuration"]["site"] == "complete" and binding["configuration"]["error"] == "none"
                 and binding["binding"] is not None and binding["binding"]["purpose"] == "selection-parent"
                 and binding["binding"]["error"] == "none" and all(binding["binding"]["checks"].values()), "failure-context")
        return value
    except (Refused, ValueError, RecursionError, UnicodeError, TypeError):
        return None


_BOOTSTRAP_DIAGNOSTIC_ORIGINS = ("admission", "query-wait")
_BOOTSTRAP_DIAGNOSTIC_CODES = (
    "runtime_unavailable", "cleanup_unknown", "invalid_request", "shutting_down", "busy", "unavailable",
    "offline_preflight_busy", "android_build_busy", "environment_diagnostics_busy", "query_timeout",
    "protocol_error", "engine_failed", "io_error", "output_limit", "other",
)
_BOOTSTRAP_DIAGNOSTIC_LINES = {
    ("MRKDBG_DESKTOP_BOOTSTRAP=capabilities-" + origin + "-" + code + "\n").encode("ascii"): (origin, code)
    for origin in _BOOTSTRAP_DIAGNOSTIC_ORIGINS for code in _BOOTSTRAP_DIAGNOSTIC_CODES
}
_BOOTSTRAP_DIAGNOSTIC_LINE_LIMIT = max(len(line) for line in _BOOTSTRAP_DIAGNOSTIC_LINES)
# Exact macOS shell context, never capability, trust, completion or finality evidence.
# Linux-only hook/content/cause tags intentionally remain unknown.
_BOOTSTRAP_INFORMATIONAL_LINES = (
    b"MRKDBG_DESKTOP_BOOTSTRAP=app-info-enter\n",
    b"MRKDBG_DESKTOP_BOOTSTRAP=catalog-enter\n",
    b"MRKDBG_DESKTOP_BOOTSTRAP=setup-enter\n",
    b"MRKDBG_DESKTOP_BOOTSTRAP=page-start-trusted\n",
    b"MRKDBG_DESKTOP_BOOTSTRAP=page-start-untrusted\n",
    b"MRKDBG_DESKTOP_BOOTSTRAP=page-finish-trusted\n",
    b"MRKDBG_DESKTOP_BOOTSTRAP=page-finish-untrusted\n",
)


def _inner_bootstrap_diagnostic(stdout, stderr):
    """One finite stderr fact, never raw output, first-CAS, EOF or finality."""
    try:
        if (type(stdout) is not bytes or type(stderr) is not bytes
                or len(stdout) + len(stderr) > OUTPUT_LIMIT):
            return None
        namespace = b"MRKDBG_DESKTOP_BOOTSTRAP"
        # A truncated namespace at the available tail is still ambiguous,
        # even when embedded/prefixed. Do not salvage a preceding valid row.
        if any(stderr.endswith(namespace[:length]) for length in range(1, len(namespace))):
            return None
        cursor, selected = 0, None
        while cursor < len(stderr):
            start = stderr.find(namespace, cursor)
            if start < 0:
                break
            # Even an embedded/malformed occurrence makes the candidate
            # ambiguous. Do not salvage a valid row beside a partial one.
            if start and stderr[start - 1] != 10:
                return None
            end = stderr.find(b"\n", start, min(len(stderr), start + _BOOTSTRAP_DIAGNOSTIC_LINE_LIMIT))
            if end < 0:
                return None
            line = stderr[start:end + 1]
            cursor = end + 1
            if line in _BOOTSTRAP_INFORMATIONAL_LINES:
                continue
            found = _BOOTSTRAP_DIAGNOSTIC_LINES.get(line)
            if found is None or selected is not None:
                return None  # Unknown, duplicate-identical, or conflicting.
            selected = found
        return {"origin": selected[0], "code": selected[1]} if selected is not None else None
    except BaseException:
        return None  # Optional diagnostic loss cannot replace the original.


def _original_exception_diagnostics(error, run_owned, case, cwd):
    """Private CI/source-pin seam: reduce only the original call's buffers.

    No import, engine method, cause traversal, outcome/finality query or raw
    output escape. Missing/changed owner contracts fail closed. The source is
    pinned by load_owner before this callable can be the original owner.
    """
    try:
        if type(case) is not str or case not in ALL_CASES:
            return None
        argv = (EXECUTABLE, case)  # Do not trust the mutable list supplied to the call.
        source = Path(__file__).absolute().parents[2] / "src" / "mobile_release"
        modules = []
        for name in ("owned_process", "_command_process"):
            module = sys.modules.get("mobile_release." + name)
            if type(module) is not ModuleType:
                return None
            namespace = vars(module)
            expected = str(source / (name + ".py"))
            spec = namespace.get("__spec__")
            if (namespace.get("__name__") != "mobile_release." + name
                    or namespace.get("__file__") != expected or type(spec) is not ModuleSpec or spec.origin != expected):
                return None
            modules.append(namespace)
        owner, command = modules
        function = command.get("run_command")
        if (type(run_owned) is not FunctionType or owner.get("run_owned") is not run_owned
                or run_owned.__globals__ is not owner or run_owned.__code__.co_filename != owner["__file__"]
                or type(function) is not FunctionType or function.__globals__ is not command
                or function.__code__.co_filename != command["__file__"]):
            return None
        original = None
        trace = error.__traceback__
        for _ in range(TRACEBACK_LIMIT):
            if trace is None:
                break
            frame = trace.tb_frame
            if frame.f_code is function.__code__:
                if frame.f_globals is not command or original is not None and frame is not original:
                    return None
                original = frame  # Re-raising can repeat this identical frame.
            trace = trace.tb_next
        if trace is not None or original is None:
            return None
        local = original.f_locals  # Python 3.14 can supply FrameLocalsProxy.
        engine = local.get("engine")
        if type(engine) is not command.get("_Outer"):
            return None
        actual = local.get("argv")
        if (type(actual) is not list or len(actual) != 2 or any(type(arg) is not str for arg in actual)
                or tuple(actual) != argv or type(local.get("cwd")) is not type(cwd) or local["cwd"] != cwd
                or type(local.get("timeout")) is not int or local["timeout"] != case_timeout(case)
                or local.get("capture") is not True or local.get("text") is not False
                or type(local.get("output_limit")) is not int or local["output_limit"] != OUTPUT_LIMIT):
            return None
        frozen = engine.frozen
        if type(frozen) is not command.get("FrozenCommand") or type(frozen.manifest) is not command.get("Manifest"):
            return None
        if (type(frozen.args) is not tuple or len(frozen.args) != 2
                or any(type(arg) is not str for arg in frozen.args) or frozen.args != argv
                or type(frozen.argv) is not tuple or len(frozen.argv) != 2 or any(type(arg) is not bytes for arg in frozen.argv)
                or frozen.argv != tuple(arg.encode("ascii") for arg in argv)
                or type(frozen.cwd) is not bytes or frozen.cwd != str(cwd).encode("ascii")
                or frozen.manifest.capture is not True or type(frozen.manifest.limit) is not int
                or frozen.manifest.limit != OUTPUT_LIMIT or engine.text is not False):
            return None
        outputs = engine.outputs
        if (type(outputs) is not list or len(outputs) != 2 or any(type(part) is not bytearray for part in outputs)
                or len(outputs[0]) + len(outputs[1]) > OUTPUT_LIMIT):
            return None
        stdout, stderr = bytes(outputs[0]), bytes(outputs[1])
        # The copies are immediately reduced; none is retained/exported by the
        # caller. Buffer availability never means EOF or original finality.
        reduced = (failure_step(stdout, stderr), failure_reason(stdout, stderr), failure_context(stdout, stderr, case),
                   _inner_bootstrap_diagnostic(stdout, stderr))
        return reduced if any(part is not None for part in reduced) else None
    except BaseException:
        return None  # Extraction must never mask the original invocation error.


@dataclass(frozen=True)
class Node:
    # dev, inode, complete mode, uid, gid, nlink, size, mtime_ns, ctime_ns.
    identity: tuple
    sha256: str | None
    entries: tuple | None


def signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


# Closed synthetic fixture bytes. The workflow strings are literal replacements
# in the authenticated shipped github-setup-v1.json; they are NOT generated by
# importing the core during qualification, and no workflow is dispatched.
LOCAL_WORKFLOW_RESOURCE_SHA256 = "6fa1f3b7dd1907f56af44ccf050458626d702ec0a06e5578a7416986c46ad29a"
LOCAL_STALE = b"# MRK local workflow original changed\n"
LOCAL_VERSION_BEFORE = b"# Public local edit fixture\n  VERSION_NAME = 1.2.3  \nBUILD_NUMBER=7\nUNRELATED = keep-this-value\n"
LOCAL_VERSION_AFTER = b"# Public local edit fixture\n  VERSION_NAME = 2.3.4  \nBUILD_NUMBER=8\nUNRELATED = keep-this-value\n"
LOCAL_TEXT_FIELDS = (
    ("android", "title.txt", b"Public title", b"Public title"),
    ("android", "short_description.txt", b"Old summary", b"Public summary"),
    ("android", "full_description.txt", None, b"Public description"),
    ("ios", "description.txt", b"Old iOS description", b"Public iOS description"),
    ("ios", "keywords.txt", b"public,example", b"public,example"),
    ("ios", "privacy_url.txt", b"https://example.com/privacy", b"https://example.com/privacy"),
    ("ios", "support_url.txt", b"https://example.com/support", b"https://example.com/support"),
    ("ios", "release_notes.txt", None, b"Public release notes"),
)
LOCAL_WORKFLOWS = {
    '.github/workflows/mobile-preflight.yml': b"name: Mobile release preflight\nrun-name: ${{ inputs.desktop_request != '' && format('MRK Desktop preflight [{0}]', inputs.desktop_request) || 'Mobile release preflight' }}\n\non:\n  workflow_dispatch:\n    inputs:\n      platform:\n        description: Platform to validate\n        required: true\n        default: both\n        type: choice\n        options:\n          - android\n          - ios\n          - both\n      desktop_request:\n        description: Optional Desktop request marker; use with the reviewed source and full ref.\n        required: false\n        default: ''\n        type: string\n      desktop_source_sha:\n        description: Optional Desktop-reviewed application commit (40 lowercase hexadecimal characters).\n        required: false\n        default: ''\n        type: string\n      desktop_expected_ref:\n        description: Optional Desktop-reviewed full branch ref, for example refs/heads/main.\n        required: false\n        default: ''\n        type: string\n\npermissions:\n  contents: read\n\njobs:\n  preflight:\n    uses: example/toolkit/.github/workflows/reusable-preflight.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n    with:\n      tooling_sha: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n      source_sha: ${{ inputs.desktop_source_sha || github.sha }}\n      platform: ${{ inputs.platform }}\n      desktop_request: ${{ inputs.desktop_request }}\n      desktop_source_sha: ${{ inputs.desktop_source_sha }}\n      desktop_expected_ref: ${{ inputs.desktop_expected_ref }}\n",
    '.github/workflows/mobile-candidate.yml': b"name: Mobile internal candidate\nrun-name: ${{ inputs.desktop_request != '' && format('MRK Desktop candidate [{0}]', inputs.desktop_request) || 'Mobile internal candidate' }}\non:\n  workflow_dispatch:\n    inputs:\n      platform:\n        description: Platform to build once and upload to internal testing\n        required: true\n        type: choice\n        options:\n        - android\n        - ios\n        - both\n      confirmation:\n        description: candidate:<platform>:<version>:<build>\n        required: true\n        type: string\n      recovery_run_id:\n        description: Run holding the original intent or selected complete final; never replaces authorization.\n        required: false\n        default: ''\n        type: string\n      recovery_confirmation:\n        description: Exact additional iOS recovery confirmation, only when requested by reconciliation.\n        required: false\n        default: ''\n        type: string\n      desktop_request:\n        description: Optional exact Desktop request marker; use with reviewed source and full ref.\n        required: false\n        default: ''\n        type: string\n      desktop_source_sha:\n        description: Optional Desktop-reviewed current dispatch commit; not a replacement for original recovery source.\n        required: false\n        default: ''\n        type: string\n      desktop_expected_ref:\n        description: Optional Desktop-reviewed full branch ref; all three Desktop inputs must be supplied together.\n        required: false\n        default: ''\n        type: string\npermissions: {}\njobs:\n  candidate:\n    permissions:\n      actions: read\n      artifact-metadata: write\n      attestations: write\n      contents: read\n      id-token: write\n    uses: example/toolkit/.github/workflows/reusable-candidate.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n    with:\n      tooling_sha: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n      source_sha: ${{ github.sha }}\n      platform: ${{ inputs.platform }}\n      confirmation: ${{ inputs.confirmation }}\n      recovery_run_id: ${{ inputs.recovery_run_id }}\n      recovery_confirmation: ${{ inputs.recovery_confirmation }}\n      desktop_request: ${{ inputs.desktop_request }}\n      desktop_source_sha: ${{ inputs.desktop_source_sha }}\n      desktop_expected_ref: ${{ inputs.desktop_expected_ref }}\n",
    '.github/workflows/mobile-external-testing.yml': b"name: Mobile external testing\nrun-name: ${{ inputs.desktop_request != '' && format('MRK Desktop external-testing [{0}]', inputs.desktop_request) || 'Mobile external testing' }}\non:\n  workflow_dispatch:\n    inputs:\n      platform:\n        description: Platform whose exact internal build should be promoted\n        required: true\n        type: choice\n        options:\n        - android\n        - ios\n        - both\n      candidate_run_id:\n        description: Common candidate evidence run; leave blank for per-platform or preserved recovery inputs.\n        required: false\n        default: ''\n        type: string\n      confirmation:\n        description: external-testing:<platform>:<version>:<build>\n        required: true\n        type: string\n      recovery_run_id:\n        description: Run holding the original intent or selected complete final; never replaces authorization.\n        required: false\n        default: ''\n        type: string\n      recovery_confirmation:\n        description: Exact additional iOS recovery confirmation, only when requested by reconciliation.\n        required: false\n        default: ''\n        type: string\n      candidate_android_run_id:\n        description: android candidate evidence run; cannot conflict with a common run.\n        required: false\n        default: ''\n        type: string\n      candidate_ios_run_id:\n        description: ios candidate evidence run; cannot conflict with a common run.\n        required: false\n        default: ''\n        type: string\n      desktop_request:\n        description: Optional exact Desktop request marker; use with reviewed source and full ref.\n        required: false\n        default: ''\n        type: string\n      desktop_source_sha:\n        description: Optional Desktop-reviewed current dispatch commit; not a replacement for original recovery source.\n        required: false\n        default: ''\n        type: string\n      desktop_expected_ref:\n        description: Optional Desktop-reviewed full branch ref; all three Desktop inputs must be supplied together.\n        required: false\n        default: ''\n        type: string\npermissions: {}\njobs:\n  external-testing:\n    permissions:\n      actions: read\n      artifact-metadata: write\n      attestations: write\n      contents: read\n      id-token: write\n    uses: example/toolkit/.github/workflows/reusable-external-testing.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n    with:\n      tooling_sha: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n      source_sha: ${{ github.sha }}\n      platform: ${{ inputs.platform }}\n      candidate_run_id: ${{ inputs.candidate_run_id }}\n      confirmation: ${{ inputs.confirmation }}\n      recovery_run_id: ${{ inputs.recovery_run_id }}\n      recovery_confirmation: ${{ inputs.recovery_confirmation }}\n      candidate_android_run_id: ${{ inputs.candidate_android_run_id }}\n      candidate_ios_run_id: ${{ inputs.candidate_ios_run_id }}\n      desktop_request: ${{ inputs.desktop_request }}\n      desktop_source_sha: ${{ inputs.desktop_source_sha }}\n      desktop_expected_ref: ${{ inputs.desktop_expected_ref }}\n",
    '.github/workflows/mobile-production-submit.yml': b"name: Mobile production submission\nrun-name: ${{ inputs.desktop_request != '' && format('MRK Desktop production-submit [{0}]', inputs.desktop_request) || 'Mobile production submission' }}\non:\n  workflow_dispatch:\n    inputs:\n      platform:\n        description: Exactly one platform to prepare for production review\n        required: true\n        type: choice\n        options:\n        - android\n        - ios\n      candidate_run_id:\n        description: Common candidate evidence run; leave blank for per-platform or preserved recovery inputs.\n        required: false\n        default: ''\n        type: string\n      external_run_id:\n        description: Common external evidence run; leave blank for per-platform or preserved recovery inputs.\n        required: false\n        default: ''\n        type: string\n      confirmation:\n        description: production-submit:<platform>:<version>:<build>\n        required: true\n        type: string\n      recovery_run_id:\n        description: Run holding the original intent or selected complete final; never replaces authorization.\n        required: false\n        default: ''\n        type: string\n      recovery_confirmation:\n        description: Exact additional iOS recovery confirmation, only when requested by reconciliation.\n        required: false\n        default: ''\n        type: string\n      candidate_android_run_id:\n        description: android candidate evidence run; cannot conflict with a common run.\n        required: false\n        default: ''\n        type: string\n      candidate_ios_run_id:\n        description: ios candidate evidence run; cannot conflict with a common run.\n        required: false\n        default: ''\n        type: string\n      external_android_run_id:\n        description: android external evidence run; cannot conflict with a common run.\n        required: false\n        default: ''\n        type: string\n      external_ios_run_id:\n        description: ios external evidence run; cannot conflict with a common run.\n        required: false\n        default: ''\n        type: string\n      desktop_request:\n        description: Optional exact Desktop request marker; use with reviewed source and full ref.\n        required: false\n        default: ''\n        type: string\n      desktop_source_sha:\n        description: Optional Desktop-reviewed current dispatch commit; not a replacement for original recovery source.\n        required: false\n        default: ''\n        type: string\n      desktop_expected_ref:\n        description: Optional Desktop-reviewed full branch ref; all three Desktop inputs must be supplied together.\n        required: false\n        default: ''\n        type: string\npermissions: {}\njobs:\n  production-submit:\n    permissions:\n      actions: read\n      artifact-metadata: write\n      attestations: write\n      contents: read\n      id-token: write\n    uses: example/toolkit/.github/workflows/reusable-production-submit.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n    with:\n      tooling_sha: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n      source_sha: ${{ github.sha }}\n      platform: ${{ inputs.platform }}\n      candidate_run_id: ${{ inputs.candidate_run_id }}\n      external_run_id: ${{ inputs.external_run_id }}\n      confirmation: ${{ inputs.confirmation }}\n      recovery_run_id: ${{ inputs.recovery_run_id }}\n      recovery_confirmation: ${{ inputs.recovery_confirmation }}\n      candidate_android_run_id: ${{ inputs.candidate_android_run_id }}\n      candidate_ios_run_id: ${{ inputs.candidate_ios_run_id }}\n      external_android_run_id: ${{ inputs.external_android_run_id }}\n      external_ios_run_id: ${{ inputs.external_ios_run_id }}\n      desktop_request: ${{ inputs.desktop_request }}\n      desktop_source_sha: ${{ inputs.desktop_source_sha }}\n      desktop_expected_ref: ${{ inputs.desktop_expected_ref }}\n",
}


def local_edit_config(case):
    need(type(case) is str and case in LOCAL_EDIT_CASES, "fixture-case")
    if case != "local-metadata-text":
        return CONFIG
    value = json.loads(CONFIG)
    value["ios"] = {"archiveConfiguration": "Release", "bundleId": "org.example.mrk.observed", "enabled": True,
                    "identityStatus": "unverified", "project": "ios/MRKObserved.xcodeproj",
                    "scheme": "MRKObserved", "symbols": {"policy": "retain"}}
    value["metadata"]["iosLocales"] = ["en-US"]
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("ascii")


def local_fixture_data(case, final):
    need(type(case) is str and case in LOCAL_EDIT_CASES and type(final) is bool, "fixture-case")
    files = {".gitignore": IGNORE_PREFIX + IGNORE_RULES, "app/build.gradle.kts": SOURCE, "keep.txt": KEEP,
             "release/mobile-release.json": local_edit_config(case), "version.properties": (
                 LOCAL_VERSION_AFTER if final else LOCAL_VERSION_BEFORE) if case == "local-release-version" else VERSION}
    if case == "local-metadata-text":
        for platform, name, before, after in LOCAL_TEXT_FIELDS:
            body = after if final else before
            if body is not None:
                files[f"release/store/{platform}/en-US/{name}"] = body
        files["release/store/keep.txt"] = KEEP
    if case == "local-github-apply":
        files[".github/workflows/unrelated.yml"] = b"# Retained unrelated workflow; no dispatch\n"
        if final:
            files.update(LOCAL_WORKFLOWS)
            files[".github/workflows/mobile-preflight.yml"] += LOCAL_STALE
    # All ancestors exist before GUI entry; the only directory mutations are
    # the actual transaction's temporary journals, which must be gone on return.
    directories = {".": set()}
    names = list(files)
    if case == "local-metadata-text":
        names += ["release/store/android/en-US/.not-a-file", "release/store/ios/en-US/.not-a-file"]
    for path in names:
        parts = path.split("/")
        for index, name in enumerate(parts):
            parent = "/".join(parts[:index]) or "."
            children = directories.setdefault(parent, set())
            if name != ".not-a-file":
                children.add(name)
    ordered = {path: (0o700, tuple(sorted(directories[path]))) for path in sorted(
        directories, key=lambda value: (0 if value == "." else value.count("/") + 1, value))}
    need(len(files) <= 32 and len(ordered) <= 24 and all(len(row[1]) <= 16 for row in ordered.values())
         and sum(map(len, files.values())) <= 1024 * 1024, "fixture-roster")
    return files, ordered


def _expected_local_edits(case):
    """Comparison DATA only; original native records must match without filling gaps."""
    files, directories = local_fixture_data(case, True)
    workflow = case == "local-github-apply"
    count = 3 if workflow else 2 if case == "local-metadata-text" else 1
    sessions = []
    for index in range(count):
        close, stale = workflow and index == 0, workflow and index == 2
        sessions.append({"apply": not close, "close": close,
            "outcome": {"effect": "not_started" if close or stale else "committed",
                        "journal": "not_created" if close or stale else "clean", "resources": "settled",
                        "reason": "stale_revision" if stale else "cancelled" if close else "none"},
            "writerFrames": 2 if close else 3, "stdoutFrames": 3, "originalsJoined": True, "fileReadback": True})
    return {"case": case, "domain": ("metadata_text", "release_version", "github_workflows")[LOCAL_EDIT_CASES.index(case)],
            "sameOriginalSessions": count, "originalFinalities": True, "visibleReviewAndResult": True,
            "passiveReadbacks": 0 if workflow else count,
            "fixture": {"files": len(files), "directories": len(directories), "completedOriginals": count,
                        "staleAppendReturnedAndClosed": workflow,
                        "sha256": {name: digest(body) for name, body in sorted(files.items())}},
            "sessions": sessions, "controlIntegrationOnly": True, "physicalDropdownGestureQualified": False,
            "imagesDoctorVaultRestartQualified": False}


def fixture_data(case, final, *, ios_output_created=None):
    need(case in ALL_CASES and type(final) is bool, "fixture-case")
    if case in LOCAL_CHECK_CASES:
        need(ios_output_created is None, "fixture-output-kind")
        return local_check_fixture_data(case)
    if case in LOCAL_EDIT_CASES:
        need(ios_output_created is None, "fixture-output-kind")
        return local_fixture_data(case, final)
    if case == RECOVERY_CASE:
        files = {name.removeprefix("project/"): body for name, body in RECOVERY_FILES.items()}
        directories = {".": (0o700, tuple(sorted(files)))}
        if final:
            files["saved-foreign-ios"] = RECOVERY_FOREIGN
            directories["."] = (0o700, tuple(sorted((*files, ".mobile-release"))))
            directories[".mobile-release"] = (0o700, ())
        return files, directories
    if case in IOS_CURRENT_CASES or case == IOS_ACCOUNT_CASE:
        return ios_fixture_data(case, final, output_created=ios_output_created)
    need(ios_output_created is None, "fixture-output-kind")
    if case == ANDROID_INPUT_CASE:
        return {"app/build.gradle.kts": SOURCE, "version.properties": VERSION, "keep.txt": KEEP,
                ".gitignore": IGNORE_PREFIX + b".mobile-release/\n", "release/mobile-release.json": ANDROID_INPUT_CONFIG,
                "overlap.jks": ANDROID_SYNTHETIC_JKS}, {
                ".": (0o700, (".gitignore", "app", "keep.txt", "overlap.jks", "release", "version.properties")),
                "app": (0o700, ("build.gradle.kts",)), "release": (0o755, ("mobile-release.json",))}
    if case == PROJECT_FIELDS_CASE:
        return {"app/build.gradle.kts": SOURCE, "version.properties": VERSION, "keep.txt": KEEP,
            ".gitignore": IGNORE_PREFIX + IGNORE_RULES, "release/mobile-release.json": CONFIG,
            "inputs/VERSION": VERSION, "inputs/link-input": b"MRK_PROJECT_FIELD_LINK_ORIGINAL\n",
            "inputs/kind-input": b"MRK_PROJECT_FIELD_KIND_ORIGINAL\n"}, {
            ".": (0o700, (".gitignore", "app", "inputs", "ios", "keep.txt", "metadata", "release", "version.properties")),
            "app": (0o700, ("build.gradle.kts",)), "inputs": (0o700, ("VERSION", "kind-input", "link-input")),
            "ios": (0o700, ("Example.xcodeproj", "Example.xcworkspace")), "ios/Example.xcodeproj": (0o700, ()),
            "ios/Example.xcworkspace": (0o700, ()), "metadata": (0o700, ()), "release": (0o755, ("mobile-release.json",))}
    saved = case == "noop-stale" or final and case == "first-save"
    files = {"app/build.gradle.kts": SOURCE, "version.properties": VERSION, "keep.txt": KEEP,
             ".gitignore": IGNORE_PREFIX + (IGNORE_RULES if saved else b"") + (STALE if final and case == "noop-stale" else b"")}
    directories = {".": (0o700, (".gitignore", "app", "keep.txt", "version.properties")),
                   "app": (0o700, ("build.gradle.kts",))}
    if saved:
        files["release/mobile-release.json"] = CONFIG
        directories["."] = (0o700, (".gitignore", "app", "keep.txt", "release", "version.properties"))
        directories["release"] = (0o755, ("mobile-release.json",))
    return files, directories


def ios_fixture_data(case, final, *, output_created=None):
    need((case in IOS_CURRENT_CASES or case == IOS_ACCOUNT_CASE) and type(final) is bool, "fixture-case")
    need(output_created is None or type(output_created) is bool and final and case in IOS_SIGNED_CASES,
         "fixture-output-kind")
    if case in ("ios-recovery-empty", IOS_ACCOUNT_CASE):
        return {".gitignore": IGNORE_PREFIX + b".mobile-release/\n", "keep.txt": KEEP}, {
            ".": (0o700, (".gitignore", "keep.txt"))}
    if final and case in IOS_SIGNED_CASES:
        need(type(output_created) is bool, "fixture-original-disposition-required")
    files = {".gitignore": IGNORE_PREFIX + b".mobile-release/\n", "keep.txt": KEEP,
             "version.properties": b"VERSION_NAME=1.2.3\nBUILD_NUMBER=8\n" if final and case == "ios-version-stale" else VERSION,
             "release/mobile-release.json": ios_config(case), "ios/MRKObserved.xcodeproj/project.pbxproj": IOS_PROJECT,
             "ios/MRKObserved.xcodeproj/xcshareddata/xcschemes/MRKObserved.xcscheme": IOS_SCHEME,
             "ios/MRKObserved.xcodeproj/project.xcworkspace/contents.xcworkspacedata": IOS_WORKSPACE,
             "ios/MRKObserved/main.m": IOS_MAIN, "ios/MRKObserved/Info.plist": IOS_PLIST}
    root = (".gitignore", "ios", "keep.txt", "release", "version.properties")
    if case == "ios-signing-inputs":
        files["overlap.p12"] = IOS_SYNTHETIC_P12
        root = tuple(sorted((*root, "overlap.p12")))
    if final and (case in IOS_CASES and case != "ios-version-stale" or output_created is True):
        root = tuple(sorted((*root, ".mobile-release")))
    directories = {".": (0o700, root), "ios": (0o700, ("MRKObserved", "MRKObserved.xcodeproj")),
        "ios/MRKObserved": (0o700, ("Info.plist", "main.m")),
        "ios/MRKObserved.xcodeproj": (0o700, ("project.pbxproj", "project.xcworkspace", "xcshareddata")),
        "ios/MRKObserved.xcodeproj/project.xcworkspace": (0o700, ("contents.xcworkspacedata",)),
        "ios/MRKObserved.xcodeproj/xcshareddata": (0o700, ("xcschemes",)),
        "ios/MRKObserved.xcodeproj/xcshareddata/xcschemes": (0o700, ("MRKObserved.xcscheme",)),
        "release": (0o755, ("mobile-release.json",))}
    return files, directories


def _shape(snapshot, case, final, uid, gid, *, ios_output_created=None):
    files, directories = fixture_data(case, final, ios_output_created=ios_output_created)
    need(type(snapshot) is dict and snapshot.keys() == files.keys() | directories.keys(), "fixture-roster")
    for path, node in snapshot.items():
        need(type(node) is Node and type(node.identity) is tuple and len(node.identity) == 9
             and all(type(v) is int and v >= 0 for v in node.identity), "fixture-identity")
        facts = node.identity
        need(facts[3:5] == (uid, gid), "fixture-owner")
        if path in files:
            need(facts[2] == stat.S_IFREG | 0o600 and facts[5] == 1 and facts[6] == len(files[path])
                 and node.sha256 == digest(files[path]) and node.entries is None, "fixture-file")
        else:
            mode, entries = directories[path]
            need(facts[2] == stat.S_IFDIR | mode and node.sha256 is None and node.entries == entries, "fixture-directory")


def validate_snapshot(original, current, case, final, uid, gid, *, ios_output_created=None):
    _shape(original, case, False, uid, gid)
    _shape(current, case, final, uid, gid, ios_output_created=ios_output_created)
    for path, before in original.items():
        after = current[path]
        if case in LOCAL_CHECK_CASES:
            need(after.identity == before.identity, "fixture-original-changed")
        elif before.entries is not None:
            bound = 6 if case in LOCAL_EDIT_CASES else 5
            need(after.identity[:bound] == before.identity[:bound], "fixture-directory-replaced")
        elif final and (case == "local-release-version" and path == "version.properties" or
                        case == "local-metadata-text" and path in ("release/store/android/en-US/short_description.txt",
                                                                   "release/store/ios/en-US/description.txt")):
            need(after.identity[0] == before.identity[0] and after.identity[1] != before.identity[1]
                 and after.identity[2:6] == before.identity[2:6], "fixture-local-replacement")
        elif final and case == "first-save" and path == ".gitignore":
            need(after.identity[:2] != before.identity[:2], "save-ignore-not-replaced")
        elif final and case == "noop-stale" and path == ".gitignore":
            need(after.identity[:6] == before.identity[:6], "stale-ignore-replaced")
        elif final and case == "ios-version-stale" and path == "version.properties":
            need(after.identity[:7] == before.identity[:7], "stale-version-replaced")
        elif final and case == PROJECT_FIELDS_CASE and path in ("inputs/link-input", "inputs/kind-input"):
            # Exclusive rename/restoration changes original ctime, never its
            # inode, ownership, mode, size, link count, mtime or file contents.
            need(after.identity[:8] == before.identity[:8] and after.identity[8] >= before.identity[8], "project-field-original-not-restored")
        else:
            need(after.identity == before.identity, "fixture-original-changed")
    result = {"completeRoster": True, "expectedBytesAndModes": True, "originalIdentitiesMatched": True,
            "transactionResidueAbsent": True,
            "files": len(fixture_data(case, final, ios_output_created=ios_output_created)[0]),
            "configSha256": current.get("release/mobile-release.json").sha256 if "release/mobile-release.json" in current else None,
            "ignoreSha256": current[".gitignore"].sha256, "ignoreBytes": current[".gitignore"].identity[6]}
    if case in LOCAL_CHECK_CASES:
        result["localChecks"] = _local_checks_base(case)["fixture"]
    if case in LOCAL_EDIT_CASES:
        result["localEdits"] = {"files": len(fixture_data(case, final)[0]), "directories": len(fixture_data(case, final)[1]),
            "sha256": {name: current[name].sha256 for name in sorted(fixture_data(case, final)[0])},
            "sameDirectoryOriginals": True, "unchangedOriginalsPreserved": True}
    if case == PROJECT_FIELDS_CASE:
        result["projectFieldRestoration"] = {"originalFileMetadataExceptRenameCtimeMatched": True,
            "allowedRenameCtimeChanges": [name for name in ("inputs/link-input", "inputs/kind-input")
                if current[name].identity[8] != original[name].identity[8]], "rootModeRestored": True,
            "sameDirectoryOriginals": all(before.identity[:6] == current[path].identity[:6]
                for path, before in original.items() if before.entries is not None)}
        need(result["projectFieldRestoration"]["sameDirectoryOriginals"], "project-field-original-directory-changed")
    return result


def app_environment(state, uid, username):
    need(type(uid) is int and uid > 0 and type(username) is str
         and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", username), "native-user")
    return {"HOME": str(state / "home"), "TMPDIR": str(state / "tmp") + "/",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8", "TZ": "UTC",
            "USER": username, "LOGNAME": username, "__CF_USER_TEXT_ENCODING": f"0x{uid:X}:0:0"}


# Exact public fixture DATA, matching the existing native observer literals.
ANDROID_INPUT_CONFIG = b'{\n  "android": {\n    "applicationId": "org.example.mrk.observed",\n    "enabled": true,\n    "identityStatus": "unverified"\n  },\n  "ios": {\n    "enabled": false\n  },\n  "metadata": {\n    "androidLocales": [\n      "en-US"\n    ],\n    "iosLocales": [],\n    "root": "release/store"\n  },\n  "projectChecks": {\n    "androidArtifact": [],\n    "iosArtifact": [],\n    "preflight": []\n  },\n  "schemaVersion": 1,\n  "services": {\n    "androidFirebase": "required",\n    "iosFirebase": "disabled"\n  },\n  "source": {\n    "candidateBranch": "main",\n    "productionBranch": "main"\n  },\n  "version": {\n    "buildKey": "BUILD_NUMBER",\n    "nameKey": "VERSION_NAME",\n    "source": "version.properties"\n  }\n}\n'
ANDROID_SYNTHETIC_JKS = b"\xfe\xed\xfe\xed\x00\x00\x00\x02\x00\x00\x00\x00\xff\x00\x80\xfe"
ANDROID_SYNTHETIC_FIREBASE = b'{"client":[{"client_info":{"android_client_info":{"package_name":"org.example.mrk.observed"}}}]}'
ANDROID_SYNTHETIC_MISMATCH = b'{"client":[{"client_info":{"android_client_info":{"package_name":"org.example.mrk.other"}}}]}'


def signing_fixture_inputs(case):
    """Closed synthetic files outside the selected project; no real credential."""
    need(case in SESSION_CASES, "signing-fixture-case")
    if case == ANDROID_INPUT_CASE:
        return {"synthetic.jks": (ANDROID_SYNTHETIC_JKS, 0o600), "google-services.json": (ANDROID_SYNTHETIC_FIREBASE, 0o600),
                "wrong-google-services.json": (ANDROID_SYNTHETIC_MISMATCH, 0o600), "public.jks": (ANDROID_SYNTHETIC_JKS, 0o644)}, {"linked.jks": "synthetic.jks"}
    files = {"synthetic.p12": (IOS_SYNTHETIC_P12, 0o600),
             "synthetic.mobileprovision": (IOS_SYNTHETIC_PROFILE, 0o600)}
    if case == "ios-signing-inputs":
        files.update({"GoogleService-Info.plist": (IOS_SYNTHETIC_FIREBASE, 0o600),
                      "public.p12": (IOS_SYNTHETIC_P12, 0o644)})
    return files, {"linked.p12": "synthetic.p12"} if case == "ios-signing-inputs" else {}


class Fixtures:
    """Finite helper-owned file custody, never process/Store custody."""

    def __init__(self, binding, uid, gid, scope=None):
        self.binding, self.uid, self.gid = binding, uid, gid
        self.cases = selected_cases(scope)
        self.path = binding.root(project_fields=(scope == PROJECT_FIELDS_CASE), vault_helper=(scope == VAULT_HELPER_SCOPE),
                                 installation_inspection=(scope == INSTALLATION_INSPECTION_CASE), recovery=(scope == RECOVERY_CASE),
                                 local_edits=(scope == LOCAL_EDITS_SCOPE), local_checks=(scope == LOCAL_CHECK_SCOPE))
        self.fds = set()
        self.close_errors = 0
        self.first_close_error = None
        self.inflight = False
        self.last_returned = False
        self.app_returncode = self.inner_failure_step = self.inner_failure_reason = None
        self.inner_failure_context = self.inner_diagnostic_source = None
        self.inner_bootstrap_diagnostic = None
        self.precursor_diagnostic = None
        self.case = None
        self.stage = "prepare"
        self.projects, self.states, self.originals, self.input_originals, self.field_outside_originals = {}, {}, {}, {}, {}
        self.vault_ancestors, self.vault_parents = [], {}
        self.vault_namespace = self.vault_support = None
        self.vault_paths, self.vault_completed = {}, set()
        self.recovery_case = None
        self.recovery_produced = False
        self.recovery_attestation = self.recovery_session = self.recovery_runtime = None
        self.recovery_runtime_originals, self.recovery_inventories = [], {}
        self.account_home = self.account_private = self.account_private_sha = self.account_private_file = None
        self.account_produced = self.account_app_returned = self.account_readback = False
        self.account_attempts = {"produce": False, "observe": False}
        self.account_producer_attestation = self.account_readback_attestation = self.account_lease = None
        self.account_fds, self.account_directories = set(), {}
        self.account_baseline_files, self.account_native_files, self.account_control_files = [], [], []
        self.gate_files, self.gate_directories = [], []
        self.gate_work = self.gate_artifact = None

    def _open(self, name, parent=None, *, directory=False, create=False):
        flags = os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        flags |= os.O_WRONLY | os.O_CREAT | os.O_EXCL if create else os.O_RDONLY
        if directory:
            flags |= os.O_DIRECTORY
        fd = os.open(name, flags, 0o600, dir_fd=parent)
        self.fds.add(fd)
        need(not os.get_inheritable(fd), "fixture-descriptor-inheritance")
        return fd

    def _close(self, fd):
        need(fd in self.fds, "fixture-close-not-original")
        self.fds.remove(fd)  # This original close is never repeated on error.
        if hasattr(self, "account_fds"):
            self.account_fds.discard(fd)
        try:
            os.close(fd)
            return True
        except BaseException as error:
            self.close_errors += 1
            if self.first_close_error is None:
                self.first_close_error = error
            return False

    @contextmanager
    def _temporary(self, fd):
        original_error = None
        try:
            yield fd
        except BaseException as error:
            original_error = error
            raise
        finally:
            closed = self._close(fd)
            if not closed and original_error is None:
                raise self.first_close_error

    def _mkdir(self, parent, name, mode=0o700):
        os.mkdir(name, 0o700, dir_fd=parent)  # Refuse occupied paths; never adopt.
        fd = self._open(name, parent, directory=True)
        original = signature(os.fstat(fd))
        need(signature(os.stat(name, dir_fd=parent, follow_symlinks=False)) == original
             and original[2] == stat.S_IFDIR | 0o700 and original[3] == self.uid,
             "fixture-created-directory-custody")
        # Darwin can inherit the parent's group even without setgid. Normalize
        # only this fresh, private, caller-owned original, before widening it.
        if original[4] != self.gid:
            os.fchown(fd, -1, self.gid)
        current = signature(os.fstat(fd))
        need(current[:4] == original[:4] and current[4] == self.gid,
             "fixture-created-directory-group")
        self._named(parent, name, fd, 0o700)
        if mode != 0o700:
            os.fchmod(fd, mode)  # Only this newly and exclusively created dir.
            self._named(parent, name, fd, mode)
        return fd

    def _named(self, parent, name, fd, mode):
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        info = os.fstat(fd)
        need(signature(before) == signature(info) and info.st_mode == stat.S_IFDIR | mode
             and (info.st_uid, info.st_gid) == (self.uid, self.gid), "fixture-directory-custody")

    def _write(self, parent, name, body, *, mode=0o600):
        need(mode in (0o600, 0o644), "fixture-write-mode")
        with self._temporary(self._open(name, parent, create=True)) as fd:
            info = os.fstat(fd)
            need(info.st_mode == stat.S_IFREG | 0o600 and info.st_nlink == 1
                 and (info.st_uid, info.st_gid) == (self.uid, self.gid), "fixture-created-file")
            offset = 0
            while offset < len(body):
                count = os.write(fd, body[offset:])
                need(count > 0, "fixture-write")
                offset += count
            if mode == 0o644:
                # Only this exclusively created synthetic permission-refusal
                # fixture is public. Never repair or change a supplied input.
                os.fchmod(fd, mode)
            current = os.fstat(fd)
            need(current.st_mode == stat.S_IFREG | mode
                 and signature(current) == signature(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                 "fixture-write-original")

    def prepare(self):
        self.parent = self._open("/private/tmp", directory=True)
        p = os.fstat(self.parent)
        need(p.st_mode == stat.S_IFDIR | 0o1777 and p.st_uid == 0, "temporary-parent")
        self.root = self._mkdir(self.parent, self.path.name)
        self.state = self._mkdir(self.root, "state")
        for case in self.cases:
            project = self._mkdir(self.root, case)
            if case == RECOVERY_CASE:
                self.recovery_case = project
                project = self._mkdir(project, "project")
            self.projects[case] = project
            files, directories = fixture_data(case, False)
            with ExitStack() as children:
                opened = {".": project}
                # Closed literal roster, parents before children. No selected
                # arbitrary project, pathname adoption, or source overwrite.
                for path, (mode, _) in directories.items():
                    if path == ".":
                        continue
                    parent, _, name = path.rpartition("/")
                    opened[path] = children.enter_context(self._temporary(self._mkdir(opened[parent or "."], name, mode)))
                for path, body in files.items():
                    parent, _, name = path.rpartition("/")
                    self._write(opened[parent or "."], name, body)
            state = self._mkdir(self.state, case)
            self.states[case] = state
            for child in ("home", "tmp"):
                with self._temporary(self._mkdir(state, child)):
                    pass
            if case in SESSION_CASES:
                with self._temporary(self._mkdir(state, "inputs")) as inputs:
                    external_files, links = signing_fixture_inputs(case)
                    for name, (body, mode) in external_files.items():
                        self._write(inputs, name, body, mode=mode)
                    for name, target in links.items():
                        os.symlink(target, name, dir_fd=inputs)
                self.input_originals[case] = self._capture_inputs(case)
            if case == PROJECT_FIELDS_CASE:
                with self._temporary(self._mkdir(state, "outside")) as outside:
                    self._write(outside, "VERSION", VERSION)
                self.field_outside_originals[case] = self._capture_field_outside(case)
            if case == RECOVERY_CASE:
                self._retain_recovery_inventory("initial", self._capture_recovery())
            else:
                self.originals[case] = self._capture(case, False)
        self._namespace()
        if self.cases == VAULT_HELPER_CASES:
            self._prepare_vault_parents()
        if self.cases == (IOS_ACCOUNT_CASE,):
            self._prepare_account()

    def _namespace(self):
        need(signature(os.stat("/private/tmp", follow_symlinks=False))[:6] == signature(os.fstat(self.parent))[:6], "temporary-parent-replaced")
        self._named(self.parent, self.path.name, self.root, 0o700)
        self._named(self.root, "state", self.state, 0o700)
        self._roster(self.root, (*self.cases, "state"), "fixture-namespace-roster")
        self._roster(self.state, self.cases, "fixture-state-roster")
        for case in self.cases:
            if case == RECOVERY_CASE:
                self._named(self.root, case, self.recovery_case, 0o700)
                self._named(self.recovery_case, "project", self.projects[case], 0o700)
                self._roster(self.recovery_case, ("project",), "recovery-case-roster")
            else:
                self._named(self.root, case, self.projects[case], 0o700)
            self._named(self.state, case, self.states[case], 0o700)

    def _roster(self, fd, expected, label):
        # A fresh openat(".") description, not dup(retained_fd), gives each
        # scan its own cursor. Never depend on a supplier's iterator rewind.
        before = signature(os.fstat(fd))
        with self._temporary(self._open(".", fd, directory=True)) as reader:
            need(signature(os.fstat(reader)) == before, "fixture-roster-original")
            iterator = os.scandir(reader)
            original_error = None
            try:
                names = []
                for entry in iterator:
                    need(len(names) < len(expected), label)  # Consume at most expected+1.
                    names.append(entry.name)
                observed = tuple(sorted(names))
                need(observed == tuple(sorted(expected)), label)
                need(signature(os.fstat(reader)) == before and signature(os.fstat(fd)) == before,
                     "fixture-roster-read-race")
                return observed
            except BaseException as error:
                original_error = error
                raise
            finally:
                try:
                    iterator.close()  # One consuming close; never retry it.
                except BaseException as error:
                    self.close_errors += 1
                    if self.first_close_error is None:
                        self.first_close_error = error
                    if original_error is None:
                        raise

    def _file(self, parent, name, body, *, mode=0o600):
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        need(before.st_mode == stat.S_IFREG | mode and before.st_nlink == 1 and before.st_size == len(body)
             and (before.st_uid, before.st_gid) == (self.uid, self.gid), "fixture-file-shape")
        with self._temporary(self._open(name, parent)) as fd:
            original = signature(before)
            need(signature(os.fstat(fd)) == original, "fixture-file-open-race")
            chunks, remaining = [], len(body) + 1
            while remaining:
                part = os.read(fd, remaining)
                if not part:
                    break
                chunks.append(part)
                remaining -= len(part)
            actual = b"".join(chunks)
            need(actual == body and signature(os.fstat(fd)) == original
                 and signature(os.stat(name, dir_fd=parent, follow_symlinks=False)) == original, "fixture-file-readback")
            return Node(original, digest(actual), None)

    def _capture_inputs(self, case):
        files, links = signing_fixture_inputs(case)
        result = {}
        with self._temporary(self._open("inputs", self.states[case], directory=True)) as inputs:
            self._named(self.states[case], "inputs", inputs, 0o700)
            original = signature(os.fstat(inputs))
            names = self._roster(inputs, (*files, *links), "signing-fixture-roster")
            result["."] = Node(original, None, names)
            for name, (body, mode) in files.items():
                result[name] = self._file(inputs, name, body, mode=mode)
            for name, target in links.items():
                before = os.stat(name, dir_fd=inputs, follow_symlinks=False)
                need(stat.S_ISLNK(before.st_mode) and before.st_nlink == 1
                     and (before.st_uid, before.st_gid) == (self.uid, self.gid)
                     and os.readlink(name, dir_fd=inputs) == target,
                     "signing-fixture-link")
                need(signature(os.stat(name, dir_fd=inputs, follow_symlinks=False)) == signature(before)
                     and os.readlink(name, dir_fd=inputs) == target, "signing-fixture-link-race")
                result[name] = Node(signature(before), digest(target.encode("ascii")), None)
            need(signature(os.fstat(inputs)) == original, "signing-fixture-directory-race")
            self._named(self.states[case], "inputs", inputs, 0o700)
        return result

    def _inputs_unchanged(self, case):
        if case in SESSION_CASES:
            need(self._capture_inputs(case) == self.input_originals[case], "signing-fixture-original-changed")
        if case == PROJECT_FIELDS_CASE:
            need(self._capture_field_outside(case) == self.field_outside_originals[case], "project-field-outside-original-changed")

    def _capture_field_outside(self, case):
        need(case == PROJECT_FIELDS_CASE and case in self.states, "project-field-outside-case")
        with self._temporary(self._open("outside", self.states[case], directory=True)) as outside:
            self._named(self.states[case], "outside", outside, 0o700)
            before = signature(os.fstat(outside))
            entries = self._roster(outside, ("VERSION",), "project-field-outside-roster")
            version = self._file(outside, "VERSION", VERSION)
            need(signature(os.fstat(outside)) == before, "project-field-outside-changed")
            self._named(self.states[case], "outside", outside, 0o700)
            return {".": Node(before, None, entries), "VERSION": version}

    def _capture(self, case, final, *, ios_output_created=None):
        files, directories = fixture_data(case, final, ios_output_created=ios_output_created)
        snapshot = {}
        project = self.projects[case]
        with ExitStack() as children:
            opened = {".": project}
            for path, (mode, entries) in directories.items():
                if path != ".":
                    parent, _, leaf = path.rpartition("/")
                    fd = children.enter_context(self._temporary(self._open(leaf, opened[parent or "."], directory=True)))
                    self._named(opened[parent or "."], leaf, fd, mode)
                    opened[path] = fd
                fd = opened[path]
                before = signature(os.fstat(fd))
                observed = self._roster(fd, entries, "fixture-directory-roster")
                for name, body in files.items():
                    parent, _, leaf = name.rpartition("/")
                    if (parent or ".") == path:
                        snapshot[name] = self._file(fd, leaf, body)
                need(signature(os.fstat(fd)) == before, "fixture-directory-read-race")
                snapshot[path] = Node(before, None, observed)
            for path, (mode, _) in directories.items():
                need(signature(os.fstat(opened[path])) == snapshot[path].identity, "fixture-directory-read-race")
                if path != ".":
                    parent, _, leaf = path.rpartition("/")
                    self._named(opened[parent or "."], leaf, opened[path], mode)
        _shape(snapshot, case, final, self.uid, self.gid, ios_output_created=ios_output_created)
        return snapshot

    def before_call(self, case):
        self.case, self.stage = case, "before-invocation"
        self._namespace()
        if case == RECOVERY_CASE:
            need(not self.inflight and self.last_returned and self.recovery_produced, "recovery-app-before-producer")
            need(self._capture_recovery() == self.recovery_inventories["before"], "recovery-before-app-changed")
        else:
            validate_snapshot(self.originals[case], self._capture(case, False), case, False, self.uid, self.gid)
        if case == IOS_ACCOUNT_CASE:
            need(self.account_produced and not self.account_app_returned, "ios-account-app-before-producer")
            self._account_current(after=False)
        state = self.states[case]
        self._roster(state, ("home", "tmp", "inputs") if case in SESSION_CASES
                     else ("home", "tmp", "outside") if case == PROJECT_FIELDS_CASE
                     else ("home", "tmp", "recovery-initial.json", "recovery-generated.json", "recovery-before.json") if case == RECOVERY_CASE
                     else ("account-baseline.json", "home", "tmp") if case == IOS_ACCOUNT_CASE
                     else ("home", "tmp"), "fresh-state-roster")
        self._inputs_unchanged(case)
        if case in VAULT_HELPER_CASES:
            self._vault_namespace_current()
            need(case not in self.vault_completed, "vault-case-reused")
            self._roster(self.vault_parents[case], (), "vault-application-collision")
        for name in ("home", "tmp"):
            with self._temporary(self._open(name, state, directory=True)) as fd:
                self._named(state, name, fd, 0o700)
                self._roster(fd, (), "fresh-state-not-empty")

    def readback(self, case, *, ios_output_created=None):
        need(not self.inflight and self.last_returned, "readback-without-return")
        self.stage = "independent-readback"
        self._namespace()
        self._inputs_unchanged(case)
        return validate_snapshot(self.originals[case], self._capture(case, True, ios_output_created=ios_output_created),
                                 case, True, self.uid, self.gid, ios_output_created=ios_output_created)

    def _capture_recovery(self):
        need(not self.inflight, "recovery-readback-before-return")
        rows, seen, total = {}, set(), 0
        device = signature(os.fstat(self.recovery_case))[0]
        def visit(parent, name, relative, original_fd=None):
            nonlocal total
            need(len(rows) < 160, "recovery-inventory-count")
            kind = _recovery_kind(relative)
            before = signature(os.fstat(original_fd) if original_fd is not None else os.stat(name, dir_fd=parent, follow_symlinks=False))
            need(before[0] == device and before[:2] not in seen and before[3:5] == (self.uid, self.gid)
                 and before[2] == (stat.S_IFDIR | 0o700 if kind == "directory" else stat.S_IFREG | 0o600)
                 and (before[5] >= 1 if kind == "directory" else before[5] == 1), "recovery-fixture-identity")
            seen.add(before[:2])
            # Each directory reader is a fresh open description, never a dup
            # cursor. Every original FD and scandir close stays in this owner.
            with self._temporary(self._open("." if original_fd is not None else name,
                                            original_fd if original_fd is not None else parent, directory=(kind == "directory"))) as fd:
                need(signature(os.fstat(fd)) == before, "recovery-fixture-open-race")
                if kind == "directory":
                    names = []
                    iterator = os.scandir(fd)
                    original_error = None
                    try:
                        for entry in iterator:
                            need(len(names) < 136 and entry.name not in names, "recovery-fixture-roster")
                            _recovery_kind(entry.name if relative == "." else relative + "/" + entry.name)
                            names.append(entry.name)
                    except BaseException as error:
                        original_error = error
                        raise
                    finally:
                        try:
                            iterator.close()
                        except BaseException as error:
                            self.close_errors += 1
                            if self.first_close_error is None:
                                self.first_close_error = error
                            if original_error is None:
                                raise
                    names.sort(); rows[relative] = Node(before, None, tuple(names))
                    for child in names:
                        visit(fd, child, child if relative == "." else relative + "/" + child)
                else:
                    need(0 < before[6] <= 256*1024, "recovery-fixture-file-limit")
                    chunks, remaining = [], before[6] + 1
                    while remaining:
                        chunk = os.read(fd, remaining)
                        if not chunk:
                            break
                        chunks.append(chunk); remaining -= len(chunk)
                    body = b"".join(chunks); total += len(body)
                    need(len(body) == before[6] and total <= 136*256*1024, "recovery-fixture-byte-limit")
                    rows[relative] = Node(before, digest(body), None)
                    if relative == "project/.mobile-release/build-inputs/header.json":
                        # Correlate the actual journal session with the two UI
                        # originals, not authority to construct/upgrade a journal.
                        header = json.loads(body, object_pairs_hook=_pairs)
                        need(type(header) is dict and type(header.get("session")) is str
                             and re.fullmatch(r"[0-9a-f]{32}", header["session"]), "recovery-fixture-session")
                        need(self.recovery_session in (None, header["session"]), "recovery-fixture-session-changed")
                        self.recovery_session = header["session"]
                need(signature(os.fstat(fd)) == before and signature(os.fstat(original_fd) if original_fd is not None
                     else os.stat(name, dir_fd=parent, follow_symlinks=False)) == before, "recovery-fixture-read-race")
        visit(None, None, ".", self.recovery_case)
        return _recovery_inventory_data(rows, self.uid, self.gid)

    def _retain_recovery_inventory(self, stage, rows):
        need(stage in ("initial", "generated", "before", "after") and stage not in self.recovery_inventories and not self.inflight,
             "recovery-inventory-stage-reused")
        self._write(self.states[RECOVERY_CASE], "recovery-" + stage + ".json", _recovery_inventory_bytes(rows))
        self.recovery_inventories[stage] = rows

    def accept_recovery_producer(self, attestation):
        need(not self.inflight and self.last_returned and not self.recovery_produced
             and set(self.recovery_inventories) == {"initial"}, "recovery-generation-before-return")
        self._namespace()
        generated = self._capture_recovery()
        _recovery_generated(self.recovery_inventories["initial"], generated, self.uid, self.gid)
        self._retain_recovery_inventory("generated", generated)
        project = self.projects[RECOVERY_CASE]
        source, target = "GoogleService-Info.plist", "saved-foreign-ios"
        before = signature(os.stat(source, dir_fd=project, follow_symlinks=False))
        need(before == generated["project/" + source].identity, "recovery-move-source-changed")
        try:
            os.stat(target, dir_fd=project, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise Refused("recovery-move-target-occupied")
        # RENAME_EXCL is atomic even if a collision appears after the DATA
        # absence observation above. No overwrite, link/unlink or retry path.
        _preserve_recovery_conflict_exclusive(project)
        preserved = self._capture_recovery()
        _recovery_before(generated, preserved, self.uid, self.gid)
        self._retain_recovery_inventory("before", preserved)
        self.recovery_attestation = attestation
        self.recovery_produced = True

    def readback_recovery(self, report):
        need(not self.inflight and self.last_returned and self.recovery_produced, "readback-without-return")
        self.stage = "independent-recovery-readback"
        _recovery_report(report)
        need(report["originals"][0]["projection"]["result"]["observation"]["session"] == self.recovery_session,
             "recovery-ui-fixture-session")
        self._namespace()
        after = self._capture_recovery()
        result = _recovery_final(*(self.recovery_inventories[s] for s in ("initial", "generated", "before")), after, self.uid, self.gid)
        self._retain_recovery_inventory("after", after)
        result["producer"] = self.recovery_attestation
        return result

    def _recovery_read(self, parent, name, owner, limit, mode=None, *, retain=False):
        before = signature(os.stat(name, dir_fd=parent, follow_symlinks=False))
        need(stat.S_ISREG(before[2]) and before[3] == owner and before[5] == 1 and 0 < before[6] <= limit
             and before[2] & 0o022 == 0 and (mode is None or before[2] == stat.S_IFREG | mode), "recovery-runtime-file")
        fd = self._open(name, parent)
        def read_original():
            need(signature(os.fstat(fd)) == before, "recovery-runtime-open-race")
            sha, chunks, total = hashlib.sha256(), [], 0
            while total <= before[6]:
                chunk = os.read(fd, min(1024*1024, before[6]-total+1))
                if not chunk:
                    break
                total += len(chunk); sha.update(chunk)
                if not retain:
                    chunks.append(chunk)
            need(total == before[6] and signature(os.fstat(fd)) == before
                 and signature(os.stat(name, dir_fd=parent, follow_symlinks=False)) == before, "recovery-runtime-read-race")
            return before, sha.hexdigest(), b"".join(chunks)
        if retain:
            answer = read_original()
            self.recovery_runtime_originals.append((parent, name, fd, before))
            return answer
        with self._temporary(fd):
            return read_original()

    def admit_recovery_runtime(self, source, work, *, supplier_origin="historical", supplier_receipt_sha256=None):
        recovery_supplier_route(supplier_origin, supplier_receipt_sha256)
        target = target_data(self.binding.target)
        need(self.binding.target == ARM_TARGET or supplier_origin == "fresh-public-source", "recovery-intel-fresh-supplier")
        need(self.cases in ((RECOVERY_CASE,), (IOS_ACCOUNT_CASE,)) and not self.inflight and self.recovery_runtime is None, "recovery-runtime-reused")
        need(type(work) is Path or isinstance(work, Path), "recovery-runtime-work")
        need(work.parent == Path("/Users/runner/work/_temp") and re.fullmatch(r"mrk-macos-aqua\.[A-Za-z0-9]{8}", work.name), "recovery-runtime-work-route")
        def private_json(path, limit):
            info, _, body = self._recovery_read(None, str(path), self.uid, limit)
            return json.loads(body, object_pairs_hook=_pairs)
        release = private_json(source / "desktop/macos-installed-inputs" / target["releaseInput"], 4096)
        need(type(release) is dict and set(release) == {"schemaVersion", "packageVersion", "release"}
             and type(release["schemaVersion"]) is int and release["schemaVersion"] == 1
             and type(release["release"]) is str and re.fullmatch(re.escape(target["releasePrefix"]) + r"[a-z0-9_.-]*[a-z0-9]", release["release"])
             and len(release["release"]) <= 128, "recovery-runtime-release")
        # Current stager output, NOT the historical supplier digest. The same
        # actual reviewed workflow builds and installs these exact bytes first.
        result = private_json(work / "runtime-result.json", 16384)
        recovery_supplier_matches(result, supplier_origin, supplier_receipt_sha256)
        if supplier_origin == "fresh-public-source":
            _, source_lock_sha, _ = self._recovery_read(None,
                str(source / "desktop/macos-cpython-source-inputs" / target["sourceLock"]), self.uid, 16*1024)
            need(result["supplierSourceLockSha256"] == source_lock_sha, "recovery-fresh-source-lock")
        _, manifest_sha, manifest_body = self._recovery_read(None, str(work / "runtime/manifest.json"), self.uid, 1024*1024)
        need(type(result) is dict and type(result.get("schemaVersion")) is int and result["schemaVersion"] == 1
             and result.get("release") == release["release"] and result.get("target") == self.binding.target
             and result.get("qualification") == "current-source-staged-no-native-execution"
             and type(result.get("sourceInputsSha256")) is str and re.fullmatch(r"[0-9a-f]{64}", result["sourceInputsSha256"])
             and result.get("successorManifestSha256") == manifest_sha, "recovery-current-runtime-binding")
        manifest = json.loads(manifest_body, object_pairs_hook=_pairs)
        need(type(manifest) is dict and set(manifest) == {"schemaVersion", "protocol", "coreVersion", "target", "coreSha256", "protocolSha256", "inventorySha256", "files"}
             and type(manifest["schemaVersion"]) is int and manifest["schemaVersion"] == 1
             and type(manifest["protocol"]) is int and manifest["protocol"] == 1 and manifest["target"] == self.binding.target
             and manifest["protocolSha256"] == result.get("protocolSha256") and manifest["coreSha256"] == result.get("coreSha256")
             and type(manifest["files"]) is list and 1 <= len(manifest["files"]) <= 2048
             and manifest["inventorySha256"] == result.get("inventorySha256")
             and digest(json.dumps(manifest["files"], sort_keys=True, separators=(",", ":")).encode("ascii")) == manifest["inventorySha256"],
             "recovery-current-manifest")
        entries = {}
        for row in manifest["files"]:
            need(type(row) is dict and set(row) == {"path", "sha256", "size"} and type(row["path"]) is str
                 and re.fullmatch(r"[A-Za-z0-9_.+/-]{1,512}", row["path"]) and not row["path"].startswith("/")
                 and all(part not in ("", ".", "..") for part in row["path"].split("/")) and row["path"] not in entries
                 and type(row["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
                 and type(row["size"]) is int and 0 <= row["size"] <= 512*1024*1024, "recovery-current-runtime-entry")
            entries[row["path"]] = row
        need(list(entries) == sorted(entries) and {"core.zip", "python/bin/python3"} <= entries.keys()
             and sum(row["size"] for row in entries.values()) <= 512*1024*1024
             and manifest["coreSha256"] == entries["core.zip"]["sha256"], "recovery-current-runtime-roster")
        installed = Path("/Library/Application Support/MobileReleaseKit/versions") / release["release"] / "runtime"
        current = self._open("/", directory=True)
        before = signature(os.fstat(current))
        need(stat.S_ISDIR(before[2]) and before[3] == 0 and before[2] & 0o022 == 0, "recovery-runtime-ancestor")
        self.recovery_runtime_originals.append((None, "/", current, before))
        parents = {"/": current}
        path = Path("/")
        for part in (*installed.parts[1:], "python", "bin"):
            parent = current; current = self._open(part, parent, directory=True); path /= part
            original = signature(os.fstat(current))
            need(original == signature(os.stat(part, dir_fd=parent, follow_symlinks=False)) and stat.S_ISDIR(original[2])
                 and original[3] == 0 and original[2] & 0o022 == 0, "recovery-runtime-ancestor")
            self.recovery_runtime_originals.append((parent, part, current, original)); parents[str(path)] = current
        runtime = parents[str(installed)]
        _, actual, _ = self._recovery_read(runtime, "manifest.json", 0, 1024*1024, 0o444, retain=True)
        need(actual == manifest_sha, "recovery-installed-current-manifest")
        for relative in ("core.zip", "python/bin/python3"):
            parent, _, name = relative.rpartition("/")
            info, sha, _ = self._recovery_read(parents[str(installed / parent)] if parent else runtime, name, 0,
                512*1024*1024, 0o555 if relative.endswith("python3") else 0o444, retain=True)
            need(info[6] == entries[relative]["size"] and sha == entries[relative]["sha256"], "recovery-installed-current-file")
        self.recovery_runtime = (str(installed / "python/bin/python3"), str(installed / "core.zip"))
        self.recovery_runtime_paths()

    def recovery_runtime_paths(self):
        need(self.recovery_runtime is not None and not self.inflight and self.recovery_runtime_originals, "recovery-runtime-unadmitted")
        for parent, name, fd, original in self.recovery_runtime_originals:
            need(signature(os.fstat(fd)) == original and signature(os.stat(name, dir_fd=parent, follow_symlinks=False)) == original,
                 "recovery-runtime-original-changed")
        return self.recovery_runtime

    def _account_open(self, name, parent=None, *, directory=False):
        need(not self.inflight and len(self.account_fds) < 32, "ios-account-descriptor-bound")
        fd = self._open(name, parent, directory=directory)
        self.account_fds.add(fd)
        return fd

    def _account_directory(self, path):
        path = Path(path)
        need(path.is_absolute() and len(str(path).encode()) <= 512 and len(path.parts)-1 <= 8
             and all(part not in (".", "..") and 0 < len(part.encode()) <= 255 for part in path.parts[1:]), "ios-account-directory-path")
        if str(path) in self.account_directories:
            return self.account_directories[str(path)][2]
        parent = None if path == Path("/") else self._account_directory(path.parent)
        name = "/" if parent is None else path.name
        fd = self._account_open(name, parent, directory=True)
        before = signature(os.fstat(fd))
        need(before == signature(os.stat(name, dir_fd=parent, follow_symlinks=False)) and stat.S_ISDIR(before[2])
             and before[3] in (0, self.uid) and before[2] & 0o7022 == 0, "ios-account-directory-original")
        self.account_directories[str(path)] = (parent, name, fd, before)
        return fd

    def _prepare_account(self):
        import pwd
        need(self.cases == (IOS_ACCOUNT_CASE,) and self.account_home is None and not self.inflight, "ios-account-prepare-order")
        account = pwd.getpwuid(self.uid)
        home = Path(account.pw_dir).resolve(strict=True)
        need(account.pw_uid == self.uid and self.uid > 0 and home.is_absolute()
             and len(str(home).encode()) <= 512 and len(home.parts)-1 <= 5, "ios-account-home")
        self.account_home = str(home)
        fd = self._account_directory(home)
        need(os.fstat(fd).st_uid == self.uid, "ios-account-home-owner")
        # Do not create/repair/adopt a pending namespace. The genuine producer
        # must acquire the ordinary core lease and refuse any existing session.

    def _account_file(self, parent, name, *, body_hash=None, limit=512*1024, identity=None, role="private"):
        need((role == "private" and name in ("intent.json", "state.json", "account-baseline.json")
              and body_hash is not None and identity is None)
             or (role == "native" and name in ("signing.keychain-db", IOS_ACCOUNT_LOCK_NAME)
                 and identity is not None and body_hash is None), "ios-account-file-role")
        need(type(limit) is int and limit >= 0, "ios-account-file-limit")
        # The native caller keeps its64MiB allowance for both names. Only the
        # fixed AtomicFile lock has an effective cap0; private JSON stays0600.
        cap = (0 if name == IOS_ACCOUNT_LOCK_NAME else 64*1024*1024 if role == "native"
               else 12*1024 if name == "account-baseline.json" else 512*1024)
        fd = self._account_open(name, parent)
        before = signature(os.fstat(fd))
        mode = stat.S_IMODE(before[2])
        role_safe = ((name == IOS_ACCOUNT_LOCK_NAME and mode in (0o400, 0o404, 0o440, 0o444) and before[6] == 0)
                     or (name != IOS_ACCOUNT_LOCK_NAME and mode == 0o600))
        need(before == signature(os.stat(name, dir_fd=parent, follow_symlinks=False))
             and stat.S_ISREG(before[2]) and role_safe and before[3] == self.uid and before[5] == 1
             and 0 <= before[6] <= min(limit, cap), "ios-account-owned-file")
        if identity is not None:
            need(before[:2] == (identity["device"], identity["inode"]), "ios-account-owned-file-identity")
        row = (parent, name, fd, before, body_hash)
        if body_hash is not None:
            self._account_hash(row)
        return row

    def _account_hash(self, row):
        parent, name, fd, before, expected = row
        need(not self.inflight and expected is not None and signature(os.fstat(fd)) == before
             and signature(os.stat(name, dir_fd=parent, follow_symlinks=False)) == before, "ios-account-control-original")
        sha, offset = hashlib.sha256(), 0
        while offset < before[6]:
            chunk = os.pread(fd, min(64*1024, before[6]-offset), offset)
            need(bool(chunk), "ios-account-control-read")
            sha.update(chunk); offset += len(chunk)
        need(offset == before[6] and sha.hexdigest() == expected and signature(os.fstat(fd)) == before
             and signature(os.stat(name, dir_fd=parent, follow_symlinks=False)) == before, "ios-account-control-changed")

    def accept_account_producer(self, value):
        need(not self.inflight and self.last_returned and not self.account_produced and self.account_private is None,
             "ios-account-producer-reused")
        private = _ios_account_private(value["private"], self.uid, self.account_home)
        self.account_private = private
        home = Path(self.account_home)
        for path, key in ((home, "homeIdentity"), (home/".mobile-release-signing", "leaseIdentity"),
                          (home/".mobile-release-signing"/("session-"+private["token"]), "sessionIdentity"),
                          (home/".mobile-release-signing"/("session-"+private["token"])/"keychain", "nativeIdentity")):
            fd = self._account_directory(path)
            need(list(signature(os.fstat(fd))[:5]) == private[key], "ios-account-producer-directory-substitution")
        lease_path = home/".mobile-release-signing"
        session_path = lease_path/("session-"+private["token"])
        lease, session, native = (self.account_directories[str(path)][2] for path in (lease_path, session_path, session_path/"keychain"))
        self.account_lease = lease
        self._roster(lease, ("session-"+private["token"],), "ios-account-session-roster")
        self._roster(session, ("intent.json", "keychain", "state.json"), "ios-account-control-roster")
        self._roster(native, tuple(sorted(private["native"])), "ios-account-native-roster")
        for row in private["members"]:
            path = Path(row["path"])
            parent = self._account_directory(path.parent)
            fd = self._account_open(path.name, parent)
            before = signature(os.fstat(fd))
            need(list(before[:6]) == row["identity"] and signature(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == before,
                 "ios-account-baseline-original")
            self.account_baseline_files.append((parent, path.name, fd, before))
        for name, identity in private["native"].items():
            self.account_native_files.append(self._account_file(native, name, identity=identity, limit=64*1024*1024, role="native"))
        for name, expected in private["controls"].items():
            row = self._account_file(session, name, body_hash=expected["sha256"])
            need(row[3][6] == expected["bytes"], "ios-account-control-size")
            self.account_control_files.append(row)
        body = json.dumps(private, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
        need(len(body) <= 12*1024, "ios-account-private-bound")
        # The existing exclusive writer briefly owns one more original FD.
        # Admit that slot before opening, even though it closes before return.
        need(len(self.account_fds) < 32, "ios-account-descriptor-bound")
        self._write(self.states[IOS_ACCOUNT_CASE], "account-baseline.json", body)
        self.account_private_sha = digest(body)
        self.account_private_file = self._account_file(self.states[IOS_ACCOUNT_CASE], "account-baseline.json",
                                                      body_hash=self.account_private_sha, limit=12*1024)
        self.account_producer_attestation = {key: item for key, item in value.items() if key != "private"}
        self._account_current(after=False)
        self.account_produced = True

    def _account_current(self, *, after):
        need(type(after) is bool and not self.inflight and self.account_private is not None, "ios-account-readback-order")
        private = self.account_private
        session_path = Path(self.account_home)/".mobile-release-signing"/("session-"+private["token"])
        def absent(parent, name):
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return
            raise Refused("ios-account-owned-state-remains")
        for path, (parent, name, fd, before) in self.account_directories.items():
            need(signature(os.fstat(fd))[:5] == before[:5], "ios-account-directory-replaced")
            if after and Path(path).is_relative_to(session_path):
                absent(parent, name)
            else:
                need(signature(os.stat(name, dir_fd=parent, follow_symlinks=False))[:5] == before[:5], "ios-account-directory-replaced")
        for parent, name, fd, before in self.account_baseline_files:
            need(signature(os.fstat(fd))[:6] == before[:6]
                 and signature(os.stat(name, dir_fd=parent, follow_symlinks=False))[:6] == before[:6], "ios-account-baseline-changed")
        for row in (*self.account_native_files, *self.account_control_files):
            parent, name, fd, before, sha = row
            current = signature(os.fstat(fd))
            if after:
                need(current[:5] == before[:5] and current[5] == 0
                     and (name != IOS_ACCOUNT_LOCK_NAME or current[6] == 0), "ios-account-original-not-unlinked")
                absent(parent, name)
            else:
                named = signature(os.stat(name, dir_fd=parent, follow_symlinks=False))
                need(current[:6] == before[:6] and named[:6] == before[:6]
                     and (name != IOS_ACCOUNT_LOCK_NAME or current[6] == named[6] == 0), "ios-account-owned-file-changed")
                if sha is not None:
                    self._account_hash(row)
        self._roster(self.account_lease, () if after else ("session-"+private["token"],), "ios-account-lease-roster")
        if self.account_private_file is not None:
            self._account_hash(self.account_private_file)

    def accept_account_app(self, report):
        need(not self.inflight and self.last_returned and self.account_produced and not self.account_app_returned,
             "ios-account-app-order")
        _ios_pending_report(report)
        need(report["originals"][0]["terminal"]["report"]["account"]["session"] == self.account_private["token"],
             "ios-account-app-session")
        self._account_current(after=True)
        self.account_app_returned = True

    def readback_account(self, report):
        need(not self.inflight and self.last_returned and self.account_produced and self.account_app_returned and self.account_readback,
             "ios-account-final-readback-order")
        self.stage = "independent-account-readback"
        _ios_pending_report(report)
        self._account_current(after=True)
        account = {
            "producer": self.account_producer_attestation, "nativeReadback": self.account_readback_attestation,
            "exactPendingSessionRecovered": True, "originalOwnedNativeAndControlsRemoved": True,
            "persistentOriginalLeaseRetained": True, "nativeBaselineMembers": len(self.account_baseline_files),
            "baselineIdentitiesMatched": True, "baselinePreferencesMatched": True, "projectMarkerUnchanged": True,
            "privateContentsExported": False, "foreignPreferenceConflictInjected": False,
            "appleSigningMaterialUsed": False, "signedExportQualified": False}
        need(len(json.dumps(account, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")) <= 8192,
             "ios-account-public-bound")
        return {**self.readback(IOS_ACCOUNT_CASE), "iosAccountRecovery": account}

    def _prepare_vault_parents(self):
        import pwd
        # Provider selection is always the ordinary native account. HOME and
        # TMPDIR still isolate unrelated app state but cannot redirect Keychain.
        account = pwd.getpwuid(self.uid)
        need(account.pw_uid == self.uid and self.uid > 0, "vault-native-user")
        self.vault_paths = {case: vault_fixture_path(self.binding, account.pw_dir, case) for case in self.cases}
        support = self.vault_paths[self.cases[0]].parents[2]
        root = self._open("/", directory=True)
        current = root
        for parent, name in [(None, "/"), *[(None, part) for part in support.parts[1:]]]:
            if name != "/":
                parent = current
                current = self._open(name, parent, directory=True)
            held = signature(os.fstat(current))
            named = signature(os.stat(name, dir_fd=parent, follow_symlinks=False))
            need(held == named and stat.S_ISDIR(held[2]) and held[2] & 0o7022 == 0
                 and held[3] in (0, self.uid), "vault-ancestor-custody")
            # Parent sizes/timestamps/link counts can change when OUR fresh
            # child is created. Object identity, owner and mode may never drift.
            self.vault_ancestors.append((parent, name, current, held[:5]))
        self.vault_support = current
        namespace = self.vault_paths[self.cases[0]].parents[1].name
        self.vault_namespace = self._mkdir(current, namespace)
        for case in self.cases:
            self.vault_parents[case] = self._mkdir(self.vault_namespace, case)
            self._roster(self.vault_parents[case], (), "vault-case-collision")
        # The core, not the fixture owner, creates the application/vault leaves.
        self._vault_namespace_current()

    def _vault_namespace_current(self):
        need(self.cases == VAULT_HELPER_CASES and self.vault_namespace is not None
             and self.vault_support is not None and self.vault_ancestors, "vault-fixture-custody")
        for parent, name, fd, original in self.vault_ancestors:
            need(signature(os.fstat(fd))[:5] == original
                 and signature(os.stat(name, dir_fd=parent, follow_symlinks=False))[:5] == original,
                 "vault-ancestor-changed")
        name = self.vault_paths[self.cases[0]].parents[1].name
        self._named(self.vault_support, name, self.vault_namespace, 0o700)
        self._roster(self.vault_namespace, self.cases, "vault-namespace-roster")
        for case in self.cases:
            self._named(self.vault_namespace, case, self.vault_parents[case], 0o700)
            self._roster(self.vault_parents[case], ("dev.mobile-release-kit.desktop",)
                         if case in self.vault_completed else (), "vault-case-roster")

    def readback_vault(self, case, report):
        need(case in VAULT_HELPER_CASES and case in self.cases and case not in self.vault_completed
             and not self.inflight and self.last_returned, "vault-readback-order")
        _vault_helper_report(report, case)  # Actual inner original finality, not outer exit alone.
        source = self.readback(case)
        # A fresh no-follow walk below the retained fixture parent; no path or
        # identity from the child report is opened, and no Keychain is queried.
        parent = self.vault_parents[case]
        self._named(self.vault_namespace, case, parent, 0o700)
        self._roster(parent, ("dev.mobile-release-kit.desktop",), "vault-case-roster")
        expected = {"vault-lock": 0, "initialization-reservation": 48}
        if report["initialized"]:
            expected["vault-header"] = 104
        with self._temporary(self._open("dev.mobile-release-kit.desktop", parent, directory=True)) as app:
            self._named(parent, "dev.mobile-release-kit.desktop", app, 0o700)
            self._roster(app, ("credential-vault-v1",), "vault-application-roster")
            with self._temporary(self._open("credential-vault-v1", app, directory=True)) as vault:
                self._named(app, "credential-vault-v1", vault, 0o700)
                before = signature(os.fstat(vault))
                self._roster(vault, expected, "vault-control-roster")
                with ExitStack() as files:
                    originals = []
                    for name, length in expected.items():
                        fd = files.enter_context(self._temporary(self._open(name, vault)))
                        original = signature(os.fstat(fd))
                        need(original[0] == before[0] and original[2] == stat.S_IFREG | 0o600
                             and original[3:6] == (self.uid, self.gid, 1) and original[6] == length
                             and original == signature(os.stat(name, dir_fd=vault, follow_symlinks=False)),
                             "vault-control-custody")
                        need(all(original[:2] != saved[:2] for _, _, saved in originals), "vault-control-alias")
                        originals.append((name, fd, original))
                    for name, fd, original in originals:
                        need(signature(os.fstat(fd)) == original
                             and signature(os.stat(name, dir_fd=vault, follow_symlinks=False)) == original,
                             "vault-control-changed")
                    need(signature(os.fstat(vault)) == before, "vault-control-roster-changed")
                    self._roster(vault, expected, "vault-control-roster")
                self._named(app, "credential-vault-v1", vault, 0o700)
            self._roster(app, ("credential-vault-v1",), "vault-application-roster")
            self._named(parent, "dev.mobile-release-kit.desktop", app, 0o700)
        self.vault_completed.add(case)
        self._vault_namespace_current()
        # No key/identity/ciphertext bytes or provider database metadata exported.
        # Core parsing/authentication is proven by its real Initialize/Unlock,
        # not reconstructed by this independent output-accounting observation.
        return {**source, "vaultOutput": {"applicationDirectoryObserved": True, "vaultDirectoryObserved": True,
            "reservationPresent": True, "headerPresent": report["initialized"],
            "controlFileCount": len(expected), "retainedPrivateBytes": sum(expected.values()),
            "privateContentsExported": False, "keychainInspectedByOwner": False,
            "retainedForDisposableAccountRetirement": True}}

    def readback_ios(self, case, report):
        need(case in IOS_OPERATION_CASES and case in self.cases and not self.inflight and self.last_returned, "ios-readback-order")
        # Parser DATA bounds the spelling; this independent original-project
        # descriptor supplies the filesystem authority. Never open a report path.
        _ios_report(report, case)
        if case == "ios-recovery-empty":
            return {**self.readback(case), "iosRecovery": {"emptyAccountAndProjectObserved": True, "mutationRequested": False}}
        original = report["original"]
        disposition = original["terminal"]["disposition"]
        output_created = disposition["output"] != "not-created" if case in IOS_SIGNED_CASES else None
        source = self.readback(case, ios_output_created=output_created)
        if disposition["output"] == "not-created":
            return {**source, "iosOutput": {"state": "not-created", "archiveObserved": False}}
        operation = original["facts"]["operationId"]
        project = self.projects[case]
        with self._temporary(self._open(".mobile-release", project, directory=True)) as private:
            self._named(project, ".mobile-release", private, 0o700)
            self._roster(private, ("desktop-ios-archive",), "ios-output-parent-roster")
            with self._temporary(self._open("desktop-ios-archive", private, directory=True)) as domain:
                self._named(private, "desktop-ios-archive", domain, 0o700)
                self._roster(domain, (operation,), "ios-output-domain-roster")
                with self._temporary(self._open(operation, domain, directory=True)) as output:
                    self._named(domain, operation, output, 0o700)
                    complete = disposition["output"] == "retained-local-result"
                    self._roster(output, ("archive.xcarchive",) if complete else (), "ios-output-roster")
                    observed = self._archive_readback(output, original["terminal"]["result"]) if complete else None
                    self._named(domain, operation, output, 0o700)
                self._named(private, "desktop-ios-archive", domain, 0o700)
            self._named(project, ".mobile-release", private, 0o700)
        # Source readback is repeated only after reading the newly declared
        # output so a concurrent replacement cannot license either observation.
        validate_snapshot(self.originals[case], self._capture(case, True, ios_output_created=output_created),
                          case, True, self.uid, self.gid, ios_output_created=output_created)
        self._inputs_unchanged(case)
        return {**source, "iosOutput": {"state": disposition["output"], "archiveObserved": complete,
                                        "workAbsent": True, "archive": observed}}

    def _archive_readback(self, parent, result):
        import plistlib
        import time
        end = time.monotonic() + 20
        rows, plists, total = {}, {}, 0
        root_device = os.fstat(parent).st_dev
        retained_info = {"Info.plist", "Products/Applications/MRKObserved.app/Info.plist"}

        def current():
            need(time.monotonic() < end, "ios-output-readback-deadline")

        def bound(parent_fd, name, fd, before):
            current()
            need(signature(os.fstat(fd)) == signature(before)
                 and signature(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)) == signature(before), "ios-output-original-changed")
            need(before.st_dev == root_device and (before.st_uid, before.st_gid) == (self.uid, self.gid)
                 and stat.S_IMODE(before.st_mode) & 0o7022 == 0
                 and (stat.S_ISDIR(before.st_mode) or stat.S_ISREG(before.st_mode) and before.st_nlink == 1), "ios-output-object")

        def names(fd):
            current()
            before = signature(os.fstat(fd))
            with self._temporary(self._open(".", fd, directory=True)) as reader:
                need(signature(os.fstat(reader)) == before, "ios-output-reader-original")
                iterator = os.scandir(reader)
                error = None
                try:
                    found = []
                    for entry in iterator:
                        current()
                        need(len(rows) + len(found) < 1024 and type(entry.name) is str, "ios-output-entry-budget")
                        need(re.fullmatch(r"[A-Za-z0-9_. -]{1,255}", entry.name) is not None and entry.name not in (".", ".."), "ios-output-name")
                        found.append(entry.name)
                    need(len(found) == len(set(name.casefold() for name in found)), "ios-output-name-collision")
                    need(signature(os.fstat(reader)) == before and signature(os.fstat(fd)) == before, "ios-output-directory-changed")
                    return sorted(found)
                except BaseException as caught:
                    error = caught
                    raise
                finally:
                    try:
                        iterator.close()
                    except BaseException as caught:
                        self.close_errors += 1
                        if self.first_close_error is None:
                            self.first_close_error = caught
                        if error is None:
                            raise

        def walk(fd, relative, depth):
            nonlocal total
            current()
            need(depth <= 16, "ios-output-depth")
            before = signature(os.fstat(fd))
            for name in names(fd):
                current()
                path = f"{relative}/{name}" if relative else name
                observed = os.stat(name, dir_fd=fd, follow_symlinks=False)
                directory = stat.S_ISDIR(observed.st_mode)
                need(directory or stat.S_ISREG(observed.st_mode), "ios-output-kind")
                need(len(rows) < 1024 and path not in rows, "ios-output-entry-budget")
                with self._temporary(self._open(name, fd, directory=directory)) as child:
                    bound(fd, name, child, observed)
                    if directory:
                        rows[path] = None
                        walk(child, path, depth + 1)
                    else:
                        need(0 <= observed.st_size <= 64 * 1024 * 1024 and total + observed.st_size <= 128 * 1024 * 1024,
                             "ios-output-byte-budget")
                        if path in retained_info:
                            need(observed.st_size <= 256 * 1024, "ios-output-plist-budget")
                        count, hashed, captured = 0, hashlib.sha256(), []
                        while True:
                            current()
                            part = os.read(child, min(1024 * 1024, observed.st_size + 1 - count))
                            if not part:
                                break
                            count += len(part)
                            need(count <= observed.st_size, "ios-output-grew")
                            hashed.update(part)
                            if path in retained_info:
                                captured.append(part)
                        need(count == observed.st_size, "ios-output-short-read")
                        total += count
                        rows[path] = {"bytes": count, "sha256": hashed.hexdigest()}
                        if path in retained_info:
                            plists[path] = b"".join(captured)
                    bound(fd, name, child, observed)
            need(signature(os.fstat(fd)) == before, "ios-output-directory-changed")

        before = os.stat("archive.xcarchive", dir_fd=parent, follow_symlinks=False)
        need(stat.S_ISDIR(before.st_mode), "ios-output-archive-kind")
        with self._temporary(self._open("archive.xcarchive", parent, directory=True)) as archive:
            bound(parent, "archive.xcarchive", archive, before)
            walk(archive, "", 0)
            bound(parent, "archive.xcarchive", archive, before)
        need(len(rows) == result["entries"] and total == result["bytes"], "ios-output-core-inventory-mismatch")
        binaries = ("Products/Applications/MRKObserved.app/MRKObserved", "dSYMs/MRKObserved.app.dSYM/Contents/Resources/DWARF/MRKObserved")
        need(retained_info <= plists.keys() and all(type(rows.get(name)) is dict and rows[name]["bytes"] > 0 for name in binaries)
             and not any("_CodeSignature" in name.split("/") or name.endswith(".mobileprovision") for name in rows), "ios-output-structure")
        try:
            archive_info = plistlib.loads(plists["Info.plist"])
            app_info = plistlib.loads(plists["Products/Applications/MRKObserved.app/Info.plist"])
        except (ValueError, TypeError, OverflowError) as error:
            raise Refused("ios-output-plist") from error
        need(type(archive_info) is dict and type(archive_info.get("ApplicationProperties")) is dict
             and archive_info["ApplicationProperties"].get("ApplicationPath") == "Applications/MRKObserved.app"
             and type(app_info) is dict and app_info.get("CFBundleIdentifier") == "org.example.mrk.observed"
             and app_info.get("CFBundleShortVersionString") == "1.2.3" and app_info.get("CFBundleVersion") == "7", "ios-output-identity")
        current()
        return {"entries": len(rows), "bytes": total,
                "inventorySha256": digest(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("ascii")),
                "savedIdentityMatched": True, "unsignedAppAndDsymPresent": True, "retainedNotDeleted": True}

    def close(self):
        need(not self.inflight, "fixture-finality-unknown")
        for fd in tuple(self.fds):
            self._close(fd)
        if self.first_close_error is not None:
            raise self.first_close_error


def run_cases(binding, fixtures, run_owned, uid, username, emit, scope=None):
    """The sole invocation seam. Inert tests supply a non-executing callable."""
    cases = selected_cases(scope)
    need(getattr(fixtures, "cases", cases) == cases, "fixture-scope")
    not_executed = []
    if scope == RECOVERY_CASE:
        produce_pending_recovery(fixtures, run_owned, uid, username)
    if scope == IOS_ACCOUNT_CASE:
        _run_ios_account_child(fixtures, run_owned, uid, username, "produce")
    for case in cases:
        fixtures.before_call(case)
        state = binding.root(project_fields=(scope == PROJECT_FIELDS_CASE), vault_helper=(scope == VAULT_HELPER_SCOPE),
                                 installation_inspection=(scope == INSTALLATION_INSPECTION_CASE), recovery=(scope == RECOVERY_CASE),
                                 local_edits=(scope == LOCAL_EDITS_SCOPE), local_checks=(scope == LOCAL_CHECK_SCOPE)) / "state" / case
        argv = [EXECUTABLE, case]
        fixtures.stage, fixtures.inflight, fixtures.last_returned = "invocation", True, False
        fixtures.app_returncode = fixtures.inner_failure_step = fixtures.inner_failure_reason = None
        fixtures.inner_failure_context = fixtures.inner_diagnostic_source = None
        fixtures.inner_bootstrap_diagnostic = None
        fixtures.precursor_diagnostic = None
        # Only the original public return contract clears this flag. An
        # exception/interruption or foreign/malformed result leaves finality
        # unknown, with no readback, close or later invocation.
        try:
            result = run_owned(argv, environ=app_environment(state, uid, username), cwd=state,
                               timeout=case_timeout(case), capture=True, text=False, output_limit=OUTPUT_LIMIT)
        except BaseException as error:
            # Diagnostics only: preserve identical error, inflight, unknown
            # finality and the no-readback/no-close/no-next-call boundary.
            try:
                reduced = _original_exception_diagnostics(error, run_owned, case, state)
                if reduced is not None:
                    (fixtures.inner_failure_step, fixtures.inner_failure_reason, fixtures.inner_failure_context,
                     fixtures.inner_bootstrap_diagnostic) = reduced
                    fixtures.inner_diagnostic_source = "original-exception-buffer"
            except BaseException:
                pass  # Even an unexpected diagnostic fault cannot replace this error.
            raise
        need(type(result) is subprocess.CompletedProcess and type(result.args) is list
             and len(result.args) == 2 and all(type(arg) is str for arg in result.args) and result.args == argv
             and type(result.returncode) is int and type(result.stdout) is bytes and type(result.stderr) is bytes
             and len(result.stdout) + len(result.stderr) <= OUTPUT_LIMIT, "owner-return-contract")
        fixtures.inflight, fixtures.last_returned, fixtures.stage = False, True, "result-validation"
        fixtures.app_returncode = result.returncode
        fixtures.inner_failure_step = failure_step(result.stdout, result.stderr)
        fixtures.inner_failure_reason = failure_reason(result.stdout, result.stderr)
        fixtures.inner_failure_context = failure_context(result.stdout, result.stderr, case)
        fixtures.inner_diagnostic_source = "completed-output"
        try:
            fixtures.inner_bootstrap_diagnostic = _inner_bootstrap_diagnostic(result.stdout, result.stderr)
        except BaseException:
            fixtures.inner_bootstrap_diagnostic = None  # Even a replaced reducer cannot mask app-return.
        need(result.returncode == 0, "app-return")
        report = parse_result(result.stdout, result.stderr, binding, case)
        if case == IOS_ACCOUNT_CASE:
            fixtures.accept_account_app(report["iosArchive"])
            _run_ios_account_child(fixtures, run_owned, uid, username, "observe")
            readback = fixtures.readback_account(report["iosArchive"])
        elif case == RECOVERY_CASE:
            readback = fixtures.readback_recovery(report["projectRecovery"])
        elif case in VAULT_HELPER_CASES:
            readback = fixtures.readback_vault(case, report["vaultHelper"])
            if report["vaultHelper"]["testResult"] == "not-executed":
                not_executed.append(case)
        else:
            readback = fixtures.readback_ios(case, report["iosArchive"]) if case in IOS_OPERATION_CASES else fixtures.readback(case)
        if case in LOCAL_CHECK_CASES:
            _exact(report["localChecks"]["fixture"], readback["localChecks"], ("localChecks", "fixture"))
        if case in LOCAL_EDIT_CASES:
            # Independent post-exit reads agree with the original app's retained
            # same-session facts; neither source alone manufactures a receipt.
            actual = report["localEdits"]["fixture"]
            observed = readback["localEdits"]
            need(actual["sha256"] == observed["sha256"] and actual["files"] == observed["files"]
                 and actual["directories"] == observed["directories"]
                 and observed["sameDirectoryOriginals"] is True and observed["unchangedOriginalsPreserved"] is True,
                 "fixture-local-readback")
        emit({"schemaVersion": 1, "type": "macos-aqua-case", **binding.public(), "case": case,
              "originalCallReturned": True, "observer": report, "independentReadback": readback})
    return tuple(not_executed)


def recovery_supplier_route(origin, expected):
    """Explicit reviewed caller selection; a receipt never selects its own mode."""
    need(type(origin) is str and origin in ("historical", "fresh-public-source"), "recovery-supplier-origin")
    need((origin == "historical" and expected is None) or
         (origin == "fresh-public-source" and type(expected) is str and re.fullmatch(r"[0-9a-f]{64}", expected)),
         "recovery-supplier-anchor")
    return origin, expected


def recovery_supplier_matches(result, origin, expected):
    recovery_supplier_route(origin, expected)
    fresh = {"supplierOrigin", "supplierReceiptSha256", "supplierSourceLockSha256", "supplierProfile", "pythonVersion", "gil"}
    historical = {"acceptedArchiveSha256", "acceptedTarSha256", "originalManifestSha256", "supplierOnlyReuse", "addedNotices"}
    need(type(result) is dict, "recovery-supplier-result")
    if origin == "historical":
        need(result.get("supplierOnlyReuse") is True and not fresh.intersection(result), "recovery-historical-supplier")
    else:
        need(fresh <= result.keys() and not historical.intersection(result)
             and result["supplierOrigin"] == origin and result["supplierReceiptSha256"] == expected
             and result["supplierProfile"] == "mrk-macos-cpython-source-supplier-v1"
             and result["pythonVersion"] == "3.14.7" and result["gil"] is True
             and type(result["supplierSourceLockSha256"]) is str
             and re.fullmatch(r"[0-9a-f]{64}", result["supplierSourceLockSha256"]), "recovery-fresh-supplier")


def admit(environment, root, *, target=ARM_TARGET):
    # Platform/user APIs are evaluated only in the actual native entry.
    import platform
    import pwd
    import threading
    selected = target_data(target)
    need(sys.platform == "darwin" and sys.maxsize == 2 ** 63 - 1
         and platform.machine() == selected["machine"] and platform.mac_ver()[0].split(".")[0] == "26", "native-platform")
    uid, gid = os.getuid(), os.getgid()
    need(uid == os.geteuid() and uid > 0 and gid == os.getegid()
         and threading.current_thread() is threading.main_thread(), "native-main-user")
    binding = Binding(environment.get("GITHUB_SHA"), environment.get("GITHUB_RUN_ID"), environment.get("GITHUB_RUN_ATTEMPT"), target).checked()
    required = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS", "RUNNER_ARCH": selected["runner"],
                "GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": REPOSITORY, "GITHUB_REF": REF,
                "GITHUB_WORKFLOW_REF": WORKFLOW, "GITHUB_WORKFLOW_SHA": binding.source, "GITHUB_WORKSPACE": str(root)}
    need(all(environment.get(key) == value for key, value in required.items()), "hosted-source-route")
    # Actions' reviewed checkout is detached at this exact source. No Git
    # command/credential lookup or alternate worktree/ref parser is needed.
    head = root / ".git" / "HEAD"
    head_info = head.lstat()
    need(stat.S_ISREG(head_info.st_mode) and head_info.st_size == 41
         and head.read_bytes() == binding.source.encode("ascii") + b"\n", "checkout-source")
    username = pwd.getpwuid(uid).pw_name
    app_environment(binding.root() / "state" / CASES[0], uid, username)
    return binding, uid, gid, username


def load_owner(root):
    need(not any(name == "mobile_release" or name.startswith("mobile_release.") for name in sys.modules), "owner-already-imported")
    for name, expected in OWNER_PINS.items():
        path = root / "src" / "mobile_release" / name
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_size <= 256 * 1024 and digest(path.read_bytes()) == expected, "owner-source-pin")
    sys.path.insert(0, str(root / "src"))
    try:
        from mobile_release import owned_process
    finally:
        sys.path.pop(0)
    need(Path(owned_process.__file__).absolute() == root / "src" / "mobile_release" / "owned_process.py", "owner-source-route")
    return owned_process


# Fixed existing shipping scopes only; DATA selection is separate from ignored1.
SHIPPING_GATE_SCOPES = ("vault-helper-shipping", "vault-helper-shipping-installation-inspection")
SHIPPING_GATE_DATA_SCOPE = "six-main-and-seven-native-macos-shipping-gate-data-regressions"
SHIPPING_GATE_MAIN_TESTS = tuple("vault_keyring_macos::tests::" + name for name in (
    "a_known_native_failure_projection_does_not_invent_cleanup_uncertainty",
    "participant_never_uses_terminal_or_missing_child_as_exit_finality",
    "failed_pipe_close_publishes_first_before_the_next_original_consume",
    "refusal_never_fabricates_driver_return_join_native_cleanup_or_refund",
    "cleanup_projection_observes_a_stop_arriving_during_original_settlement",
    "an_unknown_original_projection_cannot_reopen_cleanup_on_a_later_callback",
))
SHIPPING_GATE_NATIVE_TESTS = tuple("vault_helper_filesystem::tests::" + name for name in (
    "prearm_and_pre_go_stop_have_no_native_allocation",
    "parent_pre_stop_retires_only_an_inert_gate_and_cannot_reenter",
    "prepare_and_spawn_are_distinct_one_shot_state_claims",
    "code_settlement_never_implies_gate_postcheck_or_unknown_close_finality",
    "even_a_closed_spawned_gate_requires_its_actual_postcheck",
    "cleanup_gate_correspondence_does_not_erase_a_previous_failure",
    "an_entered_unreturned_native_arm_is_never_empty_or_settled",
))
SHIPPING_GATE_TEST = "vault_helper_filesystem::gate_custody_control::shipping_helper_retains_gate_after_parent_reference_close_until_actual_exit"
SHIPPING_GATE_COMPILER_ARGV = ["/Users/runner/.rustup/toolchains/stable-aarch64-apple-darwin/bin/cargo", "test", "--locked", "--no-default-features", "--jobs", "1",
    "--target", "aarch64-apple-darwin", "--package", "mobile-release-kit-desktop",
    "--package", "mrk-macos-installed-native", "--lib", "--no-run", "--message-format=json",
    "--features", "mrk-macos-installed-native/installed-observation"]

def shipping_gate_compiler_argv(target=ARM_TARGET):
    argv = list(SHIPPING_GATE_COMPILER_ARGV)
    argv[0], argv[7] = target_data(target)["cargo"], target
    return argv


SHIPPING_GATE_SOURCE_PINS = {
    "desktop/tools/stage_macos_installed.py": "e02fca27200986a06cf6b321425112973c9801995ca680f4705e45261c4e75d3",
    "desktop/macos-installed-inputs/build-release.json": "521cdb6880415e7f2ac7ef1ebb86d4e5ec9d341dabf7f77e70fc8dc2883c4512",
    "desktop/macos-installed-inputs/build-release-intel.json": "5864c0efb2a66219cf7efa41d3863721327148ef7b4c6d6f3252de3ce20596e7",
}
SHIPPING_GATE_REPORT = "shipping-gate-control.receipt.json"
SHIPPING_GATE_STATUS = "shipping-gate-control.status"


def _gate_json(body, limit=24 * 1024):
    need(type(body) is bytes and 0 < len(body) <= limit, "gate-json-bound")
    value = json.loads(body.decode("utf-8", "strict"), object_pairs_hook=_pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(Refused("gate-json-number")))
    need(type(value) is dict, "gate-json-object")
    return value


def _gate_sha(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _gate_integers(value, count):
    need(type(value) is list and len(value) == count and all(type(v) is str
         and re.fullmatch(r"-?(0|[1-9][0-9]{0,19})", v) and str(int(v)) == v for v in value), "gate-integer-data")
    result = tuple(int(v) for v in value)
    need(all(-(1 << 63) <= v < 1 << 64 for v in result), "gate-integer-bound")
    return result


def _gate_libtest(stdout, stderr, returncode, names):
    need(type(stdout) is bytes and type(stderr) is bytes and len(stdout) + len(stderr) <= 64 * 1024
         and type(returncode) is int and returncode == 0 and not stderr, "gate-libtest-original-result")
    count = len(names)
    lines = [line for line in stdout.decode("utf-8", "strict").splitlines() if line]
    expected = {"test " + name + " ... ok" for name in names}
    need(len(expected) == count and len(lines) == count + 2
         and lines[0] == f"running {count} " + ("test" if count == 1 else "tests")
         and len(set(lines[1:-1])) == count and set(lines[1:-1]) == expected, "gate-exact-named-results")
    summary = re.fullmatch(rf"test result: ok\. {count} passed; 0 failed; 0 ignored; 0 measured; ([0-9]{{1,8}}) filtered out; finished in [0-9]{{1,6}}\.[0-9]{{1,9}}s", lines[-1])
    need(summary is not None, "gate-exact-summary")
    return int(summary[1])


def _gate_artifact(value, work, library, *, target=ARM_TARGET):
    target_data(target)
    need(type(value) is dict and set(value) == {"path", "sha256", "identity", "full9"}
         and type(value["path"]) is str and len(value["path"]) <= 4096 and _gate_sha(value["sha256"]), "gate-artifact-shape")
    path = Path(value["path"])
    need(path.parent == work / "cargo-target" / target / "debug/deps"
         and re.fullmatch(re.escape(library) + r"-[0-9a-f]{1,64}", path.name), "gate-artifact-route")
    full = _gate_integers(value["full9"], 9)
    need(full[0] >= 0 and full[1] > 0 and stat.S_ISREG(full[2]) and full[2] & 0o111
         and not full[2] & 0o7022 and full[3] > 0 and full[4] >= 0 and full[5] == 1
         and 0 < full[6] <= 1024 * 1024 * 1024, "gate-artifact-identity")
    # Existing headless identity is legacy dev,ino,mode,nlink,uid,gid,... .
    _exact(value["identity"], [full[0], full[1], full[2], full[5], full[3], full[4], *full[6:]])
    return value


def _gate_headless(bodies, binding, checkout, work):
    value = _gate_json(bodies["headless-tests.receipt.json"], 16384)
    fixed = {"schemaVersion": 1, "scope": SHIPPING_GATE_DATA_SCOPE, "source": binding.source,
        "workflowSource": binding.source, "workflow": WORKFLOW, "runId": binding.run, "runAttempt": binding.attempt,
        "names": list(SHIPPING_GATE_MAIN_TESTS + SHIPPING_GATE_NATIVE_TESTS),
        "originalReturned": True, "artifactOriginalUnchanged": True, "artifactOriginalClosed": True,
        "passed": True, "shippingBinaryQualified": False, "distributionQualified": False,
        "compilerOriginalReturned": True, "cargoTargetRetired": False, "cargoTargetOriginalClosed": True,
        "workOriginalClosed": True, "genuineServiceQualified": False, "protectedCopyQualified": False,
        "compilerArgv": shipping_gate_compiler_argv(binding.target), "ownerCallsEntered": 3, "ownerCallsReturned": 3,
        "headlessCustodyRetained": False, "cargoTargetRetentionReason": "required-follow-on-build-and-gate-control",
        "tests": 13, "failed": 0, "ignored": 0, "measured": 0}
    need(set(value) == set(fixed) | {"targets", "cargoTargetOriginal", "workOriginal", "compilerJsonSha256"}, "gate-headless-keys")
    for key, expected in fixed.items():
        _exact(value[key], expected)
    for key in ("cargoTargetOriginal", "workOriginal"):
        original = _gate_integers(value[key], 5)
        need(original[0] >= 0 and original[1] > 0 and original[2] == stat.S_IFDIR | 0o700
             and original[3] > 0 and original[4] >= 0, "gate-headless-directory")
    need(bodies["headless-build.status"] == b"0\n" and _gate_sha(value["compilerJsonSha256"])
         and digest(bodies["headless-build.jsonl"]) == value["compilerJsonSha256"], "gate-original-compiler-binding")
    raw = bodies["headless-build.jsonl"]
    need(type(raw) is bytes and 0 < len(raw) <= 4 * 1024 * 1024, "gate-compiler-bound")
    rows = [_gate_json(line, 4 * 1024 * 1024) for line in raw.splitlines()]
    finished = [row.get("success") for row in rows if row.get("reason") == "build-finished"]
    need(len(finished) == 1 and finished[0] is True, "gate-compiler-finished")
    targets = [row for row in rows if row.get("reason") == "compiler-artifact" and row.get("executable") is not None]
    need(type(value["targets"]) is list and len(value["targets"]) == len(targets) == 2, "gate-two-libraries")
    libraries = (
        ("main", "desktop/src-tauri", "mobile-release-kit-desktop", "mobile_release_desktop", [], SHIPPING_GATE_MAIN_TESTS, "headless"),
        ("native", "desktop/native/macos-installed-native", "mrk-macos-installed-native", "mrk_macos_installed_native",
         ["default", "installed-observation"], SHIPPING_GATE_NATIVE_TESTS, "headless-native"),
    )
    native = None
    for record, (role, directory, package, library, features, names, prefix) in zip(value["targets"], libraries):
        need(type(record) is dict, "gate-library-record")
        package_id = "path+" + (checkout / directory).as_uri() + "#" + package + ("@0.1.1" if package == "mobile-release-kit-desktop" else "@0.1.0")
        expected = {"role": role, "packageId": package_id, "features": features, "names": list(names),
            "originalReturned": True, "artifactOriginalUnchanged": True, "artifactOriginalClosed": True,
            "testsPassed": True, "returncode": 0, "tests": len(names), "failed": 0, "ignored": 0, "measured": 0}
        need(set(record) == set(expected) | {"artifact", "stdoutSha256", "stderrSha256", "filtered"}, "gate-library-keys")
        for key, selected in expected.items():
            _exact(record[key], selected)
        stdout, stderr = bodies[prefix + "-tests.stdout"], bodies[prefix + "-tests.stderr"]
        need(bodies[prefix + "-tests.status"] == b"0\n" and record["stdoutSha256"] == digest(stdout)
             and record["stderrSha256"] == digest(stderr), "gate-data-output-binding")
        _exact(record["filtered"], _gate_libtest(stdout, stderr, 0, names))
        artifact = _gate_artifact(record["artifact"], work, library, target=binding.target)
        matching = [row for row in targets if type(row.get("target")) is dict and row["target"].get("name") == library]
        need(len(matching) == 1, "gate-one-library")
        target = matching[0]
        for actual, selected in ((target.get("package_id"), package_id),
            (target.get("manifest_path"), str(checkout / directory / "Cargo.toml")),
            (target["target"].get("kind"), ["lib"]), (target["target"].get("crate_types"), ["lib"]),
            (target["target"].get("src_path"), str(checkout / directory / "src/lib.rs")),
            (target.get("features"), features), (target.get("executable"), artifact["path"])):
            _exact(actual, selected)
        need(type(target.get("profile")) is dict and target["profile"].get("test") is True, "gate-test-profile")
        if role == "native":
            native = artifact
    return value, native


def _gate_package_anchors(anchors, binding, environment, stage, selection):
    # Five independent, same-book originals. Neither this receipt nor parsed
    # producer DATA supplies its own original exit or signature authority.
    binding.checked()
    need(type(selection) is stage.BuildSelection and selection.target == binding.target, "gate-package-target")
    stage.selected_build(selection)
    inventory, manifest = environment.get("MRK_MACOS_INSTALL_INVENTORY_SHA256"), environment.get("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256")
    need(_gate_sha(inventory) and _gate_sha(manifest) and type(anchors["package-install.status"]) is bytes
         and anchors["package-install.status"] == b"0\n", "gate-package-original-status")
    request_body = anchors["package-request-id.txt"]
    need(type(request_body) is bytes and re.fullmatch(rb"[0-9a-f]{32}\n", request_body)
         and request_body != b"0" * 32 + b"\n", "gate-package-request-original")
    request = request_body[:-1].decode("ascii")
    descriptor = anchors["producer-descriptor-input.json"]
    producer = stage.maintenance_producer_data(descriptor, target=binding.target)
    current = producer["releaseSet"]["current"]
    for key, expected in {"release": selection.release, "packageVersion": selection.package_version,
            "sourceCommit": binding.source, "protocolSha256": stage.CURRENT_PROTOCOL,
            "inventorySha256": inventory, "runtimeManifestSha256": manifest}.items():
        _exact(current[key], expected)
    audit = _gate_json(anchors["package-audit.json"], 16384)
    need(set(audit) == {"schemaVersion", "packageSha256", "packageSize", "originalPackageSha256", "packageInfoSha256",
                       "packageIdentifier", "scriptFileCount", "finalDestinationPayloadEntries", "qualification"}, "gate-package-audit-keys")
    for key, expected in {"schemaVersion": 1, "packageSha256": current["packageSha256"], "packageIdentifier": stage.PACKAGE_ID,
            "finalDestinationPayloadEntries": 0, "qualification": "scripts-only-package-audited-not-installed-or-GUI-qualified"}.items():
        _exact(audit[key], expected)
    need(type(audit["packageSize"]) is int and 0 < audit["packageSize"] <= stage.MAX_BYTES
         and type(audit["scriptFileCount"]) is int and 0 < audit["scriptFileCount"] <= stage.MAX_FILES
         and all(_gate_sha(audit[key]) for key in ("originalPackageSha256", "packageInfoSha256")), "gate-package-audit-bound")
    receipt = _gate_json(anchors["android-helper-package-install.json"], 16384)
    fixed = {"schemaVersion": 1, "phase": "package-install", "target": binding.target, "source": binding.source,
        "workflowSource": binding.source, "workflow": WORKFLOW, "runId": binding.run, "runAttempt": binding.attempt,
        "packageRole": "installed-shell-observation", "toolchain": target_data(binding.target)["toolchain"],
        "helperIdentifier": "dev.mobile-release-kit.desktop.android-register", "passed": True,
        "originalClosesKnown": True, "targetRetired": True, "outerFinalityRequired": True,
        "directStagerIOPending": None, "cleanupErrors": [], "androidServiceAuthenticated": False,
        "androidRegisteredCopyQualified": False, "androidBuildQualified": False,
        "developerIdOrNotarizationQualified": False, "productReady": False}
    need(set(fixed) <= receipt.keys() and "failure" not in receipt, "gate-package-helper-keys")
    for key, expected in fixed.items():
        _exact(receipt[key], expected)
    # Separate credential diagnostics may be added by the same owner. They
    # cannot weaken these original package calls or independent saved status0.
    calls = receipt.get("originalCalls")
    need(type(calls) is list and len(calls) == len(stage.PACKAGING_CALL_ROLES), "gate-package-call-roster")
    for call, role in zip(calls, stage.PACKAGING_CALL_ROLES):
        need(type(call) is dict and set(call) == {"role", "entered", "returned", "capturesSettled", "returncode",
                                                "stdoutSha256", "stderrSha256"}, "gate-package-call-shape")
        for key, expected in {"role": role, "entered": True, "returned": True, "capturesSettled": True}.items():
            _exact(call[key], expected)
        codes = (0, 1) if role in ("installer-log-cursor", "installer-log-capture") else (0,)
        need(type(call["returncode"]) is int and call["returncode"] in codes
             and _gate_sha(call["stdoutSha256"]) and _gate_sha(call["stderrSha256"]), "gate-package-call-original")
    _exact(receipt.get("packageMount"), {"attachEntered": True, "originalKnown": True, "detached": True, "retained": False,
        "installerEntered": True, "installerOriginalZero": True, "sameRequestV2Readback": True, "systemServiceExitClaimed": False})
    distribution = receipt.get("distribution")
    fixed = {"schemaVersion": 1, "kind": "mrk-ordinary-package-observed-v2", "target": binding.target,
        "packageVersion": selection.package_version, "release": selection.release, "requestId": request,
        "packageSha256": audit["packageSha256"], "packageBytes": audit["packageSize"], "descriptorSha256": digest(descriptor),
        "originalInstallerReturnedZero": True, "sameRequestV2Readback": True, "originalMountDetached": True,
        "groupEndpointMet": True, "originalOuterReturnRequired": True,
        "developerIdPurposeAuthority": "native-parent-and-application-checks-separate", "notarizationQualified": False,
        "gatekeeperQualified": False, "systemServiceExitClaimed": False, "productReady": False}
    need(type(distribution) is dict and set(distribution) == set(fixed) | {"signatureSha256", "producerSummary", "userImage",
         "observationImage", "sourceProducerProfileSha256", "sourceServiceProfileSha256", "mountIdentity"}, "gate-package-distribution-keys")
    for key, expected in fixed.items():
        _exact(distribution[key], expected)
    need(all(_gate_sha(distribution[key]) for key in ("signatureSha256", "sourceProducerProfileSha256", "sourceServiceProfileSha256")),
         "gate-package-distribution-digests")
    summary = distribution["producerSummary"]
    need(type(summary) is dict and set(summary) == {"schemaVersion", "kind", "packageSha256", "descriptorSha256",
         "signatureSha256", "descriptorBytes", "signatureBytes"}, "gate-package-producer-summary")
    for key, expected in {"schemaVersion": 1, "kind": "mrk-package-producer-emitted", "packageSha256": audit["packageSha256"],
            "descriptorSha256": digest(descriptor), "signatureSha256": distribution["signatureSha256"], "descriptorBytes": len(descriptor)}.items():
        _exact(summary[key], expected)
    need(type(summary["signatureBytes"]) is int and 0 < summary["signatureBytes"] <= stage.PRODUCER_SIGNATURE_BYTES,
         "gate-package-signature-bound")
    for key, name in (("userImage", "MobileReleaseKit.dmg"), ("observationImage", "MobileReleaseKit-Observation.dmg")):
        image = distribution[key]
        need(type(image) is dict and set(image) == {"file", "sha256", "bytes"} and image["file"] == name
             and _gate_sha(image["sha256"]) and type(image["bytes"]) is int and 0 < image["bytes"] <= stage.MAX_BYTES,
             "gate-package-image-data")
    identity = distribution["mountIdentity"]
    need(type(identity) is list and len(identity) == 5 and all(type(v) is int and 0 <= v < 1 << 64 for v in identity)
         and identity[1] > 0 and stat.S_ISDIR(identity[2]), "gate-package-mount-data")
    return producer, request, summary


def _gate_installation(body, status, binding, environment, stage, selection, anchors):
    need(type(status) is bytes and status == b"0\n", "gate-installer-status-binding")
    producer, request, summary = _gate_package_anchors(anchors, binding, environment, stage, selection)
    current = producer["releaseSet"]["current"]
    value = _gate_json(body, 65536)
    fixed = {"schemaVersion": 2, "sourceCommit": binding.source, "inventorySha256": current["inventorySha256"],
        "runtimeManifestSha256": current["runtimeManifestSha256"], "completedPackageSha256": current["packageSha256"],
        "release": selection.release, "requestId": request, "originalInstallerReturnedZero": True, "originalWriterJoined": True,
        "producerSignatureAuthority": "native-parent-and-application-checks-separate", "historicalOuterExit": "unverified",
        "applicationLaunched": False, "guiSaveQualified": False, "aquaGate": "required-separate-actual-session",
        "qualification": "engineering-install-observed-not-runtime-or-GUI-acceptance"}
    need(set(value) == set(fixed) | {"invocation", "nonrootReadbackFileCount", "originalInstallerResult", "installerResultExport",
                                   "installationMetadata", "maintenanceGate"}, "gate-installation-keys")
    for key, expected in fixed.items():
        _exact(value[key], expected)
    # This is semantic validation by the current pinned parser, NOT the raw
    # exported original's byte encoding, SHA or future finality. Its exception
    # remains the same original object. No v1 or generic-success fallback.
    original = stage.maintenance_result_data(stage.canonical(value["originalInstallerResult"]) + b"\n", request)
    _exact(value["invocation"], original["invocation"])
    count = value["nonrootReadbackFileCount"]
    need(type(count) is int and 0 < count <= stage.MAX_FILES, "gate-installation-count")
    metadata = value["installationMetadata"]
    need(type(metadata) is list and 1 <= len(metadata) <= 9, "gate-installation-generations")
    predecessors = {row["release"] for row in producer["releaseSet"]["acceptedPredecessors"]}
    releases, instances, files, byte_count = set(), set(), 0, 0
    for index, row in enumerate(metadata):
        need(type(row) is dict and set(row) == {"release", "instance", "inventoryBytes", "descriptorBytes", "producerDescriptorBytes",
             "producerSignatureBytes", "verifiedCurrentFiles", "declaredPayloadFiles", "declaredBytes", "historicalOuterExit"},
             "gate-installation-metadata-keys")
        release, instance = row["release"], row["instance"]
        need(type(release) is str and release not in releases and (release == selection.release if index == 0 else release in predecessors)
             and stage.maintenance_hex(instance, 32) and instance not in instances and row["historicalOuterExit"] == "unverified",
             "gate-installation-generation-binding")
        releases.add(release); instances.add(instance)
        for key, limit in (("inventoryBytes", 1024 * 1024), ("descriptorBytes", stage.INSTALLATION_RECORD_LIMIT),
                ("producerDescriptorBytes", stage.PRODUCER_DESCRIPTOR_BYTES), ("producerSignatureBytes", stage.PRODUCER_SIGNATURE_BYTES)):
            need(type(row[key]) is int and 0 < row[key] <= limit, "gate-installation-metadata-bound")
        declared, verified, extent = row["declaredPayloadFiles"], row["verifiedCurrentFiles"], row["declaredBytes"]
        need(type(declared) is int and 0 < declared <= stage.MAX_FILES and type(verified) is int
             and verified == (count if index == 0 else 0) and (index != 0 or declared == count)
             and type(extent) is int and sum(row[key] for key in ("inventoryBytes", "descriptorBytes", "producerDescriptorBytes", "producerSignatureBytes"))
                 <= extent <= stage.MAX_BYTES, "gate-installation-generation-accounting")
        files += declared; byte_count += extent
        need(files <= stage.MAX_FILES and byte_count <= stage.MAX_BYTES, "gate-installation-generation-total")
    _exact(metadata[0]["producerDescriptorBytes"], summary["descriptorBytes"])
    _exact(metadata[0]["producerSignatureBytes"], summary["signatureBytes"])
    action = original["action"]
    need((action != "fresh-install" or len(metadata) == 1) and (action != "update" or len(metadata) >= 2), "gate-installation-action-generations")
    if action in ("fresh-install", "update"):
        _exact(metadata[0]["instance"], original["invocation"])
    # Noop/restore retain an older instance, not the new invocation. Full
    # linked state/intent/capsule transitions and the current payload hashes
    # were checked by maintenance_history_data + observation_command before
    # the independent helper0. This reduced metadata cannot replay that history
    # or establish a historical outer exit, exclusion or signature authority.
    _exact(value["maintenanceGate"], {"state": "protected-permanent-gate-data-correspondence", "bytes": len(stage.MAINTENANCE_GATE_BYTES),
                                    "exclusionObserved": False, "workerFinalityEstablished": False})
    exported = value["installerResultExport"]
    need(type(exported) is dict and set(exported) == {"bytes", "sha256", "identity", "finalityBasis"}
         and type(exported["bytes"]) is int and 0 < exported["bytes"] <= 65536 and _gate_sha(exported["sha256"])
         and exported["finalityBasis"] == "original-successful-Installer-return-and-checked-readback", "gate-installer-export")
    identity = exported["identity"]  # Stager's explicitly legacy order, not new full9.
    need(type(identity) is list and len(identity) == 9 and all(type(v) is int and 0 <= v < 1 << 64 for v in identity)
         and identity[1] > 0 and identity[2:7] == [stat.S_IFREG | 0o444, 1, 0, 0, exported["bytes"]], "gate-installer-export-identity")
    return value


def _gate_file(fixtures, name, parent, limit, *, capture=True):
    fd = fixtures._open(name, parent)
    before = signature(os.fstat(fd))
    need(stat.S_ISREG(before[2]) and before[3] == fixtures.uid and before[4] == fixtures.gid and before[5] == 1
         and not before[2] & 0o7022 and 0 <= before[6] <= limit, "gate-original-file")
    record = {"fd": fd, "parent": parent, "name": name, "full9": before, "sha256": None}
    fixtures.gate_files.append(record)
    body, hashed = _gate_file_read(record, capture)
    record["sha256"] = hashed
    return body, record


def _gate_file_read(record, capture=False):
    fd, parent, name, before = record["fd"], record["parent"], record["name"], record["full9"]
    need(signature(os.fstat(fd)) == before == signature(os.stat(name, dir_fd=parent, follow_symlinks=False)), "gate-original-file-changed")
    hashed, pieces, count = hashlib.sha256(), [], 0
    while count < before[6]:
        part = os.pread(fd, min(65536, before[6] - count), count)
        need(bool(part), "gate-original-short-read")
        hashed.update(part); count += len(part)
        if capture:
            pieces.append(part)
    need(not os.pread(fd, 1, count) and signature(os.fstat(fd)) == before
         == signature(os.stat(name, dir_fd=parent, follow_symlinks=False)), "gate-original-readback-changed")
    return b"".join(pieces), hashed.hexdigest()


def _gate_directory(fixtures, name, parent=None, *, create=False, private=False):
    fd = fixtures._mkdir(parent, name) if create else fixtures._open(name, parent, directory=True)
    before = signature(os.fstat(fd))[:5]
    need(stat.S_ISDIR(before[2]) and before[3:] == (fixtures.uid, fixtures.gid) and not before[2] & 0o7022
         and (not private or before[2] == stat.S_IFDIR | 0o700)
         and signature(os.stat(name, dir_fd=parent, follow_symlinks=False))[:5] == before, "gate-original-directory")
    fixtures.gate_directories.append((fd, parent, name, before, create))
    return fd


def _gate_recheck(fixtures):
    need(not fixtures.inflight, "gate-owner-finality-unknown")
    for fd, parent, name, original, _created in fixtures.gate_directories:
        need(signature(os.fstat(fd))[:5] == original
             == signature(os.stat(name, dir_fd=parent, follow_symlinks=False))[:5], "gate-directory-changed")
    for record in fixtures.gate_files:
        need(_gate_file_read(record)[1] == record["sha256"], "gate-original-hash-changed")


def _gate_load_stager(fixtures, checkout, *, target=ARM_TARGET):
    import importlib.util
    target_row = target_data(target)
    selected, bodies = [], {}
    for relative, expected in SHIPPING_GATE_SOURCE_PINS.items():
        body, original = _gate_file(fixtures, str(checkout / relative), None, 256 * 1024)
        need(digest(body) == expected, "gate-stager-source-pin")
        selected.append(original)
        bodies[relative] = body
    name = "_mrk_shipping_gate_stager"
    need(name not in sys.modules, "gate-stager-already-imported")
    spec = importlib.util.spec_from_file_location(name, checkout / "desktop/tools/stage_macos_installed.py")
    need(spec is not None and spec.loader is not None, "gate-stager-loader")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    # ARM is mandatory import support even on Intel. Both release originals
    # remain in this same book; no second source_build_selection filesystem read.
    # No Installer, protected-installation readback or payload command is called.
    spec.loader.exec_module(module)
    release = module.build_release_data(bodies["desktop/macos-installed-inputs/" + target_row["releaseInput"]], target=target)
    selection = module.BuildSelection(target, release["packageVersion"], release["release"])
    for original in selected:
        need(_gate_file_read(original)[1] == original["sha256"], "gate-stager-source-changed")
    # Retained through use, rechecked by the ordinary gate POST, then consumed
    # only by its existing final settlement. Import is never a close witness.
    return module, selection


def _gate_dependencies(fixtures, binding, checkout, work, environment):
    need(work.parent == Path("/Users/runner/work/_temp") and re.fullmatch(r"mrk-macos-aqua\.[A-Za-z0-9]{8}", work.name)
         and environment.get("CARGO_TARGET_DIR") == str(work / "cargo-target")
         and environment.get("MRK_MACOS_AQUA_SCOPE") in SHIPPING_GATE_SCOPES, "gate-fixed-work-route")
    fixtures.gate_work = _gate_directory(fixtures, str(work), private=True)
    limits = {"headless-tests.receipt.json": 16384, "headless-build.jsonl": 4 * 1024 * 1024, "headless-build.status": 4,
              "installation-observation.json": 65536, "installer-output.status": 4,
              "package-install.status": 4, "package-request-id.txt": 33, "package-audit.json": 16384,
              "producer-descriptor-input.json": 65536, "android-helper-package-install.json": 16384}
    for prefix in ("headless", "headless-native"):
        limits.update({prefix + "-tests.stdout": 65536, prefix + "-tests.stderr": 65536, prefix + "-tests.status": 4})
    bodies = {name: _gate_file(fixtures, name, fixtures.gate_work, limit)[0] for name, limit in limits.items()}
    headless, native = _gate_headless(bodies, binding, checkout, work)
    need(_gate_integers(headless["workOriginal"], 5) == signature(os.fstat(fixtures.gate_work))[:5], "gate-original-work-binding")
    stage, selection = _gate_load_stager(fixtures, checkout, target=binding.target)
    _gate_installation(bodies["installation-observation.json"], bodies["installer-output.status"], binding, environment,
                       stage, selection, bodies)
    return bodies, headless, native


def _gate_new_report(binding, scope):
    return {"schemaVersion": 1, "type": "macos-installed-shipping-gate-control", **binding.public(),
        "workflow": WORKFLOW, "workflowSource": binding.source, "aquaScope": scope, "platform": target_data(binding.target)["platform"],
        "toolchain": target_data(binding.target)["toolchain"], "testName": SHIPPING_GATE_TEST, "headlessReceiptSha256": None,
        "compilerJsonSha256": None, "installationReadbackSha256": None, "artifact": None,
        "ownerEntered": False, "originalCallReturned": False, "ownerReturncode": None, "ownerElapsedNanoseconds": None,
        "stdoutSha256": None, "stderrSha256": None, "stdoutBytes": None, "stderrBytes": None, "namedTestPassed": False,
        "sourceReadbacksUnchanged": False, "artifactOriginalUnchanged": False, "artifactCloseAttempts": 0,
        "artifactOriginalClosed": False, "artifactRetired": False, "fixtureDirectoriesRetired": False,
        "fixtureHandlesClosed": False, "failure": None, "cleanupErrors": [], "passed": False,
        "actualParentProcessDisappearanceEstablished": False, "allWorkerPopulationsQualified": False,
        "directLoaderQualified": False, "shippingBinaryQualified": False, "distributionQualified": False}


def _gate_error(error, stage):
    label = str(error) if type(error) is Refused else "original-operation-error"
    if re.fullmatch(r"[a-z][a-z0-9-]{0,63}", label) is None:
        label = "original-operation-error"
    return {"stage": stage, "reason": label, "type": type(error).__name__[:64]}


def _gate_settle(fixtures, report, error):
    # Entered-but-unreturned owner means no readback, close, deletion or next call.
    if fixtures.inflight:
        return error
    try:
        _gate_recheck(fixtures)
        report["sourceReadbacksUnchanged"] = True
        report["artifactOriginalUnchanged"] = fixtures.gate_artifact is not None
    except BaseException as caught:
        if error is None:
            error = caught; report["failure"] = _gate_error(caught, "original-readback")
        else:
            report["cleanupErrors"].append(_gate_error(caught, "original-readback"))
    attempted_closes = set()
    file_closes_known = True
    for original in fixtures.gate_files:
        fd = original["fd"]
        attempted_closes.add(fd)  # Even an unexpected consuming-call exception is never retried.
        if original is fixtures.gate_artifact:
            report["artifactCloseAttempts"] += 1
        try:
            closed = fixtures._close(fd)
        except BaseException as caught:
            closed = False
            report["cleanupErrors"].append(_gate_error(caught, "original-file-close-call"))
        if closed is not True:
            file_closes_known = False
        if original is fixtures.gate_artifact:
            report["artifactOriginalClosed"] = closed
        if not closed and fixtures.first_close_error is not None:
            report["cleanupErrors"].append(_gate_error(fixtures.first_close_error, "original-file-close"))
    created = [row for row in fixtures.gate_directories if row[4]]
    if file_closes_known and not fixtures.close_errors:
        retired = 0
        for fd, parent, name, expected, _created in reversed(created):
            try:
                need(signature(os.fstat(fd))[:5] == expected
                     == signature(os.stat(name, dir_fd=parent, follow_symlinks=False))[:5], "gate-fixture-retirement-original")
                os.rmdir(name, dir_fd=parent)  # Empty only; never recursive or adopted paths.
                retired += 1
            except BaseException as caught:
                report["cleanupErrors"].append(_gate_error(caught, "empty-fixture-retirement"))
        report["fixtureDirectoriesRetired"] = len(created) == retired == 3
    # Preserve failed/unknown binary outputs for diagnosis. Successful original
    # test code is no longer needed by the remaining observer/Installer outputs.
    if error is None and not report["cleanupErrors"] and report["namedTestPassed"] and report["artifactOriginalClosed"] and report["fixtureDirectoriesRetired"]:
        try:
            original = fixtures.gate_artifact
            need(signature(os.stat(original["name"], dir_fd=original["parent"], follow_symlinks=False)) == original["full9"], "gate-retirement-original")
            for fd, parent, name, expected, created in fixtures.gate_directories:
                if created:
                    continue  # These proven empty originals were just removed.
                need(signature(os.fstat(fd))[:5] == expected
                     == signature(os.stat(name, dir_fd=parent, follow_symlinks=False))[:5], "gate-retirement-directory")
            os.unlink(original["name"], dir_fd=original["parent"])
            try:
                os.stat(original["name"], dir_fd=original["parent"], follow_symlinks=False)
            except FileNotFoundError:
                report["artifactRetired"] = True
            else:
                raise Refused("gate-retirement-incomplete")
        except BaseException as caught:
            report["cleanupErrors"].append(_gate_error(caught, "native-test-binary-retirement"))
    for fd in tuple(fixtures.fds):
        if fd in attempted_closes:
            continue
        attempted_closes.add(fd)
        try:
            if not fixtures._close(fd):
                report["cleanupErrors"].append(_gate_error(fixtures.first_close_error, "original-descriptor-close"))
        except BaseException as caught:
            report["cleanupErrors"].append(_gate_error(caught, "original-descriptor-close-call"))
    report["fixtureHandlesClosed"] = not fixtures.fds and fixtures.close_errors == 0
    return error


def run_shipping_gate_control(binding, fixtures, run_owned, checkout, work, environment, *, clock=None):
    """One fixed existing-owner call; tests inject only an inert callable/clock."""
    import time
    if clock is None:
        clock = time.monotonic_ns
    report = _gate_new_report(binding, environment.get("MRK_MACOS_AQUA_SCOPE"))
    error, phase = None, "dependency-admission"
    try:
        bodies, headless, native = _gate_dependencies(fixtures, binding, checkout, work, environment)
        report.update(headlessReceiptSha256=digest(bodies["headless-tests.receipt.json"]),
                      compilerJsonSha256=headless["compilerJsonSha256"],
                      installationReadbackSha256=digest(bodies["installation-observation.json"]), artifact=native)
        target = _gate_directory(fixtures, "cargo-target", fixtures.gate_work, private=True)
        need(signature(os.fstat(target))[:5] == _gate_integers(headless["cargoTargetOriginal"], 5), "gate-original-target-binding")
        parent = target
        for name in (binding.target, "debug", "deps"):
            parent = _gate_directory(fixtures, name, parent)
        binary = Path(native["path"])
        _body, original = _gate_file(fixtures, binary.name, parent, 1024 * 1024 * 1024, capture=False)
        fixtures.gate_artifact = original
        need(original["full9"] == _gate_integers(native["full9"], 9) and original["sha256"] == native["sha256"], "gate-live-native-artifact")
        cwd = _gate_directory(fixtures, "shipping-gate-control", fixtures.gate_work, create=True)
        _gate_directory(fixtures, "home", cwd, create=True)
        _gate_directory(fixtures, "tmp", cwd, create=True)
        _gate_recheck(fixtures)
        argv = [str(binary), "--exact", "--ignored", "--test-threads=1", "--color=never", "--format=pretty", SHIPPING_GATE_TEST]
        private = work / "shipping-gate-control"
        phase = "original-native-invocation"
        start = clock()
        need(type(start) is int and start >= 0, "gate-owner-clock")
        fixtures.inflight, report["ownerEntered"] = True, True
        returned = run_owned(argv, environ={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(private / "home"),
            "TMPDIR": str(private / "tmp"), "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}, cwd=private,
            timeout=30, capture=True, text=False, output_limit=64 * 1024)
        need(type(returned) is subprocess.CompletedProcess and type(returned.args) is list and returned.args == argv
             and type(returned.returncode) is int and type(returned.stdout) is bytes and type(returned.stderr) is bytes
             and len(returned.stdout) + len(returned.stderr) <= 64 * 1024, "gate-owner-return-contract")
        fixtures.inflight, report["originalCallReturned"] = False, True
        report.update(ownerReturncode=returned.returncode, stdoutSha256=digest(returned.stdout), stderrSha256=digest(returned.stderr),
                      stdoutBytes=len(returned.stdout), stderrBytes=len(returned.stderr))
        end = clock()
        need(type(end) is int and start <= end, "gate-owner-clock")
        report["ownerElapsedNanoseconds"] = str(end - start)
        need(end - start < 30_000_000_000, "gate-owner-deadline")
        phase = "exact-native-result"
        _gate_libtest(returned.stdout, returned.stderr, returned.returncode, (SHIPPING_GATE_TEST,))
        report["namedTestPassed"] = True
    except BaseException as caught:
        error = caught; report["failure"] = _gate_error(caught, phase)
    error = _gate_settle(fixtures, report, error)
    report["passed"] = (error is None and not report["cleanupErrors"] and report["ownerEntered"]
        and report["originalCallReturned"] and report["ownerReturncode"] == 0 and report["namedTestPassed"]
        and report["sourceReadbacksUnchanged"] and report["artifactOriginalUnchanged"]
        and report["artifactCloseAttempts"] == 1 and report["artifactOriginalClosed"] and report["artifactRetired"]
        and report["fixtureDirectoriesRetired"] and report["fixtureHandlesClosed"])
    return report


def _gate_completion(body, binding, scope, bodies, headless, native):
    value = _gate_json(body)
    expected = _gate_new_report(binding, scope)
    need(set(value) == set(expected), "gate-control-receipt-keys")
    elapsed = _gate_integers([value["ownerElapsedNanoseconds"]], 1)[0]
    need(0 <= elapsed < 30_000_000_000 and _gate_sha(value["stdoutSha256"]), "gate-control-result-binding")
    need(type(value["stdoutBytes"]) is int and type(value["stderrBytes"]) is int
         and 0 <= value["stdoutBytes"] <= 64 * 1024 and value["stderrBytes"] == 0
         and value["stdoutBytes"] + value["stderrBytes"] <= 64 * 1024, "gate-control-output-byte-counts")
    expected.update(headlessReceiptSha256=digest(bodies["headless-tests.receipt.json"]),
        compilerJsonSha256=headless["compilerJsonSha256"], installationReadbackSha256=digest(bodies["installation-observation.json"]),
        artifact=native, ownerEntered=True, originalCallReturned=True, ownerReturncode=0,
        ownerElapsedNanoseconds=str(elapsed), stdoutSha256=value["stdoutSha256"], stderrSha256=digest(b""),
        stdoutBytes=value["stdoutBytes"], stderrBytes=0,
        namedTestPassed=True, sourceReadbacksUnchanged=True, artifactOriginalUnchanged=True, artifactCloseAttempts=1,
        artifactOriginalClosed=True, artifactRetired=True, fixtureDirectoriesRetired=True, fixtureHandlesClosed=True, passed=True)
    _exact(value, expected)
    return {"receiptSha256": digest(body), "parentReferenceCloseNoGoGateControlPassed": True,
            "testName": SHIPPING_GATE_TEST, "actualParentProcessDisappearanceEstablished": False,
            "allWorkerPopulationsQualified": False, "directLoaderQualified": False}


def require_shipping_gate_receipt(binding, uid, gid, checkout, work, environment):
    fixtures = Fixtures(binding, uid, gid, VAULT_HELPER_SCOPE)
    error, result = None, None
    try:
        bodies, headless, native = _gate_dependencies(fixtures, binding, checkout, work, environment)
        body = _gate_file(fixtures, SHIPPING_GATE_REPORT, fixtures.gate_work, 24 * 1024)[0]
        status = _gate_file(fixtures, SHIPPING_GATE_STATUS, fixtures.gate_work, 4)[0]
        need(status == b"0\n", "gate-control-original-status")
        result = _gate_completion(body, binding, environment["MRK_MACOS_AQUA_SCOPE"], bodies, headless, native)
        _gate_recheck(fixtures)
    except BaseException as caught:
        error = caught
    cleanup_error = None
    try:
        fixtures.close()  # No native owner was entered here; consume each original once.
    except BaseException as caught:
        cleanup_error = caught
        if error is None:
            error = caught
    if error is not None:
        if cleanup_error is not None and cleanup_error is not error:
            raise error from cleanup_error  # Same primary object, separate actual cleanup error.
        raise error
    return result


def shipping_gate_control_main(*, target=ARM_TARGET):
    binding = None
    try:
        root = Path(__file__).absolute().parents[2]
        binding, uid, gid, _username = admit(os.environ, root, target=target)
        need(os.environ.get("MRK_MACOS_AQUA_SCOPE") in SHIPPING_GATE_SCOPES, "gate-fixed-shipping-scope")
        owner = load_owner(root)
        os.umask(0o077)
        fixtures = Fixtures(binding, uid, gid, VAULT_HELPER_SCOPE)
        result = run_shipping_gate_control(binding, fixtures, owner.run_owned, root, Path(os.environ["MRK_MACOS_WORK"]), os.environ)
        emit_record(result, sys.stdout)
        return 0 if result["passed"] else 1
    except BaseException as error:
        # Admission/publication failure remains nonzero; no fallback owner,
        # unbounded traceback, fabricated receipt or native retry is offered.
        try:
            emit_record({"schemaVersion": 1, "type": "macos-shipping-gate-control-admission-failure",
                         "failure": _gate_error(error, "admission-or-publication"), "passed": False}, sys.stdout)
        except BaseException:
            pass
        return 130 if isinstance(error, KeyboardInterrupt) else 1


# Independent capacity DATA3 from the already compiled ordinary app library.
# Never widen DATA13, its owner-call count, or the installed ignored1 contract.
SHIPPING_CAPACITY_TESTS = tuple("installed_runtime::android_registration_source::storage_capacity_tests::" + name for name in (
    "phase_checked_allocation_uses_exact_admitted_records_without_native_entry",
    "source_heap_formula_keeps_fourth_alias_string_and_checked_limits",
    "observed_sha_text_has_exact_charged_capacity",
))
SHIPPING_CAPACITY_REPORT = "shipping-capacity-data.receipt.json"
SHIPPING_CAPACITY_STATUS = "shipping-capacity-data.status"


def _capacity_dependencies(fixtures, binding, checkout, work, environment):
    need(work.parent == Path("/Users/runner/work/_temp") and re.fullmatch(r"mrk-macos-aqua\.[A-Za-z0-9]{8}", work.name)
         and environment.get("CARGO_TARGET_DIR") == str(work / "cargo-target")
         and environment.get("MRK_MACOS_AQUA_SCOPE") in SHIPPING_GATE_SCOPES, "capacity-fixed-work-route")
    fixtures.gate_work = _gate_directory(fixtures, str(work), private=True)
    limits = {"headless-tests.receipt.json": 16384, "headless-build.jsonl": 4 * 1024 * 1024, "headless-build.status": 4}
    for prefix in ("headless", "headless-native"):
        limits.update({prefix + "-tests.stdout": 65536, prefix + "-tests.stderr": 65536, prefix + "-tests.status": 4})
    bodies = {name: _gate_file(fixtures, name, fixtures.gate_work, limit)[0] for name, limit in limits.items()}
    # This unchanged validator still requires exactly two libraries, DATA13 and
    # three returned original calls. No Installer/readback dependency belongs here.
    headless, _native = _gate_headless(bodies, binding, checkout, work)
    need(_gate_integers(headless["workOriginal"], 5) == signature(os.fstat(fixtures.gate_work))[:5], "capacity-original-work-binding")
    return bodies, headless, headless["targets"][0]["artifact"]


def _capacity_new_report(binding, scope):
    return {"schemaVersion": 1, "type": "macos-shipping-capacity-data", **binding.public(),
        "workflow": WORKFLOW, "workflowSource": binding.source, "aquaScope": scope, "platform": target_data(binding.target)["platform"],
        "toolchain": target_data(binding.target)["toolchain"], "names": list(SHIPPING_CAPACITY_TESTS), "features": [],
        "headlessReceiptSha256": None, "compilerJsonSha256": None, "artifact": None,
        "ownerCallsEntered": 0, "ownerCallsReturned": 0, "originalCallReturned": False, "ownerReturncode": None,
        "ownerElapsedNanoseconds": None, "finalElapsedNanoseconds": None, "deadlineMetAfterFinalCloses": False,
        "stdoutSha256": None, "stderrSha256": None, "stdoutBytes": None, "stderrBytes": None, "namedTestsPassed": False,
        "tests": None, "failed": None, "ignored": None, "measured": None, "filtered": None,
        "sourceReadbacksUnchanged": False, "artifactOriginalUnchanged": False, "artifactCloseAttempts": 0,
        "artifactOriginalClosed": False, "artifactRetired": False, "cargoTargetRetired": False,
        "fixtureDirectoriesRetired": False, "fixtureHandlesClosed": False, "failure": None, "cleanupErrors": [], "passed": False,
        "qualification": "native-layout-and-inert-allocation-data-only", "nativeSourceOperationQualified": False,
        "genuineCatalogueQualified": False, "combinedBudgetFitEstablished": False,
        "shippingBinaryQualified": False, "distributionQualified": False}


def _capacity_settle(fixtures, report, error):
    # Same original-owner boundary as ignored1, but no binary or target retirement.
    # Unknown original return forbids readback, consuming close and empty-dir work.
    if fixtures.inflight:
        return error
    try:
        _gate_recheck(fixtures)
        report["sourceReadbacksUnchanged"] = True
        report["artifactOriginalUnchanged"] = fixtures.gate_artifact is not None
    except BaseException as caught:
        if error is None:
            error = caught; report["failure"] = _gate_error(caught, "original-readback")
        else:
            report["cleanupErrors"].append(_gate_error(caught, "original-readback"))
    attempted_closes, file_closes_known = set(), True
    for original in fixtures.gate_files:
        fd = original["fd"]
        attempted_closes.add(fd)  # A consuming exception never permits a retry.
        if original is fixtures.gate_artifact:
            report["artifactCloseAttempts"] += 1
        try:
            closed = fixtures._close(fd)
        except BaseException as caught:
            closed = False
            report["cleanupErrors"].append(_gate_error(caught, "original-file-close-call"))
        if closed is not True:
            file_closes_known = False
        if original is fixtures.gate_artifact:
            report["artifactOriginalClosed"] = closed is True
        if closed is not True and fixtures.first_close_error is not None:
            report["cleanupErrors"].append(_gate_error(fixtures.first_close_error, "original-file-close"))
    created = [row for row in fixtures.gate_directories if row[4]]
    if file_closes_known and not fixtures.close_errors:
        retired = 0
        for fd, parent, name, expected, _created in reversed(created):
            try:
                need(signature(os.fstat(fd))[:5] == expected
                     == signature(os.stat(name, dir_fd=parent, follow_symlinks=False))[:5], "capacity-fixture-retirement-original")
                os.rmdir(name, dir_fd=parent)  # Only these fresh empty originals.
                retired += 1
            except BaseException as caught:
                report["cleanupErrors"].append(_gate_error(caught, "empty-fixture-retirement"))
        report["fixtureDirectoriesRetired"] = len(created) == retired == 3
    # Keep SAME app/native binaries and cargo-target. Later builds and ignored1
    # retain their existing ownership and independent live identity admission.
    for fd in tuple(fixtures.fds):
        if fd in attempted_closes:
            continue
        attempted_closes.add(fd)
        try:
            if fixtures._close(fd) is not True:
                report["cleanupErrors"].append(_gate_error(fixtures.first_close_error, "original-descriptor-close"))
        except BaseException as caught:
            report["cleanupErrors"].append(_gate_error(caught, "original-descriptor-close-call"))
    report["fixtureHandlesClosed"] = not fixtures.fds and fixtures.close_errors == 0
    return error


def run_shipping_capacity_data(binding, fixtures, run_owned, checkout, work, environment, *, clock=None):
    """One fixed existing-owner DATA call; no compile, Installer or native probe."""
    import time
    if clock is None:
        clock = time.monotonic_ns
    report = _capacity_new_report(binding, environment.get("MRK_MACOS_AQUA_SCOPE"))
    error, phase, start, end = None, "dependency-admission", None, None
    try:
        bodies, headless, app = _capacity_dependencies(fixtures, binding, checkout, work, environment)
        report.update(headlessReceiptSha256=digest(bodies["headless-tests.receipt.json"]),
                      compilerJsonSha256=headless["compilerJsonSha256"], artifact=app)
        target = _gate_directory(fixtures, "cargo-target", fixtures.gate_work, private=True)
        need(signature(os.fstat(target))[:5] == _gate_integers(headless["cargoTargetOriginal"], 5), "capacity-original-target-binding")
        parent = target
        for name in (binding.target, "debug", "deps"):
            parent = _gate_directory(fixtures, name, parent)
        binary = Path(app["path"])
        _body, original = _gate_file(fixtures, binary.name, parent, 1024 * 1024 * 1024, capture=False)
        fixtures.gate_artifact = original
        need(original["full9"] == _gate_integers(app["full9"], 9) and original["sha256"] == app["sha256"], "capacity-live-main-artifact")
        cwd = _gate_directory(fixtures, "shipping-capacity-data", fixtures.gate_work, create=True)
        _gate_directory(fixtures, "home", cwd, create=True)
        _gate_directory(fixtures, "tmp", cwd, create=True)
        _gate_recheck(fixtures)
        argv = [str(binary), "--exact", "--test-threads=1", "--color=never", "--format=pretty", *SHIPPING_CAPACITY_TESTS]
        private = work / "shipping-capacity-data"
        phase = "original-capacity-invocation"
        start = clock()  # One start: the return and final-close gates share it.
        need(type(start) is int and start >= 0, "capacity-owner-clock")
        fixtures.inflight, report["ownerCallsEntered"] = True, 1
        returned = run_owned(argv, environ={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(private / "home"),
            "TMPDIR": str(private / "tmp"), "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}, cwd=private,
            timeout=30, capture=True, text=False, output_limit=64 * 1024)
        need(type(returned) is subprocess.CompletedProcess and type(returned.args) is list and returned.args == argv
             and type(returned.returncode) is int and type(returned.stdout) is bytes and type(returned.stderr) is bytes
             and len(returned.stdout) + len(returned.stderr) <= 64 * 1024, "capacity-owner-return-contract")
        fixtures.inflight, report["originalCallReturned"], report["ownerCallsReturned"] = False, True, 1
        report.update(ownerReturncode=returned.returncode, stdoutSha256=digest(returned.stdout), stderrSha256=digest(returned.stderr),
                      stdoutBytes=len(returned.stdout), stderrBytes=len(returned.stderr))
        end = clock()
        need(type(end) is int and start <= end, "capacity-owner-clock")
        report["ownerElapsedNanoseconds"] = str(end - start)
        need(end - start < 30_000_000_000, "capacity-owner-deadline")
        phase = "exact-capacity-result"
        filtered = _gate_libtest(returned.stdout, returned.stderr, returned.returncode, SHIPPING_CAPACITY_TESTS)
        report.update(namedTestsPassed=True, tests=3, failed=0, ignored=0, measured=0, filtered=filtered)
    except BaseException as caught:
        error = caught; report["failure"] = _gate_error(caught, phase)
    # Even a late, but known, original return still consumes independent owned
    # closes once. It cannot renew the original deadline or manufacture success.
    error = _capacity_settle(fixtures, report, error)
    if report["originalCallReturned"]:
        try:
            final = clock()
            need(type(final) is int and type(end) is int and start <= end <= final, "capacity-final-clock")
            report["finalElapsedNanoseconds"] = str(final - start)
            need(final - start < 30_000_000_000, "capacity-final-deadline")
            report["deadlineMetAfterFinalCloses"] = report["fixtureHandlesClosed"] is True
        except BaseException as caught:
            if error is None:
                error = caught; report["failure"] = _gate_error(caught, "after-final-closes")
            else:
                report["cleanupErrors"].append(_gate_error(caught, "after-final-closes"))
    report["passed"] = (error is None and not report["cleanupErrors"] and report["ownerCallsEntered"] == report["ownerCallsReturned"] == 1
        and report["originalCallReturned"] and report["ownerReturncode"] == 0 and report["namedTestsPassed"]
        and report["sourceReadbacksUnchanged"] and report["artifactOriginalUnchanged"]
        and report["artifactCloseAttempts"] == 1 and report["artifactOriginalClosed"]
        and report["fixtureDirectoriesRetired"] and report["fixtureHandlesClosed"] and report["deadlineMetAfterFinalCloses"])
    return report


def shipping_capacity_data_main(*, target=ARM_TARGET):
    try:
        root = Path(__file__).absolute().parents[2]
        binding, uid, gid, _username = admit(os.environ, root, target=target)
        need(os.environ.get("MRK_MACOS_AQUA_SCOPE") in SHIPPING_GATE_SCOPES, "capacity-fixed-shipping-scope")
        owner = load_owner(root)
        os.umask(0o077)
        fixtures = Fixtures(binding, uid, gid, VAULT_HELPER_SCOPE)
        result = run_shipping_capacity_data(binding, fixtures, owner.run_owned, root, Path(os.environ["MRK_MACOS_WORK"]), os.environ)
        emit_record(result, sys.stdout)
        return 0 if result["passed"] is True else 1
    except BaseException as error:
        try:
            emit_record({"schemaVersion": 1, "type": "macos-shipping-capacity-data-admission-failure",
                         "failure": _gate_error(error, "admission-or-publication"), "passed": False}, sys.stdout)
        except BaseException:
            pass
        return 130 if isinstance(error, KeyboardInterrupt) else 1

def diagnostic(error, owner, fixtures):
    # Preserve individual typed public lifetime facts, not a synthesized pass
    # from a later exception. Missing fields remain unknown (JSON null).
    pending, seen, facts = [error], set(), []
    while pending and len(seen) < 16:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        if owner is not None and isinstance(current, (owner.ProcessError, owner.ProcessInterrupted)):
            row = {"type": "interrupted" if isinstance(current, owner.ProcessInterrupted) else "process-error"}
            for source, target in (("dispatched", "dispatched"), ("contained", "contained"), ("cleanup_complete", "cleanupComplete")):
                value = getattr(current, source, None)
                row[target] = value if type(value) is bool else None
            facts.append(row)
        pending.extend((current.__context__, current.__cause__))
    label = str(error) if type(error) is Refused else "interrupted" if isinstance(error, (KeyboardInterrupt, SystemExit)) else "helper-or-owner-error"
    if re.fullmatch(r"[a-z][a-z0-9-]{0,63}", label) is None:
        label = "helper-refused"
    result = {"schemaVersion": 1, "type": "macos-aqua-failure", "status": "failed", "reason": label,
            "case": fixtures.case if fixtures else None, "stage": fixtures.stage if fixtures else "admission-or-source",
            "originalCallReturned": fixtures.last_returned if fixtures else False,
            "appReturncode": fixtures.app_returncode if fixtures else None,
            "innerFailureStep": fixtures.inner_failure_step if fixtures else None,
            "innerFailureReason": fixtures.inner_failure_reason if fixtures else None,
            "innerFailureContext": fixtures.inner_failure_context if fixtures else None,
            "innerBootstrapDiagnostic": getattr(fixtures, "inner_bootstrap_diagnostic", None),
            "innerDiagnosticSource": fixtures.inner_diagnostic_source if fixtures else None,
            "innerDiagnosticCompleteness": "complete" if fixtures and fixtures.last_returned else "unknown",
            "invocationFinality": "unknown" if fixtures and fixtures.inflight else "no-pending-invocation",
            "innerOutput": "unavailable" if fixtures and fixtures.inflight else "not-exported",
            "typedLifetimeFacts": facts, "exceptionChainTruncated": bool(pending),
            "fixtureCloseErrors": fixtures.close_errors if fixtures else 0,
            "fixturesPreserved": True, "laterCasesStopped": True}
    try:
        precursor = getattr(fixtures, "precursor_diagnostic", None)
        if precursor is not None:
            result["precursorDiagnostic"] = precursor
        location = _result_location(getattr(error, "result_location", None)) if type(error) is Refused else None
        if location is not None:
            result["resultLocation"] = location
    except BaseException:
        pass  # Keep the original refusal/lifetime facts if optional detail fails.
    return result


def emit_record(value, stream):
    data = json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
    project_fields = (type(value) is dict and type(value.get("type")) is str and value["type"] == "macos-aqua-case"
                      and type(value.get("case")) is str and value["case"] == PROJECT_FIELDS_CASE)
    need(len(data.encode("ascii")) <= (40 * 1024 if project_fields else 24 * 1024), "outer-result-bound")
    stream.write(data + "\n")
    stream.flush()


def main():
    fixtures = owner = binding = None
    scope = None
    original_error = None
    not_executed = ()
    shipping_gate = None
    try:
        scope, target = entry_arguments(sys.argv[1:])
        root = Path(__file__).absolute().parents[2]
        binding, uid, gid, username = admit(os.environ, root, target=target)
        if scope in (RECOVERY_CASE, IOS_ACCOUNT_CASE):
            supplier_origin, supplier_receipt_sha = recovery_supplier_route(
                os.environ.get("MRK_MACOS_RUNTIME_SUPPLIER", "historical"),
                os.environ.get("MRK_MACOS_PYTHON_SUPPLIER_SHA256"))
        owner = load_owner(root)  # Native main only; no module-import-time core.
        os.umask(0o077)
        if scope == VAULT_HELPER_SCOPE:
            # The installed no-GO control must have actually succeeded in this
            # same source/run/attempt before any ordinary app can hold SH.
            shipping_gate = require_shipping_gate_receipt(binding, uid, gid, root, Path(os.environ["MRK_MACOS_WORK"]), os.environ)
        fixtures = Fixtures(binding, uid, gid, scope)
        fixtures.prepare()
        if scope in (RECOVERY_CASE, IOS_ACCOUNT_CASE):
            fixtures.admit_recovery_runtime(root, Path(os.environ["MRK_MACOS_WORK"]),
                supplier_origin=supplier_origin, supplier_receipt_sha256=supplier_receipt_sha)
        not_executed = run_cases(binding, fixtures, owner.run_owned, uid, username, lambda value: emit_record(value, sys.stdout), scope)
    except BaseException as error:
        original_error = error
    if fixtures is not None and not fixtures.inflight:
        try:
            fixtures.close()
        except BaseException as error:
            if original_error is None:
                original_error = error  # Never overwrite an earlier failure.
    if original_error is not None:
        # The original exception object reaches this boundary unchanged. This
        # CLI emits bounded DATA and a nonzero status, never its traceback,
        # arbitrary message, child transcript or private source/project paths.
        try:
            emit_record(diagnostic(original_error, owner, fixtures), sys.stderr)
        except BaseException:
            pass  # Output loss remains failure; there is no diagnostic retry.
        return 130 if isinstance(original_error, KeyboardInterrupt) else 1
    try:
        complete = {"schemaVersion": 1, "type": "macos-aqua-complete", **binding.public(), "cases": list(selected_cases(scope)),
                    "allOriginalCallsReturned": True, "independentReadbacks": True, "fixtureHandlesClosed": True,
                    "instrumentedEngineeringApp": True, "shippingBinaryQualified": False, "distributionQualified": False}
        if scope == VAULT_HELPER_SCOPE:
            complete.update(shippingGateControl=shipping_gate, notExecutedCases=list(not_executed), focusedCasesPassed=not not_executed,
                            normalPersistenceEnabled=True, privateFixturesRetained=True,
                            syntheticKeychainRowRetirement="disposable-hosted-account-only")
        emit_record(complete, sys.stdout)
    except BaseException:
        return 1
    # A missing/locked/refused login Keychain is useful negative evidence,
    # never a successful positive prerequisite or a green qualification run.
    return 2 if not_executed else 0


if __name__ == "__main__":
    raise SystemExit(main())
