#!/usr/bin/env python3
"""One fixed, nonshipping macOS E2 native fixture.

Import is DATA-only. The native entry authenticates its original hosted source,
loads the existing process owner, builds two separate images, and invokes one
installed fixture. The explicit layout diagnostic observes two public statuses
instead and never enters registration. Parsed DATA never authorizes a service
operation. Neither route qualifies publisher identity, the desktop UI or distribution.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import struct
import subprocess
import sys
import time

REPOSITORY = "Apdelrahman1911/mobile-release-kit"
REF = "refs/heads/verify/desktop-macos-maintenance-fixture"
WORKFLOW = REPOSITORY + "/.github/workflows/desktop-macos-maintenance-fixture.yml@" + REF
CHECKOUT = Path("/Users/runner/work/mobile-release-kit/mobile-release-kit")
WORK_PARENT = Path("/Users/runner/work/_temp")
ROOT = Path("/Library/Application Support/MobileReleaseKit-E2NativeFixture")
APP = "MRK E2 Native Fixture.app"
NESTED = APP + "/Contents/Helpers/MRK E2 Native Client.app"
CONTENTS = NESTED + "/Contents/"
ENTRY = APP + "/Contents/MacOS/mrk-e2-native-entry"
CLIENT = CONTENTS + "MacOS/mrk-e2-native-client"
RESIDENT = CONTENTS + "Helpers/mrk-e2-native-resident"
IMAGES = {role: CONTENTS + "Frameworks/libmrk_e2_native_" + role + ".dylib"
          for role in ("client", "resident")}
IDENTIFIER = "dev.mobile-release-kit.fixture.e2"
SERVICE = IDENTIFIER + ".resident"
PACKAGE = IDENTIFIER + ".pkg.v1"
PLIST = CONTENTS + "Library/LaunchDaemons/" + SERVICE + ".plist"
GATE = "maintenance-gate-v1"
TARGET = "aarch64-apple-darwin"
NATIVE = "desktop/native/macos-installed-native"
HELPER = "desktop/helpers/macos-android-register"
INSTALLER = "desktop/src-tauri"
TOOLCHAIN = "1.98.1"
RUST_COMMIT = "48a229ceaefd4985c50990b14116b6d856af0985"
CASES = ("missing-b-refused", "local-f-before-admission", "genuine-tail-unregister")
NATIVE_RUST_TESTS = (
    "tests::compiled_machine_and_translation_data_refuse_foreign_or_unknown_hosts",
    "e2_native_fixture::fixture_data_tests::empty_and_unexecuted_resources_do_not_become_closes_or_joins",
    "e2_native_fixture::fixture_data_tests::result_is_bounded_one_line_with_truthful_empty_resource_projection",
    "install_producer::tests::report_decoder_binds_slots_error_outputs_and_consuming_returns",
    "install_producer::tests::signature_result_requires_same_owner_finality_and_late_gate_refuses",
    "install_producer::tests::unknown_native_or_gate_custody_never_releases_or_publishes_success",
)
INSTALLER_WORKER_RUST_TESTS = (
    "installer::worker::tests::same_absolute_endpoint_reserves_settlement_and_rejects_backwards_or_overflow",
    "installer::worker::tests::private_frames_require_fixed_binding_shapes_bounds_and_no_future_finality",
    "installer::worker::tests::original_join_requires_eof_closes_matching_return_and_timely_sources",
)
LAYOUT_SOURCE = NATIVE + "/src/e2_service_status_observer.m"
LAYOUT_ARGUMENT = "--observe-service-layout"
LAYOUT_CASES = ("single", "nested")
LAYOUT_ID = IDENTIFIER + ".status-observation"
LAYOUT_SERVICE = LAYOUT_ID + ".resident"
LAYOUT_HOST = "service-status-layout/Nested/MRK E2 Status Host.app"
LAYOUT_CLIENTS = ("service-status-layout/Single/MRK E2 Status Client.app",
                  LAYOUT_HOST + "/Contents/Helpers/MRK E2 Status Client.app")
LAYOUT_EXECUTABLE = "/Contents/MacOS/mrk-e2-status-observer"
LAYOUT_TARGET = "/Contents/Helpers/mrk-e2-status-target"
LAYOUT_PLIST = "/Contents/Library/LaunchDaemons/" + LAYOUT_SERVICE + ".plist"
LAYOUT_SECONDS = 30
LAYOUT_LOADS = frozenset((
    b"/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation",
    b"/System/Library/Frameworks/ServiceManagement.framework/Versions/A/ServiceManagement",
    b"/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
    b"/usr/lib/libobjc.A.dylib", b"/usr/lib/libSystem.B.dylib",
))
CONTEXT_CASES = ("component", "product")
CONTEXT_IDENTIFIERS = tuple(IDENTIFIER + ".installer-context." + case + ".v1" for case in CONTEXT_CASES)
CONTEXT_PACKAGES = ("context-direct.pkg", "context-wrapped.pkg", "context-product.pkg")
CONTEXT_PACKAGE_LABELS = ("direct-component", "wrapped-component", "outer-product")
CONTEXT_SOURCE = NATIVE + "/src/e2_installer_context.c"
CONTEXT_SECONDS, CONTEXT_PACKAGE_LIMIT = 120, 8 * 1024 * 1024
CONTEXT_ROLES = ("context-helper-build", "context-component-build", "context-product-component-build",
                 "context-product-build", "context-component-empty-bom", "context-product-empty-bom",
                 "context-component-receipt-census", "context-product-receipt-census",
                 "context-component-installer", "context-product-installer",
                 "context-component-receipt-query", "context-product-receipt-query")
WORK_SECONDS, HARD_SECONDS = 990, 993
CAPTURE_LIMIT, RESULT_LIMIT = 65536, 32768
IMAGE_LIMIT = 32 * 1024 * 1024
RECEIPT_CENSUS_LIMIT = 1024 * 1024
MAX_RAW = (1 << 61) - 1
AUXILIARY_NS = 60_000_000_000
BTM_ROLE, BTM_SUBSYSTEM = "fixture-btm-log", "com.apple.backgroundtaskmanagement"
BTM_LIMIT, BTM_SECONDS = 262144, 10
BTM_IDS = (IDENTIFIER, IDENTIFIER + ".client", SERVICE)
BTM_STATES = ("not-requested", "window-unavailable", "tool-unavailable", "call-failed",
              "call-unknown", "unparseable", "empty", "observed")
BTM_MARKERS = (
    ("mentions-not-found", ("not found", "notfound")), ("mentions-plist", ("plist",)),
    ("mentions-signature", ("signature", "codesign")),
    ("mentions-team", ("team identifier", "teamid", "team id")),
    ("mentions-requirement", ("requirement",)), ("mentions-responsibility", ("responsib",)),
    ("mentions-approval", ("approval", "approved")),
    ("mentions-permission", ("permission", "not permitted")),
    ("mentions-registration", ("register", "registration")),
    ("mentions-launch-constraint", ("launch constraint",)),
)
BTM_DOMAINS = (("SMAppServiceErrorDomain", "smappservice"),
               ("NSOSStatusErrorDomain", "osstatus"), ("NSCocoaErrorDomain", "cocoa"))
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
CLOSE_FLAGS = ("mainReturned", "mainClosed", "clientClosed", "workerJoined", "identityClosed")
CASE_FLAGS = ("registered", "watchRegistered", "refused", "tailAdmissionIssued",
              "testedUnregisterEntered", "fixtureCleanupUnregisterEntered", "eof",
              "noteExit") + CLOSE_FLAGS
CASE_KEYS = {"case", "outcome", "startedNs", "finishedNs", "firstFailureNs",
             "operationHex", "instanceHex", "tailHex", "resourceStates",
             "preServiceStop", "mainObservations", "mainBundleLookup", *CASE_FLAGS}
RESULT_KEYS = {"schemaVersion", "type", "fixtureProfile", "sourceCommit", "releaseId",
               "target", "outcome", "nativeFinalityKnown", "auxiliaryNanoseconds",
               "syntheticIdentity", "productionIdentityQualified",
               "actualAppIntegrationQualified", "overlapObserved", "overlapEvidence", "cases"}


class Refused(ValueError):
    """Closed labels only; never include native output or environment secrets."""


def need(value, label):
    if not value:
        raise Refused(label)


def digest(body):
    return hashlib.sha256(body).hexdigest()


def signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def pairs(items):
    value = {}
    for key, item in items:
        need(key not in value, "duplicate-json-key")
        value[key] = item
    return value


def decode(body, limit):
    need(type(body) is bytes and 0 < len(body) <= limit, "json-byte-bound")
    def constant(_value):
        raise Refused("json-constant")
    try:
        value = json.loads(body.decode("utf-8", "strict"), object_pairs_hook=pairs,
                           parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError, OverflowError) as error:
        raise Refused("json-shape") from error
    queue, count = [(value, 0)], 0
    while queue:
        item, depth = queue.pop()
        count += 1
        need(count <= 40000 and depth <= 24 and type(item) is not float, "json-shape-bound")
        if type(item) is dict:
            queue.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            queue.extend((child, depth + 1) for child in item)
    return value


def decimal(value):
    need(type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,18}", value) is not None,
         "timestamp-canonical")
    number = int(value)
    need(number <= MAX_RAW, "timestamp-range")
    return number


def identity(value, size, *, empty=False):
    return type(value) is str and ((empty and value == "") or
                                   re.fullmatch("[0-9a-f]{" + str(size) + "}", value) is not None)


def btm_clock_sample():
    """A diagnostic clock failure cannot prevent the original native call."""
    try:
        values = (time.time_ns(), time.clock_gettime_ns(time.CLOCK_MONOTONIC))
    except (OSError, OverflowError, ValueError):
        return None
    return values if all(type(value) is int and 0 < value <= MAX_RAW for value in values) else None


def btm_window(start, end):
    need(type(start) is tuple and type(end) is tuple and len(start) == len(end) == 2
         and all(type(value) is int and 0 < value <= MAX_RAW for value in (*start, *end)), "btm-log-window")
    wall, monotonic = end[0] - start[0], end[1] - start[1]
    need(0 <= wall and 0 <= monotonic <= HARD_SECONDS * 1_000_000_000
         and abs(wall - monotonic) <= 2_000_000_000, "btm-log-window")
    value = {"startSeconds": start[0] // 1_000_000_000 - 1,
             "endSeconds": (end[0] + 999_999_999) // 1_000_000_000 + 1}
    btm_argv(value)
    return value


def btm_argv(window):
    need(type(window) is dict and set(window) == {"startSeconds", "endSeconds"}
         and all(type(value) is int and 0 < value < 253402300800 for value in window.values())
         and 0 < window["endSeconds"] - window["startSeconds"] <= 998, "btm-log-window")
    dates = [time.strftime("%Y-%m-%d %H:%M:%S+0000", time.gmtime(window[key]))
             for key in ("startSeconds", "endSeconds")]
    need(all(re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\+0000", value)
             for value in dates), "btm-log-window")
    predicate = 'subsystem == "' + BTM_SUBSYSTEM + '" AND eventMessage CONTAINS "' + IDENTIFIER + '"'
    return ["/usr/bin/log", "show", "--style", "json", "--start", dates[0], "--end", dates[1],
            "--timezone", "UTC", "--info", "--debug", "--no-pager", "--predicate", predicate]


def btm_events(body):
    """Closed mentions/codes, not arbitrary logs, causal findings or authority."""
    need(type(body) is bytes and 0 < len(body) <= BTM_LIMIT, "btm-log-data")
    def constant(_value):
        raise Refused("btm-log-data")
    try:
        rows = json.loads(body.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise Refused("btm-log-data") from error
    need(type(rows) is list and len(rows) <= 256, "btm-log-data")
    counts = {name: 0 for name, _words in BTM_MARKERS}
    counts["other"] = 0
    codes, matched = set(), 0
    own = r"(?<![\w.-])(?:" + "|".join(re.escape(value) for value in BTM_IDS) + r")(?![\w.-])"
    domains = dict(BTM_DOMAINS)
    error_pattern = (r"(?<![\w])Domain=(SMAppServiceErrorDomain|NSOSStatusErrorDomain|NSCocoaErrorDomain)"
                     r" Code=(-?(?:0|[1-9][0-9]{0,9}))(?=$|[^\w.+-])")
    for row in rows:
        need(type(row) is dict and row.get("subsystem") == BTM_SUBSYSTEM
             and type(row.get("eventMessage")) is str and len(row["eventMessage"]) <= 8192, "btm-log-data")
        message = row["eventMessage"]
        if re.search(own, message) is None:
            continue  # Report only the count; never export or classify a foreign message.
        matched += 1
        lower, found = message.lower(), False
        for name, words in BTM_MARKERS:
            if any(word in lower for word in words):
                counts[name] += 1
                found = True
        if not found:
            counts["other"] += 1
        for domain, raw in re.findall(error_pattern, message):
            code = int(raw)
            if str(code) == raw and -(1 << 31) <= code < 1 << 31:
                codes.add((domains[domain], code))
        need(len(codes) <= 8, "btm-log-data")
    return {"eventCount": len(rows), "ownEventCount": matched, "unmatchedEventCount": len(rows) - matched,
            "markerCounts": counts, "errorCodes": [{"domain": domain, "code": code} for domain, code in sorted(codes)]}


def btm_record(source):
    return {"schemaVersion": 1, "type": "mrk-e2-fixture-btm-log-observation-v1", "sourceCommit": source,
            "diagnosticOnly": True, "state": "not-requested", "window": None, "commandIndex": None,
            "toolSha256": None, "stdoutSha256": None, "stderrSha256": None, "eventCount": None,
            "ownEventCount": None, "unmatchedEventCount": None, "markerCounts": None, "errorCodes": None,
            "rawOutputIncluded": False, "absenceEstablished": False, "ownershipEstablished": False,
            "nativeLifecycleQualified": False}


def btm_log_data(value, source, calls):
    need(type(value) is dict and set(value) == set(btm_record(source))
         and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and value["type"] == "mrk-e2-fixture-btm-log-observation-v1" and value["sourceCommit"] == source
         and identity(source, 40) and value["diagnosticOnly"] is True
         and all(value[key] is False for key in ("rawOutputIncluded", "absenceEstablished",
                                                "ownershipEstablished", "nativeLifecycleQualified"))
         and type(value["state"]) is str and value["state"] in BTM_STATES
         and type(calls) is list and len(calls) <= 64, "btm-log-data")
    window, index, state = value["window"], value["commandIndex"], value["state"]
    if window is not None:
        btm_argv(window)
    need(value["toolSha256"] is None or identity(value["toolSha256"], 64), "btm-log-data")
    indices = [i for i, call in enumerate(calls) if type(call) is dict and call.get("role") == BTM_ROLE]
    if index is None:
        need(not indices and state in ("not-requested", "window-unavailable", "tool-unavailable")
             and value["stdoutSha256"] is None and value["stderrSha256"] is None, "btm-log-data")
        need((window is not None) == (state == "tool-unavailable")
             and (state == "tool-unavailable" or value["toolSha256"] is None), "btm-log-data")
    else:
        need(type(index) is int and indices == [index] and 0 <= index < len(calls)
             and window is not None and identity(value["toolSha256"], 64), "btm-log-data")
        call = calls[index]
        need(call.get("entered") is True and type(call.get("returned")) is bool
             and type(call.get("workTimeoutSeconds")) is int and call["workTimeoutSeconds"] == BTM_SECONDS
             and type(call.get("outputLimitBytes")) is int and call["outputLimitBytes"] == BTM_LIMIT, "btm-log-data")
        native = [row for row in calls[:index] if type(row) is dict and row.get("role") == "native-run"]
        need(len(native) == 1 and native[0].get("entered") is True and native[0].get("returned") is True
             and all(type(row) is dict and row.get("returned") is True for row in calls[:index]), "btm-log-data")
        if call["returned"]:
            need(type(call.get("returncode")) is int and 0 <= call["returncode"] <= 255
                 and identity(value["stdoutSha256"], 64) and identity(value["stderrSha256"], 64)
                 and value["stdoutSha256"] == call.get("stdoutSha256")
                 and value["stderrSha256"] == call.get("stderrSha256")
                 and state in ("call-failed", "unparseable", "empty", "observed"), "btm-log-data")
        else:
            need(state == "call-unknown" and value["stdoutSha256"] is None
                 and value["stderrSha256"] is None, "btm-log-data")
    fields = ("eventCount", "ownEventCount", "unmatchedEventCount", "markerCounts", "errorCodes")
    if state not in ("empty", "observed"):
        need(all(value[key] is None for key in fields), "btm-log-data")
    else:
        need(index is not None and calls[index]["returned"] and calls[index]["returncode"] == 0
             and value["stderrSha256"] == digest(b"")
             and all(type(value[key]) is int and 0 <= value[key] <= 256 for key in fields[:3])
             and value["ownEventCount"] + value["unmatchedEventCount"] == value["eventCount"]
             and (state == "observed") == (value["ownEventCount"] > 0), "btm-log-data")
        markers = value["markerCounts"]
        need(type(markers) is dict and set(markers) == {"other", *(name for name, _ in BTM_MARKERS)}
             and all(type(count) is int and 0 <= count <= value["ownEventCount"] for count in markers.values())
             and sum(markers.values()) >= value["ownEventCount"],
             "btm-log-data")
        codes = value["errorCodes"]
        need(type(codes) is list and len(codes) <= 8
             and (value["ownEventCount"] > 0 or not codes)
             and all(type(row) is dict and set(row) == {"domain", "code"}
                     and type(row["domain"]) is str and row["domain"] in dict(BTM_DOMAINS).values()
                     and type(row["code"]) is int
                     and -(1 << 31) <= row["code"] < 1 << 31 for row in codes), "btm-log-data")
        need([(row["domain"], row["code"]) for row in codes]
             == sorted({(row["domain"], row["code"]) for row in codes}), "btm-log-data")
    need(len(canonical(value)) <= 4096, "btm-log-data")
    return value


def installer_worker_diagnostic_sources(rows):
    """Only already-bound SOURCE names; aliases do not read or resolve a path."""
    if type(rows) is not dict or len(rows) > 4096:
        return None
    prefixes = (INSTALLER + "/", NATIVE + "/", HELPER + "/")
    canonical_names, aliases = set(), {}
    for name in rows:
        if (type(name) is not str or not name.isascii() or not 1 <= len(name) <= 384
                or not name.endswith(".rs") or not name.startswith(prefixes)
                or "\\" in name or any(ord(char) < 32 or ord(char) == 127 for char in name)
                or any(piece in ("", ".", "..") for piece in name.split("/"))):
            continue
        canonical_names.add(name)
        prefix = next(item for item in prefixes if name.startswith(item))
        package_name = name[len(prefix):]
        spellings = {name, str(CHECKOUT) + "/" + name, package_name}
        if prefix == NATIVE + "/":
            spellings.add("../native/macos-installed-native/" + package_name)
        elif prefix == HELPER + "/":
            spellings.add("../helpers/macos-android-register/" + package_name)
        spellings |= {"./" + spelling for spelling in tuple(spellings) if not spelling.startswith("/")}
        for spelling in spellings:
            # src/lib.rs can name several crates. Do not guess which compiler
            # emitted it; even two independently real names remain ambiguous.
            if spelling in aliases and aliases[spelling] != name:
                aliases[spelling] = None
            else:
                aliases[spelling] = name
    return canonical_names, aliases


def installer_worker_diagnostic_result(stdout, stderr, rows):
    """Small diagnostic projection, not a compiler result or native authority."""
    source = installer_worker_diagnostic_sources(rows)
    if (source is None or type(stdout) is not bytes or type(stderr) is not bytes
            or len(stdout) + len(stderr) > 4 * 1024 * 1024):
        return None
    _names, aliases = source
    result = {
        "schemaVersion": 1, "type": "mrk-macos-installer-worker-diagnostic-v1", "diagnosticOnly": True,
        "classification": "unrecognized", "stdoutSha256": digest(stdout), "stderrSha256": digest(stderr),
        "stdoutBytes": len(stdout), "stderrBytes": len(stderr), "errorCodes": [], "errorLocations": [],
        "failedTests": [], "panicLocations": [], "truncated": False, "unresolvedLocations": False,
    }
    def add(key, value, limit):
        if value not in result[key]:
            if len(result[key]) == limit:
                result["truncated"] = True
            else:
                result[key].append(value)
    for body in (stdout, stderr):
        start = 0
        while start < len(body):
            end = body.find(b"\n", start)
            if end < 0:
                end = len(body)
            if end - start > 8192:
                result["truncated"] = True
                start = end + 1
                continue
            line = body[start:end]
            start = end + 1
            # Inspect the finite prefix only. Arbitrary trailing compiler text,
            # assertion values, messages and non-ASCII payloads are not decoded.
            match = re.match(rb"([^:\r\n]{1,768}):([1-9][0-9]{0,6}):([1-9][0-9]{0,5}): error(?:\[(E[0-9]{4})\])?:", line)
            if match is not None and all(32 <= byte <= 126 for byte in match.group(0)):
                code = match[4].decode("ascii") if match[4] is not None else None
                if code is not None:
                    add("errorCodes", code, 32)
                    if code not in result["errorCodes"]:
                        # A capped code cannot appear only in a location row.
                        continue
                add("errorLocations", {"code": code, "path": aliases.get(match[1].decode("ascii")),
                                       "line": int(match[2]), "column": int(match[3])}, 12)
                continue
            match = re.match(rb"error\[(E[0-9]{4})\]:", line)
            if match is not None:
                add("errorCodes", match[1].decode("ascii"), 32)
                continue
            failed = next((name for name in INSTALLER_WORKER_RUST_TESTS
                           if line == ("test " + name + " ... FAILED").encode("ascii")), None)
            if failed is not None:
                add("failedTests", failed, 3)
                continue
            match = re.fullmatch(rb"thread '([^'\r\n]{1,256})'(?: \([1-9][0-9]{0,19}\))? panicked at ([^:\r\n]{1,768}):([1-9][0-9]{0,6}):([1-9][0-9]{0,5}):", line)
            if match is not None and all(32 <= byte <= 126 for byte in line):
                name = match[1].decode("ascii")
                if name in INSTALLER_WORKER_RUST_TESTS:
                    add("panicLocations", {"test": name, "path": aliases.get(match[2].decode("ascii")),
                                           "line": int(match[3]), "column": int(match[4])}, 3)
    rust = bool(result["errorCodes"] or result["errorLocations"])
    tests = bool(result["failedTests"] or result["panicLocations"])
    result["classification"] = "mixed" if rust and tests else "rust-errors" if rust else "selected-test-failures" if tests else "unrecognized"
    result["unresolvedLocations"] = any(row["path"] is None for row in result["errorLocations"] + result["panicLocations"])
    return result if len(canonical(result)) <= 12 * 1024 else None


def installer_worker_diagnostic_data(value, call, rows):
    """Closed DATA bound to one actual failed original; no permission or pass."""
    keys = {"schemaVersion", "type", "diagnosticOnly", "classification", "stdoutSha256", "stderrSha256",
            "stdoutBytes", "stderrBytes", "errorCodes", "errorLocations", "failedTests", "panicLocations",
            "truncated", "unresolvedLocations"}
    source = installer_worker_diagnostic_sources(rows)
    if (source is None or type(value) is not dict or set(value) != keys or type(call) is not dict
            or call.get("role") != "installer-worker-rust-tests" or call.get("entered") is not True
            or call.get("returned") is not True or type(call.get("returncode")) is not int
            or not 1 <= call["returncode"] <= 255 or type(call.get("workTimeoutSeconds")) is not int
            or call["workTimeoutSeconds"] != 480 or type(call.get("outputLimitBytes")) is not int
            or call["outputLimitBytes"] != 4 * 1024 * 1024
            or type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1
            or value["type"] != "mrk-macos-installer-worker-diagnostic-v1" or value["diagnosticOnly"] is not True
            or type(value["truncated"]) is not bool or type(value["unresolvedLocations"]) is not bool):
        return None
    for stream in ("stdout", "stderr"):
        if (not identity(value[stream + "Sha256"], 64) or value[stream + "Sha256"] != call.get(stream + "Sha256")
                or type(value[stream + "Bytes"]) is not int or not 0 <= value[stream + "Bytes"] <= 4 * 1024 * 1024):
            return None
    if value["stdoutBytes"] + value["stderrBytes"] > 4 * 1024 * 1024:
        return None
    names, _aliases = source
    code = lambda item: type(item) is str and re.fullmatch(r"E[0-9]{4}", item) is not None
    for key, maximum in (("errorCodes", 32), ("errorLocations", 12), ("failedTests", 3), ("panicLocations", 3)):
        items = value[key]
        if type(items) is not list or len(items) > maximum or any(item in items[:index] for index, item in enumerate(items)):
            return None
    if (not all(code(item) for item in value["errorCodes"])
            or not all(type(item) is str and item in INSTALLER_WORKER_RUST_TESTS for item in value["failedTests"])):
        return None
    for key, tag in (("errorLocations", "code"), ("panicLocations", "test")):
        for row in value[key]:
            if (type(row) is not dict or set(row) != {tag, "path", "line", "column"}
                    or not (row["path"] is None or type(row["path"]) is str and row["path"] in names)
                    or type(row["line"]) is not int or not 1 <= row["line"] <= 9999999
                    or type(row["column"]) is not int or not 1 <= row["column"] <= 999999):
                return None
            if key == "errorLocations":
                if row[tag] is not None and (not code(row[tag]) or row[tag] not in value["errorCodes"]):
                    return None
            elif type(row[tag]) is not str or row[tag] not in INSTALLER_WORKER_RUST_TESTS:
                return None
    rust = bool(value["errorCodes"] or value["errorLocations"])
    tests = bool(value["failedTests"] or value["panicLocations"])
    classification = "mixed" if rust and tests else "rust-errors" if rust else "selected-test-failures" if tests else "unrecognized"
    unresolved = any(row["path"] is None for row in value["errorLocations"] + value["panicLocations"])
    if value["classification"] != classification or value["unresolvedLocations"] != unresolved or len(canonical(value)) > 12 * 1024:
        return None
    # Return fresh plain DATA; a later caller cannot mutate the admitted record.
    return {**value, "errorCodes": list(value["errorCodes"]), "failedTests": list(value["failedTests"]),
            "errorLocations": [dict(row) for row in value["errorLocations"]],
            "panicLocations": [dict(row) for row in value["panicLocations"]]}


def service_status_record(body, returncode, source, observer_sha, case, started, deadline):
    """Finite observed public status; NotFound is never absence or authority."""
    need(type(returncode) is int and returncode == 0 and type(body) is bytes
         and body.endswith(b"\n") and body.count(b"\n") == 1, "layout-original-result")
    value = decode(body, 2048)
    need(type(value) is dict and set(value) == {
        "schemaVersion", "type", "sourceCommit", "observerSourceSha256", "case", "outcome",
        "startedNs", "finishedNs", "bundle", "executable", "identifier", "plist", "status",
        "factoryReturned", "retainReturned", "statusReturned", "serviceReleaseReturned",
        "poolDrainReturned", "finalityKnown", "registrationEntered",
    }, "layout-record-shape")
    need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and value["type"] == "mrk-e2-service-status-observation-v1"
         and identity(source, 40) and identity(observer_sha, 64)
         and value["sourceCommit"] == source and value["observerSourceSha256"] == observer_sha
         and type(case) is str and case in LAYOUT_CASES and value["case"] == case
         and value["outcome"] == "observed", "layout-record-binding")
    need(all(value[key] == "expected-client" for key in ("bundle", "executable", "identifier"))
         and value["plist"] == "expected-daemon" and type(value["status"]) is str
         and value["status"] in ("not-registered", "enabled", "requires-approval", "not-found")
         and value["registrationEntered"] is False
         and all(value[key] is True for key in ("factoryReturned", "retainReturned", "statusReturned",
                                               "serviceReleaseReturned", "poolDrainReturned", "finalityKnown")),
         "layout-record-finality")
    first, last = decimal(value["startedNs"]), decimal(value["finishedNs"])
    need(type(started) is int and type(deadline) is int
         and 0 < started <= first <= last <= deadline <= MAX_RAW
         and deadline - started == LAYOUT_SECONDS * 1_000_000_000
         and last - first <= 15_000_000_000, "layout-record-deadline")
    return value


def service_layout_data(value, source):
    """Validate DATA shape only; an actual bound original call remains required."""
    need(type(value) is dict and set(value) == {
        "schemaVersion", "type", "sourceCommit", "observerSourceSha256", "selected", "started", "completed",
        "clock", "startedNs", "deadlineNs", "enteredCases", "cases", "pairedInstalledInputs",
        "physicalLayoutOnly", "entryResponsibilityTested", "registrationEntered",
        "productionIdentityQualified", "actualAppIntegrationQualified", "nativeLifecycleQualified",
    }, "layout-public-shape")
    need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and value["type"] == "mrk-e2-service-layout-observations-v1"
         and identity(source, 40) and value["sourceCommit"] == source
         and value["clock"] == "CLOCK_MONOTONIC"
         and (value["observerSourceSha256"] is None or identity(value["observerSourceSha256"], 64))
         and all(type(value[key]) is bool for key in ("selected", "started", "completed", "pairedInstalledInputs"))
         and value["physicalLayoutOnly"] is True
         and all(value[key] is False for key in ("entryResponsibilityTested", "registrationEntered",
                                                "productionIdentityQualified", "actualAppIntegrationQualified",
                                                "nativeLifecycleQualified")), "layout-public-binding")
    entered, cases = value["enteredCases"], value["cases"]
    need(type(entered) is list and len(entered) <= 2 and entered == list(LAYOUT_CASES[:len(entered)])
         and type(cases) is list and len(cases) <= len(entered), "layout-public-order")
    started, deadline = decimal(value["startedNs"]), decimal(value["deadlineNs"])
    if not value["selected"]:
        need(not value["started"] and value["observerSourceSha256"] is None, "layout-public-unselected")
    if not value["started"]:
        need(started == deadline == 0 and not entered and not cases
             and not value["completed"] and not value["pairedInstalledInputs"], "layout-public-unentered")
    else:
        need(value["selected"] and identity(value["observerSourceSha256"], 64)
             and 0 < started < deadline <= MAX_RAW and deadline - started == LAYOUT_SECONDS * 1_000_000_000,
             "layout-public-started")
    previous = started
    for index, row in enumerate(cases):
        need(type(row) is dict and set(row) == {"case", "stdoutSha256", "record"}
             and row["case"] == entered[index] and identity(row["stdoutSha256"], 64), "layout-public-case")
        record = service_status_record(canonical(row["record"]), 0, source, value["observerSourceSha256"],
                                       row["case"], started, deadline)
        need(previous <= decimal(record["startedNs"]) and value["pairedInstalledInputs"], "layout-public-sequence")
        previous = decimal(record["finishedNs"])
    need(not value["completed"] or value["started"] and value["pairedInstalledInputs"]
         and len(entered) == len(cases) == 2, "layout-public-completion")
    return value


def service_layout_finality(value, source):
    try:
        checked = service_layout_data(value, source)
        return len(checked["enteredCases"]) == len(checked["cases"])
    except (ValueError, TypeError, KeyError):
        return False


def service_layout_files():
    leaves = {LAYOUT_HOST + "/Contents/" + name
              for name in ("MacOS/mrk-e2-status-host", "Info.plist", "_CodeSignature/CodeResources")}
    for root in LAYOUT_CLIENTS:
        leaves.update(root + suffix for suffix in (LAYOUT_EXECUTABLE, LAYOUT_TARGET, LAYOUT_PLIST,
                                                   "/Contents/Info.plist", "/Contents/_CodeSignature/CodeResources"))
    return leaves


def service_layout_code():
    return tuple((root + LAYOUT_TARGET, LAYOUT_SERVICE) for root in LAYOUT_CLIENTS) + tuple(
        (root, LAYOUT_ID + ".client") for root in LAYOUT_CLIENTS) + ((LAYOUT_HOST, LAYOUT_ID + ".host"),)


def service_layout_plist():
    return plistlib.dumps({"Label": LAYOUT_SERVICE, "BundleProgram": "Contents/Helpers/mrk-e2-status-target",
                           "MachServices": {LAYOUT_SERVICE: True}}, sort_keys=True)


def service_layout_paired(roster):
    # Match actual signed resources, not a promise that code-signing is deterministic.
    for suffix in (LAYOUT_EXECUTABLE, LAYOUT_TARGET, LAYOUT_PLIST,
                   "/Contents/Info.plist", "/Contents/_CodeSignature/CodeResources"):
        need(roster[LAYOUT_CLIENTS[0] + suffix] == roster[LAYOUT_CLIENTS[1] + suffix],
             "layout-paired-inputs")


def tail_data(row, source, release):
    """Bound the genuine frame projection; this parser confers NO authority."""
    value = row["tailHex"]
    need(identity(value, 768), "tail-shape")
    frame = bytes.fromhex(value)
    need(frame[:8] == b"MRKMNT01"
         and struct.unpack_from(">6I", frame, 8) == (1, 8, 384, 0, 1, 256),
         "tail-header")
    need(frame[32:48].hex() == row["instanceHex"]
         and frame[48:64].hex() == row["operationHex"]
         and frame[144:184] == source.encode("ascii")
         and frame[184:248] == release.encode("ascii").ljust(64, b"\0")
         and frame[248:272] == TARGET.encode("ascii").ljust(24, b"\0")
         and frame[272:280] == b"\0" * 8 and frame[336:] == b"\0" * 48,
         "tail-binding")
    origin, work, hard = struct.unpack_from(">3Q", frame, 104)
    first = struct.unpack_from(">Q", frame, 296)[0]
    need(0 < origin < work < hard <= MAX_RAW
         and work - origin == 300_000_000_000 and hard - origin == 310_000_000_000
         and first == 0, "genuine-no-f-tail")
    return digest(frame)



def resource_states(row):
    """Known empty allocation differs from consuming an acquired original."""
    value = row["resourceStates"]
    need(type(value) is dict and set(value) == {"main", "client", "worker", "identity"}
         and all(type(value[key]) is str and value[key] in ("not-entered", "returned-empty", "settled")
                 for key in ("main", "client", "identity"))
         and type(value["worker"]) is str and value["worker"] in ("not-started", "joined"),
         "native-resource-states")
    expected_main = {"not-entered": (False, False), "returned-empty": (True, False), "settled": (True, True)}
    need((row["mainReturned"], row["mainClosed"]) == expected_main[value["main"]]
         and row["clientClosed"] is (value["client"] == "settled")
         and row["identityClosed"] is (value["identity"] == "settled")
         and row["workerJoined"] is (value["worker"] == "joined"), "native-resource-finality")
    return value


def main_observations(row):
    """Closed original checkpoint DATA, never call/nonentry or success authority."""
    stop = row["preServiceStop"]
    need(stop is None or (type(stop) is str and stop in (
        "identity-preparation", "worker-start", "observe-not-absent",
        "registration-not-returned", "registration-not-owned")
        and row["outcome"] == "unavailable"), "native-case-shape")
    value = row["mainObservations"]
    need(type(value) is dict and set(value) == {"observe", "register"}, "native-case-shape")
    for observation in value.values():
        need(observation is None or (type(observation) is dict
             and set(observation) == {"status", "outcome"}
             and type(observation["status"]) is str and observation["status"] in (
                 "not-registered", "enabled", "requires-approval", "not-found", "unavailable", "error")
             and type(observation["outcome"]) is str and observation["outcome"] in (
                 "not-entered", "observed", "registration-requested", "already-registered", "needs-approval",
                 "settings-requested", "refused", "error", "unknown", "denied-by-user", "stopped",
                 "unregister-accepted")), "native-case-shape")
    lookup = row["mainBundleLookup"]
    if lookup is not None:
        need(type(lookup) is dict and set(lookup) == {"bundle", "executable", "identifier", "plist"}
             and all(type(item) is str for item in lookup.values())
             and lookup["bundle"] in ("fixture-client", "fixture-outer", "other", "unavailable")
             and lookup["executable"] in ("fixture-client", "fixture-entry", "other", "unavailable")
             and lookup["identifier"] in ("fixture-client", "fixture-outer", "other", "unavailable")
             and value["observe"] is not None and value["observe"]["status"] != "unavailable"
             and value["observe"]["outcome"] != "not-entered", "native-case-shape")
        admitted = {"fixture-client": ("held-client-match", "client-identity-mismatch", "unavailable"),
                    "fixture-outer": ("outer-library-absent", "outer-library-present", "unavailable"),
                    "other": ("other-bundle-not-read",), "unavailable": ("unavailable",)}
        need(lookup["plist"] in admitted[lookup["bundle"]]
             and (lookup["bundle"] != "unavailable"
                  or lookup["executable"] == lookup["identifier"] == "unavailable"), "native-case-shape")
    return value


def native_result(stdout, returncode, source, release):
    """Validate only an actually returned owner's bounded native result DATA."""
    need(identity(source, 40) and source != "0" * 40 and type(release) is str
         and re.fullmatch(r"[a-z0-9_.-]{1,63}", release), "result-expected-binding")
    need(type(stdout) is bytes and stdout.endswith(b"\n") and stdout.count(b"\n") == 1,
         "one-native-result-line")
    value = decode(stdout, RESULT_LIMIT)
    need(type(value) is dict and set(value) == RESULT_KEYS
         and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and value["type"] == "mrk-macos-e2-native-fixture-v1"
         and value["fixtureProfile"] == "e2-native-fixture-v1"
         and value["sourceCommit"] == source and value["releaseId"] == release
         and value["target"] == TARGET, "native-result-binding")
    need(value["syntheticIdentity"] is True and value["productionIdentityQualified"] is False
         and value["actualAppIntegrationQualified"] is False and value["overlapObserved"] is False
         and value["overlapEvidence"] == "unexecuted", "native-result-scope")
    need(type(returncode) is int and returncode in (0, 1, 77)
         and value["outcome"] == {0: "passed", 1: "failed", 77: "unavailable"}[returncode]
         and value["nativeFinalityKnown"] is True, "native-return-finality")
    need(decimal(value["auxiliaryNanoseconds"]) <= AUXILIARY_NS, "aggregate-auxiliary-budget")
    rows = value["cases"]
    need(type(rows) is list and len(rows) == 3, "native-case-count")
    previous, terminal, operations, instances = 0, False, set(), set()
    failures = []
    for expected, row in zip(CASES, rows):
        need(type(row) is dict and set(row) == CASE_KEYS and row["case"] == expected
             and row["outcome"] in ("passed", "failed", "unavailable", "unexecuted")
             and all(type(row[key]) is bool for key in CASE_FLAGS), "native-case-shape")
        resources = resource_states(row)
        observations = main_observations(row)
        start, finish, first = (decimal(row[key]) for key in ("startedNs", "finishedNs", "firstFailureNs"))
        need(identity(row["operationHex"], 32, empty=True) and identity(row["instanceHex"], 32, empty=True)
             and identity(row["tailHex"], 768, empty=True), "native-case-identities")
        if row["outcome"] == "unexecuted":
            need(terminal and start == finish == first == 0
                 and row["operationHex"] == row["instanceHex"] == row["tailHex"] == ""
                 and row["preServiceStop"] is None and observations == {"observe": None, "register": None}
                  and row["mainBundleLookup"] is None
                 and not any(row[key] for key in CASE_FLAGS)
                 and resources == {"main": "not-entered", "client": "not-entered",
                                   "worker": "not-started", "identity": "not-entered"},
                 "unexecuted-case-facts")
            continue
        need(not terminal and 0 < start <= finish <= MAX_RAW and start >= previous
             and (first == 0 or start <= first <= finish), "native-case-order")
        previous = finish
        # Known native return settles acquired originals, but cannot invent a
        # close or join for an allocator/worker that never acquired anything.
        # resource_states enforces the closed, explicitly observed alternatives.
        for key, seen in (("operationHex", operations), ("instanceHex", instances)):
            if row[key]:
                need(row[key] not in seen, "fresh-case-incarnation")
                seen.add(row[key])
        need(not row["watchRegistered"] or row["registered"], "watch-without-registration")
        if row["outcome"] != "passed":
            terminal = True
            failures.append(row["outcome"])
            continue
        need(row["registered"] and row["watchRegistered"] and row["noteExit"]
             and row["operationHex"] and row["instanceHex"] and all(row[key] for key in CLOSE_FLAGS)
             and resources == {"main": "settled", "client": "settled", "worker": "joined", "identity": "settled"},
             "passed-native-originals")
        if expected == CASES[0]:
            need(row["refused"] and not row["tailHex"] and not row["tailAdmissionIssued"]
                 and not row["testedUnregisterEntered"] and row["fixtureCleanupUnregisterEntered"]
                 and not row["eof"], "missing-b-refusal-contract")
        else:
            tail_data(row, source, release)
            need(not row["refused"] and row["eof"], "tail-finality-contract")
            if expected == CASES[1]:
                need(first > 0 and not row["tailAdmissionIssued"] and not row["testedUnregisterEntered"]
                     and row["fixtureCleanupUnregisterEntered"], "local-f-admission-contract")
            else:
                need(first == 0 and row["tailAdmissionIssued"] and row["testedUnregisterEntered"]
                     and not row["fixtureCleanupUnregisterEntered"], "genuine-unregister-contract")
    need((returncode == 0 and not failures and all(row["outcome"] == "passed" for row in rows))
         or (returncode != 0 and failures == [value["outcome"]]), "native-aggregate-outcome")
    return value


def completed(result, argv, limit):
    need(type(result) is subprocess.CompletedProcess and type(result.args) in (list, tuple)
         and all(type(arg) is str for arg in result.args) and tuple(result.args) == tuple(argv)
         and type(result.returncode) is int and type(result.stdout) is bytes
         and type(result.stderr) is bytes and len(result.stdout) + len(result.stderr) <= limit,
         "original-owner-return")
    return result


def receipt_census_absent(stdout, stderr):
    """Validate complete DATA from an already-successful owned receipt census."""
    need(type(stdout) is bytes and 0 < len(stdout) <= RECEIPT_CENSUS_LIMIT
         and type(stderr) is bytes and not stderr, "fixture-receipt-query-inconclusive")
    try:
        identifiers = plistlib.loads(stdout)
    except Exception as error:
        raise Refused("fixture-receipt-query-inconclusive") from error
    need(type(identifiers) is list and len(identifiers) <= 4096
         and all(type(identifier) is str and 0 < len(identifier) <= 1024
                 for identifier in identifiers), "fixture-receipt-query-inconclusive")
    need(len(set(identifiers)) == len(identifiers), "fixture-receipt-query-inconclusive")
    need(PACKAGE not in identifiers, "fixture-receipt-collision")


def context_timeout(deadline, now, cap):
    """One existing phase endpoint; an individual command never renews it."""
    need(type(deadline) is int and type(now) is int and 0 <= now < deadline <= MAX_RAW
         and type(cap) is int and 0 < cap <= CONTEXT_SECONDS, "context-deadline")
    # Existing owner JSON deliberately rejects floats. Shorten to a whole
    # second (never round up or extend the deadline); an exhausted final
    # fraction cannot start another command or establish phase completion.
    remaining = (deadline - now) // 1_000_000_000
    need(remaining > 0, "context-deadline")
    return min(cap, remaining)


def context_xml(body, limit):
    import xml.etree.ElementTree as ET
    need(type(body) is bytes and 0 < len(body) <= limit and b"\0" not in body
         and b"<!DOCTYPE" not in body and b"<!ENTITY" not in body, "context-xml-bound")
    try:
        # Parse only the admitted UTF8 spelling, never an auto-detected alternate
        # XML encoding that can hide DTD/entity markers from the byte prefilter.
        root = ET.fromstring(body.decode("utf-8", "strict"))
    except (ValueError, ET.ParseError) as error:
        raise Refused("context-xml-shape") from error
    pending, count = [(root, 0)], 0
    while pending:
        element, depth = pending.pop()
        count += 1
        need(count <= 256 and depth <= 8 and type(element.tag) is str
             and len(element.attrib) <= 16, "context-xml-shape")
        pending.extend((child, depth + 1) for child in element)
    return root


def context_inflate(body, limit):
    import zlib
    stream = zlib.decompressobj(31 if body[:2] == b"\x1f\x8b" else 15)
    result = stream.decompress(body, limit + 1)
    need(len(result) <= limit and stream.eof and not stream.unconsumed_tail
         and not stream.unused_data, "context-compressed-bound")
    return result


CONTEXT_METADATA_TAGS = ("name", "type", "mode", "uid", "gid", "user", "group",
                         "atime", "ctime", "mtime", "inode", "deviceno", "FinderCreateTime")
CONTEXT_METADATA_CHECKS = ("finder-shape", "finder-values", "finder-calendar", "scalar-shape",
                           "inode-value", "deviceno-value")
CONTEXT_METADATA_ARTIFACT = "installer-context-metadata-refusal"

# Diagnostic vocabulary only, NOT accepted PackageInfo attributes/values.
# An unknown name/value is counted/classified, never copied into evidence.
CONTEXT_PACKAGE_INFO_ARTIFACT = "installer-context-package-info-refusal"
CONTEXT_PACKAGE_INFO_FAILURES = ("context-package-identity", "context-package-no-payload",
                                 "context-package-empty-action", "context-package-hook")
CONTEXT_PACKAGE_INFO_FIELDS = {
    "root": {
        "format-version": ("1", "2"), "identifier": ("expected",), "version": ("1", "1.0"),
        "install-location": ("/", ""), "auth": ("root", "none"), "generator-version": ("present",),
        "overwrite-permissions": ("true", "false"), "relocatable": ("true", "false"),
        "postinstall-action": ("none", "restart", "shutdown", "RequireRestart"),
        "minimum-system-version": ("present",), "preserve-xattr": ("true", "false"),
        "followSymLinks": ("true", "false"), "allow-external-scripts": ("true", "false"),
    },
    "payload": {"numberOfFiles": ("0", "1"), "installKBytes": ("0", "1")},
    "scripts": {},
    "postinstall": {"file": ("postinstall", "./postinstall"), "timeout": ("0", "60", "120", "600")},
}
CONTEXT_PACKAGE_INFO_CHILDREN = ("bundle-version", "upgrade-bundle", "update-bundle", "atomic-update-bundle",
                                 "strict-identifier", "relocate", "payload", "scripts")


def context_audit_call_data(package, phase, index, calls):
    """Finite original-build binding, not a parser-success or cleanup flag."""
    if (type(package) is not str or package not in CONTEXT_PACKAGE_LABELS
            or type(calls) is not list or not 1 <= len(calls) <= 64
            or type(index) is not int or not 0 <= index < len(calls)):
        return False
    position = CONTEXT_PACKAGE_LABELS.index(package)
    role = ("context-component-build", "context-product-component-build", "context-product-build")[position]
    call = calls[index]
    return (phase == ("context-component-audit" if position == 0 else "context-product-audit")
            and type(call) is dict and call.get("role") == role
            and call.get("entered") is True and call.get("returned") is True
            and type(call.get("returncode")) is int and call["returncode"] == 0
            and sum(type(row) is dict and row.get("role") == role for row in calls) == 1)


# Exact harmless defaults emitted by the original script-only pkgbuild route.
# No payload is admitted below; relocation/restart alternatives remain forbidden.
CONTEXT_PACKAGE_BASE_ATTRIBUTES = frozenset({
    "format-version", "identifier", "version", "install-location", "auth", "generator-version",
})
CONTEXT_PACKAGE_FIXED_DEFAULTS = {
    "overwrite-permissions": "true", "relocatable": "false", "postinstall-action": "none",
}


def _context_package_attributes_allowed(attributes):
    return (set(attributes) <= CONTEXT_PACKAGE_BASE_ATTRIBUTES | CONTEXT_PACKAGE_FIXED_DEFAULTS.keys()
            and all(attributes.get(name) in (None, value)
                    for name, value in CONTEXT_PACKAGE_FIXED_DEFAULTS.items()))


def _context_package_info_observation(body, identifier):
    """Inspect the SAME bounded bytes after refusal; never alter acceptance."""
    root = context_xml(body, 65536)
    children = list(root)
    scripts = [node for node in children if node.tag == "scripts"]
    selected = {"root": [root], "payload": [node for node in children if node.tag == "payload"],
                "scripts": scripts, "postinstall": [node for group in scripts for node in group if node.tag == "postinstall"]}
    rows = {}
    for role, nodes in selected.items():
        row = {"count": len(nodes), "attributes": None, "otherAttributes": None,
               "children": None, "textPresent": None, "tailPresent": None}
        if len(nodes) == 1:
            node, values = nodes[0], {}
            for name, vocabulary in CONTEXT_PACKAGE_INFO_FIELDS[role].items():
                raw = node.get(name)
                if raw is None:
                    value = None
                elif role == "root" and name == "identifier":
                    value = "expected" if raw == identifier else "other"
                elif role == "root" and name in ("generator-version", "minimum-system-version"):
                    value = "present"
                else:
                    value = raw if raw in vocabulary else "other"
                values[name] = value
            row.update(attributes=values, otherAttributes=sum(name not in values for name in node.attrib),
                       children=len(node), textPresent=bool((node.text or "").strip()),
                       tailPresent=bool((node.tail or "").strip()))
        rows[role] = row
    return {"checks": {"rootTagMatches": root.tag == "pkg-info", "identifierMatches": root.get("identifier") == identifier,
                       "versionMatches": root.get("version") == "1", "installLocationMatches": root.get("install-location") == "/",
                       "authMatches": root.get("auth") == "root", "onlyExpectedAttributes": _context_package_attributes_allowed(root.attrib)},
            "elements": rows, "childCounts": {name: sum(node.tag == name for node in children) for name in CONTEXT_PACKAGE_INFO_CHILDREN},
            "otherChildren": sum(node.tag not in CONTEXT_PACKAGE_INFO_CHILDREN for node in children)}


def context_package_info_diagnostic_data(value, phase, failure, calls):
    """Closed failure projection; no arbitrary XML names, values or paths."""
    keys = {"schemaVersion", "type", "diagnosticOnly", "phase", "package", "packageSha256", "packageBytes",
            "packageInfoSha256", "packageInfoBytes", "buildCallIndex", "packageInfo"}
    if (type(value) is not dict or set(value) != keys or type(value["schemaVersion"]) is not int
            or value["schemaVersion"] != 1 or value["type"] != "mrk-context-package-info-diagnostic-v1"
            or value["diagnosticOnly"] is not True or failure not in CONTEXT_PACKAGE_INFO_FAILURES
            or value["phase"] != phase or value["package"] not in CONTEXT_PACKAGE_LABELS[:2]
            or not context_audit_call_data(value["package"], phase, value["buildCallIndex"], calls)):
        return None
    for prefix, low, high in (("package", 28, CONTEXT_PACKAGE_LIMIT), ("packageInfo", 1, 65536)):
        if (type(value[prefix + "Bytes"]) is not int or not low <= value[prefix + "Bytes"] <= high
                or not identity(value[prefix + "Sha256"], 64)):
            return None
    info = value["packageInfo"]
    check_keys = {"rootTagMatches", "identifierMatches", "versionMatches", "installLocationMatches", "authMatches", "onlyExpectedAttributes"}
    if (type(info) is not dict or set(info) != {"checks", "elements", "childCounts", "otherChildren"}
            or type(info["checks"]) is not dict or set(info["checks"]) != check_keys
            or any(type(item) is not bool for item in info["checks"].values())
            or type(info["elements"]) is not dict or set(info["elements"]) != set(CONTEXT_PACKAGE_INFO_FIELDS)
            or type(info["childCounts"]) is not dict or set(info["childCounts"]) != set(CONTEXT_PACKAGE_INFO_CHILDREN)
            or any(type(item) is not int or not 0 <= item <= 256 for item in (*info["childCounts"].values(), info["otherChildren"]))):
        return None
    for role, fields in CONTEXT_PACKAGE_INFO_FIELDS.items():
        row = info["elements"][role]
        if (type(row) is not dict or set(row) != {"count", "attributes", "otherAttributes", "children", "textPresent", "tailPresent"}
                or type(row["count"]) is not int or not 0 <= row["count"] <= 256):
            return None
        if row["count"] != 1:
            if any(row[name] is not None for name in row if name != "count"):
                return None
            continue
        if (type(row["attributes"]) is not dict or set(row["attributes"]) != set(fields)
                or type(row["otherAttributes"]) is not int or not 0 <= row["otherAttributes"] <= 16
                or type(row["children"]) is not int or not 0 <= row["children"] <= 256
                or type(row["textPresent"]) is not bool or type(row["tailPresent"]) is not bool):
            return None
        for name, vocabulary in fields.items():
            scalar = row["attributes"][name]
            if scalar is not None and (type(scalar) is not str or scalar not in (*vocabulary, "other")):
                return None
        if sum(scalar is not None for scalar in row["attributes"].values()) + row["otherAttributes"] > 16:
            return None
    rows, checks = info["elements"], info["checks"]
    if rows["root"]["count"] != 1:
        return None
    attributes = rows["root"]["attributes"]
    expected = {"identifierMatches": attributes["identifier"] == "expected", "versionMatches": attributes["version"] == "1",
                "installLocationMatches": attributes["install-location"] == "/", "authMatches": attributes["auth"] == "root",
                "onlyExpectedAttributes": rows["root"]["otherAttributes"] == 0
                    and _context_package_attributes_allowed({name: value for name, value in attributes.items() if value is not None})}
    if (any(checks[key] != item for key, item in expected.items())
            or (failure == "context-package-identity") == all(checks.values())
            or sum(info["childCounts"].values()) + info["otherChildren"] != rows["root"]["children"]
            or any(rows[name]["count"] != info["childCounts"][name] for name in ("payload", "scripts"))
            or rows["scripts"]["count"] == 0 and rows["postinstall"]["count"] != 0
            or rows["scripts"]["count"] == 1 and rows["postinstall"]["count"] > rows["scripts"]["children"]):
        return None
    return value if len(canonical(value)) <= 4096 else None


def _context_metadata_scalar(value, *, timestamp=False):
    """Observed spelling only, never a timestamp/inode or normalization."""
    if value is None:
        return {"characters": None, "text": None}
    pattern = r"[0-9TZ:+.\-]{1,64}" if timestamp else r"[0-9+\-]{1,24}"
    return {"characters": len(value), "text": value if re.fullmatch(pattern, value) else None}


def _context_metadata_observation(element, child, check, parent):
    # context_xml already bounded the complete tree to256 nodes/16 attributes.
    # Unknown names/attributes and user/group contents are NEVER copied out.
    name = element.findtext("name")
    name = parent + name if type(name) is str else None
    members = {"PackageInfo", "Scripts", "Bom", "Distribution", CONTEXT_PACKAGES[1],
               *(CONTEXT_PACKAGES[1] + "/" + item for item in ("PackageInfo", "Scripts", "Bom"))}
    leaves = list(child)
    finder = child.tag == "FinderCreateTime"
    return {
        "member": name if name in members else "unknown", "tag": child.tag, "check": check,
        "attributes": len(child.attrib), "children": len(leaves),
        "textPresent": bool((child.text or "").strip()), "tailPresent": bool((child.tail or "").strip()),
        "timeChildren": sum(item.tag == "time" for item in leaves),
        "nanosecondChildren": sum(item.tag == "nanoseconds" for item in leaves),
        "otherChildren": sum(item.tag not in ("time", "nanoseconds") for item in leaves),
        "leafAttributes": any(item.attrib for item in leaves),
        "leafChildren": any(len(item) for item in leaves),
        "leafTailText": any((item.tail or "").strip() for item in leaves),
        "timestamp": _context_metadata_scalar(child.findtext("time") if finder else None, timestamp=True),
        "nanoseconds": _context_metadata_scalar(child.findtext("nanoseconds") if finder else None),
        "number": _context_metadata_scalar(child.text if child.tag in ("inode", "deviceno") else None),
    }


def _context_required_observation(element, parent):
    """Only finite shape of the SAME already-bounded element; no raw names."""
    names, types = element.findall("name"), element.findall("type")
    name = names[0].text if len(names) == 1 else None
    name = parent + name if type(name) is str else None
    members = {"PackageInfo", "Scripts", "Bom", "Distribution", CONTEXT_PACKAGES[1],
               *(CONTEXT_PACKAGES[1] + "/" + item for item in ("PackageInfo", "Scripts", "Bom"))}
    values = {"file": 0, "directory": 0, "empty": 0, "other": 0}
    for node in types:
        value = node.text
        values[value if value in ("file", "directory") else "empty" if value in (None, "") else "other"] += 1
    return {"member": name if name in members else "unknown", "check": "required-shape",
            "nameCount": len(names), "typeCount": len(types), "typeValues": values,
            "childCounts": {"data": len(element.findall("data")), "file": len(element.findall("file")),
                            "other": sum(node.tag not in ("data", "file") for node in element)}}


def context_metadata_diagnostic_data(value, phase, failure, calls):
    """Closed, failure-only observations; malformed DATA has no publication."""
    keys = {"schemaVersion", "type", "diagnosticOnly", "phase", "package", "packageSha256", "packageBytes",
            "parsedArchiveSha256", "parsedArchiveBytes", "buildCallIndex", "metadata"}
    if (type(value) is not dict or set(value) != keys or type(value["schemaVersion"]) is not int
            or (value["schemaVersion"], value["type"], failure) not in (
                (1, "mrk-context-xar-metadata-diagnostic-v1", "context-xar-member-metadata"),
                (2, "mrk-context-xar-required-diagnostic-v2", "context-xar-member-required"))
            or value["diagnosticOnly"] is not True
            or phase not in ("context-component-audit", "context-product-audit") or value["phase"] != phase
            or type(value["package"]) is not str or value["package"] not in CONTEXT_PACKAGE_LABELS
            or type(calls) is not list or not 1 <= len(calls) <= 64):
        return None
    index = value["buildCallIndex"]
    position = CONTEXT_PACKAGE_LABELS.index(value["package"])
    role = ("context-component-build", "context-product-component-build", "context-product-build")[position]
    expected_phase = "context-component-audit" if position == 0 else "context-product-audit"
    if (phase != expected_phase or type(index) is not int or not 0 <= index < len(calls)
            or type(calls[index]) is not dict or calls[index].get("role") != role
            or calls[index].get("entered") is not True or calls[index].get("returned") is not True
            or type(calls[index].get("returncode")) is not int or calls[index]["returncode"] != 0
            or sum(type(call) is dict and call.get("role") == role for call in calls) != 1):
        return None
    for prefix in ("package", "parsedArchive"):
        size, sha = value[prefix + "Bytes"], value[prefix + "Sha256"]
        if type(size) is not int or not 28 <= size <= CONTEXT_PACKAGE_LIMIT or not identity(sha, 64):
            return None
    metadata = value["metadata"]
    if value["schemaVersion"] == 2:
        members = {"PackageInfo", "Scripts", "Bom", "Distribution", CONTEXT_PACKAGES[1], "unknown",
                   *(CONTEXT_PACKAGES[1] + "/" + item for item in ("PackageInfo", "Scripts", "Bom"))}
        keys = {"member", "check", "nameCount", "typeCount", "typeValues", "childCounts"}
        if (type(metadata) is not dict or set(metadata) != keys
                or type(metadata["member"]) is not str or metadata["member"] not in members
                or metadata["check"] != "required-shape"
                or any(type(metadata[key]) is not int or not 0 <= metadata[key] <= 256
                       for key in ("nameCount", "typeCount"))
                or metadata["nameCount"] == metadata["typeCount"] == 1
                or metadata["member"] != "unknown" and metadata["nameCount"] != 1):
            return None
        types, children = metadata["typeValues"], metadata["childCounts"]
        if (type(types) is not dict or set(types) != {"file", "directory", "empty", "other"}
                or type(children) is not dict or set(children) != {"data", "file", "other"}
                or any(type(number) is not int or not 0 <= number <= 256
                       for number in (*types.values(), *children.values()))
                or sum(types.values()) != metadata["typeCount"] or sum(children.values()) > 256
                or children["other"] < metadata["nameCount"] + metadata["typeCount"]):
            return None
        return value if len(canonical(value)) <= 2048 else None
    metadata_keys = {"member", "tag", "check", "attributes", "children", "textPresent", "tailPresent",
                     "timeChildren", "nanosecondChildren", "otherChildren", "leafAttributes", "leafChildren",
                     "leafTailText", "timestamp", "nanoseconds", "number"}
    members = {"PackageInfo", "Scripts", "Bom", "Distribution", CONTEXT_PACKAGES[1], "unknown",
               *(CONTEXT_PACKAGES[1] + "/" + item for item in ("PackageInfo", "Scripts", "Bom"))}
    if (type(metadata) is not dict or set(metadata) != metadata_keys
            or type(metadata["member"]) is not str or metadata["member"] not in members
            or type(metadata["tag"]) is not str or metadata["tag"] not in CONTEXT_METADATA_TAGS
            or type(metadata["check"]) is not str or metadata["check"] not in CONTEXT_METADATA_CHECKS):
        return None
    tag, check = metadata["tag"], metadata["check"]
    if ((check.startswith("finder-") and tag != "FinderCreateTime")
            or (check == "scalar-shape" and tag == "FinderCreateTime")
            or (check in ("inode-value", "deviceno-value") and tag != check[:-6])):
        return None
    for name in ("attributes", "children", "timeChildren", "nanosecondChildren", "otherChildren"):
        if type(metadata[name]) is not int or not 0 <= metadata[name] <= (16 if name == "attributes" else 256):
            return None
    if metadata["timeChildren"] + metadata["nanosecondChildren"] + metadata["otherChildren"] != metadata["children"]:
        return None
    if any(type(metadata[name]) is not bool for name in
           ("textPresent", "tailPresent", "leafAttributes", "leafChildren", "leafTailText")):
        return None
    for name in ("timestamp", "nanoseconds", "number"):
        scalar = metadata[name]
        if type(scalar) is not dict or set(scalar) != {"characters", "text"}:
            return None
        count, text = scalar["characters"], scalar["text"]
        if count is None:
            if text is not None:
                return None
        elif type(count) is not int or not 0 <= count <= 2 * 1024 * 1024:
            return None
        if text is not None:
            pattern = r"[0-9TZ:+.\-]{1,64}" if name == "timestamp" else r"[0-9+\-]{1,24}"
            if type(text) is not str or len(text) != count or not re.fullmatch(pattern, text):
                return None
        if ((name in ("timestamp", "nanoseconds") and tag != "FinderCreateTime")
                or (name == "number" and tag not in ("inode", "deviceno"))):
            if scalar != {"characters": None, "text": None}:
                return None
    return value if len(canonical(value)) <= 2048 else None


def context_xar(body, *, product=False):
    """Two closed scripts-only envelopes, never an extractor or production parser.

    XAR's format checksum covers the compressed TOC. Its heap interval and every
    member must cover the original archive exactly. Independent SHA256 of the
    complete original, not the format's possible SHA1, binds package evidence.
    """
    need(type(product) is bool and type(body) is bytes and 28 <= len(body) <= CONTEXT_PACKAGE_LIMIT,
         "context-xar-bound")
    magic, header, version, compressed, expanded, checksum = struct.unpack_from(">IHHQQI", body)
    algorithms = {1: ("sha1", 20), 3: ("sha256", 32), 4: ("sha512", 64)}
    need((magic, header, version) == (0x78617221, 28, 1)
         and 0 < compressed <= 1024 * 1024 and 0 < expanded <= 2 * 1024 * 1024
         and header + compressed <= len(body) and checksum in algorithms, "context-xar-header")
    packed_toc = body[header:header + compressed]
    toc_bytes = context_inflate(packed_toc, expanded)
    need(len(toc_bytes) == expanded, "context-xar-expanded")
    root = context_xml(toc_bytes, 2 * 1024 * 1024)
    need(root.tag == "xar" and not root.attrib and [child.tag for child in root] == ["toc"],
         "context-xar-toc")
    toc = root[0]
    need(not toc.attrib and all(child.tag in ("creation-time", "checksum", "file") for child in toc)
         and len(toc.findall("checksum")) == 1 and len(toc.findall("creation-time")) <= 1,
         "context-xar-toc")
    for element in toc.findall("creation-time"):
        need(not element.attrib and not list(element), "context-xar-toc")
    algorithm, checksum_size = algorithms[checksum]
    check = toc.find("checksum")
    need(check.attrib == {"style": algorithm} and [child.tag for child in check] == ["offset", "size"]
         and check.findtext("offset") == "0" and check.findtext("size") == str(checksum_size),
         "context-xar-checksum")
    need(all(not child.attrib and not list(child) for child in check), "context-xar-checksum")
    heap = header + compressed
    need(body[heap:heap + checksum_size] == hashlib.new(algorithm, packed_toc).digest(),
         "context-xar-checksum")
    intervals, members, seen_ids, directories = [(0, checksum_size)], {}, set(), set()
    allowed = {"PackageInfo", "Scripts", "Bom"}
    if product:
        allowed = {"Distribution", CONTEXT_PACKAGES[1],
                   *(CONTEXT_PACKAGES[1] + "/" + name for name in ("PackageInfo", "Scripts", "Bom"))}
    queue = [(element, "") for element in toc.findall("file")]
    while queue:
        element, parent = queue.pop(0)
        file_id = element.get("id")
        need(set(element.attrib) == {"id"} and type(file_id) is str
             and re.fullmatch(r"[1-9][0-9]{0,3}", file_id) and file_id not in seen_ids,
             "context-xar-member-id")
        seen_ids.add(file_id)
        metadata = {"name", "type", "data", "file", "mode", "uid", "gid", "user", "group",
                    "atime", "ctime", "mtime", "inode", "deviceno", "FinderCreateTime"}
        # Closed diagnostic vocabulary only: every extra tag still refuses.
        need(not any(child.tag == "acl" for child in element), "context-xar-member-tags-acl")
        need(not any(child.tag == "flags" for child in element), "context-xar-member-tags-flags")
        need(not any(child.tag == "ea" for child in element), "context-xar-member-tags-ea")
        need(not any(child.tag == "device" for child in element), "context-xar-member-tags-device")
        need(not any(child.tag == "link" for child in element), "context-xar-member-tags-link")
        need(all(child.tag in metadata for child in element), "context-xar-member-tags")
        try:
            need(all(len(element.findall(tag)) == 1 for tag in ("name", "type")),
                 "context-xar-member-required")
        except Refused as error:
            try:
                error._context_metadata = {"metadata": _context_required_observation(element, parent),
                                           "parsedArchiveSha256": digest(body), "parsedArchiveBytes": len(body)}
            except BaseException:
                pass  # Diagnostic failure never replaces this original refusal.
            raise
        need(all(len(element.findall(tag)) <= 1 for tag in metadata - {"file"}),
             "context-xar-member-duplicate")
        for child in element:
            metadata_check = None
            try:
                if child.tag == "FinderCreateTime":
                    # Apple's extractor applies this as destination birth time. This
                    # passive audit bounds annotation shape, not calendar validity.
                    metadata_check = "finder-shape"
                    need(not child.attrib and not (child.text or "").strip() and not (child.tail or "").strip()
                         and len(child) == 2 and {item.tag for item in child} == {"time", "nanoseconds"}
                         and all(not item.attrib and not list(item) and not (item.tail or "").strip()
                                 for item in child), "context-xar-member-metadata")
                    timestamp, nanoseconds = child.findtext("time"), child.findtext("nanoseconds")
                    metadata_check = "finder-values"
                    need(type(timestamp) is str
                         and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}", timestamp)
                         and type(nanoseconds) is str and re.fullmatch(r"0|[1-9][0-9]{0,8}", nanoseconds),
                         "context-xar-member-metadata")
                    # The observed Apple tool emitted 1900-01-00T22:06:56. Public
                    # xar source ignores failed gmtime_r output; this optional
                    # annotation is never converted, normalized, applied or used
                    # as authority. Keep only the closed spelling/bounds above.
                elif child.tag not in ("file", "data"):
                    metadata_check = "scalar-shape"
                    need(not child.attrib and not list(child), "context-xar-member-metadata")
                if child.tag in ("inode", "deviceno"):
                    # Apple xar stat.c emits both through signed PRId32/PRId64
                    # formats (configure.ac). These bounded strings are inert
                    # archive metadata, never filesystem identity or size authority.
                    metadata_check = "inode-value" if child.tag == "inode" else "deviceno-value"
                    need(type(child.text) is str and re.fullmatch(r"0|-?[1-9][0-9]{0,19}", child.text),
                         "context-xar-member-metadata")
            except Refused as error:
                if type(error) is Refused and error.args == ("context-xar-member-metadata",):
                    try:
                        error._context_metadata = {
                            "metadata": _context_metadata_observation(element, child, metadata_check, parent),
                            "parsedArchiveSha256": digest(body), "parsedArchiveBytes": len(body),
                        }
                    except BaseException:
                        pass  # Unqualified diagnostic; rethrow the SAME refusal.
                raise
        name, kind = element.findtext("name"), element.findtext("type")
        need(type(name) is str and name and "/" not in name and "\\" not in name
             and name not in (".", ".."), "context-xar-member-name")
        name = parent + name
        need(name in allowed and name not in members and name not in directories, "context-xar-roster")
        if kind == "directory":
            need(product and name == CONTEXT_PACKAGES[1] and not parent
                 and element.find("data") is None and 2 <= len(element.findall("file")) <= 3,
                 "context-xar-directory")
            directories.add(name)
            queue.extend((child, name + "/") for child in element.findall("file"))
            continue
        need(kind == "file" and not element.findall("file") and len(element.findall("data")) == 1,
             "context-xar-file")
        data = element.find("data")
        required = {"length", "offset", "size", "encoding"}
        optional = {"archived-checksum", "extracted-checksum"}
        need(not data.attrib and required <= {child.tag for child in data} <= required | optional
             and len({child.tag for child in data}) == len(data), "context-xar-data")
        texts = [data.findtext(key) for key in ("length", "offset", "size")]
        need(all(type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,9}", value) for value in texts),
             "context-xar-member-bound")
        need(all(not data.find(key).attrib and not list(data.find(key)) for key in ("length", "offset", "size")),
             "context-xar-member-bound")
        length, offset, size = map(int, texts)
        encoding = data.find("encoding")
        need(0 < length <= CONTEXT_PACKAGE_LIMIT and 0 < size <= CONTEXT_PACKAGE_LIMIT
             and offset >= checksum_size and heap + offset + length <= len(body)
             and all(offset + length <= low or offset >= high for low, high in intervals),
             "context-xar-range")
        need(encoding.attrib in ({"style": "application/octet-stream"}, {"style": "application/x-gzip"})
             and not list(encoding) and not (encoding.text or "").strip(), "context-xar-encoding")
        packed = body[heap + offset:heap + offset + length]
        decoded = packed if encoding.get("style") == "application/octet-stream" else context_inflate(packed, size)
        need(len(decoded) == size, "context-xar-member-size")
        for tag, content in (("archived-checksum", packed), ("extracted-checksum", decoded)):
            item = data.find(tag)
            if item is not None:
                need(set(item.attrib) == {"style"} and item.get("style") in ("sha1", "sha256", "sha512")
                     and not list(item) and item.text == hashlib.new(item.get("style"), content).hexdigest(),
                     "context-xar-member-checksum")
        members[name] = decoded
        intervals.append((offset, offset + length))
        need(len(members) <= 4 and len(seen_ids) <= 5, "context-xar-count")
    cursor = 0
    for low, high in sorted(intervals):
        need(low == cursor, "context-xar-unaccounted")
        cursor = high
    need(heap + cursor == len(body), "context-xar-unaccounted")
    if not product:
        need(set(members) in ({"PackageInfo", "Scripts"}, {"PackageInfo", "Scripts", "Bom"}),
             "context-component-roster")
    else:
        embedded = {CONTEXT_PACKAGES[1] + "/" + name for name in ("PackageInfo", "Scripts")}
        need(set(members) == {"Distribution", CONTEXT_PACKAGES[1]}
             or set(members) in ({"Distribution", *embedded},
                                {"Distribution", *embedded, CONTEXT_PACKAGES[1] + "/Bom"}),
             "context-product-roster")
    return members


def context_package_info(body, identifier):
    need(identifier in CONTEXT_IDENTIFIERS, "context-package-identifier")
    info = context_xml(body, 65536)
    need(info.tag == "pkg-info" and info.get("identifier") == identifier
         and info.get("version") == "1" and info.get("install-location") == "/"
         and info.get("auth") == "root"
         and _context_package_attributes_allowed(info.attrib),
         "context-package-identity")
    empty = {"bundle-version", "upgrade-bundle", "update-bundle", "atomic-update-bundle",
             "strict-identifier", "relocate"}
    tags = [child.tag for child in info]
    need(len(tags) == len(set(tags)) and set(tags) <= empty | {"payload", "scripts"}
         and "scripts" in tags, "context-package-no-payload")
    for child in info:
        if child.tag in empty:
            need(not child.attrib and not list(child) and not (child.text or "").strip(),
                 "context-package-empty-action")
        elif child.tag == "payload":
            need(not list(child) and child.get("numberOfFiles") == "0"
                 and child.get("installKBytes", "0") == "0"
                 and set(child.attrib) <= {"numberOfFiles", "installKBytes"}, "context-package-no-payload")
        else:
            need(not child.attrib and len(child) == 1 and child[0].tag == "postinstall"
                 and child[0].get("file") in ("postinstall", "./postinstall")
                 and child[0].get("timeout") in (None, "600")
                 and set(child[0].attrib) <= {"file", "timeout"}
                 and not list(child[0]) and not (child[0].text or "").strip(), "context-package-hook")


def context_distribution():
    return ('<?xml version="1.0" encoding="utf-8"?>\n'
            '<installer-gui-script minSpecVersion="1"><title>MRK Installer Context Observation</title>'
            '<options customize="never" require-scripts="false" allow-external-scripts="false"/>'
            '<domains enable_localSystem="true" enable_currentUserHome="false" enable_anywhere="false"/>'
            '<choices-outline><line choice="context"/></choices-outline>'
            '<choice id="context" visible="false"><pkg-ref id="' + CONTEXT_IDENTIFIERS[1] + '"/></choice>'
            '<pkg-ref id="' + CONTEXT_IDENTIFIERS[1] + '" version="1">'
            + CONTEXT_PACKAGES[1] + '</pkg-ref></installer-gui-script>\n').encode("ascii")


def context_product(body, component, component_members):
    members = context_xar(body, product=True)
    def tree(element):
        return (element.tag, tuple(sorted(element.attrib.items())), (element.text or "").strip(),
                tuple((tree(child), (child.tail or "").strip()) for child in element))
    distribution = context_xml(members["Distribution"], 65536)
    # Apple documents productbuild's local URL and install-size completion.
    # These closed non-action forms are equivalent; no arbitrary URL, script,
    # alternate conclusion, package, destination or attribute is accepted.
    for reference in distribution.findall("pkg-ref"):
        if "installKBytes" in reference.attrib:
            need(reference.attrib.pop("installKBytes") == "0", "context-product-distribution")
        if "onConclusion" in reference.attrib:
            need(reference.attrib.pop("onConclusion") == "None", "context-product-distribution")
        if (reference.text or "").strip() == "#" + CONTEXT_PACKAGES[1]:
            reference.text = CONTEXT_PACKAGES[1]
    need(tree(distribution) == tree(context_xml(context_distribution(), 65536)),
         "context-product-distribution")
    if CONTEXT_PACKAGES[1] in members:
        need(members[CONTEXT_PACKAGES[1]] == component, "context-product-component")
    else:
        embedded = {name.removeprefix(CONTEXT_PACKAGES[1] + "/"): content
                    for name, content in members.items() if name != "Distribution"}
        need(embedded == component_members, "context-product-component")


def context_record(body, source, observer_sha, case, deadline, output_original, packages):
    """Read only actual returned helper DATA; no package or maintenance authority."""
    need(identity(source, 40) and identity(observer_sha, 64) and case in CONTEXT_CASES
         and type(deadline) is int and 0 < deadline <= MAX_RAW
         and type(body) is bytes and body.endswith(b"\n") and body.count(b"\n") == 1,
         "context-record-binding")
    row = decode(body, 4096)
    keys = {"schemaVersion", "type", "sourceCommit", "observerSourceSha256", "case", "clock", "deadlineNs",
            "scriptArgumentCount", "secondArgumentIsRoot", "thirdArgumentIsRoot", "outputOriginal",
            "argumentOne", "packagePath"}
    need(type(row) is dict and set(row) == keys and type(row["schemaVersion"]) is int
         and row["schemaVersion"] == 1 and row["type"] == "mrk-e2-installer-context-v1"
         and row["sourceCommit"] == source and row["observerSourceSha256"] == observer_sha
         and row["case"] == case and row["clock"] == "CLOCK_MONOTONIC"
         and decimal(row["deadlineNs"]) == deadline, "context-record-binding")
    raw = row["outputOriginal"]
    need(type(raw) is list and len(raw) == 6 and all(type(number) is int and 0 <= number < 1 << 64 for number in raw)
         and raw == list(output_original) and raw[5] == 1, "context-output-original")
    argc = row["scriptArgumentCount"]
    need(type(argc) is int and 0 <= argc <= 16
         and all(type(row[key]) is bool for key in ("secondArgumentIsRoot", "thirdArgumentIsRoot"))
         and (not row["secondArgumentIsRoot"] or argc >= 2)
         and (not row["thirdArgumentIsRoot"] or argc >= 3), "context-script-arguments")
    result = {key: row[key] for key in ("case", "scriptArgumentCount", "secondArgumentIsRoot", "thirdArgumentIsRoot")}
    for key in ("argumentOne", "packagePath"):
        item = row[key]
        need(type(item) is dict and set(item) == {"kind", "match", "opened", "closed", "original", "sha256"}
             and type(item["kind"]) is str and item["kind"] in ("missing", "empty", "other", "nominated"),
             "context-observation-shape")
        if item["kind"] == "nominated":
            label, raw = item["match"], item["original"]
            need(type(label) is str and label in CONTEXT_PACKAGE_LABELS and label in packages
                 and item["opened"] is True and item["closed"] is True and type(raw) is list and len(raw) == 9
                 and all(type(number) is int and 0 <= number < 1 << 64 for number in raw)
                 and raw == list(packages[label]["original"]) and item["sha256"] == packages[label]["sha256"],
                 "context-package-original")
        else:
            need(item["match"] is None and item["opened"] is False and item["closed"] is None
                 and item["original"] is None and item["sha256"] is None, "context-unopened-facts")
        need(key != "argumentOne" or (item["kind"] == "missing") is (argc == 0), "context-script-arguments")
        result[key] = {"kind": item["kind"], "match": item["match"],
                       "originalMatched": True if item["kind"] == "nominated" else None}
    return result


def installer_context_data(value, source):
    """Finite public projection; even an observed outer match grants NO authority."""
    keys = {"schemaVersion", "type", "sourceCommit", "observerSourceSha256", "clock", "deadlineNs", "started",
            "completed", "enteredCases", "cases", "receiptsRetired", "outerPackageAuthority", "maintenanceQualified"}
    need(type(value) is dict and set(value) == keys and type(value["schemaVersion"]) is int
         and value["schemaVersion"] == 1 and value["type"] == "mrk-e2-installer-context-observations-v1"
         and value["sourceCommit"] == source and value["clock"] == "CLOCK_MONOTONIC"
         and all(type(value[key]) is bool for key in ("started", "completed", "receiptsRetired",
                                                     "outerPackageAuthority", "maintenanceQualified"))
         and value["receiptsRetired"] is value["outerPackageAuthority"] is value["maintenanceQualified"] is False,
         "context-public-binding")
    deadline = decimal(value["deadlineNs"])
    entered, cases = value["enteredCases"], value["cases"]
    need(type(entered) is list and len(entered) <= 2 and entered == list(CONTEXT_CASES[:len(entered)])
         and type(cases) is list and len(cases) <= len(entered) <= len(cases) + 1,
         "context-public-order")
    if not value["started"]:
        need(not value["completed"] and not entered and not cases and deadline == 0
             and value["observerSourceSha256"] is None, "context-public-unentered")
    else:
        need((deadline > 0 or value["observerSourceSha256"] is None and not entered and not cases)
             and (value["observerSourceSha256"] is None or identity(value["observerSourceSha256"], 64)),
             "context-public-started")
    if entered:
        need(identity(value["observerSourceSha256"], 64), "context-public-started")
    need(not value["completed"] or value["started"] and len(cases) == len(entered) == 2,
         "context-public-completion")
    for expected, row in zip(CONTEXT_CASES, cases):
        need(type(row) is dict and set(row) == {"case", "recordSha256", "installerReturnedZero", "outputOriginalClosed",
             "scriptArgumentCount", "secondArgumentIsRoot", "thirdArgumentIsRoot", "argumentOne", "packagePath", "receiptOriginals"}
             and row["case"] == expected and identity(row["recordSha256"], 64)
             and row["installerReturnedZero"] is row["outputOriginalClosed"] is True
             and type(row["scriptArgumentCount"]) is int and 0 <= row["scriptArgumentCount"] <= 16
             and all(type(row[key]) is bool for key in ("secondArgumentIsRoot", "thirdArgumentIsRoot"))
             and (not row["secondArgumentIsRoot"] or row["scriptArgumentCount"] >= 2)
             and (not row["thirdArgumentIsRoot"] or row["scriptArgumentCount"] >= 3), "context-public-case")
        for key in ("argumentOne", "packagePath"):
            item = row[key]
            need(type(item) is dict and set(item) == {"kind", "match", "originalMatched"}
                 and type(item["kind"]) is str and item["kind"] in ("missing", "empty", "other", "nominated"),
                 "context-public-observation")
            if item["kind"] == "nominated":
                need(type(item["match"]) is str and item["match"] in CONTEXT_PACKAGE_LABELS
                     and item["originalMatched"] is True, "context-public-observation")
            else:
                need(item["match"] is None and item["originalMatched"] is None, "context-public-observation")
            need(key != "argumentOne" or (item["kind"] == "missing") is (row["scriptArgumentCount"] == 0),
                 "context-public-case")
        receipts = row["receiptOriginals"]
        need(type(receipts) is list and len(receipts) == 2, "context-public-receipts")
        for suffix, receipt in zip(("plist", "bom"), receipts):
            need(type(receipt) is dict and set(receipt) == {"suffix", "present", "bytes", "sha256"}
                 and receipt["suffix"] == suffix and type(receipt["present"]) is bool,
                 "context-public-receipts")
            if receipt["present"]:
                need(type(receipt["bytes"]) is int and 0 < receipt["bytes"] <= 1024 * 1024
                     and identity(receipt["sha256"], 64), "context-public-receipts")
            else:
                need(suffix == "bom" and receipt["bytes"] is None and receipt["sha256"] is None,
                     "context-public-receipts")
    return value


def native_rust_test_record():
    return {"schemaVersion": 1, "type": "mrk-macos-native-rust-tests-v1", "target": TARGET,
            "tests": list(NATIVE_RUST_TESTS), "passed": 6, "failed": 0, "ignored": 0, "measured": 0}


def installer_worker_rust_test_record():
    return {"schemaVersion": 1, "type": "mrk-macos-installer-worker-rust-tests-v1", "target": TARGET,
            "cargoProfile": "test", "tests": list(INSTALLER_WORKER_RUST_TESTS),
            "passed": 3, "failed": 0, "ignored": 0, "measured": 0}


def _rust_tests_data(value, expected, label):
    """Only the two fixed wrappers supply this expected record; never output DATA."""
    count = len(expected["tests"])  # SOURCE-fixed wrapper record, not received DATA.
    need(count in (3, 6) and expected["passed"] == count, label + "-record")
    need(type(value) is dict and set(value) == set(expected)
         and all(type(value[key]) is int and value[key] == expected[key]
                 for key in ("schemaVersion", "passed", "failed", "ignored", "measured"))
         and all(type(value[key]) is str and value[key] == item
                 for key, item in expected.items() if type(item) is str)
         and type(value["tests"]) is list and len(value["tests"]) == count
         and all(type(name) is str for name in value["tests"])
         and value["tests"] == expected["tests"], label + "-record")
    return expected


def native_rust_tests_data(value):
    """A closed projection, never authority to execute a test or native action."""
    return _rust_tests_data(value, native_rust_test_record(), "native-rust-test")


def installer_worker_rust_tests_data(value):
    """Test-profile DATA, not shipping compilation or a joined worker transaction."""
    return _rust_tests_data(value, installer_worker_rust_test_record(), "installer-worker-rust-test")


def _rust_test_output(stdout, expected_names, label):
    """Complete pinned libtest pretty output from an already-successful original."""
    count = len(expected_names)  # Only the native6 and worker3 SOURCE tuples call this.
    need(count in (3, 6), label + "-roster")
    need(type(stdout) is bytes and 0 < len(stdout) <= 65536 and stdout.isascii(), label + "-bound")
    lines = stdout.split(b"\n")
    need(len(lines) == count + 6 and lines[:2] == [b"", ("running %d tests" % count).encode("ascii")]
         and lines[count + 2] == b"" and lines[count + 4:] == [b"", b""], label + "-framing")
    names = []
    for line in lines[2:count + 2]:
        match = re.fullmatch(rb"test ([A-Za-z0-9_:]+) +\.\.\. ok", line)
        need(match is not None, label + "-roster")
        names.append(match[1].decode("ascii"))
    need(len(set(names)) == count and set(names) == set(expected_names), label + "-roster")
    finish = re.fullmatch(
        rb"test result: ok\. " + str(count).encode("ascii") + rb" passed; 0 failed; 0 ignored; 0 measured; (0|[1-9][0-9]{0,3}) filtered out; "
        rb"finished in (0|[1-9][0-9]{0,2})\.([0-9]{2})s", lines[count + 3])
    need(finish is not None and int(finish[2]) * 100 + int(finish[3]) <= 48000, label + "-result")


def native_rust_tests_result(stdout):
    _rust_test_output(stdout, NATIVE_RUST_TESTS, "native-rust-test")
    return native_rust_test_record()


def installer_worker_rust_tests_result(stdout):
    _rust_test_output(stdout, INSTALLER_WORKER_RUST_TESTS, "installer-worker-rust-test")
    return installer_worker_rust_test_record()


def cargo_artifact(messages, role, checkout, target):
    """Require the actual compiler roster, not an executable found by basename."""
    need(role in ("client", "resident") and type(messages) is bytes
         and 0 < len(messages) <= 4 * 1024 * 1024 and messages.endswith(b"\n"), "cargo-bound")
    lines = messages.splitlines()
    need(1 < len(lines) <= 8192 and all(lines), "cargo-lines")
    records, finished = [], False
    for line in lines:
        row = decode(line, 1024 * 1024)
        need(type(row) is dict and not finished and row.get("reason") in
             ("compiler-artifact", "compiler-message", "build-script-executed", "build-finished"),
             "cargo-order")
        if row["reason"] == "build-finished":
            need(set(row) == {"reason", "success"} and row["success"] is True, "cargo-finish")
            finished = True
        elif row["reason"] == "compiler-artifact":
            need(type(row.get("target")) is dict and type(row.get("filenames")) is list
                 and all(type(item) is str for item in row["filenames"]), "cargo-artifact-shape")
            records.append(row)
    need(finished, "cargo-finished")
    package = "mrk-macos-installed-native" if role == "client" else "mrk-android-register"
    directory = NATIVE if role == "client" else HELPER
    name = "e2_maintenance_client" if role == "client" else "mrk_resident_image"
    entry = "examples/e2_maintenance_client.rs" if role == "client" else "src/lib.rs"
    kind = ["example"] if role == "client" else ["cdylib"]
    features = ["desktop-image", "e2-native-fixture"] if role == "client" else ["e2-native-fixture"]
    binary = target / TARGET / "release"
    binary = binary / ("examples/libe2_maintenance_client.dylib" if role == "client" else "libmrk_resident_image.dylib")
    selected = [row for row in records if row["target"].get("name") == name
                or str(binary) in row["filenames"] or row.get("executable") == str(binary)]
    need(len(selected) == 1, "one-fixture-image")
    row = selected[0]
    need(row.get("package_id") == "path+" + (checkout / directory).as_uri() + "#" + package + "@0.1.0"
         and row.get("manifest_path") == str(checkout / directory / "Cargo.toml")
         and row.get("features") == features and row["filenames"] == [str(binary)]
         and "executable" in row and row["executable"] is None, "fixture-cargo-binding")
    image = row["target"]
    need(image.get("name") == name and image.get("kind") == kind and image.get("crate_types") == ["cdylib"]
         and image.get("src_path") == str(checkout / directory / entry) and image.get("edition") == "2021",
         "fixture-cargo-target")
    profile = row.get("profile")
    need(type(profile) is dict and profile.get("test") is False and profile.get("debug_assertions") is False
         and profile.get("opt_level") == "3" and type(row.get("fresh")) is bool, "fixture-release-profile")
    need(not any(item is not row and (item["target"].get("kind") in (["bin"], ["example"], ["test"], ["bench"], ["cdylib"])
                                     or item["target"].get("crate_types") == ["cdylib"]) for item in records),
         "separate-fixture-image-graph")
    # Each role is admitted from its own graph. Mixed shipping/observer/vault
    # roles never become acceptable merely because the selected image exists.
    native_rows = [item for item in records if item["target"].get("name") == "mrk_macos_installed_native"]
    need(len(native_rows) == 1, "one-native-role-library")
    native = native_rows[0]
    admitted = ({"desktop-image", "e2-native-fixture"} if role == "client" else
                {"android-registration-helper", "default", "resident-image", "e2-native-fixture"})
    need(type(native.get("features")) is list and all(type(item) is str for item in native["features"])
         and len(native["features"]) == len(set(native["features"]))
         and set(native["features"]) == admitted
         and native.get("package_id") == "path+" + (checkout / NATIVE).as_uri() + "#mrk-macos-installed-native@0.1.0"
         and native.get("manifest_path") == str(checkout / NATIVE / "Cargo.toml")
         and native["target"].get("kind") == ["lib"] and native["target"].get("crate_types") == ["lib"]
         and native["target"].get("src_path") == str(checkout / NATIVE / "src/lib.rs")
         and native.get("executable") is None, "native-role-features")
    return binary


def fixture_image_macho(body, role):
    """Separate fixed fixture identity; never changes product IMAGE_INSTALL_NAMES."""
    need(role in IMAGES and type(body) is bytes and 32 <= len(body) <= IMAGE_LIMIT, "fixture-image-bound")
    magic, cpu, subtype, kind, count, size, flags, reserved = struct.unpack_from("<8I", body)
    need((magic, cpu, subtype, kind, reserved) == (0xFEEDFACF, 0x0100000C, 0, 6, 0)
         and 0 < count <= 128 and size <= 65536 and 32 + size <= len(body)
         and flags & (0x4 | 0x80) == (0x4 | 0x80) and not flags & 0x20000, "fixture-image-header")
    allowed = {0x19, 0x2, 0xB, 0xC, 0xD, 0x1B, 0x32, 0x2A,
               0x26, 0x29, 0x1D, 0x2E, 0x80000022, 0x80000033, 0x80000034}
    offset, identifiers, libraries, minimum = 32, [], [], []
    for _ in range(count):
        need(offset + 8 <= 32 + size, "fixture-image-command")
        command, length = struct.unpack_from("<II", body, offset)
        need(command in allowed and length >= 8 and length % 8 == 0
             and offset + length <= 32 + size, "fixture-image-loader-command")
        if command in (0xC, 0xD):
            need(length >= 24, "fixture-image-library")
            start = struct.unpack_from("<I", body, offset + 8)[0]
            need(24 <= start < length, "fixture-image-library-offset")
            raw = body[offset + start:offset + length]
            need(b"\0" in raw, "fixture-image-library-termination")
            name, padding = raw.split(b"\0", 1)
            need(not any(padding), "fixture-image-library-padding")
            if command == 0xD:
                identifiers.append(name)
            else:
                need(name.startswith((b"/System/Library/", b"/usr/lib/"))
                     and all(32 < char < 127 for char in name)
                     and all(part not in (b"", b".", b"..") for part in name.split(b"/")[1:]),
                     "fixture-system-dependency")
                libraries.append(name)
        elif command == 0x19:
            need(length >= 72, "fixture-image-segment")
            sections = struct.unpack_from("<I", body, offset + 64)[0]
            need(sections <= 256 and length == 72 + sections * 80, "fixture-image-sections")
        elif command == 0x32:
            need(length >= 24, "fixture-image-version")
            minimum.append(struct.unpack_from("<II", body, offset + 8))
        offset += length
    # Distinguish existing fixed checks without publishing image bytes or names.
    need(offset == 32 + size, "fixture-image-command-span")
    need(minimum == [(1, 26 << 16)], "fixture-image-platform-minimum")
    need(identifiers == [("@rpath/libmrk_e2_native_" + role + ".dylib").encode("ascii")],
         "fixture-image-role-identity")
    need(len(libraries) == len(set(libraries)) and libraries.count(b"/usr/lib/libSystem.B.dylib") == 1,
         "fixture-image-system-closure")

METADATA_PATHS = (Path("/"), Path("/Library"), ROOT.parent, Path("/private"),
                  Path("/private/var"), Path("/private/var/db"),
                  Path("/private/var/db/receipts"), ROOT)
METADATA_FLAGS = ("localApfs", "ownershipEnforced", "noAce", "closeReturned")
METADATA_KEYS = {"schemaVersion", "type", "sourceCommit", "outcome", "originalClosesKnown", "rows"}


def service_observer_macho(body, stager):
    """Diagnostic-only public framework executable; ordinary entry stays unchanged."""
    stager.macho(body, system_only=True)
    flags = struct.unpack_from("<I", body, 24)[0]
    need(flags & (0x4 | 0x80 | 0x200000) == (0x4 | 0x80 | 0x200000)
         and not flags & 0x20000, "layout-image-flags")
    allowed = {0x19, 0x2, 0xB, 0xE, 0xC, 0x1B, 0x32, 0x2A, 0x80000028,
               0x26, 0x29, 0x1D, 0x2E, 0x80000022, 0x80000033, 0x80000034}
    count = struct.unpack_from("<I", body, 16)[0]
    offset, libraries, dyld, mains = 32, [], [], 0
    for _ in range(count):
        command, length = struct.unpack_from("<II", body, offset)
        row = body[offset:offset + length]
        need(command in allowed, "layout-image-command")
        if command in (0xC, 0xE):
            start = 24 if command == 0xC else 12
            need(length > start and struct.unpack_from("<I", row, 8)[0] == start,
                 "layout-image-load-offset")
            end = row.find(b"\0", start)
            need(end > start and not any(row[end + 1:]), "layout-image-load-padding")
            (libraries if command == 0xC else dyld).append(row[start:end])
        elif command == 0x19:
            need(length >= 72, "layout-image-segment")
            sections = struct.unpack_from("<I", row, 64)[0]
            need(sections <= 256 and length == 72 + sections * 80, "layout-image-sections")
            for index in range(sections):
                section = row[72 + index * 80:152 + index * 80]
                need(struct.unpack_from("<I", section, 64)[0] & 0xFF not in (0x9, 0xA, 0x15)
                     and section[:16].split(b"\0", 1)[0] not in (
                         b"__mod_init_func", b"__mod_term_func", b"__init_offsets"),
                     "layout-image-initializer")
        elif command == 0x80000028:
            need(length == 24, "layout-image-main")
            mains += 1
        offset += length
    need(mains == 1 and dyld == [b"/usr/lib/dyld"]
         and len(libraries) == len(LAYOUT_LOADS) and set(libraries) == LAYOUT_LOADS,
         "layout-image-system-closure")


def metadata_result(stdout, returncode, source, expected_present, originals):
    """Read-only observation DATA bound to already-held SAME FILE snapshots."""
    need(type(stdout) is bytes and len(stdout) <= 16384 and stdout.endswith(b"\n")
         and stdout.count(b"\n") == 1 and type(returncode) is int and returncode == 0
         and type(expected_present) is bool and identity(source, 40)
         and type(originals) is list and len(originals) == 8, "metadata-original-result")
    value = decode(stdout, 16384)
    need(type(value) is dict and set(value) == METADATA_KEYS
         and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and value["type"] == "mrk-e2-protected-metadata-v1" and value["sourceCommit"] == source
         and value["outcome"] == "passed" and value["originalClosesKnown"] is True
         and type(value["rows"]) is list and len(value["rows"]) == 8, "metadata-result-binding")
    for index, row in enumerate(value["rows"]):
        present = index != 7 or expected_present
        need(type(row) is dict and set(row) == {"pathIndex", "present", "full9", *METADATA_FLAGS}
             and type(row["pathIndex"]) is int and row["pathIndex"] == index
             and row["present"] is present and type(row["full9"]) is list
             and all(type(row[key]) is bool for key in METADATA_FLAGS), "metadata-row-shape")
        if not present:
            need(row["full9"] == [] and not any(row[key] for key in METADATA_FLAGS)
                 and originals[index] is None, "metadata-absent-fixture")
            continue
        full = row["full9"]
        need(len(full) == 9 and all(type(number) is str
             and re.fullmatch(r"0|[1-9][0-9]{0,19}", number) and int(number) < 1 << 64
             for number in full), "metadata-full9")
        full = tuple(int(number) for number in full)
        need(type(originals[index]) is tuple and full == originals[index]
             and all(row[key] for key in METADATA_FLAGS)
             and full[1] > 0 and full[5] > 0 and stat.S_ISDIR(full[2]) and full[3] == 0
             and not full[2] & 0o7022
             and (index != 7 or full[4] == 0 and stat.S_IMODE(full[2]) == 0o755),
             "metadata-same-original-policy")
    return value


# Fixed read-only SOURCE; compiled only by the admitted native owner.
METADATA_OBSERVER_C = r'''
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#ifndef MRK_IMAGE_SOURCE_COMMIT
#error fixed admitted source required
#endif
_Static_assert(sizeof(MRK_IMAGE_SOURCE_COMMIT) == 41, "fixed source width");
int mrk_user(uint32_t *);
int mrk_acl_empty(int, int *, int *, int *, int *, int *);

enum { ROWS = 8, FIELDS = 9 };
static const char *const names[ROWS] = {
    "/", "Library", "Application Support", "private", "var", "db",
    "receipts", "MobileReleaseKit-E2NativeFixture"
};
static const int parents[ROWS] = { -1, 0, 1, 0, 3, 4, 5, 2 };
struct row {
    int fd, present, full_known, local, owners, no_ace, closed;
    struct stat original;
    struct statfs filesystem;
    uint64_t full[FIELDS];
};
struct observation {
    struct row rows[ROWS];
    uint64_t last, deadline;
    int clock_started, failed, closes_known;
};

static int clock_step(struct observation *book) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0 || value.tv_sec < 0
        || value.tv_nsec < 0 || value.tv_nsec >= 1000000000
        || (uint64_t)value.tv_sec > (UINT64_MAX - 999999999u) / 1000000000u) {
        book->failed = 1; return 0;
    }
    uint64_t now = (uint64_t)value.tv_sec * 1000000000u + (uint64_t)value.tv_nsec;
    if (!book->clock_started) {
        if (!now || now > UINT64_MAX - 10000000000ull) { book->failed = 1; return 0; }
        book->last = now; book->deadline = now + 10000000000ull; book->clock_started = 1;
    } else if (now < book->last || now > book->deadline) {
        book->failed = 1; return 0;
    } else {
        book->last = now;
    }
    return 1;
}
static int full9(const struct stat *s, uint64_t out[FIELDS]) {
    if (s->st_dev < 0 || !s->st_ino || !s->st_nlink || s->st_size < 0
        || s->st_mtimespec.tv_sec < 0 || s->st_ctimespec.tv_sec < 0
        || s->st_mtimespec.tv_nsec < 0 || s->st_mtimespec.tv_nsec >= 1000000000
        || s->st_ctimespec.tv_nsec < 0 || s->st_ctimespec.tv_nsec >= 1000000000
        || (uint64_t)s->st_mtimespec.tv_sec > (UINT64_MAX - 999999999u) / 1000000000u
        || (uint64_t)s->st_ctimespec.tv_sec > (UINT64_MAX - 999999999u) / 1000000000u) return 0;
    out[0] = (uint64_t)s->st_dev; out[1] = (uint64_t)s->st_ino;
    out[2] = (uint64_t)s->st_mode; out[3] = (uint64_t)s->st_uid;
    out[4] = (uint64_t)s->st_gid; out[5] = (uint64_t)s->st_nlink;
    out[6] = (uint64_t)s->st_size;
    out[7] = (uint64_t)s->st_mtimespec.tv_sec * 1000000000u + (uint64_t)s->st_mtimespec.tv_nsec;
    out[8] = (uint64_t)s->st_ctimespec.tv_sec * 1000000000u + (uint64_t)s->st_ctimespec.tv_nsec;
    return 1;
}
static int same(const struct stat *a, const struct stat *b) {
    uint64_t aa[FIELDS], bb[FIELDS];
    return full9(a, aa) && full9(b, bb) && !memcmp(aa, bb, sizeof(aa))
        && a->st_flags == b->st_flags;
}
static int directory_policy(unsigned index, const struct stat *s) {
    /* Reuse gate.c's ancestor OWNERSHIP predicate only. Fixture root stricter. */
    return S_ISDIR(s->st_mode) && s->st_uid == 0 && !(s->st_mode & 07022)
        && (index != 7 || (s->st_gid == 0 && (s->st_mode & 07777) == 0755));
}
static int named_stat(struct observation *book, unsigned index, struct stat *s) {
    return index == 0 ? lstat("/", s)
        : fstatat(book->rows[parents[index]].fd, names[index], s, AT_SYMLINK_NOFOLLOW);
}
static int filesystem_policy(unsigned index, const struct statfs *fs) {
    return !strcmp(fs->f_fstypename, "apfs") && (fs->f_flags & MNT_LOCAL)
        && !(fs->f_flags & (MNT_UNION | MNT_AUTOMOUNTED | MNT_IGNORE_OWNERSHIP))
        && ((index != 2 && index != 6 && index != 7) || !(fs->f_flags & MNT_RDONLY));
}
static int inspect(struct observation *book, unsigned index) {
    struct row *row = &book->rows[index];
    struct stat named, actual, after;
    struct statfs filesystem;
    if (!clock_step(book)) return 0;
    errno = 0;
    int result = named_stat(book, index, &named);
    int error = errno;
    if (!clock_step(book)) return 0;
    if (result != 0) return index == 7 && error == ENOENT;
    row->present = 1;
    if (!directory_policy(index, &named)) return 0;
    if (!clock_step(book)) return 0;
    int flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;
    row->fd = index == 0 ? open("/", flags)
        : openat(book->rows[parents[index]].fd, names[index], flags);
    if (!clock_step(book) || row->fd < 0) return 0;
    if (fstat(row->fd, &actual) != 0 || !clock_step(book)
        || !same(&named, &actual) || !directory_policy(index, &actual)
        || !full9(&actual, row->full)) return 0;
    row->original = actual; row->full_known = 1;
    if (!clock_step(book) || fstatfs(row->fd, &filesystem) != 0 || !clock_step(book)
        || !filesystem_policy(index, &filesystem)) return 0;
    row->filesystem = filesystem; row->local = row->owners = 1;
    int phase = 0, returned = 0, native_errno = 0, freed = 0, free_errno = 0;
    if (!clock_step(book)) return 0;
    result = mrk_acl_empty(row->fd, &phase, &returned, &native_errno, &freed, &free_errno);
    if (freed || free_errno) book->closes_known = 0;
    if (!clock_step(book) || result || phase || returned || native_errno || freed || free_errno) return 0;
    row->no_ace = 1;
    if (!clock_step(book) || fstat(row->fd, &after) != 0 || !clock_step(book)
        || !same(&actual, &after) || named_stat(book, index, &after) != 0
        || !clock_step(book) || !same(&actual, &after)) return 0;
    return 1;
}
static int recheck(struct observation *book, unsigned index) {
    struct row *row = &book->rows[index];
    struct stat now;
    struct statfs fs;
    if (!clock_step(book)) return 0;
    if (!row->present) {
        errno = 0;
        int result = named_stat(book, index, &now);
        int error = errno;
        return clock_step(book) && index == 7 && result == -1 && error == ENOENT;
    }
    if (row->fd < 0 || !row->full_known || fstat(row->fd, &now) != 0
        || !clock_step(book) || !same(&row->original, &now)
        || named_stat(book, index, &now) != 0 || !clock_step(book)
        || !same(&row->original, &now) || fstatfs(row->fd, &fs) != 0
        || !clock_step(book) || !filesystem_policy(index, &fs)
        || fs.f_flags != row->filesystem.f_flags
        || memcmp(&fs.f_fsid, &row->filesystem.f_fsid, sizeof(fs.f_fsid))) return 0;
    return 1;
}
static int append(char *out, size_t *used, const char *format, ...) {
    va_list args; va_start(args, format);
    int count = vsnprintf(out + *used, 16384 - *used, format, args);
    va_end(args);
    if (count < 0 || (size_t)count >= 16384 - *used) return 0;
    *used += (size_t)count;
    return 1;
}
static const char *boolean(int value) { return value ? "true" : "false"; }
int main(int argc, char **argv) {
    (void)argv;
    struct observation book;
    memset(&book, 0, sizeof(book)); book.closes_known = 1;
    for (unsigned i = 0; i < ROWS; ++i) book.rows[i].fd = -1;
    uint32_t uid = 0;
    if (argc != 1 || !clock_step(&book) || mrk_user(&uid) || !clock_step(&book)) book.failed = 1;
    for (unsigned i = 0; i < ROWS && !book.failed; ++i)
        if (!inspect(&book, i)) book.failed = 1;
    for (unsigned i = 0; i < ROWS && !book.failed; ++i)
        if (!recheck(&book, i)) book.failed = 1;
    /* Deadline failure never prevents consuming each entered original once. */
    for (unsigned i = ROWS; i > 0; --i) {
        struct row *row = &book.rows[i - 1];
        int fd = row->fd; row->fd = -1;
        if (fd >= 0) {
            (void)clock_step(&book);
            if (close(fd) == 0) row->closed = 1;
            else { book.failed = 1; book.closes_known = 0; }
            (void)clock_step(&book);
        }
    }
    (void)clock_step(&book);
    char output[16384]; size_t used = 0;
    if (!append(output, &used,
        "{\"schemaVersion\":1,\"type\":\"mrk-e2-protected-metadata-v1\",\"sourceCommit\":\"%s\","
        "\"outcome\":\"%s\",\"originalClosesKnown\":%s,\"rows\":[",
        MRK_IMAGE_SOURCE_COMMIT, book.failed ? "failed" : "passed", boolean(book.closes_known))) return 1;
    for (unsigned i = 0; i < ROWS; ++i) {
        const struct row *row = &book.rows[i];
        if (!append(output, &used, "%s{\"pathIndex\":%u,\"present\":%s,\"full9\":[",
            i ? "," : "", i, boolean(row->present))) return 1;
        for (unsigned n = 0; row->full_known && n < FIELDS; ++n)
            if (!append(output, &used, "%s\"%" PRIu64 "\"", n ? "," : "", row->full[n])) return 1;
        if (!append(output, &used,
            "],\"localApfs\":%s,\"ownershipEnforced\":%s,\"noAce\":%s,\"closeReturned\":%s}",
            boolean(row->local), boolean(row->owners), boolean(row->no_ace), boolean(row->closed))) return 1;
    }
    if (!append(output, &used, "]}\n") || !clock_step(&book)) return 1;
    if (write(STDOUT_FILENO, output, used) != (ssize_t)used || !clock_step(&book)) return 1;
    return book.failed ? 1 : 0;
}
'''


class Originals:
    """Finite no-follow filesystem custody, independent of the process owner."""

    def __init__(self):
        self.entries, self.directories, self.errors = [], {}, []

    def register(self, fd, path, kind):
        entry = {"fd": fd, "path": Path(path), "kind": kind, "identity": None, "closed": False}
        self.entries.append(entry)
        need(len(self.entries) <= 2048, "original-handle-bound")
        return entry

    def directory(self, path):
        path = Path(path)
        need(path.is_absolute() and str(path) == os.path.normpath(path)
             and len(path.parts) <= 40, "directory-spelling")
        if path in self.directories:
            entry = self.directories[path]
            self.check_one(entry)
            return entry
        parent = None if path == Path("/") else self.directory(path.parent)
        fd = os.open(str(path) if parent is None else path.name, READ_FLAGS | os.O_DIRECTORY,
                     dir_fd=None if parent is None else parent["fd"])
        entry = self.register(fd, path, "directory")
        before = os.fstat(fd)
        need(stat.S_ISDIR(before.st_mode) and before.st_uid in (0, os.getuid())
             and not before.st_mode & 0o022, "directory-owner-mode")
        entry["identity"] = signature(before)[:5]
        entry["parent"] = parent
        self.directories[path] = entry
        self.check_one(entry)
        return entry

    def check_one(self, entry):
        need(entry["fd"] is not None and entry["identity"] is not None, "original-unbound")
        parent = entry.get("parent")
        named = os.stat(str(entry["path"]) if parent is None else entry["path"].name,
                        dir_fd=None if parent is None else parent["fd"], follow_symlinks=False)
        length = len(entry["identity"])
        need(signature(os.fstat(entry["fd"]))[:length] == entry["identity"]
             and signature(named)[:length] == entry["identity"], "original-changed")

    def file(self, path, limit, *, uid=None, modes=None, alias=False):
        path = Path(path)
        parent = self.directory(path.parent)
        fd = os.open(path.name, READ_FLAGS, dir_fd=parent["fd"])
        entry = self.register(fd, path, "file")
        entry["parent"] = parent
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == (os.getuid() if uid is None else uid)
             and info.st_nlink in ((1, 2) if alias else (1,))
             and 0 <= info.st_size <= limit and not info.st_mode & 0o022
             and (modes is None or stat.S_IMODE(info.st_mode) in modes), "file-original-policy")
        entry["identity"] = signature(info)
        return entry, self.read(entry)

    def read(self, entry):
        self.check_one(entry)
        expected = entry["identity"][6]
        body, offset = bytearray(), 0
        while offset < expected:
            block = os.pread(entry["fd"], min(65536, expected - offset), offset)
            need(block, "original-short-read")
            body.extend(block)
            offset += len(block)
        need(os.pread(entry["fd"], 1, expected) == b"", "original-grew")
        self.check_one(entry)
        return bytes(body)

    def check(self):
        for entry in self.entries:
            if entry["fd"] is not None:
                self.check_one(entry)

    def close(self, entry):
        if entry["fd"] is None:
            return
        fd, entry["fd"] = entry["fd"], None  # Consumed before close; never retry.
        try:
            os.close(fd)
            entry["closed"] = True
        except OSError:
            self.errors.append("original-close-unknown")

    def finish(self):
        for entry in reversed(self.entries):
            self.close(entry)
        return not self.errors and all(entry["closed"] for entry in self.entries)

    def publish(self, path, body, mode=0o600):
        need(type(body) is bytes and len(body) <= 128 * 1024 * 1024, "output-bound")
        path = Path(path)
        parent = self.directory(path.parent)
        fd = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     mode, dir_fd=parent["fd"])
        entry = self.register(fd, path, "output")
        entry["parent"] = parent
        offset = 0
        while offset < len(body):
            size = os.write(fd, body[offset:offset + 65536])
            need(size > 0, "output-short-write")
            offset += size
        os.fchmod(fd, mode)
        os.fsync(fd)
        entry["identity"] = signature(os.fstat(fd))
        need(entry["identity"][3] == os.getuid() and entry["identity"][5] == 1
             and self.read(entry) == body, "output-readback")
        self.close(entry)
        need(entry["closed"], "output-close-unknown")


def binding_data(environment, binding, inventory, rust, work_identity):
    """Pure source/run/toolchain correspondence; no environment grants authority."""
    source = environment.get("GITHUB_SHA")
    need(identity(source, 40) and source != "0" * 40, "source-shape")
    for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        need(type(environment.get(name)) is str
             and re.fullmatch(r"[1-9][0-9]{0,19}", environment[name]), "run-shape")
    need(type(binding) is dict and type(binding.get("schemaVersion")) is int
         and binding["schemaVersion"] == 1 and binding.get("source") == source
         and binding.get("workflowSource") == source == environment.get("GITHUB_WORKFLOW_SHA")
         and binding.get("runId") == environment["GITHUB_RUN_ID"]
         and binding.get("runAttempt") == environment["GITHUB_RUN_ATTEMPT"]
         and identity(binding.get("tree"), 40)
         and type(binding.get("workDirectory")) is list
         and all(type(number) is int for number in binding["workDirectory"])
         and binding["workDirectory"] == [work_identity[0], work_identity[1], work_identity[3]],
         "source-run-binding")
    need(type(inventory) is dict and set(inventory) == {"source", "tree", "files"}
         and inventory["source"] == source and inventory["tree"] == binding["tree"]
         and type(inventory["files"]) is list and 0 < len(inventory["files"]) <= 4096,
         "source-inventory-binding")
    rows = {}
    for row in inventory["files"]:
        need(type(row) is dict and set(row) == {"path", "gitMode", "blob", "size", "sha256"}
             and type(row["path"]) is str and len(row["path"]) <= 512
             and not row["path"].startswith("/") and "\\" not in row["path"]
             and "\0" not in row["path"]
             and all(piece not in ("", ".", "..") for piece in row["path"].split("/"))
             and row["path"] not in rows and row["gitMode"] in ("100644", "100755")
             and type(row["size"]) is int and 0 <= row["size"] <= IMAGE_LIMIT
             and identity(row["sha256"], 64) and identity(row["blob"], 40), "source-inventory-row")
        rows[row["path"]] = row
    need(type(rust) is dict and type(rust.get("schemaVersion")) is int and rust["schemaVersion"] == 1
         and rust.get("source") == rust.get("workflowSource") == source
         and rust.get("runId") == environment["GITHUB_RUN_ID"]
         and rust.get("runAttempt") == environment["GITHUB_RUN_ATTEMPT"]
         and rust.get("cwd") == "desktop/src-tauri" and rust.get("autoInstall") is False
         and rust.get("selectedMacToolchain") == TOOLCHAIN and rust.get("repositoryDefault") == "1.98.0"
         and type(rust.get("tools")) is dict and set(rust["tools"]) == {"rustc", "cargo"},
         "effective-rust-binding")
    for name in ("rustc", "cargo"):
        row = rust["tools"][name]
        need(type(row) is dict and row.get("command") == [name, "--version", "--verbose"]
             and type(row.get("output")) is str and len(row["output"]) <= 4096
             and row["output"].startswith(name + " "), "effective-rust-tool")
    need("release: " + TOOLCHAIN in rust["tools"]["rustc"]["output"].splitlines()
         and "commit-hash: " + RUST_COMMIT in rust["tools"]["rustc"]["output"].splitlines(),
         "effective-rust-clock-version")
    need("release: " + TOOLCHAIN in rust["tools"]["cargo"]["output"].splitlines(),
         "effective-cargo-clock-version")
    return rows


def source_names(rows):
    """Actual three-graph inputs, including core compile-time DATA and owner imports."""
    explicit = {
        ".github/workflows/desktop-macos-maintenance-fixture.yml",
        "desktop/rust-toolchain.toml", "desktop/packaging/macos-empty-entitlements.plist",
        "desktop/packaging/macos-android-service-signing.profile",
        "desktop/packaging/macos-install-producer-signing.profile",
        "desktop/tools/macos_e2_native_fixture.py", "desktop/tools/macos_aqua_qualification.py",
        "desktop/tools/stage_macos_installed.py", CONTEXT_SOURCE, LAYOUT_SOURCE,
        "desktop/tools/macos_android_sdk_metadata.py",
        "src/mobile_release/api/data/metadata-images-v1.json",
        "src/mobile_release/api/data/metadata-image-help-v1.json",
        *("src/mobile_release/" + name for name in (
            "__init__.py", "owned_process.py", "_command_process.py", "_native_process.py",
            "cancellation.py", "errors.py", "_lifetime_evidence.py",
            "_store_lane_contract.py", "_store_lane_evidence.py")),
    }
    need(explicit <= set(rows), "required-source-roster")
    # Only a configured SOURCE profile uses these three fixed public certificates.
    # The unconfigured profile must not require fabricated certificate inputs.
    optional = {"desktop/packaging/macos-install-producer-certificates/" + name + ".der"
                for name in ("leaf", "issuer", "root")}
    prefixes = ("desktop/native/macos-installed-native/", "desktop/native/macos-installed-entry/",
                "desktop/helpers/macos-android-register/", "desktop/src-tauri/",
                "desktop/macos-installed-inputs/", "templates/", "schemas/")
    # Build scripts and Rust include_bytes!/include_str! use the headless core,
    # its checked-in generated catalogue, Python bootstrap SOURCE and templates.
    # No unrelated Debian notices, UI frontend, registry cache or other platform
    # implementation is held merely because it shares a repository.
    return sorted(name for name in rows if name in explicit or name in optional or name.startswith(prefixes)
                  or name.startswith("desktop/") and name.count("/") == 1 and name.endswith(".py")
                  or name.startswith("desktop/") and name.rsplit("/", 1)[-1] in ("Cargo.toml", "Cargo.lock"))


class SourceInputs:
    def __init__(self, book, work, environment):
        self.book, self.work, self.environment = book, work, environment
        self.rows, self.held = {}, {}
        self.binding = None

    def admit(self):
        work = self.book.directory(self.work)
        info = os.fstat(work["fd"])
        need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, "private-original-work")
        binding_entry, binding_body = self.book.file(self.work / "source-binding.json", 65536, modes=(0o600,))
        _inventory_entry, inventory_body = self.book.file(self.work / "source-inventory.json", 2 * 1024 * 1024, modes=(0o600,))
        _rust_entry, rust_body = self.book.file(self.work / "effective-rust-toolchain.json", 16384, modes=(0o600,))
        self.binding = decode(binding_body, 65536)
        self.rows = binding_data(self.environment, self.binding, decode(inventory_body, 2 * 1024 * 1024),
                                 decode(rust_body, 16384), signature(info))
        self.inventory_digest = digest(inventory_body)
        self.binding_digest = digest(binding_body)
        _head, body = self.book.file(CHECKOUT / ".git/HEAD", 64, modes=(0o600, 0o644))
        need(body == (self.environment["GITHUB_SHA"] + "\n").encode("ascii"), "detached-checkout")
        # All actual Rust/native/helper/owner/build inputs are bound before
        # loading project modules. They stay held through compiler/native work.
        selected = source_names(self.rows)
        need(len(selected) <= 512, "source-original-roster-bound")
        # Admit actual capacity before accumulating the source originals. This
        # query is local to native main; DATA import does not probe a process.
        import resource
        source_parents = {parent for name in selected for parent in (CHECKOUT / name).parents}
        source_parents.update(self.work.parents)
        source_parents.update((self.work, CHECKOUT / ".git"))
        self.source_handle_count = len(selected) + len(source_parents) + 4
        self.source_handle_reserve = 192  # Existing160 plus32 retained context/helper/receipt originals.
        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        need(soft == resource.RLIM_INFINITY or soft >= self.source_handle_count + self.source_handle_reserve,
             "source-original-descriptor-capacity")
        for name in selected:
            self.read(name)
        return self.binding

    def read(self, name):
        need(name in self.rows, "unlisted-source")
        expected = self.rows[name]
        if name in self.held:
            body = self.book.read(self.held[name])
        else:
            entry, body = self.book.file(CHECKOUT / name, IMAGE_LIMIT)
            self.held[name] = entry
            mode = stat.S_IMODE(entry["identity"][2])
            need(mode in ((0o444, 0o644) if expected["gitMode"] == "100644" else (0o555, 0o755)),
                 "source-executable-mode")
        need(len(body) == expected["size"] and digest(body) == expected["sha256"]
             and hashlib.sha1(b"blob " + str(len(body)).encode("ascii") + b"\0" + body).hexdigest() == expected["blob"],
             "source-bytes")
        return body

    def load(self, filename, name):
        self.read("desktop/tools/" + filename)
        self.book.check()
        need(name not in sys.modules, "source-module-already-loaded")
        spec = importlib.util.spec_from_file_location(name, CHECKOUT / "desktop/tools" / filename)
        need(spec is not None and spec.loader is not None, "source-module-loader")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        self.book.check()
        return module


def admit(environment):
    # These native/account calls occur only in main, never DATA imports/tests.
    import platform
    import threading
    need(sys.platform == "darwin" and platform.machine() == "arm64"
         and platform.mac_ver()[0].split(".")[0] == "26"
         and os.getuid() == os.geteuid() != 0 and os.getgid() == os.getegid()
         and threading.current_thread() is threading.main_thread() and sys.version_info >= (3, 11)
         and shutil.rmtree.avoids_symlink_attacks, "native-platform-account")
    need(len(sys.argv) in (1, 2) and sys.argv[1:] in ([], [LAYOUT_ARGUMENT])
         and Path(__file__).absolute() == CHECKOUT / "desktop/tools/macos_e2_native_fixture.py"
         and Path.cwd() == CHECKOUT and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
         "native-entry-route")
    source = environment.get("GITHUB_SHA")
    expected = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS",
                "RUNNER_ARCH": "ARM64", "GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": REPOSITORY,
                "GITHUB_REF": REF, "GITHUB_WORKFLOW_REF": WORKFLOW, "GITHUB_WORKFLOW_SHA": source,
                "GITHUB_WORKSPACE": str(CHECKOUT), "RUNNER_TEMP": str(WORK_PARENT),
                "GITHUB_JOB": "e2_fixture", "MRK_EXPECTED_SHA": source,
                "MRK_MACOS_INSTALL_SOURCE_COMMIT": source, "RUSTUP_TOOLCHAIN": TOOLCHAIN,
                "DEVELOPER_DIR": "/Library/Developer/CommandLineTools", "MACOSX_DEPLOYMENT_TARGET": "26.0"}
    need(identity(source, 40) and all(environment.get(key) == value for key, value in expected.items()),
         "hosted-source-route")
    work = Path(environment.get("MRK_MACOS_WORK", ""))
    need(work.parent == WORK_PARENT and re.fullmatch(r"mrk-macos-maintenance-fixture\.[A-Za-z0-9]{8}", work.name),
         "work-route")
    return work


def fixture_domain(binding):
    value = binding.get("fixtureAdministrativeDomain")
    need(type(value) is dict and type(value.get("schemaVersion")) is int
         and value.get("priorFixtureUse") is False and value == {
        "schemaVersion": 1, "allocation": "fresh-github-hosted-single-job",
        "writer": "macos_e2_native_fixture.py", "root": str(ROOT), "receipt": PACKAGE,
        "priorFixtureUse": False,
    }, "fixture-administrative-domain")
    # This is a declaration bound to reviewed workflow SOURCE, NOT proof of a
    # runtime allocation or protection from arbitrary privileged writers.


def package_payload(body, expected):
    """Closed gzip-cpio payload DATA, before any privileged Installer entry."""
    need(type(body) is bytes and len(body) <= 3 * IMAGE_LIMIT, "fixture-cpio-bound")
    directories = {""}
    for name in expected:
        directories.update("/".join(name.split("/")[:index]) for index in range(1, len(name.split("/"))))
    found, offset, root_seen = {}, 0, False
    for _ in range(64):
        start = offset
        magic = body[start:start + 6]
        if magic == b"070707":
            cursor, values = start + 6, []
            for width in (6, 6, 6, 6, 6, 6, 6, 11, 6, 11):
                raw = body[cursor:cursor + width]
                need(len(raw) == width and re.fullmatch(b"[0-7]+", raw), "fixture-odc-header")
                values.append(int(raw, 8))
                cursor += width
            _dev, _ino, mode, uid, gid, links, _rdev, _mtime, namesize, size = values
            name_start, align = cursor, 1
        elif magic == b"070701":
            raw = body[start + 6:start + 110]
            need(len(raw) == 104 and re.fullmatch(b"[0-9a-fA-F]+", raw), "fixture-newc-header")
            values = [int(raw[index:index + 8], 16) for index in range(0, 104, 8)]
            _ino, mode, uid, gid, links, _mtime, size, _devmaj, _devmin, rdevmaj, rdevmin, namesize, check = values
            need(rdevmaj == rdevmin == check == 0, "fixture-cpio-special-entry")
            name_start, align = start + 110, 4
        else:
            raise Refused("fixture-cpio-format")
        need(1 <= namesize <= 1024 and size <= IMAGE_LIMIT
             and name_start + namesize <= len(body), "fixture-cpio-entry-bound")
        raw_name = body[name_start:name_start + namesize]
        need(raw_name.endswith(b"\0") and b"\0" not in raw_name[:-1], "fixture-cpio-name")
        try:
            name = raw_name[:-1].decode("ascii", "strict")
        except UnicodeError as error:
            raise Refused("fixture-cpio-name") from error
        data_start = (name_start + namesize + align - 1) // align * align
        offset = (data_start + size + align - 1) // align * align
        need(offset <= len(body), "fixture-cpio-data-bound")
        if name == "TRAILER!!!":
            need(size == 0 and root_seen and not any(body[offset:])
                 and set(found) == set(expected) | (directories - {""}), "fixture-cpio-complete")
            return
        if name in (".", "./"):
            need(not root_seen and stat.S_ISDIR(mode) and stat.S_IMODE(mode) == 0o755
                 and uid == gid == size == 0, "fixture-cpio-root")
            root_seen = True
            continue
        if name.startswith("./"):
            name = name[2:]
        need(name and name in set(expected) | directories and name not in found and uid == gid == 0,
             "fixture-cpio-roster-owner")
        if name in directories:
            need(stat.S_ISDIR(mode) and stat.S_IMODE(mode) == 0o755 and size == 0, "fixture-cpio-directory")
        else:
            row = expected[name]
            need(stat.S_ISREG(mode) and links == 1 and stat.S_IMODE(mode) == int(row["mode"][-3:], 8)
                 and size == row["bytes"] and digest(body[data_start:data_start + size]) == row["sha256"],
                 "fixture-cpio-file-correspondence")
        found[name] = True
    raise Refused("fixture-cpio-count")


def fixture_package(body, expected, *, service_layout=False):
    """Fixed flat package, no scripts/relocation; complete payload correspondence."""
    import xml.etree.ElementTree as ET
    import zlib

    def inflate(packed, limit):
        stream = zlib.decompressobj(31 if packed[:2] == b"\x1f\x8b" else 15)
        result = stream.decompress(packed, limit + 1)
        need(len(result) <= limit and stream.eof and not stream.unconsumed_tail and not stream.unused_data,
             "fixture-package-inflate")
        return result

    need(type(body) is bytes and 28 <= len(body) <= 4 * IMAGE_LIMIT, "fixture-package-bound")
    magic, header, version, compressed, expanded, _checksum = struct.unpack_from(">IHHQQI", body)
    need((magic, header, version) == (0x78617221, 28, 1) and 0 < compressed <= 1024 * 1024
         and 0 < expanded <= 2 * 1024 * 1024 and header + compressed <= len(body), "fixture-xar-header")
    toc_bytes = inflate(body[header:header + compressed], expanded)
    need(len(toc_bytes) == expanded and b"<!DOCTYPE" not in toc_bytes and b"<!ENTITY" not in toc_bytes,
         "fixture-xar-xml")
    toc = ET.fromstring(toc_bytes)
    need(toc.tag == "xar" and len(toc.findall("toc")) == 1, "fixture-xar-toc")
    members, intervals = {}, []
    for member in toc.findall("toc/file"):
        name = member.findtext("name")
        need(name in ("Bom", "PackageInfo", "Payload") and name not in members
             and member.findtext("type") == "file" and not member.findall("file"), "fixture-xar-roster")
        texts = [member.findtext("data/" + key) for key in ("length", "offset", "size")]
        need(all(type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,9}", value) for value in texts),
             "fixture-xar-member-bound")
        length, offset, size = map(int, texts)
        start = header + compressed + offset
        need(0 < length <= 3 * IMAGE_LIMIT and size <= 3 * IMAGE_LIMIT
             and start + length <= len(body) and all(start + length <= low or start >= high for low, high in intervals),
             "fixture-xar-member-range")
        intervals.append((start, start + length))
        encoding = member.find("data/encoding")
        need(encoding is not None and encoding.get("style") in ("application/octet-stream", "application/x-gzip"),
             "fixture-xar-encoding")
        packed = body[start:start + length]
        unpacked = packed if encoding.get("style") == "application/octet-stream" else inflate(packed, size)
        need(len(unpacked) == size, "fixture-xar-size")
        members[name] = unpacked
    need(set(members) == {"Bom", "PackageInfo", "Payload"} and len(members["PackageInfo"]) <= 65536,
         "fixture-flat-package")
    info_bytes = members["PackageInfo"]
    need(b"<!DOCTYPE" not in info_bytes and b"<!ENTITY" not in info_bytes, "fixture-package-info-xml")
    info = ET.fromstring(info_bytes)
    need(info.tag == "pkg-info" and info.get("identifier") == PACKAGE and info.get("version") == "1"
         and info.get("install-location") == str(ROOT) and info.get("auth") == "root"
         and not info.findall(".//scripts"), "fixture-package-info")
    # pkgbuild can emit an empty relocate section; only absence of relocation
    # actions, not the spelling of its empty container, proves this policy.
    for element in info.findall(".//relocate"):
        need(not list(element) and not element.attrib and not (element.text or "").strip(),
             "fixture-package-relocation")
    bundle_names = {APP: IDENTIFIER, NESTED: IDENTIFIER + ".client"}
    need(type(service_layout) is bool, "layout-package-selector")
    if service_layout:
        bundle_names.update({root: LAYOUT_ID + ".client" for root in LAYOUT_CLIENTS})
        bundle_names[LAYOUT_HOST] = LAYOUT_ID + ".host"
    for element in info.findall(".//bundle"):
        path = element.get("path")
        if path is not None:
            path = path[2:] if path.startswith("./") else path
            need(path in bundle_names and element.get("id") == bundle_names[path],
                 "fixture-package-bundle-route")
        else:
            # upgrade/update/strict-identifier sections refer to the same fixed
            # bundle ids without a second install destination.
            need(element.get("id") in set(bundle_names.values()) and not list(element),
                 "fixture-package-bundle-reference")
    payload = members["Payload"]
    if payload.startswith(b"\x1f\x8b"):
        payload = inflate(payload, 3 * IMAGE_LIMIT)
    package_payload(payload, expected)
    return {"packageSha256": digest(body), "packageBytes": len(body),
            "packageInfoSha256": digest(info_bytes), "payloadSha256": digest(members["Payload"]),
            "packageIdentifier": PACKAGE, "payloadCorrespondence": True, "scriptsAbsent": True}


def bundle_info(identifier, executable):
    return {"CFBundleIdentifier": identifier, "CFBundleExecutable": executable,
            "CFBundleName": "MRK E2 Native Fixture", "CFBundlePackageType": "APPL",
            "CFBundleVersion": "1", "CFBundleShortVersionString": "0.1.0",
            "LSMinimumSystemVersion": "26.0", "LSUIElement": True}


class Operation:
    """One finite fixture operation. run_owned is the only process controller."""

    def __init__(self, owner, source, stager, work, environment, *, service_layout=False):
        need(type(service_layout) is bool, "layout-operation-selector")
        self.owner, self.source, self.stager = owner, source, stager
        self.work, self.environment = work, environment
        self.scratch = work / "e2-native-fixture"
        self.outputs, self.protected = Originals(), Originals()
        self.calls, self.cleanup_errors, self.scratch_origins = [], [], {}
        self.phase = "prepare"
        self.native = None
        self.native_rust_tests = None
        self.installer_worker_rust_tests = None
        self.package = None
        self.installer_entered = False
        self.installed = False
        self.native_entered = False
        self.native_returned = False
        self.btm_started, self.btm_finished = None, None
        self.btm_log = btm_record(environment["GITHUB_SHA"])
        self.artifacts = {}
        self._context_audit_refusal = None
        self.context_pure_audit_refused = False
        self.observer_entry, self.observer_digest, self.metadata = None, None, []
        self.release = None
        self.sources_closed = self.outputs_closed = self.protected_closed = False
        self.installer_context = {
            "schemaVersion": 1, "type": "mrk-e2-installer-context-observations-v1",
            "sourceCommit": environment["GITHUB_SHA"], "observerSourceSha256": None,
            "clock": "CLOCK_MONOTONIC", "deadlineNs": "0", "started": False, "completed": False,
            "enteredCases": [], "cases": [], "receiptsRetired": False,
            "outerPackageAuthority": False, "maintenanceQualified": False,
        }
        self.service_layout_originals = {}
        self.service_layout_stage_originals = {}
        self.service_layout = {
            "schemaVersion": 1, "type": "mrk-e2-service-layout-observations-v1",
            "sourceCommit": environment["GITHUB_SHA"], "observerSourceSha256": None,
            "selected": service_layout, "started": False, "completed": False,
            "clock": "CLOCK_MONOTONIC", "startedNs": "0", "deadlineNs": "0",
            "enteredCases": [], "cases": [], "pairedInstalledInputs": False,
            "physicalLayoutOnly": True, "entryResponsibilityTested": False, "registrationEntered": False,
            "productionIdentityQualified": False, "actualAppIntegrationQualified": False,
            "nativeLifecycleQualified": False,
        }

    def mkdir(self, path, mode=0o700):
        need(mode in (0o700, 0o755), "scratch-directory-requested-mode")
        parent = self.outputs.directory(path.parent)
        os.mkdir(path.name, mode, dir_fd=parent["fd"])  # Exclusive, never adopt.
        created = self.outputs.directory(path)
        before = os.fstat(created["fd"])
        need(signature(before)[:5] == created["identity"] and before.st_uid == os.getuid()
             and stat.S_ISDIR(before.st_mode) and not stat.S_IMODE(before.st_mode) & ~mode
             and signature(os.stat(path.name, dir_fd=parent["fd"], follow_symlinks=False)) == signature(before),
             "scratch-directory-original-before-mode")
        # umask077 is retained globally. Normalize only this exclusive child,
        # through its held original; never chmod an existing or installed path.
        os.fchmod(created["fd"], mode)
        after = os.fstat(created["fd"])
        need(signature(after)[:2] == signature(before)[:2]
             and signature(after)[3:5] == signature(before)[3:5]
             and stat.S_ISDIR(after.st_mode) and stat.S_IMODE(after.st_mode) == mode
             and signature(os.stat(path.name, dir_fd=parent["fd"], follow_symlinks=False)) == signature(after),
             "scratch-directory-original-after-mode")
        created["identity"] = signature(after)[:5]
        self.outputs.check_one(created)
        return created

    def publish(self, name, body, mode=0o600):
        self.outputs.publish(self.work / ("e2-native-" + name), body, mode)

    def call(self, role, argv, environment, *, cwd, timeout, limit=65536):
        self.phase = role
        self.source.book.check()
        record = {"role": role, "entered": True, "returned": False,
                  "workTimeoutSeconds": timeout, "outputLimitBytes": limit}
        self.calls.append(record)
        try:
            result = self.owner.run_owned(argv, environ=environment, cwd=cwd, timeout=timeout,
                                          capture=True, text=False, output_limit=limit)
        except BaseException as error:
            for name in ("dispatched", "contained", "cleanup_complete"):
                value = getattr(error, name, None)
                record[name] = value if type(value) is bool else None
            record["errorType"] = next((name for name in ("ProcessError", "ProcessCleanupError",
                                                        "ProcessOutcomeUnknown", "ProcessInterrupted")
                                        if type(error) is getattr(self.owner, name, None)), "other")
            raise
        completed(result, argv, limit)
        record.update(returned=True, returncode=result.returncode,
                      stdoutSha256=digest(result.stdout), stderrSha256=digest(result.stderr))
        self.source.book.check()
        # Required bounded diagnostics are private task evidence, not stdout of
        # this driver and never uploaded as an automatic public report.
        self.publish(role + ".stdout", result.stdout)
        self.publish(role + ".stderr", result.stderr)
        if role == "installer-worker-rust-tests" and result.returncode != 0:
            # Only the same completed original after source POST and private
            # capture closes. Diagnostic failure must not replace its refusal.
            try:
                diagnostic = installer_worker_diagnostic_result(result.stdout, result.stderr, self.source.rows)
                if diagnostic is not None:
                    record["installerWorkerDiagnostic"] = diagnostic
            except BaseException:
                pass
        return result

    def command(self, role, argv, environment, *, cwd, timeout, limit=65536):
        result = self.call(role, argv, environment, cwd=cwd, timeout=timeout, limit=limit)
        need(result.returncode == 0, "original-command-failed")
        return result

    def native_environment(self):
        return {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(self.scratch / "home"),
                "TMPDIR": str(self.scratch / "tmp"), "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}

    def context_command(self, role, argv, cap, *, limit=65536):
        need(role in CONTEXT_ROLES, "context-command-role")
        deadline = decimal(self.installer_context["deadlineNs"])
        timeout = context_timeout(deadline, time.clock_gettime_ns(time.CLOCK_MONOTONIC), cap)
        self.outputs.check()
        self.protected.check()
        count = len(self.calls)
        try:
            result = self.call(role, argv, dict(self.native_environment(), DEVELOPER_DIR=self.environment["DEVELOPER_DIR"]),
                               cwd=self.scratch, timeout=timeout, limit=limit)
        finally:
            # Copy entry only from this original call's record. Expired/source-
            # refused preparation is NOT an entered Installer invocation.
            if role in ("context-component-installer", "context-product-installer") and len(self.calls) > count:
                need(len(self.calls) == count + 1 and self.calls[count]["role"] == role
                     and self.calls[count]["entered"] is True, "context-original-call-entry")
                self.installer_context["enteredCases"].append("component" if role == "context-component-installer" else "product")
        # The SAME endpoint must still be live after this original returned.
        context_timeout(deadline, time.clock_gettime_ns(time.CLOCK_MONOTONIC), cap)
        self.outputs.check()
        self.protected.check()
        need(result.returncode == 0, "original-command-failed")
        return result

    def context_output(self, path):
        """The only writable transition: one exclusive empty original per case."""
        parent = self.outputs.directory(path.parent)
        fd = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent["fd"])
        entry = self.outputs.register(fd, path, "context-output")
        entry["parent"] = parent
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o600
             and before.st_uid == os.getuid() and before.st_nlink == 1 and before.st_size == 0,
             "context-empty-output")
        entry["identity"] = signature(before)[:6]
        entry["initialIdentity"] = signature(before)
        self.outputs.check_one(entry)
        return entry

    def context_read_output(self, entry, case, packages):
        """Original Installer0 precedes this read; never adopt a replacement."""
        deadline = decimal(self.installer_context["deadlineNs"])
        context_timeout(deadline, time.clock_gettime_ns(time.CLOCK_MONOTONIC), CONTEXT_SECONDS)
        self.outputs.check_one(entry)
        final = signature(os.fstat(entry["fd"]))
        need(0 < final[6] <= 4096 and final[:6] == entry["identity"], "context-output-bound")
        body = os.pread(entry["fd"], final[6] + 1, 0)
        need(len(body) == final[6] and os.pread(entry["fd"], 1, final[6]) == b""
             and signature(os.fstat(entry["fd"])) == final
             and signature(os.stat(entry["path"].name, dir_fd=entry["parent"]["fd"], follow_symlinks=False)) == final,
             "context-output-readback")
        value = context_record(body, self.environment["GITHUB_SHA"], self.installer_context["observerSourceSha256"],
                               case, deadline, entry["identity"], packages)
        self.outputs.check_one(entry)
        entry["finalIdentity"] = final  # Additional fact, not replacement custody.
        self.outputs.close(entry)
        need(entry["closed"] and not self.outputs.errors, "context-output-close-unknown")
        context_timeout(deadline, time.clock_gettime_ns(time.CLOCK_MONOTONIC), CONTEXT_SECONDS)
        self.publish("context-" + case + "-record.json", body)  # Private; not the public workflow artifact.
        value.update(recordSha256=digest(body), installerReturnedZero=True, outputOriginalClosed=True)
        return value

    def context_absence(self, case, identifier):
        parent = self.protected.directory(Path("/private/var/db/receipts"))
        for suffix in ("plist", "bom"):
            try:
                os.stat(identifier + "." + suffix, dir_fd=parent["fd"], follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise Refused("context-receipt-collision")
        result = self.context_command("context-" + case + "-receipt-census",
                                      ["/usr/sbin/pkgutil", "--volume", "/", "--pkgs-plist"],
                                      15, limit=RECEIPT_CENSUS_LIMIT)
        receipt_census_absent(result.stdout, result.stderr)
        need(identifier not in plistlib.loads(result.stdout), "context-receipt-collision")
        self.protected.check()

    def context_receipts(self, case, identifier):
        directory = Path("/private/var/db/receipts")
        parent = self.protected.directory(directory)
        rows = []
        for suffix in ("plist", "bom"):
            name = identifier + "." + suffix
            try:
                os.stat(name, dir_fd=parent["fd"], follow_symlinks=False)
            except FileNotFoundError:
                need(suffix == "bom", "context-receipt-missing")
                rows.append({"suffix": suffix, "present": False, "bytes": None, "sha256": None})
                continue
            entry, body = self.protected.file(directory / name, 65536 if suffix == "plist" else 1024 * 1024,
                                              uid=0, modes=(0o644,))
            need(entry["identity"][4] == 0 and body, "context-receipt-owner")
            rows.append({"suffix": suffix, "present": True, "bytes": len(body), "sha256": digest(body)})
        result = self.context_command("context-" + case + "-receipt-query",
                                      ["/usr/sbin/pkgutil", "--pkg-info-plist", identifier], 15)
        need(not result.stderr, "context-receipt-query")
        receipt = plistlib.loads(result.stdout)
        need(type(receipt) is dict and receipt.get("pkgid") == identifier and receipt.get("pkg-version") == "1"
             and receipt.get("volume") == "/" and receipt.get("install-location") in ("/", ""),
             "context-receipt-binding")
        self.protected.check()
        return rows  # Actual root-owned receipt originals remain held until finish().

    def context_audit(self, entry, body, *, component=None, identifier=None, expected=None):
        """Pure archive/PackageInfo/scripts DATA after the original body read.

        No acquisition, tool call or readback belongs in this refusal boundary.
        Known pure refusal finality is independent of the particular error label.
        """
        self._context_audit_refusal = None
        stage, members = "archive", None
        try:
            if component is not None:
                return context_product(body, *component)
            members = context_xar(body)
            stage = "package-info"
            context_package_info(members["PackageInfo"], identifier)
            stage = "scripts"
            archive = members["Scripts"]
            if archive[:2] == b"\x1f\x8b":
                archive = context_inflate(archive, 2 * 1024 * 1024)
            need(self.stager._cpio_members(archive, (os.getuid(), os.getgid())) == expected,
                 "context-scripts-correspondence")
            return members
        except Refused as error:
            try:
                paths = [self.scratch / "installer-context" / name for name in CONTEXT_PACKAGES]
                if (type(error) is Refused and type(body) is bytes and type(entry) is dict
                        and entry.get("path") in paths and entry.get("kind") == "file"
                        and type(entry.get("fd")) is int and entry["fd"] >= 0 and entry.get("closed") is False
                        and type(entry.get("identity")) is tuple and len(entry["identity"]) == 9
                        and entry["identity"][6] == len(body) and 28 <= len(body) <= CONTEXT_PACKAGE_LIMIT
                        and any(entry is original for original in self.outputs.entries)):
                    position = paths.index(entry["path"])
                    package, call_index = CONTEXT_PACKAGE_LABELS[position], len(self.calls) - 1
                    admitted = context_audit_call_data(package, self.phase, call_index, self.calls)
                    diagnostic_known = True
                    if admitted and error.args in (("context-xar-member-metadata",), ("context-xar-member-required",)):
                        observed = getattr(error, "_context_metadata", None)
                        diagnostic_known = (type(observed) is dict
                                            and set(observed) == {"metadata", "parsedArchiveSha256", "parsedArchiveBytes"})
                        if diagnostic_known:
                            required = error.args == ("context-xar-member-required",)
                            value = {"schemaVersion": 2 if required else 1,
                                     "type": "mrk-context-xar-required-diagnostic-v2" if required else "mrk-context-xar-metadata-diagnostic-v1",
                                     "diagnosticOnly": True, "phase": self.phase,
                                     "package": package, "packageSha256": digest(body),
                                     "packageBytes": len(body), "buildCallIndex": call_index, **observed}
                            diagnostic_known = context_metadata_diagnostic_data(value, self.phase, error.args[0], self.calls) is not None
                            if diagnostic_known:
                                self.artifacts[CONTEXT_METADATA_ARTIFACT] = value
                    elif (admitted and stage == "package-info" and len(error.args) == 1
                          and error.args[0] in CONTEXT_PACKAGE_INFO_FAILURES):
                        info_body = members["PackageInfo"]
                        observed = _context_package_info_observation(info_body, identifier)
                        value = {"schemaVersion": 1, "type": "mrk-context-package-info-diagnostic-v1",
                                 "diagnosticOnly": True, "phase": self.phase,
                                 "package": package, "packageSha256": digest(body), "packageBytes": len(body),
                                 "buildCallIndex": call_index, "packageInfoBytes": len(info_body),
                                 "packageInfoSha256": digest(info_body), "packageInfo": observed}
                        diagnostic_known = (position < 2 and identifier == CONTEXT_IDENTIFIERS[position]
                                            and context_package_info_diagnostic_data(value, self.phase, error.args[0], self.calls) is not None)
                        if diagnostic_known:
                            self.artifacts[CONTEXT_PACKAGE_INFO_ARTIFACT] = value
                    if admitted and diagnostic_known:
                        # Not a serialized/input flag. execute must catch THIS
                        # exact pure Refused; every call/close still participates.
                        self._context_audit_refusal = error
            except BaseException:
                # Diagnostic/cancellation failure never becomes cleanup proof
                # and never replaces the original parser's refusal.
                self._context_audit_refusal = None
                self.artifacts.pop(CONTEXT_METADATA_ARTIFACT, None)
                self.artifacts.pop(CONTEXT_PACKAGE_INFO_ARTIFACT, None)
            raise


    def observe_installer_context(self):
        self.phase = "context-prepare"
        need(not self.installer_context["started"], "context-single-entry")
        # Start before any new acquisition. Failure/unknown cannot retire this
        # phase's scratch, including a constructor which did not return an FD.
        self.installer_context["started"] = True
        deadline = time.clock_gettime_ns(time.CLOCK_MONOTONIC) + CONTEXT_SECONDS * 1_000_000_000
        need(0 < deadline <= MAX_RAW, "context-deadline")
        self.installer_context["deadlineNs"] = str(deadline)
        context_root = self.scratch / "installer-context"
        self.mkdir(context_root)
        original_outputs = {case: self.context_output(context_root / (case + "-record.json")) for case in CONTEXT_CASES}
        source_body = self.source.read(CONTEXT_SOURCE)
        source_sha = digest(source_body)
        self.installer_context["observerSourceSha256"] = source_sha
        package_paths = [context_root / name for name in CONTEXT_PACKAGES]
        header = ["/* Fixed original input/output nominations; not general configuration. */",
                  "#define MRK_CONTEXT_UID UINT64_C(" + str(os.getuid()) + ")",
                  "#define MRK_CONTEXT_DEADLINE_NS UINT64_C(" + str(deadline) + ")",
                  "static const struct context_case MRK_CONTEXT_CASES[2] = {"]
        for case, entry in original_outputs.items():
            parent = entry["parent"]
            self.outputs.check_one(parent)
            self.outputs.check_one(entry)
            parts = [json.dumps(value, ensure_ascii=True) for value in (case, str(parent["path"]), entry["path"].name)]
            parts.extend("UINT64_C(" + str(value) + ")" for value in (*parent["identity"], *entry["identity"][:5]))
            header.append("    {" + ",".join(parts) + "},")
        header.extend(("};", "static const char *const MRK_CONTEXT_PACKAGES[3] = {"
                       + ",".join(json.dumps(str(path), ensure_ascii=True) for path in package_paths) + "};",
                       "static const char *const MRK_CONTEXT_PACKAGE_LABELS[3] = {"
                       + ",".join(json.dumps(name) for name in CONTEXT_PACKAGE_LABELS) + "};", ""))
        header_path = context_root / "mrk-context-inputs.h"
        self.outputs.publish(header_path, "\n".join(header).encode("ascii"))
        header_entry, header_body = self.outputs.file(header_path, 16384, modes=(0o600,))
        helper = context_root / "mrk-context-observer"
        argv = ["/usr/bin/xcrun", "--sdk", "macosx", "clang", "-x", "c", "-std=c11",
                "-Wall", "-Wextra", "-Werror", "-O2", "-arch", "arm64", "-mmacosx-version-min=26.0",
                '-DMRK_CONTEXT_SOURCE_COMMIT="' + self.environment["GITHUB_SHA"] + '"',
                '-DMRK_CONTEXT_OBSERVER_SHA256="' + source_sha + '"', "-I", str(context_root),
                str(CHECKOUT / CONTEXT_SOURCE), "-o", str(helper)]
        self.context_command("context-helper-build", argv, 30)
        helper_entry, helper_body = self.outputs.file(helper, 1024 * 1024, modes=(0o700, 0o755))
        self.stager.entry_macho(helper_body)
        need(self.outputs.read(header_entry) == header_body and self.source.read(CONTEXT_SOURCE) == source_body,
             "context-helper-source-changed")
        self.artifacts["installer-context-observer"] = {
            "compilerSha256": digest(helper_body), "compilerBytes": len(helper_body), "sourceSha256": source_sha,
            "headerSha256": digest(header_body), "noPayload": True, "observationOnly": True,
        }
        components, package_entries = [], []
        for index, case in enumerate(CONTEXT_CASES):
            scripts = context_root / (case + "-scripts")
            self.mkdir(scripts, 0o755)
            script = ('#!/bin/sh\nexec "${0%/*}/mrk-context-observer" ' + case
                      + ' "${PACKAGE_PATH+x}" "${PACKAGE_PATH-}" "$@"\n').encode("ascii")
            expected = {"mrk-context-observer": (helper_body, 0o555), "postinstall": (script, 0o555)}
            script_originals = []
            for name, (body, mode) in expected.items():
                self.outputs.publish(scripts / name, body, mode)
                entry, readback = self.outputs.file(scripts / name, 1024 * 1024, modes=(0o555,))
                need(readback == body, "context-scripts-original")
                script_originals.append((entry, body))
            self.context_command("context-component-build" if index == 0 else "context-product-component-build",
                                 ["/usr/bin/pkgbuild", "--nopayload", "--scripts", str(scripts),
                                  "--identifier", CONTEXT_IDENTIFIERS[index], "--version", "1", "--install-location", "/",
                                  "--ownership", "recommended", "--compression", "legacy", str(package_paths[index])], 30)
            self.phase = "context-" + case + "-audit"
            entry, body = self.outputs.file(package_paths[index], CONTEXT_PACKAGE_LIMIT, modes=(0o600, 0o644))
            members = self.context_audit(entry, body, identifier=CONTEXT_IDENTIFIERS[index], expected=expected)
            if "Bom" in members:
                self.phase = "context-lsbom-original"
                tool_entry, tool_body = self.outputs.file(Path("/usr/bin/lsbom"), 4 * 1024 * 1024, uid=0, modes=(0o555, 0o755))
                self.artifacts["installer-context-lsbom"] = {"sha256": digest(tool_body), "bytes": len(tool_body)}
                bom_path = context_root / (case + "-empty.bom")
                self.outputs.publish(bom_path, members["Bom"])
                bom_entry, bom_body = self.outputs.file(bom_path, 1024 * 1024, modes=(0o600,))
                listing = self.context_command("context-" + case + "-empty-bom", ["/usr/bin/lsbom", "-s", str(bom_path)], 10)
                need(not listing.stderr and listing.stdout in (b"", b".\n")
                     and self.outputs.read(bom_entry) == bom_body == members["Bom"]
                     and self.outputs.read(tool_entry) == tool_body, "context-nonempty-bom")
            need(all(self.outputs.read(entry) == original for entry, original in script_originals)
                 and sorted(os.listdir(self.outputs.directories[scripts]["fd"])) == sorted(expected)
                 and self.outputs.read(helper_entry) == helper_body, "context-scripts-changed")
            components.append((body, members))
            package_entries.append(entry)
        distribution = context_root / "Distribution"
        self.outputs.publish(distribution, context_distribution())
        distribution_entry, distribution_body = self.outputs.file(distribution, 65536, modes=(0o600,))
        self.phase = "context-productbuild-original"
        product_tool, product_tool_body = self.outputs.file(Path("/usr/bin/productbuild"), 4 * 1024 * 1024,
                                                           uid=0, modes=(0o555, 0o755))
        self.artifacts["installer-context-productbuild"] = {"sha256": digest(product_tool_body), "bytes": len(product_tool_body)}
        self.context_command("context-product-build", ["/usr/bin/productbuild", "--distribution", str(distribution),
                             "--package-path", str(context_root), str(package_paths[2])], 30)
        self.phase = "context-product-audit"
        entry, body = self.outputs.file(package_paths[2], CONTEXT_PACKAGE_LIMIT, modes=(0o600, 0o644))
        self.context_audit(entry, body, component=components[1])
        package_entries.append(entry)
        need(self.outputs.read(distribution_entry) == distribution_body == context_distribution()
             and self.outputs.read(product_tool) == product_tool_body,
             "context-distribution-changed")
        packages = {label: {"original": list(entry["identity"]), "sha256": digest(self.outputs.read(entry))}
                    for label, entry in zip(CONTEXT_PACKAGE_LABELS, package_entries)}
        self.artifacts["installer-context-packages"] = {label: {"sha256": row["sha256"], "bytes": row["original"][6]}
                                                        for label, row in packages.items()}
        for index, case in enumerate(CONTEXT_CASES):
            self.context_absence(case, CONTEXT_IDENTIFIERS[index])
            selected = package_entries[0 if index == 0 else 2]
            self.outputs.check()
            need(signature(os.fstat(original_outputs[case]["fd"])) == original_outputs[case]["initialIdentity"],
                 "context-output-not-empty-original")
            self.context_command("context-" + case + "-installer",
                                 ["/usr/bin/sudo", "-n", "--", "/usr/sbin/installer", "-pkg", str(selected["path"]),
                                  "-target", "/"], 60)
            self.phase = "context-" + case + "-record"
            observed = self.context_read_output(original_outputs[case], case, packages)
            observed["receiptOriginals"] = self.context_receipts(case, CONTEXT_IDENTIFIERS[index])
            need(all(self.outputs.read(entry) == components[n][0] for n, entry in enumerate(package_entries[:2]))
                 and digest(self.outputs.read(package_entries[2])) == packages[CONTEXT_PACKAGE_LABELS[2]]["sha256"],
                 "context-packages-changed")
            self.installer_context["cases"].append(observed)
        context_timeout(deadline, time.clock_gettime_ns(time.CLOCK_MONOTONIC), CONTEXT_SECONDS)
        self.outputs.check()
        self.protected.check()
        self.installer_context["completed"] = True
        installer_context_data(self.installer_context, self.environment["GITHUB_SHA"])

    def compiler_environment(self, target):
        home = Path("/Users/runner")
        need(self.environment.get("HOME") == str(home)
             and self.environment.get("RUSTUP_HOME", str(home / ".rustup")) == str(home / ".rustup")
             and self.environment.get("CARGO_HOME", str(home / ".cargo")) == str(home / ".cargo"),
             "prepared-tool-home-route")
        cargo_home, rustup_home = home / ".cargo", home / ".rustup"
        # The workflow admits these preinstalled direct tools by actual version
        # outputs. No auto-install, inherited flags/wrappers, credentials, or online fetch.
        for parent in (cargo_home, *CHECKOUT.parents, CHECKOUT, CHECKOUT / "desktop",
                       CHECKOUT / NATIVE, CHECKOUT / HELPER, CHECKOUT / INSTALLER):
            directory = parent if parent == cargo_home else parent / ".cargo"
            for name in ("config", "config.toml", "credentials", "credentials.toml"):
                try:
                    os.stat(directory / name, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise Refused("ambient-cargo-configuration")
        bin_directory = rustup_home / "toolchains" / "stable-aarch64-apple-darwin" / "bin"
        self.outputs.directory(bin_directory)
        cargo = bin_directory / "cargo"
        rustc = bin_directory / "rustc"
        result = dict(self.native_environment(), PATH=str(bin_directory) + ":/usr/bin:/bin:/usr/sbin:/sbin",
                      CARGO_HOME=str(cargo_home), RUSTUP_HOME=str(rustup_home),
                      RUSTUP_TOOLCHAIN=TOOLCHAIN, RUSTUP_AUTO_INSTALL="0", CARGO_INCREMENTAL="0",
                      CARGO_NET_OFFLINE="true", CARGO_TARGET_DIR=str(target), RUSTC=str(rustc),
                      DEVELOPER_DIR=self.environment["DEVELOPER_DIR"], MACOSX_DEPLOYMENT_TARGET="26.0",
                      MRK_MACOS_INSTALL_SOURCE_COMMIT=self.environment["GITHUB_SHA"],
                      MRK_IMAGE_RELEASE_ID=self.release)
        return str(cargo), result

    def begin(self):
        self.scratch_identity = self.mkdir(self.scratch)["identity"]
        for name in ("home", "tmp", "cwd"):
            self.mkdir(self.scratch / name)
        self.mkdir(self.scratch / "payload", 0o755)
        self.outputs.directory(self.work)
        value = self.stager.build_release_data(self.source.read("desktop/macos-installed-inputs/build-release.json"))
        need(type(value["release"]) is str and len(value["release"]) < 64, "image-release-size")
        self.release = value["release"]
        need(plistlib.loads(self.source.read("desktop/packaging/macos-empty-entitlements.plist")) == {},
             "empty-fixture-entitlements")
        # These are actual SOURCE dependencies, not implemented by this owner.
        # Their absence refuses before any compiler or installer invocation.
        for relative in (NATIVE + "/examples/e2_maintenance_client.rs",
                         NATIVE + "/src/e2_native_fixture.rs",
                         NATIVE + "/src/e2_native_fixture_identity.m",
                         NATIVE + "/src/e2_native_fixture_fixed.h"):
            self.source.read(relative)

    def retire_target(self, path):
        """Retire only this operation's fresh output after its original call."""
        original = self.scratch_origins[path]
        need(all(record["returned"] for record in self.calls) and not self.outputs.errors,
             "target-owner-finality")
        # Consume descendants before unlink; no ambiguous close may authorize it.
        for entry in reversed(self.outputs.entries):
            if entry["path"] == path or path in entry["path"].parents:
                self.outputs.close(entry)
        need(not self.outputs.errors and all(entry["closed"] for entry in self.outputs.entries
                                             if entry["path"] == path or path in entry["path"].parents),
             "target-original-closes")
        parent = self.outputs.directory(path.parent)
        need(signature(os.stat(path.name, dir_fd=parent["fd"], follow_symlinks=False))[:5] == original
             and shutil.rmtree.avoids_symlink_attacks, "target-original-before-retirement")
        shutil.rmtree(path.name, dir_fd=parent["fd"])
        try:
            os.stat(path.name, dir_fd=parent["fd"], follow_symlinks=False)
        except FileNotFoundError:
            self.scratch_origins.pop(path)
        else:
            raise Refused("target-retirement-incomplete")

    def copy_image(self, role, binary, target):
        entry, body = self.outputs.file(binary, IMAGE_LIMIT, modes=(0o700, 0o755), alias=True)
        if entry["identity"][5] == 2:
            if role == "resident":
                names = [binary.parent / "deps" / binary.name]
            else:
                parent = self.outputs.directory(binary.parent)
                siblings = os.listdir(parent["fd"])
                need(len(siblings) <= 8192, "compiler-alias-roster")
                names = [binary.parent / name for name in siblings
                         if re.fullmatch(r"libe2_maintenance_client-[0-9a-f]{16}\.dylib", name)]
            aliases = []
            for name in names:
                info = os.stat(name, follow_symlinks=False)
                if (info.st_dev, info.st_ino) == entry["identity"][:2]:
                    alias, alias_body = self.outputs.file(name, IMAGE_LIMIT, modes=(0o700, 0o755), alias=True)
                    need(alias["identity"] == entry["identity"] and alias_body == body, "compiler-alias-original")
                    aliases.append(alias)
            need(len(aliases) == 1, "compiler-one-alias")
        fixture_image_macho(body, role)
        self.write_payload(IMAGES[role], body, 0o755)
        self.artifacts[role] = {"compilerSha256": digest(body), "compilerBytes": len(body),
                                "cargoTarget": str(binary.relative_to(target)), "graphSeparated": True}
        need(self.outputs.read(entry) == body, "compiler-copy-changed")

    def build_installer_worker_tests(self):
        """One real ordinary Mac binary libtest; never a private writer invocation."""
        target = self.scratch / "installer-worker-target"
        entry = self.mkdir(target)
        self.scratch_origins[target] = entry["identity"]
        try:
            cargo, environment = self.compiler_environment(target)
            argv = [cargo, "test", "--manifest-path", str(CHECKOUT / INSTALLER / "Cargo.toml"),
                    "--locked", "--offline", "--jobs", "1", "--target", TARGET,
                    "--no-default-features", "--features", "macos-installed-installer",
                    "--bin", "mrk-macos-install", "--message-format=short", "--color", "never",
                    "--", "--exact", "--test-threads=1", "--format", "pretty", "--color", "never",
                    *INSTALLER_WORKER_RUST_TESTS]
            result = self.command("installer-worker-rust-tests", argv, environment, cwd=CHECKOUT,
                                  timeout=480, limit=4 * 1024 * 1024)
            self.installer_worker_rust_tests = installer_worker_rust_tests_result(result.stdout)
        finally:
            if all(call["returned"] for call in self.calls):
                self.retire_target(target)

    def build_images(self):
        for role in ("client", "resident"):
            target = self.scratch / (role + "-target")
            entry = self.mkdir(target)
            self.scratch_origins[target] = entry["identity"]
            cargo, environment = self.compiler_environment(target)
            directory = NATIVE if role == "client" else HELPER
            common = ["--manifest-path", str(CHECKOUT / directory / "Cargo.toml"),
                      "--locked", "--offline", "--release", "--jobs", "1", "--target", TARGET,
                      "--no-default-features", "--features",
                      "desktop-image,e2-native-fixture" if role == "client" else "e2-native-fixture"]
            argv = [cargo, "rustc" if role == "client" else "build", *common]
            argv += (["--example", "e2_maintenance_client"] if role == "client" else ["--lib"])
            argv += ["--message-format=json-render-diagnostics"]
            if role == "client":
                argv += ["--", "-C", "link-arg=-Wl,-install_name,@rpath/libmrk_e2_native_client.dylib",
                         "-C", "link-arg=-mmacosx-version-min=26.0"]
            try:
                if role == "client":
                    tests = [cargo, "test", *common, "--lib", "--message-format=short", "--color", "never",
                             "--", "--exact", "--test-threads=1", "--format", "pretty", "--color", "never",
                             *NATIVE_RUST_TESTS]
                    result = self.command("native-rust-tests", tests, environment, cwd=CHECKOUT,
                                          timeout=480, limit=4 * 1024 * 1024)
                    self.native_rust_tests = native_rust_tests_result(result.stdout)
                result = self.command(role + "-build", argv, environment, cwd=CHECKOUT,
                                      timeout=480, limit=4 * 1024 * 1024)
                binary = cargo_artifact(result.stdout, role, CHECKOUT, target)
                self.copy_image(role, binary, target)
                self.artifacts[role]["cargoMessagesSha256"] = digest(result.stdout)
            finally:
                if all(call["returned"] for call in self.calls):
                    self.retire_target(target)

    def write_payload(self, relative, body, mode):
        path = self.scratch / "payload" / relative
        relative_parent = path.parent.relative_to(self.scratch / "payload")
        current = self.scratch / "payload"
        for name in relative_parent.parts:
            current /= name
            if current not in self.outputs.directories:
                self.mkdir(current, 0o755)
        self.outputs.publish(path, body, mode)

    def compile_facades(self):
        target = self.scratch / "facade-target"
        entry = self.mkdir(target)
        self.scratch_origins[target] = entry["identity"]
        source_directory = CHECKOUT / "desktop/native/macos-installed-entry"
        try:
            for role, filename, destination in (("entry", "entry.c", ENTRY),
                                                ("client-facade", "desktop_facade.c", CLIENT),
                                                ("resident-facade", "resident_facade.c", RESIDENT)):
                self.phase = role + "-build"
                output = target / Path(destination).name
                argv = ["/usr/bin/xcrun", "--sdk", "macosx", "clang", "-x", "c", "-std=c11",
                        "-Wall", "-Wextra", "-Werror", "-O2", "-arch", "arm64", "-mmacosx-version-min=26.0",
                        "-DMRK_ENTRY_METADATA_ONLY=1", "-DMRK_E2_NATIVE_FIXTURE=1",
                        '-DMRK_IMAGE_SOURCE_COMMIT="' + self.environment["GITHUB_SHA"] + '"',
                        '-DMRK_IMAGE_RELEASE_ID="' + self.release + '"', str(source_directory / filename),
                        str(source_directory / "gate.c"), str(CHECKOUT / NATIVE / "src/native.m"),
                        "-o", str(output)]
                self.command(role + "-build", argv, dict(self.native_environment(),
                             DEVELOPER_DIR=self.environment["DEVELOPER_DIR"]), cwd=CHECKOUT, timeout=30)
                entry, body = self.outputs.file(output, 1024 * 1024, modes=(0o700, 0o755))
                self.stager.entry_macho(body)
                self.write_payload(destination, body, 0o755)
                self.artifacts[role] = {"compilerSha256": digest(body), "compilerBytes": len(body)}
                need(self.outputs.read(entry) == body, "facade-copy-changed")
        finally:
            if all(call["returned"] for call in self.calls):
                self.retire_target(target)

    def compile_service_layout(self):
        need(self.service_layout["selected"] and not self.service_layout["started"], "layout-build-route")
        source_body = self.source.read(LAYOUT_SOURCE)
        observer_sha = digest(source_body)
        self.service_layout["observerSourceSha256"] = observer_sha
        target = self.scratch / "service-layout-target"
        entry = self.mkdir(target)
        self.scratch_origins[target] = entry["identity"]
        output = target / "mrk-e2-status-observer"
        try:
            argv = ["/usr/bin/xcrun", "--sdk", "macosx", "clang", "-x", "objective-c", "-std=c11",
                    "-Wall", "-Wextra", "-Werror", "-O2", "-fno-objc-arc", "-fobjc-exceptions",
                    "-arch", "arm64", "-mmacosx-version-min=26.0", "-DMRK_E2_SERVICE_LAYOUT_DIAGNOSTIC=1",
                    '-DMRK_IMAGE_SOURCE_COMMIT="' + self.environment["GITHUB_SHA"] + '"',
                    '-DMRK_OBSERVER_SOURCE_SHA256="' + observer_sha + '"',
                    str(CHECKOUT / LAYOUT_SOURCE), "-framework", "Foundation", "-framework", "ServiceManagement",
                    "-framework", "CoreFoundation", "-lobjc", "-o", str(output)]
            self.command("service-layout-build", argv, dict(self.native_environment(),
                         DEVELOPER_DIR=self.environment["DEVELOPER_DIR"]), cwd=CHECKOUT, timeout=30)
            original, body = self.outputs.file(output, 1024 * 1024, modes=(0o700, 0o755))
            service_observer_macho(body, self.stager)
            for root in LAYOUT_CLIENTS:
                for suffix in (LAYOUT_EXECUTABLE, LAYOUT_TARGET):
                    self.write_payload(root + suffix, body, 0o755)
                self.write_payload(root + "/Contents/Info.plist",
                                   plistlib.dumps(bundle_info(LAYOUT_ID + ".client", "mrk-e2-status-observer"),
                                                  sort_keys=True), 0o444)
                self.write_payload(root + LAYOUT_PLIST, service_layout_plist(), 0o444)
            self.write_payload(LAYOUT_HOST + "/Contents/MacOS/mrk-e2-status-host", body, 0o755)
            self.write_payload(LAYOUT_HOST + "/Contents/Info.plist",
                               plistlib.dumps(bundle_info(LAYOUT_ID + ".host", "mrk-e2-status-host"),
                                              sort_keys=True), 0o444)
            need(self.outputs.read(original) == body and self.source.read(LAYOUT_SOURCE) == source_body,
                 "layout-compiler-source-changed")
            self.artifacts["service-status-observer"] = {
                "compilerSha256": digest(body), "compilerBytes": len(body),
                "observerSourceSha256": observer_sha, "readOnly": True,
            }
        finally:
            if all(call["returned"] for call in self.calls):
                self.retire_target(target)

    def sign(self):
        self.phase = "bundle-staging"
        for relative, value in ((APP + "/Contents/Info.plist", bundle_info(IDENTIFIER, "mrk-e2-native-entry")),
                                (CONTENTS + "Info.plist", bundle_info(IDENTIFIER + ".client", "mrk-e2-native-client")),
                                (PLIST, {"Label": SERVICE, "BundleProgram": "Contents/Helpers/mrk-e2-native-resident",
                                         "MachServices": {SERVICE: True}})):
            self.write_payload(relative, plistlib.dumps(value, sort_keys=True), 0o444)
        self.write_payload(GATE, self.stager.MAINTENANCE_GATE_BYTES, 0o444)
        code = ((IMAGES["client"], IDENTIFIER + ".client.image"),
                (IMAGES["resident"], SERVICE + ".image"), (RESIDENT, SERVICE),
                (NESTED, IDENTIFIER + ".client"), (APP, IDENTIFIER))
        if self.service_layout["selected"]:
            code += service_layout_code()
        payload = self.scratch / "payload"
        # codesign also inherits the private umask. Supply only its two exact
        # fresh signature directories ourselves instead of normalizing a tree.
        signature_dirs = (APP + "/Contents/_CodeSignature", CONTENTS + "_CodeSignature")
        if self.service_layout["selected"]:
            signature_dirs += tuple(root + "/Contents/_CodeSignature" for root in (*LAYOUT_CLIENTS, LAYOUT_HOST))
        for relative in signature_dirs:
            self.mkdir(payload / relative, 0o755)
        for index, (relative, identifier) in enumerate(code):
            path = payload / relative
            self.command("sign-" + str(index), ["/usr/bin/codesign", "--force", "--sign", "-",
                         "--identifier", identifier, "--options", "runtime", "--entitlements",
                         str(CHECKOUT / "desktop/packaging/macos-empty-entitlements.plist"),
                         "--timestamp=none", str(path)], self.native_environment(), cwd=self.scratch, timeout=30)
        for index, (relative, _identifier) in enumerate(code):
            self.command("verify-sign-" + str(index), ["/usr/bin/codesign", "--verify", "--strict",
                         "--all-architectures", "--deep", str(payload / relative)],
                         self.native_environment(), cwd=self.scratch, timeout=30)
        # Seal only our freshly authored/signed files, never a caller's source.
        self.stage_roster = self.payload_roster(payload, installed=False, seal=True)
        for role in ("client", "resident"):
            self.artifacts[role].update(signedSha256=self.stage_roster[IMAGES[role]]["sha256"],
                                        signedBytes=self.stage_roster[IMAGES[role]]["bytes"])
        self.publish("stage-roster.json", canonical(self.stage_roster))

    def payload_roster(self, root, *, installed, seal=False):
        """Exact fixture leaves only, bounded and held; no recursive adoption."""
        need(not (installed and seal), "protected-write-forbidden")
        book = self.protected if installed else self.outputs
        expected = {ENTRY, CLIENT, RESIDENT, IMAGES["client"], IMAGES["resident"], PLIST, GATE,
                    APP + "/Contents/Info.plist", CONTENTS + "Info.plist",
                    APP + "/Contents/_CodeSignature/CodeResources", CONTENTS + "_CodeSignature/CodeResources"}
        layout_files = service_layout_files() if self.service_layout["selected"] else set()
        layout_executables = ({root + suffix for root in LAYOUT_CLIENTS for suffix in (LAYOUT_EXECUTABLE, LAYOUT_TARGET)}
                              | {LAYOUT_HOST + "/Contents/MacOS/mrk-e2-status-host"}) if layout_files else set()
        expected.update(layout_files)
        expected_dirs = {""}
        for name in expected:
            expected_dirs.update("/".join(name.split("/")[:index]) for index in range(1, len(name.split("/"))))
        found, total = {}, 0
        for relative in sorted(expected_dirs, key=lambda value: (value.count("/"), value)):
            directory = book.directory(root / relative)
            info = os.fstat(directory["fd"])
            need(info.st_uid == (0 if installed else os.getuid())
                 and (not installed or info.st_gid == 0)
                 and stat.S_IMODE(info.st_mode) == 0o755,
                 "fixture-directory-policy")
            self.stager.no_xattrs(directory["fd"])
            children = set(os.listdir(directory["fd"]))
            allowed = {Path(name).name for name in expected | expected_dirs
                       if name and str(Path(name).parent) == (relative or ".")}
            need(children == allowed, "fixture-exact-roster")
        for relative in sorted(expected):
            path = root / relative
            executable = relative in {ENTRY, CLIENT, RESIDENT, *IMAGES.values()} | layout_executables
            if seal:
                parent = book.directory(path.parent)
                fd = os.open(path.name, READ_FLAGS, dir_fd=parent["fd"])
                entry = book.register(fd, path, "seal")
                entry["parent"] = parent
                info = os.fstat(fd)
                need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1,
                     "fresh-sealing-original")
                os.fchmod(fd, 0o555 if executable else 0o444)
                os.fsync(fd)
                entry["identity"] = signature(os.fstat(fd))
                book.check_one(entry)
                book.close(entry)
                need(entry["closed"], "sealing-close-unknown")
            layout_originals = self.service_layout_originals if installed else self.service_layout_stage_originals
            if relative in layout_files and relative in layout_originals and not seal:
                entry = layout_originals[relative]
                body = book.read(entry)  # Same held original, including named/full9 POST.
            else:
                entry, body = book.file(path, IMAGE_LIMIT, uid=0 if installed else None,
                                        modes=(0o555,) if executable else (0o444,))
            need(not installed or entry["identity"][4] == 0, "installed-group")
            self.stager.no_xattrs(entry["fd"])
            total += len(body)
            need(total <= 3 * IMAGE_LIMIT, "fixture-total-bytes")
            if relative in IMAGES.values():
                fixture_image_macho(body, next(role for role, name in IMAGES.items() if name == relative))
            elif relative in layout_executables:
                service_observer_macho(body, self.stager)
            elif executable:
                self.stager.entry_macho(body)
            elif relative == GATE:
                need(body == self.stager.MAINTENANCE_GATE_BYTES, "fixture-gate-bytes")
            found[relative] = {"bytes": len(body), "sha256": digest(body),
                               "mode": "100555" if executable else "100444"}
            if relative in layout_files:
                if relative in (root + LAYOUT_PLIST for root in LAYOUT_CLIENTS):
                    need(0 < len(body) <= 4096 and body == service_layout_plist(), "layout-plist-original")
                # Reuse the finite 13 originals, both in package/signature POST
                # and in observation PRE/POST. Do not accumulate duplicate FDs.
                layout_originals[relative] = entry
        if layout_files:
            service_layout_paired(found)
        book.check()
        return found



    def compile_metadata_observer(self):
        """One fixed C front end; reuse native.m's unchanged filesec/ACL body."""
        front = self.scratch / "protected-metadata-observer.c"
        output = self.scratch / "protected-metadata-observer"
        body = METADATA_OBSERVER_C.encode("ascii")
        self.outputs.publish(front, body)
        front_entry, original = self.outputs.file(front, 16384, modes=(0o600,))
        need(original == body, "observer-source-original")
        argv = ["/usr/bin/xcrun", "--sdk", "macosx", "clang", "-x", "c", "-std=c11",
                "-Wall", "-Wextra", "-Werror", "-O2", "-arch", "arm64", "-mmacosx-version-min=26.0",
                "-DMRK_ENTRY_METADATA_ONLY=1",
                '-DMRK_IMAGE_SOURCE_COMMIT="' + self.environment["GITHUB_SHA"] + '"',
                str(front), str(CHECKOUT / NATIVE / "src/native.m"), "-o", str(output)]
        self.command("metadata-observer-build", argv, dict(self.native_environment(),
                     DEVELOPER_DIR=self.environment["DEVELOPER_DIR"]), cwd=self.scratch, timeout=30)
        self.observer_entry, compiled = self.outputs.file(output, 1024 * 1024, modes=(0o700, 0o755))
        self.stager.entry_macho(compiled)
        need(self.outputs.read(front_entry) == body, "observer-source-changed")
        self.observer_digest = digest(compiled)
        self.artifacts["protected-metadata-observer"] = {
            "compilerSha256": self.observer_digest, "compilerBytes": len(compiled),
            "frontSourceSha256": digest(body),
            "nativeSourceSha256": digest(self.source.read(NATIVE + "/src/native.m")),
            "sharedAclImplementation": True, "readOnly": True,
        }

    def metadata_snapshots(self, expected_present):
        snapshots = []
        for index, path in enumerate(METADATA_PATHS):
            parent = None if index == 0 else self.protected.directory(path.parent)
            try:
                named = os.stat(str(path) if parent is None else path.name,
                                dir_fd=None if parent is None else parent["fd"], follow_symlinks=False)
            except FileNotFoundError:
                need(index == 7 and not expected_present, "metadata-required-directory-absent")
                snapshots.append(None)
                continue
            need(index != 7 or expected_present, "metadata-fixture-collision")
            entry = self.protected.directory(path)
            actual = os.fstat(entry["fd"])
            need(signature(actual) == signature(named) and actual.st_uid == 0
                 and stat.S_ISDIR(actual.st_mode) and not actual.st_mode & 0o7022
                 and (index != 7 or actual.st_gid == 0 and stat.S_IMODE(actual.st_mode) == 0o755),
                 "metadata-original-policy")
            self.protected.check_one(entry)
            snapshots.append(signature(actual))
        return snapshots

    def observe_metadata(self, phase, *, present):
        need(self.observer_entry is not None
             and digest(self.outputs.read(self.observer_entry)) == self.observer_digest,
             "metadata-observer-original")
        before = self.metadata_snapshots(present)
        result = self.command("metadata-" + phase, [str(self.observer_entry["path"])], {},
                              cwd=self.scratch / "cwd", timeout=15, limit=32768)
        after = self.metadata_snapshots(present)
        need(before == after and not result.stderr
             and digest(self.outputs.read(self.observer_entry)) == self.observer_digest,
             "metadata-original-correspondence")
        observed = metadata_result(result.stdout, result.returncode, self.environment["GITHUB_SHA"],
                                   present, before)
        self.metadata.append({"phase": phase, "sha256": digest(result.stdout), "observation": observed})

    def absence(self, role):
        fixture_domain(self.source.binding)
        self.observe_metadata(role, present=False)
        parent = self.protected.directory(ROOT.parent)
        try:
            os.stat(ROOT.name, dir_fd=parent["fd"], follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise Refused("fixture-root-collision")
        receipts = self.protected.directory(Path("/private/var/db/receipts"))
        for name in (PACKAGE + ".plist", PACKAGE + ".bom"):
            try:
                os.stat(name, dir_fd=receipts["fd"], follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise Refused("fixture-receipt-collision")
        # A filtered no-match can return nonzero, which is not proof of absence.
        # Require one successful complete root-volume census; never accept a
        # failed lookup, truncate output, or normalize unrelated identifiers.
        result = self.command(role + "-receipt-query",
                              ["/usr/sbin/pkgutil", "--volume", "/", "--pkgs-plist"],
                              self.native_environment(), cwd=self.scratch, timeout=15,
                              limit=RECEIPT_CENSUS_LIMIT)
        receipt_census_absent(result.stdout, result.stderr)
        self.protected.check()

    def package_fixture(self):
        self.phase = "package-components"
        payload = self.scratch / "payload"
        analysis = self.scratch / "components-original.plist"
        self.command("package-analyze", ["/usr/bin/pkgbuild", "--analyze", "--root", str(payload), str(analysis)],
                     self.native_environment(), cwd=self.scratch, timeout=30)
        original, data = self.outputs.file(analysis, 65536, modes=(0o600, 0o644))
        components = plistlib.loads(data)
        need(type(components) is list and 0 < len(components) <= 4, "package-components")
        bundle_names = {APP, NESTED}
        if self.service_layout["selected"]:
            bundle_names.update((*LAYOUT_CLIENTS, LAYOUT_HOST))
        pending, seen = [(row, 0) for row in components], set()
        while pending:
            row, depth = pending.pop()
            need(type(row) is dict and depth <= 2 and len(seen) <= len(bundle_names), "package-component-shape")
            path = row.get("RootRelativeBundlePath")
            need(path in bundle_names and path not in seen and not any("Script" in key for key in row),
                 "package-component-path")
            seen.add(path)
            row.update(BundleIsRelocatable=False, BundleHasStrictIdentifier=True, BundleIsVersionChecked=False)
            children = row.get("ChildBundles", [])
            need(type(children) is list and len(children) <= 1, "package-component-children")
            pending.extend((child, depth + 1) for child in children)
        need(APP in seen and self.outputs.read(original) == data, "package-component-root")
        need(not self.service_layout["selected"] or seen == bundle_names, "layout-package-components")
        component_path = self.scratch / "components.plist"
        self.outputs.publish(component_path, plistlib.dumps(components, sort_keys=True))
        output = self.scratch / "MRK-E2-NativeFixture.pkg"
        self.command("package-build", ["/usr/bin/pkgbuild", "--root", str(payload),
                     "--identifier", PACKAGE, "--version", "1", "--install-location", str(ROOT),
                     "--ownership", "recommended", "--component-plist", str(component_path),
                     "--compression", "legacy", str(output)], self.native_environment(), cwd=self.scratch, timeout=90)
        self.package_entry, body = self.outputs.file(output, 4 * IMAGE_LIMIT, modes=(0o600, 0o644))
        self.package = fixture_package(body, self.stage_roster, service_layout=self.service_layout["selected"])
        need(self.payload_roster(payload, installed=False) == self.stage_roster, "package-inputs-changed")
        self.publish("package-binding.json", canonical(self.package))

    def install_fixture(self):
        # Applicability depends on the independently reviewed fresh single-job
        # administrative domain, not on flat Installer atomic no-replace.
        self.absence("before-install")
        need(digest(self.outputs.read(self.package_entry)) == self.package["packageSha256"],
             "package-original-changed")
        self.source.book.check()
        self.outputs.check()
        self.protected.check()
        self.installer_entered = True
        self.command("standard-installer", ["/usr/bin/sudo", "-n", "--", "/usr/sbin/installer",
                     "-pkg", str(self.package_entry["path"]), "-target", "/"],
                     self.native_environment(), cwd=self.scratch, timeout=120)
        self.installed = True
        actual = self.payload_roster(ROOT, installed=True)
        need(actual == self.stage_roster, "installed-payload-correspondence")
        self.observe_metadata("installed", present=True)
        receipt_dir = Path("/private/var/db/receipts")
        self.receipt_originals = []
        for name, limit in ((PACKAGE + ".plist", 65536), (PACKAGE + ".bom", 1024 * 1024)):
            entry, body = self.protected.file(receipt_dir / name, limit, uid=0, modes=(0o644,))
            need(entry["identity"][4] == 0 and body, "installed-receipt-owner")
            self.receipt_originals.append({"name": name, "bytes": len(body), "sha256": digest(body)})
        result = self.command("installed-receipt", ["/usr/sbin/pkgutil", "--pkg-info-plist", PACKAGE],
                              self.native_environment(), cwd=self.scratch, timeout=15, limit=65536)
        need(not result.stderr, "installed-receipt-query")
        receipt = plistlib.loads(result.stdout)
        need(type(receipt) is dict and receipt.get("pkgid") == PACKAGE and receipt.get("pkg-version") == "1"
             and receipt.get("volume") == "/" and receipt.get("install-location") in (str(ROOT), str(ROOT)[1:]),
             "installed-receipt-binding")
        code = (IMAGES["client"], IMAGES["resident"], RESIDENT, NESTED, APP)
        if self.service_layout["selected"]:
            code += tuple(relative for relative, _identifier in service_layout_code())
        for index, relative in enumerate(code):
            self.command("installed-signature-" + str(index),
                         ["/usr/bin/codesign", "--verify", "--strict", "--all-architectures", "--deep", str(ROOT / relative)],
                         self.native_environment(), cwd=self.scratch, timeout=30)
        need(self.payload_roster(ROOT, installed=True) == actual, "installed-originals-changed")

    def service_layout_inputs(self):
        need(set(self.service_layout_originals) == service_layout_files(), "layout-installed-originals")
        self.source.book.check()
        self.outputs.check()
        self.protected.check()
        for relative, original in self.service_layout_originals.items():
            body = self.protected.read(original)
            row = self.stage_roster[relative]
            need(len(body) == row["bytes"] and digest(body) == row["sha256"], "layout-installed-bytes")
        service_layout_paired(self.stage_roster)

    def observe_service_layout(self):
        value = self.service_layout
        need(value["selected"] and not value["started"] and self.installed
             and self.package is not None and self.native is None and not self.native_entered
             and not self.installer_context["started"]
             and all(call["returned"] and call["returncode"] == 0 for call in self.calls),
             "layout-admission-prerequisites")
        self.service_layout_inputs()
        origin = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        deadline = origin + LAYOUT_SECONDS * 1_000_000_000
        need(0 < origin < deadline <= MAX_RAW, "layout-phase-clock")
        value.update(started=True, startedNs=str(origin), deadlineNs=str(deadline), pairedInstalledInputs=True)
        cwd = self.outputs.directory(self.scratch / "cwd")
        for index, case in enumerate(LAYOUT_CASES):
            self.service_layout_inputs()
            need(os.listdir(cwd["fd"]) == [], "layout-empty-cwd")
            before = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
            timeout = context_timeout(deadline, before, 15)
            role = "service-layout-" + case
            count = len(self.calls)
            try:
                result = self.call(role, [str(ROOT / (LAYOUT_CLIENTS[index] + LAYOUT_EXECUTABLE))],
                                   self.native_environment(), cwd=self.scratch / "cwd", timeout=timeout, limit=2048)
            finally:
                # A planned attempt is not entry: source admission can refuse
                # before the original call exists. Unknown actual calls stay entered.
                if len(self.calls) > count:
                    need(len(self.calls) == count + 1 and self.calls[count]["role"] == role
                         and self.calls[count]["entered"] is True, "layout-original-call-entry")
                    value["enteredCases"].append(case)
            self.service_layout_inputs()
            returned = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
            context_timeout(deadline, returned, 15)
            need(not result.stderr and os.listdir(cwd["fd"]) == [], "layout-output-correspondence")
            record = service_status_record(result.stdout, result.returncode, self.environment["GITHUB_SHA"],
                                           value["observerSourceSha256"], case, origin, deadline)
            need(before <= decimal(record["startedNs"]) <= decimal(record["finishedNs"]) <= returned,
                 "layout-original-clock-correspondence")
            value["cases"].append({"case": case, "stdoutSha256": digest(result.stdout), "record": record})
            service_layout_data(value, self.environment["GITHUB_SHA"])
        value["completed"] = True
        service_layout_data(value, self.environment["GITHUB_SHA"])

    def run_native(self):
        need(self.installed and self.package is not None and self.stage_roster
             and all(record["returned"] and record["returncode"] == 0 for record in self.calls),
             "native-admission-prerequisites")
        self.protected.check()
        cwd = self.outputs.directory(self.scratch / "cwd")
        need(os.listdir(cwd["fd"]) == [], "native-empty-cwd")
        self.native_entered = True
        self.btm_started = btm_clock_sample()
        result = self.call("native-run", [str(ROOT / ENTRY)], {}, cwd=self.scratch / "cwd",
                            timeout=WORK_SECONDS, limit=CAPTURE_LIMIT)
        self.native_returned = True
        self.btm_finished = btm_clock_sample()
        self.native = native_result(result.stdout, result.returncode, self.environment["GITHUB_SHA"], self.release)
        # Actual source, installed originals, capture custody and native finality
        # all participate. A native JSON assertion alone can never pass.
        need(os.listdir(cwd["fd"]) == [] and self.payload_roster(ROOT, installed=True) == self.stage_roster,
             "native-filesystem-postcondition")
        self.protected.check()
        self.observe_metadata("after-native", present=True)

    def observe_btm_logs(self):
        """One read-only diagnostic after a known original, never a service action."""
        value = self.btm_log
        need(value["state"] == "not-requested", "btm-log-original")
        native = [row for row in self.calls if row.get("role") == "native-run"]
        if (self.service_layout["selected"] or not self.native_returned or not self.native_entered
                or len(native) != 1 or native[0].get("entered") is not True or native[0].get("returned") is not True
                or any(row.get("returned") is not True for row in self.calls)):
            return
        if len(self.calls) >= 64:
            value["state"] = "window-unavailable"
            return
        try:
            value["window"] = btm_window(self.btm_started, self.btm_finished)
        except (Refused, OSError, OverflowError, ValueError):
            value["state"] = "window-unavailable"
            return
        value["state"] = "tool-unavailable"
        try:
            original, body = self.protected.file(Path("/usr/bin/log"), IMAGE_LIMIT, uid=0, modes=(0o555, 0o755))
            need(body, "btm-log-tool")
            value["toolSha256"] = digest(body)
            del body
            home = self.outputs.directory(self.scratch / "home")
            try:
                os.stat(".logrc", dir_fd=home["fd"], follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise Refused("btm-log-tool")
            self.outputs.check()
            self.protected.check_one(original)
            self.protected.check()
        except (Refused, OSError):
            return  # No tool call or diagnostic authority; original closes still participate.
        count = len(self.calls)
        try:
            result = self.call(BTM_ROLE, btm_argv(value["window"]), self.native_environment(),
                               cwd=self.scratch, timeout=BTM_SECONDS, limit=BTM_LIMIT)
        finally:
            # Derive entry from the original record, not from an intended call.
            if len(self.calls) > count:
                need(len(self.calls) == count + 1 and self.calls[count]["role"] == BTM_ROLE
                     and self.calls[count]["entered"] is True, "btm-log-original")
                record = self.calls[count]
                value["commandIndex"] = count
                value["state"] = "call-failed" if record["returned"] else "call-unknown"
                if record["returned"]:
                    value.update(stdoutSha256=record["stdoutSha256"], stderrSha256=record["stderrSha256"])
        self.outputs.check()
        self.protected.check_one(original)
        self.protected.check()
        need(result.returncode == 0, "original-command-failed")
        value["state"] = "unparseable"
        if result.stderr:
            return
        try:
            parsed = btm_events(result.stdout)
        except (Refused, ValueError, TypeError, RecursionError):
            return
        value.update(parsed, state="observed" if parsed["ownEventCount"] else "empty")
        btm_log_data(value, self.environment["GITHUB_SHA"], self.calls)

    def finish(self):
        self.protected_closed = self.protected.finish()
        self.sources_closed = self.source.book.finish()
        self.outputs_closed = self.outputs.finish()
        self.cleanup_errors.extend(self.protected.errors + self.source.book.errors + self.outputs.errors)
        # The exact installed root and receipt are deliberately retained.
        # Only original task scratch is disposable, and only after every
        # entered owner call and descriptor original is known settled.
        # Returning the outer process is not evidence that its resident
        # population settled. Only native_result's accepted closed resource map
        # can supply that fact; malformed/unknown reports retain this scratch.
        native_finality = (not self.native_entered or self.native_returned
                           and self.native is not None and self.native["nativeFinalityKnown"] is True)
        context_finality = (not self.installer_context["started"] or self.installer_context["completed"]
                            or self.context_pure_audit_refused is True
                            and self.installer_context["started"] is True
                            and self.installer_context["completed"] is False
                            and self.installer_context["enteredCases"] == [] and self.installer_context["cases"] == []
                            and not self.installer_entered and not self.native_entered
                            and not any(call["role"] in ("context-component-installer", "context-product-installer")
                                        for call in self.calls))
        layout_finality = service_layout_finality(self.service_layout, self.environment["GITHUB_SHA"])
        safe = (all(record["returned"] for record in self.calls) and self.sources_closed
                and self.outputs_closed and self.protected_closed and native_finality and context_finality
                and layout_finality and not self.cleanup_errors)
        self.scratch_retired = False
        if safe:
            cleanup = Originals()
            try:
                parent = cleanup.directory(self.work)
                info = os.stat(self.scratch.name, dir_fd=parent["fd"], follow_symlinks=False)
                need(signature(info)[:5] == self.scratch_identity and shutil.rmtree.avoids_symlink_attacks,
                     "scratch-original-before-retirement")
                shutil.rmtree(self.scratch.name, dir_fd=parent["fd"])
                try:
                    os.stat(self.scratch.name, dir_fd=parent["fd"], follow_symlinks=False)
                except FileNotFoundError:
                    self.scratch_retired = True
                else:
                    raise Refused("scratch-retirement-incomplete")
            except BaseException:
                self.cleanup_errors.append("scratch-retirement-failed")
            finally:
                if not cleanup.finish():
                    self.cleanup_errors.append("scratch-retirement-close-unknown")

    def receipt(self, failure):
        native_passed = self.native is not None and self.native["outcome"] == "passed"
        unit_passed = self.native_rust_tests is not None and native_rust_tests_data(self.native_rust_tests) is not None
        installer_unit_passed = (self.installer_worker_rust_tests is not None
                                and installer_worker_rust_tests_data(self.installer_worker_rust_tests) is not None)
        passed = (failure is None and native_passed and self.native_entered and self.native_returned
                  and unit_passed and installer_unit_passed and self.installer_context["completed"]
                  and self.sources_closed and self.outputs_closed and self.protected_closed
                  and self.scratch_retired and not self.cleanup_errors
                  and all(call["returned"] and call["returncode"] == 0 for call in self.calls))
        return {"schemaVersion": 1, "type": "mrk-macos-e2-native-fixture-owner-v1",
                "source": self.environment["GITHUB_SHA"], "tree": self.source.binding["tree"],
                "workflowSource": self.environment["GITHUB_WORKFLOW_SHA"], "workflow": WORKFLOW,
                "runId": self.environment["GITHUB_RUN_ID"], "runAttempt": self.environment["GITHUB_RUN_ATTEMPT"],
                "platform": "macos-26-arm64", "toolchain": TOOLCHAIN, "sourceInventorySha256": self.source.inventory_digest,
                "sourceOriginalHandleCount": self.source.source_handle_count,
                "sourceOriginalHandleReserve": self.source.source_handle_reserve,
                "bindingSha256": self.source.binding_digest, "sourceReleaseId": self.release,
                "outcome": "passed" if passed else "unavailable" if failure is None and self.native is not None
                           and self.native["outcome"] == "unavailable" else "failed",
                "failure": failure, "phase": self.phase, "originalCalls": self.calls,
                "workTimeoutSeconds": WORK_SECONDS, "hardTimeoutSeconds": HARD_SECONDS,
                "auxiliaryBudgetNanoseconds": str(AUXILIARY_NS), "artifacts": self.artifacts,
                "protectedMetadataObservations": self.metadata,
                "package": self.package, "installedArtifactRoster": getattr(self, "stage_roster", None),
                "receiptOriginals": getattr(self, "receipt_originals", []), "native": self.native,
                "nativeRustTests": self.native_rust_tests,
                "installerWorkerRustTests": self.installer_worker_rust_tests,
                "installerContext": self.installer_context,
                "serviceLayoutObservation": self.service_layout,
                "btmLogObservation": self.btm_log,
                "installerEntered": self.installer_entered, "installationReturnedSuccess": self.installed,
                "nativeEntered": self.native_entered, "nativeOwnerReturned": self.native_returned,
                "sourceClosesKnown": self.sources_closed, "protectedClosesKnown": self.protected_closed,
                "outputClosesKnown": self.outputs_closed, "cleanupErrors": self.cleanup_errors,
                "scratchRetired": self.scratch_retired, "protectedRootRetired": False,
                "exactReceiptRetired": False, "protectedRetentionRequired": self.installer_entered,
                "administrativeDomain": "reviewed-fresh-single-hosted-job-sole-fixture-writer",
                "arbitraryConcurrentPrivilegedWriterResistance": False, "flatPayloadAtomicNoReplace": False,
                "syntheticIdentity": True, "productionIdentityQualified": False,
                "actualAppIntegrationQualified": False, "distributionQualified": False,
                "rawOutputIncluded": False, "environmentValuesIncluded": False,
                "outerReceiptWriteCloseAndOriginalCallerExitRequired": True, "passed": passed}

    def execute(self):
        failure = None
        self.scratch_retired = False
        try:
            self.begin()
            self.scratch_identity = self.outputs.directories[self.scratch]["identity"]
            if not self.service_layout["selected"]:
                self.build_installer_worker_tests()
                # Native DATA/client compilation is independent of Context.
                # Keep this complete original graph/retirement before Context
                # so a metadata refusal cannot hide a native compiler failure.
                self.build_images()
                self.observe_installer_context()
            self.compile_metadata_observer()
            self.absence("initial")
            if self.service_layout["selected"]:
                self.build_images()  # Diagnostic layout retains its original order.
            self.compile_facades()
            if self.service_layout["selected"]:
                self.compile_service_layout()
            self.sign()
            self.package_fixture()
            self.install_fixture()
            if self.service_layout["selected"]:
                self.observe_service_layout()
            else:
                self.run_native()
        except BaseException as error:
            self.context_pure_audit_refused = (type(error) is Refused and error is self._context_audit_refusal)
            failure = (error.args[0] if type(error) is Refused and len(error.args) == 1
                       and type(error.args[0]) is str and re.fullmatch(r"[a-z][a-z0-9-]{0,95}", error.args[0])
                       else "original-operation-refused-or-unknown")
        finally:
            original_phase = self.phase
            try:
                self.observe_btm_logs()
            except BaseException as error:
                self.context_pure_audit_refused = False
                if failure is None:
                    failure = (error.args[0] if type(error) is Refused and len(error.args) == 1
                               and type(error.args[0]) is str and re.fullmatch(r"[a-z][a-z0-9-]{0,95}", error.args[0])
                               else "original-operation-refused-or-unknown")
                else:
                    self.phase = original_phase
            else:
                self.phase = original_phase
            self.finish()
        return self.receipt(failure)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                       allow_nan=False) + "\n").encode("ascii")


def main():
    book, operation = Originals(), None
    try:
        work = admit(os.environ)
        source = SourceInputs(book, work, os.environ)
        source.admit()
        fixture_domain(source.binding)
        stager = source.load("stage_macos_installed.py", "_mrk_e2_fixture_stager")
        qualification = source.load("macos_aqua_qualification.py", "_mrk_e2_fixture_owner_loader")
        owner = qualification.load_owner(CHECKOUT)
        book.check()
        operation = Operation(owner, source, stager, work, os.environ,
                              service_layout=sys.argv[1:] == [LAYOUT_ARGUMENT])
        value = operation.execute()
    except BaseException:
        book.finish()
        print("E2 fixture admission refused; no native qualification was established.", file=sys.stderr)
        return 1
    report = Originals()
    try:
        body = canonical(value)
        need(len(body) <= 65536, "owner-result-bound")
        report.publish(work / "e2-native-result.json", body)
        need(report.finish(), "owner-result-original-close")
        # The persisted report is provisional until this original writer/caller
        # also returns zero. A later write/close/exit failure vetoes acceptance.
        summary = canonical({"source": value["source"], "runId": value["runId"],
                             "runAttempt": value["runAttempt"], "outcome": value["outcome"],
                             "type": value["type"], "reportSha256": digest(body),
                             "nativeChecksPassed": value["passed"]})
        need(os.write(1, summary) == len(summary), "owner-summary-write")
    except BaseException:
        report.finish()
        print("E2 fixture evidence finalization failed; do not accept a provisional result.", file=sys.stderr)
        return 1
    return 0 if value["passed"] else 77 if value["outcome"] == "unavailable" else 1


if __name__ == "__main__":
    raise SystemExit(main())
