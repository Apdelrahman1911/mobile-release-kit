#!/usr/bin/env python3
"""One fixed, nonshipping macOS E2 native fixture.

Import is DATA-only. The native entry authenticates its original hosted source,
loads the existing process owner, builds two separate images, and invokes one
installed fixture. Parsed DATA never authorizes a service operation. The fixed
fixture cannot qualify publisher identity, the desktop UI, or distribution.
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
TOOLCHAIN = "1.98.1"
RUST_COMMIT = "48a229ceaefd4985c50990b14116b6d856af0985"
CASES = ("missing-b-refused", "local-f-before-admission", "genuine-tail-unregister")
WORK_SECONDS, HARD_SECONDS = 990, 993
CAPTURE_LIMIT, RESULT_LIMIT = 65536, 32768
IMAGE_LIMIT = 32 * 1024 * 1024
RECEIPT_CENSUS_LIMIT = 1024 * 1024
MAX_RAW = (1 << 61) - 1
AUXILIARY_NS = 60_000_000_000
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
CLOSE_FLAGS = ("mainReturned", "mainClosed", "clientClosed", "workerJoined", "identityClosed")
CASE_FLAGS = ("registered", "watchRegistered", "refused", "tailAdmissionIssued",
              "testedUnregisterEntered", "fixtureCleanupUnregisterEntered", "eof",
              "noteExit") + CLOSE_FLAGS
CASE_KEYS = {"case", "outcome", "startedNs", "finishedNs", "firstFailureNs",
             "operationHex", "instanceHex", "tailHex", "resourceStates",
             "preServiceStop", "mainObservations", *CASE_FLAGS}
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
    """Actual two-graph inputs, including core compile-time DATA and owner imports."""
    explicit = {
        ".github/workflows/desktop-macos-maintenance-fixture.yml",
        "desktop/rust-toolchain.toml", "desktop/packaging/macos-empty-entitlements.plist",
        "desktop/packaging/macos-android-service-signing.profile",
        "desktop/tools/macos_e2_native_fixture.py", "desktop/tools/macos_aqua_qualification.py",
        "desktop/tools/stage_macos_installed.py",
        *("src/mobile_release/" + name for name in (
            "__init__.py", "owned_process.py", "_command_process.py", "_native_process.py",
            "cancellation.py", "errors.py", "_lifetime_evidence.py",
            "_store_lane_contract.py", "_store_lane_evidence.py")),
    }
    need(explicit <= set(rows), "required-source-roster")
    prefixes = ("desktop/native/macos-installed-native/", "desktop/native/macos-installed-entry/",
                "desktop/helpers/macos-android-register/", "desktop/src-tauri/",
                "desktop/macos-installed-inputs/", "templates/", "schemas/")
    # Build scripts and Rust include_bytes!/include_str! use the headless core,
    # its checked-in generated catalogue, Python bootstrap SOURCE and templates.
    # No unrelated Debian notices, UI frontend, registry cache or other platform
    # implementation is held merely because it shares a repository.
    return sorted(name for name in rows if name in explicit or name.startswith(prefixes)
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
        self.source_handle_reserve = 160  # Observer, payload and process-owner originals.
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
    need(len(sys.argv) == 1 and Path(__file__).absolute() == CHECKOUT / "desktop/tools/macos_e2_native_fixture.py"
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


def fixture_package(body, expected):
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

    def __init__(self, owner, source, stager, work, environment):
        self.owner, self.source, self.stager = owner, source, stager
        self.work, self.environment = work, environment
        self.scratch = work / "e2-native-fixture"
        self.outputs, self.protected = Originals(), Originals()
        self.calls, self.cleanup_errors, self.scratch_origins = [], [], {}
        self.phase = "prepare"
        self.native = None
        self.package = None
        self.installer_entered = False
        self.installed = False
        self.native_entered = False
        self.native_returned = False
        self.artifacts = {}
        self.observer_entry, self.observer_digest, self.metadata = None, None, []
        self.release = None
        self.sources_closed = self.outputs_closed = self.protected_closed = False

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
        return result

    def command(self, role, argv, environment, *, cwd, timeout, limit=65536):
        result = self.call(role, argv, environment, cwd=cwd, timeout=timeout, limit=limit)
        need(result.returncode == 0, "original-command-failed")
        return result

    def native_environment(self):
        return {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(self.scratch / "home"),
                "TMPDIR": str(self.scratch / "tmp"), "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}

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
                       CHECKOUT / NATIVE, CHECKOUT / HELPER):
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

    def build_images(self):
        for role in ("client", "resident"):
            target = self.scratch / (role + "-target")
            entry = self.mkdir(target)
            self.scratch_origins[target] = entry["identity"]
            cargo, environment = self.compiler_environment(target)
            directory = NATIVE if role == "client" else HELPER
            argv = [cargo, "build", "--manifest-path", str(CHECKOUT / directory / "Cargo.toml"),
                    "--locked", "--offline", "--release", "--jobs", "1", "--target", TARGET,
                    "--no-default-features", "--features",
                    "desktop-image,e2-native-fixture" if role == "client" else "e2-native-fixture"]
            argv += (["--example", "e2_maintenance_client"] if role == "client" else ["--lib"])
            argv += ["--message-format=json-render-diagnostics"]
            try:
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
        payload = self.scratch / "payload"
        # codesign also inherits the private umask. Supply only its two exact
        # fresh signature directories ourselves instead of normalizing a tree.
        for relative in (APP + "/Contents/_CodeSignature", CONTENTS + "_CodeSignature"):
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
            executable = relative in {ENTRY, CLIENT, RESIDENT, *IMAGES.values()}
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
            entry, body = book.file(path, IMAGE_LIMIT, uid=0 if installed else None,
                                    modes=(0o555,) if executable else (0o444,))
            need(not installed or entry["identity"][4] == 0, "installed-group")
            self.stager.no_xattrs(entry["fd"])
            total += len(body)
            need(total <= 3 * IMAGE_LIMIT, "fixture-total-bytes")
            if relative in IMAGES.values():
                fixture_image_macho(body, next(role for role, name in IMAGES.items() if name == relative))
            elif executable:
                self.stager.entry_macho(body)
            elif relative == GATE:
                need(body == self.stager.MAINTENANCE_GATE_BYTES, "fixture-gate-bytes")
            found[relative] = {"bytes": len(body), "sha256": digest(body),
                               "mode": "100555" if executable else "100444"}
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
        pending, seen = [(row, 0) for row in components], set()
        while pending:
            row, depth = pending.pop()
            need(type(row) is dict and depth <= 2 and len(seen) <= 2, "package-component-shape")
            path = row.get("RootRelativeBundlePath")
            need(path in (APP, NESTED) and path not in seen and not any("Script" in key for key in row),
                 "package-component-path")
            seen.add(path)
            row.update(BundleIsRelocatable=False, BundleHasStrictIdentifier=True, BundleIsVersionChecked=False)
            children = row.get("ChildBundles", [])
            need(type(children) is list and len(children) <= 1, "package-component-children")
            pending.extend((child, depth + 1) for child in children)
        need(APP in seen and self.outputs.read(original) == data, "package-component-root")
        component_path = self.scratch / "components.plist"
        self.outputs.publish(component_path, plistlib.dumps(components, sort_keys=True))
        output = self.scratch / "MRK-E2-NativeFixture.pkg"
        self.command("package-build", ["/usr/bin/pkgbuild", "--root", str(payload),
                     "--identifier", PACKAGE, "--version", "1", "--install-location", str(ROOT),
                     "--ownership", "recommended", "--component-plist", str(component_path),
                     "--compression", "legacy", str(output)], self.native_environment(), cwd=self.scratch, timeout=90)
        self.package_entry, body = self.outputs.file(output, 4 * IMAGE_LIMIT, modes=(0o600, 0o644))
        self.package = fixture_package(body, self.stage_roster)
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
        for index, relative in enumerate((IMAGES["client"], IMAGES["resident"], RESIDENT, NESTED, APP)):
            self.command("installed-signature-" + str(index),
                         ["/usr/bin/codesign", "--verify", "--strict", "--all-architectures", "--deep", str(ROOT / relative)],
                         self.native_environment(), cwd=self.scratch, timeout=30)
        need(self.payload_roster(ROOT, installed=True) == actual, "installed-originals-changed")

    def run_native(self):
        need(self.installed and self.package is not None and self.stage_roster
             and all(record["returned"] and record["returncode"] == 0 for record in self.calls),
             "native-admission-prerequisites")
        self.protected.check()
        cwd = self.outputs.directory(self.scratch / "cwd")
        need(os.listdir(cwd["fd"]) == [], "native-empty-cwd")
        self.native_entered = True
        result = self.call("native-run", [str(ROOT / ENTRY)], {}, cwd=self.scratch / "cwd",
                           timeout=WORK_SECONDS, limit=CAPTURE_LIMIT)
        self.native_returned = True
        self.native = native_result(result.stdout, result.returncode, self.environment["GITHUB_SHA"], self.release)
        # Actual source, installed originals, capture custody and native finality
        # all participate. A native JSON assertion alone can never pass.
        need(os.listdir(cwd["fd"]) == [] and self.payload_roster(ROOT, installed=True) == self.stage_roster,
             "native-filesystem-postcondition")
        self.protected.check()
        self.observe_metadata("after-native", present=True)

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
        safe = (all(record["returned"] for record in self.calls) and self.sources_closed
                and self.outputs_closed and self.protected_closed and native_finality and not self.cleanup_errors)
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
        passed = (failure is None and native_passed and self.native_entered and self.native_returned
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
            self.compile_metadata_observer()
            self.absence("initial")
            self.build_images()
            self.compile_facades()
            self.sign()
            self.package_fixture()
            self.install_fixture()
            self.run_native()
        except BaseException as error:
            failure = (error.args[0] if type(error) is Refused and len(error.args) == 1
                       and type(error.args[0]) is str and re.fullmatch(r"[a-z][a-z0-9-]{0,95}", error.args[0])
                       else "original-operation-refused-or-unknown")
        finally:
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
        operation = Operation(owner, source, stager, work, os.environ)
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
