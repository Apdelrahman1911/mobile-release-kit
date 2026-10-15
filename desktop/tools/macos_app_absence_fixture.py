"""Fixed nonshipping app-absence DATA and existing-Operation adapter.

No subprocess or independent supervisor. The caller retains every original,
clock, process capture, stager latch and finality decision. This module never
admits an arbitrary command, path, installed instance or user-selected role.
"""

PRODUCT_LIMIT = 512 * 1024 * 1024
FIXTURE_PACKAGE_LIMIT = 640 * 1024 * 1024
FIXTURE_IMAGE_LIMIT = 2560 * 1024 * 1024
RECORD_LIMIT = 64 * 1024
FIXTURE_EXECUTABLE = "mrk-macos-app-absence-fixture"
PHASE_NAMES = (
    "MRK-AppAbsence-Baseline.pkg",
    "MRK-AppAbsence-Withdraw.pkg",
    "MRK-AppAbsence-Verify.pkg",
)
CARRIER_NAMES = ("Install.pkg", "producer.json", "producer.sig") + PHASE_NAMES
TARGETS = ("aarch64-apple-darwin", "x86_64-apple-darwin")
POSTINSTALL = (
    b"#!/bin/sh\n"
    b"set -eu\n"
    b'd="${0%/*}"\n'
    b'exec "$d/mrk-macos-app-absence-fixture" "$d/input" "$1"\n'
)


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def nonzero_hex_data(value, length):
    return (type(value) is str and len(value) == length
            and all(c in "0123456789abcdef" for c in value) and any(c != "0" for c in value))


def decimal_data(value, limit):
    return (type(value) is str and 0 < len(value) <= limit and not value.startswith("0")
            and all(c in "0123456789" for c in value))


def component_data(value):
    return (type(value) is str and 0 < len(value) <= 255 and value not in (".", "..")
            and not value.startswith(" ") and not value.endswith(" ") and "  " not in value
            and all(c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ._-" for c in value))


def transport_data(path):
    """Fixed phase basename and same-parent P; spelling is not native authority."""
    need(type(path) is str and path.startswith("/") and len(path) <= 4096, "fixture-transport-path")
    parts = path[1:].split("/")
    need(2 <= len(parts) <= 32 and all(component_data(part) for part in parts), "fixture-transport-path")
    need(parts[-1] in PHASE_NAMES, "fixture-fixed-phase")
    parent = path.rsplit("/", 1)[0]
    return {"phase": ("baseline", "withdraw", "verify")[PHASE_NAMES.index(parts[-1])],
            "productPath": parent + "/Install.pkg"}


def binding_data(value):
    """Closed DATA projection, never the whole process environment."""
    fields = {"fixtureSource", "productSource", "runId", "runAttempt", "target"}
    need(type(value) is dict and set(value) == fields, "fixture-binding-fields")
    need(nonzero_hex_data(value["fixtureSource"], 40)
         and value["fixtureSource"] == value["productSource"]
         and decimal_data(value["runId"], 20) and decimal_data(value["runAttempt"], 10)
         and type(value["target"]) is str and value["target"] in TARGETS, "fixture-binding-values")
    return dict(value)


def baseline_name_data(binding):
    value = binding_data(binding)
    target = "arm64" if value["target"] == TARGETS[0] else "intel"
    return ("MobileReleaseKit-AppAbsence-" + value["fixtureSource"][:12] + "-" + value["runId"]
            + "-" + value["runAttempt"] + "-" + target + "-baseline.json")


def private_name_data(binding, root_nonce):
    value = binding_data(binding)
    need(nonzero_hex_data(root_nonce, 32), "fixture-root-nonce")
    return "MobileReleaseKit-AppAbsenceFixture-" + value["fixtureSource"][:12] + "-" + root_nonce


def transport_layout_data(rows):
    """Six metadata rows; no payload bytes, native opens, extraction or copying.

    Each future actual original must independently prove its shape, hash and
    single-link identity. Three fixture copies are identical; the product P is
    untouched. No user-distribution roster/cap is changed by this function.
    """
    need(type(rows) is list and len(rows) == 6, "fixture-layout-count")
    entries = {}
    for row in rows:
        need(type(row) is dict and set(row) == {"name", "bytes", "sha256", "mode", "links"}, "fixture-layout-fields")
        name = row["name"]
        need(type(name) is str and name in CARRIER_NAMES and name not in entries, "fixture-layout-name")
        size = row["bytes"]
        need(type(size) is int and type(row["mode"]) is int and row["mode"] == 0o444
             and type(row["links"]) is int and row["links"] == 1 and nonzero_hex_data(row["sha256"], 64),
             "fixture-layout-original-shape")
        limit = (PRODUCT_LIMIT if name == "Install.pkg" else 16 * 1024 if name == "producer.json"
                 else 512 if name == "producer.sig" else FIXTURE_PACKAGE_LIMIT)
        lower = 28 if name.endswith(".pkg") else 1
        need(lower <= size <= limit, "fixture-layout-file-bound")
        entries[name] = dict(row)
    fixture = entries[PHASE_NAMES[0]]
    need(all((entries[name]["bytes"], entries[name]["sha256"]) == (fixture["bytes"], fixture["sha256"])
             for name in PHASE_NAMES), "fixture-package-copies-differ")
    return {"kind": "app-absence-six-file-layout-data", "fileCount": 6,
            "bytes": sum(row["bytes"] for row in entries.values()),
            "productSha256": entries["Install.pkg"]["sha256"],
            "fixtureSha256": fixture["sha256"], "fixtureBytes": fixture["bytes"]}


def transport_output_bytes_data(product_bytes, fixture_bytes, image_bytes):
    """Partial output quote ONLY; final live-peak owner admission is deferred."""
    need(all(type(value) is int for value in (product_bytes, fixture_bytes, image_bytes)), "fixture-output-types")
    need(28 <= product_bytes <= PRODUCT_LIMIT and 28 <= fixture_bytes <= FIXTURE_PACKAGE_LIMIT
         and 1 <= image_bytes <= FIXTURE_IMAGE_LIMIT, "fixture-output-bound")
    return product_bytes + 3 * fixture_bytes + image_bytes + 16 * 1024 + 512


def fresh_install_matches_data(action, actual_created_root, original_joined, original_status,
                               instance, expected_instance):
    """Comparison only: an initial no-op must not establish task ownership."""
    return (type(action) is str and action == "fresh-install" and actual_created_root is True
            and original_joined is True and type(original_status) is int and original_status == 0
            and nonzero_hex_data(instance, 32) and instance == expected_instance)


def outer_phase_credit_data(verified_before_export, record_readback, original_joined,
                            actual_exit, all_originals_closed, deadline_met, unknown):
    """A pending-original-exit record cannot certify its own future closes."""
    return (all(value is True for value in (verified_before_export, record_readback, original_joined,
                                          all_originals_closed, deadline_met))
            and type(actual_exit) is int and actual_exit == 0 and unknown is False)


def fixed_binding_and_layout_data_checks():
    binding = {"fixtureSource": "1" * 40, "productSource": "1" * 40,
               "runId": "123", "runAttempt": "1", "target": TARGETS[0]}
    for target in TARGETS:
        current = dict(binding, target=target)
        assert len(baseline_name_data(current)) < 255
        assert len(private_name_data(current, "2" * 32)) < 255
    for index, name in enumerate(PHASE_NAMES):
        parsed = transport_data("/Volumes/Fixture " + str(index) + "/" + name)
        assert parsed["productPath"] == "/Volumes/Fixture " + str(index) + "/Install.pkg"
    rows = [{"name": name, "bytes": 100, "sha256": "3" * 64, "mode": 0o444, "links": 1}
            for name in CARRIER_NAMES]
    assert transport_layout_data(rows)["fileCount"] == 6
    for change in ({"name": "foreign"}, {"links": 2}, {"bytes": True}, {"mode": True}, {"sha256": "0" * 64}):
        bad = [dict(row) for row in rows]
        bad[0].update(change)
        try:
            transport_layout_data(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("bad fixture layout accepted")
    bad = [dict(row) for row in rows]
    bad[-1]["sha256"] = "4" * 64
    try:
        transport_layout_data(bad)
    except ValueError:
        pass
    else:
        raise AssertionError("different fixture copies accepted")
    for path in ("MRK-AppAbsence-Baseline.pkg", "/MRK-AppAbsence-Baseline.pkg",
                 "/Volumes/P/Install.pkg", "/Volumes/../P/" + PHASE_NAMES[0]):
        try:
            transport_data(path)
        except ValueError:
            pass
        else:
            raise AssertionError("wrong fixture transport accepted")


def ownership_and_finality_data_checks():
    instance = "4" * 32
    assert fresh_install_matches_data("fresh-install", True, True, 0, instance, instance)
    for action in ("same-package-noop", "restore-fixed-app", "update"):
        assert not fresh_install_matches_data(action, True, True, 0, instance, instance)
    for status in (None, False, True, 1, 20):
        assert not fresh_install_matches_data("fresh-install", True, True, status, instance, instance)
        assert not outer_phase_credit_data(True, True, True, status, True, True, False)
    assert outer_phase_credit_data(True, True, True, 0, True, True, False)
    assert not outer_phase_credit_data(True, True, False, 0, True, True, False)
    assert not outer_phase_credit_data(True, True, True, 0, False, True, False)
    assert not outer_phase_credit_data(True, True, True, 0, True, False, False)
    assert not outer_phase_credit_data(True, True, True, 0, True, True, True)
    assert transport_output_bytes_data(PRODUCT_LIMIT, FIXTURE_PACKAGE_LIMIT, FIXTURE_IMAGE_LIMIT) > FIXTURE_IMAGE_LIMIT
    for sizes in ((27, 28, 1), (28, 27, 1), (28, 28, 0), (True, 28, 1),
                  (PRODUCT_LIMIT + 1, 28, 1), (28, FIXTURE_PACKAGE_LIMIT + 1, 1), (28, 28, FIXTURE_IMAGE_LIMIT + 1)):
        try:
            transport_output_bytes_data(*sizes)
        except ValueError:
            pass
        else:
            raise AssertionError("unbounded fixture output accepted")

import hashlib
import json
import os
import re
from pathlib import Path
import stat
import time
from types import SimpleNamespace

REF = "refs/heads/verify/desktop-macos-app-absence-fixture"
PREPARE = "prepare-app-absence"
RESTORE = "app-absence-restore"
PHASES = (PREPARE, RESTORE)
PREPARE_ROLES = ("app-absence-build", "app-absence-data-tests", "app-absence-adhoc", "app-absence-verify-code",
                 "app-absence-pkgbuild", "app-absence-tar", "app-absence-xar")
RESTORE_ROLES = ("app-absence-restore-attach", "app-absence-withdraw", "app-absence-install",
                 "app-absence-verify", "app-absence-restore-detach")
PACKAGE_INSERT = ("app-absence-image-create", "app-absence-image-verify", "app-absence-baseline-attach")
BINDING_FIELDS = ("fixtureSource", "productSource", "runId", "runAttempt", "target", "packageSha256",
                  "producerDescriptorSha256", "producerSignatureSha256", "fixtureExecutableSha256",
                  "inventorySha256", "runtimeManifestSha256", "protocolSha256")
PROOFS = {
    "baseline": ("rootAbsent", "privateDirectoryCreated", "parentCensusMatched", "recordReadback"),
    "withdraw": ("initialFreshInstallRecorded", "createdRootMatchedPriorAbsence", "sameInstance",
                 "reservationClosedUnderMaintenance", "renameKnownSuccess", "appAbsent", "runtimeUnchanged",
                 "historyUnchanged", "withdrawnAppVerified", "recordReadback"),
    "verify": ("restoreFixedAppRecorded", "initialHistoryPreserved", "sameInstance", "runtimeUnchanged",
               "newAppOriginal", "currentAppVerified", "withdrawnAppVerified", "reservationClosedUnderMaintenance",
               "recordReadback", "retainedPrivateEvidence"),
}
MIB = 1024 * 1024
OUTPUTS = {"executable": 64*MIB, "scripts": 577*MIB, "original": 640*MIB, "archive": 640*MIB,
           "fixture": 640*MIB, "copies": 1920*MIB, "product": 512*MIB, "image": 2560*MIB,
           "withdrawn": 512*MIB}
FREE_FLOOR = 3 * 1024 * MIB
STORAGE_RESERVE = 2 * 1024 * MIB
CONTROL_RESERVE = 16 * MIB


def digest(body):
    return hashlib.sha256(body).hexdigest()


def package_roles(old):
    need(type(old) is tuple and len(old) == 16 and old[:3] == ("producer-tests", "producer-build", "producer-emitter")
         and old[-1] == "distribution-detach" and old.count("installer") == 1, "app-absence-old-roster")
    return old[:3] + PACKAGE_INSERT + old[3:old.index("installer")] + ("app-absence-baseline",) + old[old.index("installer"):] + ("app-absence-baseline-detach",)


def source_binding(environment, target):
    value = {"fixtureSource": environment.get("GITHUB_SHA"), "productSource": environment.get("MRK_MACOS_INSTALL_SOURCE_COMMIT"),
             "runId": environment.get("GITHUB_RUN_ID"), "runAttempt": environment.get("GITHUB_RUN_ATTEMPT"), "target": target}
    return binding_data(value)


def clock(op, *, work=True):
    state = op.app_absence
    now = time.monotonic_ns()
    need(type(now) is int and state["started"] <= state["observed"] <= now
         < state["started"] + (state["workSeconds"] if work else state["hardSeconds"]) * 1_000_000_000,
         "app-absence-original-deadline")
    state["observed"] = now
    return now


def start(op, api):
    need(op.environment.get("GITHUB_REF") == REF and op.phase in PHASES + ("package-install",)
         and op.environment.get("MRK_MACOS_SAME_PACKAGE_SCOPE", "disabled") == "disabled"
         and op.environment.get("MRK_MACOS_PACKAGE_ROLE") == "ordinary-image", "app-absence-fixed-route")
    binding = source_binding(op.environment, op.target)
    work, hard = (3180, 3240) if op.phase == PREPARE else (660, 720) if op.phase == RESTORE else (1740, 1800)
    now = time.monotonic_ns()
    op.app_absence_api = api
    op.app_absence = {"binding": binding, "started": now, "observed": now, "workSeconds": work,
        "hardSeconds": hard, "outputs": [], "roots": [], "mount": None, "pendingRoot": None,
        "complete": False, "future": {k: v for k, v in OUTPUTS.items()
            if op.phase == PREPARE or op.phase == "package-install" and k in ("copies", "product", "image", "withdrawn")
            or op.phase == RESTORE and k == "withdrawn"}, "summary": None}
    op.package_started = op.package_observed = now
    op.package_endpoint = now + work * 1_000_000_000
    clock(op)
    reserve(op)


def reserve(op, allocation=None):
    clock(op)
    op.recheck_directory(op.work_entry)
    future = op.app_absence["future"]
    need(all(type(v) is int and v >= 0 for v in future.values()), "app-absence-storage-ledger")
    info = os.fstatvfs(op.work_entry["fd"])
    need(type(info.f_bavail) is int and type(info.f_frsize) is int and info.f_bavail >= 0 and info.f_frsize > 0
         and info.f_bavail * info.f_frsize >= sum(future.values()) + FREE_FLOOR + STORAGE_RESERVE + CONTROL_RESERVE,
         "app-absence-storage-reserve")
    if allocation is not None:
        need(allocation in future, "app-absence-storage-allocation")
        del future[allocation]  # Full ceiling accounted BEFORE the new output.


def io(op, label, function, *args, **kwargs):
    need(op.package_settled(), "app-absence-stager-unknown")
    clock(op)
    op.stager_io_pending = "app-absence-" + label
    value = function(*args, **kwargs)
    clock(op)
    op.stager_io_pending = None
    return value


def roles(op):
    return (PREPARE_ROLES if op.phase == PREPARE else RESTORE_ROLES if op.phase == RESTORE
            else package_roles(op.stager.PACKAGING_CALL_ROLES))


def dispatch(op, role):
    state = op.app_absence
    clock(op)
    expected = roles(op)
    need(not op.errors and op.stager_io_pending is None and state["pendingRoot"] is None
         and len(op.calls) < len(expected) and role == expected[len(op.calls)]
         and all(row.get("returned") is True and row.get("capturesSettled") is True
                 and type(row.get("returncode")) is int and (row.get("returncode") == 0 or op.phase == "package-install"
                      and row.get("role") in ("installer-log-cursor", "installer-log-capture") and row.get("returncode") == 1)
                 for row in op.calls), "app-absence-exact-original-order")
    if role in ("app-absence-baseline", "app-absence-withdraw", "app-absence-install", "app-absence-verify"):
        state["pendingRoot"] = role  # Before the SAME owner dispatch; failure retains this latch.
    if role in ("app-absence-baseline-attach", "app-absence-restore-attach"):
        need(state["mount"] is not None and not state["mount"]["entered"], "app-absence-mount-dispatch")
        state["mount"]["entered"] = True


def returned(op, role):
    if op.app_absence["pendingRoot"] == role:
        need(op.calls[-1].get("role") == role and type(op.calls[-1].get("returncode")) is int and op.calls[-1].get("returncode") == 0
             and op.calls[-1].get("returned") is True and op.calls[-1].get("capturesSettled") is True,
             "app-absence-root-original-incomplete")
        op.app_absence["pendingRoot"] = None
    clock(op)


def call(op, role, argv, *, maximum=30, limit=65536, environment=None, cwd=None):
    post(op)
    result = op.package_call(role, argv, timeout=maximum, limit=limit, environment=environment, cwd=cwd)
    post(op)
    return result


def original_hash(op, entry):
    api = op.app_absence_api
    need(entry["fd"] is not None and not entry["closed"], "app-absence-original-closed")
    op.recheck_directory(entry["parent_entry"])
    identity = entry["identity"]
    need(api.signature(os.fstat(entry["fd"])) == identity
         == api.signature(os.stat(entry["name"], dir_fd=entry["parent"], follow_symlinks=False)), "app-absence-original-post")
    h, offset = hashlib.sha256(), 0
    while offset < identity[6]:
        clock(op)
        chunk = os.pread(entry["fd"], min(65536, identity[6] - offset), offset)
        need(0 < len(chunk) <= identity[6] - offset, "app-absence-short-read")
        h.update(chunk); offset += len(chunk)
    need(os.pread(entry["fd"], 1, offset) == b"" and api.signature(os.fstat(entry["fd"])) == identity
         == api.signature(os.stat(entry["name"], dir_fd=entry["parent"], follow_symlinks=False)), "app-absence-original-read-post")
    op.recheck_directory(entry["parent_entry"])
    return h.hexdigest()


def retained(op, parent, name, limit, modes=(0o444, 0o600)):
    entry = op.original(parent, name, "app-absence-retained-" + name, limit, modes)
    sha = original_hash(op, entry)
    op.app_absence["outputs"].append((entry, sha))
    return entry, sha


def small(op, parent, name, limit=16384, modes=(0o444, 0o600)):
    entry, sha = retained(op, parent, name, limit, modes)
    body = op.read(entry)
    need(digest(body) == sha, "app-absence-small-post")
    return body


def copy(op, original, parent, name, maximum, *, mode=0o444):
    api = op.app_absence_api
    need(type(name) is str and component_data(name) and original["identity"][6] <= maximum
         and mode in (0o444, 0o555), "app-absence-copy-bound")
    expected = original_hash(op, original)
    op.recheck_directory(parent)
    fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent["fd"])
    entry = op.register(fd, "app-absence-copy-" + name, "file", parent["fd"], name)
    entry["parent_entry"] = parent
    offset = 0
    while offset < original["identity"][6]:
        clock(op)
        chunk = os.pread(original["fd"], min(65536, original["identity"][6] - offset), offset)
        need(chunk, "app-absence-copy-short-read")
        written = 0
        while written < len(chunk):
            count = os.write(fd, chunk[written:])
            need(count > 0, "app-absence-copy-short-write")
            written += count
        offset += len(chunk)
    os.fchmod(fd, mode); os.fsync(fd)
    info = os.fstat(fd)
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid() and info.st_gid == os.getgid()
         and info.st_size == original["identity"][6] and stat.S_IMODE(info.st_mode) == mode, "app-absence-copy-original")
    entry["identity"] = api.signature(info)
    need(original_hash(op, entry) == expected == original_hash(op, original), "app-absence-copy-correspondence")
    os.fsync(parent["fd"])
    op.app_absence["outputs"].append((entry, expected))
    return entry


def output(op, parent, name, body, *, mode=0o444):
    need(type(body) is bytes and 0 < len(body) <= 65536 and mode in (0o444, 0o555, 0o600), "app-absence-control-bound")
    op.recheck_directory(parent)
    fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent["fd"])
    entry = op.register(fd, "app-absence-control-" + name, "file", parent["fd"], name)
    entry["parent_entry"] = parent
    need(os.write(fd, body) == len(body), "app-absence-control-short-write")
    os.fchmod(fd, mode); os.fsync(fd)
    entry["identity"] = op.app_absence_api.signature(os.fstat(fd))
    need(os.pread(fd, len(body) + 1, 0) == body, "app-absence-control-readback")
    os.fsync(parent["fd"])
    op.app_absence["outputs"].append((entry, digest(body)))
    return entry


def mkdir(op, parent, name):
    op.recheck_directory(parent)
    os.mkdir(name, 0o700, dir_fd=parent["fd"])
    entry = op.directory(parent, name, "app-absence-directory-" + name)
    need(not os.listdir(entry["fd"]), "app-absence-directory-empty")
    return entry


def post(op):
    clock(op)
    for root, names in op.app_absence["roots"]:
        op.recheck_directory(root)
        need(set(os.listdir(root["fd"])) == names, "app-absence-directory-roster")
    for entry, expected in op.app_absence["outputs"]:
        need(original_hash(op, entry) == expected, "app-absence-held-output-post")
    mounted_post(op)


def finish_ready(op):
    state = op.app_absence
    if state is None:
        return True
    mount = state["mount"]
    return (state["pendingRoot"] is None and op.stager_io_pending is None
            and (mount is None or not mount["entered"] or mount["detached"]) )


def artifact_data(body, checkout, root, target):
    need(type(body) is bytes and 0 < len(body) <= 4*MIB and body.endswith(b"\n") and target in TARGETS,
         "app-absence-cargo-bound")
    def pairs(rows):
        need(len({k for k, _ in rows}) == len(rows), "app-absence-cargo-duplicate")
        return dict(rows)
    rows = [json.loads(line, object_pairs_hook=pairs) for line in body.splitlines()]
    need(1 < len(rows) <= 8192 and all(type(row) is dict for row in rows), "app-absence-cargo-rows")
    artifacts, finished = [], False
    for row in rows:
        need(not finished and row.get("reason") in ("compiler-artifact", "compiler-message", "build-script-executed", "build-finished"),
             "app-absence-cargo-order")
        if row["reason"] == "build-finished":
            need(row == {"reason": "build-finished", "success": True} and row["success"] is True, "app-absence-cargo-failed")
            finished = True
        elif row["reason"] == "compiler-artifact":
            need(type(row.get("target")) is dict and type(row.get("filenames")) is list, "app-absence-cargo-artifact")
            artifacts.append(row)
    binary = root / target / "release" / FIXTURE_EXECUTABLE
    selected = [r for r in artifacts if r["target"].get("name") in (FIXTURE_EXECUTABLE, "mobile_release_desktop")]
    need(finished and len(selected) == 2, "app-absence-cargo-selected")
    for name, source, kind, executable in ((FIXTURE_EXECUTABLE, "src/bin/macos_install.rs", ["bin"], str(binary)),
                                         ("mobile_release_desktop", "src/lib.rs", ["lib"], None)):
        matched = [r for r in selected if r["target"].get("name") == name]
        need(len(matched) == 1, "app-absence-cargo-one-target")
        row = matched[0]; target_row = row["target"]; profile = row.get("profile")
        package_root = checkout / "desktop/src-tauri"
        need(row.get("package_id") == "path+" + package_root.as_uri() + "#mobile-release-kit-desktop@0.1.2"
             and row.get("manifest_path") == str(package_root / "Cargo.toml")
             and row.get("features") == ["macos-installed-app-absence-fixture"]
             and target_row.get("kind") == target_row.get("crate_types") == kind
             and target_row.get("src_path") == str(package_root / source) and target_row.get("edition") == "2021"
             and "executable" in row and row["executable"] == executable and type(row.get("fresh")) is bool
             and type(profile) is dict and profile.get("test") is False and profile.get("debug_assertions") is False
             and profile.get("opt_level") == "3", "app-absence-cargo-exact-graph")
        if executable is not None:
            need(row["filenames"] == [executable], "app-absence-cargo-executable")
    need(all(r in selected or r["target"].get("kind") not in (["bin"], ["test"], ["example"], ["bench"], ["cdylib"])
             for r in artifacts), "app-absence-no-extra-executable")
    return binary


NATIVE_DATA_TESTS = ('installer::worker::app_absence_fixture::tests::fixed_transport_and_same_source_bindings', 'installer::worker::app_absence_fixture::tests::initial_fresh_install_and_same_gate_not_name_only', 'installer::worker::app_absence_fixture::tests::output_quote_and_original_exit_finality_are_separate', 'installer::worker::app_absence_fixture::tests::actual_restore_requires_new_app_and_exact_initial_history', 'installer::worker::app_absence_fixture::tests::exclusive_rename_metadata_and_record_bounds_are_not_identity_reset', 'installer::worker::app_absence_fixture::tests::phase_observations_are_pending_outer_exit_and_keep_private_fields_private')

def native_data_tests_result(result):
    need(type(result.returncode) is int and result.returncode == 0
         and type(result.stdout) is bytes and type(result.stderr) is bytes
         and 0 < len(result.stdout) and len(result.stdout) + len(result.stderr) <= 4*MIB
         and result.stdout.endswith(b"\n"), "app-absence-data-tests-original")
    lines = [line for line in result.stdout.split(b"\n") if line]
    need(len(lines) == 8 and lines[0] == b"running 6 tests", "app-absence-data-tests-count")
    expected = {("test " + name + " ... ok").encode("ascii") for name in NATIVE_DATA_TESTS}
    need(len(set(lines[1:7])) == 6 and set(lines[1:7]) == expected, "app-absence-data-tests-names")
    end = re.fullmatch(rb"test result: ok\. 6 passed; 0 failed; 0 ignored; 0 measured; ([0-9]{1,6}) filtered out; finished in ([0-9]{1,6}\.[0-9]{1,9})s", lines[-1])
    need(end is not None and float(end[2]) <= 1440, "app-absence-data-tests-summary")
    return {"schemaVersion": 1, "kind": "fixture-rust-data-test-observation", "methodNames": list(NATIVE_DATA_TESTS),
            "testCount": 6, "passed": 6, "failed": 0, "ignored": 0, "filteredCount": int(end[1]),
            "stdoutSha256": digest(result.stdout), "stderrSha256": digest(result.stderr), "productReady": False}


def script_quote(rows, program_bytes):
    need(type(rows) is dict and 0 < len(rows) <= 4096 and type(program_bytes) is int and 0 < program_bytes <= 64*MIB,
         "app-absence-script-quote")
    payload = sum(row["size"] for row in rows.values()) + program_bytes + len(POSTINSTALL) + MIB
    odc = payload + (len(rows) * 3 + 16) * 1200
    quote = odc + odc // 1000 + 65536 + 4*MIB
    need(quote <= PRODUCT_LIMIT, "app-absence-fixture-ineligible")
    return quote


def selected(op):
    return op.stager.BuildSelection(op.target, op.stager.build_release_data(op.read(op.release_entry), target=op.target)["packageVersion"], op.image_release)


def input_rows(op):
    entry, sha = retained(op, op.directory(op.work_entry, "input", "app-absence-input"),
                          op.stager.INSTALLATION_INVENTORY_NAME, MIB, (0o444,))
    body = op.read(entry)
    need(sha == op.environment["MRK_MACOS_INSTALL_INVENTORY_SHA256"], "app-absence-input-anchor")
    rows = op.stager.observation_inventory_bytes(body, sha, op.environment["MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"], selection=selected(op))
    return entry, rows


def tree_directory(op, parent, name, *, create=False):
    op.recheck_directory(parent)
    if create:
        os.mkdir(name, 0o700, dir_fd=parent["fd"])
    fd = os.open(name, op.app_absence_api.READ_FLAGS | os.O_DIRECTORY, dir_fd=parent["fd"])
    entry = op.register(fd, "app-absence-tree-directory", "directory", parent["fd"], name)
    entry["parent_entry"] = parent
    entry["identity"] = op.app_absence_api.directory_identity(os.fstat(fd))
    op.recheck_directory(entry)
    return entry


def tree_leaf(op, parent, name, row):
    op.recheck_directory(parent)
    fd = os.open(name, op.app_absence_api.READ_FLAGS, dir_fd=parent["fd"])
    entry = op.register(fd, "app-absence-tree-file", "file", parent["fd"], name)
    entry["parent_entry"] = parent
    info = os.fstat(fd)
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
         and info.st_gid == os.getgid() and stat.S_IMODE(info.st_mode) == row[2] and info.st_size == row[0],
         "app-absence-tree-file-shape")
    entry["identity"] = op.app_absence_api.signature(info)
    need(original_hash(op, entry) == row[1], "app-absence-tree-file-bytes")
    return entry


def copy_input(op, destination, inventory_entry, rows):
    source = op.directory(op.work_entry, "input", "app-absence-input")
    expected = {name: (row["size"], row["sha256"], 0o555 if row["executable"] else 0o444) for name, row in rows.items()}
    expected[op.stager.INSTALLATION_INVENTORY_NAME] = (inventory_entry["identity"][6], original_hash(op, inventory_entry), 0o444)
    paths = {""}
    for name in expected:
        parts = name.split("/")
        need(len(parts) <= 16, "app-absence-tree-depth")
        paths.update("/".join(parts[:i]) for i in range(1, len(parts)))
    need(6 * len(expected) + 6 * len(paths) + len(op.entries) + 256 <= 24576, "app-absence-tree-original-quote")
    originals = {}
    def visit(old, new, prefix):
        names = {name[len(prefix):].split("/")[0] for name in expected if name.startswith(prefix)}
        need(set(os.listdir(old["fd"])) == names, "app-absence-input-complete-roster")
        for name in sorted(names):
            path = prefix + name
            if path in expected:
                item = tree_leaf(op, old, name, expected[path])
                copied = copy(op, item, new, name, PRODUCT_LIMIT, mode=expected[path][2])
                originals[path] = (item["identity"], copied["identity"])
                op.app_absence["outputs"].remove(next(row for row in op.app_absence["outputs"] if row[0] is copied))
                for entry in (copied, item):
                    op.close(entry); need(entry["closed"], "app-absence-tree-close")
            else:
                old_child = tree_directory(op, old, name)
                new_child = tree_directory(op, new, name, create=True)
                visit(old_child, new_child, path + "/")
                for entry in (new_child, old_child):
                    op.close(entry); need(entry["closed"], "app-absence-tree-close")
        need(set(os.listdir(old["fd"])) == set(os.listdir(new["fd"])) == names, "app-absence-input-roster-post")
        os.fchmod(new["fd"], 0o555); os.fsync(new["fd"])
        new["identity"] = op.app_absence_api.directory_identity(os.fstat(new["fd"]))
        op.recheck_directory(old); op.recheck_directory(new)
    visit(source, destination, "")
    op.app_absence["inputCopies"] = (source, destination, expected, originals)


def input_post(op):
    source, destination, expected, originals = op.app_absence["inputCopies"]
    def visit(old, new, prefix):
        names = {name[len(prefix):].split("/")[0] for name in expected if name.startswith(prefix)}
        need(set(os.listdir(old["fd"])) == set(os.listdir(new["fd"])) == names, "app-absence-input-roster-post")
        for name in sorted(names):
            path = prefix + name
            if path in expected:
                left, right = tree_leaf(op, old, name, expected[path]), tree_leaf(op, new, name, expected[path])
                need((left["identity"], right["identity"]) == originals[path], "app-absence-input-original-post")
                for entry in (right, left):
                    op.close(entry); need(entry["closed"], "app-absence-tree-close")
            else:
                left, right = tree_directory(op, old, name), tree_directory(op, new, name)
                visit(left, right, path + "/")
                for entry in (right, left):
                    op.close(entry); need(entry["closed"], "app-absence-tree-close")
        op.recheck_directory(old); op.recheck_directory(new)
    visit(source, destination, "")


def prepare(op):
    api = op.app_absence_api
    inventory, rows = input_rows(op)
    environment = api.build_environment(op.environment, op.work, op.image_release, target=op.target)
    environment.update(CARGO_TARGET_DIR=str(op.work / op.target_name), TMPDIR=str(op.work / op.target_name / "tmp"),
        MRK_MACOS_INSTALL_INVENTORY_SHA256=op.environment["MRK_MACOS_INSTALL_INVENTORY_SHA256"],
        MRK_BUNDLED_RUNTIME_MANIFEST_SHA256=op.environment["MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"],
        MRK_BUNDLED_PROTOCOL_SHA256=op.stager.CURRENT_PROTOCOL,
        MRK_APP_ABSENCE_FIXTURE_SOURCE_COMMIT=op.image_source, MRK_APP_ABSENCE_FIXTURE_RUN_ID=op.environment["GITHUB_RUN_ID"],
        MRK_APP_ABSENCE_FIXTURE_RUN_ATTEMPT=op.environment["GITHUB_RUN_ATTEMPT"])
    result = call(op, "app-absence-build", [api.direct_rust_tools(op.target)[0], "build", "--manifest-path",
        str(op.checkout / "desktop/src-tauri/Cargo.toml"), "--locked", "--offline", "--release", "--jobs", "1", "--target", op.target,
        "--no-default-features", "--features", "macos-installed-app-absence-fixture", "--bin", FIXTURE_EXECUTABLE,
        "--message-format=json-render-diagnostics"], maximum=1440, limit=4*MIB, environment=environment, cwd=op.checkout / "desktop/src-tauri")
    binary_path = artifact_data(result.stdout, op.checkout, op.work / op.target_name, op.target)
    release = op.descend(op.target_entry, (op.target, "release"))
    binary = op.original(release, FIXTURE_EXECUTABLE, "app-absence-compiler-binary", 64*MIB, (0o700, 0o755), alias=True)
    program = op.read(binary)
    op.stager.macho(program, target=op.target)
    script_quote(rows, len(program))
    del program
    binary_sha = original_hash(op, binary)
    tests_entry = op.source_original("desktop/src-tauri/src/macos_app_absence_fixture.rs", "source-app-absence-data-tests", 2*MIB)
    tests_source = op.read(tests_entry)
    names = re.findall(rb"#\[test\]\s*fn ([A-Za-z0-9_]+)\(", tests_source)
    need(len(names) == 6 and {name.decode("ascii") for name in names} == {name.rsplit("::", 1)[1] for name in NATIVE_DATA_TESTS}
         and b"#[ignore" not in tests_source and b"#[should_panic" not in tests_source, "app-absence-data-tests-source")
    op.package_sources.append((tests_entry, tests_source))
    tested = call(op, "app-absence-data-tests", [api.direct_rust_tools(op.target)[0], "test", "--manifest-path",
        str(op.checkout / "desktop/src-tauri/Cargo.toml"), "--locked", "--offline", "--release", "--jobs", "1", "--target", op.target,
        "--no-default-features", "--features", "macos-installed-app-absence-fixture", "--bin", FIXTURE_EXECUTABLE,
        "--color", "never", "installer::worker::app_absence_fixture::tests::", "--", "--test-threads=1", "--color", "never"],
        maximum=1440, limit=4*MIB, environment=environment, cwd=op.checkout / "desktop/src-tauri")
    pure_tests = native_data_tests_result(tested)
    need(original_hash(op, binary) == binary_sha and op.read(tests_entry) == tests_source, "app-absence-data-tests-original-post")
    reserve(op, "executable")
    prepared = op.package_directory("app-absence-prepared")
    executable = copy(op, binary, prepared, FIXTURE_EXECUTABLE, 64*MIB, mode=0o555)
    op.close(binary); need(binary["closed"], "app-absence-compiler-close")
    op.app_absence["outputs"].remove(next(row for row in op.app_absence["outputs"] if row[0] is executable))
    op.close(executable); need(executable["closed"], "app-absence-presign-close")
    path = op.work / "app-absence-prepared" / FIXTURE_EXECUTABLE
    call(op, "app-absence-adhoc", ["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", str(path)])
    executable, program_sha = retained(op, prepared, FIXTURE_EXECUTABLE, 64*MIB, (0o555,))
    program = op.read(executable); op.stager.macho(program, target=op.target); del program
    call(op, "app-absence-verify-code", ["/usr/bin/codesign", "--verify", "--strict", str(path)])
    reserve(op, "scripts")
    scripts = op.package_directory("app-absence-scripts")
    output(op, scripts, "postinstall", POSTINSTALL, mode=0o555)
    copy(op, executable, scripts, FIXTURE_EXECUTABLE, 64*MIB, mode=0o555)
    projected = mkdir(op, scripts, "input")
    copy_input(op, projected, inventory, rows)
    os.fchmod(scripts["fd"], 0o755); scripts["identity"] = api.directory_identity(os.fstat(scripts["fd"]))
    op.app_absence["roots"].append((scripts, {"postinstall", FIXTURE_EXECUTABLE, "input"}))
    reserve(op, "original")
    original_path = op.work / "app-absence-original.pkg"
    call(op, "app-absence-pkgbuild", ["/usr/bin/pkgbuild", "--nopayload", "--scripts", str(op.work / "app-absence-scripts"),
        "--identifier", op.stager.PACKAGE_ID + "-app-absence-fixture", "--version", selected(op).package_version,
        "--install-location", "/", str(original_path)])
    original, original_sha = retained(op, op.work_entry, original_path.name, PRODUCT_LIMIT, (0o644, 0o444))
    args = SimpleNamespace(target=op.target, scripts=op.work / "app-absence-scripts", original_package=original_path,
        package=op.work / "app-absence-prepared/fixture.pkg", expected_program=program_sha,
        expected_inventory=op.environment["MRK_MACOS_INSTALL_INVENTORY_SHA256"])
    input_post(op)
    compact = io(op, "original-audit", op.stager.app_absence_original_command, args)
    need(compact["originalPackageSha256"] == original_sha, "app-absence-original-audit-post")
    output(op, prepared, "PackageInfo", compact["packageInfo"])
    reserve(op, "archive")
    call(op, "app-absence-tar", ["/usr/bin/tar", "-c", "-z", "-f", str(op.work / "app-absence-prepared/Scripts"),
        "--format=odc", "--uid=0", "--gid=0", "--uname=root", "--gname=wheel", "."], maximum=60, cwd=op.work / "app-absence-scripts")
    retained(op, prepared, "Scripts", PRODUCT_LIMIT, (0o644, 0o444))
    reserve(op, "fixture")
    call(op, "app-absence-xar", ["/usr/bin/xar", "-cf", str(args.package), "--compression=none", "PackageInfo", "Scripts"],
         cwd=op.work / "app-absence-prepared")
    fixture = op.original(prepared, "fixture.pkg", "app-absence-fixture-package", PRODUCT_LIMIT, (0o644, 0o444))
    os.fchmod(fixture["fd"], 0o444); fixture["identity"] = api.signature(os.fstat(fixture["fd"]))
    fixture_sha = original_hash(op, fixture)
    op.app_absence["outputs"].append((fixture, fixture_sha))
    audit = io(op, "final-audit", op.stager.app_absence_final_command, args, compact)
    del compact
    need(audit["packageSha256"] == fixture_sha and audit["packageSize"] == fixture["identity"][6], "app-absence-final-audit-post")
    op.app_absence["roots"].append((prepared, {FIXTURE_EXECUTABLE, "PackageInfo", "Scripts", "fixture.pkg"}))
    op.receipt["appAbsencePreparation"] = dict(op.app_absence["binding"], fixtureExecutableSha256=program_sha,
        fixtureExecutableBytes=executable["identity"][6], fixturePackageSha256=fixture_sha, fixturePackageBytes=fixture["identity"][6],
        inventorySha256=op.environment["MRK_MACOS_INSTALL_INVENTORY_SHA256"],
        runtimeManifestSha256=op.environment["MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"], protocolSha256=op.stager.CURRENT_PROTOCOL,
        cargoMessagesSha256=digest(result.stdout), pureDataTests=pure_tests, archiveAudited=True, adHocOnly=True, productReady=False)
    input_post(op)
    post(op); reserve(op)
    op.sha256 = fixture_sha
    op.app_absence["complete"] = True


def preparation_input(op):
    need(small(op, op.work_entry, "app-absence-preparation.status", 4) == b"0\n", "app-absence-prepare-original-zero")
    body = small(op, op.work_entry, "android-helper-prepare-app-absence.json")
    value = op.app_absence_api.tool_json(body)
    receipt_data(op, value, PREPARE, PREPARE_ROLES)
    data = value.get("appAbsencePreparation")
    need(type(data) is dict and all(data.get(k) == v for k, v in op.app_absence["binding"].items())
         and data.get("inventorySha256") == op.environment["MRK_MACOS_INSTALL_INVENTORY_SHA256"]
         and data.get("runtimeManifestSha256") == op.environment["MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"]
         and data.get("protocolSha256") == op.stager.CURRENT_PROTOCOL
         and data.get("archiveAudited") is True and data.get("adHocOnly") is True and data.get("productReady") is False,
         "app-absence-preparation-binding")
    tests = data.get("pureDataTests")
    need(type(tests) is dict and tests.get("methodNames") == list(NATIVE_DATA_TESTS)
         and all(type(tests.get(k)) is int and tests[k] == v for k,v in (("schemaVersion",1),("testCount",6),("passed",6),("failed",0),("ignored",0)))
         and tests.get("kind") == "fixture-rust-data-test-observation" and tests.get("productReady") is False
         and all(nonzero_hex_data(tests.get(k),64) and tests[k] == value["originalCalls"][1].get(k)
                 for k in ("stdoutSha256","stderrSha256")), "app-absence-prior-native-tests")
    root = op.directory(op.work_entry, "app-absence-prepared", "app-absence-prepared")
    need(set(os.listdir(root["fd"])) == {FIXTURE_EXECUTABLE, "PackageInfo", "Scripts", "fixture.pkg"}, "app-absence-prepared-roster")
    program, program_sha = retained(op, root, FIXTURE_EXECUTABLE, 64*MIB, (0o555,))
    fixture, fixture_sha = retained(op, root, "fixture.pkg", PRODUCT_LIMIT, (0o444,))
    need(program_sha == data.get("fixtureExecutableSha256") and program["identity"][6] == data.get("fixtureExecutableBytes")
         and fixture_sha == data.get("fixturePackageSha256") and fixture["identity"][6] == data.get("fixturePackageBytes"),
         "app-absence-prepared-originals")
    op.app_absence["preparation"] = data
    op.app_absence["preparationSha256"] = digest(body)
    return fixture


def receipt_data(op, value, phase, expected_roles):
    need(type(value) is dict and type(value.get("schemaVersion")) is int and value["schemaVersion"] == 1
         and value.get("phase") == phase and value.get("target") == op.target
         and value.get("source") == value.get("workflowSource") == op.image_source
         and value.get("workflow") == op.environment["GITHUB_WORKFLOW_REF"]
         and value.get("runId") == op.environment["GITHUB_RUN_ID"] and value.get("runAttempt") == op.environment["GITHUB_RUN_ATTEMPT"]
         and value.get("packageRole") == "ordinary-image" and value.get("cleanupErrors") == []
         and value.get("directStagerIOPending", False) is None and "failure" not in value
         and all(value.get(k) is True for k in ("passed", "targetRetired", "originalClosesKnown", "outerFinalityRequired")),
         "app-absence-prior-owner-finality")
    calls = value.get("originalCalls")
    need(type(calls) is list and len(calls) == len(expected_roles)
         and all(type(row) is dict and row.get("role") == role and row.get("returned") is True
             and row.get("capturesSettled") is True and type(row.get("returncode")) is int
             and (row["returncode"] == 0 or phase == "package-install" and role in ("installer-log-cursor", "installer-log-capture")
                  and row["returncode"] == 1) for row, role in zip(calls, expected_roles)), "app-absence-prior-owner-roster")
    if phase != "package-install":
        need(value.get("credentialOriginals") == value.get("credentialContexts") == [], "app-absence-no-credential-context")


def binding_for(op, rows):
    prepare = op.app_absence["preparation"]
    return dict(op.app_absence["binding"], packageSha256=rows["Install.pkg"]["sha256"],
        producerDescriptorSha256=rows["producer.json"]["sha256"], producerSignatureSha256=rows["producer.sig"]["sha256"],
        fixtureExecutableSha256=prepare["fixtureExecutableSha256"], inventorySha256=prepare["inventorySha256"],
        runtimeManifestSha256=prepare["runtimeManifestSha256"], protocolSha256=prepare["protocolSha256"])


def image_prepare(op, producer):
    fixture = preparation_input(op)
    root = op.package_directory("app-absence-carrier")
    reserve(op, "product")
    rows = {}
    for name, limit in (("Install.pkg", PRODUCT_LIMIT), ("producer.json", 16384), ("producer.sig", 16384)):
        old, sha = retained(op, producer, name, limit, (0o444,))
        entry = copy(op, old, root, name, limit)
        rows[name] = {"name": name, "bytes": entry["identity"][6], "sha256": sha, "mode": 0o444, "links": 1}
    reserve(op, "copies")
    for name in PHASE_NAMES:
        entry = copy(op, fixture, root, name, PRODUCT_LIMIT)
        rows[name] = {"name": name, "bytes": entry["identity"][6], "sha256": original_hash(op, entry), "mode": 0o444, "links": 1}
    transport_layout_data(list(rows.values()))
    op.app_absence["roots"].append((root, set(CARRIER_NAMES)))
    op.app_absence["layout"] = rows
    op.app_absence["nativeBinding"] = binding_for(op, rows)
    reserve(op, "image")
    path = op.work / "app-absence-fixture.dmg"
    call(op, "app-absence-image-create", ["/usr/bin/hdiutil", "create", "-srcfolder", str(op.work / "app-absence-carrier"),
        "-volname", "MRK App Absence Fixture", "-fs", "HFS+", "-format", "UDZO", str(path)], maximum=180)
    entry = op.original(op.work_entry, path.name, "app-absence-image", FIXTURE_IMAGE_LIMIT, (0o644, 0o444))
    os.fchmod(entry["fd"], 0o444); entry["identity"] = op.app_absence_api.signature(os.fstat(entry["fd"]))
    image_sha = original_hash(op, entry)
    op.app_absence["outputs"].append((entry, image_sha))
    op.app_absence["image"] = {"bytes": entry["identity"][6], "sha256": image_sha}
    call(op, "app-absence-image-verify", ["/usr/bin/hdiutil", "verify", str(path)], maximum=120)
    attach(op, "app-absence-baseline-attach", rows)


def mount_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def mounted_post(op):
    state = op.app_absence["mount"]
    if state is None or not state["known"] or state["detached"]:
        return
    entry = state["entry"]; api = op.app_absence_api
    need(entry["fd"] is not None and not entry["closed"]
         and mount_identity(os.fstat(entry["fd"])) == entry["identity"]
         == mount_identity(os.stat(state["name"], dir_fd=op.work_entry["fd"], follow_symlinks=False))
         and os.fstatvfs(entry["fd"]).f_flag & os.ST_RDONLY
         and entry["identity"][0] != op.work_entry["identity"][0]
         and set(os.listdir(entry["fd"])) == set(CARRIER_NAMES), "app-absence-readonly-mount-post")
    for leaf in state["files"]:
        identity = leaf["identity"]
        need(api.signature(os.fstat(leaf["fd"])) == identity
             == api.signature(os.stat(leaf["name"], dir_fd=entry["fd"], follow_symlinks=False)), "app-absence-mounted-original")
        h, offset = hashlib.sha256(), 0
        while offset < identity[6]:
            clock(op)
            chunk = os.pread(leaf["fd"], min(65536, identity[6] - offset), offset)
            need(chunk, "app-absence-mounted-short-read")
            h.update(chunk); offset += len(chunk)
        need(os.pread(leaf["fd"], 1, offset) == b"" and h.hexdigest() == leaf["sha256"]
             and api.signature(os.fstat(leaf["fd"])) == identity
             == api.signature(os.stat(leaf["name"], dir_fd=entry["fd"], follow_symlinks=False)), "app-absence-mounted-byte-post")


def attach(op, role, rows):
    need(role in ("app-absence-baseline-attach", "app-absence-restore-attach"), "app-absence-attach-role")
    name = "app-absence-mount"
    placeholder = op.package_directory(name)
    state = {"name": name, "placeholder": placeholder, "entered": False, "known": False, "detached": False,
             "entry": None, "device": None, "files": []}
    op.app_absence["mount"] = state
    result = call(op, role, ["/usr/bin/hdiutil", "attach", str(op.work / "app-absence-fixture.dmg"), "-readonly", "-nobrowse",
                  "-noautoopen", "-mountpoint", str(op.work / name), "-plist"], maximum=60)
    state["device"] = op.stager.distribution_mount_data(result.stdout, result.stderr, result.returncode, op.work / name)
    fd = os.open(name, op.app_absence_api.READ_FLAGS | os.O_DIRECTORY, dir_fd=op.work_entry["fd"])
    entry = op.register(fd, "app-absence-mount", "app-absence-mount", op.work_entry["fd"], name)
    entry["identity"] = mount_identity(os.fstat(fd)); state["entry"] = entry
    state["known"] = True
    need(set(rows) == set(CARRIER_NAMES) and set(os.listdir(fd)) == set(CARRIER_NAMES), "app-absence-mount-roster")
    for name in CARRIER_NAMES:
        file_fd = os.open(name, op.app_absence_api.READ_FLAGS, dir_fd=fd)
        leaf = op.register(file_fd, "app-absence-mounted-" + name, "app-absence-mounted-file", fd, name)
        info = os.fstat(file_fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o444
             and info.st_uid in (0, os.getuid()) and 0 < info.st_size == rows[name]["bytes"], "app-absence-mounted-shape")
        leaf["identity"] = op.app_absence_api.signature(info); leaf["sha256"] = rows[name]["sha256"]
        state["files"].append(leaf)
    mounted_post(op)


def detach(op, role):
    state = op.app_absence["mount"]
    need(role in ("app-absence-baseline-detach", "app-absence-restore-detach") and state is not None
         and state["known"] and not state["detached"] and op.app_absence["pendingRoot"] is None
         and op.package_settled(), "app-absence-detach-incomplete")
    post(op)
    for entry in state["files"] + [state["entry"]]:
        op.close(entry); need(entry["closed"], "app-absence-mount-close-unknown")
    state["closing"] = True
    result = op.package_call(role, ["/usr/bin/hdiutil", "detach", state["device"]], timeout=30)
    need(result.returncode == 0, "app-absence-detach-original")
    state["detached"] = True
    op.recheck_directory(state["placeholder"])
    need(not os.listdir(state["placeholder"]["fd"]), "app-absence-mount-placeholder")
    op.close(state["placeholder"]); need(state["placeholder"]["closed"], "app-absence-placeholder-close")
    os.rmdir(state["name"], dir_fd=op.work_entry["fd"])
    post(op)


def phase_observation(op, result, phase):
    need(phase in PROOFS and type(result.returncode) is int and result.returncode == 0 and type(result.stdout) is bytes and type(result.stderr) is bytes
         and len(result.stdout) + len(result.stderr) <= 256*1024, "app-absence-phase-output-bound")
    marker = b"MRK_MACOS_APP_ABSENCE_RESULT="
    found = []
    for stream in (result.stdout, result.stderr):
        need(stream.count(marker) <= 1, "app-absence-phase-marker-count")
        for line in stream.splitlines(keepends=True):
            if marker not in line:
                continue
            prefix, body = line.split(marker, 1)
            need(len(marker) + len(body) <= 4096 and body.endswith(b"\n")
                 and (not prefix or prefix[-1:] in b" :=>\t")
                 and all(32 <= byte < 127 or byte == 9 for byte in prefix), "app-absence-phase-marker-shape")
            found.append(body)
    need(len(found) == 1, "app-absence-phase-marker-count")
    value = op.app_absence_api.tool_json(found[0])
    need(json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n" == found[0],
         "app-absence-phase-canonical-json")
    need(type(value) is dict and set(value) == set(BINDING_FIELDS) | {"schemaVersion", "kind", "phase", "baselineSha256", "recordSha256",
         "proof", "originalOuterExitRequired", "systemServiceExitClaimed", "productReady"}
         and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and value["kind"] == "app-absence-phase-observation" and value["phase"] == phase
         and all(value[k] == v for k, v in op.app_absence["nativeBinding"].items())
         and nonzero_hex_data(value["baselineSha256"], 64) and nonzero_hex_data(value["recordSha256"], 64)
         and (phase != "baseline" or value["baselineSha256"] == value["recordSha256"])
         and value["originalOuterExitRequired"] is True and value["systemServiceExitClaimed"] is False and value["productReady"] is False
         and type(value["proof"]) is dict and set(value["proof"]) == set(PROOFS[phase])
         and all(v is True for v in value["proof"].values()), "app-absence-phase-observation")
    if phase != "baseline":
        need(value["baselineSha256"] == op.app_absence["baselineSha256"], "app-absence-baseline-unchanged")
    return value


def baseline_read(op, expected_sha):
    name = baseline_name_data(op.app_absence["binding"])
    with op.stager.installer_channel_parent(op.stager.INSTALL_ROOT) as (fd, _root_name):
        parent_before = os.fstat(fd)
        parent_identity = {"device": parent_before.st_dev, "inode": parent_before.st_ino, "mode": parent_before.st_mode,
                           "uid": parent_before.st_uid, "gid": parent_before.st_gid}
        before = os.stat(name, dir_fd=fd, follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == before.st_gid == 0
             and stat.S_IMODE(before.st_mode) == 0o444 and 0 < before.st_size <= RECORD_LIMIT, "app-absence-baseline-original")
        body, actual = op.stager.read_at(fd, name, RECORD_LIMIT)
        parent_after = os.fstat(fd)
        need(op.app_absence_api.signature(before) == op.app_absence_api.signature(actual) and digest(body) == expected_sha
             and parent_identity == {"device": parent_after.st_dev, "inode": parent_after.st_ino, "mode": parent_after.st_mode,
                                     "uid": parent_after.st_uid, "gid": parent_after.st_gid}, "app-absence-baseline-original-post")
    value = op.stager.maintenance_json(body, RECORD_LIMIT)
    need(type(value) is dict and set(value) == {"schemaVersion", "kind", "binding", "rootNonce", "parentIdentity", "privateIdentity",
         "siblingCensusSha256", "siblingCount", "rootAbsent", "transportState"}
         and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["kind"] == "app-absence-baseline"
         and value["binding"] == op.app_absence["nativeBinding"] and nonzero_hex_data(value["rootNonce"], 32)
         and nonzero_hex_data(value["siblingCensusSha256"], 64) and type(value["siblingCount"]) is int and 0 <= value["siblingCount"] <= 512
         and value["rootAbsent"] is True and value["transportState"] == "pending-original-exit", "app-absence-baseline-binding")
    for key in ("parentIdentity", "privateIdentity"):
        row = value[key]
        need(type(row) is dict and set(row) == {"device", "inode", "mode", "uid", "gid"}
             and all(type(v) is int for v in row.values()) and -(2**63) <= row["device"] < 2**63
             and 0 < row["inode"] < 2**64 and all(0 <= row[k] < 2**32 for k in ("mode", "uid", "gid"))
             and row["uid"] == 0 and stat.S_ISDIR(row["mode"]), "app-absence-baseline-identity")
    need(value["parentIdentity"] == parent_identity and value["privateIdentity"]["gid"] == 0
         and stat.S_IMODE(value["privateIdentity"]["mode"]) == 0o700, "app-absence-baseline-parent-original")
    need(value["parentIdentity"]["device"] == value["privateIdentity"]["device"], "app-absence-baseline-volume")
    return {"bytes": len(body), "sha256": expected_sha, "identity": list(op.app_absence_api.signature(actual))}


def root_call(op, phase):
    index = {"baseline": 0, "withdraw": 1, "verify": 2}[phase]
    role = "app-absence-" + phase
    reserve(op)
    result = call(op, role, ["/usr/bin/sudo", "-n", "--", "/usr/sbin/installer", "-pkg",
        str(op.work / "app-absence-mount" / PHASE_NAMES[index]), "-target", "/", "-dumplog", "-verboseR"], maximum=123, limit=256*1024)
    return phase_observation(op, result, phase)


def baseline(op):
    observed = root_call(op, "baseline")
    op.app_absence["baselineSha256"] = observed["baselineSha256"]
    op.app_absence["baselineOriginal"] = io(op, "baseline-read", baseline_read, op, observed["baselineSha256"])
    op.app_absence["baselineObservation"] = observed


def initial_readback(op, observed):
    need(type(observed) is dict and observed.get("schemaVersion") == 2
         and observed.get("originalInstallerReturnedZero") is True and observed.get("originalWriterJoined") is True
         and observed.get("originalInstallerResult", {}).get("action") == "fresh-install"
         and observed["originalInstallerResult"].get("writerState") == "installed"
         and observed["sourceCommit"] == op.image_source and observed["inventorySha256"] == op.environment["MRK_MACOS_INSTALL_INVENTORY_SHA256"]
         and observed["runtimeManifestSha256"] == op.environment["MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"]
         and observed["completedPackageSha256"] == op.app_absence["nativeBinding"]["packageSha256"], "app-absence-initial-fresh-only")
    census = io(op, "initial-census", op.stager.same_package_result_census)
    request = observed["requestId"]
    need(set(census) == {request} and census[request] == {k: observed["installerResultExport"][k] for k in ("bytes", "sha256", "identity")},
         "app-absence-one-fresh-export")
    need(io(op, "baseline-post", baseline_read, op, op.app_absence["baselineSha256"]) == op.app_absence["baselineOriginal"],
         "app-absence-baseline-changed")
    op.app_absence["initial"] = {"requestId": request, "invocation": observed["invocation"],
        "stateSha256": observed["originalInstallerResult"]["stateSha256"], "resultSha256": census[request]["sha256"],
        "instance": observed["installationMetadata"][0]["instance"]}
    op.app_absence["initialCensus"] = census


def package_complete(op):
    need(op.installer_zero and op.installation_readback and op.mount_detached and "initial" in op.app_absence,
         "app-absence-initial-completion")
    detach(op, "app-absence-baseline-detach")
    op.receipt["appAbsenceBaseline"] = {"schemaVersion": 1, "binding": op.app_absence["nativeBinding"],
        "preparationReceiptSha256": op.app_absence["preparationSha256"], "layout": op.app_absence["layout"],
        "image": op.app_absence["image"], "baselineSha256": op.app_absence["baselineSha256"],
        "baselineOriginal": op.app_absence["baselineOriginal"], "baselineObservation": op.app_absence["baselineObservation"],
        "initial": op.app_absence["initial"], "initialFreshInstall": True, "initialExportCount": 1,
        "originalBaselineZero": True, "originalMountDetached": True, "systemServiceExitClaimed": False, "productReady": False}
    op.app_absence["complete"] = True


def restore(op):
    preparation_input(op)
    need(small(op, op.work_entry, "package-install.status", 4) == b"0\n", "app-absence-baseline-caller-zero")
    body = small(op, op.work_entry, "android-helper-package-install.json")
    owner = op.app_absence_api.tool_json(body)
    receipt_data(op, owner, "package-install", package_roles(op.stager.PACKAGING_CALL_ROLES))
    previous = owner.get("appAbsenceBaseline")
    need(type(previous) is dict and previous.get("initialFreshInstall") is True and previous.get("initialExportCount") == 1
         and previous.get("originalBaselineZero") is True and previous.get("originalMountDetached") is True
         and previous.get("preparationReceiptSha256") == op.app_absence["preparationSha256"]
         and previous.get("productReady") is False and previous.get("systemServiceExitClaimed") is False,
         "app-absence-baseline-owner")
    rows = previous["layout"]
    transport_layout_data(list(rows.values()))
    need(previous["binding"] == binding_for(op, rows), "app-absence-same-native-binding")
    op.app_absence.update(nativeBinding=previous["binding"], baselineSha256=previous["baselineSha256"],
                         baselineOriginal=previous["baselineOriginal"])
    need(io(op, "baseline-read", baseline_read, op, previous["baselineSha256"]) == previous["baselineOriginal"], "app-absence-baseline-original")
    image, image_sha = retained(op, op.work_entry, "app-absence-fixture.dmg", FIXTURE_IMAGE_LIMIT, (0o444,))
    need(previous["image"] == {"bytes": image["identity"][6], "sha256": image_sha}, "app-absence-image-same-original")
    carrier = op.directory(op.work_entry, "app-absence-carrier", "app-absence-carrier")
    need(set(os.listdir(carrier["fd"])) == set(CARRIER_NAMES), "app-absence-carrier-roster")
    for name in CARRIER_NAMES:
        entry, sha = retained(op, carrier, name, PRODUCT_LIMIT, (0o444,))
        need(rows[name]["bytes"] == entry["identity"][6] and rows[name]["sha256"] == sha, "app-absence-carrier-post")
    attach(op, "app-absence-restore-attach", rows)
    initial = previous["initial"]
    args = SimpleNamespace(target=op.target, fixture=False, input=op.work / "input", expected_source=op.image_source,
        expected_inventory=op.environment["MRK_MACOS_INSTALL_INVENTORY_SHA256"], expected_manifest=op.environment["MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"],
        request_id=initial["requestId"], expected_package=previous["binding"]["packageSha256"],
        producer_descriptor=op.work / "app-absence-mount/producer.json", producer_signature=op.work / "app-absence-mount/producer.sig",
        installer_status=op.work / "installer-output.status", package=op.work / "app-absence-mount/Install.pkg")
    observed = io(op, "initial-readback", op.stager.observation_command, args)
    initial_readback(op, observed)
    need(op.app_absence["initial"] == initial, "app-absence-initial-state-post")
    before = op.app_absence["initialCensus"]
    case = op.package_directory("app-absence-case")
    projected = mkdir(op, case, "input")
    inventory, _rows = input_rows(op)
    copy(op, inventory, projected, op.stager.INSTALLATION_INVENTORY_NAME, MIB)
    op.app_absence["roots"].append((projected, {op.stager.INSTALLATION_INVENTORY_NAME}))
    op.app_absence["case"] = case
    args.input = op.work / "app-absence-case/input"
    args.installer_status = op.work / "app-absence-case/installer-output.status"
    withdraw = root_call(op, "withdraw")
    need(withdraw["proof"]["renameKnownSuccess"] is True, "app-absence-known-withdraw-required")
    result = call(op, "app-absence-install", ["/usr/bin/sudo", "-n", "--", "/usr/sbin/installer", "-pkg", str(args.package),
        "-target", "/", "-dumplog", "-verboseR"], maximum=123, limit=256*1024)
    after = io(op, "restore-census", op.stager.same_package_result_census)
    args.request_id = op.stager.same_package_new_request(before, after, initial["requestId"])
    expected = {"invocation": initial["invocation"], "sha256": initial["stateSha256"]}
    restored = io(op, "restore-readback", op.stager.observation_command, args, expected_restore_previous=expected)
    need(restored.get("restorePredecessorMatched") is True and restored["invocation"] != initial["invocation"]
         and restored["installationMetadata"][0]["instance"] == initial["instance"]
         and after[args.request_id] == {k: restored["installerResultExport"][k] for k in ("bytes", "sha256", "identity")},
         "app-absence-ordinary-restore-correspondence")
    verify = root_call(op, "verify")
    need(io(op, "restore-census-post", op.stager.same_package_result_census) == after
         and io(op, "baseline-final", baseline_read, op, previous["baselineSha256"]) == previous["baselineOriginal"], "app-absence-evidence-post")
    detach(op, "app-absence-restore-detach")
    op.receipt["appAbsenceRestore"] = {"schemaVersion": 1, "binding": previous["binding"],
        "preparationReceiptSha256": op.app_absence["preparationSha256"], "baselineOwnerReceiptSha256": digest(body),
        "imageSha256": image_sha, "baselineSha256": previous["baselineSha256"],
        "initialResultSha256": initial["resultSha256"], "restoreResultSha256": after[args.request_id]["sha256"],
        "withdraw": withdraw, "verify": verify, "initialFreshInstall": True, "restoreFixedAppObserved": True,
        "immediatePredecessorMatched": True, "currentBytesVerified": True, "initialHistoryPreserved": True,
        "beforeExportCount": 1, "afterExportCount": 2, "newExportCount": 1, "verifiedCurrentFiles": restored["nonrootReadbackFileCount"],
        "originalInstallerReturnedZero": True, "originalMountDetached": True, "retainedPrivateEvidence": True,
        "systemServiceExitClaimed": False, "productReady": False}
    op.sha256 = image_sha
    op.app_absence["complete"] = True
    post(op)


def save_restore_status(op, code):
    need(op.phase == RESTORE and type(code) is int and op.app_absence["pendingRoot"] == "app-absence-install",
         "app-absence-status-purpose")
    output(op, op.app_absence["case"], "installer-output.status", (str(code) + "\n").encode("ascii"), mode=0o600)
