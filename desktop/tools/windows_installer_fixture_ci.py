"""Fixed retained-shell fixture DATA/compiler integration, never a process owner.

Only the reviewed windows-installed-native hosted route calls phase(). The
separate16-original historical or54-original selection episode and three raw-pipe probes belong exclusively to
the directly retained PowerShell owner. foundation.run is compiler/supplier only.
No Store, vendor installer, shell payload, production GUI or release is invoked.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import tomllib

PROFILE = "windows-installer-retained-shell-v1"
DISPATCH = "windows-installer-retained-shell"
REF = "refs/heads/verify/desktop-windows-installer-retained-shell"
TARGET = "x86_64-pc-windows-msvc"
CASES = ("fresh", "reuse", "stop-copy", "wrong-caller", "bad-manifest")
PROBES = ("balanced", "overflow", "writer-fault")
CHAIN = tuple((case, role) for case in CASES
              for role in (("stage", "corrupt", "app", "observe") if case == "bad-manifest"
                           else ("stage", "app", "observe")))
FLAGS = ("--exact", "--ignored", "--nocapture", "--test-threads=1")
PHASES = ("windows-retained-probes-finalize", "windows-retained-precheck", "windows-retained-finalize")
PRE_HEADER = "MRK_WINDOWS_RETAINED_SHELL_PRECHECK_V1"
PRE_KEYS = ("profile", "sourceSha", "sourceTree", "runId", "attempt", "sourceInventorySha256",
    "profilesSha256", "rosterSha256", "nativeArtifact", "nativeArtifactBytes", "nativeArtifactSha256",
    "nativeArtifactIdentity", "nativeCompileMessagesSha256", "nativeCompileArgvSha256",
    "appArtifact", "appArtifactBytes", "appArtifactSha256", "appArtifactIdentity",
    "appCompileMessagesSha256", "appCompileArgvSha256", "preparedRuntimeSha256")
EXIT_HEADER = "MRK_WINDOWS_RETAINED_SHELL_ORIGINAL_EXIT_V1"
EXIT_KEYS = ("profile", "sourceSha", "sourceTree", "runId", "attempt", "role", "artifactSha256",
    "precheckSha256", "commandSha256", "resultBytes", "resultSha256", "originalWaitReturned",
    "exitCode", "writerCloseGate")
SNAP_HEADER = "MRK_WINDOWS_RETAINED_SHELL_SNAPSHOT_V1"
SNAP_KEYS = ("profile", "sourceSha", "sourceTree", "runId", "attempt", "case", "phase",
    "precheckSha256", "profilesSha256", "rosterSha256", "image", "manifest", "candidate", "freshMrkAbsent",
    "objects", "fileOriginals", "fileOriginalsClosed", "parentBookSettled", "unknown", "resultCloseGate")
APP_PREFIX = "MRK_WINDOWS_RETAINED_SHELL_CASE_V1="
APP_KEYS = ("case", "rows", "sourceRead", "confirmedWritten", "readbackRead", "prerequisite",
    "runtime", "activation", "roles", "transitions", "originalWatchdogJoined", "nativeSettled")
NATIVE_FEATURES = ("installer-acquisition", "installer-protected-fixture", "qualification-result", "runtime-publication")
APP_FEATURES = ("windows-installer-acquisition", "windows-installer-profile", "windows-installer-protected-fixture")
SELECTED_FEATURES = {"native": "installer-protected-fixture", "app": "windows-installer-protected-fixture"}
NATIVE_PACKAGES = {
    "mrk-windows-installed-native": "0.1.0", "windows-sys": "0.61.2", "windows-link": "0.2.1",
    "sha2": "0.10.9", "cfg-if": "1.0.5", "cpufeatures": "0.2.17", "digest": "0.10.7",
    "block-buffer": "0.10.4", "crypto-common": "0.1.7", "generic-array": "0.14.7",
    "typenum": "1.20.1", "version_check": "0.9.5",
}
NATIVE_EDGES = {
    "mrk-windows-installed-native": {"sha2", "windows-sys"}, "windows-sys": {"windows-link"},
    "windows-link": set(), "sha2": {"cfg-if", "cpufeatures", "digest"}, "cfg-if": set(),
    "cpufeatures": set(), "digest": {"block-buffer", "crypto-common"},
    "block-buffer": {"generic-array"}, "crypto-common": {"generic-array", "typenum"},
    "generic-array": {"typenum", "version_check"}, "typenum": set(), "version_check": set(),
}
COMPILER_CHECKS = {
    "acquire": "retained-compiler-acquire",
    "native-metadata": "retained-native-locked-metadata",
    "app-metadata": "retained-app-locked-metadata",
    "native-compile": "retained-native-compile-only",
    "app-compile": "retained-app-compile-only",
}
TOOLS = ("windows_installer_fixture_ci.py", "windows_installer_fixture_owner.ps1",
    "windows_installer_fixture_pipe_probe.py", "windows_installer_fixture_data.py",
    "windows_installer_profile.py", "windows_installer_source.py", "stage_windows_installer.py")
NOT_VERIFIED = (
    "shipping-installer-or-normal-GUI", "opaque-fixture-PE-validity-or-signatures",
    "vendor-prerequisite-installation", "production-distribution-signing",
    "non-fixture-arbitrary-user-projects", "Store-or-release-operations",
    "unknown-native-completion-fault-injection", "physical-device-or-physical-Mac",
)

# This second episode is a fresh VM route, never appended to historical five.
SELECTION_PROFILE = "windows-installer-selection-v1"
SELECTION_DISPATCH = "windows-installer-selection"
SELECTION_PHASES = ("windows-selection-finalize",)
SELECTION_NATIVE_FEATURES = tuple(sorted((*NATIVE_FEATURES, "installer-selection", "installer-selection-fixture")))
SELECTION_APP_FEATURES = tuple(sorted((*APP_FEATURES, "windows-installer-selection", "windows-installer-selection-fixture")))
SELECTION_SELECTED_FEATURES = {"native": "installer-selection-fixture", "app": "windows-installer-selection-fixture"}
SELECTION_OUTPUT_BUDGET = 5_947_392
SELECTION_ACCOUNT_PREFIX = "MRK_WINDOWS_SELECTION_ACCOUNTING_V1="
SELECTION_PREVIEW_PREFIX = "MRK_WINDOWS_SELECTION_PREVIEW_V1="
SELECTION_RECOVERY_PREFIX = "MRK_WINDOWS_SELECTION_RECOVERY_V1="
SELECTION_CASE_PREFIX = "MRK_WINDOWS_SELECTION_CASE_V1="
SELECTION_CASE_KEYS = ("case", "disposition", "inputs", "runtime", "closedRecords", "phaseMask",
    "charged", "confirmed", "originalWatchdogJoined", "nativeSettled")
SELECTION_ACCOUNT_HEAD = ("version", "profile", "sourceSha", "sourceTree", "runId", "attempt", "case",
    "previewObservationSha256", "recoveryRun", "inputs", "runtime", "readonlyClosed",
    "conflictStaged", "conflictReturned", "competitorClosed", "competitorPresent")
SELECTION_ACCOUNT_REPORT = ("mode", "stage", "disposition", "firstFailure", "oldMoveEntered", "newMoveEntered",
    "registryCommitEntered", "registryCommitted", "nativeClosed", "oldMoveNative", "newMoveNative",
    "registryNative", "flushedRecords", "closedRecords", "phaseMask", "writeCountUnknown",
    "charged", "confirmed", "retainedBytes", "controllerFinalityRequired", "shippingInstallerEnabled", "outputs")
SELECTION_SNAP_HEADER = "MRK_WINDOWS_SELECTION_SNAPSHOT_V1"
SELECTION_SNAP_KEYS = ("profile", "sourceSha", "sourceTree", "runId", "attempt", "role", "precheckSha256",
    "profilesSha256", "rosterSha256", "programFiles", "commonPrograms", "candidate", "freshMrkAbsent",
    "selectorImage", "registrationImage", "registrationSha256", "registrationSecurityDigest",
    "registrationParentSha256", "registrationWrite", "trees", "objects", "damagedShell", "foreignSelector",
    "accountedRuns", "fileOriginals", "fileOriginalsClosed", "parentBookSettled", "selectionPrimitivesClosed",
    "unknown", "resultCloseGate")
SELECTION_PREVIEW_KEYS = ("version", "mode", "beforeImage", "afterImage", "runtime", "coreVersion",
    "shortcutPath", "registrationPath", "observationSha256", "preservedPaths", "retainedImageBytesObserved", "warning")
SELECTION_REGISTRATION = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MobileReleaseKit"
SELECTION_WARNING = ("Launch entries can be partially changed if Windows refuses a later step. "
    "Existing application images, runtime files, projects, credentials and evidence remain retained. "
    "Recovery requires a new preview and verification; this is not a full uninstall.")
SELECTION_SOURCES = ("fresh", "reuse", "wrong-caller", "bad-manifest")
# input profile, wire mode, previous preview, previous STOP, emits preview,
# actual acquisition, emits recovery. Every key is a literal reviewed app case.
SELECTION_CASE_CONFIG = {
    "preview-fresh": ("fresh", "install-activated", None, None, True, False, False),
    "select-fresh": ("fresh", "install-activated", "preview-fresh", None, False, True, False),
    "preview-reuse": ("reuse", "install-activated", None, None, True, False, False),
    "select-reuse": ("reuse", "install-activated", "preview-reuse", None, False, True, False),
    "preview-verify-reuse": ("reuse", "verify-and-restore-launch-entries", None, None, True, False, False),
    "verify-reuse": ("reuse", "verify-and-restore-launch-entries", "preview-verify-reuse", None, False, False, False),
    "preview-remove-reuse": ("reuse", "remove-launch-entries", None, None, True, False, False),
    "remove-reuse": ("reuse", "remove-launch-entries", "preview-remove-reuse", None, False, False, False),
    "refuse-stale-repair": ("reuse", "verify-and-restore-launch-entries", "preview-verify-reuse", None, False, False, False),
    "preview-repair-reuse": ("reuse", "verify-and-restore-launch-entries", None, None, True, False, False),
    "repair-reuse": ("reuse", "verify-and-restore-launch-entries", "preview-repair-reuse", None, False, False, False),
    "preview-registry-conflict": ("reuse", "remove-launch-entries", None, None, True, False, False),
    "registry-conflict": ("reuse", "remove-launch-entries", "preview-registry-conflict", None, False, False, False),
    "preview-stop-old": ("wrong-caller", "install-activated", None, None, True, False, False),
    "stop-old": ("wrong-caller", "install-activated", "preview-stop-old", None, False, True, True),
    "preview-previous": ("wrong-caller", "recover-previous-launch-selection", None, "stop-old", True, False, False),
    "recover-previous": ("wrong-caller", "recover-previous-launch-selection", "preview-previous", "stop-old", False, False, False),
    "preview-stop-new": ("bad-manifest", "install-activated", None, None, True, False, False),
    "stop-new": ("bad-manifest", "install-activated", "preview-stop-new", None, False, True, True),
    "preview-current": ("bad-manifest", "recover-current-launch-selection", None, "stop-new", True, False, False),
    "recover-current": ("bad-manifest", "recover-current-launch-selection", "preview-current", "stop-new", False, False, False),
    "preview-remove-damaged": ("bad-manifest", "remove-launch-entries", None, None, True, False, False),
    "remove-damaged": ("bad-manifest", "remove-launch-entries", "preview-remove-damaged", None, False, False, False),
    "refuse-foreign-selector": ("reuse", "verify-and-restore-launch-entries", None, None, False, False, False),
}
SELECTION_CHAIN = (
    ("stage-fresh", "native-stage", "qualification_fixture::installer::selection::stage_fresh"),
    ("preview-fresh", "app", "windows_installer_controller::selection_fixture::preview_fresh"),
    ("preview-fresh-observe", "native-observe", "qualification_fixture::installer::selection::observe_preview_fresh"),
    ("select-fresh", "app", "windows_installer_controller::selection_fixture::select_fresh"),
    ("select-fresh-observe", "native-observe", "qualification_fixture::installer::selection::observe_select_fresh"),
    ("stage-reuse", "native-stage", "qualification_fixture::installer::selection::stage_reuse"),
    ("preview-reuse", "app", "windows_installer_controller::selection_fixture::preview_reuse"),
    ("preview-reuse-observe", "native-observe", "qualification_fixture::installer::selection::observe_preview_reuse"),
    ("select-reuse", "app", "windows_installer_controller::selection_fixture::select_reuse"),
    ("select-reuse-observe", "native-observe", "qualification_fixture::installer::selection::observe_select_reuse"),
    ("preview-verify-reuse", "app", "windows_installer_controller::selection_fixture::preview_verify_reuse"),
    ("preview-verify-reuse-observe", "native-observe", "qualification_fixture::installer::selection::observe_preview_verify_reuse"),
    ("verify-reuse", "app", "windows_installer_controller::selection_fixture::verify_reuse"),
    ("verify-reuse-observe", "native-observe", "qualification_fixture::installer::selection::observe_verify_reuse"),
    ("preview-remove-reuse", "app", "windows_installer_controller::selection_fixture::preview_remove_reuse"),
    ("preview-remove-reuse-observe", "native-observe", "qualification_fixture::installer::selection::observe_preview_remove_reuse"),
    ("remove-reuse", "app", "windows_installer_controller::selection_fixture::remove_reuse"),
    ("remove-reuse-observe", "native-observe", "qualification_fixture::installer::selection::observe_remove_reuse"),
    ("refuse-stale-repair", "app", "windows_installer_controller::selection_fixture::refuse_stale_repair"),
    ("refuse-stale-repair-observe", "native-observe", "qualification_fixture::installer::selection::observe_refuse_stale_repair"),
    ("preview-repair-reuse", "app", "windows_installer_controller::selection_fixture::preview_repair_reuse"),
    ("preview-repair-reuse-observe", "native-observe", "qualification_fixture::installer::selection::observe_preview_repair_reuse"),
    ("repair-reuse", "app", "windows_installer_controller::selection_fixture::repair_reuse"),
    ("repair-reuse-observe", "native-observe", "qualification_fixture::installer::selection::observe_repair_reuse"),
    ("preview-registry-conflict", "app", "windows_installer_controller::selection_fixture::preview_registry_conflict"),
    ("preview-registry-conflict-observe", "native-observe", "qualification_fixture::installer::selection::observe_preview_registry_conflict"),
    ("registry-conflict", "app", "windows_installer_controller::selection_fixture::registry_conflict"),
    ("registry-conflict-observe", "native-observe", "qualification_fixture::installer::selection::observe_registry_conflict"),
    ("stage-wrong-caller", "native-stage", "qualification_fixture::installer::selection::stage_wrong_caller"),
    ("preview-stop-old", "app", "windows_installer_controller::selection_fixture::preview_stop_old"),
    ("preview-stop-old-observe", "native-observe", "qualification_fixture::installer::selection::observe_preview_stop_old"),
    ("stop-old", "app", "windows_installer_controller::selection_fixture::stop_old"),
    ("stop-old-observe", "native-observe", "qualification_fixture::installer::selection::observe_stop_old"),
    ("preview-previous", "app", "windows_installer_controller::selection_fixture::preview_previous"),
    ("preview-previous-observe", "native-observe", "qualification_fixture::installer::selection::observe_preview_previous"),
    ("recover-previous", "app", "windows_installer_controller::selection_fixture::recover_previous"),
    ("recover-previous-observe", "native-observe", "qualification_fixture::installer::selection::observe_recover_previous"),
    ("stage-bad-manifest", "native-stage", "qualification_fixture::installer::selection::stage_bad_manifest"),
    ("preview-stop-new", "app", "windows_installer_controller::selection_fixture::preview_stop_new"),
    ("preview-stop-new-observe", "native-observe", "qualification_fixture::installer::selection::observe_preview_stop_new"),
    ("stop-new", "app", "windows_installer_controller::selection_fixture::stop_new"),
    ("stop-new-observe", "native-observe", "qualification_fixture::installer::selection::observe_stop_new"),
    ("preview-current", "app", "windows_installer_controller::selection_fixture::preview_current"),
    ("preview-current-observe", "native-observe", "qualification_fixture::installer::selection::observe_preview_current"),
    ("recover-current", "app", "windows_installer_controller::selection_fixture::recover_current"),
    ("recover-current-observe", "native-observe", "qualification_fixture::installer::selection::observe_recover_current"),
    ("damage-owned-shell", "native-setup", "qualification_fixture::installer::selection::damage_owned_shell"),
    ("preview-remove-damaged", "app", "windows_installer_controller::selection_fixture::preview_remove_damaged"),
    ("preview-remove-damaged-observe", "native-observe", "qualification_fixture::installer::selection::observe_preview_remove_damaged"),
    ("remove-damaged", "app", "windows_installer_controller::selection_fixture::remove_damaged"),
    ("remove-damaged-observe", "native-observe", "qualification_fixture::installer::selection::observe_remove_damaged"),
    ("stage-owned-foreign-selector", "native-setup", "qualification_fixture::installer::selection::stage_owned_foreign_selector"),
    ("refuse-foreign-selector", "app", "windows_installer_controller::selection_fixture::refuse_foreign_selector"),
    ("refuse-foreign-selector-observe", "native-observe", "qualification_fixture::installer::selection::observe_refuse_foreign_selector"),
)
SELECTION_ROLES = tuple(row[0] for row in SELECTION_CHAIN)
SELECTION_ROUTES = {row[0]: row[1:] for row in SELECTION_CHAIN}
SELECTION_NATIVE_OPEN_BUDGET = {
    "stage-fresh": 226,
    "preview-fresh-observe": 112,
    "select-fresh-observe": 252,
    "stage-reuse": 425,
    "preview-reuse-observe": 317,
    "select-reuse-observe": 397,
    "preview-verify-reuse-observe": 399,
    "verify-reuse-observe": 401,
    "preview-remove-reuse-observe": 403,
    "remove-reuse-observe": 411,
    "refuse-stale-repair-observe": 413,
    "preview-repair-reuse-observe": 415,
    "repair-reuse-observe": 424,
    "preview-registry-conflict-observe": 426,
    "registry-conflict-observe": 429,
    "stage-wrong-caller": 602,
    "preview-stop-old-observe": 494,
    "stop-old-observe": 569,
    "preview-previous-observe": 571,
    "recover-previous-observe": 580,
    "stage-bad-manifest": 753,
    "preview-stop-new-observe": 645,
    "stop-new-observe": 722,
    "preview-current-observe": 724,
    "recover-current-observe": 735,
    "damage-owned-shell": 804,
    "preview-remove-damaged-observe": 737,
    "remove-damaged-observe": 745,
    "stage-owned-foreign-selector": 756,
    "refuse-foreign-selector-observe": 748,
}


class FixtureError(ValueError):
    pass


def need(condition: bool, message: str) -> None:
    if not condition:
        raise FixtureError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def number(value: object, maximum: int, minimum: int = 0) -> int:
    need(type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,19}", value) is not None, "Noncanonical decimal")
    result = int(value)
    need(minimum <= result <= maximum, "Decimal exceeds its fixed role")
    return result


def wire(raw: bytes, header: str, keys: tuple[str, ...], limit: int = 65536) -> dict[str, str]:
    need(type(raw) is bytes and 0 < len(raw) <= limit and raw.isascii() and raw.endswith(b"\n")
         and all(byte == 10 or 32 <= byte <= 126 for byte in raw), "Closed wire framing differs")
    lines = raw[:-1].decode("ascii").split("\n")
    need(len(lines) == len(keys) + 1 and lines[0] == header, "Closed wire header/count differs")
    result = {}
    for line, key in zip(lines[1:], keys, strict=True):
        name, separator, value = line.partition("=")
        need(name == key and separator == "=" and value and "=" not in value, "Closed wire key/order differs")
        if key.endswith("Sha256"):
            need(re.fullmatch(r"[0-9a-f]{64}", value) is not None and value != "0"*64, "Wire digest differs")
        result[key] = value
    return result


def encoded_wire(header: str, keys: tuple[str, ...], values: dict) -> bytes:
    need(set(values) == set(keys), "Output wire fields differ")
    raw = (header + "\n" + "".join(f"{key}={values[key]}\n" for key in keys)).encode("ascii")
    wire(raw, header, keys)
    return raw


def binding(context: dict) -> dict[str, str]:
    profile = context.get("qualificationProfile")
    need(profile in (PROFILE, SELECTION_PROFILE) and context.get("ref") == REF
         and context.get("attempt") == 1 and context.get("event") == "workflow_dispatch"
         and context.get("scope") == "windows-installed-native-v1", "Fixture context is not the closed route")
    return {"profile": profile, **{key: str(context[key]) for key in ("sourceSha", "sourceTree", "runId", "attempt")}}


def require_bound(value: dict, context: dict) -> None:
    need(all(value.get(key) == item for key, item in binding(context).items()), "Fixture source/run/profile differs")


def selector(case: str, role: str) -> str:
    need((case, role) in CHAIN, "Not a fixed behavioral role")
    if role == "app":
        return "windows_installer_controller::retained_fixture::owned_" + case.replace("-", "_")
    if role == "corrupt":
        return "qualification_fixture::installer::corrupt_owned_manifest_last"
    return "qualification_fixture::installer::" + role + "_" + case.replace("-", "_")


def command_sha(executable: str, case: str, role: str) -> str:
    command = f'"{executable}" {selector(case, role)} ' + " ".join(FLAGS)
    need(len(command.encode("utf-16le")) <= 2046, "Fixed original command is oversized")
    return sha(command.encode("utf-16le"))


def outcomes(raw: str, names: tuple[str, ...]) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, "Duplicate original step outcome")
            result[key] = value
        return result
    need(type(raw) is str and len(raw) <= 8192, "Step outcome envelope exceeds its bound")
    value = json.loads(raw, object_pairs_hook=unique)
    need(type(value) is dict and set(value) == set(names)
         and all(value[name] == "success" for name in names), "Every actual predecessor must have succeeded")
    return value


def libtest(raw: bytes) -> None:
    need(type(raw) is bytes and 0 < len(raw) <= 65536, "Libtest output exceeds its bound")
    text = raw.decode("utf-8", "strict")
    need(len(re.findall(r"(?m)^running 1 test\r?$", text)) == 1
         and len(re.findall(r"(?m)^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; "
                            r"[0-9]+ filtered out; finished in [0-9.]+s\r?$", text)) == 1,
         "Not one actual successful fixed libtest")


def new_bytes(f, path: Path, raw: bytes) -> None:
    # Exclusive creation, short-write check and actual consuming close. No
    # overwrite, retry, repair, deletion or inference from an existing record.
    with path.open("xb") as output:
        need(output.write(raw) == len(raw), "Original DATA write was incomplete")
        output.flush()
        os.fsync(output.fileno())
    need(f.windows_installed_bytes(path, len(raw)) == raw, "Original DATA readback differs")


def new_json(f, path: Path, value: object) -> None:
    new_bytes(f, path, canonical(value) + b"\n")


def output(values: dict[str, str]) -> None:
    need(all(re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", key) and type(value) is str
             and not any(c in value for c in "\r\n\0") for key, value in values.items()), "Workflow output differs")
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8", newline="\n") as stream:
        text = "".join(key + "=" + value + "\n" for key, value in values.items())
        need(stream.write(text) == len(text), "Workflow handoff write incomplete")


def source_pins(context: dict) -> dict:
    rows = {row["path"]: row for row in context["sourceFiles"]}
    need(all("desktop/tools/" + name in rows for name in TOOLS), "Fixture integration source is incomplete")
    return rows


def prepare(f, context: dict) -> None:
    root, source = Path(context["root"]), Path(context["source"])
    rows = source_pins(context)
    def tool(name):
        row = rows["desktop/tools/" + name]
        need(f.windows_installed_record(source / row["path"], 2 << 20)
             == {"size": row["size"], "sha256": row["sha256"]}, "Fixture tool source changed")
        return {"size": row["size"], "sha256": row["sha256"]}
    value = {"schemaVersion": 1, **binding(context), "attempt": 1, "root": str(root), "source": str(source),
        "contextSha256": f.windows_installed_record(root / "context.json", 1 << 20)["sha256"],
        "sourceInventorySha256": sha(canonical(context["sourceFiles"])),
        "owner": tool("windows_installer_fixture_owner.ps1"),
        "emitter": tool("windows_installer_fixture_pipe_probe.py"),
        "python": {"path": context["python"], **context["pythonIdentity"]}}
    path = root / "retained-shell-owner-input.private.json"
    new_json(f, path, value)
    output({"ownerInputSha256": f.windows_installed_record(path, 16384)["sha256"], "sourceTree": context["sourceTree"]})


def probe_value(context: dict, name: str, owner_sha: str) -> dict:
    need(name in PROBES, "Unexpected pipe probe")
    stdout = b"O" * (65536 if name == "overflow" else 0 if name == "writer-fault" else 30720)
    stderr = b"" if name == "overflow" else b"E" * 30720
    errors = ["aggregate-overflow", "stdout-overflow"] if name == "overflow" else ["stdout-write"] if name == "writer-fault" else []
    return {"schemaVersion": 1, **binding(context), "attempt": 1, "probe": name,
        "ownerInputSha256": owner_sha, "stdoutBytes": len(stdout), "stdoutSha256": sha(stdout),
        "stderrBytes": len(stderr), "stderrSha256": sha(stderr),
        "stdoutObserved": 81920 if name == "overflow" else 30720, "stderrObserved": len(stderr),
        "errors": errors, "originalWaitReturned": True, "exitCode": 0, "bothEof": True,
        "readersClosed": True, "writersClosed": True, "processClosed": True,
        "behavioralAcceptance": False, "refusalExpected": name != "balanced"}


def probes(f, context: dict, *, create: bool) -> dict:
    root = Path(context["root"])
    outcomes(os.environ.get("MRK_RETAINED_PROBE_OUTCOMES", ""), PROBES)
    owner_sha = f.windows_installed_record(root / "retained-shell-owner-input.private.json", 16384)["sha256"]
    records = {}
    for name in PROBES:
        expected = probe_value(context, name, owner_sha)
        path = root / f"probe-{name}-result.private.json"
        value = f.read_bounded_json(path, 8192)
        need(f.same_compile_json(value, expected), "Raw owner probe settlement/result differs")
        for channel in ("stdout", "stderr"):
            raw = f.windows_installed_bytes(root / f"probe-{name}.{channel}.private.bin", 65536)
            need(len(raw) == expected[channel + "Bytes"] and sha(raw) == expected[channel + "Sha256"],
                 "Raw owner original probe bytes differ")
        records[name] = f.windows_installed_record(path, 8192)
    result = {"schemaVersion": 1, **binding(context), "probeCount": 3, "records": records,
              "behavioralAcceptance": False}
    if create:
        new_json(f, root / "retained-shell-probes-checks.private.json", result)
    else:
        need(f.same_compile_json(f.read_bounded_json(root / "retained-shell-probes-checks.private.json", 16384), result),
             "Separately finalized pipe probes changed")
    return result


def declared_native_features(f) -> dict:
    # Single source-authoritative declaration catalog. Declarations are not
    # active graph permission, and an adapter must never repair a bad catalog.
    return dict(f.WINDOWS_NATIVE_DECLARED_FEATURES)


def native_graph(f, value: object, lock: object, *, source: Path, root: Path, profile: str = PROFILE) -> dict:
    need(profile in (PROFILE, SELECTION_PROFILE), "Unknown native graph profile")
    need(type(lock) is dict and lock.get("version") == 4 and type(lock.get("package")) is list
         and 12 <= len(lock["package"]) <= 128, "Fixture native source lock differs")
    locked = {}
    registry = "registry+https://github.com/rust-lang/crates.io-index"
    for row in lock["package"]:
        need(type(row) is dict and type(row.get("name")) is str and type(row.get("version")) is str, "Lock package differs")
        key = (row["name"], row["version"])
        need(key not in locked and (row.get("source") is None if key == ("mrk-windows-installed-native", "0.1.0")
             else row.get("source") == registry and f.sha256_value(row.get("checksum"))), "Lock source differs")
        locked[key] = row
    need(type(value) is dict and value.get("version") == 1 and type(value.get("packages")) is list
         and len(value["packages"]) == len(NATIVE_PACKAGES), "Fixture native package inventory differs")
    packages, names = {}, {}
    for package in value["packages"]:
        need(type(package) is dict and type(package.get("id")) is str and 0 < len(package["id"]) <= 4096
             and package["id"] not in packages and package.get("name") in NATIVE_PACKAGES
             and package["name"] not in names and package.get("version") == NATIVE_PACKAGES[package["name"]],
             "Unexpected fixture native package")
        name, version = package["name"], package["version"]
        need((name, version) in locked and package.get("source") == locked[(name, version)].get("source")
             and type(package.get("manifest_path")) is str and type(package.get("features")) is dict,
             "Fixture native package identity/source differs")
        manifest = Path(package["manifest_path"])
        if name == "mrk-windows-installed-native":
            need(manifest == source / f.WINDOWS_INSTALLED_CRATE / "Cargo.toml"
                 and package["features"] == declared_native_features(f), "Fixture native declarations differ")
            need(f.windows_native_declarations_valid(package),
                 "Fixture native optional SHA2 declaration differs")
        else:
            registry_root = root / "cargo/registry/src"
            need(manifest.is_absolute() and manifest.is_relative_to(registry_root)
                 and len(manifest.relative_to(registry_root).parts) == 3 and manifest.name == "Cargo.toml"
                 and manifest.parent.name == name + "-" + version, "Fixture dependency left private acquisition")
        targets = package.get("targets")
        need(type(targets) is list and 0 < len(targets) <= 512, "Native target inventory differs")
        for target in targets:
            need(type(target) is dict and type(target.get("src_path")) is str
                 and Path(target["src_path"]).is_relative_to(manifest.parent)
                 and not any(p in {".", ".."} for p in re.split(r"[\\/]", target["src_path"])), "Native target left package")
        if name == "mrk-windows-installed-native":
            need(len(targets) == 1 and targets[0].get("kind") == ["lib"] and targets[0].get("crate_types") == ["lib"]
                 and targets[0].get("src_path") == str(manifest.parent / "src/lib.rs"), "Native root is not the one libtest")
        packages[package["id"]], names[name] = package, package["id"]
    native = names["mrk-windows-installed-native"]
    need(value.get("workspace_root") == str(source / f.WINDOWS_INSTALLED_CRATE)
         and value.get("workspace_members") == [native] and value.get("workspace_default_members") == [native]
         and value.get("target_directory") == str(root / "target"), "Native workspace/target differs")
    resolve = value.get("resolve")
    need(type(resolve) is dict and resolve.get("root") == native and type(resolve.get("nodes")) is list
         and len(resolve["nodes"]) == len(packages), "Native resolution differs")
    nodes = {}
    for node in resolve["nodes"]:
        need(type(node) is dict and node.get("id") in packages and node["id"] not in nodes
             and type(node.get("dependencies")) is list and type(node.get("deps")) is list
             and type(node.get("features")) is list, "Native resolved node differs")
        package = packages[node["id"]]
        features = node["features"]
        need(all(type(item) is str and item in package["features"] for item in features)
             and features == sorted(set(features)), "Native resolved features differ")
        expected = {names[name] for name in NATIVE_EDGES[package["name"]]}
        need(all(type(key) is str for key in node["dependencies"]) and len(node["dependencies"]) == len(expected)
             and set(node["dependencies"]) == expected and len(node["deps"]) == len(expected), "Native resolved edges differ")
        edges = set()
        for edge in node["deps"]:
            need(type(edge) is dict and edge.get("pkg") in expected and edge["pkg"] not in edges
                 and edge.get("name") == packages[edge["pkg"]]["name"].replace("-", "_")
                 and type(edge.get("dep_kinds")) is list and 1 <= len(edge["dep_kinds"]) <= 2, "Native dependency role differs")
            for kind in edge["dep_kinds"]:
                need(type(kind) is dict and set(kind) == {"kind", "target"} and kind["kind"] in (None, "build")
                     and (kind["target"] is None or type(kind["target"]) is str), "Native dependency kind differs")
            edges.add(edge["pkg"])
        nodes[node["id"]] = node
    need(nodes[native]["features"] == list(SELECTION_NATIVE_FEATURES if profile == SELECTION_PROFILE else NATIVE_FEATURES), "Native fixture feature closure differs")
    return {"packages": packages, "nodes": nodes, "nativeId": native}


def app_graph(f, value: object, lock: object, *, source: Path, root: Path, profile: str = PROFILE) -> dict:
    """Separate fixture profile of the reviewed app DATA graph, not a relaxation
    of legacy windows_installed_app_graph or its feature/call-site behavior."""
    need(profile in (PROFILE, SELECTION_PROFILE), "Unknown app graph profile")
    need(type(value) is dict and type(value.get("version")) is int and value["version"] == 1 and type(value.get("packages")) is list
            and 4 <= len(value["packages"]) <= 512, "Windows app package inventory differs")
    need(type(lock) is dict and type(lock.get("version")) is int and lock["version"] == 4 and type(lock.get("package")) is list
            and 4 <= len(lock["package"]) <= 2048, "Windows app source-bound lock differs")
    locked = {}
    for row in lock["package"]:
        need(type(row) is dict and type(row.get("name")) is str and type(row.get("version")) is str
                and (row.get("source") is None or type(row["source"]) is str), "Windows app lock identity differs")
        key = (row["name"], row["version"], row.get("source"))
        need(key not in locked and (key[2] is None or key[2] == "registry+https://github.com/rust-lang/crates.io-index"
                and f.sha256_value(row.get("checksum"))), "Windows app lock source/checksum differs")
        locked[key] = row
    need({key[:2] for key in locked if key[2] is None}
            == set(f.WINDOWS_INSTALLED_APP_LOCK_LOCALS.items()), "Windows app declared lock locals differ")
    active_locals = {"mobile-release-kit-desktop", "mrk-windows-installed-native"}
    packages, local, identities = {}, {}, set()
    for package in value["packages"]:
        need(type(package) is dict and type(package.get("id")) is str and 0 < len(package["id"]) <= 4096
                and package["id"] not in packages and type(package.get("name")) is str
                and type(package.get("version")) is str and type(package.get("manifest_path")) is str
                and type(package.get("features")) is dict and (package.get("source") is None or type(package["source"]) is str),
                "Windows app package identity differs")
        # Cargo inventories unselected integration tests too (locked tokio has
        # 158 declarations). This finite DATA bound is not compiler permission:
        # windows_installed_app_test_path separately admits actual selected units.
        need(type(package.get("targets")) is list and 0 < len(package["targets"]) <= 512,
                "Windows app declared target inventory differs")
        key = (package["name"], package["version"], package.get("source"))
        need(key in locked and key not in identities, "Windows app package is duplicated/outside the original lock")
        identities.add(key)
        if key[2] is None:
            need(key[0] in active_locals and key[0] not in local and key[1] == "0.1.0"
                    and package["manifest_path"] == str(source / f.WINDOWS_INSTALLED_APP_LOCALS[key[0]]),
                    "Windows app declared local path differs")
            local[key[0]] = package["id"]
        else:
            manifest = Path(package["manifest_path"])
            registry = root / "cargo" / "registry" / "src"
            need(manifest.is_absolute() and manifest.is_relative_to(registry)
                    and len(manifest.relative_to(registry).parts) == 3
                    and manifest.parent.name == key[0] + "-" + key[1] and manifest.name == "Cargo.toml",
                    "Windows app registry manifest left the private acquisition")
        packages[package["id"]] = package
    need(set(local) == active_locals, "Windows app target must contain exactly two local packages")
    need(f.windows_native_declarations_valid(packages[local["mrk-windows-installed-native"]]),
         "Fixture app native optional SHA2 declaration differs")
    app = local["mobile-release-kit-desktop"]
    need(packages[app]["features"].get("windows-runtime-publisher") == ["mrk-windows-installed-native/runtime-publication"],
            "Windows app publisher feature must forward only the production native feature")
    definitions = {
        "windows-installer-acquisition": ["mrk-windows-installed-native/installer-acquisition"],
        "windows-installer-profile": ["windows-installer-acquisition", "mrk-windows-installed-native/runtime-publication"],
        "windows-installer-protected-fixture": ["windows-installer-profile", "mrk-windows-installed-native/installer-protected-fixture"],
        "windows-installer-selection": ["windows-installer-profile", "mrk-windows-installed-native/installer-selection"],
        "windows-installer-selection-fixture": ["windows-installer-selection", "windows-installer-protected-fixture", "mrk-windows-installed-native/installer-selection-fixture"],
    }
    need(all(packages[app]["features"].get(key) == refs for key, refs in definitions.items()),
         "Fixture app feature declarations differ")
    need(value.get("workspace_root") == str(source / f.WINDOWS_INSTALLED_APP)
            and value.get("workspace_members") == [app] and value.get("workspace_default_members") == [app]
            and value.get("target_directory") == str(root / "target"), "Windows app original workspace/target differs")
    # Cargo filters package/resolve rows, not the selected app's declarations.
    # Keep the source lock's six locals separate from actual Windows packages:
    # three native normal declarations, the qualified Windows dev declaration,
    # and two inactive Linux secret-service declarations. zbus is a registry
    # dependency resolved through the source patch, not another path declaration.
    declarations = packages[app].get("dependencies")
    need(type(declarations) is list and 6 <= len(declarations) <= 256
            and all(type(dep) is dict and type(dep.get("name")) is str for dep in declarations),
            "Windows app dependency declarations differ")
    targets = {
        "mrk-linux-mount-observation": 'cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))',
        "mrk-macos-installed-native": 'cfg(all(target_os = "macos", target_arch = "aarch64"))',
        "mrk-windows-installed-native": 'cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))',
    }
    normal = {name: {"name": name, "source": None, "req": "*", "kind": None, "rename": None,
        "optional": False, "uses_default_features": True, "features": [], "target": target,
        "registry": None, "path": str((source / f.WINDOWS_INSTALLED_APP_LOCALS[name]).parent)}
        for name, target in targets.items()}
    secret_service = {"name": "secret-service", "source": None, "req": "=5.2.0", "kind": None,
        "rename": None, "optional": False, "uses_default_features": False, "features": ["rt-tokio-crypto-rust"],
        "target": targets["mrk-linux-mount-observation"], "registry": None,
        "path": str(source / "desktop/vendor/secret-service-5.2.0")}
    expected = [*normal.values(), {**normal["mrk-windows-installed-native"],
                                  "kind": "dev", "features": ["qualification-result"]},
        secret_service, {**secret_service, "kind": "dev", "features": ["rt-tokio-crypto-rust", "mrk-retrieval-test-support"]}]
    declared_locals = [dep for dep in declarations
                       if dep.get("source") is None or "path" in dep or dep["name"] in {*targets, "secret-service"}]
    # A map keyed only by name would collapse normal/dev or duplicate entries.
    # Compare each complete declaration exactly once, independent of order.
    need(len(declared_locals) == 6
            and all(sum(f.same_compile_json(actual, wanted) for actual in declared_locals) == 1 for wanted in expected),
            "Windows app exact normal and qualification-dev declarations differ")
    resolve = value.get("resolve")
    need(type(resolve) is dict and resolve.get("root") == app and type(resolve.get("nodes")) is list
            and 2 <= len(resolve["nodes"]) <= 256, "Windows app active resolution differs")
    nodes = {}
    for node in resolve["nodes"]:
        need(type(node) is dict and type(node.get("id")) is str and node["id"] in packages and node["id"] not in nodes
                and type(node.get("dependencies")) is list and type(node.get("deps")) is list
                and type(node.get("features")) is list, "Windows app active node differs")
        features = node["features"]
        need(all(type(feature) is str for feature in features) and features == sorted(set(features))
                and set(features) <= set(packages[node["id"]]["features"]), "Windows app resolved features differ")
        nodes[node["id"]] = node
    need(set(nodes) & set(local.values()) == {app, local["mrk-windows-installed-native"]}
            and nodes[app]["features"] == list(SELECTION_APP_FEATURES if profile == SELECTION_PROFILE else APP_FEATURES)
            and packages[local["mrk-windows-installed-native"]]["features"] == declared_native_features(f)
            and nodes[local["mrk-windows-installed-native"]]["features"]
                == list(SELECTION_NATIVE_FEATURES if profile == SELECTION_PROFILE else NATIVE_FEATURES),
            "Windows app active locals/features differ")
    for node in nodes.values():
        edges = []
        for dep in node["deps"]:
            need(type(dep) is dict and type(dep.get("name")) is str and type(dep.get("pkg")) is str
                    and dep["pkg"] in nodes and type(dep.get("dep_kinds")) is list and 0 < len(dep["dep_kinds"]) <= 3,
                    "Windows app active dependency is missing/inactive")
            for kind in dep["dep_kinds"]:
                need(type(kind) is dict and set(kind) == {"kind", "target"}
                        and (kind["kind"] is None or type(kind["kind"]) is str and kind["kind"] in {"dev", "build"})
                        and (kind["target"] is None or type(kind["target"]) is str), "Windows app dependency kind differs")
            edges.append(dep["pkg"])
        need(all(type(item) is str for item in node["dependencies"])
                and len(set(node["dependencies"])) == len(node["dependencies"])
                and set(node["dependencies"]) == set(edges), "Windows app original edge tables differ")
    native_edges = [edge for edge in nodes[app]["deps"] if edge["pkg"] == local["mrk-windows-installed-native"]]
    expected_kinds = [{"kind": kind, "target": targets["mrk-windows-installed-native"]} for kind in (None, "dev")]
    need(len(native_edges) == 1 and native_edges[0]["name"] == "mrk_windows_installed_native"
            and len(native_edges[0]["dep_kinds"]) == 2
            and all(sum(f.same_compile_json(actual, wanted) for actual in native_edges[0]["dep_kinds"]) == 1
                    for wanted in expected_kinds), "Windows app qualification dependency edge differs")
    seen, pending = set(), [app]
    while pending:
        current = pending.pop()
        if current not in seen:
            seen.add(current)
            pending.extend(nodes[current]["dependencies"])
    need(seen == set(nodes), "Windows app has a disconnected active compiler node")
    root_dependencies = {(packages[key]["name"], packages[key]["version"]) for key in nodes[app]["dependencies"]}
    need(root_dependencies == f.WINDOWS_INSTALLED_APP_DIRECT_ROLES,
            "Windows app selected direct dependencies differ")
    need({(packages[key]["name"], packages[key]["version"]) for key in nodes[local["mrk-windows-installed-native"]]["dependencies"]}
            == {("windows-sys", "0.61.2"), ("sha2", "0.10.9")}, "Windows app native dependency differs")
    return {"packages": packages, "nodes": nodes, "appId": app, "localIds": local, "publication": False, "retainedFixture": True}


def graphs(f, context: dict) -> dict:
    root, source = Path(context["root"]), Path(context["source"])
    result = {}
    for role, crate in (("native", f.WINDOWS_INSTALLED_CRATE), ("app", f.WINDOWS_INSTALLED_APP)):
        value = f.read_bounded_json(root / f"retained-{role}-metadata.private.json", 8 << 20)
        lock = tomllib.loads(f.windows_installed_bytes(source / crate / "Cargo.lock", 1 << 20).decode("utf-8"))
        result[role] = (native_graph if role == "native" else app_graph)(f, value, lock, source=source, root=root,
            profile=binding(context)["profile"])
    return result


def metadata_argv(f, context: dict, cargo: str, role: str) -> list[str]:
    selected = SELECTION_SELECTED_FEATURES if binding(context)["profile"] == SELECTION_PROFILE else SELECTED_FEATURES
    need(role in selected, "Unknown fixed compiler graph")
    crate = f.WINDOWS_INSTALLED_CRATE if role == "native" else f.WINDOWS_INSTALLED_APP
    return [cargo, "metadata", "--locked", "--format-version", "1", "--no-default-features",
            "--filter-platform", TARGET, "--features", selected[role],
            "--manifest-path", str(Path(context["source"]) / crate / "Cargo.toml")]


def compile_argv(f, context: dict, cargo: str, role: str) -> list[str]:
    selected = SELECTION_SELECTED_FEATURES if binding(context)["profile"] == SELECTION_PROFILE else SELECTED_FEATURES
    need(role in selected, "Unknown fixed compiler role")
    crate = f.WINDOWS_INSTALLED_CRATE if role == "native" else f.WINDOWS_INSTALLED_APP
    return [cargo, "test", "--locked", "--offline", "--jobs", "1", "--no-default-features", "--target", TARGET,
            "--manifest-path", str(Path(context["source"]) / crate / "Cargo.toml"),
            "--target-dir", str(Path(context["root"]) / "target"), "--features", selected[role],
            "--lib", "--no-run", "--message-format=json"]


def native_test_path(f, raw: bytes, graph: dict, *, root: Path, source: Path) -> Path:
    need(type(raw) is bytes and 0 < len(raw) <= 16 << 20, "Native compiler output exceeds bound")
    packages, nodes = graph["packages"], graph["nodes"]
    features = f.windows_installed_platform_unit_features(graph, {key: node["features"] for key, node in nodes.items()})
    found, finished, scripts = None, False, set()
    for line in raw.splitlines():
        need(not finished, "Native compiler output follows final result")
        row = f.bounded_json(line, 2 << 20)
        need(type(row) is dict and row.get("reason") in
             {"compiler-artifact", "compiler-message", "build-script-executed", "build-finished"}, "Compiler message differs")
        if row["reason"] == "build-finished":
            need(row.get("success") is True, "Original compiler failed")
            finished = True
            continue
        key = row.get("package_id")
        need(key in nodes, "Compiler unit is not in fixed native graph")
        package = packages[key]
        if row["reason"] == "build-script-executed":
            need(key in scripts and package["name"] == "generic-array" and type(row.get("out_dir")) is str
                 and Path(row["out_dir"]).is_relative_to(root / "target")
                 and Path(row["out_dir"]) != root / "target"
                 and not any(part in {".", ".."} for part in re.split(r"[\\/]", row["out_dir"])), "Build script output differs")
            continue
        target = row.get("target")
        need(type(target) is dict and any(f.same_compile_json(target, original) for original in package["targets"])
             and target.get("kind") in (["lib"], ["custom-build"]), "Native compiler target differs")
        if row["reason"] == "compiler-message":
            continue
        profile = row.get("profile")
        need(type(profile) is dict and type(profile.get("test")) is bool and row.get("features") == features[key]
             and row.get("manifest_path") == package["manifest_path"], "Native compiler unit features/source differ")
        if target["kind"] == ["custom-build"]:
            need(package["name"] == "generic-array" and profile["test"] is False, "Unexpected native build script")
            scripts.add(key)
        elif key != graph["nativeId"]:
            need(profile["test"] is False, "Dependency became an unrelated libtest")
        if row.get("executable") is not None:
            need(found is None and key == graph["nativeId"] and target.get("kind") == ["lib"]
                 and target.get("name") == "mrk_windows_installed_native" and target.get("crate_types") == ["lib"]
                 and target.get("src_path") == str(source / f.WINDOWS_INSTALLED_CRATE / "src/lib.rs")
                 and profile["test"] is True and profile.get("debug_assertions") is True
                 and row.get("fresh") is False, "Wrong original native executable")
            found = row["executable"]
    need(finished and found is not None, "No complete successful native compiler artifact")
    return f.ordinary_windows_executable(found, target_root=root / "target")


def artifacts(f, context: dict, selected_graphs: dict) -> dict:
    root, source = Path(context["root"]), Path(context["source"])
    result = {}
    for role in ("native", "app"):
        messages = root / f"retained-{role}-compile-messages.private.jsonl"
        raw = f.windows_installed_bytes(messages, 16 << 20)
        path = (native_test_path(f, raw, selected_graphs[role], root=root, source=source) if role == "native"
                else f.windows_installed_app_test_path(raw, selected_graphs[role], root=root, source=source))
        before = path.lstat()
        identity = (list(f.windows_installed_state(before)) if role == "app"
                    else [before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns])
        record = f.windows_installed_record(path, (512 if role == "app" else 128) << 20)
        need(f.windows_installed_state(before) == f.windows_installed_state(path.lstat()), "Original artifact changed")
        result[role] = {"path": str(path), **record, "identity": identity,
                        "messages": f.windows_installed_record(messages, 16 << 20)}
        result[role]["nativeIdentity"] = f.windows_ordinary_original(result[role], app_role=role == "app")
    return result


def load_fixture_data(f, context: dict):
    source = Path(context["source"])
    source_pins(context)
    f.windows_installed_inputs(context)
    path = source / "desktop/tools/windows_installer_fixture_data.py"
    spec = importlib.util.spec_from_file_location("_mrk_retained_shell_data", path)
    need(spec is not None and spec.loader is not None, "Fixed fixture DATA module unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    f.windows_installed_inputs(context)
    return module


def stage_data(f, context: dict, prepared: dict) -> dict:
    root = Path(context["root"])
    data = load_fixture_data(f, context)
    staging = data.profile.staging
    manifest = f.read_bounded_json(root / "runtime/manifest.json", 1 << 20)
    # Conservative payload-only accounting across local stage, native source,
    # acquired I and shared D. Compilers have separate existing output budgets.
    runtime_bytes = sum(row["size"] for row in prepared["physical"])
    payload_bound = 15 * (runtime_bytes + (64 << 10)) + 2 * runtime_bytes + f.WINDOWS_FULLWALK_ZIP_BYTES
    need(payload_bound <= 1536 << 20, "All fixed payload copies exceed 1.5 GiB")
    private = root / "retained-fixture-inputs"
    private.mkdir(mode=0o700)
    staged = root / "installer-fixtures"
    staged.mkdir(mode=0o700)
    shared = {
        "publisher": b"MRK retained-shell inert publisher; never execute\n",
        "webview2": b"MRK retained-shell inert vendor row; existing-only admission\n",
        "applicationNotices": b"Nonshipping retained-shell synthetic application input\n",
        "webview2Notices": b"Nonshipping retained-shell synthetic prerequisite input\n",
    }
    for role, raw in shared.items():
        new_bytes(f, private / (role + ".data"), raw)
    common = {"sourceCommit": context["sourceSha"], "target": TARGET,
              "runtimeManifestSha256": prepared["manifestSha256"], "protocolSha256": prepared["protocolSha256"],
              "coreVersion": manifest["coreVersion"]}
    controls = []
    for case in CASES:
        shell = ("MRK retained-shell inert shell " + case + "; never execute\n").encode("ascii")
        shell_path = private / (case + ".shell.data")
        new_bytes(f, shell_path, shell)
        def record(raw):
            return {"size": len(raw), "sha256": sha(raw)}
        admission = {"schemaVersion": 1, "purpose": "windows-installer-input-data", **common,
            "shell": {**common, "profile": "release", "features": ["desktop-shell", "custom-protocol"], **record(shell)},
            "publisher": {**common, "profile": "release", "features": ["windows-runtime-publisher"], **record(shared["publisher"])},
            "webview2": {"kind": "evergreen-standalone-offline-x64", **record(shared["webview2"])},
            "applicationNotices": record(shared["applicationNotices"]), "webview2Notices": record(shared["webview2Notices"])}
        raw = canonical(admission) + b"\n"
        admission_path = private / (case + ".admission.json")
        new_bytes(f, admission_path, raw)
        staging.stage(admission=admission_path, expected_admission=sha(raw), source=context["sourceSha"], target=TARGET,
            manifest=prepared["manifestSha256"], protocol=prepared["protocolSha256"], shell=shell_path,
            publisher=private / "publisher.data", runtime=root / "runtime", webview2=private / "webview2.data",
            application_notices=private / "applicationNotices.data", webview2_notices=private / "webview2Notices.data",
            output=staged / case)
        inventory = f.windows_installed_bytes(staged / case / "inventory.json", 32768)
        controls.append({"inventory": inventory, "admission": raw, "expected_inventory": sha(inventory), "expected_admission": sha(raw)})
    rendered = data.render_fixture_data(controls)
    for name, raw in rendered.items():
        new_bytes(f, root / name, raw)
    first = data.profile.render_profile(**controls[0])
    result = {"profiles": f.windows_installed_record(root / "fixture-profiles.ndjson", 65536),
              "roster": f.windows_installed_record(root / "fixture-roster.txt", 32768),
              "firstProfile": first.decode("ascii"), "firstProfileSha256": sha(first),
              "payloadCopyBoundBytes": payload_bound, "genuinePreparedRuntime": prepared,
              "opaqueFixtureBytesNeverExecutable": True}
    new_json(f, root / "retained-fixture-data.private.json", result)
    return result


def fixture_data(f, context: dict) -> dict:
    root = Path(context["root"])
    data = f.read_bounded_json(root / "retained-fixture-data.private.json", 128 << 10)
    rendered = load_fixture_data(f, context)
    controls = []
    for case in CASES:
        staged = root / "installer-fixtures" / case
        inventory = f.windows_installed_bytes(staged / "inventory.json", 32768)
        admission = f.windows_installed_bytes(staged / "admission.json", 16384)
        controls.append({"inventory": inventory, "admission": admission,
                         "expected_inventory": sha(inventory), "expected_admission": sha(admission)})
        value = f.bounded_json(inventory, 32768)
        # Complete local staged payload census; no aliases or newly introduced
        # files/directories become native input merely because controls matched.
        members = rendered.profile.staging.preparation.files(staged)
        expected = sorted([*(row["path"] for row in value["files"]), "inventory.json", "admission.json"])
        need([path.relative_to(staged).as_posix() for path in members] == expected, "Staged source census changed")
        for row in value["files"]:
            need(f.windows_installed_record(staged / row["path"], 128 << 20)
                 == {"size": row["size"], "sha256": row["sha256"]}, "Staged source bytes changed")
    originals = rendered.render_fixture_data(controls)
    for name, raw in originals.items():
        need(f.windows_installed_bytes(root / name, 65536) == raw, "Compile fixture data changed")
    first = rendered.profile.render_profile(**controls[0])
    need(data["profiles"] == f.windows_installed_record(root / "fixture-profiles.ndjson", 65536)
         and data["roster"] == f.windows_installed_record(root / "fixture-roster.txt", 32768)
         and data["firstProfile"] == first.decode("ascii") and data["firstProfileSha256"] == sha(first)
         and data["genuinePreparedRuntime"] == f.windows_fullwalk_prepared(context)
         and data["opaqueFixtureBytesNeverExecutable"] is True, "Fixture original DATA/anchors changed")
    return data


def compiler_environment(f, context: dict, data: dict | None = None) -> dict:
    root = Path(context["root"])
    env = f.clean_environment(root)
    env.update(GITHUB_SHA=context["sourceSha"], GITHUB_RUN_ID=context["runId"],
               MRK_WINDOWS_SOURCE_TREE=context["sourceTree"], CARGO_TARGET_DIR=str(root / "target"))
    if data is not None:
        prepared = data["genuinePreparedRuntime"]
        env.update(MRK_BUNDLED_RUNTIME_MANIFEST_SHA256=prepared["manifestSha256"],
            MRK_BUNDLED_PROTOCOL_SHA256=prepared["protocolSha256"],
            MRK_WINDOWS_INSTALLER_PROFILE_JSON=data["firstProfile"],
            MRK_WINDOWS_INSTALLER_PROFILE_SHA256=data["firstProfileSha256"],
            MRK_WINDOWS_INSTALLER_SOURCE_COMMIT=context["sourceSha"],
            MRK_WINDOWS_RETAINED_FIXTURE_PROFILES=str(root / "fixture-profiles.ndjson"),
            MRK_WINDOWS_RETAINED_FIXTURE_PROFILES_SHA256=data["profiles"]["sha256"],
            MRK_WINDOWS_RETAINED_FIXTURE_ROSTER=str(root / "fixture-roster.txt"),
            MRK_WINDOWS_RETAINED_FIXTURE_ROSTER_SHA256=data["roster"]["sha256"])
    return env


def compiler_tools(f, cargo: str, rustc: str) -> dict:
    return {name: {"path": path, **f.windows_installed_record(Path(path), 128 << 20)}
            for name, path in (("cargo", cargo), ("rustc", rustc))}


def acquire(f, context: dict, deadline: float) -> None:
    root = Path(context["root"])
    probes(f, context, create=False)
    need(os.environ.get("MRK_RETAINED_PROBES_OUTCOME") == "success", "Actual probe finalizer did not succeed")
    new_json(f, root / "retained-acquire-started.private.json", binding(context))
    env = compiler_environment(f, context)
    prepared = f.windows_fullwalk_acquire(context, env, deadline)
    f.run([context["rustup"], "toolchain", "install", f.RUST, "--profile", "minimal", "--no-self-update"],
          check=COMPILER_CHECKS["acquire"], cwd=root, env=env, timeout=f.windows_installed_remaining(deadline, 600))
    cargo, rustc = f.tools(context, env)
    for role in ("native", "app"):
        argv = metadata_argv(f, context, cargo, role)
        with (root / f"retained-{role}-metadata.private.json").open("x", encoding="utf-8", newline="\n") as stream, \
             (root / f"retained-{role}-acquire.stderr.private.txt").open("x", encoding="utf-8", newline="\n") as diagnostic:
            f.run(argv, check=COMPILER_CHECKS[role + "-metadata"], cwd=root, env=env,
                  timeout=f.windows_installed_remaining(deadline, 600), output=stream, diagnostics=diagnostic)
    selected = graphs(f, context)
    data = stage_data(f, context, prepared["prepared"])
    tools = compiler_tools(f, cargo, rustc)
    new_json(f, root / "retained-compiler-tools.private.json", tools)
    f.windows_installed_inputs(context)
    f.source_unchanged(context)
    f.windows_installed_remaining(deadline, 1)
    new_json(f, root / "retained-acquire-checks.private.json", {**binding(context),
        "metadata": {role: f.windows_installed_record(root / f"retained-{role}-metadata.private.json", 8 << 20)
                     for role in ("native", "app")},
        "compilerTools": f.windows_installed_record(root / "retained-compiler-tools.private.json", 65536),
        "data": f.windows_installed_record(root / "retained-fixture-data.private.json", 128 << 10),
        "activePackageCounts": {role: len(graph["nodes"]) for role, graph in selected.items()},
        "genuineRuntime": prepared, "originalCompilerExitCodes": [0, 0]})


def acquisition(f, context: dict) -> dict:
    root = Path(context["root"])
    value = f.read_bounded_json(root / "retained-acquire-checks.private.json", 256 << 10)
    require_bound(value, context)
    need(f.read_bounded_json(root / "retained-acquire-started.private.json", 4096) == binding(context)
         and value["originalCompilerExitCodes"] == [0, 0], "Acquisition original result differs")
    for role in ("native", "app"):
        need(value["metadata"][role] == f.windows_installed_record(root / f"retained-{role}-metadata.private.json", 8 << 20),
             "Acquired graph changed")
    need(value["compilerTools"] == f.windows_installed_record(root / "retained-compiler-tools.private.json", 65536)
         and value["data"] == f.windows_installed_record(root / "retained-fixture-data.private.json", 128 << 10),
         "Acquisition tools or DATA changed")
    return value


def compile_only(f, context: dict, deadline: float) -> None:
    root = Path(context["root"])
    need(os.environ.get("MRK_RETAINED_ACQUIRE_OUTCOME") == "success", "Original acquisition step did not succeed")
    acquisition(f, context)
    selected = graphs(f, context)
    data = fixture_data(f, context)
    env = compiler_environment(f, context, data)
    cargo, rustc = f.tools(context, env)
    need(compiler_tools(f, cargo, rustc) == f.read_bounded_json(root / "retained-compiler-tools.private.json", 65536),
         "Pinned compiler changed")
    new_json(f, root / "retained-compile-started.private.json", binding(context))
    # Persist the complete actual allowlisted compiler environment and argv,
    # privately. It is a DATA binding, never native-process execution authority.
    new_json(f, root / "retained-compile-environment.private.json", env)
    argv_records = {}
    for role in ("native", "app"):
        argv = compile_argv(f, context, cargo, role)
        new_json(f, root / f"retained-{role}-compile-argv.private.json", argv)
        with (root / f"retained-{role}-compile-messages.private.jsonl").open("x", encoding="utf-8", newline="\n") as stream, \
             (root / f"retained-{role}-compile.stderr.private.txt").open("x", encoding="utf-8", newline="\n") as diagnostic:
            f.run(argv, check=COMPILER_CHECKS[role + "-compile"], cwd=root, env=env,
                  timeout=f.windows_installed_remaining(deadline, 600), output=stream, diagnostics=diagnostic)
        argv_records[role] = f.windows_installed_record(root / f"retained-{role}-compile-argv.private.json", 16384)
    originals = artifacts(f, context, selected)
    need(data == fixture_data(f, context), "Compile DATA changed during original compiler use")
    f.windows_installed_inputs(context)
    f.source_unchanged(context)
    f.windows_installed_remaining(deadline, 1)
    new_json(f, root / "retained-compile-checks.private.json", {**binding(context), "artifacts": originals,
        "argv": argv_records, "environment": f.windows_installed_record(root / "retained-compile-environment.private.json", 65536),
        "originalCompilerExitCodes": [0, 0], "nativeNotStarted": True})


def compilation(f, context: dict, *, inspect_inputs: bool) -> tuple[dict, dict, dict]:
    root = Path(context["root"])
    acquisition(f, context)
    value = f.read_bounded_json(root / "retained-compile-checks.private.json", 256 << 10)
    require_bound(value, context)
    need(f.read_bounded_json(root / "retained-compile-started.private.json", 4096) == binding(context)
         and value["originalCompilerExitCodes"] == [0, 0] and value["nativeNotStarted"] is True, "Compile original result differs")
    data = (fixture_data(f, context) if inspect_inputs
            else f.read_bounded_json(root / "retained-fixture-data.private.json", 128 << 10))
    selected = graphs(f, context)
    originals = artifacts(f, context, selected)
    need(f.same_compile_json(value["artifacts"], originals), "Compiled original artifact changed")
    # DATA-only reinspection: do not invoke rustup, rustc, Git or another
    # process after the final native namespace user.
    tools = f.read_bounded_json(root / "retained-compiler-tools.private.json", 65536)
    need(type(tools) is dict and set(tools) == {"cargo", "rustc"}, "Compiler tool roster differs")
    cargo, rustc = tools["cargo"]["path"], tools["rustc"]["path"]
    env = compiler_environment(f, context, data)
    env["RUSTC"] = rustc
    env["PATH"] = str(Path(cargo).parent) + os.pathsep + env["PATH"]
    need(compiler_tools(f, cargo, rustc) == tools
         and f.same_compile_json(f.read_bounded_json(root / "retained-compile-environment.private.json", 65536), env)
         and value["environment"] == f.windows_installed_record(root / "retained-compile-environment.private.json", 65536),
         "Actual compiler environment changed")
    for role in ("native", "app"):
        path = root / f"retained-{role}-compile-argv.private.json"
        need(f.read_bounded_json(path, 16384) == compile_argv(f, context, cargo, role)
             and value["argv"][role] == f.windows_installed_record(path, 16384), "Actual compiler invocation differs")
    return value, data, originals


def precheck(f, context: dict) -> None:
    need(os.environ.get("MRK_RETAINED_COMPILE_OUTCOME") == "success", "Actual original compile step did not succeed")
    value, data, originals = compilation(f, context, inspect_inputs=True)
    root = Path(context["root"])
    pre = {**binding(context), "sourceInventorySha256": sha(canonical(context["sourceFiles"])),
           "profilesSha256": data["profiles"]["sha256"], "rosterSha256": data["roster"]["sha256"],
           "preparedRuntimeSha256": sha(canonical(data["genuinePreparedRuntime"]))}
    for role in ("native", "app"):
        artifact = originals[role]
        pre.update({role+"Artifact": artifact["path"], role+"ArtifactBytes": str(artifact["size"]),
            role+"ArtifactSha256": artifact["sha256"], role+"ArtifactIdentity": artifact["nativeIdentity"],
            role+"CompileMessagesSha256": artifact["messages"]["sha256"], role+"CompileArgvSha256": value["argv"][role]["sha256"]})
    expected = {name.casefold() for name in behavior_files(binding(context)["profile"])}
    with os.scandir(root) as entries:
        need(not any(entry.name.casefold() in expected for entry in entries), "A one-use behavioral output is occupied")
    raw = encoded_wire(PRE_HEADER, PRE_KEYS, pre)
    new_bytes(f, root / "retained-shell-precheck.private.txt", raw)
    output({"precheckSha256": sha(raw)})


def app_record(raw: bytes, case: str, profile: dict) -> dict:
    libtest(raw)
    matching = [line[len(APP_PREFIX):] for line in raw.decode("utf-8").splitlines() if line.startswith(APP_PREFIX)]
    need(len(matching) == 1, "Missing or repeated actual app proof")
    proof = wire(("APP\n" + matching[0].replace(";", "\n") + "\n").encode("ascii"), "APP", APP_KEYS, 4096)
    need(proof["case"] == case and proof["originalWatchdogJoined"] == "true" and proof["nativeSettled"] == "true",
         "Actual app owner/watchdog did not settle")
    total = sum(row["size"] for row in profile["inputs"])
    if case == "stop-copy":
        written = number(proof["confirmedWritten"], profile["inputs"][0]["size"], 1)
        need(proof["rows"] == "0" and proof["readbackRead"] == "0"
             and number(proof["sourceRead"], total) == profile["inputs"][52]["size"] + profile["inputs"][53]["size"] + written,
             "STOP must follow the actual first copy return")
    else:
        need(proof["rows"] == "54" and all(number(proof[key], total) == total
             for key in ("sourceRead", "confirmedWritten", "readbackRead")), "App did not retain all54 actual inputs")
    active = case in ("fresh", "reuse")
    need(proof["activation"] == str(active).lower() and proof["roles"] == ("63" if active else "0")
         and proof["transitions"] == ("63" if case == "fresh" else "56" if case == "reuse" else "0"),
         "Retained-shell activation role/transition differs")
    need(proof["prerequisite"] == ("not-started" if case in ("stop-copy", "wrong-caller") else "already-present")
         and proof["runtime"] == {"fresh": "published-new", "reuse": "reused-existing",
             "stop-copy": "not-started", "wrong-caller": "caller-refused", "bad-manifest": "own-manifest-refused"}[case],
         "Wrong publication/prerequisite or refusal outcome")
    return proof


def snapshot_members(case: str, role: str, profiles: dict) -> list[tuple[str, bool, dict | None]]:
    profile = profiles[case]
    if role == "stage":
        return [(f"s/f/{i}", False, row) for i, row in enumerate(profile["inputs"])] + [(f"s/d/{i}", True, None) for i in range(9)]
    if role == "corrupt":
        need(case == "bad-manifest", "Only final case may corrupt its original")
        return [("d/f/7", False, {"size": profile["inputs"][7]["size"]})]
    need(role == "observe", "Unknown native snapshot role")
    expected = []
    if case in ("fresh", "reuse"):
        expected += [(f"d/f/{i}", False, row) for i, row in enumerate(profile["inputs"][:47])]
        expected += [(f"d/d/{i}", True, None) for i in range(2)]
    for name in (("fresh", "reuse") if case == "reuse" else (case,)):
        index = CASES.index(name)
        expected += [(f"i{index}/f/{i}", False, None if name == "stop-copy" else row)
                     for i, row in enumerate(profiles[name]["inputs"][:1 if name == "stop-copy" else 54])]
        expected += [(f"i{index}/d/{i}", True, None) for i in range(7)]
    if case == "bad-manifest":
        expected += [("d/f/7", False, {"size": profile["inputs"][7]["size"]})]
    return expected


def snapshot(f, raw: bytes, context: dict, pre: dict, pre_sha: str,
             case: str, role: str, profiles: dict) -> tuple[dict, list[dict]]:
    need(type(raw) is bytes and 0 < len(raw) <= 65536 and raw.isascii()
         and raw.endswith(b"\n") and b"\r" not in raw, "Native snapshot framing differs")
    lines = raw[:-1].split(b"\n")
    count = len(SNAP_KEYS) + 1
    need(len(lines) >= count, "Native snapshot is incomplete")
    value = wire(b"\n".join(lines[:count]) + b"\n", SNAP_HEADER, SNAP_KEYS)
    require_bound(value, context)
    profile = profiles[case]
    image = sha(canonical(profile))
    need(value["case"] == case and value["phase"] == role and value["precheckSha256"] == pre_sha
         and value["profilesSha256"] == pre["profilesSha256"] and value["rosterSha256"] == pre["rosterSha256"]
         and value["image"] == image and value["manifest"] == profile["runtimeManifestSha256"]
         and value["freshMrkAbsent"] == str(case == "fresh" and role == "stage").lower()
         and value["parentBookSettled"] == "true" and value["unknown"] == "false"
         and value["resultCloseGate"] == "original-fixture-exit-zero-required"
         and number(value["fileOriginals"], 256, 1) == number(value["fileOriginalsClosed"], 256, 1),
         "Native snapshot source or original settlement differs")
    candidate = f.windows_ordinary_path(value["candidate"])
    need(candidate.name == "MRK Installer Fixture " + image, "Native source hint is not the fixed owned fixture")
    expected = snapshot_members(case, role, profiles)
    need(number(value["objects"], 192, 1) == len(lines) - count == len(expected), "Native object census count differs")
    rows, identities = [], set()
    for line, (name, directory, record) in zip(lines[count:], expected, strict=True):
        need(line.startswith(b"observed="), "Native object frame differs")
        fields = line[9:].decode("ascii").split("|")
        need(len(fields) == 6 and fields[0] == name and fields[1] == ("directory" if directory else "file")
             and f.sha256_value(fields[3]), "Native object role/security differs")
        stamp = f.windows_fullwalk_stamp(fields[2])
        identity = (stamp["volume"], stamp["fileId"])
        need(identity not in identities and bool(stamp["attributes"] & 0x10) is directory,
             "Native object aliases another or has the wrong kind")
        identities.add(identity)
        need((fields[4] == "-" and f.sha256_value(fields[5])) if directory
             else (f.sha256_value(fields[4]) and fields[5] == "-"), "Native object hash/census differs")
        if record is not None:
            need(stamp["size"] == record["size"] and ("sha256" not in record or fields[4] == record["sha256"]),
                 "Native original bytes differ from the compiled profile")
        rows.append({"role": name, "directory": directory, "stamp": stamp,
                     "security": fields[3], "sha256": fields[4], "inventorySha256": fields[5]})
    return value, rows


def exit_record(raw: bytes, context: dict, pre: dict, pre_sha: str,
                case: str, role: str, result: bytes) -> dict:
    value = wire(raw, EXIT_HEADER, EXIT_KEYS, 8192)
    require_bound(value, context)
    kind = "app" if role == "app" else "native"
    need(value["role"] == case + "-" + role and value["precheckSha256"] == pre_sha
         and value["artifactSha256"] == pre[kind + "ArtifactSha256"]
         and value["commandSha256"] == command_sha(pre[kind + "Artifact"], case, role)
         and number(value["resultBytes"], 65536, 1) == len(result) and value["resultSha256"] == sha(result)
         and value["originalWaitReturned"] == "true" and value["exitCode"] == "0"
         and value["writerCloseGate"] == "original-owner-closed-output", "Original fixed process exit/result differs")
    return value


def behavior_files(profile: str = PROFILE) -> dict[str, int]:
    need(profile in (PROFILE, SELECTION_PROFILE), "Unknown output-inventory profile")
    if profile == SELECTION_PROFILE:
        return selection_behavior_files()
    names = {}
    for case, role in CHAIN:
        stem = f"retained-{case}-{role}"
        names[stem + ".private.txt"] = 65536
        names[stem + "-exit.private.txt"] = 8192
        names[stem + ".stderr.private.bin"] = 65536
        if role != "app":
            names[stem + ".stdout.private.bin"] = 65536
    return names


def finalize(f, context: dict) -> None:
    root = Path(context["root"])
    names = tuple(case + "-" + role for case, role in CHAIN)
    outcomes(os.environ.get("MRK_RETAINED_OUTCOMES", ""), names)
    need(os.environ.get("MRK_RETAINED_PRECHECK_OUTCOME") == "success"
         and os.environ.get("MRK_RETAINED_PROBES_OUTCOME") == "success", "Actual precheck/probe finality is absent")
    probes(f, context, create=False)
    compiled, data, originals = compilation(f, context, inspect_inputs=False)
    pre_raw = f.windows_installed_bytes(root / "retained-shell-precheck.private.txt", 16384)
    pre_sha = sha(pre_raw)
    pre = wire(pre_raw, PRE_HEADER, PRE_KEYS)
    require_bound(pre, context)
    need(pre["sourceInventorySha256"] == sha(canonical(context["sourceFiles"]))
         and pre["profilesSha256"] == data["profiles"]["sha256"] and pre["rosterSha256"] == data["roster"]["sha256"]
         and pre["preparedRuntimeSha256"] == sha(canonical(data["genuinePreparedRuntime"])), "Precheck input binding differs")
    for role in ("native", "app"):
        artifact = originals[role]
        need(pre[role+"Artifact"] == artifact["path"] and pre[role+"ArtifactSha256"] == artifact["sha256"]
             and pre[role+"ArtifactIdentity"] == artifact["nativeIdentity"]
             and number(pre[role+"ArtifactBytes"], (512 if role == "app" else 128) << 20, 1) == artifact["size"]
             and pre[role+"CompileMessagesSha256"] == artifact["messages"]["sha256"]
             and pre[role+"CompileArgvSha256"] == compiled["argv"][role]["sha256"], "Precheck compiler original differs")
    profile_raw = f.windows_installed_bytes(root / "fixture-profiles.ndjson", 65536)
    roster_raw = f.windows_installed_bytes(root / "fixture-roster.txt", 32768)
    need(sha(profile_raw) == pre["profilesSha256"] and sha(roster_raw) == pre["rosterSha256"], "Actual compile DATA changed")
    parts = profile_raw.splitlines()
    need(parts[0] == b"MRK_WINDOWS_RETAINED_SHELL_FIXTURE_PROFILE_SET_V1" and len(parts) == 6,
         "Compile profile set framing differs")
    profiles = dict(zip(CASES, (f.bounded_json(raw, 8192) for raw in parts[1:]), strict=True))
    snapshots, proofs, retained = {}, {}, {}
    for case, role in CHAIN:
        stem = f"retained-{case}-{role}"
        result = f.windows_installed_bytes(root / (stem + ".private.txt"), 65536)
        exit_raw = f.windows_installed_bytes(root / (stem + "-exit.private.txt"), 8192)
        exit_record(exit_raw, context, pre, pre_sha, case, role, result)
        stderr = f.windows_installed_bytes(root / (stem + ".stderr.private.bin"), 65536)
        need(stderr == b"", "Behavioral original stderr was not empty")
        if role == "app":
            proofs[case] = app_record(result, case, profiles[case])
        else:
            stdout = f.windows_installed_bytes(root / (stem + ".stdout.private.bin"), 65536)
            libtest(stdout)
            snapshots[(case, role)] = snapshot(f, result, context, pre, pre_sha, case, role, profiles)
        retained[stem] = {"result": {"size": len(result), "sha256": sha(result)},
                          "exit": {"size": len(exit_raw), "sha256": sha(exit_raw)}}
    fresh = snapshots[("fresh", "observe")][1]
    reuse = snapshots[("reuse", "observe")][1]
    need(reuse[:len(fresh)] == fresh, "Reuse changed any old D47/IA54 original, ACL, metadata or byte")
    for case in CASES:
        stage = snapshots[(case, "stage")][0]
        observed = snapshots[(case, "observe")][0]
        need(stage["candidate"] == observed["candidate"], "Native input source changed between stage and observation")
    partial = snapshots[("stop-copy", "observe")][1][0]
    written = number(proofs["stop-copy"]["confirmedWritten"], profiles["stop-copy"]["inputs"][0]["size"], 1)
    staged = root / "installer-fixtures/stop-copy"
    inventory = f.read_bounded_json(staged / "inventory.json", 32768)
    first = next(row for row in inventory["files"] if row["role"] == "runtimeInput")
    original = f.windows_installed_bytes(staged / first["path"], 128 << 20)
    need(partial["stamp"]["size"] == written and partial["sha256"] == sha(original[:written]),
         "STOP snapshot does not retain the actual first copied prefix")
    corrupted = snapshots[("bad-manifest", "corrupt")][1][0]
    after_bad = snapshots[("bad-manifest", "observe")][1][-1]
    before = next(row for row in fresh if row["role"] == "d/f/7")
    changed = bytearray(f.windows_installed_bytes(root / "runtime/manifest.json", 1 << 20))
    need(changed and sha(changed) == profiles["fresh"]["inputs"][7]["sha256"], "Original uncorrupted manifest changed")
    changed[0] ^= 1
    need(corrupted == after_bad and corrupted["sha256"] == sha(changed)
         and corrupted["sha256"] != before["sha256"] and corrupted["security"] == before["security"]
         and all(corrupted["stamp"][key] == before["stamp"][key]
                 for key in ("volume", "fileId", "creation", "size", "allocation", "links", "attributes"))
         and all(corrupted["stamp"][key] >= before["stamp"][key] for key in ("write", "change")),
         "Final refusal did not preserve the one original-owned manifest corruption")
    # Read/account every finite original owner output. No raw content, native
    # identities or local path is eligible for public retention.
    outputs = {name: f.windows_installed_record(root / name, limit) for name, limit in behavior_files().items()}
    need(sum(row["size"] for row in outputs.values()) <= 4 << 20, "Behavioral evidence exceeded its aggregate output budget")
    f.windows_installed_inputs(context, retention_only=True)
    result = {"schemaVersion": 1, **binding(context), "status": "passed", "behavioralOriginals": 16,
        "nativeOriginals": 11, "appOriginals": 5, "pipeProbeOriginals": 3, "caseCount": 5,
        "precheckSha256": pre_sha, "records": retained, "privateOutputs": outputs,
        "sourceInventorySha256": pre["sourceInventorySha256"], "notVerified": list(NOT_VERIFIED),
        "shippingInstallerEnabled": False, "desktopReady": False}
    new_json(f, root / "retained-shell-final.private.json", result)


def retain(f, context: dict) -> None:
    root = Path(context["root"])
    actual = os.environ.get("MRK_RETAINED_FINALIZE_OUTCOME", "")
    need(actual in ("success", "failure", "cancelled", "skipped"), "Finalizer outcome was not observed")
    summary = {"schemaVersion": 1, **binding(context), "status": "not-verified",
        "actualFinalizerOutcome": actual, "desktopReady": False, "shippingInstallerEnabled": False,
        "notVerified": list(NOT_VERIFIED), "rawPrivateOutputUploaded": False}
    if actual == "success":
        value = f.read_bounded_json(root / "retained-shell-final.private.json", 65536)
        require_bound(value, context)
        need(value["status"] == "passed" and value["behavioralOriginals"] == 16
             and value["nativeOriginals"] == 11 and value["appOriginals"] == 5 and value["pipeProbeOriginals"] == 3,
             "Actual finalizer result differs")
        summary.update(status="passed", behavioralOriginals=16, nativeOriginals=11, appOriginals=5,
                       pipeProbeOriginals=3, caseCount=5, precheckSha256=value["precheckSha256"],
                       privateResultSha256=f.windows_installed_record(root / "retained-shell-final.private.json", 65536)["sha256"])
    public = root / "public/retained-shell-summary.json"
    new_json(f, public, summary)



def selection_route(role: str) -> tuple[str, str]:
    need(type(role) is str and role in SELECTION_ROUTES, "Not a fixed selection role")
    return SELECTION_ROUTES[role]


def selection_command_sha(executable: str, role: str) -> str:
    command = f'"{executable}" {selection_route(role)[1]} ' + " ".join(FLAGS)
    need(len(command.encode("utf-16le")) <= 2046, "Selection original command is oversized")
    return sha(command.encode("utf-16le"))


def selection_behavior_files() -> dict[str, int]:
    names = {}
    for role, kind, _ in SELECTION_CHAIN:
        stem = "retained-" + role
        names[stem + ".private.txt"] = 65536
        names[stem + "-exit.private.txt"] = 8192
        names[stem + ".stderr.private.bin"] = 65536
        if kind != "app":
            names[stem + ".stdout.private.bin"] = 65536
    return names


def selection_digest(value: object, length: int = 64) -> bool:
    return type(value) is str and re.fullmatch("[0-9a-f]{" + str(length) + "}", value) is not None


def selection_dos_path(value: object) -> bool:
    return (type(value) is str and re.match(r"^[A-Za-z]:\\", value) is not None
            and len(value.encode("utf-16le")) < 16384 and not any(c in value for c in '\0\r\n%/"')
            and all(part not in ("", ".", "..") and not part.endswith((" ", ".")) and ":" not in part
                    for part in value[3:].split("\\")))


def selection_output_role(value: object) -> bool:
    if type(value) is not str:
        return False
    parts = value.split("/")
    if parts in (["selector"], ["selection"], ["selection", "recovery"], ["selection", TARGET]):
        return True
    if len(parts) in (3, 4) and parts[:2] == ["selection", "recovery"]:
        return selection_digest(parts[2], 32) and (len(parts) == 3
            or parts[3] in ("incoming.lnk", "previous.lnk", *(f"record-{i:02}.bin" for i in range(7))))
    if len(parts) in (3, 4) and parts[:2] == ["selection", TARGET]:
        return selection_digest(parts[2]) and (len(parts) == 3 or parts[3] in ("profile.json", "launch.lnk"))
    return False


def selection_preview(raw: str, case: str) -> dict:
    need(case in SELECTION_CASE_CONFIG and type(raw) is str and 0 < len(raw.encode("utf-8")) <= 16384,
         "Selection preview transport bound differs")
    def closed(pairs):
        need(tuple(key for key, _ in pairs) == SELECTION_PREVIEW_KEYS, "Preview fields/nulls/order differ")
        return dict(pairs)
    value = json.loads(raw, object_pairs_hook=closed)
    need(type(value) is dict and tuple(value) == SELECTION_PREVIEW_KEYS
         and type(value["version"]) is int and value["version"] == 1
         and value["mode"] == SELECTION_CASE_CONFIG[case][1]
         and value["registrationPath"] == SELECTION_REGISTRATION and value["warning"] == SELECTION_WARNING
         and selection_digest(value["observationSha256"])
         and all(value[key] is None or selection_digest(value[key]) for key in ("beforeImage", "afterImage", "runtime"))
         and (value["coreVersion"] is None or type(value["coreVersion"]) is str
              and re.fullmatch(r"[A-Za-z0-9._+\-]{1,64}", value["coreVersion"]) is not None)
         and selection_dos_path(value["shortcutPath"])
         and type(value["preservedPaths"]) is list and len(value["preservedPaths"]) == 4
         and all(selection_dos_path(path) for path in value["preservedPaths"])
         and (value["retainedImageBytesObserved"] is None
              or type(value["retainedImageBytesObserved"]) is int and 0 < value["retainedImageBytesObserved"] <= 2 << 30),
         "Selection preview shape differs")
    need(json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False) == raw,
         "Original preview bytes were normalized, escaped differently or extended")
    return value


def selection_one(text: str, prefix: str, count: int = 1) -> str | None:
    rows = [line[len(prefix):] for line in text.splitlines() if line.startswith(prefix)]
    need(len(rows) == count and all(rows), "Selection original output field count differs")
    return rows[0] if rows else None


def selection_native_return(value: str) -> tuple[int, int] | None:
    if value == "-":
        return None
    first, separator, second = value.partition(",")
    need(separator == "," and re.fullmatch(r"0|-?[1-9][0-9]{0,9}", first) is not None,
         "Noncanonical native return")
    result = int(first)
    need(-(1 << 31) <= result < 1 << 31, "Native return outside its original type")
    return result, number(second, (1 << 32)-1)


def selection_phase_mask(case: str) -> int:
    return {"select-fresh": 121, "select-reuse": 127, "remove-reuse": 103, "repair-reuse": 121,
            "stop-old": 3, "recover-previous": 121, "stop-new": 15, "recover-current": 127,
            "remove-damaged": 103}.get(case, 0)


def selection_accounting(raw: str, case: str, context: dict) -> dict:
    need(binding(context)["profile"] == SELECTION_PROFILE and case in SELECTION_CASE_CONFIG
         and type(raw) is str and 0 < len(raw) <= 16384 and raw.isascii()
         and all(32 <= ord(c) <= 126 for c in raw), "Selection accounting bound/profile differs")
    iterator = iter(raw.split(";"))
    fields = {}
    def take(key):
        part = next(iterator, "")
        name, separator, value = part.partition("=")
        need(name == key and separator == "=" and value and "=" not in value and key not in fields,
             "Accounting fields/order/nullable field differs")
        fields[key] = value
        return value
    for key in SELECTION_ACCOUNT_HEAD:
        take(key)
    require_bound(fields, context)
    need(fields["version"] == "1" and fields["case"] == case
         and selection_digest(fields["sourceSha"], 40) and selection_digest(fields["sourceTree"], 40)
         and number(fields["runId"], (1 << 64)-1, 1) > 0, "Accounting source identity differs")
    need(fields["previewObservationSha256"] == "-" if case == "refuse-foreign-selector"
         else selection_digest(fields["previewObservationSha256"]), "Accounting preview observation differs")
    need(fields["recoveryRun"] == "-" or selection_digest(fields["recoveryRun"], 32), "Accounting recovery ID differs")
    number(fields["inputs"], 54); number(fields["runtime"], 47)
    need(fields["readonlyClosed"] == fields["competitorClosed"] == "true", "Originals not settled")
    competing = case == "registry-conflict"
    need(all(fields[key] == str(competing).lower() for key in ("conflictStaged", "conflictReturned", "competitorPresent")),
         "Genuine second-transaction observation differs")
    reports = {}
    for prefix in (("main", "competitor") if competing else ("main",)):
        report = {key: take(prefix + "." + key) for key in SELECTION_ACCOUNT_REPORT}
        need(report["mode"] == SELECTION_CASE_CONFIG[case][1]
             and report["stage"] in ("Fresh", "Observed", "RegistryStaged", "BackupIntentFlushed",
                 "BackupReturned", "SelectIntentFlushed", "SelectReturned", "RegistryIntentFlushed", "RegistryReturned", "Closed")
             and report["disposition"] in ("Unchanged", "Selected", "LaunchEntriesRemoved", "Partial")
             and (report["firstFailure"] == "-" or re.fullmatch(r"[a-z0-9\-]{1,96}", report["firstFailure"]) is not None),
             "Closed report mode/stage/disposition differs")
        need(all(report[key] in ("true", "false") for key in
                 ("oldMoveEntered", "newMoveEntered", "registryCommitEntered", "registryCommitted"))
             and report["nativeClosed"] == ("true" if prefix == "main" else "false")
             and report["writeCountUnknown"] == report["shippingInstallerEnabled"] == "false"
             and report["controllerFinalityRequired"] == "true", "Accounting native/finality policy differs")
        for key in ("oldMoveNative", "newMoveNative", "registryNative"):
            selection_native_return(report[key])
        closed, flushed = number(report["closedRecords"], 7), number(report["flushedRecords"], 7)
        need(closed <= flushed and number(report["phaseMask"], 127).bit_count() == closed,
             "Closed records/mask/flush acknowledgements differ")
        need(number(report["confirmed"], 8 << 20) <= number(report["charged"], 8 << 20),
             "Output confirms more than originally charged")
        if report["retainedBytes"] != "-":
            number(report["retainedBytes"], 2 << 30)
        outputs = []
        for index in range(number(report["outputs"], 24)):
            value = {key: take(f"{prefix}.o{index}.{key}") for key in ("kind", "path", "destination", "native")}
            need(value["kind"] in ("CreatedDirectory", "CreatedFile", "Rename")
                 and selection_output_role(value["path"])
                 and ((value["kind"] == "Rename" and selection_output_role(value["destination"]))
                      or (value["kind"] != "Rename" and value["destination"] == "-"))
                 and selection_native_return(value["native"]) == (1, 0), "Unclosed or invalid original output")
            outputs.append(value)
        report["outputRows"] = outputs
        reports[prefix] = report
    need(next(iterator, None) is None and sum(len(r["outputRows"]) for r in reports.values()) <= 24,
         "Accounting trailing or aggregate output rows differ")
    main = reports["main"]
    need(main["charged"] == main["confirmed"] and number(main["phaseMask"], 127) == selection_phase_mask(case),
         "Actual returned accounting/phase contract differs")
    old = case in ("select-reuse", "remove-reuse", "stop-old", "stop-new", "recover-current", "remove-damaged")
    new = case in ("select-fresh", "select-reuse", "repair-reuse", "recover-previous", "stop-new", "recover-current")
    commit = case in ("select-fresh", "select-reuse", "remove-reuse", "repair-reuse",
                      "recover-previous", "recover-current", "remove-damaged")
    for key, expected in (("oldMove", old), ("newMove", new), ("registryCommit", commit)):
        need(main[key+"Entered"] == str(expected).lower(), "Unexpected entered selection effect")
    need(main["registryCommitted"] == str(commit).lower()
         and main["oldMoveNative"] == ("1,0" if old else "-")
         and main["newMoveNative"] == ("1,0" if new else "-")
         and main["registryNative"] == ("1,0" if commit else "-"), "Actual native effect returns differ")
    root = "selection/recovery/" + fields["recoveryRun"]
    expected_moves = ([("selector", root + "/previous.lnk")] if old else []) + \
                     ([(root + "/incoming.lnk", "selector")] if new else [])
    need([(r["path"], r["destination"]) for r in main["outputRows"] if r["kind"] == "Rename"] == expected_moves,
         "Additional or reordered original rename is not permitted")
    stop = case in ("stop-old", "stop-new")
    failed = stop or case in ("registry-conflict", "refuse-stale-repair", "refuse-foreign-selector")
    disposition = "Partial" if stop else "LaunchEntriesRemoved" if case in ("remove-reuse", "remove-damaged") \
        else "Selected" if commit or case == "verify-reuse" else "Unchanged"
    need(main["disposition"] == disposition and (main["firstFailure"] != "-") == failed,
         "Selection success/refusal disposition differs")
    if commit:
        need(main["stage"] == "Closed", "Completed operation was not closed")
    if commit or stop:
        need(selection_digest(fields["recoveryRun"], 32) and main["charged"] != "0",
             "Mutating selection lost its original recovery/output account")
    elif competing:
        need(selection_digest(fields["recoveryRun"], 32) and main["outputRows"] == [
                 {"kind": "CreatedDirectory", "path": root, "destination": "-", "native": "1,0"}]
             and main["charged"] == main["confirmed"] == "0"
             and main["closedRecords"] == main["flushedRecords"] == main["phaseMask"] == "0",
             "Unchanged conflict still requires its created recovery directory")
        second = reports["competitor"]
        need(not second["outputRows"] and second["charged"] == second["confirmed"]
             and number(second["charged"], 8 << 20, 1) > 0
             and second["nativeClosed"] == "false", "Original staging account must not fabricate competitor settlement")
        need(all(second[k] == "false" for k in ("oldMoveEntered", "newMoveEntered", "registryCommitEntered", "registryCommitted"))
             and all(second[k] == "-" for k in ("oldMoveNative", "newMoveNative", "registryNative"))
             and all(second[k] == "0" for k in ("closedRecords", "flushedRecords", "phaseMask")),
             "Competitor attempted an unreviewed effect")
    else:
        need(fields["recoveryRun"] == "-" and not main["outputRows"]
             and all(main[k] == "0" for k in ("charged", "confirmed", "closedRecords", "flushedRecords", "phaseMask")),
             "Readonly/refused operation produced unaccounted output")
    readonly = (SELECTION_CASE_CONFIG[case][4] and SELECTION_CASE_CONFIG[case][1] in
                ("verify-and-restore-launch-entries", "recover-previous-launch-selection", "recover-current-launch-selection")) \
        or (commit and case not in ("remove-reuse", "remove-damaged")) or stop or case == "verify-reuse"
    if readonly:
        need(fields["inputs"] == "54" and fields["runtime"] == "47", "Full readonly input/runtime census absent")
    if SELECTION_CASE_CONFIG[case][4] and not readonly or case in ("remove-reuse", "remove-damaged", "registry-conflict"):
        need(fields["inputs"] == fields["runtime"] == "0", "Offline namespace-only operation did not remain narrow")
    return {"fields": fields, "main": main, "competitor": reports.get("competitor")}


def selection_app_record(raw: bytes, case: str, context: dict) -> dict:
    libtest(raw)
    text = raw.decode("utf-8", "strict")
    accounting = selection_accounting(selection_one(text, SELECTION_ACCOUNT_PREFIX), case, context)
    proof = wire(("CASE\n" + selection_one(text, SELECTION_CASE_PREFIX).replace(";", "\n") + "\n").encode("ascii"),
                 "CASE", SELECTION_CASE_KEYS, 4096)
    need(proof["case"] == case and proof["originalWatchdogJoined"] == proof["nativeSettled"] == "true",
         "App original/watchdog did not settle")
    for key in ("disposition", "closedRecords", "phaseMask", "charged", "confirmed"):
        need(proof[key] == accounting["main"][key], "Summary disagrees with full accounting")
    for key in ("inputs", "runtime"):
        need(proof[key] == accounting["fields"][key], "Summary census differs")
    config = SELECTION_CASE_CONFIG[case]
    raw_preview = selection_one(text, SELECTION_PREVIEW_PREFIX, int(config[4]))
    preview = selection_preview(raw_preview, case) if raw_preview is not None else None
    recovery = selection_one(text, SELECTION_RECOVERY_PREFIX, int(config[6]))
    if recovery is not None:
        need(selection_digest(recovery, 32) and recovery == accounting["fields"]["recoveryRun"],
             "STOP did not emit its actual owned recovery ID")
    if preview is not None:
        need(preview["observationSha256"] == accounting["fields"]["previewObservationSha256"],
             "Preview/accounting observation differ")
    return {**accounting, "preview": preview, "previewRaw": raw_preview, "recovery": recovery}


def selection_exit(raw: bytes, context: dict, pre: dict, pre_sha: str, role: str, result: bytes) -> dict:
    value = wire(raw, EXIT_HEADER, EXIT_KEYS, 8192)
    require_bound(value, context)
    kind = "app" if selection_route(role)[0] == "app" else "native"
    need(value["role"] == role and value["precheckSha256"] == pre_sha
         and value["artifactSha256"] == pre[kind + "ArtifactSha256"]
         and value["commandSha256"] == selection_command_sha(pre[kind + "Artifact"], role)
         and number(value["resultBytes"], 65536, 1) == len(result) and value["resultSha256"] == sha(result)
         and value["originalWaitReturned"] == "true" and value["exitCode"] == "0"
         and value["writerCloseGate"] == "original-owner-closed-output", "Selection original exit/binding differs")
    return value


def selection_state(role: str, proofs: dict, profiles: dict) -> dict:
    selection_route(role)
    prefix = SELECTION_ROLES[:SELECTION_ROLES.index(role)+1]
    need(set(proofs) == {name for name in prefix if name in SELECTION_CASE_CONFIG}, "Selection prefix app census differs")
    sources, images, objects, runs = [], [], {}, []
    selector = registration = None
    def add(path, directory, owner):
        need(path not in objects, "Selection effect collides with retained output")
        objects[path] = (directory, owner, path)
    for name in prefix:
        kind, _ = selection_route(name)
        if kind == "native-stage":
            source = name.removeprefix("stage-")
            need(source in SELECTION_SOURCES and source not in sources, "Invalid source stage")
            sources.append(source)
        if kind != "app":
            continue
        proof = proofs[name]
        if SELECTION_CASE_CONFIG[name][5]:
            image = SELECTION_CASE_CONFIG[name][0]
            need(image in sources and image not in images, "Selection used unstaged/repeated image")
            images.append(image)
        for item in proof["main"]["outputRows"]:
            if item["kind"] in ("CreatedDirectory", "CreatedFile"):
                add(item["path"], item["kind"] == "CreatedDirectory", name)
            else:
                need(item["path"] in objects and not objects[item["path"]][0]
                     and item["destination"] not in objects, "Rename source/target ownership differs")
                objects[item["destination"]] = objects.pop(item["path"])
        run = proof["fields"]["recoveryRun"]
        if run != "-":
            need(selection_digest(run, 32) and run not in [value[1] for value in runs], "Recovery run ID reused")
            runs.append((name, run))
        chosen = {"select-fresh": "fresh", "select-reuse": "reuse", "repair-reuse": "reuse",
                  "recover-previous": "reuse", "recover-current": "bad-manifest"}.get(name)
        if chosen is not None:
            selector = registration = chosen
        elif name in ("remove-reuse", "remove-damaged"):
            selector = registration = None
        elif name == "stop-old":
            selector = None
        elif name == "stop-new":
            selector = "bad-manifest"
    foreign = "stage-owned-foreign-selector" in prefix
    if foreign:
        need(selector is registration is None, "Foreign setup must not replace selected launch entries")
        add("selector", False, "stage-owned-foreign-selector")
    expected = set()
    if images:
        expected.update(("selection", "selection/" + TARGET, "selection/recovery"))
        for name in images:
            root = "selection/" + TARGET + "/" + sha(canonical(profiles[name]))
            expected.update((root, root+"/profile.json", root+"/launch.lnk"))
        for name, run in runs:
            root = "selection/recovery/" + run
            expected.add(root)
            report = proofs[name]["main"]
            expected.update(f"{root}/record-{index:02}.bin" for index in range(7)
                            if int(report["phaseMask"]) & (1 << index))
            if report["oldMoveEntered"] == "true":
                expected.add(root + "/previous.lnk")
            if name == "stop-old":
                expected.add(root + "/incoming.lnk")
    if selector is not None or foreign:
        expected.add("selector")
    need(set(objects) == expected and len(runs) <= 10, "Complete final effect census differs")
    return {"sources": sources, "images": images, "objects": objects, "runs": runs,
            "selector": selector, "registration": registration, "foreign": foreign}


def selection_snapshot(f, raw: bytes, context: dict, pre: dict, pre_sha: str, role: str,
                       state: dict, profiles: dict) -> dict:
    need(binding(context)["profile"] == SELECTION_PROFILE and role in SELECTION_NATIVE_OPEN_BUDGET
         and type(raw) is bytes and 0 < len(raw) <= 65536 and raw.isascii()
         and raw.endswith(b"\n") and all(c == 10 or 32 <= c <= 126 for c in raw), "Selection snapshot framing differs")
    lines = raw[:-1].split(b"\n")
    head = len(SELECTION_SNAP_KEYS) + 1
    need(len(lines) >= head, "Truncated snapshot")
    value = wire(b"\n".join(lines[:head]) + b"\n", SELECTION_SNAP_HEADER, SELECTION_SNAP_KEYS)
    require_bound(value, context)
    need(value["role"] == role and value["precheckSha256"] == pre_sha
         and value["profilesSha256"] == pre["profilesSha256"] and value["rosterSha256"] == pre["rosterSha256"]
         and value["parentBookSettled"] == value["selectionPrimitivesClosed"] == "true"
         and value["unknown"] == "false" and value["resultCloseGate"] == "original-fixture-exit-zero-required"
         and number(value["fileOriginals"], SELECTION_NATIVE_OPEN_BUDGET[role], 1)
             == number(value["fileOriginalsClosed"], SELECTION_NATIVE_OPEN_BUDGET[role], 1)
         and selection_dos_path(value["programFiles"]) and selection_dos_path(value["commonPrograms"]),
         "Selection snapshot original source/settlement differs")
    need(value["freshMrkAbsent"] == str(not state["images"]).lower()
         and number(value["accountedRuns"], 10) == len(state["runs"]), "Selection snapshot state/run census differs")
    def image(name):
        return "-" if name is None else sha(canonical(profiles[name]))
    need(value["selectorImage"] == ("f"*64 if state["foreign"] else image(state["selector"]))
         and value["registrationImage"] == image(state["registration"])
         and (value["registrationSecurityDigest"] == "-" if state["registration"] is None
              else selection_digest(value["registrationSecurityDigest"])), "Selection launch/registry image differs")
    write = number(value["registrationWrite"], (1 << 64)-1)
    need(write == 0 if state["registration"] is None else write > 0, "Registry write observation differs")
    stage = selection_route(role)[0] == "native-stage"
    need(value["candidate"] == (value["programFiles"] + "\\MRK Installer Fixture " + image(role[6:]) if stage else "-"),
         "Selected source candidate is not exact")
    ntree, nobject = number(value["trees"], 9), number(value["objects"], 130, 2)
    need(len(lines) == head + ntree + nobject, "Selection snapshot tree/object count differs")
    trees = {}
    expected_trees = {"source/"+name: (9, 54, sum(row["size"] for row in profiles[name]["inputs"])) for name in state["sources"]}
    expected_trees.update({"image/"+name: (7, 54, sum(row["size"] for row in profiles[name]["inputs"])) for name in state["images"]})
    if state["images"]:
        expected_trees["runtime"] = (2, 47, sum(row["size"] for row in profiles["fresh"]["inputs"][:47]))
    previous = ""
    for raw_row in lines[head:head+ntree]:
        need(raw_row.startswith(b"tree="), "Selection complete-tree frame differs")
        row = raw_row[5:].decode("ascii").split("|")
        need(len(row) == 5 and row[0] in expected_trees and row[0] > previous
             and (number(row[1], 12), number(row[2], 54), number(row[3], 128 << 20, 1)) == expected_trees[row[0]]
             and selection_digest(row[4]), "Selection complete-tree commitment differs")
        trees[row[0]] = tuple(row[1:])
        previous = row[0]
    need(set(trees) == set(expected_trees), "Selection complete tree census omitted/added a tree")
    shared = {"os/program-files", "os/programs"}
    if state["images"]:
        shared.update(("shared/mrk", "shared/installer-input", "shared/installer-target",
                       "shared/runtime-input", "shared/runtime-target", "shared/versions", "shared/versions-target"))
    expected_objects = set(state["objects"]) | shared
    objects, identities, previous = {}, set(), ""
    for raw_row in lines[head+ntree:]:
        need(raw_row.startswith(b"observed="), "Selection object frame differs")
        row = raw_row[9:].decode("ascii").split("|")
        need(len(row) == 6 and row[0] in expected_objects and row[0] > previous
             and row[1] in ("directory", "file") and selection_digest(row[3]), "Selection object name/kind/ACL differs")
        directory = row[1] == "directory"
        need(directory == (row[0] in shared or state["objects"][row[0]][0]), "Selection output kind differs")
        stamp = f.windows_fullwalk_stamp(row[2])
        identity = stamp["volume"], stamp["fileId"]
        need(identity not in identities and bool(stamp["attributes"] & 0x10) is directory
             and ((row[4] == "-" and selection_digest(row[5])) if directory
                  else (selection_digest(row[4]) and row[5] == "-")), "Selection object identity/content/census differs")
        identities.add(identity)
        objects[row[0]] = {"role": row[0], "directory": directory, "stamp": stamp,
                          "security": row[3], "sha256": row[4], "inventorySha256": row[5]}
        previous = row[0]
    need(set(objects) == expected_objects and len({obj["stamp"]["volume"] for obj in objects.values()}) == 1,
         "Selection namespace census/volume differs")
    # Recompute every selection-directory census from ALL returned immediate
    # child identities, not a sampled/stripped object inventory.
    for name, obj in objects.items():
        if name not in state["objects"] or not obj["directory"]:
            continue
        children = sorted((path.rsplit("/", 1)[1], child) for path, child in objects.items()
                          if "/" in path and path.rsplit("/", 1)[0] == name)
        encoded = "".join(f'{leaf}|{"directory" if child["directory"] else "file"}|'
                          f'{child["stamp"]["fileId"]}|{child["stamp"]["attributes"]}\n' for leaf, child in children)
        need(obj["inventorySha256"] == sha(encoded.encode("ascii")), "Selection exact child identity census differs")
    for name in state["images"]:
        path = "selection/" + TARGET + "/" + image(name) + "/profile.json"
        need(objects[path]["stamp"]["size"] == len(canonical(profiles[name]))
             and objects[path]["sha256"] == image(name), "Persisted canonical provenance differs")
    damaged = None
    if value["damagedShell"] != "-":
        parts = value["damagedShell"].split("|")
        need(len(parts) == 3 and selection_digest(parts[1]) and selection_digest(parts[2]), "Damage observation framing differs")
        damaged = {"stamp": f.windows_fullwalk_stamp(parts[0]), "security": parts[1], "sha256": parts[2]}
        need(damaged["stamp"]["size"] == profiles["bad-manifest"]["inputs"][48]["size"]
             and not damaged["stamp"]["attributes"] & 0x10
             and damaged["sha256"] != profiles["bad-manifest"]["inputs"][48]["sha256"], "Damage is not actual fourth shell payload")
    need((damaged is not None) == ("damage-owned-shell" in SELECTION_ROLES[:SELECTION_ROLES.index(role)+1]),
         "Owned damage boundary missing/early")
    need(selection_digest(value["foreignSelector"]) if state["foreign"] else value["foreignSelector"] == "-",
         "Fixed owned foreign selector missing/early")
    if state["foreign"]:
        need(objects["selector"]["sha256"] == value["foreignSelector"], "Foreign source bytes differ")
    return {"fields": value, "trees": trees, "objects": objects, "damage": damaged, "state": state}


def selection_same_directory(before: dict, after: dict, changed: bool) -> None:
    if not changed:
        need(before == after, "Untouched directory metadata, ACL or roster changed")
        return
    a, b = before["stamp"], after["stamp"]
    need(before["directory"] and after["directory"] and before["role"] == after["role"]
         and before["security"] == after["security"] and before["sha256"] == after["sha256"] == "-"
         and before["inventorySha256"] != after["inventorySha256"]
         and all(a[key] == b[key] for key in ("volume", "fileId", "creation", "links", "attributes"))
         and b["write"] >= a["write"] and b["change"] >= a["change"]
         and b["size"] >= 0 and b["allocation"] >= 0, "Owned child change exceeded allowed directory delta")


def selection_transition(before: dict | None, after: dict, role: str, proofs: dict) -> None:
    if before is None:
        need(role == "stage-fresh" and set(after["trees"]) == {"source/fresh"}
             and set(after["objects"]) == {"os/program-files", "os/programs"}
             and after["fields"]["selectorImage"] == after["fields"]["registrationImage"] == "-",
             "Selection episode did not start fresh")
        return
    old, new = before["state"], after["state"]
    fields_before, fields_after = before["fields"], after["fields"]
    for key in ("programFiles", "commonPrograms", "registrationParentSha256"):
        need(fields_before[key] == fields_after[key], "Original system/registry parent changed")
    for name, tree in before["trees"].items():
        need(name in after["trees"], "An immutable tree disappeared")
        if role == "damage-owned-shell" and name == "image/bad-manifest":
            need(tree[:3] == after["trees"][name][:3] and tree[3] != after["trees"][name][3],
                 "Owned same-length shell damage did not change its complete commitment")
        else:
            need(tree == after["trees"][name], "Existing complete tree commitment changed")
    reverse = {origin: name for name, origin in old["objects"].items()}
    need(len(reverse) == len(old["objects"]), "Duplicated retained origin")
    for name, obj in after["objects"].items():
        if name in new["objects"]:
            origin = new["objects"][name]
            old_name = reverse.get(origin)
            if old_name is None:
                need(origin[1] == role.removesuffix("-observe")
                     and all((obj["stamp"]["volume"], obj["stamp"]["fileId"])
                             != (v["stamp"]["volume"], v["stamp"]["fileId"]) for v in before["objects"].values()),
                     "New effect does not belong to current original")
                continue
            previous = before["objects"][old_name]
            if obj["directory"]:
                def children(state, at):
                    return {p.rsplit("/", 1)[1]: value for p, value in state["objects"].items()
                            if "/" in p and p.rsplit("/", 1)[0] == at}
                selection_same_directory(previous, obj, children(old, old_name) != children(new, name))
            elif old_name == name:
                need(previous == obj, "Retained output changed without a recorded rename")
            else:
                need(obj["security"] == previous["security"] and obj["sha256"] == previous["sha256"]
                     and all(obj["stamp"][k] == previous["stamp"][k] for k in previous["stamp"] if k != "change")
                     and obj["stamp"]["change"] >= previous["stamp"]["change"], "Rename changed content, ACL or other full identity")
        elif name in before["objects"]:
            changed = (old["sources"] != new["sources"] or bool(old["images"]) != bool(new["images"])) if name == "os/program-files" \
                else old["objects"].get("selector") != new["objects"].get("selector") if name == "os/programs" \
                else old["images"] != new["images"] if name in ("shared/installer-target", "shared/runtime-target") else False
            selection_same_directory(before["objects"][name], obj, changed)
        else:
            need(role == "select-fresh-observe" and name.startswith("shared/"), "Unexplained shared namespace object")
    need(set(old["objects"].values()) <= set(new["objects"].values()), "A retained output origin was deleted")
    case = role.removesuffix("-observe")
    committed = case in proofs and proofs[case]["main"]["registryCommitted"] == "true"
    if not committed:
        for key in ("registrationSha256", "registrationSecurityDigest", "registrationWrite", "registrationImage"):
            need(fields_before[key] == fields_after[key], "Uncommitted operation changed native registration")
    elif fields_before["registrationImage"] != "-" and fields_after["registrationImage"] != "-":
        need(fields_before["registrationSecurityDigest"] == fields_after["registrationSecurityDigest"],
             "Registry overwrite changed the retained key descriptor")
    if role != "damage-owned-shell":
        need(before["damage"] == after["damage"], "Owned damage observation was replaced")
    if role != "stage-owned-foreign-selector":
        need(fields_before["foreignSelector"] == fields_after["foreignSelector"], "Foreign source observation was replaced")


def selection_finalize(f, context: dict) -> None:
    need(binding(context)["profile"] == SELECTION_PROFILE, "Wrong selection finalizer profile")
    root = Path(context["root"])
    outcomes(os.environ.get("MRK_SELECTION_OUTCOMES", ""), SELECTION_ROLES)
    need(os.environ.get("MRK_RETAINED_PRECHECK_OUTCOME") == os.environ.get("MRK_RETAINED_PROBES_OUTCOME") == "success",
         "Selection original precheck/probe finality absent")
    probes(f, context, create=False)
    compiled, data, originals = compilation(f, context, inspect_inputs=False)
    pre_raw = f.windows_installed_bytes(root / "retained-shell-precheck.private.txt", 16384)
    pre_sha = sha(pre_raw)
    pre = wire(pre_raw, PRE_HEADER, PRE_KEYS)
    require_bound(pre, context)
    need(pre["sourceInventorySha256"] == sha(canonical(context["sourceFiles"]))
         and pre["profilesSha256"] == data["profiles"]["sha256"] and pre["rosterSha256"] == data["roster"]["sha256"]
         and all(pre[role+"ArtifactSha256"] == originals[role]["sha256"] for role in ("native", "app")),
         "Original selection compilation binding changed")
    profile_raw = f.windows_installed_bytes(root / "fixture-profiles.ndjson", 65536)
    roster_raw = f.windows_installed_bytes(root / "fixture-roster.txt", 32768)
    need(sha(profile_raw) == pre["profilesSha256"] and sha(roster_raw) == pre["rosterSha256"], "Actual selection compile DATA changed")
    parts = profile_raw.splitlines()
    need(len(parts) == 6 and parts[0] == b"MRK_WINDOWS_RETAINED_SHELL_FIXTURE_PROFILE_SET_V1", "Profile set framing differs")
    profiles = dict(zip(CASES, (f.bounded_json(part, 8192) for part in parts[1:]), strict=True))
    need(all(sha(canonical(profile)) != "f"*64 for profile in profiles.values()), "Foreign fixed image collides with source")
    proofs, snapshots, records = {}, {}, {}
    previous = None
    for role, kind, _ in SELECTION_CHAIN:
        stem = "retained-" + role
        result = f.windows_installed_bytes(root / (stem + ".private.txt"), 65536)
        exit_raw = f.windows_installed_bytes(root / (stem + "-exit.private.txt"), 8192)
        selection_exit(exit_raw, context, pre, pre_sha, role, result)
        stderr = f.windows_installed_bytes(root / (stem + ".stderr.private.bin"), 65536)
        need(stderr == b"", "Selection behavioral original stderr is nonempty")
        if kind == "app":
            proofs[role] = selection_app_record(result, role, context)
            config = SELECTION_CASE_CONFIG[role]
            if config[2] is not None:
                need(config[2] in proofs and proofs[config[2]]["previewRaw"] is not None
                     and proofs[role]["fields"]["previewObservationSha256"]
                         == proofs[config[2]]["preview"]["observationSha256"],
                     "Apply did not retain the exact prior confirmation observation")
            if config[3] is not None:
                need(config[3] in proofs and selection_digest(proofs[config[3]]["recovery"], 32),
                     "Recovery has no prior actual STOP output")
        else:
            stdout = f.windows_installed_bytes(root / (stem + ".stdout.private.bin"), 65536)
            libtest(stdout)
            need(len(stdout) + len(stderr) <= 65536, "Aggregate original stdout/stderr exceeded64KiB")
            state = selection_state(role, proofs, profiles)
            current = selection_snapshot(f, result, context, pre, pre_sha, role, state, profiles)
            selection_transition(previous, current, role, proofs)
            snapshots[role], previous = current, current
        records[role] = {"result": {"size": len(result), "sha256": sha(result)},
                         "exit": {"size": len(exit_raw), "sha256": sha(exit_raw)}}
    need(len(proofs) == 24 and len(snapshots) == 30 and len(previous["state"]["runs"]) == 10,
         "Selection original prefix is incomplete")
    files = selection_behavior_files()
    with os.scandir(root) as entries:
        actual = {entry.name for entry in entries if entry.name.startswith("retained-")
                  and any(entry.name.endswith(suffix) for suffix in
                          (".private.txt", "-exit.private.txt", ".stdout.private.bin", ".stderr.private.bin"))}
    # Common precheck is a separate known DATA file, not a behavioral original.
    actual.difference_update({"retained-shell-precheck.private.txt",
        *(f"retained-{role}-{phase}.stderr.private.txt" for role in ("native", "app") for phase in ("acquire", "compile"))})
    need(actual == set(files), "Unexpected historical/mixed/partial behavioral outputs")
    outputs = {name: f.windows_installed_record(root / name, limit) for name, limit in files.items()}
    need(sum(row["size"] for row in outputs.values()) <= SELECTION_OUTPUT_BUDGET,
         "Selection evidence exceeded exact aggregate output budget")
    f.windows_installed_inputs(context, retention_only=True)
    new_json(f, root / "selection-final.private.json", {
        "schemaVersion": 1, **binding(context), "status": "passed",
        "behavioralOriginals": 54, "nativeOriginals": 30, "appOriginals": 24, "pipeProbeOriginals": 3,
        "caseCount": 24, "accountedRuns": 10, "precheckSha256": pre_sha, "records": records,
        "privateOutputs": outputs, "sourceInventorySha256": pre["sourceInventorySha256"],
        "notVerified": list(NOT_VERIFIED), "shippingInstallerEnabled": False, "desktopReady": False})


def selection_retain(f, context: dict) -> None:
    root = Path(context["root"])
    actual = os.environ.get("MRK_SELECTION_FINALIZE_OUTCOME", "")
    need(actual in ("success", "failure", "cancelled", "skipped"), "Selection finalizer outcome absent")
    summary = {"schemaVersion": 1, **binding(context), "status": "not-verified", "actualFinalizerOutcome": actual,
        "desktopReady": False, "shippingInstallerEnabled": False, "notVerified": list(NOT_VERIFIED),
        "rawPrivateOutputUploaded": False}
    if actual == "success":
        value = f.read_bounded_json(root / "selection-final.private.json", 256 << 10)
        require_bound(value, context)
        need(value["status"] == "passed" and (value["behavioralOriginals"], value["nativeOriginals"],
            value["appOriginals"], value["pipeProbeOriginals"], value["caseCount"], value["accountedRuns"]) == (54, 30, 24, 3, 24, 10),
            "Selection finalizer counts differ")
        summary.update(status="passed", behavioralOriginals=54, nativeOriginals=30, appOriginals=24,
                       pipeProbeOriginals=3, caseCount=24, accountedRuns=10, precheckSha256=value["precheckSha256"],
                       privateResultSha256=f.windows_installed_record(root / "selection-final.private.json", 256 << 10)["sha256"])
    new_json(f, root / "public/selection-summary.json", summary)


def phase(f, context: dict, name: str, deadline: float) -> None:
    binding(context)
    allowed = ("prepare", "acquire", "compile", "retain", *PHASES[:2],
               *(SELECTION_PHASES if binding(context)["profile"] == SELECTION_PROFILE else PHASES[2:]))
    need(name in allowed, "No cross-profile, legacy or shipping fixture fallback")
    source_pins(context)
    if name == "prepare":
        prepare(f, context)
    elif name == "acquire":
        acquire(f, context, deadline)
    elif name == "compile":
        compile_only(f, context, deadline)
    elif name == "windows-retained-probes-finalize":
        probes(f, context, create=True)
    elif name == "windows-retained-precheck":
        precheck(f, context)
    elif name == "windows-retained-finalize":
        finalize(f, context)
    elif name == "windows-selection-finalize":
        selection_finalize(f, context)
    else:
        (selection_retain if binding(context)["profile"] == SELECTION_PROFILE else retain)(f, context)
