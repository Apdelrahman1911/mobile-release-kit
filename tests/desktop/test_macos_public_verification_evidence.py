"""Inert DATA/privacy tests; never native tools, secret inputs or Apple requests."""
import ast
import copy
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import re
from subprocess import CompletedProcess
import tempfile
import time
from types import SimpleNamespace
import unittest
from contextlib import redirect_stderr, redirect_stdout

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("macos_public_verification_evidence", ROOT / "desktop/tools/macos_public_verification_evidence.py")
DATA = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DATA)
CONTEXT = {"profile": "installed", "source": "1" * 40, "workflowSource": "1" * 40,
           "runId": "123", "runAttempt": "2", "target": "aarch64-apple-darwin"}
SENTINEL = "PRIVATE_SENTINEL_do_not_publish_/key/file_or_argv"


def budget():
    return {"nodes": 0, "deadline": time.monotonic_ns() + 45_000_000_000}


def receipt(phase="finalize-image"):
    return {"schemaVersion": 1, "phase": phase, **CONTEXT, "passed": True,
            "targetRetired": True, "originalClosesKnown": True, "outerFinalityRequired": True,
            "originalCalls": [{"role": "final-image-log", "entered": True, "returned": True,
                "capturesSettled": True, "returncode": 0, "stdoutSha256": "a" * 64, "stderrSha256": "b" * 64}],
            "credentialOriginals": [], "credentialContexts": [],
            "notaryAuthentication": {"created": True, "closed": True, "retired": True},
            "notarySubmission": {"id": "12345678-1234-1234-1234-123456789abc", "status": "Accepted"},
            "finalImage": {"schemaVersion": 1, "kind": "mrk-final-user-image", "target": CONTEXT["target"], "submissionId": "12345678-1234-1234-1234-123456789abc", "status": "Accepted",
                "logSha256": "a" * 64, "sha256Compared": False, "errorCount": 0, "warningCount": 2,
                "ticketRowCount": 3, "imageSha256": "c" * 64, "imageBytes": 4096,
                "actualStaplerValidation": True, "originalMountDetached": True}}


def same_package_receipt():
    value = receipt("same-package-noop")
    del value["finalImage"], value["notarySubmission"]
    value.update(productReady=False, notaryAuthentication={"created": False, "closed": False, "retired": False},
        directStagerIOPending=None, cleanupErrors=[],
        originalCalls=[{"role": role, "entered": True, "returned": True, "capturesSettled": True,
            "returncode": 0, "stdoutSha256": "a" * 64, "stderrSha256": "b" * 64}
            for role in ("distribution-attach", "installer", "distribution-detach")],
        packageMount={"attachEntered": True, "originalKnown": True, "detached": True, "retained": False,
            "installerEntered": True, "installerOriginalZero": True, "sameRequestV2Readback": True, "systemServiceExitClaimed": False})
    value["samePackageObservation"] = {"schemaVersion": 1, "kind": "final-carrier-same-package-noop",
        **{name: "a" * 64 for name in ("finalImageReceiptSha256", "imageSha256", "packageSha256", "inventorySha256",
              "runtimeManifestSha256", "baselineResultSha256")}, "resultSha256": "b" * 64,
        "beforeExportCount": 1, "afterExportCount": 2, "newExportCount": 1, "payloadWriteCount": 0,
        "payloadWriteBytes": 0, "verifiedCurrentFiles": 2048,
        **{name: True for name in ("samePackageNoopObserved", "immediatePredecessorMatched", "currentObjectsPreserved",
            "retainedGenerationsPreserved", "currentBytesVerified", "baselineExportUnchanged", "originalInstallerReturnedZero",
            "mountReadOnly", "mountOriginalsMatch", "originalMountDetached")},
        "systemServiceExitClaimed": False, "productReady": False}
    return value



def update_documents():
    # Execute only the genuine closed current-receipt writer, not the adapter
    # loader, owner, SOURCE nomination, sentinel or any native/I/O operation.
    path = ROOT / "desktop/tools/macos_update_verification.py"
    nodes = [node for node in ast.parse(path.read_text()).body if isinstance(node, ast.FunctionDef)
             and node.name in ("need", "context", "current_complete")]
    assert {node.name for node in nodes} == {"need", "context", "current_complete"}
    namespace = {}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), namespace)
    baseline = receipt("update-baseline"); current = receipt("package-install")
    for row in (baseline, current):
        del row["finalImage"], row["notarySubmission"]
        row.update(productReady=False, notaryAuthentication={"created": False, "closed": False, "retired": False})
    baseline["originalCalls"] = [{"role": role, "entered": True, "returned": True, "capturesSettled": True,
        "returncode": 0, "stdoutSha256": "a" * 64, "stderrSha256": "b" * 64}
        for role in ("update-baseline-attach", "update-baseline-installer", "update-baseline-detach")]
    current["originalCalls"] = [{"role": role, "entered": True, "returned": True, "capturesSettled": True,
        "returncode": 0, "stdoutSha256": "a" * 64, "stderrSha256": "b" * 64}
        for role in ("producer-tests", "producer-build", "producer-emitter", "distribution-create", "distribution-sign", "distribution-verify-signature",
            "distribution-verify-image", "observation-create", "observation-sign", "observation-verify-signature", "observation-verify-image",
            "distribution-attach", "installer-log-cursor", "installer", "installer-log-capture", "distribution-detach")]
    old_facts = {"previous": {"invocation": "a" * 32, "sha256": "a" * 64},
                 "rootIdentity": {"private": SENTINEL}, "generation": {"instance": "a" * 32}}
    old = {"schemaVersion": 1, **{key: CONTEXT[key] for key in ("source", "workflowSource", "runId", "runAttempt", "target")},
        "predecessorSource": "2" * 40, "predecessorPackageSha256": "3" * 64, "qualificationEvidenceSha256": "4" * 64,
        "expectedCurrentDescriptorSha256": "5" * 64, "readback": old_facts, "productReady": False,
        "originalInstallerReturnedZero": True, "originalMountDetached": True, "freshCurrentBytesReadback": True,
        "privatePath": SENTINEL}
    baseline["updateBaseline"] = old
    op = SimpleNamespace(image_source=CONTEXT["source"], target=CONTEXT["target"], receipt=current,
        environment={"GITHUB_SHA": CONTEXT["source"], "GITHUB_RUN_ID": CONTEXT["runId"], "GITHUB_RUN_ATTEMPT": CONTEXT["runAttempt"]},
        installer_zero=True, installation_readback=True, mount_detached=True, package_settled=lambda: True,
        update={"baseline": old, "facts": {**old_facts, "previous": {"invocation": "b" * 32, "sha256": "b" * 64},
            "generation": {"instance": "b" * 32}}, "nomination": {"source": "2" * 40,
            "package": {"sha256": "3" * 64}, "qualificationEvidenceSha256": "4" * 64}})
    namespace["current_complete"](op)
    assert op.update["complete"] is True
    return baseline, current


def write_update_documents(root, documents):
    baseline, current = documents
    write(root, "android-helper-update-baseline.json", baseline)
    write(root, "android-helper-package-install.json", current)
    write(root, "update-baseline.status", b"0\n")
    write(root, "package-install.status", b"0\n")

def write(root, name, value):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if type(value) is bytes else json.dumps(value).encode())
    path.chmod(0o600)
    return path


def project(root, *, removal_case="disabled"):
    return DATA.project(str(root), profile="installed", source=CONTEXT["source"], workflow_source=CONTEXT["workflowSource"],
                        run_id=CONTEXT["runId"], run_attempt=CONTEXT["runAttempt"], target=CONTEXT["target"], removal_case=removal_case)


def normal_diagnostic_data(*, removal=False, positive=False):
    """Compile only genuine DATA writers/constants, never import the native runner.

    CompletedProcess is only an inert record constructor; no subprocess runner
    or native-owner namespace is exposed. The optional output-DATA resultPost
    branch is outside these build/query fixtures and is never entered.
    """
    path = ROOT / "desktop/tools/macos_normal_ui_runner.py"
    names = {"Refused", "need", "sha", "pairs", "document", "encoded", "failure_base",
        "normal_failure_diagnostics", "normal_admission_failure", "classify_normal_admission_failure", "ADMISSION_OWNER_REASONS",
        "NORMAL_SELECTIONS", "OUTPUT_DATA_RESULT",
        "IOS_PENDING_RESULT", "IOS_PENDING_METHOD", "IOS_UNSIGNED_RESULT", "IOS_UNSIGNED_METHOD", "IOS_UNSIGNED_STAGES", "ios_unsigned_stage_diagnostics", "LOADER", "TOOLCHAIN_QUERIES", "ADMISSION_STAGES",
        "ADMISSION_EXCEPTION_TYPES", "ADMISSION_EXCEPTION_LABELS", "ADMISSION_SOURCE_FILES", "ADMISSION_COMMAND_ROLES",
        "TARGET", "PROJECT", "INTEL_TARGET", "PhaseClock", "NormalPhase", "original_command",
        "normal_build_settings_arguments", "normal_build_settings_data", "publish_normal_build_settings",
        "NORMAL_BUILD_SETTINGS", "NORMAL_BUILD_ARCHITECTURES", "NORMAL_BUILD_PLATFORMS", "DESTINATION_REJECTIONS"}
    if positive:
        names.update(("android_signed_facts", "ios_unsigned_facts", "ANDROID_FACTS_SCOPE", "ARM_TARGET", "normal_target_data"))
    if removal:
        names.update(("TARGET", "CLASS", "REMOVAL_METHODS", "removal_selection", "removal_ui_result"))
    nodes, found = [], set()
    for node in ast.parse(path.read_text()).body:
        name = node.name if isinstance(node, (ast.FunctionDef, ast.ClassDef)) else (
            node.targets[0].id if isinstance(node, ast.Assign) and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name) else None)
        if name in names:
            nodes.append(node); found.add(name)
    if found != names:
        raise AssertionError("finite-normal-diagnostic-DATA-dependencies")
    namespace = {"hashlib": hashlib, "json": json, "re": re, "Path": Path, "__file__": str(path),
                 "subprocess": SimpleNamespace(CompletedProcess=CompletedProcess)}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), namespace)
    return namespace


def ordinary_ui_producer_data(context):
    """Evaluate actual producer result expressions with inert DATA ports only.

    No workflow shell/owner/result writer runs. The actual singleton DATA
    function validates its synthetic recovery input before producing a result.
    """
    lines = (ROOT / ".github/workflows/desktop-macos-installed.yml").read_text().splitlines()
    blocks = []
    for index, line in enumerate(lines):
        if "<<'PY_" not in line: continue
        delimiter = line.split("<<'", 1)[1].split("'", 1)[0]
        if delimiter not in ("PY_UI_RESULT", "PY_PERSISTENCE_RESULT", "PY_DIAGNOSTICS_RESULT",
                             "PY_SAVED_CHECKS_RESULT", "PY_SAVED_VERSION_RECOVERY_RESULT"): continue
        end = next(j for j in range(index + 1, len(lines)) if lines[j].strip() == delimiter)
        body = "\n".join(item[10:] for item in lines[index + 1:end]) + "\n"
        module = ast.parse(body)
        expression = next(node.value for node in module.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "result" for target in node.targets))
        blocks.append((module, expression))
    assert len(blocks) == 7 and ast.dump(blocks[-1][1]) == ast.dump(blocks[-2][1])
    preview = dict(schemaVersion=2, scope="normal-macos-early-preview", sourceCommit=context["source"],
        sourceTree="2" * 40, runId=context["runId"], runAttempt=context["runAttempt"],
        platform="macOS26-arm64" if context["target"] == DATA.TARGETS[0] else "macOS26-x86_64",
        packageSize=4096, entryBundleIdentifier="dev.mobile-release-kit.desktop.entry",
        payloadBundleIdentifier="dev.mobile-release-kit.desktop")
    preview.update({name: "a" * 64 for name in ("packageSha256", "runtimeManifestSha256",
        "installerInventorySha256", "normalBinaryBeforeSigningSha256", "signedAppBinarySha256", "signedEntryBinarySha256")})
    installation_receipt = receipt("package-install") | {name: context[name] for name in
        ("source", "workflowSource", "runId", "runAttempt", "target")}
    installation_receipt["finalImage"]["target"] = context["target"]
    installed = DATA.project_receipt(installation_receipt, context, "package-install")
    statuses = {"package-install.status": {"receiptState": "observed", "returncode": 0},
                "normal-ui/build.status": {"receiptState": "observed", "returncode": 0}}
    for definition in DATA.ORDINARY_UI_INPUTS:
        key = definition[0]
        role = {"launch": None, "savedChecks": "saved-checks", "savedVersion": "saved-version-recovery",
                "workflowRefusal": "workflow-refusal", "releaseEvidence": "release-evidence"}.get(key, key)
        for suffix in ("test", "summary"):
            statuses["normal-ui/" + ((role + "-") if role else "") + suffix + ".status"] = {
                "receiptState": "observed", "returncode": 0}
    inventory = {"receiptState": "observed", "tree": preview["sourceTree"]}
    ns = {"hashlib": hashlib, "re": re, "source": context["source"], "build_target": context["target"],
        "target": context["target"], "preview": preview,
        "os": SimpleNamespace(environ={"GITHUB_SHA": context["source"], "GITHUB_RUN_ID": context["runId"],
                                      "GITHUB_RUN_ATTEMPT": context["runAttempt"]}),
        "toolchain": {key: SENTINEL for key in ("xcode", "sdkPath", "sdkVersion", "sdkBuild")},
        "helper": {"helperSha256": "b" * 64, "helperBytes": 4096},
        "runner_bytes": b"runner", "build_bytes": b"build", "summary_admission_bytes": b"summary-owner",
        "summary_owner_bytes": b"summary-owner", "summary_bytes": b"summary", "budget_bytes": b"budget",
        "facts_bytes": b"facts"}
    names = {"need", "singleton_selection", "digest", "hex64", "singleton_case_data"}
    nodes = [node for node in blocks[-1][0].body if isinstance(node, ast.FunctionDef) and node.name in names]
    assert {node.name for node in nodes} == names
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "ordinary-singleton-passive-data", "exec"), ns)
    values, bodies = {}, {}
    for index, definition in enumerate(DATA.ORDINARY_UI_INPUTS):
        key, path, count, methods, prerequisites = definition[:5]
        ns["expected"] = ns["counts"] = dict(DATA.POSITIVE_UI_COUNTS, totalTestCount=count, passedTests=count)
        ns["prior_hashes"] = {DATA.ORDINARY_UI_INPUTS[j][1].split("/")[-1]: hashlib.sha256(bodies[name]).hexdigest()
            for name in prerequisites for j in range(len(DATA.ORDINARY_UI_INPUTS)) if DATA.ORDINARY_UI_INPUTS[j][0] == name}
        if index >= 5:
            selected = ("workflow-refusal", "release-evidence", "saved-version-recovery")[index - 5]
            recovery = {name: "c" * 64 for name in ("sourceInputsSha256", "runtimeManifestSha256", "runtimeResultSha256",
                "sourceClosureSha256", "fixtureDataSha256", "producerSha256", "producerFramesSha256", "handoffSha256")}
            recovery["runtimeManifestSha256"] = preview["runtimeManifestSha256"]
            recovery.update({name: True for name in ("originalFixtureRestored", "unrelatedOriginalsUnchanged",
                "readyJournalRemoved", "sourcePrePostMatched", "uiOriginalMarkersObserved", "originalClosesCompleted")})
            recovery.update(producerReturncode=86, publicOriginalCount=13, readyJournalFileCount=6, interruptedGuiSaveObserved=False)
            runner = ({"managedWorkflowRefusalMarkerObserved": True} if index == 5 else
                {"savedReleaseEvidenceMarkerObserved": True} if index == 6 else
                {"savedVersionRecovery": recovery, "commands": [{}, {}, {"stdoutSha256": "c" * 64,
                    "stderrBytes": 0, "stderrSha256": hashlib.sha256(b"").hexdigest()}]})
            ns.update(selected_scope=selected, method=methods[0].split("/")[-1], prior=values["diagnostics"],
                prior_bytes=bodies["diagnostics"], case_data=ns["singleton_case_data"](selected, runner, preview,
                    "c" * 64, "c" * 64 if index == 7 else None))
        expression = blocks[index if index < 5 else -1][1]
        value = eval(compile(ast.Expression(expression), "ordinary-result-passive-data", "eval"), ns)
        assert value["scope"] == definition[5]["scope"]
        values[key] = value
        bodies[key] = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    return values, bodies, preview, statuses, {"package-install": installed}, inventory


def build_diagnostic(normal, phase="build", *, fallback=False):
    original = CompletedProcess([], 70, b"Error Domain=NSPOSIXErrorDomain Code=2\n", (
        b"NormalAppUITests.swift:123:7: error: cannot find '" + SENTINEL.encode() + b"' in scope\n"
        b"** BUILD FAILED **\nxcodebuild: error: " + SENTINEL.encode() + b"\n"))
    return normal["failure_base" if fallback else "normal_failure_diagnostics"](phase, None, original)


def build_settings_fixture(normal, outcome="observed"):
    """Genuine DATA producer/phase with one inert original; never a native query."""
    context = {**CONTEXT, "target": "x86_64-apple-darwin"}
    original = CompletedProcess([], 70, b"failed-build-out", b"failed-build-err")
    build = normal["normal_failure_diagnostics"]("build", None, original)
    raw = {"ARCHS": " ".join(normal["NORMAL_BUILD_ARCHITECTURES"]),
        "VALID_ARCHS": " ".join(normal["NORMAL_BUILD_ARCHITECTURES"]),
        "EXCLUDED_ARCHS": " ".join(normal["NORMAL_BUILD_ARCHITECTURES"]),
        "NATIVE_ARCH_ACTUAL": "x86_64h", "NATIVE_ARCH_64_BIT": "x86_64h",
        "SUPPORTED_PLATFORMS": " ".join(sorted(normal["NORMAL_BUILD_PLATFORMS"], key=len, reverse=True)[:8]),
        "ONLY_ACTIVE_ARCH": "YES", "MACOSX_DEPLOYMENT_TARGET": "999.999.999", "SDK_VERSION": "999.999.999",
        "PRIVATE_KEY": SENTINEL}
    body = json.dumps([{"target": normal["TARGET"], "buildSettings": raw, "private": SENTINEL}]).encode()
    writes = []
    def run(argv, **kwargs):
        if outcome == "unavailable": raise RuntimeError("inert-original-did-not-return")
        return CompletedProcess(argv, 9 if outcome == "nonzero" else 0,
            b"" if outcome == "malformed" else body, SENTINEL.encode())
    clock = normal["PhaseClock"](450, now=lambda: 0)
    phase = normal["NormalPhase"](SimpleNamespace(run_owned=run), {}, Path("/inert"), clock)
    normal["exclusive_output"] = lambda path, body, limit: writes.append((path, body, limit))
    try:
        normal["publish_normal_build_settings"](phase,
            dict(phase="build", target=context["target"], derived=Path("/inert/normal-ui/DerivedData")),
            context["source"], original, "26.999.999.999")
    except RuntimeError:
        if outcome != "unavailable": raise
    assert len(writes) == 1 and writes[0][2] == 4096 and len(writes[0][1]) <= 4096
    return json.loads(writes[0][1]), build, {"receiptState": "observed", "returncode": 70}, context


def admission_diagnostic(normal):
    raw = {"schemaVersion": 1, "scope": "generated-ui-runner-refused", "productReady": False,
        "error": "runner-admission-or-owner-error", "stage": "execute", "exceptionClass": "ProcessError",
        "unknownStateRetained": True, "sourceFrames": [{"source": "owned_process.py", "line": 321}],
        "ownerFailure": {"dispatched": True, "contained": False, "cleanupComplete": None},
        "commands": [{"role": "normal-toolchain-sdkPath", "returncode": 70, "timeoutSeconds": 30,
            "roleCapSeconds": 30, "outputLimitBytes": 4096, "argvSha256": "1" * 64,
            "stdoutBytes": 0, "stdoutSha256": "2" * 64, "stderrBytes": 256, "stderrSha256": "3" * 64}]}
    return normal["classify_normal_admission_failure"](json.dumps(raw).encode())


def removal_data():
    """Only existing terminal-comparison and fixed-role DATA, no native owners."""
    result = []
    for filename, names in (
        ("stage_macos_installed.py", {"Refused", "need", "maintenance_hex", "REMOVAL_FIXTURE_CASES", "REMOVAL_FIXTURE_PHASES",
            "removal_fixture_case_data", "removal_fixture_observation_pair", "removal_fixture_terminal_data"}),
        ("macos_android_helper_package.py", {"Refused", "need", "REMOVAL_CASES", "removal_runtime_roles", "removal_native_result_data"}),
    ):
        path = ROOT / "desktop/tools" / filename
        nodes, found = [], set()
        for node in ast.parse(path.read_text()).body:
            name = node.name if isinstance(node, (ast.FunctionDef, ast.ClassDef)) else (
                node.targets[0].id if isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) else None)
            if name in names:
                nodes.append(node); found.add(name)
        if found != names:
            raise AssertionError("finite-removal-DATA-dependencies")
        namespace = {"re": re}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), namespace)
        result.append(namespace)
    return result


def removal_receipt(case, stager, helper, normal):
    """Synthetic normalized observations, never native/removal authority."""
    binding = {"sourceCommit": CONTEXT["source"], "target": CONTEXT["target"], "release": DATA.REMOVAL_RELEASE,
        "inventorySha256": "b" * 64, "packageSha256": "c" * 64, "removeDescriptorSha256": "d" * 64,
        "removeSignatureSha256": "e" * 64}
    before = {"phase": "before", "binding": binding, "rootIdentity": [1, 2, 3, 4, 5, 6, 7, 8, 9],
        "expectedFiles": 3, "expectedDirectories": 2, "presentFiles": 3, "presentDirectories": 2,
        "archives": [], "appPresent": True, "firstEligibleAbsent": False, "allPayloadAbsent": False,
        **{key: "f" * 64 for key in ("installationStateSha256", "installedProducerSha256", "installedSignatureSha256", "payloadCommitmentSha256")}}
    old = {"invocation": "1" * 32, "snapshotSha256": "4" * 64, "tipSha256": "5" * 64, "prefix": 3,
        "requestId": "6" * 32, "rootNonce": "1" * 32, "previousTipSha256": None, "genesisSnapshotSha256": "4" * 64}
    new = {"invocation": "2" * 32, "snapshotSha256": None, "tipSha256": "8" * 64, "prefix": 4,
        "requestId": "9" * 32, "rootNonce": "2" * 32, "previousTipSha256": old["tipSha256"], "genesisSnapshotSha256": old["genesisSnapshotSha256"]}
    middle = dict(before, phase="after-cancel") if case == "ordinary" else dict(before,
        phase="after-cut", presentFiles=2, firstEligibleAbsent=True, archives=[old])
    terminal = dict(before, phase="terminal", presentFiles=0, presentDirectories=0,
        appPresent=False, firstEligibleAbsent=True, allPayloadAbsent=True,
        archives=[dict(old, prefix=4)] if case == "ordinary" else [old, new])
    arguments = {} if case == "ordinary" else {
        "effects_sha": "a" * 64, "supervisor": {"role": "resume", "actualChildReturncode": 0,
            "originalChildWaitObserved": True, "effectsSha256": "a" * 64},
        "effects": {"requestId": new["requestId"], "rootNonce": new["rootNonce"], "previousTipSha256": old["tipSha256"],
            "genesisSnapshotSha256": old["genesisSnapshotSha256"], "returnedUnlinks": 4, "appRootUnlinkOrdinal": 4}}
    final = stager["removal_fixture_terminal_data"](case, before, middle, terminal, **arguments)
    method = normal["REMOVAL_METHODS"][case]
    selected = "-[MRKNormalAppUITests.NormalAppUITests " + method + "]"
    output = ("MRK_MACOS_REMOVAL_UI=v1;case=" + case + ";cancelObserved=" + ("1" if case == "ordinary" else "0")
        + ";continueObserved=1;originalTerminated=1;gateClosed=1;gateFree=unqualified;normalQuit=0;channelClosed=1\n"
        + "Test Case '" + selected + "' started.\nTest Case '" + selected + "' passed (1.0 seconds).\n").encode()
    counts = {"totalTestCount": 1, "passedTests": 1, "failedTests": 0, "skippedTests": 0, "expectedFailures": 0}
    tree = {"testNodes": [{"name": "MRKNormalAppUITests", "nodeType": "Test Suite", "children": [
        {"name": method + "()", "nodeType": "Test Case", "nodeIdentifier": "NormalAppUITests/" + method + "()", "result": "Passed"}]}]}
    ui = normal["removal_ui_result"](output, json.dumps(counts).encode(), json.dumps(tree).encode(), case)
    value = receipt("package-removal-fixture"); del value["finalImage"]
    value["notarySubmission"] = value["notaryAuthentication"] = None
    value["originalCalls"] = [{"role": role, "entered": True, "returned": True, "capturesSettled": True,
        "returncode": 1 if role in ("removal-live-cancel", "removal-live-cut") else 0,
        "stdoutSha256": "a" * 64, "stderrSha256": "b" * 64} for role in helper["removal_runtime_roles"](case)]
    value["removalFixture"] = dict(final, originalUIJoined=True, uiObservation=ui, outputs=3 if case == "ordinary" else 6,
        outputsSha256="c" * 64, requestsDirectoryNamedOnly=True, mountedInputsDetached=True,
        sourcePrePostMatched=True, firstOriginalErrorPreserved=True, productReady=False)
    return value


def data_contract_diagnostics():
    """Only genuine inline DATA reducers/constants; never execute the shell/owner."""
    path = ROOT / "desktop/tools/macos_installed_data_contracts.sh"
    source = path.read_text().split("<<'PY_DATA_CONTRACTS'\n", 1)[1].rsplit("\nPY_DATA_CONTRACTS", 1)[0]
    tree = ast.parse(source)
    wanted = {"DATA_FAILURE_GUARDS", "data_failure_guard", "data_failure_json", "data_failure_python",
              "data_failure_cargo", "data_failure_rust_panic", "data_failure_rust_panic_diagnostic", "data_failure_document"}
    nodes, found, assignments = [], set(), {}
    for node in tree.body:
        name = node.name if isinstance(node, ast.FunctionDef) else (
            node.targets[0].id if isinstance(node, ast.Assign) and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name) else None)
        if name in wanted:
            nodes.append(node); found.add(name)
        if isinstance(node, ast.Assign) and name is not None:
            assignments[name] = node.value
    if found != wanted:
        raise AssertionError("finite-data-contract-diagnostic-closure")
    names = ast.literal_eval(assignments["names"])
    child = ast.literal_eval(assignments["child_code"].right)
    functions = [node for node in ast.parse(child).body
                 if isinstance(node, ast.FunctionDef) and node.name == "data_failed_test_rows"]
    if len(functions) != 1:
        raise AssertionError("finite-child-failure-ID-reducer")
    namespace = {"json": json, "hashlib": hashlib, "re": re}
    exec(compile(ast.Module(body=nodes + functions, type_ignores=[]), str(path), "exec"), namespace)
    return namespace, names


def data_contract_failure(data, names, *, phase="python", code=1, raw=None, flags=None,
                          guard="command-not-complete", source_paths=frozenset(), failed_names=None, stderr=None):
    if raw is None:
        if phase == "python":
            selected = [names[0]] if failed_names is None else failed_names
            failures = [(SimpleNamespace(id=lambda name=name: name), SENTINEL) for name in selected]
            value = dict(testsRun=84, failures=len(failures), errors=0, skipped=0, expectedFailures=0,
                unexpectedSuccesses=0, testIds=names, actualHostBeforeAndAfter=True,
                **data["data_failed_test_rows"](failures, [], names))
            raw = json.dumps(value).encode()
        else:
            raw = b""
    command = dict(phase=phase, returnCode=code, originalReturned=True, outputComplete=True,
                   captureClosed=True, timedOut=False, outputOverflow=False)
    command.update(flags or {})
    context = {key: CONTEXT[key] for key in ("source", "workflowSource", "runId", "runAttempt", "target")}
    return json.loads(data["data_failure_document"](command, {"stdout": raw, "stderr": SENTINEL.encode() if stderr is None else stderr},
        guard, context, names, source_paths, "/public/checkout"))


def positive_ui_data(context=None, *, ios=False):
    """Synthetic receipt DATA shaped by genuine pure fact validators; no native proof."""
    context = CONTEXT if context is None else context
    normal = normal_diagnostic_data(positive=True)
    facts = normal["ios_unsigned_facts"](dict(schemaVersion=1, scope="one-ordinary-local-unsigned-ios-archive",
        sourceCommit=context["source"], savedVersion="1.2.3", savedBuild=7, inputFiles=9, inputBytes=7264,
        topLevelDirectories=4, archiveDescendantsObserved=False, nativeResultDisplayed=True, outputPostMatched=True,
        originalsClosed=True, normalQuitObserved=True, successBeforeCutoff=True, signed=False, ipaExported=False,
        releaseQualified=False, parentReturncodeRequired=0, operationId="4" * 32, ownerGeneration="5" * 32,
        originalEntries=100, originalBytes=10000), source=context["source"])
    android_facts = normal["android_signed_facts"](dict(schemaVersion=1,
        scope=normal["ANDROID_FACTS_SCOPE"], sourceCommit=context["source"], target=context["target"],
        runId=context["runId"], runAttempt=context["runAttempt"], sourceRegistrationObserved=True,
        serviceEnabledObserved=True, serviceRegistrationRequested=False, vendorAcknowledgementAutomated=True,
        protectedCopyInstance="b" * 32,
        nativeSigningVerified=True, privateOriginalsClosed=True, memorySessionDiscarded=True, parentReturncodeRequired=0,
        outputPostMatched=True, normalQuitObserved=True, releaseQualified=False, operationId="4" * 32,
        ownerGeneration="5" * 32, publicCertificateSha256="6" * 64, artifactSha256="7" * 64,
        outputCensusSha256="8" * 64, artifactBytes=200, outputEntries=100, outputNameBytes=1000,
        outputLogicalBytes=10000, moduleLogicalBytes=2000), source=context["source"], run=context["runId"], attempt=context["runAttempt"], target=context["target"])
    inventory = {"receiptState": "observed", "tree": "9" * 40}
    android = dict(schemaVersion=1, scope="ordinary-installed-one-android-signed-build-ui", target=context["target"],
        applicationSourceCommit=context["source"], harnessSourceCommit=context["source"], sourceTree=inventory["tree"],
        workflow=".github/workflows/desktop-macos-installed.yml", runId=context["runId"], runAttempt=context["runAttempt"],
        testIdentifier="MRKNormalAppUITests/NormalAppUITests/testSyntheticProjectAndroidSignedBuild",
        resultOriginalReturncodeRequired=0, privateInputsPublished=False, vendorAcknowledgementAutomated=True,
        newProtectedCopyRegistered=True, cleanExitStatus=None, allWorkerFinality="not-established-by-XCTest-UI-state",
        fullUIQualified=False, distributionQualified=False, productReady=False, packageSha256="2" * 64, packageBytes=1024,
        runtimeManifestSha256="3" * 64, installerInventorySha256="4" * 64,
        originalCommandStatuses=dict(packageInstall=0, installer=0, supplier=0, build=0, test=0, summary=0),
        testCounts=dict(DATA.POSITIVE_UI_COUNTS), observation=android_facts)
    common = dict(target=context["target"], sourceCommit=context["source"], sourceRosterSha256="a" * 64,
        sourcePrePostMatched=True, originalCommandReturned=True, receiptPolicy="exclusive0600-readback-consuming-close",
        resultBundle="ios-unsigned-archive-test.xcresult", fileLimitBytes=[1024**3] * 2)
    def commands(rows):
        return [dict(role=role, returncode=0, roleCapSeconds=cap, timeoutSeconds=cap, outputLimitBytes=limit,
            argvSha256="1" * 64, stdoutSha256="2" * 64, stderrSha256="3" * 64, stdoutBytes=1, stderrBytes=0)
            for role, cap, limit in rows]
    def clock(seconds):
        return dict(startNs="1", deadlineNs=str(1 + seconds * 10**9), beforePublicationNs="2", postCloseDeadlineRequired=True)
    source_row = ("normal-ui-source-roster", 15, 1048576)
    original = ["file", ["1", "2", str(0o100600), "501", "20", "1", "100", "3", "4"], "b" * 64]
    test = dict(common, schemaVersion=1, scope="actual-generated-xctrunner-admission-only",
        strictCodesignOriginalZero=True, reSignedOrRepaired=False, originalProductsPrePostMatched=True,
        originalClosesCompleted=True, originalTestReturncode=0, normalPhase="test", iosUnsignedObservation=copy.deepcopy(facts),
        runnerPath=SENTINEL, xctestrunPath=SENTINEL, runnerExecutable=copy.deepcopy(original),
        testExecutable=copy.deepcopy(original), xctestrun=copy.deepcopy(original), productEntryCount=5,
        productRosterSha256="c" * 64, entitlementsSha256="d" * 64, appSandboxEntitlement="absent",
        phaseClock=clock(1245), commands=commands((source_row, ("verify-generated-runner", 30, 1048576),
        ("generated-runner-entitlements", 30, 1048576), ("one-admitted-ui-test", 1020, 1048576), source_row)))
    summary = dict(common, schemaVersion=1, scope="normal-ui-original-command-admission-only", phase="summary",
        originalCommandRole="normal-ui-summary", originalReturncode=0, iosUnsignedTestCounts=dict(DATA.POSITIVE_UI_COUNTS),
        phaseClock=clock(90), commands=commands((source_row, ("normal-ui-summary", 30, 262144), source_row)))
    statuses = {name: {"receiptState": "observed", "returncode": 0} for name in
                ("package-install.status", "normal-ui/build.status", *DATA.POSITIVE_UI_STATUSES["ios" if ios else "android"])}
    phases = {"package-install": {"receiptState": "observed", "recordedPassed": True,
                                 "originalClosesKnown": True, "targetRetired": True}}
    return android, facts, test, summary, statuses, phases, inventory


def ios_pending_recovery_data(context=CONTEXT):
    """Synthetic completed originals for the DATA boundary, not native evidence.

    Reuse only the private runner-admission shape. Recovery facts/roles are the
    separate normal-account interface; unsigned success is never transformed
    into a claim that account recovery actually ran.
    """
    _, _, test, summary, _, phases, inventory = positive_ui_data(context, ios=True)
    fixture = f"/private/tmp/mrk-macos-aqua-{context['source']}-{context['runId']}-{context['runAttempt']}/ios-recovery-pending"
    observation = dict(schemaVersion=1, sourceCommit=context["source"], target=context["target"],
        runId=context["runId"], runAttempt=context["runAttempt"], fixtureSha256=hashlib.sha256(fixture.encode()).hexdigest(),
        sessionSha256="f" * 64, inspectUnchecked=True, recoverUnchecked=True, ordinaryQuit=True,
        inspect=dict(operationId="4" * 32, ownerGeneration="5" * 32, phase="terminal", outcome="complete",
                     reason="none", accountStatus="pending"),
        recover=dict(operationId="6" * 32, ownerGeneration="7" * 32, phase="terminal", outcome="complete",
                     reason="none", accountStatus="recovered"))
    common = dict(schemaVersion=1, case="ios-recovery-pending", profileCalls=0, commandFinalities=True,
        leaseClosed=True, sessionClosed=True, handlersRestored=True, fixtureDescriptorsClosed=True,
        originalDeadlineMet=True, keychainContentsRead=False)
    account = dict(producer=dict(common, scope="real-core-pending-account-fixture-v1", commands=3, pendingLeft=True),
        nativeReadback=dict(common, scope="real-core-account-baseline-readback-v1", commands=2, pendingAbsent=True,
                           baselinePreferencesMatched=True, baselineMemberIdentitiesMatched=True),
        exactPendingSessionRecovered=True, originalOwnedNativeAndControlsRemoved=True, persistentOriginalLeaseRetained=True,
        nativeBaselineMembers=1, baselineIdentitiesMatched=True, baselinePreferencesMatched=True, projectMarkerUnchanged=True,
        privateContentsExported=False, foreignPreferenceConflictInjected=False, appleSigningMaterialUsed=False,
        signedExportQualified=False)
    facts = dict(schemaVersion=1, scope="normal-ui-pending-account-recovery-v1", observation=observation,
                 account=account, originalClosesCompleted=True)
    test.pop("iosUnsignedObservation"); summary.pop("iosUnsignedTestCounts")
    test.update(iosPendingRecovery=copy.deepcopy(facts), resultBundle="ios-pending-recovery-test.xcresult")
    summary.update(iosPendingRecoveryTestCounts=dict(DATA.POSITIVE_UI_COUNTS), resultBundle="ios-pending-recovery-test.xcresult")
    test["phaseClock"]["deadlineNs"] = str(1 + 1080 * 10**9)
    test["commands"] = [dict(role=role, returncode=0, roleCapSeconds=cap, timeoutSeconds=cap, outputLimitBytes=limit,
        argvSha256="1" * 64, stdoutSha256="2" * 64, stderrSha256="3" * 64, stdoutBytes=1, stderrBytes=0)
        for role, cap, limit in (("normal-ui-source-roster", 15, 1048576), ("verify-generated-runner", 30, 1048576),
            ("generated-runner-entitlements", 30, 1048576), ("ios-account-produce", 180, 16384),
            ("one-admitted-ui-test", 645, 1048576), ("ios-account-observe", 90, 2048), ("normal-ui-source-roster", 15, 1048576))]
    statuses = {name: {"receiptState": "observed", "returncode": 0} for name in
        ("package-install.status", "normal-ui/build.status", "normal-ui/ios-pending-recovery-test.status",
         "normal-ui/ios-pending-recovery-summary.status")}
    return facts, test, summary, statuses, phases, inventory


def app_absence_documents(context=CONTEXT):
    """Genuine pure parser and three receipt assignments; no adapter execution.

    The supplied observations stand in for completed native originals solely to
    test the public DATA boundary. They do not establish native fixture success.
    """
    path = ROOT / "desktop/tools/macos_app_absence_fixture.py"
    module = ast.parse(path.read_text())
    names = {"MIB", "NATIVE_DATA_TESTS", "need", "digest", "native_data_tests_result"}
    selected = [node for node in module.body if isinstance(node, (ast.FunctionDef, ast.Assign))
                and (node.name if isinstance(node, ast.FunctionDef) else
                     node.targets[0].id if isinstance(node.targets[0], ast.Name) else None) in names]
    actual = {node.name if isinstance(node, ast.FunctionDef) else node.targets[0].id for node in selected}
    if actual != names:
        raise AssertionError("app-absence pure closure changed")
    namespace = {"hashlib": hashlib, "re": re}
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(path), "exec"), namespace)
    assignments = {}
    for function, field in (("prepare", "appAbsencePreparation"), ("package_complete", "appAbsenceBaseline"),
                            ("restore", "appAbsenceRestore")):
        functions = [node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == function]
        if len(functions) != 1:
            raise AssertionError("app-absence writer changed")
        rows = [node for node in functions[0].body if isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Subscript)
                and ast.dump(node.targets[0].value) == ast.dump(ast.parse("op.receipt", mode="eval").body)
                and isinstance(node.targets[0].slice, ast.Constant) and node.targets[0].slice.value == field]
        if len(rows) != 1:
            raise AssertionError("app-absence exact receipt clause changed")
        assignments[field] = compile(ast.Module(body=rows, type_ignores=[]), str(path), "exec")
    def serialized(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    def owner(phase, roles):
        value = receipt(phase)
        value.pop("finalImage"); value.pop("notarySubmission")
        value.update(context, packageRole="ordinary-image", productReady=False, cleanupErrors=[], directStagerIOPending=None,
                     workflow="Apdelrahman1911/mobile-release-kit/.github/workflows/desktop-macos-installed.yml@refs/heads/verify/desktop-macos-app-absence-fixture")
        value["notaryAuthentication"] = {"created": False, "closed": False, "retired": False}
        value["originalCalls"] = [{"role": role, "returned": True, "capturesSettled": True, "returncode": 0,
                                  "stdoutSha256": "a" * 64, "stderrSha256": "b" * 64} for role in roles]
        return value
    binding = {"fixtureSource": context["source"], "productSource": context["source"],
               **{key: context[key] for key in ("runId", "runAttempt", "target")}}
    hashes = dict(zip(("packageSha256", "producerDescriptorSha256", "producerSignatureSha256", "fixtureExecutableSha256",
                       "inventorySha256", "runtimeManifestSha256", "protocolSha256"), (format(n, "064x") for n in range(1, 8))))
    native_binding = {**binding, **hashes}
    baseline_sha, fixture_sha, image_sha = "8" * 64, "9" * 64, "a" * 64
    proofs = {
        "baseline": ("rootAbsent", "privateDirectoryCreated", "parentCensusMatched", "recordReadback"),
        "withdraw": ("initialFreshInstallRecorded", "createdRootMatchedPriorAbsence", "sameInstance", "reservationClosedUnderMaintenance",
                     "renameKnownSuccess", "appAbsent", "runtimeUnchanged", "historyUnchanged", "withdrawnAppVerified", "recordReadback"),
        "verify": ("restoreFixedAppRecorded", "initialHistoryPreserved", "sameInstance", "runtimeUnchanged", "newAppOriginal",
                   "currentAppVerified", "withdrawnAppVerified", "reservationClosedUnderMaintenance", "recordReadback", "retainedPrivateEvidence"),
    }
    def observation(phase):
        return {"schemaVersion": 1, "kind": "app-absence-phase-observation", "phase": phase, **native_binding,
                "baselineSha256": baseline_sha, "recordSha256": baseline_sha if phase == "baseline" else "b" * 64,
                "proof": dict.fromkeys(proofs[phase], True), "originalOuterExitRequired": True,
                "systemServiceExitClaimed": False, "productReady": False}
    data_output = ("running 6 tests\n" + "".join("test " + name + " ... ok\n" for name in namespace["NATIVE_DATA_TESTS"])
                   + "test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 999999 filtered out; finished in 1.00s\n").encode()
    data_original = CompletedProcess([], 0, data_output, SENTINEL.encode())
    pure_tests = namespace["native_data_tests_result"](data_original)
    prepare = owner("prepare-app-absence", DATA.APP_ABSENCE_PREPARE_ROLES)
    op = SimpleNamespace(receipt=prepare, app_absence={"binding": binding},
                         environment={"MRK_MACOS_INSTALL_INVENTORY_SHA256": hashes["inventorySha256"],
                                      "MRK_BUNDLED_RUNTIME_MANIFEST_SHA256": hashes["runtimeManifestSha256"]},
                         stager=SimpleNamespace(CURRENT_PROTOCOL=hashes["protocolSha256"]))
    namespace.update(op=op, program_sha=hashes["fixtureExecutableSha256"], executable={"identity": [0]*6 + [64*1024*1024]},
                     fixture_sha=fixture_sha, fixture={"identity": [0]*6 + [512*1024*1024]}, result=data_original, pure_tests=pure_tests)
    exec(assignments["appAbsencePreparation"], namespace)
    prepare["originalCalls"][1].update({key: pure_tests[key] for key in ("stdoutSha256", "stderrSha256")})
    prepare_sha = hashlib.sha256(serialized(prepare)).hexdigest()
    carrier_names = ("Install.pkg", "producer.json", "producer.sig", "MRK-AppAbsence-Baseline.pkg", "MRK-AppAbsence-Withdraw.pkg", "MRK-AppAbsence-Verify.pkg")
    sizes = (512*1024*1024, 16384, 512, 512*1024*1024, 512*1024*1024, 512*1024*1024)
    layout = {name: {"name": name, "bytes": size, "sha256": sha, "mode": 0o444, "links": 1}
              for name, size, sha in zip(carrier_names, sizes,
                  (hashes["packageSha256"], hashes["producerDescriptorSha256"], hashes["producerSignatureSha256"], fixture_sha, fixture_sha, fixture_sha))}
    initial = {"requestId": "c"*32, "invocation": "d"*32, "stateSha256": "e"*64, "resultSha256": "f"*64, "instance": "a"*32}
    baseline = owner("package-install", DATA.APP_ABSENCE_PACKAGE_ROLES)
    op.receipt = baseline
    op.app_absence = {"nativeBinding": native_binding, "preparationSha256": prepare_sha, "layout": layout,
                      "image": {"bytes": 2560*1024*1024, "sha256": image_sha}, "baselineSha256": baseline_sha,
                      "baselineOriginal": {"bytes": 65536, "sha256": baseline_sha, "identity": [123]*9},
                      "baselineObservation": observation("baseline"), "initial": initial}
    namespace["data"] = op.app_absence
    exec(assignments["appAbsenceBaseline"], namespace)
    body = serialized(baseline)
    restore = owner("app-absence-restore", DATA.APP_ABSENCE_RESTORE_ROLES)
    op.receipt = restore
    namespace.update(previous=baseline["appAbsenceBaseline"], body=body, image_sha=image_sha, initial=initial,
                     after={"request": {"sha256": "b"*64}}, args=SimpleNamespace(request_id="request"),
                     withdraw=observation("withdraw"), verify=observation("verify"), restored={"nonrootReadbackFileCount": 4096})
    exec(assignments["appAbsenceRestore"], namespace)
    return prepare, baseline, restore


def write_app_absence_documents(root, documents):
    for phase, value in zip(("prepare-app-absence", "package-install", "app-absence-restore"), documents):
        body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        if len(body) > 16384:
            raise AssertionError("app-absence actual receipt exceeds existing bound")
        write(root, "android-helper-" + phase + ".json", body)
    for name in ("app-absence-preparation.status", "package-install.status", "app-absence-restore.status"):
        write(root, name, b"0\n")


class PublicVerificationEvidenceData(unittest.TestCase):
    def test_primary_owner_finality_projection_preserves_unknown_and_parent_applicability(self):
        def project(value, *, present=True):
            failure = {"available": True, "ownerErrorType": "ProcessError", "classification": "deadline",
                       "timeoutSeconds": 720, "outputLimitBytes": 1024, "rawPrivate": SENTINEL}
            if present:
                failure["ownerFinality"] = value
            row = {"role": "build", "entered": True, "returned": False, "capturesSettled": False,
                   "dispatched": True, "contained": False, "cleanup_complete": False,
                   "originalFailure": failure}
            result = DATA.project_calls([row])["calls"][0]
            self.assertEqual((result["returned"], result["capturesSettled"], result["contained"], result["cleanup_complete"]),
                             (False, False, False, False))
            self.assertIsNone(result["returncode"])
            self.assertNotIn(SENTINEL, json.dumps(result))
            return result["originalFailure"]
        self.assertNotIn("ownerFinality", project(None, present=False))
        self.assertEqual(project(None)["ownerFinality"], {"available": False})
        for value in ([1, 0, 1023, 15, None], [1, 1, 0, 0, 0],
                      [1, 1, (1 << 3) | (1 << 7) | (1 << 10), 15, None],
                      *([1, 1, 0, 0, mask] for mask in (32, *range(48, 64)))):
            self.assertEqual(project(value)["ownerFinality"], {"available": True,
                "branch": "child" if value[1] else "no-child", "predicateMask": value[2],
                "cleanupMask": value[3], "terminalFailureMask": value[4]})
        invalid = [SENTINEL, {}, [], (1, 1, 0, 0, None), [1], [2, 1, 0, 0, None],
            [True, 1, 0, 0, None], [1, True, 0, 0, None], [1, 1, False, 0, None],
            [1, 1, 0, False, None], [1, 2, 0, 0, None], [1, 0, 1024, 0, None],
            [1, 1, 1048576, 0, None], [1, 1, -1, 0, None], [1, 1, 0, 16, None],
            [1, 1, 0, -1, None], [1, 0, 0, 0, 0], [1, 1, 0, 0, True],
            [1, 1, 0, 0, -1], [1, 1, 0, 0, 1], [1, 1, 0, 0, 47], [1, 1, 0, 0, 64]]
        # Missing parents cannot turn unset subordinate bits into positive facts.
        for parent, children in ((3, (4, 5, 6)), (7, (8, 18, 19)), (10, (11, 12))):
            invalid.extend([1, 1, (1 << parent) | (1 << child), 0, None] for child in children)
        invalid.extend([1, 1, 1 << bit, 0, 32] for bit in (7, 8, 9))
        for value in invalid:
            with self.subTest(invalid=repr(value)), self.assertRaises(DATA.Refused):
                project(value)


    def test_notary_key_precontext_failure_preserves_only_four_genuine_literals(self):
        source = (ROOT / "desktop/tools/macos_android_helper_package.py").read_bytes()
        parsed = ast.parse(source)
        labels = {node.value for method in ast.walk(parsed)
            if isinstance(method, ast.FunctionDef) and method.name in {"notary_key_scope", "notary_key_data"}
            for node in ast.walk(method) if isinstance(node, ast.Constant)
            and type(node.value) is str and node.value.startswith("notary-key-")}
        expected = {"notary-key-purpose", "notary-key-input", "notary-key-base64", "notary-key-pem-shape"}
        self.assertTrue(expected <= labels)
        for reason in expected:
            value = {"stage": "payload-zip", "type": "Refused", "reason": reason, "errno": None}
            self.assertEqual(DATA.project_failure(value), value)
            self.assertEqual(DATA.project_failure({**value, "reason": reason + SENTINEL})["reason"],
                             "notary-authentication")
        self.assertNotIn(SENTINEL, json.dumps(DATA.project_failure({"reason": SENTINEL})))


    def test_notary_preflight_failure_preserves_only_fixed_current_guard_literals(self):
        source = (ROOT / "desktop/tools/macos_android_helper_package.py").read_bytes()
        parsed = ast.parse(source)
        selected = {"notary_tool", "notary_tool_post", "notary_rename_copy", "notary_snapshot",
                    "notary_post", "notary_io", "notary_space"}
        labels = {node.args[1].value for method in ast.walk(parsed)
            if isinstance(method, ast.FunctionDef) and method.name in selected
            for node in ast.walk(method) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name) and node.func.id == "need" and len(node.args) == 2
            and isinstance(node.args[1], ast.Constant) and type(node.args[1].value) is str
            and node.args[1].value.startswith("notary-")}
        self.assertEqual(len(labels), 29)
        self.assertEqual(DATA.NOTARY_ADMISSION_REASONS, labels)
        for reason in labels:
            with self.subTest(reason=reason):
                expected = {"stage": "notary-preflight-input", "type": "Refused", "reason": reason, "errno": None}
                self.assertEqual(DATA.project_failure(expected), expected)
                self.assertEqual(DATA.project_failure({**expected, "reason": reason + SENTINEL})["reason"],
                    "notary-authentication" if reason.startswith("notary-key-") else "notary-refused")
        self.assertEqual(DATA.project_failure({"stage": SENTINEL, "type": "OSError", "errno": 13}),
                         {"stage": "unclassified", "type": "OSError", "reason": "unclassified", "errno": 13})
        self.assertNotIn(SENTINEL, json.dumps(DATA.project_failure({"reason": SENTINEL})))
        # Same explicit SOURCE passive closure, not dynamic exception rendering.
        helper_parsed = ast.parse(source)
        stager_parsed = ast.parse((ROOT / "desktop/tools/stage_macos_installed.py").read_bytes())
        functions = {node.name: node for node in stager_parsed.body if isinstance(node, ast.FunctionDef)}
        closure = ('build_release_data', 'mac_target', 'maintenance_hex', 'maintenance_json', 'decode', 'pairs', 'maintenance_map', 'maintenance_result_data', 'maintenance_write_data', 'registration_reservation_result', 'emitted_package_data', 'maintenance_producer_data', 'maintenance_release_data', 'packaging_signing_data', 'service_signing_data', 'digest')
        reasons = set()
        for name in closure:
            for node in ast.walk(functions[name]):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                    continue
                index = {"need": 1, "Refused": 0, "maintenance_map": 2}.get(node.func.id)
                if index is not None and len(node.args) > index and isinstance(node.args[index], ast.Constant) and type(node.args[index].value) is str:
                    reasons.add(node.args[index].value)
        def declared(name):
            value = next(node.value for node in helper_parsed.body if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == name for target in node.targets))
            return ast.literal_eval(value.args[0] if isinstance(value, ast.Call) else value)
        self.assertEqual(len(reasons), 45)
        self.assertEqual(set(declared("FINAL_IMAGE_INPUT_STAGER_REASONS")), reasons)
        self.assertEqual(DATA.FINAL_IMAGE_INPUT_STAGER_REASONS, reasons)
        expected_stages = ('final-image-original-inputs', 'final-image-package-owner', 'final-image-original-readback', 'final-image-package-audit', 'final-image-producer', 'final-image-source-profiles', 'final-image-original-image')
        self.assertEqual(declared("FINAL_IMAGE_INPUT_STAGES"), expected_stages)
        self.assertEqual(DATA.FINAL_IMAGE_INPUT_STAGES, expected_stages)
        input_method = next(node for node in ast.walk(helper_parsed) if isinstance(node, ast.FunctionDef) and node.name == "final_image_input")
        assigned = tuple(node.value.value for node in input_method.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name)
                and target.value.id == "self" and target.attr == "stage" for target in node.targets))
        self.assertEqual(assigned, expected_stages)
        for stage in expected_stages:
            for reason in reasons:
                expected = {"stage": stage, "type": "Refused", "reason": reason, "errno": None}
                self.assertEqual(DATA.project_failure(expected), expected)
                unknown = DATA.project_failure({**expected, "reason": reason + SENTINEL})
                self.assertEqual(unknown["reason"], "unclassified")
                self.assertNotIn(SENTINEL, json.dumps(unknown))
                self.assertEqual(set(unknown), {"stage", "type", "reason", "errno"})
        self.assertEqual(DATA.project_failure({"stage": SENTINEL, "type": True, "reason": SENTINEL, "errno": None}),
            {"stage": "unclassified", "type": "unclassified", "reason": "unclassified", "errno": None})

    def test_android_positive_closed_result_matches_genuine_facts_and_statuses(self):
        for target_value in DATA.TARGETS:
            context = dict(CONTEXT, target=target_value)
            selected, _, _, _, statuses, phases, inventory = positive_ui_data(context)
            self.assertEqual(DATA.project_android_positive(selected, context, statuses, phases, inventory)['recordedResult'], selected)
            other = next(target for target in DATA.TARGETS if target != target_value)
            for bad in (dict(selected, target=other), dict(selected, observation=dict(selected['observation'], target=other))):
                with self.assertRaises(DATA.Refused): DATA.project_android_positive(bad, context, statuses, phases, inventory)
        value, _, _, _, statuses, phases, inventory = positive_ui_data()
        result = DATA.project_android_positive(value, CONTEXT, statuses, phases, inventory)
        self.assertEqual(result["recordedResult"], value)
        self.assertIs(result["nativeSuccessInferred"], False)
        self.assertEqual(result["binding"], "source-run-target-fields-and-current-statuses")
        for requested in (False, True):
            observed = copy.deepcopy(value); observed["observation"]["serviceRegistrationRequested"] = requested
            self.assertEqual(DATA.project_android_positive(observed, CONTEXT, statuses, phases, inventory)["recordedResult"], observed)
        for missing in ("sourceRegistrationObserved", "serviceEnabledObserved", "serviceRegistrationRequested",
                        "vendorAcknowledgementAutomated", "protectedCopyInstance"):
            bad = copy.deepcopy(value); del bad["observation"][missing]
            with self.subTest(missing=missing), self.assertRaises(DATA.Refused):
                DATA.project_android_positive(bad, CONTEXT, statuses, phases, inventory)
        changes = (("applicationSourceCommit", "2" * 40), ("harnessSourceCommit", "2" * 40),
                   ("runAttempt", "3"), ("target", "x86_64-apple-darwin"), ("sourceTree", "2" * 40),
                   ("vendorAcknowledgementAutomated", False), ("newProtectedCopyRegistered", False),
                   ("privateInputsPublished", True), ("cleanExitStatus", 0), ("productReady", True),
                   ("testIdentifier", SENTINEL), ("packageBytes", True), ("unexpected", SENTINEL))
        for key, item in changes:
            with self.subTest(field=key):
                bad = copy.deepcopy(value); bad[key] = item
                with self.assertRaises(DATA.Refused):
                    DATA.project_android_positive(bad, CONTEXT, statuses, phases, inventory)
        for key in DATA.POSITIVE_UI_COUNTS:
            bad = copy.deepcopy(value); bad["testCounts"][key] = True
            with self.assertRaises(DATA.Refused):
                DATA.project_android_positive(bad, CONTEXT, statuses, phases, inventory)
        for key, item in (("sourceRegistrationObserved", False), ("nativeSigningVerified", False),
                          ("serviceEnabledObserved", False), ("vendorAcknowledgementAutomated", False),
                          ("serviceRegistrationRequested", 1), ("serviceRegistrationRequested", "true"),
                          ("protectedCopyInstance", "private/path"), ("protectedCopyInstance", "A" * 32),
                          ("privateOriginalsClosed", False), ("memorySessionDiscarded", False),
                          ("releaseQualified", True), ("artifactBytes", (64 << 20) + 1)):
            bad = copy.deepcopy(value); bad["observation"][key] = item
            with self.assertRaises(DATA.Refused):
                DATA.project_android_positive(bad, CONTEXT, statuses, phases, inventory)
        for status in (1, -1, True):
            bad = copy.deepcopy(statuses); bad[DATA.POSITIVE_UI_STATUSES["android"][-1]]["returncode"] = status
            with self.assertRaises(DATA.Refused):
                DATA.project_android_positive(value, CONTEXT, bad, phases, inventory)
        bad = copy.deepcopy(statuses); bad[DATA.POSITIVE_UI_STATUSES["ios"][0]] = {"receiptState": "observed", "returncode": 0}
        with self.assertRaises(DATA.Refused):
            DATA.project_android_positive(value, CONTEXT, bad, phases, inventory)

    def test_ios_positive_paired_admissions_preserve_parent_context_and_limits(self):
        for target in DATA.TARGETS:
            context = dict(CONTEXT, target=target)
            _, facts, test, summary, statuses, phases, inventory = positive_ui_data(context, ios=True)
            result = DATA.project_ios_positive(facts, test, summary, context, statuses, phases, inventory)
            self.assertEqual(result["observation"], facts)
            self.assertEqual(result["testCounts"], DATA.POSITIVE_UI_COUNTS)
            self.assertEqual(result["binding"], "same-work-root-parent-context-only")
            self.assertNotIn("runId", result)
            self.assertIs(result["nativeSuccessInferred"], False)
            self.assertIsNone(result["cleanExitStatus"])
            self.assertNotIn(SENTINEL, json.dumps(result))
            self.assertEqual([row["role"] for row in result["commands"]["test"]],
                             [row["role"] for row in test["commands"]])
            for which, key, item in (("test", "target", "wrong"), ("test", "sourceCommit", "2" * 40),
                    ("test", "originalTestReturncode", True), ("test", "originalClosesCompleted", False),
                    ("test", "strictCodesignOriginalZero", False), ("test", "reSignedOrRepaired", True),
                    ("test", "originalProductsPrePostMatched", False), ("test", "appSandboxEntitlement", "true"),
                    ("test", "runId", "123"), ("summary", "sourceRosterSha256", "2" * 64),
                    ("summary", "originalReturncode", 1), ("summary", "phase", "test")):
                bad_test, bad_summary = copy.deepcopy(test), copy.deepcopy(summary)
                (bad_test if which == "test" else bad_summary)[key] = item
                with self.subTest(target=target, which=which, field=key), self.assertRaises(DATA.Refused):
                    DATA.project_ios_positive(facts, bad_test, bad_summary, context, statuses, phases, inventory)
            for fault in ("role", "count", "status", "timeout", "output", "clock", "observation", "counts"):
                bad_test, bad_summary = copy.deepcopy(test), copy.deepcopy(summary)
                if fault == "role": bad_test["commands"][0]["role"] = "one-admitted-ui-test"
                if fault == "count": bad_test["commands"].append(copy.deepcopy(test["commands"][0]))
                if fault == "status": bad_test["commands"][3]["returncode"] = 1
                if fault == "timeout": bad_test["commands"][3]["timeoutSeconds"] = 1021
                if fault == "output": bad_test["commands"][3]["stdoutBytes"] = 1048577
                if fault == "clock": bad_test["phaseClock"]["deadlineNs"] = str(int(test["phaseClock"]["deadlineNs"]) + 1)
                if fault == "observation": bad_test["iosUnsignedObservation"]["operationId"] = "3" * 32
                if fault == "counts": bad_summary["iosUnsignedTestCounts"]["passedTests"] = 2
                with self.subTest(target=target, fault=fault), self.assertRaises(DATA.Refused):
                    DATA.project_ios_positive(facts, bad_test, bad_summary, context, statuses, phases, inventory)
            for key in ("signed", "ipaExported", "releaseQualified", "archiveDescendantsObserved"):
                bad = copy.deepcopy(facts); bad[key] = True
                with self.assertRaises(DATA.Refused):
                    DATA.project_ios_positive(bad, test, summary, context, statuses, phases, inventory)

    def test_positive_ui_fixed_files_keep_private_originals_and_partial_refusals(self):
        for ios in (False, True):
            with self.subTest(ios=ios), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                android, facts, test, summary, statuses, _, inventory = positive_ui_data(ios=ios)
                write(root, "source-inventory.json", {"source": CONTEXT["source"], "tree": inventory["tree"],
                    "files": [{"path": "public.rs", "gitMode": "100644", "blob": "2" * 40, "size": 1, "sha256": "3" * 64}]})
                write(root, "android-helper-package-install.json", receipt("package-install"))
                for name, row in statuses.items():
                    write(root, name, (str(row["returncode"]) + "\n").encode())
                source_values = {"android": android} if not ios else {"iosFacts": facts, "iosTest": test, "iosSummary": summary}
                originals = []
                for key, path, _, _ in DATA.POSITIVE_UI_INPUTS:
                    if key in source_values:
                        item = write(root, path, source_values[key]); originals.append((item, item.read_bytes()))
                private = write(root, "normal-ui/android-input-fixture.json", SENTINEL.encode())
                write(root, "normal-ui/ios-unsigned-archive-summary.json", SENTINEL.encode())
                result = project(root)
                selected = "iosUnsignedArchive" if ios else "androidSignedBuild"
                other = "androidSignedBuild" if ios else "iosUnsignedArchive"
                self.assertEqual(result["positiveUiObservations"][selected]["receiptState"], "observed")
                self.assertEqual(result["positiveUiObservations"][other], {"receiptState": "absent"})
                self.assertNotIn(SENTINEL.encode(), (root / DATA.OUTPUT).read_bytes())
                self.assertEqual(private.read_bytes(), SENTINEL.encode())
                for item, body in originals: self.assertEqual(item.read_bytes(), body)
                self.assertLessEqual((root / DATA.OUTPUT).stat().st_size, DATA.OUTPUT_LIMIT)
        for fault in ("missing-summary", "status-failure", "wrong-source", "closed-false", "malformed-facts", "linked-facts"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                _, facts, test, summary, statuses, phases, inventory = positive_ui_data(ios=True)
                if fault == "status-failure": statuses[DATA.POSITIVE_UI_STATUSES["ios"][0]]["returncode"] = 70
                if fault == "wrong-source": summary["sourceCommit"] = "2" * 40
                if fault == "closed-false": phases["package-install"]["originalClosesKnown"] = False
                for key, path, _, _ in DATA.POSITIVE_UI_INPUTS:
                    if key not in ("iosFacts", "iosTest", "iosSummary"): continue
                    if fault == "missing-summary" and key == "iosSummary": continue
                    item = write(root, path, {"iosFacts": facts, "iosTest": test, "iosSummary": summary}[key])
                    if key == "iosFacts" and fault == "malformed-facts": item.write_bytes(b'{"source":NaN}')
                    if key == "iosFacts" and fault == "linked-facts": os.link(item, root / "second-link")
                fd = DATA.open_root(str(root))
                try:
                    b = dict(budget(), files=0, bytes=0, outputBytes=16384)
                    result = DATA.positive_ui_observations(fd, CONTEXT, statuses, phases, inventory, b)
                finally: os.close(fd)
                self.assertEqual(result["iosUnsignedArchive"], {"receiptState": "refused"})
                self.assertEqual(result["androidSignedBuild"], {"receiptState": "absent"})
        with tempfile.TemporaryDirectory() as directory:
            result = DATA.project(directory, profile="aqua", source=CONTEXT["source"], workflow_source=CONTEXT["source"],
                run_id="123", run_attempt="2", target=CONTEXT["target"])
            self.assertNotIn("positiveUiObservations", result)

        # Every document comes from the actual inert workflow result expression.
        for target in DATA.TARGETS:
            context = dict(CONTEXT, target=target)
            values, bodies, preview, statuses, phases, inventory = ordinary_ui_producer_data(context)
            with self.subTest(ordinaryTarget=target), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                originals = []
                for key, path, *_ in DATA.ORDINARY_UI_INPUTS:
                    item = write(root, path, bodies[key]); originals.append((item, bodies[key]))
                fd = DATA.open_root(str(root))
                try:
                    b = dict(budget(), files=120, bytes=0, outputBytes=16384)
                    result = DATA.ordinary_ui_observations(fd, context, statuses, phases, inventory,
                        DATA.project_summary(preview, context, False), b)
                    self.assertEqual((b["files"], b["bytes"]), (128, 8 * (16384 + 1)))
                    self.assertTrue(all(value is False for value in b["ordinaryUiReads"].values()))
                    self.assertIs(b["ordinaryUiOutputReserved"], True)
                    self.assertEqual(b["outputBytes"], 16384 + 8192)
                    with self.assertRaises(DATA.Refused):
                        DATA.read_input(fd, DATA.ORDINARY_UI_INPUTS[0][1], 16384, b, ordinary_ui_reserved=True)
                finally: os.close(fd)
                self.assertLessEqual(len(json.dumps(result, sort_keys=True, separators=(",", ":"))), 8192)
                for key, row in result["results"].items():
                    self.assertEqual(row["receiptState"], "observed")
                    self.assertEqual(row["testCounts"], [2, 2, 0, 0, 0] if key in ("project", "savedChecks") else [1, 1, 0, 0, 0])
                    self.assertIs(row["resultWriterFinalityEstablished"], False)
                    self.assertIsNone(row["cleanExitStatus"])
                    self.assertIs(row["productReady"], False)
                    self.assertEqual(row["resultSha256"], hashlib.sha256(bodies[key]).hexdigest())
                self.assertEqual(result["results"]["savedVersion"]["producerReturncode"], 86)
                for key in ("workflowRefusal", "releaseEvidence", "savedVersion"):
                    self.assertNotIn("originalCommandStatuses", result["results"][key])
                self.assertNotIn(SENTINEL, json.dumps(result))
                for item, body in originals: self.assertEqual(item.read_bytes(), body)
                # Full real project path, not just a copied positive-validator call.
                write(root, "source-inventory.json", {"source": context["source"], "tree": inventory["tree"],
                    "files": [{"path": "public.rs", "gitMode": "100644", "blob": "2" * 40,
                               "size": 1, "sha256": "3" * 64}]})
                write(root, "preview/PREVIEW.json", preview)
                installation_receipt = receipt("package-install") | {name: context[name] for name in
                    ("source", "workflowSource", "runId", "runAttempt", "target")}
                installation_receipt["finalImage"]["target"] = context["target"]
                write(root, "android-helper-package-install.json", installation_receipt)
                for name, status in statuses.items(): write(root, name, (str(status["returncode"]) + "\n").encode())
                complete = DATA.project(str(root), profile="installed", source=context["source"],
                    workflow_source=context["workflowSource"], run_id=context["runId"],
                    run_attempt=context["runAttempt"], target=context["target"])
                combined = complete["positiveUiObservations"]
                self.assertTrue(all(row["receiptState"] == "observed" for row in combined["ordinary"]["results"].values()))
                self.assertEqual(combined["ordinary"]["binding"]["sourceTree"], complete["sourceInventory"]["tree"])
                self.assertLessEqual(len(json.dumps(combined, sort_keys=True, separators=(",", ":"))), 16384)
                self.assertLessEqual((root / DATA.OUTPUT).stat().st_size, DATA.OUTPUT_LIMIT)
                self.assertNotIn(SENTINEL.encode(), (root / DATA.OUTPUT).read_bytes())
                for item, body in originals: self.assertEqual(item.read_bytes(), body)
                # Prospective ordinary charge survives until the real enclosing projection;
                # all absent legacy rows still charge actual combined result bytes.
                fd = DATA.open_root(str(root))
                try:
                    tight = dict(budget(), files=0, bytes=0, outputBytes=DATA.OUTPUT_LIMIT - 8192)
                    DATA.reserve_ordinary_ui_reads(tight)
                    self.assertEqual(tight["outputBytes"], DATA.OUTPUT_LIMIT)
                    with self.assertRaises(DATA.Refused):
                        DATA.positive_ui_observations(fd, context, statuses, phases, inventory, tight,
                            {"preview": DATA.project_summary(preview, context, False)})
                    self.assertIs(tight["ordinaryUiOutputReserved"], False)
                    with self.assertRaises(DATA.Refused): DATA.reserve_ordinary_ui_reads(tight)
                finally: os.close(fd)
                # Missing saved-checks is legitimate for the genuine remaining-three cohort.
                (root / DATA.ORDINARY_UI_INPUTS[4][1]).unlink()
                fd = DATA.open_root(str(root))
                try:
                    result = DATA.ordinary_ui_observations(fd, context, statuses, phases, inventory,
                        DATA.project_summary(preview, context, False), dict(budget(), files=0, bytes=0, outputBytes=16384))
                finally: os.close(fd)
                self.assertEqual(result["results"]["savedChecks"], {"receiptState": "absent"})
                self.assertTrue(all(result["results"][key]["receiptState"] == "observed" for key in
                    ("workflowRefusal", "releaseEvidence", "savedVersion")))
            faults = ("missing", "oversize", "linked", "duplicate", "nonfinite", "unknown-key", "bool-count",
                "source", "run", "tree", "package", "hash", "prior", "closed-false", "mixed-singleton", "status", "build-hash")
            for fault in faults:
                with self.subTest(ordinaryFault=fault, target=target), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory); bad = copy.deepcopy(values); changed_phases = copy.deepcopy(phases)
                    changed_statuses = copy.deepcopy(statuses)
                    if fault == "unknown-key": bad["launch"]["privateUnknown"] = SENTINEL
                    if fault == "bool-count": bad["launch"]["testCounts"]["totalTestCount"] = True
                    if fault == "source": bad["launch"]["harnessSourceCommit"] = "9" * 40
                    if fault == "run": bad["launch"]["runId"] = "999"
                    if fault == "tree": bad["launch"]["sourceTree"] = "9" * 40
                    if fault == "package": bad["launch"]["packageSha256"] = "9" * 64
                    if fault == "hash": bad["launch"]["nativeSummarySha256"] = SENTINEL
                    if fault == "prior": bad["diagnostics"]["priorResultSha256"]["result.json"] = "9" * 64
                    if fault == "closed-false": changed_phases["package-install"]["originalClosesKnown"] = False
                    if fault == "mixed-singleton": bad["workflowRefusal"]["selectedSavedFileScope"] = "release-evidence"
                    if fault == "status": changed_statuses["normal-ui/test.status"]["returncode"] = 70
                    if fault == "build-hash": bad["project"]["buildCommandAdmissionSha256"] = "9" * 64
                    for key, path, *_ in DATA.ORDINARY_UI_INPUTS:
                        if fault == "missing" and key == "launch": continue
                        raw = (json.dumps(bad[key], sort_keys=True, separators=(",", ":")) + "\n").encode()
                        if key == "launch" and fault in ("duplicate", "nonfinite", "oversize"):
                            raw = {"duplicate": b'{"schemaVersion":1,"schemaVersion":1}',
                                "nonfinite": b'{"schemaVersion":NaN}', "oversize": b"x" * 16385}[fault]
                        item = write(root, path, raw)
                        if key == "launch" and fault == "linked": os.link(item, root / "second-original-link")
                    fd = DATA.open_root(str(root))
                    try:
                        result = DATA.ordinary_ui_observations(fd, context, changed_statuses, changed_phases, inventory,
                            DATA.project_summary(preview, context, False), dict(budget(), files=0, bytes=0, outputBytes=16384))
                    finally: os.close(fd)
                    selected = {"prior": "diagnostics", "mixed-singleton": "workflowRefusal", "build-hash": "project"}.get(fault, "launch")
                    self.assertEqual(result["results"][selected], {"receiptState": "absent" if fault == "missing" else "refused"})
                    self.assertNotIn(SENTINEL, json.dumps(result))
        with tempfile.TemporaryDirectory() as directory:
            fd = DATA.open_root(directory)
            try:
                empty = DATA.ordinary_ui_observations(fd, CONTEXT, {}, {}, {}, {},
                    dict(budget(), files=120, bytes=0, outputBytes=16384))
            finally: os.close(fd)
            self.assertEqual(empty["receiptState"], "absent")
            self.assertTrue(all(row == {"receiptState": "absent"} for row in empty["results"].values()))
        for changes in ({"files": 121}, {"bytes": DATA.INPUT_LIMIT - 8 * (16384 + 1) + 1},
                        {"outputBytes": DATA.OUTPUT_LIMIT - 8192 + 1}):
            with self.assertRaises(DATA.Refused):
                DATA.reserve_ordinary_ui_reads(dict(budget(), files=0, bytes=0, outputBytes=16384) | changes)

    def test_positive_ui_specific_decoder_and_complete_fixed_roster_bounds(self):
        def padded(size):
            prefix, suffix = b'{"opaque":"', b'"}'
            return prefix + b"x" * (size - len(prefix) - len(suffix)) + suffix
        DATA.decode(padded(16384), budget())
        for size in (16385, 32768):
            with self.assertRaises(DATA.Refused): DATA.decode(padded(size), budget())
            self.assertEqual(len(DATA.decode(padded(size), budget(), ui_admission=True)["opaque"]), size - 13)
        with self.assertRaises(DATA.Refused): DATA.decode(padded(32769), budget(), ui_admission=True)
        for option in (1, None, "true"):
            with self.assertRaises(DATA.Refused): DATA.decode(b"{}", budget(), ui_admission=option)
        with self.assertRaises(DATA.Refused): DATA.decode(b"{}", budget(), inventory=True, ui_admission=True)
        for body in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1.5}', b'{"a":Infinity}'):
            with self.assertRaises(DATA.Refused): DATA.decode(body, budget(), ui_admission=True)
        self.assertEqual(len(DATA.POSITIVE_UI_INPUTS), 7)
        self.assertEqual([item[2] for item in DATA.POSITIVE_UI_INPUTS], [16384, 16384, 32768, 32768, 16384, 32768, 32768])
        attempts = (len(DATA.STATUS_FILES) + len(DATA.PHASES) + 4 + len(DATA.PACKAGE_SIGNATURE_CAPTURES)
            + len(DATA.INSTALLER_DIAGNOSTIC_INPUTS) + len(DATA.UI_DIAGNOSTICS) + 6
            + len(DATA.POSITIVE_UI_INPUTS) + len(DATA.ORDINARY_UI_INPUTS))
        self.assertEqual((len(DATA.STATUS_FILES), len(DATA.PHASES), len(DATA.UI_DIAGNOSTICS), len(DATA.POSITIVE_UI_INPUTS)),
                         (76, 20, 3, 7))
        self.assertEqual(attempts, 128)
        self.assertEqual(len(DATA.ORDINARY_UI_INPUTS), 8)
        self.assertLessEqual(attempts, 128)
        self.assertEqual((DATA.INPUT_LIMIT, DATA.OUTPUT_LIMIT), (3 * 1024 * 1024, 128 * 1024))
        # Each legal positive maximum remains finite without displacing old report facts.
        value, facts, test, summary, statuses, phases, inventory = positive_ui_data()
        value["observation"].update(artifactBytes=64 << 20, outputEntries=100000, outputNameBytes=2 << 20,
            moduleLogicalBytes=1 << 30, outputLogicalBytes=2 << 30)
        android = DATA.project_android_positive(value, CONTEXT, statuses, phases, inventory)
        _, facts, test, summary, statuses, phases, inventory = positive_ui_data(ios=True)
        facts.update(originalEntries=100000, originalBytes=8 << 30); test["iosUnsignedObservation"] = copy.deepcopy(facts)
        ios = DATA.project_ios_positive(facts, test, summary, CONTEXT, statuses, phases, inventory)
        recovery_facts, recovery_test, recovery_summary, recovery_statuses, recovery_phases, recovery_inventory = ios_pending_recovery_data()
        recovery_facts["account"].update(nativeBaselineMembers=8)
        recovery_facts["account"]["producer"]["commands"] = 64
        recovery_test["iosPendingRecovery"] = copy.deepcopy(recovery_facts)
        recovery = DATA.project_ios_pending_recovery(recovery_facts, recovery_test, recovery_summary, CONTEXT,
                                                    recovery_statuses, recovery_phases, recovery_inventory)
        self.assertLessEqual(len(json.dumps(android)) + len(json.dumps(ios)) + len(json.dumps(recovery)), 16384)

    def test_ios_pending_recovery_requires_distinct_ui_and_real_account_readback(self):
        for target in DATA.TARGETS:
            context = dict(CONTEXT, target=target)
            facts, test, summary, statuses, phases, inventory = ios_pending_recovery_data(context)
            result = DATA.project_ios_pending_recovery(facts, test, summary, context, statuses, phases, inventory)
            self.assertEqual(result["observation"], facts["observation"])
            self.assertEqual(result["account"], facts["account"])
            self.assertEqual(result["testCounts"], DATA.POSITIVE_UI_COUNTS)
            self.assertEqual(result["allWorkerFinality"], "not-established-by-XCTest-UI-state")
            self.assertIsNone(result["cleanExitStatus"])
            for name in ("nativeSuccessInferred", "appleSigningMaterialUsed", "signedExportQualified",
                         "fullUIQualified", "distributionQualified", "productReady"):
                self.assertIs(result[name], False)
            self.assertNotIn(SENTINEL, json.dumps(result))
            for section, key, value in (
                ("observation", "sourceCommit", "9" * 40), ("observation", "target", "wrong"),
                ("observation", "runId", "124"), ("observation", "runAttempt", "3"),
                ("observation", "fixtureSha256", "9" * 64), ("observation", "sessionSha256", "not-hex"),
                ("observation", "inspectUnchecked", False), ("observation", "recoverUnchecked", 1),
                ("observation", "ordinaryQuit", False), ("observation", "session", SENTINEL),
                ("account", "exactPendingSessionRecovered", False), ("account", "originalOwnedNativeAndControlsRemoved", False),
                ("account", "persistentOriginalLeaseRetained", False), ("account", "baselineIdentitiesMatched", False),
                ("account", "baselinePreferencesMatched", False), ("account", "projectMarkerUnchanged", False),
                ("account", "nativeBaselineMembers", 0), ("account", "nativeBaselineMembers", 9),
                ("account", "nativeBaselineMembers", True), ("account", "privateContentsExported", True),
                ("account", "foreignPreferenceConflictInjected", True), ("account", "appleSigningMaterialUsed", True),
                ("account", "signedExportQualified", True), ("account", "private", SENTINEL)):
                bad = copy.deepcopy(facts); bad[section][key] = value
                bad_test = copy.deepcopy(test); bad_test["iosPendingRecovery"] = copy.deepcopy(bad)
                with self.subTest(target=target, section=section, field=key), self.assertRaises(DATA.Refused):
                    DATA.project_ios_pending_recovery(bad, bad_test, summary, context, statuses, phases, inventory)
            for side in ("inspect", "recover"):
                for key, value in (("phase", "running"), ("outcome", "unknown"), ("reason", "failed"),
                                   ("operationId", "x" * 32), ("ownerGeneration", "x" * 32),
                                   ("accountStatus", "absent"), ("lifetime", {"allFinality": True})):
                    bad = copy.deepcopy(facts); bad["observation"][side][key] = value
                    with self.subTest(side=side, field=key), self.assertRaises(DATA.Refused):
                        DATA.ios_pending_recovery_facts(bad, context)
            for key in ("operationId", "ownerGeneration"):
                bad = copy.deepcopy(facts); bad["observation"]["recover"][key] = bad["observation"]["inspect"][key]
                with self.assertRaises(DATA.Refused): DATA.ios_pending_recovery_facts(bad, context)
            for side in ("producer", "nativeReadback"):
                for key, value in (("scope", "invented"), ("case", "ios-recovery-empty"), ("commands", True),
                    ("profileCalls", 1), ("commandFinalities", False), ("leaseClosed", False), ("sessionClosed", False),
                    ("handlersRestored", False), ("fixtureDescriptorsClosed", False), ("originalDeadlineMet", False),
                    ("keychainContentsRead", True), ("private", SENTINEL)):
                    bad = copy.deepcopy(facts); bad["account"][side][key] = value
                    with self.subTest(side=side, field=key), self.assertRaises(DATA.Refused):
                        DATA.ios_pending_recovery_facts(bad, context)
            for side, key, value in (("producer", "commands", 2), ("producer", "commands", 65),
                    ("producer", "pendingLeft", False), ("nativeReadback", "commands", 3),
                    ("nativeReadback", "pendingAbsent", False), ("nativeReadback", "baselinePreferencesMatched", False),
                    ("nativeReadback", "baselineMemberIdentitiesMatched", False)):
                bad = copy.deepcopy(facts); bad["account"][side][key] = value
                with self.assertRaises(DATA.Refused): DATA.ios_pending_recovery_facts(bad, context)
            for side in ("producer", "nativeReadback"):
                bad = copy.deepcopy(facts); del bad["account"][side]
                with self.assertRaises(DATA.Refused): DATA.ios_pending_recovery_facts(bad, context)
            maximum = copy.deepcopy(facts); maximum["account"]["nativeBaselineMembers"] = 8
            maximum["account"]["producer"]["commands"] = 64
            self.assertEqual(DATA.ios_pending_recovery_facts(maximum, context), maximum)

    def test_ios_pending_recovery_requires_seven_originals_deadlines_and_summary(self):
        facts, test, summary, statuses, phases, inventory = ios_pending_recovery_data()
        def project(selected=test, summed=summary, status=statuses):
            return DATA.project_ios_pending_recovery(facts, selected, summed, CONTEXT, status, phases, inventory)
        result = project()
        self.assertEqual([row["role"] for row in result["commands"]["test"]], [
            "normal-ui-source-roster", "verify-generated-runner", "generated-runner-entitlements",
            "ios-account-produce", "one-admitted-ui-test", "ios-account-observe", "normal-ui-source-roster"])
        self.assertEqual(len(result["commands"]["summary"]), 3)
        for slot in range(7):
            for key, value in (("returncode", 1), ("returncode", -1), ("returncode", True), ("timeoutSeconds", 0),
                    ("timeoutSeconds", test["commands"][slot]["roleCapSeconds"] + 1), ("role", "made-up"),
                    ("outputLimitBytes", test["commands"][slot]["outputLimitBytes"] + 1),
                    ("stdoutBytes", test["commands"][slot]["outputLimitBytes"] + 1), ("argvSha256", SENTINEL)):
                bad = copy.deepcopy(test); bad["commands"][slot][key] = value
                with self.subTest(slot=slot, field=key), self.assertRaises(DATA.Refused): project(bad)
            bad = copy.deepcopy(test); del bad["commands"][slot]
            with self.assertRaises(DATA.Refused): project(bad)
        for fault in ("reordered", "duplicate", "legacy-ui-cap", "late", "phase-duration", "unknown-close", "facts-differ", "facts-close",
                      "nonzero-test", "unsigned-result", "no-source-post", "no-runner-verification", "private-roster"):
            bad = copy.deepcopy(test)
            if fault == "reordered": bad["commands"][3], bad["commands"][5] = bad["commands"][5], bad["commands"][3]
            if fault == "duplicate": bad["commands"].append(copy.deepcopy(bad["commands"][-1]))
            if fault == "legacy-ui-cap": bad["commands"][4].update(roleCapSeconds=1020, timeoutSeconds=1020)
            if fault == "late": bad["phaseClock"]["beforePublicationNs"] = bad["phaseClock"]["deadlineNs"]
            if fault == "phase-duration": bad["phaseClock"]["deadlineNs"] = str(1 + 1245 * 10**9)
            if fault == "unknown-close": bad["originalClosesCompleted"] = False
            if fault == "facts-differ": bad["iosPendingRecovery"]["observation"]["sessionSha256"] = "e" * 64
            if fault == "facts-close": bad["iosPendingRecovery"]["originalClosesCompleted"] = False
            if fault == "nonzero-test": bad["originalTestReturncode"] = 1
            if fault == "unsigned-result": bad["resultBundle"] = "ios-unsigned-archive-test.xcresult"
            if fault == "no-source-post": bad["sourcePrePostMatched"] = False
            if fault == "no-runner-verification": bad["strictCodesignOriginalZero"] = False
            if fault == "private-roster": bad["runnerExecutable"][1][5] = "2"
            with self.subTest(fault=fault), self.assertRaises(DATA.Refused): project(bad)
        for slot in range(3):
            bad = copy.deepcopy(summary); bad["commands"][slot]["returncode"] = 1
            with self.assertRaises(DATA.Refused): project(summed=bad)
        for key, value in (("sourceRosterSha256", "e" * 64), ("sourceCommit", "e" * 40), ("originalReturncode", 1)):
            bad = copy.deepcopy(summary); bad[key] = value
            with self.assertRaises(DATA.Refused): project(summed=bad)
        for key in DATA.POSITIVE_UI_COUNTS:
            bad = copy.deepcopy(summary); bad["iosPendingRecoveryTestCounts"][key] += 1
            with self.assertRaises(DATA.Refused): project(summed=bad)
        for names in DATA.POSITIVE_UI_STATUSES.values():
            bad = copy.deepcopy(statuses)
            if names == DATA.POSITIVE_UI_STATUSES["iosRecovery"]: bad[names[0]]["returncode"] = 1
            else: bad[names[0]] = {"receiptState": "observed", "returncode": 0}
            with self.assertRaises(DATA.Refused): project(status=bad)
        _, old_facts, old_test, old_summary, old_status, _, _ = positive_ui_data(ios=True)
        with self.assertRaises(DATA.Refused):
            DATA.project_ios_pending_recovery(old_facts, old_test, old_summary, CONTEXT, statuses, phases, inventory)
        with self.assertRaises(DATA.Refused):
            DATA.project_ios_positive(facts, test, summary, CONTEXT, old_status, phases, inventory)

    def test_ios_pending_recovery_fixed_reader_keeps_private_inputs_and_refuses_partial(self):
        for fault in (None, "missing-observer", "partial", "linked", "private-field", "failed-status"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                facts, test, summary, statuses, _, inventory = ios_pending_recovery_data()
                if fault == "missing-observer": del facts["account"]["nativeReadback"]
                if fault == "private-field": facts["account"]["private"] = SENTINEL
                if fault == "failed-status": statuses["normal-ui/ios-pending-recovery-test.status"]["returncode"] = 1
                write(root, "source-inventory.json", {"source": CONTEXT["source"], "tree": inventory["tree"],
                    "files": [{"path": "public.rs", "gitMode": "100644", "blob": "2" * 40, "size": 1, "sha256": "3" * 64}]})
                write(root, "android-helper-package-install.json", receipt("package-install"))
                for name, row in statuses.items(): write(root, name, (str(row["returncode"]) + "\n").encode())
                supplied = {"iosRecoveryFacts": facts, "iosRecoveryTest": test, "iosRecoverySummary": summary}
                originals = []
                for key, path, _, _ in DATA.POSITIVE_UI_INPUTS:
                    if key not in supplied or fault == "partial" and key == "iosRecoverySummary": continue
                    item = write(root, path, supplied[key]); originals.append((item, item.read_bytes()))
                    if fault == "linked" and key == "iosRecoveryFacts": os.link(item, root / "second-link")
                raw = write(root, "normal-ui/ios-pending-recovery-summary.json", SENTINEL.encode())
                private = write(root, "normal-ui/account-baseline.json", SENTINEL.encode())
                value = project(root)["positiveUiObservations"]
                if fault is None:
                    self.assertEqual(value["iosPendingRecovery"]["receiptState"], "observed")
                    self.assertTrue(value["iosPendingRecovery"]["account"]["baselinePreferencesMatched"])
                elif fault == "failed-status":
                    self.assertEqual(value["iosPendingRecovery"], {"receiptState": "refused", "failureDiagnostic": {"receiptState": "absent"}})
                else: self.assertEqual(value["iosPendingRecovery"], {"receiptState": "refused"})
                self.assertEqual(value["iosUnsignedArchive"], {"receiptState": "absent"})
                self.assertEqual(value["androidSignedBuild"], {"receiptState": "absent"})
                self.assertNotIn(SENTINEL.encode(), (root / DATA.OUTPUT).read_bytes())
                self.assertEqual(private.read_bytes(), SENTINEL.encode()); self.assertEqual(raw.read_bytes(), SENTINEL.encode())
                for item, body in originals: self.assertEqual(item.read_bytes(), body)
                self.assertLessEqual((root / DATA.OUTPUT).stat().st_size, DATA.OUTPUT_LIMIT)

    def test_genuine_removal_data_preserves_case_facts_and_expected_nonzero(self):
        stager, helper = removal_data(); normal = normal_diagnostic_data(removal=True)
        self.assertEqual(DATA.REMOVAL_RELEASE, json.loads((ROOT / "desktop/macos-installed-inputs/build-release.json").read_text())["release"])
        self.assertEqual(DATA.REMOVAL_METHODS, normal["REMOVAL_METHODS"])
        union = set()
        for case in ("ordinary", "abrupt"):
            roles = helper["removal_runtime_roles"](case)
            self.assertEqual(DATA.REMOVAL_ROLES[case], roles)
            union.update(roles)
            value = removal_receipt(case, stager, helper, normal)
            row = DATA.project_receipt(value, {**CONTEXT, "expectedRemovalCase": case}, "package-removal-fixture")
            self.assertEqual(row["originalCalls"]["recordedCount"], 9)
            self.assertEqual(row["originalCalls"]["unclassifiedCount"], 0)
            nonzero = [call for call in row["originalCalls"]["calls"] if call["returncode"] != 0]
            self.assertEqual(len(nonzero), 1)
            self.assertTrue(helper["removal_native_result_data"](case, nonzero[0]["role"], nonzero[0]["returncode"]))
            final = row["removalFixture"]
            self.assertEqual(final, value["removalFixture"])
            self.assertEqual(final["qualification"], "pending-original-owner-finality")
            self.assertIs(final["powerLossQualified"], False)
            self.assertIs(final["productReady"], False)
            self.assertEqual(final["uiObservation"]["gateFree"], "unqualified")
            self.assertIs(final["uiObservation"]["normalQuit"], False)
            self.assertIs(row["recordedPassed"], True)  # Separate from pending fixture qualification.
        self.assertEqual(len(union), 12)
        self.assertTrue(union <= DATA.NATIVE_ROLES)

    def test_removal_mixed_cases_context_and_closed_fields_are_refused(self):
        stager, helper = removal_data(); normal = normal_diagnostic_data(removal=True)
        value = removal_receipt("ordinary", stager, helper, normal)
        context = {**CONTEXT, "expectedRemovalCase": "ordinary"}
        for key, bad in (("expectedRemovalCase", "disabled"), ("expectedRemovalCase", "abrupt"),
                         ("target", "x86_64-apple-darwin"), ("profile", "aqua"), ("source", "2" * 40)):
            with self.subTest(context=key), self.assertRaises(DATA.Refused):
                DATA.project_receipt(value, {**context, key: bad}, "package-removal-fixture")
        mutations = (((), "case", "abrupt"), ((), "archives", True), ((), "outputs", 6),
            ((), "qualification", "passed"), ((), "powerLossQualified", True), ((), "originalUIJoined", False),
            ((), "allPayloadAbsent", 1), ((), "abruptProcessCutObserved", True), ((), "outputsSha256", SENTINEL),
            (("targetBinding",), "release", SENTINEL), (("targetBinding",), "sourceCommit", "2" * 40),
            (("targetBinding",), "target", "x86_64-apple-darwin"), (("targetBinding",), "packageSha256", SENTINEL),
            (("uiObservation",), "case", "abrupt"), (("uiObservation",), "testIdentifier", SENTINEL),
            (("uiObservation",), "normalQuit", True), (("uiObservation",), "gateFree", "qualified"),
            (("uiObservation",), "nativeSummarySha256", SENTINEL), (("uiObservation", "testCounts"), "passedTests", True))
        for path, name, bad in mutations:
            broken = copy.deepcopy(value); node = broken["removalFixture"]
            for part in path: node = node[part]
            node[name] = bad
            with self.subTest(path=path, name=name), self.assertRaises(DATA.Refused):
                DATA.project_receipt(broken, context, "package-removal-fixture")
        for key in value["removalFixture"]:
            broken = copy.deepcopy(value); del broken["removalFixture"][key]
            with self.subTest(missing=key), self.assertRaises(DATA.Refused):
                DATA.project_receipt(broken, context, "package-removal-fixture")
        for path in ((), ("targetBinding",), ("uiObservation",), ("uiObservation", "testCounts")):
            broken = copy.deepcopy(value); node = broken["removalFixture"]
            for part in path: node = node[part]
            node["rawMessage"] = SENTINEL
            with self.subTest(extra=path), self.assertRaises(DATA.Refused):
                DATA.project_receipt(broken, context, "package-removal-fixture")
        for role in ("removal-live-cut", SENTINEL):
            broken = copy.deepcopy(value); broken["originalCalls"][3]["role"] = role
            with self.assertRaises(DATA.Refused):
                DATA.project_receipt(broken, context, "package-removal-fixture")
        broken = copy.deepcopy(value); broken["originalCalls"] *= 15
        with self.assertRaises(DATA.Refused):
            DATA.project_receipt(broken, context, "package-removal-fixture")
        broken = copy.deepcopy(value); broken["phase"] = "package-remove"
        with self.assertRaises(DATA.Refused):
            DATA.project_receipt(broken, context, "package-remove")

    def test_removal_failed_parent_and_partial_originals_never_become_success(self):
        stager, helper = removal_data(); normal = normal_diagnostic_data(removal=True)
        value = removal_receipt("ordinary", stager, helper, normal)
        context = {**CONTEXT, "expectedRemovalCase": "ordinary"}
        value.update(passed=False, originalClosesKnown=False, targetRetired=False)
        row = DATA.project_receipt(value, context, "package-removal-fixture")
        self.assertIs(row["recordedPassed"], False)
        self.assertIs(row["originalClosesKnown"], False)
        self.assertEqual(row["removalFixture"]["qualification"], "pending-original-owner-finality")
        del value["removalFixture"]
        value["originalCalls"] = [{"role": "removal-target-attach", "entered": True, "returned": False, "capturesSettled": False}]
        row = DATA.project_receipt(value, context, "package-removal-fixture")
        self.assertIsNone(row["removalFixture"])
        self.assertEqual(row["originalCalls"]["recordedCount"], 1)
        self.assertIsNone(row["originalCalls"]["calls"][0].get("returncode"))
        self.assertIs(row["originalCalls"]["calls"][0]["returned"], False)

    def test_removal_cli_case_suffix_is_optional_explicit_and_fixed(self):
        choices = (("installed", CONTEXT["target"], [], 0, "disabled"),
            ("aqua", CONTEXT["target"], [], 0, "disabled"),
            ("installed", "x86_64-apple-darwin", [], 0, "disabled"),
            *( ("installed", CONTEXT["target"], ["--removal-case", case], 0, case) for case in ("disabled", "ordinary", "abrupt") ),
            ("aqua", CONTEXT["target"], ["--removal-case", "ordinary"], 1, None),
            ("installed", "x86_64-apple-darwin", ["--removal-case", "ordinary"], 1, None),
            ("installed", CONTEXT["target"], ["--removal-case", SENTINEL], 1, None),
            ("installed", CONTEXT["target"], ["--other", "ordinary"], 1, None),
            ("installed", CONTEXT["target"], ["--removal-case", "ordinary", "--removal-case", "ordinary"], 1, None))
        for profile, target, suffix, expected, case in choices:
            with self.subTest(profile=profile, target=target, suffix=suffix), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                args = ["--profile", profile, "--work", str(root), "--target", target, "--source", CONTEXT["source"],
                    "--workflow-source", CONTEXT["workflowSource"], "--run-id", CONTEXT["runId"], "--run-attempt", CONTEXT["runAttempt"]]
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(DATA.main(args + suffix), expected)
                if expected == 0:
                    self.assertEqual(json.loads((root / DATA.OUTPUT).read_text())["expectedRemovalCase"], case)
                else:
                    self.assertFalse((root / DATA.OUTPUT).exists())
                # A recognized option in the wrong position is not a generic CLI.
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(DATA.main(["--removal-case", "ordinary"] + args), 1)

    def test_removal_file_projection_keeps_case_and_caller_status_independent(self):
        stager, helper = removal_data(); normal = normal_diagnostic_data(removal=True)
        for case in ("ordinary", "abrupt"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory); value = removal_receipt(case, stager, helper, normal)
                path = write(root, "android-helper-package-removal-fixture.json", value); before = path.read_bytes()
                result = project(root, removal_case=case)
                self.assertEqual(result["expectedRemovalCase"], case)
                row = result["phases"]["package-removal-fixture"]
                self.assertEqual(row["removalFixture"]["case"], case)
                self.assertEqual(row["callerStatus"], {"receiptState": "absent"})
                self.assertEqual(path.read_bytes(), before)

    def test_data_contract_five_statuses_are_observations_not_phase_acceptance(self):
        names = tuple("data-contracts/" + role + ".status" for role in ("mount", "apfs", "build", "rust", "python"))
        self.assertEqual(tuple(name for name in DATA.STATUS_FILES if name.startswith("data-contracts/")), names)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = [write(root, name, body) for name, body in zip(names, (b"0\n", b"1\n", b"unavailable\n", b"0 0 0\n"))]
            raw = write(root, "data-contracts/result.json", SENTINEL.encode())
            before = [path.read_bytes() for path in paths + [raw]]
            result = project(root)
            self.assertEqual(result["statuses"][names[0]], {"receiptState": "observed", "returncode": 0})
            self.assertEqual(result["statuses"][names[1]], {"receiptState": "observed", "returncode": 1})
            self.assertEqual(result["statuses"][names[2]], {"receiptState": "refused"})
            self.assertEqual(result["statuses"][names[3]], {"receiptState": "refused"})
            self.assertEqual(result["statuses"][names[4]], {"receiptState": "absent"})
            self.assertEqual([path.read_bytes() for path in paths + [raw]], before)
            self.assertIs(result["diagnosticOnly"], True)
            self.assertIs(result["productReady"], False)
            self.assertNotIn(SENTINEL, (root / DATA.OUTPUT).read_text())

    def test_genuine_normal_build_writer_preserves_finite_cause_without_compiler_prose(self):
        value = build_diagnostic(normal_diagnostic_data())
        row = DATA.project_ui_diagnostic(value, "build", {"receiptState": "observed", "returncode": 70})
        self.assertEqual(row["originalReturncode"], 70)
        self.assertEqual(row["status"], "classified")
        self.assertEqual(row["errorCodes"], [{"stream": "stdout", "domain": "NSPOSIXErrorDomain", "code": 2}])
        self.assertEqual(row["compilerDiagnostics"], [{"stream": "stderr", "source": "NormalAppUITests.swift",
            "line": 123, "column": 7, "severity": "error", "reasonCodes": ["missing-name"]}])
        self.assertIs(row["markers"]["buildFailed"], True)
        self.assertIs(row["markers"]["xcodebuildError"], True)
        self.assertEqual(row["stderrSha256"], value["stderrSha256"])
        self.assertEqual(row["binding"], "same-work-root-parent-context-only")
        self.assertIs(row["nativeSuccessInferred"], False)
        self.assertNotIn(SENTINEL, json.dumps(row))
        self.assertNotIn("source", row)  # The writer did not bind a source commit.

    def test_genuine_query_and_fallback_keep_unavailable_distinct(self):
        normal = normal_diagnostic_data()
        status = {"receiptState": "observed", "returncode": 70}
        for role, phase in (("build", "build"), ("toolchain", "query")):
            for fallback in (True, False):
                value = build_diagnostic(normal, phase, fallback=fallback)
                row = DATA.project_ui_diagnostic(value, role, status)
                self.assertEqual(row["status"], "unavailable" if fallback else "classified")
                self.assertEqual("compilerDiagnostics" in row, role == "build")
                self.assertIs(row["nativeSuccessInferred"], False)
        value = build_diagnostic(normal, "query"); value["stdoutBytes"] = 4097
        with self.assertRaises(DATA.Refused):
            DATA.project_ui_diagnostic(value, "toolchain", status)
        with self.assertRaises(DATA.Refused):
            DATA.project_ui_diagnostic(build_diagnostic(normal), "toolchain", status)
        original = CompletedProcess([], 70, b"MRK_MACOS_NORMAL_DASHBOARD_QUERY=observation=identifier;matches=5;exceedsFour=1;nonAtomic=1\n", b"")
        value = normal["normal_failure_diagnostics"]("query", None, original)
        row = DATA.project_ui_diagnostic(value, "toolchain", status)
        self.assertEqual(row["queryObservations"], [{"stream": "stdout", "kind": "dashboard", "observation": "identifier",
            "matches": 5, "exceedsFour": True, "nonAtomic": True}])
        for key, bad in (("matches", True), ("matches", 6), ("exceedsFour", False), ("nonAtomic", False),
                         ("kind", SENTINEL), ("observation", SENTINEL), ("stream", SENTINEL)):
            broken = copy.deepcopy(value); broken["queryObservations"][0][key] = bad
            with self.subTest(key=key), self.assertRaises(DATA.Refused):
                DATA.project_ui_diagnostic(broken, "toolchain", status)

    def test_genuine_admission_projection_preserves_only_exception_facts(self):
        normal = normal_diagnostic_data()
        self.assertEqual(DATA.UI_ADMISSION_STAGES, frozenset(normal["ADMISSION_STAGES"]))
        self.assertEqual(DATA.UI_ADMISSION_EXCEPTIONS, frozenset(normal["ADMISSION_EXCEPTION_LABELS"]))
        self.assertEqual(DATA.UI_ADMISSION_SOURCES, frozenset(Path(name).name for name in normal["ADMISSION_SOURCE_FILES"]))
        self.assertEqual(DATA.UI_ADMISSION_ROLES, frozenset(normal["ADMISSION_COMMAND_ROLES"]))
        value = admission_diagnostic(normal)
        row = DATA.project_ui_diagnostic(value, "admission", {"receiptState": "observed", "returncode": 70})
        self.assertEqual(row["status"], "observed-exception-only")
        self.assertEqual((row["stage"], row["exceptionClass"]), ("execute", "ProcessError"))
        self.assertEqual(row["sourceFrames"], [{"source": "owned_process.py", "line": 321}])
        self.assertEqual(row["commands"], [{"role": "normal-toolchain-sdkPath", "returncode": 70,
                                          "stdoutBytes": 0, "stderrBytes": 256}])
        self.assertIsNone(row["ownerFailure"]["cleanupComplete"])
        self.assertIs(row["ownerFailure"]["contained"], False)
        self.assertIs(row["nativeSuccessInferred"], False)
        unavailable = normal["classify_normal_admission_failure"](SENTINEL.encode())
        self.assertEqual(DATA.project_ui_diagnostic(unavailable, "admission",
            {"receiptState": "observed", "returncode": 70})["status"], "unavailable")
        self.assertNotIn(SENTINEL, json.dumps(row))

    def test_owner_predicates_and_frame_omission_are_closed_optional_observations(self):
        normal = normal_diagnostic_data()
        self.assertEqual(DATA.UI_OWNER_REASONS, frozenset((*normal["ADMISSION_OWNER_REASONS"].values(), "unknown")))
        class OwnerError(Exception):
            dispatched = contained = cleanup_complete = True
            owner_failure_mask = 63
            def __str__(self):
                raise AssertionError("private-owner-text-must-not-be-read")
        owner = SimpleNamespace(ProcessError=OwnerError, ProcessInterrupted=KeyboardInterrupt,
            ProcessCleanupError=type("CleanupError", (OwnerError,), {}),
            ProcessOutcomeUnknown=type("OutcomeUnknown", (OwnerError,), {}))
        raw = normal["normal_admission_failure"]("execute",
            OwnerError("owned command produced incomplete output"), owner, [])
        raw["sourceFrames"] = [{"source": "_command_process.py", "line": 1000000}]
        raw["sourceFramesTruncated"] = True
        value = normal["classify_normal_admission_failure"](normal["encoded"](raw))
        status = {"receiptState": "observed", "returncode": 1}
        for mask in (None, 32, *range(48, 64)):
            value["ownerDiagnostic"]["failureMask"] = mask
            row = DATA.project_ui_diagnostic(value, "admission", status)
            self.assertEqual(row["ownerDiagnostic"], {"reason": "incomplete-output", "failureMask": mask})
            self.assertEqual(row["sourceFrames"], raw["sourceFrames"])
            self.assertIs(row["sourceFramesTruncated"], True)
            self.assertIs(row["nativeSuccessInferred"], False)
            self.assertEqual(row["binding"], "same-work-root-parent-context-only")
        legacy = admission_diagnostic(normal)
        self.assertNotIn("ownerDiagnostic", DATA.project_ui_diagnostic(legacy, "admission", status))
        value.update(ownerDiagnostic=None, sourceFramesTruncated=False)
        self.assertIsNone(DATA.project_ui_diagnostic(value, "admission", status)["ownerDiagnostic"])
        self.assertIs(DATA.project_ui_diagnostic(value, "admission", status)["sourceFramesTruncated"], False)
        good = {"reason": "incomplete-output", "failureMask": 63}
        for bad in (True, [], {}, {**good, "message": SENTINEL}, {**good, "reason": SENTINEL},
                    *({**good, "failureMask": mask} for mask in (True, False, 0, 1, 31, 33, 47, 64, "63"))):
            with self.subTest(bad=bad), self.assertRaises(DATA.Refused):
                DATA.project_ui_diagnostic({**value, "ownerDiagnostic": bad}, "admission", status)
        for broken in ({**value, "ownerDiagnostic": good, "exceptionClass": "Refused"},
                       {**value, "sourceFramesTruncated": None}, {**value, "sourceFramesTruncated": 1},
                       {**value, "sourceFrames": [{"source": SENTINEL, "line": 1}]},
                       {**value, "sourceFrames": [{"source": "_command_process.py", "line": True}]}):
            with self.assertRaises(DATA.Refused):
                DATA.project_ui_diagnostic(broken, "admission", status)
        unavailable = normal["classify_normal_admission_failure"](b"{}")
        with self.assertRaises(DATA.Refused):
            DATA.project_ui_diagnostic({**unavailable, "ownerDiagnostic": None}, "admission", status)
        self.assertNotIn(SENTINEL, json.dumps(value))

    def test_optional_build_destination_reasons_are_closed_and_backward_compatible(self):
        normal = normal_diagnostic_data()
        status = {"receiptState": "observed", "returncode": 70}
        value = build_diagnostic(normal); value.pop("buildFailureReasons", None)
        self.assertNotIn("buildFailureReasons", DATA.project_ui_diagnostic(value, "build", status))
        for reasons in ([], [{"stream": stream, "code": code} for stream in ("stdout", "stderr")
                            for code in ("destination-not-found", "no-eligible-destination")]):
            value["buildFailureReasons"] = reasons
            self.assertEqual(DATA.project_ui_diagnostic(value, "build", status)["buildFailureReasons"], reasons)
        valid = {"stream": "stderr", "code": "destination-not-found"}
        for reasons in (None, {}, [valid] * 5, [valid] * 2, [{**valid, "message": SENTINEL}],
                        [{**valid, "code": SENTINEL}], [{**valid, "stream": SENTINEL}],
                        [{**valid, "stream": True}], [{**valid, "code": 1}], [{}]):
            value["buildFailureReasons"] = reasons
            with self.subTest(reasons=reasons), self.assertRaises(DATA.Refused):
                DATA.project_ui_diagnostic(value, "build", status)
        query = build_diagnostic(normal, "query"); query["buildFailureReasons"] = []
        with self.assertRaises(DATA.Refused):
            DATA.project_ui_diagnostic(query, "toolchain", status)

    def test_ui_diagnostic_typed_and_closed_schema_mutations_are_refused(self):
        normal = normal_diagnostic_data()
        status = {"receiptState": "observed", "returncode": 70}
        cases = {
            "build": (("schemaVersion", True), ("status", SENTINEL), ("phase", "test"), ("selection", SENTINEL),
                ("stdoutBytes", True), ("stdoutBytes", 1048577), ("stderrSha256", SENTINEL), ("findingsTruncated", 1),
                ("errorCodes", [{}] * 9), ("errorCodes", [{"stream": "stdout", "domain": SENTINEL, "code": 2}]),
                ("errorCodes", [{"stream": "stderr", "domain": "NSPOSIXErrorDomain", "code": True}]),
                ("queryObservations", [{}] * 5), ("compilerDiagnostics", [{}] * 5), ("markers", {}),
                ("sourceFailures", [SENTINEL]), ("requireObservations", [SENTINEL]), ("dashboardReadiness", {})),
            "admission": (("schemaVersion", True), ("stage", SENTINEL), ("exceptionClass", SENTINEL),
                ("nativeSuccessInferred", True), ("productReady", True), ("unknownStateRetained", False),
                ("sourceFrames", [{"source": SENTINEL, "line": 1}]), ("sourceFrames", [{}] * 5),
                ("commands", [{}] * 17), ("ownerFailure", {"dispatched": 1, "contained": False, "cleanupComplete": None})),
        }
        for role, mutations in cases.items():
            base = build_diagnostic(normal) if role == "build" else admission_diagnostic(normal)
            for key, bad in mutations:
                value = copy.deepcopy(base); value[key] = bad
                with self.subTest(role=role, key=key, bad=bad), self.assertRaises(DATA.Refused):
                    DATA.project_ui_diagnostic(value, role, status)
            for key in base.keys() - {"buildFailureReasons", "destinationTable"}:
                value = copy.deepcopy(base); del value[key]
                with self.subTest(role=role, missing=key), self.assertRaises(DATA.Refused):
                    DATA.project_ui_diagnostic(value, role, status)
            for key in ("message", "path", "argv", "resultPost"):
                value = copy.deepcopy(base); value[key] = SENTINEL
                with self.subTest(role=role, extra=key), self.assertRaises(DATA.Refused):
                    DATA.project_ui_diagnostic(value, role, status)
        value = build_diagnostic(normal); value["compilerDiagnostics"][0]["reasonCodes"] = [SENTINEL]
        with self.assertRaises(DATA.Refused):
            DATA.project_ui_diagnostic(value, "build", status)
        for code in (True, 256, -1):
            value = admission_diagnostic(normal); value["commands"][0]["returncode"] = code
            with self.assertRaises(DATA.Refused):
                DATA.project_ui_diagnostic(value, "admission", status)

    def test_ui_diagnostics_require_independent_failed_scalar_status(self):
        normal = normal_diagnostic_data()
        for role, value in (("build", build_diagnostic(normal)), ("admission", admission_diagnostic(normal))):
            for status in (None, {}, {"receiptState": "absent"}, {"receiptState": "refused"},
                           *({"receiptState": "observed", "returncode": code} for code in (0, True, "70", "0 0 0", -1, 256))):
                with self.subTest(role=role, status=status), self.assertRaises(DATA.Refused):
                    DATA.project_ui_diagnostic(value, role, status)
        with self.assertRaises(DATA.Refused):
            DATA.project_ui_diagnostic(build_diagnostic(normal), "build", {"receiptState": "observed", "returncode": 1})

    def test_build_only_fixed_projection_needs_no_helper_phases_or_raw_log(self):
        normal = normal_diagnostic_data()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = [write(root, "normal-ui/build.status", b"70\n"),
                write(root, "normal-ui/build.failure-diagnostics.json", build_diagnostic(normal)),
                write(root, "normal-ui/build.admission-diagnostics.json", admission_diagnostic(normal)),
                write(root, "normal-ui/build.log", SENTINEL.encode())]
            before = [path.read_bytes() for path in files]
            value = project(root)
            self.assertTrue(all(row["receiptState"] == "absent" for row in value["phases"].values()))
            self.assertEqual(value["normalUiBuildDiagnostics"]["build"]["status"], "classified")
            self.assertEqual(value["normalUiBuildDiagnostics"]["admission"]["status"], "observed-exception-only")
            self.assertEqual(value["normalUiBuildDiagnostics"]["toolchain"], {"receiptState": "absent"})
            self.assertEqual({key: value[key] for key in CONTEXT}, CONTEXT)
            self.assertEqual([path.read_bytes() for path in files], before)
            self.assertNotIn(SENTINEL, (root / DATA.OUTPUT).read_text())
        for status in (b"0\n", b"0 0 0\n", b"71\n"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                write(root, "normal-ui/build.status", status)
                write(root, "normal-ui/build.failure-diagnostics.json", build_diagnostic(normal))
                self.assertEqual(project(root)["normalUiBuildDiagnostics"]["build"], {"receiptState": "refused"})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(root, "normal-ui/build.status", b"70\n")
            write(root, "normal-ui/build.failure-diagnostics.json", b" " * 4097)
            self.assertEqual(project(root)["normalUiBuildDiagnostics"]["build"], {"receiptState": "refused"})

    def test_correlated_finality_hashes_and_unknown_fields_are_not_raw_exports(self):
        value = receipt()
        value.update(private=SENTINEL, tools={"output": SENTINEL}, argv=[SENTINEL], environment={SENTINEL: SENTINEL})
        value["originalCalls"][0].update(stdout=SENTINEL, stderr=SENTINEL, path=SENTINEL)
        value["finalImage"].update(issues=[{"message": SENTINEL}], tickets=[{"path": SENTINEL}])
        row = DATA.project_receipt(value, CONTEXT, "finalize-image")
        encoded = json.dumps(row)
        self.assertNotIn(SENTINEL, encoded)
        self.assertNotIn("tools", row)
        self.assertNotIn("stdout", row["originalCalls"]["calls"][0])
        self.assertEqual(row["originalCalls"]["calls"][0]["stdoutSha256"], "a" * 64)
        self.assertIs(row["notaryAuthentication"]["retired"], True)
        self.assertIs(row["finalImage"]["actualStaplerValidation"], True)
        self.assertIs(row["finalImage"]["sha256Compared"], False)
        self.assertIsNone(row["finalImage"].get("strictSignatureBeforeAndAfter"))
        self.assertEqual(row["finalImage"]["warningCount"], 2)
        self.assertIsNone(row["originalCalls"]["calls"][0].get("dispatched"))
        policy_fields = ("assessmentSubsystemEnabledBefore", "actualDiskImagePolicyAssessment")
        self.assertTrue(all(name not in row["finalImage"] for name in policy_fields))
        for enabled in (False, True):
            value["finalImage"].update({name: enabled for name in policy_fields})
            current = DATA.project_receipt(value, CONTEXT, "finalize-image")
            self.assertTrue(all(current["finalImage"][name] is enabled for name in policy_fields))
        value["finalImage"][policy_fields[0]] = None
        self.assertIsNone(DATA.project_receipt(value, CONTEXT, "finalize-image")["finalImage"][policy_fields[0]])
        for invalid in (1, "true", [True]):
            value["finalImage"][policy_fields[0]] = invalid
            with self.assertRaises(DATA.Refused): DATA.project_receipt(value, CONTEXT, "finalize-image")

        # The new optional field is closed and diagnostic only. A recorded
        # branch without completed checks never becomes native validation.
        package = receipt("finalize-package"); del package["finalImage"]
        self.assertIsNone(DATA.project_receipt(package, CONTEXT, "finalize-package")["packageStapleObservation"])
        observation = {name: None for name in ("heldPreIdentityMatched", "namedPreIdentityMatched",
            "fdNameIdentityMatched", "fdNameMetadataMatched", "namedShapeExpected")}
        observation.update(heldLinkState="unavailable", selectedBranch="unavailable", transitionComplete=False)
        package["packageStapleObservation"] = observation
        self.assertEqual(DATA.project_receipt(package, CONTEXT, "finalize-package")["packageStapleObservation"], observation)
        for branch in ("same-original", "returned-output"):
            same = branch == "same-original"
            observation.update(heldPreIdentityMatched=True, namedPreIdentityMatched=same, fdNameIdentityMatched=same,
                fdNameMetadataMatched=same, namedShapeExpected=True, heldLinkState="single" if same else "unlinked",
                selectedBranch=branch, transitionComplete=True)
            result = DATA.project_receipt(package, CONTEXT, "finalize-package")
            self.assertEqual(result["packageStapleObservation"], observation)
            self.assertIsNone(result["finalPackage"])
            self.assertIsNone(result["finalImage"])
        package["passed"] = False
        observation["transitionComplete"] = False
        observation["heldPreIdentityMatched"] = False
        result = DATA.project_receipt(package, CONTEXT, "finalize-package")
        self.assertFalse(result["recordedPassed"] or result["packageStapleObservation"]["transitionComplete"])
        for key in observation:
            for bad in (SENTINEL, [], 1):
                changed = copy.deepcopy(package); changed["packageStapleObservation"][key] = bad
                with self.assertRaises(DATA.Refused): DATA.project_receipt(changed, CONTEXT, "finalize-package")
            changed = copy.deepcopy(package); del changed["packageStapleObservation"][key]
            with self.assertRaises(DATA.Refused): DATA.project_receipt(changed, CONTEXT, "finalize-package")
        for bad in (None, {}, dict(observation, extra=SENTINEL), dict(observation, transitionComplete=True)):
            changed = copy.deepcopy(package); changed["packageStapleObservation"] = bad
            with self.assertRaises(DATA.Refused): DATA.project_receipt(changed, CONTEXT, "finalize-package")
        changed = copy.deepcopy(package); changed["phase"] = "finalize-image"
        with self.assertRaises(DATA.Refused): DATA.project_receipt(changed, CONTEXT, "finalize-image")

    def test_entire_exact_correlation_tuple_is_required(self):
        for field in ("source", "workflowSource", "runId", "runAttempt", "target", "phase"):
            for change in ("wrong", 1, True, None, ["wrong"]):
                with self.subTest(field=field, change=change):
                    value = receipt(); value[field] = change
                    with self.assertRaises(DATA.Refused):
                        DATA.project_receipt(value, CONTEXT, "finalize-image")
            value = receipt(); del value[field]
            with self.assertRaises(DATA.Refused):
                DATA.project_receipt(value, CONTEXT, "finalize-image")
        for field, changed in (("submissionId", "23456789-1234-1234-1234-123456789abc"),
                               ("status", "Invalid"), ("kind", "mrk-final-removal-image"),
                               ("target", "x86_64-apple-darwin")):
            value = receipt(); value["finalImage"][field] = changed
            with self.subTest(conflict=field), self.assertRaises(DATA.Refused):
                DATA.project_receipt(value, CONTEXT, "finalize-image")
        failed_observer = {"schemaVersion": 1, "phase": "prepare-removal-observers", "source": CONTEXT["source"],
                           "target": CONTEXT["target"], "passed": False}
        with self.assertRaises(DATA.Refused):
            DATA.project_receipt(failed_observer, CONTEXT, "prepare-removal-observers")

    def test_typed_facts_do_not_promote_malformed_values_or_missing_facts(self):
        mutations = (("passed", 1), ("targetRetired", "true"), ("originalCalls", [{}] * 129),
                     ("credentialContexts", [{}] * 17), ("nativeCalls", 1000001))
        for name, value in mutations:
            broken = receipt(); broken[name] = value
            with self.subTest(name=name), self.assertRaises(DATA.Refused):
                DATA.project_receipt(broken, CONTEXT, "finalize-image")
        for name, bad in (("imageBytes", True), ("imageBytes", 2**40 + 1), ("warningCount", 2049),
                          ("actualStaplerValidation", 1), ("logSha256", SENTINEL), ("status", SENTINEL)):
            broken = receipt(); broken["finalImage"][name] = bad
            with self.subTest(name=name), self.assertRaises(DATA.Refused):
                DATA.project_receipt(broken, CONTEXT, "finalize-image")

    def test_json_duplicate_numbers_depth_and_total_nodes_are_bounded(self):
        for raw in (b'{"source":1,"source":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}',
                    b'{"x":1e999}', b'{"x":1.0}', b'{"x":' + b'[' * 18 + b'0' + b']' * 18 + b'}',
                    b'{"x":123456789012345678901}'):
            with self.subTest(raw=raw), self.assertRaises(DATA.Refused):
                DATA.decode(raw, budget())
        exhausted = budget(); exhausted["nodes"] = DATA.JSON_NODE_LIMIT
        with self.assertRaises(DATA.Refused):
            DATA.decode(b'{"ok":true}', exhausted)
        expired = budget(); expired["deadline"] = 0
        with self.assertRaises(DATA.Refused):
            DATA.decode(b'{}', expired)

    def test_real_source_inventory_row_ceiling_has_sufficient_graph_budget(self):
        rows = [{"path": "public/source-%d.py" % index, "gitMode": "100644", "blob": "2" * 40,
                 "size": 1, "sha256": "3" * 64} for index in range(4095)]
        value = {"source": CONTEXT["source"], "tree": "4" * 40, "files": rows}
        body = json.dumps(value).encode()
        observed = DATA.project_inventory(DATA.decode(body, budget(), inventory=True), body, CONTEXT)
        self.assertEqual(observed["fileCount"], 4095)
        self.assertNotIn("files", observed)
        value["files"].append(dict(rows[0]))
        with self.assertRaises(DATA.Refused):
            DATA.decode(json.dumps(value).encode(), budget(), inventory=True)

    def test_finite_failure_roles_keep_original_classification_not_messages(self):
        # Genuine producer -> public consumer; no raw logs or positive facts salvage.
        normal = normal_diagnostic_data()
        marker = b"MRK_MACOS_PACKAGED_REQUIRE_FAILURE=v1;line=3942;check=singleton\n"
        for role, selection, method, sidecar, status_file, positive_name, facts_key in (
            ("ios-unsigned-test", DATA.IOS_UNSIGNED_SELECTION, DATA.IOS_UNSIGNED_METHOD, DATA.IOS_UNSIGNED_DIAGNOSTIC,
                "normal-ui/ios-unsigned-archive-test.status", "iosUnsignedArchive", "iosFacts"),
            ("ios-pending-test", DATA.IOS_PENDING_SELECTION, DATA.IOS_PENDING_METHOD, DATA.IOS_PENDING_DIAGNOSTIC,
                "normal-ui/ios-pending-recovery-test.status", "iosPendingRecovery", "iosRecoveryFacts"),
        ):
            original = CompletedProcess([], 65, marker + SENTINEL.encode() + b"\n", b"")
            value = normal["normal_failure_diagnostics"]("test", selection, original)
            row = DATA.project_ui_diagnostic(value, role, {"receiptState": "observed", "returncode": 65})
            self.assertEqual(row["requireObservations"], [{"source": "NormalAppUITests.swift", "line": 3942, "check": "singleton"}])
            self.assertIs(row["nativeSuccessInferred"], False)
            self.assertIsNone(row["dashboardReadiness"])
            self.assertNotIn(SENTINEL, json.dumps(row))
            wrong_role = "ios-pending-test" if role == "ios-unsigned-test" else "ios-unsigned-test"
            with self.assertRaises(DATA.Refused): DATA.project_ui_diagnostic(value, wrong_role, {"receiptState": "observed", "returncode": 65})
            for key, replacement in (("line", True), ("line", 0), ("line", 65536), ("line", "3942"),
                    ("source", SENTINEL), ("check", SENTINEL)):
                bad = copy.deepcopy(value); bad["requireObservations"][0][key] = replacement
                with self.assertRaises(DATA.Refused): DATA.project_ui_diagnostic(bad, role, {"receiptState": "observed", "returncode": 65})
            bad = copy.deepcopy(value); bad["requireObservations"] *= 2
            with self.assertRaises(DATA.Refused): DATA.project_ui_diagnostic(bad, role, {"receiptState": "observed", "returncode": 65})
            for code in (0, True, -1, 256, 64):
                with self.assertRaises(DATA.Refused): DATA.project_ui_diagnostic(value, role, {"receiptState": "observed", "returncode": code})
            if role == "ios-pending-test":
                bad = copy.deepcopy(value); bad["iosUnsignedStages"] = {"state": "absent", "events": []}
                with self.assertRaises(DATA.Refused): DATA.project_ui_diagnostic(bad, role, {"receiptState": "observed", "returncode": 65})
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                write(root, status_file, b"65\n")
                output = write(root, sidecar, value)
                facts_path = next(path for key, path, _, _ in DATA.POSITIVE_UI_INPUTS if key == facts_key)
                facts = write(root, facts_path, {"private": SENTINEL})
                before = output.read_bytes(), facts.read_bytes()
                result = project(root)["positiveUiObservations"][positive_name]
                self.assertEqual(result["receiptState"], "refused")
                self.assertEqual(result["failureDiagnostic"]["requireObservations"], row["requireObservations"])
                self.assertEqual((output.read_bytes(), facts.read_bytes()), before)
                self.assertNotIn(SENTINEL, (root / DATA.OUTPUT).read_text())
        from unittest import mock
        # One fixed failed unsigned test: original65 is attribution, not positive or native authority.
        _ios_normal = normal_diagnostic_data()
        self.assertEqual(DATA.IOS_UNSIGNED_STAGES, _ios_normal["IOS_UNSIGNED_STAGES"])
        _ios_method = _ios_normal["IOS_UNSIGNED_METHOD"]
        _ios_selection = _ios_normal["IOS_UNSIGNED_RESULT"]
        _ios_stages = DATA.IOS_UNSIGNED_STAGES
        _ios_raw = ("Test Case '-[MRKNormalAppUITests.NormalAppUITests " + _ios_method + "]' started.\n").encode()
        for _ios_name in _ios_stages[:2]:
            _ios_raw += ("MRK_NORMAL_PROJECT_STAGE=" + _ios_name + ";result=started\nMRK_NORMAL_PROJECT_STAGE="
                + _ios_name + ";result=passed\n").encode()
        _ios_raw += ("MRK_NORMAL_PROJECT_STAGE=" + _ios_stages[2] + ";result=started\nMRK_NORMAL_PROJECT_STAGE="
            + _ios_stages[2] + ";result=failed;laterStages=not-run\nNormalAppUITests.swift:5751: error: "
            + "-[MRKNormalAppUITests.NormalAppUITests " + _ios_method + "] : " + SENTINEL + "\n").encode()
        _ios_value = _ios_normal["normal_failure_diagnostics"]("test", _ios_selection, CompletedProcess([], 65, _ios_raw, b""))
        self.assertEqual(_ios_value["sourceFailures"], [{"stream": "stdout", "source": "NormalAppUITests.swift",
            "method": _ios_method, "line": 5751, "column": None}])
        self.assertEqual(len(_ios_value["iosUnsignedStages"]["events"]), 6)
        self.assertEqual(_ios_value["iosUnsignedStages"]["state"], "observed")
        self.assertNotIn(SENTINEL, json.dumps(_ios_value))
        for _ios_code in (1, 65, 255):
            _ios_case = _ios_normal["normal_failure_diagnostics"]("test", _ios_selection, CompletedProcess([], _ios_code, _ios_raw, b""))
            _ios_row = DATA.project_ui_diagnostic(_ios_case, "ios-unsigned-test", {"receiptState": "observed", "returncode": _ios_code})
            self.assertEqual(_ios_row["originalReturncode"], _ios_code)
            self.assertIs(_ios_row["nativeSuccessInferred"], False)
        for _ios_bad_status in (None, {}, {"receiptState": "absent"}, *({"receiptState": "observed", "returncode": x}
                for x in (0, True, -1, 256, "65", 1))):
            with self.assertRaises(DATA.Refused): DATA.project_ui_diagnostic(_ios_value, "ios-unsigned-test", _ios_bad_status)
        for _ios_key, _ios_bad in (("selection", "sibling.xcresult"), ("phase", "summary"), ("sourceFailures", [SENTINEL]),
                ("iosUnsignedStages", {"state": "observed", "events": [{"stage": SENTINEL, "result": "failed"}]}), ("message", SENTINEL)):
            _ios_broken = copy.deepcopy(_ios_value); _ios_broken[_ios_key] = _ios_bad
            with self.assertRaises(DATA.Refused): DATA.project_ui_diagnostic(_ios_broken, "ios-unsigned-test", {"receiptState": "observed", "returncode": 65})
        for _ios_key, _ios_bad in (("method", "sibling"), ("source", SENTINEL), ("line", True), ("column", 4097)):
            _ios_broken = copy.deepcopy(_ios_value); _ios_broken["sourceFailures"][0][_ios_key] = _ios_bad
            with self.assertRaises(DATA.Refused): DATA.project_ui_diagnostic(_ios_broken, "ios-unsigned-test", {"receiptState": "observed", "returncode": 65})
        for _ios_events in (_ios_value["iosUnsignedStages"]["events"] + [_ios_value["iosUnsignedStages"]["events"][0]],
                list(reversed(_ios_value["iosUnsignedStages"]["events"])),
                [{"stage": _ios_stages[0], "result": "passed"}]):
            _ios_broken = copy.deepcopy(_ios_value)
            _ios_broken["iosUnsignedStages"] = {"state": "observed", "events": _ios_events}
            with self.assertRaises(DATA.Refused): DATA.project_ui_diagnostic(_ios_broken, "ios-unsigned-test", {"receiptState": "observed", "returncode": 65})
        _ios_first = b"MRK_NORMAL_PROJECT_STAGE=ios-unsigned-fixture;result=started\n"
        for _ios_bad in (_ios_first * 2, _ios_first.rstrip(b"\n"), _ios_first.replace(b"started", b"started;private=" + SENTINEL.encode()),
                _ios_first.replace(b"fixture", b"close"), _ios_first.replace(b"fixture", b"other"),
                _ios_first.replace(b"started", b"started\t"), _ios_first.replace(b"started", b"started\xff")):
            _ios_invalid = _ios_normal["normal_failure_diagnostics"]("test", _ios_selection, CompletedProcess([], 65, _ios_bad, b""))
            self.assertEqual(_ios_invalid["iosUnsignedStages"], {"state": "refused", "events": []})
            self.assertNotIn(SENTINEL, json.dumps(_ios_invalid))
        _ios_invalid = _ios_normal["normal_failure_diagnostics"]("test", _ios_selection, CompletedProcess([], 65, b"", _ios_first))
        self.assertEqual(_ios_invalid["iosUnsignedStages"], {"state": "refused", "events": []})
        _ios_raw_admission = _ios_normal["normal_admission_failure"]("execute", _ios_normal["Refused"](SENTINEL), None, [])
        with self.assertRaises(DATA.Refused): DATA.project_ui_diagnostic(_ios_raw_admission, "ios-unsigned-test", {"receiptState": "observed", "returncode": 65})
        _ios_admission = _ios_normal["classify_normal_admission_failure"](_ios_normal["encoded"](_ios_raw_admission))
        _ios_admitted = DATA.project_ui_diagnostic(_ios_admission, "ios-unsigned-test", {"receiptState": "observed", "returncode": 65})
        self.assertEqual(_ios_admitted["originalCallerReturncode"], 65)
        self.assertIs(_ios_admitted["unknownStateRetained"], True)
        for _ios_document in (_ios_value, _ios_admission):
            with tempfile.TemporaryDirectory() as _ios_directory:
                _ios_root = Path(_ios_directory)
                _ios_status_path = write(_ios_root, "normal-ui/ios-unsigned-archive-test.status", b"65\n")
                _ios_sidecar = write(_ios_root, DATA.IOS_UNSIGNED_DIAGNOSTIC, _ios_document)
                _ios_private = write(_ios_root, "normal-ui/ios-unsigned-archive.facts.json", SENTINEL.encode())
                _ios_log = write(_ios_root, "normal-ui/ios-unsigned-archive-test.log", SENTINEL.encode())
                _ios_before = {p: p.read_bytes() for p in (_ios_status_path, _ios_sidecar, _ios_private, _ios_log)}
                with mock.patch.object(DATA, "read_input", wraps=DATA.read_input) as _ios_read:
                    _ios_public = project(_ios_root)
                _ios_names = [call.args[1] for call in _ios_read.call_args_list]
                self.assertEqual(_ios_names.count(DATA.IOS_UNSIGNED_DIAGNOSTIC), 1)
                _ios_expected_attempts = (len(DATA.STATUS_FILES) + len(DATA.PHASES) + 4
                    + len(DATA.PACKAGE_SIGNATURE_CAPTURES) + len(DATA.INSTALLER_DIAGNOSTIC_INPUTS)
                    + len(DATA.UI_DIAGNOSTICS) + 6 + len(DATA.POSITIVE_UI_INPUTS) + len(DATA.ORDINARY_UI_INPUTS))
                self.assertEqual(len(_ios_names), _ios_expected_attempts)
                self.assertLessEqual(_ios_expected_attempts, 128)
                self.assertNotIn("normal-ui/ios-unsigned-archive.facts.json", _ios_names)
                _ios_failure = _ios_public["positiveUiObservations"]["iosUnsignedArchive"]
                self.assertEqual(_ios_failure["receiptState"], "refused")
                self.assertEqual(_ios_failure["failureDiagnostic"]["receiptState"], "observed")
                self.assertIs(_ios_failure["failureDiagnostic"]["nativeSuccessInferred"], False)
                self.assertIs(_ios_public["productReady"], False)
                self.assertEqual({p: p.read_bytes() for p in _ios_before}, _ios_before)
                self.assertNotIn(SENTINEL, (_ios_root / DATA.OUTPUT).read_text())
        with tempfile.TemporaryDirectory() as _ios_directory:
            _ios_root = Path(_ios_directory)
            write(_ios_root, "normal-ui/ios-unsigned-archive-test.status", b"0\n")
            write(_ios_root, DATA.IOS_UNSIGNED_DIAGNOSTIC, SENTINEL.encode())
            with mock.patch.object(DATA, "read_input", wraps=DATA.read_input) as _ios_read: project(_ios_root)
            _ios_names = [call.args[1] for call in _ios_read.call_args_list]
            self.assertNotIn(DATA.IOS_UNSIGNED_DIAGNOSTIC, _ios_names)
            self.assertEqual(_ios_names.count("normal-ui/ios-unsigned-archive.facts.json"), 1)
        for _ios_bad_body in (b'{"scope":1,"scope":2}', b'{"bad":NaN}', b" " * 4097):
            with tempfile.TemporaryDirectory() as _ios_directory:
                _ios_root = Path(_ios_directory)
                write(_ios_root, "normal-ui/ios-unsigned-archive-test.status", b"65\n")
                write(_ios_root, DATA.IOS_UNSIGNED_DIAGNOSTIC, _ios_bad_body)
                self.assertEqual(project(_ios_root)["positiveUiObservations"]["iosUnsignedArchive"]["failureDiagnostic"], {"receiptState": "refused"})
        with tempfile.TemporaryDirectory() as _ios_directory:
            _ios_root = Path(_ios_directory)
            write(_ios_root, DATA.IOS_UNSIGNED_DIAGNOSTIC, _ios_value)
            _ios_fd = DATA.open_root(str(_ios_root))
            try:
                _ios_budget = {"deadline": time.monotonic_ns() + 45_000_000_000, "files": 0, "bytes": 0,
                    "nodes": 0, "outputBytes": 0}
                DATA.reserve_ordinary_ui_reads(_ios_budget)
                _ios_budget["outputBytes"] = DATA.OUTPUT_LIMIT + DATA.ORDINARY_UI_OUTPUT_LIMIT
                with self.assertRaises(DATA.Refused):
                    DATA.positive_ui_observations(_ios_fd, CONTEXT,
                        {"normal-ui/ios-unsigned-archive-test.status": {"receiptState": "observed", "returncode": 65}},
                        {}, {}, _ios_budget)
                self.assertIs(_ios_budget["ordinaryUiOutputReserved"], False)
            finally: os.close(_ios_fd)
        # The original fixed roster and combined/global output ceilings do not grow.
        self.assertEqual((DATA.INPUT_LIMIT, DATA.OUTPUT_LIMIT), (3 << 20, 128 << 10))
        self.assertEqual(len(DATA.UI_DIAGNOSTICS), 3)
        value = receipt(); value["passed"] = False
        value["failure"] = {"stage": "final-image-log", "type": "Refused", "reason": "notary-log-" + SENTINEL}
        call = value["originalCalls"][0]
        call.update(returned=False, capturesSettled=False, returncode=None, dispatched=True, contained=False,
                    cleanup_complete=False, originalFailure={"available": True, "ownerErrorType": "ProcessOutcomeUnknown",
                    "classification": "deadline", "timeoutSeconds": 30, "outputLimitBytes": 1048576,
                    "frames": [{"path": SENTINEL}], "message": SENTINEL})
        value["originalCalls"].append({"role": SENTINEL, "message": SENTINEL})
        result = DATA.project_receipt(value, CONTEXT, "finalize-image")
        self.assertEqual(result["failure"]["reason"], "notary-log")
        self.assertEqual(result["originalCalls"]["unclassifiedCount"], 1)
        self.assertEqual(result["originalCalls"]["calls"][0]["originalFailure"]["classification"], "deadline")
        self.assertIsNone(result["originalCalls"]["calls"][0]["returncode"])
        self.assertNotIn(SENTINEL, json.dumps(result))
        self.assertEqual(DATA.project_failure({"stage": SENTINEL, "type": SENTINEL, "reason": SENTINEL}),
                         {"stage": "unclassified", "type": "unclassified", "reason": "unclassified", "errno": None})
        for role, status in (("final-image-policy-status", 1), ("final-image-policy-assess", 3)):
            policy = receipt(); policy["passed"] = False
            policy["originalCalls"][0].update(role=role, returncode=status, stdout=SENTINEL, stderr=SENTINEL)
            policy["failure"] = {"stage": role, "type": "Refused", "reason": "original-nonzero-" + role}
            projected = DATA.project_receipt(policy, CONTEXT, "finalize-image")
            self.assertEqual(projected["originalCalls"]["unclassifiedCount"], 0)
            self.assertEqual(projected["originalCalls"]["calls"][0]["role"], role)
            self.assertEqual(projected["originalCalls"]["calls"][0]["returncode"], status)
            self.assertEqual(projected["failure"]["stage"], role)
            self.assertIs(projected["recordedPassed"], False)
            self.assertNotIn(SENTINEL, json.dumps(projected))

        # Exact original stager failures remain distinct from helper refusals.
        # Execute only the real finite classifier and real receipt projection
        # SOURCE fragment; no Operation admission, process, signing or mount.
        helper_path = ROOT / "desktop/tools/macos_android_helper_package.py"
        helper_tree = ast.parse(helper_path.read_bytes())
        names = {"Refused", "DISTRIBUTION_STAGER_REASONS", "_FAILURE_REASONS", "failure_exception"}
        nodes = [node for node in helper_tree.body if
                 isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names or
                 isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                 and node.targets[0].id in names]
        self.assertEqual(len(nodes), len(names))
        namespace = {"sys": __import__("sys"), "json": json}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(helper_path), "exec"), namespace)
        stager_path = ROOT / "desktop/tools/stage_macos_installed.py"
        refused_node = [node for node in ast.parse(stager_path.read_bytes()).body
                        if isinstance(node, ast.ClassDef) and node.name == "Refused"]
        self.assertEqual(len(refused_node), 1)
        stager = type(__import__("sys"))("original_stager_refusal_DATA")
        exec(compile(ast.Module(body=refused_node, type_ignores=[]), str(stager_path), "exec"), vars(stager))
        operation = next(node for node in helper_tree.body if isinstance(node, ast.ClassDef) and node.name == "Operation")
        execute = next(node for node in operation.body if isinstance(node, ast.FunctionDef) and node.name == "execute")
        handler = next(node for node in ast.walk(execute) if isinstance(node, ast.ExceptHandler)
                       and node.name == "error" and any(isinstance(child, ast.Assign) and
                       isinstance(child.targets[0], ast.Subscript) and isinstance(child.targets[0].value, ast.Attribute)
                       and child.targets[0].value.attr == "receipt" for child in node.body))
        start = next(i for i, node in enumerate(handler.body) if isinstance(node, ast.Assign)
                     and isinstance(node.targets[0], ast.Subscript) and isinstance(node.targets[0].value, ast.Attribute)
                     and node.targets[0].value.attr == "receipt")
        fragment = handler.body[start:start+3]
        self.assertEqual([type(node) for node in fragment], [ast.Assign, ast.Assign, ast.If])
        function = ast.FunctionDef(name="project_original", args=ast.arguments(posonlyargs=[],
            args=[ast.arg(arg="self"), ast.arg(arg="error")], kwonlyargs=[], kw_defaults=[], defaults=[]),
            body=copy.deepcopy(fragment), decorator_list=[])
        exec(compile(ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[])), str(helper_path), "exec"), namespace)
        labels = frozenset(("distribution-attach-original", "distribution-attach-plist", "distribution-attach-entity",
            "distribution-attach-mount", "distribution-attach-single-mount", "distribution-package-name",
            "distribution-three-file-roster", "distribution-original-byte-mode"))
        self.assertEqual(namespace["DISTRIBUTION_STAGER_REASONS"], labels)
        self.assertEqual(DATA.DISTRIBUTION_STAGER_REASONS, labels)
        for label in labels:
            error = stager.Refused(label); before = BaseException.args.__get__(error)
            captured = namespace["failure_exception"](error, stager)
            original = SimpleNamespace(stage="package-readonly-attach", stager=stager, diagnostic_failure=captured, receipt={})
            namespace["project_original"](original, error)
            self.assertEqual(original.receipt["failure"], {"stage": "package-readonly-attach", "type": "Refused", "reason": label})
            self.assertEqual(DATA.project_failure(original.receipt["failure"])["reason"], label)
            self.assertEqual(BaseException.args.__get__(error), before)
            self.assertIs(type(error), stager.Refused)
        class ForeignRefused(Exception):
            def __str__(self): raise AssertionError("private exception rendered")
        class StagerChild(stager.Refused):
            def __str__(self): raise AssertionError("private subclass rendered")
        class PrivateArgument:
            def __str__(self): raise AssertionError("private argument rendered")
        unknown = [stager.Refused(SENTINEL), stager.Refused(PrivateArgument()), stager.Refused(*sorted(labels)[:2]),
                   ForeignRefused(next(iter(labels))), StagerChild(next(iter(labels)))]
        for error in unknown:
            before = BaseException.args.__get__(error)
            captured = namespace["failure_exception"](error, stager)
            original = SimpleNamespace(stage="package-readonly-attach", stager=stager, diagnostic_failure=captured, receipt={})
            namespace["project_original"](original, error)
            self.assertEqual(original.receipt["failure"]["reason"], "original-operation-refused")
            self.assertEqual(BaseException.args.__get__(error), before)
            self.assertNotIn(SENTINEL, json.dumps(original.receipt))
        for captured in (None, SimpleNamespace(type="stager-refused"), {},
                         {"type": "other", "reason": next(iter(labels)), "errno": None},
                         {"type": "stager-refused", "reason": SENTINEL, "errno": None},
                         {"type": "stager-refused", "reason": next(iter(labels)), "errno": 1},
                         {"type": "stager-refused", "reason": next(iter(labels)), "errno": None, "extra": SENTINEL}):
            error = stager.Refused(next(iter(labels)))
            original = SimpleNamespace(stage="package-readonly-attach", stager=stager, diagnostic_failure=captured, receipt={})
            namespace["project_original"](original, error)
            self.assertEqual(original.receipt["failure"]["reason"], "original-operation-refused")
            self.assertNotIn(SENTINEL, json.dumps(original.receipt))

        # The real helper receipt retains fixed transport guards even though
        # its separate captured diagnostic classifier intentionally omits them.
        transport = ('package-mount-host-admission', 'package-mount-host-source', 'package-mount-host-source-post', 'package-transport-automounted', 'package-transport-context', 'package-transport-detach-original', 'package-transport-host-original', 'package-transport-host-unavailable', 'package-transport-mounted-namespace', 'package-transport-one-admission', 'package-transport-original-device', 'package-transport-original-mount', 'removal-bounded-roster', 'removal-directory-facts-changed', 'removal-directory-flags', 'removal-directory-named-held', 'removal-directory-original', 'removal-directory-post', 'removal-fixed-name-collision', 'removal-local-filesystem', 'removal-original-control-pool', 'removal-original-empty-acl', 'removal-original-headroom', 'removal-protected-apfs', 'removal-protected-owner', 'removal-readonly-filesystem', 'removal-roster-original', 'removal-roster-post', 'removal-roster-previous-unknown')
        direct = ("normal_mount_host", "transport_source_post", "transport_mount_admit",
                  "transport_mount_facts", "transport_mount_detached")
        protected = ("removal_reserve", "removal_acl", "removal_directory_facts",
                     "removal_directory_post", "removal_absent", "removal_names", "removal_roster")
        path_guard = next(node for node in helper_tree.body if isinstance(node, ast.FunctionDef)
                          and node.name == "transport_mount_path_data")
        selected_guards = [path_guard] + [node for node in operation.body
            if isinstance(node, ast.FunctionDef) and node.name in direct + protected]
        self.assertEqual(len(selected_guards), 1 + len(direct) + len(protected))
        source_guards = set()
        for selected in selected_guards:
            for node in ast.walk(selected):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                        and node.func.id == "need" and len(node.args) > 1
                        and isinstance(node.args[-1], ast.Constant) and type(node.args[-1].value) is str):
                    source_guards.add(node.args[-1].value)
                if (isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call)
                        and isinstance(node.exc.func, ast.Name) and node.exc.func.id == "Refused"
                        and node.exc.args and isinstance(node.exc.args[0], ast.Constant)
                        and type(node.exc.args[0].value) is str):
                    source_guards.add(node.exc.args[0].value)
        self.assertEqual(set(transport), source_guards - {"removal-channel-directory", "removal-input-flags"})
        self.assertTrue(set(transport) <= DATA.REASONS)
        self.assertTrue(set(transport).isdisjoint(namespace["_FAILURE_REASONS"]))
        for label in transport:
            error = namespace["Refused"](label); before = BaseException.args.__get__(error)
            captured = namespace["failure_exception"](error, stager)
            self.assertEqual(captured, {"type": "helper-refused", "reason": "unclassified", "errno": None})
            original = SimpleNamespace(stage="package-readonly-attach", stager=stager,
                diagnostic_failure=captured, receipt={})
            namespace["project_original"](original, error)
            expected = {"stage": "package-readonly-attach", "type": "Refused", "reason": label}
            self.assertEqual(original.receipt["failure"], expected)
            self.assertEqual(DATA.project_failure(expected), dict(expected, errno=None))
            self.assertIs(type(error), namespace["Refused"])
            self.assertEqual(BaseException.args.__get__(error), before)
            private = namespace["Refused"](label + "-" + SENTINEL)
            current = SimpleNamespace(stage="package-readonly-attach", stager=stager,
                diagnostic_failure=namespace["failure_exception"](private, stager), receipt={})
            namespace["project_original"](current, private)
            projected = DATA.project_failure(current.receipt["failure"])
            self.assertEqual(projected["reason"], "unclassified")
            self.assertNotIn(SENTINEL, json.dumps(projected))
        class HelperChild(namespace["Refused"]):
            def __str__(self): raise AssertionError("private helper subclass rendered")
        class TokenChild(str): pass
        # Exact classifier/public DATA boundaries remain unchanged. Do not run
        # the existing helper str(error) receipt path on an opaque argument.
        for error in (namespace["Refused"](PrivateArgument()), namespace["Refused"](*transport[:2]),
                      ForeignRefused(transport[0]), HelperChild(transport[0])):
            before = BaseException.args.__get__(error)
            classified = namespace["failure_exception"](error, stager)
            self.assertEqual(classified["reason"], "unclassified")
            self.assertEqual(BaseException.args.__get__(error), before)
            if type(error) is not namespace["Refused"]:
                current = SimpleNamespace(stage="package-readonly-attach", stager=stager,
                    diagnostic_failure=classified, receipt={})
                namespace["project_original"](current, error)
                projected = DATA.project_failure(current.receipt["failure"])
                self.assertEqual(projected["reason"], "original-operation-refused")
                self.assertNotIn(projected["reason"], transport)
                self.assertNotIn(SENTINEL, json.dumps(projected))
        for invalid in (None, transport[0].encode(), list(transport[:2]), TokenChild(transport[0]),
                        "package-transport-" + SENTINEL, "removal-" + SENTINEL,
                        transport[0] + "\x00", SENTINEL):
            projected = DATA.project_failure({"reason": invalid})
            self.assertEqual(projected["reason"], "unclassified")
            self.assertNotIn(SENTINEL, json.dumps(projected))
        for label in ("package-transport-context", "removal-protected-owner"):
            with self.subTest(transport_original=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); failed = receipt("package-install")
                del failed["finalImage"], failed["notarySubmission"]
                failed.update(passed=False, targetRetired=False, originalClosesKnown=False,
                    originalCalls=[], productReady=False,
                    notaryAuthentication={"created": False, "closed": False, "retired": False},
                    failure={"stage": "package-readonly-attach", "type": "Refused", "reason": label})
                original = write(root, "android-helper-package-install.json", failed)
                write(root, "package-install.status", b"1\n")
                before = original.read_bytes(); output = project(root); phase = output["phases"]["package-install"]
                self.assertIs(output["diagnosticOnly"], True); self.assertIs(output["productReady"], False)
                self.assertIs(phase["recordedPassed"], False)
                self.assertIs(phase["targetRetired"], False); self.assertIs(phase["originalClosesKnown"], False)
                self.assertEqual(phase["failure"]["reason"], label)
                self.assertEqual(phase["callerStatus"], {"receiptState": "observed", "returncode": 1})
                self.assertEqual(phase["originalCalls"], {"recordedCount": 0, "unclassifiedCount": 0, "calls": []})
                self.assertEqual(original.read_bytes(), before)
                encoded = json.dumps(output, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
                self.assertLessEqual(len(encoded), DATA.OUTPUT_LIMIT)
                self.assertNotIn(SENTINEL.encode(), encoded); self.assertNotIn(str(root).encode(), encoded)

        # Genuine fixed-token projector and reader, no native/credential work.
        source = (ROOT / "desktop/src-tauri/examples/macos_package_producer.rs").read_text()
        mapping = dict(re.findall(r'"([a-z-]+)"=>"(package-producer-refused:[a-z-]+)"', source))
        self.assertEqual({(token + "\n").encode(): reason for reason, token in mapping.items()},
                         DATA.PRODUCER_REFUSAL_TOKENS)
        self.assertIn('_=>"package-producer-refused"', source)
        self.assertIn('eprintln!("{}",failure_token(reason));std::process::ExitCode::from(78)', source)
        token = b"package-producer-refused:private-acl\n"
        value = receipt("package-install"); value["passed"] = False
        del value["finalImage"], value["notarySubmission"]
        value["failure"] = {"stage": "package-producer-emission", "type": "Refused",
                            "reason": "original-nonzero-producer-emitter"}
        call = value["originalCalls"][0]
        call.update(role="producer-emitter", returncode=78, stdoutSha256=hashlib.sha256(b"").hexdigest(),
                    stderrSha256=hashlib.sha256(token).hexdigest())
        phase = DATA.project_receipt(value, CONTEXT, "package-install")
        phase["callerStatus"] = {"receiptState": "observed", "returncode": 1}
        for body, reason in DATA.PRODUCER_REFUSAL_TOKENS.items():
            fresh = copy.deepcopy(phase)
            fresh["originalCalls"]["calls"][0]["stderrSha256"] = hashlib.sha256(body).hexdigest()
            result = DATA.project_producer_refusal(body, fresh)
            self.assertEqual(result["reason"], reason)
            self.assertIs(result["nativeSuccessInferred"], False)
        bad = []
        for name, replacement in (("entered", False), ("returned", False), ("capturesSettled", False),
                                  ("returncode", 0), ("returncode", True), ("stdoutSha256", "1" * 64),
                                  ("stderrSha256", "2" * 64), ("role", "installer")):
            fresh = copy.deepcopy(phase); fresh["originalCalls"]["calls"][0][name] = replacement; bad.append(fresh)
        for name, replacement in (("recordedPassed", True), ("correlationMatches", False),
                                  ("receiptState", "refused"), ("callerStatus", {"receiptState": "observed", "returncode": 0})):
            fresh = copy.deepcopy(phase); fresh[name] = replacement; bad.append(fresh)
        for appended in ({"role": "installer", "entered": True}, phase["originalCalls"]["calls"][0]):
            fresh = copy.deepcopy(phase); fresh["originalCalls"]["calls"].append(copy.deepcopy(appended))
            fresh["originalCalls"]["recordedCount"] += 1; bad.append(fresh)
        for fresh in bad:
            with self.assertRaises(DATA.Refused): DATA.project_producer_refusal(token, fresh)
        for body in (b"package-producer-refused\n", b"package-producer-refused:unknown\n",
                     token + b"extra\n", token.rstrip(), SENTINEL.encode(), b"x" * 129, b"\xff\n"):
            with self.assertRaises(DATA.Refused): DATA.project_producer_refusal(body, phase)
        for scenario in ("valid", "wrong-context", "hash", "private", "long", "linked", "symlink", "absent"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); fresh = copy.deepcopy(value)
                if scenario == "wrong-context": fresh["runAttempt"] = "99"
                if scenario == "hash": fresh["originalCalls"][0]["stderrSha256"] = "3" * 64
                original = write(root, "android-helper-package-install.json", fresh)
                write(root, "package-install.status", b"1\n")
                body = SENTINEL.encode() if scenario == "private" else b"x" * 129 if scenario == "long" else token
                path = root / "android-helper-producer-emitter.stderr"
                if scenario == "symlink":
                    private = write(root, "private-original", body); os.symlink(private.name, path)
                elif scenario != "absent":
                    write(root, path.name, body)
                    if scenario == "linked": os.link(path, root / "retained-original")
                before = original.read_bytes(); result = project(root)
                diagnostic = result["producerFailureDiagnostic"]
                self.assertEqual(diagnostic["receiptState"], "observed" if scenario == "valid" else "absent" if scenario == "absent" else "refused")
                self.assertIs(result["productReady"], False)
                self.assertNotIn(SENTINEL, json.dumps(result)); self.assertNotIn(str(root), json.dumps(result))
                self.assertEqual(original.read_bytes(), before)
                if scenario != "absent": self.assertEqual(path.read_bytes(), body)


        # Pkgutil already has original captured bytes; expose finite positions,
        # never raw dates/paths/certificates or weaker trust acceptance.
        before_body = (b'Package "/private/DO-NOT-EMIT.pkg":\n'
            b'Status: signed by a certificate trusted by macOS\n'
            b'Signed with a trusted timestamp on: PRIVATE-DATE\n'
            b'Certificate Chain:\n1. PRIVATE-CERTIFICATE\n')
        after_body = before_body.replace(b'Certificate Chain:\n', b'Notarization: trusted by macOS\nCertificate Chain:\n')
        facts = DATA.package_signature_preamble(after_body)
        self.assertEqual((facts['statusClass'], facts['statusIndex'], facts['trustedTimestampIndex'],
            facts['chainMarkerIndex'], facts['notarizationIndex']), ('macOS', 1, 2, 4, 3))
        self.assertTrue(facts['statusAtIndex1Accepted']); self.assertTrue(facts['trustedTimestampAtIndex2'])
        self.assertFalse(facts['chainMarkerAtIndex3']); self.assertEqual(facts['notarizationClass'], 'trustedByMacOS')
        for body, expected in ((before_body.replace(b'trusted by macOS', b'trusted by Mac OS X'), 'macOSX'),
            (before_body.replace(b'signed by a certificate trusted by macOS', b'signed by a developer certificate issued by Apple for distribution'), 'appleDistribution'),
            (before_body.replace(b'trusted by macOS', SENTINEL.encode()), 'other')):
            self.assertEqual(DATA.package_signature_preamble(body)['statusClass'], expected)
        duplicated = DATA.package_signature_preamble(after_body + b'Notarization: trusted by macOS\n')
        self.assertEqual(duplicated['notarizationCount'], 2); self.assertEqual(duplicated['notarizationClass'], 'other')
        duplicate_status = DATA.package_signature_preamble(before_body + b'Status: signed by a certificate trusted by macOS\n')
        self.assertEqual(duplicate_status['statusCount'], 2); self.assertEqual(duplicate_status['statusClass'], 'other')
        bounded = DATA.package_signature_preamble(b'x' * 1024 + b'\n')
        self.assertEqual(bounded['lineCount'], 1); self.assertEqual(bounded['statusClass'], 'absent')
        self.assertFalse(DATA.package_signature_preamble(before_body.replace(b'PRIVATE-DATE', b'x' * 129))['trustedTimestampSuffixBounded'])
        for invalid in (None, 'plain string', b'', before_body.rstrip(), b'\xff\n', b'bad\x00\n',
            b'x' * 1025 + b'\n', b'x\n' * 257, b'x' * 65537):
            with self.assertRaises(DATA.Refused): DATA.package_signature_preamble(invalid)
        # Actual unchanged parser still rejects the informational-line shape.
        parser_nodes = [node for node in helper_tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))
                        and node.name in ('need', 'Refused', 'package_signature_data')]
        self.assertEqual(len(parser_nodes), 3)
        parser_namespace = {'Path': Path, 're': re, 'hashlib': hashlib}
        exec(compile(ast.Module(body=parser_nodes, type_ignores=[]), str(helper_path), 'exec'), parser_namespace)
        with self.assertRaisesRegex(parser_namespace['Refused'], '^package-signature-trust-timestamp$'):
            parser_namespace['package_signature_data'](after_body.replace(b'Package "/private/DO-NOT-EMIT.pkg":', b'Package "MobileReleaseKit.pkg":'), {}, (b'a', b'b', b'c'), Path('MobileReleaseKit.pkg'))

        signature_value = receipt('finalize-package'); signature_value['passed'] = False
        del signature_value['finalImage'], signature_value['notarySubmission']
        signature_value['failure'] = {'stage': 'final-package-signature-after', 'type': 'Refused', 'reason': 'package-signature-trust-timestamp'}
        signature_value['originalCalls'] = [dict(role=role, entered=True, returned=True, capturesSettled=True,
            returncode=0, stdoutSha256=hashlib.sha256(body).hexdigest(), stderrSha256=hashlib.sha256(b'').hexdigest())
            for role, body in (('final-package-signature-before', before_body), ('final-package-signature-after', after_body))]
        signature_phase = DATA.project_receipt(signature_value, CONTEXT, 'finalize-package')
        signature_phase['callerStatus'] = {'receiptState': 'observed', 'returncode': 1}
        captures = {'before': before_body, 'after': after_body}
        diagnostic = DATA.project_package_signature_diagnostic(captures, signature_phase)
        self.assertTrue(diagnostic['policyUnchanged']); self.assertFalse(diagnostic['nativeSuccessInferred'])
        self.assertEqual(diagnostic['after']['chainMarkerIndex'], 4)
        wrong = []
        for key, changed in (('entered', False), ('returned', False), ('capturesSettled', False), ('returncode', True),
            ('returncode', 1), ('stdoutSha256', '1' * 64), ('stderrSha256', '1' * 64), ('role', 'installer')):
            altered = copy.deepcopy(signature_phase); altered['originalCalls']['calls'][1][key] = changed; wrong.append(altered)
        for key, changed in (('recordedPassed', True), ('correlationMatches', False), ('callerStatus', {'receiptState': 'observed', 'returncode': 0}),
            ('failure', {'type': 'Refused', 'stage': 'final-package-signature-before', 'reason': 'package-signature-trust-timestamp'})):
            altered = copy.deepcopy(signature_phase); altered[key] = changed; wrong.append(altered)
        altered = copy.deepcopy(signature_phase); altered['originalCalls']['unclassifiedCount'] = True; wrong.append(altered)
        altered = copy.deepcopy(signature_phase); altered['originalCalls']['calls'].append(dict(role='installer', entered=True)); altered['originalCalls']['recordedCount'] += 1; wrong.append(altered)
        altered = copy.deepcopy(signature_phase); altered['originalCalls']['calls'].append(copy.deepcopy(altered['originalCalls']['calls'][1])); altered['originalCalls']['recordedCount'] += 1; wrong.append(altered)
        for altered in wrong:
            with self.assertRaises(DATA.Refused): DATA.project_package_signature_diagnostic(captures, altered)
        self.assertNotIn('PRIVATE', json.dumps(diagnostic)); self.assertNotIn('DO-NOT-EMIT', json.dumps(diagnostic))

        # Both file attempts and complete raw bounds are admitted prospectively,
        # consumed once including absence, never refunded or charged twice.
        charge = 2 * (DATA.PACKAGE_SIGNATURE_CAPTURE_LIMIT + 1)
        fixed_budget = {'files': 126, 'bytes': DATA.INPUT_LIMIT - charge, 'deadline': time.monotonic_ns() + 45_000_000_000}
        DATA.reserve_package_signature_reads(fixed_budget)
        self.assertEqual((fixed_budget['files'], fixed_budget['bytes']), (128, DATA.INPUT_LIMIT))
        with self.assertRaises(DATA.Refused): DATA.reserve_package_signature_reads(fixed_budget)
        for key in ('files', 'bytes'):
            refused_budget = {'files': 126, 'bytes': DATA.INPUT_LIMIT - charge, 'deadline': time.monotonic_ns() + 45_000_000_000}
            refused_budget[key] += 1
            with self.assertRaises(DATA.Refused): DATA.reserve_package_signature_reads(refused_budget)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); name = DATA.PACKAGE_SIGNATURE_CAPTURES[0][1]
            write(root, name, before_body); fd = DATA.open_root(str(root))
            try:
                reserved = {'files': 0, 'bytes': 0, 'deadline': time.monotonic_ns() + 45_000_000_000}
                DATA.reserve_package_signature_reads(reserved)
                self.assertEqual(DATA.read_input(fd, name, 65536, reserved, package_signature_reserved=True), before_body)
                self.assertEqual((reserved['files'], reserved['bytes']), (2, charge))
                with self.assertRaises(DATA.Refused): DATA.read_input(fd, name, 65536, reserved, package_signature_reserved=True)
                missing = DATA.PACKAGE_SIGNATURE_CAPTURES[1][1]
                with self.assertRaises(FileNotFoundError): DATA.read_input(fd, missing, 65536, reserved, package_signature_reserved=True)
                with self.assertRaises(DATA.Refused): DATA.read_input(fd, missing, 65536, reserved, package_signature_reserved=True)
                self.assertEqual((reserved['files'], reserved['bytes']), (2, charge))
            finally: os.close(fd)

        for scenario in ('valid', 'wrong-context', 'hash', 'wrong-status', 'linked', 'symlink', 'absent', 'partial', 'oversize'):
            with self.subTest(signature=scenario), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); current = copy.deepcopy(signature_value)
                if scenario == 'wrong-context': current['runAttempt'] = '99'
                if scenario == 'hash': current['originalCalls'][1]['stdoutSha256'] = '1' * 64
                original = write(root, 'android-helper-finalize-package.json', current)
                write(root, 'package-finalization.status', b'0\n' if scenario == 'wrong-status' else b'1\n')
                body_map = dict(captures)
                if scenario == 'oversize': body_map['after'] = b'x' * 65537
                for key, name, _ in DATA.PACKAGE_SIGNATURE_CAPTURES:
                    if scenario == 'absent' or scenario == 'partial' and key == 'after': continue
                    if scenario == 'symlink' and key == 'after':
                        private = write(root, 'private-signature-original', body_map[key]); os.symlink(private.name, root / name)
                    else:
                        write(root, name, body_map[key])
                        if scenario == 'linked' and key == 'after': os.link(root / name, root / 'retained-signature-original')
                before = original.read_bytes(); output = project(root); item = output['packageSignatureDiagnostic']
                self.assertEqual(item['receiptState'], 'observed' if scenario == 'valid' else 'absent' if scenario == 'absent' else 'refused')
                self.assertFalse(output['productReady']); self.assertFalse(item['nativeSuccessInferred'])
                self.assertEqual(original.read_bytes(), before)
                for private in ('PRIVATE', 'DO-NOT-EMIT', str(root)):
                    self.assertNotIn(private, json.dumps(item))

        # Actual fixed Installer log originals: byte-preserving selector DATA,
        # failed original hash/status/context join, never arbitrary line text.
        stage_names = {'need', 'Refused', 'digest', 'select_installer_log', 'LOG_INTERVAL_BYTES', 'LOG_LINE_BYTES', 'LOG_SELECTED_BYTES',
                       'distribution_request_name', 'maintenance_hex', 'INSTALL_LOG'}
        stage_nodes = [node for node in ast.parse(stager_path.read_bytes()).body if
            isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in stage_names or
            isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id in stage_names]
        self.assertEqual(len(stage_nodes), len(stage_names))
        selector = {'re': re, 'hashlib': hashlib, 'Path': Path}
        exec(compile(ast.Module(body=stage_nodes, type_ignores=[]), str(stager_path), 'exec'), selector)
        binding = {'packageKind': 'ordinary', 'packageIdentifier': 'dev.mobile-release-kit.desktop.installed',
            'packagePath': '/private/' + SENTINEL + '/package-mount/' + selector['distribution_request_name']('7' * 32),
            'sourceCommit': CONTEXT['source'], 'inventorySha256': '8' * 64, 'runtimeManifestSha256': '9' * 64,
            'runId': CONTEXT['runId'], 'runAttempt': CONTEXT['runAttempt'], 'requestId': '7' * 32}
        self.assertEqual(selector['distribution_request_name']('7' * 32), 'MobileReleaseKit-Request-' + '7' * 32 + '.pkg')
        self.assertEqual(str(selector['INSTALL_LOG']), '/private/var/log/install.log')
        for invalid_request in ('0' * 32, '7' * 31, 'G' * 32, 7):
            with self.assertRaises(selector['Refused']): selector['distribution_request_name'](invalid_request)
        phase_line = (SENTINEL + ' MRK_MACOS_POSTINSTALL_PHASE=entry\n').encode()
        refusal_line = (SENTINEL + ' MRK_MACOS_POSTINSTALL_REFUSED=cwd\n').encode()
        acl_line = (SENTINEL + ' MRK_MACOS_INSTALL_ACL_DIAGNOSTIC=role=input-directory;phase=fstatx-snapshot;'
            'result=-1;call=-1;errno=13;freeCall=0;freeErrno=0\n').encode()
        interval_body = b'unselected private line\n' + phase_line + refusal_line + acl_line
        selected_body, selection = selector['select_installer_log'](interval_body, binding)
        self.assertNotEqual(selected_body, interval_body)
        self.assertEqual(selected_body, phase_line + refusal_line + acl_line)
        metadata = {'schemaVersion': 1, 'kind': 'installer-log-capture', 'state': 'observed-project-correlated',
            'binding': binding, 'logPath': str(selector['INSTALL_LOG']),
            'identity': {'device': 1, 'inode': 2, 'mode': 0o100644, 'uid': 0, 'gid': 0, 'links': 1},
            'cursorSha256': 'a' * 64, 'startOffsetBytes': 100, 'endOffsetBytes': 100 + len(interval_body),
            'growthBeyondSnapshotBytes': 0, 'intervalBytes': len(interval_body),
            'intervalSha256': hashlib.sha256(interval_body).hexdigest(), **selection,
            'selectedData': {'file': 'installer-log-selected.txt', 'bytes': len(selected_body),
                'sha256': hashlib.sha256(selected_body).hexdigest()},
            'authority': DATA.INSTALLER_LOG_AUTHORITY, 'scriptOutputFinality': 'unestablished'}
        payload_value = receipt('notarize-payload')
        payload_value['payloadNotarization'] = payload_value.pop('finalImage')
        payload_value['payloadNotarization'].update(inventorySha256='8' * 64, runtimeManifestSha256='9' * 64)
        final_value = receipt('finalize-package'); final_value['finalPackage'] = final_value.pop('finalImage')
        final_value['finalPackage']['kind'] = 'mrk-final-installer-package'
        final_bytes = json.dumps(final_value).encode()
        installer_value = receipt('package-install'); del installer_value['finalImage'], installer_value['notarySubmission']
        installer_value.update(passed=False, targetRetired=False,
            finalPackageReceiptSha256=hashlib.sha256(final_bytes).hexdigest(),
            failure={'stage': 'standard-original-installer', 'type': 'Refused', 'reason': 'original-nonzero-installer'})
        installer_value['originalCalls'] = [dict(role=role, entered=True, returned=True, capturesSettled=True,
            returncode=status, stdoutSha256='a' * 64, stderrSha256=hashlib.sha256(b'').hexdigest())
            for role, status in (('distribution-attach', 0), ('installer-log-cursor', 0), ('installer', 1), ('installer-log-capture', 0))]
        statuses = {name: {'receiptState': 'observed', 'returncode': status} for name, status in
            (('installer-log-cursor.status', 0), ('installer-output.status', 1), ('installer-log-capture.status', 0))}
        def observed_phases(document):
            current = copy.deepcopy(installer_value)
            body = json.dumps(document).encode()
            current['originalCalls'][-1]['stdoutSha256'] = hashlib.sha256(body).hexdigest()
            current['originalCalls'][-1]['returncode'] = 1 if document['state'] == 'unknown' else 0
            phase = DATA.project_receipt(current, CONTEXT, 'package-install')
            phase['callerStatus'] = {'receiptState': 'observed', 'returncode': 1}
            payload = DATA.project_receipt(payload_value, CONTEXT, 'notarize-payload')
            payload['callerStatus'] = {'receiptState': 'observed', 'returncode': 0}
            finalized = DATA.project_receipt(final_value, CONTEXT, 'finalize-package')
            finalized.update(receiptSha256=hashlib.sha256(final_bytes).hexdigest(),
                callerStatus={'receiptState': 'observed', 'returncode': 0})
            return body, current, phase, payload, finalized
        def diagnose(document, selected=selected_body, *, changed=None, trace=None):
            body, current, phase, payload, finalized = observed_phases(document)
            scalar = copy.deepcopy(statuses)
            scalar['installer-log-capture.status']['returncode'] = current['originalCalls'][-1]['returncode']
            if changed is not None: changed(phase, scalar, payload, finalized)
            return DATA.project_installer_failure_diagnostic(body, selected, phase, scalar, CONTEXT, payload, finalized,
                trace if trace is not None else {'nodes': 0, 'deadline': time.monotonic_ns() + 45_000_000_000})
        diagnostic = diagnose(metadata)
        self.assertEqual(diagnostic['postinstallPhaseCounts']['entry'], 1)
        self.assertEqual(diagnostic['postinstallRefusalCounts']['cwd'], 1)
        self.assertEqual(diagnostic['aclDiagnostics'][0], {'role': 'input-directory', 'phase': 'fstatx-snapshot',
            'result': -1, 'call': -1, 'errno': 13, 'freeCall': 0, 'freeErrno': 0})
        self.assertEqual(diagnostic['completedParentDiagnostic']['state'], 'missing')
        self.assertFalse(diagnostic['originalInstallerReturnedZero']); self.assertTrue(diagnostic['diagnosticOnly'])
        self.assertNotIn(SENTINEL, json.dumps(diagnostic)); self.assertNotIn('/private/', json.dumps(diagnostic))
        # Exact future ninth grammar is pure DATA: no native symbol/error text.
        parent_token = ('MRK_MACOS_INSTALL_COMPLETED_REFUSED=reasonSha256=' + 'b' * 64 +
            ';exit=1;originals=1;native=0;timely=1;unknown=1\n').encode()
        def parent_document(lines):
            fresh = copy.deepcopy(metadata); interval = b''.join(lines)
            body, selection = selector['select_installer_log'](interval, binding)
            fresh.update(startOffsetBytes=0, endOffsetBytes=len(interval), intervalBytes=len(interval),
                intervalSha256=hashlib.sha256(interval).hexdigest(), **selection)
            fresh['selectedData'].update(bytes=len(body), sha256=hashlib.sha256(body).hexdigest())
            return fresh, body
        for lines, state in (([parent_token], 'observed'), ([parent_token, parent_token], 'duplicate'),
            ([parent_token, parent_token.replace(b'unknown=1', b'unknown=0')], 'conflicting')):
            document, selected = parent_document(lines); parent = diagnose(document, selected)['completedParentDiagnostic']
            self.assertEqual(parent['state'], state)
            self.assertEqual('reasonSha256' in parent, state == 'observed')
            if state == 'observed':
                self.assertEqual(parent['reasonSha256'], 'b' * 64); self.assertIs(parent['unknown'], True)
                self.assertIs(parent['native'], False); self.assertEqual(parent['exit'], 1)
        # The same byte-preserved legacy8 metadata remains compatible without
        # inventing a ninth zero key in the historical writer's original output.
        legacy8 = copy.deepcopy(metadata); del legacy8['markerCounts'][DATA.INSTALLER_PARENT_KEY]
        self.assertEqual(diagnose(legacy8)['selectorCatalog'], 'fixed8')
        self.assertEqual(diagnose(metadata)['selectorCatalog'], 'fixed9')
        # A line may match earlier postinstall data and the terminal parent marker.
        # Ordered anchors must be the real selector's SOURCE order, not a copied projector list.
        mixed_document, mixed_selected = parent_document([phase_line.rstrip(b'\n') + b' ' + parent_token])
        self.assertEqual(mixed_document['selectedLines'][0]['anchors'],
                         [DATA.INSTALLER_PARENT_KEY, 'postinstall-phase'])
        mixed_result = diagnose(mixed_document, mixed_selected)
        self.assertEqual(mixed_result['completedParentDiagnostic']['state'], 'observed')
        self.assertEqual(mixed_result['postinstallPhaseCounts']['entry'], 1)
        self.assertNotIn(SENTINEL, json.dumps(mixed_result))
        wrong_order = copy.deepcopy(mixed_document)
        wrong_order['selectedLines'][0]['anchors'].reverse()
        with self.assertRaises(DATA.Refused): diagnose(wrong_order, mixed_selected)
        # Each finite boundary is reached through the actual original validation,
        # with the metadata digest genuinely rejoined before a selected mutation.
        stage_vectors = [
            ('metadata-schema', lambda d: d.update(kind='private-unknown')),
            ('binding-schema', lambda d: d['binding'].update(extra=SENTINEL)),
            ('binding-context', lambda d: d['binding'].update(runAttempt='99')),
            ('binding-path', lambda d: d['binding'].update(packagePath='/private/other.pkg')),
            ('captured-schema', lambda d: d.update(cursorSha256='c' * 64)),
            ('log-identity', lambda d: d['identity'].update(links=2)),
            ('interval', lambda d: d.update(intervalBytes=len(interval_body) + 1)),
            ('row-list', lambda d: d.update(linesUnselected=0)),
            ('selected-body-hash', lambda d: d['selectedData'].update(sha256='c' * 64)),
            ('selector-catalog', lambda d: d['markerCounts'].update({'postinstall-phase': True})),
            ('row-shape', lambda d: d['selectedLines'][0].update(extra=SENTINEL)),
            ('row-bounds', lambda d: d['selectedLines'][0].update(retainedOffsetBytes=1)),
            ('row-hash', lambda d: d['selectedLines'][0].update(sha256='c' * 64)),
            ('row-anchors', lambda d: d['selectedLines'][0].update(anchors=['package-path'])),
            ('count-correspondence', lambda d: d['markerCounts'].update({'postinstall-phase': 2})),
            ('result-state', lambda d: d.update(resultMarkerState='unbound'))]
        stage_vectors.extend([
            ('binding-path', lambda d: d['binding'].update(packagePath='/private/' + SENTINEL + '/package-mount/MobileReleaseKit-' + '7' * 32 + '.pkg')),
            ('binding-path', lambda d: d['binding'].update(packagePath='/private/' + SENTINEL + '/package-mount/' + selector['distribution_request_name']('6' * 32))),
            ('captured-schema', lambda d: d.update(logPath='/var/log/install.log'))])
        for expected, mutate in stage_vectors:
            fresh = copy.deepcopy(metadata); mutate(fresh)
            trace = {'nodes': 0, 'deadline': time.monotonic_ns() + 45_000_000_000}
            with self.subTest(refusal_stage=expected), self.assertRaises(DATA.Refused):
                diagnose(fresh, trace=trace)
            self.assertEqual(trace['installerDiagnosticStage'], expected)
        for expected, mutation in (
            ('original-caller', lambda p, s, n, f: p.update(recordedPassed=True)),
            ('preceding-originals', lambda p, s, n, f: n.update(correlationMatches=False)),
            ('payload-originals', lambda p, s, n, f: n['originalCalls']['calls'][0].update(returncode=1)),
            ('finalizer-caller', lambda p, s, n, f: f['callerStatus'].update(returncode=1)),
            ('finalizer-receipt-hash', lambda p, s, n, f: f.update(receiptSha256='e' * 64)),
            ('payload-acceptance', lambda p, s, n, f: n['payloadNotarization'].update(status='Invalid'))):
            trace = {'nodes': 0, 'deadline': time.monotonic_ns() + 45_000_000_000}
            with self.subTest(refusal_stage=expected), self.assertRaises(DATA.Refused):
                diagnose(metadata, changed=mutation, trace=trace)
            self.assertEqual(trace['installerDiagnosticStage'], expected)
        wrong_documents = []
        for key, replacement in (('state', 'unknown'), ('authority', SENTINEL), ('cursorSha256', 'c' * 64),
            ('resultMarkerState', 'unbound'), ('linesUnselected', 0), ('intervalBytes', len(interval_body) + 1),
            ('identity', {'device': 1, 'inode': 2, 'mode': 0o100666, 'uid': 0, 'gid': 0, 'links': 1})):
            wrong = copy.deepcopy(metadata); wrong[key] = replacement; wrong_documents.append(wrong)
        for key, replacement in (('sourceCommit', '2' * 40), ('runAttempt', '99'), ('inventorySha256', '3' * 64),
            ('runtimeManifestSha256', '4' * 64), ('requestId', '5' * 32), ('packagePath', '/private/other.pkg')):
            wrong = copy.deepcopy(metadata); wrong['binding'][key] = replacement; wrong_documents.append(wrong)
        for key, replacement in (('bytes', len(selected_body) + 1), ('sha256', 'c' * 64), ('file', SENTINEL)):
            wrong = copy.deepcopy(metadata); wrong['selectedData'][key] = replacement; wrong_documents.append(wrong)
        for key, replacement in (('relativeOffsetBytes', len(interval_body)), ('retainedOffsetBytes', 1),
            ('bytes', 0), ('sha256', 'c' * 64), ('anchors', ['package-path'])):
            wrong = copy.deepcopy(metadata); wrong['selectedLines'][0][key] = replacement; wrong_documents.append(wrong)
        wrong = copy.deepcopy(metadata); wrong['selectedLines'].append(copy.deepcopy(wrong['selectedLines'][0])); wrong_documents.append(wrong)
        wrong = copy.deepcopy(metadata); wrong['markerCounts']['arbitrary-private-key'] = 1; wrong_documents.append(wrong)
        wrong = copy.deepcopy(metadata); wrong['markerCounts']['postinstall-phase'] += 1; wrong_documents.append(wrong)
        for document in wrong_documents:
            with self.assertRaises(DATA.Refused): diagnose(document)
        for key, replacement in (('entered', False), ('returned', False), ('capturesSettled', False),
            ('returncode', 2), ('returncode', True), ('stdoutSha256', 'd' * 64), ('stderrSha256', 'd' * 64)):
            with self.assertRaises(DATA.Refused):
                diagnose(metadata, changed=lambda p, s, n, f, key=key, replacement=replacement:
                    p['originalCalls']['calls'][-1].update({key: replacement}))
        for change in (lambda p, s, n, f: p.update(recordedPassed=True),
            lambda p, s, n, f: p.update(callerStatus={'receiptState': 'observed', 'returncode': 0}),
            lambda p, s, n, f: s['installer-output.status'].update(returncode=0),
            lambda p, s, n, f: n.update(correlationMatches=False),
            lambda p, s, n, f: n.update(receiptState='absent'),
            lambda p, s, n, f: f.update(receiptSha256='e' * 64)):
            with self.assertRaises(DATA.Refused): diagnose(metadata, changed=change)
        with self.assertRaises(DATA.Refused): diagnose(metadata, selected_body + b'extra\n')
        for body in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1.5}', b'\xff', b'x' * (256 * 1024 + 1),
            json.dumps({'x': [0] * 2049}).encode()):
            with self.assertRaises(DATA.Refused):
                DATA.decode_installer_diagnostic(body, {'nodes': 0, 'deadline': time.monotonic_ns() + 45_000_000_000})
        large_metadata = json.dumps({'x': [0] * 2048, 'y': 'x' * 4096, 'z': [0] * 2048}).encode()
        self.assertGreater(len(large_metadata), 16384)
        self.assertEqual(len(DATA.decode_installer_diagnostic(large_metadata,
            {'nodes': 0, 'deadline': time.monotonic_ns() + 45_000_000_000})['x']), 2048)
        unavailable = {key: metadata[key] for key in ('schemaVersion', 'kind', 'binding', 'authority', 'scriptOutputFinality')}
        unavailable.update(state='unknown', reason='log-output-readback', plannedSelectedData=metadata['selectedData'],
            selectedOutputState='write-or-close-unknown-preserve-original')
        self.assertEqual(diagnose(unavailable, None)['captureState'], 'unavailable')
        self.assertFalse(diagnose(unavailable, None)['selectionOriginalAuthorized'])

        for malformed in (b'{"x":1,"x":2}', b'\xff'):
            body, current, phase, payload, finalized = observed_phases(metadata)
            phase['originalCalls']['calls'][-1]['stdoutSha256'] = hashlib.sha256(malformed).hexdigest()
            trace = {'nodes': 0, 'deadline': time.monotonic_ns() + 45_000_000_000}
            with self.assertRaises(DATA.Refused):
                DATA.project_installer_failure_diagnostic(malformed, selected_body, phase, statuses, CONTEXT,
                    payload, finalized, trace)
            self.assertEqual(trace['installerDiagnosticStage'], 'metadata-decode')
        trace = {'nodes': 0, 'deadline': time.monotonic_ns() + 45_000_000_000}
        with self.assertRaises(DATA.Refused):
            diagnose(metadata, changed=lambda p, s, n, f: p['originalCalls']['calls'][-1].update(stdoutSha256='d' * 64), trace=trace)
        self.assertEqual(trace['installerDiagnosticStage'], 'metadata-original-hash')
        bad_unavailable = copy.deepcopy(unavailable); bad_unavailable['reason'] = SENTINEL
        trace = {'nodes': 0, 'deadline': time.monotonic_ns() + 45_000_000_000}
        with self.assertRaises(DATA.Refused): diagnose(bad_unavailable, None, trace=trace)
        self.assertEqual(trace['installerDiagnosticStage'], 'capture-unavailable-schema')

        # Both fixed attempts are precharged and consume once even on absence.
        log_charge = 2 * (DATA.INSTALLER_DIAGNOSTIC_LIMIT + 1)
        reserved = {'files': 126, 'bytes': DATA.INPUT_LIMIT - log_charge, 'deadline': time.monotonic_ns() + 45_000_000_000}
        DATA.reserve_installer_diagnostic_reads(reserved)
        self.assertEqual((reserved['files'], reserved['bytes']), (128, DATA.INPUT_LIMIT))
        with self.assertRaises(DATA.Refused): DATA.reserve_installer_diagnostic_reads(reserved)
        for key in ('files', 'bytes'):
            bad_budget = {'files': 126, 'bytes': DATA.INPUT_LIMIT - log_charge, 'deadline': time.monotonic_ns() + 45_000_000_000}
            bad_budget[key] += 1
            with self.assertRaises(DATA.Refused): DATA.reserve_installer_diagnostic_reads(bad_budget)
        for scenario in ('valid', 'mixed', 'absent', 'partial', 'metadata-linked', 'metadata-symlink', 'wrong-context', 'hash', 'wrong-status', 'linked', 'symlink', 'oversize'):
            with self.subTest(installer=scenario), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); document, selected = (mixed_document, mixed_selected) if scenario == 'mixed' else (metadata, selected_body)
                body, current, phase, payload, finalized = observed_phases(document)
                if scenario == 'wrong-context': current['runAttempt'] = '99'
                if scenario == 'hash': current['originalCalls'][-1]['stdoutSha256'] = 'f' * 64
                original = write(root, 'android-helper-package-install.json', current)
                write(root, 'package-install.status', b'1\n')
                write(root, 'android-helper-notarize-payload.json', payload_value)
                write(root, 'android-helper-finalize-package.json', final_bytes); write(root, 'package-finalization.status', b'0\n')
                for name, scalar in statuses.items(): write(root, name, (str(scalar['returncode']) + '\n').encode())
                if scenario == 'wrong-status': write(root, 'installer-output.status', b'0\n')
                for name, content in zip(DATA.INSTALLER_DIAGNOSTIC_INPUTS, (body, selected)):
                    if scenario == 'absent' or scenario == 'partial' and name == 'installer-log-selected.txt': continue
                    if scenario == 'oversize' and name.endswith('.txt'): content = b'x' * (256 * 1024 + 1)
                    if scenario == 'symlink' and name.endswith('.txt') or scenario == 'metadata-symlink' and name.endswith('.json'):
                        private = write(root, 'private-installer-original', content); os.symlink(private.name, root / name)
                    else:
                        write(root, name, content)
                        if scenario == 'linked' and name.endswith('.txt') or scenario == 'metadata-linked' and name.endswith('.json'):
                            os.link(root / name, root / 'retained-installer-original')
                before = original.read_bytes(); output = project(root); item = output['installerFailureDiagnostic']
                self.assertEqual(item['receiptState'], 'observed' if scenario in ('valid', 'mixed') else 'absent' if scenario == 'absent' else 'refused')
                if scenario in ('valid', 'mixed'):
                    self.assertNotIn('refusalStage', item); self.assertNotIn('inputStates', item)
                else:
                    expected = 'metadata-original-read' if scenario in ('absent', 'metadata-linked', 'metadata-symlink') else \
                        'original-caller' if scenario in ('wrong-context', 'wrong-status') else \
                        'metadata-original-hash' if scenario == 'hash' else 'selected-body-hash'
                    self.assertEqual(item['refusalStage'], expected)
                    states = {'metadata': 'absent' if scenario == 'absent' else 'refused' if scenario in ('metadata-linked', 'metadata-symlink') else 'observed',
                              'selected': 'absent' if scenario in ('absent', 'partial') else 'refused' if scenario in ('linked', 'symlink', 'oversize') else 'observed'}
                    self.assertEqual(item['inputStates'], states)
                self.assertFalse(output['productReady']); self.assertFalse(item['originalInstallerReturnedZero'])
                self.assertEqual(original.read_bytes(), before)
                self.assertNotIn(SENTINEL, json.dumps(output)); self.assertNotIn(str(root), json.dumps(output))
        # Real fixed reader POST and one-shot close failures remain original
        # errors, never converted into a successful diagnostic or retried.
        for fault in ('post', 'close'):
            with self.subTest(installer_reader=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); name = DATA.INSTALLER_DIAGNOSTIC_INPUTS[1]
                write(root, name, selected_body); root_fd = DATA.open_root(str(root))
                original_stat, original_close = DATA.os.stat, DATA.os.close
                closed = []
                try:
                    def changed_stat(path, *args, **kwargs):
                        value = original_stat(path, *args, **kwargs)
                        if path == name and fault == 'post':
                            return SimpleNamespace(st_dev=value.st_dev, st_ino=value.st_ino + 1, st_mode=value.st_mode,
                                st_uid=value.st_uid, st_gid=value.st_gid, st_nlink=value.st_nlink, st_size=value.st_size,
                                st_mtime_ns=value.st_mtime_ns, st_ctime_ns=value.st_ctime_ns)
                        return value
                    def failed_close(fd):
                        closed.append(fd); original_close(fd)
                        if fault == 'close': raise OSError('private-close-must-not-render')
                    DATA.os.stat, DATA.os.close = changed_stat, failed_close
                    live_budget = {'files': 0, 'bytes': 0, 'deadline': time.monotonic_ns() + 45_000_000_000}
                    DATA.reserve_installer_diagnostic_reads(live_budget)
                    with self.assertRaises(DATA.Refused if fault == 'post' else OSError):
                        DATA.read_input(root_fd, name, DATA.INSTALLER_DIAGNOSTIC_LIMIT, live_budget,
                            installer_diagnostic_reserved=True)
                    self.assertEqual(len(closed), 1)
                    with self.assertRaises(DATA.Refused):
                        DATA.read_input(root_fd, name, DATA.INSTALLER_DIAGNOSTIC_LIMIT, live_budget,
                            installer_diagnostic_reserved=True)
                finally:
                    DATA.os.stat, DATA.os.close = original_stat, original_close
                    os.close(root_fd)

    def test_fixed_signature_and_notary_refusals_remain_distinguishable(self):
        reasons = ("package-signature-bound", "package-signature-header", "package-signature-trust-timestamp",
                   "package-signature-source-chain", "package-signature-source-fingerprint", "notary-submit-terminal",
                   "notary-submit-metadata", "notary-submit-archive", "notary-uuid")
        for reason in reasons:
            self.assertEqual(DATA.project_failure({"reason": reason})["reason"], reason)
        self.assertEqual(DATA.project_failure({"reason": "package-signature-" + SENTINEL})["reason"], "unclassified")

    def test_successful_normalized_receipt_and_original_zero_survive_file_projection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(root, "android-helper-finalize-image.json", receipt())
            write(root, "image-finalization.status", b"0\n")
            result = project(root)
            observed = result["phases"]["finalize-image"]
            self.assertEqual(observed["receiptState"], "observed")
            self.assertIs(observed["recordedPassed"], True)
            self.assertIs(observed["originalClosesKnown"], True)
            self.assertIs(observed["notaryAuthentication"]["closed"], True)
            self.assertEqual(observed["callerStatus"]["returncode"], 0)
            self.assertEqual(observed["finalImage"]["imageSha256"], "c" * 64)
            self.assertEqual(observed["finalImage"]["logSha256"], "a" * 64)
            self.assertIs(observed["finalImage"]["actualStaplerValidation"], True)
            self.assertEqual(observed["notarySubmission"]["status"], "Accepted")
            self.assertIs(result["productReady"], False)

    def test_same_package_positive_is_closed_data_not_service_or_ui_authority(self):
        value = same_package_receipt()
        value.update(arbitraryPrivateField=SENTINEL)
        value["originalCalls"][1]["argv"] = [SENTINEL]
        for target in DATA.TARGETS:
            context = dict(CONTEXT, target=target)
            result = DATA.project_receipt(dict(value, target=target), context, "same-package-noop")
            self.assertEqual(result["samePackageObservation"], value["samePackageObservation"])
            self.assertNotIn(SENTINEL, json.dumps(result))
            self.assertFalse(result["samePackageObservation"]["systemServiceExitClaimed"])
        for key, changed in (("newExportCount", 2), ("payloadWriteCount", 1), ("payloadWriteBytes", True),
                             ("verifiedCurrentFiles", 2049), ("currentObjectsPreserved", 1),
                             ("baselineResultSha256", "b" * 64), ("productReady", True), ("requestId", SENTINEL)):
            invalid = copy.deepcopy(value); invalid["samePackageObservation"][key] = changed
            with self.subTest(key=key), self.assertRaises(DATA.Refused):
                DATA.project_receipt(invalid, CONTEXT, "same-package-noop")
        with self.assertRaises(DATA.Refused): DATA.project_receipt(value, dict(CONTEXT, profile="aqua"), "same-package-noop")
        with self.assertRaises(DATA.Refused): DATA.project_receipt(dict(value, phase="package-install"), CONTEXT, "package-install")

    def test_same_package_requires_originals_cleanups_and_independent_caller_zero(self):
        value = same_package_receipt()
        for fault in ("role", "returned", "capture", "nonzero", "close", "cleanup", "pending", "credentials", "mount"):
            invalid = copy.deepcopy(value)
            if fault == "role": invalid["originalCalls"].reverse()
            elif fault == "returned": invalid["originalCalls"][1]["returned"] = False
            elif fault == "capture": invalid["originalCalls"][1]["capturesSettled"] = False
            elif fault == "nonzero": invalid["originalCalls"][1]["returncode"] = 1
            elif fault == "close": invalid["originalClosesKnown"] = False
            elif fault == "cleanup": invalid["cleanupErrors"] = [{}]
            elif fault == "pending": invalid["directStagerIOPending"] = "same-package-readback"
            elif fault == "credentials": invalid["credentialContexts"] = [{}]
            else: invalid["packageMount"]["detached"] = 1
            with self.subTest(fault=fault), self.assertRaises(DATA.Refused):
                DATA.project_receipt(invalid, CONTEXT, "same-package-noop")
        for code in (None, 1, 0):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                write(root, "android-helper-same-package-noop.json", value)
                if code is not None: write(root, "same-package-noop.status", (str(code) + "\n").encode())
                result = project(root)["phases"]["same-package-noop"]
                self.assertEqual(result["receiptState"], "observed" if code == 0 else "refused")
                self.assertEqual("samePackageObservation" in result, code == 0)
        failed = dict(value, passed=False, failure={"stage": "installer", "type": "RuntimeError", "reason": "original-operation-refused"})
        del failed["samePackageObservation"]
        self.assertIsNone(DATA.project_receipt(failed, CONTEXT, "same-package-noop")["samePackageObservation"])

    def test_app_absence_genuine_receipts_require_seven_twenty_five_originals(self):
        self.assertEqual(DATA.APP_ABSENCE_PREPARE_ROLES, ("app-absence-build", "app-absence-data-tests", "app-absence-adhoc",
            "app-absence-verify-code", "app-absence-pkgbuild", "app-absence-tar", "app-absence-xar"))
        self.assertEqual(len(DATA.APP_ABSENCE_PACKAGE_ROLES), 21)
        self.assertEqual(DATA.APP_ABSENCE_PACKAGE_ROLES[:3], ("producer-tests", "producer-build", "producer-emitter"))
        self.assertEqual(DATA.APP_ABSENCE_PACKAGE_ROLES[16], "app-absence-baseline")
        self.assertEqual(DATA.APP_ABSENCE_PACKAGE_ROLES[-1], "app-absence-baseline-detach")
        self.assertEqual(DATA.APP_ABSENCE_RESTORE_ROLES, ("app-absence-restore-attach", "app-absence-withdraw", "app-absence-install",
            "app-absence-verify", "app-absence-restore-detach"))
        for target in ("aarch64-apple-darwin", "x86_64-apple-darwin"):
            context = {**CONTEXT, "target": target}
            documents = app_absence_documents(context)
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                write_app_absence_documents(root, documents)
                originals = {p.name: p.read_bytes() for p in root.iterdir()}
                value = DATA.project(str(root), profile="installed", source=context["source"], workflow_source=context["workflowSource"],
                                     run_id=context["runId"], run_attempt=context["runAttempt"], target=target)
                row = value["appAbsence"]
                self.assertEqual(row["receiptState"], "observed")
                self.assertIs(row["proofComplete"], True)
                self.assertEqual(row["nativeCalls"], {"prepare": 7, "baseline": 21, "restore": 5})
                self.assertEqual(row["prepare"]["pureDataTests"]["passed"], 6)
                self.assertEqual(row["prepare"]["pureDataTests"]["filteredCount"], 999999)
                self.assertIs(row["retainedPrivateEvidence"], True)
                for key in ("systemServiceExitClaimed", "downloadedLaunchQualified", "guiQualified", "productReady"):
                    self.assertIs(row[key], False)
                self.assertEqual(row["restore"]["baselineOwnerReceiptSha256"], value["phases"]["package-install"]["receiptSha256"])
                self.assertEqual(row["prepare"]["receiptSha256"], row["restore"]["preparationReceiptSha256"])
                self.assertNotEqual(row["initialResultSha256"], row["restoreResultSha256"])
                self.assertEqual(row["restore"]["verifiedCurrentFiles"], 4096)
                encoded = (root / DATA.OUTPUT).read_bytes()
                self.assertNotIn(SENTINEL.encode(), encoded)
                for private_key in (b'"requestId"', b'"invocation"', b'"instance"', b'"identity"', b'"rootNonce"', b'"proof"'):
                    self.assertNotIn(private_key, encoded)
                for name, original in originals.items():
                    self.assertEqual((root / name).read_bytes(), original)
        # No fixture inputs is absence, never proof of a successful no-op.
        with tempfile.TemporaryDirectory() as directory:
            row = project(Path(directory))["appAbsence"]
            self.assertEqual(row["receiptState"], "absent")
            self.assertIs(row["proofComplete"], False)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); write_app_absence_documents(root, documents)
            value = DATA.project(str(root), profile="aqua", source=CONTEXT["source"], workflow_source=CONTEXT["workflowSource"],
                                 run_id=CONTEXT["runId"], run_attempt=CONTEXT["runAttempt"], target=CONTEXT["target"])
            self.assertIsNone(value["appAbsence"])

    def test_app_absence_refuses_incomplete_owners_cross_run_and_private_proofs(self):
        documents = app_absence_documents()
        phases = ("prepare-app-absence", "package-install", "app-absence-restore")
        fields = ("appAbsencePreparation", "appAbsenceBaseline", "appAbsenceRestore")
        def reduce(index, value):
            if index == 1:
                return DATA.project_app_absence_baseline(value, CONTEXT)
            return DATA.project_app_absence_receipt(value, CONTEXT, phases[index], "a" * 64)
        def set_at(value, path, changed):
            for key in path[:-1]:
                value = value[key]
            value[path[-1]] = changed
        # Each mutation changes a real admitted field; do not count an already
        # invalid fixture or an identical runAttempt as negative coverage.
        for index, original in enumerate(documents):
            reduce(index, original)
            faults = [(('workflow',), 'unrelated'), (('source',), '2'*40), (('workflowSource',), '2'*40),
                (('runId',), '124'), (('runAttempt',), '3'), (('target',), 'x86_64-apple-darwin'),
                (('packageRole',), 'removal-image'), (('schemaVersion',), True),
                (('passed',), False), (('targetRetired',), False), (('originalClosesKnown',), False),
                (('outerFinalityRequired',), False), (('directStagerIOPending',), SENTINEL),
                (('cleanupErrors',), [SENTINEL]), (('originalCalls', 0, 'returned'), False),
                (('originalCalls', 0, 'capturesSettled'), False), (('originalCalls', 0, 'returncode'), True),
                (('originalCalls', 0, 'returncode'), 70), (('originalCalls', 0, 'role'), 'unlisted')]
            for path, bad in faults:
                with self.subTest(phase=phases[index], path=path, bad=bad):
                    value = copy.deepcopy(original)
                    old = value
                    for key in path:
                        old = old[key]
                    self.assertTrue(type(old) is not type(bad) or old != bad)
                    set_at(value, path, bad)
                    with self.assertRaises(DATA.Refused):
                        reduce(index, value)
            for change in ('missing', 'extra', 'reordered'):
                value = copy.deepcopy(original)
                if change == 'missing': value['originalCalls'].pop()
                elif change == 'extra': value['originalCalls'].append(copy.deepcopy(value['originalCalls'][0]))
                else: value['originalCalls'][0], value['originalCalls'][1] = value['originalCalls'][1], value['originalCalls'][0]
                with self.subTest(phase=phases[index], roster=change), self.assertRaises(DATA.Refused):
                    reduce(index, value)
            for key in original[fields[index]]:
                value = copy.deepcopy(original); del value[fields[index]][key]
                with self.subTest(phase=phases[index], missing=key), self.assertRaises(DATA.Refused):
                    reduce(index, value)
        # The current extra native test original cannot be dropped, duplicated,
        # nonzero or unsettled and counted as a current package proof.
        for fault in ("missing-tests", "duplicate-tests", "nonzero-tests", "unsettled-tests"):
            value = copy.deepcopy(documents[1])
            if fault == "missing-tests": value["originalCalls"].pop(0)
            elif fault == "duplicate-tests": value["originalCalls"][1] = copy.deepcopy(value["originalCalls"][0])
            elif fault == "nonzero-tests": value["originalCalls"][0]["returncode"] = 1
            else: value["originalCalls"][0]["capturesSettled"] = False
            with self.subTest(testOriginal=fault), self.assertRaises(DATA.Refused): reduce(1, value)
        # The genuine DATA parser's six names/counts are not arbitrary stdout.
        for key, bad in (("passed", 5), ("failed", 1), ("ignored", 1), ("filteredCount", 1000000),
                         ("schemaVersion", True), ("methodNames", [SENTINEL]*6), ("stdoutSha256", SENTINEL)):
            value = copy.deepcopy(documents[0]); value[fields[0]]["pureDataTests"][key] = bad
            with self.subTest(data=key), self.assertRaises(DATA.Refused):
                reduce(0, value)
        for index, phase_fields in ((1, ("baselineObservation",)), (2, ("withdraw", "verify"))):
            for field in phase_fields:
                observation = documents[index][fields[index]][field]
                for proof_key in observation["proof"]:
                    value = copy.deepcopy(documents[index]); value[fields[index]][field]["proof"][proof_key] = False
                    with self.subTest(phase=field, proof=proof_key), self.assertRaises(DATA.Refused):
                        reduce(index, value)
                for key, bad in (("productSource", "2"*40), ("runAttempt", "3"), ("baselineSha256", "c"*64),
                                 ("originalOuterExitRequired", False), ("systemServiceExitClaimed", True), ("productReady", True)):
                    value = copy.deepcopy(documents[index]); value[fields[index]][field][key] = bad
                    with self.subTest(phase=field, key=key), self.assertRaises(DATA.Refused):
                        reduce(index, value)
                value = copy.deepcopy(documents[index]); value[fields[index]][field]["rootNonce"] = SENTINEL
                with self.assertRaises(DATA.Refused): reduce(index, value)
        for key, bad in (("initialFreshInstall", False), ("initialExportCount", True), ("originalBaselineZero", False),
                         ("originalMountDetached", False), ("productReady", True)):
            value = copy.deepcopy(documents[1]); value[fields[1]][key] = bad
            with self.subTest(baseline=key), self.assertRaises(DATA.Refused): reduce(1, value)
        for key in ("restoreFixedAppObserved", "immediatePredecessorMatched", "currentBytesVerified", "initialHistoryPreserved",
                    "originalInstallerReturnedZero", "originalMountDetached", "retainedPrivateEvidence"):
            value = copy.deepcopy(documents[2]); value[fields[2]][key] = False
            with self.subTest(restore=key), self.assertRaises(DATA.Refused): reduce(2, value)
        for key, bad in (("beforeExportCount", 0), ("afterExportCount", 3), ("newExportCount", True), ("verifiedCurrentFiles", 4097)):
            value = copy.deepcopy(documents[2]); value[fields[2]][key] = bad
            with self.subTest(restore=key), self.assertRaises(DATA.Refused): reduce(2, value)
        # Cross-receipt joins and independent statuses are checked at the real
        # fixed-file projector, not inferred from pre-exit proofs/counts alone.
        cases = [("status", name, body) for name in ("app-absence-preparation.status", "package-install.status", "app-absence-restore.status")
                 for body in (None, b"70\n", b"0 0 0\n")]
        cases += [("join", key, "c"*64) for key in ("preparationReceiptSha256", "baselineOwnerReceiptSha256", "imageSha256", "initialResultSha256")]
        for kind, key, bad in cases:
            with self.subTest(kind=kind, key=key, bad=bad), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); values = copy.deepcopy(documents)
                if kind == "join":
                    self.assertNotEqual(values[2][fields[2]][key], bad)
                    values[2][fields[2]][key] = bad
                write_app_absence_documents(root, values)
                if kind == "status":
                    if bad is None: (root / key).unlink()
                    else: write(root, key, bad)
                row = project(root)["appAbsence"]
                self.assertEqual(row["receiptState"], "incomplete")
                self.assertIs(row["proofComplete"], False)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); write_app_absence_documents(root, documents)
            raw = write(root, "unpublished-private", SENTINEL.encode())
            (root / "android-helper-app-absence-restore.json").unlink()
            os.symlink(raw.name, root / "android-helper-app-absence-restore.json")
            before = raw.read_bytes(); row = project(root)["appAbsence"]
            self.assertEqual(row["restore"]["receiptState"], "refused")
            self.assertIs(row["proofComplete"], False)
            self.assertEqual(raw.read_bytes(), before)
            self.assertNotIn(SENTINEL.encode(), (root / DATA.OUTPUT).read_bytes())

    def test_positive_update_projects_genuine_current_writer_and_both_original_callers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_update_documents(root, update_documents())
            result = project(root)
            self.assertEqual(result["positiveUpdate"]["receiptState"], "observed")
            self.assertFalse(result["positiveUpdate"]["productReady"])
            old, new = result["positiveUpdate"]["baseline"], result["positiveUpdate"]["current"]
            self.assertEqual(old["expectedCurrentDescriptorSha256"], new["currentDescriptorSha256"])
            self.assertEqual(old["invocation"], new["baselineInvocation"])
            self.assertNotEqual(new["baselineInvocation"], new["currentInvocation"])
            self.assertTrue(new["rootIdentityPreserved"] and new["generationInstancesDistinct"] and new["testedAppDataOriginalPreserved"])
            self.assertFalse(new["allUserDataCompatible"] or new["retainedPayloadRehashed"] or new["downloadedLaunchQualified"])
            self.assertEqual(result["phases"]["update-baseline"]["originalCalls"]["recordedCount"], 3)
            self.assertEqual(result["phases"]["package-install"]["originalCalls"]["recordedCount"], 16)
            self.assertNotIn(SENTINEL, (root / DATA.OUTPUT).read_text())
            self.assertLessEqual((root / DATA.OUTPUT).stat().st_size, DATA.OUTPUT_LIMIT)

    def test_positive_update_refuses_conflicting_originals_context_and_lineage(self):
        for fault in ("status", "status-bool", "unknown", "close", "retired", "source", "baseline-invocation", "package", "descriptor",
                      "qualification", "same-instance", "payload-claim", "missing-current", "missing-baseline", "role", "native-bool"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); old, new = update_documents()
                if fault == "unknown": old["originalCalls"][1]["returned"] = False
                elif fault == "close": old["originalClosesKnown"] = False
                elif fault == "retired": new["targetRetired"] = False
                elif fault == "source": old["updateBaseline"]["source"] = "f" * 40
                elif fault == "baseline-invocation": new["positiveUpdate"]["baselineInvocation"] = "f" * 32
                elif fault == "package": new["positiveUpdate"]["predecessorPackageSha256"] = "f" * 64
                elif fault == "descriptor": new["positiveUpdate"]["currentDescriptorSha256"] = "f" * 64
                elif fault == "qualification": new["positiveUpdate"]["predecessorQualificationEvidenceSha256"] = "f" * 64
                elif fault == "same-instance": new["positiveUpdate"]["generationInstancesDistinct"] = False
                elif fault == "payload-claim": new["positiveUpdate"]["retainedPayloadRehashed"] = True
                elif fault == "missing-current": del new["positiveUpdate"]
                elif fault == "missing-baseline": del old["updateBaseline"]
                elif fault == "role": old["originalCalls"][1]["role"] = "installer"
                elif fault == "native-bool": old["originalCalls"][1]["returncode"] = False
                write_update_documents(root, (old, new))
                if fault == "status": write(root, "update-baseline.status", b"1\n")
                if fault == "status-bool": write(root, "update-baseline.status", b"false\n")
                result = project(root)
                self.assertNotEqual(result["positiveUpdate"]["receiptState"], "observed")
                self.assertNotIn(SENTINEL, (root / DATA.OUTPUT).read_text())

    def test_full_preview_original_rosters_fit_fixed_public_output_bound(self):
        def literals(path, names):
            module = ast.parse(path.read_text())
            return {node.targets[0].id: ast.literal_eval(node.value) for node in module.body
                    if isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name) and node.targets[0].id in names}
        fixed = literals(ROOT / "desktop/tools/macos_android_helper_package.py",
                         {"PREPARE_ROLES", "CREDENTIAL_ROLES", "SIGNING_PHASES", "NOTARY_ROLES",
                          "FINAL_PACKAGE_ROLES", "FINAL_IMAGE_ROLES", "INSTALLER_CREDENTIAL_ROSTER", "REMOVE_PACKAGE_ROLES"})
        package = literals(ROOT / "desktop/tools/stage_macos_installed.py", {"PACKAGING_CALL_ROLES"})["PACKAGING_CALL_ROLES"]
        self.assertEqual(len(package), 16)
        self.assertEqual(package[:3], ("producer-tests", "producer-build", "producer-emitter"))
        failed_fetch = DATA.project_calls([{"role": "resident-fetch", "entered": True, "returned": False,
            "capturesSettled": False, "dispatched": True, "contained": True, "cleanup_complete": True,
            "originalFailure": {"available": True, "ownerErrorType": "ProcessError", "classification": "deadline",
                                "timeoutSeconds": 120, "outputLimitBytes": 4 * 1024 * 1024}, "raw": SENTINEL}])
        self.assertEqual((failed_fetch["recordedCount"], failed_fetch["unclassifiedCount"]), (1, 0))
        self.assertEqual(failed_fetch["calls"][0]["role"], "resident-fetch")
        self.assertEqual(failed_fetch["calls"][0]["originalFailure"]["timeoutSeconds"], 120)
        self.assertNotIn(SENTINEL, json.dumps(failed_fetch))
        application = fixed["CREDENTIAL_ROLES"][:17] + ("search-final", "default-after")
        ad_hoc = ("producer-adhoc", "producer-adhoc-verify", "producer-cdhash")
        roster = {
            "prepare": (("resident-fetch",) + fixed["PREPARE_ROLES"], application * 2, 2),
            "verify-before": (("verify-before", "verify-before-resident-image", "verify-before-history-provider", "verify-before-github-seal"), (), 0),
            "verify-after": (("verify-after", "verify-after-resident-image", "verify-after-history-provider", "verify-after-github-seal"), (), 0),
            **{phase: ((phase, phase + "-verify"), application, 1) for phase in fixed["SIGNING_PHASES"]},
            "notarize-payload": (fixed["NOTARY_ROLES"], (), 0),
            "finalize-package": (("final-package-productbuild",) + fixed["FINAL_PACKAGE_ROLES"], fixed["INSTALLER_CREDENTIAL_ROSTER"], 1),
            "package-install": (package, ad_hoc + application * 3, 3),
            "finalize-image": (fixed["FINAL_IMAGE_ROLES"], (), 0),
            "finalize-remove-package": (fixed["FINAL_PACKAGE_ROLES"], fixed["INSTALLER_CREDENTIAL_ROSTER"], 1),
            "package-remove": (fixed["REMOVE_PACKAGE_ROLES"], ad_hoc + application * 2, 2),
            "finalize-remove-image": (fixed["FINAL_IMAGE_ROLES"], (), 0),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for phase, (native, credentials, contexts) in roster.items():
                value = receipt(phase); del value["finalImage"]
                value["originalCalls"] = [{"role": role, "entered": True, "returned": True, "capturesSettled": True,
                    "returncode": 0, "stdoutSha256": "a" * 64, "stderrSha256": "b" * 64} for role in native]
                value["credentialOriginals"] = [{"role": role, "entered": True, "returned": True, "settled": True,
                    "status": 0} for role in credentials]
                value["credentialContexts"] = [{"purpose": "installer", "retired": True, "closed": True,
                    "searchRestored": True, "defaultUnchanged": True} for _ in range(contexts)]
                # Conservative all-allowlisted finite final fields, beyond each
                # genuine sparse writer, plus every actual native/credential row.
                final = {**{key: True for key in DATA.FINAL_BOOLS}, **{key: "c" * 64 for key in DATA.FINAL_HASHES},
                         **{key: 4096 for key in DATA.FINAL_SIZES}, "submissionId": value["notarySubmission"]["id"],
                         "status": "Accepted", "errorCount": 0, "warningCount": 2048, "ticketRowCount": 2048}
                if phase == "notarize-payload":
                    value["payloadNotarization"] = final
                elif phase in ("finalize-package", "finalize-remove-package", "package-install", "package-remove"):
                    value["finalPackage"] = {**final, "schemaVersion": 1, "kind":
                        "mrk-final-remover-package" if "remove" in phase else "mrk-final-installer-package"}
                elif phase in ("finalize-image", "finalize-remove-image"):
                    value["finalImage"] = {**final, "schemaVersion": 1, "kind":
                        "mrk-final-removal-image" if "remove" in phase else "mrk-final-user-image"}
                body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
                self.assertLessEqual(len(body), 16384)
                write(root, "android-helper-" + phase + ".json", body)
            for name in DATA.STATUS_FILES:
                write(root, name, b"0\n")
            # Conservative simultaneous maxima (beyond the genuine mutually
            # exclusive failure paths) must still fit alongside full preview.
            normal = normal_diagnostic_data()
            write(root, "normal-ui/build.status", b"70\n")
            for role, path in DATA.UI_DIAGNOSTICS:
                if role == "admission":
                    diagnostic = admission_diagnostic(normal)
                    diagnostic["sourceFrames"] *= 4
                    diagnostic["commands"] *= 16
                    diagnostic["ownerDiagnostic"] = {"reason": "command-failed-or-incomplete", "failureMask": 63}
                    diagnostic["sourceFramesTruncated"] = True
                else:
                    diagnostic = build_diagnostic(normal, "build" if role == "build" else "query")
                    diagnostic["errorCodes"] = [{"stream": "stderr", "domain": "IDETestOperationsObserverErrorDomain",
                        "code": -2147483648 + index} for index in range(8)]
                    diagnostic["queryObservations"] = [{"stream": "stderr", "kind": "dashboard",
                        "observation": "containingSameStaticText", "matches": 5, "exceedsFour": True,
                        "nonAtomic": True} for _ in range(4)]
                    if role == "build":
                        terms_raw = (b'Ineligible destinations for the "MRKNormalAppUI" scheme:\n'
                            b'{ platform:macOS, arch:x86_64h, name:PRIVATE, error:architectures platforms macOS Xcode SDKs deployment versions supports installed }\n')
                        terms_value = normal["normal_failure_diagnostics"]("build", None, CompletedProcess([], 70, terms_raw, b""))
                        diagnostic["destinationTable"] = terms_value["destinationTable"]
                        self.assertEqual(len(diagnostic["destinationTable"]["rows"][0]["errorTerms"]), 9)
                        diagnostic["buildFailureReasons"] = [{"stream": stream, "code": code}
                            for stream in ("stdout", "stderr") for code in ("destination-not-found", "no-eligible-destination")]
                        diagnostic["compilerDiagnostics"] = [{"stream": "stderr", "source": "NormalAppUITests.swift",
                            "line": 65535 - index, "column": 4096, "severity": "error",
                            "reasonCodes": ["ambiguous-overload", "missing-argument", "actor-isolation"]} for index in range(4)]
                body = json.dumps(diagnostic, sort_keys=True, separators=(",", ":")).encode()
                self.assertLessEqual(len(body), 4096)
                write(root, path, body)
            stager, helper = removal_data()
            removal = removal_receipt("ordinary", stager, helper, normal_diagnostic_data(removal=True))
            write(root, "android-helper-package-removal-fixture.json", removal)
            diagnostic_data, diagnostic_names = data_contract_diagnostics()
            longest = sorted(diagnostic_names, key=len, reverse=True)[:16]
            failure = data_contract_failure(diagnostic_data, diagnostic_names, failed_names=longest)
            self.assertEqual(len(failure["python"]["failureTests"]), 16)
            write(root, "data-contracts/failure-diagnostics.json", failure)
            write(root, "data-contracts/python.status", b"1\n")
            write(root, "android-helper-same-package-noop.json", same_package_receipt())
            write(root, "same-package-noop.status", b"0\n")
            result = project(root, removal_case="ordinary")
            self.assertEqual(result["phases"]["same-package-noop"]["receiptState"], "observed")
            self.assertEqual(result["dataContractFailure"]["receiptState"], "observed")
            self.assertEqual(len(result["dataContractFailure"]["python"]["failureTests"]), 16)
            for phase in roster:
                self.assertEqual(result["phases"][phase]["receiptState"], "observed", phase)
                self.assertIs(result["phases"][phase]["recordedPassed"], True, phase)
                self.assertEqual(result["phases"][phase]["originalCalls"]["unclassifiedCount"], 0, phase)
                self.assertEqual(result["phases"][phase]["originalCalls"]["recordedCount"], len(roster[phase][0]))
            for phase in ("finalize-image", "finalize-remove-image"):
                self.assertEqual(result["phases"][phase]["originalCalls"]["recordedCount"], 13)
                self.assertIs(result["phases"][phase]["finalImage"]["assessmentSubsystemEnabledBefore"], True)
                self.assertIs(result["phases"][phase]["finalImage"]["actualDiskImagePolicyAssessment"], True)
            self.assertTrue(all(row["receiptState"] == "observed" for row in result["normalUiBuildDiagnostics"].values()))
            self.assertEqual(result["phases"]["package-removal-fixture"]["originalCalls"]["recordedCount"], 9)
            self.assertEqual(result["phases"]["package-removal-fixture"]["removalFixture"]["case"], "ordinary")
            self.assertLessEqual((root / DATA.OUTPUT).stat().st_size, DATA.OUTPUT_LIMIT)
            # Intel-only settings are independently validated under their own
            # parent/build tuple. This combined ARM+Intel object is ONLY an
            # inert conservative byte budget, never one semantically valid run.
            settings, intel_build, intel_status, intel_context = build_settings_fixture(normal)
            intel_build = DATA.project_ui_diagnostic(intel_build, "build", intel_status)
            projected = DATA.project_build_settings(settings, intel_context, intel_status, intel_build)
            self.assertEqual(projected["receiptState"], "observed")
            self.assertEqual(len(projected["settings"]), 9)
            combined_budget_only = {**result, "buildSettingsDiagnostic": projected}
            # Also reserve the opaque tuple beside the largest Python facts as
            # a conservative byte-only union, never a genuine mixed-phase row.
            combined_budget_only["dataContractFailure"] = {**result["dataContractFailure"],
                "rustPanicDiagnostic": {"parseState": "unmapped-source", "spellingSha256": "f" * 64,
                                        "line": 1000000, "column": 1000000}}
            # The optional fixture route is exclusive with ordinary preview.
            # Add its complete genuine-writer projection to the dense old report
            # as a conservative byte-only union, not a claim of one valid run.
            with tempfile.TemporaryDirectory() as fixture_directory:
                fixture_root = Path(fixture_directory)
                write_app_absence_documents(fixture_root, app_absence_documents())
                fixture_report = project(fixture_root)
                self.assertIs(fixture_report["appAbsence"]["proofComplete"], True)
                self.assertEqual(fixture_report["appAbsence"]["nativeCalls"], {"prepare": 7, "baseline": 21, "restore": 5})
                combined_budget_only["appAbsence"] = fixture_report["appAbsence"]
                # Retain all old package facts/calls AND reserve the complete
                # additional twenty-one-call baseline; do not replace old coverage.
                combined_budget_only["additionalAppAbsenceBaselineBudgetOnly"] = fixture_report["phases"]["package-install"]
                self.assertEqual(combined_budget_only["additionalAppAbsenceBaselineBudgetOnly"]["originalCalls"]["recordedCount"], 21)
            # Reserve the exclusive update route as another conservative byte
            # union without deleting/replacing any dense prior facts or calls.
            with tempfile.TemporaryDirectory() as update_directory:
                update_root = Path(update_directory)
                write_update_documents(update_root, update_documents())
                update_report = project(update_root)
                self.assertEqual(update_report["positiveUpdate"]["receiptState"], "observed")
                combined_budget_only["positiveUpdate"] = update_report["positiveUpdate"]
                combined_budget_only["additionalUpdateBaselineBudgetOnly"] = update_report["phases"]["update-baseline"]
                # P1 reuses the existing package-install phase, not a second
                # sixteen-call installation. Prove the old dense common-field
                # quote covers the genuine current writer before reserving only
                # its complete new observation. Every old fact remains below.
                current = update_report["phases"]["package-install"]
                dense = result["phases"]["package-install"]
                self.assertEqual(set(current), set(dense))
                self.assertEqual(current["originalCalls"], dense["originalCalls"])
                self.assertEqual(current["originalCalls"]["recordedCount"], 16)
                def common_bytes(row):
                    return (json.dumps({key: value for key, value in row.items() if key != "updateObservation"},
                        sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
                self.assertLessEqual(len(common_bytes(current)), len(common_bytes(dense)))
                combined_budget_only["additionalUpdateObservationBudgetOnly"] = current["updateObservation"]
            encoded = (json.dumps(combined_budget_only, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()
            self.assertLessEqual(len(encoded), DATA.OUTPUT_LIMIT)

    def test_fixed_roster_preserves_originals_and_independent_failure_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = write(root, "source-binding.json", SENTINEL.encode())
            raw_log = write(root, "android-helper-final-image-log.stdout", SENTINEL.encode())
            value = receipt(); value["runAttempt"] = "99"
            original = write(root, "android-helper-finalize-image.json", value)
            before = original.read_bytes()
            write(root, "image-finalization.status", b"13\n")
            fixed_statuses = (
                ("normal-ui/workflow-refusal-test.status", b"0\n", {"receiptState": "observed", "returncode": 0}),
                ("normal-ui/workflow-refusal-summary.status", b"13\n", {"receiptState": "observed", "returncode": 13}),
                ("normal-ui/release-evidence-test.status", b"-15\n", {"receiptState": "observed", "returncode": -15}),
                ("normal-ui/release-evidence-summary.status", b"unavailable\n", {"receiptState": "refused"}),
            )
            fixed_names = tuple(name for name, _, _ in fixed_statuses)
            self.assertEqual(tuple(name for name in DATA.STATUS_FILES if name in fixed_names), fixed_names)
            fixed_originals = [(write(root, name, body), body) for name, body, _ in fixed_statuses]
            result = project(root)
            phase = result["phases"]["finalize-image"]
            self.assertEqual(phase["receiptState"], "refused")
            self.assertNotIn("recordedPassed", phase)
            self.assertEqual(phase["callerStatus"], {"receiptState": "observed", "returncode": 13})
            self.assertEqual(result["statuses"]["package-install.status"], {"receiptState": "absent"})
            for (name, _, expected), (path, body) in zip(fixed_statuses, fixed_originals, strict=True):
                self.assertEqual(result["statuses"][name], expected)
                self.assertEqual(path.read_bytes(), body)
            self.assertEqual(original.read_bytes(), before)
            self.assertEqual(private.read_bytes(), SENTINEL.encode())
            self.assertEqual(raw_log.read_bytes(), SENTINEL.encode())
            output = root / DATA.OUTPUT
            self.assertNotIn(SENTINEL.encode(), output.read_bytes())
            self.assertNotIn(str(root).encode(), output.read_bytes())
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertLessEqual(output.stat().st_size, DATA.OUTPUT_LIMIT)
            self.assertIs(result["diagnosticOnly"], True)
            self.assertIs(result["productReady"], False)
            saved = output.read_bytes()
            with self.assertRaises(FileExistsError):
                project(root)
            self.assertEqual(output.read_bytes(), saved)

    def test_invalid_scalar_statuses_are_never_success(self):
        for body in (b"", b"0", b"00\n", b"True\n", b"0 0 0\n", b"65536\n", b"-65537\n", SENTINEL.encode()):
            with self.subTest(body=body), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); write(root, "image-finalization.status", body)
                self.assertEqual(project(root)["statuses"]["image-finalization.status"], {"receiptState": "refused"})

    def test_linked_receipts_and_oversize_inputs_are_not_admitted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = write(root, "unread-private", SENTINEL.encode())
            os.link(original, root / "android-helper-finalize-image.json")
            write(root, "android-helper-finalize-package.json", b"x" * 16385)
            os.symlink("unread-private", root / "android-helper-prepare.json")
            result = project(root)
            for phase in ("prepare", "finalize-package", "finalize-image"):
                self.assertEqual(result["phases"][phase]["receiptState"], "refused")
            self.assertEqual(original.read_bytes(), SENTINEL.encode())

    def test_delivery_projection_excludes_guide_text_and_unknown_fields(self):
        value = {"schemaVersion": 2, "scope": "normal-macos-early-preview", "sourceCommit": CONTEXT["source"],
                 "sourceTree": "4" * 40, "runId": "123", "runAttempt": "2", "platform": "macOS26-arm64",
                 "distributionSha256": "5" * 64, "originalImageFinalizationReturnedZero": True,
                 "guide": SENTINEL, "error": SENTINEL}
        observed = DATA.project_summary(value, CONTEXT, False)
        self.assertNotIn(SENTINEL, json.dumps(observed))
        self.assertIs(observed["originalImageFinalizationReturnedZero"], True)
        self.assertIsNone(observed.get("originalInstallerReturnedZero"))
        value["platform"] = "macOS26-x86_64"
        with self.assertRaises(DATA.Refused):
            DATA.project_summary(value, CONTEXT, False)

    def test_genuine_destination_table_projection_preserves_partial_observations_only(self):
        normal = normal_diagnostic_data()
        status = {"receiptState": "observed", "returncode": 70}
        header = b'Available destinations for the "MRKNormalAppUI" scheme:\n'
        good = b'{ platform:macOS, arch:x86_64, name:' + SENTINEL.encode() + b' }\n'
        for raw in (b'', header, header + good, header + b'{ platform:iOS, name:unknown }\n',
                    header + b'{ platform:macOS }\n', header + good * 9,
                    header + good.rstrip(b'\n')):
            original = CompletedProcess([], 70, raw, b'')
            value = normal["normal_failure_diagnostics"]("build", None, original)
            row = DATA.project_ui_diagnostic(value, "build", status)
            self.assertEqual(row["destinationTable"], value["destinationTable"])
            self.assertEqual(row["originalReturncode"], 70)
            self.assertEqual(row["binding"], "same-work-root-parent-context-only")
            self.assertIs(row["nativeSuccessInferred"], False)
            self.assertNotIn(SENTINEL, json.dumps(row))
        value = normal["failure_base"]("build", None, CompletedProcess([], 70, b'', b''))
        self.assertEqual(DATA.project_ui_diagnostic(value, "build", status)["destinationTable"]["state"], "unavailable")
        value.pop("destinationTable")
        self.assertNotIn("destinationTable", DATA.project_ui_diagnostic(value, "build", status))

    def test_destination_table_public_schema_is_optional_typed_and_closed(self):
        normal = normal_diagnostic_data()
        status = {"receiptState": "observed", "returncode": 70}
        original = CompletedProcess([], 70, b'Available destinations for the "MRKNormalAppUI" scheme:\n'
            b'{ platform:macOS, name:Any Mac }\n', b'')
        value = normal["normal_failure_diagnostics"]("build", None, original)
        table = value["destinationTable"]
        row = table["rows"][0]
        for key, bad in (("stream", SENTINEL), ("stream", True), ("section", SENTINEL), ("section", 1),
                         ("platform", "iOS"), ("platform", None), ("architecture", "future-arch"), ("architecture", False),
                         ("errorPresent", 1), ("errorPresent", None), ("name", SENTINEL)):
            broken = copy.deepcopy(value); broken["destinationTable"]["rows"] = [{**row, key: bad}]
            with self.subTest(key=key, bad=bad), self.assertRaises(DATA.Refused):
                DATA.project_ui_diagnostic(broken, "build", status)
        for bad in (None, [], {}, {**table, "state": SENTINEL}, {**table, "state": True},
                    {**table, "state": "absent"}, {**table, "state": "unavailable"},
                    {**table, "rows": [row] * 9}, {**table, "rows": [None]}, {**table, "rows": None},
                    {**table, "unknownRowObserved": 1}, {**table, "malformedRowObserved": None},
                    {**table, "rowsTruncated": 1}, {**table, "rowsTruncated": True},
                    {**table, "complete": True}, {**table, "error": SENTINEL}):
            broken = copy.deepcopy(value); broken["destinationTable"] = bad
            with self.subTest(table=bad), self.assertRaises(DATA.Refused):
                DATA.project_ui_diagnostic(broken, "build", status)
        for state in ("absent", "unavailable"):
            for flag in ("unknownRowObserved", "malformedRowObserved", "rowsTruncated"):
                broken = copy.deepcopy(value); broken["findingsTruncated"] = True
                broken["destinationTable"] = {**table, "state": state, "rows": [], flag: True}
                with self.subTest(state=state, flag=flag), self.assertRaises(DATA.Refused):
                    DATA.project_ui_diagnostic(broken, "build", status)
        query = build_diagnostic(normal, "query"); query["destinationTable"] = table
        with self.assertRaises(DATA.Refused):
            DATA.project_ui_diagnostic(query, "toolchain", status)
        with self.assertRaises(DATA.Refused):
            DATA.project_ui_diagnostic(value, "build", {"receiptState": "observed", "returncode": 0})

    def test_destination_table_fixed_file_projection_keeps_full_eight_rows_and_status70(self):
        normal = normal_diagnostic_data()
        header = b'Ineligible destinations for the "MRKNormalAppUI" scheme:\n'
        raw = header + (b'{ platform:macOS, arch:arm64, id:' + SENTINEL.encode()
                        + b', name:Private Mac, error:' + SENTINEL.encode() + b' }\n') * 8
        value = normal["normal_failure_diagnostics"]("build", None, CompletedProcess([], 70, b'', raw))
        self.assertEqual(len(value["destinationTable"]["rows"]), 8)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write(root, "normal-ui/build.failure-diagnostics.json", value)
            before = path.read_bytes()
            self.assertLessEqual(len(before), 4096)
            write(root, "normal-ui/build.status", b"70\n")
            result = project(root)
            observed = result["normalUiBuildDiagnostics"]["build"]
            self.assertEqual(observed["receiptState"], "observed")
            self.assertEqual(observed["destinationTable"], value["destinationTable"])
            self.assertEqual(observed["originalReturncode"], 70)
            self.assertIs(observed["nativeSuccessInferred"], False)
            self.assertEqual(path.read_bytes(), before)
            self.assertNotIn(SENTINEL.encode(), (root / DATA.OUTPUT).read_bytes())
            self.assertLessEqual((root / DATA.OUTPUT).stat().st_size, DATA.OUTPUT_LIMIT)


    def test_data_contract_failure_genuine_python_rows_and_context(self):
        data, names = data_contract_diagnostics()
        self.assertEqual(DATA.DATA_CONTRACT_TEST_IDS, tuple(names))
        self.assertEqual(DATA.DATA_CONTRACT_GUARDS, set(data["DATA_FAILURE_GUARDS"].values()) | {"unclassified"})
        failures = [(SimpleNamespace(id=lambda name=name: name), SENTINEL) for name in names]
        errors = [(SimpleNamespace(id=lambda name=name: name), SENTINEL) for name in names]
        unknown = (SimpleNamespace(id=lambda: names[0] + " (private=" + SENTINEL + ")"), SENTINEL)
        facts = dict(testsRun=84, failures=85, errors=84, skipped=0, expectedFailures=0, unexpectedSuccesses=0,
            actualHostBeforeAndAfter=False, testIds=names,
            **data["data_failed_test_rows"](failures + [unknown], errors, names))
        value = data_contract_failure(data, names, raw=json.dumps(facts).encode())
        row = DATA.project_data_contract_failure(value, CONTEXT, {
            "data-contracts/python.status": {"receiptState": "observed", "returncode": 1}}, set())
        self.assertEqual(row["python"], value["python"])
        self.assertEqual((len(row["python"]["failureTests"]), row["python"]["classifiedTestCount"],
                          row["python"]["omittedTestCount"], row["python"]["unclassifiedTestCount"]), (16, 168, 152, 1))
        self.assertIs(row["python"]["actualHostBeforeAndAfter"], False)
        self.assertIs(row["statusMatched"], True)
        self.assertIs(row["nativeSuccessInferred"], False)
        self.assertEqual(row["binding"], "same-source-run-target-context")
        self.assertNotIn(SENTINEL, json.dumps(row))
        for key in ("source", "workflowSource", "runId", "runAttempt", "target"):
            broken = copy.deepcopy(value); broken[key] = "2" * 40 if key.endswith("ource") else "wrong"
            with self.subTest(key=key), self.assertRaises(DATA.Refused):
                DATA.project_data_contract_failure(broken, CONTEXT, {}, set())

    def test_data_contract_failure_phase_capture_and_scalar_observations(self):
        data, names = data_contract_diagnostics()
        for phase in DATA.DATA_CONTRACT_PHASES:
            for code in (-15, 0, 1):
                value = data_contract_failure(data, names, phase=phase, code=code, guard="source-post", failed_names=[])
                status_name = "data-contracts/" + phase + ".status"
                for state in ("observed", "absent", "refused"):
                    status = {"receiptState": state, **({"returncode": code} if state == "observed" else {})}
                    row = DATA.project_data_contract_failure(value, CONTEXT, {status_name: status}, set())
                    self.assertEqual(row["originalReturncode"], code)
                    self.assertEqual(row["callerStatus"], status)
                    self.assertIs(row["statusMatched"], True if state == "observed" else None)
                    self.assertIs(row["nativeSuccessInferred"], False)
                with self.assertRaises(DATA.Refused):
                    DATA.project_data_contract_failure(value, CONTEXT, {
                        status_name: {"receiptState": "observed", "returncode": code + 1}}, set())
        complete = data_contract_failure(data, names)
        for flag, observed in (("originalReturned", False), ("outputComplete", False), ("captureClosed", False),
                               ("timedOut", True), ("outputOverflow", True)):
            value = data_contract_failure(data, names, code=None if flag == "originalReturned" else 1, flags={flag: observed})
            row = DATA.project_data_contract_failure(value, CONTEXT, {}, set())
            self.assertIsNone(row["python"])
            self.assertIs(row[flag], observed)
            self.assertIsNone(row["statusMatched"])
            value["python"] = complete["python"]
            with self.assertRaises(DATA.Refused):
                DATA.project_data_contract_failure(value, CONTEXT, {}, set())

    def test_data_contract_failure_cargo_sources_require_validated_inventory(self):
        data, names = data_contract_diagnostics()
        path = "desktop/src-tauri/src/bin/macos_install.rs"
        def message(name, code="E0123", line=12):
            return {"reason": "compiler-message", "manifest_path": "/public/checkout/desktop/src-tauri/Cargo.toml",
                "message": {"level": "error", "message": SENTINEL, "rendered": SENTINEL, "code": {"code": code},
                    "spans": [{"is_primary": True, "file_name": name, "line_start": line, "column_start": 7}]}}
        raw = b"\n".join(json.dumps(message("src/bin/macos_install.rs", "E%04d" % index)).encode() for index in range(8))
        value = data_contract_failure(data, names, phase="build", raw=raw, source_paths={path})
        inventory = {"source": CONTEXT["source"], "tree": "2" * 40, "files": [
            {"path": path, "gitMode": "100644", "blob": "3" * 40, "size": 1, "sha256": "4" * 64}]}
        paths = set()
        DATA.project_inventory(inventory, json.dumps(inventory).encode(), CONTEXT, collect_paths=paths)
        row = DATA.project_data_contract_failure(value, CONTEXT, {}, paths)
        self.assertEqual(len(row["cargo"]["errors"]), 8)
        self.assertTrue(all(error["source"] == path for error in row["cargo"]["errors"]))
        self.assertNotIn(SENTINEL, json.dumps(row))
        redacted = DATA.project_data_contract_failure(value, CONTEXT, {}, set())
        self.assertTrue(all(error["source"] is error["line"] is error["column"] is None for error in redacted["cargo"]["errors"]))
        self.assertEqual([error["code"] for error in redacted["cargo"]["errors"]], ["E%04d" % n for n in range(8)])
        broken_inventory = copy.deepcopy(inventory)
        broken_inventory["files"].append({**inventory["files"][0], "path": "other", "sha256": SENTINEL})
        paths = set()
        with self.assertRaises(DATA.Refused):
            DATA.project_inventory(broken_inventory, b"synthetic", CONTEXT, collect_paths=paths)
        self.assertEqual(paths, set())  # Earlier valid row cannot escape failed whole-inventory validation.
        other = "desktop/src-tauri/src/other.rs"
        raw = b"\n".join(json.dumps(message(name)).encode() for name in (path, other))
        value = data_contract_failure(data, names, phase="build", raw=raw, source_paths={path, other})
        row = DATA.project_data_contract_failure(value, CONTEXT, {}, set())
        self.assertEqual(len(row["cargo"]["errors"]), 2)
        self.assertEqual(row["cargo"]["errors"][0], row["cargo"]["errors"][1])  # No post-redaction dedup/count invention.
        value["cargo"]["errors"][1] = copy.deepcopy(value["cargo"]["errors"][0])
        with self.assertRaises(DATA.Refused):
            DATA.project_data_contract_failure(value, CONTEXT, {}, set())

    def test_data_contract_failure_rust_site_is_inventory_bound_observation(self):
        data, names = data_contract_diagnostics()
        site = "desktop/src-tauri/src/shell/installed_observation.rs"
        stderr = ("thread 'main' (123) panicked at tests/../src/shell/installed_observation.rs:12:7:\n" + SENTINEL).encode()
        value = data_contract_failure(data, names, phase="rust", code=101, stderr=stderr, source_paths={site})
        statuses = {"data-contracts/rust.status": {"receiptState": "observed", "returncode": 101}}
        row = DATA.project_data_contract_failure(value, CONTEXT, statuses, {site})
        self.assertEqual(row["rustPanic"], {"source": site, "line": 12, "column": 7})
        spelling = "tests/../src/shell/installed_observation.rs"
        expected = {"parseState": "observed", "spellingSha256": hashlib.sha256(spelling.encode()).hexdigest(),
                    "line": 12, "column": 7}
        self.assertEqual(row["rustPanicDiagnostic"], expected)
        self.assertEqual(row["receiptState"], "observed")
        self.assertIs(row["statusMatched"], True)
        self.assertIs(row["nativeSuccessInferred"], False)
        self.assertNotIn(SENTINEL, json.dumps(row))
        redacted = DATA.project_data_contract_failure(value, CONTEXT, statuses, set())
        self.assertIsNone(redacted["rustPanic"])
        self.assertIsNone(redacted["rustPanicDiagnostic"])
        # A tuple is not an admitted inventory; the fixture default is an empty frozenset.
        self.assertEqual(data["data_failure_rust_panic_diagnostic"](stderr, (), "/public/checkout"),
            {"parseState": "input-invalid", "spellingSha256": None, "line": None, "column": None})
        unknown = "/outside/checkout/unknown.rs"
        unlisted = data_contract_failure(data, names, phase="rust", code=101,
            stderr=("thread 'main' panicked at " + unknown + ":1000000:1000000:\n" + SENTINEL).encode())
        unlisted_row = DATA.project_data_contract_failure(unlisted, CONTEXT, statuses, set())
        self.assertIsNone(unlisted_row["rustPanic"])
        self.assertEqual(unlisted_row["rustPanicDiagnostic"], {"parseState": "unmapped-source",
            "spellingSha256": hashlib.sha256(unknown.encode()).hexdigest(), "line": 1000000, "column": 1000000})
        self.assertNotIn(unknown, json.dumps(unlisted_row)); self.assertNotIn(SENTINEL, json.dumps(unlisted_row))
        for bad in ({}, {**expected, "parseState": "other"}, {**expected, "parseState": []},
                    {**expected, "spellingSha256": "A" * 64}, {**expected, "spellingSha256": "f" * 63},
                    {**expected, "spellingSha256": None}, {**expected, "line": True},
                    {**expected, "line": 0}, {**expected, "column": 1000001},
                    {**expected, "column": 8}, {**expected, "message": SENTINEL},
                    {**expected, "parseState": "unmapped-source"},
                    {"parseState": "header-format", "spellingSha256": None, "line": None, "column": None}):
            broken = copy.deepcopy(value); broken["rustPanicDiagnostic"] = bad
            with self.subTest(diagnostic=bad), self.assertRaises(DATA.Refused):
                DATA.project_data_contract_failure(broken, CONTEXT, statuses, {site})
        broken = copy.deepcopy(unlisted); broken["rustPanicDiagnostic"]["parseState"] = "observed"
        with self.assertRaises(DATA.Refused):
            DATA.project_data_contract_failure(broken, CONTEXT, statuses, set())
        for state in ("input-invalid", "empty", "bounds", "header-missing", "header-multiple", "header-format", "coordinate-range"):
            refusal = copy.deepcopy(unlisted)
            refusal["rustPanicDiagnostic"] = {"parseState": state, "spellingSha256": None, "line": None, "column": None}
            self.assertEqual(DATA.project_data_contract_failure(refusal, CONTEXT, statuses, set())["rustPanicDiagnostic"],
                             refusal["rustPanicDiagnostic"])
            for key, bad in (("spellingSha256", "f" * 64), ("line", 1), ("column", 1)):
                broken = copy.deepcopy(refusal); broken["rustPanicDiagnostic"][key] = bad
                with self.subTest(state=state, key=key), self.assertRaises(DATA.Refused):
                    DATA.project_data_contract_failure(broken, CONTEXT, statuses, set())
        for key, bad in (("phase", "python"), ("originalReturncode", 0), ("originalReturned", False),
                         ("outputComplete", False), ("captureClosed", False), ("timedOut", True),
                         ("outputOverflow", True), ("source", "b" * 40), ("workflowSource", "b" * 40),
                         ("runId", "999"), ("runAttempt", "3"), ("target", "x86_64-apple-darwin")):
            self.assertNotEqual(unlisted[key], bad, "binding mutation must change the fixture")
            broken = copy.deepcopy(unlisted); broken[key] = bad
            with self.subTest(diagnostic_binding=key), self.assertRaises(DATA.Refused):
                DATA.project_data_contract_failure(broken, CONTEXT, {}, set())
        for bad in ({}, {"source": site, "line": True, "column": 7},
                    {"source": site, "line": 0, "column": 7}, {"source": site, "line": 12, "column": 1000001},
                    {"source": site, "line": 12, "column": 7, "message": SENTINEL},
                    {"source": "tests/../src/shell/installed_observation.rs", "line": 12, "column": 7},
                    {"source": "desktop/src-tauri/src/../shell.rs", "line": 12, "column": 7},
                    {"source": "/private/file.rs", "line": 12, "column": 7},
                    {"source": "desktop/src-tauri/src/file name.rs", "line": 12, "column": 7},
                    {"source": "desktop/src-tauri/src/file.py", "line": 12, "column": 7}):
            broken = copy.deepcopy(value); broken["rustPanic"] = bad
            with self.subTest(site=bad), self.assertRaises(DATA.Refused):
                DATA.project_data_contract_failure(broken, CONTEXT, {}, {site})
        for key, bad in (("phase", "python"), ("originalReturncode", 0), ("originalReturncode", 1),
                         ("stderrBytes", 0), ("originalReturned", False), ("outputComplete", False),
                         ("captureClosed", False), ("timedOut", True), ("outputOverflow", True)):
            broken = copy.deepcopy(value); broken[key] = bad
            with self.subTest(key=key), self.assertRaises(DATA.Refused):
                DATA.project_data_contract_failure(broken, CONTEXT, {}, {site})
        legacy = copy.deepcopy(value); del legacy["rustPanicDiagnostic"]
        self.assertIsNone(DATA.project_data_contract_failure(legacy, CONTEXT, statuses, {site})["rustPanicDiagnostic"])
        del legacy["rustPanic"]
        old = DATA.project_data_contract_failure(legacy, CONTEXT, statuses, {site})
        self.assertIsNone(old["rustPanic"]); self.assertIsNone(old["rustPanicDiagnostic"])
        value["rustPanicDiagnostic"] = None
        self.assertIsNone(DATA.project_data_contract_failure(value, CONTEXT, statuses, {site})["rustPanicDiagnostic"])

    def test_data_contract_failure_closed_schema_and_bounds(self):
        data, names = data_contract_diagnostics()
        base = data_contract_failure(data, names)
        self.assertIsNone(base["rustPanic"])
        legacy = copy.deepcopy(base); del legacy["rustPanic"]
        self.assertIsNone(DATA.project_data_contract_failure(legacy, CONTEXT, {}, set())["rustPanic"])
        self.assertIsNone(base.get("rustPanicDiagnostic"))
        self.assertIsNone(DATA.project_data_contract_failure(legacy, CONTEXT, {}, set())["rustPanicDiagnostic"])
        legacy.pop("rustPanicDiagnostic", None)
        self.assertIsNone(DATA.project_data_contract_failure(legacy, CONTEXT, {}, set())["rustPanicDiagnostic"])
        for key in base.keys() - {"rustPanic", "rustPanicDiagnostic"}:
            value = copy.deepcopy(base); del value[key]
            with self.subTest(missing=key), self.assertRaises(DATA.Refused):
                DATA.project_data_contract_failure(value, CONTEXT, {}, set())
        for key, bad in (("schemaVersion", True), ("kind", SENTINEL), ("phase", None), ("phase", "other"),
                         ("originalReturncode", True), ("originalReturncode", 65536), ("originalReturncode", None),
                         ("originalReturned", 1), ("outputComplete", None), ("captureClosed", 0), ("timedOut", 1),
                         ("outputOverflow", 1), ("stdoutBytes", True), ("stderrBytes", 4194305),
                         ("stdoutSha256", SENTINEL), ("guardCode", SENTINEL), ("diagnosticOnly", False),
                         ("productReady", True), ("message", SENTINEL), ("cargo", {})):
            value = copy.deepcopy(base); value[key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(DATA.Refused):
                DATA.project_data_contract_failure(value, CONTEXT, {}, set())
        for key, bad in (("testsRun", 85), ("errors", True), ("actualHostBeforeAndAfter", 1),
                         ("classifiedTestCount", 169), ("omittedTestCount", 153), ("unclassifiedTestCount", 65536),
                         ("classifiedTestCount", 0), ("failures", 0), ("extra", SENTINEL),
                         ("failureTests", [{"kind": "failure", "id": SENTINEL}]),
                         ("failureTests", [{"kind": "other", "id": names[0]}]),
                         ("failureTests", base["python"]["failureTests"] * 17),
                         ("failureTests", base["python"]["failureTests"] * 2)):
            value = copy.deepcopy(base); value["python"][key] = bad
            with self.subTest(python=key, bad=bad), self.assertRaises(DATA.Refused):
                DATA.project_data_contract_failure(value, CONTEXT, {}, set())
        value = copy.deepcopy(base); value["python"] = None
        self.assertIsNone(DATA.project_data_contract_failure(value, CONTEXT, {}, set())["python"])
        value["python"] = {}
        with self.assertRaises(DATA.Refused):
            DATA.project_data_contract_failure(value, CONTEXT, {}, set())
        cargo = data_contract_failure(data, names, phase="build")
        good = {"code": "E0001", "source": None, "line": None, "column": None}
        cargo["cargo"] = {"errors": [good], "unclassifiedErrors": 0, "omittedErrors": 0}
        for bad in ({"errors": [good] * 9, "unclassifiedErrors": 0, "omittedErrors": 0},
                    {"errors": [good], "unclassifiedErrors": 4097, "omittedErrors": 0},
                    {"errors": [{**good, "code": SENTINEL}], "unclassifiedErrors": 0, "omittedErrors": 0},
                    {"errors": [{**good, "line": 1}], "unclassifiedErrors": 0, "omittedErrors": 0},
                    {"errors": [{**good, "source": "/private/file", "line": 1, "column": 1}], "unclassifiedErrors": 0, "omittedErrors": 0},
                    {"errors": [{**good, "source": "public/file", "line": True, "column": 1}], "unclassifiedErrors": 0, "omittedErrors": 0}):
            value = copy.deepcopy(cargo); value["cargo"] = bad
            with self.subTest(cargo=bad), self.assertRaises(DATA.Refused):
                DATA.project_data_contract_failure(value, CONTEXT, {}, set())

    def test_data_contract_failure_fixed_files_preserve_originals(self):
        data, names = data_contract_diagnostics()
        value = data_contract_failure(data, names, code=0, guard="source-post", failed_names=[])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sidecar = write(root, "data-contracts/failure-diagnostics.json", value)
            raw = [write(root, name, SENTINEL.encode()) for name in
                   ("data-contracts/result.json", "data-contracts/python.stdout", "data-contracts/python.stderr")]
            before = [path.read_bytes() for path in [sidecar] + raw]
            write(root, "data-contracts/python.status", b"0\n")
            result = project(root)
            row = result["dataContractFailure"]
            self.assertEqual(row["receiptState"], "observed")
            self.assertEqual(row["originalReturncode"], 0)
            self.assertIs(row["statusMatched"], True)
            self.assertIs(row["nativeSuccessInferred"], False)
            self.assertEqual([path.read_bytes() for path in [sidecar] + raw], before)
            self.assertNotIn(SENTINEL.encode(), (root / DATA.OUTPUT).read_bytes())
        site = "desktop/src-tauri/src/shell/installed_observation.rs"
        stderr = ("thread 'main' panicked at tests/../src/shell/installed_observation.rs:12:7:\n" + SENTINEL).encode()
        rust = data_contract_failure(data, names, phase="rust", code=101, stderr=stderr, source_paths={site})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sidecar = write(root, "data-contracts/failure-diagnostics.json", rust)
            inventory = write(root, "source-inventory.json", {"source": CONTEXT["source"], "tree": "2" * 40,
                "files": [{"path": site, "gitMode": "100644", "blob": "3" * 40, "size": 1, "sha256": "4" * 64}]})
            originals = [sidecar, inventory] + [write(root, name, body) for name, body in (
                ("data-contracts/rust.stdout", b""), ("data-contracts/rust.stderr", stderr),
                ("data-contracts/result.json", SENTINEL.encode()))]
            before = [path.read_bytes() for path in originals]
            write(root, "data-contracts/rust.status", b"101\n")
            row = project(root)["dataContractFailure"]
            self.assertEqual(row["receiptState"], "observed")
            self.assertEqual(row["rustPanic"], {"source": site, "line": 12, "column": 7})
            self.assertEqual(row["rustPanicDiagnostic"]["parseState"], "observed")
            self.assertIs(row["statusMatched"], True)
            self.assertIs(row["nativeSuccessInferred"], False)
            self.assertEqual([path.read_bytes() for path in originals], before)
            self.assertNotIn(SENTINEL.encode(), (root / DATA.OUTPUT).read_bytes())
        spelling = "tests/../src/unlisted.rs"
        opaque_stderr = ("thread 'main' panicked at " + spelling + ":12:7:\n" + SENTINEL).encode()
        opaque = data_contract_failure(data, names, phase="rust", code=101, stderr=opaque_stderr)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            originals = [write(root, "data-contracts/failure-diagnostics.json", opaque),
                         write(root, "data-contracts/rust.stderr", opaque_stderr)]
            before = [path.read_bytes() for path in originals]
            write(root, "data-contracts/rust.status", b"101\n")
            row = project(root)["dataContractFailure"]
            self.assertEqual(row["receiptState"], "observed"); self.assertIsNone(row["rustPanic"])
            self.assertEqual(row["rustPanicDiagnostic"], {"parseState": "unmapped-source",
                "spellingSha256": hashlib.sha256(spelling.encode()).hexdigest(), "line": 12, "column": 7})
            self.assertIs(row["statusMatched"], True); self.assertIs(row["nativeSuccessInferred"], False)
            self.assertEqual([path.read_bytes() for path in originals], before)
            public = (root / DATA.OUTPUT).read_bytes()
            self.assertNotIn(spelling.encode(), public); self.assertNotIn(SENTINEL.encode(), public)
        for raw in (b"{}", b"x" * 16385, b'{"schemaVersion":1,"schemaVersion":1}'):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory); write(root, "data-contracts/failure-diagnostics.json", raw)
                self.assertEqual(project(root)["dataContractFailure"], {"receiptState": "refused"})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = write(root, "data-contracts/failure-diagnostics.json", SENTINEL.encode())
            result = DATA.project(str(root), profile="aqua", source=CONTEXT["source"], workflow_source=CONTEXT["workflowSource"],
                run_id=CONTEXT["runId"], run_attempt=CONTEXT["runAttempt"], target=CONTEXT["target"])
            self.assertIsNone(result["dataContractFailure"])
            self.assertEqual(path.read_bytes(), SENTINEL.encode())



    def test_build_settings_genuine_tuple_and_enum_parity(self):
        normal = normal_diagnostic_data()
        for public, producer in (("BUILD_SETTINGS", "NORMAL_BUILD_SETTINGS"),
                ("BUILD_ARCHITECTURES", "NORMAL_BUILD_ARCHITECTURES"),
                ("BUILD_PLATFORMS", "NORMAL_BUILD_PLATFORMS"), ("DESTINATION_REJECTIONS", "DESTINATION_REJECTIONS")):
            self.assertEqual(getattr(DATA, public), normal[producer])
        self.assertEqual(DATA.UI_ADMISSION_ROLES, frozenset(normal["ADMISSION_COMMAND_ROLES"]))
        self.assertIn("normal-build-settings", DATA.UI_ADMISSION_ROLES)
        for state in ("observed", "nonzero", "malformed", "unavailable"):
            value, build, status, context = build_settings_fixture(normal, state)
            build = DATA.project_ui_diagnostic(build, "build", status)
            row = DATA.project_build_settings(value, context, status, build)
            self.assertEqual(row["receiptState"], "observed")
            self.assertEqual(row["settingsState"], state)
            self.assertEqual(row["originalBuildReturncode"], 70)
            self.assertEqual(row["sourceBinding"], "prior-build-source-pre-post-only")
            self.assertEqual(row["binding"], "same-work-root-parent-context-and-failed-build-captures")
            self.assertEqual(row["phaseFinality"], "not-asserted")
            self.assertIs(row["nativeSuccessInferred"], False); self.assertIs(row["productReady"], False)
            self.assertNotIn(SENTINEL, json.dumps(row))
            if state == "observed": self.assertEqual(len(row["settings"]), 9)
            else: self.assertIsNone(row["settings"])

    def test_build_settings_public_closed_schema_and_correlations(self):
        value, build, status, context = build_settings_fixture(normal_diagnostic_data())
        build = DATA.project_ui_diagnostic(build, "build", status)
        mutations = (("schemaVersion", True), ("target", "aarch64-apple-darwin"), ("sourceCommit", "2" * 40),
            ("originalBuildReturncode", 0), ("originalBuildReturncode", True),
            ("originalBuildStdoutSha256", "2" * 64), ("originalBuildStderrSha256", "3" * 64),
            ("hostVersion", SENTINEL), ("hostVersion", "25.0"), ("hostVersion", True),
            ("queryRole", SENTINEL), ("queryState", "not-returned"), ("queryReturncode", True),
            ("queryReturncode", 1), ("stdoutBytes", 0), ("stdoutBytes", True), ("stdoutBytes", 262145),
            ("stderrBytes", 262144), ("stdoutSha256", SENTINEL), ("stderrSha256", None),
            ("settingsState", "unavailable"), ("settings", None), ("sourceBinding", SENTINEL),
            ("phaseFinality", "settled"), ("nativeSuccessInferred", True), ("productReady", 0), ("extra", SENTINEL))
        for key, bad in mutations:
            broken = copy.deepcopy(value); broken[key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(DATA.Refused):
                DATA.project_build_settings(broken, context, status, build)
        for key in value:
            broken = dict(value); broken.pop(key)
            with self.subTest(missing=key), self.assertRaises(DATA.Refused):
                DATA.project_build_settings(broken, context, status, build)
        for field, bad in (("ARCHS", {"state": "observed", "value": ["x86_64", "PRIVATE"]}),
                ("VALID_ARCHS", {"state": "observed", "value": ["x86_64", "x86_64"]}),
                ("ONLY_ACTIVE_ARCH", {"state": "observed", "value": 1}),
                ("SDK_VERSION", {"state": "observed", "value": "26.0.0.0"}),
                ("NATIVE_ARCH_ACTUAL", {"state": "observed", "value": "i386"}),
                ("ARCHS", {"state": "absent", "value": []}),
                ("ARCHS", {"state": "unsupported", "value": False}),
                ("ARCHS", {"state": "observed", "value": [], "private": SENTINEL})):
            broken = copy.deepcopy(value); broken["settings"][field] = bad
            with self.subTest(field=field, bad=bad), self.assertRaises(DATA.Refused):
                DATA.project_build_settings(broken, context, status, build)
        for other_context, other_status, other_build in (({**context, "target": "aarch64-apple-darwin"}, status, build),
                (context, {"receiptState": "absent"}, build), (context, {**status, "returncode": 0}, build),
                (context, status, {"receiptState": "refused"}), (context, status, {**build, "phase": "query"}),
                (context, status, {**build, "stdoutSha256": "4" * 64}),
                (context, status, {**build, "stderrSha256": "4" * 64})):
            with self.assertRaises(DATA.Refused):
                DATA.project_build_settings(value, other_context, other_status, other_build)

    def test_build_settings_fixed_file_states_and_aqua_absence(self):
        value, build, _, context = build_settings_fixture(normal_diagnostic_data())
        def run(root, profile="installed"):
            return DATA.project(str(root), profile=profile, source=context["source"], workflow_source=context["workflowSource"],
                run_id=context["runId"], run_attempt=context["runAttempt"], target=context["target"])
        for mode in ("valid", "absent", "oversized", "duplicate", "bad-status", "bad-build", "raw-unlisted"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); before = {}
                path = write(root, "normal-ui/build.failure-diagnostics.json", build); before[path] = path.read_bytes()
                path = write(root, "normal-ui/build.status", b"0\n" if mode == "bad-status" else b"70\n"); before[path] = path.read_bytes()
                if mode != "absent":
                    raw = json.dumps(value).encode()
                    if mode == "oversized": raw += b" " * (4097 - len(raw))
                    if mode == "duplicate": raw = raw[:-1] + b',"schemaVersion":1}'
                    path = write(root, "normal-ui/build.settings-diagnostics.json", raw); before[path] = raw
                if mode == "bad-build":
                    broken = {**build, "stderrSha256": "a" * 64}; path = write(root, "normal-ui/build.failure-diagnostics.json", broken); before[path] = path.read_bytes()
                if mode == "raw-unlisted":
                    path = write(root, "normal-ui/private-build-settings.stdout", SENTINEL.encode()); before[path] = path.read_bytes()
                result = run(root)
                expected = "absent" if mode == "absent" else "observed" if mode in ("valid", "raw-unlisted") else "refused"
                self.assertEqual(result["buildSettingsDiagnostic"]["receiptState"], expected)
                if expected == "observed": self.assertEqual(result["buildSettingsDiagnostic"]["originalBuildReturncode"], 70)
                for path, body in before.items(): self.assertEqual(path.read_bytes(), body)
                self.assertNotIn(SENTINEL.encode(), (root / DATA.OUTPUT).read_bytes())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); raw = write(root, "normal-ui/build.settings-diagnostics.json", SENTINEL.encode())
            self.assertIsNone(run(root, "aqua")["buildSettingsDiagnostic"])
            self.assertEqual(raw.read_bytes(), SENTINEL.encode())

    def test_destination_rejection_details_public_schema(self):
        normal = normal_diagnostic_data(); status = {"receiptState": "observed", "returncode": 70}
        raw = b'Available destinations for the "MRKNormalAppUI" scheme:\n{ platform:macOS }\n'
        value = normal["normal_failure_diagnostics"]("build", None, CompletedProcess([], 70, raw, b""))
        observed = DATA.project_ui_diagnostic(value, "build", status)
        expected = [{"stream": "stdout", "section": "available", "reason": "missing-required-field"}]
        self.assertEqual(observed["destinationTable"]["rejections"], expected)
        self.assertIs(observed["destinationTable"]["rejectionDetailsTruncated"], False)
        legacy = copy.deepcopy(value)
        del legacy["destinationTable"]["rejections"], legacy["destinationTable"]["rejectionDetailsTruncated"]
        self.assertNotIn("rejections", DATA.project_ui_diagnostic(legacy, "build", status)["destinationTable"])
        for field, bad in (("rejections", None), ("rejections", []), ("rejections", expected * 2),
                ("rejections", [{**expected[0], "reason": SENTINEL}]),
                ("rejections", [{**expected[0], "stream": True}]),
                ("rejections", [{**expected[0], "section": "other"}]),
                ("rejections", [{**expected[0], "private": SENTINEL}]), ("rejectionDetailsTruncated", 1)):
            broken = copy.deepcopy(value); broken["destinationTable"][field] = bad
            with self.subTest(field=field, bad=bad), self.assertRaises(DATA.Refused):
                DATA.project_ui_diagnostic(broken, "build", status)


    def test_destination_opaque_utf8_public_projection_never_exports_private_values(self):
        normal = normal_diagnostic_data(); status = {"receiptState": "observed", "returncode": 70}
        header = b'Ineligible destinations for the "MRKNormalAppUI" scheme:\n'
        raw = header + ("{ platform:macOS, arch:x86_64, name:PRIVATE_名, error:PRIVATE_“reason” }\n").encode()
        original = CompletedProcess([], 70, b"", raw)
        value = normal["normal_failure_diagnostics"]("build", None, original)
        observed = DATA.project_ui_diagnostic(value, "build", status)
        self.assertEqual(observed["destinationTable"]["rows"], [{"stream": "stderr", "section": "ineligible",
            "platform": "macos", "architecture": "x86_64", "errorPresent": True, "errorTerms": []}])
        self.assertEqual(observed["destinationTable"], value["destinationTable"])
        self.assertEqual(observed["stderrSha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(observed["originalReturncode"], 70)
        self.assertIs(observed["nativeSuccessInferred"], False)
        self.assertNotIn("PRIVATE_", json.dumps(observed))
        for code in (0, True, 1):
            with self.assertRaises(DATA.Refused):
                DATA.project_ui_diagnostic(value, "build", {"receiptState": "observed", "returncode": code})
        invalid = header + b"{ platform:macOS, name:PRIVATE_\xff }\n"
        value = normal["normal_failure_diagnostics"]("build", None, CompletedProcess([], 70, b"", invalid))
        observed = DATA.project_ui_diagnostic(value, "build", status)
        self.assertTrue(observed["destinationTable"]["malformedRowObserved"])
        self.assertEqual(observed["destinationTable"]["rows"], [])
        self.assertIs(observed["nativeSuccessInferred"], False)
        self.assertNotIn("PRIVATE_", json.dumps(observed))


    def test_destination_unknown_rows_public_schema_is_closed_and_optional(self):
        normal = normal_diagnostic_data(); status = {"receiptState": "observed", "returncode": 70}
        header = b'Ineligible destinations for the "MRKNormalAppUI" scheme:\n'
        raw = header + b"{ platform:PRIVATE, arch:PRIVATE, extra:PRIVATE, error:PRIVATE, name:PRIVATE }\n"
        value = normal["normal_failure_diagnostics"]("build", None, CompletedProcess([], 70, b"", raw))
        projected = DATA.project_ui_diagnostic(value, "build", status)
        expected = {"stream": "stderr", "section": "ineligible", "platform": "unrecognized",
            "architecture": "unrecognized", "unsupportedKeyPresent": True, "errorPresent": True}
        self.assertEqual(projected["destinationTable"]["unknownRows"], [expected])
        self.assertEqual(projected["stderrSha256"], hashlib.sha256(raw).hexdigest())
        self.assertIs(projected["nativeSuccessInferred"], False)
        self.assertNotIn("PRIVATE", json.dumps(projected))
        legacy = copy.deepcopy(value)
        del legacy["destinationTable"]["unknownRows"], legacy["destinationTable"]["unknownRowsTruncated"]
        self.assertNotIn("unknownRows", DATA.project_ui_diagnostic(legacy, "build", status)["destinationTable"])
        for arch in ("arm64e", "x86_64h", "i386"):
            body = header + ("{ platform:macOS, arch:" + arch + ", name:PRIVATE }\n").encode()
            observed = normal["normal_failure_diagnostics"]("build", None, CompletedProcess([], 70, body, b""))
            row = DATA.project_ui_diagnostic(observed, "build", status)
            self.assertEqual(row["destinationTable"]["rows"][0]["architecture"], arch)
            self.assertFalse(row["destinationTable"]["unknownRowObserved"])
        for key, item in (("stream", True), ("section", "other"), ("platform", "PRIVATE"),
                ("architecture", "PRIVATE"), ("architecture", False), ("unsupportedKeyPresent", 1),
                ("errorPresent", None), ("extra", "PRIVATE")):
            bad = copy.deepcopy(value); bad["destinationTable"]["unknownRows"][0][key] = item
            with self.subTest(key=key), self.assertRaises(DATA.Refused):
                DATA.project_ui_diagnostic(bad, "build", status)
        for fault in ("missing-rows", "missing-truncation", "not-list", "ninth", "empty", "bad-truncation",
                      "unknown-false", "not-observed", "no-unknown-predicate", "truncation-without-findings"):
            bad = copy.deepcopy(value); table = bad["destinationTable"]
            if fault == "missing-rows": del table["unknownRows"]
            elif fault == "missing-truncation": del table["unknownRowsTruncated"]
            elif fault == "not-list": table["unknownRows"] = None
            elif fault == "ninth": table["unknownRows"] *= 9
            elif fault == "empty": table["unknownRows"] = []
            elif fault == "bad-truncation": table["unknownRowsTruncated"] = 1
            elif fault == "unknown-false": table["unknownRowObserved"] = False
            elif fault == "not-observed": table["state"] = "absent"
            elif fault == "no-unknown-predicate": table["unknownRows"][0].update(platform="macos", architecture=None, unsupportedKeyPresent=False)
            elif fault == "truncation-without-findings": table["unknownRowsTruncated"] = True
            with self.subTest(fault=fault), self.assertRaises(DATA.Refused):
                DATA.project_ui_diagnostic(bad, "build", status)
        truncated = copy.deepcopy(value); truncated["destinationTable"].update(unknownRows=[], unknownRowsTruncated=True)
        truncated["findingsTruncated"] = True
        self.assertEqual(DATA.project_ui_diagnostic(truncated, "build", status)["destinationTable"]["unknownRows"], [])
        for code in (0, True, 1):
            with self.assertRaises(DATA.Refused):
                DATA.project_ui_diagnostic(value, "build", {"receiptState": "observed", "returncode": code})

    def test_destination_error_terms_public_schema_is_closed_and_optional(self):
        normal = normal_diagnostic_data(); status = {"receiptState": "observed", "returncode": 70}
        terms = ["architecture", "platform", "macos", "xcode", "sdk", "deployment", "version", "support", "install"]
        raw = (b'Ineligible destinations for the "MRKNormalAppUI" scheme:\n'
               b'{ platform:macOS, arch:x86_64h, name:PRIVATE, error:architectures platforms macOS Xcode SDKs deployment versions supported installation 26.6.1 }\n')
        value = normal["normal_failure_diagnostics"]("build", None, CompletedProcess([], 70, b"", raw))
        projected = DATA.project_ui_diagnostic(value, "build", status)
        self.assertEqual(projected["destinationTable"]["rows"][0]["errorTerms"], terms)
        self.assertEqual(projected["stderrSha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(projected["originalReturncode"], 70)
        self.assertIs(projected["nativeSuccessInferred"], False)
        self.assertEqual(projected["status"], "unclassified")
        self.assertNotIn("PRIVATE", json.dumps(projected)); self.assertNotIn("26.6.1", json.dumps(projected))
        for replacement in ([], ["architecture"], ["support", "install"]):
            candidate = copy.deepcopy(value); candidate["destinationTable"]["rows"][0]["errorTerms"] = replacement
            self.assertEqual(DATA.project_ui_diagnostic(candidate, "build", status)["destinationTable"]["rows"][0]["errorTerms"], replacement)
        legacy = copy.deepcopy(value); del legacy["destinationTable"]["rows"][0]["errorTerms"]
        self.assertNotIn("errorTerms", DATA.project_ui_diagnostic(legacy, "build", status)["destinationTable"]["rows"][0])
        for replacement in (None, True, "architecture", {}, [True], [1], [None], ["PRIVATE"],
                            ["Architecture"], ["architectures"], ["version", "architecture"],
                            ["architecture", "architecture"], terms + ["support"]):
            candidate = copy.deepcopy(value); candidate["destinationTable"]["rows"][0]["errorTerms"] = replacement
            with self.subTest(replacement=replacement), self.assertRaises(DATA.Refused):
                DATA.project_ui_diagnostic(candidate, "build", status)
        for key, item in (("errorPresent", False), ("errorPresent", 1), ("rawError", "PRIVATE")):
            candidate = copy.deepcopy(value); candidate["destinationTable"]["rows"][0][key] = item
            with self.subTest(key=key), self.assertRaises(DATA.Refused):
                DATA.project_ui_diagnostic(candidate, "build", status)
        for missing in ("errorPresent", "stream", "section", "platform", "architecture"):
            candidate = copy.deepcopy(value); del candidate["destinationTable"]["rows"][0][missing]
            with self.subTest(missing=missing), self.assertRaises(DATA.Refused):
                DATA.project_ui_diagnostic(candidate, "build", status)
        with self.assertRaises(DATA.Refused):
            DATA.project_ui_diagnostic(value, "build", {"receiptState": "observed", "returncode": 0})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); write(root, "normal-ui/build.status", b"70\n")
            original = write(root, "normal-ui/build.failure-diagnostics.json", value); before = original.read_bytes()
            result = project(root)
            self.assertEqual(result["normalUiBuildDiagnostics"]["build"]["destinationTable"]["rows"][0]["errorTerms"], terms)
            self.assertEqual(original.read_bytes(), before)
            self.assertNotIn("PRIVATE", (root / DATA.OUTPUT).read_text())
            self.assertIs(result["productReady"], False)


if __name__ == "__main__":
    unittest.main()
