"""Three fixed tool journeys on the existing installed observation/Fixtures.

Import is passive DATA. No downloader, process owner, vendor extraction,
privileged installer, ordinary source selection, or cleanup policy is added.
Only the existing Fixtures retains descriptors; Rust's original owners decide
all native settlement. Reports never nominate a path to open.
"""
from pathlib import Path
from importlib.util import spec_from_file_location, module_from_spec
import os
import re
import stat

# Fixed comparison/recipe sibling. No IO or process owner is created at import.
_public_spec = spec_from_file_location("mrk_public_tool_observation", Path(__file__).with_name("macos_tool_acquisition_observation.py"))
if _public_spec is None or _public_spec.loader is None:
    raise RuntimeError("public-tool-observation-unavailable")
PUBLIC = module_from_spec(_public_spec)
_public_spec.loader.exec_module(PUBLIC)
del _public_spec

SCOPE = "tool-setup"
SERVICE_SCOPE = SERVICE_CASE = "tool-service-prerequisite"
SERVICE_CASES = (SERVICE_CASE,)
SERVICE_TIMEOUT = 765
CASES = ("tool-setup-missing-sdk", "tool-setup-cancel-transfer", "tool-setup-source-drift")
# Protected publication is intentionally durable. Run both nonpublishing cuts
# FIRST, then the positive case, without deleting/adopting any existing row.
RUN_ORDER = (CASES[1], CASES[2], CASES[0])
TIMEOUT = 2415
APPLICATION = "dev.mobile-release-kit.desktop"
EMPTY_SDK = "empty-sdk"
APP = (b'plugins { id("com.android.application") }\n'
       b'android { compileSdk = 35; buildToolsVersion = "35.0.0"; defaultConfig { applicationId = "org.example.mrk.observed" } }\n'
       b'kotlin { jvmToolchain(17) }\n')
ROOT = b'plugins { id("com.android.application") version "8.9.2" apply false }\n'
WRAPPER = (b'distributionUrl=https\\://services.gradle.org/distributions/gradle-8.14.5-bin.zip\n'
           b'distributionSha256Sum=6f74b601422d6d6fc4e1f9a1ab6522f642c2fdcbc15ae33ebd30ba3d7198e854\n')
BOOLS = ("firstFailure", "sameActive", "accepted", "terminal", "current", "allJoined", "sourceInspected", "sourceClosed", "cacheClosed",
         "runtimeClosed", "cacheAttempted", "caArmed", "transferAttempted", "childAttempted", "childWaited", "ioJoined",
         "completeSdkLocation", "reuseSelected")
SAMPLE_KEYS = frozenset(("action", "outcome", "reason", "sourceFailure", *BOOLS))
REASONS = frozenset(("none cancelled timed-out context-changed document-lost shutdown runtime-unavailable protocol-error "
    "intent-expired stale-intent cleanup-unknown input-limit result-limit input unsupported stale census-incomplete "
    "existing-tools-incompatible existing-tools-unreadable recovery-required cache-conflict disk-space network redirect framing "
    "archive-digest archive-layout archive-member limit already-used unknown").split())


def fixture_data(config, version, keep, ignore):
    """Seven fixed public files. No Gradle execution and no project mutation."""
    files = {"app/build.gradle.kts": APP, "build.gradle.kts": ROOT,
             "gradle/wrapper/gradle-wrapper.properties": WRAPPER, "release/mobile-release.json": config,
             "version.properties": version, "keep.txt": keep, ".gitignore": ignore}
    directories = {".": (0o700, (".gitignore", "app", "build.gradle.kts", "gradle", "keep.txt", "release", "version.properties")),
                   "app": (0o700, ("build.gradle.kts",)), "gradle": (0o700, ("wrapper",)),
                   "gradle/wrapper": (0o700, ("gradle-wrapper.properties",)), "release": (0o700, ("mobile-release.json",))}
    return files, directories


def service_terminal(value, report, need):
    """Returned finite status, never a substitute for the existing Ready gates."""
    need(type(value) is dict and set(value) - {"registrationReturn"} == {
        "validation", "statusValid", "phase", "reason", "prerequisite", "observation"}
        and value["validation"] == "terminal" and value["statusValid"] is True
        and value["phase"] in ("complete", "refused")
        and value["reason"] in ("none", "approval-required", "approval-denied", "service-unavailable", "signing-unavailable")
        and value["prerequisite"] in ("ready", "approval-required", "approval-denied", "service-unavailable", "signing-unavailable"),
        "tool-service-terminal")
    observed = value["observation"]
    flags = {"mutationEntered", "mutationReturned", "mutationUncertain", "nativeSettled"}
    need(type(observed) is dict and set(observed) == flags | {"state", "outcome"}
        and all(type(observed[k]) is bool for k in flags)
        and observed["nativeSettled"] and not observed["mutationUncertain"]
        and (not observed["mutationReturned"] or observed["mutationEntered"])
        and observed["state"] in ("not-registered", "enabled", "requires-approval", "not-found", "unavailable", "error")
        and observed["outcome"] in ("not-entered", "observed", "registration-requested", "already-registered",
            "needs-approval", "denied-by-user", "stopped", "refused", "error"), "tool-service-terminal-observation")
    if "registrationReturn" in value:
        returned = value["registrationReturn"]
        need(type(returned) is dict and set(returned) == {"accepted", "error"}
            and type(returned["accepted"]) is bool
            and returned["error"] in ("none", "internal-failure", "invalid-signature", "authorization-failure",
                "tool-not-valid", "job-not-found", "service-unavailable", "job-plist-not-found", "job-must-be-enabled",
                "invalid-plist", "launch-denied-by-user", "already-registered", "other-service-error", "other-error-domain")
            and observed["mutationEntered"] and observed["mutationReturned"]
            and not report["checkSettled"], "tool-service-registration-return")
    if report["execution"] == "ready":
        need(value["phase"] == "complete" and value["reason"] == "none" and value["prerequisite"] == "ready"
            and observed["state"] == "enabled" and observed["outcome"] == "observed"
            and not observed["mutationEntered"] and not observed["mutationReturned"], "tool-service-terminal-ready")


def service_report(value, need):
    """Comparison only, after the original invocation and native finalization.

    In particular a lost/admitted request cannot masquerade as known nonentry.
    The actual prerequisite invocation is separate from the three Check-only
    journeys and does not require or inspect any supplier input.
    """
    flags = ("requestAdmitted", "checkAdmitted", "requestSettled", "checkSettled", "knownNonentry",
             "sameOriginalBindings", "allOriginalsSettled", "projectSentinelPreserved", "sourceInputsRead",
             "toolAcquisitionEntered", "settingsOpened", "serviceUnregistered", "productionQualified")
    keys = frozenset(("mechanism", "execution", "finding", "requestCalls", "checkCalls", "normalQuitOriginal", *flags))
    need(type(value) is dict and set(value) - {"terminal"} == keys
         and value["mechanism"] == "same-original-tool-service-prerequisite-v1"
         and all(type(value[k]) is bool for k in flags), "tool-service-report")
    need(type(value["requestCalls"]) is int and value["requestCalls"] == 1
         and type(value["checkCalls"]) is int and value["checkCalls"] in (0, 1)
         and type(value["normalQuitOriginal"]) is int and value["normalQuitOriginal"] == 2
         and all(value[k] for k in ("sameOriginalBindings", "allOriginalsSettled", "projectSentinelPreserved"))
         and not any(value[k] for k in ("sourceInputsRead", "toolAcquisitionEntered", "settingsOpened",
                                      "serviceUnregistered", "productionQualified")), "tool-service-scope")
    need(value["requestSettled"] == value["requestAdmitted"]
         and value["checkSettled"] == value["checkAdmitted"]
         and (not value["checkCalls"] or value["requestAdmitted"])
         and (not value["checkAdmitted"] or value["checkCalls"] == 1), "tool-service-originals")
    if value["knownNonentry"]:
        need((not value["requestAdmitted"] and not value["checkCalls"])
             or (value["requestSettled"] and value["checkCalls"] == 1 and not value["checkAdmitted"]),
             "tool-service-nonentry")
        need(value["finding"] == "service-unavailable", "tool-service-nonentry-finding")
    else:
        need(value["requestSettled"] and (not value["checkCalls"] or value["checkSettled"]),
             "tool-service-no-lost-admission")
    if value["execution"] == "ready":
        need(value["finding"] == "ready" and value["checkCalls"] == 1 and value["checkSettled"]
             and not value["knownNonentry"], "tool-service-ready")
    else:
        need(value["execution"] == "not-executed-prerequisite" and value["finding"] in (
            "approval-required", "approval-denied", "service-not-found", "service-unavailable"),
            "tool-service-unexecuted")
    if "terminal" in value:
        service_terminal(value["terminal"], value, need)
    return value


def service_readback(fixtures, case, value, need):
    need(case == SERVICE_CASE and fixtures.cases == SERVICE_CASES
         and not fixtures.inflight and fixtures.last_returned, "tool-service-readback-order")
    service_report(value, need)
    return {**fixtures.readback(case), "toolService": {"projectUnchanged": True,
        "sourceInputsRead": False, "serviceUnregistered": False}}


def application_path(binding, native_home, case, need):
    binding.checked()
    need(case in (*CASES, PUBLIC.COLD) and type(case) is str and type(native_home) is str, "tool-fixture-case")
    home = Path(native_home)
    need(home.is_absolute() and str(home) == native_home and home != Path("/")
         and len(home.parts) <= 17 and len(os.fsencode(home)) <= 4096
         and all(part not in (".", "..") and len(os.fsencode(part)) <= 255 for part in home.parts[1:]), "tool-native-home")
    prefix = "mrk-macos-aqua-tools-public" if case == PUBLIC.COLD else "mrk-macos-aqua-tools"
    return home / "Library/Application Support" / f"{prefix}-{binding.source}-{binding.run}-{binding.attempt}" / case / APPLICATION


def fixture_path(binding, native_home, *, service, need, public_acquisition=False):
    """Comparison path only. Fixtures supplies pwd; Rust uses the same User.dir."""
    need(type(service) is bool and type(public_acquisition) is bool and not (service and public_acquisition), "tool-fixture-scope")
    # Reuse the exact native-home syntax, not a caller environment pathname.
    support = application_path(binding, native_home, CASES[0], need).parents[2]
    suffix = SERVICE_SCOPE if service else PUBLIC.SCOPE if public_acquisition else SCOPE
    return support / f"mrk-macos-aqua-{binding.source}-{binding.run}-{binding.attempt}-{suffix}"


def prepare_namespace(fixtures, need, signature):
    """Hold protected ancestors before creating the one fixed task namespace.

    No ancestor is created, chmodded, adopted, or exempted for sticky /tmp.
    Every descriptor belongs to the existing Fixtures close path.
    """
    import pwd
    need(fixtures.cases in (CASES, SERVICE_CASES, PUBLIC.CASES) and fixtures.path is None
         and not fixtures.tool_fixture_ancestors and not fixtures.inflight, "tool-fixture-order")
    account = pwd.getpwuid(fixtures.uid)
    need(fixtures.uid > 0 and account.pw_uid == fixtures.uid and account.pw_gid == fixtures.gid,
         "tool-native-user")
    fixtures.path = fixture_path(fixtures.binding, account.pw_dir,
                                service=fixtures.cases == SERVICE_CASES, public_acquisition=fixtures.cases == PUBLIC.CASES, need=need)
    support = fixtures.path.parent
    current = fixtures._open("/", directory=True)
    parent = None
    for name in ("/", *support.parts[1:]):
        if name != "/":
            parent, current = current, fixtures._open(name, current, directory=True)
        held = signature(os.fstat(current))
        need(held == signature(os.stat(name, dir_fd=parent, follow_symlinks=False))
             and stat.S_ISDIR(held[2]) and held[2] & 0o7022 == 0
             and held[3] in (0, fixtures.uid), "tool-fixture-protected-ancestor")
        fixtures.tool_fixture_ancestors.append((parent, name, current, held[:5]))
    fixtures.parent = current
    namespace_current(fixtures, need, signature)


def namespace_current(fixtures, need, signature):
    need(fixtures.cases in (CASES, SERVICE_CASES, PUBLIC.CASES) and fixtures.path is not None
         and fixtures.tool_fixture_ancestors and fixtures.parent == fixtures.tool_fixture_ancestors[-1][2],
         "tool-fixture-parent-custody")
    for parent, name, current, original in fixtures.tool_fixture_ancestors:
        need(signature(os.fstat(current))[:5] == original
             == signature(os.stat(name, dir_fd=parent, follow_symlinks=False))[:5],
             "tool-fixture-ancestor-changed")


def _sample(value, phase, need):
    need(type(value) is dict and value.keys() == SAMPLE_KEYS
         and all(type(value[key]) is bool for key in BOOLS), "tool-original-sample")
    need(value["action"] == ("acquire" if phase in ("acquire", "cancel", "drift") else "inspect")
         and type(value["reason"]) is str and value["reason"] in REASONS
         and all(value[key] for key in ("sameActive", "allJoined", "sourceClosed", "cacheClosed", "runtimeClosed")), "tool-original-closure")
    need(value["sourceInspected"] == (phase != "reuse")
         and (value["sourceFailure"] is None or type(value["sourceFailure"]) is str
              and value["sourceFailure"] in ("existing-tools-incompatible", "stale")), "tool-source-inspection")
    if phase in ("initial", "acquire", "reuse"):
        need(value["outcome"] == "complete" and value["reason"] == "none" and not value["firstFailure"]
             and value["sourceFailure"] is None
             and all(value[key] for key in ("accepted", "terminal", "current", "childAttempted", "childWaited", "ioJoined")), "tool-positive-original")
        need(value["cacheAttempted"] == (phase == "acquire") and value["caArmed"] == (phase == "acquire")
             and value["completeSdkLocation"] == (phase == "acquire") and value["reuseSelected"] == (phase == "reuse")
             and value["transferAttempted"], "tool-missing-only-effects")
    else:
        need(value["firstFailure"] and not any(value[key] for key in (
             "accepted", "terminal", "transferAttempted", "childAttempted", "childWaited", "ioJoined", "completeSdkLocation", "reuseSelected")), "tool-negative-before-child")
        if phase == "cancel":
            need(value["outcome"] == "cancelled" and value["reason"] == "cancelled"
                 and value["sourceFailure"] is None, "tool-original-cancel")
        else:
            need(value["outcome"] in ("refused", "failed") and value["reason"] in ("existing-tools-incompatible", "stale")
                 and value["sourceFailure"] == value["reason"]
                 and not value["cacheAttempted"] and not value["caArmed"], "tool-source-refused-before-effects")


def report(value, case, need):
    """Validate returned comparison DATA. Never fill missing original facts."""
    keys = frozenset(("mechanism", "normalAcquisitionEnabled", "execution", "testResult", "initial", "acquire", "reuse",
        "selectedSources", "protectedCopyRegistered", "selectedCatalogVerified", "normalQuitOriginal", "allOriginalsSettled",
        "projectSentinelPreserved", "automaticRegistration", "privilegedInstallRequested", "productionQualified", "pendingCaseReused", "retirement"))
    need(type(case) is str and case in CASES and type(value) is dict and value.keys() == keys, "tool-report-shape")
    need(value["mechanism"] == "same-original-tool-setup-v1"
         and value["retirement"] == "retain-task-owned-cache-and-source-until-original-host-retirement", "tool-report-scope")
    for key in ("normalAcquisitionEnabled", "automaticRegistration", "privilegedInstallRequested", "productionQualified", "pendingCaseReused"):
        need(value[key] is False, "tool-unqualified-scope")
    for key in ("allOriginalsSettled", "projectSentinelPreserved"):
        need(value[key] is True, "tool-original-finality")
    need(type(value["selectedSources"]) is list and len(value["selectedSources"]) == 4
         and all(type(item) is bool for item in value["selectedSources"])
         and type(value["normalQuitOriginal"]) is int
         and type(value["protectedCopyRegistered"]) is bool and type(value["selectedCatalogVerified"]) is bool, "tool-report-fields")
    if value["execution"] == "not-executed-prerequisite":
        need(value["testResult"] == "not-executed" and all(value[key] is None for key in ("initial", "acquire", "reuse"))
             and value["selectedSources"] == [False] * 4 and value["normalQuitOriginal"] == 2
             and not value["protectedCopyRegistered"] and not value["selectedCatalogVerified"], "tool-unexecuted-not-pass")
    else:
        need(value["execution"] == "executed", "tool-execution-kind")
        positive = case == CASES[0]
        need(value["testResult"] == ("registered-reused" if positive else "cancelled-before-transfer" if case == CASES[1] else "source-refused-before-effects")
             and value["selectedSources"] == ([True] * 4 if positive else [True, True, True, False])
             and value["normalQuitOriginal"] == (6 if positive else 5)
             and value["protectedCopyRegistered"] == positive and value["selectedCatalogVerified"] == positive, "tool-case-result")
        _sample(value["initial"], "initial", need)
        _sample(value["acquire"], "acquire" if positive else "cancel" if case == CASES[1] else "drift", need)
        if positive:
            _sample(value["reuse"], "reuse", need)
        else:
            need(value["reuse"] is None, "tool-no-later-reuse")
    return value


def prepare_parents(fixtures, need, signature):
    import pwd
    need(fixtures.cases in (CASES, PUBLIC.CASES) and not fixtures.inflight and fixtures.tool_namespace is None, "tool-fixture-order")
    cache_cases = CASES if fixtures.cases == CASES else (PUBLIC.COLD,)
    account = pwd.getpwuid(fixtures.uid)  # Never HOME or an environment pathname.
    need(account.pw_uid == fixtures.uid and fixtures.uid > 0, "tool-native-user")
    fixtures.tool_paths = {case: application_path(fixtures.binding, account.pw_dir, case, need) for case in cache_cases}
    support = fixtures.tool_paths[cache_cases[0]].parents[2]
    current = fixtures._open("/", directory=True)
    for parent, name in [(None, "/"), *[(None, part) for part in support.parts[1:]]]:
        if name != "/":
            parent, current = current, fixtures._open(name, current, directory=True)
        held, named = signature(os.fstat(current)), signature(os.stat(name, dir_fd=parent, follow_symlinks=False))
        need(held == named and stat.S_ISDIR(held[2]) and held[2] & 0o7022 == 0 and held[3] in (0, fixtures.uid), "tool-ancestor-custody")
        fixtures.tool_ancestors.append((parent, name, current, held[:5]))
    fixtures.tool_support = current
    fixtures.tool_namespace = fixtures._mkdir(current, fixtures.tool_paths[cache_cases[0]].parents[1].name)
    for case in cache_cases:
        fixtures.tool_parents[case] = fixtures._mkdir(fixtures.tool_namespace, case)
        fixtures._roster(fixtures.tool_parents[case], (), "tool-case-collision")
        if case == PUBLIC.COLD:
            # Real explicit Browse source, not a hidden/replaced global SDK.
            # The existing original closes this temporary FD before admission.
            with fixtures._temporary(fixtures._mkdir(fixtures.tool_parents[case], EMPTY_SDK)) as sdk:
                fixtures._roster(sdk, (), "tool-empty-sdk-not-empty")
                fixtures.tool_empty_sdk = signature(os.fstat(sdk))
    # Native cache owns the app-data leaf. Never mkdir it here or adopt any
    # previous run/case's cache, successful result, pending output or receipt.
    parents_current(fixtures, need, signature)


def _empty_sdk_current(fixtures, need, signature):
    original = fixtures.tool_empty_sdk
    need(type(original) is tuple and len(original) == 9, "tool-empty-sdk-original")
    parent = fixtures.tool_parents[PUBLIC.COLD]
    with fixtures._temporary(fixtures._open(EMPTY_SDK, parent, directory=True)) as sdk:
        fixtures._named(parent, EMPTY_SDK, sdk, 0o700)
        need(signature(os.fstat(sdk)) == original, "tool-empty-sdk-changed")
        fixtures._roster(sdk, (), "tool-empty-sdk-not-empty")
        need(signature(os.fstat(sdk)) == original
             == signature(os.stat(EMPTY_SDK, dir_fd=parent, follow_symlinks=False)), "tool-empty-sdk-changed")
    fixtures._named(fixtures.tool_namespace, PUBLIC.COLD, parent, 0o700)


def parents_current(fixtures, need, signature):
    cache_cases = CASES if fixtures.cases == CASES else (PUBLIC.COLD,)
    need(fixtures.cases in (CASES, PUBLIC.CASES) and fixtures.tool_namespace is not None and fixtures.tool_support is not None
         and len(fixtures.tool_parents) == len(cache_cases) and fixtures.tool_ancestors, "tool-fixture-custody")
    for parent, name, fd, original in fixtures.tool_ancestors:
        need(signature(os.fstat(fd))[:5] == original
             and signature(os.stat(name, dir_fd=parent, follow_symlinks=False))[:5] == original, "tool-ancestor-changed")
    fixtures._named(fixtures.tool_support, fixtures.tool_paths[cache_cases[0]].parents[1].name, fixtures.tool_namespace, 0o700)
    fixtures._roster(fixtures.tool_namespace, cache_cases, "tool-namespace-roster")
    for case in cache_cases:
        fixtures._named(fixtures.tool_namespace, case, fixtures.tool_parents[case], 0o700)
        if case not in fixtures.tool_entered:
            fixtures._roster(fixtures.tool_parents[case], (EMPTY_SDK,) if case == PUBLIC.COLD else (), "tool-unentered-case-occupied")
    if fixtures.cases == PUBLIC.CASES:
        _empty_sdk_current(fixtures, need, signature)
    else:
        need(fixtures.tool_empty_sdk is None, "tool-unexpected-empty-sdk")


def before_call(fixtures, case, need, signature):
    parents_current(fixtures, need, signature)
    need(case in fixtures.cases and case not in fixtures.tool_entered, "tool-case-reused")
    if case in PUBLIC.CASES:
        PUBLIC.space_before(fixtures, case)
    if case == PUBLIC.CANCEL:
        need(fixtures.cli is not None, "tool-cli-application-original")
        fixtures.cli.current()
    else:
        fixtures._roster(fixtures.tool_parents[case], (EMPTY_SDK,) if case == PUBLIC.COLD else (), "tool-application-collision")
    fixtures.tool_entered.add(case)  # Armed before the SAME original invocation.


def readback(fixtures, case, value, need, signature):
    if case in PUBLIC.CASES:
        PUBLIC.report(value, case, need, _sample)
    else:
        report(value, case, need)
    need(not fixtures.inflight and fixtures.last_returned and case in fixtures.tool_entered
         and case not in fixtures.tool_completed, "tool-readback-order")
    parents_current(fixtures, need, signature)
    result = fixtures.readback(case)  # Existing independent unchanged project/sentinel check.
    created = value["execution"] == "executed" and case != CASES[2]
    if case == PUBLIC.CANCEL:
        cli = PUBLIC.cli_readback(fixtures, value["cli"])
        fixtures.tool_completed.add(case)
        return {**result, "installedCli": cli, "toolSetup": {"projectUnchanged": True,
                "retainedForHostRetirement": True, "partialArchivePreserved": True}}
    entries = ((EMPTY_SDK,) if case == PUBLIC.COLD else ()) + ((APPLICATION,) if created else ())
    fixtures._roster(fixtures.tool_parents[case], entries, "tool-application-result")
    if created:
        with fixtures._temporary(fixtures._open(APPLICATION, fixtures.tool_parents[case], directory=True)) as app:
            fixtures._named(fixtures.tool_parents[case], APPLICATION, app, 0o700)
            # Only native-produced fixed cache leaf; don't traverse/repair/adopt
            # its contents or substitute this outer check for native joins.
            fixtures._roster(app, ("tool-cache-v1",), "tool-cache-root-roster")
            if case == PUBLIC.COLD:
                PUBLIC.cold_readback(fixtures, app, value)
    fixtures.tool_completed.add(case)
    return {**result, "toolSetup": {"sameCaseParents": True, "appDataCreated": created,
            "projectUnchanged": True, "cacheContentRevalidated": False, "retainedForHostRetirement": True}}
