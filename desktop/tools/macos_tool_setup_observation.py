"""Three fixed tool journeys on the existing installed observation/Fixtures.

Import is passive DATA. No downloader, process owner, vendor extraction,
privileged installer, ordinary source selection, or cleanup policy is added.
Only the existing Fixtures retains descriptors; Rust's original owners decide
all native settlement. Reports never nominate a path to open.
"""
from pathlib import Path
import os
import re
import stat

SCOPE = "tool-setup"
CASES = ("tool-setup-missing-sdk", "tool-setup-cancel-transfer", "tool-setup-source-drift")
# Protected publication is intentionally durable. Run both nonpublishing cuts
# FIRST, then the positive case, without deleting/adopting any existing row.
RUN_ORDER = (CASES[1], CASES[2], CASES[0])
TIMEOUT = 2415
APPLICATION = "dev.mobile-release-kit.desktop"
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


def application_path(binding, native_home, case, need):
    binding.checked()
    need(case in CASES and type(case) is str and type(native_home) is str, "tool-fixture-case")
    home = Path(native_home)
    need(home.is_absolute() and str(home) == native_home and home != Path("/")
         and len(home.parts) <= 17 and len(os.fsencode(home)) <= 4096
         and all(part not in (".", "..") and len(os.fsencode(part)) <= 255 for part in home.parts[1:]), "tool-native-home")
    return home / "Library/Application Support" / f"mrk-macos-aqua-tools-{binding.source}-{binding.run}-{binding.attempt}" / case / APPLICATION


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
    need(fixtures.cases == CASES and not fixtures.inflight and fixtures.tool_namespace is None, "tool-fixture-order")
    account = pwd.getpwuid(fixtures.uid)  # Never HOME or an environment pathname.
    need(account.pw_uid == fixtures.uid and fixtures.uid > 0, "tool-native-user")
    fixtures.tool_paths = {case: application_path(fixtures.binding, account.pw_dir, case, need) for case in CASES}
    support = fixtures.tool_paths[CASES[0]].parents[2]
    current = fixtures._open("/", directory=True)
    for parent, name in [(None, "/"), *[(None, part) for part in support.parts[1:]]]:
        if name != "/":
            parent, current = current, fixtures._open(name, current, directory=True)
        held, named = signature(os.fstat(current)), signature(os.stat(name, dir_fd=parent, follow_symlinks=False))
        need(held == named and stat.S_ISDIR(held[2]) and held[2] & 0o7022 == 0 and held[3] in (0, fixtures.uid), "tool-ancestor-custody")
        fixtures.tool_ancestors.append((parent, name, current, held[:5]))
    fixtures.tool_support = current
    fixtures.tool_namespace = fixtures._mkdir(current, fixtures.tool_paths[CASES[0]].parents[1].name)
    for case in CASES:
        fixtures.tool_parents[case] = fixtures._mkdir(fixtures.tool_namespace, case)
        fixtures._roster(fixtures.tool_parents[case], (), "tool-case-collision")
    # Native cache owns the app-data leaf. Never mkdir it here or adopt any
    # previous run/case's cache, successful result, pending output or receipt.
    parents_current(fixtures, need, signature)


def parents_current(fixtures, need, signature):
    need(fixtures.cases == CASES and fixtures.tool_namespace is not None and fixtures.tool_support is not None
         and len(fixtures.tool_parents) == 3 and fixtures.tool_ancestors, "tool-fixture-custody")
    for parent, name, fd, original in fixtures.tool_ancestors:
        need(signature(os.fstat(fd))[:5] == original
             and signature(os.stat(name, dir_fd=parent, follow_symlinks=False))[:5] == original, "tool-ancestor-changed")
    fixtures._named(fixtures.tool_support, fixtures.tool_paths[CASES[0]].parents[1].name, fixtures.tool_namespace, 0o700)
    fixtures._roster(fixtures.tool_namespace, CASES, "tool-namespace-roster")
    for case in CASES:
        fixtures._named(fixtures.tool_namespace, case, fixtures.tool_parents[case], 0o700)
        if case not in fixtures.tool_entered:
            fixtures._roster(fixtures.tool_parents[case], (), "tool-unentered-case-occupied")


def before_call(fixtures, case, need, signature):
    parents_current(fixtures, need, signature)
    need(case in CASES and case not in fixtures.tool_entered, "tool-case-reused")
    fixtures._roster(fixtures.tool_parents[case], (), "tool-application-collision")
    fixtures.tool_entered.add(case)  # Armed before the SAME original invocation.


def readback(fixtures, case, value, need, signature):
    report(value, case, need)
    need(not fixtures.inflight and fixtures.last_returned and case in fixtures.tool_entered
         and case not in fixtures.tool_completed, "tool-readback-order")
    parents_current(fixtures, need, signature)
    result = fixtures.readback(case)  # Existing independent unchanged project/sentinel check.
    created = value["execution"] == "executed" and case != CASES[2]
    fixtures._roster(fixtures.tool_parents[case], (APPLICATION,) if created else (), "tool-application-result")
    if created:
        with fixtures._temporary(fixtures._open(APPLICATION, fixtures.tool_parents[case], directory=True)) as app:
            fixtures._named(fixtures.tool_parents[case], APPLICATION, app, 0o700)
            # Only native-produced fixed cache leaf; don't traverse/repair/adopt
            # its contents or substitute this outer check for native joins.
            fixtures._roster(app, ("tool-cache-v1",), "tool-cache-root-roster")
    fixtures.tool_completed.add(case)
    return {**result, "toolSetup": {"sameCaseParents": True, "appDataCreated": created,
            "projectUnchanged": True, "cacheContentRevalidated": False, "retainedForHostRetirement": True}}
