"""Run one unchanged first-party journey against verified installed media."""
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys


JOURNEYS = {
    "local-edits-images": ("testSyntheticProjectLocalEditsAndImages", "project-test", "PROJECT_UI"),
    "metadata-only": ("testSyntheticProjectLocalEditsAndImages", "project-test", "METADATA_UI"),
    "path-fields": ("testSyntheticProjectPathFields", "project-test", "PROJECT_FIELDS_UI"),
    "vault-persistence": ("testSyntheticPersistentCredentials", "persistence-test", "PERSISTENCE_UI"),
    "workflow-refusal": ("testSyntheticProjectManagedWorkflowRefusal", "workflow-refusal-test", "WORKFLOW_REFUSAL_UI"),
    "release-evidence": ("testSyntheticProjectSavedReleaseEvidence", "release-evidence-test", "RELEASE_EVIDENCE_UI"),
    "offline-checks": ("testSyntheticProjectSavedOfflineChecks", "saved-checks-test", "OFFLINE_UI"),
    "empty-build-inputs": ("testSyntheticProjectEmptyBuildInputInspection", "saved-checks-test", "RECOVERY_IDLE_UI"),
    "native-menus": ("testLaunchCancelAndQuit", "test", "UI"),
}


def run(suite, source, tree, media, work):
    method, bundle, marker = JOURNEYS[suite]
    manifest = json.loads((media / "RELEASE-MANIFEST.json").read_bytes())
    installed = json.loads((work / "evidence/INSTALLED.json").read_bytes())
    assert (installed["sourceCommit"], manifest["sourceCommit"], manifest["sourceTree"]) == (source, source, tree)
    assert installed["nativeSignaturesVerified"] and installed["packageVersion"] == manifest["version"]
    packages = {role: manifest["packages"][role + ".pkg"]["sha256"] for role in ("Install", "Remove")}
    assert installed["packageSha256"] == packages["Install"]
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == source
    update = runpy.run_path("desktop/tools/macos_update_check.py")
    before = set(update["recent_crashes"]())
    temporary = work / "xctest-tmp"
    temporary.mkdir(mode=0o700)
    report = {
        "suite": suite, "method": method, "sourceCommit": source, "sourceTree": tree,
        "harnessCommit": os.environ["GITHUB_SHA"], "workflowCommit": os.environ["GITHUB_SHA"],
        "buildRun": manifest["buildRun"], "carrierRun": manifest["carrierRun"],
        "carrierAttempt": manifest["carrierAttempt"], "packageSha256": packages["Install"],
        "removeSha256": packages["Remove"], "passed": False,
    }
    result_file = work / "evidence" / "ORDINARY-XCTEST.json"
    environment = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/Users/runner", "USER": "runner",
        "LOGNAME": "runner", "TMPDIR": str(temporary) + "/", "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8",
        "TZ": "UTC", "DEVELOPER_DIR": "/Applications/Xcode.app/Contents/Developer",
        "TEST_RUNNER_MRK_NORMAL_UI_HOSTED_JOB": "github-hosted-macos26-arm64",
        "TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE": source,
        "TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE": os.environ["GITHUB_SHA"],
        "TEST_RUNNER_MRK_NORMAL_UI_CURRENT_ORDINARY": "current-candidate-ordinary-only-v1",
        "TEST_RUNNER_MRK_NORMAL_UI_GUIDED_PRODUCT_SURFACE": "exact-0.2.13-frozen-ui",
    }
    if suite == "metadata-only":
        environment["TEST_RUNNER_MRK_NORMAL_UI_METADATA_ONLY"] = "fixed-metadata-journey-v1"
    project = Path.cwd() / "desktop/native/macos-normal-ui/MRKNormalAppUI.xcodeproj"
    derived = work / "DerivedData"
    platform = ["-destination", "platform=macOS,arch=arm64", "-destination-timeout", "15"]
    base = ["/usr/bin/xcodebuild", "-project", str(project), "-scheme", "MRKNormalAppUI",
            "-configuration", "Debug", *platform, "-derivedDataPath", str(derived), "-jobs", "2",
            "-disableAutomaticPackageResolution", "COMPILER_INDEX_STORE_ENABLE=NO"]
    try:
        with (work / "xctest-build.log").open("wb") as log:
            built = subprocess.run([*base, "build-for-testing"], env=environment, stdout=log,
                                   stderr=subprocess.STDOUT, timeout=600)
        report["buildReturn"] = built.returncode
        if built.returncode:
            return 1
        candidates = tuple((derived / "Build/Products").glob("MRKNormalAppUI_*.xctestrun"))
        assert len(candidates) == 1 and candidates[0].is_file() and not candidates[0].is_symlink()
        xcresult = work / (bundle + ".xcresult")
        tested = subprocess.run(
            ["/usr/bin/xcodebuild", "test-without-building", "-xctestrun", str(candidates[0]), *platform,
             "-resultBundlePath", str(xcresult), "-disableAutomaticPackageResolution",
             "-only-testing:MRKNormalAppUITests/NormalAppUITests/" + method, "-parallel-testing-enabled", "NO",
             "-test-timeouts-enabled", "YES", "-default-test-execution-time-allowance", "300",
             "-maximum-test-execution-time-allowance", "300"],
            env=environment, capture_output=True, text=True, errors="replace", timeout=500)
        report["xctestReturn"] = tested.returncode
        transcript = tested.stdout + "\n" + tested.stderr
        report["stages"] = re.findall(r"(?m)^MRK_NORMAL_PROJECT_STAGE=([a-z0-9-]{1,70});result=(started|passed|failed)",
                                      transcript)[-70:]
        report["launchStages"] = re.findall(
            r"(?m)^MRK_NORMAL_PROJECT_LAUNCH_STAGE=(account|identity|proxies|gate-open|gate-free|request|gate-held|owner|window|renderer|dashboard)$",
            transcript)[-20:]
        report["failureLines"] = re.findall(
            r"MRK_NORMAL_PROJECT_REQUIRE_FAILURE=v1;method=" + method + r";line=([0-9]{1,5});check=", transcript)[-4:]
        expected = {"totalTestCount": 1, "passedTests": 1, "failedTests": 0, "skippedTests": 0, "expectedFailures": 0}
        if xcresult.is_dir():
            summary = subprocess.run(["/usr/bin/xcrun", "xcresulttool", "get", "test-results", "summary",
                                      "--path", str(xcresult), "--compact"], env=environment,
                                     capture_output=True, timeout=30)
            if summary.returncode == 0:
                records = json.loads(summary.stdout)
                report["testCounts"] = {key: records.get(key) for key in expected}
        report["nativeJourneyMarkers"] = sum(row.startswith(f"MRK_MACOS_NORMAL_{marker}=")
                                              for row in transcript.splitlines())
        report["namedTestPassed"] = bool(re.search(r"(?m)^Test Case .*" + method + r"\]' passed ", transcript))
        report["newCrashReports"] = len(set(update["recent_crashes"]()) - before)
        report["passed"] = bool(tested.returncode == 0 and report.get("testCounts") == expected
                                and report["nativeJourneyMarkers"] == 1 and report["namedTestPassed"]
                                and report["newCrashReports"] == 0)
        return 0 if report["passed"] else 1
    except subprocess.TimeoutExpired:
        report["timedOut"] = True
        return 1
    finally:
        result_file.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    suite, source, tree, media, work = sys.argv[1:]
    raise SystemExit(run(suite, source, tree, Path(media), Path(work)))
