"""Execute the actual workflow parsers against synthetic, private local files.

These are parser/failure-injection checks, not XCTest, Keychain, app or signing
evidence. No native command is run; every synthetic output is discarded.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).absolute().parents[2]
WORKFLOW = ROOT / ".github/workflows/desktop-macos-installed.yml"
SHA = "a" * 40
HELPER = "b" * 64
SELECTED = "-[MRKNormalAppUITests.NormalAppUITests testSyntheticPersistentCredentials]"
START = ("Test Case '" + SELECTED + "' started.").encode()
PASS = ("Test Case '" + SELECTED + "' passed (1.000 seconds).").encode()
LIFETIME = (b";outerRequest=1;completion=1;body=1;handoff=1;payloadIdentity=1;originalTerminated=1;"
            b"gateFree=1;gateClosed=1;failureCleanup=0;caseDeadlineMet=1")
FIRST = b"MRK_MACOS_PERSISTENCE_LIFETIME=phase=1" + LIFETIME
SECOND = b"MRK_MACOS_PERSISTENCE_LIFETIME=phase=2" + LIFETIME
FINAL = b"MRK_MACOS_NORMAL_PERSISTENCE_UI=initialize-save-assess-bind-context-lock-reopen-rebind-replace-delete-restart-unlock-reassess-rebind;appRestart=passed;ordinaryLifetimes=2;cleanExitStatus=unavailable;allWorkerFinality=unavailable;fixtures=retained-for-disposable-job-retirement"


def parser_body(marker):
    text = WORKFLOW.read_text()
    start = "<<'" + marker + "'\n"
    if text.count(start) != 1:
        raise AssertionError("exact original workflow parser required")
    lines = text.split(start, 1)[1].splitlines()
    body = []
    for line in lines:
        if line == "          " + marker:
            return "\n".join(body) + "\n"
        if not line.startswith("          "):
            raise AssertionError("unexpected parser indentation")
        body.append(line[10:])
    raise AssertionError("missing parser terminator")


def inputs():
    preview = {"scope": "normal-macos-early-preview", "sourceCommit": SHA,
               "sourceTree": "c" * 40, "runId": "1234", "runAttempt": "1",
               "platform": "macOS26-arm64", "instrumented": False,
               "normalBuild": "passed", "packageAudit": "passed", "installationReadback": "passed",
               "signedAppBinarySha256": "d" * 64, "packageSha256": "e" * 64,
               "normalBinaryBeforeSigningSha256": "f" * 64, "packageSize": 128,
               "runtimeManifestSha256": "1" * 64, "installerInventorySha256": "2" * 64}
    basic = {"scope": "normal-app-launch-cancel-navigation-quit-ui-only",
             "applicationSourceCommit": SHA, "harnessSourceCommit": SHA,
             "runId": "1234", "runAttempt": "1", "signedAppBinarySha256": "d" * 64,
             "packageSha256": "e" * 64, "launchRenderCancelNavigationQuitUI": "passed",
             "testIdentifier": "MRKNormalAppUITests/NormalAppUITests/testLaunchCancelAndQuit"}
    helper = {"source": SHA, "workflowSource": SHA, "runId": "1234", "runAttempt": "1",
              "helperSha256": HELPER, "helperBytes": 4096}
    app = {"vaultHelperSha256": HELPER, "appBinarySha256BeforeSigning": "f" * 64}
    summary = {"totalTestCount": 1, "passedTests": 1, "failedTests": 0,
               "skippedTests": 0, "expectedFailures": 0}
    files = {name: json.dumps(value).encode() for name, value in (
        ("preview/PREVIEW.json", preview), ("normal-ui/result.json", basic),
        ("vault-helper-signing.json", helper), ("app-result.json", app),
        ("normal-ui/persistence-summary.raw.json", summary))}
    for name in ("build", "persistence-test", "persistence-summary"):
        files["normal-ui/" + name + ".status"] = b"0\n"
    for name in ("xcode-version", "sdk-path", "sdk-version", "sdk-build"):
        files["normal-ui/" + name + ".txt"] = b"synthetic-tool-binding\n"
    files["normal-ui/persistence-test.log"] = b"\n".join((START, FIRST, SECOND, FINAL, PASS)) + b"\n"
    return files


def replace_field(files, name, key, value):
    parsed = json.loads(files[name])
    parsed[key] = value
    files[name] = json.dumps(parsed).encode()


@contextlib.contextmanager
def private_fixture(files):
    with tempfile.TemporaryDirectory(prefix="mrk-persistence-parser-") as directory:
        root = Path(directory)
        for name, data in files.items():
            path = root / name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
        environment = {"MRK_MACOS_WORK": directory, "GITHUB_SHA": SHA, "GITHUB_WORKFLOW_SHA": SHA,
                       "GITHUB_RUN_ID": "1234", "GITHUB_RUN_ATTEMPT": "1",
                       "MRK_MACOS_VAULT_HELPER_SHA256": HELPER, "MRK_MACOS_VAULT_HELPER_BYTES": "4096"}
        with patch.dict(os.environ, environment, clear=True):
            yield root


def execute(marker):
    # No copied acceptance predicate: execute the unchanged reviewed heredoc.
    with contextlib.redirect_stdout(io.StringIO()):
        exec(compile(parser_body(marker), "<workflow-" + marker + ">", "exec"), {})


class MacPersistenceWorkflowTests(unittest.TestCase):
    def rejected(self, files):
        with private_fixture(files) as root:
            with self.assertRaises((ValueError, KeyError, TypeError, OSError)):
                execute("PY_PERSISTENCE_RESULT")
            self.assertFalse((root / "normal-ui/persistence-result.json").exists())

    def test_exact_synthetic_result_keeps_native_limitations(self):
        with private_fixture(inputs()) as root:
            execute("PY_PERSISTENCE_RESULT")
            result = json.loads((root / "normal-ui/persistence-result.json").read_text())
            self.assertEqual(result["applicationSourceCommit"], SHA)
            self.assertEqual(result["vaultHelperSha256"], HELPER)
            self.assertEqual(result["testCounts"], json.loads(inputs()["normal-ui/persistence-summary.raw.json"]))
            self.assertEqual(result["applicationRestart"], "passed")
            self.assertEqual(result["ordinaryApplicationLifetimes"], 2)
            self.assertIs(result["originalReferenceAndGateTerminalObserved"], True)
            self.assertIsNone(result["cleanExitStatus"])
            self.assertEqual(result["allWorkerFinality"], "not-established-by-XCTest-UI-state")
            for field in ("signingOrStoreValidated", "fullUIQualified", "distributionQualified", "productReady"):
                self.assertIs(result[field], False)

    def test_both_lifetimes_and_final_marker_are_unique_ordered_and_inside_the_test(self):
        original = inputs()["normal-ui/persistence-test.log"]
        changes = [original.replace(marker + b"\n", b"") for marker in (FIRST, SECOND, FINAL)]
        changes += [original.replace(marker + b"\n", marker + b"\n" + marker + b"\n") for marker in (FIRST, SECOND, FINAL)]
        changes += [b"\n".join(events) + b"\n" for events in (
            (START, SECOND, FIRST, FINAL, PASS), (START, FIRST, FINAL, SECOND, PASS),
            (FIRST, START, SECOND, FINAL, PASS), (START, FIRST, SECOND, PASS, FINAL))]
        changes += [original.replace(FINAL, FINAL.replace(b"ordinaryLifetimes=2", b"ordinaryLifetimes=1")),
                    original.replace(FINAL, FINAL.replace(b"appRestart=passed", b"appRestart=not-run")),
                    original + b"MRK_MACOS_UI_ORIGINAL=outerRequest=1\n"]
        for index, changed in enumerate(changes):
            with self.subTest(mutation=index):
                files = inputs(); files["normal-ui/persistence-test.log"] = changed
                self.rejected(files)

    def test_each_original_terminal_fact_and_failure_cleanup_is_a_restart_gate(self):
        original = inputs()["normal-ui/persistence-test.log"]
        for marker in (FIRST, SECOND):
            for field in (b"outerRequest", b"completion", b"body", b"handoff", b"payloadIdentity",
                          b"originalTerminated", b"gateFree", b"gateClosed", b"caseDeadlineMet"):
                with self.subTest(phase=marker[:40], field=field):
                    files = inputs()
                    files["normal-ui/persistence-test.log"] = original.replace(marker, marker.replace(field + b"=1", field + b"=0"))
                    self.rejected(files)
        for changed in (original.replace(b"failureCleanup=0", b"failureCleanup=1", 1),
                        original + b"MRK_MACOS_UI_FAILURE_CLEANUP=normalRequested=true\n",
                        original.replace(FINAL, b"MRK_MACOS_UI_FAILURE_CLEANUP=unknownStateRetained=true\n" + FINAL)):
            files = inputs(); files["normal-ui/persistence-test.log"] = changed
            self.rejected(files)

    def test_wrong_selected_case_duplicate_attempt_or_late_failure_never_passes(self):
        original = inputs()["normal-ui/persistence-test.log"]
        for changed in (original.replace(START + b"\n", b""), original.replace(PASS + b"\n", b""),
                        START + b"\n" + original, original + PASS + b"\n",
                        original.replace(b"testSyntheticPersistentCredentials", b"testLaunchCancelAndQuit"),
                        original.replace(START, START.replace(b"testSyntheticPersistentCredentials", b"testLaunchCancelAndQuit")),
                        original.replace(PASS, PASS.replace(b"testSyntheticPersistentCredentials", b"testLaunchCancelAndQuit")),
                        original + ("Test Case '" + SELECTED + "' failed (0.001 seconds).\n").encode()):
            files = inputs(); files["normal-ui/persistence-test.log"] = changed
            self.rejected(files)

    def test_original_source_attempt_package_and_helper_must_match(self):
        mutations = (
            ("preview/PREVIEW.json", "sourceCommit", "9" * 40),
            ("preview/PREVIEW.json", "runAttempt", "2"),
            ("preview/PREVIEW.json", "instrumented", True),
            ("preview/PREVIEW.json", "installationReadback", "skipped"),
            ("normal-ui/result.json", "harnessSourceCommit", "9" * 40),
            ("normal-ui/result.json", "packageSha256", "9" * 64),
            ("normal-ui/result.json", "launchRenderCancelNavigationQuitUI", "not-run"),
            ("vault-helper-signing.json", "helperBytes", True),
            ("vault-helper-signing.json", "helperSha256", "9" * 64),
            ("app-result.json", "vaultHelperSha256", "9" * 64),
            ("app-result.json", "appBinarySha256BeforeSigning", "9" * 64),
        )
        for name, key, value in mutations:
            with self.subTest(name=name, key=key):
                files = inputs()
                replace_field(files, name, key, value)
                self.rejected(files)

    def test_only_actual_zero_status_and_exact_one_test_summary_can_pass(self):
        for command in ("build", "persistence-test", "persistence-summary"):
            for status in (b"65\n", b"", b"0\n0\n", b"0"):
                with self.subTest(command=command, status=status):
                    files = inputs()
                    files["normal-ui/" + command + ".status"] = status
                    self.rejected(files)
        for key, value in (("totalTestCount", 0), ("passedTests", 0), ("passedTests", True),
                           ("failedTests", 1), ("skippedTests", 1), ("expectedFailures", 1)):
            with self.subTest(key=key, value=value):
                files = inputs()
                replace_field(files, "normal-ui/persistence-summary.raw.json", key, value)
                self.rejected(files)

    def test_duplicate_fields_missing_tool_binding_and_unsafe_input_fail_closed(self):
        files = inputs()
        name = "normal-ui/persistence-summary.raw.json"
        files[name] = files[name][:-1] + b',"passedTests":1}'
        self.rejected(files)
        files = inputs()
        files["normal-ui/sdk-build.txt"] = b"\n"
        self.rejected(files)
        with private_fixture(inputs()) as root:
            path = root / "vault-helper-signing.json"
            path.chmod(0o622)
            with self.assertRaisesRegex(ValueError, "input shape"):
                execute("PY_PERSISTENCE_RESULT")
            self.assertFalse((root / "normal-ui/persistence-result.json").exists())

    def test_result_publication_never_overwrites_existing_evidence(self):
        files = inputs()
        files["normal-ui/persistence-result.json"] = b"original-task-output\n"
        with private_fixture(files) as root:
            with self.assertRaises(FileExistsError):
                execute("PY_PERSISTENCE_RESULT")
            self.assertEqual((root / "normal-ui/persistence-result.json").read_bytes(), files["normal-ui/persistence-result.json"])

    def test_failure_diagnostics_export_only_closed_stages_and_counts(self):
        secret = b"SYNTHETIC-PRIVATE-KEYSTROKE-NOT-FOR-EXPORT"
        log = (secret + b"\nMRK_NORMAL_PROJECT_STAGE=persistence-save-and-bind-p12;result=failed;laterStages=not-run\n"
               b"MRK_NORMAL_PROJECT_QUERY=stage:persistence-save-and-bind-p12;buttons:2;textFields:1;comboBoxes:0;sheets:1\n"
               b"MRK_NORMAL_PROJECT_STAGE=unrecognized;result=passed\n"
               b"MRK_NORMAL_PROJECT_QUERY=stage:persistence-save-and-bind-p12;buttons:999;textFields:1;comboBoxes:0;sheets:1\n")
        with private_fixture({"normal-ui/persistence-test.log": log}) as root:
            execute("PY_PERSISTENCE_DIAGNOSTICS")
            raw = (root / "normal-ui/persistence-diagnostics.json").read_bytes()
            self.assertNotIn(secret, raw)
            result = json.loads(raw)
            self.assertEqual(len(result["events"]), 2)
            self.assertEqual(result["events"][0]["result"], "failed")
            self.assertEqual(result["events"][1]["roleCounts"], [2, 1, 0, 1])
            self.assertIs(result["nativeSuccessInferred"], False)
            self.assertIs(result["rawTextExported"], False)
        events = b"MRK_NORMAL_PROJECT_STAGE=persistence-launch;result=started\n" * 65
        with private_fixture({"normal-ui/persistence-test.log": events}) as root:
            with self.assertRaisesRegex(ValueError, "event bound"):
                execute("PY_PERSISTENCE_DIAGNOSTICS")
            self.assertFalse((root / "normal-ui/persistence-diagnostics.json").exists())


if __name__ == "__main__":
    unittest.main()
