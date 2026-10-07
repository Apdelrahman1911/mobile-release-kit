"""In-memory compiler-only contracts; no compiler, application or native execution."""
from __future__ import annotations

from copy import deepcopy
import contextlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import unittest
from unittest.mock import patch

HELPER = Path(__file__).resolve().parents[2] / "desktop/tools/ci_foundation.py"
SPEC = importlib.util.spec_from_file_location("desktop_shell_compile_contract", HELPER)
assert SPEC is not None and SPEC.loader is not None
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


def environment() -> dict[str, str]:
    return {"GITHUB_SHA": "1" * 40, "GITHUB_WORKFLOW_SHA": "1" * 40,
            "GITHUB_REPOSITORY": "fictional/project", "GITHUB_REF": helper.COMPILE_REF,
            "GITHUB_WORKFLOW_REF": f"fictional/project/{helper.COMPILE_WORKFLOW}@{helper.COMPILE_REF}",
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_EVENT_NAME": "push"}


def context() -> dict:
    return {**helper.compile_workflow_binding(environment()), "platform": "linux",
            "workflowSha256": "2" * 64, "executionScope": helper.COMPILE_SCOPE}


def receipt(phase: str) -> dict:
    binding = context()
    return {"schemaVersion": 1, "scope": helper.COMPILE_EVIDENCE_SCOPE, "phase": phase, "status": "passed",
            **{key: binding[key] for key in ("sourceSha", "platform", "workflowPath", "workflowSha", "workflowRef", "workflowSha256", "runId", "attempt")},
            "rust": {"release": helper.RUST, "target": helper.TARGETS["linux"]}, "node": helper.NODE,
            "checks": [{"check": check, "exitCode": 0} for check in helper.COMPILE_CHECKS[phase]]}


def mac_environment(target="aarch64-apple-darwin"):
    arch, _, images, _, _ = helper.MAC_COMPILE_HOSTS[target]
    return {**environment(), "GITHUB_REF": helper.MAC_COMPILE_REF,
            "GITHUB_WORKFLOW_REF": f"fictional/project/{helper.MAC_COMPILE_WORKFLOW}@{helper.MAC_COMPILE_REF}",
            "MRK_MACOS_TARGET": target, "RUNNER_OS": "macOS", "RUNNER_ARCH": arch, "ImageOS": images[0],
            "GITHUB_WORKSPACE": "/inert/source", "RUNNER_TEMP": "/inert/tmp", "PATH": "/selected/bin",
            "GITHUB_OUTPUT": "/inert/output", "MRK_DESKTOP_PLATFORM": "macos",
            "MRK_DESKTOP_HOSTED_CHECKS": helper.MAC_COMPILE_SCOPE}


def mac_context(target="aarch64-apple-darwin"):
    return {**helper.compile_workflow_binding(mac_environment(target), helper.MAC_COMPILE_SCOPE),
            "root": "/inert/tmp/mrk-desktop-foundation-original", "source": "/inert/source", "git": "/usr/bin/git",
            "platform": "macos", "sourceTree": "3" * 40, "workflowSha256": "2" * 64,
            "executionScope": helper.MAC_COMPILE_SCOPE,
            # Synthetic in-memory context only; never an admitted source receipt.
            "macCompile": {"target": target, "release": helper.MAC_COMPILE_HOSTS[target][4] + "desktop-01",
                           "sources": [], "graphs": [list(row) for row in helper.MAC_COMPILE_GRAPHS], "execution": "compile-only"}}


# Independent SOURCE expectations, not copied from the production tuple map.
# These are synthetic probe/receipt DATA; only a later real -vV can qualify it.
MAC_RUST_EXPECTED = {
    "aarch64-apple-darwin": {"release": "1.98.1", "commitHash": "48a229ceaefd4985c50990b14116b6d856af0985",
                             "target": "aarch64-apple-darwin"},
    "x86_64-apple-darwin": {"release": "1.98.0", "commitHash": "88d9e12ae178fab0fb5cc050a94da85685d449ea",
                           "target": "x86_64-apple-darwin"},
}


def memory_paths(events):
    class Stream:
        def __init__(self, *args, **kwargs):
            self.name = str(args[0]) if args else "memory"
        def __enter__(self):
            return self
        def __exit__(self, *args):
            events.append(("closed", self.name))
        def write(self, value):
            events.append(("write", self.name, value))
            return len(value)
    class MemoryPath(PurePosixPath):
        def resolve(self, strict=False):
            return self
        def exists(self):
            return False
        def is_symlink(self):
            return False
        def mkdir(self, **kwargs):
            events.append(("mkdir", str(self)))
        def touch(self, **kwargs):
            events.append(("touch", str(self)))
        def rglob(self, pattern):
            return iter(())
        def open(self, *args, **kwargs):
            events.append(("open", str(self), args))
            return Stream(self)
    return MemoryPath, Stream


class ShellCompileContractTests(unittest.TestCase):
    def test_compile_scope_refuses_every_native_phase_before_context_or_tools(self):
        with patch.object(helper, "load_context", side_effect=AssertionError("context must not be opened")), \
                patch.object(helper, "tools", side_effect=AssertionError("no tool may be selected")):
            for phase in ("native", "config-owner", "config-task-loss", "config-owner-delta",
                          "config-transaction-eof", "config-core", "windows-snapshot", "unexpected"):
                with self.subTest(phase=phase), self.assertRaises(helper.CheckFailure):
                    helper.phase(phase, "linux", helper.COMPILE_SCOPE)
        for phase in helper.COMPILE_PHASES:
            helper.admit_phase(helper.COMPILE_SCOPE, phase)
        helper.admit_phase(helper.BOUNDARY_SCOPE, "native")  # No native call.
        with self.assertRaises(helper.CheckFailure):
            helper.admit_phase("unknown", "compile")

        with patch.object(helper, "load_context", side_effect=AssertionError("no source IO")):
            for phase in ("native", "windows-snapshot", "environment-native", "workflow-owner", "unknown"):
                with self.subTest(phase=phase), self.assertRaises(helper.CheckFailure):
                    helper.phase(phase, "macos", helper.MAC_COMPILE_SCOPE)
            for platform in ("linux", "windows", "unknown"):
                for phase in helper.COMPILE_PHASES:
                    with self.subTest(platform=platform, phase=phase), self.assertRaises(helper.CheckFailure):
                        helper.phase(phase, platform, helper.MAC_COMPILE_SCOPE)
        for target in helper.MAC_COMPILE_HOSTS:
            env = mac_environment(target)
            self.assertEqual(helper.mac_compile_target(env), target)
            for key, bad in (("MRK_MACOS_TARGET", "foreign"), ("RUNNER_ARCH", "other"),
                             ("RUNNER_OS", "Linux"), ("ImageOS", "macos15")):
                with self.subTest(target=target, key=key), self.assertRaises(helper.CheckFailure):
                    helper.mac_compile_target({**env, key: bad})
        self.assertEqual(helper.RUST, "1.98.0")
        self.assertEqual(helper.TARGETS["macos"], "aarch64-apple-darwin")

    def test_compile_binding_requires_actual_fixed_workflow_ref_source_and_attempt(self):
        original = environment()
        expected = helper.compile_workflow_binding(original)
        self.assertEqual(expected["sourceSha"], "1" * 40)
        for key, value in (("GITHUB_REF", "refs/heads/main"), ("GITHUB_SHA", "bad"),
                           ("GITHUB_WORKFLOW_SHA", "3" * 40), ("GITHUB_WORKFLOW_REF", "other/workflow"),
                           ("GITHUB_REPOSITORY", "other/project"), ("GITHUB_RUN_ID", "0"),
                           ("GITHUB_RUN_ATTEMPT", "-1"), ("GITHUB_EVENT_NAME", "pull_request")):
            with self.subTest(key=key), self.assertRaises(helper.CheckFailure):
                helper.compile_workflow_binding({**original, key: value})
        dispatched = {**original, "GITHUB_EVENT_NAME": "workflow_dispatch"}
        with self.assertRaises(helper.CheckFailure):
            helper.compile_workflow_binding(dispatched)
        self.assertEqual(helper.compile_workflow_binding({**dispatched, "MRK_EXPECTED_SHA": "1" * 40}), expected)

        for target in helper.MAC_COMPILE_HOSTS:
            env = mac_environment(target)
            binding = helper.compile_workflow_binding(env, helper.MAC_COMPILE_SCOPE)
            self.assertEqual(binding["workflowPath"], helper.MAC_COMPILE_WORKFLOW)
            for key, bad in (("GITHUB_REF", helper.COMPILE_REF), ("GITHUB_WORKFLOW_SHA", "4" * 40),
                             ("GITHUB_WORKFLOW_REF", environment()["GITHUB_WORKFLOW_REF"]), ("GITHUB_RUN_ATTEMPT", "0")):
                with self.subTest(key=key), self.assertRaises(helper.CheckFailure):
                    helper.compile_workflow_binding({**env, key: bad}, helper.MAC_COMPILE_SCOPE)
            release = {"schemaVersion": 1, "packageVersion": "0.1.1", "release": helper.MAC_COMPILE_HOSTS[target][4] + "desktop-01"}
            cargo, tauri = b'[package]\nversion = "0.1.1"\n', b'{"version":"0.1.1"}'
            self.assertEqual(helper.mac_compile_release(json.dumps(release).encode(), target, cargo, tauri), release["release"])
            for bad in ({**release, "schemaVersion": True}, {**release, "extra": 1}, {**release, "packageVersion": "0.1.0"},
                        {**release, "release": "foreign-desktop-01"}):
                with self.subTest(bad=bad), self.assertRaises(helper.CheckFailure):
                    helper.mac_compile_release(json.dumps(bad).encode(), target, cargo, tauri)
            with self.assertRaises(helper.CheckFailure):
                helper.mac_compile_release(b'{"schemaVersion":1,"schemaVersion":1}', target, cargo, tauri)
        workflow = (HELPER.parents[2] / helper.MAC_COMPILE_WORKFLOW).read_text(encoding="utf-8")
        # Exact closed Actions expression, not an evaluator or a free-form matrix.
        arm_row = '{"platform":"macos","os":"macos-26","target":"aarch64-apple-darwin"}'
        intel_row = '{"platform":"macos","os":"macos-26-intel","target":"x86_64-apple-darwin"}'
        matrix = ("        include: ${{ fromJSON(inputs.target == 'arm' && '[" + arm_row + "]' || "
                  "inputs.target == 'intel' && '[" + intel_row + "]' || '[" + arm_row + ',' + intel_row + "]') }}\n")
        self.assertEqual(workflow.count(matrix), 1)
        self.assertIn("      target:\n"
                      "        description: Fixed compiler target (both by default)\n"
                      "        required: false\n"
                      "        type: choice\n"
                      "        default: both\n"
                      "        options: [both, arm, intel]\n", workflow)
        self.assertIn("      MRK_COMPILE_SELECTION: ${{ inputs.target || 'both' }}\n", workflow)
        admission = workflow.split("      - name: Require exact disposable verification source\n", 1)[1].split(
            "      - name: Check out exact source without persisted credentials\n", 1)[0]
        self.assertIn('          if [[ "$GITHUB_EVENT_NAME" == workflow_dispatch ]]; then\n'
                      '            [[ "$MRK_EXPECTED_SHA" == "$GITHUB_SHA" ]]\n'
                      '            case "$MRK_COMPILE_SELECTION" in\n'
                      '              both) ;;\n'
                      '              arm) [[ "$MRK_MACOS_TARGET" == aarch64-apple-darwin ]] ;;\n'
                      '              intel) [[ "$MRK_MACOS_TARGET" == x86_64-apple-darwin ]] ;;\n'
                      '              *) exit 1 ;;\n'
                      '            esac\n'
                      '          else\n'
                      '            [[ "$GITHUB_EVENT_NAME" == push && "$MRK_COMPILE_SELECTION" == both ]]\n'
                      '          fi\n', admission)
        self.assertIn('[[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ && "$GITHUB_WORKFLOW_SHA" == "$GITHUB_SHA" ]]', admission)
        self.assertIn('[[ "$GITHUB_REF" == refs/heads/verify/desktop-macos-normal-compile ]]', admission)
        self.assertIn('[[ "$GITHUB_WORKFLOW_REF" == "$GITHUB_REPOSITORY/.github/workflows/desktop-macos-normal-compile.yml@$GITHUB_REF" ]]', admission)
        self.assertIn('[[ "$RUNNER_ENVIRONMENT" == github-hosted ]]', admission)
        header = workflow.split('    steps:\n', 1)[0]
        self.assertIn("    timeout-minutes: ${{ matrix.target == 'x86_64-apple-darwin' && 65 || 45 }}\n", header)
        self.assertIn('      fail-fast: false\n      max-parallel: 2\n', header)
        acquire = workflow.split('      - name: Acquire locked active-platform inputs without npm scripts\n', 1)[1].split('      - name:', 1)[0]
        compile_step = workflow.split('      - name: Compile actual frontend and native shell without launching them\n', 1)[1].split('      - name:', 1)[0]
        self.assertIn('        timeout-minutes: 15\n', acquire)
        self.assertIn("        timeout-minutes: ${{ matrix.target == 'x86_64-apple-darwin' && 47 || 25 }}\n", compile_step)
        self.assertIn("desktop-macos-normal-compile-${{ matrix.target }}-", workflow)
        self.assertNotIn("ubuntu-", workflow)
        self.assertNotIn("windows-2025", workflow)
        self.assertNotIn("secrets.", workflow)
        self.assertEqual(workflow.count("ci_foundation.py compile'"), 1)
        self.assertIn("MRK_DESKTOP_HOSTED_CHECKS: macos-normal-compile-v1", workflow)
        cleanup = workflow.split("      - name: Immediately remove positively settled compiler outputs\n", 1)[1]
        self.assertIn("        if: success()\n", cleanup)
        self.assertIn("ci_foundation.py clean'", cleanup)

    def test_compile_cleanup_requires_complete_matching_original_positive_receipts(self):
        for phase in helper.COMPILE_CHECKS:
            original = receipt(phase)
            self.assertEqual(helper.validate_compile_receipt(original, context(), phase), original)
            for key, value in (("schemaVersion", True), ("scope", "passive-development-foundation-only"),
                               ("sourceSha", "3" * 40), ("platform", "macos"), ("runId", "124"),
                               ("attempt", "1"), ("workflowPath", ".github/workflows/desktop-foundation.yml"),
                               ("workflowSha", "4" * 40), ("workflowRef", "other/workflow"),
                               ("workflowSha256", "5" * 64), ("status", "failed"), ("node", "other"),
                               ("rust", {"release": helper.RUST, "target": "wrong"}),
                               ("checks", original["checks"][:-1]), ("extra", False)):
                with self.subTest(phase=phase, key=key), self.assertRaises(helper.CheckFailure):
                    helper.validate_compile_receipt({**original, key: value}, context(), phase)
            for exit_code in (False, 1, None):
                broken = deepcopy(original)
                broken["checks"][0]["exitCode"] = exit_code
                with self.assertRaises(helper.CheckFailure):
                    helper.validate_compile_receipt(broken, context(), phase)
            with self.assertRaises(helper.CheckFailure):
                helper.validate_compile_receipt(None, context(), phase)
            with self.assertRaises(helper.CheckFailure):
                helper.validate_compile_receipt(original, {**context(), "executionScope": helper.BOUNDARY_SCOPE}, phase)

        self.assertEqual(helper.MAC_COMPILE_RUST,
                         {target: (value["release"], value["commitHash"])
                          for target, value in MAC_RUST_EXPECTED.items()})
        for target, expected_rust in MAC_RUST_EXPECTED.items():
            bound = mac_context(target)
            self.assertEqual(helper.compiler_binding(bound), expected_rust)
            other_target = next(value for value in MAC_RUST_EXPECTED if value != target)
            other_rust = MAC_RUST_EXPECTED[other_target]
            for phase in helper.MAC_COMPILE_CHECKS:
                original = {"schemaVersion": 1, "scope": "desktop-macos-normal-compile-only-v1", "phase": phase, "status": "passed",
                    **{key: bound[key] for key in ("sourceSha", "platform", "workflowPath", "workflowSha", "workflowRef", "workflowSha256", "runId", "attempt", "sourceTree", "macCompile")},
                    "rust": deepcopy(expected_rust), "node": helper.NODE,
                    "checks": [{"check": name, "exitCode": 0} for name in helper.MAC_COMPILE_CHECKS[phase]]}
                self.assertEqual(helper.validate_compile_receipt(original, bound, phase), original)
                published = []
                with patch.object(helper, "write_json", side_effect=lambda path, value: published.append((str(path), deepcopy(value)))):
                    helper.phase_receipt(bound, phase, list(helper.MAC_COMPILE_CHECKS[phase]), node=helper.NODE)
                self.assertEqual(published, [(bound["root"] + "/" + phase + "-checks.json", original)])
                for key, bad in (("rust", {"release": "1.98.0", "target": target}), ("sourceTree", "4" * 40),
                                 ("macCompile", {**bound["macCompile"], "graphs": bound["macCompile"]["graphs"][:-1]}),
                                 ("checks", original["checks"][:-1])):
                    with self.subTest(target=target, key=key), self.assertRaises(helper.CheckFailure):
                        helper.validate_compile_receipt({**original, key: bad}, bound, phase)
                for bad_rust in ({**expected_rust, "release": "1.0.0"},
                                 {**expected_rust, "commitHash": "0" * 40},
                                 {**expected_rust, "target": other_target},
                                 {**other_rust, "target": target}):
                    with self.subTest(target=target, phase=phase, rust=bad_rust), self.assertRaises(helper.CheckFailure):
                        helper.validate_compile_receipt({**original, "rust": bad_rust}, bound, phase)
                failed = deepcopy(original)
                failed["checks"][-1]["exitCode"] = 1
                with self.assertRaises(helper.CheckFailure):
                    helper.validate_compile_receipt(failed, bound, phase)
            calls = []
            positive_version = ("rustc " + expected_rust["release"] + "\nrelease: " + expected_rust["release"]
                                + "\ncommit-hash: " + expected_rust["commitHash"] + "\nhost: " + target + "\n")
            version = positive_version
            def probe(argv, **kw):
                calls.append((argv, kw))
                return version if kw["check"] == "rust-version-target" else "cargo 1.98.0 (abcdef123 2026-09-01)"
            with patch.object(helper, "ordinary"), patch.object(helper, "run", side_effect=probe), \
                    patch.object(helper.shutil, "which", side_effect=AssertionError("no ambient compiler")):
                env = {"PATH": "/selected/bin"}
                cargo, rustc = helper.tools(bound, env)
                prefix = "/Users/runner/.rustup/toolchains/stable-" + target + "/bin/"
                self.assertEqual((cargo, rustc), (prefix + "cargo", prefix + "rustc"))
                self.assertEqual([row[0] for row in calls], [[rustc, "-vV"], [cargo, "--version"]])
                self.assertEqual(env["RUSTC"], rustc)
                self.assertEqual(env["RUSTUP_AUTO_INSTALL"], "0")
                calls.clear()
                helper.tools(bound, {"PATH": "/selected/bin"}, timeout_for=lambda cap: min(cap, 3))
                self.assertEqual([row[1]["timeout"] for row in calls], [3, 3])
                wrong_versions = (
                    positive_version.replace("release: " + expected_rust["release"], "release: 1.0.0"),
                    positive_version.replace("commit-hash: " + expected_rust["commitHash"], "commit-hash: " + "0" * 40),
                    positive_version.replace("host: " + target, "host: " + other_target),
                    "rustc " + other_rust["release"] + "\nrelease: " + other_rust["release"]
                    + "\ncommit-hash: " + other_rust["commitHash"] + "\nhost: " + target + "\n",
                )
                for version in wrong_versions:
                    calls.clear()
                    with self.subTest(target=target, version=version), self.assertRaises(helper.CheckFailure):
                        helper.tools(bound, {"PATH": "/selected/bin"})
                    self.assertEqual([row[1]["check"] for row in calls], ["rust-version-target"])


    def test_compile_cleanup_never_adopts_native_or_unexpected_outputs(self):
        names = set(helper.COMPILER_DIRECTORIES + helper.EMPTY_NATIVE_DIRECTORIES + helper.COMPILER_PRIVATE_FILES + helper.COMPILE_PUBLIC_FILES)
        helper.validate_compile_inventory(names, set())
        for altered in (names | {"native-checks.json"}, names | {"foreign-output"}, names - {"compile-checks.json"}):
            with self.assertRaises(helper.CheckFailure):
                helper.validate_compile_inventory(altered, set())
        with self.assertRaises(helper.CheckFailure):
            helper.validate_compile_inventory(names, {"native"})

        # Actual prepare and acquire, all filesystem/process edges inert and
        # scoped. No patched decorator or sibling fixture is bypassed.
        for target, expected_rust in MAC_RUST_EXPECTED.items():
            events, calls, written, guards = [], [], [], []
            MemoryPath, Stream = memory_paths(events)
            bound = mac_context(target)
            def invoke(argv, **kw):
                calls.append((list(map(str, argv)), kw))
                if kw["check"] == "source-head":
                    return bound["sourceSha"]
                if kw["check"] == "source-tree":
                    return bound["sourceTree"]
                if kw["check"] == "rust-version-target":
                    return ("release: " + expected_rust["release"] + "\ncommit-hash: "
                            + expected_rust["commitHash"] + "\nhost: " + target)
                if kw["check"] == "mac-cargo-version":
                    return "cargo 1.98.0 (abcdef123 2026-09-01)"
                if kw["check"] == "node-version":
                    return helper.NODE
                return ""
            def selected(name):
                self.assertIn(name, ("git", "node"))
                return "/usr/bin/git" if name == "git" else "/selected/bin/node"
            with patch.dict(helper.os.environ, mac_environment(target), clear=True), \
                    patch.object(helper, "Path", MemoryPath), patch.object(helper, "run", side_effect=invoke), \
                    patch.object(helper, "ordinary"), patch.object(helper, "hash_file", return_value="5" * 64), \
                    patch.object(helper, "mac_compile_inputs", return_value=bound["macCompile"]), \
                    patch.object(helper, "no_cargo_configuration", side_effect=lambda paths: guards.append(tuple(map(str, paths)))), \
                    patch.object(helper, "write_json", side_effect=lambda path, value: written.append((str(path), deepcopy(value)))), \
                    patch.object(helper.shutil, "which", side_effect=selected), \
                    patch.object(helper.tempfile, "mkdtemp", return_value=bound["root"]), \
                    patch.object(helper.zipfile, "ZipFile", Stream), patch.object(helper.time, "monotonic", return_value=100.0):
                with io.StringIO() as prepared_stdout, contextlib.redirect_stdout(prepared_stdout):
                    helper.prepare("macos", helper.MAC_COMPILE_SCOPE)
                    self.assertEqual(prepared_stdout.getvalue(),
                        "Prepared bounded source ZIP and source-bound synthetic check inputs.\n")
                prepared = next(value for path, value in written if path.endswith("context.json"))
                public = next(value for path, value in written if path.endswith("public-bindings.json"))
                self.assertIsNone(prepared["rustup"])
                self.assertEqual(prepared["macCompile"], bound["macCompile"])
                self.assertEqual(public["expectedRust"], expected_rust["release"])
                self.assertEqual(public["compiler"], expected_rust)
                self.assertEqual(helper.compiler_binding(prepared), expected_rust)
                self.assertTrue(any("/inert/source/desktop/helpers/macos-desktop-image" in paths
                                    and "/inert/source/desktop/helpers" in paths for paths in guards))
                helper.phase_mac_compile("acquire", prepared)
            commands = [row for row in calls if row[1]["check"] in ("mac-normal-locked-metadata", "mac-image-locked-metadata")]
            self.assertEqual(len(commands), 2)
            self.assertEqual([row[0][0] for row in commands],
                             ["/Users/runner/.rustup/toolchains/stable-" + target + "/bin/cargo"] * 2)
            self.assertEqual(commands[0][0][-1], "/inert/source/desktop/src-tauri/Cargo.toml")
            self.assertEqual(commands[1][0][-1], "/inert/source/desktop/helpers/macos-desktop-image/Cargo.toml")
            self.assertNotIn("--features", commands[1][0])
            self.assertEqual([row[0][1] for row in commands], ["metadata", "metadata"])
            self.assertFalse(any("rustup" == Path(arg).name for row, _ in calls for arg in row))
            receipt_value = next(value for path, value in written if path.endswith("acquire-checks.json"))
            self.assertEqual(receipt_value["rust"], expected_rust)
            self.assertEqual(receipt_value["checks"], [{"check": name, "exitCode": 0} for name in helper.MAC_COMPILE_CHECKS["acquire"]])
            self.assertTrue(any(event[:2] == ("closed", bound["root"] + "/target/mac-image-metadata.json") for event in events))
            cleanup_order = []
            with patch.object(helper, "source_unchanged", side_effect=lambda *args, **kw: cleanup_order.append("source")), \
                    patch.object(helper, "mac_compile_source_guard", side_effect=lambda *args: cleanup_order.append("guard")), \
                    patch.object(helper, "mac_compile_inputs", return_value=bound["macCompile"]), \
                    patch.object(helper, "clean_compile", side_effect=lambda *args: cleanup_order.append("cleanup")):
                helper.phase_mac_compile("clean", bound)
                self.assertEqual(cleanup_order, ["source", "guard", "cleanup"])
                cleanup_order.clear()
                with patch.object(helper, "mac_compile_inputs", return_value={}), self.assertRaises(helper.CheckFailure):
                    helper.phase_mac_compile("clean", bound)
                self.assertEqual(cleanup_order, ["source", "guard"])


    def test_compile_receipt_bytes_reject_duplicate_nonfinite_extra_or_oversized_frames(self):
        value = receipt("compile")
        raw = json.dumps(value, separators=(",", ":")).encode()
        self.assertEqual(helper.parse_compile_receipt(raw), value)
        for broken in (raw.replace(b'"schemaVersion":1', b'"schemaVersion":0,"schemaVersion":1'),
                       raw.replace(b'"exitCode":0', b'"exitCode":1,"exitCode":0', 1),
                       raw + b'{}', b'{"secret":"not real","bad":NaN}', b'\xff', b' ' * 16385, b''):
            with self.assertRaises(helper.CheckFailure):
                helper.parse_compile_receipt(broken)

        bound = mac_context()
        calls, receipts, clock = [], [], [100.0]
        def invoke(argv, **kw):
            calls.append((list(argv), deepcopy({key: value for key, value in kw.items() if key != "output"})))
            return helper.NODE if kw["check"] == "node-version" else ""
        with patch.object(helper, "source_unchanged"), patch.object(helper, "mac_compile_source_guard"), \
                patch.object(helper, "mac_compile_inputs", return_value=bound["macCompile"]), \
                patch.object(helper, "tools", return_value=("/direct/cargo", "/direct/rustc")), \
                patch.object(helper.shutil, "which", return_value="/selected/bin/node"), \
                patch.object(helper, "run", side_effect=invoke), \
                patch.object(helper, "phase_receipt", side_effect=lambda *args, **kw: receipts.append((args, kw))), \
                patch.object(helper.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.dict(helper.os.environ, {"PATH": "/selected/bin", "MRK_MACOS_DEVELOPER_ID_P12_BASE64": "synthetic-never-exported"}, clear=True):
            helper.phase_mac_compile("compile", bound)
            builds = [(argv, kw) for argv, kw in calls if kw["check"] in {row[0] for row in helper.MAC_COMPILE_GRAPHS}]
            self.assertEqual(len(builds), 3)
            self.assertEqual([kw["timeout"] for _, kw in builds], [1470, 1470, 1470])
            self.assertEqual([argv[1] for argv, _ in builds], ["build", "test", "build"])
            self.assertEqual([argv[argv.index("--target-dir") + 1] for argv, _ in builds], [bound["root"] + "/target"] * 3)
            self.assertEqual(builds[0][0][-5:], ["--release", "--features", "desktop-shell,custom-protocol", "--bin", "mobile-release-kit-desktop"])
            self.assertEqual(builds[1][0][-5:], ["--features", "desktop-shell,custom-protocol,macos-installed-observation", "--test", "installed-shell-observation", "--no-run"])
            self.assertEqual(builds[2][0][-2:], ["--release", "--lib"])
            self.assertNotIn("--features", builds[2][0])
            for argv, kw in builds:
                self.assertIn("--offline", argv)
                self.assertEqual(argv[argv.index("--jobs") + 1], "1")
                self.assertNotIn("development-runtime", argv)
                self.assertNotIn("MRK_MACOS_DEVELOPER_ID_P12_BASE64", kw["env"])
                self.assertNotIn("MRK_BUNDLED_RUNTIME_MANIFEST_SHA256", kw["env"])
                self.assertEqual(kw["env"]["MRK_MACOS_INSTALL_SOURCE_COMMIT"], bound["sourceSha"])
                self.assertEqual(kw["env"]["MRK_IMAGE_RELEASE_ID"], bound["macCompile"]["release"])
            self.assertEqual(len(receipts), 1)
            calls.clear(); receipts.clear()
            intel = mac_context("x86_64-apple-darwin")
            with patch.object(helper, "mac_compile_inputs", return_value=intel["macCompile"]):
                helper.phase_mac_compile("compile", intel)
            intel_builds = [(argv, kw) for argv, kw in calls if kw["check"] in {row[0] for row in helper.MAC_COMPILE_GRAPHS}]
            self.assertEqual(len(intel_builds), 3)
            self.assertEqual([kw["timeout"] for _, kw in intel_builds], [1500, 1500, 1500])
            for argv, kw in intel_builds:
                self.assertEqual(argv[argv.index("--target") + 1], "x86_64-apple-darwin")
                self.assertEqual(kw["env"]["MRK_IMAGE_RELEASE_ID"], intel["macCompile"]["release"])
            self.assertEqual(len(receipts), 1)
            calls.clear(); receipts.clear()
            def failed(argv, **kw):
                result = invoke(argv, **kw)
                if kw["check"] == "mac-normal-bin-compile-only":
                    raise helper.CheckFailure("original compiler failed")
                return result
            with patch.object(helper, "run", side_effect=failed), self.assertRaisesRegex(helper.CheckFailure, "original compiler failed"):
                helper.phase_mac_compile("compile", bound)
            self.assertFalse(receipts)
            self.assertFalse(any(kw["check"] == "mac-observer-compile-only" for _, kw in calls))
            calls.clear()
            def late(argv, **kw):
                result = invoke(argv, **kw)
                if kw["check"] == "mac-normal-bin-compile-only":
                    clock[0] = 1601.0
                return result
            with patch.object(helper, "run", side_effect=late), self.assertRaises(helper.CheckFailure):
                helper.phase_mac_compile("compile", bound)
            self.assertFalse(receipts)
            self.assertFalse(any(kw["check"] == "mac-observer-compile-only" for _, kw in calls))
            clock[0] = 100.0
            def late_publication(*args, **kw):
                receipts.append((args, kw))
                clock[0] = 1601.0
            with patch.object(helper, "phase_receipt", side_effect=late_publication), self.assertRaises(helper.CheckFailure):
                helper.phase_mac_compile("compile", bound)
            # Retained bytes are diagnostic only without this original phase0.
            self.assertEqual(len(receipts), 1)

            # Synthetic scheduling DATA only, not measured Intel completion.
            # Each original retains its1500s cap and all share the same endpoint.
            calls.clear(); receipts.clear(); clock[0] = 100.0
            elapsed = {"mac-normal-bin-compile-only": 1120.0,
                       "mac-observer-compile-only": 555.0,
                       "mac-image-compile-only": 515.0}
            def elapsed_original(argv, **kw):
                result = invoke(argv, **kw)
                clock[0] += elapsed.get(kw["check"], 0.0)
                return result
            with patch.object(helper, "mac_compile_inputs", return_value=intel["macCompile"]), \
                    patch.object(helper, "run", side_effect=elapsed_original):
                helper.phase_mac_compile("compile", intel)
            progressed = [(argv, kw) for argv, kw in calls if kw["check"] in elapsed]
            self.assertEqual([kw["check"] for _, kw in progressed], list(elapsed))
            self.assertEqual([kw["timeout"] for _, kw in progressed], [1500, 1500, 995])
            self.assertEqual([argv for argv, _ in progressed], [argv for argv, _ in intel_builds])
            self.assertEqual(clock[0], 2290.0)
            self.assertEqual(len(receipts), 1)

            for selected, budget in ((bound, 1500), (intel, 2700)):
                with self.subTest(target=selected["macCompile"]["target"]), \
                        patch.object(helper, "mac_compile_inputs", return_value=selected["macCompile"]):
                    calls.clear(); receipts.clear(); clock[0] = 100.0
                    with patch.object(helper, "run", side_effect=failed), self.assertRaisesRegex(helper.CheckFailure, "original compiler failed"):
                        helper.phase_mac_compile("compile", selected)
                    self.assertFalse(receipts)
                    self.assertFalse(any(kw["check"] in ("mac-observer-compile-only", "mac-image-compile-only") for _, kw in calls))
                    for returned_clock in (100.0 + budget - 30, 99.0):
                        calls.clear(); receipts.clear(); clock[0] = 100.0
                        def expired_original(argv, **kw):
                            result = invoke(argv, **kw)
                            if kw["check"] == "mac-normal-bin-compile-only":
                                clock[0] = returned_clock
                            return result
                        with patch.object(helper, "run", side_effect=expired_original), self.assertRaisesRegex(
                                helper.CheckFailure, "endpoint expired or clock reversed"):
                            helper.phase_mac_compile("compile", selected)
                        self.assertFalse(receipts)
                        self.assertFalse(any(kw["check"] in ("mac-observer-compile-only", "mac-image-compile-only") for _, kw in calls))
                    calls.clear(); receipts.clear(); clock[0] = 100.0
                    def expired_publication(*args, **kw):
                        receipts.append((args, kw))
                        clock[0] = 100.0 + budget - 30
                    with patch.object(helper, "phase_receipt", side_effect=expired_publication), self.assertRaisesRegex(
                            helper.CheckFailure, "endpoint expired or clock reversed"):
                        helper.phase_mac_compile("compile", selected)
                    self.assertEqual(len(receipts), 1)
                    self.assertEqual(sum(kw["check"] in elapsed for _, kw in calls), 3)


if __name__ == "__main__":
    unittest.main()
