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


def mac_environment(target="aarch64-apple-darwin", mode="full4"):
    arch, _, images, _, _ = helper.MAC_COMPILE_HOSTS[target]
    value = {**environment(), "GITHUB_REF": helper.MAC_COMPILE_REF,
             "GITHUB_WORKFLOW_REF": f"fictional/project/{helper.MAC_COMPILE_WORKFLOW}@{helper.MAC_COMPILE_REF}",
             "MRK_MACOS_TARGET": target, "MRK_MACOS_COMPILE_MODE": mode, "MRK_COMPILE_SELECTION": "both",
             "RUNNER_OS": "macOS", "RUNNER_ARCH": arch, "ImageOS": images[0],
             "GITHUB_WORKSPACE": "/inert/source", "RUNNER_TEMP": "/inert/tmp", "PATH": "/selected/bin",
             "GITHUB_OUTPUT": "/inert/output", "MRK_DESKTOP_PLATFORM": "macos",
             "MRK_DESKTOP_HOSTED_CHECKS": helper.MAC_COMPILE_SCOPE}
    if mode == "vault-only":
        value.update(GITHUB_EVENT_NAME="workflow_dispatch", MRK_COMPILE_SELECTION="remaining", MRK_EXPECTED_SHA="1" * 40)
    return value


def mac_context(target="aarch64-apple-darwin", mode="full4"):
    vault = ["mac-vault-bin-compile-only", "desktop/helpers/macos-vault-helper/Cargo.toml", "release", "", "mrk-vault-keychain"]
    return {**helper.compile_workflow_binding(mac_environment(target, mode), helper.MAC_COMPILE_SCOPE),
            "root": "/inert/tmp/mrk-desktop-foundation-original", "source": "/inert/source", "git": "/usr/bin/git",
            "platform": "macos", "sourceTree": "3" * 40, "workflowSha256": "2" * 64,
            "executionScope": helper.MAC_COMPILE_SCOPE,
            # Synthetic context only; never an admitted native/source receipt.
            "macCompile": {"target": target, "mode": mode, "release": helper.MAC_COMPILE_HOSTS[target][4] + "desktop-01",
                           "sources": [], "graphs": [vault, *([list(row) for row in helper.MAC_COMPILE_GRAPHS] if mode == "full4" else [])],
                           "execution": "compile-only"}}


def engineering_environment():
    value = mac_environment()
    value.pop("MRK_COMPILE_SELECTION")
    value.pop("MRK_MACOS_COMPILE_MODE")
    value.update(GITHUB_REF=helper.ENGINEERING_COMPILE_REF,
                 GITHUB_WORKFLOW_REF=f"fictional/project/{helper.ENGINEERING_COMPILE_WORKFLOW}@{helper.ENGINEERING_COMPILE_REF}",
                 MRK_DESKTOP_HOSTED_CHECKS=helper.ENGINEERING_COMPILE_SCOPE,
                 MRK_MACOS_WORK="/inert/tmp/mrk-macos-engineering-ui.ABCdef12")
    return value


def engineering_context():
    env = engineering_environment()
    return {**helper.compile_workflow_binding(env, helper.ENGINEERING_COMPILE_SCOPE),
            "root": "/inert/tmp/mrk-desktop-foundation-original", "source": "/inert/source", "git": "/usr/bin/git",
            "platform": "macos", "sourceTree": "3" * 40, "workflowSha256": "2" * 64,
            "executionScope": helper.ENGINEERING_COMPILE_SCOPE, "engineeringWork": env["MRK_MACOS_WORK"]}


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


# Independent fixed-selector DATA, never a caller-provided test filter.
SOURCE_SLOTS_CASE = "installed_runtime::android_registration_source::storage_capacity_tests::phase_checked_allocation_uses_exact_admitted_records_without_native_entry"


def source_slots_environment():
    value = mac_environment("x86_64-apple-darwin")
    value.pop("MRK_COMPILE_SELECTION")
    value.pop("MRK_MACOS_COMPILE_MODE")
    value.update(GITHUB_REF="refs/heads/verify/desktop-macos-intel-source-slots",
                 GITHUB_WORKFLOW_REF="fictional/project/.github/workflows/desktop-macos-intel-source-slots.yml@refs/heads/verify/desktop-macos-intel-source-slots",
                 MRK_DESKTOP_HOSTED_CHECKS="macos-intel-source-slots-v1")
    return value


def source_slots_context():
    return {**helper.compile_workflow_binding(source_slots_environment(), helper.SOURCE_SLOTS_SCOPE),
            "root": "/inert/tmp/mrk-desktop-foundation-original", "source": "/inert/source", "git": "/usr/bin/git",
            "platform": "macos", "sourceTree": "3" * 40, "workflowSha256": "2" * 64,
            "executionScope": "macos-intel-source-slots-v1", "rustup": None,
            "sourceSlots": {"target": "x86_64-apple-darwin", "features": ["development-runtime"],
                            "testTarget": "lib", "test": SOURCE_SLOTS_CASE}}


def source_slots_result():
    return {"test": SOURCE_SLOTS_CASE, "running": 1, "passed": 1, "failed": 0,
            "ignored": 0, "measured": 0, "filtered": 7}


def source_slots_stdout():
    return ("\nrunning 1 test\ntest " + SOURCE_SLOTS_CASE + " ... ok\n\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 0.03s\n\n").encode()


def source_slots_receipt(phase):
    bound = source_slots_context()
    checks = ["rust-version-target", "mac-cargo-version"] + (
        ["mac-source-slots-locked-metadata"] if phase == "acquire" else ["headless-test-compile-only", "mac-source-slots-data-test"])
    value = {"schemaVersion": 1, "scope": "desktop-macos-intel-source-slots-data-v1", "phase": phase, "status": "passed",
             **{key: bound[key] for key in ("sourceSha", "sourceTree", "platform", "workflowPath", "workflowSha",
                                           "workflowRef", "workflowSha256", "runId", "attempt", "sourceSlots")},
             "rust": deepcopy(MAC_RUST_EXPECTED["x86_64-apple-darwin"]), "node": None,
             "checks": [{"check": check, "exitCode": 0} for check in checks]}
    if phase == "compile":
        value["testResult"] = source_slots_result()
    return value


def source_slots_paths(events, captures):
    MemoryPath, _ = memory_paths(events)
    class Capture(io.StringIO):
        def __init__(self, path):
            super().__init__()
            self.path = str(path)
        def __exit__(self, *args):
            captures[self.path] = self.getvalue().encode()
            events.append(("closed", self.path))
            return super().__exit__(*args)
    class SlotsPath(MemoryPath):
        def open(self, *args, **kwargs):
            events.append(("open", str(self), args))
            return Capture(self)
    def writer(path, stream):
        assert str(path) == stream.path
        return (1, 3, 0o100600, 501, 20, 1, len(stream.getvalue().encode()), 1, 1)
    def read(path, expected):
        body = captures[str(path)]
        assert len(body) == expected[6]
        return body if path.name == "source-slots-test.stdout" else b""
    return SlotsPath, writer, read


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

        # The new lane compiles one real main binary; it cannot invoke any UI,
        # native fixture, installed, or writer phase through this compiler API.
        with patch.object(helper, "load_context", side_effect=AssertionError("no context IO")), \
                patch.object(helper, "tools", side_effect=AssertionError("no compiler selection")):
            for phase in ("native", "engineering-main-test", "windows-snapshot", "workflow-owner", "config-owner", "unknown"):
                with self.subTest(engineering_phase=phase), self.assertRaises(helper.CheckFailure):
                    helper.phase(phase, "macos", helper.ENGINEERING_COMPILE_SCOPE)
            for platform in ("linux", "windows", "unknown"):
                for phase in helper.COMPILE_PHASES:
                    with self.subTest(engineering_platform=platform, phase=phase), self.assertRaises(helper.CheckFailure):
                        helper.phase(phase, platform, helper.ENGINEERING_COMPILE_SCOPE)
        for phase in helper.COMPILE_PHASES:
            helper.admit_phase(helper.ENGINEERING_COMPILE_SCOPE, phase)
        self.assertEqual(helper.ENGINEERING_COMPILE_FEATURES, "desktop-shell,custom-protocol,development-runtime")
        self.assertEqual(helper.ENGINEERING_APP_IDENTIFIER, "dev.mobile-release-kit.engineering-ui")
        self.assertEqual(helper.ENGINEERING_COMPILE_TARGET, "aarch64-apple-darwin")
        self.assertEqual(helper.compiler_binding(engineering_context()), MAC_RUST_EXPECTED["aarch64-apple-darwin"])
        with self.assertRaises(helper.CheckFailure):
            helper.compiler_binding({**engineering_context(), "platform": "linux"})

        # This distinct native DATA profile still cannot dispatch a native
        # product/fixture phase or borrow another host's feature graph.
        with patch.object(helper, "load_context", side_effect=AssertionError("no context IO")), \
                patch.object(helper, "tools", side_effect=AssertionError("no tool selection")):
            for phase in ("native", "workflow-owner", "config-core", "windows-snapshot", "engineering-main-test", "unexpected"):
                with self.subTest(source_slots_phase=phase), self.assertRaises(helper.CheckFailure):
                    helper.phase(phase, "macos", helper.SOURCE_SLOTS_SCOPE)
            for platform in ("linux", "windows", "unknown"):
                for phase in helper.COMPILE_PHASES:
                    with self.subTest(source_slots_platform=platform, phase=phase), self.assertRaises(helper.CheckFailure):
                        helper.phase(phase, platform, helper.SOURCE_SLOTS_SCOPE)
        for phase in ("prepare", "acquire", "compile", "clean"):
            helper.admit_phase(helper.SOURCE_SLOTS_SCOPE, phase)
        self.assertEqual(helper.SOURCE_SLOTS_TEST, SOURCE_SLOTS_CASE)
        self.assertEqual(helper.source_slots_selection(), source_slots_context()["sourceSlots"])
        self.assertEqual(helper.compiler_binding(source_slots_context()), MAC_RUST_EXPECTED["x86_64-apple-darwin"])
        for bad in ({**source_slots_context(), "platform": "linux"},
                    {**source_slots_context(), "executionScope": helper.MAC_COMPILE_SCOPE}):
            with self.assertRaises(helper.CheckFailure):
                helper.phase_source_slots("compile", bad)
        changed = source_slots_context()
        changed["sourceSlots"]["features"] = ["registration-helper"]
        with self.assertRaises(helper.CheckFailure):
            helper.phase_source_slots("compile", changed)

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
        # Every actual row is checked independently before original root allocation.
        pairs = (("aarch64-apple-darwin", "full4"), ("x86_64-apple-darwin", "full4"),
                 ("aarch64-apple-darwin", "vault-only"))
        for target, mode in pairs:
            env = mac_environment(target, mode)
            self.assertEqual(helper.mac_compile_mode(env, target), mode)
            self.assertEqual([list(row) for row in helper.mac_compile_graphs(target, mode)], mac_context(target, mode)["macCompile"]["graphs"])
            for key in ("MRK_COMPILE_SELECTION", "MRK_MACOS_COMPILE_MODE", "MRK_MACOS_TARGET"):
                missing = dict(env); del missing[key]
                with self.subTest(target=target, mode=mode, missing=key), self.assertRaises(helper.CheckFailure):
                    helper.mac_compile_mode(missing, target)
            for bad in ("normal3", "arbitrary", "", None, False):
                with self.subTest(mode=bad), self.assertRaises(helper.CheckFailure):
                    helper.mac_compile_mode({**env, "MRK_MACOS_COMPILE_MODE": bad}, target)
            with self.assertRaises(helper.CheckFailure):
                helper.mac_compile_mode({**env, "GITHUB_EVENT_NAME": "pull_request"}, target)
            with self.assertRaises(helper.CheckFailure):
                helper.mac_compile_mode({**env, "MRK_COMPILE_SELECTION": "other"}, target)
        for target in helper.MAC_COMPILE_HOSTS:
            for selection in ("arm", "intel", "remaining"):
                mode = "vault-only" if selection == "remaining" and target == "aarch64-apple-darwin" else "full4"
                env = {**mac_environment(target, mode), "GITHUB_EVENT_NAME": "workflow_dispatch",
                       "MRK_EXPECTED_SHA": "1" * 40, "MRK_COMPILE_SELECTION": selection}
                if selection == "arm" and target != "aarch64-apple-darwin" or selection == "intel" and target != "x86_64-apple-darwin":
                    with self.assertRaises(helper.CheckFailure):
                        helper.mac_compile_mode(env, target)
                else:
                    self.assertEqual(helper.mac_compile_mode(env, target), mode)
        for target, mode in (("x86_64-apple-darwin", "vault-only"), ("unknown", "full4")):
            with self.assertRaises(helper.CheckFailure):
                helper.mac_compile_graphs(target, mode)
        env = mac_environment("aarch64-apple-darwin", "vault-only")
        with self.assertRaises(helper.CheckFailure):
            helper.mac_compile_mode({**env, "GITHUB_EVENT_NAME": "push"}, "aarch64-apple-darwin")
        with self.assertRaises(helper.CheckFailure):
            helper.mac_compile_mode({**env, "MRK_MACOS_COMPILE_MODE": "full4"}, "aarch64-apple-darwin")

        # Actual SOURCE input/hash and separate-manifest configuration guards,
        # with only bounded inert BytesIO edges (no source fixture execution).
        source_names = ("desktop/src-tauri/Cargo.toml", "desktop/src-tauri/Cargo.lock",
                        "desktop/helpers/macos-desktop-image/Cargo.toml", "desktop/helpers/macos-desktop-image/Cargo.lock",
                        "desktop/src-tauri/tauri.conf.json", "desktop/native/macos-installed-native/build.rs",
                        "desktop/packaging/macos-android-service-signing.profile", "desktop/packaging/macos-install-producer-signing.profile",
                        "desktop/helpers/macos-vault-helper/Cargo.toml", "desktop/helpers/macos-vault-helper/Cargo.lock",
                        "desktop/helpers/macos-vault-helper/src/main.rs", "desktop/native/macos-installed-native/Cargo.toml")
        fake_bodies, present, symlinks, streams, guards = {}, set(), set(), [], []
        class SourcePath(PurePosixPath):
            def open(self, mode):
                self_outer.assertEqual(mode, "rb")
                stream = io.BytesIO(fake_bodies[str(self)])
                streams.append(stream)
                return stream
            def exists(self):
                return str(self) in present
            def is_symlink(self):
                return str(self) in symlinks
        self_outer = self
        for target, mode in pairs:
            release = {"schemaVersion": 1, "packageVersion": "0.1.1", "release": helper.MAC_COMPILE_HOSTS[target][4] + "desktop-01"}
            release_name = "desktop/macos-installed-inputs/" + helper.MAC_COMPILE_HOSTS[target][3]
            fake_bodies = {"/inert/source/" + name: b"inert source data\n" for name in source_names}
            fake_bodies["/inert/source/desktop/src-tauri/Cargo.toml"] = b'[package]\nversion="0.1.1"\n'
            fake_bodies["/inert/source/desktop/src-tauri/tauri.conf.json"] = b'{"version":"0.1.1"}'
            fake_bodies["/inert/source/" + release_name] = json.dumps(release).encode()
            streams.clear()
            with patch.object(helper, "ordinary"):
                actual = helper.mac_compile_inputs(SourcePath("/inert/source"), target, mode)
            self.assertEqual(actual["mode"], mode)
            self.assertEqual(actual["graphs"], mac_context(target, mode)["macCompile"]["graphs"])
            self.assertEqual([row["path"] for row in actual["sources"]], [*source_names, release_name])
            self.assertTrue(streams and all(stream.closed for stream in streams))
            for row in actual["sources"]:
                raw = fake_bodies["/inert/source/" + row["path"]]
                self.assertEqual((row["size"], row["sha256"]), (len(raw), helper.hashlib.sha256(raw).hexdigest()))
        with patch.object(helper, "no_cargo_configuration", side_effect=lambda paths: guards.append(tuple(map(str, paths)))):
            helper.mac_compile_source_guard(SourcePath("/inert/source"), SourcePath("/inert/root"))
            self.assertEqual(guards[-1][:3], ("/inert/source/desktop/helpers/macos-desktop-image",
                                            "/inert/source/desktop/helpers/macos-vault-helper", "/inert/source/desktop/helpers"))
            for relative in ("macos-desktop-image", "macos-vault-helper"):
                path = "/inert/source/desktop/helpers/" + relative + "/target"
                for state in (present, symlinks):
                    state.add(path)
                    with self.assertRaises(helper.CheckFailure):
                        helper.mac_compile_source_guard(SourcePath("/inert/source"), SourcePath("/inert/root"))
                    state.clear()

        workflow = (HELPER.parents[2] / helper.MAC_COMPILE_WORKFLOW).read_text(encoding="utf-8")
        arm_row = '{"platform":"macos","os":"macos-26","target":"aarch64-apple-darwin","mode":"full4"}'
        intel_row = '{"platform":"macos","os":"macos-26-intel","target":"x86_64-apple-darwin","mode":"full4"}'
        arm_vault = '{"platform":"macos","os":"macos-26","target":"aarch64-apple-darwin","mode":"vault-only"}'
        matrix = ("        include: ${{ fromJSON(inputs.target == 'remaining' && '[" + arm_vault + ',' + intel_row + "]' || "
                  "inputs.target == 'arm' && '[" + arm_row + "]' || inputs.target == 'intel' && '[" + intel_row + "]' || '[" + arm_row + ',' + intel_row + "]') }}\n")
        self.assertEqual(workflow.count(matrix), 1)
        self.assertIn("      target:\n"
                      "        description: Fixed compiler rows (both full graphs, or remaining Intel plus ARM vault)\n"
                      "        required: false\n"
                      "        type: choice\n"
                      "        default: both\n"
                      "        options: [both, arm, intel, remaining]\n", workflow)
        self.assertIn("      MRK_COMPILE_SELECTION: ${{ inputs.target || 'both' }}\n", workflow)
        self.assertIn("      MRK_MACOS_COMPILE_MODE: ${{ matrix.mode }}\n", workflow)
        admission = workflow.split("      - name: Require exact disposable verification source\n", 1)[1].split(
            "      - name: Check out exact source without persisted credentials\n", 1)[0]
        self.assertIn('          if [[ "$GITHUB_EVENT_NAME" == workflow_dispatch ]]; then\n'
                      '            [[ "$MRK_EXPECTED_SHA" == "$GITHUB_SHA" ]]\n'
                      '            case "$MRK_COMPILE_SELECTION" in\n'
                      '              both) [[ "$MRK_MACOS_COMPILE_MODE" == full4 ]] ;;\n'
                      '              arm) [[ "$MRK_MACOS_TARGET" == aarch64-apple-darwin && "$MRK_MACOS_COMPILE_MODE" == full4 ]] ;;\n'
                      '              intel) [[ "$MRK_MACOS_TARGET" == x86_64-apple-darwin && "$MRK_MACOS_COMPILE_MODE" == full4 ]] ;;\n'
                      '              remaining) [[ ( "$MRK_MACOS_TARGET" == aarch64-apple-darwin && "$MRK_MACOS_COMPILE_MODE" == vault-only ) || ( "$MRK_MACOS_TARGET" == x86_64-apple-darwin && "$MRK_MACOS_COMPILE_MODE" == full4 ) ]] ;;\n'
                      '              *) exit 1 ;;\n'
                      '            esac\n'
                      '          else\n'
                      '            [[ "$GITHUB_EVENT_NAME" == push && "$MRK_COMPILE_SELECTION" == both && "$MRK_MACOS_COMPILE_MODE" == full4 ]]\n'
                      '          fi\n', admission)
        self.assertIn('[[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ && "$GITHUB_WORKFLOW_SHA" == "$GITHUB_SHA" ]]', admission)
        self.assertIn('[[ "$GITHUB_REF" == refs/heads/verify/desktop-macos-normal-compile ]]', admission)
        self.assertIn('[[ "$GITHUB_WORKFLOW_REF" == "$GITHUB_REPOSITORY/.github/workflows/desktop-macos-normal-compile.yml@$GITHUB_REF" ]]', admission)
        self.assertIn('[[ "$RUNNER_ENVIRONMENT" == github-hosted ]]', admission)
        header = workflow.split('    steps:\n', 1)[0]
        self.assertIn("    timeout-minutes: ${{ matrix.target == 'x86_64-apple-darwin' && 120 || matrix.mode == 'full4' && 50 || 45 }}\n", header)
        self.assertIn('      fail-fast: false\n      max-parallel: 2\n', header)
        acquire = workflow.split('      - name: Acquire locked active-platform inputs without npm scripts\n', 1)[1].split('      - name:', 1)[0]
        compile_step = workflow.split('      - name: Compile selected graphs without launching outputs\n', 1)[1].split('      - name:', 1)[0]
        self.assertIn('        timeout-minutes: 15\n', acquire)
        self.assertIn("        timeout-minutes: ${{ matrix.target == 'x86_64-apple-darwin' && 92 || matrix.mode == 'full4' && 32 || 25 }}\n", compile_step)
        self.assertIn("      - name: Select fixed frontend compiler\n        if: matrix.mode == 'full4'\n", workflow)
        self.assertIn("desktop-macos-normal-compile-${{ matrix.target }}-${{ matrix.mode }}-", workflow)
        self.assertNotIn("ubuntu-", workflow)
        self.assertNotIn("windows-2025", workflow)
        self.assertNotIn("secrets.", workflow)
        self.assertEqual(workflow.count("ci_foundation.py compile'"), 1)
        self.assertIn("MRK_DESKTOP_HOSTED_CHECKS: macos-normal-compile-v1", workflow)
        cleanup = workflow.split("      - name: Immediately remove positively settled compiler outputs\n", 1)[1]
        self.assertIn("        if: success()\n", cleanup)
        self.assertIn("ci_foundation.py clean'", cleanup)

        engineering = engineering_environment()
        selected = helper.compile_workflow_binding(engineering, helper.ENGINEERING_COMPILE_SCOPE)
        self.assertEqual(selected["workflowPath"], ".github/workflows/desktop-macos-engineering-ui.yml")
        for key, bad in (("GITHUB_REF", helper.MAC_COMPILE_REF), ("GITHUB_WORKFLOW_SHA", "f" * 40),
                         ("GITHUB_WORKFLOW_REF", environment()["GITHUB_WORKFLOW_REF"]),
                         ("GITHUB_RUN_ID", "0"), ("GITHUB_RUN_ATTEMPT", "0"),
                         ("GITHUB_EVENT_NAME", "workflow_dispatch")):
            with self.subTest(engineering_binding=key), self.assertRaises(helper.CheckFailure):
                helper.compile_workflow_binding({**engineering, key: bad, "MRK_EXPECTED_SHA": "1" * 40}, helper.ENGINEERING_COMPILE_SCOPE)
        # Actual new workflow source is also nominated, not a synthetic manifest.
        engineering_workflow = (HELPER.parents[2] / helper.ENGINEERING_COMPILE_WORKFLOW).read_text(encoding="utf-8")
        self.assertIn("branches: [verify/desktop-macos-engineering-ui]", engineering_workflow)
        self.assertIn("environment: macos-engineering", engineering_workflow)
        self.assertIn("runs-on: macos-26", engineering_workflow)
        self.assertIn("MRK_DESKTOP_HOSTED_CHECKS: macos-engineering-ui-compile-v1", engineering_workflow)
        self.assertNotIn("secrets.", engineering_workflow)
        self.assertNotIn("macos-26-intel", engineering_workflow)
        self.assertNotIn("--configured-signing", engineering_workflow)
        self.assertNotIn("workflow_dispatch:", engineering_workflow)
        upload = engineering_workflow.split("      - name: Retain only bounded compiler and engineering evidence", 1)[1].split("      - name: Dispose only", 1)[0]
        self.assertNotIn("*.stdout", upload)
        self.assertNotIn("*.stderr", upload)
        self.assertIn("/normal-ui/engineering-smoke.json", upload)
        self.assertIn("/normal-ui/engineering-summary.status", upload)
        self.assertNotIn("/normal-ui/*", upload)
        self.assertEqual(engineering_workflow.count('--work "$MRK_MACOS_WORK"'), 3)
        self.assertIn('--expected-source "$MRK_CURRENT_SOURCE" --expected-manifest "$MRK_CURRENT_MANIFEST"', engineering_workflow)
        self.assertIn("set -o noclobber", engineering_workflow)
        self.assertEqual(engineering_workflow.count("ci_foundation.py compile'"), 1)
        self.assertIn("--engineering-main-test", engineering_workflow)
        self.assertIn("--engineering-main-summary", engineering_workflow)
        self.assertIn("engineering-summary.status", engineering_workflow)
        self.assertLess(engineering_workflow.index("--engineering-main-summary"), engineering_workflow.index("ci_foundation.py clean'"))

        fixed = source_slots_environment()
        binding = helper.compile_workflow_binding(fixed, helper.SOURCE_SLOTS_SCOPE)
        self.assertEqual(binding["workflowPath"], ".github/workflows/desktop-macos-intel-source-slots.yml")
        for key, bad in (("GITHUB_SHA", "0" * 40), ("GITHUB_WORKFLOW_SHA", "a" * 40),
                         ("GITHUB_REF", helper.MAC_COMPILE_REF), ("GITHUB_WORKFLOW_REF", "foreign/workflow"),
                         ("GITHUB_RUN_ID", "0"), ("GITHUB_RUN_ATTEMPT", "0"), ("GITHUB_EVENT_NAME", "pull_request")):
            with self.subTest(source_slots_field=key), self.assertRaises(helper.CheckFailure):
                helper.compile_workflow_binding({**fixed, key: bad}, helper.SOURCE_SLOTS_SCOPE)
        with self.assertRaises(helper.CheckFailure):
            helper.compile_workflow_binding({**fixed, "GITHUB_EVENT_NAME": "workflow_dispatch"}, helper.SOURCE_SLOTS_SCOPE)
        self.assertEqual(helper.compile_workflow_binding({**fixed, "GITHUB_EVENT_NAME": "workflow_dispatch",
                         "MRK_EXPECTED_SHA": "1" * 40}, helper.SOURCE_SLOTS_SCOPE), binding)
        workflow = (HELPER.parents[2] / helper.SOURCE_SLOTS_WORKFLOW).read_text(encoding="utf-8")
        self.assertEqual(workflow.count("runs-on: macos-26-intel"), 1)
        self.assertIn("branches: [verify/desktop-macos-intel-source-slots]", workflow)
        self.assertEqual(workflow.count("type: string"), 1)
        self.assertIn('[[ "$MRK_EXPECTED_SHA" == "$GITHUB_SHA" ]]', workflow)
        self.assertIn('[[ "$GITHUB_WORKFLOW_SHA" == "$GITHUB_SHA" ]]', workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("timeout-minutes: 40", workflow)
        self.assertEqual(workflow.count("timeout-minutes: 16"), 2)
        for phase in ("prepare", "acquire", "compile", "clean"):
            self.assertEqual(workflow.count('desktop/tools/ci_foundation.py ' + phase + "'"), 1)
        self.assertIn("if: success() && steps.allocation.outcome == 'success'", workflow)
        upload = workflow.split("          path: |\n", 1)[1].split("          if-no-files-found:", 1)[0]
        self.assertEqual([line.strip() for line in upload.splitlines()],
                         ["${{ steps.prepare.outputs.root }}/" + name for name in
                          ("public-bindings.json", "acquire-checks.json", "compile-checks.json", "source-slots-failure.json")])
        for forbidden in ("actions/setup-node", "npm ", "--ignored", "--selector", "matrix:", ".stdout", ".stderr", "secrets."):
            self.assertNotIn(forbidden, workflow)

        # Actual direct-tools admission checks each original selected field,
        # including contradictory/space-mangled duplicates, before Cargo runs.
        original = "release: 1.98.0\ncommit-hash: 88d9e12ae178fab0fb5cc050a94da85685d449ea\nhost: x86_64-apple-darwin"
        probes = (original, original + "\nrelease: 1.98.1", original + "\n release : 1.98.0",
                  original + "\ncommit-hash: " + "a" * 40, original + "\nhost: aarch64-apple-darwin",
                  original.replace("release: 1.98.0", "release: 1.98.1"),
                  original.replace("commit-hash: 88d9e12ae178fab0fb5cc050a94da85685d449ea", ""))
        for probe in probes:
            calls = []
            def invoke(argv, **kw):
                calls.append((list(argv), kw))
                return probe if kw["check"] == "rust-version-target" else "cargo 1.98.1 (abcdef123 2026-09-01)"
            env = {"PATH": "/selected/bin"}
            with self.subTest(source_slots_probe=probe), patch.object(helper, "ordinary"), \
                    patch.object(helper, "run", side_effect=invoke):
                if probe == original:
                    cargo, rustc = helper.tools(source_slots_context(), env)
                    prefix = "/Users/runner/.rustup/toolchains/stable-x86_64-apple-darwin/bin/"
                    self.assertEqual((cargo, rustc), (prefix + "cargo", prefix + "rustc"))
                    self.assertEqual([kw["check"] for _, kw in calls], ["rust-version-target", "mac-cargo-version"])
                    self.assertEqual(env["RUSTUP_AUTO_INSTALL"], "0")
                else:
                    with self.assertRaises(helper.CheckFailure):
                        helper.tools(source_slots_context(), env)
                    self.assertEqual([kw["check"] for _, kw in calls], ["rust-version-target"])

        events = []
        MemoryPath, _ = memory_paths(events)
        bound = source_slots_context()
        loaded = deepcopy(bound)
        with patch.dict(helper.os.environ, {**fixed, "MRK_DESKTOP_CI_ROOT": bound["root"]}, clear=True), \
                patch.object(helper, "Path", MemoryPath), patch.object(helper, "ordinary"), \
                patch.object(helper, "hash_file", return_value=bound["workflowSha256"]), \
                patch.object(helper, "read_bounded_json", side_effect=lambda *args: deepcopy(loaded)), \
                patch.object(helper, "source_slots_source_guard"):
            self.assertEqual(helper.load_context("macos", helper.SOURCE_SLOTS_SCOPE), bound)
            for key, bad in (("target", "aarch64-apple-darwin"), ("features", ["desktop-shell"]),
                             ("testTarget", "bin"), ("test", "other::test")):
                loaded = deepcopy(bound); loaded["sourceSlots"][key] = bad
                with self.subTest(selection=key), self.assertRaises(helper.CheckFailure):
                    helper.load_context("macos", helper.SOURCE_SLOTS_SCOPE)
            for key, bad in (("sourceSlots", None), ("sourceTree", "0" * 40), ("source", "/foreign/source")):
                loaded = {**deepcopy(bound), key: bad}
                with self.assertRaises(helper.CheckFailure):
                    helper.load_context("macos", helper.SOURCE_SLOTS_SCOPE)

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

        # A vault-only receipt cannot claim Node or any unentered normal graph.
        bound = mac_context("aarch64-apple-darwin", "vault-only")
        checks = {"acquire": ("rust-version-target", "mac-cargo-version", "mac-vault-locked-metadata"),
                  "compile": ("rust-version-target", "mac-cargo-version", "mac-vault-bin-compile-only")}
        for phase, selected in checks.items():
            value = {"schemaVersion": 1, "scope": "desktop-macos-normal-compile-only-v1", "phase": phase, "status": "passed",
                     **{key: bound[key] for key in ("sourceSha", "platform", "workflowPath", "workflowSha", "workflowRef", "workflowSha256", "runId", "attempt", "sourceTree", "macCompile")},
                     "rust": deepcopy(MAC_RUST_EXPECTED["aarch64-apple-darwin"]), "node": None,
                     "checks": [{"check": check, "exitCode": 0} for check in selected]}
            self.assertEqual(helper.validate_compile_receipt(value, bound, phase), value)
            emitted = []
            with patch.object(helper, "write_json", side_effect=lambda path, frame: emitted.append((str(path), deepcopy(frame)))):
                helper.phase_receipt(bound, phase, list(selected), node=None)
                self.assertEqual(emitted, [(bound["root"] + "/" + phase + "-checks.json", value)])
                emitted.clear()
                with self.assertRaises(helper.CheckFailure):
                    helper.phase_receipt(bound, phase, list(helper.MAC_COMPILE_CHECKS[phase]), node=helper.NODE)
                self.assertFalse(emitted)
            for key, bad in (("node", helper.NODE), ("checks", value["checks"][:-1]),
                             ("checks", [{"check": check, "exitCode": 0} for check in helper.MAC_COMPILE_CHECKS[phase]]),
                             ("macCompile", mac_context()["macCompile"]), ("sourceSha", "4" * 40)):
                with self.subTest(phase=phase, key=key), self.assertRaises(helper.CheckFailure):
                    helper.validate_compile_receipt({**value, key: bad}, bound, phase)
            altered = deepcopy(bound["macCompile"]); del altered["mode"]
            bad_contexts = (altered, {**bound["macCompile"], "mode": None},
                            {**bound["macCompile"], "mode": "normal3"},
                            {**bound["macCompile"], "mode": "full4"},
                            {**bound["macCompile"], "target": "x86_64-apple-darwin"},
                            {**bound["macCompile"], "graphs": []})
            for bad in bad_contexts:
                with self.assertRaises(helper.CheckFailure):
                    helper.validate_compile_receipt(value, {**bound, "macCompile": bad}, phase)
        full = mac_context()
        normal_only = deepcopy(full["macCompile"])
        normal_only["graphs"] = normal_only["graphs"][1:]
        with self.assertRaises(helper.CheckFailure):
            helper.validate_compile_receipt(value, {**full, "macCompile": normal_only}, "compile")

        # Reuse the actual direct Mac tools and phase receipt code with local
        # original-command doubles. No rustup discovery/install or libtest is
        # performed by this fixed main-only profile; old profiles above persist.
        bound = engineering_context()
        expected_checks = {
            "acquire": ("rust-version-target", "mac-cargo-version", "locked-platform-metadata", "node-version", "npm-locked-no-scripts"),
            "compile": ("rust-version-target", "mac-cargo-version", "node-version", "typescript-no-emit", "vite-assets", "tauri-debug-compile-only"),
        }
        self.assertEqual(helper.ENGINEERING_COMPILE_CHECKS, expected_checks)
        for phase, checks in expected_checks.items():
            calls, events, published, discovered = [], [], [], []
            MemoryPath, _ = memory_paths(events)
            def original_call(argv, **kwargs):
                calls.append((list(map(str, argv)), {**kwargs, "env": dict(kwargs["env"])}))
                if kwargs["check"] == "rust-version-target":
                    return "rustc 1.98.1\nrelease: 1.98.1\ncommit-hash: 48a229ceaefd4985c50990b14116b6d856af0985\nhost: aarch64-apple-darwin\n"
                if kwargs["check"] == "mac-cargo-version":
                    return "cargo 1.98.1 (abcdef123 2026-09-01)"
                if kwargs["check"] == "node-version":
                    return "v24.20.0"
                return ""
            def selected_tool(name):
                discovered.append(name)
                self.assertEqual(name, "node")
                return "/selected/bin/node"
            with patch.object(helper, "Path", MemoryPath), patch.object(helper, "load_context", return_value=bound), \
                    patch.object(helper, "copy_engineering_main", return_value={"relativePath": "target/engineering-main/mobile-release-kit-desktop", "bytes": 32, "sha256": "4" * 64}), \
                    patch.object(helper, "source_unchanged"), patch.object(helper, "ordinary"), \
                    patch.object(helper, "no_cargo_configuration"), patch.object(helper, "run", side_effect=original_call), \
                    patch.object(helper.shutil, "which", side_effect=selected_tool), \
                    patch.dict(helper.os.environ, {"PATH": "/selected/bin"}, clear=True), \
                    patch.object(helper, "write_json", side_effect=lambda path, value: published.append((str(path), deepcopy(value)))):
                helper.phase(phase, "macos", helper.ENGINEERING_COMPILE_SCOPE)
            self.assertEqual([row[1]["check"] for row in calls], list(checks))
            self.assertEqual(discovered, ["node"])
            self.assertEqual(len(published), 1)
            value = published[0][1]
            self.assertEqual(value["scope"], "desktop-macos-engineering-ui-compile-only-v1")
            self.assertEqual(value["engineeringWork"], bound["engineeringWork"])
            self.assertEqual(value["sourceTree"], bound["sourceTree"])
            self.assertEqual(value["rust"], MAC_RUST_EXPECTED["aarch64-apple-darwin"])
            self.assertEqual(helper.validate_compile_receipt(value, bound, phase), value)
            for key, bad in (("scope", helper.COMPILE_EVIDENCE_SCOPE), ("engineeringWork", "/foreign/work"),
                             ("sourceTree", "f" * 40), ("checks", value["checks"][:-1]),
                             ("rust", MAC_RUST_EXPECTED["x86_64-apple-darwin"])):
                with self.subTest(engineering_receipt=key, phase=phase), self.assertRaises(helper.CheckFailure):
                    helper.validate_compile_receipt({**value, key: bad}, bound, phase)
            cargo_commands = [row for row in calls if row[0][0].endswith("/cargo") and row[1]["check"] != "mac-cargo-version"]
            self.assertEqual(len(cargo_commands), 1)
            argv, kwargs = cargo_commands[0]
            self.assertTrue(argv[0].startswith("/Users/runner/.rustup/toolchains/stable-aarch64-apple-darwin/bin/"))
            self.assertIn("--locked", argv)
            self.assertEqual(argv[argv.index("--features") + 1], "desktop-shell,custom-protocol,development-runtime")
            self.assertEqual(kwargs["env"]["RUSTUP_AUTO_INSTALL"], "0")
            self.assertEqual(kwargs["env"]["TAURI_CONFIG"], '{"identifier":"dev.mobile-release-kit.engineering-ui"}')
            self.assertNotIn("test", argv)
            if phase == "compile":
                self.assertIn("--offline", argv)
                self.assertEqual(argv[argv.index("--bin") + 1], "mobile-release-kit-desktop")
                self.assertEqual(kwargs["timeout"], 1500)
            self.assertTrue(all(not any("rustup" == part for part in row[0]) for row in calls))

        # Exercise the real streaming copy with in-memory original descriptors.
        # Cargo's primary has TWO links, but the newly published file must have
        # exactly one. No host path/open/write or binary execution occurs here.
        OriginalOS = helper.os
        class CopyOS:
            def __init__(self, fault):
                self.fault, self.nodes, self.fds, self.opened, self.closed = fault, {}, {}, [], []
                self.writes = 0
                self.next_fd = 100
                for flag in ("O_RDONLY", "O_RDWR", "O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_CREAT", "O_EXCL"):
                    setattr(self, flag, getattr(OriginalOS, flag))
                root = PurePosixPath(bound["root"])
                for path in (root, root / "target", root / "target/aarch64-apple-darwin", root / "target/aarch64-apple-darwin/debug"):
                    self.add(str(path), 0o40700)
                self.source = str(root / "target/aarch64-apple-darwin/debug/mobile-release-kit-desktop")
                self.output = str(root / "target/engineering-main/mobile-release-kit-desktop")
                self.add(self.source, 0o100755, b"actual compiled main fixture bytes", links=2)
                if fault == "source-symlink":
                    self.nodes[self.source]["mode"] = 0o120777
            def add(self, path, mode, body=b"", links=1):
                self.nodes[path] = {"mode": mode, "body": bytearray(body), "links": links, "ino": len(self.nodes) + 10}
            def get(self, path, dir_fd=None):
                return str(PurePosixPath(self.fds[dir_fd]) / str(path)) if dir_fd is not None else str(path)
            def geteuid(self):
                return 501
            def open(self, path, flags, mode=0o777, *, dir_fd=None):
                name = self.get(path, dir_fd)
                if flags & self.O_CREAT:
                    if name in self.nodes:
                        raise FileExistsError("exclusive fixture output")
                    self.add(name, 0o100000 | mode)
                node = self.nodes[name]
                if node["mode"] & 0o170000 == 0o120000:
                    raise OSError("no-follow fixture")
                if flags & self.O_DIRECTORY:
                    self.assert_directory(node)
                fd = self.next_fd
                self.next_fd += 1
                self.fds[fd] = name
                self.opened.append(fd)
                return fd
            def assert_directory(self, node):
                if node["mode"] & 0o170000 != 0o40000:
                    raise OSError("directory fixture")
            def mkdir(self, path, mode, *, dir_fd=None):
                name = self.get(path, dir_fd)
                if name in self.nodes:
                    raise FileExistsError("directory exists")
                self.add(name, 0o40000 | mode)
            def details(self, name):
                node = self.nodes[name]
                class Details:
                    pass
                value = Details()
                values = dict(st_dev=1, st_ino=node["ino"], st_mode=node["mode"], st_uid=501, st_gid=20,
                              st_nlink=node["links"], st_size=len(node["body"]), st_mtime_ns=1, st_ctime_ns=1)
                if name == self.source and self.fault == "oversized":
                    values["st_size"] = 256 * 1024 * 1024 + 1
                if name == self.source and self.fault == "original-changed" and self.writes:
                    values["st_mtime_ns"] = 2
                if name == self.output and self.fault == "copy-hardlink":
                    values["st_nlink"] = 2
                for key, item in values.items():
                    setattr(value, key, item)
                return value
            def fstat(self, fd):
                return self.details(self.fds[fd])
            def stat(self, path, *, dir_fd=None, follow_symlinks=True):
                if follow_symlinks:
                    raise AssertionError("copy must not follow names")
                return self.details(self.get(path, dir_fd))
            def pread(self, fd, size, offset):
                name = self.fds[fd]
                body = bytes(self.nodes[name]["body"])
                if name == self.source and self.fault == "early-eof":
                    body = body[:-1]
                if name == self.output and self.fault == "readback-changed":
                    body = b"!" + body[1:]
                return body[offset:offset + size]
            def write(self, fd, body):
                if self.fault == "write-zero":
                    return 0
                size = min(len(body), 3)  # Real code must complete partial writes.
                self.nodes[self.fds[fd]]["body"].extend(body[:size])
                self.writes += 1
                return size
            def fsync(self, fd):
                if self.fault == "fsync-failed":
                    raise OSError("fixture fsync")
            def close(self, fd):
                name = self.fds.pop(fd)
                self.closed.append(fd)
                if self.fault == "close-failed" and name == self.source:
                    raise OSError("consumed fixture close")
        for fault in (None, "source-symlink", "oversized", "original-changed", "copy-hardlink",
                      "early-eof", "readback-changed", "write-zero", "fsync-failed", "close-failed", "timeout", "late-close"):
            original = CopyOS(fault)
            class Clock:
                calls = 0
                def monotonic(self):
                    self.calls += 1
                    return (31 if fault == "timeout" and self.calls > 1
                            or fault == "late-close" and original.opened and len(original.closed) == len(original.opened) else 0)
            with self.subTest(copy_fault=fault), patch.object(helper, "os", original), patch.object(helper, "time", Clock()):
                if fault is None:
                    copied = helper.copy_engineering_main(bound)
                    self.assertEqual(copied, {"relativePath": "target/engineering-main/mobile-release-kit-desktop",
                        "bytes": 34, "sha256": helper.hashlib.sha256(b"actual compiled main fixture bytes").hexdigest()})
                    self.assertEqual(bytes(original.nodes[original.output]["body"]), b"actual compiled main fixture bytes")
                    self.assertEqual(original.nodes[original.source]["links"], 2)
                    self.assertEqual(original.nodes[original.output]["links"], 1)
                    self.assertGreater(original.writes, 1)
                else:
                    with self.assertRaises((helper.CheckFailure, OSError)):
                        helper.copy_engineering_main(bound)
            self.assertEqual(original.fds, {})
            self.assertEqual(sorted(original.closed), sorted(original.opened))
            self.assertEqual(len(original.closed), len(set(original.closed)))
        self.assertIs(helper.os, OriginalOS)
        for bad in ({"relativePath": "target/debug/foreign", "bytes": 1, "sha256": "4" * 64},
                    {"relativePath": helper.ENGINEERING_MAIN_RELATIVE, "bytes": True, "sha256": "4" * 64},
                    {"relativePath": helper.ENGINEERING_MAIN_RELATIVE, "bytes": 256 * 1024 * 1024 + 1, "sha256": "4" * 64},
                    {"relativePath": helper.ENGINEERING_MAIN_RELATIVE, "bytes": 1, "sha256": "0" * 64}):
            with self.subTest(copy_receipt=bad), self.assertRaises(helper.CheckFailure):
                helper.validate_engineering_main(bad)

        # Exact completion DATA is separate from mere compile receipts. A
        # missing/nonzero/unknown UI original cannot authorize even first delete.
        digests = {key: "a" * 64 for key in ("compilerReceiptSha256", "runtimeResultSha256", "runtimeManifestSha256",
            "testAdmissionSha256", "summaryAdmissionSha256", "nativeSummarySha256")}
        completed = {"schemaVersion": 1, "scope": "engineering-main-ui-smoke-only", "status": "passed",
            **{key: bound[key] for key in ("sourceSha", "sourceTree", "workflowPath", "workflowSha", "workflowRef",
                                         "workflowSha256", "runId", "attempt", "engineeringWork")},
            "compilerRoot": bound["root"], "target": "aarch64-apple-darwin", **digests,
            "compilerBinarySha256": "4" * 64, "runtimeRosterSha256": "b" * 64, "applicationRosterSha256": "c" * 64,
            "testIdentifier": "MRKNormalAppUITests/NormalAppUITests/testEngineeringMainCatalogueAndQuit",
            "testCounts": {"totalTestCount": 1, "passedTests": 1, "failedTests": 0, "skippedTests": 0, "expectedFailures": 0},
            "sameOriginalNormalQuitObserved": True, "cleanExitStatus": None, "allWorkerFinality": "not-established",
            "fullUIQualified": False, "productReady": False, "sourcePrePostMatched": True, "inputPrePostMatched": True,
            "inputOriginalClosesCompleted": True, "generatedRunnerOriginalClosesCompleted": True,
            "originalCommandsReturned": True, "originalWrapperZeroRequired": True}
        compiled = {"compiledMain": {"relativePath": "target/engineering-main/mobile-release-kit-desktop", "bytes": 32, "sha256": "4" * 64}}
        self.assertEqual(len(completed), 36)
        self.assertIs(helper.validate_engineering_cleanup(completed, bound, compiled, digests), completed)
        for key, bad in (("sourceSha", "f" * 40), ("sourceTree", "e" * 40), ("runId", "456"), ("attempt", "3"),
                         ("compilerRoot", "/foreign/root"), ("engineeringWork", "/foreign/work"),
                         ("target", "x86_64-apple-darwin"), ("sameOriginalNormalQuitObserved", False),
                         ("inputOriginalClosesCompleted", False), ("generatedRunnerOriginalClosesCompleted", False),
                         ("sourcePrePostMatched", False), ("inputPrePostMatched", False), ("originalCommandsReturned", False),
                         ("originalWrapperZeroRequired", False), ("cleanExitStatus", 0), ("allWorkerFinality", "known"),
                         ("fullUIQualified", True), ("productReady", True), ("compilerBinarySha256", "5" * 64),
                         ("compilerReceiptSha256", "6" * 64), ("runtimeResultSha256", "7" * 64),
                         ("nativeSummarySha256", "8" * 64), ("unexpected", True)):
            with self.subTest(cleanup_field=key), self.assertRaises(helper.CheckFailure):
                helper.validate_engineering_cleanup({**completed, key: bad}, bound, compiled, digests)
        for counts in ({**completed["testCounts"], "skippedTests": 1}, {**completed["testCounts"], "totalTestCount": 2},
                       {**completed["testCounts"], "passedTests": True}):
            with self.assertRaises(helper.CheckFailure):
                helper.validate_engineering_cleanup({**completed, "testCounts": counts}, bound, compiled, digests)
        with patch.object(helper, "engineering_cleanup", side_effect=helper.CheckFailure("unknown UI original")) as terminal, \
                patch.object(helper.shutil, "rmtree", side_effect=AssertionError("must not delete before positive UI")):
            with self.assertRaises(helper.CheckFailure):
                helper.clean_compile(bound)
            terminal.assert_called_once_with(bound)

        # A compile0 is not the DATA test: both original checks, exact selector,
        # one nonignored result and the same source/tree/run are mandatory.
        bound = source_slots_context()
        for phase in ("acquire", "compile"):
            positive = source_slots_receipt(phase)
            self.assertEqual(helper.validate_compile_receipt(positive, bound, phase), positive)
            published = []
            with patch.object(helper, "write_json", side_effect=lambda path, value: published.append((str(path), deepcopy(value)))):
                helper.phase_receipt(bound, phase, [row["check"] for row in positive["checks"]], node=None,
                                     source_slots_result=source_slots_result() if phase == "compile" else None)
            self.assertEqual(published, [(bound["root"] + "/" + phase + "-checks.json", positive)])
            for key, bad in (("scope", "desktop-macos-normal-compile-only-v1"), ("sourceTree", "4" * 40),
                             ("sourceSha", "4" * 40), ("workflowSha256", "4" * 64), ("attempt", "3"),
                             ("node", helper.NODE), ("rust", MAC_RUST_EXPECTED["aarch64-apple-darwin"]),
                             ("checks", positive["checks"][:-1]), ("checks", list(reversed(positive["checks"]))),
                             ("extra", None), ("sourceSlots", {**positive["sourceSlots"], "features": []})):
                with self.subTest(source_slots_phase=phase, field=key), self.assertRaises(helper.CheckFailure):
                    helper.validate_compile_receipt({**deepcopy(positive), key: bad}, bound, phase)
            for check_index in range(len(positive["checks"])):
                for exit_code in (False, 1, None):
                    bad = deepcopy(positive); bad["checks"][check_index]["exitCode"] = exit_code
                    with self.assertRaises(helper.CheckFailure):
                        helper.validate_compile_receipt(bad, bound, phase)
            changed = deepcopy(bound); changed["sourceSlots"]["target"] = "aarch64-apple-darwin"
            with self.assertRaises(helper.CheckFailure):
                helper.validate_compile_receipt(positive, changed, phase)
        for bad in (None, {}, {**source_slots_result(), "passed": 0}, {**source_slots_result(), "running": 2},
                    {**source_slots_result(), "passed": True}, {**source_slots_result(), "ignored": 1},
                    {**source_slots_result(), "failed": 1}, {**source_slots_result(), "measured": 1},
                    {**source_slots_result(), "test": "other::test"}, {**source_slots_result(), "filtered": -1},
                    {**source_slots_result(), "filtered": 65536}, {**source_slots_result(), "filtered": False},
                    {**source_slots_result(), "extra": 0}):
            with self.subTest(result=bad), self.assertRaises(helper.CheckFailure):
                helper.validate_compile_receipt({**source_slots_receipt("compile"), "testResult": bad}, bound, "compile")
        missing = source_slots_receipt("compile"); del missing["testResult"]
        with self.assertRaises(helper.CheckFailure):
            helper.validate_compile_receipt(missing, bound, "compile")
        with self.assertRaises(helper.CheckFailure):
            helper.validate_compile_receipt({**source_slots_receipt("acquire"), "testResult": source_slots_result()}, bound, "acquire")
        published = []
        with patch.object(helper, "write_json", side_effect=lambda *args: published.append(args)):
            for wrong_node, wrong_result in ((helper.NODE, source_slots_result()), (None, None)):
                with self.assertRaises(helper.CheckFailure):
                    helper.phase_receipt(bound, "compile", [row["check"] for row in source_slots_receipt("compile")["checks"]],
                                         node=wrong_node, source_slots_result=wrong_result)
            with self.assertRaises(helper.CheckFailure):
                helper.phase_receipt(bound, "acquire", [row["check"] for row in source_slots_receipt("acquire")["checks"]],
                                     source_slots_result=source_slots_result())
        self.assertFalse(published)
        positive_stdout = source_slots_stdout()
        self.assertEqual(helper.source_slots_test_result(positive_stdout), source_slots_result())
        for broken in (b"", b"\xff", positive_stdout.decode(), b" " * (1024 * 1024 + 1),
                       positive_stdout.replace(b"running 1 test", b"running 0 tests"),
                       positive_stdout.replace(b"running 1 test", b"running 2 tests"),
                       positive_stdout.replace(b"1 passed", b"0 passed"),
                       positive_stdout.replace(b"0 failed", b"1 failed"),
                       positive_stdout.replace(b"0 ignored", b"1 ignored"),
                       positive_stdout.replace(b"... ok", b"... ignored"),
                       positive_stdout.replace(SOURCE_SLOTS_CASE.encode(), b"other::test"),
                       positive_stdout.replace(b"7 filtered", b"65536 filtered"),
                       b"compiler diagnostic\n" + positive_stdout, positive_stdout + positive_stdout):
            with self.subTest(stdout=broken[:80]), self.assertRaises(helper.CheckFailure):
                helper.source_slots_test_result(broken)


    def test_compile_cleanup_never_adopts_native_or_unexpected_outputs(self):
        names = set(helper.COMPILER_DIRECTORIES + helper.EMPTY_NATIVE_DIRECTORIES + helper.COMPILER_PRIVATE_FILES + helper.COMPILE_PUBLIC_FILES)
        helper.validate_compile_inventory(names, set())
        for altered in (names | {"native-checks.json"}, names | {"foreign-output"}, names - {"compile-checks.json"}):
            with self.assertRaises(helper.CheckFailure):
                helper.validate_compile_inventory(altered, set())
        with self.assertRaises(helper.CheckFailure):
            helper.validate_compile_inventory(names, {"native"})

        pairs = (("aarch64-apple-darwin", "full4"), ("x86_64-apple-darwin", "full4"),
                 ("aarch64-apple-darwin", "vault-only"))
        for target, mode in pairs:
            expected_rust = MAC_RUST_EXPECTED[target]
            events, calls, written, guards, input_calls = [], [], [], [], []
            MemoryPath, Stream = memory_paths(events)
            bound = mac_context(target, mode)
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
                    self.assertEqual(mode, "full4")
                    return helper.NODE
                return ""
            def selected(name):
                self.assertIn(name, ("git", "node") if mode == "full4" else ("git",))
                return "/usr/bin/git" if name == "git" else "/selected/bin/node"
            def selected_inputs(source, selected_target, selected_mode):
                input_calls.append((str(source), selected_target, selected_mode))
                return deepcopy(mac_context(selected_target, selected_mode)["macCompile"])
            with patch.dict(helper.os.environ, mac_environment(target, mode), clear=True), \
                    patch.object(helper, "Path", MemoryPath), patch.object(helper, "run", side_effect=invoke), \
                    patch.object(helper, "ordinary"), patch.object(helper, "hash_file", return_value="5" * 64), \
                    patch.object(helper, "mac_compile_inputs", side_effect=selected_inputs), \
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
                self.assertEqual(public["macCompile"], prepared["macCompile"])
                self.assertEqual(public["expectedRust"], expected_rust["release"])
                self.assertEqual(public["compiler"], expected_rust)
                self.assertEqual(helper.compiler_binding(prepared), expected_rust)
                self.assertTrue(any("/inert/source/desktop/helpers/macos-desktop-image" in paths
                                    and "/inert/source/desktop/helpers/macos-vault-helper" in paths
                                    and "/inert/source/desktop/helpers" in paths for paths in guards))
                helper.phase_mac_compile("acquire", prepared)
            self.assertTrue(input_calls and all(row == (bound["source"], target, mode) for row in input_calls))
            metadata_names = ("mac-vault-locked-metadata", "mac-normal-locked-metadata", "mac-image-locked-metadata") if mode == "full4" else ("mac-vault-locked-metadata",)
            commands = [row for row in calls if row[1]["check"] in metadata_names]
            self.assertEqual([row[1]["check"] for row in commands], list(metadata_names))
            self.assertEqual([row[0][0] for row in commands],
                             ["/Users/runner/.rustup/toolchains/stable-" + target + "/bin/cargo"] * len(commands))
            expected_paths = ["desktop/helpers/macos-vault-helper/Cargo.toml"] + (["desktop/src-tauri/Cargo.toml", "desktop/helpers/macos-desktop-image/Cargo.toml"] if mode == "full4" else [])
            self.assertEqual([row[0][-1] for row in commands], [bound["source"] + "/" + path for path in expected_paths])
            self.assertEqual([row[0][1] for row in commands], ["metadata"] * len(commands))
            self.assertNotIn("--features", commands[0][0])
            if mode == "full4":
                self.assertEqual(commands[1][0][commands[1][0].index("--features") + 1], "desktop-shell,custom-protocol,macos-installed-observation")
                self.assertNotIn("--features", commands[2][0])
            for argv, kw in commands:
                self.assertIn("--locked", argv)
                self.assertEqual(argv[argv.index("--filter-platform") + 1], target)
                self.assertEqual(kw["timeout"], 600)
            self.assertFalse(any("rustup" == Path(arg).name for row, _ in calls for arg in row))
            receipt_value = next(value for path, value in written if path.endswith("acquire-checks.json"))
            expected_checks = ["rust-version-target", "mac-cargo-version", *metadata_names] + (["node-version", "npm-locked-no-scripts"] if mode == "full4" else [])
            self.assertEqual(receipt_value["rust"], expected_rust)
            self.assertEqual(receipt_value["node"], helper.NODE if mode == "full4" else None)
            self.assertEqual(receipt_value["checks"], [{"check": name, "exitCode": 0} for name in expected_checks])
            output_names = ["target/mac-vault-metadata.json", "metadata.json", "target/mac-image-metadata.json"] if mode == "full4" else ["metadata.json"]
            for name in output_names:
                self.assertTrue(any(event[:2] == ("closed", bound["root"] + "/" + name) for event in events))
            if mode == "vault-only":
                self.assertFalse(any(row[1]["check"] in ("node-version", "npm-locked-no-scripts") for row in calls))

            # Actual retained-context reader recomputes mode+SOURCE, not a
            # caller-provided graph list or a mode-less default.
            loaded_frame = deepcopy(prepared)
            class ContextPath(MemoryPath):
                def read_text(self, **kwargs):
                    self_outer.assertTrue(str(self).endswith('/context.json'))
                    return json.dumps(loaded_frame)
            self_outer = self
            load_env = {**mac_environment(target, mode), "MRK_DESKTOP_CI_ROOT": bound["root"]}
            with patch.dict(helper.os.environ, load_env, clear=True), patch.object(helper, "Path", ContextPath), \
                    patch.object(helper, "ordinary"), patch.object(helper, "hash_file", return_value="5" * 64), \
                    patch.object(helper, "mac_compile_inputs", side_effect=selected_inputs):
                self.assertEqual(helper.load_context("macos", helper.MAC_COMPILE_SCOPE), prepared)
                for bad_mode in (None, "normal3", "other"):
                    loaded_frame = deepcopy(prepared)
                    if bad_mode is None:
                        del loaded_frame["macCompile"]["mode"]
                    else:
                        loaded_frame["macCompile"]["mode"] = bad_mode
                    with self.assertRaises(helper.CheckFailure):
                        helper.load_context("macos", helper.MAC_COMPILE_SCOPE)
                loaded_frame = deepcopy(prepared)
                loaded_frame["macCompile"]["graphs"] = []
                with self.assertRaises(helper.CheckFailure):
                    helper.load_context("macos", helper.MAC_COMPILE_SCOPE)

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

            # Invoke actual cleanup against a finite, original in-memory tree.
            # The same parser/validator checks both receipts before any delete.
            files, directories, symbolic, cleanup_events = {}, set(), set(), []
            source_outputs = [bound["source"] + "/" + rel for rel in ("desktop/node_modules", "desktop/dist", "desktop/src-tauri/gen")]
            class MemoryReceipt(io.BytesIO):
                def __init__(self, path, value):
                    super().__init__(value); self.path = path
                def close(self):
                    if not self.closed:
                        cleanup_events.append(("close", self.path))
                    super().close()
            class CleanPath(PurePosixPath):
                def exists(self):
                    return str(self) in files or str(self) in directories
                def is_symlink(self):
                    return str(self) in symbolic
                def is_dir(self):
                    return str(self) in directories
                def stat(self):
                    class Info:
                        st_file_attributes = 0
                    result = Info(); result.st_size = len(files.get(str(self), b''))
                    return result
                lstat = stat
                def open(self, mode):
                    self_outer.assertEqual(mode, "rb")
                    return MemoryReceipt(str(self), files[str(self)])
                def iterdir(self):
                    return iter(CleanPath(name) for name in sorted(set(files) | directories) if PurePosixPath(name).parent == self)
                def rmdir(self):
                    self_outer.assertFalse(list(self.iterdir()))
                    directories.remove(str(self)); cleanup_events.append(("rmdir", str(self)))
                def unlink(self):
                    del files[str(self)]; cleanup_events.append(("unlink", str(self)))
            def reset_tree():
                files.clear(); directories.clear(); symbolic.clear(); cleanup_events.clear()
                directories.update(bound["root"] + "/" + name for name in helper.COMPILER_DIRECTORIES + helper.EMPTY_NATIVE_DIRECTORIES)
                if mode == "full4":
                    directories.update(source_outputs)
                files.update({bound["root"] + "/" + name: b"inert data" for name in helper.COMPILER_PRIVATE_FILES + helper.COMPILE_PUBLIC_FILES})
                for phase in ("acquire", "compile"):
                    checks = expected_checks if phase == "acquire" else ["rust-version-target", "mac-cargo-version", "mac-vault-bin-compile-only"] + (["node-version", "typescript-no-emit", "vite-assets", "mac-normal-bin-compile-only", "mac-observer-compile-only", "mac-image-compile-only"] if mode == "full4" else [])
                    frame = {"schemaVersion": 1, "scope": "desktop-macos-normal-compile-only-v1", "phase": phase, "status": "passed",
                             **{key: bound[key] for key in ("sourceSha", "platform", "workflowPath", "workflowSha", "workflowRef", "workflowSha256", "runId", "attempt", "sourceTree", "macCompile")},
                             "rust": deepcopy(expected_rust), "node": helper.NODE if mode == "full4" else None,
                             "checks": [{"check": check, "exitCode": 0} for check in checks]}
                    files[bound["root"] + "/" + phase + "-checks.json"] = json.dumps(frame).encode()
            def original_file(path):
                helper.require(str(path) in files and str(path) not in symbolic, "inert original file differs")
            def remove_tree(path):
                value = str(path)
                self.assertIn(value, directories)
                self.assertNotIn(value, symbolic)
                cleanup_events.append(("rmtree", value))
                for name in list(files):
                    if name.startswith(value + "/"):
                        del files[name]
                for name in list(directories):
                    if name == value or name.startswith(value + "/"):
                        directories.remove(name)
            def no_deletion():
                self.assertFalse(any(event[0] in ("rmtree", "rmdir", "unlink") for event in cleanup_events))
            with patch.object(helper, "Path", CleanPath), patch.object(helper, "ordinary", side_effect=original_file), \
                    patch.object(helper.shutil, "rmtree", side_effect=remove_tree):
                reset_tree()
                with io.StringIO() as cleanup_stdout, contextlib.redirect_stdout(cleanup_stdout):
                    helper.clean_compile(bound)
                    self.assertEqual(cleanup_stdout.getvalue(),
                        "Removed settled compiler-only outputs; preserved exactly three public receipts. No native qualification.\n")
                self.assertEqual(set(files), {bound["root"] + "/" + name for name in helper.COMPILE_PUBLIC_FILES})
                self.assertFalse(directories)
                first_delete = next(index for index, event in enumerate(cleanup_events) if event[0] == "rmtree")
                self.assertEqual([event[0] for event in cleanup_events[:first_delete]], ["close", "close"])
                if mode == "vault-only":
                    self.assertTrue(all(not value.startswith(bound["source"] + "/") for event, value in cleanup_events if event == "rmtree"))
                    for path in source_outputs:
                        for state in (directories, symbolic):
                            reset_tree(); state.add(path)
                            with self.assertRaises(helper.CheckFailure):
                                helper.clean_compile(bound)
                            no_deletion()
                else:
                    reset_tree(); directories.remove(source_outputs[0])
                    with self.assertRaises(helper.CheckFailure):
                        helper.clean_compile(bound)
                    no_deletion()
                reset_tree(); del files[bound["root"] + "/compile-checks.json"]
                with self.assertRaises(helper.CheckFailure):
                    helper.clean_compile(bound)
                no_deletion()
                reset_tree()
                key = bound["root"] + "/compile-checks.json"
                foreign = json.loads(files[key]); foreign["sourceSha"] = "9" * 40
                files[key] = json.dumps(foreign).encode()
                with self.assertRaises(helper.CheckFailure):
                    helper.clean_compile(bound)
                no_deletion()

        # Actual prepare + acquisition, with only original IO/commands replaced
        # by finite in-memory doubles. No Node/rustup or extra graph enters.
        bound = source_slots_context()
        events, captures, written, calls, guards = [], {}, [], [], []
        SlotsPath, writer, read = source_slots_paths(events, captures)
        _, ZipStream = memory_paths(events)
        def invoke_slots(argv, **kw):
            calls.append((list(map(str, argv)), {**kw, "env": dict(kw["env"])}))
            if kw["check"] == "source-head":
                return bound["sourceSha"]
            if kw["check"] == "source-tree":
                return bound["sourceTree"]
            if kw["check"] == "rust-version-target":
                return "release: 1.98.0\ncommit-hash: 88d9e12ae178fab0fb5cc050a94da85685d449ea\nhost: x86_64-apple-darwin"
            if kw["check"] == "mac-cargo-version":
                return "cargo 1.98.0 (abcdef123 2026-09-01)"
            if kw["check"] == "mac-source-slots-locked-metadata":
                kw["output"].write('{"packages":[]}\n')
                self.assertIsNotNone(kw["diagnostics"])
            return ""
        def only_git(name):
            self.assertEqual(name, "git")
            return "/usr/bin/git"
        with patch.dict(helper.os.environ, source_slots_environment(), clear=True), \
                patch.object(helper, "Path", SlotsPath), patch.object(helper, "run", side_effect=invoke_slots), \
                patch.object(helper, "ordinary"), patch.object(helper, "hash_file", return_value="2" * 64), \
                patch.object(helper, "no_cargo_configuration", side_effect=lambda paths: guards.append(tuple(map(str, paths)))), \
                patch.object(helper, "write_json", side_effect=lambda path, value: written.append((str(path), deepcopy(value)))), \
                patch.object(helper.shutil, "which", side_effect=only_git), \
                patch.object(helper.tempfile, "mkdtemp", return_value=bound["root"]), \
                patch.object(helper.zipfile, "ZipFile", ZipStream), patch.object(helper.time, "monotonic", return_value=100.0), \
                patch.object(helper, "source_slots_writer", side_effect=writer), patch.object(helper, "source_slots_read", side_effect=read):
            with io.StringIO() as prepared_stdout, contextlib.redirect_stdout(prepared_stdout):
                helper.prepare("macos", helper.SOURCE_SLOTS_SCOPE)
                self.assertEqual(prepared_stdout.getvalue(), "Prepared bounded source ZIP and source-bound synthetic check inputs.\n")
            prepared = next(value for path, value in written if path.endswith("/context.json"))
            public = next(value for path, value in written if path.endswith("/public-bindings.json"))
            self.assertIsNone(prepared["rustup"])
            self.assertEqual(prepared["sourceSlots"], bound["sourceSlots"])
            self.assertEqual(public["sourceSlots"], bound["sourceSlots"])
            self.assertEqual(public["sourceTree"], bound["sourceTree"])
            self.assertEqual(public["compiler"], MAC_RUST_EXPECTED["x86_64-apple-darwin"])
            self.assertIsNone(public["node"])
            self.assertNotIn("test-execution", public["notQualified"])
            self.assertTrue({"other-tests", "supplier-native-loading", "Apple-provider-closure", "service-registration",
                             "signing", "installed-runtime"}.issubset(public["notQualified"]))
            helper.phase_source_slots("acquire", prepared)
        metadata = [(argv, kw) for argv, kw in calls if kw["check"] == "mac-source-slots-locked-metadata"]
        self.assertEqual(len(metadata), 1)
        argv, kw = metadata[0]
        self.assertEqual(argv, ["/Users/runner/.rustup/toolchains/stable-x86_64-apple-darwin/bin/cargo", "metadata",
                               "--locked", "--format-version", "1", "--no-default-features", "--features", "development-runtime",
                               "--filter-platform", "x86_64-apple-darwin", "--manifest-path", bound["source"] + "/desktop/src-tauri/Cargo.toml"])
        self.assertEqual(kw["timeout"], 600)
        self.assertEqual(next(value for path, value in written if path.endswith("/acquire-checks.json")), source_slots_receipt("acquire"))
        self.assertEqual([kw["check"] for _, kw in calls if kw["check"] not in ("source-head", "source-tree", "source-clean")],
                         ["rust-version-target", "mac-cargo-version", "mac-source-slots-locked-metadata"])
        self.assertTrue(any(bound["root"] + "/home" in row and bound["root"] + "/cargo" in row for row in guards))
        self.assertTrue(kw["output"].closed and kw["diagnostics"].closed)

        # Actual ambient/config/adjacent-output refusal, without touching disk.
        paths = set()
        class GuardPath(PurePosixPath):
            def exists(self):
                return str(self) in paths
            def is_symlink(self):
                return str(self) in paths
        with patch.dict(helper.os.environ, {}, clear=True):
            helper.source_slots_source_guard(GuardPath(bound["source"]), GuardPath(bound["root"]))
            for relative in ("desktop/node_modules", "desktop/dist", "desktop/src-tauri/gen", "desktop/src-tauri/target",
                             "desktop/helpers/macos-vault-helper/target", "desktop/src-tauri/.cargo/config.toml"):
                paths.add(bound["source"] + "/" + relative)
                with self.subTest(adjacent=relative), self.assertRaises(helper.CheckFailure):
                    helper.source_slots_source_guard(GuardPath(bound["source"]), GuardPath(bound["root"]))
                paths.clear()
            for relative in ("home/.cargo/config", "cargo/.cargo/config.toml"):
                paths.add(bound["root"] + "/" + relative)
                with self.assertRaises(helper.CheckFailure):
                    helper.source_slots_source_guard(GuardPath(bound["source"]), GuardPath(bound["root"]))
                paths.clear()
            for flag in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
                         "CARGO_BUILD_RUSTFLAGS", "CARGO_TARGET_X86_64_APPLE_DARWIN_RUSTFLAGS", "CARGO_TARGET_X86_64_APPLE_DARWIN_LINKER"):
                with patch.dict(helper.os.environ, {flag: ""}), self.assertRaises(helper.CheckFailure):
                    helper.source_slots_source_guard(GuardPath(bound["source"]), GuardPath(bound["root"]))

        # Reuse the finite cleanup tree defined above, but replace its synthetic
        # normal receipts with this profile's exact acquisition+DATA originals.
        # The existing classes close reads and record every inert deletion.
        def reset_slots_tree():
            files.clear(); directories.clear(); symbolic.clear(); cleanup_events.clear()
            directories.update(bound["root"] + "/" + name for name in helper.COMPILER_DIRECTORIES + helper.EMPTY_NATIVE_DIRECTORIES)
            files.update({bound["root"] + "/" + name: b"inert data" for name in helper.COMPILER_PRIVATE_FILES + helper.COMPILE_PUBLIC_FILES})
            for phase_name in ("acquire", "compile"):
                files[bound["root"] + "/" + phase_name + "-checks.json"] = json.dumps(source_slots_receipt(phase_name)).encode()
        source_order = []
        with patch.object(helper, "Path", CleanPath), patch.object(helper, "ordinary", side_effect=original_file), \
                patch.object(helper.shutil, "rmtree", side_effect=remove_tree), \
                patch.object(helper, "source_unchanged", side_effect=lambda *args, **kw: source_order.append("source")), \
                patch.object(helper, "source_slots_source_guard", side_effect=lambda *args: source_order.append("guard")):
            reset_slots_tree()
            with io.StringIO() as cleanup_stdout, contextlib.redirect_stdout(cleanup_stdout):
                helper.phase_source_slots("clean", bound)
                self.assertEqual(cleanup_stdout.getvalue(), "Removed settled compiler-only outputs; preserved exactly three public receipts. No native qualification.\n")
            self.assertEqual(source_order, ["source", "guard"])
            self.assertEqual(set(files), {bound["root"] + "/" + name for name in helper.COMPILE_PUBLIC_FILES})
            self.assertFalse(directories)
            for fault in ("failure-summary", "foreign-output", "missing-receipt", "ignored", "native-output", "frontend", "symlink"):
                reset_slots_tree()
                if fault in ("failure-summary", "foreign-output"):
                    files[bound["root"] + ("/source-slots-failure.json" if fault == "failure-summary" else "/foreign")] = b"{}"
                elif fault == "missing-receipt":
                    del files[bound["root"] + "/compile-checks.json"]
                elif fault == "ignored":
                    value = source_slots_receipt("compile"); value["testResult"]["ignored"] = 1
                    files[bound["root"] + "/compile-checks.json"] = json.dumps(value).encode()
                elif fault == "native-output":
                    files[bound["root"] + "/native/foreign"] = b"original"
                elif fault == "frontend":
                    directories.add(bound["source"] + "/desktop/dist")
                else:
                    symbolic.add(bound["root"] + "/target")
                with self.subTest(cleanup_fault=fault), self.assertRaises(helper.CheckFailure):
                    helper.phase_source_slots("clean", bound)
                no_deletion()


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
            self.assertEqual([kw["timeout"] for _, kw in builds], [1500, 1500, 1500])
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
            self.assertEqual([kw["check"] for _, kw in calls],
                             ["mac-vault-bin-compile-only", "node-version", "typescript-no-emit", "vite-assets",
                              "mac-normal-bin-compile-only", "mac-observer-compile-only", "mac-image-compile-only"])
            vault_argv, vault_kw = calls[0]
            self.assertEqual(vault_argv[-5:], ["--manifest-path", bound["source"] + "/desktop/helpers/macos-vault-helper/Cargo.toml",
                                             "--release", "--bin", "mrk-vault-keychain"])
            self.assertNotIn("--features", vault_argv)
            self.assertEqual(vault_kw["timeout"], 1500)
            self.assertEqual(vault_argv[vault_argv.index("--jobs") + 1], "1")
            self.assertIn("--locked", vault_argv)
            self.assertIn("--offline", vault_argv)
            self.assertEqual(receipts[0][0][2], list(helper.MAC_COMPILE_CHECKS["compile"]))
            calls.clear(); receipts.clear()
            def vault_failed(argv, **kw):
                result = invoke(argv, **kw)
                if kw["check"] == "mac-vault-bin-compile-only":
                    raise helper.CheckFailure("original vault compiler failed")
                return result
            with patch.object(helper, "run", side_effect=vault_failed), self.assertRaisesRegex(helper.CheckFailure, "original vault compiler failed"):
                helper.phase_mac_compile("compile", bound)
            self.assertEqual([kw["check"] for _, kw in calls], ["mac-vault-bin-compile-only"])
            self.assertFalse(receipts)
            calls.clear(); receipts.clear()
            intel = mac_context("x86_64-apple-darwin")
            with patch.object(helper, "mac_compile_inputs", return_value=intel["macCompile"]):
                helper.phase_mac_compile("compile", intel)
            intel_builds = [(argv, kw) for argv, kw in calls if kw["check"] in {row[0] for row in helper.MAC_COMPILE_GRAPHS}]
            self.assertEqual(len(intel_builds), 3)
            self.assertEqual([kw["timeout"] for _, kw in intel_builds], [2700, 2700, 2700])
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
                    clock[0] = 1901.0
                return result
            with patch.object(helper, "run", side_effect=late), self.assertRaises(helper.CheckFailure):
                helper.phase_mac_compile("compile", bound)
            self.assertFalse(receipts)
            self.assertFalse(any(kw["check"] == "mac-observer-compile-only" for _, kw in calls))
            clock[0] = 100.0
            def late_publication(*args, **kw):
                receipts.append((args, kw))
                clock[0] = 1901.0
            with patch.object(helper, "phase_receipt", side_effect=late_publication), self.assertRaises(helper.CheckFailure):
                helper.phase_mac_compile("compile", bound)
            # Retained bytes are diagnostic only without this original phase0.
            self.assertEqual(len(receipts), 1)

            # Synthetic scheduling DATA only, not measured Intel completion.
            # Vault retains1500s; Intel normal caps2700s; all share one endpoint.
            calls.clear(); receipts.clear(); clock[0] = 100.0
            elapsed = {"mac-normal-bin-compile-only": 2100.0,
                       "mac-observer-compile-only": 1050.0,
                       "mac-image-compile-only": 975.0}
            def elapsed_original(argv, **kw):
                result = invoke(argv, **kw)
                clock[0] += elapsed.get(kw["check"], 0.0)
                return result
            with patch.object(helper, "mac_compile_inputs", return_value=intel["macCompile"]), \
                    patch.object(helper, "run", side_effect=elapsed_original):
                helper.phase_mac_compile("compile", intel)
            progressed = [(argv, kw) for argv, kw in calls if kw["check"] in elapsed]
            self.assertEqual([kw["check"] for _, kw in progressed], list(elapsed))
            self.assertEqual([kw["timeout"] for _, kw in progressed], [2700, 2700, 2220])
            self.assertEqual([argv for argv, _ in progressed], [argv for argv, _ in intel_builds])
            self.assertEqual(clock[0], 4225.0)
            self.assertEqual(len(receipts), 1)

            for selected, budget in ((bound, 1800), (intel, 5400)):
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

            # Fixed ARM remaining row: only the original vault compiler enters.
            vault = mac_context("aarch64-apple-darwin", "vault-only")
            calls.clear(); receipts.clear(); clock[0] = 100.0
            with patch.object(helper, "mac_compile_inputs", return_value=vault["macCompile"]), \
                    patch.object(helper.shutil, "which", side_effect=AssertionError("no frontend in vault-only")):
                helper.phase_mac_compile("compile", vault)
                self.assertEqual([kw["check"] for _, kw in calls], ["mac-vault-bin-compile-only"])
                self.assertEqual(calls[0][1]["timeout"], 1470)
                self.assertEqual(calls[0][0], vault_argv)
                self.assertEqual(receipts, [((vault, "compile", ["rust-version-target", "mac-cargo-version", "mac-vault-bin-compile-only"]), {"node": None})])
                calls.clear(); receipts.clear()
                with patch.object(helper, "run", side_effect=vault_failed), self.assertRaises(helper.CheckFailure):
                    helper.phase_mac_compile("compile", vault)
                self.assertFalse(receipts)
                for returned_clock in (1570.0, 99.0):
                    calls.clear(); receipts.clear(); clock[0] = 100.0
                    def vault_late(argv, **kw):
                        result = invoke(argv, **kw)
                        clock[0] = returned_clock
                        return result
                    with patch.object(helper, "run", side_effect=vault_late), self.assertRaisesRegex(helper.CheckFailure, "endpoint expired or clock reversed"):
                        helper.phase_mac_compile("compile", vault)
                    self.assertEqual([kw["check"] for _, kw in calls], ["mac-vault-bin-compile-only"])
                    self.assertFalse(receipts)
                calls.clear(); receipts.clear(); clock[0] = 100.0
                def vault_late_publication(*args, **kw):
                    receipts.append((args, kw)); clock[0] = 1570.0
                with patch.object(helper, "phase_receipt", side_effect=vault_late_publication), self.assertRaisesRegex(helper.CheckFailure, "endpoint expired or clock reversed"):
                    helper.phase_mac_compile("compile", vault)
                self.assertEqual(len(receipts), 1)
            for bad in ({key: value for key, value in vault["macCompile"].items() if key != "mode"},
                        {**vault["macCompile"], "mode": "other"}, {**vault["macCompile"], "graphs": []}):
                calls.clear(); receipts.clear(); clock[0] = 100.0
                with self.assertRaises(helper.CheckFailure):
                    helper.phase_mac_compile("compile", {**vault, "macCompile": bad})
                self.assertFalse(calls)
                self.assertFalse(receipts)

        # Original success is insufficient without the exact one-test stdout,
        # source POST and the unchanged aggregate endpoint. Both raw streams
        # remain private, exclusive and consuming-closed even on failure.
        bound = source_slots_context()
        expected_order = ["rust-version-target", "mac-cargo-version", "headless-test-compile-only", "mac-source-slots-data-test"]
        for fault in (None, "compile-nonzero", "test-nonzero", "zero-tests", "ignored", "readback", "source-post",
                      "late-test", "reversed-test", "late-receipt", "publication-failure", "expired-before-tools"):
            events, captures, calls, publications, clock = [], {}, [], [], [100.0]
            SlotsPath, writer, read = source_slots_paths(events, captures)
            source_calls = []
            def source_original(*args, **kw):
                source_calls.append("source")
                if fault == "source-post" and len(source_calls) == 2:
                    raise helper.CheckFailure("source original changed")
            def original(argv, **kw):
                calls.append((list(map(str, argv)), {**kw, "env": dict(kw["env"])}))
                if kw["check"] == "rust-version-target":
                    return "release: 1.98.0\ncommit-hash: 88d9e12ae178fab0fb5cc050a94da85685d449ea\nhost: x86_64-apple-darwin"
                if kw["check"] == "mac-cargo-version":
                    return "cargo 1.98.0 (abcdef123 2026-09-01)"
                if kw["check"] == "headless-test-compile-only":
                    if fault in ("compile-nonzero", "publication-failure"):
                        raise helper.CheckFailure("original compile nonzero")
                elif kw["check"] == "mac-source-slots-data-test":
                    body = source_slots_stdout()
                    if fault == "zero-tests":
                        body = body.replace(b"running 1 test", b"running 0 tests").replace(b"1 passed", b"0 passed")
                    if fault == "ignored":
                        body = body.replace(b"0 ignored", b"1 ignored")
                    kw["output"].write(body.decode())
                    if fault == "test-nonzero":
                        raise helper.CheckFailure("original test nonzero")
                    if fault == "late-test":
                        clock[0] = 970.0
                    if fault == "reversed-test":
                        clock[0] = 99.0
                return ""
            def read_original(path, expected):
                if fault == "readback":
                    raise helper.CheckFailure("output original changed")
                return read(path, expected)
            def publication(path, value):
                if fault == "publication-failure":
                    raise OSError("inert publication failure")
                publications.append((str(path), deepcopy(value)))
                if fault == "late-receipt" and path.name == "compile-checks.json":
                    clock[0] = 970.0
            observed_clock = []
            def clock_original():
                observed_clock.append(clock[0])
                return 970.0 if fault == "expired-before-tools" and len(observed_clock) > 1 else clock[0]
            with self.subTest(original_fault=fault), patch.object(helper, "Path", SlotsPath), \
                    patch.object(helper, "ordinary"), patch.object(helper, "source_unchanged", side_effect=source_original), \
                    patch.object(helper, "source_slots_source_guard"), patch.object(helper, "run", side_effect=original), \
                    patch.object(helper, "source_slots_writer", side_effect=writer), patch.object(helper, "source_slots_read", side_effect=read_original), \
                    patch.object(helper, "write_json", side_effect=publication), patch.object(helper.time, "monotonic", side_effect=clock_original), \
                    patch.dict(helper.os.environ, {"PATH": "/selected/bin", "MRK_MACOS_DEVELOPER_ID_P12_BASE64": "synthetic-not-forwarded"}, clear=True):
                if fault is None:
                    helper.phase_source_slots("compile", bound)
                else:
                    with self.assertRaises(helper.CheckFailure):
                        helper.phase_source_slots("compile", bound)
            checks = [kw["check"] for _, kw in calls]
            if fault == "expired-before-tools":
                self.assertFalse(checks)
            elif fault in ("compile-nonzero", "publication-failure", "readback"):
                self.assertEqual(checks, expected_order[:-1])
            else:
                self.assertEqual(checks, expected_order)
            commands = [(argv, kw) for argv, kw in calls if "output" in kw]
            for argv, kw in commands:
                self.assertIn("--locked", argv); self.assertIn("--offline", argv)
                self.assertEqual(argv[argv.index("--jobs") + 1], "1")
                self.assertIn("--no-default-features", argv)
                self.assertEqual(argv[argv.index("--features") + 1], "development-runtime")
                self.assertEqual(argv[argv.index("--target") + 1], "x86_64-apple-darwin")
                self.assertEqual(argv[argv.index("--manifest-path") + 1], bound["source"] + "/desktop/src-tauri/Cargo.toml")
                self.assertEqual(argv[argv.index("--target-dir") + 1], bound["root"] + "/target")
                self.assertIn("--lib", argv)
                self.assertFalse(any(value in argv for value in ("--ignored", "--release", "registration-helper", "desktop-shell")))
                self.assertEqual(kw["env"]["RUSTUP_AUTO_INSTALL"], "0")
                self.assertEqual(kw["env"]["GITHUB_SHA"], bound["sourceSha"])
                self.assertNotIn("MRK_MACOS_DEVELOPER_ID_P12_BASE64", kw["env"])
                self.assertTrue(kw["output"].closed and kw["diagnostics"].closed)
                self.assertEqual(kw["timeout"], 600 if kw["check"] == "headless-test-compile-only" else 150)
                if kw["check"] == "headless-test-compile-only":
                    self.assertEqual(argv[-2:], ["--message-format=json", "--no-run"])
                else:
                    self.assertNotIn("--message-format=json", argv)
                    self.assertNotIn("--no-run", argv)
                    self.assertEqual(argv[-4:], [SOURCE_SLOTS_CASE, "--", "--exact", "--test-threads=1"])
            passed = [value for path, value in publications if path.endswith("/compile-checks.json")]
            failures = [value for path, value in publications if path.endswith("/source-slots-failure.json")]
            self.assertEqual(passed, [source_slots_receipt("compile")] if fault in (None, "late-receipt") else [])
            self.assertEqual(len(failures), 0 if fault in (None, "publication-failure") else 1)
            for failure in failures:
                expected_fields = {"schemaVersion", "scope", "phase", "status", "lastFixedStage",
                    "sourceSha", "sourceTree", "workflowPath", "workflowSha", "workflowRef", "workflowSha256", "runId", "attempt"}
                if failure["lastFixedStage"] == "headless-test-compile-only":
                    expected_fields.add("compilerDiagnostic")
                    self.assertEqual(failure["compilerDiagnostic"], {"state": "unavailable", "reason": "original-unavailable",
                                     "returnCode": None, "errors": [], "sources": []})
                self.assertEqual(set(failure), expected_fields)
                self.assertEqual(failure["status"], "failed-or-unknown")
                self.assertLessEqual(len(json.dumps(failure).encode()), 16384)
                self.assertNotIn("synthetic-not-forwarded", json.dumps(failure))
            if fault is None:
                self.assertEqual(len(source_calls), 2)
                self.assertTrue(all(event[2] == ("x",) for event in events if event[0] == "open"))
                self.assertEqual(len([event for event in events if event[0] == "closed"]), 4)
                # Successful commands may legitimately leave both raw streams
                # empty except for the mandatory actual libtest stdout.
                self.assertEqual(captures[bound["root"] + "/target/source-slots-compile.stdout"], b"")
                self.assertEqual(captures[bound["root"] + "/target/source-slots-test.stderr"], b"")

        # The unchanged run owner keeps its private-output contract and actual
        # original exit/timeout handling; subprocess.run is never entered here.
        with io.StringIO() as output, io.StringIO() as diagnostics, io.StringIO() as notices, \
                contextlib.redirect_stdout(notices), patch.object(helper.subprocess, "run") as original_run:
            helper.run(["/fixed/cargo"], check="mac-source-slots-data-test", cwd=PurePosixPath("/inert"), env={},
                       timeout=150, output=output, diagnostics=diagnostics)
            self.assertEqual(original_run.call_args.kwargs["stdout"], output)
            self.assertEqual(original_run.call_args.kwargs["stderr"], diagnostics)
            self.assertTrue(original_run.call_args.kwargs["check"])
            self.assertEqual(original_run.call_count, 1)
            for fields in ({"capture": True, "output": output, "diagnostics": diagnostics}, {"diagnostics": diagnostics}):
                with self.assertRaises(helper.CheckFailure):
                    helper.run(["/fixed/cargo"], check="mac-source-slots-data-test", cwd=PurePosixPath("/inert"), env={}, timeout=150, **fields)
            self.assertEqual(original_run.call_count, 1)
            for error in (helper.subprocess.CalledProcessError(101, ["/fixed/cargo"]),
                          helper.subprocess.TimeoutExpired(["/fixed/cargo"], 150), OSError("inert")):
                original_run.side_effect = error
                with self.assertRaises(helper.CheckFailure) as failure:
                    helper.run(["/fixed/cargo"], check="mac-source-slots-data-test", cwd=PurePosixPath("/inert"), env={},
                               timeout=150, output=output, diagnostics=diagnostics)
                self.assertEqual(type(failure.exception), helper.CheckFailure)
                if isinstance(error, helper.subprocess.CalledProcessError):
                    self.assertEqual(str(failure.exception), "Fixed check mac-source-slots-data-test exited 101")
                    self.assertEqual(failure.exception.__dict__["_returned_command"], ("mac-source-slots-data-test", 101))
                else:
                    self.assertNotIn("_returned_command", failure.exception.__dict__)

        # Exercise the actual no-follow bounded original reader with inert FD
        # bindings, not a mock return from the parser. No host open/read/close.
        actual_os = helper.os
        class Info:
            st_dev, st_ino, st_mode, st_uid, st_gid, st_nlink = 1, 2, 0o100600, 501, 20, 1
            st_mtime_ns, st_ctime_ns = 3, 4
            def __init__(self, size):
                self.st_size = size
        class OriginalOS:
            O_RDONLY, O_NOFOLLOW = actual_os.O_RDONLY, actual_os.O_NOFOLLOW
            O_CLOEXEC, O_NONBLOCK = actual_os.O_CLOEXEC, actual_os.O_NONBLOCK
            def __init__(self, body, fault):
                self.body, self.fault, self.position, self.closes, self.fstats, self.opened = body, fault, 0, [], 0, []
                self.info = Info(len(body))
                if fault == "oversize": self.info.st_size = 1024 * 1024 + 1
                if fault == "mode": self.info.st_mode = 0o100644
                if fault == "link": self.info.st_nlink = 2
                if fault == "uid": self.info.st_uid = 502
            def geteuid(self): return 501
            def open(self, path, flags):
                self.opened.append((str(path), flags))
                return 77
            def fstat(self, fd):
                self_outer.assertEqual(fd, 77)
                self.fstats += 1
                if self.fault == "post" and self.fstats == 2:
                    self.info.st_mtime_ns += 1
                return self.info
            def read(self, fd, size):
                self_outer.assertEqual(fd, 77)
                self_outer.assertLessEqual(size, 65536)
                if self.fault == "early": return b""
                if self.fault == "tail" and self.position == len(self.body): return b"x"
                result = self.body[self.position:self.position + size]; self.position += len(result)
                return result
            def close(self, fd):
                self_outer.assertEqual(fd, 77); self.closes.append(fd)
        class ReadPath(PurePosixPath):
            def lstat(self):
                if original.fault == "named":
                    altered = Info(original.info.st_size); altered.st_ino = 8
                    return altered
                return original.info
        self_outer = self
        for name, body in (("source-slots-test.stdout", source_slots_stdout()), ("source-slots-test.stderr", b""),
                           ("metadata.json", b'{"packages":[]}')):
            faults = (None, "named", "mode", "link", "uid", "post", "tail") + (("early",) if body else ())
            if name != "metadata.json": faults += ("oversize",)
            for fault in faults:
                original = OriginalOS(body, fault)
                expected = helper.source_slots_identity(original.info)
                path = ReadPath("/inert/target") / name
                with self.subTest(read_name=name, fault=fault), patch.object(helper, "os", original):
                    if fault is None:
                        self.assertEqual(helper.source_slots_read(path, expected), body if name == "source-slots-test.stdout" else b"")
                    else:
                        with self.assertRaises(helper.CheckFailure):
                            helper.source_slots_read(path, expected)
                self.assertEqual(original.closes, [77])
                self.assertEqual(original.opened, [(str(path), actual_os.O_RDONLY | actual_os.O_NOFOLLOW | actual_os.O_CLOEXEC | actual_os.O_NONBLOCK)])
        original = OriginalOS(b"", None)
        with patch.object(helper, "os", original):
            with self.assertRaises(helper.CheckFailure):
                helper.source_slots_read(ReadPath("/inert/metadata.json"), helper.source_slots_identity(original.info))
            with self.assertRaises(helper.CheckFailure):
                helper.source_slots_read(ReadPath("/inert/unselected"), helper.source_slots_identity(original.info))
        self.assertEqual(original.closes, [77])
        self.assertEqual(len(original.opened), 1)
        class Writer:
            def fileno(self): return 77
        for fault in (None, "named", "mode", "link", "uid"):
            original = OriginalOS(b"inert", fault)
            with self.subTest(writer_fault=fault), patch.object(helper, "os", original):
                if fault is None:
                    self.assertEqual(helper.source_slots_writer(ReadPath("/inert/source-slots-test.stdout"), Writer()),
                                     helper.source_slots_identity(original.info))
                else:
                    with self.assertRaises(helper.CheckFailure):
                        helper.source_slots_writer(ReadPath("/inert/source-slots-test.stdout"), Writer())
            self.assertFalse(original.closes)  # The surrounding original stream owns close, not this check.

        # Failed Cargo JSON is optional DATA, not a new success/cleanup path.
        # All path names below are inert; only a fixed Git metadata double is
        # consulted, never a SOURCE body, compiler, dependency or native API.
        source = bound["source"]
        app = "desktop/src-tauri"
        native = "desktop/native/macos-installed-native"
        private = "synthetic-private-diagnostic-must-not-escape"
        def primary(name, line=19, column=7):
            return {"file_name": name, "line_start": line, "column_start": column, "is_primary": True}
        def message(code="E0433", spans=None, wording=private, package=app):
            return {"reason": "compiler-message", "manifest_path": source + "/" + package + "/Cargo.toml",
                    "message": {"level": "error", "code": None if code is None else {"code": code, "explanation": private},
                                "message": wording, "spans": [primary("src/lib.rs")] if spans is None else spans,
                                "rendered": private}}
        terminal = {"reason": "build-finished", "success": False}
        def cargo_bytes(rows):
            return b"".join((json.dumps(row, separators=(",", ":")) + "\n").encode() for row in rows)
        blob = "a" * 40
        simple_raw = cargo_bytes([message(), terminal])
        metadata = "100644 blob " + blob + "\t" + app + "/src/lib.rs\0"
        calls, source_checks = [], []
        def metadata_original(argv, **kw):
            calls.append((argv, kw))
            self.assertEqual(source_checks, ["post"])
            return metadata
        with patch.object(helper, "source_unchanged", side_effect=lambda *a, **kw: source_checks.append("post")), \
                patch.object(helper, "run", side_effect=metadata_original), patch.dict(helper.os.environ, {"PATH": "/fixed/bin"}, clear=True):
            diagnostic = helper.source_slots_compiler_diagnostic(bound, simple_raw, b"", 101, timeout_for=lambda cap: cap)
        self.assertEqual(diagnostic, {"state": "complete", "reason": None, "returnCode": 101,
            "errors": [{"category": "compiler-error", "code": "E0433", "package": "mobile-release-kit-desktop",
                        "spans": [{"source": 0, "line": 19, "column": 7}], "unboundSpans": 0}],
            "sources": [{"path": app + "/src/lib.rs", "gitBlob": blob}]})
        self.assertEqual(len(calls), 1)
        argv, fields = calls[0]
        self.assertEqual(argv, [bound["git"], "ls-tree", "-z", "--full-tree", bound["sourceSha"], "--", app + "/src/lib.rs"])
        self.assertEqual(fields["check"], "source-slots-diagnostic-source")
        self.assertEqual(str(fields["cwd"]), source)
        self.assertEqual(fields["timeout"], 15)
        self.assertTrue(fields["capture"])
        self.assertEqual(fields["env"]["HOME"], bound["root"] + "/home")
        self.assertNotIn(private, json.dumps(diagnostic))
        self.assertNotIn(source, json.dumps(diagnostic))

        kinds = [message("E0599", [primary(source + "/" + app + "/src/lib.rs")]),
                 message(None, [primary("src/lib.rs")]),
                 message(None, [], "linking with `cc` failed: exit status: 1 " + private),
                 message("E0308", [primary("build.rs")], package=native),
                 message("E0001", [primary("/foreign/" + private + ".rs")], package="foreign")]
        stderr = ("error: failed to run custom build command for `mrk-macos-installed-native v0.1.0 (" + private + ")`\n"
                  "error: failed to run custom build command for `foreign-package v9.9.9`\n").encode()
        records = helper.source_slots_diagnostic_records(cargo_bytes(kinds + [terminal]), stderr, source)
        self.assertEqual([row["category"] for row in records], ["compiler-error", "compiler-error-without-code", "linker-error",
                         "compiler-error", "compiler-error", "build-script-failure", "build-script-failure"])
        self.assertEqual([row["code"] for row in records], ["E0599", None, None, "E0308", "E0001", None, None])
        self.assertEqual(records[3]["spans"][0]["path"], native + "/build.rs")
        self.assertEqual(records[4]["unboundSpans"], 1)
        self.assertEqual(records[5]["package"], "mrk-macos-installed-native")
        self.assertEqual(records[6]["package"], "unknown")
        self.assertNotIn(private, json.dumps(records))
        for bad_path in ("../src/lib.rs", "src/../lib.rs", "src//lib.rs", "src/./lib.rs", "src/*.rs", "src/a\0.rs",
                         "/foreign/src/lib.rs", source + "-other/" + app + "/src/lib.rs", "file:///src/lib.rs",
                         "lib.rs", "desktop/not-a-package/lib.rs", "desktop/src-tauri-other/lib.rs", "src/lib.txt"):
            with self.subTest(unbound_path=bad_path):
                row = helper.source_slots_diagnostic_records(cargo_bytes([message(spans=[primary(bad_path)]), terminal]), b"", source)[0]
                self.assertEqual(row["spans"], [])
                self.assertEqual(row["unboundSpans"], 1)
        for good_path in ("src/lib.rs", app + "/src/lib.rs", source + "/" + app + "/src/lib.rs"):
            row = helper.source_slots_diagnostic_records(cargo_bytes([message(spans=[primary(good_path)]), terminal]), b"", source)[0]
            self.assertEqual(row["spans"], [{"path": app + "/src/lib.rs", "line": 19, "column": 7}])
        malformed = [b"", simple_raw[:-1], simple_raw + b"\n", simple_raw + cargo_bytes([terminal]), b"\xff\n",
                     simple_raw.replace(b'"level":"error"', b'"level":"error","level":"error"'),
                     simple_raw.replace(b'"line_start":19', b'"line_start":NaN'),
                     cargo_bytes([message()]), cargo_bytes([message(), {"reason": "build-finished", "success": True}]),
                     cargo_bytes([message("E12345"), terminal]), cargo_bytes([message(spans=[primary("src/lib.rs", True)]), terminal]),
                     cargo_bytes([message(spans=[primary("src/lib.rs", 0)]), terminal]),
                     cargo_bytes([message(spans=[primary("src/lib.rs", column=1048577)]), terminal]),
                     cargo_bytes([message()] * 17 + [terminal]), cargo_bytes([message(spans=[primary("src/lib.rs")] * 33), terminal]),
                     cargo_bytes([message(spans=[primary("src/" + str(n) + ".rs") for n in range(9)]), terminal]),
                     cargo_bytes([{"reason": "compiler-artifact"}] * 4096 + [terminal]), b"x" * (1024 * 1024 + 1)]
        for overflow in (b"1e9999", b"-1e9999"):
            malformed.append(b'{"reason":"compiler-artifact","ignored":{"nested":' + overflow + b'}}\n' + simple_raw)
            malformed.append(simple_raw.replace(b'"reason":"compiler-message"',
                             b'"reason":"compiler-message","ignored":{"nested":' + overflow + b'}'))
        finite = b'{"reason":"compiler-artifact","ignored":{"nested":[1.25,-1e300]}}\n' + simple_raw
        self.assertEqual(helper.source_slots_diagnostic_records(finite, b"", source),
                         helper.source_slots_diagnostic_records(simple_raw, b"", source))
        for raw in malformed:
            with self.subTest(malformed_bytes=len(raw)), self.assertRaises(helper.CheckFailure):
                helper.source_slots_diagnostic_records(raw, b"", source)
        with self.assertRaises(helper.CheckFailure):
            helper.source_slots_diagnostic_records(simple_raw, b"x" * (1024 * 1024 + 1), source)
        for fault in ("missing", "bad-mode", "duplicate", "extra-path", "partial", "large", "source", "clock"):
            returned = {"missing": "", "bad-mode": metadata.replace("100644", "120000"), "duplicate": metadata * 2,
                        "extra-path": metadata.replace(app + "/src/lib.rs", native + "/src/lib.rs"),
                        "partial": metadata[:-1], "large": metadata * 200}.get(fault, metadata)
            with self.subTest(metadata_fault=fault), patch.object(helper, "run", return_value=returned) as metadata_run, \
                    patch.object(helper, "source_unchanged", side_effect=helper.CheckFailure("inert source") if fault == "source" else None), \
                    patch.dict(helper.os.environ, {"PATH": "/fixed/bin"}, clear=True):
                def remaining(cap):
                    if fault == "clock": raise helper.CheckFailure("inert late")
                    return cap
                observed = helper.source_slots_compiler_diagnostic(bound, simple_raw, b"", 101, timeout_for=remaining)
            if fault == "missing":
                self.assertEqual(observed["state"], "complete")
                self.assertEqual(observed["sources"], [])
                self.assertEqual(observed["errors"][0]["spans"], [])
                self.assertEqual(observed["errors"][0]["unboundSpans"], 1)
            else:
                self.assertEqual(observed["state"], "unavailable")
                self.assertEqual(observed["errors"], [])
                self.assertEqual(observed["sources"], [])
            if fault in ("source", "clock"):
                self.assertEqual(metadata_run.call_count, 0)
        with patch.object(helper, "source_unchanged", side_effect=AssertionError("not reached")), \
                patch.object(helper, "run", side_effect=AssertionError("not reached")):
            self.assertEqual(helper.source_slots_compiler_diagnostic(bound, b"partial", b"", 101, timeout_for=lambda cap: cap)["reason"], "cargo-json-unavailable")
            self.assertEqual(helper.source_slots_compiler_diagnostic(bound, cargo_bytes([terminal]), b"", 101, timeout_for=lambda cap: cap)["reason"], "no-error-records")

        # Retaining the compile originals adds no weak reader: full identity,
        # byte cap, EOF, post-stat and consuming close are still mandatory.
        for name in ("source-slots-compile.stdout", "source-slots-compile.stderr"):
            for fault in (None, "named", "mode", "link", "uid", "post", "tail", "early", "oversize"):
                original = OriginalOS(simple_raw, fault)
                expected = helper.source_slots_identity(original.info)
                with self.subTest(retained_name=name, fault=fault), patch.object(helper, "os", original):
                    if fault is None:
                        self.assertEqual(helper.source_slots_read(ReadPath("/inert") / name, expected, retain=True), simple_raw)
                    else:
                        with self.assertRaises(helper.CheckFailure):
                            helper.source_slots_read(ReadPath("/inert") / name, expected, retain=True)
                self.assertEqual(original.closes, [77])
        original = OriginalOS(b"x" * (1024 * 1024), None)
        with patch.object(helper, "os", original):
            self.assertEqual(len(helper.source_slots_read(ReadPath("/inert/source-slots-compile.stdout"),
                             helper.source_slots_identity(original.info), retain=True)), 1024 * 1024)
        self.assertEqual(original.closes, [77])
        for name, retain in (("source-slots-test.stdout", True), ("metadata.json", True), ("source-slots-compile.stdout", 1)):
            original = OriginalOS(b"x", None)
            with patch.object(helper, "os", original), self.assertRaises(helper.CheckFailure):
                helper.source_slots_read(ReadPath("/inert") / name, helper.source_slots_identity(original.info), retain=retain)
            self.assertFalse(original.opened)
        class CloseFailureOS(OriginalOS):
            def close(self, fd):
                super().close(fd)
                raise OSError("inert consuming close uncertainty")
        original = CloseFailureOS(simple_raw, None)
        with patch.object(helper, "os", original), self.assertRaises(OSError):
            helper.source_slots_read(ReadPath("/inert/source-slots-compile.stdout"), helper.source_slots_identity(original.info), retain=True)
        self.assertEqual(original.closes, [77])

        # The actual run() manufactures the private returned-original witness.
        # Only subprocess.run is doubled. No fake success/unknown witness may
        # unlock capture parsing, and later faults cannot replace that error.
        actual_run = helper.run
        for fault in (None, "signal", "timeout", "start", "unknown", "witness-bool", "flush", "writer-post", "close",
                      "read", "source", "metadata", "deadline", "late-metadata", "malformed", "publication"):
            events, captures, streams, publications, originals, raised, reads, clock, source_checks = [], {}, [], [], [], [], [], [100.0], []
            BasePath, writer, _ = source_slots_paths(events, captures)
            class FailureCapture(io.StringIO):
                def __init__(self, path):
                    super().__init__(); self.path = str(path); streams.append(self)
                def flush(self):
                    if fault == "flush" and self.path.endswith(".stdout") and self.getvalue():
                        raise OSError("inert flush failure")
                    return super().flush()
                def __exit__(self, *args):
                    captures[self.path] = self.getvalue().encode()
                    events.append(("closed", self.path))
                    try:
                        return super().__exit__(*args)
                    finally:
                        if fault == "close" and self.path.endswith(".stderr"):
                            raise OSError("inert writer close uncertainty")
            class FailurePath(BasePath):
                def open(self, *args, **kw):
                    self_outer.assertEqual(args, ("x",))
                    return FailureCapture(self)
            def subprocess_original(argv, **kw):
                originals.append((list(map(str, argv)), dict(kw)))
                if argv[0] == "/fixed/cargo":
                    self.assertIn("--message-format=json", argv)
                    self.assertEqual(argv[-1], "--no-run")
                    self.assertEqual(kw["timeout"], 600)
                    self.assertTrue(kw["check"])
                    kw["stdout"].write((b"partial" if fault == "malformed" else simple_raw).decode())
                    kw["stderr"].write(private)
                    if fault == "deadline": clock[0] = 970.0
                    if fault == "timeout": raise helper.subprocess.TimeoutExpired(argv, 600)
                    if fault == "start": raise OSError("inert startup")
                    raise helper.subprocess.CalledProcessError(-9 if fault == "signal" else 101, argv)
                self.assertEqual(argv, [bound["git"], "ls-tree", "-z", "--full-tree", bound["sourceSha"], "--", app + "/src/lib.rs"])
                self.assertTrue(all(stream.closed for stream in streams))
                self.assertEqual(len(reads), 2)
                if fault == "metadata": raise OSError("inert Git error")
                if fault == "late-metadata": clock[0] = 970.0
                class Returned:
                    stdout = metadata
                return Returned()
            def observe_run(argv, **kw):
                try:
                    return actual_run(argv, **kw)
                except helper.CheckFailure as error:
                    if kw["check"] == "headless-test-compile-only":
                        raised.append(error)
                        if fault == "unknown": error.__dict__.pop("_returned_command", None)
                        if fault == "witness-bool": error._returned_command = (kw["check"], True)
                    raise
            def writer_post(path, stream):
                if fault == "writer-post" and stream.getvalue():
                    raise helper.CheckFailure("inert original writer changed")
                return writer(path, stream)
            def read_returned(path, expected, *, retain=False):
                self.assertTrue(retain)
                self.assertEqual(len(streams), 2)
                self.assertTrue(all(stream.closed for stream in streams))
                reads.append(path.name)
                if fault == "read": raise helper.CheckFailure("inert original capture changed")
                self.assertEqual(expected[6], len(captures[str(path)]))
                return captures[str(path)]
            def source_post(*args, **kw):
                source_checks.append("checked")
                if len(source_checks) == 2:
                    self.assertTrue(all(stream.closed for stream in streams))
                    self.assertEqual(len(reads), 2)
                    if fault == "source": raise helper.CheckFailure("inert changed source")
            def failure_publication(path, value):
                self.assertEqual(path.name, "source-slots-failure.json")
                if fault == "publication": raise OSError("inert publication")
                publications.append(deepcopy(value))
            with self.subTest(returned_original_fault=fault), contextlib.redirect_stdout(io.StringIO()), \
                    patch.object(helper, "Path", FailurePath), patch.object(helper, "tools", return_value=("/fixed/cargo", None)), \
                    patch.object(helper, "source_unchanged", side_effect=source_post), patch.object(helper, "source_slots_source_guard"), \
                    patch.object(helper.subprocess, "run", side_effect=subprocess_original), patch.object(helper, "run", side_effect=observe_run), \
                    patch.object(helper, "source_slots_writer", side_effect=writer_post), patch.object(helper, "source_slots_read", side_effect=read_returned), \
                    patch.object(helper, "write_json", side_effect=failure_publication), patch.object(helper.time, "monotonic", side_effect=lambda: clock[0]), \
                    patch.dict(helper.os.environ, {"PATH": "/fixed/bin"}, clear=True), self.assertRaises(helper.CheckFailure) as failure:
                helper.phase_source_slots("compile", bound)
            self.assertEqual(len(raised), 1)
            self.assertIs(failure.exception, raised[0])
            self.assertEqual(type(failure.exception), helper.CheckFailure)
            self.assertEqual(len(streams), 2)
            self.assertTrue(all(stream.closed for stream in streams))
            self.assertEqual(len([argv for argv, _ in originals if argv[0] == "/fixed/cargo"]), 1)
            self.assertEqual(len(publications), 0 if fault == "publication" else 1)
            for value in publications:
                self.assertEqual(value["status"], "failed-or-unknown")
                self.assertEqual(value["lastFixedStage"], "headless-test-compile-only")
                observed = value["compilerDiagnostic"]
                self.assertEqual(observed["state"], "complete" if fault is None else "unavailable")
                self.assertEqual(observed["returnCode"], None if fault in ("signal", "timeout", "start", "unknown", "witness-bool") else 101)
                self.assertNotIn(private, json.dumps(value))
                self.assertNotIn(source + "/", json.dumps(value))
                self.assertLessEqual(len(json.dumps(value).encode()), 16384)
                if fault is None:
                    self.assertEqual(observed, diagnostic)
            if fault in ("signal", "timeout", "start", "unknown", "witness-bool", "flush", "writer-post", "close", "deadline"):
                self.assertFalse(reads)
                self.assertEqual(len(originals), 1)
            if fault in ("read", "source", "malformed"):
                self.assertEqual(len(originals), 1)


if __name__ == "__main__":
    unittest.main()
