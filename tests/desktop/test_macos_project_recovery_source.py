"""Small SOURCE-only closure checks; never import/execute any native owner."""
import ast
import hashlib
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).absolute().parents[2]
MAC = ROOT / "desktop/src-tauri/src"


def literal(path, name):
    module = ast.parse(path.read_bytes(), filename=str(path))
    values = [node.value for node in module.body if isinstance(node, ast.Assign)
              and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
    if len(values) != 1 or not isinstance(values[0], ast.Constant) or type(values[0].value) is not str:
        raise AssertionError("one literal source input required")
    return values[0].value


class MacProjectRecoverySourceTests(unittest.TestCase):
    def test_authentic_producer_literal_is_exact_source_not_a_historical_runner_import(self):
        adapter = ROOT / "desktop/tools/macos_aqua_qualification.py"
        wrapped = literal(adapter, "SHELL_RECOVERY_PRODUCER")
        self.assertTrue(wrapped.startswith("try:\n"))
        handler_marker = "except BaseException as _failure_error:\n"
        self.assertEqual(wrapped.count("\n" + handler_marker), 1)
        indented, boundary, handler = wrapped[len("try:\n"):].partition(handler_marker)
        self.assertEqual(boundary, handler_marker)
        body_lines = indented.splitlines(keepends=True)
        self.assertTrue(body_lines and all(line.startswith("    ") for line in body_lines))
        # The new closed footer wraps, but never replaces/rewrites, the original body.
        source = "".join(line[4:] for line in body_lines).encode()
        self.assertTrue(handler.endswith("    raise SystemExit(1) from None\n"))
        self.assertEqual(source, literal(ROOT / "desktop/tools/ubuntu_publication_lifecycle.py", "SHELL_RECOVERY_PRODUCER").encode())
        self.assertEqual(len(source), 6088)
        self.assertEqual(hashlib.sha256(source).hexdigest(), "7dcdd821b07f611e1339ce40add59e318363637ea25b2277b468ba794cbd1080")
        decoded = source.decode("utf-8")
        self.assertIn("from mobile_release.owned_process import ProcessError\n", decoded)
        self.assertIn("need(type(caught) is ProcessError and invocation is not None and original is not None", decoded)
        for fact in ("caught.dispatched is False", "caught.contained is True", "caught.cleanup_complete is False",
                     "ledger._profile_contained is True", "ledger._command_contained is True"):
            self.assertIn(fact, decoded)
        self.assertNotIn("ProcessCleanupError", decoded)
        self.assertEqual(literal(ROOT / "desktop/tools/macos_normal_ui_runner.py", "LOADER_SHA"),
                         hashlib.sha256(adapter.read_bytes()).hexdigest())
        imports = [node for node in ast.walk(ast.parse(adapter.read_bytes())) if isinstance(node, (ast.Import, ast.ImportFrom))]
        self.assertFalse(any(isinstance(node, ast.ImportFrom) and node.module and "ubuntu_publication" in node.module
                             or isinstance(node, ast.Import) and any("ubuntu_publication" in alias.name for alias in node.names) for node in imports))
        source = adapter.read_text()
        self.assertIn('library.renameatx_np', source)
        self.assertIn('project, b"GoogleService-Info.plist", project, b"saved-foreign-ios", 0x4', source)
        accept = source.split('    def accept_recovery_producer(', 1)[1].split('\n    def ', 1)[0]
        self.assertNotIn('os.rename(', accept)
        self.assertIn('result.get("qualification") == "current-source-staged-no-native-execution"', source)
        self.assertIn('result.get("successorManifestSha256") == manifest_sha', source)

    def test_shared_original_book_and_narrow_cfg_leave_linux_hold_unchanged(self):
        shared = (MAC / "saved_command_recovery_observation.rs").read_text()
        self.assertIn('originals: [Option<Original>; 2]', shared)
        self.assertIn('original.retired && original.review_minted && original.accepted', shared)
        self.assertIn('Arc::ptr_eq(&other.owner, owner)', shared)
        self.assertIn('crate::shell::installed_observation::recovery::OriginalFacts', shared)
        hold = shared.split('pub(super) fn settlement_hold(', 1)[0].splitlines()[-1]
        for condition in ('all(test, debug_assertions', 'feature = "desktop-shell"', 'feature = "custom-protocol"',
                          'target_os = "linux"', 'target_arch = "x86_64"', 'target_env = "gnu"'):
            self.assertIn(condition, hold)
        self.assertNotIn('macos', hold)
        source = (MAC / "saved_command_owner.rs").read_text()
        cfg = source.split('mod recovery_observation;', 1)[0].splitlines()[-2]
        for condition in ('all(test, debug_assertions', 'not(feature = "development-runtime")',
                          'not(feature = "ubuntu-runtime-publisher")', 'target_os = "linux"',
                          'target_os = "macos"', 'target_arch = "aarch64"', 'feature = "macos-installed-observation"',
                          'not(feature = "macos-installed-installer")'):
            self.assertIn(condition, cfg)
        for match in re.finditer(r'recovery_observation::settlement_hold\(', source):
            prefix = source[:match.start()].splitlines()[-2]
            self.assertIn('target_os = "linux"', prefix)
            self.assertNotIn('macos', prefix)

    def test_ordinary_original_selection_precedes_admission_and_no_new_ipc_or_mode(self):
        saved = (MAC / "saved_command_owner.rs").read_text()
        for name in ('IOS_SIGNED_NATIVE_QUALIFIED', 'IOS_RECOVERY_NATIVE_QUALIFIED'):
            self.assertIn(f'const {name}: bool = false;', saved)
        ios = (MAC / "installed_shell_observation_macos_ios.rs").read_text()
        self.assertIn('claimed: AtomicU8', ios)
        self.assertIn('claimed.compare_exchange(before, after, Ordering::SeqCst, Ordering::SeqCst)', ios)
        self.assertIn('!self.permits() || !claim_observation_slot(self.case, &self.claimed, index)', ios)
        recovery = (MAC / "installed_shell_observation_macos_recovery.rs").read_text()
        # The implementation is two modules below the shell caller, not one.
        self.assertEqual(recovery.count('    pub(crate) fn attach_recovery('), 1)
        parent = (MAC / "installed_shell_observation_macos.rs").read_text()
        self.assertIn('#[path = "installed_shell_observation_macos_recovery.rs"]\npub(crate) mod recovery;', parent)
        attach = recovery.split('    fn attach(', 1)[1].split('    pub(crate) fn permits', 1)[0]
        self.assertLess(attach.index('owner.observe_installed_selection()?'), attach.index('document.admit_installed_recovery('))
        permits = recovery.split('    pub(crate) fn permits(', 1)[1].split('    pub(crate) fn claim', 1)[0]
        self.assertNotIn('.record()', permits); self.assertNotIn('.lock()', permits)
        for forbidden in ('tauri::command', 'Command::new(', 'std::process', '.cancel_case(', 'prepare_hold('):
            self.assertNotIn(forbidden, recovery)
        shell = (MAC / "shell.rs").read_text()
        observer_cfg = shell.split('\npub(crate) mod installed_observation;', 1)[0].splitlines()[-4:]
        self.assertIn('#[cfg_attr(target_os = "macos", path = "installed_shell_observation_macos.rs")]', observer_cfg)
        for condition in ('all(test, debug_assertions', 'feature = "macos-installed-observation"',
                          'not(feature = "macos-installed-installer")'):
            self.assertIn(condition, observer_cfg[0])
        self.assertEqual(shell.count('q.attach_recovery(&document, &bridge.project_recovery)?'), 1)
        for command in ('Prepare', 'Start', 'Status', 'Cancel'):
            self.assertEqual(shell.count(f'installed_recovery_request!(state, {command}, &value);'), 1)
            self.assertEqual(shell.count(f'installed_recovery_result!(state, {command}, &result);'), 1)

    def test_pending_case_reuses_original_sample_boundaries_and_normal_journeys_stay_separate(self):
        parent = (MAC / "installed_shell_observation_macos.rs").read_text()
        self.assertIn('r.recovery_record.as_ref().filter(|record|record.sample_ready(step))', parent)
        sample = parent.index('let recovery_sample = if self.case == Case::PendingRecovery')
        original = parent.index('installed_observation_snapshot(a)', sample)
        compare = parent.index('record.advance(step, control, &status, snapshot)', original)
        self.assertLess(original, compare)
        self.assertIn('!recovery::data_checks()', parent)
        new = (MAC / "installed_shell_observation_macos_recovery.rs").read_text()
        self.assertIn('requests: [u8; 4], replies: [u8; 4]', new)
        self.assertIn('current == final_projection', new)
        self.assertIn('wire::Phase::Starting|wire::Phase::Running', new)
        self.assertIn('"workMs":120000,"hardMs":130000,"observationMs":315000,"outerInvocationMs":325000', new)
        self.assertIn('wire::Role::AndroidServices, wire::Role::IosServices', new)
        self.assertIn('self.originals[1].is_some()', new)
        for name in ('desktop/native/macos-normal-ui/MRKNormalAppUITests/NormalAppUITests.swift',
                     '.github/workflows/desktop-macos-installed.yml'):
            self.assertNotIn('project-recovery-pending', (ROOT / name).read_text())

        # Keep actual whole-class census and BOTH CI gates connected. Extending
        # this existing method deliberately does not add another counted case.
        self.assertEqual(unittest.defaultTestLoader.testMethodPrefix, "test")
        class_specs = (
            ("test_macos_aqua_qualification.py", "PendingProjectRecoveryAquaDataTests", 9),
            ("test_macos_project_recovery_source.py", "MacProjectRecoverySourceTests", 4),
            ("test_macos_ios_pending_account.py", "PendingAccountRecoveryDataTests", 13),
        )
        counts = {}
        for filename, class_name, expected in class_specs:
            tree = ast.parse((ROOT / "tests/desktop" / filename).read_bytes())
            classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name]
            self.assertEqual(len(classes), 1)
            selected = classes[0]
            self.assertEqual(len(selected.bases), 1)
            self.assertIsInstance(selected.bases[0], ast.Attribute)
            self.assertIsInstance(selected.bases[0].value, ast.Name)
            self.assertEqual((selected.bases[0].value.id, selected.bases[0].attr), ("unittest", "TestCase"))
            names = [node.name for node in selected.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                     and node.name.startswith("test")]
            self.assertEqual(len(names), len(set(names)))
            self.assertEqual(len(names), expected)
            counts[class_name] = len(names)
        workflow = (ROOT / ".github/workflows/desktop-macos-aqua.yml").read_text()
        blocks = dict(block.split("\n", 1) for block in workflow.split("      - name: ")[1:])
        project_title = "Check pending recovery SOURCE and DATA contracts before native preparation"
        account_title = "Check pending account SOURCE and DATA contracts before native preparation"
        project, account = blocks[project_title], blocks[account_title]
        for block, scope, count, label in (
            (project, "project-recovery-pending", counts["PendingProjectRecoveryAquaDataTests"] + counts["MacProjectRecoverySourceTests"], "recovery"),
            (account, "ios-recovery-pending", counts["PendingAccountRecoveryDataTests"], "account"),
        ):
            self.assertEqual(count, 13)
            self.assertIn("if: success() && env.MRK_MACOS_AQUA_SCOPE == '" + scope + "'", block)
            self.assertIn(f'if suite.countTestCases() != {count}: raise SystemExit("fixed {label} DATA roster")', block)
            self.assertEqual(re.findall(r"suite\.countTestCases\(\) != ([0-9]+)", block), [str(count)])
            self.assertEqual(re.findall(r"result\.testsRun != ([0-9]+)", block), [str(count)])
            self.assertIn("unittest.TextTestRunner(verbosity=2, failfast=True).run(suite)", block)
            self.assertIn("or not result.wasSuccessful()", block)
            self.assertIn("any((result.failures, result.errors, result.skipped, result.expectedFailures, result.unexpectedSuccesses))", block)
            self.assertNotIn("continue-on-error", block)
        for selector in (
            '("_mrk_pending_recovery_data", "test_macos_aqua_qualification.py", "PendingProjectRecoveryAquaDataTests")',
            '("_mrk_pending_recovery_source", "test_macos_project_recovery_source.py", "MacProjectRecoverySourceTests")',
        ):
            self.assertIn(selector, project)
        self.assertIn('path = pathlib.Path("tests/desktop") / filename', project)
        self.assertIn("suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(getattr(module, cls)))", project)
        self.assertIn('path = pathlib.Path("tests/desktop/test_macos_ios_pending_account.py").absolute()', account)
        self.assertIn("suite = unittest.defaultTestLoader.loadTestsFromTestCase(module.PendingAccountRecoveryDataTests)", account)


if __name__ == "__main__":
    unittest.main()
