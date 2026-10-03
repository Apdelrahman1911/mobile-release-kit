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
        source = literal(adapter, "SHELL_RECOVERY_PRODUCER").encode()
        self.assertEqual(source, literal(ROOT / "desktop/tools/ubuntu_publication_lifecycle.py", "SHELL_RECOVERY_PRODUCER").encode())
        self.assertEqual(len(source), 5919)
        self.assertEqual(hashlib.sha256(source).hexdigest(), "32ccb0e534e1021442e8620b0cbcdf73c8a7f6bb4799d8f791b2d9282ffb23fd")
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
        self.assertIn('claimed: AtomicBool', ios)
        self.assertIn('self.claimed.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)', ios)
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


if __name__ == "__main__":
    unittest.main()
