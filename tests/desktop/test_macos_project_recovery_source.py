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


        # Complete SOURCE census, not a Rust cfg interpreter or a native test.
        # Keep the ordinary feature/negative gates in each full expression;
        # only the Mac target term is shared by the two admitted LP64 targets.
        target = ('target_os = "macos", target_pointer_width = "64", '
                  'any(target_arch = "aarch64", target_arch = "x86_64")')
        linux = 'all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")'
        mac = ('all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", '
               'feature = "macos-installed-observation", not(feature = "development-runtime"), '
               'not(feature = "ubuntu-runtime-publisher"), not(feature = "macos-installed-installer"), ' + target + ')')
        joined = ('all(test, debug_assertions, feature = "desktop-shell", feature = "custom-protocol", '
                  'not(feature = "development-runtime"), not(feature = "ubuntu-runtime-publisher"), '
                  'any(' + linux + ', all(' + target + ', feature = "macos-installed-observation", '
                  'not(feature = "macos-installed-installer"))))')
        short_mac = 'all(' + target + ', feature = "macos-installed-observation")'
        short_joined = ('any(' + linux + ', all(' + target + ', feature = "macos-installed-observation", '
                        'not(feature = "macos-installed-installer")))')
        shapes = (mac, joined, 'not(' + mac + ')', short_mac, short_joined)
        roster = {
            'asset_session.rs': (19, 2, 1, 0, 0),
            'asset_session_installation.rs': (11, 0, 1, 0, 0),
            'asset_session_installation_memory.rs': (2, 0, 0, 0, 0),
            'asset_session_keyring_macos.rs': (2, 0, 0, 0, 0),
            'asset_session_vault.rs': (10, 0, 0, 0, 0),
            'edit_owner.rs': (14, 15, 0, 2, 10),
            'ios_archive_owner.rs': (1, 0, 0, 0, 0),
            'project_recovery_owner.rs': (1, 3, 0, 0, 0),
            'project_recovery_protocol.rs': (0, 1, 0, 0, 0),
            'saved_command_owner.rs': (25, 9, 0, 0, 0),
            'supervisor.rs': (1, 0, 0, 0, 0),
            'vault_keyring_macos.rs': (14, 0, 0, 0, 0),
        }
        texts, actual_targets, total = {}, set(), 0
        for filename, counts in roster.items():
            body = (MAC / filename).read_text()
            texts[filename] = ' '.join(body.split())
            attrs = [' '.join(match.group(1).split())
                     for match in re.finditer(r'#\[cfg\((.*?)\)\]', body, re.S)
                     if 'macos-installed-observation' in match.group(1)]
            self.assertEqual(len(attrs), sum(counts), filename)
            self.assertEqual(set(attrs), {shape for shape, count in zip(shapes, counts) if count}, filename)
            self.assertEqual(tuple(attrs.count(shape) for shape in shapes), counts, filename)
            total += len(attrs)
            for attr in attrs:
                match = re.search(r'target_os = "([^"]+)", target_pointer_width = "([^"]+)", '
                                  r'any\(target_arch = "([^"]+)", target_arch = "([^"]+)"\)', attr)
                self.assertIsNotNone(match)
                actual_targets.add(match.groups())
        self.assertEqual(total, 144)
        self.assertEqual(actual_targets, {('macos', '64', 'aarch64', 'x86_64')})
        actual_os, actual_width, *actual_arches = next(iter(actual_targets))
        for system, width, architecture, expected in (
            ('macos', '64', 'aarch64', True), ('macos', '64', 'x86_64', True),
            ('macos', '32', 'aarch64', False), ('macos', '32', 'x86_64', False),
            ('macos', '64', 'powerpc64', False), ('linux', '64', 'x86_64', False),
            ('windows', '64', 'x86_64', False), ('darwin', '64', 'aarch64', False),
        ):
            self.assertIs(system == actual_os and width == actual_width and architecture in actual_arches, expected)

        # These are one signature/call and one memory-accounting alternative,
        # not independent broad allowances. Normal builds keep their originals.
        asset = texts['asset_session.rs']
        self.assertIn('#[cfg(' + mac + ')] { self.project_result_original(id, None).await }', asset)
        self.assertIn('#[cfg(not(' + mac + '))] { self.project_result_original(id).await }', asset)
        self.assertIn('#[cfg(' + mac + ')] mut selection: Option<&mut Option<InstalledMacProjectSelectionData>>,', asset)
        installation = texts['asset_session_installation.rs']
        self.assertIn('#[cfg(' + mac + ')] let observation = {', installation)
        self.assertIn('#[cfg(not(' + mac + '))] let observation = 0;', installation)

        # Short child guards inherit the unchanged complete test/feature gate.
        edit = texts['edit_owner.rs']
        self.assertIn('#[cfg(' + joined + ')] #[derive(Clone)] pub(crate) struct InstalledConfigFinality { '
                      '#[cfg(' + short_mac + ')] original: std::sync::Weak<Session>,', edit)
        for parent in ('enum InstalledEditFinality {', 'impl InstalledEditFinality {',
                       'pub(crate) fn installed_observation_final(',
                       'let mut installed_observed = None;',
                       'if settled && installed_edit_selected(owner.domain, &inner.runtime) && startup.returned {'):
            self.assertIn('#[cfg(' + joined + ')] ' + parent, edit)
        self.assertIn('InstalledConfigFinality { #[cfg(' + short_mac + ')] original: Arc::downgrade(&owner),', edit)

        # Paired DATA check: choose ONE exact current-target protocol profile.
        # No target-independent Some(Arm|Intel) allowance or production change.
        check = texts['saved_command_owner.rs'].split('pub(crate) fn installed_offline_owner_data_check() -> bool {', 1)[1]
        expected_profile = ('let expected_profile = if cfg!(target_arch = "aarch64") { '
                            'wire::Profile::MacosArm64 } else { wire::Profile::MacosX64 };')
        self.assertIn(expected_profile, check)
        self.assertIn('if wire::Profile::current() != Some(expected_profile) '
                      '|| wire::CONSENT != "saved-offline-android-v1" { return false; }', check)
        self.assertIn('#[cfg(all(test, ' + target + '))] pub(crate) fn installed_offline_owner_data_check()',
                      texts['saved_command_owner.rs'])
        profiles = ' '.join((MAC / 'offline_preflight_protocol.rs').read_text().split())
        mappings = re.findall(r'else if cfg!\(all\(target_os = "macos", target_arch = "(aarch64|x86_64)"\)\) '
                              r'\{ Some\(Self::(MacosArm64|MacosX64)\) \}', profiles)
        self.assertEqual(mappings, [('x86_64', 'MacosX64'), ('aarch64', 'MacosArm64')])

    def test_ordinary_original_selection_precedes_admission_and_no_new_ipc_or_mode(self):
        saved = (MAC / "saved_command_owner.rs").read_text()
        ios_selection = saved.split('fn ios_installed_selected(', 1)[1].split('fn android_original_document_matches(', 1)[0]
        self.assertIn('self.domain == SavedCommandDomain::IOSArchive', ios_selection)
        self.assertIn('&& self.runtime.ios_archive_installed_profile_available()', ios_selection)
        self.assertNotIn('recovery_installed_selected', ios_selection)
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
