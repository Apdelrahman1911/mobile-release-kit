"""Static preparation contracts only; no app import, package tool or native call."""
from pathlib import Path
import json
import plistlib
import re
import tomllib
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
INPUTS = ROOT / "desktop/macos-installed-inputs"


class MacMaintenancePreparationTests(unittest.TestCase):
    def test_distribution_is_local_fixed_declarative_and_not_relocatable(self):
        root = ET.fromstring((INPUTS / "Distribution.xml").read_bytes())
        self.assertEqual(root.tag, "installer-gui-script")
        self.assertEqual(root.attrib, {"minSpecVersion": "2"})
        self.assertEqual(root.find("domains").attrib,
                         {"enable_anywhere": "false", "enable_currentUserHome": "false", "enable_localSystem": "true"})
        self.assertEqual(root.find("options").attrib, {"customize": "never", "require-scripts": "false",
                                                     "allow-external-scripts": "false", "rootVolumeOnly": "true"})
        self.assertEqual(root.find("volume-check").attrib, {"script": "true"})
        self.assertEqual(root.find("volume-check/allowed-os-versions/os-version").attrib, {"min": "26.0", "before": "27"})
        for node in root.iter():
            self.assertNotIn(node.tag, {"script", "installation-check", "relocate", "locator", "search"})
            self.assertNotIn("customLocation", node.attrib)
        self.assertEqual(root.find("choices-outline/line").attrib, {"choice": "fixed-install"})
        self.assertEqual(root.find("pkg-ref/must-close/app").attrib, {"id": "dev.mobile-release-kit.desktop"})

    def test_component_binding_remains_the_fixed_ordinary_fresh_only_package(self):
        root = ET.fromstring((INPUTS / "Distribution.xml").read_bytes())
        refs = list(root.iter("pkg-ref"))
        self.assertEqual(len(refs), 3)
        self.assertTrue(all(node.get("id") == "dev.mobile-release-kit.desktop.installed" for node in refs))
        component = [node for node in refs if node.text and node.text.strip()]
        self.assertEqual(len(component), 1)
        self.assertEqual(component[0].text.strip(), "MobileReleaseKit.pkg")
        self.assertEqual(component[0].get("auth"), "root")
        plist = plistlib.loads((INPUTS / "Info.plist").read_bytes())
        self.assertEqual(component[0].get("version"), plist["CFBundleVersion"])
        selected = json.loads((INPUTS / "build-release.json").read_bytes())
        self.assertEqual(set(selected), {"schemaVersion", "packageVersion", "release"})
        self.assertEqual(selected["schemaVersion"], 1)
        self.assertTrue(selected["release"].isascii())
        self.assertTrue(0 < len(selected["release"]) < 64)
        self.assertEqual(component[0].get("version"), selected["packageVersion"])
        tauri = json.loads((ROOT / "desktop/src-tauri/tauri.conf.json").read_bytes())
        self.assertEqual(tauri["version"], selected["packageVersion"])
        postinstall = (INPUTS / "postinstall").read_text()
        self.assertIn('if [ "${3:-}" != / ]; then', postinstall)
        self.assertIn('exec ./mrk-macos-install "$PWD/input"', postinstall)
        stage = (ROOT / "desktop/tools/stage_macos_installed.py").read_text()
        self.assertIn('"installer-must-have-no-payload"', stage)
        self.assertIn('set(members) == {"PackageInfo", "Scripts"}', stage)
        native = (ROOT / "desktop/src-tauri/src/bin/macos_install.rs").read_text()
        self.assertIn('self.absent(destination, paths::APP_NAME)?;', native)
        self.assertIn('self.absent(versions, paths::RELEASE)?;', native)
        self.assertIn('No retry/fallback and no deletion.', native)

    def test_one_fixed_selection_reaches_actual_build_and_all_facade_consumers(self):
        paths = (ROOT / "desktop/src-tauri/src/macos_install_paths.rs").read_text()
        self.assertIn('include!(concat!(env!("OUT_DIR"), "/mrk-macos-build-release.rs"));', paths)
        self.assertIn('#[path = "macos_install_fixed_paths.rs"]', paths)
        self.assertNotRegex(paths, r'pub const (?:PACKAGE_VERSION|RELEASE):')
        build = (ROOT / "desktop/src-tauri/build.rs").read_text()
        self.assertIn('fn main() {\n    macos_build_release_data();', build)
        self.assertIn('include_bytes!("../macos-installed-inputs/build-release.json")', build)
        self.assertIn('env::var("CARGO_PKG_VERSION")', build)
        self.assertIn('include_bytes!("tauri.conf.json")', build)
        self.assertEqual(build.count('fn macos_build_release_data()'), 1)
        self.assertEqual(build.count('macos_build_release_data();'), 1)
        library = (ROOT / "desktop/src-tauri/src/lib.rs").read_text()
        self.assertIn('pub mod macos_install_paths;', library)
        installer = (ROOT / "desktop/src-tauri/src/bin/macos_install.rs").read_text()
        self.assertIn('macos_install_paths as paths', installer)
        for target in ('installed_shell_observation.rs', 'session_gtk_qualification.rs'):
            source = (ROOT / 'desktop/src-tauri/tests' / target).read_text()
            self.assertIn('#[path = "../src/macos_install_paths.rs"] mod macos_install_paths;', source)
        helper = (ROOT / "desktop/native/macos-installed-native/build.rs").read_text()
        self.assertIn('#[path = "../../src-tauri/src/macos_install_fixed_paths.rs"]', helper)
        self.assertNotIn('src/macos_install_paths.rs', helper)
        self.assertEqual(helper.count('installed_paths::PAYLOAD_APP'), 2)
        self.assertNotIn('installed_paths::APP', helper)
        stable = (ROOT / "desktop/src-tauri/src/macos_install_fixed_paths.rs").read_text()
        self.assertIn('pub const APP: &str = "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app";', stable)
        self.assertIn('pub const PAYLOAD_APP: &str = "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app/Contents/Helpers/MobileReleaseKitPayload.app";', stable)
        self.assertNotIn('OUT_DIR', '\n'.join(line for line in stable.splitlines() if not line.startswith('//!')))
        for root, package, library, feature in (
            ("macos-desktop-image", "mrk-desktop-image", "mrk_desktop_image", "macos-installed-desktop-image"),
            ("macos-android-register", "mrk-android-register", "mrk_resident_image", "macos-installed-resident-image"),
        ):
            manifest = tomllib.loads((ROOT / "desktop/helpers" / root / "Cargo.toml").read_text())
            self.assertEqual(manifest["package"]["name"], package)
            self.assertIs(manifest["package"]["autobins"], False)
            self.assertEqual(manifest["lib"]["name"], library)
            self.assertEqual(manifest["lib"]["path"], "src/lib.rs")
            self.assertEqual(manifest["lib"]["crate-type"], ["cdylib"])
            self.assertEqual(manifest["profile"]["release"]["panic"], "unwind")
            self.assertEqual(manifest["dependencies"]["mobile-release-kit-desktop"]["features"], [feature])
            self.assertIn(library + ".dylib", stable)
        package = (ROOT / "desktop/tools/macos_android_helper_package.py").read_text()
        self.assertIn('self.release_entry = self.source_original("desktop/macos-installed-inputs/build-release.json"', package)
        self.assertIn('self.read(self.release_entry) == release_body', package)
        self.assertIn('MRK_MACOS_INSTALL_SOURCE_COMMIT=environment["GITHUB_SHA"], MRK_IMAGE_RELEASE_ID=release', package)
        self.assertIn('source == self.environment["MRK_MACOS_INSTALL_SOURCE_COMMIT"]', package)
        self.assertIn("'-DMRK_IMAGE_SOURCE_COMMIT=", package)
        self.assertIn("'-DMRK_IMAGE_RELEASE_ID=", package)
        self.assertNotIn('environment["MRK_IMAGE_RELEASE_ID"]', package)
        self.assertIn('resident-image-sha256=', package)
        self.assertIn('desktop-facade-sha256=', package)
        self.assertIn('image-release-id=', package)

    def test_readme_is_static_honest_and_preserves_user_and_unknown_content(self):
        root = ET.fromstring((INPUTS / "Distribution.xml").read_bytes())
        self.assertEqual(root.find("readme").attrib, {"file": "InstallerReadMe.html", "mime-type": "text/html"})
        text = (INPUTS / "InstallerReadMe.html").read_text()
        for term in ["fresh installation", "exact same-package", "explicitly authorized predecessor", "Uninstall is unavailable", "engineering-v1", "credential vault", "Keychain",
                     "signing originals", "provider registrations", "moved copies", "partial-installation evidence",
                     "does not prove", "never run as root", "separately", "reviewed recovery route"]:
            self.assertIn(term, text)
        self.assertNotRegex(text.lower(), r'<(?:script|form|button|iframe|img)\b|(?:href|src)\s*=|javascript:')

    def test_data_preparation_adds_no_io_authority_or_current_maintenance_availability(self):
        module = (ROOT / "desktop/src-tauri/src/macos_install_maintenance.rs").read_text()
        self.assertIn("pub fn classify_data", module)
        self.assertIn("pub fn matches_current_data", module)
        self.assertIn("#![forbid(unsafe_code)]", module)
        for forbidden in ["std::fs", "std::process", "std::os", "std::env", "getrandom", "tokio::", "tauri::", "mrk_macos_installed_native"]:
            self.assertNotIn(forbidden, module)
        transaction = (ROOT / "desktop/src-tauri/src/macos_install_transaction.rs").read_text()
        self.assertIn("#![forbid(unsafe_code)]", transaction)
        self.assertIn("pub fn correspondence_data", transaction)
        for forbidden in ["std::fs", "std::process", "std::os", "std::env", "getrandom", "tokio::", "tauri::", "mrk_macos_installed_native"]:
            self.assertNotIn(forbidden, transaction)
        self.assertIn("pub use crate::macos_build_profile::MacBuildTarget as MaintenanceTargetData;", module)
        self.assertIn("pub fn parse_for_target_data", module)
        description = (ROOT / "desktop/src-tauri/src/installation.rs").read_text()
        self.assertIn('install_mode: "verified-package-required", maintenance: "unavailable"', description)
        frontend = (ROOT / "desktop/src/installation.ts").read_text()
        self.assertIn("maintenance: 'unavailable'", frontend)
        record = (ROOT / "desktop/src-tauri/src/macos_install_record.rs").read_text()
        self.assertIn('enum CodeLayout { OrdinaryImage, ObserverExecutable }', record)
        self.assertIn('pub(crate) fn require_layout', record)
        self.assertIn('DESKTOP_IMAGE | RESIDENT_IMAGE | "runtime/python/bin/python3"', record)
        self.assertIn('files.contains_key(ANDROID_HELPER) == files.contains_key(RESIDENT_IMAGE)', record)
        self.assertIn('!files.contains_key(DESKTOP_IMAGE) || files.contains_key(RESIDENT_IMAGE)', record)
        runtime = (ROOT / "desktop/src-tauri/src/installed_runtime_macos.rs").read_text()
        self.assertIn('cfg!(feature = "macos-installed-desktop-image")', runtime)
        self.assertIn('cfg!(feature = "macos-installed-observation")', runtime)
        self.assertIn('index.require_layout(layout)', runtime)
        self.assertIn('self.fixed_code_group(outer_contents,contents,layout,end,stop)?;', runtime)
        self.assertNotIn('std::env::var("MRK_MACOS_PACKAGE_ROLE")', runtime)
        for name in ('libmrk_desktop_image.dylib', 'libmrk_resident_image.dylib'):
            self.assertIn(name, runtime)
        guide = (ROOT / "desktop/packaging/macos-maintenance-data.md").read_text()
        for boundary in ('ordinary-image', 'installed-shell-observation', 'non-image fixture',
                         'public maintenance remains unavailable', 'No native acceptance'):
            self.assertIn(boundary, guide)

    def test_normal_preparation_routes_to_original_owner_without_installer_authority(self):
        """SOURCE routing only; never instantiates native ownership or finality."""
        rust = ROOT / 'desktop/src-tauri/src'
        wire = (rust / 'installation.rs').read_text()
        document = (rust / 'asset_session_macos_maintenance.rs').read_text()
        saved = (rust / 'saved_command_android_maintenance.rs').read_text()
        facade = (rust / 'android_build_owner.rs').read_text()
        shell = (rust / 'shell.rs').read_text()
        profile = wire.split('fn preparation_profile_available()', 1)[1].split('fn preparation_request', 1)[0]
        for guard in ['NORMAL_MAC_PROFILE', 'cfg!(feature = "macos-installed-desktop-image")',
                      '!cfg!(feature = "macos-installed-observation")', '!cfg!(feature = "macos-android-registration-helper")']:
            self.assertIn(guard, profile)
        self.assertIn('body.len() == 1', wire.split('fn preparation_request', 1)[1].split('#[derive', 1)[0])
        self.assertIn('CONFIRMATION:&str=crate::installation::PREPARE_QUIT_CONFIRMATION;', saved)
        readiness = saved.split('fn maintenance_readiness(inner:', 1)[1].split('impl SavedCommandOwner', 1)[0]
        for original in ['signing_profile_configured()', 'android_original_document_matches(Some(document))',
                         'android_service_dispatcher.get().is_some()', 'registry.android_registration.unknown()',
                         'inner.android_registration_control.is_unknown()', 'inner.poisoned.load(Ordering::SeqCst)']:
            self.assertIn(original, readiness)
        for acquisition in ['.epoch(', '.claim(', '.census_originals(', '.spawn(', 'getrandom', 'Preparation::']:
            self.assertNotIn(acquisition, readiness)
        snapshot = saved.split('pub(crate) fn maintenance_snapshot', 1)[1].split('pub(crate) fn admit_maintenance', 1)[0]
        self.assertLess(snapshot.index('maintenance_readiness(&self.inner,&registry,document).1'), snapshot.index('.epoch()?'))
        self.assertIn('self.saved.maintenance_readiness(document)', facade)
        start = document.split('pub(crate) fn start_macos_maintenance', 1)[1].split('pub(super) fn reconcile_macos_maintenance_locked', 1)[0]
        self.assertEqual(start.count('self.macos_maintenance_gate(&state)?'), 2)
        self.assertLess(start.index('state.maintenance.closed=true'), start.index('admitted.release()?'))
        self.assertLess(start.index('let original=admitted.handle()'), start.index('admitted.release()?'))
        self.assertLess(start.index('admitted.release()?'), start.index('current.same(&original)'))
        self.assertIn('last.operation==own.operation && last.generation==own.generation', start)
        self.assertNotIn('self.macos_maintenance_status().ok_or_else', start)
        view = document.split('fn installation_preparation_view', 1)[1].split('pub(crate) fn prepare_installation_quit', 1)[0]
        self.assertLess(view.index('let state=self.lock()'), view.index('expected.is_some_and('))
        self.assertLess(view.index('expected.is_some_and('), view.index('Ok(PreparationStatus{'))
        self.assertIn('new_work_closed:state.maintenance.closed()', view)
        public = document.split('impl DocumentBinding {\n    pub(crate) fn installation_preparation_status', 1)[1]
        for authority in ['.release()', '.request_quit(', 'completion=', 'closed=false', 'Completion{']:
            self.assertNotIn(authority, public)
        self.assertIn('if completion.may_reopen()', document)
        self.assertIn('if completion.request_quit(){self.request_quit(app);}', document)
        self.assertIn('document.finish_macos_maintenance(app.clone())', shell)
        for command, target in [('installation_preparation_status', 'installation_preparation_status()'),
                                ('prepare_installation_quit', 'prepare_installation_quit(confirmation)')]:
            block = shell.split('fn ' + command + '(', 1)[1].split('\n#[tauri::command]', 1)[0]
            self.assertLess(block.index('fixture_command!(state, Forbidden'), block.index('edit_window(&webview)?'))
            self.assertLess(block.index('edit_window(&webview)?'), block.index('request_body(&request)?'))
            self.assertIn('state.document.' + target, block)
        handler = shell.split('tauri::generate_handler![', 1)[1].split('];', 1)[0]
        self.assertIn('installation_preparation_status, prepare_installation_quit', handler)
        build = (ROOT / 'desktop/src-tauri/build.rs').read_text()
        capability = json.loads((ROOT / 'desktop/src-tauri/capabilities/main.json').read_text())
        self.assertEqual(capability['windows'], ['main'])
        self.assertIs(capability['local'], True)
        self.assertNotIn('remote', capability)
        for command in ('installation_preparation_status', 'prepare_installation_quit'):
            self.assertEqual(build.count('"' + command + '"'), 1)
            self.assertEqual(capability['permissions'].count('allow-' + command.replace('_', '-')), 1)
        ui = (ROOT / 'desktop/src/components/InstallationDetails.tsx').read_text()
        controller = (ROOT / 'desktop/src/installationController.ts').read_text().split('export class InstallationPreparationController', 1)[1]
        self.assertIn('type="checkbox"', ui)
        self.assertIn('HelpButton content={installationPreparationHelp}', ui)
        self.assertIn('Preparing to quit does not authorize installation changes.', ui)
        self.assertIn('Uninstall is not yet available', ui)
        self.assertIn('if (this.pending) { this.refreshAgain = true; return; }', controller)
        self.assertIn('next.operationId !== before.operationId', controller)
        self.assertIn("['prepared', 'refused', 'unknown'].includes(before.phase)", controller)
        for authority in ['invoke(', '.quit(', '.exit(', 'registerHelper', 'cancelInstallation']:
            self.assertNotIn(authority, controller)
        self.assertIn('install_mode: "verified-package-required", maintenance: "unavailable"', wire)

    def test_private_writer_keeps_original_custody_and_does_not_activate_maintenance(self):
        """SOURCE boundary, not proof of Darwin lock, child or package finality."""
        source = (ROOT / 'desktop/src-tauri/src/bin/macos_install.rs').read_text()
        marker = '    #[cfg(not(feature = "macos-installed-installer-fixture"))]\n    pub(super) fn run() -> i32 {'
        private, ordinary = source.split('    mod worker {', 1)[1].split(marker, 1)
        ordinary = ordinary.split('    // Exactly eight separately named cases', 1)[0]
        self.assertIn('worker::entry()', ordinary)
        self.assertNotIn('Install::new(', ordinary)
        self.assertNotIn('finish_transport(', ordinary)
        self.assertIn('pub(super) fn run() -> i32 { fixture::run() }', ordinary)
        self.assertNotIn('dispatch_private', ordinary)
        self.assertNotIn('Parent::', ordinary)
        # Actual completed-package argv forwarding remains unqualified until
        # the existing Context lane observes it. The legacy stub is not silently
        # treated as a complete-package pathname or given an environment fallback.
        self.assertIn('exec ./mrk-macos-install "$PWD/input"', (INPUTS / 'postinstall').read_text())
        entry = private.split('pub(super) fn entry()', 1)[1].split('#[cfg(test)]', 1)[0]
        self.assertLess(entry.index('let started = match monotonic()'), entry.index('entry_arguments_data(std::env::args_os())'))
        self.assertIn('EntryKind::PrivateWriter) => dispatch_private(&args)', entry)
        self.assertIn('EntryKind::CompletedPackage) => completed_entry(&args[1],&args[2],started)', entry)
        arguments = private.split('fn entry_arguments_data(', 1)[1].split('pub(super) fn entry()', 1)[0]
        self.assertIn('const ARGUMENT_COUNT_LIMIT: usize = if cfg!(feature = "macos-installed-removal-observer") { 7 } else { 4 };', private)
        self.assertIn('values.into_iter().take(ARGUMENT_COUNT_LIMIT + 1)', arguments)
        self.assertIn('result.len() < ARGUMENT_COUNT_LIMIT', arguments)
        self.assertIn('value.into_string()', arguments)
        self.assertNotIn('to_string_lossy', arguments)
        self.assertIn('[_,source,completed] if source.starts_with', arguments)
        self.assertIn('[_,role,endpoint,invocation] if role == ROLE', arguments)
        completed = private.split('fn completed_entry(', 1)[1].split('fn ', 1)[0]
        self.assertIn('Deadline::from_entry(started).and_then(Parent::new)', completed)
        self.assertNotIn('Deadline::start', completed)
        self.assertNotIn('Install::new(', completed)
        self.assertLess(completed.index('parent.run_completed('), completed.index('parent.record_maintenance_export('))
        self.assertLess(completed.index('parent.record_maintenance_export('), completed.index('parent.settle_parent_originals()'))
        self.assertEqual(source.count('fn install_prepared('), 1)
        self.assertEqual(source.count('self.copy_tree("app", prepared.input, stage,'), 1)
        self.assertEqual(source.count('self.copy_tree("runtime", prepared.input, stage,'), 1)
        self.assertIn('self.install_prepared(prepared, &invocation)', source)
        self.assertIn('book.install_prepared(prepared,&args[3])', private)
        for guard in ['const TOTAL: u64 = 120 * SECOND', 'const SETTLEMENT: u64 = 10 * SECOND',
                      'ClockId::CLOCK_MONOTONIC', 'start.checked_add(TOTAL) == Some(end)',
                      'now < self.last.get()', 'end.checked_sub(TOTAL)',
                      'self.book.shared_deadline().and_then(Deadline::check_work)',
                      'self.close_command(); self.terminate_original();']:
            self.assertIn(guard, private)
        constructor = private.split('fn with_worker_deadline(', 1)[1].split('fn shared_deadline', 1)[0]
        self.assertNotIn('Install::new(', constructor)
        self.assertNotIn('Duration::', constructor)
        self.assertIn('command: Option<ManuallyDrop<Command>>', private)
        self.assertIn('self.command_gate_kernel_retained = true', private)
        self.assertIn('Stdio::from(duplicate)', private)
        self.assertIn('OFlag::O_ACCMODE == OFlag::O_RDONLY', private)
        self.assertIn('pread(fd,&mut bytes[used..],used as i64)', private)
        self.assertEqual(private.count('.spawn()'), 1)
        self.assertIn('self.child.as_mut().map(Child::try_wait)', private)
        self.assertIn('self.child.as_mut().map(Child::kill)', private)
        admission = private.split('fn admit_and_go(', 1)[1].split('fn collect(', 1)[0]
        self.assertLess(admission.index('self.book.gate.exclusive_acquired'), admission.index('.spawn()'))
        self.assertLess(admission.index('let output_owned = self.book.control_original'),
                        admission.index('input_owned?; output_owned?;'))
        self.assertLess(admission.index('input_owned?; output_owned?;'),
                        admission.index('self.book.validate_control_original'))
        dispatch = private.split('fn dispatch_private(', 1)[1].split('#[cfg(test)]', 1)[0]
        self.assertLess(dispatch.index('Deadline::inherit(end)'), dispatch.index('read_frame(stdin.as_fd()'))
        self.assertLess(dispatch.index('command_eof(stdin.as_fd()'), dispatch.index('book.worker_go_eof = true'))
        self.assertLess(dispatch.index('book.worker_go_eof = true'), dispatch.index('book.install_prepared'))
        for held in ['parentCommandEndpoint', 'parentResultEndpoint', 'writerCommandEndpoint', 'writerResultEndpoint',
                     'worker-pipe-post', 'worker-source-binding', 'worker-gate-binding']:
            self.assertIn(held, private)
        for forbidden in ['LOCK_UN', 'pre_exec', 'FromRawFd', 'killpg', 'Command::new("/bin',
                          'Command::new("sh', 'std::env::var(', 'std::env::var_os(']:
            self.assertNotIn(forbidden, private)
        for pending in ['"stdoutClosed":false', '"inheritedGateClosed":false', '"selfJoined":false']:
            self.assertIn(pending, private)
        self.assertIn('wait == Some(reported)', private)
        self.assertIn('source_post && timely && !uncertainty', private)
        self.assertIn('fn successful(&self) -> bool { self.outcome.exit == 0 }', private)
        self.assertIn('other-original-refusal', private)
        # B3 action/persistence is still subordinate to the SAME original B2
        # owner. Ordinary entry now uses that owner, but source checks cannot
        # attest Context forwarding, signing, native calls or outer finality.
        actions = source.split('    mod maintenance {', 1)[1].split('    // B2 is deliberately private', 1)[0]
        self.assertEqual(source.count('fn stage_payload('), 1)
        self.assertEqual(source.count('fn record_file('), 1)
        self.assertIn('ActionData::SamePackageNoop', actions)
        self.assertIn('ActionData::RestoreFixedApp', actions)
        self.assertIn('state.mutation_recorded_data()', actions)
        self.assertIn('CorrespondenceData::MatchingRecordedData', actions)
        self.assertIn('IntentData::parse_data', actions)
        self.assertIn('StateData::encode_inverse_data', actions)
        self.assertIn('transaction::archived_state_name_data', actions)
        self.assertIn('native::swap_installation_state', actions)
        self.assertNotIn('std::fs', actions)
        self.assertNotIn('remove_file', actions)
        self.assertNotIn('remove_dir', actions)
        self.assertIn('at < clock.original_endpoint()', actions)
        self.assertIn('fn run_maintenance(', private)
        self.assertIn('self.run_selected(source,Some((selected,request_id)))', private)
        # A request ID is correlation only. The original same-clock parent
        # reserves one fixed EXCL output before intent/GO and never reuses the
        # old per-release export owner or attests its own future return.
        self.assertLess(admission.index('RequestExport::reserve'), admission.index('observed.create_intent'))
        self.assertLess(admission.index('observed.create_intent'), admission.index('.spawn()'))
        self.assertIn('request.empty_original(&self.book)?', admission)
        export = private.split('struct RequestExport {', 1)[1].split('struct Parent {', 1)[0]
        for original in ['transaction::export_name_data(request_id)',
                         'book.create_file(support,&name,Role::ReceiptWriter)',
                         'self.empty_original(book)?', 'self.attempted = true',
                         'book.record_reserved_file(self.writer,&bytes.0)',
                         'book.persist(self.support,false)', 'book.forward_close(reader,']:
            self.assertIn(original, export)
        for renewed in ['Instant::now', 'Duration::', 'Export::', 'std::fs', 'remove_file', 'remove_dir']:
            self.assertNotIn(renewed, export)
        self.assertIn('OFlag::O_EXCL | OFlag::O_NOFOLLOW', source)
        self.assertIn('"resultFinality":"pending-own-write-readback-close-and-outer-return"', private)
        self.assertIn('request_id_data() == request.request_id', private)
        self.assertIn('"requestId":intent.request_id_data()', actions)
        self.assertLess(dispatch.index('command_eof(stdin.as_fd()'), dispatch.index('maintenance::execute('))
        joined_capsule = private.split('fn record_maintenance_capsule(', 1)[1].split('fn ', 1)[0]
        self.assertIn('joined: &JoinedWriter', joined_capsule)
        self.assertIn('maintenance::state_after_join', joined_capsule)
        self.assertIn('CapsuleData::encode_data', joined_capsule)
        self.assertIn('maintenance::persist_capsule', joined_capsule)
        self.assertIn('"parentFinality":"pending-original-closes-and-outer-return"', joined_capsule)
        self.assertLess(joined_capsule.index('maintenance-original-join-required'), joined_capsule.index('observed.publish_controls('))
        self.assertLess(joined_capsule.index('observed.publish_controls('), joined_capsule.index('CapsuleData::encode_data'))
        controls = actions.split('fn publish_controls(', 1)[1].split('pub(super) fn previous(', 1)[0]
        for held in ['self.incoming_controls(book,descriptor,signature)?', 'book.record_file(',
                     'book.persist(self.prepared.destination,false)?', 'held_bytes(book,first,descriptor)?',
                     'held_bytes(book,second,signature)?']:
            self.assertIn(held, controls)
        for invented in ['remove_file', 'remove_dir', 'rename', 'std::fs', 'Command::', 'Duration::']:
            self.assertNotIn(invented, controls)
        reader = (ROOT / 'desktop/src-tauri/src/installation_observation_macos.rs').read_text()
        self.assertIn('self.run_selected(None,end,stop,publish,cleanup_expired,read_returned)', reader)
        self.assertIn('pub(crate) fn run_for_selected_release_data', reader)
        self.assertIn('MaintenanceTargetData::compiled() != Some(selected.target_data())', reader)
        self.assertIn('generation.release_data() != selected.current_data()', reader)
        self.assertIn('CorrespondenceData::MatchingRecordedData', reader)
        self.assertIn('version_roster.keys().cloned().collect::<BTreeSet<_>>() != version_names', reader)
        self.assertNotIn('std::fs', reader)
        route = reader.split('fn producer_route_data(', 1)[1].split('// This cell belongs', 1)[0]
        self.assertIn('(true,true,true) => Ok(true)', route)
        self.assertIn('(false,false,false) if !supplied => Ok(false)', route)
        self.assertIn('_ => Err(Problem::Incomplete)', route)
        selected = reader.split('fn installed_selection(', 1)[1].split('fn roster(', 1)[0]
        self.assertLess(selected.index('InstalledProducer::planned_bytes()'), selected.index('self.held_record('))
        self.assertLess(selected.index('self.producer = Some(InstalledProducer::new('), selected.index('producer.verify('))
        self.assertIn('old.current_data() != selected.current_data()', selected)
        verifier = reader.split('fn verify(&mut self, book: &Book', 1)[1].split('fn settle(', 1)[0]
        self.assertLess(verifier.index('signature.verify_and_close('), verifier.index('ProducerData::parse_data('))
        self.assertLess(verifier.index('signature.settled()'), verifier.index('ProducerData::parse_data('))
        self.assertIn('matches_source_data(signer.team_data(),signer.leaf_sha1_data(),signer.leaf_sha256_data())', verifier)
        self.assertLess(verifier.index('entry.verify_and_close('), verifier.index('payload.verify_and_close('))
        self.assertLess(verifier.index('payload.settled()'), verifier.index('Ok(parsed.release_set_data().clone())'))
        inspect = reader.split('fn inspect(', 1)[1].split('pub(crate) fn run(', 1)[0]
        self.assertLess(inspect.index('!crate::installation::NORMAL_MAC_PROFILE'), inspect.index('native::real_user()'))
        self.assertLess(inspect.index('self.installed_selection('), inspect.index('data::Record::parse_for_release_data('))
        finish = reader.split('fn run_selected(', 1)[1].split('\nfn immediate_child', 1)[0]
        self.assertLess(finish.index('producer.settle('), finish.index('book.settle('))
        self.assertIn('let cleaned = producer_cleaned && self.book.as_mut()', finish)
        self.assertLess(finish.index('if cleaned {'), finish.index('self.producer.take()'))
        self.assertLess(finish.index('self.producer.take()'), finish.index('self.storage_disposed = true'))
        # The isolated helper never enters this app inspection path. Prove the
        # actual role/entry chain instead of enabling producer/signing APIs in
        # the helper or silently rejecting the supported helper startup itself.
        helper = (ROOT / 'desktop/src-tauri/src/android_registration_helper.rs').read_text()
        self.assertNotIn('InstallationSlots', helper)
        self.assertNotIn('installation_observation', helper)
        self.assertIn('ServiceRegistry::new_image(fixed_helper_bytes()?,host)', helper)
        self.assertIn('ServiceRegistry::new(fixed_helper_bytes()?)', helper)
        self.assertIn('MainCustody::start_bound(Some(host))?.drive()', helper)
        runtime = (ROOT / 'desktop/src-tauri/src/installed_runtime_macos.rs').read_text()
        self.assertIn('#[cfg(not(feature = "macos-android-registration-helper"))]\npub(crate) struct AndroidServiceIdentitySlots', runtime)
        app_lib = (ROOT / 'desktop/src-tauri/src/lib.rs').read_text()
        helper_guard = app_lib.split('#[cfg(all(feature = "macos-android-registration-helper", any(', 1)[1].split('compile_error!', 1)[0]
        for feature in ('desktop-shell', 'custom-protocol'):
            self.assertIn('feature = "' + feature + '"', helper_guard)
        normal_profile = (ROOT / 'desktop/src-tauri/src/installation.rs').read_text().split('const NORMAL_MAC_PROFILE:', 1)[1].split('));', 1)[0]
        for feature in ('desktop-shell', 'custom-protocol'):
            self.assertIn('feature = "' + feature + '"', normal_profile)
        native_lib = (ROOT / 'desktop/native/macos-installed-native/src/lib.rs').read_text()
        self.assertIn('#[cfg(not(any(feature = "android-registration-helper", feature = "vault-helper")))]\npub mod install_producer;', native_lib)
        shim = (ROOT / 'desktop/native/macos-installed-native/src/native.m').read_text()
        swap = shim.split('int mrk_swap_installation_state(', 1)[1].split('\n}', 1)[0]
        # A whole-line C comment (including the Apple rename(2) citation) is
        # not a call. Keep every other source character: do not strip arbitrary
        # inline text/strings or turn this into a permissive C-code parser.
        swap_code = '\n'.join(line for line in swap.splitlines() if not line.lstrip().startswith('//'))
        self.assertEqual(len(re.findall(r'\brenameatx_np\s*\(', swap_code)), 1)
        self.assertIn('RENAME_SWAP | RENAME_NOFOLLOW_ANY | RENAME_RESOLVE_BENEATH', swap_code)
        self.assertIn('"installation-v2.json"', swap_code)
        for forbidden in ('unlink', 'rename', 'system', 'remove'):
            self.assertNotRegex(swap_code, r'\b' + forbidden + r'\s*\(')
        cargo = tomllib.loads((ROOT / 'desktop/src-tauri/Cargo.toml').read_text())
        mac = cargo['target']['cfg(all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))']['dependencies']['nix']
        self.assertEqual(mac['version'], '=0.30.1')
        self.assertEqual(set(mac['features']), {'fs', 'mount', 'user', 'process', 'time', 'uio'})
        self.assertEqual(cargo['features']['macos-installed-installer'], [])
        # The external signer is an explicitly selected example, never an
        # ordinary app/Installer/helper capability or default feature.
        self.assertEqual(cargo['features']['macos-package-producer'],
                         ['mrk-macos-installed-native/package-producer-signing'])
        self.assertNotIn('macos-package-producer', cargo['features']['default'])
        examples = [row for row in cargo['example'] if row['name'] == 'macos_package_producer']
        self.assertEqual(examples, [{'name': 'macos_package_producer',
            'path': 'examples/macos_package_producer.rs', 'required-features': ['macos-package-producer'], 'bench': False}])
        signer_guard = app_lib.split('#[cfg(all(any(feature = "macos-package-producer", feature = "macos-remove-producer"), any(', 1)[1].split('compile_error!', 1)[0]
        for feature in ('desktop-shell', 'custom-protocol', 'development-runtime', 'ubuntu-runtime-publisher',
                        'windows-runtime-publisher', 'macos-installed-installer', 'macos-installed-installer-fixture',
                        'macos-android-registration-helper', 'macos-installed-resident-image',
                        'macos-installed-desktop-image', 'macos-installed-observation', 'windows-installed-observation'):
            self.assertIn('feature = "' + feature + '"', signer_guard)
        self.assertIn('PACKAGE_PRODUCER_SIGNING_BUILD\n    == cfg!(any(feature = "macos-package-producer", feature = "macos-remove-producer"))', app_lib)
        native_cargo = tomllib.loads((ROOT / 'desktop/native/macos-installed-native/Cargo.toml').read_text())
        self.assertEqual(native_cargo['features']['package-producer-signing'], [])
        self.assertNotIn('package-producer-signing', native_cargo['features']['default'])
        native_guard = native_lib.split('#[cfg(all(feature = "package-producer-signing", any(', 1)[1].split('compile_error!', 1)[0]
        for feature in ('installed-observation', 'vault-helper', 'android-registration-helper',
                        'desktop-image', 'resident-image', 'e2-native-fixture'):
            self.assertIn('feature = "' + feature + '"', native_guard)
        self.assertIn('mrk_wrapping_keychain_qualification', native_guard)
        build = (ROOT / 'desktop/native/macos-installed-native/build.rs').read_text()
        self.assertIn('Some(if producer_signing { "1" } else { "0" })', build)
        self.assertIn('!helper && !android_helper && !desktop_image && !resident_image', build)
        self.assertIn('&& !observation && !e2_fixture && !qualification', build)
        syntax = build.split('let mut syntax = cc::Build::new();', 1)[1].split('if e2_fixture {', 1)[0]
        aliases = re.findall(r'\("(mrk_install_producer_[a-z_]+)", "(mrk_install_producer_compile_only_[a-z_]+)"\)', syntax)
        suffixes = ('source', 'source_leaf_matches', 'new', 'code_new', 'sign_new', 'sign_copy', 'step', 'release', 'retire')
        self.assertEqual(aliases, [('mrk_install_producer_' + name, 'mrk_install_producer_compile_only_' + name) for name in suffixes])
        self.assertIn('syntax.define("MRK_INSTALL_PRODUCER_SIGNING", Some("1"))', syntax)
        self.assertIn('syntax.include(&compile_only).file("src/install_producer.m")', syntax)
        self.assertIn('include_bytes!("build_support/producer_compile_only.h")', build)
        example = (ROOT / 'desktop/src-tauri/examples/macos_package_producer.rs').read_text()
        self.assertIn('feature="macos-package-producer"', example)
        self.assertIn('validate_emission_data(', example)
        for field in ('MRK_MACOS_INSTALL_SOURCE_COMMIT', 'MRK_BUNDLED_RUNTIME_MANIFEST_SHA256',
                      'MRK_MACOS_INSTALL_INVENTORY_SHA256'):
            self.assertIn('option_env!("' + field + '")', example)
        self.assertNotIn('mrk_install_producer_compile_only_', example)
        remover = [row for row in cargo['bin'] if row['name'] == 'mrk-macos-remove']
        self.assertEqual(remover, [{'name': 'mrk-macos-remove', 'path': 'src/bin/macos_install.rs',
                                   'required-features': ['macos-installed-remover']}])
        self.assertEqual(cargo['features']['macos-installed-remover'], [])
        self.assertEqual(cargo['features']['macos-remove-producer'], ['mrk-macos-installed-native/package-producer-signing'])
        self.assertNotIn('macos-remove-producer', cargo['features']['default'])
        self.assertEqual([row for row in cargo['example'] if row['name'] == 'macos_remove_producer'], [{
            'name': 'macos_remove_producer', 'path': 'examples/macos_remove_producer.rs',
            'required-features': ['macos-remove-producer'], 'bench': False}])
        remover_guard = app_lib.split('#[cfg(all(feature = "macos-installed-remover", any(', 1)[1].split('compile_error!', 1)[0]
        for feature in ('macos-installed-installer', 'desktop-shell', 'macos-android-registration-helper',
                        'macos-installed-observation', 'macos-package-producer', 'macos-remove-producer'):
            self.assertIn('feature = "' + feature + '"', remover_guard)
        common = (ROOT / 'desktop/src-tauri/examples/macos_producer_common/mod.rs').read_text()
        removal = (ROOT / 'desktop/src-tauri/examples/macos_remove_producer.rs').read_text()
        self.assertIn('#[path="macos_producer_common/mod.rs"]', example)
        self.assertIn('#[path="macos_producer_common/mod.rs"]', removal)
        self.assertEqual(common.count('struct Book {'), 1)
        self.assertNotIn('struct Book {', example + removal)
        self.assertIn('ORIGINAL_LIMIT:usize=80', common)
        self.assertIn('READ_LIMIT:u64=2*1024*1024*1024', common)
        self.assertIn('fn native_point(&self,point:ProducerCheckpoint)', common)
        self.assertIn('if self.all().is_ok()', common)
        self.assertNotIn('RefCell', common)
        self.assertNotIn('try_clone', common + removal)
        self.assertIn('current.inventory_sha256==inventory_hash', removal)
        self.assertIn('Inventory::parse(&inventory_raw,runtime_manifest)', removal)
        self.assertIn('paths::REMOVER_INVENTORY_PATH', removal)
        self.assertIn('RemovalProgramVerifier::new()', removal)
        self.assertIn('book.fd(input_root)?.as_fd(),book.fd(program)?.as_fd()', removal)
        self.assertLess(removal.index('install_verifier.verify_and_close'), removal.index('RemovalData::parse_data'))
        self.assertLess(removal.index('program_verifier.verify_and_close'), removal.index('signer.sign_and_close'))
        self.assertLess(removal.index('verifier.verify_and_close(&descriptor'), removal.index('book.create(root,DESCRIPTOR_FILENAME'))
        self.assertEqual(removal.count('book.roster('), 4)
        self.assertNotIn('MRK_MACOS_INSTALL_INVENTORY_SHA256', removal)
        self.assertIn('mrk-remove-producer-emitted', removal)
        guide = (ROOT / 'desktop/packaging/macos-maintenance-data.md').read_text()
        self.assertIn('B3 ordinary entry and result/export integration are mandatory', guide)
        self.assertIn('does not establish native acceptance', guide)
