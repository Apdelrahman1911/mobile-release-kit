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
        for term in ["fresh installation only", "unavailable", "engineering-v1", "credential vault", "Keychain",
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
        description = (ROOT / "desktop/src-tauri/src/installation.rs").read_text()
        self.assertIn('install_mode: "fresh-only", maintenance: "unavailable"', description)
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
