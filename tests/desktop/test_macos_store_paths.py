"""Inert DATA regressions for genuine Store template/notice path shapes.

No Ruby/native signature execution or supplier acquisition occurs here.
"""
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_macos_launcher_staging import TOOL, binary
from test_macos_store_composition import fixture, args

_SPEC = importlib.util.spec_from_file_location("store_path_preparer", TOOL.DESKTOP / "tools/prepare_runtime.py")
PREP = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(PREP)

# Complete 18 filename differences in the authenticated unsigned ARM supplier.
# Bodies below are synthetic, not copies of supplier payloads or evidence.
STORE_NAMES = ('bundle/ruby/3.3.0/gems/fastlane-2.235.0/fastlane/lib/fastlane/plugins/template/%gem_name%.gemspec.erb', 'bundle/ruby/3.3.0/gems/fastlane-2.235.0/fastlane/lib/fastlane/plugins/template/lib/fastlane/plugin/%plugin_name%.rb.erb', 'bundle/ruby/3.3.0/gems/fastlane-2.235.0/fastlane/lib/fastlane/plugins/template/lib/fastlane/plugin/%plugin_name%/version.rb.erb', 'bundle/ruby/3.3.0/gems/fastlane-2.235.0/fastlane/lib/fastlane/plugins/template/lib/fastlane/plugin/%plugin_name%/helper/%plugin_name%_helper.rb.erb', 'bundle/ruby/3.3.0/gems/fastlane-2.235.0/fastlane/lib/fastlane/plugins/template/lib/fastlane/plugin/%plugin_name%/actions/%plugin_name%_action.rb.erb', 'bundle/ruby/3.3.0/gems/fastlane-2.235.0/fastlane/lib/fastlane/plugins/template/spec/%plugin_name%_action_spec.rb.erb', 'bundle/ruby/3.3.0/gems/terminal-notifier-2.0.0/vendor/terminal-notifier/Terminal Notifier/AppDelegate.h', 'bundle/ruby/3.3.0/gems/terminal-notifier-2.0.0/vendor/terminal-notifier/Terminal Notifier/Terminal Notifier-Prefix.pch', 'bundle/ruby/3.3.0/gems/terminal-notifier-2.0.0/vendor/terminal-notifier/Terminal Notifier/main.m', 'bundle/ruby/3.3.0/gems/terminal-notifier-2.0.0/vendor/terminal-notifier/Terminal Notifier/AppDelegate.m', 'bundle/ruby/3.3.0/gems/terminal-notifier-2.0.0/vendor/terminal-notifier/Terminal Notifier/Terminal Notifier-Info.plist', 'bundle/ruby/3.3.0/gems/terminal-notifier-2.0.0/vendor/terminal-notifier/Terminal Notifier/en.lproj/InfoPlist.strings', 'bundle/ruby/3.3.0/gems/terminal-notifier-2.0.0/vendor/terminal-notifier/Terminal Notifier/en.lproj/Credits.rtf', 'bundle/ruby/3.3.0/gems/terminal-notifier-2.0.0/vendor/terminal-notifier/Terminal Notifier/en.lproj/MainMenu.xib', 'bundle/ruby/3.3.0/gems/terminal-notifier-2.0.0/vendor/terminal-notifier/Terminal Notifier.xcodeproj/project.pbxproj', 'bundle/ruby/3.3.0/gems/terminal-notifier-2.0.0/vendor/terminal-notifier/Terminal Notifier.xcodeproj/xcshareddata/xcschemes/Terminal Notifier.xcscheme', 'bundle/ruby/3.3.0/gems/terminal-notifier-2.0.0/vendor/terminal-notifier/Terminal Notifier.xcodeproj/project.xcworkspace/contents.xcworkspacedata', 'bundle/ruby/3.3.0/gems/terminal-notifier-2.0.0/vendor/terminal-notifier/Terminal Notifier.xcodeproj/project.xcworkspace/xcshareddata/Terminal Notifier.xccheckout')


def cpio(rows):
    def member(name, body, mode, inode):
        encoded = name.encode("ascii") + b"\0"
        fields = (inode, mode, 0, 0, 1, 0, len(body), 0, 0, 0, 0, len(encoded), 0)
        head = b"070701" + b"".join(f"{value:08x}".encode() for value in fields) + encoded
        head += bytes(-len(head) % 4)
        return head + body + bytes(-len(body) % 4)
    entries = [(".", b"", stat.S_IFDIR | 0o755)] + rows + [("TRAILER!!!", b"", 0)]
    return b"".join(member(name, body, mode, index + 1) for index, (name, body, mode) in enumerate(entries))


class StorePaths(unittest.TestCase):
    def test_contextual_names_and_full_depth_keep_other_roots_strict(self):
        self.assertEqual(len(STORE_NAMES), 18)
        self.assertEqual(max(len(name.split("/")) for name in STORE_NAMES), 16)
        for suffix in STORE_NAMES:
            self.assertTrue(PREP._safe_runtime_path(suffix, store_prefix=""))
            self.assertFalse(PREP._safe_runtime_path(suffix))
            for prefix in ("store", "runtime/store", "input/runtime/store"):
                name = prefix + "/" + suffix
                self.assertTrue(TOOL.safe_path(name, mac_store_prefix=prefix), name)
                self.assertFalse(TOOL.safe_path(name))
                self.assertTrue(TOOL.directories({name}, mac_store_prefix=prefix))
        deepest = max(STORE_NAMES, key=lambda name: len(name.split("/")))
        for prefix in ("store", "runtime/store", "input/runtime/store"):
            self.assertFalse(TOOL.safe_path(prefix + "/extra/" + deepest, mac_store_prefix=prefix))
            for suffix in ("../x", "a//b", "a/./b", " leading", "trailing ", "dot.", "a\\b", "a:b", "a\tb", "NUL.txt", "COM1", "é"):
                self.assertFalse(TOOL.safe_path(prefix + "/" + suffix, mac_store_prefix=prefix))
            with self.assertRaises(TOOL.Refused):
                TOOL.directories({prefix + "/A b/a", prefix + "/a b/b"}, mac_store_prefix=prefix)
            with self.assertRaises(TOOL.Refused):
                TOOL.directories({prefix + "/A b", prefix + "/A b/b"}, mac_store_prefix=prefix)
        self.assertFalse(TOOL.safe_path("app/Contents/Terminal Notifier/file", mac_store_prefix="runtime/store"))
        self.assertFalse(PREP._safe_runtime_path("python/Terminal Notifier/file", store_prefix="store"))

    def test_supplier_empty_directories_are_observed_and_rechecked_not_output(self):
        self.assertNotEqual(os.geteuid(), 0)
        with tempfile.TemporaryDirectory(prefix="mrk-store-paths-") as tmp:
            root = Path(tmp)
            path = root / STORE_NAMES[0]
            path.parent.mkdir(parents=True); path.write_bytes(b"inert template\n")
            empty = root / "lib/ruby/gems/3.3.0/gems/fiddle-1.1.2"
            empty.mkdir(parents=True)
            directories = {}
            paths = PREP.store_component_files(root, directories=directories)
            self.assertEqual(paths, [path])
            self.assertIn(empty, directories)
            rows = [(p.relative_to(root).as_posix(), PREP._state(PREP._ordinary(p)), PREP.digest(p.read_bytes()), p.stat().st_size) for p in paths]
            PREP._store_post(root, rows, directories)
            with self.assertRaises(PREP.PreparationError): PREP.files(root)
            empty.rmdir()
            with self.assertRaisesRegex(PREP.PreparationError, "original or roster changed"):
                PREP._store_post(root, rows, directories)
            empty.mkdir()
            path.unlink(); path.symlink_to("/never-read")
            with self.assertRaises(PREP.PreparationError): PREP.store_component_files(root, directories={})

    def test_real_current_composition_keeps_all_names_bytes_and_omits_only_empty_directories(self):
        with fixture() as f:
            for name in STORE_NAMES:
                path = f.component / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(("inert DATA " + name).encode()); path.chmod(0o444)
            empty = f.component / "lib/ruby/gems/3.3.0/gems/fiddle-1.1.2"
            empty.mkdir(parents=True)
            described = TOOL.current_runtime_command(args(f, "describe-paths"))
            final = args(f, "final-paths", final=True)
            final.expected_source = described["sourceInputsSha256"]
            final.expected_manifest = described["successorManifestSha256"]
            TOOL.current_runtime_command(final)
            output = TOOL.runtime_tree(final.output, final.expected_manifest, current=True)
            for name in STORE_NAMES:
                self.assertEqual(output["store/" + name], (("inert DATA " + name).encode(), 0o444))
                self.assertTrue((f.component / name).is_file())
            self.assertTrue(empty.is_dir())
            self.assertFalse((final.output / "store/lib/ruby/gems/3.3.0/gems/fiddle-1.1.2").exists())
            with self.assertRaises(TOOL.Refused): TOOL.tree(final.output)

    def test_scripts_copy_requires_explicit_selected_profile_before_native_parser(self):
        with tempfile.TemporaryDirectory(prefix="mrk-store-scripts-paths-") as tmp:
            root = Path(tmp)
            files = {"runtime/store/" + name: (b"inert DATA", 0o444) for name in STORE_NAMES}
            files["install-inventory.json"] = (b"inert inventory anchor", 0o444)
            source = root / "input"
            TOOL.write_tree(source, files, mac_store_prefix="runtime/store")
            installer = root / "installer"
            installer.write_bytes(binary(TOOL.ARM_TARGET))
            values = dict(input=source, installer=installer, expected_inventory=TOOL.digest(files["install-inventory.json"][0]),
                          expected_source="1" * 40, fixture=False, target=TOOL.ARM_TARGET)
            with self.assertRaises(TOOL.Refused):
                TOOL.scripts_command(SimpleNamespace(**values, output=root / "strict", store_runtime=False))
            self.assertFalse((root / "strict").exists())
            with mock.patch.object(TOOL, "signed_store_selection", side_effect=TOOL.Refused("missing-selection")):
                with self.assertRaisesRegex(TOOL.Refused, "missing-selection"):
                    TOOL.scripts_command(SimpleNamespace(**values, output=root / "missing", store_runtime=True))
            self.assertFalse((root / "missing").exists())
            with self.assertRaisesRegex(TOOL.Refused, "package-store-purpose"):
                TOOL.package_store_profile(SimpleNamespace(store_runtime=True, remove=True))
            TOOL.scripts_command(SimpleNamespace(**values, output=root / "scripts", store_runtime=True))
            actual = TOOL.tree(root / "scripts", packager=True, mac_store_prefix="input/runtime/store")
            for name, body in files.items(): self.assertEqual(actual["input/" + name], body)
            archive = cpio([(name, body or b"", stat.S_IFREG | mode) for name, (body, mode) in actual.items()] +
                           [(name, b"", stat.S_IFDIR | 0o555) for name in TOOL.directories(actual, mac_store_prefix="input/runtime/store")])
            self.assertEqual(TOOL.cpio_members(archive, store_runtime=True),
                             {**actual, **{name: (None, 0o555) for name in TOOL.directories(actual, mac_store_prefix="input/runtime/store")}})
            with self.assertRaises(TOOL.Refused): TOOL.cpio_members(archive)

    def test_scoped_cpio_count_preserves_legacy_limit_and_total_bound(self):
        # One tiny DATA archive, not thousands of filesystem objects/native work.
        rows = [(f"input/runtime/store/f{index:05}", b"x", stat.S_IFREG | 0o444) for index in range(4097)]
        archive = cpio(rows)
        self.assertEqual(len(TOOL.cpio_members(archive, store_runtime=True)), 4097)
        with self.assertRaisesRegex(TOOL.Refused, "scripts-entry-count"):
            TOOL.cpio_members(archive)
        # Exercise max/+1 using a scoped inert cap to avoid a large test allocation.
        with mock.patch.object(TOOL, "MAX_ENTRIES", 4097):
            self.assertEqual(len(TOOL.cpio_members(archive, store_runtime=True)), 4097)
            with self.assertRaisesRegex(TOOL.Refused, "scripts-entry-count"):
                TOOL.cpio_members(cpio(rows + [("input/runtime/store/extra", b"x", stat.S_IFREG | 0o444)]), store_runtime=True)
