"""Real temporary-tree staging tests; synthetic Mach-O, not native signing proof."""
import contextlib
import importlib.util
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

PATH = Path(__file__).resolve().parents[2] / 'desktop/tools/stage_macos_installed.py'
SPEC = importlib.util.spec_from_file_location('launcher_staging_test_tool', PATH)
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)


def binary(target, dependency=b'/usr/lib/swift/libswiftCore.dylib'):
    def text_command(kind, text, prefix):
        size = (len(prefix) + len(text) + 1 + 7) & ~7
        return struct.pack('<II', kind, size) + prefix[8:] + text + bytes(size - len(prefix) - len(text))
    dyld = text_command(0xE, b'/usr/lib/dyld', struct.pack('<III', 0xE, 0, 12))
    load = text_command(0xC, dependency, struct.pack('<6I', 0xC, 0, 24, 0, 0, 0))
    build = struct.pack('<6I', 0x32, 24, 1, 26 << 16, 26 << 16, 0)
    cpu, subtype = (0x0100000C, 0) if target == TOOL.ARM_TARGET else (0x01000007, 3)
    commands = dyld + load + build
    return struct.pack('<8I', 0xFEEDFACF, cpu, subtype, 2, 3, len(commands), 0, 0) + commands


class LauncherStaging(unittest.TestCase):
    def fixture(self, root, *, target=TOOL.ARM_TARGET, ticket=False):
        root.mkdir()
        rows = {
            'Contents/MacOS/mrk-macos-launcher': (binary(target), 0o755),
            'Contents/Info.plist': ((TOOL.DESKTOP / 'native/macos-applications-launcher/Info.plist').read_bytes(), 0o644),
            'Contents/Resources/icon.png': ((TOOL.DESKTOP / 'src-tauri/icons/icon.png').read_bytes(), 0o644),
            'Contents/_CodeSignature/CodeResources': (b'synthetic-signature-not-proof', 0o644),
        }
        if ticket:
            rows['Contents/CodeResources'] = (b'synthetic-ticket-not-notarization', 0o644)
        for name, (body, mode) in rows.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
            path.chmod(mode)
        return SimpleNamespace(target=target, package_role='ordinary-image', applications_launcher=root,
            expected_applications_launcher=TOOL.digest(rows['Contents/MacOS/mrk-macos-launcher'][0]),
            expected_applications_launcher_ticket=TOOL.digest(rows['Contents/CodeResources'][0]) if ticket else None)

    def test_legacy_absence_and_incomplete_or_wrong_role_refuse(self):
        self.assertEqual(TOOL.applications_launcher_files(SimpleNamespace()), {})
        for args in [SimpleNamespace(applications_launcher=Path('/not-opened')),
                     SimpleNamespace(expected_applications_launcher='a' * 64),
                     SimpleNamespace(expected_applications_launcher_ticket='b' * 64),
                     SimpleNamespace(applications_launcher=Path('/not-opened'), expected_applications_launcher='a' * 64,
                                     package_role='installed-shell-observation')]:
            with self.subTest(args=args), mock.patch.object(TOOL, 'tree', side_effect=AssertionError('must not read')):
                with self.assertRaises(TOOL.Refused):
                    TOOL.applications_launcher_files(args)

    def test_both_architectures_and_explicit_ticket_preserve_every_byte(self):
        for target in TOOL.MAC_TARGETS:
            for ticket in (False, True):
                with self.subTest(target=target, ticket=ticket), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp) / 'launcher.app'
                    args = self.fixture(root, target=target, ticket=ticket)
                    before = TOOL.tree(root)
                    result = TOOL.applications_launcher_files(args)
                    self.assertEqual(len(result), 5 if ticket else 4)
                    for path, (body, mode) in before.items():
                        copied, copied_mode = result[TOOL.LAUNCHER_BUNDLE + '/' + path]
                        self.assertEqual(body, copied)
                        self.assertEqual(copied_mode, 0o555 if mode == 0o755 else 0o644)
                    self.assertEqual(TOOL.tree(root), before)

    def test_actual_tree_rejects_missing_extra_symlink_and_invalid_modes(self):
        for change in ('missing', 'extra', 'symlink', 'mode', 'empty', 'ticket-unrequested'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / 'launcher.app'
                args = self.fixture(root)
                info = root / 'Contents/Info.plist'
                if change == 'missing': info.unlink()
                elif change == 'extra': (root / 'extra').write_bytes(b'extra')
                elif change == 'symlink':
                    info.unlink(); info.symlink_to('/never-read')
                elif change == 'mode': info.chmod(0o755)
                elif change == 'empty': info.write_bytes(b'')
                else: (root / 'Contents/CodeResources').write_bytes(b'not-requested')
                with self.assertRaises(TOOL.Refused): TOOL.applications_launcher_files(args)

    def test_changed_signed_bytes_info_icon_or_ticket_refuse(self):
        for field in ('binary', 'info', 'icon', 'ticket', 'version'):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / 'launcher.app'
                args = self.fixture(root, ticket=True)
                if field == 'binary': args.expected_applications_launcher = 'f' * 64
                elif field == 'ticket': args.expected_applications_launcher_ticket = 'f' * 64
                elif field == 'info': (root / 'Contents/Info.plist').write_bytes(b'not the expected Info')
                elif field == 'icon': (root / 'Contents/Resources/icon.png').write_bytes(b'wrong icon')
                with mock.patch.object(TOOL, 'source_build_selection', return_value=SimpleNamespace(
                        package_version='99.0.0')) if field == 'version' else contextlib.nullcontext():
                    with self.assertRaises(TOOL.Refused): TOOL.applications_launcher_files(args)

    def test_existing_system_loader_policy_is_not_relaxed_for_swift(self):
        for dependency in (b'@rpath/libswiftCore.dylib', b'/tmp/lib.dylib', b'/usr/lib/../tmp/lib.dylib'):
            with self.subTest(dependency=dependency), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / 'launcher.app'
                args = self.fixture(root)
                data = binary(TOOL.ARM_TARGET, dependency)
                (root / 'Contents/MacOS/mrk-macos-launcher').write_bytes(data)
                args.expected_applications_launcher = TOOL.digest(data)
                with self.assertRaises(TOOL.Refused): TOOL.applications_launcher_files(args)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'launcher.app'; args = self.fixture(root)
            args.target = TOOL.INTEL_TARGET
            with self.assertRaises(TOOL.Refused): TOOL.applications_launcher_files(args)
