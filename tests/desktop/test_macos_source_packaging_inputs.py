"""Fixed SOURCE input policy; no app, native writer, signing or Installer."""
import contextlib
import ctypes
import importlib.util
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('source_packaging_input_data',
    ROOT / 'desktop/tools/stage_macos_installed.py')
S = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(S)


def attribute_list(names, *, query_error=False, changed=False):
    def call(fd, buffer, count, flags):
        if buffer is None:
            return -1 if query_error else len(names)
        ctypes.memmove(buffer, names, len(names))
        return len(names) - 1 if changed else len(names)
    return call


class SourcePackagingInputData(unittest.TestCase):
    def test_actual_fixed_sources_and_packaging_selection(self):
        paths = {'history': ROOT / 'desktop/macos-installed-inputs/producer-history.json',
                 'producer-profile': S.PRODUCER_PROFILE, 'service-profile': S.SERVICE_PROFILE,
                 'service-plist': ROOT / 'desktop/macos-installed-inputs' / Path(S.ANDROID_SERVICE_PLIST).name}
        before = {role: (path.read_bytes(), path.stat()) for role, path in paths.items()}
        with mock.patch('subprocess.Popen', side_effect=AssertionError('no native or child execution')):
            for role, path in paths.items():
                self.assertEqual(S.source_packaging_input(role), before[role][0])
                self.assertEqual(S.signature(path.stat()), S.signature(before[role][1]))
            for target in S.MAC_TARGETS:
                result = S.packaging_selection_command(SimpleNamespace(target=target))
                self.assertEqual((result['target'], result['packageVersion']), (target, '0.1.4'))
                self.assertFalse(result['nativeAuthority'])

    def test_roles_select_only_fixed_paths_and_caps(self):
        paths = {'history': (ROOT / 'desktop/macos-installed-inputs/producer-history.json', 65536),
                 'producer-profile': (S.PRODUCER_PROFILE, 1024), 'service-profile': (S.SERVICE_PROFILE, 512),
                 'service-plist': (ROOT / 'desktop/macos-installed-inputs' / Path(S.ANDROID_SERVICE_PLIST).name, 4096)}
        @contextlib.contextmanager
        def parent(path):
            yield 91, path.name
        for role, (path, cap) in paths.items():
            with mock.patch.object(S, 'parent', side_effect=parent) as opened, \
                 mock.patch.object(S, 'read_at', return_value=(b'captured', None)) as read:
                self.assertEqual(S.source_packaging_input(role), b'captured')
                opened.assert_called_once_with(path)
                read.assert_called_once_with(91, path.name, cap, source_metadata=True)
        with mock.patch.object(S, 'parent') as opened, mock.patch.object(S, 'read_at') as read:
            for role in (None, True, 1, [], {}, Path('history'), '', '../history', 'package', 'History'):
                with self.subTest(role=role), self.assertRaises(S.Refused):
                    S.source_packaging_input(role)
            with self.assertRaises(TypeError):
                S.source_packaging_input('history', path=Path('/other'))
            with self.assertRaises(TypeError):
                S.source_packaging_input('history', limit=2**30)
            opened.assert_not_called(); read.assert_not_called()

    def test_source_attribute_policy_and_generic_default(self):
        provenance = b'com.apple.provenance\0'
        for names in (b'', provenance, b'com.apple.quarantine\0', b'com.apple.macl\0',
                      b'dev.mrk.other\0', provenance + b'dev.mrk.other\0', b'com.apple.provenanxe\0'):
            for source in (False, True):
                with self.subTest(names=names, source=source), \
                     mock.patch.object(S.sys, 'platform', 'darwin'), \
                     mock.patch.object(S, '_DARWIN_XATTRS', attribute_list(names)):
                    if names == b'' or (source and names == provenance):
                        S.no_xattrs(91, source_metadata=source)
                    else:
                        with self.assertRaises(S.Refused):
                            S.no_xattrs(91, source_metadata=source)
        for fault in ({'query_error': True}, {'changed': True}):
            with mock.patch.object(S.sys, 'platform', 'darwin'), \
                 mock.patch.object(S, '_DARWIN_XATTRS', attribute_list(provenance, **fault)):
                with self.assertRaises(S.Refused):
                    S.no_xattrs(91, source_metadata=True)
        with mock.patch.object(S.sys, 'platform', 'linux'), mock.patch.object(S.os, 'listxattr', return_value=['com.apple.provenance'], create=True):
            with self.assertRaises(S.Refused):
                S.no_xattrs(91, source_metadata=True)

    def test_source_capture_preserves_file_bounds_and_consuming_close(self):
        info = SimpleNamespace(st_dev=1, st_ino=2, st_mode=stat.S_IFREG | 0o644,
            st_nlink=1, st_uid=501, st_gid=20, st_size=3, st_mtime_ns=4, st_ctime_ns=5)
        @contextlib.contextmanager
        def parent(path):
            yield 91, path.name
        for fault in ('none', 'size', 'symlink', 'links', 'changed', 'short', 'read-error', 'close'):
            first = SimpleNamespace(**vars(info))
            if fault == 'size': first.st_size = 1025
            if fault == 'symlink': first.st_mode = stat.S_IFLNK | 0o777
            if fault == 'links': first.st_nlink = 2
            final = SimpleNamespace(**vars(first))
            if fault == 'changed': final.st_ino += 1
            data = b'xy' if fault == 'short' else b'xyz'
            with self.subTest(fault=fault), mock.patch.object(S, 'parent', side_effect=parent), \
                 mock.patch.object(S.os, 'stat', side_effect=[first, final]), \
                 mock.patch.object(S.os, 'open', return_value=92) as opened, \
                 mock.patch.object(S.os, 'fstat', side_effect=[first, final]), \
                 mock.patch.object(S.os, 'read', side_effect=OSError('inert-read') if fault == 'read-error' else [data, b'']), \
                 mock.patch.object(S, 'no_xattrs') as attributes, \
                 mock.patch.object(S, 'close_once', side_effect=S.Refused('inert-close') if fault == 'close' else None) as closed:
                if fault == 'none':
                    self.assertEqual(S.source_packaging_input('producer-profile'), b'xyz')
                else:
                    with self.assertRaises((S.Refused, OSError)):
                        S.source_packaging_input('producer-profile')
                if fault in ('size', 'symlink', 'links'):
                    opened.assert_not_called(); closed.assert_not_called()
                else:
                    attributes.assert_called_once_with(92, source_metadata=True)
                    closed.assert_called_once_with(92)

    def test_remove_input_keeps_installed_records_on_the_strict_reader(self):
        with mock.patch.object(S.sys, 'platform', 'darwin'), \
             mock.patch.object(S, '_DARWIN_XATTRS', attribute_list(b'com.apple.provenance\0')), \
             mock.patch('subprocess.Popen', side_effect=AssertionError('no native or child execution')):
            with self.assertRaisesRegex(S.Refused, '^file-extended-attributes$'):
                S.remove_input_command(SimpleNamespace(target=S.ARM_TARGET,
                    installed_producer=ROOT / 'desktop/macos-installed-inputs/producer-history.json'))

    def test_service_plist_parser_keeps_its_exact_closed_content(self):
        expected = {'Label': S.ANDROID_SERVICE_LABEL, 'BundleProgram': S.ANDROID_HELPER_BUNDLE_PROGRAM,
                    'MachServices': {S.ANDROID_SERVICE_LABEL: True}}
        valid = S.plistlib.dumps(expected)
        with mock.patch.object(S, 'source_packaging_input', return_value=valid) as source:
            self.assertEqual(S.android_service_plist(), valid)
            source.assert_called_once_with('service-plist')
        for value in ({**expected, 'Label': 'other'}, {**expected, 'BundleProgram': '/other'},
                      {**expected, 'MachServices': {S.ANDROID_SERVICE_LABEL: 1}},
                      {**expected, 'MachServices': {S.ANDROID_SERVICE_LABEL: False}},
                      {**expected, 'extra': True}):
            with self.subTest(value=value), mock.patch.object(S, 'source_packaging_input', return_value=S.plistlib.dumps(value)):
                with self.assertRaises(S.Refused):
                    S.android_service_plist()
        with mock.patch.object(S, 'source_packaging_input', return_value=b'not a plist'):
            with self.assertRaises(S.Refused):
                S.android_service_plist()


if __name__ == '__main__':
    unittest.main()
