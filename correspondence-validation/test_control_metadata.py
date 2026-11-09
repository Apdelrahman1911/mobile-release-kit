"""Focused control-image custody checks; only fresh temporary fixtures are written."""
import ctypes
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ROOT = Path(sys.argv.pop(1)).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
bootstrap = load('_control_metadata_bootstrap', Path(__file__).with_name('diagnostic_bootstrap.py'))
stager = load('_control_metadata_stager', ROOT / 'desktop/tools/stage_macos_installed.py')


class ControlMetadata(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mrk-control-metadata-')
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'control'
        self.body = b'inert control fixture\n'
        self.path.write_bytes(self.body)
        self.fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        self.addCleanup(os.close, self.fd)
        self.entry = {'fd': self.fd}
        self.book = SimpleNamespace(file=Mock(return_value=(self.entry, self.body)), check_one=Mock())

    def check(self, adapter=stager):
        bootstrap.control_image_readback(self.book, adapter, self.path, self.body)

    @unittest.skipUnless(sys.platform == 'darwin', 'Darwin native metadata fixture')
    def test_empty_metadata_uses_darwin_descriptor_api(self):
        adapter = SimpleNamespace(no_xattrs=Mock(wraps=stager.no_xattrs))
        with patch.object(stager, '_DARWIN_XATTRS', Mock(return_value=0)) as query:
            self.check(adapter)
            query.assert_called_once_with(self.fd, None, 0, 0)
        self.book.file.assert_called_once_with(self.path, 16 * 1024 * 1024, modes=(0o555,))
        adapter.no_xattrs.assert_called_once_with(self.fd)
        self.book.check_one.assert_called_once_with(self.entry)
        self.assertEqual(os.fstat(self.fd).st_ino, self.path.stat().st_ino)

    @unittest.skipUnless(sys.platform == 'darwin', 'Darwin native metadata fixture')
    def test_nonempty_metadata_is_rejected_without_removal(self):
        library = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
        put = library.fsetxattr
        put.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
        put.restype = ctypes.c_int
        self.assertEqual(put(self.fd, b'com.mrk.control-test', b'x', 1, 0, 0), 0)
        with self.assertRaisesRegex(stager.Refused, 'file-extended-attributes'):
            self.check()
        with self.assertRaisesRegex(stager.Refused, 'file-extended-attributes'):
            stager.no_xattrs(self.fd)

    def test_changed_body_refuses_before_metadata_query(self):
        self.book.file.return_value = (self.entry, b'changed')
        adapter = SimpleNamespace(no_xattrs=Mock())
        with self.assertRaisesRegex(ValueError, 'control-image-readback-metadata'):
            self.check(adapter)
        adapter.no_xattrs.assert_not_called()

    def test_metadata_query_failure_propagates(self):
        adapter = SimpleNamespace(no_xattrs=Mock(side_effect=OSError('query failed')))
        with self.assertRaisesRegex(OSError, 'query failed'):
            self.check(adapter)
        self.book.check_one.assert_not_called()
        os.fstat(self.fd)

    def test_name_replacement_after_metadata_is_rejected(self):
        def query(fd):
            self.assertEqual(fd, self.fd)
            self.path.unlink()
            self.path.write_bytes(self.body)
        def identity(entry):
            if os.fstat(entry['fd']).st_ino != self.path.stat().st_ino:
                raise ValueError('original-changed')
        self.book.check_one.side_effect = identity
        with self.assertRaisesRegex(ValueError, 'original-changed'):
            self.check(SimpleNamespace(no_xattrs=query))


if __name__ == '__main__':
    unittest.main(verbosity=2)
