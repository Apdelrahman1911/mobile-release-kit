"""Offline fixture coverage for dependency authentication and safe extraction."""
import hashlib
import importlib.util
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('store_input_test_tool',
    Path(__file__).resolve().parents[2] / 'desktop/tools/prepare_macos_store_inputs.py')
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)


class StoreInputs(unittest.TestCase):
    def test_tooling_copy_uses_core_completeness_without_overwriting(self):
        # Actual first-party imports are stdlib only; no release/build action.
        import sys
        sys.path.insert(0, str(TOOL.ROOT / 'src'))
        try:
            from mobile_release.tooling import REQUIRED_TOOLING_FILES, _complete_tooling_root
        finally:
            sys.path.pop(0)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'source'; source.mkdir()
            for relative in REQUIRED_TOOLING_FILES:
                file = source / relative; file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(('synthetic:' + relative).encode())
            destination = root / 'tooling'
            TOOL.copy_tooling(source, destination)
            self.assertTrue(_complete_tooling_root(destination))
            self.assertEqual({str(p.relative_to(destination)) for p in destination.rglob('*') if p.is_file()},
                             set(REQUIRED_TOOLING_FILES))
            for relative in REQUIRED_TOOLING_FILES:
                self.assertEqual((destination / relative).read_bytes(), (source / relative).read_bytes())
            with self.assertRaises(FileExistsError): TOOL.copy_tooling(source, destination)
            missing = source / 'schemas/project.schema.json'; missing.unlink()
            with self.assertRaises(ValueError): TOOL.copy_tooling(source, root / 'missing')
            self.assertFalse((root / 'missing').exists())
            missing.symlink_to(destination / 'schemas/project.schema.json')
            with self.assertRaises(ValueError): TOOL.copy_tooling(source, root / 'linked')
            self.assertFalse((root / 'linked').exists())

    def test_download_authentication_and_no_overwrite(self):
        data = b'public synthetic dependency'
        asset = {'url': 'https://example.invalid/dependency', 'bytes': len(data),
                 'sha256': hashlib.sha256(data).hexdigest()}
        def download(argv, *, stdout, check, timeout):
            self.assertIn('=https', argv)
            self.assertIn('--disable', argv)
            self.assertEqual(timeout, 125)
            stdout.write(data)
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(TOOL.subprocess, 'run', side_effect=download) as call:
            target = Path(tmp) / 'asset'
            TOOL.fetch(asset, target)
            self.assertEqual(target.read_bytes(), data)
            with self.assertRaises(FileExistsError): TOOL.fetch(asset, target)
            self.assertEqual(call.call_count, 1)
            for field, value in [('sha256', 'f' * 64), ('bytes', len(data) + 1)]:
                with self.assertRaises(ValueError): TOOL.fetch({**asset, field: value}, Path(tmp) / field)
            call.side_effect = subprocess.CalledProcessError(22, 'curl')
            with self.assertRaises(subprocess.CalledProcessError): TOOL.fetch(asset, Path(tmp) / 'failed')

    @staticmethod
    def archive(path, name, *, target=None, size=1):
        with tarfile.open(path, 'w:gz') as archive:
            row = tarfile.TarInfo(name)
            row.mode = 0o755
            if target is not None:
                row.type = tarfile.SYMTYPE
                row.linkname = target
                archive.addfile(row)
            else:
                row.size = size
                archive.addfile(row, io.BytesIO(b'x' * size))

    def test_safe_archive_preserves_executable_and_expected_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / 'source.tar.gz'
            self.archive(archive, 'source/configure')
            result = TOOL.unpack(archive, root / 'extracted', 'source')
            self.assertEqual((result / 'configure').read_bytes(), b'x')
            self.assertEqual((result / 'configure').stat().st_mode & 0o777, 0o755)

    def test_wrong_root_traversal_and_outside_link_refuse(self):
        for name, target in [('other/file', None), ('source/../../escaped', None),
                             ('source/link', '/outside'), ('source/link', '../../outside')]:
            with self.subTest(name=name, target=target), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                archive = root / 'source.tar.gz'
                self.archive(archive, name, target=target)
                with self.assertRaises((ValueError, tarfile.FilterError)):
                    TOOL.unpack(archive, root / 'extracted', 'source')
                self.assertFalse((root / 'escaped').exists())


if __name__ == '__main__':
    unittest.main()
