"""Finite original-source tests; no installed files, native grants or product build."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class CanonicalBundleMetadataTests(unittest.TestCase):
    def test_original_book_policy_and_close(self):
        original = (ROOT / 'desktop/src-tauri/src/installed_runtime_macos.rs').read_text()
        body = (ROOT / 'tests/desktop/fixtures/canonical_bundle_metadata_data.rs').read_text()
        for marker, start, end in (
            ('BOOK_POLICY', '    fn check_identity_with(', '    fn chain('),
            ('BOOK_CLOSE', '    fn close(&mut self, index:', '    fn walk('),
            ('SERVICE_MODE', '    fn mode(book:', '    fn fixed_payload('),
        ):
            first = original.index(start)
            last = original.index(end, first)
            token = '/* MRK_' + marker + '_ORIGINAL */'
            self.assertEqual(body.count(token), 1)
            body = body.replace(token, original[first:last])
        compiler = shutil.which('rustc')
        self.assertIsNotNone(compiler, 'use the existing compiler; download nothing')
        with tempfile.TemporaryDirectory(dir=os.environ.get('MRK_PART_TEST_ROOT')) as temporary:
            source = Path(temporary) / 'original-data.rs'
            binary = Path(temporary) / 'original-data'
            source.write_text(body)
            compiled = subprocess.run([compiler, '--edition=2021', str(source), '-o', str(binary)],
                                      capture_output=True, text=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'MRK_CANONICAL_BUNDLE_METADATA_DATA=PASS\n')
        self.assertEqual(result.stderr, '')

    def test_consumers_keep_role_and_source_boundaries(self):
        runtime = (ROOT / 'desktop/src-tauri/src/installed_runtime_macos.rs').read_text()
        observer = (ROOT / 'desktop/src-tauri/src/installation_observation_macos.rs').read_text()
        installer = (ROOT / 'desktop/src-tauri/src/bin/macos_install.rs').read_text()
        protected = observer[observer.index('    fn protected('):observer.index('    fn open(')]
        self.assertIn('book.installed_attributes(index,end,stop)?;', protected)
        for field in ('id.uid != 0', 'id.gid != 0', 'id.mode & 0o7777 != mode', 'id.flags != 0'):
            self.assertIn(field, protected)
        fixed = runtime[runtime.index('    fn protected_app_once('):runtime.index('    fn inspect(&mut self, selection:')]
        for role in ('entry', 'payload'):
            self.assertIn(f'self.installed_attributes({role},end,stop)?;', fixed)
        self.assertIn('native::no_xattrs(self.fd(binary)?.as_fd())', fixed)
        producer = installer[installer.index('        impl ProducerAdmission {'):installer.index('        struct RemovalOriginals {')]
        self.assertIn('native::no_xattrs(book.fd(original)?.as_fd())', producer)
        removal = installer[installer.index('        impl RemovalAdmission {'):installer.index('            fn inspect(&mut self, book: &Install)', installer.index('        impl RemovalAdmission {'))]
        self.assertIn('if matches!(slot,4|7)', removal)
        self.assertIn('book.capture_existing_app_metadata(code[slot],true,', removal)
        self.assertIn('native::no_xattrs(book.fd(code[slot])?.as_fd())', removal)
        inspect = installer[installer.index('            fn inspect(&mut self, book: &Install)', installer.index('        impl RemovalAdmission {')):]
        for check in ('removal-package-signature', 'removal-installed-signature', 'removal-source-binding',
                      'removal-entry-purpose', 'removal-payload-purpose', 'removal-program-purpose'):
            self.assertIn(check, inspect)
        self.assertIn('for n in self.code { book.check_name(n,true)?; }', installer)
        self.assertIn('self.close(index,&mut |book|expired(book.first_failure()))', runtime)
        android = (ROOT / 'desktop/src-tauri/src/android_runtime_macos.rs').read_text()
        self.assertIn('self.close(index,&mut |book|fd_cleanup_expired_at(end,cleanup,', android)
        self.assertIn('book.android_first_failure().map(|(_,at)|at),Instant::now()))', android)
        # These are executable leaves and the installation infrastructure gate.
        helper = (ROOT / 'desktop/native/macos-installed-native/src/vault_helper_filesystem.rs').read_text()
        self.assertIn('if matches!(i,APP|HELPER){crate::no_xattrs(self.fd(i)?)', helper)
        gate = (ROOT / 'desktop/native/macos-installed-entry/gate.c').read_text()
        self.assertIn('return (!leaf && !product) || mrk_no_xattrs(fd) == 0;', gate)


if __name__ == '__main__':
    unittest.main()
