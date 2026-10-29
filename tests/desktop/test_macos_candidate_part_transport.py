"""Adversarial finite DATA archives with an inert attribute-query port.

The owner Mac attributes files created by this interpreter. Positive byte/FD
tests do not admit those attributes or claim hosted native transport success.
The real source attribute guard remains unmodified and is separately refused.
"""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
import sys
import unittest
from unittest.mock import patch
import zipfile

from desktop.tools import macos_candidate_part_transport as T
from tests.desktop.test_macos_candidate_parts import fixture


class CandidatePartTransportTests(unittest.TestCase):
    def setUp(self):
        parent = os.environ['MRK_PART_TEST_ROOT']
        self.temp = tempfile.TemporaryDirectory(dir=parent)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.work = self.root / 'mrk-macos-installed.ABC123de'; self.work.mkdir(mode=0o700)
        self.workspace = self.root / 'source'; self.workspace.mkdir(mode=0o700)
        self.attributes = patch.object(T.S, 'no_xattrs', return_value=None)
        self.attributes.start()
        self.addCleanup(self.attributes.stop)

    def archive(self, manifest=None, bodies=None):
        manifest = manifest or fixture()[0]
        bodies = bodies or {'work/runtime/manifest.json': b'inert\n'}
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_STORED) as out:
            out.writestr('PART.json', T.P.canonical(manifest))
            for row in manifest['members']:
                entry = zipfile.ZipInfo(row['path']); entry.create_system = 3
                entry.external_attr = (stat.S_IFREG | row['mode']) << 16
                out.writestr(entry, bodies[row['path']])
        return archive.getvalue()

    def saved(self, body, name='archive.zip'):
        path = self.root / name; T.write(path, body)
        return path

    def test_completed_bytes_are_freshly_admitted_with_original_modes_and_hashes(self):
        manifest = fixture()[0]
        path = self.saved(self.archive(manifest))
        self.assertEqual(T.archive_manifest(path), manifest)
        T.project_archive(path, manifest, self.work, self.workspace, {'work/runtime/manifest.json': 'prepare'})
        out = self.work / 'runtime/manifest.json'
        self.assertEqual(T.read(out, 6), b'inert\n')
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o444)
        self.assertEqual(out.stat().st_nlink, 1)
        with self.assertRaises(FileExistsError):
            T.project_archive(path, manifest, self.work, self.workspace, {'work/runtime/manifest.json': 'prepare'})

    def test_tampered_bytes_cannot_pass_even_when_skipped_for_a_later_signed_copy(self):
        manifest = fixture()[0]
        body = self.archive(manifest, {'work/runtime/manifest.json': b'wrong\n'})
        path = self.saved(body)
        for selected in ('prepare', 'later'):
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                T.project_archive(path, manifest, self.work, self.workspace, {'work/runtime/manifest.json': selected})
        self.assertFalse((self.work / 'part-dependencies.json').exists())

    def test_roster_refuses_credentials_foreign_outputs_and_mismatched_modes(self):
        for name in ('work/private.keychain-db', 'work/android-helper-sign-keychain.stdout',
                     'work/runtime/../credentials', 'work/app/private.p12'):
            manifest = fixture()[0]; manifest['members'][0]['path'] = name
            with self.subTest(name=name), self.assertRaises(ValueError):
                T.archive_manifest(self.saved(self.archive(manifest, {name: b'inert\n'}), str(len(name)) + '.zip'))
        manifest = fixture()[0]; body = bytearray(self.archive(manifest))
        start = body.index(b'PK\x01\x02', body.index(b'PK\x01\x02') + 4)
        struct.pack_into('<L', body, start + 38, (stat.S_IFREG | 0o755) << 16)
        with self.assertRaises(ValueError): T.archive_manifest(self.saved(bytes(body), 'mode.zip'))

    def test_local_headers_footer_spans_and_crc_are_all_independent_checks(self):
        body = self.archive()
        for name, change in (
            ('footer', lambda b: b.__setitem__(-1, 1)),
            ('prefix', lambda b: b.__setitem__(0, ord('X'))),
            ('local-crc', lambda b: b.__setitem__(14, b[14] ^ 1)),
            ('member-crc', lambda b: b.__setitem__(b.index(b'inert\n'), ord('X'))),
        ):
            damaged = bytearray(body); change(damaged)
            path = self.saved(bytes(damaged), name + '.zip')
            with self.subTest(name=name), self.assertRaises(ValueError):
                manifest = T.archive_manifest(path)
                T.project_archive(path, manifest, self.work, self.workspace, {'work/runtime/manifest.json': 'prepare'})

    def test_real_deflate_eof_crc_and_trailing_data_are_checked_before_copy_admission(self):
        body = b'fixed data\n' * 10000
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as out: out.writestr('PART.zip', body)
        raw = archive.getvalue()
        entries = T.archive_entries(io.BytesIO(raw), len(raw), maximum_members=1)
        out = io.BytesIO()
        self.assertEqual(T.stream_member(io.BytesIO(raw), entries['PART.zip'], len(body), out), hashlib.sha256(body).hexdigest())
        self.assertEqual(out.getvalue(), body)
        info, start = entries['PART.zip']
        for change in ('crc', 'short', 'tail', 'oversize'):
            wrong = copy.copy(info); stream = io.BytesIO(raw)
            if change == 'crc': wrong.CRC ^= 1
            elif change == 'short': wrong.compress_size -= 1
            elif change == 'tail': wrong.compress_size += 1
            else: wrong.file_size -= 1
            with self.subTest(change=change), self.assertRaises(ValueError):
                T.stream_member(stream, (wrong, start), len(body), io.BytesIO())

    def test_links_attributes_unknown_closes_and_changed_originals_never_publish_success(self):
        path = self.saved(b'fixed\n', 'original')
        alias = self.root / 'alias'; os.link(path, alias)
        with self.assertRaises(ValueError): T.read(path, 6)
        alias.unlink()
        link = self.root / 'link'; link.symlink_to(path)
        with self.assertRaises((ValueError, OSError)): T.read(link, 6)
        with patch.object(T.S, 'no_xattrs', side_effect=ValueError('inert-attribute-refusal')):
            with self.assertRaises(ValueError): T.read(path, 6)
        actual_close = T.S.close_once
        def refused_close(fd):
            actual_close(fd)
            raise ValueError('inert-close-refusal')
        with patch.object(T.S, 'close_once', side_effect=refused_close):
            with self.assertRaises(ValueError): T.read(path, 6)
        with self.assertRaises(ValueError):
            with T.original(path, 6):
                with path.open('ab') as changed: changed.write(b'x')
        # The preceding context itself must reject the changed held original.

    def test_export_selects_only_completed_output_roster_and_no_compiler_cache(self):
        runtime = self.work / 'runtime'; runtime.mkdir(mode=0o700)
        T.write(runtime / 'manifest.json', b'inert\n', 0o444)
        T.write(self.work / 'runtime-binding.json', b'{}\n', 0o444)
        capsule = self.work / 'signed-python-capsule'; capsule.mkdir(mode=0o700)
        T.write(capsule / 'python-signed-receipt.json', b'{}\n')
        android = self.work / 'signed-android-transport'; android.mkdir(mode=0o700)
        T.write(android / 'receipt.json', b'{}\n')
        T.write(self.work / 'unrelated-keychain-secret', b'inert private bytes')
        compiler = self.work / 'cargo-target'; compiler.mkdir(mode=0o700)
        T.write(compiler / 'opaque-cache', b'compiler cache')
        files, dirs = T.selected_files('prepare', self.work, self.workspace)
        self.assertEqual(set(files), {'work/runtime/manifest.json','work/runtime-binding.json',
            'work/signed-python-capsule/python-signed-receipt.json','work/signed-android-transport/receipt.json'})
        self.assertFalse(any('cargo-target' in n or 'secret' in n for n in files))
        manifest = fixture()[0]; manifest['members'] = [files[n] for n in sorted(files)]
        manifest['directories'] = [dict(path=n, mode=m) for n,m in sorted(dirs.items())]
        path = self.root / 'export.zip'
        T.encode_archive(path, manifest, files, self.work, self.workspace)
        self.assertEqual(T.archive_manifest(path), manifest)

    def test_failed_or_unclosed_owner_receipt_is_not_reusable(self):
        origin = fixture('sign-cli')[0]['origin']
        row = dict(phase='sign-installed-cli', source=origin['source'], workflowSource=origin['source'],
                   runId=origin['runId'], runAttempt=origin['runAttempt'], target=T.P.TARGET,
                   passed=True,targetRetired=True,originalClosesKnown=True)
        path = self.work / 'android-helper-sign-installed-cli.json'
        T.write(path, json.dumps(row).encode())
        T.receipt_checks('sign-cli', self.work, origin)
        for key,value in [('passed',False),('targetRetired',False),('originalClosesKnown',False),
                          ('runAttempt','2'),('source','3'*40)]:
            path.unlink(); wrong=dict(row,**{key:value});T.write(path,json.dumps(wrong).encode())
            with self.subTest(key=key), self.assertRaises(ValueError): T.receipt_checks('sign-cli', self.work, origin)

    @unittest.skipUnless(os.environ.get('GITHUB_ACTIONS') == 'true' and sys.platform == 'darwin',
                         'actual hosted attribute admission is separate from inert local DATA tests')
    def test_actual_hosted_archive_roundtrip_keeps_the_original_attribute_policy(self):
        self.attributes.stop()
        manifest = fixture()[0]
        path = self.saved(self.archive(manifest))
        self.assertEqual(T.archive_manifest(path), manifest)
        T.project_archive(path, manifest, self.work, self.workspace, {'work/runtime/manifest.json':'prepare'})
        self.assertEqual(T.read(self.work / 'runtime/manifest.json',6), b'inert\n')


if __name__ == '__main__': unittest.main()
