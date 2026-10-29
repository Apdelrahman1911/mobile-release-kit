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
from types import SimpleNamespace
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

    def prepare_fixture(self):
        runtime = self.work / 'runtime'; runtime.mkdir(mode=0o700)
        T.write(runtime / 'manifest.json', b'inert\n', 0o444)
        T.write(self.work / 'runtime-binding.json', b'{}\n', 0o444)
        capsule = self.work / 'signed-python-capsule'; capsule.mkdir(mode=0o700)
        T.write(capsule / 'python-signed-receipt.json', b'{}\n')
        android = self.work / 'signed-android-transport'; android.mkdir(mode=0o700)
        T.write(android / 'receipt.json', b'{}\n')
        return runtime

    def signed_app_fixture(self):
        origin = fixture('assemble')[0]['origin']
        bodies = {T.S.ENTRY_BINARY: b'inert signed entry\n', T.S.APP_BINARY: b'inert signed payload\n'}
        for name, body in bodies.items():
            path = self.work / 'app' / T.S.APP_NAME / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            T.write(path, body, 0o555)
        T.write(self.work / 'app-result.json', b'{}\n', 0o444)
        receipts = {}
        for phase in T.RECEIPTS['assemble']:
            row = dict(phase=phase, source=origin['source'], workflowSource=origin['source'],
                       runId=origin['runId'], runAttempt=origin['runAttempt'], target=T.P.TARGET,
                       passed=True, targetRetired=True, originalClosesKnown=True)
            if phase in ('sign-root-app', 'sign-desktop-payload'):
                leaf = T.S.ENTRY_BINARY if phase == 'sign-root-app' else T.S.APP_BINARY
                row['signedBytesSha256'] = T.P.sha(bodies[leaf])
            receipts[phase] = row
            T.write(self.work / ('android-helper-' + phase + '.json'), T.P.canonical(row), 0o444)
        return origin, bodies, receipts

    def test_signed_app_hashes_survive_archive_and_fresh_projection(self):
        origin, bodies, _ = self.signed_app_fixture()
        files, dirs = T.selected_files('assemble', self.work, self.workspace)
        manifest = fixture('assemble')[0]
        manifest['members'] = [files[n] for n in sorted(files)]
        manifest['directories'] = [dict(path=n, mode=m) for n, m in sorted(dirs.items())]
        path = self.root / 'signed-app.zip'
        T.encode_archive(path, manifest, files, self.work, self.workspace)
        self.assertEqual(T.archive_manifest(path), manifest)
        parent = self.root / 'fresh-signed-owner'; parent.mkdir(mode=0o700)
        fresh = parent / self.work.name; fresh.mkdir(mode=0o700)
        T.project_archive(path, manifest, fresh, self.workspace, {n: 'assemble' for n in files})
        values = T.signed_app_bindings(fresh, origin)
        self.assertEqual(values, {'MRK_MACOS_SIGNED_ENTRY_SHA256': T.P.sha(bodies[T.S.ENTRY_BINARY]),
                                 'MRK_MACOS_SIGNED_PAYLOAD_SHA256': T.P.sha(bodies[T.S.APP_BINARY])})
        self.assertFalse(manifest['nativeAuthority'] or manifest['installed'] or manifest['productReady'])

    def test_signed_hash_data_requires_same_original_receipts_and_fresh_bytes(self):
        origin, bodies, receipts = self.signed_app_fixture()
        for name, body in bodies.items():
            path = self.work / 'app' / T.S.APP_NAME / name
            path.unlink(); T.write(path, b'changed signed bytes\n', 0o555)
            with self.subTest(leaf=name), self.assertRaisesRegex(ValueError, '^part-signed-app-correspondence$'):
                T.signed_app_bindings(self.work, origin)
            with patch.object(T, 'current', return_value=origin), \
                 self.assertRaisesRegex(ValueError, '^part-signed-app-correspondence$'):
                T.freeze('assemble', self.work, self.workspace)
            path.unlink(); T.write(path, body, 0o555)
        path = self.work / 'android-helper-sign-root-app.json'
        for key, value in (('passed', False), ('originalClosesKnown', False), ('targetRetired', False),
                           ('runAttempt', '9'), ('source', '3' * 40)):
            wrong = dict(receipts['sign-root-app'], **{key: value})
            path.unlink(); T.write(path, T.P.canonical(wrong), 0o444)
            with self.subTest(field=key), self.assertRaisesRegex(ValueError, '^part-original-owner-completion$'):
                T.signed_app_bindings(self.work, origin)
        path.unlink(); T.write(path, T.P.canonical(receipts['sign-root-app']), 0o444)
        binary = self.work / 'app' / T.S.APP_NAME / T.S.ENTRY_BINARY
        binary.chmod(0o444)
        with self.assertRaisesRegex(ValueError, '^part-signed-app-correspondence$'):
            T.signed_app_bindings(self.work, origin)

    def test_original_notary_first_signature_predicate_keeps_missing_or_wrong_hashes_strict(self):
        # Execute the unchanged original consumer through its first signed-byte
        # predicate using inert DATA ports, stopping before further parsing.
        # This is not a complete original input/notary/native qualification.
        origin, bodies, _ = self.signed_app_fixture()
        values = T.signed_app_bindings(self.work, origin)
        S = T.S
        names = {S.ENTRY_BINARY, S.APP_BINARY, S.VAULT_HELPER, S.ANDROID_HELPER, S.ANDROID_SERVICE_PLIST,
                 S.RESIDENT_IMAGE, S.REMOVER, S.INSTALLED_CLI, 'Contents/Info.plist', S.PAYLOAD_INFO,
                 'Contents/PkgInfo', S.PAYLOAD_CONTENTS + 'PkgInfo', 'Contents/Resources/icon.png',
                 S.PAYLOAD_CONTENTS + 'Resources/icon.png', 'Contents/_CodeSignature/CodeResources',
                 S.PAYLOAD_CONTENTS + '_CodeSignature/CodeResources'}
        app = {name: (b'inert\n', 0o555) for name in names}
        app.update({name: (body, 0o555) for name, body in bodies.items()})
        app['Contents/Info.plist'] = (b'inert entry info', 0o644)
        app[S.PAYLOAD_INFO] = (b'inert payload info', 0o644)
        args = SimpleNamespace(target=T.P.TARGET, package_role='installed-shell-observation', current_runtime=True,
                               expected_resident_image='1' * 64, expected_android_helper='2' * 64,
                               runtime=self.work / 'runtime', expected_manifest='3' * 64, app=self.work / 'app')
        class OriginalPredicatePassed(Exception): pass
        with patch.object(S, 'command_target', return_value=T.P.TARGET), \
             patch.object(S, 'source_build_selection', return_value=None), \
             patch.object(S, 'runtime_tree', return_value={}), patch.object(S, 'tree', return_value=app), \
             patch.object(S, 'android_support_manifest', return_value=('4' * 64, [])), \
             patch.object(S, 'source_entry_info', return_value=b'inert entry info'), \
             patch.object(S, 'source_app_info', return_value=b'inert payload info'), \
             patch.object(S, 'applications_launcher_files', return_value={}), \
             patch.object(S, 'ticket_input_names', return_value=set()), \
             patch.object(S, 'entry_macho', side_effect=OriginalPredicatePassed):
            entry, payload = values['MRK_MACOS_SIGNED_ENTRY_SHA256'], values['MRK_MACOS_SIGNED_PAYLOAD_SHA256']
            for pair in ((None, None), (None, payload), (entry, None), ('5' * 64, payload), (entry, '6' * 64)):
                args.expected_entry, args.expected_app_binary = pair
                with self.subTest(pair=pair), self.assertRaisesRegex(S.Refused, '^final-entry-payload-signature-bytes-changed$'):
                    S.input_with_github_seal(args, {})
            args.expected_entry, args.expected_app_binary = entry, payload
            with self.assertRaises(OriginalPredicatePassed):
                S.input_with_github_seal(args, {})

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

    def test_actual_service_streamed_descriptor_matches_central_and_payload_crc(self):
        class Unseekable(io.BytesIO):
            def seekable(self): return False
            def seek(self,*args): raise OSError('inert nonseekable service writer')
        body=b'fixed inert part bytes\n'*100
        for codec in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED):
            archive=Unseekable()
            with zipfile.ZipFile(archive,'w',compression=codec) as out:
                out.writestr('PART.zip',body)
            raw=archive.getvalue()
            self.assertEqual(struct.unpack_from('<H',raw,6)[0],8)
            self.assertEqual(raw[14:26],b'\0'*12)
            with self.assertRaises(ValueError):
                T.archive_entries(io.BytesIO(raw),len(raw),maximum_members=1)
            entries=T.archive_entries(io.BytesIO(raw),len(raw),maximum_members=1,service_descriptor=True)
            out=io.BytesIO()
            self.assertEqual(T.stream_member(io.BytesIO(raw),entries['PART.zip'],len(body),out),hashlib.sha256(body).hexdigest())
            self.assertEqual(out.getvalue(),body)
            descriptor=raw.index(b'PK\x07\x08')
            for field in (0,4,8,12):
                bad=bytearray(raw);bad[descriptor+field]^=1
                with self.subTest(codec=codec,field=field),self.assertRaises(ValueError):
                    T.archive_entries(io.BytesIO(bad),len(bad),maximum_members=1,service_descriptor=True)
            bad=bytearray(raw);bad[14]=1
            with self.assertRaises(ValueError):
                T.archive_entries(io.BytesIO(bad),len(bad),maximum_members=1,service_descriptor=True)
            info,start=entries['PART.zip'];bad=bytearray(raw);bad[start]^=1
            with self.assertRaises((ValueError,__import__('zlib').error)):
                T.stream_member(io.BytesIO(bad),entries['PART.zip'],len(body),io.BytesIO())

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
        self.prepare_fixture()
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

    def test_original_history_receipt_survives_export_and_fresh_projection(self):
        runtime = self.prepare_fixture()
        tools = runtime / 'tools'; tools.mkdir(mode=0o700)
        T.write(tools / 'gh', b'inert tool bytes\n', 0o555)
        capsule = self.work / 'history-provider-capsule'; capsule.mkdir(mode=0o700)
        receipt = b'{"inert":"original receipt bytes, never signing authority"}\n'
        T.write(capsule / 'tool-signed-receipt.json', receipt, 0o444)
        T.write(capsule / 'unrelated-output', b'not a selected output\n')
        files, dirs = T.selected_files('prepare', self.work, self.workspace)
        self.assertIn(T.HISTORY_RECEIPT, files)
        self.assertNotIn('work/history-provider-capsule/unrelated-output', files)
        manifest = fixture()[0]
        manifest['members'] = [files[n] for n in sorted(files)]
        manifest['directories'] = [dict(path=n, mode=m) for n,m in sorted(dirs.items())]
        path = self.root / 'history-export.zip'
        T.encode_archive(path, manifest, files, self.work, self.workspace)
        self.assertEqual(T.archive_manifest(path), manifest)
        parent = self.root / 'fresh-owner'; parent.mkdir(mode=0o700)
        fresh = parent / self.work.name; fresh.mkdir(mode=0o700)
        T.project_archive(path, manifest, fresh, self.workspace, {n: 'prepare' for n in files})
        self.assertEqual(T.read(fresh / 'history-provider-capsule/tool-signed-receipt.json', 4096), receipt)
        self.assertEqual(T.read(fresh / 'runtime/tools/gh', 4096), b'inert tool bytes\n')
        self.assertEqual(stat.S_IMODE((fresh / 'history-provider-capsule/tool-signed-receipt.json').stat().st_mode), 0o444)
        self.assertFalse(manifest['nativeAuthority'] or manifest['installed'] or manifest['productReady'])

    def test_missing_history_tool_receipt_pair_refuses_during_preparation(self):
        runtime = self.prepare_fixture()
        tools = runtime / 'tools'; tools.mkdir(mode=0o700)
        T.write(tools / 'gh', b'inert tool bytes\n', 0o555)
        with self.assertRaisesRegex(ValueError, '^part-history-capsule-pair$'):
            T.selected_files('prepare', self.work, self.workspace)
        (tools / 'gh').unlink()
        capsule = self.work / 'history-provider-capsule'; capsule.mkdir(mode=0o700)
        T.write(capsule / 'tool-signed-receipt.json', b'inert receipt\n', 0o444)
        with self.assertRaisesRegex(ValueError, '^part-history-capsule-pair$'):
            T.selected_files('prepare', self.work, self.workspace)

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
