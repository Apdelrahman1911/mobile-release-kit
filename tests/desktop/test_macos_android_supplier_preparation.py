"""DATA-only supplier-preparation regressions; no vendor/network/native run.

Only synthetic ZIP/HTTP metadata and task-owned temporary DATA are exercised.
These tests cannot produce supplier provenance or macOS execution evidence.
"""
from __future__ import annotations

from email.message import Message
import http.client
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import zipfile

_SOURCE = Path(__file__).resolve().parents[2] / "desktop/tools/macos_android_supplier_preparation.py"
_SPEC = importlib.util.spec_from_file_location("mrk_supplier_preparation_data", _SOURCE)
M = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(M)  # Definitions only; main is not run.


def member(name, size=1, mode=stat.S_IFREG | 0o644):
    info = zipfile.ZipInfo(name)
    info.external_attr = mode << 16
    info.file_size = size
    return info


def valid_gradle():
    return [member("gradle-8.14.5/bin/gradle"), member("gradle-8.14.5/lib/gradle-launcher-8.14.5.jar")]


class SupplierPreparationPureDataTests(unittest.TestCase):
    def test_fixed_source_table_has_no_arbitrary_or_response_selected_url(self):
        self.assertEqual(set(M.SOURCES), {"agp-pom", "agp-module", "aapt2-sha256", "aapt2-osx", "gradle", "bundletool", "sdk-repository"})
        self.assertEqual(M.fixed_source("aapt2-osx")[0], "https://dl.google.com/dl/android/maven2/com/android/tools/build/aapt2/8.9.2-12782657/aapt2-8.9.2-12782657-osx.jar")
        with self.assertRaises(M.Refused):
            M.fixed_source("https://example.invalid/arbitrary")
        self.assertEqual(M.checksum(b"A" * 64 + b"\n"), "a" * 64)
        for value in (b"a" * 40, b"a" * 64 + b" file.jar", b"a" * 64 + b"\nextra"):
            with self.subTest(value=value), self.assertRaises(M.Refused):
                M.checksum(value)

    def test_redirect_is_one_exact_https_asset_not_a_new_download_interface(self):
        good = "https://release-assets.githubusercontent.com/github-production-release-asset/123/01234567-89ab-cdef-0123-456789abcdef?fixture=public"
        self.assertEqual(M.release_redirect(good), good)
        for value in (None, "http" + good[5:], good.replace(".com/", ".com.evil/"),
                      good.replace(".com/", ".com:443/"), good.replace("https://", "https://user@"),
                      good + "#fragment", good.split("?")[0], good + "\n", "file:///tmp/body"):
            with self.subTest(value=value), self.assertRaises(M.Refused):
                M.release_redirect(value)

    def test_archive_roster_rejects_alias_traversal_case_and_parent_collisions(self):
        picked, total, count = M.zip_members(valid_gradle(), "gradle")
        self.assertEqual((len(picked), total, count), (2, 2, 2))
        extras = [member("../outside"), member("/outside"), member("gradle-8.14.5/lib/../outside"),
                  member("gradle-8.14.5/lib/a\\b"), member("gradle-8.14.5/lib/a:b"),
                  member("gradle-8.14.5/lib/alias", mode=stat.S_IFLNK | 0o777),
                  member("gradle-8.14.5/lib/pipe", mode=stat.S_IFIFO | 0o600),
                  member("gradle-8.14.5/lib/suid", mode=stat.S_IFREG | 0o4755),
                  member("gradle-8.14.5/bin/gradle"), member("gradle-8.14.5/BIN/other"),
                  member("gradle-8.14.5/lib"), member("gradle-8.14.5/lib/bad\0hidden")]
        for extra in extras:
            with self.subTest(name=extra.orig_filename), self.assertRaises(M.Refused):
                M.zip_members(valid_gradle() + [extra], "gradle")
        with self.assertRaises(M.Refused):
            M.zip_members([member("other/bin/gradle")], "gradle")
        with self.assertRaises(M.Refused):
            M.zip_members([member("aapt2", M.FILE_LIMIT + 1)], "aapt2")
        with self.assertRaises(M.Refused):
            M.zip_members([member("aapt2"), member("AAPT2")], "aapt2")

    def test_all_seven_selections_must_have_real_attempts_and_nonempty_result(self):
        roster = {key: None for key in M.INPUTS}
        attempts = {key: {"status": "refused"} for key in M.INPUTS}
        with self.assertRaises(M.Refused):
            M.roster_bytes(roster, attempts)
        roster["jdkHome"] = "/fixture/jdk"
        attempts["jdkHome"] = {"status": "selected"}
        self.assertEqual(json.loads(M.roster_bytes(roster, attempts)), roster)
        for status in ("not-attempted", "attempted", "selected"):
            broken = {key: dict(row) for key, row in attempts.items()}
            broken["agpAapt2"]["status"] = status
            with self.subTest(status=status), self.assertRaises(M.Refused):
                M.roster_bytes(roster, broken)
        with self.assertRaises(M.Refused):
            M.roster_bytes({**roster, "extra": None}, attempts)

    def test_transfer_framing_rejects_ambiguous_duplicate_and_unsupported_encoding(self):
        for headers in ([('Transfer-Encoding', 'chunked'), ('Content-Length', '7')],
                        [('Transfer-Encoding', 'chunked'), ('Transfer-Encoding', 'chunked')],
                        [('Transfer-Encoding', 'gzip')], [('Transfer-Encoding', 'gzip, chunked')]):
            response = FakeResponse(headers=headers)
            with self.subTest(headers=headers), self.assertRaises(M.Refused):
                M.response_headers(response)
        for headers in ([], [('Content-Length', '7')], [('Transfer-Encoding', 'chunked')]):
            self.assertIsInstance(M.response_headers(FakeResponse(headers=headers)), dict)

    def test_original_endpoint_covers_serialization_and_every_stdout_return(self):
        for phase in ('serialization', 'partial-write', 'complete-write', 'write-error', 'timely'):
            budget = M.Budget()
            budget.end = 600
            clock = [599.0]
            writes = []
            def encode(value):
                if phase == 'serialization':
                    clock[0] = 600.0
                return b'{"status":"prepared"}\n'
            def write(fd, data):
                writes.append((fd, bytes(data)))
                if phase == 'write-error':
                    raise OSError('synthetic returned-output uncertainty')
                if phase != 'timely':
                    clock[0] = 600.0
                return 1 if phase == 'partial-write' else len(data)
            with self.subTest(phase=phase), mock.patch.object(M.time, 'monotonic', side_effect=lambda: clock[0]), \
                 mock.patch.object(M, 'canonical', side_effect=encode), mock.patch.object(M.os, 'write', side_effect=write):
                status = M.emit_report(budget, {}, 0)
            self.assertEqual(status, 0 if phase == 'timely' else 79 if phase == 'write-error' else 78)
            self.assertEqual(len(writes), 0 if phase == 'serialization' else 1)
            self.assertEqual(budget.end, 600)  # No replacement allowance.

    def test_descriptor_soft_limit_never_increases_a_tighter_limit_or_changes_hard(self):
        # Mock the documented resource module; no actual process limit changes.
        for before, target in (((256, 1024), 128), ((64, 1024), 64), ((-1, -1), 128)):
            stub = mock.Mock(RLIMIT_NOFILE=7, RLIM_INFINITY=-1)
            stub.getrlimit.side_effect = [before, (target, before[1])]
            with self.subTest(before=before), mock.patch.dict(M.sys.modules, {"resource": stub}):
                row = M.process_descriptor_bound()
            self.assertEqual(row["soft"], target)
            self.assertEqual(row["hard"], before[1])
            if target == before[0]:
                stub.setrlimit.assert_not_called()
            else:
                stub.setrlimit.assert_called_once_with(7, (target, before[1]))
        stub = mock.Mock(RLIMIT_NOFILE=7, RLIM_INFINITY=-1)
        stub.getrlimit.side_effect = [(256, 1024), (256, 1024)]
        with mock.patch.dict(M.sys.modules, {"resource": stub}), self.assertRaises(M.Refused):
            M.process_descriptor_bound()

    def test_sdk_catalog_keeps_published_algorithm_and_does_not_acquire_payload(self):
        def package(name, version, host):
            return f'<remotePackage path="{name}"><revision><major>{version}</major></revision><archives><archive>{host}<complete><size>1024</size><checksum type="sha1">{"a" * 40}</checksum><url>fixture.zip</url></complete></archive></archives></remotePackage>'
        raw = ('<repository>' + package('platforms;android-35', 2, '')
               + package('build-tools;35.0.0', 35, '<host-os>macosx</host-os>') + '</repository>').encode()
        result = M.sdk_packages(raw)
        self.assertEqual(set(result), {'platforms;android-35', 'build-tools;35.0.0'})
        row = result['build-tools;35.0.0']['archives'][0]
        self.assertEqual(row['publishedChecksumAlgorithm'], 'sha1')
        self.assertFalse(row['payloadAcquired'])
        self.assertFalse(row['installedCorrespondenceVerified'])
        for bad in (raw.replace(b'<major>35</major>', b'<major>35</major><major>35</major>'),
                    raw.replace(b'<major>35</major>', b'<major>35</major><preview>1</preview>'),
                    raw.replace(b'fixture.zip', b'../fixture.zip'), b'<!DOCTYPE x>' + raw):
            with self.subTest(value=bad[:64]), self.assertRaises(M.Refused):
                M.sdk_packages(bad)


class FakeResponse:
    def __init__(self, body=b"", code=200, headers=(), *, fail_close=False):
        self.code = code
        self.headers = Message()
        for key, value in headers:
            self.headers[key] = value
        self.body = io.BytesIO(body)
        self.close_calls = 0
        self.fail_close = fail_close

    def read(self, amount):
        return self.body.read(amount)

    def close(self):
        self.close_calls += 1
        self.body.close()
        if self.fail_close:
            raise OSError("synthetic returned-close uncertainty")


@unittest.skipUnless(os.name == 'posix' and all(hasattr(os, name) for name in
    ('O_NOFOLLOW', 'O_DIRECTORY', 'O_CLOEXEC', 'pread', 'getuid')), 'POSIX task-owned DATA fixture primitives required')
class SupplierPreparationOwnedDataTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mrk-supplier-data-")
        self.base = Path(self.temporary.name).resolve(strict=True)
        self.path = self.base / 'owned'
        self.path.mkdir(mode=0o700)
        self.budget = M.Budget()
        self.files = M.PrivateFiles(self.budget, str(self.path))

    def tearDown(self):
        try:
            self.files.close()
        finally:
            self.temporary.cleanup()
        self.assertEqual(self.budget.fds, 0)

    def downloads(self, responses):
        value = object.__new__(M.Downloads)
        value.budget, value.files, value.records = self.budget, self.files, []
        value.calls = []
        def response(url):
            value.calls.append(url)
            return responses[len(value.calls) - 1]
        value.response = response  # Inert HTTP DATA; no opener, CA or network.
        return value

    def test_valid_body_is_read_back_and_refused_body_is_accounted_not_selected(self):
        body = b'synthetic public fixture data'
        good = FakeResponse(body, headers=[('Content-Length', str(len(body)))])
        download = self.downloads([good])
        row = download.get('aapt2-osx', published_sha=hashlib.sha256(body).hexdigest())
        self.assertEqual(self.files.read(row, 1024), body)
        self.assertEqual(good.close_calls, 1)
        self.assertEqual(download.records[0]['authenticationTier'], 'official-https-and-published-sha256')
        self.files.check()

    def test_partial_read_exception_charges_full_allowance_without_claiming_observed_bytes(self):
        response = FakeResponse()
        def partial_read(amount):
            raise http.client.IncompleteRead(b'partially consumed but not returned', amount)
        response.read = partial_read
        download = self.downloads([response])
        with self.assertRaises(M.Refused):
            download.get('aapt2-osx', published_sha='0' * 64)
        self.assertEqual(self.budget.download_bytes, M.CHUNK)
        self.assertEqual(self.budget.download_observed_bytes, 0)
        self.assertEqual(self.budget.download_unknown_reads, 1)
        self.assertTrue(download.records[0]['readOutcomeUnknown'])
        self.assertEqual(download.records[0]['status'], 'refused')
        self.assertEqual(response.close_calls, 1)
        row = next(row for row in self.files.rows if row['kind'] == 'file')
        self.assertEqual(row['bytes'], 0)
        self.assertEqual(row['selectionUse'], 'refused-data-only')
        self.files.check()

    def test_mismatched_download_retains_exact_owned_partial_without_success(self):
        response = FakeResponse(b'not the declared supplier')
        download = self.downloads([response])
        with self.assertRaises(M.Refused):
            download.get('aapt2-osx', published_sha='0' * 64)
        self.assertEqual(download.records[0]['status'], 'refused')
        row = next(row for row in self.files.rows if row['kind'] == 'file')
        self.assertTrue(row['complete'])  # Exact persisted bytes, NOT supplier acceptance.
        self.assertEqual(row['selectionUse'], 'refused-data-only')
        self.assertEqual(response.close_calls, 1)
        self.files.check()

    def test_foreign_redirect_never_starts_second_request_or_creates_body(self):
        response = FakeResponse(code=302, headers=[('Location', 'https://example.invalid/foreign')])
        download = self.downloads([response])
        with self.assertRaises(M.Refused):
            download.get('gradle')
        self.assertEqual(len(download.calls), 1)
        self.assertEqual(response.close_calls, 1)
        self.assertEqual(self.files.rows, [])

    def test_original_close_uncertainty_latches_before_any_later_operation(self):
        response = FakeResponse(b'fixture', fail_close=True)
        download = self.downloads([response])
        download.get('aapt2-osx', published_sha=hashlib.sha256(b'fixture').hexdigest())
        self.assertEqual(response.close_calls, 1)
        with self.assertRaises(M.CleanupUnknown):
            self.budget.point()
        with self.assertRaises(M.CleanupUnknown):
            self.files.put('must-not-exist', b'x')
        self.assertFalse((self.path / 'must-not-exist').exists())

    def test_exclusive_outputs_do_not_overwrite_and_sync_uncertainty_is_not_retried(self):
        row = self.files.put('fixed', b'first')
        with self.assertRaises(FileExistsError):
            self.files.put('fixed', b'second')
        self.assertEqual(self.files.read(row, 1024), b'first')
        token = self.files.create('sync-failure')
        self.files.write(token, b'kept')
        actual_fsync = os.fsync
        calls = []
        def uncertain(fd):
            calls.append(fd)
            actual_fsync(fd)
            raise OSError('synthetic returned-sync uncertainty')
        with mock.patch.object(M.os, 'fsync', side_effect=uncertain):
            with self.assertRaises(M.CleanupUnknown):
                self.files.finish(token)
        self.assertEqual(calls, [token['fd']])
        with self.assertRaises(M.CleanupUnknown):
            self.files.account_refused(token)
        self.files.close_token(token)

    def test_authenticated_zip_data_extracts_private_modes_and_preserves_archive_modes(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w') as archive:
            for name, body, mode in (
                ('gradle-8.14.5/bin/gradle', b'not an executable fixture', stat.S_IFREG | 0o755),
                ('gradle-8.14.5/lib/gradle-launcher-8.14.5.jar', b'not an executable jar', stat.S_IFREG | 0o644)):
                info = member(name, mode=mode)
                archive.writestr(info, body)
        row = self.files.put('bodies/synthetic-archive', data.getvalue())
        M.extract(self.budget, self.files, row, 'gradle')
        target = self.path / 'fixtures/gradle-8.14.5/bin/gradle'
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        selected = next(item for item in self.files.rows if item['path'].endswith('/bin/gradle'))
        self.assertEqual(selected['archiveMember']['mode'], stat.S_IFREG | 0o755)
        self.assertEqual(selected['archiveMember']['archiveSha256'], row['sha256'])
        self.files.check()

    def test_actual_input_metadata_uses_only_explicit_originals_and_preserves_sources(self):
        jdk = self.base / 'fixture-jdk'
        jdk.mkdir(mode=0o700)
        body = b'JAVA_VERSION="17.0.99"\nIMPLEMENTOR="SyntheticVendor"\nOS_ARCH="aarch64"\n'
        (jdk / 'release').write_bytes(body)
        selected, values = M.local_selection(self.budget, {'JAVA_HOME_17_arm64': str(jdk), 'PATH': '/unrelated'}, 'jdkHome')
        self.assertEqual(selected, str(jdk))
        self.assertEqual(values['IMPLEMENTOR'], 'SyntheticVendor')
        self.assertEqual((jdk / 'release').read_bytes(), body)
        with self.assertRaises(M.Refused):
            M.local_selection(self.budget, {'JAVA_HOME': str(jdk)}, 'jdkHome')
        (jdk / 'release').write_bytes(body.replace(b'17.0.99', b'21.0.1'))
        with self.assertRaises(M.Refused):
            M.local_selection(self.budget, {'JAVA_HOME_17_arm64': str(jdk)}, 'jdkHome')

    def test_namespace_postcheck_refuses_unexpected_data_without_deleting_it(self):
        self.files.put('expected', b'owned')
        extra = self.path / 'unexpected'
        extra.write_bytes(b'preserve this original')
        with self.assertRaises(M.Refused):
            self.files.check()
        self.assertEqual(extra.read_bytes(), b'preserve this original')

    def test_selected_input_alias_is_not_followed_or_changed(self):
        target = self.base / 'original-data'
        target.write_bytes(b'private fixture')
        alias = self.base / 'alias'
        alias.symlink_to(target)
        with self.assertRaises((M.Refused, OSError)):
            M.original_bytes(self.budget, str(alias), 1024)
        self.assertEqual(target.read_bytes(), b'private fixture')

    def test_one_latched_deadline_refuses_new_work_without_new_clock(self):
        self.budget.end = 0
        original = self.budget.end
        with self.assertRaises(M.Deadline):
            self.files.put('not-started', b'fixture')
        self.assertEqual(self.budget.end, original)
        self.assertTrue(self.budget.expired)
        self.assertFalse((self.path / 'not-started').exists())


if __name__ == '__main__':
    unittest.main()
