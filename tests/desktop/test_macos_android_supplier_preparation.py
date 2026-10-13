"""DATA-only supplier-preparation regressions; no vendor/network/native run.

Only synthetic ZIP/gzip/HTTP metadata and task-owned temporary DATA are exercised.
These tests cannot produce supplier provenance or macOS execution evidence.
"""
from __future__ import annotations

from email.message import Message
import http.client
import hashlib
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import tarfile
from types import SimpleNamespace
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
        self.assertEqual(set(M.SOURCES), {"agp-pom", "agp-module", "aapt2-sha256", "aapt2-osx", "gradle", "bundletool", "sdk-repository", "intel-jdk"})
        self.assertEqual(M.fixed_source("intel-jdk"), (
            "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.20.1%2B1/OpenJDK17U-jdk_x64_mac_hotspot_17.0.20.1_1.tar.gz",
            180578248, "c01975da12ed4235250ff891fe8bba73a9e73037d444b269c9d0922b5dbc8e0a", 180578248))
        self.assertEqual(M.fixed_source("aapt2-osx")[0], "https://dl.google.com/dl/android/maven2/com/android/tools/build/aapt2/8.9.2-12782657/aapt2-8.9.2-12782657-osx.jar")
        with self.assertRaises(M.Refused):
            M.fixed_source("https://example.invalid/arbitrary")
        self.assertEqual(M.checksum(b"A" * 64 + b"\n"), "a" * 64)
        for value in (b"a" * 40, b"a" * 64 + b" file.jar", b"a" * 64 + b"\nextra"):
            with self.subTest(value=value), self.assertRaises(M.Refused):
                M.checksum(value)

    def test_intel_correspondence_closed_host_ca_source_and_finality_precede_network(self):
        self.assertEqual(M.system_ca(), "/private/etc/ssl/cert.pem")
        self.assertEqual(M.system_ca("Darwin"), "/private/etc/ssl/cert.pem")
        self.assertEqual(M.system_ca("Linux"), "/etc/ssl/certs/ca-certificates.crt")
        for value in ([], "darwin", "Windows", "/untrusted/ca", False):
            with self.subTest(ca=value), self.assertRaisesRegex(M.Refused, "^fixed_system_ca_required$"):
                M.system_ca(value)
        # Only a source-pinned task entry may nominate the already parent-bound
        # readonly CA. These inert originals prove refusal/routing, not host
        # ownership or native evidence; no real file/network/SSL work occurs.
        ca_body = b"-----BEGIN CERTIFICATE-----\nDATA-fixture\n-----END CERTIFICATE-----\n"
        pair = (len(ca_body), M.hashlib.sha256(ca_body).hexdigest())

        def ca_attempt(phase):
            budget, events = M.Budget(), []
            ca_uid = 0 if phase == "default-root" else 42 if phase == "foreign-owner" else 65534
            streams = {201: b"     65534          0          1\n", 202: b"     65534          0          1\n"}
            if phase in ("uid-map", "gid-map"):
                streams[201 if phase == "uid-map" else 202] = b"65534 65534 1\n"
            if phase == "map-bound":
                streams[201] = b" " * 257
            closed = set()

            class Original:
                def __init__(self, active_budget, path):
                    self.path = path
                    self.fd = 104 if path.endswith("ca-certificates.crt") else 201 if path.endswith("uid_map") else 202
                    events.append(("open", self.fd))
                    self.items = []
                    for at, name in enumerate(("/", "etc", "ssl", "certs", "ca-certificates.crt")):
                        mode = (stat.S_IFREG | 0o644) if at == 4 else (stat.S_IFDIR | 0o755)
                        if phase == "writable-component" and at == 2:
                            mode |= 0o020
                        identity = (1, 100 + at, mode, ca_uid, ca_uid, 1, len(ca_body), 0, 0)
                        self.items.append((100 + at, None, name, identity, at != 4))

                def read(self, limit):
                    self_outer.assertEqual((self.fd, limit), (104, 1024 * 1024))
                    events.append(("ca-read", self.fd))
                    return ca_body + b"extra" if phase == "body-size" else ca_body

                def close(self):
                    self_outer.assertNotIn(self.fd, closed)
                    closed.add(self.fd)
                    events.append(("close", self.fd))
                    if (phase == "map-close" and self.fd == 201 or phase == "ca-close" and self.fd == 104):
                        budget.errors.append("input_close_unknown")

            self_outer = self
            def read_map(fd, count):
                self.assertIn(fd, (201, 202))
                self.assertGreater(count, 0)
                self.assertLessEqual(count, 257)
                part, streams[fd] = streams[fd][:count], streams[fd][count:]
                events.append(("map-read", fd))
                return part

            def mount_state(fd):
                writable = phase == "writable-mount" or phase == "post-mount" and ("ca-read", 104) in events
                return SimpleNamespace(f_flag=0 if writable and fd == 102 else 1)

            context = SimpleNamespace()
            context.load_verify_locations = lambda **kw: events.append(("cadata", kw))
            def tls(protocol):
                self.assertEqual(protocol, M.ssl.PROTOCOL_TLS_CLIENT)
                self.assertEqual(closed, {104} if phase == "default-root" else {104, 201, 202})
                events.append(("tls", protocol))
                return context

            fake_os = SimpleNamespace(getuid=lambda: 0 if phase == "uid" else 65534,
                                      geteuid=lambda: 65534, getgid=lambda: 65534, getegid=lambda: 65534,
                                      getpid=lambda: 42, fstatvfs=mount_state, ST_RDONLY=1, read=read_map)
            fake_ssl = SimpleNamespace(SSLContext=tls, PROTOCOL_TLS_CLIENT=M.ssl.PROTOCOL_TLS_CLIENT,
                                       TLSVersion=M.ssl.TLSVersion, CERT_REQUIRED=M.ssl.CERT_REQUIRED)
            fake_http = SimpleNamespace(request=SimpleNamespace(
                ProxyHandler=lambda settings: ("proxy", settings),
                HTTPSHandler=lambda **settings: ("https", settings),
                build_opener=lambda *handlers: events.append(("opener", handlers)) or object()))
            nomination = None if phase.startswith("default-") else pair
            if phase == "tuple-type": nomination = list(pair)
            if phase == "size-type": nomination = (True, pair[1])
            if phase == "hash-shape": nomination = (pair[0], "A" * 64)
            if phase == "body-hash": nomination = (pair[0], "0" * 64)
            with mock.patch.object(M, "InputPath", Original), mock.patch.object(M, "os", fake_os), \
                 mock.patch.object(M, "sys", SimpleNamespace(platform="darwin" if phase == "platform" else "linux")), \
                 mock.patch.object(M, "ssl", fake_ssl), mock.patch.object(M, "urllib", fake_http):
                if phase in ("valid", "default-root"):
                    value = M.Downloads(budget, object(), system="Linux", _root_bound_linux_ca=nomination)
                    self.assertEqual(value.ca_sha256, pair[1])
                    self.assertEqual(context.minimum_version, M.ssl.TLSVersion.TLSv1_2)
                    self.assertIs(context.check_hostname, True)
                    self.assertEqual(context.verify_mode, M.ssl.CERT_REQUIRED)
                    self.assertIn(("cadata", {"cadata": ca_body.decode("ascii")}), events)
                    handlers = [item[1] for item in events if item[0] == "opener"]
                    self.assertEqual(handlers[0][0], ("proxy", {}))
                    self.assertEqual(budget.errors, [])
                else:
                    expected = ("stock_ca_authority_unavailable" if phase == "default-user" else
                                "original_cleanup_unknown" if phase in ("map-close", "ca-close") else
                                "root_bound_linux_ca_required" if phase in ("tuple-type", "size-type", "hash-shape", "platform", "uid") else
                                "root_bound_linux_ca_namespace" if phase in ("uid-map", "gid-map", "map-bound") else
                                "root_bound_linux_ca_pin" if phase in ("body-size", "body-hash") else
                                "root_bound_linux_ca_readonly")
                    with self.assertRaisesRegex(M.Refused, "^" + expected + "$"):
                        M.Downloads(budget, object(), system="Linux", _root_bound_linux_ca=nomination)
                    self.assertFalse(any(event[0] in ("tls", "cadata", "opener") for event in events))
            self.assertIn(104, closed)
            if phase.startswith("default-"):
                self.assertEqual(closed, {104})  # No automatic namespace fallback.

        for phase in ("valid", "default-root", "default-user", "tuple-type", "size-type", "hash-shape",
                      "platform", "uid", "uid-map", "gid-map", "map-bound", "map-close", "foreign-owner",
                      "writable-component", "writable-mount", "post-mount", "body-size", "body-hash", "ca-close"):
            with self.subTest(bound_linux_ca=phase):
                ca_attempt(phase)

        for platform, system in (("linux", "Linux"), ("darwin", "Darwin")):
            stub = SimpleNamespace(platform=platform, version_info=(3, 12),
                                   flags=SimpleNamespace(isolated=True, no_site=True), dont_write_bytecode=True)
            host = SimpleNamespace(sysname=system, release="fixture", machine="x86_64")
            with self.subTest(host=system), mock.patch.object(M, "sys", stub), \
                 mock.patch.object(M.os, "getuid", return_value=65534), \
                 mock.patch.object(M.os, "geteuid", return_value=65534), \
                 mock.patch.object(M.os, "uname", return_value=host) as uname:
                self.assertEqual(M.correspondence_host(), {"system": system, "release": "fixture", "machine": "x86_64"})
                uname.assert_called_once_with()
        for bad in ("platform", "system", "root", "effective", "version", "isolated", "site", "bytecode"):
            stub = SimpleNamespace(platform="win32" if bad == "platform" else "linux",
                                   version_info=(3, 10) if bad == "version" else (3, 12),
                                   flags=SimpleNamespace(isolated=bad != "isolated", no_site=bad != "site"),
                                   dont_write_bytecode=bad != "bytecode")
            host = SimpleNamespace(sysname="Darwin" if bad == "system" else "Linux", release="fixture", machine="x86_64")
            with self.subTest(refusal=bad), mock.patch.object(M, "sys", stub), \
                 mock.patch.object(M.os, "getuid", return_value=0 if bad == "root" else 65534), \
                 mock.patch.object(M.os, "geteuid", return_value=1 if bad == "effective" else 65534), \
                 mock.patch.object(M.os, "uname", return_value=host), \
                 self.assertRaisesRegex(M.Refused, "^actual_nonroot_isolated_data_host_required$"):
                M.correspondence_host()

        # A failed original source close must stop before definitions/network;
        # the wrong source bytes must never be compiled as a fallback module.
        for phase in ("source-pin", "source-close"):
            budget = M.Budget()
            source = M.CorrespondenceSource(budget)
            def read(*args):
                if phase == "source-close":
                    budget.errors.append("input_close_unknown")
                return b"not the nominated parser"
            with self.subTest(source=phase), mock.patch.object(M, "original_bytes", side_effect=read), \
                 self.assertRaisesRegex(M.Refused, "^(correspondence_source_pin|original_cleanup_unknown)$"):
                source.load()
            source.close()
            self.assertNotIn(M.CORRESPONDENCE_MODULE, M.sys.modules)
        foreign = object()
        with mock.patch.dict(M.sys.modules, {M.CORRESPONDENCE_MODULE: foreign}), \
             mock.patch.object(M.sys, "argv", [str(_SOURCE), "--intel-jdk-correspondence", "/not-consumed"]), \
             mock.patch.object(M, "correspondence_host", return_value={"system": "Linux"}), \
             mock.patch.object(M, "process_descriptor_bound", return_value={}), \
             mock.patch.object(M, "PrivateFiles") as private, mock.patch.object(M, "Downloads") as download, \
             mock.patch.object(M, "emit_report", side_effect=lambda budget, report, code: (code, report)):
            code, report = M.main()
            self.assertEqual((code, report["failure"], report["correspondencePublished"]),
                             (78, "correspondence_module_collision", False))
            self.assertIs(M.sys.modules[M.CORRESPONDENCE_MODULE], foreign)
            private.assert_not_called()
            download.assert_not_called()
        source = M.CorrespondenceSource(M.Budget())
        source.module = object()  # Not the foreign registry object, no original IO.
        with mock.patch.dict(M.sys.modules, {M.CORRESPONDENCE_MODULE: foreign}):
            source.close()
            self.assertIs(M.sys.modules[M.CORRESPONDENCE_MODULE], foreign)
        self.assertEqual(source.budget.errors, ["correspondence_module_identity"])

        # Exercise the actual command's finality latch with inert inner work.
        # This is not a download/parser/native success claim.
        for phase in ("timely", "explicit-timely", "private-close", "module-close", "response-close", "deadline"):
            source = SimpleNamespace(module=SimpleNamespace(Pin=lambda *args: args, Refused=ValueError))
            files = SimpleNamespace(rows=[])
            download = SimpleNamespace(ca_sha256="0" * 64, records=[])
            budget = M.Budget()
            def close_private():
                if phase == "private-close":
                    budget.errors.append("private_files_close_unknown")
            def close_source():
                if phase == "module-close":
                    budget.errors.append("correspondence_module_identity")
                if phase == "deadline":
                    budget.end = 0
            def get(role):
                self.assertEqual(role, "intel-jdk")
                if phase == "response-close":
                    budget.errors.append("http_response_close_unknown")
                return {"test-only": True}
            files.close = close_private
            source.load, source.close = lambda: None, close_source
            download.get = get
            with self.subTest(finality=phase), \
                 mock.patch.object(M.sys, "argv", [str(_SOURCE), "--intel-jdk-correspondence", "/not-consumed"]), \
                 mock.patch.object(M, "Budget", return_value=budget), \
                 mock.patch.object(M, "correspondence_host", return_value={"system": "Linux"}), \
                 mock.patch.object(M, "process_descriptor_bound", return_value={}), \
                 mock.patch.object(M, "CorrespondenceSource", return_value=source), \
                 mock.patch.object(M, "PrivateFiles", return_value=files), \
                 mock.patch.object(M, "Downloads", return_value=download) as downloads, \
                 mock.patch.object(M, "publish_jdk_correspondence", return_value={"test-only": True}) as publish, \
                 mock.patch.object(M, "emit_report", side_effect=lambda budget, report, code: (code, report)):
                if phase == "explicit-timely":
                    nominated = (182140, "9481fcd95f41b221f02f14d896535fe500bec539bc563c4cdca1acee483a8bdd")
                    code, report = M.intel_jdk_correspondence_main(_root_bound_linux_ca=nominated)
                    downloads.assert_called_once_with(budget, files, system="Linux", _root_bound_linux_ca=nominated)
                else:
                    code, report = M.main()
                    downloads.assert_called_once_with(budget, files, system="Linux")
            timely = phase in ("timely", "explicit-timely")
            self.assertEqual(code, 0 if timely else 78 if phase == "deadline" else 79)
            self.assertEqual(report["correspondencePublished"], timely)
            for field in ("nativeExecution", "nativeClosure", "supplierAuthority"):
                self.assertFalse(report[field])
            if phase == "response-close":
                publish.assert_not_called()
            else:
                self.assertEqual(publish.call_args.args[-1],
                                 ("jdk", 180578248, "c01975da12ed4235250ff891fe8bba73a9e73037d444b269c9d0922b5dbc8e0a"))
        with mock.patch.object(M.sys, "argv", [str(_SOURCE), "--intel-jdk-correspondence", "/fixture", "--url"]), \
             mock.patch.object(M, "correspondence_host") as host, \
             mock.patch.object(M, "emit_report", side_effect=lambda budget, report, code: (code, report)):
            code, report = M.main()
            self.assertEqual((code, report["failure"]), (78, "fixed_intel_correspondence_arguments_required"))
            host.assert_not_called()

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

    def test_intel_correspondence_real_parser_binds_archive_publication_and_original_closes(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, body, mode in (("jdk/Contents/Home/bin/java", b"not executable DATA", 0o755),
                                     ("jdk/Contents/Home/release", b'OS_ARCH="x86_64"\n', 0o644)):
                info = tarfile.TarInfo(name)
                info.mode, info.size, info.mtime = mode, len(body), 0
                archive.addfile(info, io.BytesIO(body))
        valid = gzip.compress(data.getvalue(), mtime=0)
        actual_pread, actual_close = os.pread, M.CorrespondenceOriginal.close
        for phase in ("valid", "pin", "replaced-before-open", "changed-during-read", "short-read",
                      "read-bound", "codec", "sink", "archive-close", "deadline"):
            path = self.base / ("intel-" + phase)
            path.mkdir(mode=0o700)
            budget = M.Budget()
            files = M.PrivateFiles(budget, str(path))
            source = M.CorrespondenceSource(budget)
            original = None
            try:
                source.load()  # Exact real sibling bytes/registry, not a parser stub.
                C = source.module
                payload = valid if phase != "codec" else b"not a gzip archive"
                row = files.put("bodies/intel-jdk", payload)
                pin = C.Pin("jdk", len(payload), hashlib.sha256(payload).hexdigest())
                self.assertIs(M.sys.modules[M.CORRESPONDENCE_MODULE], C)
                if phase == "pin":
                    pin = C.Pin("jdk", len(payload), "0" * 64)
                if phase == "replaced-before-open":
                    body = path / "bodies/intel-jdk"
                    body.rename(path / "original-retained")
                    body.write_bytes(payload)
                    body.chmod(0o600)
                if phase in ("changed-during-read", "short-read"):
                    original = M.CorrespondenceOriginal(budget, files, row)
                    original.open()
                    before_charge = budget.read_bytes
                    def read(fd, count, offset):
                        raw = actual_pread(fd, count, offset)
                        if phase == "changed-during-read":
                            os.chmod(path / "bodies/intel-jdk", 0o400)
                            return raw
                        return raw[:-1]
                    with mock.patch.object(M.os, "pread", side_effect=read), \
                         self.assertRaisesRegex(M.Refused, "^correspondence_original_(binding|short_read)$"):
                        original.read_at(0, 1)
                    self.assertEqual(budget.read_bytes, before_charge + 1)
                elif phase == "read-bound":
                    original = M.CorrespondenceOriginal(budget, files, row)
                    original.open()
                    before_charge = budget.read_bytes
                    for offset, count in ((-1, 1), (False, 1), (0, True), (0, M.CHUNK + 1), (len(payload), 1)):
                        with self.subTest(range=(offset, count)), \
                             self.assertRaisesRegex(M.Refused, "^correspondence_original_read_bound$"):
                            original.read_at(offset, count)
                    self.assertEqual(budget.read_bytes, before_charge)
                elif phase == "deadline":
                    original = M.CorrespondenceOriginal(budget, files, row)
                    original.open()
                    capture = C.compile_archive(original, pin)
                    budget.end = 0
                    with self.assertRaises(M.Deadline):
                        capture.publish(lambda raw: files.put("intel-jdk-correspondence.json", raw))
                    with self.assertRaisesRegex(C.Refused, "^report_finality$"):
                        capture.publish(lambda raw: self.fail("failed capture retried publication"))
                else:
                    def close(value):
                        actual_close(value)
                        if phase == "archive-close":
                            value.budget.errors.append("input_close_unknown")
                    actual_put = files.put
                    def put(name, raw):
                        if phase == "sink" and name == "intel-jdk-correspondence.json":
                            raise M.Refused("synthetic_sink_refused")
                        return actual_put(name, raw)
                    expected = {"pin": "correspondence_archive_pin",
                                "replaced-before-open": "correspondence_original_binding",
                                "codec": "correspondence_gzip_header",
                                "sink": "synthetic_sink_refused",
                                "archive-close": "original_cleanup_unknown"}
                    with mock.patch.object(M.CorrespondenceOriginal, "close", close), \
                         mock.patch.object(files, "put", side_effect=put):
                        if phase == "valid":
                            receipt = M.publish_jdk_correspondence(budget, files, row, C, pin)
                            published = next(item for item in files.rows if item["path"] == "intel-jdk-correspondence.json")
                            raw = files.read(published, 8192)
                            parsed = json.loads(raw)
                            self.assertEqual((receipt["bytes"], receipt["sha256"]), (len(raw), hashlib.sha256(raw).hexdigest()))
                            self.assertEqual((parsed["files"], parsed["members"], parsed["archiveSha256"]), (2, 2, pin.sha256))
                            self.assertTrue(parsed["completeMemberHashes"])
                            self.assertFalse(parsed["supplierAuthority"])
                            self.assertFalse(parsed["nativeClosure"])
                            self.assertEqual({item[0]: (item[2], item[4]) for item in parsed["rows"]}, {
                                "jdk/Contents/Home/bin/java": (stat.S_IFREG | 0o755, hashlib.sha256(b"not executable DATA").hexdigest()),
                                "jdk/Contents/Home/release": (stat.S_IFREG | 0o644, hashlib.sha256(b'OS_ARCH="x86_64"\n').hexdigest())})
                        else:
                            with self.assertRaises((M.Refused, C.Refused)) as refused:
                                M.publish_jdk_correspondence(budget, files, row, C, pin)
                            self.assertEqual(M.correspondence_failure(refused.exception, C), expected[phase])
                exists = (path / "intel-jdk-correspondence.json").exists()
                # The close-failure leaf is persisted DATA, but no successful
                # receipt can escape; final command status also vetoes it above.
                self.assertEqual(exists, phase in ("valid", "archive-close"))
                if phase == "archive-close":
                    with self.assertRaises(M.CleanupUnknown):
                        budget.point()
            finally:
                if original is not None:
                    original.close()
                source.close()
                files.close()
            self.assertNotIn(M.CORRESPONDENCE_MODULE, M.sys.modules)
            self.assertEqual(budget.fds, 0)
            self.assertLessEqual(budget.peak_fds, M.FD_LIMIT)

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
