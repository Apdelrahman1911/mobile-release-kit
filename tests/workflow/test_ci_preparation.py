"""Pure offline-input contracts: tiny DATA fixtures, never network or installers.

The real acquirer/parser/writer runs against task-owned temporary files and an
inert urllib opener. No wheel, gem, actionlint binary, or project code executes.
"""
from __future__ import annotations

import copy
import functools
import gzip
import hashlib
import importlib.util
import io
import json
import stat
import tarfile
import tempfile
import unittest
import urllib.error
import urllib.request
from contextlib import ExitStack
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[2]
PINS = {
    "pip": "24.0", "setuptools": "80.9.0", "wheel": "0.45.1",
    "attrs": "26.1.0", "jsonschema": "4.25.1", "jsonschema-specifications": "2025.9.1",
    "referencing": "0.36.2", "rpds-py": "0.27.1", "typing-extensions": "4.16.0",
}
GROUPS = {"pip": ("pip",), "build": ("setuptools", "wheel"),
          "test": ("attrs", "jsonschema", "jsonschema-specifications", "referencing", "rpds-py", "typing-extensions")}
BINARY = b"Inert synthetic actionlint member; not an executable.\n"


@functools.lru_cache(maxsize=1)
def preparation_module():
    spec = importlib.util.spec_from_file_location("_mrk_pure_preparation", ROOT / ".github/scripts/ci_prepare.py")
    if spec is None or spec.loader is None:
        raise AssertionError("required preparation source is missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tar_data(entries):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data, mode, kind in entries:
            member = tarfile.TarInfo(name)
            member.mode, member.type = mode, kind
            member.size = len(data) if kind == tarfile.REGTYPE else 0
            if kind == tarfile.SYMTYPE:
                member.linkname = "synthetic-relative-target"
            archive.addfile(member, io.BytesIO(data) if member.isfile() else None)
    return gzip.compress(buffer.getvalue(), mtime=0)


class Reply:
    def __init__(self, data: bytes, url: str, *, status=200, headers=(), read_error=None, close_error=None, on_read=None, on_close=None):
        self.body, self.url, self.status = io.BytesIO(data), url, status
        self.headers = Message()
        for name, value in headers:
            self.headers[name] = value
        self.read_error, self.close_error = read_error, close_error
        self.on_read, self.on_close = on_read, on_close
        self.read_sizes, self.close_calls = [], 0

    def geturl(self):
        return self.url

    def read(self, *args):
        raise AssertionError("unbounded/redirect/error response read")

    def read1(self, size):
        if not 0 < size <= 65536:
            raise AssertionError("unbounded asset read")
        self.read_sizes.append(size)
        if self.read_error is not None:
            raise self.read_error
        data = self.body.read(size)
        if self.on_read is not None:
            self.on_read()
        return data

    def close(self):
        self.close_calls += 1
        self.body.close()
        if self.on_close is not None:
            self.on_close()
        if self.close_error is not None:
            raise self.close_error


class PreparationContractsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="mrk-pure-preparation-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.prep = preparation_module()
        self.now, self.deadline = 100.0, 200.0
        self.stack.enter_context(patch.object(self.prep.time, "monotonic", side_effect=lambda: self.now))
        self.stack.enter_context(patch.object(self.prep.shutil, "disk_usage", return_value=SimpleNamespace(free=8 * 1024**3)))
        self.stack.enter_context(patch("socket.create_connection", side_effect=AssertionError("live network forbidden")))
        self.stack.enter_context(patch.object(self.prep.urllib.request, "urlopen", side_effect=AssertionError("live urlopen forbidden")))
        self.opener_factory = self.stack.enter_context(patch.object(
            self.prep.urllib.request, "build_opener", side_effect=AssertionError("unconfigured network forbidden")))
        self.stack.enter_context(patch.object(self.prep.ssl, "create_default_context", return_value=object()))
        self.original_manifest = json.loads((ROOT / ".github/verification-tools.json").read_bytes())
        self.original_lock = (ROOT / "Gemfile.lock").read_bytes()
        self.source = self.root / "source"
        self.save_source(copy.deepcopy(self.original_manifest), self.original_lock)

    def save_source(self, manifest, lock):
        (self.source / ".github").mkdir(parents=True, mode=0o700, exist_ok=True)
        (self.source / ".github/verification-tools.json").write_text(json.dumps(manifest) + "\n", encoding="utf-8")
        (self.source / "Gemfile.lock").write_bytes(lock)
        self.manifest = manifest

    def synthetic_source(self):
        manifest, payloads = copy.deepcopy(self.original_manifest), {}
        for asset in [*manifest["wheels"], manifest["bundler"]]:
            data = b"Synthetic opaque public DATA: " + asset["filename"].encode("ascii")
            asset["bytes"], asset["sha256"] = len(data), hashlib.sha256(data).hexdigest()
            payloads[asset["url"]] = data
        lock = []
        for line in self.original_lock.decode("ascii").splitlines(keepends=True):
            if " sha256=" in line:
                head = line.split(" sha256=", 1)[0]
                name, version = head.strip().split(" (", 1)
                filename = name + "-" + version[:-1] + ".gem"
                data = b"Synthetic opaque gem DATA: " + filename.encode("ascii")
                payloads["https://rubygems.org/downloads/" + filename] = data
                line = head + " sha256=" + hashlib.sha256(data).hexdigest() + "\n"
            lock.append(line)
        lock_bytes = "".join(lock).encode("ascii")
        manifest["gemfile_lock_sha256"] = hashlib.sha256(lock_bytes).hexdigest()
        actionlint = manifest["actionlint"]
        archive = tar_data([("LICENSE.txt", b"synthetic license", 0o644, tarfile.REGTYPE),
                            ("actionlint", BINARY, 0o755, tarfile.REGTYPE),
                            ("docs/ignored.txt", b"not extracted", 0o644, tarfile.REGTYPE)])
        actionlint.update(bytes=len(archive), sha256=hashlib.sha256(archive).hexdigest())
        actionlint["binary"].update(bytes=len(BINARY), sha256=hashlib.sha256(BINARY).hexdigest())
        payloads[actionlint["url"]] = archive
        self.save_source(manifest, lock_bytes)
        self.payloads, self.requests, self.replies = payloads, [], []

        def open_data(request, *, timeout):
            self.requests.append((request, timeout))
            reply = Reply(payloads[request.full_url], request.full_url)
            self.replies.append(reply)
            return reply

        self.opener_factory.side_effect = None
        self.opener_factory.return_value = SimpleNamespace(open=open_data)

    def prepare(self, name="inputs", platform="linux"):
        return self.prep.prepare_inputs(source_root=self.source, destination=self.root / name,
                                        platform=platform, deadline=self.deadline)

    def download(self, reply, name="download", *, data=b"fixed data"):
        asset = {"name": "synthetic", "version": "1", "url": "https://files.pythonhosted.org/synthetic",
                 "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        self.opener_factory.side_effect = None
        self.opener_factory.return_value = SimpleNamespace(open=Mock(return_value=reply))
        return self.prep.download(asset, name, frozenset({"files.pythonhosted.org"}), self.prep.Budget(self.root, self.deadline))

    def test_committed_pins_are_complete_for_both_native_wheel_tags_and_all_locked_gems(self):
        for platform, tag, digest in (
            ("linux", "cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", "cb56c6210ef77caa58e16e8c17d35c63fe3f5b60fd9ba9d424470c3400bcf9ed"),
            ("macos", "cp311-cp311-macosx_11_0_arm64.whl", "62ac3d4e3e07b58ee0ddecd71d6ce3b1637de2d373501412df395a0ec5f9beb5"),
        ):
            with self.subTest(platform=platform):
                manifest, wheels, gems, manifest_hash, lock_hash = self.prep.load_assets(ROOT, platform)
                self.assertEqual({asset["name"]: asset["version"] for asset in wheels}, PINS)
                self.assertEqual(len(wheels), 9)
                rpds = next(asset for asset in wheels if asset["name"] == "rpds-py")
                self.assertEqual((rpds["filename"], rpds["sha256"]), ("rpds_py-0.27.1-" + tag, digest))
                self.assertEqual((manifest["ruby"], manifest["fiddle"], manifest["locked_gem_count"]), ("3.3.12", "1.1.2", 99))
                self.assertEqual(len(gems), 100)
                self.assertEqual(len({asset["filename"] for asset in gems}), 100)
                locked_lines = [line.strip() for line in self.original_lock.decode("ascii").splitlines() if " sha256=" in line]
                self.assertEqual(len(locked_lines), 99)
                self.assertEqual({f'{a["name"]} ({a["version"]}) sha256={a["sha256"]}' for a in gems if a["name"] != "bundler"}, set(locked_lines))
                fiddle = next(asset for asset in gems if asset["name"] == "fiddle")
                self.assertEqual((fiddle["version"], fiddle["filename"], fiddle["sha256"]),
                                 ("1.1.2", "fiddle-1.1.2.gem", "59bd18c38e65cdc36863ab68e3ffd78658b8f025d1d080b218de94370420a074"))
                self.assertEqual(gems[-1]["sha256"], "d6ca5dd440c24f9abce9844cf44cc8e18c6a553de65a47efb4544137af92c47d")
                self.assertEqual(manifest["actionlint"]["sha256"], "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8")
                self.assertEqual(lock_hash, hashlib.sha256(self.original_lock).hexdigest())
                self.assertEqual(manifest_hash, hashlib.sha256((ROOT / ".github/verification-tools.json").read_bytes()).hexdigest())
        self.opener_factory.assert_not_called()

    def test_missing_duplicate_wrong_platform_or_changed_lock_cannot_reach_acquisition(self):
        changes = (
            lambda value: value["wheels"].pop(),
            lambda value: value["wheels"].__setitem__(-1, copy.deepcopy(value["wheels"][0])),
            lambda value: next(a for a in value["wheels"] if a["name"] == "rpds-py").update(filename="rpds_py-0.27.1-cp312-cp312-macosx_11_0_arm64.whl"),
            lambda value: value["wheels"][0].update(bytes=True),
            lambda value: value.update(ruby="3.3.11"),
            lambda value: value.update(fiddle="1.1.3"),
            lambda value: value.pop("fiddle"),
            lambda value: value.update(locked_gem_count=98),
            lambda value: value.update(locked_gem_count=True),
        )
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                manifest = copy.deepcopy(self.original_manifest)
                change(manifest)
                self.save_source(manifest, self.original_lock)
                with self.assertRaises(self.prep.PreparationError):
                    self.prepare()
                self.assertFalse((self.root / "inputs").exists())
        checksums = self.original_lock.decode("ascii").splitlines(keepends=True)
        checksum = next(line for line in checksums if " sha256=" in line)
        for kind, lock in (
            ("changed-unpinned", self.original_lock + b"\n"),
            ("missing", self.original_lock.replace(checksum.encode(), b"", 1)),
            ("duplicate", self.original_lock.replace(checksum.encode(), (checksum * 2).encode(), 1)),
            ("wrong-version", self.original_lock.replace(checksum.encode(), checksum.replace(" (", " (9", 1).encode(), 1)),
            ("wrong-fiddle", self.original_lock.replace(b"fiddle (1.1.2)", b"fiddle (1.1.3)")),
        ):
            with self.subTest(lock=kind):
                manifest = copy.deepcopy(self.original_manifest)
                if kind != "changed-unpinned":
                    manifest["gemfile_lock_sha256"] = hashlib.sha256(lock).hexdigest()
                self.save_source(manifest, lock)
                with self.assertRaises(self.prep.PreparationError):
                    self.prepare()
        self.opener_factory.assert_not_called()

    def test_complete_preparation_returns_every_byte_and_requirement_without_executing_assets(self):
        self.synthetic_source()
        before = {name: (self.source / name).read_bytes() for name in ("Gemfile.lock", ".github/verification-tools.json")}
        for platform, file_count, request_count in (("linux", 115, 110), ("macos", 113, 109)):
            with self.subTest(platform=platform), patch.object(self.prep, "remaining", wraps=self.prep.remaining) as clock:
                self.requests.clear()
                self.replies.clear()
                self.opener_factory.reset_mock()
                result = self.prepare(platform, platform)
                destination = self.root / platform
                files = {record["path"]: record for record in result["files"]}
                self.assertEqual(len(files), file_count)
                self.assertEqual(len(result["files"]), file_count)
                self.assertEqual(set(files), {path.relative_to(destination).as_posix() for path in destination.rglob("*") if path.is_file()})
                for directory in [destination, *(path for path in destination.rglob("*") if path.is_dir())]:
                    self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
                for relative, record in files.items():
                    path = destination / relative
                    data = path.read_bytes()
                    self.assertEqual((len(data), hashlib.sha256(data).hexdigest()), (record["bytes"], record["sha256"]))
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(result["requirements"], {group: f"python/{group}-requirements.txt" for group in GROUPS})
                selected = {asset["name"]: asset for asset in self.manifest["wheels"] if platform in asset["platforms"]}
                for group, names in GROUPS.items():
                    expected = "".join(f'{name}=={PINS[name]} --hash=sha256:{selected[name]["sha256"]}\n' for name in names)
                    self.assertEqual((destination / result["requirements"][group]).read_text(), expected)
                diagnostic = json.loads((destination / "inputs.json").read_bytes())
                self.assertEqual(diagnostic["files"], [record for record in result["files"] if record["path"] != "inputs.json"])
                self.assertEqual(len(self.requests), request_count)
                self.assertTrue(all(reply.close_calls == 1 for reply in self.replies))
                self.assertEqual({call.args[0] for call in clock.call_args_list}, {self.deadline})
                for request, timeout in self.requests:
                    self.assertEqual(timeout, 30)
                    self.assertEqual({k.lower(): v for k, v in request.header_items()}, {"accept-encoding": "identity", "user-agent": "MRK-offline-inputs/1"})
                for call in self.opener_factory.call_args_list:
                    self.assertEqual(call.args[0].proxies, {})
                    self.assertEqual(call.args[1].deadline, self.deadline)
                if platform == "linux":
                    self.assertEqual((destination / result["actionlint"]).read_bytes(), BINARY)
                    self.assertFalse((destination / "actionlint/docs").exists())
                else:
                    self.assertIsNone(result["actionlint"])
                    self.assertIsNone(result["actionlint_archive"])
                    self.assertFalse((destination / "actionlint").exists())
        self.assertEqual({name: (self.source / name).read_bytes() for name in before}, before)

    def test_unsupported_nonempty_and_symlink_roots_never_adopt_or_overwrite_inputs(self):
        with self.assertRaisesRegex(self.prep.PreparationError, "unsupported_preparation_platform"):
            self.prepare(platform="windows")
        destination = self.root / "inputs"
        destination.mkdir()
        marker = destination / "inputs.json"
        marker.write_bytes(b'{"status":"PASS"}\n')
        with self.assertRaises(FileExistsError):
            self.prepare()
        self.assertEqual(marker.read_bytes(), b'{"status":"PASS"}\n')
        linked = self.root / "linked"
        linked.symlink_to(destination, target_is_directory=True)
        with self.assertRaises(FileExistsError):
            self.prepare("linked")
        source_link = self.root / "source-link"
        source_link.symlink_to(self.source, target_is_directory=True)
        for source, target in ((source_link, self.root / "new"), (self.source, linked / "new"), (self.source, self.source / "new")):
            with self.subTest(source=source.name, target=target.name), self.assertRaises(self.prep.PreparationError):
                self.prep.prepare_inputs(source_root=source, destination=target, platform="linux", deadline=self.deadline)
        manifest_path = self.source / ".github/verification-tools.json"
        original = manifest_path.read_bytes()
        outside = self.root / "manifest-target.json"
        outside.write_bytes(original)
        manifest_path.unlink()
        manifest_path.symlink_to(outside)
        with self.assertRaises(OSError):
            self.prepare("new")
        self.assertEqual(outside.read_bytes(), original)
        self.assertEqual(marker.read_bytes(), b'{"status":"PASS"}\n')
        self.opener_factory.assert_not_called()

    def test_stream_hash_size_response_origin_and_headers_fail_closed_and_close(self):
        url = "https://files.pythonhosted.org/synthetic"
        cases = (
            Reply(b"wrong data", url), Reply(b"fixed dat", url), Reply(b"fixed data!", url),
            Reply(b"fixed data", "https://unapproved.invalid/asset"), Reply(b"fixed data", url, status=206),
            Reply(b"fixed data", url, headers=(("Content-Length", "10"), ("Content-Length", "10"))),
            Reply(b"fixed data", url, headers=(("Content-Encoding", "gzip"),)),
            *(Reply(b"fixed data", url, headers=(("Content-Length", length),))
              for length in ("9", "11", "0", "-1", "unknown", "99999999999")),
        )
        for index, reply in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(self.prep.PreparationError):
                self.download(reply, f"bad-{index}")
            self.assertEqual(reply.close_calls, 1)
        path = self.root / "protected"
        path.write_bytes(b"keep existing bytes")
        reply = Reply(b"fixed data", url)
        with self.assertRaises(FileExistsError):
            self.download(reply, "protected")
        self.assertEqual(path.read_bytes(), b"keep existing bytes")
        self.assertEqual(reply.close_calls, 1)

    def test_redirects_close_without_reading_and_preserve_host_and_original_deadline_bounds(self):
        hosts = frozenset({"github.com", "release-assets.githubusercontent.com"})
        request = urllib.request.Request("https://github.com/synthetic")
        redirects = self.prep.Redirects(hosts, self.deadline)
        opened = Mock(return_value=object())
        redirects.parent = SimpleNamespace(open=opened)
        for index in range(4):
            reply = Reply(b"unread body", request.full_url, headers=(("Location", "https://release-assets.githubusercontent.com/synthetic"),))
            self.now = 170 + index
            if index < 3:
                redirects.http_error_302(request, reply, 302, "redirect", reply.headers)
                self.assertEqual(opened.call_args.kwargs["timeout"], self.deadline - self.now)
            else:
                with self.assertRaisesRegex(self.prep.PreparationError, "invalid_asset_redirect"):
                    redirects.http_error_302(request, reply, 302, "redirect", reply.headers)
            self.assertEqual((reply.close_calls, reply.read_sizes), (1, []))
        self.assertEqual(opened.call_count, 3)
        for url in ("http://github.com/asset", "https://unapproved.invalid/asset", "https://user:password@github.com/asset", "https://github.com:444/asset"):
            subject = self.prep.Redirects(hosts, self.deadline)
            subject.parent = SimpleNamespace(open=Mock(side_effect=AssertionError("forbidden redirect followed")))
            reply = Reply(b"unread", request.full_url, headers=(("Location", url),))
            with self.subTest(url=url), self.assertRaises(self.prep.PreparationError):
                subject.http_error_302(request, reply, 302, "redirect", reply.headers)
            self.assertEqual(reply.close_calls, 1)
        for code in (301, 303, 307, 308):
            self.assertIs(getattr(redirects, f"http_error_{code}").__func__, redirects.http_error_302.__func__)

    def test_http_error_body_and_late_close_cannot_turn_downloaded_bytes_into_success(self):
        url = "https://files.pythonhosted.org/synthetic"
        reply = Reply(b"unread private diagnostic", url)
        error = urllib.error.HTTPError(url, 503, "unavailable", Message(), reply)
        self.opener_factory.side_effect = None
        self.opener_factory.return_value = SimpleNamespace(open=Mock(side_effect=error))
        asset = {"name": "synthetic", "version": "1", "url": url, "bytes": 10, "sha256": hashlib.sha256(b"fixed data").hexdigest()}
        with self.assertRaisesRegex(self.prep.PreparationError, "asset_http_error"):
            self.prep.download(asset, "http-error", frozenset({"files.pythonhosted.org"}), self.prep.Budget(self.root, self.deadline))
        self.assertEqual((reply.close_calls, reply.read_sizes), (1, []))
        self.assertFalse((self.root / "http-error").exists())
        primary, secondary = OSError("original synthetic read failure"), OSError("synthetic close failure")
        reply = Reply(b"fixed data", url, read_error=primary, close_error=secondary)
        with self.assertRaises(OSError) as caught:
            self.download(reply, "primary")
        self.assertIs(caught.exception, primary)
        self.assertIn("additional preparation resource close failure", primary.__notes__)
        reply = Reply(b"fixed data", url, close_error=secondary)
        with self.assertRaises(OSError) as caught:
            self.download(reply, "late-close")
        self.assertIs(caught.exception, secondary)
        self.assertEqual((self.root / "late-close").read_bytes(), b"fixed data")

    def test_deadline_expiry_before_read_after_read_and_after_close_never_renews_or_adopts(self):
        self.now = self.deadline
        with self.assertRaisesRegex(self.prep.PreparationError, "preparation_deadline_expired"):
            self.prepare()
        self.assertFalse((self.root / "inputs").exists())
        self.opener_factory.assert_not_called()
        self.now = 100.0
        url = "https://files.pythonhosted.org/synthetic"
        for phase in ("read", "close"):
            self.now = 100.0
            expire = lambda: setattr(self, "now", self.deadline)
            reply = Reply(b"fixed data", url, **{"on_" + phase: expire})
            with self.subTest(phase=phase), self.assertRaisesRegex(self.prep.PreparationError, "preparation_deadline_expired"):
                self.download(reply, "expired-" + phase)
            self.assertEqual(reply.close_calls, 1)
        self.now = 100.0
        self.synthetic_source()
        first = self.manifest["wheels"][0]
        reply = Reply(self.payloads[first["url"]], first["url"], on_close=lambda: setattr(self, "now", self.deadline))
        opener = SimpleNamespace(open=Mock(return_value=reply))
        self.opener_factory.return_value = opener
        with self.assertRaisesRegex(self.prep.PreparationError, "preparation_deadline_expired"):
            self.prepare()
        self.assertEqual(opener.open.call_count, 1)
        self.assertFalse((self.root / "inputs/inputs.json").exists())
        self.now = 100.0
        with self.assertRaises(FileExistsError):
            self.prepare()
        self.assertEqual(opener.open.call_count, 1)

    def test_short_writes_charge_once_and_aggregate_disk_or_zero_write_failures_stop_output(self):
        budget = self.prep.Budget(self.root, self.deadline)
        written = bytearray()
        def short_write(data):
            written.extend(data[:1])
            return 1
        budget.write(SimpleNamespace(write=short_write), b"abc")
        self.assertEqual((written, budget.written), (b"abc", 3))
        with patch.object(self.prep, "MAX_INPUT_BYTES", 4), self.assertRaisesRegex(self.prep.PreparationError, "aggregate_size_limit"):
            budget.write(SimpleNamespace(write=short_write), b"de")
        self.assertEqual((written, budget.written), (b"abc", 3))
        with patch.object(self.prep.shutil, "disk_usage", return_value=SimpleNamespace(free=self.prep.DISK_RESERVE)), self.assertRaisesRegex(self.prep.PreparationError, "disk_reserve"):
            budget.write(SimpleNamespace(write=short_write), b"d")
        self.assertEqual(written, b"abc")
        with self.assertRaisesRegex(self.prep.PreparationError, "short_write"):
            budget.write(SimpleNamespace(write=lambda data: 0), b"d")
        self.assertEqual(budget.written, 4)

    def test_actionlint_extraction_writes_only_one_named_regular_pinned_member(self):
        self.synthetic_source()
        actionlint = self.manifest["actionlint"]
        parent = self.root / "extraction"
        parent.mkdir()
        entries = [("../../escape", b"not extracted", 0o644, tarfile.REGTYPE), ("actionlint", BINARY, 0o755, tarfile.REGTYPE)]
        for kind, values in (("valid", entries), ("duplicate", [entries[-1], entries[-1]]),
                             ("link", [("actionlint", b"", 0o755, tarfile.SYMTYPE)]),
                             ("hard-link", [("actionlint", b"", 0o755, tarfile.LNKTYPE)]),
                             ("directory", [("actionlint", b"", 0o755, tarfile.DIRTYPE)]),
                             ("wrong-mode", [("actionlint", BINARY, 0o644, tarfile.REGTYPE)]),
                             ("short-size", [("actionlint", BINARY[:-1], 0o755, tarfile.REGTYPE)]),
                             ("missing", entries[:1]), ("bad-hash", [("actionlint", b"x" * len(BINARY), 0o755, tarfile.REGTYPE)])):
            directory = parent / kind
            (directory / "actionlint").mkdir(parents=True)
            (directory / "actionlint" / actionlint["filename"]).write_bytes(tar_data(values))
            budget = self.prep.Budget(directory, self.deadline)
            with self.subTest(kind=kind):
                if kind == "valid":
                    record = self.prep.extract_actionlint(actionlint, budget)
                    self.assertEqual((directory / record["path"]).read_bytes(), BINARY)
                    self.assertEqual(record["sha256"], hashlib.sha256(BINARY).hexdigest())
                    self.assertEqual(stat.S_IMODE((directory / record["path"]).stat().st_mode), 0o600)
                    self.assertEqual({path.relative_to(directory).as_posix() for path in directory.rglob("*") if path.is_file()},
                                     {"actionlint/" + actionlint["filename"], "actionlint/actionlint"})
                else:
                    with self.assertRaises(self.prep.PreparationError):
                        self.prep.extract_actionlint(actionlint, budget)
                # Any mistaken extraction of ../../escape stays task-owned,
                # whether an implementation chose either possible output root.
                self.assertFalse((parent / "escape").exists())
                self.assertFalse((self.root / "escape").exists())
        for kind, compressed in (("truncated", tar_data(entries)[:-5]), ("expanded-cap", tar_data(entries))):
            directory = parent / kind
            (directory / "actionlint").mkdir(parents=True)
            (directory / "actionlint" / actionlint["filename"]).write_bytes(compressed)
            with self.subTest(kind=kind), ExitStack() as stack:
                if kind == "expanded-cap":
                    stack.enter_context(patch.object(self.prep, "MAX_TAR_BYTES", 2048))
                with self.assertRaises((EOFError, self.prep.PreparationError)):
                    self.prep.extract_actionlint(actionlint, self.prep.Budget(directory, self.deadline))


if __name__ == "__main__":
    unittest.main()
