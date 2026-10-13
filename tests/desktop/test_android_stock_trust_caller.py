"""Inert caller/owner DATA tests; never curl, Java, native execution or host admission.

The real Check record writer/forwarder calls a byte-only owner spy. Private
temporary originals stand in for protected host acquisition; that substitution
does not qualify a host. Original read/close/collision code and Policy are real.
"""
from contextlib import contextmanager, ExitStack
from copy import deepcopy
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


M = load("_stock_caller", "desktop/tools/android_material_preparation.py")
P = load("_stock_original_check", "desktop/tools/ci_ubuntu_publication.py")
F = load("_stock_public_fixture", "tests/desktop/test_stock_trust_correspondence.py")


@contextmanager
def stage(fault=None):
    with tempfile.TemporaryDirectory(prefix="mrk-stock-caller-inert-") as folder, ExitStack() as patches:
        base = Path(folder)
        root, compiler = base / "material", base / "compiler"
        root.mkdir(mode=0o700); compiler.mkdir(mode=0o700)
        owner = (os.getuid(), os.getgid())
        directories = {".": M._private(root, owner, directory=True, mode=0o700)[:5]}
        for name in ("private", "home", "tmp", "empty-capath", "bodies"):
            M._staging_mkdir(root, name, directories, owner)
        pem, jks, custom = base / "fixture.pem", base / "fixture.jks", base / "custom"
        M.D.write(pem, F.PEM, 0o400); M.D.write(jks, F.JKS, 0o400); custom.mkdir(mode=0o700)
        host = {"bindings": {"files": {M.STOCK_PEM: {"path": str(pem)}, M.STOCK_JKS: {"path": str(jks)}},
                            "androidDirectories": {M.STOCK_CUSTOM: {"path": str(custom)}}}}
        policy = {"hostPolicy": {"generated": {"javaTrustStore": {"path": M.STOCK_JKS,
            "classification": M.STOCK_CLASSIFICATION, "policySha256": M.STOCK_POLICY_SHA256,
            "pemPath": M.STOCK_PEM, "customCaDirectory": M.STOCK_CUSTOM}},
            "inputs": {"files": sorted((M.STOCK_PEM, M.STOCK_JKS)), "directories": {M.STOCK_CUSTOM: []}, "absences": []}}}
        events, live, calls, close_attempts = [], set(), [], []
        armed = [False]
        old_open = M.D._open

        def opened(path, limit):
            stream, before = old_open(path, limit)
            if path != pem or fault != "close":
                return stream, before
            class CloseFailure:
                def fileno(self): return stream.fileno()
                def read(self, n): return stream.read(n)
                def close(self):
                    stream.close()
                    if armed[0]:
                        close_attempts.append(None)
                        raise OSError("inert original close failed")
            return CloseFailure(), before
        patches.enter_context(patch.object(M.D, "_open", side_effect=opened))

        @contextmanager
        def host_original(binding, selected, limit, deadline):
            path = Path(binding["path"])
            with M._stock_private_original(path, owner, limit, deadline) as (raw, pin):
                events.append(("open", selected)); live.add(selected)
                try:
                    yield raw, {"binding": deepcopy(binding), "file": {"path": str(path), "size": pin["size"],
                        "sha256": pin["sha256"], "mode": 0o400}, "identity": pin["identity"]}
                finally:
                    live.remove(selected)
            events.append(("closed", selected))
        patches.enter_context(patch.object(M, "_stock_host_original", side_effect=host_original))
        # Only protected-host location/profile acquisition is replaced. The
        # actual bounded empty-directory read and original identity checks run.
        patches.enter_context(patch.object(M, "_protected_namespace", return_value=None))
        patches.enter_context(patch.object(subprocess, "Popen", side_effect=AssertionError("no process permitted")))
        patches.enter_context(patch("sys.stdout", new=io.StringIO()))
        data = {name: ("inert-body-" + name).encode() for name in ("direct", "body-142", "body-143")}
        suppliers = [{"id": name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "sha1": None,
                      "publishedSha1": None, "publishedSha256": None, "githubAsset": name != "direct",
                      "url": "https://" + ("github.com/owner/repo/releases/download/v1/" if name != "direct" else "example.invalid/") + name}
                     for name, raw in data.items()]
        location = "https://release-assets.githubusercontent.com/github-production-release-asset/1/" + "a" * 36 + "?fixture=only"

        def owner_spy(argv, *, environ, cwd, timeout, capture, text, output_limit):
            calls.append((deepcopy(argv), deepcopy(environ), cwd, timeout, capture, text, output_limit))
            if live != {M.STOCK_PEM}:
                raise AssertionError("The original PEM must remain held during each consumer")
            stderr = b""
            if "--parallel" in argv:
                config = (root / "private/replay.curl").read_bytes()
                if config != M._stock_replay_config(root, [suppliers[0]]):
                    raise AssertionError("original replay bytes differ")
                (root / "bodies/direct").write_bytes(data["direct"])
                stdout = ("0\t0\t200\t" + str(len(data["direct"])) + "\t0\t0\n").encode()
            elif "--dump-header" in argv:
                stdout = ("HTTP/2 302\r\nLocation: " + location + "\r\nContent-Length: 0\r\n\r\n"
                          "\nMRK_HTTP=302\t0\t0\t0\t0\n").encode()
            else:
                target = Path(argv[argv.index("--output") + 1])
                target.write_bytes(data[target.name])
                stdout = ("\nMRK_HTTP=200\t0\t" + str(len(data[target.name])) + "\t0\t0\n").encode()
            if len(calls) == 1:
                if fault == "owner": raise OSError("inert original owner failure")
                if fault == "stderr": stderr = b"inert error"
                if fault == "pem-replaced":
                    pem.rename(base / "retained-original.pem"); M.D.write(pem, F.PEM, 0o400)
                if fault == "config-replaced":
                    config_path = root / "private/replay.curl"
                    raw = config_path.read_bytes(); config_path.rename(root / "private/retained-replay.curl")
                    M.D.write(config_path, raw, 0o400)
                if fault == "capath": M.D.write(root / "empty-capath/unexpected", b"retain", 0o400)
                if fault == "environment": environ["CURL_CA_BUNDLE"] = "unexpected"
                if fault == "late": check.end = time.monotonic() - 1
                armed[0] = True
            return subprocess.CompletedProcess(argv, 0, stdout, stderr)

        check = P.Check(compiler, owner_spy, deadline=time.monotonic() + 30, private=True)
        if fault == "writer-pins":
            original_command = check.private_command
            def changed_writer(*args, **kwargs):
                result = original_command(*args, **kwargs)
                check.private_metadata["material"][-1]["sha256"] = "0" * 64
                return result
            check.private_command = changed_writer
        if fault == "capath-before-next":
            original_consumer = M._stock_consumer
            def after_consumer(*args, **kwargs):
                result = original_consumer(*args, **kwargs)
                if len(calls) == 1: os.utime(root / "empty-capath", ns=(1, 1))
                return result
            patches.enter_context(patch.object(M, "_stock_consumer", side_effect=after_consumer))
        stock = M._stock_trust_state(policy, host, check.end)
        yield {"check": check, "root": root, "owner": owner, "directories": directories, "host": host,
               "policy": policy, "stock": stock, "suppliers": suppliers, "calls": calls, "events": events,
               "pem": pem, "jks": jks, "custom": custom, "live": live, "close_attempts": close_attempts}


def download(s):
    return M._download(s["check"], s["root"], s["suppliers"], s["owner"], directories=s["directories"],
                       host=s["host"], stock=s["stock"])


def readback(s, consumers):
    return M._stock_readback(s["policy"], s["host"], s["root"], s["owner"], s["directories"], s["check"].root,
                            s["suppliers"], s["stock"], consumers, s["check"].end)


class StockCallerContracts(unittest.TestCase):
    def test_five_original_consumers_forward_clean_environment_and_readback_without_commands(self):
        with stage() as s, patch.dict(os.environ, {"CURL_CA_BUNDLE": "/ambient", "HTTPS_PROXY": "ambient"}):
            observations, consumers = download(s)
            self.assertEqual(len(observations), 3)
            self.assertEqual(len(consumers), 5)
            self.assertEqual(len(s["calls"]), 5)
            self.assertFalse(s["stock"]["producerExecutionProven"])
            self.assertFalse(s["check"].failed)
            for argv, env, cwd, timeout, capture, text, bound in s["calls"]:
                self.assertEqual(env, M._stock_environment(s["root"]))
                self.assertEqual(argv[:2], ["/usr/bin/curl", "-q"])
                self.assertEqual(cwd, s["root"])
                self.assertTrue(capture); self.assertFalse(text)
                self.assertGreaterEqual(timeout, 1); self.assertLessEqual(bound, 128 << 10)
            self.assertFalse(s["live"])
            s["check"].owner = lambda *a, **k: self.fail("readback launched a command")
            self.assertEqual(readback(s, consumers), consumers)
            self.assertEqual(len(s["calls"]), 5)
            self.assertLess(len(M.D.canonical({"stockTrust": s["stock"], "curlConsumers": consumers})), M.PRIVATE_DOCS["provenance"])

    def test_first_failure_closes_originals_and_never_launches_a_successor(self):
        for fault in ("owner", "stderr", "pem-replaced", "config-replaced", "capath", "environment", "late", "close",
                      "writer-pins", "capath-before-next"):
            with self.subTest(fault=fault), stage(fault) as s:
                with self.assertRaises((ValueError, OSError)):
                    download(s)
                self.assertTrue(s["check"].failed)
                self.assertEqual(len(s["calls"]), 1)
                self.assertFalse(s["live"])
                with self.assertRaisesRegex(M.D.Refused, "failure is latched"):
                    download(s)
                self.assertEqual(len(s["calls"]), 1)
                if fault == "close": self.assertEqual(len(s["close_attempts"]), 1)
                if fault == "capath": self.assertEqual((s["root"] / "empty-capath/unexpected").read_bytes(), b"retain")

    def test_readback_rejects_forged_consumer_environment_original_config_or_owner_result(self):
        with stage() as s:
            _, original = download(s)
            for mutate in (lambda x: x.reverse(), lambda x: x[0]["environment"].update(SSL_CERT_FILE="other"),
                           lambda x: x[0].update(cwd="/other"), lambda x: x[0]["replay"]["identity"].__setitem__(1, -1),
                           lambda x: x[1]["ownerRecords"]["files"][0].update(sha256="0" * 64)):
                changed = deepcopy(original); mutate(changed)
                with self.subTest(changed=changed[0]["label"]), self.assertRaises(M.D.Refused): readback(s, changed)
            path = s["check"].root / "private-material/android-asset-body-body-143.result.json"
            raw = path.read_bytes(); path.rename(path.with_name("retained-result.json")); M.D.write(path, raw)
            with self.assertRaisesRegex(M.D.Refused, "owner records changed"): readback(s, original)
            self.assertEqual(len(s["calls"]), 5)

    def test_jks_staging_returns_only_checked_original_bytes_and_rejects_equal_byte_replacement(self):
        with stage() as s:
            original_read = M.D.read
            def no_detached(path, limit):
                self.assertNotIn(path, (s["pem"], s["jks"]))
                return original_read(path, limit)
            with patch.object(M.D, "read", side_effect=no_detached):
                self.assertEqual(M._stock_jks_bytes(s["host"], s["stock"], s["check"].end), F.JKS)
            s["jks"].rename(s["jks"].with_name("retained-original.jks")); M.D.write(s["jks"], F.JKS, 0o400)
            with self.assertRaisesRegex(M.D.Refused, "staged JKS differs"):
                M._stock_jks_bytes(s["host"], s["stock"], s["check"].end)

    def test_real_staging_writer_and_validate_reader_agree_on_private_not_public_jks_mode(self):
        with stage() as s:
            for name in ("tools", "tools/jdk", "tools/jdk/lib", "tools/jdk/lib/security"):
                M._staging_mkdir(s["root"], name, s["directories"], s["owner"])
            row = {"path": M.GENERATED[0], "size": len(F.JKS), "sha256": hashlib.sha256(F.JKS).hexdigest(),
                   "mode": 0o444, "sourceMode": 0o400}
            originals = {}
            M._member_output(io.BytesIO(F.JKS), s["root"], [row],
                {"size": row["size"], "sha256": row["sha256"], "mode": row["sourceMode"]}, s["check"].end,
                directories=s["directories"], originals=originals, owner=s["owner"])
            path = s["root"] / "tools" / row["path"]
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
            M._tree(s["root"], [row], s["owner"], s["check"].end,
                    directories=s["directories"], originals=originals)
            M._stock_staged_jks(s["root"], s["owner"], row, originals[row["path"]], F.JKS, s["check"].end)
            # Public manifest0444 never changes private staging0400. An equal
            # body with a changed mode or original cannot pass final readback.
            os.chmod(path, 0o444)
            with self.assertRaises(M.D.Refused):
                M._stock_staged_jks(s["root"], s["owner"], row, originals[row["path"]], F.JKS, s["check"].end)
            path.rename(path.with_name("retained-staging.jks")); M.D.write(path, F.JKS, 0o400)
            with self.assertRaises(M.D.Refused):
                M._stock_staged_jks(s["root"], s["owner"], row, originals[row["path"]], F.JKS, s["check"].end)

    def test_wrong_anchors_policy_or_custom_input_never_becomes_correspondence(self):
        with stage() as s:
            for wrong in (F.PEM.replace(b"MII", b"AAA", 1), F.PEM + F.PEM, b"not PEM"):
                os.chmod(s["pem"], 0o600); s["pem"].write_bytes(wrong); os.chmod(s["pem"], 0o400)
                with self.subTest(size=len(wrong)), self.assertRaises(ValueError):
                    M._stock_trust_state(s["policy"], s["host"], s["check"].end)
            os.chmod(s["pem"], 0o600); s["pem"].write_bytes(F.PEM); os.chmod(s["pem"], 0o400)
            changed = deepcopy(s["policy"]); changed["hostPolicy"]["generated"]["javaTrustStore"]["policySha256"] = "0" * 64
            with self.assertRaisesRegex(M.D.Refused, "source rule differs"):
                M._stock_trust_state(changed, s["host"], s["check"].end)
            M.D.write(s["custom"] / "uninspected", b"not read", 0o400)
            with self.assertRaisesRegex(M.D.Refused, "contains an entry"):
                M._stock_trust_state(s["policy"], s["host"], s["check"].end)
            s["custom"].rename(s["custom"].with_name("retained-custom"))
            with self.assertRaises(FileNotFoundError):
                M._stock_trust_state(s["policy"], s["host"], s["check"].end)
            self.assertEqual(len(s["calls"]), 0)

    def test_original_read_changes_close_errors_and_expired_endpoint_are_not_success(self):
        with tempfile.TemporaryDirectory(prefix="mrk-stock-original-inert-") as folder:
            path = Path(folder) / "original"; M.D.write(path, b"original", 0o400)
            owner = (os.getuid(), os.getgid())
            with self.assertRaisesRegex(M.D.Refused, "original.*changed"):
                with M._stock_private_original(path, owner, 64, time.monotonic() + 10):
                    path.rename(path.with_name("retained")); M.D.write(path, b"original", 0o400)
            with patch.object(M.D, "_open", side_effect=AssertionError("expired must not open")), \
                 self.assertRaisesRegex(M.D.Refused, "endpoint expired"):
                with M._stock_private_original(path, owner, 64, time.monotonic() - 1): pass
            stream, before = M.D._open(path, 64)
            count = []
            class Original:
                def fileno(self): return stream.fileno()
                def read(self, n): return stream.read(n)
                def close(self):
                    count.append(None); stream.close(); raise OSError("inert close")
            primary = RuntimeError("original body failure")
            with patch.object(M.D, "_open", return_value=(Original(), before)), self.assertRaises(RuntimeError) as result:
                with M._stock_private_original(path, owner, 64, time.monotonic() + 10): raise primary
            self.assertIs(result.exception, primary); self.assertEqual(len(count), 1)
            self.assertEqual(primary.__notes__, ["Android stock original close also failed; no retry or successor."])
            stream, before = M.D._open(path, 64)
            reads = []
            class ChangeDuringRead:
                def fileno(self): return stream.fileno()
                def read(self, n):
                    block = stream.read(n)
                    if not reads:
                        path.rename(path.with_name("retained-during-read"))
                        with path.open("xb") as changed:
                            os.fchmod(changed.fileno(), 0o400); changed.write(b"original")
                    reads.append(None)
                    return block
                def close(self): stream.close()
            with patch.object(M.D, "_open", return_value=(ChangeDuringRead(), before)), \
                 self.assertRaises(M.D.Refused):
                with M._stock_private_original(path, owner, 64, time.monotonic() + 10):
                    self.fail("replaced original reached the parser")
            self.assertTrue(stream.closed)

    def test_empty_directory_inspection_is_bounded_closed_and_never_exports_names(self):
        reads, closes = [], []
        class Entry:
            @property
            def name(self): raise AssertionError("unexpected names must not be inspected")
        class Scan:
            def __enter__(self): return self
            def __exit__(self, *unused): closes.append(None)
            def __next__(self):
                reads.append(None)
                if len(reads) > 1: raise AssertionError("no census permitted")
                return Entry()
        with patch.object(M.os, "scandir", return_value=Scan()), self.assertRaisesRegex(M.D.Refused, "contains an entry"):
            M._empty_directory(Path("/inert"), time.monotonic() + 10)
        self.assertEqual((len(reads), len(closes)), (1, 1))


if __name__ == "__main__":
    unittest.main()
