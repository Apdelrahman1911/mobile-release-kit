"""Focused inert smoke-input/mapping contracts; no candidate/runtime execution.

Tiny ordinary files are non-executable fixture DATA. The native observer is
never called; no SSL/resource/XML import, real proc read, socket or child occurs.
Select this class only after the distinct source/command review.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def source_module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


P = source_module("conventional_smoke_data", "desktop/tools/probe_cpython_source_runtime.py")
I = source_module("conventional_smoke_inputs", "desktop/tools/cpython_static_inputs.py")


def forbidden(*_args, **_kwargs):
    raise AssertionError("native operation or unadmitted path reached")


def manifest(rows=None):
    if rows is None:
        rows = [{"path": name, "size": 5, "sha256": P._digest(b"inert")} for name in sorted(P.SELECTED)]
        for row in rows:
            if row["path"] == "github-ca.pem":
                row.update(size=P.CA[0], sha256=P.CA[1])
    return {"schemaVersion": 1, "protocol": 1, "coreVersion": "0.3.0", "target": P.TARGET,
            "protocolSha256": "a" * 64, "coreSha256": next(row["sha256"] for row in rows if row["path"] == "core.zip"),
            "inventorySha256": P._digest(P._canonical(rows)), "files": rows}


def selected(document):
    raw = P._canonical(document) + b"\n"
    return P._selected_records(raw, P._digest(raw), "a" * 64)


class ConventionalRuntimeSmokeTests(unittest.TestCase):
    def test_missing_prepared_pins_refuse_before_path_or_observer(self):
        self.assertIsNone(P.APPROVED_PREPARED_MANIFEST_SHA256)
        self.assertIsNone(P.APPROVED_PROTOCOL_SHA256)
        with patch.multiple(P, Path=forbidden, _read=forbidden, _observe=forbidden):
            with self.assertRaises(P.SmokeRefused):
                P.inspect_prepared(object())
            with self.assertRaises(P.SmokeRefused):
                P.main()

    def test_exact_conventional_sixty_ca_and_profile_are_reused(self):
        self.assertEqual(P.EXPECTED_BUILTINS,
                         tuple(sorted(I.BOOTSTRAP_MODULES + I.INTRINSIC_MODULES + I.SOURCE_STATIC_MODULES)))
        self.assertEqual(len(set(P.EXPECTED_BUILTINS)), 60)
        self.assertEqual(P.CA, I.SOURCE_CA)
        self.assertEqual(P.PROFILE, I.SOURCE_PROFILE)
        self.assertTrue({"_ssl", "_socket", "pyexpat", "resource"} <= set(P.EXPECTED_BUILTINS))

    def test_openssl_release_token_is_exact_bounded_printable_data(self):
        self.assertTrue(P._openssl_version("OpenSSL 3.5.8 inert-release-text"))
        for value in (None, (3, 5, 0, 8, 0), "OpenSSL 3.5.7 inert", "OpenSSL 3.5.80 inert",
                      "OpenSSL 3.5.8-dev inert", "LibreSSL 3.5.8 inert", "OpenSSL 3.5.8",
                      "OpenSSL 3.5.8 inert\n", "OpenSSL 3.5.8 \x00", "OpenSSL 3.5.8 \u0080",
                      "OpenSSL 3.5.8 " + "x" * 128):
            with self.subTest(value=value):
                self.assertFalse(P._openssl_version(value))

    def test_public_diagnostic_keeps_only_known_codes_or_fixed_categories(self):
        secret = "INERT_PRIVATE_MARKER/unknown-input\n"
        cases = ((P.SmokeRefused("candidate-openssl-version"), "candidate-openssl-version"),
                 (P.SmokeRefused(secret), "unrecognized-refusal"),
                 (P.SmokeRefused("prepared-body-pin", secret), "unrecognized-refusal"),
                 (ImportError(secret), "import-failed"), (OSError(secret), "io-failed"),
                 (ValueError(secret), "data-or-api-failed"), (KeyboardInterrupt(secret), "interrupted"),
                 (RuntimeError(secret), "unexpected-exception"))
        with patch.multiple(P, Path=forbidden, _read=forbidden, _observe=forbidden):
            for error, code in cases:
                with self.subTest(category=code):
                    diagnostic = P._diagnostic(error)
                    self.assertEqual(diagnostic, f"Conventional runtime smoke refused or failed [{P.SCOPE}]: "
                                     f"{code}; preserve original evidence.\n")
                    self.assertLessEqual(len(diagnostic.encode("ascii")), 256)
                    self.assertNotIn(secret, diagnostic)

    def test_prepared_records_require_real_pins_and_exact_selected_roster(self):
        original = manifest()
        self.assertEqual([row["path"] for row in selected(original)], sorted(P.SELECTED))
        mutations = []
        for key, value in (("target", "unselected"), ("protocol", True), ("protocolSha256", "b" * 64),
                           ("coreSha256", "c" * 64), ("inventorySha256", "d" * 64)):
            mutations.append({**original, key: value})
        for rows in (original["files"][:-1], original["files"] + [original["files"][0]], list(reversed(original["files"]))):
            mutations.append(manifest(rows))
        for change in ({"size": True}, {"sha256": "e" * 64}, {"size": 0}, {"extra": False}):
            rows = [dict(row) for row in original["files"]]
            next(row for row in rows if row["path"] == "github-ca.pem").update(change)
            mutations.append(manifest(rows))
        for value in mutations:
            with self.subTest(document=value), self.assertRaises(P.SmokeRefused):
                selected(value)
        raw = P._canonical(original) + b"\n"
        with self.assertRaises(P.SmokeRefused):
            P._selected_records(raw, "f" * 64, "a" * 64)
        duplicate = raw.replace(b'"protocol":1', b'"protocol":1,"protocol":1')
        with self.assertRaises(P.SmokeRefused):
            P._selected_records(duplicate, P._digest(duplicate), "a" * 64)

    def test_selected_file_bodies_and_checkout_bootstrap_are_checked_without_execution(self):
        # Only the private DATA inspector receives fictional pins. The public
        # entry's absent source admission is never opened by these fixtures.
        ca = b"inert-not-a-certificate\n"
        with tempfile.TemporaryDirectory() as temporary, patch.object(P, "CA", (len(ca), P._digest(ca))), \
                patch.object(P, "_observe", side_effect=forbidden):
            base = Path(temporary)
            runtime = base / "runtime"
            runtime.mkdir()
            source = base / "engine_bootstrap.py"
            source.write_bytes(b"inert")
            rows = []
            for name in sorted(P.SELECTED):
                path = runtime / name
                path.parent.mkdir(parents=True, exist_ok=True)
                raw = ca if name == "github-ca.pem" else b"inert"
                path.write_bytes(raw)
                rows.append({"path": name, "size": len(raw), "sha256": P._digest(raw)})
            raw = P._canonical(manifest(rows)) + b"\n"
            (runtime / "manifest.json").write_bytes(raw)
            args = (runtime, P._digest(raw), "a" * 64, source)
            self.assertEqual(P._inspect_prepared(*args)["files"], rows)
            inert_dso = runtime / "python/lib/libssl.so.3"
            metadata = inert_dso.stat()
            identity = (P.os.major(metadata.st_dev), P.os.minor(metadata.st_dev), metadata.st_ino)
            self.assertEqual(P._read(inert_dso, 5, identity), b"inert")
            with self.assertRaises(P.SmokeRefused):
                P._read(inert_dso, 5, (*identity[:2], identity[2] + 1))
            (runtime / "python/bin/python3").write_bytes(b"other")
            with self.assertRaises(P.SmokeRefused):
                P._inspect_prepared(*args)
            (runtime / "python/bin/python3").write_bytes(b"inert")
            source.write_bytes(b"other")
            with self.assertRaises(P.SmokeRefused):
                P._inspect_prepared(*args)

    def test_private_maps_require_two_exact_backings_not_filenames_or_vma_count(self):
        paths = {name: "/inert/runtime/python/lib/" + name for name in ("libssl.so.3", "libcrypto.so.3")}
        lines = [f"1000-2000 {mode} 00000000 07:03 500 {path}" for path in paths.values()
                 for mode in ("r--p", "r-xp", "r-xp")]
        raw = ("\n".join(lines) + "\n").encode()
        with patch.object(P, "Path", side_effect=forbidden):
            self.assertEqual(P._mapped_private_rows(raw, paths), {name: (7, 3, 500) for name in paths})
            bad = [raw.replace(b"/inert/runtime/python/lib/libssl", b"/usr/lib/libssl"),
                   raw.replace(b"libssl.so.3", b"libssl.so.3 (deleted)"),
                   raw.replace(b"libssl.so.3", b"libssl.so.1"),
                   raw.replace(b"07:03", b"not-device", 1), raw.replace(b" 500 ", b" 0 ", 1),
                   raw.replace(b"r-xp", b"r--p"), raw.replace(b" 500 ", b" 501 ", 1),
                   b"x" * ((1 << 20) + 1)]
            for value in bad:
                with self.subTest(mapping=value[:120]), self.assertRaises(P.SmokeRefused):
                    P._mapped_private_rows(value, paths)

    def test_fixed_two_case_source_does_not_change_old_suite_or_retention(self):
        source = (ROOT / "desktop/src-tauri/src/conventional_smoke_tests.rs").read_text()
        self.assertIn('const CASES: [&str; 2] = ["core-capabilities", "core-zip-catalog"];', source)
        self.assertIn('Case::new(&inputs, name, None, true)', source)
        self.assertIn('const SCOPE: &str = "conventional-runtime-bootstrap-smoke-v1";', source)
        settle = source.index('if !case.settle(checked.is_err()).await')
        hold = source.index('pending::<()>().await;', settle)
        facts = source.index('case.native_facts(true, true)', hold)
        reset = source.index('std::env::set_var("MRK_DESKTOP_DEV_CORE", &inputs.source)', facts)
        self.assertLess(settle, hold)
        self.assertLess(hold, facts)
        self.assertLess(facts, reset)
        self.assertIn('prepared_bindings(&inputs, manifest_sha, protocol_sha)', source[:settle])
        old = (ROOT / "desktop/src-tauri/src/hosted_tests.rs").read_text()
        self.assertIn('"scope":"passive-hosted-v2"', old)
        self.assertIn('async fn passive_hosted_contract()', old)
        self.assertNotIn('load_default_certs(', (ROOT / "desktop/tools/probe_cpython_source_runtime.py").read_text())


if __name__ == "__main__":
    unittest.main()
