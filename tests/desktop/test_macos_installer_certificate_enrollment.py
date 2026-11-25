"""Bounded DATA/failure tests; no native OpenSSL, credentials or signing proof."""
import base64
import contextlib
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import resource
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("installer_bootstrap_test_subject", ROOT / "desktop/tools/macos_installer_certificate_enrollment.py")
SUBJECT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUBJECT)


class InstallerCertificateEnrollmentData(unittest.TestCase):
    def test_bounded_input_selection_and_fixed_source_workflow(self):
        m = SUBJECT
        self.assertEqual(m.EXPECTED_SHA1, "2176c921a318fd50510672b92022813c4e617fbd")
        self.assertEqual(m.SECRETS, ("MRK_MACOS_INSTALLER_P12_BASE64", "MRK_MACOS_INSTALLER_P12_PASSWORD"))
        self.assertEqual(m.REF, "refs/heads/verify/desktop-macos-installer-certificate-enrollment")
        self.assertEqual(m.WORKFLOW, ".github/workflows/desktop-macos-installer-certificate-enrollment.yml")
        self.assertEqual(m.credentials("eA==", "passé"), (b"x", "passé\n".encode()))
        self.assertEqual(len(m.credentials(base64.b64encode(b"x" * m.P12_LIMIT).decode(), "x")[0]), m.P12_LIMIT)
        for encoded, password in ((None, "x"), ("eA==\n", "x"), ("eB==", "x"), ("eA==", ""),
                                  ("eA==", "x\n"), ("eA==", "x\r"), ("eA==", "x\0"),
                                  ("eA==", "é" * 2049), ("eA==", "\ud800"),
                                  (base64.b64encode(b"x" * (m.P12_LIMIT + 1)).decode(), "x")):
            with self.subTest(case=(len(encoded) if isinstance(encoded, str) else None, len(password))):
                with self.assertRaises((m.Refused, ValueError, UnicodeError)):
                    m.credentials(encoded, password)
        leaf = b"INERT PUBLIC DER DATA"
        pem = b"-----BEGIN CERTIFICATE-----\n" + base64.b64encode(leaf) + b"\n-----END CERTIFICATE-----\n"
        with mock.patch.object(m, "EXPECTED_SHA1", hashlib.sha1(leaf).hexdigest()):
            self.assertEqual(m.select_leaf(b"Bag Attributes\n  friendlyName: PRIVATE FIXTURE\n" + pem), leaf)
            for bad in (pem + pem, pem * 9, pem.replace(b"CERTIFICATE", b"PRIVATE KEY"),
                        pem.replace(b"-----END", b"-----WRONG"), b"x" * (m.OUTPUT_LIMIT + 1)):
                with self.assertRaises((m.Refused, ValueError)):
                    m.select_leaf(bad)
        with self.assertRaises(m.Refused):
            m.select_leaf(pem)  # Synthetic bytes cannot qualify as the real authorized leaf.
        oversized = b"x" * (m.DER_LIMIT + 1)
        with mock.patch.object(m, "EXPECTED_SHA1", hashlib.sha1(oversized).hexdigest()), self.assertRaises(m.Refused):
            m.select_leaf(b"-----BEGIN CERTIFICATE-----\n" + base64.b64encode(oversized) + b"\n-----END CERTIFICATE-----\n")
        workflow = (ROOT / m.WORKFLOW).read_text()
        self.assertIn("branches:\n      - verify/desktop-macos-installer-certificate-enrollment", workflow)
        self.assertIn("environment: macos-developer-id", workflow)
        self.assertIn("runs-on: macos-26", workflow)
        self.assertIn("permissions:\n  contents: read\n", workflow)
        self.assertIn("if: success() && steps.enroll.outcome == 'success'", workflow)
        self.assertIn("retention-days: 1", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", workflow)
        self.assertEqual(workflow.count("secrets."), 2)
        self.assertIn("export -n MRK_MACOS_INSTALLER_P12_BASE64 MRK_MACOS_INSTALLER_P12_PASSWORD", workflow)
        for name in m.SECRETS:
            self.assertIn("${{ secrets." + name + " }}", workflow)
        self.assertNotIn("MRK_MACOS_DEVELOPER_ID_P12", workflow)
        self.assertNotIn("MRK_MACOS_NOTARY", workflow)
        self.assertIn("name: installer-public-leaf-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}", workflow)
        self.assertIn("path: ${{ runner.temp }}/mrk-installer-public-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}/leaf.der", workflow)
        self.assertNotIn("GITHUB_ENV", workflow)
        self.assertNotIn("always()", workflow)
        self.assertNotIn("codesign", workflow)
        self.assertNotIn("-nodes", workflow)
        # Positive admitted context is synthetic DATA, not a GitHub/Mac receipt.
        with tempfile.TemporaryDirectory() as temporary:
            checkout = Path(temporary) / "checkout"
            parent = Path(temporary) / "temp"
            (checkout / ".git").mkdir(parents=True)
            parent.mkdir()
            (checkout / ".git/HEAD").write_text("a" * 40 + "\n")
            env = {"GITHUB_SHA": "a" * 40, "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "push",
                   "GITHUB_REPOSITORY": m.REPOSITORY, "GITHUB_REF": m.REF, "GITHUB_WORKFLOW_SHA": "a" * 40,
                   "GITHUB_WORKFLOW_REF": m.REPOSITORY + "/" + m.WORKFLOW + "@" + m.REF,
                   "GITHUB_WORKSPACE": str(checkout), "MRK_EXPECTED_SHA": "a" * 40,
                   "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64",
                   "RUNNER_TEMP": str(parent), "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1"}
            with contextlib.ExitStack() as stack:
                for obj, key, value in ((m, "CHECKOUT", checkout), (m, "TEMP", parent),
                        (m, "__file__", str(checkout / "desktop/tools/macos_installer_certificate_enrollment.py")),
                        (m.sys, "platform", "darwin"), (m.os, "getuid", lambda: 501),
                        (m.os, "geteuid", lambda: 501), (m.os, "getgid", lambda: 20),
                        (m.os, "getegid", lambda: 20),
                        (m.os, "uname", lambda: os.uname_result(("Darwin", "DATA", "25.0", "DATA", "arm64")))):
                    stack.enter_context(mock.patch.object(obj, key, value))
                self.assertEqual(m.admit(env), (parent, parent / ("mrk-installer-public-" + "a" * 40 + "-1-1")))
                for key, value in (("GITHUB_REF", "refs/heads/main"), ("GITHUB_WORKFLOW_SHA", "b" * 40),
                                   ("GITHUB_EVENT_NAME", "pull_request"), ("GITHUB_RUN_ID", "9007199254740992")):
                    with self.assertRaises(m.Refused):
                        m.admit(dict(env, **{key: value}))
        # Pre-native DATA refusals, not a runner fallback.
        for env in ({}, {"GITHUB_SHA": "0" * 40}, {"GITHUB_SHA": "a" * 40, "GITHUB_REF": "refs/heads/main"}):
            with self.assertRaises(m.Refused):
                m.admit(env)

    def test_actual_private_files_cleanup_precedes_publication_and_failures_preserve_originals(self):
        m = SUBJECT
        leaf = b"INERT PUBLIC DER FOR PIPE AND FILE DATA"
        pem = b"Bag Attributes\n  friendlyName: NEVER PUBLISH THIS\n-----BEGIN CERTIFICATE-----\n" + base64.b64encode(leaf) + b"\n-----END CERTIFICATE-----\n"
        for case in ("success", "missing", "mismatch", "nonzero", "timeout", "oversize", "roundtrip", "cleanup", "existing"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                parent = Path(temporary)
                public = parent / "public"
                env = {m.SECRETS[0]: "SU5FUlQgRU5DUllQVEVEIERBVEE=", m.SECRETS[1]: "PRIVATE PASSWORD", "OTHER": "preserve"}
                if case == "missing":
                    del env[m.SECRETS[1]]
                if case == "existing":
                    public.mkdir()
                    (public / "original").write_bytes(b"preserve")
                calls, private_paths, cleanup_originals = [], [], []
                actual_temp = tempfile.TemporaryDirectory
                actual_mkdir = os.mkdir

                def mkdir(path, *args, **kwargs):
                    if Path(path) == public:
                        self.assertTrue(private_paths and all(not p.exists() for p in private_paths))
                    return actual_mkdir(path, *args, **kwargs)

                def temp_factory(*args, **kwargs):
                    td = actual_temp(*args, **kwargs)
                    private_paths.append(Path(td.name))
                    if case == "cleanup":
                        cleanup_originals.append(td.cleanup)
                        td.cleanup = mock.Mock(side_effect=OSError("PRIVATE cleanup detail"))
                    return td

                def call(argv, **kwargs):
                    calls.append((argv, kwargs))
                    self.assertTrue(all(key not in env and key not in kwargs["env"] for key in m.SECRETS))
                    self.assertNotIn("PRIVATE PASSWORD", repr(argv))
                    self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
                    self.assertFalse(kwargs["shell"])
                    self.assertTrue(kwargs["close_fds"])
                    self.assertLessEqual(kwargs["timeout"], 15)
                    self.assertGreater(kwargs["timeout"], 0)
                    self.assertIs(kwargs["preexec_fn"], m._file_output_limit)
                    self.assertEqual(set(kwargs["env"]), {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "OPENSSL_CONF"})
                    private = Path(kwargs["cwd"])
                    self.assertEqual(private.stat().st_mode & 0o777, 0o700)
                    self.assertEqual((private / "identity.p12").stat().st_mode & 0o777, 0o600)
                    self.assertEqual((private / "identity.p12").read_bytes(), b"INERT ENCRYPTED DATA")
                    self.assertFalse((public / "leaf.der").exists())
                    if len(calls) == 1:
                        self.assertEqual(argv, [m.OPENSSL, "pkcs12", "-in", str(private / "identity.p12"), "-nokeys", "-passin", "stdin"])
                        self.assertEqual(kwargs["input"], b"PRIVATE PASSWORD\n")
                    else:
                        self.assertEqual(argv, [m.OPENSSL, "x509", "-inform", "DER", "-outform", "DER"])
                        self.assertEqual(kwargs["input"], leaf)
                    if case == "timeout":
                        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
                    data = (pem if len(calls) == 1 else leaf)
                    if case == "oversize":
                        data = b"x" * (m.OUTPUT_LIMIT + 1)  # Injected output, not a waiver of real child RLIMIT.
                    if case == "roundtrip" and len(calls) == 2:
                        data = leaf + b"x"
                    kwargs["stdout"].write(data)
                    kwargs["stdout"].flush()
                    return subprocess.CompletedProcess(argv, 1 if case == "nonzero" else 0)

                expected = "0" * 40 if case == "mismatch" else hashlib.sha1(leaf).hexdigest()
                with mock.patch.object(m, "admit", return_value=(parent, public)), mock.patch.object(m, "EXPECTED_SHA1", expected), \
                        mock.patch.object(m.subprocess, "run", side_effect=call), \
                        mock.patch.object(m.resource, "setrlimit") as limits, \
                        mock.patch.object(m.tempfile, "TemporaryDirectory", side_effect=temp_factory), \
                        mock.patch.object(m.os, "mkdir", side_effect=mkdir):
                    if case == "success":
                        self.assertEqual(m.enroll(env), public / "leaf.der")
                    else:
                        with self.assertRaises(m.Refused) as caught:
                            m.enroll(env)
                        self.assertEqual(caught.exception.phase, {"missing": "inputs", "mismatch": "fingerprint",
                            "nonzero": "pkcs12", "timeout": "pkcs12", "oversize": "pkcs12", "roundtrip": "x509",
                            "cleanup": "private-cleanup", "existing": "publication"}[case])
                    limits.assert_called_with(resource.RLIMIT_CORE, (0, 0))
                self.assertTrue(all(kwargs["stdout"].closed for _argv, kwargs in calls))
                self.assertTrue(all(key not in env for key in m.SECRETS))
                self.assertEqual(env["OTHER"], "preserve")
                if case == "cleanup":
                    self.assertTrue(any(path.exists() for path in private_paths))
                    for cleanup in cleanup_originals:
                        cleanup()  # Test-owned failed-cleanup injection; no production success inferred.
                self.assertTrue(all(not path.exists() for path in private_paths))
                if case == "success":
                    self.assertEqual(len(calls), 2)
                    self.assertEqual(sorted(p.name for p in public.iterdir()), ["leaf.der"])
                    self.assertEqual((public / "leaf.der").read_bytes(), leaf)
                else:
                    self.assertFalse((public / "leaf.der").exists())
                if case == "existing":
                    self.assertEqual((public / "original").read_bytes(), b"preserve")

    def test_output_cap_deadline_and_fixed_failure_projection(self):
        m = SUBJECT
        with mock.patch.object(m.resource, "setrlimit") as limit:
            m._file_output_limit()
            limit.assert_called_once_with(resource.RLIMIT_FSIZE, (524288, 524288))
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(m.subprocess, "run") as run:
            with self.assertRaises(m.Refused):
                m._run([m.OPENSSL, "x509"], b"public", Path(temporary), "out", 0)
            run.assert_not_called()
            self.assertEqual(list(Path(temporary).iterdir()), [])
        output = io.StringIO()
        with mock.patch.object(m.sys, "argv", ["fixed-script"]), \
                mock.patch.object(m, "enroll", side_effect=RuntimeError("PRIVATE PASSWORD AND PATH")), \
                contextlib.redirect_stderr(output):
            self.assertEqual(m.main(), 1)
        self.assertEqual(output.getvalue(), "Public certificate enrollment refused: entry.\n")


if __name__ == "__main__":
    unittest.main()
