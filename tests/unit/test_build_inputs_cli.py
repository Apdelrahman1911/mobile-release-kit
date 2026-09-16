"""Synthetic public-entry QA-004 regression source; run only through the reviewed owner."""
from __future__ import annotations

import io
import json
import os
import tempfile
import threading
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path, PurePosixPath
from unittest.mock import patch

from mobile_release import build_inputs as inputs
from mobile_release import cli
from mobile_release.owned_process import ProcessError


class BuildInputCliTests(unittest.TestCase):
    session = "0123456789abcdef0123456789abcdef"
    confirmation = "project-build-inputs-are-idle-and-restore-owned-state"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="mrk-build-input-cli-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        (self.root / ".gitignore").write_text(".mobile-release/\n", encoding="utf-8")
        facility = patch.multiple(inputs, _ENV_LOCK=threading.Lock(), _ENV_OWNER=None,
                                  _ENV_TAINTED=False, _ENV_PID=os.getpid())
        facility.start()
        self.addCleanup(facility.stop)

    def command(self, operation, *options):
        outgoing, errors = io.StringIO(), io.StringIO()
        with ExitStack() as stack:
            for name in ("load_config", "discover_project", "credential_findings", "doctor", "preflight",
                         "prepare_store_operation", "execute_store_operation", "_local_signing"):
                stack.enter_context(patch.object(cli, name, side_effect=AssertionError(
                    "build-input recovery crossed into an unrelated consumer")))
            with redirect_stdout(outgoing), redirect_stderr(errors):
                code = cli.main(["build-inputs", operation, "--root", str(self.root), *options])
        return code, outgoing.getvalue(), errors.getvalue()

    def test_parser_requires_explicit_bounded_recovery_arguments(self):
        invalid = (
            ["status"],
            ["status", "--roo", str(self.root)],
            ["recover", "--root", str(self.root)],
            ["recover", "--root", str(self.root), "--session", self.session],
            ["recover", "--root", str(self.root), "--session", self.session,
             "--confirm", self.confirmation, "--force"],
            ["recover", "--root", str(self.root), "--session", self.session,
             "--confirm", self.confirmation, "--pid", "12345"],
        )
        for arguments in invalid:
            with self.subTest(arguments=arguments), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as failure:
                    cli.build_parser().parse_args(["build-inputs", *arguments])
                self.assertEqual(failure.exception.code, 2)

    def test_status_routes_before_consumers_and_emits_only_helper_status(self):
        state = {"status": "pending", "session": self.session, "roles": ["android-services"]}
        with patch.object(inputs, "build_inputs_status", return_value=state) as inspect:
            code, output, errors = self.command("status")
        inspect.assert_called_once_with(self.root)
        self.assertEqual((code, json.loads(output), errors), (1, state, ""))

    def test_manual_recovery_forwards_exact_binding_without_an_account_route(self):
        state = {"status": "recovered", "session": self.session}
        with patch.object(inputs, "recover_build_inputs", return_value=state) as recover:
            code, output, errors = self.command("recover", "--session", self.session,
                "--confirm", self.confirmation, "--manual")
        recover.assert_called_once_with(self.root, session=self.session,
                                        confirm=self.confirmation, manual=True)
        self.assertEqual((code, json.loads(output), errors), (0, state, ""))

    def test_root_traversal_is_not_normalized_into_another_recovery_project(self):
        with patch.object(inputs, "build_inputs_status") as inspect:
            code, output, errors = self.command("status", "--root", str(self.root / ".." / "other-project"))
        inspect.assert_not_called()
        self.assertEqual((code, output), (2, ""))
        self.assertIn("must not contain '..'", errors)
        with patch.object(Path, "expanduser", side_effect=RuntimeError("private-home-diagnostic")), \
                patch.object(inputs, "build_inputs_status") as inspect:
            code, output, errors = self.command("status")
        inspect.assert_not_called()
        self.assertEqual((code, output), (2, ""))
        self.assertIn("home expansion is unavailable", errors)
        self.assertNotIn("private-home-diagnostic", errors)

    def test_bad_session_or_confirmation_rejects_before_project_inspection(self):
        for session, confirm in ((self.session.upper(), self.confirmation), (self.session, "different")):
            with self.subTest(session=session, confirm=confirm), patch.object(inputs, "_inspection") as inspect:
                code, output, _ = self.command("recover", "--session", session, "--confirm", confirm)
            inspect.assert_not_called()
            self.assertEqual((code, output), (2, ""))

    def test_filesystem_failure_is_bounded_and_interruption_is_not_success(self):
        private_diagnostic = "synthetic-private-path-not-for-output"
        with patch.object(inputs, "build_inputs_status", side_effect=OSError(private_diagnostic)):
            code, output, errors = self.command("status")
        self.assertEqual((code, output), (2, ""))
        self.assertNotIn(private_diagnostic, errors)
        self.assertIn("preserve private state", errors)
        with patch.object(inputs, "build_inputs_status", side_effect=KeyboardInterrupt):
            code, output, errors = self.command("status")
        self.assertEqual((code, output), (130, ""))
        self.assertIn("interrupted", errors)

    def test_actual_public_recovery_preserves_foreign_edit_and_restores_recorded_original(self):
        target = self.root / "google-services.json"
        target.write_bytes(b"synthetic-original")
        before = target.stat().st_ino
        with self.assertRaises(ProcessError):
            with inputs.invocation_custody(self.root, mode="build") as invocation:
                with invocation.project(signing_lease=None):
                    with invocation.materialization(signing_lease=None) as owner:
                        owner.replace_all((inputs.TargetReplacement("android-services",
                            PurePosixPath(target.name), b"synthetic-publication"),))
                        target.write_bytes(b"synthetic-intervening-edit")
        code, output, errors = self.command("status")
        state = json.loads(output)
        self.assertEqual((code, state["status"], errors), (1, "pending", ""))
        options = ("--session", state["session"], "--confirm", self.confirmation)
        code, output, _ = self.command("recover", *options)
        self.assertEqual((code, output), (2, ""))
        self.assertEqual(target.read_bytes(), b"synthetic-intervening-edit")

        # Preserve only this independently identified fixture-owned edit, outside
        # the reserved journal, before explicitly freeing its original name.
        saved = self.root / "saved-intervening-edit"
        self.assertFalse(saved.exists())
        target.rename(saved)
        code, output, errors = self.command("recover", *options)
        self.assertEqual((code, json.loads(output)["status"], errors), (0, "recovered", ""))
        self.assertEqual((target.read_bytes(), target.stat().st_ino), (b"synthetic-original", before))
        self.assertEqual(saved.read_bytes(), b"synthetic-intervening-edit")
        code, output, _ = self.command("recover", *options)
        self.assertEqual((code, json.loads(output)["status"]), (0, "absent"))


if __name__ == "__main__":
    unittest.main()
