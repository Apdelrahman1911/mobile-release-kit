"""Actual fixed hooks with inert streams/mocked native IO, never HTTP or processes.

Requires the accompanying shared-hook patch; no missing-hook skip/fallback.
"""
from __future__ import annotations

import io
import unittest
from unittest.mock import patch

from mobile_release import _desktop_github_setup_engine as engine
from mobile_release import _github_connection_transport as transport
from mobile_release import desktop_version_enrollment as worker
from mobile_release import version_enrollment as enrollment
from mobile_release import version_allocation as allocation
from test_version_enrollment import TARGET, initial_frame


PROFILE = transport._ExchangeProfile.VERSION_ENROLLMENT
ROLE = transport._ResponseRole
ROOT = "/repos/" + TARGET.repository


class EnrollmentTransportTests(unittest.TestCase):
    def test_actual_profile_admits_only_six_fixed_get_roles_and_pinned_paths(self):
        endpoints = (
            (ROLE.VERSION_ENROLLMENT_ACCOUNT, "/user"),
            (ROLE.VERSION_ENROLLMENT_REPOSITORY, ROOT),
            (ROLE.VERSION_ENROLLMENT_PROTECTION, ROOT + "/branches/" + allocation.LEDGER_BRANCH + "/protection"),
            (ROLE.VERSION_ENROLLMENT_REF, ROOT + "/git/ref/heads/" + allocation.LEDGER_BRANCH),
            (ROLE.VERSION_ENROLLMENT_LEDGER, ROOT + "/contents/" + allocation.LEDGER_PATH + "?ref=" + "1" * 40),
            (ROLE.VERSION_ENROLLMENT_COMPARE, ROOT + "/compare/" + "1" * 40 + "..." + "2" * 40 + "?per_page=1&page=1"),
        )
        for role, path in endpoints:
            self.assertEqual(transport._request_limits(PROFILE, role, "GET", path), (256 * 1024, 1024))
            enrollment.validate_body(role.value, None, path=path)
            for other in transport._ExchangeProfile:
                if other is not PROFILE:
                    with self.assertRaises(ValueError):
                        transport._request_limits(other, role, "GET", path)
            for method in ("POST", "PUT", "DELETE"):
                with self.assertRaises(ValueError):
                    transport._request_limits(PROFILE, role, method, path)
            for wrong in (path + "/", path + "&page=2", "https://api.github.com" + path):
                with self.assertRaises(ValueError):
                    transport._request_limits(PROFILE, role, "GET", wrong)
            with self.assertRaises(ValueError):
                enrollment.validate_body(role.value, b"{}", path=path)
        with self.assertRaises(ValueError):
            transport._request_limits(PROFILE, ROLE.STANDARD, "GET", "/user")
        with self.assertRaises(ValueError):
            transport._request_limits(PROFILE, ROLE.VERSION_ENROLLMENT_LEDGER, "GET",
                                      ROOT + "/contents/" + allocation.LEDGER_PATH + "?ref=main")

    def test_actual_budget_keeps_sixty_seconds_one_mib_and_ten_actual_attempts(self):
        budget = transport._Budget(100.0, monotonic=lambda: 101.0, _profile=PROFILE)
        self.assertEqual((budget.end, budget.body_total_limit), (160.0, 1024 * 1024))
        for _ in range(10):
            budget.claim_request()
        with self.assertRaises(transport.ReadFailure) as caught:
            budget.claim_request()
        self.assertEqual(caught.exception.reason, "response-limit")
        self.assertEqual(budget.requests, 10)
        for now in (99.0, 160.0, float("nan")):
            budget.monotonic = lambda: now
            with self.assertRaises(transport.ReadFailure):
                budget.remaining()

    def test_response_cap_and_failure_control_use_original_bounded_reader(self):
        def read(body, extra=b"", status=200):
            budget = transport._Budget(0.0, monotonic=lambda: 1.0, wall=lambda: 100.0, _profile=PROFILE)
            head = (f"HTTP/1.1 {status} Synthetic\r\nContent-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\n").encode() + extra + b"\r\n"
            source = io.BytesIO(head + body)
            return transport._response_result(transport._ResponseBody(source, budget,
                _role=ROLE.VERSION_ENROLLMENT_LEDGER), budget)
        self.assertEqual(read(b"{}").control["reason"], "none")
        self.assertEqual(read(b"x" * (256 * 1024 + 1)).observation["failure"], "response-limit")
        failed = read(b'{"message":"private synthetic error"}', b"Retry-After: 30\r\n", 429)
        self.assertEqual(failed.control["reason"], "rate-limited")
        self.assertEqual(failed.control["cooldownSeconds"], 30)
        self.assertIsNone(failed.observation["body"])

    def test_native_reader_factory_borrows_only_existing_exchange_with_exact_profile(self):
        result = transport.ReadResult({"status": 200, "body": {"id": 456}, "failure": "none"}, transport._control())
        with patch.object(transport, "_make_live_exchange", return_value=lambda *a, **k: result) as factory:
            reader = enrollment.make_reader(TARGET, "inert-placeholder", previous=None,
                                            started=100.0, runtime_dir="/synthetic-runtime")
            factory.assert_called_once_with("inert-placeholder", started=100.0,
                runtime_dir="/synthetic-runtime", api_version="2026-03-10", _profile=PROFILE)
            self.assertIs(reader.read("account"), result)

    def test_same_bootstrap_dispatch_and_consuming_closes_on_success_or_failure(self):
        for failure, expected in ((None, 0), (RuntimeError("synthetic"), 70), (KeyboardInterrupt(), 130)):
            with patch.object(engine.time, "monotonic", return_value=101.0), \
                 patch.object(engine.os, "dup", side_effect=[20, 21]), \
                 patch.object(engine.os, "set_inheritable"), patch.object(engine.os, "open", return_value=22), \
                 patch.object(engine.os, "dup2"), patch.object(engine.os, "close") as close, \
                 patch.object(engine, "_read_initial", return_value=initial_frame()), \
                 patch.object(worker, "run_owned", side_effect=failure) as run, \
                 patch.object(engine.policy, "parse_initial", side_effect=AssertionError("wrong profile")):
                self.assertEqual(engine.main(started=100.0, runtime_dir="/synthetic-runtime"), expected)
                run.assert_called_once_with(20, 21, initial_frame(), started=100.0, runtime_dir="/synthetic-runtime")
                self.assertEqual([c.args[0] for c in close.call_args_list], [22, 21, 20])


if __name__ == "__main__":
    unittest.main()
