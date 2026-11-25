"""Inert fixed-role framing/budget checks: no credential, socket, or native job.

The separately reviewed version-allocation module must be integrated for its
two endpoint/body tests; all other tests exercise the original finite reader.
"""
from __future__ import annotations

import importlib.util
import io
import unittest

from mobile_release import _github_connection_transport as transport


PROFILE = transport._ExchangeProfile.VERSION_ALLOCATION
ROLE = transport._ResponseRole
ROOT = "/repos/synthetic-owner/synthetic-repository"
LEDGER = ROOT + "/contents/release/.mrk-version-allocations-v1.json"
SHA = "1" * 40


class VersionAllocationTransportHookTests(unittest.TestCase):
    def budget(self):
        return transport._Budget(0.0, monotonic=lambda: 1.0, wall=lambda: 100.0, _profile=PROFILE)

    def read(self, status, role, body=b'{"message":"private synthetic error"}', headers=b""):
        head = (b"HTTP/1.1 " + str(status).encode() + b" Synthetic\r\nContent-Type: application/json\r\n"
                + b"Content-Length: " + str(len(body)).encode() + b"\r\n" + headers + b"\r\n")
        source, budget = io.BytesIO(head + body), self.budget()
        reader = transport._ResponseBody(source, budget, _role=role)
        return transport._response_result(reader, budget), source.tell(), len(head)

    def require_validators(self):
        if importlib.util.find_spec("mobile_release.version_allocation_transport") is None:
            self.skipTest("requires reviewed version-allocation lane integration")

    def test_new_roles_cannot_borrow_existing_profiles(self):
        for role in transport._ALLOCATION_ROLES:
            self.assertEqual(transport._role_limits(PROFILE, role), (256 * 1024, 1024))
            for other in transport._ExchangeProfile:
                if other is not PROFILE:
                    with self.subTest(role=role, profile=other), self.assertRaises(ValueError):
                        transport._role_limits(other, role)
        # STANDARD can validate private factory initialization, not an endpoint.
        self.assertEqual(transport._role_limits(PROFILE, ROLE.STANDARD), (256 * 1024, 1024))
        for other in (ROLE.PUBLICATION_CREATE, ROLE.SETUP_SECRET_WRITE, ROLE.RELEASE_CONFIG):
            with self.assertRaises(ValueError):
                transport._role_limits(PROFILE, other)

    def test_original_budget_is_sixty_seconds_one_mib_and_ten_wire_claims(self):
        budget = self.budget()
        self.assertEqual(budget.end, 60.0)
        self.assertEqual(budget.body_total_limit, 1024 * 1024)
        for _ in range(10):
            budget.claim_request()
        with self.assertRaises(transport.ReadFailure) as failure:
            budget.claim_request()
        self.assertEqual(failure.exception.reason, "response-limit")
        self.assertEqual(budget.requests, 10)
        budget.monotonic = lambda: 60.0
        with self.assertRaises(transport.ReadFailure):
            budget.remaining()

    def test_shared_endpoint_hook_uses_only_fixed_roles_and_pinned_paths(self):
        self.require_validators()
        endpoints = (
            (ROLE.VERSION_ALLOCATION_REPOSITORY, "GET", ROOT),
            (ROLE.VERSION_ALLOCATION_REF, "GET", ROOT + "/git/ref/heads/mrk-version-allocations"),
            (ROLE.VERSION_ALLOCATION_COMPARE, "GET", ROOT + "/compare/" + SHA + "..." + "2" * 40 + "?per_page=1&page=1"),
            (ROLE.VERSION_ALLOCATION_LEDGER_READ, "GET", LEDGER + "?ref=" + SHA),
            (ROLE.VERSION_ALLOCATION_LEDGER_WRITE, "PUT", LEDGER),
        )
        for role, method, path in endpoints:
            self.assertEqual(transport._request_limits(PROFILE, role, method, path), (256 * 1024, 1024))
            for wrong in (path + "#fragment", "https://api.github.com" + path, path + "&page=2"):
                with self.assertRaises(ValueError):
                    transport._request_limits(PROFILE, role, method, wrong)
            with self.assertRaises(ValueError):
                transport._request_limits(PROFILE, role, "DELETE", path)
        for role, path in ((ROLE.STANDARD, "/user"), (ROLE.STANDARD, ROOT),
                           (ROLE.VERSION_ALLOCATION_LEDGER_READ, LEDGER + "?ref=main")):
            with self.assertRaises(ValueError):
                transport._request_limits(PROFILE, role, "GET", path)

    def test_shared_body_hook_does_not_allow_generic_put_or_get_bodies(self):
        self.require_validators()
        transport._allocation_body(PROFILE, ROLE.VERSION_ALLOCATION_REPOSITORY, None, path=ROOT)
        for role, body, path in ((ROLE.VERSION_ALLOCATION_REPOSITORY, b"{}", ROOT),
                                 (ROLE.VERSION_ALLOCATION_LEDGER_WRITE, b"{}", LEDGER),
                                 (ROLE.VERSION_ALLOCATION_LEDGER_WRITE, None, LEDGER),
                                 (ROLE.STANDARD, None, ROOT)):
            with self.assertRaises(ValueError):
                transport._allocation_body(PROFILE, role, body, path=path)
        with self.assertRaises(ValueError):
            transport._allocation_body(transport._ExchangeProfile.STANDARD,
                                       ROLE.VERSION_ALLOCATION_LEDGER_WRITE, b"{}", path=LEDGER)

    def test_only_conditional_write_conflicts_are_status_only_without_body_read(self):
        for status in (409, 422):
            result, consumed, header_size = self.read(status, ROLE.VERSION_ALLOCATION_LEDGER_WRITE)
            self.assertEqual(result.observation, {"status": status, "body": None, "failure": "none"})
            self.assertEqual(result.control["reason"], "none")
            self.assertEqual(consumed, header_size)
            for other in transport._ALLOCATION_ROLES - {ROLE.VERSION_ALLOCATION_LEDGER_WRITE}:
                result, consumed, header_size = self.read(status, other)
                self.assertEqual(result.observation["failure"], "response-invalid")
                self.assertEqual(consumed, header_size)

    def test_conflict_does_not_erase_cooldown_or_malformed_control(self):
        result, consumed, header_size = self.read(409, ROLE.VERSION_ALLOCATION_LEDGER_WRITE,
                                                 headers=b"Retry-After: 30\r\n")
        self.assertEqual(result.control["reason"], "response-invalid")
        self.assertEqual(result.control["cooldownSeconds"], 30)
        self.assertEqual(consumed, header_size)
        result, consumed, header_size = self.read(422, ROLE.VERSION_ALLOCATION_LEDGER_WRITE,
                                                 headers=b"Retry-After: not-a-delay\r\n")
        self.assertEqual(result.observation["failure"], "response-invalid")
        self.assertEqual(consumed, header_size)

    def test_existing_contents_update_admits_only_200_not_create_201(self):
        result, _, _ = self.read(200, ROLE.VERSION_ALLOCATION_LEDGER_WRITE, body=b'{"content":{},"commit":{}}')
        self.assertEqual(result.observation["status"], 200)
        self.assertEqual(result.control["reason"], "none")
        for status in (201, 204):
            result, consumed, header_size = self.read(status, ROLE.VERSION_ALLOCATION_LEDGER_WRITE)
            self.assertEqual(result.observation["failure"], "response-invalid")
            self.assertEqual(consumed, header_size)
        result, _, _ = self.read(200, ROLE.VERSION_ALLOCATION_LEDGER_READ, body=b"x" * (256 * 1024 + 1))
        self.assertEqual(result.observation["failure"], "response-limit")


if __name__ == "__main__":
    unittest.main()
