"""Inert adapter slice: allocation values use the ORIGINAL version transaction.

OS/file/process calls are trapped by the existing version_adapter harness.
No project, native transaction, build or Store is exercised by these tests.
"""
from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace

from mobile_release import release_version_edit as edit
from mobile_release import version_allocation as allocation
from mobile_release import version_policy as policy
from mobile_release.config import ReleaseVersion

from test_release_version_edit import ORIGINAL, VersionLease, observed, version_adapter

PROJECT = "00000000-0000-4000-8000-000000000001"
CANDIDATE = "00000000-0000-4000-8000-000000000002"
IDENTITY = "a" * 64
NOW = 10000


def reserved(lease, enabled=("android", "ios")):
    source = policy.SourceBinding("b" * 40, "c" * 40, "refs/heads/main",
        hashlib.sha256(lease.config).hexdigest(), hashlib.sha256(ORIGINAL).hexdigest())
    base = ReleaseVersion("1.2.3", 7)
    request = allocation.AllocationRequest(PROJECT, CANDIDATE, IDENTITY, source, base,
        enabled, policy.VersionPolicy("automatic", (policy.RefRule(source.ref, "patch"),)))
    genesis = allocation.Genesis(PROJECT, "123", "00000000-0000-4000-8000-000000000003", base)
    observations = tuple(policy.StoreObservation(platform, IDENTITY, str(index + 1) * 64,
                         NOW, 7, "1.2.3") for index, platform in enumerate(request.enabled_platforms))
    reservation = allocation.Ledger(genesis).append(request, observations, now=NOW).reservations[0]
    return request, reservation


class VersionAllocationEditTests(unittest.TestCase):
    def test_reserved_pair_changes_only_original_two_spans_through_existing_transaction(self):
        with version_adapter():
            lease = VersionLease()
            checkout = edit.capture_release_version_edit(lease)
            request, reservation = reserved(lease)
            plan = allocation.prepare_reserved_version_edit(lease, checkout, checkout.revision,
                                                             checkout.baseline, reservation, request)
            expected = ORIGINAL.replace(b"'1.2.3'", b"'1.2.4'").replace(b'"7"', b'"8"')
            self.assertEqual(plan.view["file"]["after"]["text"].encode(), expected)
            self.assertEqual(plan.view["values"], {"name": "1.2.4", "build": "8"})
            result = edit.apply_release_version_edit(lease, plan)
            self.assertEqual((result.effect, result.journal, result.reason), ("committed", "clean", "none"))
            self.assertEqual(len(lease.applies), 1)
            self.assertEqual(lease.applies[0][0][1], expected)
            self.assertEqual(edit.apply_release_version_edit(lease, plan).effect, "not_started")

    def test_stale_revision_is_rejected_by_original_owner_without_apply(self):
        with version_adapter():
            lease = VersionLease()
            checkout = edit.capture_release_version_edit(lease)
            request, reservation = reserved(lease)
            with self.assertRaises(edit.ConfigEditFailure):
                allocation.prepare_reserved_version_edit(lease, checkout, "f" * 32,
                                                         checkout.baseline, reservation, request)
            self.assertEqual(lease.applies, [])

    def test_reservation_never_authorizes_different_source_or_checkout(self):
        with version_adapter():
            lease = VersionLease()
            checkout = edit.capture_release_version_edit(lease)
            request, reservation = reserved(lease)
            changed = replace(request, source=replace(request.source, version_sha256="f" * 64))
            changed_reservation = replace(reservation, request=changed)
            with self.assertRaises(allocation.VersionAllocationError) as caught:
                allocation.prepare_reserved_version_edit(lease, checkout, checkout.revision,
                                                         checkout.baseline, changed_reservation, changed)
            self.assertEqual(caught.exception.reason, "source-changed")
            with self.assertRaises(allocation.VersionAllocationError):
                allocation.prepare_reserved_version_edit(lease, object(), checkout.revision,
                                                         checkout.baseline, reservation, request)
            self.assertEqual(lease.applies, [])

    def test_changed_identity_same_candidate_cannot_borrow_previous_reservation(self):
        with version_adapter():
            lease = VersionLease()
            checkout = edit.capture_release_version_edit(lease)
            request, reservation = reserved(lease)
            with self.assertRaises(allocation.VersionAllocationError) as caught:
                allocation.prepare_reserved_version_edit(lease, checkout, checkout.revision,
                    checkout.baseline, reservation, replace(request, identity_revision="f" * 64))
            self.assertEqual(caught.exception.reason, "candidate-binding-conflict")
            self.assertEqual(lease.applies, [])

    def test_exact_captured_platform_tuple_rejects_ios_only_and_both_mismatches(self):
        for saved, requested in ((("ios",), ("android", "ios")), (("android", "ios"), ("ios",))):
            with self.subTest(saved=saved, requested=requested), version_adapter():
                lease = VersionLease()
                if saved == ("ios",):
                    data = json.loads(lease.config)
                    data["android"] = {"enabled": False}
                    lease.config = json.dumps(data).encode()
                    # Only the inert fixture changes, before the real capture.
                    lease.originals["release/mobile-release.json"] = observed(
                        "release/mobile-release.json", lease.config, 30)
                checkout = edit.capture_release_version_edit(lease)
                self.assertEqual(checkout.enabled_platforms, saved)
                request, reservation = reserved(lease, requested)
                self.assertEqual(request.source.configuration_sha256, checkout.baseline["savedConfig"]["sha256"])
                with self.assertRaises(allocation.VersionAllocationError) as caught:
                    allocation.prepare_reserved_version_edit(lease, checkout, checkout.revision,
                                                             checkout.baseline, reservation, request)
                self.assertEqual(caught.exception.reason, "source-changed")
                self.assertEqual(lease.applies, [])


if __name__ == "__main__":
    unittest.main()
