"""Explicit v2 values reach the ORIGINAL version writer through inert custody.

Provider replies, journal and version workspace are synthetic; no actual Store,
process, native receipt, project IO or native durability is claimed.
"""
from dataclasses import replace
import hashlib
import json
import unittest

from mobile_release import ios_store_versions as inventory
from mobile_release import release_version_edit as edit
from mobile_release import version_allocation as allocation
from mobile_release import version_policy as policy
from mobile_release.config import ReleaseVersion
from test_release_version_edit import ORIGINAL, VersionLease, observed, version_adapter
from tests.unit.test_version_allocation import Journal, Repository, initial, PROJECT, CANDIDATE, COMMIT, IDENTITY, NOW


def selected(lease):
    source = policy.SourceBinding("b" * 40, "c" * 40, "refs/heads/main",
        hashlib.sha256(lease.config).hexdigest(), hashlib.sha256(ORIGINAL).hexdigest())
    return allocation.AllocationRequest(PROJECT, CANDIDATE, IDENTITY, source, ReleaseVersion("1.2.3", 7),
        ("ios",), policy.VersionPolicy("automatic", (policy.RefRule(source.ref, "patch"),),
        store_scope=inventory.POLICY_SCOPE), "d" * 64)


def current():
    return (inventory.CurrentInventory(IDENTITY, "d" * 64, "e" * 64, NOW, 9, "1.3.0", (0, 1, 0)),)


def ios_lease():
    lease = VersionLease()
    data = json.loads(lease.config)
    data["android"] = {"enabled": False}
    lease.config = json.dumps(data).encode()
    lease.originals["release/mobile-release.json"] = observed("release/mobile-release.json", lease.config, 30)
    return lease


class IOSReservedEditTests(unittest.TestCase):
    def test_original_allocation_then_current_inventory_prepares_only_exact_version_spans(self):
        with version_adapter():
            lease = ios_lease()
            checkout = edit.capture_release_version_edit(lease)
            request = selected(lease)
            genesis, authority = initial()
            journal = Journal(authority, allocation.Checkpoint(0, genesis.head_sha256, COMMIT))
            remote = Repository(genesis, authority)
            reserved = allocation.allocate_version(request, authority, remote, journal,
                observations=current(), clock=lambda: NOW)
            self.assertEqual(reserved.status, "reserved")
            plan = allocation.prepare_reserved_version_edit(lease, checkout, checkout.revision,
                checkout.baseline, reserved.reservation, request, current_inventory=current(), now=NOW)
            expected = ORIGINAL.replace(b"'1.2.3'", b"'1.3.1'").replace(b'"7"', b'"10"')
            self.assertEqual(plan.view["file"]["after"]["text"].encode(), expected)
            result = edit.apply_release_version_edit(lease, plan)
            self.assertEqual((result.effect, result.journal, result.reason), ("committed", "clean", "none"))
            self.assertEqual(len(lease.applies), 1)
            self.assertEqual(lease.applies[0][0][1], expected)
            self.assertEqual(edit.apply_release_version_edit(lease, plan).effect, "not_started")
            repeated = allocation.allocate_version(request, authority, remote, journal,
                observations=(), clock=lambda: NOW + 9999)
            self.assertEqual(repeated.reservation, reserved.reservation)
            self.assertEqual(len(remote.writes), 1)

    def test_old_or_consumed_inventory_cannot_preview_and_retry_never_renumbers(self):
        with version_adapter():
            lease = ios_lease()
            checkout = edit.capture_release_version_edit(lease)
            request = selected(lease)
            genesis, _ = initial()
            reservation = genesis.append(request, current(), now=NOW).reservations[0]
            for observation, now in ((None, None), ((), NOW),
                (current(), NOW + 901), ((replace(current()[0], max_build=10),), NOW),
                ((replace(current()[0], context_revision="f" * 64),), NOW),
                ((replace(current()[0], identity_revision="f" * 64),), NOW)):
                with self.subTest(observation=observation is None, now=now), self.assertRaises(policy.VersionPolicyError):
                    allocation.prepare_reserved_version_edit(lease, checkout, checkout.revision,
                        checkout.baseline, reservation, request, current_inventory=observation, now=now)
            self.assertEqual(lease.applies, [])
            self.assertEqual(reservation.version, ReleaseVersion("1.3.1", 10))
            changed = replace(request, source=replace(request.source, version_sha256="f" * 64))
            with self.assertRaises(allocation.VersionAllocationError):
                allocation.prepare_reserved_version_edit(lease, checkout, checkout.revision,
                    checkout.baseline, replace(reservation, request=changed), changed,
                    current_inventory=current(), now=NOW)
            self.assertEqual(lease.applies, [])


if __name__ == "__main__":
    unittest.main()
