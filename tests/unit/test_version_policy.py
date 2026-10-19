"""Synthetic policy tests only: no Store, native tool or project mutation."""
from __future__ import annotations

import unittest
from dataclasses import replace
from unittest.mock import patch

from mobile_release.config import ReleaseVersion
from mobile_release import version_policy as p

IDENTITY = "a" * 64
NOW = 10_000
BASE = ReleaseVersion("1.2.3", 7)


def policy(increment="build", **kwargs):
    return p.VersionPolicy("automatic", (p.RefRule("refs/heads/main", increment),), **kwargs)


def observations(enabled=("android",), **kwargs):
    return tuple(p.StoreObservation(platform, IDENTITY, str(index + 1) * 64,
                                   NOW, 7, "1.2.3", **kwargs)
                 for index, platform in enumerate(enabled))


def propose(selected=None, **kwargs):
    args = dict(source="refs/heads/main", base=BASE, allocated=BASE, enabled=("android",),
                identity_revision=IDENTITY, observations=observations(), now=NOW)
    args.update(kwargs)
    return p.propose_version(selected or policy(), **args)


class VersionPolicyTests(unittest.TestCase):
    def refused(self, reason, call):
        with self.assertRaises(p.VersionPolicyError) as raised:
            call()
        self.assertEqual(raised.exception.reason, reason)
        self.assertEqual(str(raised.exception), "Version policy input was refused")

    def test_manual_is_default_and_never_infers_an_increment(self):
        with patch("builtins.open", side_effect=AssertionError("unexpected file access")):
            self.assertEqual(p.VersionPolicy.parse(), p.VersionPolicy())
            self.assertEqual(p.VersionPolicy.parse(p.VersionPolicy().value()), p.VersionPolicy())
            self.refused("manual-policy", lambda: p.VersionPolicy().increment_for("refs/heads/main"))
            self.refused("invalid-policy", lambda: p.VersionPolicy("automatic"))
            self.refused("invalid-policy", lambda: p.VersionPolicy("manual", policy().rules))
            self.refused("invalid-input", lambda: p.VersionPolicy.parse({"mode": "automatic"}))

    def test_build_patch_minor_major_matrix_and_two_component_base(self):
        for increment, name in (("build", "1.2.3"), ("patch", "1.2.4"),
                                ("minor", "1.3.0"), ("major", "2.0.0")):
            with self.subTest(increment=increment):
                self.assertEqual(propose(policy(increment)), ReleaseVersion(name, 8))
        pair = ReleaseVersion("1.2", 7)
        empty = (replace(observations()[0], max_build=0, marketing_version=None),)
        self.assertEqual(propose(policy("build"), base=pair, allocated=pair, observations=empty), ReleaseVersion("1.2", 8))
        self.assertEqual(propose(policy("patch"), base=pair, allocated=pair, observations=empty), ReleaseVersion("1.2.1", 8))

    def test_exact_branch_and_tag_rules_reject_ambiguity_and_globs(self):
        selected = p.VersionPolicy("automatic", (p.RefRule("refs/heads/release/v1", "build"),
                                                  p.RefRule("refs/tags/v1.2.3", "patch")))
        self.assertEqual(selected.increment_for("refs/tags/v1.2.3"), "patch")
        self.assertEqual(selected.increment_for("refs/heads/release/v1"), "build")
        for ref in ("refs/heads/main", "refs/heads/v1.2.3", "refs/tags/v1.2.4"):
            self.refused("ref-not-allowed", lambda ref=ref: selected.increment_for(ref))
        for ref in ("HEAD", "main", "refs/heads/*", "refs/tags/x..y", "refs/heads/.hidden", "refs/heads/x.lock", "refs/heads/x//y"):
            self.refused("invalid-input", lambda ref=ref: p.RefRule(ref, "build"))
        self.refused("ambiguous-rule", lambda: p.VersionPolicy("automatic", (
            p.RefRule("refs/heads/main", "build"), p.RefRule("refs/heads/main", "patch"))))

    def test_manual_parser_compatibility_and_automatic_format_refusal(self):
        android = ReleaseVersion("1.2.3.4-beta.1", 2_100_000_000)
        self.assertEqual(p.version(android, ("android",)), android)
        self.refused("unsupported-version", lambda: propose(base=android))
        wider_manual = ReleaseVersion("1.2.3", 10000)
        self.assertEqual(p.version(wider_manual, ("ios",)), wider_manual)
        for name in ("01.2.3", "1.02.3", "1.2.03", "1.2-beta", "1.2.3.4", "1.2 "):
            self.refused("unsupported-version", lambda name=name: propose(base=ReleaseVersion(name, 7)))

    def test_android_ios_shared_ranges_and_explicit_ceiling_never_wrap(self):
        maximum = ReleaseVersion("1.2.3", p.MAX_BUILD)
        self.refused("build-exhausted", lambda: propose(base=maximum))
        self.refused("build-exhausted", lambda: propose(policy(build_ceiling=7)))
        self.assertEqual(propose(base=ReleaseVersion("1.2.3", p.MAX_BUILD - 1)).build, p.MAX_BUILD)
        for enabled in (("ios",), ("android", "ios")):
            args = dict(enabled=enabled, observations=observations(enabled))
            self.assertEqual(propose(base=ReleaseVersion("1.2.3", 9998), **args).build, 9999)
            self.refused("ios-integer-build-exhausted", lambda args=args: propose(base=ReleaseVersion("1.2.3", 9999), **args))
        for build in (True, 0, -1, p.MAX_BUILD + 1):
            self.refused("invalid-input", lambda build=build: p.version(ReleaseVersion("1.2.3", build), ("android",)))

    def test_store_and_shared_authority_floors_keep_all_platforms_consistent(self):
        enabled = ("android", "ios")
        store = (replace(observations(enabled)[0], max_build=28, marketing_version="3.1"),
                 replace(observations(enabled)[1], max_build=30, marketing_version="2.9.9"))
        self.assertEqual(propose(policy("patch"), allocated=ReleaseVersion("2.0.0", 20),
                                 enabled=enabled, observations=store), ReleaseVersion("3.1.1", 31))
        self.assertEqual(propose(policy("build"), allocated=ReleaseVersion("4.0.0", 50),
                                 enabled=enabled, observations=store), ReleaseVersion("4.0.0", 51))

    def test_store_freshness_identity_complete_coverage_and_unknown_format(self):
        item = observations()[0]
        cases = (
            (replace(item, observed_at=NOW - 901), "store-observation-stale"),
            (replace(item, observed_at=NOW + 1), "store-observation-stale"),
            (replace(item, identity_revision="b" * 64), "store-identity-changed"),
            (replace(item, complete=False), "store-observation-incomplete"),
            (replace(item, format_supported=False), "store-format-unsupported"),
            (replace(item, max_build=0), "store-observation-incomplete"),
            (replace(item, marketing_version=None), "store-observation-incomplete"),
            (replace(item, marketing_version="1.2-preview"), "store-format-unsupported"),
        )
        for changed, reason in cases:
            with self.subTest(reason=reason, item=changed.value()):
                self.refused(reason, lambda changed=changed: propose(observations=(changed,)))
        for rows in ((), observations(("ios",)), (item, item), tuple(reversed(observations(("android", "ios"))))):
            self.refused("store-platform-mismatch", lambda rows=rows: propose(observations=rows))
        self.assertEqual(propose(observations=(replace(item, observed_at=NOW - 900),)).build, 8)

    def test_reused_number_does_not_gain_fresh_store_release_eligibility(self):
        args = dict(enabled=("android",), identity_revision=IDENTITY, observations=observations(), now=NOW)
        p.check_reserved_for_new_release(ReleaseVersion("1.2.3", 8), policy(), **args)
        self.refused("reservation-consumed", lambda: p.check_reserved_for_new_release(BASE, policy(), **args))
        changed = (replace(observations()[0], max_build=8, marketing_version="1.2.4"),)
        self.refused("reservation-consumed", lambda: p.check_reserved_for_new_release(
            ReleaseVersion("1.2.4", 8), policy(), **{**args, "observations": changed}))

    def test_closed_roundtrips_and_boolean_scalar_refusals(self):
        selected = policy("minor")
        self.assertEqual(p.VersionPolicy.parse(selected.value()), selected)
        self.assertEqual(p.VersionPolicy.parse(selected.value()).sha256, selected.sha256)
        source = p.SourceBinding("a" * 40, "b" * 40, "refs/tags/v1.0.0", "c" * 64, "d" * 64)
        self.assertEqual(p.SourceBinding.parse(source.value()), source)
        self.assertEqual(p.StoreObservation.parse(observations()[0].value()), observations()[0])
        self.refused("invalid-input", lambda: p.VersionPolicy(build_ceiling=True))
        self.refused("invalid-input", lambda: p.VersionPolicy(store_max_age_seconds=False))
        self.refused("invalid-input", lambda: replace(observations()[0], observed_at=True))
        self.refused("invalid-input", lambda: p.platforms(("ios", "android")))


if __name__ == "__main__":
    unittest.main()
