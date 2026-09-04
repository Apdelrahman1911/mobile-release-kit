from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FASTFILE = (ROOT / "fastlane/Fastfile").read_text(encoding="utf-8")
GEMFILE = (ROOT / "Gemfile").read_text(encoding="utf-8")
LOCKFILE = (ROOT / "Gemfile.lock").read_text(encoding="utf-8")
RUNNER = (ROOT / "fastlane/run_lane.rb").read_text(encoding="utf-8")
PLAY_STORE = (ROOT / "fastlane/play_store.rb").read_text(encoding="utf-8")


class FastlaneContractTests(unittest.TestCase):
    def test_all_store_lanes_are_explicit(self) -> None:
        lanes = set(re.findall(r"^lane :([a-z0-9_]+) do$", FASTFILE, re.MULTILINE))
        self.assertEqual(
            {
                "android_internal_upload",
                "android_online_preflight",
                "android_external_promote",
                "android_production_draft",
                "ios_testflight_internal",
                "ios_online_preflight",
                "ios_testflight_external",
                "ios_app_store_submit",
            },
            lanes,
        )

    def test_shared_lane_runner_is_fixed_and_allowlisted(self) -> None:
        self.assertIn('File.join(__dir__, "Fastfile")', RUNNER)
        self.assertIn("ALLOWED_LANES", RUNNER)
        self.assertIn("Fastlane::LaneManager.cruise_lane", RUNNER)
        self.assertNotIn("--fastfile", RUNNER)
        for lane in re.findall(r"^lane :([a-z0-9_]+) do$", FASTFILE, re.MULTILINE):
            self.assertRegex(RUNNER, rf"(?m)^  {re.escape(lane)}$")

    def test_google_online_preflight_never_commits_its_edit(self) -> None:
        body = FASTFILE.split('lane :android_online_preflight do', 1)[1].split('\nend', 1)[0]
        self.assertIn("service.delete_edit", body)
        self.assertNotIn("commit_edit", body)
        self.assertNotIn("commit_current_edit", body)

    def test_closed_play_tracks_require_api_verified_group_assignment(self) -> None:
        self.assertIn("service.get_edit_tester", FASTFILE)
        self.assertIn('fields: "googleGroups"', FASTFILE)
        self.assertIn("closedTesterAssignmentVerified", FASTFILE)
        self.assertGreaterEqual(FASTFILE.count("verify_closed_track_testers(destination)"), 2)
        self.assertNotIn("google_groups.join", FASTFILE)

    def test_testing_and_production_store_states_are_fail_closed(self) -> None:
        self.assertIn('track: "internal"', FASTFILE)
        self.assertIn('release_status: "completed"', FASTFILE)
        self.assertIn('to: "production", status: "draft"', FASTFILE)
        self.assertIn('automatic_release: false', FASTFILE)
        self.assertIn('submit_for_review: true', FASTFILE)
        self.assertIn("this workflow never releases publicly", FASTFILE)
        self.assertIn("Target version code already exists in the destination Play track", PLAY_STORE)
        self.assertNotIn("create_app_store_version_release_request", FASTFILE)

    def test_candidate_uploads_no_store_listing_metadata(self) -> None:
        options = FASTFILE.split("def play_upload_options", 1)[1].split("\nend", 1)[0]
        self.assertIn('json_key: required_env("GOOGLE_APPLICATION_CREDENTIALS")', options)
        self.assertIn("skip_upload_metadata: true", options)
        self.assertIn("skip_upload_changelogs: true", options)
        self.assertIn("skip_upload_images: true", options)
        self.assertIn("skip_upload_screenshots: true", options)

    def test_ios_upload_requires_processed_valid_build(self) -> None:
        self.assertIn('expected VALID', FASTFILE)
        self.assertIn('demo_required ? required_secret_env("MOBILE_RELEASE_APPLE_DEMO_ACCOUNT_USERNAME")', FASTFILE)
        self.assertIn('demo_required ? required_secret_env("MOBILE_RELEASE_APPLE_DEMO_ACCOUNT_PASSWORD")', FASTFILE)
        self.assertIn('key_content: required_secret_env("MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64")', FASTFILE)
        self.assertRegex(FASTFILE, r'return "approved" if .*APPROVED')
        self.assertIn('return "pending-developer-release"', FASTFILE)

    def test_external_testflight_requires_separate_what_to_test_metadata(self) -> None:
        lane = FASTFILE.split("lane :ios_testflight_external do", 1)[1].split("\nend", 1)[0]
        self.assertIn(
            'what_to_test = required_metadata_text("testflight/what-to-test.txt")',
            lane,
        )
        self.assertIn("changelog: what_to_test", lane)
        self.assertIn("beta_app_review_info: review_contact(beta: true)", lane)
        self.assertIn(
            'notes_path = beta ? "review/ios-beta-notes.txt" : "review/ios-notes.txt"',
            FASTFILE,
        )
        self.assertNotIn("changelog: review_contact", lane)

    def test_ios_production_rerun_is_readback_first_and_fail_closed(self) -> None:
        lane = FASTFILE.split("lane :ios_app_store_submit do", 1)[1].split("\nend", 1)[0]
        self.assertLess(
            lane.index("existing_app_store_submission(app, build)"),
            lane.index("upload_to_app_store("),
        )
        self.assertIn('result = "already_present"', lane)
        self.assertIn("require_exact_submitted_app_store_version(version, build)", lane)
        self.assertIn("MobileReleaseKit.manual_app_store_release?(version)", FASTFILE)
        self.assertIn("partial earlier submission cannot be distinguished", FASTFILE)
        self.assertIn("references a different build; refusing production adoption", FASTFILE)
        existing = FASTFILE.split("def existing_app_store_submission", 1)[1].split("\nend", 1)[0]
        self.assertIn("unless version.build", existing)
        self.assertNotIn("PREPARE_FOR_SUBMISSION", existing)
        self.assertNotIn("READY_FOR_REVIEW", existing)
        self.assertIn('automatic_release: false', lane)
        self.assertNotIn("create_app_store_version_release_request", lane)

    def test_store_dependencies_and_transitives_are_locked(self) -> None:
        self.assertIn('ruby "~> 3.3.0"', GEMFILE)
        self.assertIn('gem "fastlane", "= 2.235.0"', GEMFILE)
        self.assertIn('gem "google-apis-androidpublisher_v3", "= 0.106.0"', GEMFILE)
        self.assertIn("fastlane (= 2.235.0)", LOCKFILE)
        self.assertIn("google-apis-androidpublisher_v3 (= 0.106.0)", LOCKFILE)
        self.assertIn("CHECKSUMS", LOCKFILE)
        self.assertRegex(LOCKFILE, r"(?m)^  ruby$")


if __name__ == "__main__":
    unittest.main()
