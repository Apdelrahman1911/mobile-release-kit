"""Original private file/Init owners with synthetic Git/HTTP/command results.

Only this test's temporary files are edited. No process, real credential, native
receipt, provider request or application project is used.
"""
from contextlib import contextmanager
from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from mobile_release import android_store_versions as inventory
from mobile_release import _desktop_store_preflight_protocol as store_wire
from mobile_release import desktop_store_preflight as store
from mobile_release import version_allocation as allocation
from mobile_release import version_allocation_source as source
from mobile_release import version_allocation_state as state
from mobile_release import version_policy as policy
from mobile_release.config import default_config_data
from mobile_release.config_payloads import prepare_edit_ignore
from . import test_android_store_versions as raw_fixture
from . import test_desktop_store_preflight as store_fixture

# These existing narrowly scoped fixtures bind real readers/Init locks. Their
# C/A/W, native journal port and HTTP results remain expressly synthetic DATA.
import test_desktop_version_reserve as reserve_fixture
import test_reserved_version_edit as edit_fixture
from test_version_allocation import COMMIT, IDENTITY, NOW, Repository, initial, request
from test_version_allocation_source import SourceFixture
from test_version_allocation_state import LOCAL_PROJECT, NativePortFixture


class OriginalPlayInventoryTests(unittest.TestCase):
    @contextmanager
    def original_query(self):
        original = store_fixture.request
        def selected(root, runtime):
            value = original(root, runtime)
            value["context"]["query"] = inventory.QUERY
            return value
        with patch.object(store_fixture, "request", side_effect=selected), \
             store_fixture.DesktopStorePreflightTests().original() as values:
            yield values

    def raw(self, environment):
        with patch.object(raw_fixture, "PACKAGE", environment["MOBILE_RELEASE_PLAY_PACKAGE"]):
            value = raw_fixture.frame(apks=[{"versionCode": 50}])
        value["contextSha256"] = environment["MOBILE_RELEASE_PLAY_CONTEXT"]
        return policy.canonical(value)

    def commands(self, operation, final):
        calls = []
        output = ("3.3.12", "4.0.16", "", "MRK_RUNTIME_3.3.12_FIDDLE_1.1.2", "MRK_RUNTIME_3.3.12_FIDDLE_1.1.2")
        def call(argv, **kwargs):
            index = len(calls); calls.append(tuple(argv))
            self.assertIs(kwargs["cancellation"], operation.guard)
            self.assertTrue(kwargs["capture"])
            self.assertLessEqual(kwargs["timeout"], 60)
            if index < 5:
                return subprocess.CompletedProcess(argv, 0, stdout=output[index], stderr="")
            self.assertEqual(index, 5)
            self.assertIsNone(kwargs["_evidence"])
            self.assertFalse(kwargs["text"])
            self.assertEqual(kwargs["output_limit"], inventory.FRAME_LIMIT)
            return final(argv, kwargs)
        return calls, call

    def test_same_original_six_commands_google_material_and_absolute_cleanup_budget(self):
        with self.original_query() as (_, _, runtime, source_input, operation):
            def final(argv, kwargs):
                self.assertEqual(tuple(argv), inventory.fixed_argv(runtime / "store/tooling"))
                environment = kwargs["environ"]
                self.assertEqual(json.loads(Path(environment["GOOGLE_APPLICATION_CREDENTIALS"]).read_bytes()), store_fixture.account())
                for name in ("HTTPS_PROXY", "RUBYOPT", "GH_TOKEN", "GOOGLE_CLOUD_PROJECT", "MOBILE_RELEASE_STORE_MODE"):
                    self.assertNotIn(name, environment)
                read = int(environment["MOBILE_RELEASE_PLAY_READ_END_NS"])
                hard = int(environment["MOBILE_RELEASE_PLAY_HARD_END_NS"])
                self.assertLess(read, hard)
                self.assertLessEqual(hard, int(operation.source.work_end * 1_000_000_000))
                return subprocess.CompletedProcess(argv, 0, stdout=self.raw(environment), stderr=b"")
            calls, call = self.commands(operation, final)
            with patch("mobile_release._command_process.run_command", side_effect=call), patch.dict(os.environ, {
                "HTTPS_PROXY": "https://not-used.invalid", "GH_TOKEN": "INERT", "GOOGLE_CLOUD_PROJECT": "ambient-denied",
            }):
                operation.run()
            self.assertEqual(len(calls), 6)
            summary = operation.report["currentVersions"]
            self.assertEqual((summary["observation"], summary["maxBuild"], summary["temporaryEdit"]), ("observed", 50, "deleted"))
            store_wire.validate_result(operation.report, platform="android", query=inventory.QUERY)
            self.assertNotIn("synthetic-edit", json.dumps(operation.report))
            self.assertNotIn("client_email", json.dumps(operation.report))
            self.assertTrue(operation.closed())
            self.assertIsNone(operation.terminal()["result"])  # Original input/signals have not returned yet.
            with patch("mobile_release._command_process.run_command") as repeat:
                with self.assertRaises(ValueError): operation.run()
                repeat.assert_not_called()
        self.assertTrue(source_input.material_closed())

    def test_actual_source_change_after_raw_lists_vetoes_current_inventory(self):
        with self.original_query() as (_, root, _, _, operation):
            def final(argv, kwargs):
                raw = self.raw(kwargs["environ"])
                path = root / "release/version.properties"
                path.write_bytes(path.read_bytes() + b"\n")
                return subprocess.CompletedProcess(argv, 0, stdout=raw, stderr=b"")
            calls, call = self.commands(operation, final)
            with patch("mobile_release._command_process.run_command", side_effect=call):
                with self.assertRaises(store._Refused): operation.run()
            self.assertEqual(len(calls), 6)
            self.assertIsNone(operation.report)

    def test_missing_response_or_unconfirmed_delete_never_becomes_empty_or_echoes_raw_error(self):
        for missing in (False, True):
            with self.subTest(missing=missing), self.original_query() as (_, _, _, _, operation):
                def final(argv, kwargs):
                    if missing:
                        return subprocess.CompletedProcess(argv, 1, stdout=b"PRIVATE_ERROR", stderr=b"")
                    value = json.loads(self.raw(kwargs["environ"]))
                    value["pages"][-1]["response"]["status"] = 500
                    value["temporaryEdit"]["deleteConfirmed"] = False
                    value["queryFinished"] = False
                    return subprocess.CompletedProcess(argv, 0, stdout=policy.canonical(value), stderr=b"")
                _, call = self.commands(operation, final)
                with patch("mobile_release._command_process.run_command", side_effect=call): operation.run()
                self.assertEqual(operation.report["currentVersions"], inventory.unavailable(
                    "temporary-edit-unconfirmed", temporary_edit="unconfirmed"))
                self.assertNotIn("PRIVATE_ERROR", json.dumps(operation.report))

    def test_temporary_edit_query_never_borrows_old_access_or_delivery_protocol_opt_in(self):
        with store_fixture.DesktopStorePreflightTests().files() as (_, root, runtime):
            value = store_fixture.request(root, runtime)
            value["context"]["query"] = inventory.QUERY
            parsed = store_wire.parse_request(store_fixture.encode(value))
            for options in ({}, {"apple_access": True}, {"bundle_query": True}):
                with self.assertRaises(ValueError): store_wire.context(parsed.context, **options)
            self.assertEqual(store_wire.context(parsed.context, apple_access=True, bundle_query=True), parsed.context)
            value["context"]["platform"] = "ios"
            with self.assertRaises(ValueError): store_wire.parse_request(store_fixture.encode(value))
            with self.assertRaises(ValueError): store_wire.validate_result(
                inventory.project_result([], inventory.unavailable("not-checked")), platform="android")


class AndroidEditFixture(edit_fixture.EditFixture):
    def __init__(self, root, *, mixed=False):
        # No earlier authority/operation is reused or reminted. This constructs
        # one new synthetic candidate before its first command/effect.
        SourceFixture.__init__(self, root)
        if mixed:
            self.data = default_config_data({"android": {"applicationId": "com.example.inert"}, "ios": {"bundleId": "com.example.inert"}})
            self.data["source"]["localStoreEnabled"] = False
            self.save()
        self.ledger, self.authority = initial()
        self.selected = request(source=self.binding(), enabled_platforms=("android",),
            version_policy=policy.VersionPolicy("automatic", (policy.RefRule("refs/heads/main", "build"),),
                                                store_scope=inventory.POLICY_SCOPE), store_context_revision="9" * 64)
        self.native = NativePortFixture()
        self.native_journal = state.NativeAllocationJournal(self.native, local_project_id=LOCAL_PROJECT)
        self.native_journal.enroll_authority(self.authority, allocation.Checkpoint(0, self.ledger.head_sha256, COMMIT))
        self.native_journal.select_candidate(self.authority, self.selected)
        self.repository = Repository(self.ledger, self.authority)
        self.observation = inventory.CurrentInventory(IDENTITY, "9" * 64, "8" * 64, NOW, 7, (0, 0, 0, 0, 1))
        self.sequence = 0; self.cut = self.fin = None
        self.write(".gitignore", prepare_edit_ignore(b"")[0])
        self.editing = False; self.edit_input_closes = 0
        self.engine = self.owner = self.checkout = None


class AndroidReserveEditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="mrk-play-reserved-edit-inert-")
        root = Path(self.tmp.name) / "project"; root.mkdir()
        self.f = AndroidEditFixture(root)
        self.retained = len(source._RETAINED)

    def tearDown(self):
        del source._RETAINED[self.retained:]
        self.tmp.cleanup()

    def test_android_v3_reserve_real_preview_apply_and_retry_keeps_original_flock_and_candidate(self):
        # Reuse the real positive file/borrowed-flock regression with a v3
        # Android candidate; no duplicated writer or invented native receipt.
        self.assertEqual(self.f.selected.version_policy.schema_version, 3)
        edit_fixture.ReservedVersionEditTests.test_reserve_real_preview_apply_and_retry_retains_exact_candidate_without_another_put(self)
        self.assertEqual(self.f.checkout.enabled_platforms, ("android",))
        self.assertEqual(self.f.fin["outcome"]["reservation"]["request"]["policy"]["schemaVersion"], 3)

    def test_android_source_change_after_durable_pending_ack_cannot_put_or_renumber(self):
        reserve_fixture.DesktopVersionReserveTests.test_source_change_after_pending_ack_vetoes_put_and_keeps_same_intent(self)
        self.assertEqual(self.f.native_journal.pending_for(self.f.authority, self.f.selected.candidate_id)
                         .reservation.request.version_policy.schema_version, 3)

    def test_android_build_above_ios_range_reaches_same_real_version_writer(self):
        f = self.f
        f.observation = replace(f.observation, max_build=10_001)
        f.run()
        self.assertEqual(f.fin["outcome"]["reservation"]["version"]["build"], 10_002)
        with f.opened() as owner:
            plan = owner.prepare(f.checkout, {"revision": f.checkout.revision,
                "expectedBaseline": f.checkout.baseline, "intent": "edit",
                "values": {"name": "1.2.3", "build": "10002"}})
            f.engine.authority = plan
            self.assertTrue(edit_fixture.edit._authentic_plan(plan))
            outcome = owner.apply(plan)
            self.assertEqual((outcome.effect, outcome.journal, outcome.resources),
                             ("committed", "clean", "settled"))
            self.assertEqual((f.root / f.data["version"]["source"]).read_bytes(),
                             b"VERSION_NAME=1.2.3\nBUILD_NUMBER=10002\n")
        self.assertTrue(f.settled)
        self.assertEqual(len(f.repository.writes), 1)

    def test_android_current_material_context_refuses_before_put(self):
        self.f.observation = replace(self.f.observation, context_revision="e" * 64)
        self.f.run()
        self.assertEqual(len(self.f.repository.writes), 0)
        self.assertNotEqual(self.f.fin["outcome"]["status"], "reserved")

    def test_mixed_saved_platforms_need_two_original_receipts_not_one_android_floor(self):
        root = Path(self.tmp.name) / "mixed"; root.mkdir()
        mixed = AndroidEditFixture(root, mixed=True)
        # The actual source reader discovers BOTH saved platforms and refuses
        # before HTTP; one native credential witness is not a paired receipt.
        mixed.run()
        self.assertEqual(len(mixed.repository.writes), 0)
        mixed.factory.assert_not_called()
        self.assertNotEqual(mixed.fin["outcome"]["status"], "reserved")


if __name__ == "__main__": unittest.main()
