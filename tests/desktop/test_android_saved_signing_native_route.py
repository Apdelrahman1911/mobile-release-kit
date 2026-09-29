"""Saved3 joined DATA contracts; these tests are NOT native qualification.

Every receipt, configuration hash, signing fingerprint, map identity and fixture
export below is invented comparison DATA. No GUI, JVM, compiler, process owner,
credential, network route, installed profile or filesystem fixture is acquired.
The real CI aggregator and real lifecycle/core predicates must accept or reject
the DATA; no successful parser or finality result is mocked. Native saved UI,
signing, cancellation and original-owner cleanup still require real native runs.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[2]


def source_module(name, relative):
    spec = importlib.util.spec_from_file_location(name, SOURCE / relative)
    assert spec is not None and spec.loader is not None
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


S = source_module("_mrk_saved3_ci_data", "desktop/tools/ci_ubuntu_publication.py")
L = source_module("_mrk_saved3_lifecycle_data", "desktop/tools/ubuntu_publication_lifecycle.py")
P = source_module("_mrk_saved3_projection_data", "tests/desktop/test_android_saved_signing_qualification.py")

CASES = ("android-saved-signing", "android-saved-signing-wrong-fingerprint", "android-saved-signing-cancel")
FIREBASE = b'{"client":[{"client_info":{"android_client_info":{"package_name":"org.example.saved"}}}]}\n'
PRIVATE_TEXT = "INERT_PRIVATE_INPUT_MUST_NOT_REACH_PUBLIC_SUMMARY"
NATIVE_FIXTURE_KEYS = {
    "sourceControlsAccounted", "savedVersionChanged", "savedConfigApplied", "signingSourcesRetained",
    "firebaseRestoredToAbsence", "pendingMaterialAbsent", "certificateSha256", "keystoreBytes",
    "firebaseBytes", "gradleBoundary", "generatedScopesNotExported",
}


def record(path, raw):
    return {"path": path, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def receipt_data(case):
    terminal, lifetime, expected = P.data(case)
    cancelled, mismatch = case == CASES[2], case == CASES[1]
    native_fixture = {
        "sourceControlsAccounted": True, "savedVersionChanged": False, "savedConfigApplied": True,
        "signingSourcesRetained": True, "firebaseRestoredToAbsence": True, "pendingMaterialAbsent": True,
        "certificateSha256": expected["certificate_sha256"], "keystoreBytes": 1536, "firebaseBytes": len(FIREBASE),
        "gradleBoundary": "" if mismatch else "active\n",
        "generatedScopesNotExported": ["project/.mobile-release", "project/app/build", "project/build"],
    }
    receipt = {
        "schema": "installed-android-saved-signing-v1", "case": case, "qualificationOnly": True, "builder": "normal",
        "normalSelection": {"selectedBeforeObservation": True, "observerGranted": False},
        "projectPicker": True, "savedObservation": True, "savedVersionObservation": True,
        "requests": {"androidPrepare": 1, "androidStart": 1, "androidCancel": 1 if cancelled else 0},
        "ui": {"start": True, "consent": True, "terminal": True, "cancel": cancelled}, "busyObserved": cancelled,
        "original": expected["original"], "toolsLedgerSettled": True, "nativeIntegrity": True,
        "coreLifetime": lifetime, "terminal": terminal, "fixture": deepcopy(native_fixture),
        "savedConfig": expected["saved_config"], "savedVersion": expected["saved_version"], "selection": expected["selection"],
        "dispatch": expected["dispatch"],
        "configSave": {"requests": [1, 1, 1], "replies": [1, 1, 1], "previewObserved": True,
                       "acknowledged": True, "applied": True, "readback": True, "originalFinal": True},
        "session": {"assessments": 2, "fileChoosers": 2, "capturedFiles": 2, "capturesClosed": 2, "kept": 2,
                    "assigned": 2, "originalQueries": 2, "queriesRetired": True, "originalsSettled": True,
                    "relayJoined": True, "exit": True, "configBeforeAssignments": True,
                    "binding": deepcopy(terminal["context"]["signing"])},
        "limits": {"normalActivation": False, "work3000Expiry": False, "privateJvmProfile": False,
                   "noAutoInstall": False, "allHelperNativeGates": False, "networkIsolated": False},
    }
    independent = {**deepcopy(native_fixture), "savedConfig": deepcopy(expected["saved_config"]),
                   "savedVersion": deepcopy(expected["saved_version"]), "selection": deepcopy(expected["selection"])}
    return receipt, independent


def refresh_cases_export(observed):
    replacement = record("lifecycle-shell-cases.json", S.D.canonical(observed["cases"]))
    index = next(i for i, row in enumerate(observed["files"]) if row["path"] == replacement["path"])
    observed["files"][index] = replacement


def observation_data():
    selection = L.shell_android_saved_selection()
    selected = {"shell": {"savedSigning": deepcopy(selection)}}
    observed = {
        "savedSigning": deepcopy(selection), "state": L.result_state(selected),
        "productQualified": False, "packageLifecycleQualified": False, "shellPackageBuilt": False,
        "sourceSha": "a" * 40, "consumerAttempt": "1", "shellLocalTransport": {"sha256": "8" * 64},
        "cases": {}, "androidSavedSigning": {},
        "files": [record("lifecycle-" + name, b"")
                  for name in sorted(L.public_files(selected) | {"client.stdout", "client.stderr"})],
    }
    by_name = {row["path"]: row for row in observed["files"]}
    roles = sorted(L.PRIVATE_SONAMES | {"python", "ld-linux-x86-64.so.2", "libc.so.6", "libm.so.6"})
    for case in CASES:
        receipt, fixture = receipt_data(case)
        for phase in ("before", "after"):
            name = "lifecycle-shell-" + case + "-" + phase + ".json"
            exported = record(name, S.D.canonical({"case": case, "phase": phase, "inertDataOnly": True}))
            by_name[name].update(exported)
            fixture[phase + "Sha256"] = exported["sha256"]
        maps = [[{"role": role, "path": "/inert-saved3/" + role, "deviceMajor": 8, "deviceMinor": 2,
                  "inode": (1 << 63) + index + 11} for index, role in enumerate(roles)] for _ in range(2)]
        observed["cases"][case] = {"case": case, "exitCode": 0, "bootstrapReturned": True, "domAndGtkObserved": True,
                                   "maps": maps, "androidSavedSigning": receipt}
        observed["androidSavedSigning"][case] = {"native": deepcopy(receipt), "fixture": fixture}
    refresh_cases_export(observed)
    return selection, observed


def summary_inputs(selection):
    source = {"sourceSha": "a" * 40, "sourceTree": "b" * 40, "runId": "1", "attempt": "1", "savedSigning": deepcopy(selection)}
    preparation = {
        "materials": {"instance": "inert-android", "manifestSha256": "1" * 64,
                      "osContractSha256": "2" * 64, "distributionSha256": "3" * 64},
        "publication": {
            "documents": {key: {"size": 1, "sha256": digit * 64}
                          for key, digit in (("manifest", "1"), ("osContract", "2"), ("sources", "4"))},
            "totals": {"toolFiles": 5, "toolDirectories": 6, "toolBytes": 5, "osFiles": 4, "osAliases": 1, "osBytes": 4},
        },
        "provenance": {"policySha256": "5" * 64},
        "privateData": PRIVATE_TEXT,
    }
    records = {name: {"path": "/inert-private/" + PRIVATE_TEXT, "size": 1, "sha256": "7" * 64}
               for name in ("source.json", "result.json", "private-evidence-roster.json")}
    return source, preparation, records


class AndroidSavedSigningNativeRouteDataTests(unittest.TestCase):
    def rejected(self, observed, selection):
        with self.assertRaises((L.Refused, S.D.Refused, ValueError)):
            S.shell_android_saved_observation(observed, L, selection)

    def test_three_real_parsers_join_independent_fixture_data_without_native_credit(self):
        selection, observed = observation_data()
        before = deepcopy(observed)
        self.assertEqual(tuple(L.SHELL_ANDROID_SAVED_CASES), CASES)
        self.assertEqual(P.subject.SAVED_SIGNING_CASES, CASES)
        self.assertEqual(selection["profile"], "android-saved-signing3-v1")
        self.assertEqual(S.shell_android_saved_observation(observed, L, selection), observed["androidSavedSigning"])
        self.assertEqual(observed, before)
        for case in CASES:
            receipt = observed["cases"][case]["androidSavedSigning"]
            fixture = observed["androidSavedSigning"][case]["fixture"]
            self.assertEqual(L.shell_android_saved_receipt(S.D.canonical(receipt), case,
                saved_config=fixture["savedConfig"], saved_version=fixture["savedVersion"],
                selection=fixture["selection"], certificate_sha256=fixture["certificateSha256"]), receipt)
            self.assertIs(observed["productQualified"], False)

    def test_saved_scope_reuses_android_build_but_requires_its_private_same_job_route(self):
        selection = L.shell_android_saved_selection()
        environment = {"GITHUB_REF": S.SHELL_REF, "MRK_INSTALLED_SHELL_SCOPE": L.SHELL_ANDROID_SAVED_PROFILE,
                       "MRK_INSTALLED_SHELL_TRANSPORT": "android-same-job-local-v1"}
        with patch.dict(S.os.environ, environment, clear=True):
            self.assertIsNone(S.installed_shell_scope(L))
            self.assertEqual(S.installed_shell_saved_selection(L), selection)
        for change in ({"GITHUB_REF": "refs/heads/main"}, {"GITHUB_REF": S.SHELL_GITHUB_REF},
                       {"MRK_INSTALLED_SHELL_TRANSPORT": "actions-artifact-v1"},
                       {"MRK_INSTALLED_SHELL_TRANSPORT": ""}):
            with self.subTest(change=change), patch.dict(S.os.environ, {**environment, **change}, clear=True):
                with self.assertRaises(S.D.Refused):
                    S.installed_shell_scope(L)
        for environment in ({}, {"MRK_INSTALLED_SHELL_SCOPE": ""}):
            with patch.dict(S.os.environ, environment, clear=True):
                self.assertIsNone(S.installed_shell_scope(L))
                self.assertIsNone(S.installed_shell_saved_selection(L))

    def test_missing_mixed_and_legacy_scopes_cannot_be_relabelled_as_saved3(self):
        for mutation in ("missing-case", "extra-case", "missing-pair", "wrong-selection", "legacy-scope", "public-credit"):
            with self.subTest(mutation=mutation):
                selection, observed = observation_data()
                if mutation == "missing-case": observed["cases"].pop(CASES[0])
                elif mutation == "extra-case": observed["cases"]["android-build"] = deepcopy(observed["cases"][CASES[0]])
                elif mutation == "missing-pair": observed["androidSavedSigning"].pop(CASES[0])
                elif mutation == "wrong-selection": observed["savedSigning"]["cases"] = ["android-build"]
                elif mutation == "legacy-scope": observed["androidBuild"] = {}
                else: observed["productQualified"] = True
                refresh_cases_export(observed)
                self.rejected(observed, selection)

    def test_two_original_maps_keep_full_integer_identity_and_reject_substitutes(self):
        selection, original = observation_data()
        accepted = S.shell_android_saved_observation(original, L, selection)
        self.assertEqual(accepted, original["androidSavedSigning"])
        self.assertGreater(original["cases"][CASES[0]]["maps"][0][0]["inode"], 1 << 53)
        for mutation in ("missing", "extra", "role", "duplicate-role", "bool-device", "bool-inode", "wide-inode", "relative"):
            with self.subTest(mutation=mutation):
                observed = deepcopy(original)
                maps = observed["cases"][CASES[0]]["maps"]
                if mutation == "missing": maps.pop()
                elif mutation == "extra": maps.append(deepcopy(maps[0]))
                elif mutation == "role": maps[0][0]["role"] = "unrelated"
                elif mutation == "duplicate-role": maps[0][0]["role"] = maps[0][1]["role"]
                elif mutation == "bool-device": maps[0][0]["deviceMajor"] = True
                elif mutation == "bool-inode": maps[0][0]["inode"] = True
                elif mutation == "wide-inode": maps[0][0]["inode"] = 1 << 64
                else: maps[0][0]["path"] = "relative/inert"
                refresh_cases_export(observed)  # Reject the map itself, not a stale case-file digest.
                self.rejected(observed, selection)

    def test_independent_saved_config_version_selection_and_certificate_are_authoritative(self):
        for mutation in ("config", "version", "selection", "certificate"):
            with self.subTest(mutation=mutation):
                selection, observed = observation_data()
                fixture = observed["androidSavedSigning"][CASES[0]]["fixture"]
                if mutation == "config": fixture["savedConfig"]["sha256"] = "e" * 64
                elif mutation == "version": fixture["savedVersion"]["build"] += 1
                elif mutation == "selection": fixture["selection"]["module"] = ":another"
                else: fixture["certificateSha256"] = "e" * 64
                self.rejected(observed, selection)

    def test_original_save_session_closures_and_no_generated_material_are_required(self):
        for section, key, value in (
            ("configSave", "readback", False), ("configSave", "originalFinal", False),
            ("configSave", "replies", [1, 1, 0]), ("session", "originalQueries", True),
            ("session", "queriesRetired", False), ("session", "capturesClosed", 1),
            ("session", "originalsSettled", False), ("session", "relayJoined", False),
            ("session", "configBeforeAssignments", False), ("session", "binding", {"source": "assigned-session", "contextRevision": 99, "assignments": []}),
            ("fixture", "signingSourcesRetained", False), ("fixture", "firebaseRestoredToAbsence", False),
            ("fixture", "pendingMaterialAbsent", False),
        ):
            with self.subTest(section=section, key=key):
                selection, observed = observation_data()
                receipt = observed["cases"][CASES[0]]["androidSavedSigning"]
                receipt[section][key] = value
                observed["androidSavedSigning"][CASES[0]]["native"] = deepcopy(receipt)
                if section == "fixture":
                    observed["androidSavedSigning"][CASES[0]]["fixture"][key] = value
                refresh_cases_export(observed)
                self.rejected(observed, selection)

    def test_cancellation_core_predicate_is_not_bypassed_by_a_complete_outer_receipt(self):
        # The full core mutation matrix lives in the reused P test module.
        # These cases specifically prove that the joined CI route invokes it.
        for mutation in ("unobserved-dispatch", "known-signer-exit", "wrong-owner"):
            with self.subTest(mutation=mutation):
                selection, observed = observation_data()
                receipt = observed["cases"][CASES[2]]["androidSavedSigning"]
                if mutation == "unobserved-dispatch": receipt["dispatch"]["observed"] = False
                elif mutation == "known-signer-exit":
                    receipt["terminal"]["activity"]["signing"]["signingCommand"] = {"outcome": "exited", "exitCode": 0}
                else: receipt["dispatch"]["ownerGeneration"] = "9" * 32
                observed["androidSavedSigning"][CASES[2]]["native"] = deepcopy(receipt)
                refresh_cases_export(observed)
                self.rejected(observed, selection)

    def test_receipt_case_scope_exactness_and_native_fixture_pairing_are_enforced(self):
        for mutation in ("legacy-marker", "wrong-case", "private-field", "missing-fixture", "different-native"):
            with self.subTest(mutation=mutation):
                selection, observed = observation_data()
                receipt = observed["cases"][CASES[0]]["androidSavedSigning"]
                if mutation == "legacy-marker": receipt["schema"] = "installed-android-build-v2"
                elif mutation == "wrong-case": receipt["case"] = CASES[1]
                elif mutation == "private-field": receipt["private"] = PRIVATE_TEXT
                elif mutation == "missing-fixture": observed["androidSavedSigning"][CASES[0]]["fixture"].pop("savedConfig")
                else: observed["androidSavedSigning"][CASES[0]]["native"]["fixture"]["keystoreBytes"] += 1
                if mutation != "different-native":
                    observed["androidSavedSigning"][CASES[0]]["native"] = deepcopy(receipt)
                refresh_cases_export(observed)
                self.rejected(observed, selection)

    def test_export_roster_and_original_before_after_digests_cannot_be_fabricated_from_labels(self):
        for mutation in ("missing", "duplicate", "extra", "bool-size", "case-digest", "fixture-digest", "unchanged-fixture"):
            with self.subTest(mutation=mutation):
                selection, observed = observation_data()
                rows = observed["files"]
                if mutation == "missing": rows.pop()
                elif mutation == "duplicate": rows[-1] = deepcopy(rows[0])
                elif mutation == "extra": rows.append(record("lifecycle-unrelated.json", b""))
                elif mutation == "bool-size": rows[0]["size"] = True
                elif mutation == "case-digest":
                    next(row for row in rows if row["path"] == "lifecycle-shell-cases.json")["sha256"] = "e" * 64
                elif mutation == "fixture-digest":
                    observed["androidSavedSigning"][CASES[0]]["fixture"]["afterSha256"] = "e" * 64
                else:
                    fixture = observed["androidSavedSigning"][CASES[0]]["fixture"]
                    fixture["afterSha256"] = fixture["beforeSha256"]
                    next(row for row in rows if row["path"] == "lifecycle-shell-" + CASES[0] + "-after.json")["sha256"] = fixture["afterSha256"]
                self.rejected(observed, selection)

    def test_public_summary_contains_only_fixed_case_status_and_content_pins(self):
        selection, observed = observation_data()
        observed["unexportedPrivateData"] = PRIVATE_TEXT
        source, preparation, records = summary_inputs(selection)
        summary = S.android_native_public_summary(source, observed, preparation, records, L)
        self.assertEqual(summary["scope"], "android-saved-signing-private-native-summary-v1")
        self.assertEqual(summary["cases"], [{"case": name, "exitCode": 0, "qualified": False} for name in CASES])
        self.assertIs(summary["signingExercised"], True)
        for key in ("qualified", "packageBuilt", "compilerRerun", "supplierRebuilt"):
            self.assertIs(summary[key], False)
        raw = S.D.canonical(summary).decode()
        for forbidden in (PRIVATE_TEXT, "/inert-saved3", "/inert-private", "savedConfig", "savedVersion",
                          "androidSavedSigning", "certificateSha256", "storePassword"):
            self.assertNotIn(forbidden, raw)
        self.assertEqual(set(summary["privateRecords"]), {"source.json", "result.json", "private-evidence-roster.json"})
        self.assertTrue(all(set(row) == {"size", "sha256"} for row in summary["privateRecords"].values()))

    def test_public_signing_exercised_requires_all_three_real_predicates(self):
        selection, observed = observation_data()
        source, preparation, records = summary_inputs(selection)
        receipt = observed["cases"][CASES[0]]["androidSavedSigning"]
        receipt["coreLifetime"]["materialRetired"] = False
        observed["androidSavedSigning"][CASES[0]]["native"] = deepcopy(receipt)
        refresh_cases_export(observed)
        with self.assertRaises((L.Refused, S.D.Refused, ValueError)):
            S.android_native_public_summary(source, observed, preparation, records, L)
        selection, observed = observation_data()
        source["savedSigning"]["cases"] = ["android-build"]
        with self.assertRaises(S.D.Refused):
            S.android_native_public_summary(source, observed, preparation, records, L)

    def test_legacy_full25_is_not_expanded_or_granted_saved_signing_credit(self):
        self.assertEqual(len(L.SHELL_CASES), 25)
        self.assertTrue(set(CASES).isdisjoint(L.SHELL_CASES))
        selection, _ = observation_data()
        source, preparation, records = summary_inputs(selection)
        source.pop("savedSigning")
        legacy = {
            "state": L.result_state({"shell": {}}), "productQualified": False, "packageLifecycleQualified": False,
            "shellPackageBuilt": False, "sourceSha": source["sourceSha"], "consumerAttempt": source["attempt"],
            "shellLocalTransport": {"sha256": "8" * 64},
            "cases": {name: {"exitCode": 1 if name == "settled-failure" else 0} for name in L.SHELL_CASES},
        }
        summary = S.android_native_public_summary(source, legacy, preparation, records, L)
        self.assertEqual(summary["scope"], "android-same-job-private-native-summary-v1")
        self.assertIs(summary["signingExercised"], False)
        self.assertEqual([row["case"] for row in summary["cases"]], list(L.SHELL_CASES))
        self.assertFalse(any("android-saved-signing" in name for name in L.public_files({"shell": {}})))
