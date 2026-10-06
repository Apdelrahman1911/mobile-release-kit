"""Focused DATA contracts only; never macOS/native/Store execution evidence."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import plistlib
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zlib

PATH = Path(__file__).absolute().parents[2] / "desktop/tools/macos_e2_native_fixture.py"
SPEC = importlib.util.spec_from_file_location("mrk_e2_native_fixture_data", PATH)
fixture = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = fixture
SPEC.loader.exec_module(fixture)

SOURCE = "a" * 40
RELEASE = "macos26-arm64-e2-data"
WORK = (1, 2, 0o40700, 501, 20, 1, 0, 0, 0)


def tail(row):
    frame = bytearray(384)
    frame[:8] = b"MRKMNT01"
    struct.pack_into(">6I", frame, 8, 1, 8, 384, 0, 1, 256)
    frame[32:48] = bytes.fromhex(row["instanceHex"])
    frame[48:64] = bytes.fromhex(row["operationHex"])
    origin = int(row["startedNs"]) + 1000
    struct.pack_into(">3Q", frame, 104, origin, origin + 300_000_000_000, origin + 310_000_000_000)
    frame[144:184] = SOURCE.encode()
    frame[184:248] = RELEASE.encode().ljust(64, b"\0")
    frame[248:272] = fixture.TARGET.encode().ljust(24, b"\0")
    return frame.hex()


def cases():
    rows = []
    for index, name in enumerate(fixture.CASES):
        start = 1_000_000_000_000 + index * 400_000_000_000
        row = {key: True for key in fixture.CASE_FLAGS}
        row.update(case=name, outcome="passed", startedNs=str(start), finishedNs=str(start + 100_000_000_000),
                   firstFailureNs=str(start + 5000) if index == 1 else "0",
                   operationHex=bytes([11 + index] * 16).hex(), instanceHex=bytes([31 + index] * 16).hex(),
                   tailHex="", refused=index == 0, tailAdmissionIssued=index == 2,
                   testedUnregisterEntered=index == 2, fixtureCleanupUnregisterEntered=index != 2,
                   eof=index != 0)
        row["resourceStates"] = {"main": "settled", "client": "settled", "worker": "joined", "identity": "settled"}
        row["preServiceStop"] = None
        row["mainBundleLookup"] = {"bundle": "fixture-client", "executable": "fixture-client",
                                  "identifier": "fixture-client", "plist": "held-client-match"}
        row["mainObservations"] = {
            "observe": {"status": "not-registered", "outcome": "observed"},
            "register": {"status": "enabled", "outcome": "registration-requested"}}
        if index:
            row["tailHex"] = tail(row)
        rows.append(row)
    return rows


def result():
    return {"schemaVersion": 1, "type": "mrk-macos-e2-native-fixture-v1",
            "fixtureProfile": "e2-native-fixture-v1", "sourceCommit": SOURCE, "releaseId": RELEASE,
            "target": fixture.TARGET, "outcome": "passed", "nativeFinalityKnown": True,
            "auxiliaryNanoseconds": "1000", "syntheticIdentity": True,
            "productionIdentityQualified": False, "actualAppIntegrationQualified": False,
            "overlapObserved": False, "overlapEvidence": "unexecuted", "cases": cases()}


def parse(value, code=0):
    return fixture.native_result(fixture.canonical(value), code, SOURCE, RELEASE)


def unexecuted(name):
    row = {key: False for key in fixture.CASE_FLAGS}
    row.update(case=name, outcome="unexecuted", startedNs="0", finishedNs="0", firstFailureNs="0",
               operationHex="", instanceHex="", tailHex="",
               preServiceStop=None, mainObservations={"observe": None, "register": None}, mainBundleLookup=None,
               resourceStates={"main": "not-entered", "client": "not-entered",
                               "worker": "not-started", "identity": "not-entered"})
    return row


class NativeResultTests(unittest.TestCase):
    def test_three_distinct_cases_are_data_not_production_qualification(self):
        value = parse(result())
        self.assertEqual([row["case"] for row in value["cases"]], list(fixture.CASES))
        self.assertFalse(value["productionIdentityQualified"])
        self.assertFalse(value["actualAppIntegrationQualified"])

    def test_success_requires_all_actual_close_exit_and_custody_facts(self):
        for index, fields in ((0, ("watchRegistered", "refused", "noteExit", *fixture.CLOSE_FLAGS)),
                              (1, ("eof", "noteExit", "fixtureCleanupUnregisterEntered", *fixture.CLOSE_FLAGS)),
                              (2, ("eof", "noteExit", "tailAdmissionIssued", "testedUnregisterEntered", *fixture.CLOSE_FLAGS))):
            for field in fields:
                with self.subTest(case=index, field=field):
                    value = result()
                    value["cases"][index][field] = False
                    with self.assertRaises(fixture.Refused):
                        parse(value)

    def test_failed_admission_cannot_publish_tested_unregister_or_swap_cleanup(self):
        for field in ("tailAdmissionIssued", "testedUnregisterEntered"):
            value = result()
            value["cases"][1][field] = True
            with self.assertRaises(fixture.Refused):
                parse(value)
        value = result()
        value["cases"][2]["fixtureCleanupUnregisterEntered"] = True
        with self.assertRaises(fixture.Refused):
            parse(value)
        value = result()
        value["cases"][1]["firstFailureNs"] = "0"
        with self.assertRaises(fixture.Refused):
            parse(value)

    def test_source_incarnation_tail_and_scope_are_not_interchangeable(self):
        changes = (
            lambda value: value.update(sourceCommit="b" * 40),
            lambda value: value.update(releaseId="macos26-arm64-other"),
            lambda value: value.update(productionIdentityQualified=True),
            lambda value: value.update(actualAppIntegrationQualified=True),
            lambda value: value.update(overlapObserved=True),
            lambda value: value.update(nativeFinalityKnown=False),
            lambda value: value["cases"][1].update(operationHex=value["cases"][0]["operationHex"]),
            lambda value: value["cases"][1].update(instanceHex=value["cases"][0]["instanceHex"]),
            lambda value: value["cases"][1].update(tailHex="00" * 384),
            lambda value: value["cases"][1].update(tailHex=value["cases"][2]["tailHex"]),
        )
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                value = result()
                change(value)
                with self.assertRaises(fixture.Refused):
                    parse(value)
        value = result()
        frame = bytearray.fromhex(value["cases"][1]["tailHex"])
        struct.pack_into(">Q", frame, 296, 1)  # Local F cannot be forged into resident F.
        value["cases"][1]["tailHex"] = frame.hex()
        with self.assertRaises(fixture.Refused):
            parse(value)

    def test_clock_bounds_case_order_and_aggregate_budget_do_not_reset(self):
        for clock in ("-1", "01", 1, True, str(fixture.MAX_RAW + 1)):
            value = result()
            value["cases"][0]["startedNs"] = clock
            with self.assertRaises(fixture.Refused):
                parse(value)
        value = result()
        value["cases"][1]["startedNs"] = value["cases"][0]["startedNs"]
        with self.assertRaises(fixture.Refused):
            parse(value)
        value = result()
        value["auxiliaryNanoseconds"] = str(fixture.AUXILIARY_NS + 1)
        with self.assertRaises(fixture.Refused):
            parse(value)
        value["auxiliaryNanoseconds"] = str(fixture.AUXILIARY_NS)
        self.assertEqual(parse(value)["outcome"], "passed")
        self.assertEqual((fixture.WORK_SECONDS, fixture.HARD_SECONDS), (990, 993))

    def test_known_unavailability_is_never_a_pass_and_no_later_case_runs(self):
        value = result()
        value.update(outcome="unavailable")
        row = unexecuted(fixture.CASES[0])
        row.update(outcome="unavailable", startedNs="1", finishedNs="2")
        value["cases"] = [row, unexecuted(fixture.CASES[1]), unexecuted(fixture.CASES[2])]
        self.assertEqual(parse(value, 77)["outcome"], "unavailable")
        for code in (0, 1, -9, True):
            with self.assertRaises(fixture.Refused):
                parse(value, code)
        changed = copy.deepcopy(value)
        changed["cases"][1] = cases()[1]
        with self.assertRaises(fixture.Refused):
            parse(changed, 77)

        # Different original stop sites/observations stay distinguishable,
        # without turning unavailable native work into a passed case.
        row.update(mainReturned=True, mainClosed=True, identityClosed=True, workerJoined=True,
                   preServiceStop="observe-not-absent")
        row["resourceStates"].update(main="settled", identity="settled", worker="joined")
        row["mainObservations"]["observe"] = {"status": "not-found", "outcome": "observed"}
        observed = parse(value, 77)
        self.assertEqual(observed["cases"][0]["mainObservations"], row["mainObservations"])
        self.assertEqual(observed["outcome"], "unavailable")
        self.assertFalse(observed["cases"][0]["registered"])
        # Real native lookup diagnostics remain DATA, never permission to treat
        # NotFound as absence. Each relation is finite and no raw path escapes.
        examples = (("fixture-client", "fixture-client", "fixture-client", "held-client-match"),
                    ("fixture-client", "fixture-client", "fixture-client", "client-identity-mismatch"),
                    ("fixture-client", "unavailable", "other", "unavailable"),
                    ("fixture-outer", "fixture-entry", "fixture-outer", "outer-library-absent"),
                    ("fixture-outer", "fixture-entry", "fixture-outer", "outer-library-present"),
                    ("fixture-outer", "unavailable", "other", "unavailable"),
                    ("other", "other", "other", "other-bundle-not-read"),
                    ("unavailable", "unavailable", "unavailable", "unavailable"))
        for fields in examples:
            changed = copy.deepcopy(value)
            location = dict(zip(("bundle", "executable", "identifier", "plist"), fields))
            changed["cases"][0]["mainBundleLookup"] = location
            actual = parse(changed, 77)
            self.assertEqual(actual["cases"][0]["mainBundleLookup"], location)
            self.assertEqual(actual["cases"][0]["mainObservations"]["observe"]["status"], "not-found")
            self.assertEqual(actual["outcome"], "unavailable")
            self.assertFalse(actual["cases"][0]["registered"])
        valid_lookup = dict(zip(("bundle", "executable", "identifier", "plist"), examples[0]))
        for malformed_lookup in (False, [], {}, dict(valid_lookup, raw="private"),
                                 dict(valid_lookup, bundle="/private/unreported/app"),
                                 dict(valid_lookup, executable=None), dict(valid_lookup, identifier=[]),
                                 dict(valid_lookup, plist="outer-library-absent"),
                                 dict(valid_lookup, bundle="fixture-outer"),
                                 dict(valid_lookup, bundle="unavailable", plist="unavailable")):
            changed = copy.deepcopy(value)
            changed["cases"][0]["mainBundleLookup"] = malformed_lookup
            with self.assertRaises(fixture.Refused):
                parse(changed, 77)
        changed = copy.deepcopy(value)
        changed["cases"][0]["mainBundleLookup"] = valid_lookup
        changed["cases"][0]["mainObservations"]["observe"] = None
        with self.assertRaises(fixture.Refused):
            parse(changed, 77)
        changed = copy.deepcopy(value)
        changed["cases"][1]["mainBundleLookup"] = valid_lookup
        with self.assertRaises(fixture.Refused):
            parse(changed, 77)
        later = copy.deepcopy(value)
        later["cases"][0].update(preServiceStop="registration-not-returned", mainObservations={
            "observe": {"status": "not-registered", "outcome": "observed"}, "register": None})
        self.assertNotEqual(parse(later, 77)["cases"][0]["mainObservations"], row["mainObservations"])
        for stop in (False, [], {}, "private native error", "unknown"):
            changed = copy.deepcopy(value)
            changed["cases"][0]["preServiceStop"] = stop
            with self.assertRaises(fixture.Refused):
                parse(changed, 77)
        malformed = (None, False, [], {}, {"observe": None},
                     {"observe": None, "register": None, "raw": "private native error"},
                     {"observe": False, "register": None},
                     {"observe": {"status": [], "outcome": "observed"}, "register": None},
                     {"observe": {"status": "private native error", "outcome": "observed"}, "register": None},
                     {"observe": {"status": "not-found", "outcome": {}}, "register": None},
                     {"observe": {"status": "not-found", "outcome": "private native error"}, "register": None},
                     {"observe": {"status": "not-found", "outcome": "observed", "raw": "private"}, "register": None})
        for observations in malformed:
            changed = copy.deepcopy(value)
            changed["cases"][0]["mainObservations"] = observations
            with self.assertRaises(fixture.Refused):
                parse(changed, 77)
        changed = copy.deepcopy(value)
        changed["cases"][1]["mainObservations"]["observe"] = {"status": "not-found", "outcome": "observed"}
        with self.assertRaises(fixture.Refused):
            parse(changed, 77)
        changed = result()
        changed["cases"][0]["preServiceStop"] = "observe-not-absent"
        with self.assertRaises(fixture.Refused):
            parse(changed)


    def test_early_empty_allocations_do_not_fabricate_a_close_or_join(self):
        value = result()
        value["outcome"] = "unavailable"
        row = unexecuted(fixture.CASES[0])
        row.update(outcome="unavailable", startedNs="1", finishedNs="2", mainReturned=True)
        row["resourceStates"].update(main="returned-empty", client="returned-empty", identity="returned-empty")
        value["cases"] = [row, unexecuted(fixture.CASES[1]), unexecuted(fixture.CASES[2])]
        observed = parse(value, 77)
        self.assertFalse(observed["cases"][0]["workerJoined"])
        self.assertFalse(observed["cases"][0]["mainClosed"])
        for flag in ("mainClosed", "clientClosed", "identityClosed", "workerJoined"):
            changed = copy.deepcopy(value)
            changed["cases"][0][flag] = True
            with self.assertRaises(fixture.Refused):
                parse(changed, 77)
        for state in ("unknown", "not-started"):
            changed = copy.deepcopy(value)
            changed["cases"][0]["resourceStates"]["main"] = state
            with self.assertRaises(fixture.Refused):
                parse(changed, 77)
        changed = result()
        changed["cases"][0]["resourceStates"]["worker"] = "not-started"
        changed["cases"][0]["workerJoined"] = False
        with self.assertRaises(fixture.Refused):
            parse(changed)

    def test_ambiguous_json_extra_rows_and_unknown_return_are_refused(self):
        raw = fixture.canonical(result())
        for body in (raw + raw, raw[:-1], raw.replace(b'"schemaVersion":1', b'"schemaVersion":1,"schemaVersion":1'),
                     raw.replace(b'"schemaVersion":1', b'"schemaVersion":NaN'), raw + b" "):
            with self.assertRaises(fixture.Refused):
                fixture.native_result(body, 0, SOURCE, RELEASE)
        for code in (1, 77, -9):
            with self.assertRaises(fixture.Refused):
                fixture.native_result(raw, code, SOURCE, RELEASE)
        value = result()
        value["cases"].append(copy.deepcopy(value["cases"][-1]))
        with self.assertRaises(fixture.Refused):
            parse(value)


def bindings():
    environment = {"GITHUB_SHA": SOURCE, "GITHUB_WORKFLOW_SHA": SOURCE,
                   "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"}
    binding = {"schemaVersion": 1, "source": SOURCE, "workflowSource": SOURCE, "tree": "b" * 40,
               "runId": "123", "runAttempt": "1", "workDirectory": [1, 2, 501]}
    inventory = {"source": SOURCE, "tree": "b" * 40, "files": [
        {"path": "src/example.rs", "gitMode": "100644", "blob": "c" * 40, "size": 1, "sha256": "d" * 64}]}
    rust = {"schemaVersion": 1, "source": SOURCE, "workflowSource": SOURCE, "runId": "123", "runAttempt": "1",
            "cwd": "desktop/src-tauri", "autoInstall": False, "repositoryDefault": "1.98.0",
            "selectedMacToolchain": "1.98.1", "tools": {
                "rustc": {"command": ["rustc", "--version", "--verbose"],
                          "output": "rustc 1.98.1\nrelease: 1.98.1\ncommit-hash: " + fixture.RUST_COMMIT},
                "cargo": {"command": ["cargo", "--version", "--verbose"], "output": "cargo 1.98.1\nrelease: 1.98.1"}}}
    return environment, binding, inventory, rust


class BindingAndOriginalTests(unittest.TestCase):
    def test_source_run_work_and_effective_toolchain_are_jointly_bound(self):
        values = bindings()
        self.assertIn("src/example.rs", fixture.binding_data(*values, WORK))
        changes = (
            lambda values: values[1].update(runAttempt="2"),
            lambda values: values[1].update(workDirectory=[1, 3, 501]),
            lambda values: values[2].update(tree="e" * 40),
            lambda values: values[2]["files"].append(copy.deepcopy(values[2]["files"][0])),
            lambda values: values[2]["files"][0].update(path="../source.rs"),
            lambda values: values[3].update(autoInstall=True),
            lambda values: values[3].update(schemaVersion=True),
            lambda values: values[3]["tools"]["rustc"].update(output="rustc 1.98.0"),
        )
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                value = copy.deepcopy(bindings())
                change(value)
                with self.assertRaises(fixture.Refused):
                    fixture.binding_data(*value, WORK)

    def test_exact_cargo_release_is_required_in_the_existing_bound_output(self):
        self.assertIn("src/example.rs", fixture.binding_data(*bindings(), WORK))
        for output in ("cargo 1.98.1", "cargo 1.98.1\nrelease: 1.98.0",
                       "cargo 1.98.1\nrelease: 1.98.10", "cargo 1.98.1\nrelease: 1.98.1-nightly",
                       "cargo 1.98.1\nprerelease: 1.98.1"):
            with self.subTest(output=output):
                value = bindings()
                value[3]["tools"]["cargo"]["output"] = output
                with self.assertRaisesRegex(fixture.Refused, "^effective-cargo-clock-version$"):
                    fixture.binding_data(*value, WORK)

    def test_compiler_environment_uses_only_the_fixed_direct_image_bin(self):
        operation = object.__new__(fixture.Operation)
        operation.environment = {
            "HOME": "/Users/runner", "GITHUB_SHA": SOURCE,
            "DEVELOPER_DIR": "/Library/Developer/CommandLineTools",
            "PATH": "/unreviewed/bin", "RUSTUP_TOOLCHAIN": "nightly",
            "RUSTUP_AUTO_INSTALL": "1", "CARGO_NET_OFFLINE": "false",
        }
        operation.scratch, operation.release = Path("/synthetic/work"), RELEASE
        observed = []
        operation.outputs = SimpleNamespace(directory=observed.append)
        target = Path("/synthetic/target")
        direct = Path("/Users/runner/.rustup/toolchains/stable-aarch64-apple-darwin/bin")
        named = []
        def absent(path, *, follow_symlinks):
            self.assertFalse(follow_symlinks)
            named.append(path)
            raise FileNotFoundError()
        with patch.object(fixture.os, "stat", side_effect=absent), \
                patch.object(fixture.Path, "resolve", side_effect=AssertionError("no runtime path resolution")):
            cargo_path, environment = operation.compiler_environment(target)
        for name in ("config", "config.toml", "credentials", "credentials.toml"):
            self.assertIn(fixture.CHECKOUT / "desktop/src-tauri/.cargo" / name, named)
        self.assertEqual(observed, [direct])
        self.assertEqual(cargo_path, str(direct / "cargo"))
        self.assertEqual(environment["PATH"], str(direct) + ":/usr/bin:/bin:/usr/sbin:/sbin")
        self.assertEqual(environment["RUSTC"], str(direct / "rustc"))
        self.assertEqual(environment["RUSTUP_TOOLCHAIN"], "1.98.1")
        self.assertEqual(environment["RUSTUP_AUTO_INSTALL"], "0")
        self.assertEqual(environment["CARGO_NET_OFFLINE"], "true")
        self.assertEqual(environment["CARGO_TARGET_DIR"], str(target))
        self.assertNotIn("RUSTUP_DIST_SERVER", environment)
        self.assertNotIn("RUSTUP_UPDATE_ROOT", environment)
        self.assertEqual(fixture.RUST_COMMIT, "48a229ceaefd4985c50990b14116b6d856af0985")
        observed.clear()
        def forbidden_app_config(path, *, follow_symlinks):
            self.assertFalse(follow_symlinks)
            if path == fixture.CHECKOUT / "desktop/src-tauri/.cargo/config.toml":
                return SimpleNamespace()
            raise FileNotFoundError()
        with patch.object(fixture.os, "stat", side_effect=forbidden_app_config):
            with self.assertRaisesRegex(fixture.Refused, "^ambient-cargo-configuration$"):
                operation.compiler_environment(target)
        self.assertEqual(observed, [])  # Refuse before borrowing the direct compiler directory.

    def test_missing_or_unadmitted_direct_image_bin_has_no_fallback(self):
        operation = object.__new__(fixture.Operation)
        operation.environment = {"HOME": "/Users/runner", "GITHUB_SHA": SOURCE,
                                 "DEVELOPER_DIR": "/Library/Developer/CommandLineTools"}
        operation.scratch, operation.release = Path("/synthetic/work"), RELEASE
        direct = Path("/Users/runner/.rustup/toolchains/stable-aarch64-apple-darwin/bin")
        for error in (FileNotFoundError("fixed image bin missing"), fixture.Refused("directory-owner-mode")):
            with self.subTest(reason=type(error).__name__):
                observed = []
                def refuse(path):
                    observed.append(path)
                    raise error
                operation.outputs = SimpleNamespace(directory=refuse)
                with patch.object(fixture.os, "stat", side_effect=FileNotFoundError()), \
                        patch.object(fixture.Path, "resolve", side_effect=AssertionError("no path repair")):
                    with self.assertRaises(type(error)):
                        operation.compiler_environment(Path("/synthetic/target"))
                self.assertEqual(observed, [direct])

    def test_domain_declaration_is_narrow_and_no_retry_or_integer_false_alias(self):
        domain = {"schemaVersion": 1, "allocation": "fresh-github-hosted-single-job",
                  "writer": "macos_e2_native_fixture.py", "root": str(fixture.ROOT), "receipt": fixture.PACKAGE,
                  "priorFixtureUse": False}
        fixture.fixture_domain({"fixtureAdministrativeDomain": domain})
        for key, replacement in (("priorFixtureUse", True), ("priorFixtureUse", 0),
                                 ("schemaVersion", True), ("root", "/Library/Application Support/MobileReleaseKit"),
                                 ("receipt", "dev.mobile-release-kit.desktop.installed")):
            with self.subTest(key=key, replacement=replacement):
                value = dict(domain)
                value[key] = replacement
                with self.assertRaises(fixture.Refused):
                    fixture.fixture_domain({"fixtureAdministrativeDomain": value})

    def test_unknown_close_is_consumed_once_and_does_not_hide_other_closes(self):
        originals = fixture.Originals()
        first = originals.register(90, "/synthetic/first", "file")
        second = originals.register(91, "/synthetic/second", "file")
        calls = []
        def close(fd):
            calls.append(fd)
            if fd == 91:
                raise OSError("synthetic")
        with patch.object(fixture.os, "close", close):
            self.assertFalse(originals.finish())
            self.assertFalse(originals.finish())
        self.assertEqual(calls, [91, 90])
        self.assertFalse(second["closed"])
        self.assertTrue(first["closed"])

    def test_original_owner_result_contract_is_not_a_fabricated_receipt(self):
        argv = ["/fixed/synthetic"]
        good = subprocess.CompletedProcess(argv, 0, b"data", b"")
        self.assertIs(fixture.completed(good, argv, 4), good)
        for value in (SimpleNamespace(args=argv, returncode=0, stdout=b"data", stderr=b""),
                      subprocess.CompletedProcess(["/wrong"], 0, b"data", b""),
                      subprocess.CompletedProcess(argv, True, b"data", b""),
                      subprocess.CompletedProcess(argv, 0, "data", b""),
                      subprocess.CompletedProcess(argv, 0, b"data", b"extra")):
            with self.assertRaises(fixture.Refused):
                fixture.completed(value, argv, 4)


def cargo(role):
    checkout = Path("/synthetic/checkout")
    target = Path("/synthetic/target-" + role)
    native_features = (["desktop-image", "e2-native-fixture"] if role == "client" else
                       ["android-registration-helper", "default", "e2-native-fixture", "resident-image"])
    native = {"reason": "compiler-artifact", "target": {"name": "mrk_macos_installed_native",
              "kind": ["lib"], "crate_types": ["lib"], "src_path": str(checkout / fixture.NATIVE / "src/lib.rs"),
              "edition": "2021"}, "features": native_features,
              "filenames": [str(target / "native.rlib")], "executable": None,
              "package_id": "path+" + (checkout / fixture.NATIVE).as_uri() + "#mrk-macos-installed-native@0.1.0",
              "manifest_path": str(checkout / fixture.NATIVE / "Cargo.toml"),
              "profile": {"test": False, "debug_assertions": False, "opt_level": "3"}, "fresh": False}
    directory = fixture.NATIVE if role == "client" else fixture.HELPER
    package = "mrk-macos-installed-native" if role == "client" else "mrk-android-register"
    binary = target / fixture.TARGET / "release" / (
        "examples/libe2_maintenance_client.dylib" if role == "client" else "libmrk_resident_image.dylib")
    row = {"reason": "compiler-artifact",
           "package_id": "path+" + (checkout / directory).as_uri() + "#" + package + "@0.1.0",
           "manifest_path": str(checkout / directory / "Cargo.toml"),
           "features": ["desktop-image", "e2-native-fixture"] if role == "client" else ["e2-native-fixture"],
           "filenames": [str(binary)], "executable": None,
           "target": {"name": "e2_maintenance_client" if role == "client" else "mrk_resident_image",
                      "kind": ["example"] if role == "client" else ["cdylib"], "crate_types": ["cdylib"],
                      "src_path": str(checkout / directory / ("examples/e2_maintenance_client.rs" if role == "client" else "src/lib.rs")),
                      "edition": "2021"},
           "profile": {"test": False, "debug_assertions": False, "opt_level": "3"}, "fresh": False}
    return checkout, target, binary, [native, row, {"reason": "build-finished", "success": True}]


NATIVE_TEST_NAMES = (
    "tests::compiled_machine_and_translation_data_refuse_foreign_or_unknown_hosts",
    "e2_native_fixture::fixture_data_tests::empty_and_unexecuted_resources_do_not_become_closes_or_joins",
    "e2_native_fixture::fixture_data_tests::result_is_bounded_one_line_with_truthful_empty_resource_projection",
)


INSTALLER_WORKER_TEST_NAMES = (
    "installer::worker::tests::same_absolute_endpoint_reserves_settlement_and_rejects_backwards_or_overflow",
    "installer::worker::tests::private_frames_require_fixed_binding_shapes_bounds_and_no_future_finality",
    "installer::worker::tests::original_join_requires_eof_closes_matching_return_and_timely_sources",
)


def native_test_stdout(names=NATIVE_TEST_NAMES):
    return ("\nrunning 3 tests\n" + "".join("test " + name + " ... ok\n" for name in names)
            + "\ntest result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 127 filtered out; finished in 0.01s\n\n").encode("ascii")


class CargoTests(unittest.TestCase):
    def test_exact_separate_example_and_resident_compiler_rosters(self):
        for role in ("client", "resident"):
            checkout, target, binary, rows = cargo(role)
            data = b"".join(fixture.canonical(row) for row in rows)
            self.assertEqual(fixture.cargo_artifact(data, role, checkout, target), binary)

    def test_wrong_role_profile_terminal_or_guessed_binary_is_refused(self):
        changes = (
            lambda rows: rows[1]["features"].append("installed-observation"),
            lambda rows: rows[0]["features"].append("resident-image"),
            lambda rows: rows[1]["target"].update(crate_types=["bin"]),
            lambda rows: rows[1]["profile"].update(test=True),
            lambda rows: rows[1].update(filenames=["/guessed/lib.dylib"]),
            lambda rows: rows[-1].update(success=False),
            lambda rows: rows.append(copy.deepcopy(rows[0])),
        )
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                checkout, target, _binary, rows = cargo("client")
                change(rows)
                with self.assertRaises(fixture.Refused):
                    fixture.cargo_artifact(b"".join(fixture.canonical(row) for row in rows), "client", checkout, target)

    def test_native_rust_batch_preserves_fixed_target_scope_and_original_lifecycle(self):
        # Instance-only inert originals: real build_images/call/command/receipt,
        # but no compiler, native action, filesystem mutation or process runs.
        build = (PATH.parents[1] / "native/macos-installed-native/build.rs").read_text(encoding="utf-8")
        self.assertNotIn("cargo:rustc-link-arg=-Wl,-install_name,@rpath/libmrk_e2_native_client.dylib", build)
        self.assertNotIn("cargo:rustc-link-arg=-mmacosx-version-min=26.0", build)
        self.assertEqual(fixture.NATIVE_RUST_TESTS, NATIVE_TEST_NAMES)

        class UnknownOriginal(Exception):
            dispatched, contained, cleanup_complete = True, False, False

        modes = (("success", 3, 2, True), ("unit-nonzero", 1, 1, False),
                 ("unit-unknown", 1, 0, False), ("unit-malformed", 1, 1, False),
                 ("client-nonzero", 2, 1, True), ("client-unknown", 2, 0, True))
        for mode, count, retired_count, unit_passed in modes:
            with self.subTest(mode=mode):
                invocations, created, retired, copied, published, checks = [], [], [], [], [], []
                source = SimpleNamespace(book=SimpleNamespace(check=lambda: checks.append(True)),
                                         binding={"tree": "b" * 40}, inventory_digest="c" * 64,
                                         source_handle_count=1, source_handle_reserve=64, binding_digest="d" * 64)
                environment = {"GITHUB_SHA": SOURCE, "GITHUB_WORKFLOW_SHA": SOURCE,
                               "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1"}
                value = fixture.Operation(None, source, None, Path("/synthetic/build-scope"), environment)
                value.mkdir = lambda path: created.append(path) or {"identity": WORK[:5]}
                value.compiler_environment = lambda target: ("/synthetic/cargo", {"CARGO_TARGET_DIR": str(target)})
                value.retire_target = retired.append
                value.publish = lambda name, body: published.append((name, body))

                def copy_image(role, binary, target):
                    copied.append((role, binary, target))
                    value.artifacts[role] = {}
                value.copy_image = copy_image

                def owned(argv, **kwargs):
                    invocations.append((list(argv), kwargs))
                    unit = argv[1] == "test"
                    if (unit and mode == "unit-unknown") or (argv[1] == "rustc" and mode == "client-unknown"):
                        raise UnknownOriginal("inert unknown original")
                    code = 1 if (unit and mode == "unit-nonzero") or (argv[1] == "rustc" and mode == "client-nonzero") else 0
                    if unit:
                        body = b"\nrunning 0 tests\n" if mode == "unit-malformed" else native_test_stdout()
                    else:
                        role = "client" if argv[1] == "rustc" else "resident"
                        checkout, target, _binary, rows = cargo(role)
                        body = b"".join(fixture.canonical(row) for row in rows)
                        body = body.replace(str(checkout).encode(), str(fixture.CHECKOUT).encode())
                        body = body.replace(str(target).encode(), kwargs["environ"]["CARGO_TARGET_DIR"].encode())
                    return subprocess.CompletedProcess(argv, code, body, b"")
                value.owner = SimpleNamespace(run_owned=owned, ProcessOutcomeUnknown=UnknownOriginal)
                self.assertIsNone(value.native_rust_tests)
                if mode == "success":
                    value.build_images()
                else:
                    error = UnknownOriginal if mode.endswith("unknown") else fixture.Refused
                    with self.assertRaises(error):
                        value.build_images()
                self.assertEqual(len(invocations), count)
                self.assertEqual([row["role"] for row in value.calls],
                                 ["native-rust-tests", "client-build", "resident-build"][:count])
                self.assertEqual([row["returned"] for row in value.calls],
                                 [True] * (count - 1) + [not mode.endswith("unknown")])
                self.assertEqual(retired, [value.scratch / (role + "-target") for role in ("client", "resident")][:retired_count])
                self.assertEqual(created, [value.scratch / (role + "-target") for role in ("client", "resident")][:2 if mode == "success" else 1])
                self.assertEqual(len(copied), 2 if mode == "success" else 0)
                self.assertEqual(len(checks), 2 * count - int(mode.endswith("unknown")))
                self.assertEqual(len(published), 2 * (count - int(mode.endswith("unknown"))))
                self.assertEqual(value.native_rust_tests is not None, unit_passed)
                if mode.endswith("unknown"):
                    self.assertEqual(value.calls[-1]["errorType"], "ProcessOutcomeUnknown")
                    self.assertFalse(value.calls[-1]["cleanup_complete"])
                if mode.endswith("nonzero"):
                    self.assertEqual(value.calls[-1]["returncode"], 1)

                def common(directory, features):
                    return ["--manifest-path", str(fixture.CHECKOUT / directory / "Cargo.toml"),
                            "--locked", "--offline", "--release", "--jobs", "1", "--target", "aarch64-apple-darwin",
                            "--no-default-features", "--features", features]
                expected = [
                    ["/synthetic/cargo", "test", *common(fixture.NATIVE, "desktop-image,e2-native-fixture"),
                     "--lib", "--message-format=short", "--color", "never", "--", "--exact", "--test-threads=1",
                     "--format", "pretty", "--color", "never", *NATIVE_TEST_NAMES],
                    ["/synthetic/cargo", "rustc", *common(fixture.NATIVE, "desktop-image,e2-native-fixture"),
                     "--example", "e2_maintenance_client", "--message-format=json-render-diagnostics", "--", "-C",
                     "link-arg=-Wl,-install_name,@rpath/libmrk_e2_native_client.dylib", "-C", "link-arg=-mmacosx-version-min=26.0"],
                    ["/synthetic/cargo", "build", *common(fixture.HELPER, "e2-native-fixture"),
                     "--lib", "--message-format=json-render-diagnostics"],
                ]
                self.assertEqual([argv for argv, _kwargs in invocations], expected[:count])
                for index, (_argv, kwargs) in enumerate(invocations):
                    self.assertEqual(kwargs, {"environ": {"CARGO_TARGET_DIR": str(value.scratch / (
                        "resident-target" if index == 2 else "client-target"))}, "cwd": fixture.CHECKOUT,
                        "timeout": 480, "capture": True, "text": False, "output_limit": 4 * 1024 * 1024})
                if count >= 2:
                    self.assertIs(invocations[0][1]["environ"], invocations[1][1]["environ"])
                if mode == "success":
                    # Owner success cannot silently omit the now-required unit batch.
                    value.native, value.release = {"outcome": "passed"}, RELEASE
                    for key in ("native_entered", "native_returned", "sources_closed", "outputs_closed",
                                "protected_closed", "scratch_retired", "installer_entered", "installed"):
                        setattr(value, key, True)
                    self.assertFalse(value.receipt(None)["passed"])  # New context phase cannot be omitted.
                    value.installer_context = InstallerContextTests.public()
                    self.assertFalse(value.receipt(None)["passed"])  # Installer bin3 is independently required.
                    value.installer_worker_rust_tests = fixture.installer_worker_rust_test_record()
                    self.assertTrue(value.receipt(None)["passed"])  # Inert receipt DATA only, not an executed Mac test.
                    self.assertEqual(value.receipt(None)["nativeRustTests"], value.native_rust_tests)
                    self.assertEqual(value.receipt(None)["installerWorkerRustTests"], value.installer_worker_rust_tests)
                    value.installer_worker_rust_tests = None
                    self.assertFalse(value.receipt(None)["passed"])
                    value.installer_worker_rust_tests = fixture.installer_worker_rust_test_record()
                    value.native_rust_tests = None
                    self.assertFalse(value.receipt(None)["passed"])

        # The current real bin/feature/build script are SOURCE, not substitutes.
        app = PATH.parents[1] / "src-tauri"
        manifest = (app / "Cargo.toml").read_text(encoding="utf-8")
        installer = (app / "src/bin/macos_install.rs").read_text(encoding="utf-8")
        build = (app / "build.rs").read_text(encoding="utf-8")
        self.assertIn('name = "mrk-macos-install"\npath = "src/bin/macos_install.rs"\nrequired-features = ["macos-installed-installer"]', manifest)
        self.assertIn('macos-installed-installer = []', manifest)
        self.assertIn('#[path = "src/macos_build_release.rs"]', build)
        for name in ("platforms-v1.json", "build-release.json", "build-release-intel.json"):
            self.assertIn("../macos-installed-inputs/" + name, build)
        self.assertEqual(fixture.INSTALLER_WORKER_RUST_TESTS, INSTALLER_WORKER_TEST_NAMES)
        for name in INSTALLER_WORKER_TEST_NAMES:
            self.assertIn("fn " + name.rsplit("::", 1)[1] + "(", installer)

        for mode in ("success", "nonzero", "unknown", "malformed", "source-before-entry", "compiler-refused"):
            with self.subTest(installer_bin=mode):
                invocations, created, retired, published, events = [], [], [], [], []
                def source_check():
                    if mode == "source-before-entry":
                        raise fixture.Refused("original-changed")
                source = SimpleNamespace(book=SimpleNamespace(check=source_check),
                                         binding={"tree": "b" * 40}, inventory_digest="c" * 64,
                                         source_handle_count=1, source_handle_reserve=192, binding_digest="d" * 64,
                                         rows={"desktop/src-tauri/src/bin/macos_install.rs": {}})
                environment = {"GITHUB_SHA": SOURCE, "GITHUB_WORKFLOW_SHA": SOURCE,
                               "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1"}
                value = fixture.Operation(None, source, None, Path("/synthetic/installer-bin"), environment)
                value.release = RELEASE
                value.outputs.directories[value.scratch] = {"identity": WORK[:5]}
                value.begin = lambda: events.append("begin")
                value.mkdir = lambda path: created.append(path) or {"identity": WORK[:5]}
                value.retire_target = retired.append
                value.publish = lambda name, body: published.append((name, body))
                value.finish = lambda: events.append("finish")  # Real finish custody has its existing selected tests.
                def compiler_environment(target):
                    if mode == "compiler-refused":
                        raise fixture.Refused("ambient-cargo-configuration")
                    return "/synthetic/cargo", {"CARGO_TARGET_DIR": str(target)}
                value.compiler_environment = compiler_environment
                def context():
                    events.append("context")
                    raise fixture.Refused("inert-context-stop")  # Never enter a real Installer from this DATA test.
                value.observe_installer_context = context
                def owned(argv, **options):
                    invocations.append((list(argv), options))
                    if mode == "unknown":
                        raise UnknownOriginal("inert unknown original")
                    body = b"\nrunning 0 tests\n" if mode == "malformed" else native_test_stdout(INSTALLER_WORKER_TEST_NAMES)
                    return subprocess.CompletedProcess(argv, 1 if mode == "nonzero" else 0, body, b"")
                value.owner = SimpleNamespace(run_owned=owned, ProcessOutcomeUnknown=UnknownOriginal)
                receipt = value.execute()  # Real ordering, build method, call and command; no external originals.
                target = value.scratch / "installer-worker-target"
                self.assertEqual(created, [target])
                self.assertEqual(retired, [] if mode == "unknown" else [target])
                self.assertEqual(events, ["begin", "context", "finish"] if mode == "success" else ["begin", "finish"])
                self.assertEqual(receipt["failure"], {
                    "success": "inert-context-stop", "nonzero": "original-command-failed",
                    "unknown": "original-operation-refused-or-unknown", "malformed": "installer-worker-rust-test-framing",
                    "source-before-entry": "original-changed", "compiler-refused": "ambient-cargo-configuration",
                }[mode])
                self.assertFalse(receipt["passed"])
                self.assertFalse(receipt["installerEntered"] or receipt["nativeEntered"])
                self.assertFalse(receipt["installerContext"]["started"])
                self.assertIsNone(receipt["nativeRustTests"])
                self.assertEqual(receipt["installerWorkerRustTests"] is not None, mode == "success")
                if mode in ("source-before-entry", "compiler-refused"):
                    self.assertEqual(invocations, [])
                    self.assertEqual(receipt["originalCalls"], [])
                    self.assertEqual(published, [])
                    continue
                self.assertEqual([row["role"] for row in receipt["originalCalls"]], ["installer-worker-rust-tests"])
                self.assertEqual(receipt["originalCalls"][0]["returned"], mode != "unknown")
                self.assertEqual(len(published), 0 if mode == "unknown" else 2)
                diagnostic = receipt["originalCalls"][0].get("installerWorkerDiagnostic")
                self.assertEqual(diagnostic is not None, mode == "nonzero")
                if diagnostic is not None:
                    self.assertEqual(diagnostic["classification"], "unrecognized")
                    self.assertIsNotNone(fixture.installer_worker_diagnostic_data(diagnostic, receipt["originalCalls"][0], source.rows))
                self.assertEqual(invocations, [([
                    "/synthetic/cargo", "test", "--manifest-path", str(fixture.CHECKOUT / "desktop/src-tauri/Cargo.toml"),
                    "--locked", "--offline", "--jobs", "1", "--target", "aarch64-apple-darwin",
                    "--no-default-features", "--features", "macos-installed-installer", "--bin", "mrk-macos-install",
                    "--message-format=short", "--color", "never", "--", "--exact", "--test-threads=1",
                    "--format", "pretty", "--color", "never", *INSTALLER_WORKER_TEST_NAMES,
                ], {"environ": {"CARGO_TARGET_DIR": str(target)}, "cwd": fixture.CHECKOUT,
                    "timeout": 480, "capture": True, "text": False, "output_limit": 4 * 1024 * 1024})])
                self.assertNotIn("--release", invocations[0][0])  # Ordinary test profile, not shipping compilation.
                if mode == "unknown":
                    self.assertEqual(receipt["originalCalls"][0]["errorType"], "ProcessOutcomeUnknown")
                    self.assertFalse(receipt["originalCalls"][0]["cleanup_complete"])


        # A bounded diagnostic explains only already-returned failure; no raw
        # compiler message, foreign filename or test assertion value escapes.
        path = "desktop/src-tauri/src/bin/macos_install.rs"
        source_rows = {path: {}, "desktop/src-tauri/src/lib.rs": {},
                       "desktop/native/macos-installed-native/src/lib.rs": {}}
        selected = INSTALLER_WORKER_TEST_NAMES[0]
        private = "PRIVATE-DIAGNOSTIC-TEXT"
        stderr = ("src/bin/macos_install.rs:1674:9: error[E0282]: " + private + "\n"
                  + str(fixture.CHECKOUT / path) + ":1684:4: error: " + private + "\n"
                  + "src/lib.rs:2:3: error[E0308]: " + private + "\n"
                  + "/private/unrelated.rs:4:5: error[E0412]: " + private + "\n"
                  + "./desktop/src-tauri/src/bin/macos_install.rs:6:7: error[E0283]: " + private + "\n"
                  + "error[E0599]: " + private + "\n").encode()
        stdout = ("test " + selected + " ... FAILED\n"
                  + "thread '" + selected + "' (42) panicked at src/bin/macos_install.rs:7:8:\n"
                  + private + "\n").encode()
        diagnostic = fixture.installer_worker_diagnostic_result(stdout, stderr, source_rows)
        self.assertEqual(diagnostic["classification"], "mixed")
        self.assertEqual(diagnostic["errorCodes"], ["E0282", "E0308", "E0412", "E0283", "E0599"])
        self.assertEqual([row["path"] for row in diagnostic["errorLocations"]], [path, path, None, None, path])
        self.assertTrue(diagnostic["unresolvedLocations"])
        self.assertEqual(diagnostic["failedTests"], [selected])
        self.assertEqual(diagnostic["panicLocations"], [{"test": selected, "path": path, "line": 7, "column": 8}])
        self.assertNotIn(private.encode(), fixture.canonical(diagnostic))
        self.assertNotIn(b"/private/", fixture.canonical(diagnostic))
        self.assertNotIn(str(fixture.CHECKOUT).encode(), fixture.canonical(diagnostic))
        embedded = b"src/bin/macos_install.rs:9:10: error[E0282]: arbitrary:11:12: error[E9999]: private\n"
        prefix_only = fixture.installer_worker_diagnostic_result(b"", embedded, source_rows)
        self.assertEqual(prefix_only["errorCodes"], ["E0282"])
        self.assertEqual(prefix_only["errorLocations"], [{"code": "E0282", "path": path, "line": 9, "column": 10}])
        original_call = {"role": "installer-worker-rust-tests", "entered": True, "returned": True, "returncode": 101,
                         "workTimeoutSeconds": 480, "outputLimitBytes": 4 * 1024 * 1024,
                         "stdoutSha256": fixture.digest(stdout), "stderrSha256": fixture.digest(stderr)}
        validated = fixture.installer_worker_diagnostic_data(diagnostic, original_call, source_rows)
        self.assertEqual(validated, diagnostic)
        self.assertIsNot(validated, diagnostic)
        self.assertIsNot(validated["errorLocations"][0], diagnostic["errorLocations"][0])
        for change in ({"returned": False}, {"returncode": 0}, {"returncode": True}, {"role": "client-build"},
                       {"workTimeoutSeconds": 481}, {"outputLimitBytes": True}, {"stdoutSha256": "f" * 64}):
            with self.subTest(call=change):
                self.assertIsNone(fixture.installer_worker_diagnostic_data(diagnostic, dict(original_call, **change), source_rows))
        for change in ({"schemaVersion": True}, {"diagnosticOnly": False}, {"rawOutput": private}, {"truncated": 1},
                       {"classification": "passed"}, {"unresolvedLocations": False}, {"stdoutBytes": True},
                       {"stdoutBytes": 4 * 1024 * 1024}, {"failedTests": ["foreign::test"]},
                       {"errorCodes": ["E0282", "E0282"]}, {"errorCodes": ["E0282\nsecret"]}):
            with self.subTest(diagnostic=change):
                self.assertIsNone(fixture.installer_worker_diagnostic_data(dict(diagnostic, **change), original_call, source_rows))
        for change in ({"path": "/private/unrelated.rs"}, {"line": True}, {"column": 0}, {"code": "E9999"}):
            copy_value = copy.deepcopy(diagnostic)
            copy_value["errorLocations"][0].update(change)
            self.assertIsNone(fixture.installer_worker_diagnostic_data(copy_value, original_call, source_rows))
        hostile = (b"\x1b[31msrc/bin/macos_install.rs:1:1: error[E0001]: secret\n"
                   b"src/bin/\xff.rs:1:1: error[E0002]: secret\n"
                   b"src/bin/macos_install.rs:0:1: error[E0003]: secret\n"
                   b"src/bin/macos_install.rs:10000000:1: error[E0004]: secret\n"
                   b"test foreign::test ... FAILED\nthread 'foreign::test' panicked at src/bin/macos_install.rs:1:1:\n")
        self.assertEqual(fixture.installer_worker_diagnostic_result(hostile, b"", source_rows)["classification"], "unrecognized")
        many = b"\n".join(("src/bin/macos_install.rs:1:1: error[E%04d]: private" % number).encode() for number in range(40))
        bounded = fixture.installer_worker_diagnostic_result(b"x" * 8193 + b"\n", many, source_rows)
        self.assertTrue(bounded["truncated"])
        self.assertEqual(len(bounded["errorCodes"]), 32)
        self.assertEqual(len(bounded["errorLocations"]), 12)
        self.assertLessEqual(len(fixture.canonical(bounded)), 12 * 1024)
        saturated = b"\n".join(("error[E%04d]: private" % number).encode() for number in range(32))
        saturated += b"\nsrc/bin/macos_install.rs:1:1: error[E0032]: private\n"
        capped = fixture.installer_worker_diagnostic_result(b"", saturated, source_rows)
        self.assertTrue(capped["truncated"])
        self.assertEqual(capped["errorLocations"], [])
        self.assertIsNotNone(fixture.installer_worker_diagnostic_data(capped, dict(original_call,
                            stdoutSha256=fixture.digest(b""), stderrSha256=fixture.digest(saturated)), source_rows))
        self.assertEqual(fixture.installer_worker_diagnostic_result(stdout, b"", source_rows)["classification"], "selected-test-failures")
        self.assertEqual(fixture.installer_worker_diagnostic_result(b"", stderr, source_rows)["classification"], "rust-errors")
        for output, other, supplied in ((None, b"", source_rows), (b"", "text", source_rows),
                                         (b"x" * (4 * 1024 * 1024 + 1), b"", source_rows), (b"", b"", None)):
            self.assertIsNone(fixture.installer_worker_diagnostic_result(output, other, supplied))

        # Diagnostic exception/capture failure cannot replace the actual refusal.
        # Everything below uses the same call/command plus inert per-instance originals.
        for mode in ("known", "diagnostic-refused", "capture-refused", "post-refused"):
            events, checks = [], []
            def source_check():
                checks.append(True)
                if mode == "post-refused" and len(checks) == 2:
                    raise fixture.Refused("original-changed")
            source = SimpleNamespace(book=SimpleNamespace(check=source_check), rows=source_rows)
            value = fixture.Operation(None, source, None, Path("/synthetic/failure-diagnostic"), {"GITHUB_SHA": SOURCE})
            def publish(name, body):
                events.append(name)
                if mode == "capture-refused":
                    raise fixture.Refused("output-close-unknown")
            value.publish = publish
            value.owner = SimpleNamespace(run_owned=lambda argv, **kwargs: subprocess.CompletedProcess(argv, 101, stdout, stderr))
            original_parser = fixture.installer_worker_diagnostic_result
            def observe_parser(*args):
                self.assertEqual(events, ["installer-worker-rust-tests.stdout", "installer-worker-rust-tests.stderr"])
                if mode == "diagnostic-refused":
                    raise fixture.Refused("inert-diagnostic-refused")
                return original_parser(*args)
            with patch.object(fixture, "installer_worker_diagnostic_result", side_effect=observe_parser):
                expected_failure = {"capture-refused": "output-close-unknown", "post-refused": "original-changed"}.get(mode, "original-command-failed")
                with self.assertRaisesRegex(fixture.Refused, "^" + expected_failure + "$"):
                    value.command("installer-worker-rust-tests", ["/synthetic/cargo"], {}, cwd=Path("/synthetic"), timeout=480, limit=4 * 1024 * 1024)
            self.assertTrue(value.calls[0]["returned"])
            self.assertEqual(value.calls[0]["returncode"], 101)
            self.assertEqual("installerWorkerDiagnostic" in value.calls[0], mode == "known")

    def test_native_rust_results_require_three_actual_successes_and_exact_closed_record(self):
        expected = {"schemaVersion": 1, "type": "mrk-macos-native-rust-tests-v1", "target": "aarch64-apple-darwin",
                    "tests": list(NATIVE_TEST_NAMES), "passed": 3, "failed": 0, "ignored": 0, "measured": 0}
        body = native_test_stdout()
        for data in (body, native_test_stdout(tuple(reversed(NATIVE_TEST_NAMES))), body.replace(b"0.01s", b"480.00s")):
            self.assertEqual(fixture.native_rust_tests_result(data), expected)
        projected = fixture.native_rust_tests_data(expected)
        self.assertEqual(projected, expected)
        self.assertIsNot(projected, expected)
        self.assertIsNot(projected["tests"], expected["tests"])
        bad_output = (None, "not bytes", b"", b"x" * 65537, body + b"\xff", body[:-1], b"extra\n" + body,
                      body.replace(b"running 3 tests", b"running 0 tests"),
                      native_test_stdout(NATIVE_TEST_NAMES[:2]),
                      native_test_stdout((NATIVE_TEST_NAMES[0], NATIVE_TEST_NAMES[0], NATIVE_TEST_NAMES[2])),
                      body.replace(NATIVE_TEST_NAMES[0].encode(), b"unknown::test"),
                      body.replace(b" ... ok\n", b" ... ignored\n", 1),
                      body.replace(b" ... ok\n", b" ... FAILED\n", 1),
                      body.replace(b"3 passed; 0 failed", b"2 passed; 1 failed"),
                      body.replace(b"0 ignored", b"1 ignored"), body.replace(b"127 filtered", b"0127 filtered"),
                      body.replace(b"0.01s", b"NaNs"), body.replace(b"0.01s", b"480.01s"),
                      body.replace(b" ... ok\n", b" ... \x1b[32mok\x1b[0m\n", 1))
        for index, data in enumerate(bad_output):
            with self.subTest(output=index), self.assertRaises(fixture.Refused):
                fixture.native_rust_tests_result(data)
        mutations = [{key: bool(expected[key])} for key in ("schemaVersion", "passed", "failed", "ignored", "measured")]
        mutations += [{"target": "x86_64-apple-darwin"}, {"tests": tuple(NATIVE_TEST_NAMES)},
                      {"tests": [NATIVE_TEST_NAMES[0]] * 3}, {"tests": [None, *NATIVE_TEST_NAMES[1:]]},
                      {"rawOutput": "synthetic-private-output"}, {"type": "other"}]
        for index, change in enumerate(mutations):
            with self.subTest(record=index), self.assertRaises(fixture.Refused):
                fixture.native_rust_tests_data(dict(expected, **change))
        for data in (None, [], {key: item for key, item in expected.items() if key != "failed"}):
            with self.assertRaises(fixture.Refused):
                fixture.native_rust_tests_data(data)

        worker_expected = {"schemaVersion": 1, "type": "mrk-macos-installer-worker-rust-tests-v1",
                           "target": "aarch64-apple-darwin", "cargoProfile": "test",
                           "tests": list(INSTALLER_WORKER_TEST_NAMES), "passed": 3, "failed": 0,
                           "ignored": 0, "measured": 0}
        worker_body = native_test_stdout(INSTALLER_WORKER_TEST_NAMES)
        for data in (worker_body, native_test_stdout(tuple(reversed(INSTALLER_WORKER_TEST_NAMES)))):
            self.assertEqual(fixture.installer_worker_rust_tests_result(data), worker_expected)
        projected = fixture.installer_worker_rust_tests_data(worker_expected)
        self.assertEqual(projected, worker_expected)
        self.assertIsNot(projected, worker_expected)
        self.assertIsNot(projected["tests"], worker_expected["tests"])
        for parser, data in ((fixture.native_rust_tests_result, worker_body),
                             (fixture.installer_worker_rust_tests_result, body),
                             (fixture.native_rust_tests_data, worker_expected),
                             (fixture.installer_worker_rust_tests_data, expected)):
            with self.assertRaises(fixture.Refused):
                parser(data)  # A different actual three-test batch cannot satisfy this role.
        for data in (worker_body.replace(b"0 ignored", b"1 ignored"),
                     worker_body.replace(b"0.01s", b"480.01s"),
                     native_test_stdout((INSTALLER_WORKER_TEST_NAMES[0],) * 3),
                     worker_body + b"private trailing output\n"):
            with self.assertRaises(fixture.Refused):
                fixture.installer_worker_rust_tests_result(data)
        for change in ({"cargoProfile": "release"}, {"cargoProfile": None}, {"target": "x86_64-apple-darwin"},
                       {"passed": True}, {"ignored": 1}, {"tests": list(NATIVE_TEST_NAMES)},
                       {"tests": [INSTALLER_WORKER_TEST_NAMES[0]] * 3}, {"futureWorkerFinality": True}):
            with self.subTest(worker_record=change), self.assertRaises(fixture.Refused):
                fixture.installer_worker_rust_tests_data(dict(worker_expected, **change))
        with self.assertRaises(fixture.Refused):
            fixture.installer_worker_rust_tests_data({key: value for key, value in worker_expected.items()
                                                       if key != "cargoProfile"})


def cpio(entries):
    output = bytearray()
    for index, (name, mode, body, uid, gid, links) in enumerate([*entries, ("TRAILER!!!", 0, b"", 0, 0, 1)]):
        encoded = name.encode("ascii") + b"\0"
        fields = [index + 1, mode, uid, gid, links, 0, len(body), 0, 0, 0, 0, len(encoded), 0]
        output.extend(b"070701" + "".join(f"{value:08x}" for value in fields).encode("ascii"))
        output.extend(encoded)
        output.extend(b"\0" * (-len(output) % 4))
        output.extend(body)
        output.extend(b"\0" * (-len(output) % 4))
    return bytes(output)


def package(payload, *, info=None, extra=None):
    if info is None:
        info = ('<pkg-info identifier="' + fixture.PACKAGE + '" version="1" install-location="' + str(fixture.ROOT)
                + '" auth="root"><payload numberOfFiles="2"/></pkg-info>').encode()
    members = [("Bom", b"synthetic-bom"), ("PackageInfo", info), ("Payload", payload)]
    if extra:
        members.append(extra)
    offset, toc, heap = 0, ["<xar><toc>"], bytearray()
    for name, body in members:
        toc.append(f'<file><name>{name}</name><type>file</type><data><length>{len(body)}</length>'
                   f'<offset>{offset}</offset><size>{len(body)}</size><encoding style="application/octet-stream"/></data></file>')
        heap.extend(body)
        offset += len(body)
    toc.append("</toc></xar>")
    plain = "".join(toc).encode()
    packed = zlib.compress(plain)
    return struct.pack(">IHHQQI", 0x78617221, 28, 1, len(packed), len(plain), 0) + packed + heap


class PackageTests(unittest.TestCase):
    def test_complete_payload_correspondence_without_extraction_or_execution(self):
        data = b"fixed-gate-data"
        expected = {"gate": {"bytes": len(data), "sha256": fixture.digest(data), "mode": "100444"}}
        payload = cpio([(".", 0o40755, b"", 0, 0, 2), ("gate", 0o100444, data, 0, 0, 1)])
        fixture.package_payload(payload, expected)
        value = fixture.fixture_package(package(payload), expected)
        self.assertTrue(value["payloadCorrespondence"])
        self.assertTrue(value["scriptsAbsent"])

    def test_wrong_mode_owner_link_path_bytes_scripts_or_install_root_is_refused(self):
        data = b"fixed"
        expected = {"gate": {"bytes": len(data), "sha256": fixture.digest(data), "mode": "100444"}}
        root = (".", 0o40755, b"", 0, 0, 2)
        for row in (("gate", 0o100644, data, 0, 0, 1), ("gate", 0o100444, data, 501, 20, 1),
                    ("gate", 0o120444, data, 0, 0, 1), ("gate", 0o100444, data, 0, 0, 2),
                    ("../gate", 0o100444, data, 0, 0, 1), ("gate", 0o100444, b"wrong", 0, 0, 1)):
            with self.subTest(row=row):
                with self.assertRaises(fixture.Refused):
                    fixture.package_payload(cpio([root, row]), expected)
        payload = cpio([root, ("gate", 0o100444, data, 0, 0, 1)])
        for body in (package(payload, extra=("Scripts", b"not-executed")),
                     package(payload, info=('<pkg-info identifier="' + fixture.PACKAGE
                                             + '" version="1" install-location="/wrong" auth="root"/>').encode()),
                     package(payload[:-1])):
            with self.assertRaises((fixture.Refused, ValueError, zlib.error)):
                fixture.fixture_package(body, expected)


    def test_empty_relocation_and_fixed_bundle_references_differ_from_actions(self):
        data = b"fixed"
        expected = {"gate": {"bytes": len(data), "sha256": fixture.digest(data), "mode": "100444"}}
        payload = cpio([(".", 0o40755, b"", 0, 0, 2), ("gate", 0o100444, data, 0, 0, 1)])
        prefix = ('<pkg-info identifier="' + fixture.PACKAGE + '" version="1" install-location="'
                  + str(fixture.ROOT) + '" auth="root">')
        safe = ('<bundle-version><bundle path="./' + fixture.APP + '" id="' + fixture.IDENTIFIER
                + '"/></bundle-version><strict-identifier><bundle id="' + fixture.IDENTIFIER
                + '"/></strict-identifier><relocate/>')
        fixture.fixture_package(package(payload, info=(prefix + safe + "</pkg-info>").encode()), expected)
        for action in ('<relocate><bundle id="' + fixture.IDENTIFIER + '"/></relocate>',
                       '<bundle-version><bundle path="../outside" id="' + fixture.IDENTIFIER + '"/></bundle-version>',
                       '<strict-identifier><bundle id="unrelated"/></strict-identifier>'):
            with self.assertRaises(fixture.Refused):
                fixture.fixture_package(package(payload, info=(prefix + action + "</pkg-info>").encode()), expected)


def image(role):
    def dylib(command, name):
        raw = name.encode("ascii") + b"\0"
        raw += b"\0" * (-(24 + len(raw)) % 8)
        return struct.pack("<6I", command, 24 + len(raw), 24, 0, 0, 0) + raw
    commands = (dylib(0xD, "@rpath/libmrk_e2_native_" + role + ".dylib")
                + dylib(0xC, "/usr/lib/libSystem.B.dylib")
                + struct.pack("<6I", 0x32, 24, 1, 26 << 16, 26 << 16, 0))
    return struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 6, 3, len(commands), 0x84, 0) + commands


class ImageTests(unittest.TestCase):
    def test_only_the_fixed_fixture_role_and_system_loader_closure_are_accepted(self):
        for role in ("client", "resident"):
            fixture.fixture_image_macho(image(role), role)
        wrong_role = image("client")
        with self.assertRaises(fixture.Refused) as mismatch:
            fixture.fixture_image_macho(wrong_role, "resident")
        self.assertEqual(mismatch.exception.args, ("fixture-image-role-identity",))
        # Each mutation reaches the named original predicate with earlier checks valid.
        span = bytearray(wrong_role)
        struct.pack_into("<I", span, 16, 2)  # Complete command bytes, smaller claimed command count.
        minimum = bytearray(wrong_role)
        struct.pack_into("<I", minimum, len(minimum) - 12, 25 << 16)
        system = wrong_role.replace(b"/usr/lib/libSystem.B.dylib", b"/usr/lib/libSystem.C.dylib")
        for changed, label in ((bytes(span), "fixture-image-command-span"),
                               (bytes(minimum), "fixture-image-platform-minimum"),
                               (system, "fixture-image-system-closure")):
            with self.subTest(label=label), self.assertRaises(fixture.Refused) as refused:
                fixture.fixture_image_macho(changed, "client")
            self.assertEqual(refused.exception.args, (label,))
        for offset, value in ((4, 0x01000007), (12, 2), (28, 1), (32, 0x8000001C)):
            changed = bytearray(wrong_role)
            struct.pack_into("<I", changed, offset, value)
            with self.assertRaises(fixture.Refused):
                fixture.fixture_image_macho(bytes(changed), "client")
        changed = wrong_role.replace(b"/usr/lib/libSystem.B.dylib", b"/tmp/bad/libSystem.B.dylib")
        with self.assertRaises(fixture.Refused):
            fixture.fixture_image_macho(changed, "client")


class OriginalCallTests(unittest.TestCase):
    @staticmethod
    def operation(callback):
        value = object.__new__(fixture.Operation)
        value.owner = SimpleNamespace(run_owned=callback)
        value.source = SimpleNamespace(book=SimpleNamespace(check=lambda: None))
        value.calls = []
        value.phase = None
        value.published = []
        value.publish = lambda name, body: value.published.append((name, body))
        return value

    def test_owner_error_never_returns_parseable_native_evidence(self):
        class OriginalFailure(Exception):
            dispatched = True
            contained = False
            cleanup_complete = False
        def call(*_args, **_kwargs):
            raise OriginalFailure("synthetic")
        value = self.operation(call)
        value.owner.ProcessError = OriginalFailure
        with self.assertRaises(OriginalFailure):
            value.call("native-run", ["/fixed"], {}, cwd=Path("/synthetic"), timeout=990)
        self.assertEqual(len(value.calls), 1)
        self.assertTrue(value.calls[0]["entered"])
        self.assertFalse(value.calls[0]["returned"])
        self.assertFalse(value.calls[0]["cleanup_complete"])
        self.assertEqual(value.published, [])

    def test_malformed_owner_return_cannot_be_persisted_as_a_success(self):
        value = self.operation(lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=b"", stderr=b""))
        with self.assertRaises(fixture.Refused):
            value.call("native-run", ["/fixed"], {}, cwd=Path("/synthetic"), timeout=990)
        self.assertFalse(value.calls[0]["returned"])
        self.assertEqual(value.published, [])


class ReceiptAbsenceTests(unittest.TestCase):
    @staticmethod
    def operation(stdout, returncode=0, stderr=b"", error=None):
        def run_owned(argv, **kwargs):
            value.invocations.append((list(argv), kwargs))
            if error is not None:
                raise error
            return subprocess.CompletedProcess(argv, returncode, stdout, stderr)
        value = OriginalCallTests.operation(run_owned)
        value.scratch = Path("/synthetic/receipt-census")
        value.source.binding = {"fixtureAdministrativeDomain": {
            "schemaVersion": 1, "allocation": "fresh-github-hosted-single-job",
            "writer": "macos_e2_native_fixture.py", "root": str(fixture.ROOT),
            "receipt": fixture.PACKAGE, "priorFixtureUse": False}}
        value.invocations, value.observations = [], []
        value.observe_metadata = lambda role, *, present: value.observations.append((role, present))
        directories = {fixture.ROOT.parent: 90, Path("/private/var/db/receipts"): 91}
        value.protected = SimpleNamespace(
            directory=lambda path: {"fd": directories[path]},
            check=lambda: value.observations.append("protected-check"))
        value.installer_entered = value.native_entered = False
        return value

    def test_successful_complete_census_preserves_both_absence_call_sites(self):
        samples = (("initial", [], plistlib.FMT_XML),
                   ("before-install", ["com.example.unrelated", fixture.PACKAGE + ".different"], plistlib.FMT_XML),
                   ("initial", ["com.example.other"], plistlib.FMT_BINARY))
        for role, identifiers, fmt in samples:
            with self.subTest(role=role, fmt=fmt):
                value = self.operation(plistlib.dumps(identifiers, fmt=fmt))
                with patch.object(fixture.os, "stat", side_effect=FileNotFoundError()) as observe:
                    value.absence(role)
                self.assertEqual([call.args[0] for call in observe.call_args_list],
                                 [fixture.ROOT.name, fixture.PACKAGE + ".plist", fixture.PACKAGE + ".bom"])
                self.assertEqual([call.kwargs for call in observe.call_args_list],
                                 [{"dir_fd": fd, "follow_symlinks": False} for fd in (90, 91, 91)])
                self.assertEqual(value.invocations, [
                    (["/usr/sbin/pkgutil", "--volume", "/", "--pkgs-plist"], {
                        "environ": value.native_environment(), "cwd": value.scratch,
                        "timeout": 15, "capture": True, "text": False,
                        "output_limit": 1024 * 1024})])
                self.assertEqual(value.observations, [(role, False), "protected-check"])
                self.assertEqual(len(value.calls), 1)
                self.assertEqual(value.calls[0]["role"], role + "-receipt-query")
                self.assertIs(value.calls[0]["returned"], True)
                self.assertEqual(value.calls[0]["returncode"], 0)
                self.assertFalse(value.installer_entered or value.native_entered)

    def test_nonzero_unknown_or_diagnostic_return_never_establishes_absence(self):
        valid = plistlib.dumps([])
        for code, body, stderr in ((1, b"", b""), (1, valid, b""), (2, valid, b""),
                                   (-9, valid, b""), (0, valid, b"synthetic diagnostic")):
            with self.subTest(code=code, empty=not body, diagnostic=bool(stderr)):
                value = self.operation(body, code, stderr)
                with patch.object(fixture.os, "stat", side_effect=FileNotFoundError()), \
                        patch.object(fixture, "receipt_census_absent", wraps=fixture.receipt_census_absent) as parser:
                    with self.assertRaises(fixture.Refused) as refused:
                        value.absence("initial")
                    self.assertEqual(parser.call_count, 1 if code == 0 else 0)
                self.assertEqual(refused.exception.args,
                                 ("fixture-receipt-query-inconclusive" if code == 0 else "original-command-failed",))
                self.assertEqual(value.observations, [("initial", False)])
                self.assertEqual(value.calls[0]["returncode"], code)
                self.assertFalse(value.installer_entered or value.native_entered)
        class UnknownOriginal(Exception):
            dispatched, contained, cleanup_complete = True, False, False
        value = self.operation(valid, error=UnknownOriginal())
        with patch.object(fixture.os, "stat", side_effect=FileNotFoundError()), \
                patch.object(fixture, "receipt_census_absent") as parser:
            with self.assertRaises(UnknownOriginal):
                value.absence("initial")
            parser.assert_not_called()
        self.assertFalse(value.calls[0]["returned"])
        self.assertEqual(value.published, [])
        self.assertEqual(value.observations, [("initial", False)])
        self.assertFalse(value.installer_entered or value.native_entered)

    def test_malformed_incomplete_oversized_or_ambiguous_census_is_refused(self):
        valid = plistlib.dumps([])
        bodies = [b"", b"not a plist", valid[:-10], valid + b"trailing non-plist bytes"]
        bodies.extend(plistlib.dumps(value) for value in (
            {}, "com.example.not-an-array", [False], [float("nan")], [float("inf")], [[]], [""],
            ["com.example.duplicate", "com.example.duplicate"], ["x" * 1025],
            ["com.example.item" + str(index) for index in range(4097)]))
        for index, body in enumerate(bodies):
            with self.subTest(case=index):
                value = self.operation(body)
                with patch.object(fixture.os, "stat", side_effect=FileNotFoundError()):
                    with self.assertRaises(fixture.Refused) as refused:
                        value.absence("before-install")
                self.assertEqual(refused.exception.args, ("fixture-receipt-query-inconclusive",))
                self.assertEqual(value.observations, [("before-install", False)])
                self.assertFalse(value.installer_entered or value.native_entered)
        # Oversized or non-byte original output must fail even before plist parsing.
        for body in (b"x" * (1024 * 1024 + 1), "not-bytes"):
            value = self.operation(body)
            with patch.object(fixture.os, "stat", side_effect=FileNotFoundError()), \
                    patch.object(fixture, "receipt_census_absent") as parser:
                with self.assertRaises(fixture.Refused) as refused:
                    value.absence("initial")
                parser.assert_not_called()
            self.assertEqual(refused.exception.args, ("original-owner-return",))
            self.assertFalse(value.calls[0]["returned"])
            self.assertEqual(value.published, [])

    def test_exact_receipt_path_or_same_original_conflict_cannot_authorize_work(self):
        for present in (fixture.ROOT.name, fixture.PACKAGE + ".plist", fixture.PACKAGE + ".bom"):
            with self.subTest(present=present):
                def observe(name, **_kwargs):
                    if name == present:
                        return SimpleNamespace()
                    raise FileNotFoundError()
                value = self.operation(plistlib.dumps([]))
                with patch.object(fixture.os, "stat", side_effect=observe):
                    with self.assertRaises(fixture.Refused) as refused:
                        value.absence("initial")
                self.assertEqual(refused.exception.args,
                                 ("fixture-root-collision" if present == fixture.ROOT.name else "fixture-receipt-collision",))
                self.assertEqual(value.invocations, [])
                self.assertEqual(value.observations, [("initial", False)])
                self.assertFalse(value.installer_entered or value.native_entered)
        value = self.operation(plistlib.dumps(["com.example.other", fixture.PACKAGE]))
        with patch.object(fixture.os, "stat", side_effect=FileNotFoundError()):
            with self.assertRaises(fixture.Refused) as refused:
                value.absence("before-install")
        self.assertEqual(refused.exception.args, ("fixture-receipt-collision",))
        self.assertEqual(value.observations, [("before-install", False)])
        self.assertEqual(len(value.invocations), 1)
        value = self.operation(plistlib.dumps([]))
        def changed_original():
            raise fixture.Refused("synthetic-protected-original-changed")
        value.protected.check = changed_original
        with patch.object(fixture.os, "stat", side_effect=FileNotFoundError()):
            with self.assertRaises(fixture.Refused) as refused:
                value.absence("before-install")
        self.assertEqual(refused.exception.args, ("synthetic-protected-original-changed",))
        self.assertFalse(value.installer_entered or value.native_entered)


def metadata(present=False):
    snapshots, rows = [], []
    for index in range(8):
        if index == 7 and not present:
            full = None
        else:
            full = (1, 100 + index, 0o40755, 0, 80 if index == 2 else 0, 2, 64,
                    1_791_000_000_000_000_000, 1_791_000_000_000_000_000)
        snapshots.append(full)
        rows.append({"pathIndex": index, "present": full is not None,
                     "full9": [str(number) for number in full] if full is not None else [],
                     **{flag: full is not None for flag in fixture.METADATA_FLAGS}})
    value = {"schemaVersion": 1, "type": "mrk-e2-protected-metadata-v1", "sourceCommit": SOURCE,
             "outcome": "passed", "originalClosesKnown": True, "rows": rows}
    return value, snapshots


class MetadataObservationTests(unittest.TestCase):
    def test_actual_ancestor_group_is_preserved_but_fixture_root_is_root_wheel(self):
        for present in (False, True):
            value, originals = metadata(present)
            observed = fixture.metadata_result(fixture.canonical(value), 0, SOURCE, present, originals)
            self.assertEqual(observed["rows"][2]["full9"][4], "80")
        value, originals = metadata(True)
        value["rows"][7]["full9"][4] = "80"
        originals[7] = tuple(int(number) for number in value["rows"][7]["full9"])
        with self.assertRaises(fixture.Refused):
            fixture.metadata_result(fixture.canonical(value), 0, SOURCE, True, originals)

    def test_acl_mount_close_or_original_identity_failure_cannot_authorize_installer(self):
        changes = [
            lambda value: value.update(sourceCommit="b" * 40),
            lambda value: value.update(originalClosesKnown=False),
            lambda value: value["rows"].pop(),
            lambda value: value["rows"].__setitem__(1, copy.deepcopy(value["rows"][0])),
            lambda value: value["rows"][2].update(full9=["1"] * 9),
            lambda value: value["rows"][7].update(present=True),
        ]
        changes.extend((lambda value, flag=flag: value["rows"][2].update({flag: False}))
                       for flag in fixture.METADATA_FLAGS)
        for change in changes:
            value, originals = metadata()
            change(value)
            with self.assertRaises(fixture.Refused):
                fixture.metadata_result(fixture.canonical(value), 0, SOURCE, False, originals)
        for mode, uid in ((0o40775, 0), (0o40757, 0), (0o41755, 0), (0o40755, 501), (0o120755, 0)):
            value, originals = metadata()
            value["rows"][2]["full9"][2:4] = [str(mode), str(uid)]
            originals[2] = tuple(int(number) for number in value["rows"][2]["full9"])
            with self.assertRaises(fixture.Refused):
                fixture.metadata_result(fixture.canonical(value), 0, SOURCE, False, originals)

    def test_inconclusive_native_return_or_ambiguous_json_is_never_metadata_evidence(self):
        value, originals = metadata()
        body = fixture.canonical(value)
        for raw, code in ((body, 1), (body + b"\n", 0),
                          (body.replace(b'"schemaVersion":1', b'"schemaVersion":1,"schemaVersion":1'), 0)):
            with self.assertRaises(fixture.Refused):
                fixture.metadata_result(raw, code, SOURCE, False, originals)
        value["rows"][0]["full9"][0] = "01"
        with self.assertRaises(fixture.Refused):
            fixture.metadata_result(fixture.canonical(value), 0, SOURCE, False, originals)

    def test_owner_failure_never_reaches_metadata_parser(self):
        class OwnerFailed(Exception):
            pass
        operation = object.__new__(fixture.Operation)
        operation.observer_entry = {"path": Path("/not-executed")}
        operation.observer_digest = fixture.digest(b"synthetic-code")
        operation.outputs = SimpleNamespace(read=lambda _entry: b"synthetic-code")
        operation.metadata_snapshots = lambda _present: metadata()[1]
        operation.scratch = Path("/not-executed")
        operation.command = lambda *_args, **_kwargs: (_ for _ in ()).throw(OwnerFailed())
        with patch.object(fixture, "metadata_result") as parser:
            with self.assertRaises(OwnerFailed):
                operation.observe_metadata("synthetic", present=False)
            parser.assert_not_called()

    def test_changed_same_file_snapshot_vetoes_success_before_parser(self):
        value, originals = metadata()
        changed = list(originals)
        changed[2] = (2, *changed[2][1:])
        operation = object.__new__(fixture.Operation)
        operation.observer_entry = {"path": Path("/not-executed")}
        operation.observer_digest = fixture.digest(b"synthetic-code")
        operation.outputs = SimpleNamespace(read=lambda _entry: b"synthetic-code")
        snapshots = iter((originals, changed))
        operation.metadata_snapshots = lambda _present: next(snapshots)
        operation.scratch = Path("/not-executed")
        operation.command = lambda *_args, **_kwargs: SimpleNamespace(stdout=fixture.canonical(value), stderr=b"")
        with patch.object(fixture, "metadata_result") as parser:
            with self.assertRaises(fixture.Refused):
                operation.observe_metadata("synthetic", present=False)
            parser.assert_not_called()



class OwnerRetirementAndModeTests(unittest.TestCase):
    @staticmethod
    def operation(stdout, returncode):
        # All books/process returns here are inert DATA, not native evidence.
        book = lambda: SimpleNamespace(check=lambda: None, finish=lambda: True, errors=[])
        owner = SimpleNamespace(run_owned=lambda argv, **_kwargs:
                                subprocess.CompletedProcess(argv, returncode, stdout, b""))
        operation = fixture.Operation(owner, SimpleNamespace(book=book()), None,
                                      Path("/inert-e2-retirement"), {"GITHUB_SHA": SOURCE})
        operation.protected, operation.outputs = book(), book()
        operation.outputs.directory = lambda _path: {"fd": 90}
        operation.release, operation.installed, operation.package = RELEASE, True, {}
        operation.stage_roster = {"inert-entry": {}}
        operation.payload_roster = lambda *_args, **_kwargs: operation.stage_roster
        operation.observe_metadata = lambda *_args, **_kwargs: None
        operation.scratch_identity = WORK[:5]
        operation.published = []
        operation.publish = lambda name, body: operation.published.append((name, body))
        return operation

    def test_scratch_retirement_requires_accepted_native_finality_not_outer_return(self):
        unknown = result()
        unknown["nativeFinalityKnown"] = False
        inconsistent = result()
        inconsistent["cases"][0]["resourceStates"]["worker"] = "not-started"
        empty = unexecuted(fixture.CASES[0])
        empty.update(outcome="unavailable", startedNs="1", finishedNs="2", mainReturned=True)
        empty["resourceStates"]["main"] = "returned-empty"
        unavailable = result()
        unavailable.update(outcome="unavailable",
                           cases=[empty, *(unexecuted(name) for name in fixture.CASES[1:])])
        samples = ((b"{invalid-json}\n", 0, False), (fixture.canonical(unknown), 0, False),
                   (fixture.canonical(inconsistent), 0, False),
                   (fixture.canonical(result()), 0, True), (fixture.canonical(unavailable), 77, True))
        stat_info = SimpleNamespace(**dict(zip(
            ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size",
             "st_mtime_ns", "st_ctime_ns"), WORK)))
        for index, (body, code, accepted) in enumerate(samples):
            with self.subTest(sample=index):
                operation = self.operation(body, code)
                with patch.object(fixture.os, "listdir", return_value=[]):
                    if accepted:
                        operation.run_native()
                    else:
                        with self.assertRaises(fixture.Refused):
                            operation.run_native()
                self.assertTrue(operation.native_entered and operation.native_returned)
                self.assertTrue(operation.calls[0]["returned"])
                self.assertEqual(operation.native is not None, accepted)
                captures = list(operation.published)
                cleanup = SimpleNamespace(directory=lambda _path: {"fd": 93}, finish=lambda: True)
                with patch.object(fixture, "Originals", return_value=cleanup) as originals, \
                     patch.object(fixture.os, "stat", side_effect=[stat_info, FileNotFoundError()]) as named, \
                     patch.object(fixture.shutil, "rmtree") as retire:
                    retire.avoids_symlink_attacks = True
                    operation.finish()
                    if accepted:
                        originals.assert_called_once_with()
                        retire.assert_called_once_with(operation.scratch.name, dir_fd=93)
                        self.assertEqual(named.call_count, 2)
                    else:
                        originals.assert_not_called()
                        named.assert_not_called()
                        retire.assert_not_called()
                self.assertEqual(operation.scratch_retired, accepted)
                self.assertEqual(operation.cleanup_errors, [])
                self.assertEqual(operation.published, captures)

    def test_umask077_keeps_private_defaults_and_exact_fresh_payload_modes(self):
        # This test owns only a private temporary directory. Seed its held root
        # directly so shared /tmp permissions are not mistaken for native paths.
        with tempfile.TemporaryDirectory(prefix="mrk-e2-mode-data-") as temporary:
            root = Path(temporary)
            book = fixture.Originals()
            try:
                fd = fixture.os.open(root, fixture.READ_FLAGS | fixture.os.O_DIRECTORY)
                parent = book.register(fd, root, "directory")
                parent.update(identity=fixture.signature(fixture.os.fstat(fd))[:5], parent=None)
                book.directories[root] = parent
                operation = object.__new__(fixture.Operation)
                operation.outputs, operation.scratch = book, root
                previous = fixture.os.umask(0o077)
                try:
                    operation.mkdir(root / "payload", 0o755)
                    operation.mkdir(root / "private", 0o700)
                    for relative in (fixture.APP + "/Contents/Info.plist", fixture.CONTENTS + "Info.plist"):
                        operation.write_payload(relative, b"inert metadata", 0o444)
                    for relative in (fixture.APP + "/Contents/_CodeSignature", fixture.CONTENTS + "_CodeSignature"):
                        operation.mkdir(root / "payload" / relative, 0o755)
                    self.assertEqual(fixture.os.umask(0o077), 0o077)
                    for path, entry in book.directories.items():
                        expected = 0o700 if path in (root, root / "private") else 0o755
                        self.assertEqual(fixture.stat.S_IMODE(fixture.os.fstat(entry["fd"]).st_mode), expected)
                    book.check()  # Controlled mode initialization updated custody.
                    with patch.object(fixture.os, "fchmod") as change:
                        with self.assertRaises(FileExistsError):
                            operation.mkdir(root / "private", 0o755)
                        change.assert_not_called()  # Never normalize/adopt a collision.
                    self.assertEqual(fixture.stat.S_IMODE(fixture.os.stat(root / "private").st_mode), 0o700)
                finally:
                    fixture.os.umask(previous)
            finally:
                self.assertTrue(book.finish())


class ServiceLayoutObservationTests(unittest.TestCase):
    @staticmethod
    def record(case="single"):
        first = 2 if case == "single" else 5
        return {
            "schemaVersion": 1, "type": "mrk-e2-service-status-observation-v1",
            "sourceCommit": SOURCE, "observerSourceSha256": "b" * 64, "case": case,
            "outcome": "observed", "startedNs": str(first * 1_000_000_000),
            "finishedNs": str((first + 1) * 1_000_000_000),
            "bundle": "expected-client", "executable": "expected-client", "identifier": "expected-client",
            "plist": "expected-daemon", "status": "not-found", "factoryReturned": True,
            "retainReturned": True, "statusReturned": True, "serviceReleaseReturned": True,
            "poolDrainReturned": True, "finalityKnown": True, "registrationEntered": False,
        }

    @staticmethod
    def initial(selected=True):
        return fixture.Operation(None, None, None, Path("/inert-layout-data"),
                                 {"GITHUB_SHA": SOURCE}, service_layout=selected).service_layout

    def test_status_binding_order_deadline_and_original_finality_never_grant_absence(self):
        raw = self.record()
        parse_record = lambda value, code=0: fixture.service_status_record(
            fixture.canonical(value), code, SOURCE, "b" * 64, "single", 1_000_000_000, 31_000_000_000)
        for status in ("not-found", "not-registered", "enabled", "requires-approval"):
            observed = parse_record(dict(raw, status=status))
            self.assertEqual(observed["status"], status)
            self.assertFalse(observed["registrationEntered"])
            self.assertNotIn("absent", observed)
        mutations = {"schemaVersion": True, "sourceCommit": "c" * 40, "observerSourceSha256": "c" * 64,
                     "case": "nested", "status": "absent", "bundle": "outer-host", "plist": "missing",
                     "registrationEntered": True, "factoryReturned": False, "retainReturned": False,
                     "statusReturned": False, "serviceReleaseReturned": False, "poolDrainReturned": False,
                     "finalityKnown": False, "startedNs": "0", "finishedNs": "31000000001"}
        for key, item in mutations.items():
            with self.subTest(field=key), self.assertRaises(fixture.Refused):
                parse_record(dict(raw, **{key: item}))
        for code in (True, 1, 77):
            with self.assertRaises(fixture.Refused):
                parse_record(raw, code)
        with self.assertRaises(fixture.Refused):
            parse_record(dict(raw, extra="not-allowed"))
        value = self.initial()
        self.assertIs(fixture.service_layout_data(value, SOURCE), value)
        self.assertTrue(fixture.service_layout_finality(value, SOURCE))
        value.update(started=True, startedNs="1000000000", deadlineNs="31000000000",
                     observerSourceSha256="b" * 64, pairedInstalledInputs=True)
        value["enteredCases"].append("single")
        self.assertFalse(fixture.service_layout_finality(value, SOURCE))
        value["cases"].append({"case": "single", "stdoutSha256": fixture.digest(fixture.canonical(raw)), "record": raw})
        self.assertTrue(fixture.service_layout_finality(value, SOURCE))
        for key in ("entryResponsibilityTested", "registrationEntered", "productionIdentityQualified",
                    "actualAppIntegrationQualified", "nativeLifecycleQualified"):
            changed = copy.deepcopy(value)
            changed[key] = True
            with self.subTest(scope=key), self.assertRaises(fixture.Refused):
                fixture.service_layout_data(changed, SOURCE)
        changed = copy.deepcopy(value)
        changed["completed"] = True
        with self.assertRaises(fixture.Refused):
            fixture.service_layout_data(changed, SOURCE)
        nested = self.record("nested")
        value["enteredCases"].append("nested")
        value["cases"].append({"case": "nested", "stdoutSha256": fixture.digest(fixture.canonical(nested)), "record": nested})
        value["completed"] = True
        self.assertTrue(fixture.service_layout_finality(value, SOURCE))
        for field in ("enteredCases", "cases"):
            changed = copy.deepcopy(value)
            changed[field].reverse()
            with self.assertRaises(fixture.Refused):
                fixture.service_layout_data(changed, SOURCE)
        changed = copy.deepcopy(value)
        changed["cases"][1]["record"]["startedNs"] = "2000000000"
        with self.assertRaises(fixture.Refused):
            fixture.service_layout_data(changed, SOURCE)

    def test_actual_diagnostic_route_never_enters_context_or_native_and_unknown_call_retains_scratch(self):
        # Original controller methods are real; only external work/books are
        # inert instance fixtures. No compiler, filesystem or native API runs.
        class UnknownOriginal(Exception):
            dispatched, contained, cleanup_complete = True, False, False

        info = SimpleNamespace(**dict(zip(
            ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size",
             "st_mtime_ns", "st_ctime_ns"), WORK)))
        for mode in ("complete", "malformed-second", "unknown-second", "future-clock", "source-before-entry", "ordinary"):
            with self.subTest(mode=mode):
                events, calls, captures = [], [], []
                book = lambda: SimpleNamespace(check=lambda: None, finish=lambda: True, errors=[])
                source = SimpleNamespace(book=book(), binding={"tree": "c" * 40}, inventory_digest="d" * 64,
                                         binding_digest="e" * 64, source_handle_count=1, source_handle_reserve=192)
                env = {"GITHUB_SHA": SOURCE, "GITHUB_WORKFLOW_SHA": SOURCE,
                       "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1"}
                op = fixture.Operation(None, source, None, Path("/inert-layout-data"), env,
                                       service_layout=mode != "ordinary")
                op.outputs, op.protected = book(), book()
                op.outputs.directories = {op.scratch: {"identity": WORK[:5]}}
                op.outputs.directory = lambda _path: {"fd": 90}
                op.publish = lambda name, body: captures.append((name, body))
                op.begin = lambda: events.append("begin")
                op.build_installer_worker_tests = lambda: events.append("installer-bin")
                op.observe_installer_context = lambda: events.append("context")
                op.compile_metadata_observer = lambda: events.append("metadata")
                op.absence = lambda _role: events.append("absence")
                op.build_images = lambda: events.append("images")
                op.compile_facades = lambda: events.append("facades")
                def compile_observer():
                    events.append("observer-build")
                    op.service_layout["observerSourceSha256"] = "b" * 64
                op.compile_service_layout = compile_observer
                op.sign = lambda: events.append("sign")
                def package_fixture():
                    events.append("package")
                    op.package = {}
                op.package_fixture = package_fixture
                def install():
                    events.append("install")
                    op.installed = op.installer_entered = True
                op.install_fixture = install
                op.run_native = lambda: events.append("native")
                op.service_layout_inputs = lambda: events.append("input-check")
                def run_owned(argv, **kwargs):
                    calls.append((argv, kwargs))
                    case = "single" if len(calls) == 1 else "nested"
                    if mode == "unknown-second" and case == "nested":
                        raise UnknownOriginal()
                    data = self.record(case)
                    if mode == "future-clock":
                        data["finishedNs"] = "9000000000"
                    body = (b"{}\n" if mode == "malformed-second" and case == "nested"
                            else fixture.canonical(data))
                    return subprocess.CompletedProcess(argv, 0, body, b"")
                op.owner = SimpleNamespace(run_owned=run_owned)
                if mode == "source-before-entry":
                    def refuse_source():
                        raise fixture.Refused("original-changed")
                    source.book.check = refuse_source
                cleanup = SimpleNamespace(directory=lambda _path: {"fd": 93}, finish=lambda: True)
                with patch.object(fixture.time, "clock_gettime_ns", side_effect=[
                         1_000_000_000, 2_000_000_000, 4_000_000_000, 5_000_000_000, 7_000_000_000]), \
                     patch.object(fixture.os, "listdir", return_value=[]), \
                     patch.object(fixture, "Originals", return_value=cleanup) as originals, \
                     patch.object(fixture.os, "stat", side_effect=[info, FileNotFoundError()]) as named, \
                     patch.object(fixture.shutil, "rmtree") as retire:
                    retire.avoids_symlink_attacks = True
                    receipt = op.execute()
                    if mode in ("complete", "ordinary", "source-before-entry"):
                        retire.assert_called_once_with(op.scratch.name, dir_fd=93)
                    else:
                        originals.assert_not_called()
                        named.assert_not_called()
                        retire.assert_not_called()
                self.assertFalse(receipt["passed"])
                self.assertFalse(receipt["actualAppIntegrationQualified"])
                self.assertFalse(receipt["nativeEntered"])
                self.assertFalse(receipt["nativeOwnerReturned"])
                self.assertIsNone(receipt["native"])
                self.assertTrue(receipt["sourceClosesKnown"] and receipt["protectedClosesKnown"]
                                and receipt["outputClosesKnown"])
                self.assertEqual(receipt["scratchRetired"], mode in ("complete", "ordinary", "source-before-entry"))
                if mode == "ordinary":
                    self.assertLess(events.index("installer-bin"), events.index("context"))
                    self.assertIn("context", events)
                    self.assertIn("native", events)
                    self.assertNotIn("observer-build", events)
                    self.assertEqual(calls, [])
                    continue
                self.assertNotIn("installer-bin", events)
                if mode == "source-before-entry":
                    self.assertEqual(calls, [])
                    self.assertEqual(receipt["originalCalls"], [])
                    layout = receipt["serviceLayoutObservation"]
                    self.assertTrue(layout["started"])
                    self.assertEqual(layout["enteredCases"], [])
                    self.assertEqual(layout["cases"], [])
                    self.assertTrue(fixture.service_layout_finality(layout, SOURCE))
                    self.assertEqual(receipt["failure"], "original-changed")
                self.assertNotIn("context", events)
                self.assertNotIn("native", events)
                self.assertFalse(receipt["installerContext"]["started"])
                self.assertEqual(receipt["serviceLayoutObservation"]["completed"], mode == "complete")
                for index, (argv, options) in enumerate(calls):
                    self.assertEqual(argv, [str(fixture.ROOT / (fixture.LAYOUT_CLIENTS[index] + fixture.LAYOUT_EXECUTABLE))])
                    self.assertEqual(options["output_limit"], 2048)
                    self.assertEqual(options["timeout"], 15)
                    self.assertEqual(set(options["environ"]), {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TZ"})
                if mode == "future-clock":
                    self.assertEqual(receipt["failure"], "layout-original-clock-correspondence")
                if mode == "unknown-second":
                    self.assertFalse(receipt["originalCalls"][-1]["returned"])

    def test_fixed_public_observer_paired_inputs_and_private_loader_layer_keep_closed_scope(self):
        native = (PATH.parents[1] / fixture.LAYOUT_SOURCE.removeprefix("desktop/")).read_text(encoding="utf-8")
        owner = PATH.read_text(encoding="utf-8")
        for forbidden in ("registerAndReturnError", "unregisterAndReturnError", "openSystemSettingsLoginItems",
                          "posix_spawn", "system(", "fork(", "NSTask", "dlopen("):
            self.assertNotIn(forbidden, native)
        self.assertEqual(native.count("daemonServiceWithPlistName:"), 1)
        self.assertIn("SMAppServiceStatusNotFound: status = \"not-found\"", native)
        self.assertLess(native.index("bundle.bundleIdentifier"), native.index("dataWithContentsOfURL:"))
        self.assertLess(native.index("dataWithContentsOfURL:"), native.index("daemonServiceWithPlistName:"))
        self.assertLess(native.index("[original release]"), native.index("[original drain]"))
        self.assertLess(native.index("[original drain]"), native.index("snprintf(output"))
        self.assertIn("Single/MRK E2 Status Client.app", native)
        self.assertIn("Nested/MRK E2 Status Host.app/Contents/Helpers/MRK E2 Status Client.app", native)
        self.assertIn('"-fno-objc-arc", "-fobjc-exceptions"', owner)
        self.assertIn('"-framework", "CoreFoundation", "-lobjc"', owner)
        self.assertIn('layout_originals[relative] = entry', owner)
        self.assertIn('body = book.read(entry)  # Same held original', owner)
        self.assertIn('body = self.protected.read(original)', owner)
        self.assertIn('layout_finality and not self.cleanup_errors', owner)

        leaves = fixture.service_layout_files()
        self.assertEqual(len(leaves), 13)
        paired = {name: {"bytes": 3, "sha256": "a" * 64, "mode": "100444"} for name in leaves}
        fixture.service_layout_paired(paired)
        for suffix in (fixture.LAYOUT_EXECUTABLE, fixture.LAYOUT_TARGET, fixture.LAYOUT_PLIST,
                       "/Contents/Info.plist", "/Contents/_CodeSignature/CodeResources"):
            changed = copy.deepcopy(paired)
            changed[fixture.LAYOUT_CLIENTS[1] + suffix]["sha256"] = "c" * 64
            with self.assertRaisesRegex(fixture.Refused, "^layout-paired-inputs$"):
                fixture.service_layout_paired(changed)
        # Existing package policy changes only by the explicit diagnostic selector.
        payload = cpio([(".", 0o40755, b"", 0, 0, 2), ("gate", 0o100444, b"gate", 0, 0, 1)])
        expected = {"gate": {"bytes": 4, "sha256": fixture.digest(b"gate"), "mode": "100444"}}
        info = ('<pkg-info identifier="' + fixture.PACKAGE + '" version="1" auth="root" install-location="'
                + str(fixture.ROOT) + '"><bundle path="' + fixture.LAYOUT_CLIENTS[0]
                + '" id="' + fixture.LAYOUT_ID + '.client"/></pkg-info>').encode()
        with self.assertRaisesRegex(fixture.Refused, "^fixture-package-bundle-route$"):
            fixture.fixture_package(package(payload, info=info), expected)
        fixture.fixture_package(package(payload, info=info), expected, service_layout=True)

        # The unchanged generic Mach-O boundary is a spy, not native evidence.
        # These cases exercise only the new, narrower public-framework layer.
        generic_calls = []
        stager = SimpleNamespace(macho=lambda body, *, system_only: generic_calls.append((body, system_only)))
        libraries = (
            b"/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation",
            b"/System/Library/Frameworks/ServiceManagement.framework/Versions/A/ServiceManagement",
            b"/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
            b"/usr/lib/libobjc.A.dylib", b"/usr/lib/libSystem.B.dylib",
        )
        def load(command, name):
            start = 12 if command == 0xE else 24
            size = (start + len(name) + 1 + 7) & ~7
            return struct.pack("<III", command, size, start) + b"\0" * (start - 12) + name + b"\0" * (size - start - len(name))
        def executable(names=libraries, *, flags=0x200084, first_command=0xC, extra=b""):
            commands = [load(first_command if i == 0 else 0xC, name) for i, name in enumerate(names)]
            commands += [load(0xE, b"/usr/lib/dyld"), struct.pack("<6I", 0x32, 24, 1, 26 << 16, 26 << 16, 0),
                         struct.pack("<IIQQ", 0x80000028, 24, 0, 0)]
            if extra:
                commands.append(extra)
            body = b"".join(commands)
            return struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 2, len(commands), len(body), flags, 0) + body
        body = executable()
        fixture.service_observer_macho(body, stager)
        self.assertEqual(generic_calls, [(body, True)])
        fixture.service_observer_macho(executable(tuple(reversed(libraries))), stager)
        segment = bytearray(152)
        struct.pack_into("<II", segment, 0, 0x19, 152)
        struct.pack_into("<I", segment, 64, 1)
        segment[72:87] = b"__mod_init_func"
        struct.pack_into("<I", segment, 136, 0x9)
        for bad, label in (
            (executable(libraries + (libraries[-1],)), "layout-image-system-closure"),
            (executable((*libraries[:-1], b"/usr/lib/libsqlite3.dylib")), "layout-image-system-closure"),
            (executable(first_command=0x80000018), "layout-image-command"),
            (executable(first_command=0x8000001F), "layout-image-command"),
            (executable(flags=0x84), "layout-image-flags"),
            (executable(extra=bytes(segment)), "layout-image-initializer"),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(fixture.Refused, "^" + label + "$"):
                fixture.service_observer_macho(bad, stager)


class BTMLogObservationTests(unittest.TestCase):
    def test_only_own_bounded_log_events_produce_finite_diagnostics(self):
        wall = 1_700_000_000_250_000_000
        start, end = (wall, 1_000_000_000), (wall + 4_000_000_000, 5_000_000_000)
        window = fixture.btm_window(start, end)
        argv = fixture.btm_argv(window)
        self.assertEqual(window, {"startSeconds": 1699999999, "endSeconds": 1700000006})
        self.assertEqual(argv, ["/usr/bin/log", "show", "--style", "json", "--start", "2023-11-14 22:13:19+0000",
                              "--end", "2023-11-14 22:13:26+0000", "--timezone", "UTC", "--info", "--debug",
                              "--no-pager", "--predicate", 'subsystem == "com.apple.backgroundtaskmanagement" '
                              'AND eventMessage CONTAINS "dev.mobile-release-kit.fixture.e2"'])
        for left, right in ((None, end), (start, [*end]), ((True, start[1]), end), (end, start),
                            (start, (wall + 10_000_000_000, 2_000_000_000)),
                            (start, (wall + 994_000_000_000, 995_000_000_000))):
            with self.subTest(invalid_window=(left, right)), self.assertRaises(fixture.Refused):
                fixture.btm_window(left, right)
        for invalid in ({}, dict(window, path="/private/CANARY"), dict(window, endSeconds=True),
                        dict(window, endSeconds=window["startSeconds"] + 999)):
            with self.subTest(window_shape=invalid), self.assertRaises(fixture.Refused):
                fixture.btm_argv(invalid)

        rows = [{"subsystem": fixture.BTM_SUBSYSTEM,
                 "eventMessage": fixture.IDENTIFIER + ".client: NotFound plist signature team identifier "
                                 "responsibility approval permission registration launch constraint requirement "
                                 "Domain=SMAppServiceErrorDomain Code=3 /private/BTM-PRIVATE-CANARY",
                 "processImagePath": "/private/BTM-PRIVATE-CANARY", "arbitraryMetric": 1.25},
                {"subsystem": fixture.BTM_SUBSYSTEM, "eventMessage": fixture.IDENTIFIER + ".foreign: signature CANARY"}]
        body = fixture.canonical(rows)
        parsed = fixture.btm_events(body)
        self.assertEqual((parsed["eventCount"], parsed["ownEventCount"], parsed["unmatchedEventCount"]), (2, 1, 1))
        self.assertEqual(parsed["markerCounts"], {**{name: 1 for name, _ in fixture.BTM_MARKERS}, "other": 0})
        self.assertEqual(parsed["errorCodes"], [{"domain": "smappservice", "code": 3}])
        public = fixture.canonical(parsed)
        for private in (b"CANARY", b"/private/", b"processImagePath", b"eventMessage", b"arbitraryMetric"):
            self.assertNotIn(private, public)
        for message in ("x." + fixture.IDENTIFIER, fixture.SERVICE + ".foreign", "unrelated signature"):
            self.assertEqual(fixture.btm_events(fixture.canonical([
                {"subsystem": fixture.BTM_SUBSYSTEM, "eventMessage": message}]))["ownEventCount"], 0)
        unknown = fixture.btm_events(fixture.canonical([{"subsystem": fixture.BTM_SUBSYSTEM,
            "eventMessage": fixture.SERVICE + " Domain=PrivateErrorDomain Code=4 "
                            "Domain=NSCocoaErrorDomain Code=-0 Domain=NSOSStatusErrorDomain Code=2147483648"}]))
        self.assertEqual(unknown["errorCodes"], [])
        malformed = [b"", b"{}", b"[", b"\xff", bytearray(body), body.decode(),
                     b" " * (fixture.BTM_LIMIT + 1), fixture.canonical(rows * 129),
                     b'[{"subsystem":"x","subsystem":"x","eventMessage":"x"}]',
                     fixture.canonical([{"subsystem": "foreign", "eventMessage": fixture.IDENTIFIER}]),
                     fixture.canonical([{"subsystem": fixture.BTM_SUBSYSTEM, "eventMessage": "x" * 8193}]),
                     b'[{"eventMessage":NaN}]', fixture.canonical([None]),
                     fixture.canonical([{"subsystem": fixture.BTM_SUBSYSTEM,
                        "eventMessage": fixture.IDENTIFIER + " Domain=SMAppServiceErrorDomain Code=" + str(i)}
                                        for i in range(9)])]
        for number, invalid in enumerate(malformed):
            with self.subTest(invalid_log=number), self.assertRaises(fixture.Refused):
                fixture.btm_events(invalid)
        empty = fixture.btm_events(b"[]")
        self.assertEqual((empty["eventCount"], empty["ownEventCount"], empty["errorCodes"]), (0, 0, []))

        calls = [{"role": "native-run", "entered": True, "returned": True},
                 {"role": fixture.BTM_ROLE, "entered": True, "returned": True, "returncode": 0,
                  "workTimeoutSeconds": 10, "outputLimitBytes": 262144,
                  "stdoutSha256": fixture.digest(body), "stderrSha256": fixture.digest(b"")}]
        value = fixture.btm_record(SOURCE)
        value.update(parsed, state="observed", window=window, commandIndex=1, toolSha256="c" * 64,
                     stdoutSha256=fixture.digest(body), stderrSha256=fixture.digest(b""))
        self.assertIs(fixture.btm_log_data(value, SOURCE, calls), value)
        self.assertLessEqual(len(fixture.canonical(value)), 4096)
        for mutation in ({"nativeLifecycleQualified": True}, {"ownEventCount": True}, {"ownEventCount": 3},
                         {"state": "not-requested"}, {"commandIndex": True}, {"commandIndex": 0},
                         {"stdoutSha256": "f" * 64}, {"toolSha256": None},
                         {"markerCounts": {"raw": "CANARY"}},
                         {"markerCounts": {key: 0 for key in parsed["markerCounts"]}},
                         {"errorCodes": [{"domain": "private", "code": 0}]},
                         {"state": "empty", "ownEventCount": 0, "unmatchedEventCount": 2,
                          "markerCounts": {key: 0 for key in parsed["markerCounts"]}}):
            changed = copy.deepcopy(value)
            changed.update(mutation)
            with self.subTest(forged_public=list(mutation)), self.assertRaises(fixture.Refused):
                fixture.btm_log_data(changed, SOURCE, calls)
        for forged in (calls + [calls[1]], [{**calls[0], "returned": False}, calls[1]],
                       [calls[0], {**calls[1], "workTimeoutSeconds": 11}]):
            with self.assertRaises(fixture.Refused):
                fixture.btm_log_data(value, SOURCE, forged)

    def test_log_call_preserves_primary_failure_originals_and_native_acceptance(self):
        class UnknownOriginal(Exception):
            dispatched, contained, cleanup_complete = True, False, False

        native = result()
        row = unexecuted(fixture.CASES[0])
        row.update(outcome="unavailable", startedNs="1", finishedNs="2")
        native.update(outcome="unavailable", cases=[row, unexecuted(fixture.CASES[1]), unexecuted(fixture.CASES[2])])
        expected_native = parse(native, 77)
        wall = 1_700_000_000_250_000_000
        sample = ((wall, 1_000_000_000), (wall + 4_000_000_000, 5_000_000_000))
        info = SimpleNamespace(**dict(zip(("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                                           "st_size", "st_mtime_ns", "st_ctime_ns"), WORK)))
        modes = ("observed", "empty", "unparseable", "nonzero-log", "unknown-native", "unknown-log",
                 "primary-and-log-unknown", "native-data-refused", "bad-window", "tool-refused", "logrc-present",
                 "source-before-log", "source-after-log", "call-cap")
        for mode in modes:
            with self.subTest(mode=mode):
                dispatches, captures, tool_checks, scratch_checks = [], [], [], []
                book = lambda: SimpleNamespace(check=lambda: None, finish=lambda: True, errors=[])
                source = SimpleNamespace(book=book(), binding={"tree": "c" * 40}, inventory_digest="d" * 64,
                                         binding_digest="e" * 64, source_handle_count=1, source_handle_reserve=192)
                env = {"GITHUB_SHA": SOURCE, "GITHUB_WORKFLOW_SHA": SOURCE, "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1"}
                op = fixture.Operation(None, source, None, Path("/inert-btm-data"), env)
                op.outputs, op.protected = book(), book()
                op.outputs.directories = {op.scratch: {"identity": WORK[:5]}}
                op.outputs.directory = lambda _path: {"fd": 90}
                op.protected.check_one = lambda _entry: None
                def tool(path, limit, **options):
                    tool_checks.append((path, limit, options))
                    if mode == "tool-refused":
                        raise fixture.Refused("btm-log-tool")
                    return {"fd": 91}, b"inert protected tool DATA"
                op.protected.file = tool
                op.publish = lambda name, body: captures.append((name, body))
                op.begin = lambda: None
                op.build_installer_worker_tests = lambda: None
                op.observe_installer_context = lambda: None
                op.compile_metadata_observer = lambda: None
                op.absence = lambda _role: None
                op.build_images = lambda: None
                op.compile_facades = lambda: None
                op.sign = lambda: None
                op.package_fixture = lambda: None
                def install():
                    op.installed = op.installer_entered = True
                    op.package, op.stage_roster, op.release = {}, {"inert": "roster"}, RELEASE
                op.install_fixture = install
                def roster(_root, *, installed):
                    if mode == "primary-and-log-unknown":
                        raise fixture.Refused("native-filesystem-postcondition")
                    return op.stage_roster
                op.payload_roster = roster
                op.observe_metadata = lambda _phase, *, present: None
                def check_source():
                    if op.phase == fixture.BTM_ROLE and ((mode == "source-before-log" and len(op.calls) == 1)
                                                        or (mode == "source-after-log" and len(op.calls) == 2)):
                        raise fixture.Refused("original-changed")
                source.book.check = check_source
                def run_owned(argv, **options):
                    dispatches.append((argv, options))
                    if argv == [str(fixture.ROOT / fixture.ENTRY)]:
                        if mode == "unknown-native":
                            raise UnknownOriginal()
                        return subprocess.CompletedProcess(argv, 77, b"{}" if mode == "native-data-refused"
                                                           else fixture.canonical(native), b"")
                    self.assertEqual(argv, fixture.btm_argv(fixture.btm_window(*sample)))
                    if mode in ("unknown-log", "primary-and-log-unknown"):
                        raise UnknownOriginal()
                    if mode == "nonzero-log":
                        return subprocess.CompletedProcess(argv, 69, b"", b"PRIVATE-LOG-ERROR")
                    body = b"[]" if mode == "empty" else b"{" if mode == "unparseable" else fixture.canonical([
                        {"subsystem": fixture.BTM_SUBSYSTEM, "eventMessage": fixture.SERVICE + " NotFound"}])
                    return subprocess.CompletedProcess(argv, 0, body, b"")
                op.owner = SimpleNamespace(run_owned=run_owned)
                if mode == "call-cap":
                    op.calls = [{"role": "inert", "entered": True, "returned": True, "returncode": 0} for _ in range(63)]
                def named(path, *, dir_fd, follow_symlinks):
                    self.assertFalse(follow_symlinks)
                    if path == ".logrc":
                        if mode == "logrc-present":
                            return info
                        raise FileNotFoundError()
                    self.assertEqual(path, op.scratch.name)
                    scratch_checks.append(path)
                    if len(scratch_checks) == 1:
                        return info
                    raise FileNotFoundError()
                cleanup = SimpleNamespace(directory=lambda _path: {"fd": 93}, finish=lambda: True)
                samples = [sample[0], None if mode == "bad-window" else sample[1]]
                with patch.object(fixture, "btm_clock_sample", side_effect=samples), \
                     patch.object(fixture.os, "listdir", return_value=[]), \
                     patch.object(fixture.os, "stat", side_effect=named), \
                     patch.object(fixture, "Originals", return_value=cleanup) as originals, \
                     patch.object(fixture.shutil, "rmtree") as retire:
                    retire.avoids_symlink_attacks = True
                    receipt = op.execute()
                    unknown = mode in ("unknown-native", "unknown-log", "primary-and-log-unknown", "native-data-refused")
                    self.assertEqual(receipt["scratchRetired"], not unknown)
                    if unknown:
                        originals.assert_not_called()
                        retire.assert_not_called()
                    else:
                        retire.assert_called_once_with(op.scratch.name, dir_fd=93)
                self.assertFalse(receipt["passed"])
                self.assertFalse(receipt["actualAppIntegrationQualified"])
                value = receipt["btmLogObservation"]
                self.assertIs(fixture.btm_log_data(value, SOURCE, receipt["originalCalls"]), value)
                if mode not in ("unknown-native", "native-data-refused"):
                    self.assertEqual(receipt["native"], expected_native)
                else:
                    self.assertIsNone(receipt["native"])
                no_log = mode in ("unknown-native", "bad-window", "tool-refused", "logrc-present", "source-before-log", "call-cap")
                self.assertEqual(len(dispatches), 1 if no_log else 2)
                if not no_log:
                    self.assertEqual(dispatches[-1][1]["timeout"], 10)
                    self.assertEqual(dispatches[-1][1]["output_limit"], 262144)
                    self.assertEqual(dispatches[-1][1]["environ"], op.native_environment())
                    self.assertEqual(dispatches[-1][1]["cwd"], op.scratch)
                if tool_checks:
                    self.assertEqual(tool_checks, [(Path("/usr/bin/log"), fixture.IMAGE_LIMIT, {"uid": 0, "modes": (0o555, 0o755)})])
                if mode == "primary-and-log-unknown":
                    self.assertEqual(receipt["failure"], "native-filesystem-postcondition")
                    self.assertEqual(receipt["phase"], "native-run")
                if mode == "source-before-log":
                    self.assertEqual(len(receipt["originalCalls"]), 1)
                    self.assertIsNone(value["commandIndex"])
                if mode in ("unknown-log", "primary-and-log-unknown"):
                    self.assertEqual(value["state"], "call-unknown")
                    self.assertFalse(receipt["originalCalls"][-1]["returned"])
                if mode in ("observed", "empty", "unparseable"):
                    self.assertEqual(value["state"], mode)
                    self.assertIsNone(receipt["failure"])
                self.assertNotIn(b"PRIVATE-LOG-ERROR", fixture.canonical(value))


class InstallerContextTests(unittest.TestCase):
    """Synthetic DATA + one private FS case; none is a Mac Installer receipt."""

    @staticmethod
    def xar(members, *, directory=False, mutate=None):
        import xml.etree.ElementTree as ET
        root = ET.Element("xar")
        toc = ET.SubElement(root, "toc")
        check = ET.SubElement(toc, "checksum", style="sha256")
        ET.SubElement(check, "offset").text = "0"
        ET.SubElement(check, "size").text = "32"
        heap, serial = bytearray(), 0
        parent = toc
        if directory:
            serial += 1
            parent = ET.SubElement(toc, "file", id=str(serial))
            ET.SubElement(parent, "name").text = fixture.CONTEXT_PACKAGES[1]
            ET.SubElement(parent, "type").text = "directory"
        for name, content in members.items():
            serial += 1
            element = ET.SubElement(toc if name == "Distribution" else parent, "file", id=str(serial))
            ET.SubElement(element, "name").text = name
            ET.SubElement(element, "type").text = "file"
            data = ET.SubElement(element, "data")
            for key, value in (("length", len(content)), ("offset", 32 + len(heap)), ("size", len(content))):
                ET.SubElement(data, key).text = str(value)
            ET.SubElement(data, "encoding", style="application/octet-stream")
            ET.SubElement(data, "extracted-checksum", style="sha256").text = fixture.digest(content)
            heap.extend(content)
        # Standard XAR metadata also appears on product directories.
        for element in toc.iter("file"):
            ET.SubElement(element, "inode").text = "314159"
            ET.SubElement(element, "deviceno").text = "16777233"
            created = ET.SubElement(element, "FinderCreateTime")
            ET.SubElement(created, "time").text = "2026-10-06T03:04:05"
            ET.SubElement(created, "nanoseconds").text = "123456789"
        if mutate is not None:
            mutate(toc)
        plain = ET.tostring(root, encoding="utf-8")
        packed = zlib.compress(plain)
        return (struct.pack(">IHHQQI", 0x78617221, 28, 1, len(packed), len(plain), 3)
                + packed + bytes.fromhex(fixture.digest(packed)) + bytes(heap))

    @staticmethod
    def package_info(index=1):
        return ('<pkg-info format-version="2" identifier="' + fixture.CONTEXT_IDENTIFIERS[index]
                + '" version="1" install-location="/" auth="root"><payload numberOfFiles="0" installKBytes="0"/>'
                '<scripts><postinstall file="./postinstall"/></scripts><relocate/></pkg-info>').encode("ascii")

    @staticmethod
    def raw(*, case="component", output=(1, 2, 0o100600, 501, 20, 1)):
        absent = {"kind": "missing", "match": None, "opened": False, "closed": None, "original": None, "sha256": None}
        return {"schemaVersion": 1, "type": "mrk-e2-installer-context-v1", "sourceCommit": SOURCE,
                "observerSourceSha256": "b" * 64, "case": case, "clock": "CLOCK_MONOTONIC", "deadlineNs": "100000000000",
                "scriptArgumentCount": 0, "secondArgumentIsRoot": False, "thirdArgumentIsRoot": False,
                "outputOriginal": list(output), "argumentOne": dict(absent), "packagePath": dict(absent)}

    @staticmethod
    def public():
        value = {"schemaVersion": 1, "type": "mrk-e2-installer-context-observations-v1", "sourceCommit": SOURCE,
                 "observerSourceSha256": "b" * 64, "clock": "CLOCK_MONOTONIC", "deadlineNs": "100000000000",
                 "started": True, "completed": True, "enteredCases": list(fixture.CONTEXT_CASES), "cases": [],
                 "receiptsRetired": False, "outerPackageAuthority": False, "maintenanceQualified": False}
        for case in fixture.CONTEXT_CASES:
            body = fixture.canonical(InstallerContextTests.raw(case=case))
            row = fixture.context_record(body, SOURCE, "b" * 64, case, 100_000_000_000,
                                         (1, 2, 0o100600, 501, 20, 1), {})
            row.update(recordSha256=fixture.digest(body), installerReturnedZero=True, outputOriginalClosed=True,
                       receiptOriginals=[{"suffix": "plist", "present": True, "bytes": 128, "sha256": "c" * 64},
                                         {"suffix": "bom", "present": False, "bytes": None, "sha256": None}])
            value["cases"].append(row)
        return value

    def test_no_payload_component_and_both_product_envelopes(self):
        members = {"PackageInfo": self.package_info(), "Scripts": b"synthetic archive DATA, not executed"}
        component = self.xar(members)
        self.assertEqual(fixture.context_xar(component), members)
        for value in ("0", "-9223372036854775808", "18446744073709551615"):
            def stat_text(toc):
                for element in toc.iter("file"):
                    for tag in ("inode", "deviceno"):
                        element.find(tag).text = value
            with self.subTest(stat_text=value):
                self.assertEqual(fixture.context_xar(self.xar(members, mutate=stat_text)), members)
        def without_stat(toc):
            for element in toc.iter("file"):
                for tag in ("inode", "deviceno"):
                    element.remove(element.find(tag))
        self.assertEqual(fixture.context_xar(self.xar(members, mutate=without_stat)), members)
        def without_created(toc):
            for element in toc.iter("file"):
                element.remove(element.find("FinderCreateTime"))
        self.assertEqual(fixture.context_xar(self.xar(members, mutate=without_created)), members)
        # These annotations are not returned as dates or used as authority.
        # Include the real pkgbuild day00 and retain the old calendar-only
        # cases as positive opaque DATA rather than normalizing them.
        for timestamp, nanoseconds in (("0001-01-01T00:00:00", "0"),
                                       ("2000-02-29T12:34:56", "123456789"),
                                       ("9999-12-31T23:59:59", "999999999"),
                                       ("1900-01-00T22:06:56", "0"),
                                       ("0000-01-01T00:00:00", "0"),
                                       ("2026-02-29T12:34:56", "0"),
                                       ("2026-04-31T12:34:56", "0"),
                                       ("2026-13-01T12:34:56", "0"),
                                       ("2026-01-01T24:00:00", "0"),
                                       ("2026-01-01T12:60:00", "0"),
                                       ("2026-01-01T12:34:60", "0")):
            def created_text(toc):
                for element in toc.iter("file"):
                    created = element.find("FinderCreateTime")
                    created.find("time").text = timestamp
                    created.find("nanoseconds").text = nanoseconds
                    created[:] = list(reversed(created))
                    created.text = created.tail = "\n"
                    for field in created:
                        field.tail = "\n"
            with self.subTest(created_time=timestamp, nanoseconds=nanoseconds):
                annotated = self.xar(members, mutate=created_text)
                self.assertEqual(fixture.context_xar(annotated), members)
                if timestamp == "1900-01-00T22:06:56":
                    for directory in (False, True):
                        product = self.xar({"Distribution": fixture.context_distribution(),
                                            **(members if directory else {fixture.CONTEXT_PACKAGES[1]: annotated})},
                                           directory=directory, mutate=created_text)
                        fixture.context_product(product, annotated, members)
        fixture.context_package_info(members["PackageInfo"], fixture.CONTEXT_IDENTIFIERS[1])
        for directory in (False, True):
            product = self.xar({"Distribution": fixture.context_distribution(),
                               **(members if directory else {fixture.CONTEXT_PACKAGES[1]: component})}, directory=directory)
            fixture.context_product(product, component, members)
        completed = fixture.context_distribution().replace(b'version="1">', b'version="1" installKBytes="0" onConclusion="None">')
        completed = completed.replace(b'>context-wrapped.pkg<', b'>#context-wrapped.pkg<')
        fixture.context_product(self.xar({"Distribution": completed, fixture.CONTEXT_PACKAGES[1]: component}), component, members)

    def test_archive_alias_payload_overlap_tail_checksum_hooks_and_product_change_are_refused(self):
        members = {"PackageInfo": self.package_info(), "Scripts": b"inert"}
        component = self.xar(members)
        checksum_bad = bytearray(component)
        compressed = struct.unpack_from(">Q", component, 8)[0]
        checksum_bad[28 + compressed] ^= 1
        bad = (
            self.xar({**members, "Payload": b"no"}), self.xar({"../Scripts": b"no", "PackageInfo": members["PackageInfo"]}),
            self.xar(members, mutate=lambda toc: setattr(toc.findall("file")[1].find("type"), "text", "symlink")),
            self.xar(members, mutate=lambda toc: setattr(toc.findall("file")[1].find("data/offset"), "text", "32")),
            component + b"\0", bytes(checksum_bad), component[:-1],
        )
        for index, body in enumerate(bad):
            with self.subTest(archive=index), self.assertRaises(fixture.Refused):
                fixture.context_xar(body)
        import xml.etree.ElementTree as ET
        for tag in ("inode", "deviceno"):
            for value in ("", "+1", "-0", "01", " 1", "1" * 21, "not-a-number"):
                def bad_stat(toc):
                    toc.find("file/" + tag).text = value
                with self.subTest(stat_tag=tag, value=value), self.assertRaisesRegex(
                        fixture.Refused, "^context-xar-member-metadata$"):
                    fixture.context_xar(self.xar(members, mutate=bad_stat))
            for shape in ("attribute", "child", "duplicate"):
                def bad_shape(toc):
                    element = toc.find("file")
                    leaf = element.find(tag)
                    if shape == "attribute":
                        leaf.set("unexpected", "1")
                    elif shape == "child":
                        ET.SubElement(leaf, "unexpected")
                    else:
                        element.append(copy.deepcopy(leaf))
                label = "duplicate" if shape == "duplicate" else "metadata"
                with self.subTest(stat_tag=tag, shape=shape), self.assertRaisesRegex(
                        fixture.Refused, "^context-xar-member-" + label + "$"):
                    fixture.context_xar(self.xar(members, mutate=bad_shape))
        bad_created_values = (
            ("time", ("", "2026-01-01T12:34:56Z", "2026-01-01T12:34:56+00:00",
                      "2026-01-01T12:34:56.0", "2026-1-01T12:34:56", "\u0662" + "026-01-01T12:34:56",
                      "1900-01-00T22:06:56\n", "1900-01-00T22:06:5\t", "1900-01-00T22:06:56extra", "1" * 65)),
            ("nanoseconds", ("", "-1", "+1", "00", "01", "1000000000", "1.0", " 1", "\u0661")),
        )
        for tag, values in bad_created_values:
            for value in values:
                def bad_created_text(toc):
                    toc.find("file/FinderCreateTime/" + tag).text = value
                with self.subTest(created_tag=tag, value=value), self.assertRaisesRegex(
                        fixture.Refused, "^context-xar-member-metadata$"):
                    fixture.context_xar(self.xar(members, mutate=bad_created_text))
        for shape in ("attribute", "text", "tail", "duplicate", "missing-time", "missing-nanoseconds",
                      "duplicate-leaf", "extra-leaf", "leaf-attribute", "leaf-child", "leaf-tail"):
            def bad_created_shape(toc):
                element = toc.find("file")
                created = element.find("FinderCreateTime")
                field = created.find("time")
                if shape == "attribute":
                    created.set("unexpected", "1")
                elif shape == "text":
                    created.text = "unexpected"
                elif shape == "tail":
                    created.tail = "unexpected"
                elif shape == "duplicate":
                    element.append(copy.deepcopy(created))
                elif shape == "missing-time":
                    created.remove(field)
                elif shape == "missing-nanoseconds":
                    created.remove(created.find("nanoseconds"))
                elif shape == "duplicate-leaf":
                    created.remove(created.find("nanoseconds"))
                    created.append(copy.deepcopy(field))
                elif shape == "extra-leaf":
                    ET.SubElement(created, "unexpected")
                elif shape == "leaf-attribute":
                    field.set("unexpected", "1")
                elif shape == "leaf-child":
                    ET.SubElement(field, "unexpected")
                else:
                    field.tail = "unexpected"
            label = "duplicate" if shape == "duplicate" else "metadata"
            with self.subTest(created_shape=shape), self.assertRaisesRegex(
                    fixture.Refused, "^context-xar-member-" + label + "$"):
                fixture.context_xar(self.xar(members, mutate=bad_created_shape))
        for tag in ("acl", "flags", "ea", "device", "link"):
            def diagnostic_tag(toc):
                ET.SubElement(toc.find("file"), tag)
            with self.subTest(refused_metadata=tag), self.assertRaisesRegex(
                    fixture.Refused, "^context-xar-member-tags-" + tag + "$"):
                fixture.context_xar(self.xar(members, mutate=diagnostic_tag))
        for shape, label in (("unknown", "tags"), ("missing-name", "required"), ("duplicate-name", "required")):
            def bad_member(toc):
                element = toc.find("file")
                if shape == "unknown":
                    ET.SubElement(element, "unrecognized")
                elif shape == "missing-name":
                    element.remove(element.find("name"))
                else:
                    element.append(copy.deepcopy(element.find("name")))
            with self.subTest(member_shape=shape), self.assertRaisesRegex(
                    fixture.Refused, "^context-xar-member-" + label + "$"):
                fixture.context_xar(self.xar(members, mutate=bad_member))
        # Remaining live guards, not a guessed acceptance format. Preserve
        # each original Refused; only bounded annotation/number spellings show.
        # finder-calendar stays in the closed vocabulary for old diagnostics,
        # but the parser no longer treats optional annotation text as a date.
        diagnostic_samples = (
            ("finder-shape", "FinderCreateTime", lambda toc: toc.find("file/FinderCreateTime").set("private-name", "private-value")),
            ("finder-values", "FinderCreateTime", lambda toc: setattr(toc.find("file/FinderCreateTime/time"), "text", "2026-01-01T12:34:56Z")),
            ("scalar-shape", "inode", lambda toc: ET.SubElement(toc.find("file/inode"), "private-name")),
            ("inode-value", "inode", lambda toc: setattr(toc.find("file/inode"), "text", "+1")),
            ("deviceno-value", "deviceno", lambda toc: setattr(toc.find("file/deviceno"), "text", "01")),
        )
        calls = [{"role": "context-component-build", "entered": True, "returned": True, "returncode": 0}]
        for check, tag, mutate in diagnostic_samples:
            body = self.xar(members, mutate=mutate)
            with self.subTest(diagnostic_check=check), self.assertRaises(fixture.Refused) as caught:
                fixture.context_xar(body)
            self.assertEqual(caught.exception.args, ("context-xar-member-metadata",))
            self.assertIs(type(caught.exception), fixture.Refused)
            observed = caught.exception._context_metadata
            self.assertEqual(observed["metadata"]["check"], check)
            self.assertEqual(observed["metadata"]["tag"], tag)
            self.assertNotIn("private-", fixture.canonical(observed).decode("ascii"))
            self.assertEqual(observed["parsedArchiveSha256"], fixture.digest(body))
            diagnostic = {"schemaVersion": 1, "type": "mrk-context-xar-metadata-diagnostic-v1", "diagnosticOnly": True,
                          "phase": "context-component-audit", "package": "direct-component",
                          "packageSha256": fixture.digest(body), "packageBytes": len(body), "buildCallIndex": 0, **observed}
            self.assertIs(fixture.context_metadata_diagnostic_data(diagnostic, diagnostic["phase"], caught.exception.args[0], calls), diagnostic)
            self.assertLessEqual(len(fixture.canonical(diagnostic)), 2048)
            for field, value in (("buildCallIndex", True), ("package", "outside"), ("packageBytes", 0),
                                 ("packageSha256", "path-or-other-text"), ("diagnosticOnly", 1)):
                bad_diagnostic = dict(diagnostic, **{field: value})
                self.assertIsNone(fixture.context_metadata_diagnostic_data(bad_diagnostic, diagnostic["phase"], caught.exception.args[0], calls))
            for key, value in (("check", "guessed"), ("tag", "host-path"), ("member", "/unrelated"),
                               ("attributes", 17), ("children", True), ("leafAttributes", 1)):
                bad_diagnostic = copy.deepcopy(diagnostic)
                bad_diagnostic["metadata"][key] = value
                self.assertIsNone(fixture.context_metadata_diagnostic_data(bad_diagnostic, diagnostic["phase"], caught.exception.args[0], calls))
            for bad_calls in ([], calls * 2, [dict(calls[0], returned=False)], [dict(calls[0], returncode=1)],
                              [dict(calls[0], returncode=False)], [dict(calls[0], role="context-product-build")]):
                self.assertIsNone(fixture.context_metadata_diagnostic_data(diagnostic, diagnostic["phase"], caught.exception.args[0], bad_calls))
            self.assertIsNone(fixture.context_metadata_diagnostic_data(diagnostic, "context-product-audit", caught.exception.args[0], calls))
            self.assertIsNone(fixture.context_metadata_diagnostic_data(diagnostic, diagnostic["phase"], None, calls))
        for tag, value in (("time", "2026-01-01T12:34:56+00:00"), ("nanoseconds", "1000000000"),
                           ("time", "/Users/private/path"), ("time", "\u0662" + "026-01-01T12:34:56"),
                           ("time", "1" * 65), ("nanoseconds", " 1"), ("nanoseconds", "1" * 25)):
            body = self.xar(members, mutate=lambda toc: setattr(toc.find("file/FinderCreateTime/" + tag), "text", value))
            with self.subTest(scalar_tag=tag, value=value), self.assertRaises(fixture.Refused) as caught:
                fixture.context_xar(body)
            scalar = caught.exception._context_metadata["metadata"]["timestamp" if tag == "time" else "nanoseconds"]
            self.assertEqual(scalar["characters"], len(value))
            self.assertEqual(scalar["text"], value if value in ("2026-01-01T12:34:56+00:00", "1000000000") else None)
        self.assertEqual(fixture.context_xar(component), members)  # Same accepted parse.

        entity = '<!DOCTYPE pkg-info [<!ENTITY hidden "expanded">]><pkg-info>&hidden;</pkg-info>'
        for encoding in ("utf-8", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"):
            with self.subTest(xml_encoding=encoding), self.assertRaises(fixture.Refused):
                fixture.context_xml(entity.encode(encoding), 65536)
        with self.assertRaises(fixture.Refused):
            fixture.context_xml(b"<pkg-info>\xff</pkg-info>", 65536)
        for body in (members["PackageInfo"].replace(b'numberOfFiles="0"', b'numberOfFiles="1"'),
                     members["PackageInfo"].replace(b"<postinstall", b"<preinstall"),
                     members["PackageInfo"].replace(b"<relocate/>", b'<relocate><bundle path="/unrelated"/></relocate>')):
            with self.assertRaises(fixture.Refused):
                fixture.context_package_info(body, fixture.CONTEXT_IDENTIFIERS[1])
        for extra in ({"Distribution": fixture.context_distribution() + b"<script/>"},
                      {"Distribution": fixture.context_distribution().replace(b'>context-wrapped.pkg<', b'>https://outside.invalid/pkg<')},
                      {"Distribution": fixture.context_distribution().replace(b'version="1">', b'version="1" onConclusion="RequireRestart">')},
                      {fixture.CONTEXT_PACKAGES[1]: component + b"\0"}):
            body = self.xar({"Distribution": fixture.context_distribution(), fixture.CONTEXT_PACKAGES[1]: component, **extra})
            with self.assertRaises(fixture.Refused):
                fixture.context_product(body, component, members)

    def test_record_distinguishes_unopened_context_and_requires_the_same_input_and_output_originals(self):
        expected_output = (1, 2, 0o100600, 501, 20, 1)
        original = (1, 3, 0o100600, 501, 20, 1, 4096, 10, 20)
        packages = {"outer-product": {"original": original, "sha256": "d" * 64}}
        missing = self.raw()
        valid = self.raw()
        valid["packagePath"] = {"kind": "nominated", "match": "outer-product", "opened": True, "closed": True,
                                "original": list(original), "sha256": "d" * 64}
        for row in (missing, valid):
            data = fixture.context_record(fixture.canonical(row), SOURCE, "b" * 64, "component",
                                          100_000_000_000, expected_output, packages)
            self.assertNotIn("original", data["packagePath"])
            self.assertIs(data["packagePath"]["originalMatched"], True if row is valid else None)
        mutations = (
            lambda row: row.update(outputClosed=True), lambda row: row.update(case="product"),
            lambda row: row.update(schemaVersion=True), lambda row: row.update(deadlineNs="100000000001"),
            lambda row: row["outputOriginal"].__setitem__(1, 99),
            lambda row: row["packagePath"]["original"].__setitem__(8, 21),
            lambda row: row["packagePath"].update(sha256="e" * 64),
            lambda row: row["packagePath"].update(closed=None),
            lambda row: row["packagePath"].update(match="/private/unrelated"),
            lambda row: row["argumentOne"].update(closed=True),
        )
        for index, change in enumerate(mutations):
            row = copy.deepcopy(valid)
            change(row)
            with self.subTest(record=index), self.assertRaises(fixture.Refused):
                fixture.context_record(fixture.canonical(row), SOURCE, "b" * 64, "component",
                                       100_000_000_000, expected_output, packages)

    def test_public_projection_cannot_grant_authority_or_invent_unexecuted_cases_and_closes(self):
        value = self.public()
        self.assertEqual(fixture.installer_context_data(value, SOURCE), value)
        self.assertFalse(value["outerPackageAuthority"] or value["maintenanceQualified"] or value["receiptsRetired"])
        for change in (
            lambda row: row.update(outerPackageAuthority=True), lambda row: row.update(maintenanceQualified=True),
            lambda row: row.update(enteredCases=["product", "component"]),
            lambda row: row["cases"][0].update(outputOriginalClosed=False),
            lambda row: row["cases"][0]["argumentOne"].update(rawPath="/private/local-file"),
            lambda row: row["cases"][0]["receiptOriginals"][0].update(present=False),
            lambda row: row.update(completed=True, cases=[]),
        ):
            row = copy.deepcopy(value)
            change(row)
            with self.assertRaises(fixture.Refused):
                fixture.installer_context_data(row, SOURCE)
        value.update(completed=False, enteredCases=["component"], cases=[])
        self.assertEqual(fixture.installer_context_data(value, SOURCE), value)  # Honest failure, no completion.

    def test_common_deadline_is_checked_before_and_after_the_original_owner_return(self):
        self.assertEqual(fixture.context_timeout(100_000_000_000, 40_100_000_000, 60), 59)
        with self.assertRaises(fixture.Refused):
            fixture.context_timeout(100_000_000_000, 99_100_000_000, 60)
        for mode, ticks, code, calls in (("timely", (40_000_000_000, 50_000_000_000), 0, 1),
                                        ("late", (40_000_000_000, 100_000_000_000), 0, 1),
                                        ("expired", (100_000_000_000,), 0, 0),
                                        ("nonzero", (40_000_000_000, 50_000_000_000), 1, 1)):
            with self.subTest(mode=mode):
                invocations = []
                def owner(argv, **kwargs):
                    invocations.append((list(argv), kwargs))
                    return subprocess.CompletedProcess(argv, code, b"", b"")
                book = SimpleNamespace(check=lambda: None)
                op = fixture.Operation(SimpleNamespace(run_owned=owner), SimpleNamespace(book=book), None, Path("/inert"),
                                       {"GITHUB_SHA": SOURCE, "DEVELOPER_DIR": "/inert/sdk"})
                op.outputs = op.protected = book
                op.publish = lambda *_args: None
                op.installer_context.update(started=True, deadlineNs="100000000000")
                clock = iter(ticks)
                fixed_time = SimpleNamespace(CLOCK_MONOTONIC=17, clock_gettime_ns=lambda selected:
                                             next(clock) if selected == 17 else self.fail("different clock"))
                with patch.object(fixture, "time", fixed_time):
                    if mode == "timely":
                        op.context_command("context-component-installer", ["/inert/installer"], 60)
                    else:
                        with self.assertRaises(fixture.Refused):
                            op.context_command("context-component-installer", ["/inert/installer"], 60)
                self.assertEqual(len(invocations), calls)
                self.assertEqual(len(op.calls), calls)
                self.assertEqual(op.installer_context["enteredCases"], ["component"] if calls else [])
                if calls:
                    self.assertEqual(invocations[0][1]["timeout"], 60)
                    self.assertTrue(op.calls[0]["returned"])
                    self.assertEqual(op.calls[0]["returncode"], code)
                self.assertFalse(op.installer_context["completed"])

    def test_private_output_keeps_original_custody_and_close_uncertainty_cannot_settle(self):
        # Real task-private filesystem, but no Installer/helper execution. The
        # test's explicit write stands only for record DATA in the same output.
        for inject_close in (False, True):
            with self.subTest(close_uncertain=inject_close), tempfile.TemporaryDirectory(prefix="mrk-context-data-") as temporary:
                root, book = Path(temporary), fixture.Originals()
                try:
                    fd = fixture.os.open(root, fixture.READ_FLAGS | fixture.os.O_DIRECTORY)
                    parent = book.register(fd, root, "directory")
                    parent.update(identity=fixture.signature(fixture.os.fstat(fd))[:5], parent=None)
                    book.directories[root] = parent
                    op = fixture.Operation(None, None, None, root, {"GITHUB_SHA": SOURCE})
                    op.outputs = book
                    captured = []
                    op.publish = lambda name, body: captured.append((name, body))
                    op.installer_context.update(started=True, deadlineNs="100000000000", observerSourceSha256="b" * 64)
                    output = op.context_output(root / "original.json")
                    structure = output["identity"]
                    with self.assertRaises(FileExistsError):
                        op.context_output(root / "original.json")  # Never adopt a pre-existing output.
                    body = fixture.canonical(self.raw(output=structure))
                    self.assertEqual(fixture.os.write(output["fd"], body), len(body))
                    fixture.os.fsync(output["fd"])
                    original_close = book.close
                    def close_unknown(entry):
                        original_close(entry)  # Join the real local FD, then inject an UNKNOWN verdict.
                        entry["closed"] = False
                        book.errors.append("original-close-unknown")
                    fixed_time = SimpleNamespace(CLOCK_MONOTONIC=17, clock_gettime_ns=lambda _clock: 1)
                    with patch.object(fixture, "time", fixed_time), \
                         patch.object(book, "close", close_unknown if inject_close else original_close):
                        if inject_close:
                            with self.assertRaises(fixture.Refused):
                                op.context_read_output(output, "component", {})
                        else:
                            result = op.context_read_output(output, "component", {})
                            self.assertTrue(result["outputOriginalClosed"])
                    self.assertIs(output["identity"], structure)
                    self.assertIsNone(output["fd"])
                    self.assertEqual(output["closed"], not inject_close)
                    self.assertEqual(len(captured), 0 if inject_close else 1)
                    self.assertFalse(op.installer_context["completed"])
                finally:
                    self.assertEqual(book.finish(), not inject_close)

    def test_entered_context_without_complete_original_receipt_never_retires_scratch(self):
        op = OwnerRetirementAndModeTests.operation(b"", 0)
        op.installer_context.update(started=True, deadlineNs="100000000000", enteredCases=["component"])
        op.calls = [{"returned": True, "returncode": 0}]
        with patch.object(fixture, "Originals") as cleanup, patch.object(fixture.shutil, "rmtree") as retire:
            op.finish()
            cleanup.assert_not_called()
            retire.assert_not_called()
        self.assertFalse(op.scratch_retired or op.installer_context["completed"])
        self.assertTrue(op.sources_closed and op.outputs_closed and op.protected_closed)

        # These are inert original-read/process/book DATA. The actual pure
        # parser and execute/finish run; no native process or deletion occurs.
        def invalid_finder(toc):
            toc.find("file/FinderCreateTime/time").text = "2026-01-01T12:34:56Z"
        body = self.xar({"PackageInfo": self.package_info(), "Scripts": b"inert"}, mutate=invalid_finder)
        scenarios = ("known-pure", "read-refused", "read-unknown", "parser-unexpected", "parser-unmarked",
                     "diagnostic-unknown", "foreign-original", "context-entered", "installer-entered",
                     "call-unknown", "source-close-unknown", "output-close-unknown", "protected-close-unknown",
                     "secondary-unknown")
        stat_info = SimpleNamespace(**dict(zip(
            ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"), WORK)))
        for scenario in scenarios:
            with self.subTest(retirement=scenario):
                op = OwnerRetirementAndModeTests.operation(b"", 0)
                op.installed = False
                op.installer_context.update(started=True, deadlineNs="100000000000")
                op.phase = "context-component-audit"
                op.calls = [{"role": "context-component-build", "entered": True, "returned": True, "returncode": 0}]
                entry = {"fd": 92, "path": op.scratch / "installer-context" / fixture.CONTEXT_PACKAGES[0],
                         "kind": "file", "closed": False, "identity": (*WORK[:6], len(body), *WORK[7:])}
                op.outputs.entries = [] if scenario == "foreign-original" else [entry]
                op.outputs.directories = {op.scratch: {"identity": WORK[:5]}}
                events = []
                def original_read(*_args, **_kwargs):
                    if scenario == "read-refused":
                        raise fixture.Refused("context-xar-member-metadata")
                    if scenario == "read-unknown":
                        raise KeyboardInterrupt()
                    events.append("original-body-read-eof-post-returned")
                    return entry, body
                op.outputs.file = original_read
                def audit():
                    bound, original_body = op.outputs.file(entry["path"], fixture.CONTEXT_PACKAGE_LIMIT)
                    try:
                        op.context_audit(bound, original_body)
                    except fixture.Refused as error:
                        events.append(error)
                        raise
                op.begin = op.build_installer_worker_tests = lambda: None
                op.observe_installer_context = audit
                op.observe_btm_logs = lambda: None
                op.receipt = lambda failure: failure  # No synthetic receipt/pass.
                if scenario == "context-entered":
                    op.installer_context["enteredCases"] = ["component"]
                elif scenario == "installer-entered":
                    op.installer_entered = True
                elif scenario == "call-unknown":
                    op.calls[0]["returned"] = False
                elif scenario.endswith("close-unknown"):
                    book = {"source-close-unknown": op.source.book, "output-close-unknown": op.outputs,
                            "protected-close-unknown": op.protected}[scenario]
                    book.finish = lambda: False
                elif scenario == "secondary-unknown":
                    def unknown_log():
                        raise KeyboardInterrupt()
                    op.observe_btm_logs = unknown_log
                parse = fixture.context_xar
                observation = fixture._context_metadata_observation
                unmarked = fixture.Refused("context-xar-member-metadata")
                def selected_parse(data, **kwargs):
                    if scenario == "parser-unexpected":
                        raise RuntimeError("inert")
                    if scenario == "parser-unmarked":
                        raise unmarked
                    return parse(data, **kwargs)
                def selected_observation(*args):
                    if scenario == "diagnostic-unknown":
                        raise KeyboardInterrupt()
                    return observation(*args)
                cleanup = SimpleNamespace(directory=lambda _path: {"fd": 93}, finish=lambda: True)
                with patch.object(fixture, "context_xar", selected_parse), \
                     patch.object(fixture, "_context_metadata_observation", selected_observation), \
                     patch.object(fixture, "Originals", return_value=cleanup) as originals, \
                     patch.object(fixture.os, "stat", side_effect=[stat_info, FileNotFoundError()]) as named, \
                     patch.object(fixture.shutil, "rmtree") as retire:
                    retire.avoids_symlink_attacks = True
                    failure = op.execute()
                    if scenario == "known-pure":
                        self.assertEqual(events[0], "original-body-read-eof-post-returned")
                        self.assertIs(events[1], op._context_metadata_refusal)
                        self.assertTrue(op.context_pure_metadata_refused)
                        self.assertEqual(failure, "context-xar-member-metadata")
                        self.assertIn(fixture.CONTEXT_METADATA_ARTIFACT, op.artifacts)
                        originals.assert_called_once_with()
                        retire.assert_called_once_with(op.scratch.name, dir_fd=93)
                        self.assertEqual(named.call_count, 2)
                    else:
                        originals.assert_not_called()
                        retire.assert_not_called()
                        named.assert_not_called()
                self.assertEqual(op.scratch_retired, scenario == "known-pure")
                self.assertFalse(op.installer_context["completed"])
                if scenario in ("read-refused", "read-unknown", "parser-unexpected", "parser-unmarked",
                                "diagnostic-unknown", "foreign-original", "call-unknown", "secondary-unknown"):
                    self.assertFalse(op.context_pure_metadata_refused)
                if scenario == "parser-unmarked":
                    self.assertIs(events[-1], unmarked)

    def test_fixed_context_source_uses_only_existing_owner_and_private_original_output_channel(self):
        source = PATH.read_text(encoding="utf-8")
        observer = (PATH.parents[1] / "native/macos-installed-native/src/e2_installer_context.c").read_text(encoding="utf-8")
        workflow = (PATH.parents[2] / ".github/workflows/desktop-macos-maintenance-fixture.yml").read_text(encoding="utf-8")
        self.assertIn('"--nopayload", "--scripts"', source)
        self.assertIn('self.stager._cpio_members(archive, (os.getuid(), os.getgid())) == expected', source)
        self.assertIn('"${0%/*}/mrk-context-observer" ', source)
        self.assertIn('"${PACKAGE_PATH+x}" "${PACKAGE_PATH-}" "$@"', source)
        self.assertLess(source.index('self.observe_installer_context()', source.index('    def execute(self):')),
                        source.index('self.build_images()', source.index('    def execute(self):')))
        self.assertLess(source.index('self.context_command("context-" + case + "-installer"'),
                        source.index('self.context_read_output(original_outputs[case], case, packages)'))
        self.assertIn('context_timeout(deadline, time.clock_gettime_ns(time.CLOCK_MONOTONIC), cap)', source)
        self.assertIn('clock_gettime(CLOCK_MONOTONIC', observer)
        self.assertIn('output_closed && parent_closed && timely()', observer)
        self.assertNotIn('"outputClosed"', observer)
        self.assertNotIn('/var/log/install.log', source + observer + workflow)
        self.assertNotIn('--forget', source)
        self.assertIn('fixture.installer_context_data(result["installerContext"], source)', workflow)
        self.assertIn('installer_context is not None and installer_context["completed"]', workflow)


if __name__ == "__main__":
    unittest.main()
