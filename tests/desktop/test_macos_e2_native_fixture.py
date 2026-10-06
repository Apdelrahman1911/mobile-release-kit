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
        with patch.object(fixture.os, "stat", side_effect=FileNotFoundError()), \
                patch.object(fixture.Path, "resolve", side_effect=AssertionError("no runtime path resolution")):
            cargo_path, environment = operation.compiler_environment(target)
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
                    self.assertTrue(value.receipt(None)["passed"])
                    self.assertEqual(value.receipt(None)["nativeRustTests"], value.native_rust_tests)
                    value.native_rust_tests = None
                    self.assertFalse(value.receipt(None)["passed"])

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
