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
        value["cases"][1] = cases()[1]
        with self.assertRaises(fixture.Refused):
            parse(value, 77)


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
        with self.assertRaises(fixture.Refused):
            fixture.fixture_image_macho(wrong_role, "resident")
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


if __name__ == "__main__":
    unittest.main()
