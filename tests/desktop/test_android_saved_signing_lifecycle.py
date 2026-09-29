"""Saved3 lifecycle DATA/source regressions; never native evidence.

The first two classes use invented inventories, identities, capture bytes and
signing inputs. The native-route test supplies their terminal/receipt factory.
The added boundary class uses a small exclusive temporary DATA directory and
the five actual source dependencies for routing/import regression coverage.
It also proves early rejection with fail-if-called private-reader guards.
No tool process, GUI, signing credential, network route or native owner is
acquired, and none of these comparison fixtures is native qualification.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[2]


def source_module(name, relative):
    spec = importlib.util.spec_from_file_location(name, SOURCE / relative)
    assert spec is not None and spec.loader is not None
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


D = source_module("_mrk_saved3_lifecycle_receipt_data", "tests/desktop/test_android_saved_signing_native_route.py")
L, CASES = D.L, D.CASES
STAMP = 1790240000326184301


def selected():
    return {"runId": "12345", "attempt": "1", "runnerUid": 1001, "runnerGid": 1001,
            "shell": {"savedSigning": L.shell_android_saved_selection()}}


def maps_data():
    roles = sorted({"python", "libssl.so.3", "libcrypto.so.3", "ld-linux-x86-64.so.2", "libc.so.6", "libm.so.6"})
    expected = {role: {"paths": ["/inert/saved3/" + role], "deviceMajor": 8, "deviceMinor": 2,
                       "inode": (1 << 63) + index + 11} for index, role in enumerate(roles)}
    rows = [{"role": role, "path": row["paths"][0],
             **{key: row[key] for key in ("deviceMajor", "deviceMinor", "inode")}}
            for role, row in sorted(expected.items())]
    return expected, rows


def capture_data(case, receipt=None):
    expected, rows = maps_data()
    receipt = D.receipt_data(case)[0] if receipt is None else receipt
    frames = [b"MRK_DESKTOP_CAPABILITIES=available\n",
              b"MRK_DESKTOP_CATALOGUE=returned\n",
              b"MRK_INSTALLED_SHELL_CONTRACTS=capability-intersection,packaged-allowlist-verified\n",
              L.CHILD_MARKER.encode("ascii") + L.canonical(rows),
              L.CHILD_MARKER.encode("ascii") + L.canonical(deepcopy(rows)),
              L.SHELL_ANDROID_SAVED_MARKER + L.canonical(receipt),
              b"MRK_INSTALLED_SHELL_OBSERVATION=" + case.encode("ascii") + b"-verified\n"]
    return frames, expected, rows


def decoded_receipt(receipt, fixture, case):
    return L.shell_android_saved_receipt(L.canonical(receipt), case,
        saved_config=fixture["savedConfig"], saved_version=fixture["savedVersion"],
        selection=fixture["selection"], certificate_sha256=fixture["certificateSha256"])


class AndroidSavedSigningLifecycleFrames(unittest.TestCase):
    def test_closed_selection_has_three_only_namespace_without_expanding_legacy_cases(self):
        value = selected()
        self.assertEqual(L.shell_android_saved_selection(), {
            "profile": "android-saved-signing3-v1", "cases": list(CASES), "compilerCaseExecution": False})
        self.assertEqual(L.shell_cases(value), CASES)
        self.assertEqual(L.shell_android_cases(value), CASES)
        self.assertEqual(L.shell_fixture_children(value), tuple(sorted(CASES)))
        self.assertEqual(len(L.shell_cases({"shell": {}})), 25)
        self.assertTrue(set(CASES).isdisjoint(L.shell_cases({"shell": {}})))
        for change in ("extra-case", "duplicate-case", "order", "compiler", "legacy", "mixed"):
            with self.subTest(change=change):
                value = selected()
                chosen = value["shell"]["savedSigning"]
                if change == "extra-case": chosen["cases"].append("android-build")
                elif change == "duplicate-case": chosen["cases"][1] = CASES[0]
                elif change == "order": chosen["cases"].reverse()
                elif change == "compiler": chosen["compilerCaseExecution"] = True
                elif change == "legacy": chosen["profile"] = "android-build4-v1"
                else: value["shell"]["ordinary21"] = {"profile": "unrelated"}
                with self.assertRaises(L.Refused):
                    L.shell_cases(value)

    def test_actual_frame_parser_requires_both_maps_and_preserves_full_width_identity(self):
        for case in CASES:
            with self.subTest(case=case):
                receipt, fixture = D.receipt_data(case)
                frames, expected, rows = capture_data(case, receipt)
                before = deepcopy((receipt, expected, rows))
                raw, observed = L._shell_android_saved_frames(
                    b"ordinary non-authoritative diagnostic\n" + b"".join(frames), b"", case, 0, expected)
                self.assertEqual(raw, L.canonical(receipt))
                self.assertEqual(observed, [rows, rows])
                self.assertGreater(observed[0][0]["inode"], 1 << 53)
                self.assertEqual(decoded_receipt(receipt, fixture, case), receipt)
                self.assertEqual((receipt, expected, rows), before)

    def test_frame_order_complete_capture_and_zero_integer_exit_cannot_be_inferred(self):
        case = CASES[0]
        for change in ("missing-map", "extra-map", "receipt-before-map", "completion-before-receipt",
                       "foreign-marker", "stderr-marker", "noncanonical-receipt", "partial-receipt",
                       "partial-completion", "exit-one", "exit-bool"):
            with self.subTest(change=change):
                frames, expected, _ = capture_data(case)
                stderr, code = b"", 0
                if change == "missing-map": frames.pop(3)
                elif change == "extra-map": frames.insert(3, frames[3])
                elif change == "receipt-before-map": frames[4], frames[5] = frames[5], frames[4]
                elif change == "completion-before-receipt": frames[5], frames[6] = frames[6], frames[5]
                elif change == "foreign-marker": frames.insert(3, b"MRK_UNRELATED=pass\n")
                elif change == "stderr-marker": stderr = frames[0]
                elif change == "noncanonical-receipt":
                    receipt = D.receipt_data(case)[0]
                    frames[5] = L.SHELL_ANDROID_SAVED_MARKER + json.dumps(receipt, sort_keys=True, indent=2).encode() + b"\n"
                elif change == "partial-receipt": frames[5] = frames[5][:-2] + b"\n"
                elif change == "partial-completion": frames[-1] = frames[-1][:-1]
                elif change == "exit-one": code = 1
                else: code = True
                with self.assertRaises(L.Refused):
                    L._shell_android_saved_frames(b"".join(frames), stderr, case, code, expected)

    def test_early_frame_gate_refuses_unsettled_native_and_original_session_owners(self):
        for section, key, value in (
            ("original", "ioJoined", False), ("original", "observerJoined", False),
            ("original", "retiredBeforeCutoff", False), ("original", "activeRetained", True),
            ("original", "resourceUnknown", True), ("session", "queriesRetired", False),
            ("session", "originalsSettled", False), ("session", "relayJoined", False),
            ("session", "exit", False), ("configSave", "originalFinal", False),
        ):
            with self.subTest(section=section, key=key):
                receipt, _ = D.receipt_data(CASES[0])
                receipt[section][key] = value
                frames, expected, _ = capture_data(CASES[0], receipt)
                with self.assertRaises(L.Refused):
                    L._shell_android_saved_frames(b"".join(frames), b"", CASES[0], 0, expected)

    def test_original_map_correspondence_is_checked_before_fixture_acceptance(self):
        for change in ("path", "role", "inode", "boolean", "missing-role", "noncanonical-newline"):
            with self.subTest(change=change):
                frames, expected, rows = capture_data(CASES[0])
                if change == "path": rows[0]["path"] = "/inert/another/python"
                elif change == "role": rows[0]["role"] = rows[1]["role"]
                elif change == "inode": rows[0]["inode"] += 1
                elif change == "boolean": rows[0]["deviceMajor"] = True
                elif change == "missing-role": rows.pop()
                frames[3] = L.CHILD_MARKER.encode("ascii") + L.canonical(rows)
                if change == "noncanonical-newline": frames[3] = frames[3].replace(b"\n", b"\r\n")
                with self.assertRaises(L.Refused):
                    L._shell_android_saved_frames(b"".join(frames), b"", CASES[0], 0, expected)

    def test_receipt_has_exact_session13_and_original_precommand_binding(self):
        receipt, fixture = D.receipt_data(CASES[0])
        self.assertEqual(set(receipt["session"]), {
            "assessments", "fileChoosers", "capturedFiles", "capturesClosed", "kept", "assigned",
            "originalQueries", "queriesRetired", "originalsSettled", "relayJoined", "exit",
            "configBeforeAssignments", "binding"})
        for change in ("extra", "missing-binding", "foreign-binding", "save-not-final", "not-before"):
            with self.subTest(change=change):
                candidate = deepcopy(receipt)
                if change == "extra": candidate["session"]["invented"] = True
                elif change == "missing-binding": del candidate["session"]["binding"]
                elif change == "foreign-binding": candidate["session"]["binding"]["contextRevision"] += 1
                elif change == "save-not-final": candidate["configSave"]["originalFinal"] = False
                else: candidate["session"]["configBeforeAssignments"] = False
                with self.assertRaises((L.Refused, ValueError)):
                    decoded_receipt(candidate, fixture, CASES[0])


MATERIALS = {"instance": "inert-android", "manifestSha256": "1" * 64,
             "osContractSha256": "2" * 64, "distributionSha256": "3" * 64}
# Not real signing material; these bodies exist only in this DATA factory.
INPUTS = {
    "sources/input.jks": b"INERT_KEYSTORE_COMPARISON_DATA" * 64,
    "sources/certificate.der": b"\x30INERT_DER_COMPARISON_DATA",
    "sources/signing-fields.json": (
        b'{"storePassword":"' + b"a" * 64 + b'","keyAlias":"fixture_saved","keyPassword":"' + b"b" * 64 + b'"}\n'),
    "sources/firebase.json": b'{"client":[{"client_info":{"android_client_info":{"package_name":"org.example.saved"}}}]}\n',
}
CONFIG_PATH = "project/release/mobile-release.json"
TRACE_PATH = "project/native-stage.trace"
ABSENT = ["project/app/google-services.json", "project/.mobile-release/build-inputs",
          "project/.mobile-release/build-inputs-complete.json", "project/.mobile-release/build-inputs-complete.stage"]
GENERATED = ["project/.mobile-release", "project/app/build", "project/build"]
CONFIG_SECTIONS = {".", "version", "source", "android", "ios", "metadata", "services", "projectChecks"}


def config_data(case, *, certificate=None, reverse_order=False):
    """Independent semantic/encoding expectation, not the production generator."""
    certificate = hashlib.sha256(INPUTS["sources/certificate.der"]).hexdigest() if certificate is None else certificate
    config = json.loads(L.SHELL_ANDROID_CONFIG)
    fingerprint = certificate
    if case == CASES[1]:
        fingerprint = certificate[:-1] + ("1" if certificate[-1] == "0" else "0")
    config["android"]["uploadCertificateSha256"] = fingerprint
    config["services"]["androidFirebase"] = "required"
    order = {".": sorted(config, reverse=reverse_order),
             **{key: sorted(value, reverse=reverse_order) for key, value in config.items() if type(value) is dict}}
    ordered = {key: ({name: config[key][name] for name in order[key]} if type(config[key]) is dict else config[key])
               for key in order["."]}
    raw = (json.dumps(ordered, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    return ordered, raw, order, certificate


def fixture_data(case, *, reverse_order=False):
    """Invented 30-original correspondence only; no filesystem is accessed."""
    value = selected()
    config, saved_raw, order, certificate = config_data(case, reverse_order=reverse_order)
    namespace = {
        "root": "/var/lib/mrk-ubuntu-shell-fixtures-12345-1",
        "identity": [1, (1 << 63) + 5, stat.S_IFDIR | 0o755, 0, 0, 5, 4096, STAMP, STAMP],
        "children": sorted(CASES),
        "control": {"path": "/var/lib/mrk-ubuntu-native-12345-1",
                    "identity": [1, (1 << 63) + 4, stat.S_IFDIR | 0o711, 0, 0]},
        "ancestors": [{"path": name, "identity": [1, (1 << 63) + index + 1, stat.S_IFDIR | 0o755, 0, 0]}
                      for index, name in enumerate(("/", "/var", "/var/lib"))],
    }
    offset = (1 << 63) + 3000 + 100 * CASES.index(case)
    documents = []
    for after in (False, True):
        roster = L._shell_android_saved_roster(value, case, after,
            certificate_sha256=certificate, config_order=order if after else None)
        rows = []
        for index, (name, mode, owners, expected) in enumerate(roster):
            directory = stat.S_ISDIR(mode)
            body = None
            if not directory:
                if name in INPUTS:
                    body = INPUTS[name]
                elif name == CONFIG_PATH:
                    body = saved_raw if after else L.SHELL_ANDROID_CONFIG
                elif name == TRACE_PATH:
                    body = b"active\n" if after and case != CASES[1] else b""
                else:
                    body = expected
            changed = after and name in ("project", "project/release", "project/app", *GENERATED[1:], CONFIG_PATH, TRACE_PATH)
            links = (2 + sum(stat.S_ISDIR(m) and n != "." and str(Path(n).parent) == name for n, m, _, _ in roster)
                     + int(after and name == "project")) if directory else 1
            size = 4096 if directory else len(body)
            inode = offset + 98 if after and name == CONFIG_PATH else offset + index
            row = {"path": name, "kind": "directory" if directory else "file",
                   "identity": [1, inode, mode, *owners, links, size, STAMP + int(changed), STAMP + int(changed)]}
            if directory:
                row.update(children=expected, contentsInspected=expected is not None)
            else:
                row.update(size=size, sha256=hashlib.sha256(body).hexdigest())
            rows.append(row)
        generated = ({"path": GENERATED[0], "kind": "directory", "contentsInspected": False,
                      "identity": [1, offset + 99, stat.S_IFDIR | 0o700, value["runnerUid"], value["runnerGid"],
                                   3, 4096, STAMP + 1, STAMP + 1]} if after else None)
        documents.append({
            "schemaVersion": 1, "fixture": "installed-android-saved-signing-fixture-v1", "case": case,
            "root": namespace["root"] + "/" + case, "after": after, "entries": rows, "generatedNamespace": generated,
            "generatedScopesNotExported": list(GENERATED), "namespace": deepcopy(namespace), "materials": deepcopy(MATERIALS),
            "configKeyOrder": deepcopy(order) if after else None, "absent": list(ABSENT),
        })
    return value, documents[0], documents[1], saved_raw, config


def named(document, path):
    return next(row for row in document["entries"] if row["path"] == path)


def replace_descriptor(row, body):
    row["size"] = row["identity"][6] = len(body)
    row["sha256"] = hashlib.sha256(body).hexdigest()


def parse_fixture(value, before, after, case):
    return L.shell_android_saved_fixture(value, case, L.canonical(before), L.canonical(after))


def receipt_for_fixture(case, fixture, config):
    # Rebind only invented DATA; no parser outcome/finality routine is replaced.
    receipt, _ = D.receipt_data(case)
    receipt["fixture"] = {key: deepcopy(fixture[key]) for key in D.NATIVE_FIXTURE_KEYS}
    for key in ("savedConfig", "savedVersion", "selection"):
        receipt[key] = deepcopy(fixture[key])
    context = receipt["terminal"]["context"]
    context["savedConfig"], context["savedVersion"] = deepcopy(fixture["savedConfig"]), deepcopy(fixture["savedVersion"])
    context["artifactValidation"]["uploadCertificateSha256"] = config["android"]["uploadCertificateSha256"]
    result = receipt["terminal"]["result"]
    if result is not None:
        result["usedConfig"], result["usedVersion"] = deepcopy(fixture["savedConfig"]), deepcopy(fixture["savedVersion"])
        result["artifactValidation"] = deepcopy(context["artifactValidation"])
    return receipt


class AndroidSavedSigningLifecycleFixtures(unittest.TestCase):
    def setUp(self):
        # This is a validated synthetic selector, not a replacement parser,
        # filesystem reader, profile, tool owner or native admission result.
        material = patch.object(L, "SHELL_ANDROID_MATERIALS", deepcopy(MATERIALS))
        material.start()
        self.addCleanup(material.stop)

    def rejected(self, value, before, after, case):
        with self.assertRaises(L.Refused):
            parse_fixture(value, before, after, case)

    def test_independent_30_originals_join_receipts_without_exporting_private_bodies(self):
        for case in CASES:
            with self.subTest(case=case):
                value, before, after, raw, config = fixture_data(case)
                originals = deepcopy((value, before, after))
                fixture = parse_fixture(value, before, after, case)
                self.assertEqual(set(fixture), D.NATIVE_FIXTURE_KEYS | {
                    "savedConfig", "savedVersion", "selection", "beforeSha256", "afterSha256"})
                self.assertEqual(len(before["entries"]), 30)
                self.assertEqual(sum(row["kind"] == "directory" for row in before["entries"]), 16)
                self.assertEqual(sum(row["kind"] == "file" for row in before["entries"]), 14)
                self.assertEqual(fixture["savedConfig"], {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
                self.assertEqual(fixture["certificateSha256"], hashlib.sha256(INPUTS["sources/certificate.der"]).hexdigest())
                self.assertEqual(fixture["keystoreBytes"], len(INPUTS["sources/input.jks"]))
                self.assertEqual(fixture["firebaseBytes"], len(INPUTS["sources/firebase.json"]))
                self.assertEqual(fixture["selection"], {"module": ":app", "variant": "release",
                    "applicationId": "org.example.saved", "task": ":app:bundleRelease"})
                self.assertEqual(fixture["savedVersion"], {
                    "source": "release/version.properties", "bytes": len(L.SHELL_ANDROID_VERSION),
                    "sha256": hashlib.sha256(L.SHELL_ANDROID_VERSION).hexdigest(), "name": "1.2.3", "build": 7})
                self.assertEqual(fixture["beforeSha256"], hashlib.sha256(L.canonical(before)).hexdigest())
                self.assertEqual(fixture["afterSha256"], hashlib.sha256(L.canonical(after)).hexdigest())
                self.assertNotEqual(fixture["beforeSha256"], fixture["afterSha256"])
                self.assertEqual((value, before, after), originals)
                self.assertGreater(named(before, CONFIG_PATH)["identity"][7], 1 << 53)
                for body in (b"storePassword", b"keyPassword", b"INERT_DER_COMPARISON_DATA", b"INERT_KEYSTORE_COMPARISON_DATA"):
                    self.assertNotIn(body, L.canonical(before) + L.canonical(after))
                receipt = receipt_for_fixture(case, fixture, config)
                frames, expected, _ = capture_data(case, receipt)
                actual, _ = L._shell_android_saved_frames(b"".join(frames), b"", case, 0, expected)
                self.assertEqual(actual, L.canonical(decoded_receipt(receipt, fixture, case)))

    def test_key_order_is_preserved_but_cannot_authorize_different_semantics_or_encoding(self):
        value, before, after, original_raw, _ = fixture_data(CASES[0])
        self.assertEqual(set(after["configKeyOrder"]), CONFIG_SECTIONS)
        _, alt_before, alt_after, alternative_raw, _ = fixture_data(CASES[0], reverse_order=True)
        self.assertNotEqual(original_raw, alternative_raw)
        accepted = parse_fixture(value, alt_before, alt_after, CASES[0])
        self.assertEqual(accepted["savedConfig"]["sha256"], hashlib.sha256(alternative_raw).hexdigest())
        for change in ("missing-section", "duplicate-key", "missing-after", "order-with-old-hash", "wrong-services", "compact"):
            with self.subTest(change=change):
                old, new = deepcopy(before), deepcopy(after)
                if change == "missing-section": new["configKeyOrder"].pop("services")
                elif change == "duplicate-key": new["configKeyOrder"]["android"].append(new["configKeyOrder"]["android"][0])
                elif change == "missing-after": new["configKeyOrder"] = None
                elif change == "order-with-old-hash": new["configKeyOrder"] = deepcopy(alt_after["configKeyOrder"])
                else:
                    config = json.loads(original_raw)
                    if change == "wrong-services": config["services"]["androidFirebase"] = "disabled"
                    body = (json.dumps(config, indent=None if change == "compact" else 2,
                                       ensure_ascii=False, allow_nan=False) + "\n").encode()
                    replace_descriptor(named(new, CONFIG_PATH), body)
                self.rejected(value, old, new, CASES[0])
        bad_before = deepcopy(before)
        bad_before["configKeyOrder"] = deepcopy(after["configKeyOrder"])
        self.rejected(value, bad_before, after, CASES[0])

    def test_source_ownership_bounds_originals_and_config_replacement_are_not_peer_claims(self):
        value, before, after, _, _ = fixture_data(CASES[0])
        for change in ("keystore-zero", "keystore-large", "der-large", "fields-large", "bool-size", "wrong-owner",
                       "alias-namespace", "same-config-inode", "source-hash-change", "parent-replaced",
                       "self-consistent-new-certificate"):
            with self.subTest(change=change):
                old, new = deepcopy(before), deepcopy(after)
                if change in ("keystore-zero", "keystore-large", "der-large", "fields-large"):
                    path, size = {
                        "keystore-zero": ("sources/input.jks", 0), "keystore-large": ("sources/input.jks", 65537),
                        "der-large": ("sources/certificate.der", 16385), "fields-large": ("sources/signing-fields.json", 2049),
                    }[change]
                    for document in (old, new):
                        row = named(document, path)
                        row["size"] = row["identity"][6] = size
                elif change == "bool-size":
                    row = named(new, "sources/input.jks")
                    row["size"] = row["identity"][6] = True
                elif change == "wrong-owner": named(new, "sources/input.jks")["identity"][3] = 0
                elif change == "alias-namespace": named(new, "sources/input.jks")["identity"][:2] = new["namespace"]["identity"][:2]
                elif change == "same-config-inode": named(new, CONFIG_PATH)["identity"][1] = named(old, CONFIG_PATH)["identity"][1]
                elif change == "source-hash-change": named(new, "sources/input.jks")["sha256"] = "e" * 64
                elif change == "parent-replaced": named(new, "project/release")["identity"][1] += 10000
                else:
                    # Even matching the new after-config cannot excuse changing
                    # the original source certificate between observations.
                    named(new, "sources/certificate.der")["sha256"] = "e" * 64
                    _, body, order, _ = config_data(CASES[0], certificate="e" * 64)
                    new["configKeyOrder"] = order
                    replace_descriptor(named(new, CONFIG_PATH), body)
                self.rejected(value, old, new, CASES[0])

    def test_namespace_complete_membership_absence_and_generated_body_exclusion_are_exact(self):
        value, before, after, _, _ = fixture_data(CASES[0])
        self.assertEqual(before["absent"], ABSENT)
        self.assertEqual(after["generatedScopesNotExported"], GENERATED)
        for change in ("extra-control", "legacy-namespace", "namespace-drift", "missing-absence", "read-generated",
                       "export-generated", "wrong-case", "foreign-materials"):
            with self.subTest(change=change):
                old, new = deepcopy(before), deepcopy(after)
                if change == "extra-control": new["entries"].append(deepcopy(new["entries"][-1]))
                elif change == "legacy-namespace":
                    for document in (old, new): document["namespace"]["children"].append("android-build")
                elif change == "namespace-drift": new["namespace"]["identity"][8] += 1
                elif change == "missing-absence": new["absent"].pop()
                elif change == "read-generated": named(new, "project/app/build").update(children=[], contentsInspected=True)
                elif change == "export-generated": new["generatedNamespace"]["contentsInspected"] = True
                elif change == "wrong-case": new["case"] = CASES[1]
                else:
                    for document in (old, new): document["materials"]["manifestSha256"] = "e" * 64
                self.rejected(value, old, new, CASES[0])
        with self.assertRaises(L.Refused):
            L.shell_android_saved_fixture(value, CASES[0],
                (json.dumps(before, indent=2) + "\n").encode(), L.canonical(after))

    def test_wrong_fingerprint_and_cancel_keep_distinct_original_build_boundaries(self):
        for case in CASES:
            with self.subTest(case=case):
                value, before, after, _, config = fixture_data(case)
                fixture = parse_fixture(value, before, after, case)
                actual = fixture["certificateSha256"]
                configured = config["android"]["uploadCertificateSha256"]
                expected_trace = "" if case == CASES[1] else "active\n"
                self.assertEqual(fixture["gradleBoundary"], expected_trace)
                self.assertEqual(named(after, TRACE_PATH)["sha256"], hashlib.sha256(expected_trace.encode()).hexdigest())
                if case == CASES[1]:
                    self.assertNotEqual(configured, actual)
                    self.assertEqual(configured[:-1], actual[:-1])
                else:
                    self.assertEqual(configured, actual)
                candidate = deepcopy(after)
                replace_descriptor(named(candidate, TRACE_PATH), b"active\n" if case == CASES[1] else b"")
                self.rejected(value, before, candidate, case)
                candidate = deepcopy(after)
                wrong = deepcopy(config)
                wrong["android"]["uploadCertificateSha256"] = actual if case == CASES[1] else (
                    actual[:-1] + ("1" if actual[-1] == "0" else "0"))
                body = (json.dumps(wrong, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode()
                replace_descriptor(named(candidate, CONFIG_PATH), body)
                self.rejected(value, before, candidate, case)

    def test_private_input_shape_is_checked_before_hash_only_export(self):
        self.assertEqual(L._shell_android_saved_inputs(INPUTS), hashlib.sha256(INPUTS["sources/certificate.der"]).hexdigest())
        for change in ("empty-key", "large-key", "bad-der-prefix", "same-passwords", "foreign-alias", "unknown-field", "wrong-firebase"):
            with self.subTest(change=change):
                inputs = deepcopy(INPUTS)
                if change == "empty-key": inputs["sources/input.jks"] = b""
                elif change == "large-key": inputs["sources/input.jks"] = b"x" * 65537
                elif change == "bad-der-prefix": inputs["sources/certificate.der"] = b"not DER"
                elif change == "wrong-firebase": inputs["sources/firebase.json"] = b"{}\n"
                else:
                    fields = json.loads(inputs["sources/signing-fields.json"])
                    if change == "same-passwords": fields["keyPassword"] = fields["storePassword"]
                    elif change == "foreign-alias": fields["keyAlias"] = "unrelated"
                    else: fields["unknown"] = "not an approved signing field"
                    inputs["sources/signing-fields.json"] = L.canonical(fields)
                with self.assertRaises(L.Refused):
                    L._shell_android_saved_inputs(inputs)



class AndroidSavedSigningLifecycleBoundaryReview(unittest.TestCase):
    """Review regressions for Ubuntu DATA routing/import/finality boundaries.

    The namespace test supplies only nonroot-portable input-origin DATA: it does
    not claim that a temporary directory is an admitted privileged namespace.
    The real selected-name enumeration, named-path observations and xattr checks
    still run. The import test reads the five actual composed source files.
    The after-gate test never reads an invented private path.
    """

    def test_saved_namespace_route_enumerates_exact_three_names_not_the_legacy_roster(self):
        from tempfile import TemporaryDirectory

        value = selected()
        # Privileged ancestry admission is covered by the existing inventory
        # DATA tests. Here adapt only that input origin, not the roster result.
        ancestry = {"control": {"inputOrigin": "temporary-test-data"}, "ancestors": []}
        with TemporaryDirectory(prefix="mrk-saved3-roster-") as temporary:
            root = Path(temporary)
            for case in CASES:
                (root / case).mkdir(mode=0o700)

            def binding():
                return L.canonical({"root": str(root), "identity": list(L.identity(root.lstat())),
                                    "children": list(sorted(CASES)), **ancestry})

            with patch.object(L, "shell_fixture_root", return_value=root), \
                    patch.object(L, "_shell_namespace_data", side_effect=lambda supplied, data: data), \
                    patch.object(L, "_shell_fixture_ancestry", return_value=ancestry), \
                    patch.object(L, "_shell_namespace_roster", wraps=L._shell_namespace_roster) as roster:
                observed = L._shell_namespace_check(value, binding())
                self.assertEqual(observed["children"], list(sorted(CASES)))
                roster.assert_called_once_with(root, tuple(sorted(CASES)))

                foreign = root / "android-build"
                foreign.mkdir(mode=0o700)
                with self.assertRaises(L.Refused):
                    L._shell_namespace_check(value, binding())
                foreign.rmdir()

                (root / CASES[-1]).rmdir()
                with self.assertRaises(L.Refused):
                    L._shell_namespace_check(value, binding())
                (root / CASES[-1]).mkdir(mode=0o700)

                for case in CASES:
                    (root / case).rmdir()
                for name in L.SHELL_FIXTURE_CHILDREN:
                    (root / name).mkdir(mode=0o700)
                with self.assertRaises(L.Refused):
                    L._shell_namespace_check(value, binding())
        # TemporaryDirectory retires only this invocation's exclusive DATA
        # directory and empty task-owned children; there is no runtime cleanup.

    def test_actual_saved_data_imports_refuse_wrong_pins_origins_and_incomplete_registration(self):
        from types import SimpleNamespace

        # This is the real source checker and ordinary five-module DATA import.
        # Do not replace record/directory/import or invent a successful result.
        original_owner = L._OWNER
        L._saved_data_modules(SOURCE)
        package = L.sys.modules["mobile_release"]
        module = L.sys.modules["mobile_release.config"]
        predicate_name = "mobile_release._desktop_android_saved_signing_data"
        originals = {name: L.sys.modules[name] for name in (
            "mobile_release", "mobile_release.errors", "mobile_release.config",
            "mobile_release._desktop_android_build_protocol", predicate_name)}

        size, _ = L.ANDROID_SAVED_DATA_PINS["config.py"]
        with patch.dict(L.ANDROID_SAVED_DATA_PINS, {"config.py": (size, "0" * 64)}):
            with self.assertRaises(L.Refused):
                L._saved_data_modules(SOURCE)
        with patch.object(module, "__file__", str(SOURCE / "not-the-admitted-config.py")):
            with self.assertRaises(L.Refused):
                L._saved_data_modules(SOURCE)
        with patch.object(module, "__spec__", SimpleNamespace(origin="/inert/foreign-config.py")):
            with self.assertRaises(L.Refused):
                L._saved_data_modules(SOURCE)
        with patch.object(package, "__path__", [str(SOURCE / "src/mobile_release"), "/inert/foreign-package"]):
            with self.assertRaises(L.Refused):
                L._saved_data_modules(SOURCE)
        # The existing package attribute is not a replacement for registration.
        with patch.dict(L.sys.modules, {predicate_name: None}):
            with self.assertRaises(L.Refused):
                L._saved_data_modules(SOURCE)
        with patch.object(package, "config", object()):
            with self.assertRaises(L.Refused):
                L._saved_data_modules(SOURCE)

        L._saved_data_modules(SOURCE)
        self.assertTrue(all(L.sys.modules[name] is module for name, module in originals.items()))
        self.assertIs(L._OWNER, original_owner)

    def test_after_gate_latches_refusal_before_any_private_read_for_wrong_or_unsettled_originals(self):
        from types import SimpleNamespace

        case = CASES[0]
        changes = ("missing-terminal", "terminal-not-object", "wrong-id", "wrong-generation",
                   "running-terminal", "usable-terminal", "core-not-settled",
                   "query-not-retired", "config-not-final")
        for change in changes:
            with self.subTest(change=change):
                receipt = D.receipt_data(case)[0]
                if change == "missing-terminal":
                    del receipt["terminal"]
                elif change == "terminal-not-object":
                    receipt["terminal"] = []
                elif change == "wrong-id":
                    receipt["terminal"]["operationId"] = (
                        "0" if receipt["original"]["id"][0] != "0" else "1") * 32
                elif change == "wrong-generation":
                    receipt["terminal"]["ownerGeneration"] = (
                        "0" if receipt["original"]["generation"][0] != "0" else "1") * 32
                elif change == "running-terminal":
                    receipt["terminal"]["phase"] = "running"
                elif change == "usable-terminal":
                    receipt["terminal"]["intentUsable"] = True
                elif change == "core-not-settled":
                    receipt["original"]["coreLifetimeSettled"] = False
                elif change == "query-not-retired":
                    receipt["session"]["queriesRetired"] = False
                else:
                    receipt["configSave"]["originalFinal"] = False
                frames, expected, _ = capture_data(case, receipt)
                result = L.subprocess.CompletedProcess(["inert-comparison-only"], 0, b"".join(frames), b"")
                # This dependency-local clock supplies only test input; do not
                # patch the shared time module or change an actual owner's end.
                with patch.object(L, "time", SimpleNamespace(monotonic=lambda: 1.0)), \
                        patch.object(L, "_END", 2.0), patch.object(L, "_FAILED", False), \
                        patch.object(L, "_ROOT", Path("/inert/saved3-no-read")), \
                        patch.object(L, "read", side_effect=AssertionError("private read before finality")) as private_read, \
                        patch.object(L, "_shell_android_saved_inventory",
                                     side_effect=AssertionError("inventory before finality")) as inventory:
                    with self.assertRaises(L.Refused):
                        L._shell_android_saved_after(selected(), b"inert-unobserved-binding", case, result, expected)
                    self.assertIs(L._FAILED, True)
                    private_read.assert_not_called()
                    inventory.assert_not_called()
