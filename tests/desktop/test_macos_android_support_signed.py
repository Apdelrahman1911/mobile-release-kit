"""Pure nomination/capsule correspondence, not genuine signed-supplier evidence.

Original SOURCE manifest is genuine; all nominated producer IDs, derived bytes,
receipts and signatures below are intentionally synthetic. No shipping entry,
network, native tool, signing identity or actual producer is exercised here.
"""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
NAME = "mrk_signed_android_support_data_tests"
if NAME in sys.modules:
    raise RuntimeError("signed-support test module collision")
_SPEC = importlib.util.spec_from_file_location(NAME, ROOT / "desktop/tools/macos_android_support_signed.py")
M = importlib.util.module_from_spec(_SPEC)
sys.modules[NAME] = M
try:
    _SPEC.loader.exec_module(M)
finally:
    if sys.modules.get(NAME) is M:
        del sys.modules[NAME]


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def pin(body):
    return {"size": len(body), "sha256": hashlib.sha256(body).hexdigest()}


def profiles():
    return {"producer_profile_raw": (ROOT / "desktop/packaging/macos-install-producer-signing.profile").read_bytes(),
            "service_profile_raw": (ROOT / "desktop/packaging/macos-android-service-signing.profile").read_bytes()}


def admit(relation, receipt, bodies):
    return M.admit_capsule(relation, receipt, bodies, **profiles())


def receipt_fixture(value):
    """Synthetic DATA with the genuine frozen producer schema, not signed bytes."""
    producer = value["producer"]
    archive_rows = [{"name": row["fileName"], "upstreamUrl": row["upstream"]["url"],
                     "originalBytes": row["upstream"]["size"], "originalSha256": row["upstream"]["sha256"],
                     "originalInventorySha256": "e" * 64, "derivedBytes": row["derived"]["size"],
                     "derivedSha256": row["derived"]["sha256"], "derivedInventorySha256": row["inventorySha256"],
                     "nonNativeUnchanged": True} for row in value["archives"]]
    native_rows = []
    for row in value["members"]:
        runtime = row["role"] != "bundletool-jna"
        native_rows.append({"role": row["role"], "member": row["path"],
                            "originalBytes": row["upstream"]["size"], "originalSha256": row["upstream"]["sha256"],
                            "signedBytes": row["derived"]["size"], "signedSha256": row["derived"]["sha256"],
                            "slices": [dict(item, size=1, sha256="e" * 64,
                                            codeDirectoryFlags=[0x10000 if runtime else 0], cmsPresent=True) for item in row["slices"]],
                            "identifier": "dev.mobile-release-kit.desktop.android-support." + row["role"],
                            "runtimeRequired": runtime, "timestampRequested": True})
    roles = [row["role"] + suffix for row in value["members"] for suffix in ("-sign", "-verify")]
    roles += [row["role"] + "-final-verify" for row in value["members"]]
    return {"schemaVersion": 1, "kind": "macos-android-support-signed-v1", "source": producer["sourceCommit"],
            "sourceTree": producer["sourceTree"], "runId": producer["runId"], "runAttempt": producer["runAttempt"],
            "workflow": M.REPOSITORY + "/" + M.WORKFLOW + "@refs/heads/verify/desktop-macos-android-support-signing",
            "sourceNominationSha256": M.UPSTREAM_SHA256,
            "signer": {"teamIdentifier": "7CGZ2343AA", "certificateSha1": "5effa7d19bbe005b19c1617833cbe22186c2af96",
                       "producerProfileSha256": pin(profiles()["producer_profile_raw"])["sha256"],
                       "serviceProfileSha256": pin(profiles()["service_profile_raw"])["sha256"]},
            "archives": archive_rows, "nativeMembers": native_rows,
            "notarizationQualified": False, "productReady": False, "outerExitRequired": True,
            "sourcePost": True, "inputPost": True, "nonDeliveryScratchRetired": True, "originalsClosed": True,
            "nativeOriginals": [{"role": role, "entered": True, "returned": True, "capturesSettled": True,
                                 "returncode": 0, "stdoutSha256": "e" * 64, "stderrSha256": "f" * 64} for role in roles],
            "credentialOriginalsSha256": "d" * 64, "credentialOriginalCount": 57,
            "credentialContexts": [{"purpose": row["role"], "searchRestored": True, "defaultUnchanged": True,
                                    "retired": True, "closed": True} for row in value["members"]]}


def fixture():
    upstream = (ROOT / "desktop/macos-installed-inputs/android-support.json").read_bytes()
    original = json.loads(upstream)
    receipt = b'{"synthetic":true,"notASigningReceipt":true}\n'
    bodies = {name: ("synthetic-derived-archive:" + name).encode() for _, name in M._LAYOUT}
    archives = []
    for row in original["archives"]:
        archives.append({"id": row["id"], "fileName": row["fileName"], "resourcePath": row["resourcePath"],
                         "upstream": {k: row[k] for k in ("url", "size", "sha256")},
                         "derived": pin(bodies[row["fileName"]]), "inventorySha256": "c" * 64})
    members = []
    for role, archive, path, size, digest, slices in M._MEMBERS:
        members.append({"role": role, "archiveId": archive, "path": path,
                        "upstream": {"size": size, "sha256": digest}, "derived": pin(("synthetic-native:" + role).encode()),
                        "slices": [{"cpuType": cpu, "cpuSubtype": subtype} for cpu, subtype in slices]})
    value = {"schemaVersion": 1, "kind": M.KIND, "upstreamManifestSha256": M.UPSTREAM_SHA256,
             "producer": {"repository": M.REPOSITORY, "workflow": M.WORKFLOW, "sourceCommit": "a" * 40,
                          "sourceTree": "b" * 40, "runId": "123", "runAttempt": "1", "artifactId": "456",
                          "artifactName": M.ARTIFACT_NAME, "artifactSha256": "d" * 64},
             "receipt": dict(pin(receipt), fileName=M.RECEIPT_NAME), "archives": archives, "members": members}
    receipt = encoded(receipt_fixture(value))
    value["receipt"] = dict(pin(receipt), fileName=M.RECEIPT_NAME)
    return value, upstream, receipt, bodies


class SignedSupportDataTests(unittest.TestCase):
    def test_fixed_nomination_and_capsule_hashes_are_not_signing_authority(self):
        value, upstream, receipt, bodies = fixture()
        raw = encoded(value)
        relation = M.nomination(raw, upstream)
        actual = admit(relation, receipt, bodies)
        self.assertEqual(actual["nominationSha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(actual["receiptSha256"], pin(receipt)["sha256"])
        self.assertEqual(actual["archives"], [dict(pin(bodies[n]), fileName=n) for _, n in M._LAYOUT])
        self.assertIs(actual["dataOnly"], True)
        self.assertIs(actual["receiptEnvelopeValidated"], True)
        for field in ("originalProducerValidated", "signedNativeQualified", "shippingEnrollment"):
            self.assertIs(actual[field], False)
        # Parser outputs retain no mutable input lists/dicts; JNA's actual
        # fixed roster remains i386+x64, not an ARM capability assertion.
        value["members"][1]["slices"][0]["cpuType"] = 16777228
        self.assertEqual(relation.members[1].slices, ((7, 3), (16777223, 3)))
        with self.assertRaises(FrozenInstanceError):
            relation.archives[0].derived.size = 1
        self.assertEqual(admit(relation, receipt, bodies), actual)

    def test_fixed_upstream_cannot_be_replaced_with_a_jointly_renominated_recipe(self):
        value, upstream, _, _ = fixture()
        changed = json.loads(upstream)
        changed["archives"][0]["sha256"] = "f" * 64
        forged = encoded(changed)
        value["upstreamManifestSha256"] = hashlib.sha256(forged).hexdigest()
        value["archives"][0]["upstream"]["sha256"] = "f" * 64
        for original in (forged, upstream + b"\n", bytearray(upstream)):
            with self.subTest(kind=type(original).__name__, length=len(original)):
                with self.assertRaisesRegex(M.Refused, "^fixed-upstream-original$"):
                    M.nomination(encoded(value), original)
        value, upstream, _, _ = fixture()
        mutations = [
            ("URL", lambda v: v["archives"][0]["upstream"].update(url="https://example.invalid/not-a-supplier")),
            ("original digest", lambda v: v["archives"][0]["upstream"].update(sha256="f" * 64)),
            ("original size", lambda v: v["archives"][0]["upstream"].update(size=1)),
            ("unchanged JAR", lambda v: v["archives"][0].update(derived={k: v["archives"][0]["upstream"][k] for k in ("size", "sha256")})),
            ("original member", lambda v: v["members"][0]["upstream"].update(sha256="f" * 64)),
            ("unchanged native", lambda v: v["members"][0].update(derived=dict(v["members"][0]["upstream"]))),
            ("changed role", lambda v: v["members"][0].update(role="other")),
            ("cross archive", lambda v: v["members"][0].update(archiveId="aapt2")),
            ("path", lambda v: v["members"][0].update(path="../aapt2")),
            ("missing member", lambda v: v["members"].pop()),
            ("swapped archives", lambda v: v["archives"].reverse()),
            ("invented ARM JNA", lambda v: v["members"][1]["slices"][0].update(cpuType=16777228)),
            ("thinned slice", lambda v: v["members"][1]["slices"].pop()),
            ("CPU bool", lambda v: v["members"][1]["slices"][0].update(cpuType=True)),
        ]
        for label, mutate in mutations:
            with self.subTest(label=label):
                candidate = copy.deepcopy(value)
                mutate(candidate)
                with self.assertRaises(M.Refused):
                    M.nomination(encoded(candidate), upstream)

    def test_closed_json_producer_identity_and_resource_limits(self):
        value, upstream, _, _ = fixture()
        raw = encoded(value)
        invalid = (b"\xef\xbb\xbf" + raw, b"\xff", b'{"a":1,"a":2}', raw + b"x",
                   raw.replace(b'"schemaVersion":1', b'"schemaVersion":1.0'),
                   raw.replace(b'"schemaVersion":1', b'"schemaVersion":NaN'),
                   b"[" * 20 + b"0" + b"]" * 20,
                   encoded([0] * 1100), encoded({"x": "x" * 2049}), b" " * (M.DOCUMENT_LIMIT + 1))
        for candidate in invalid:
            with self.subTest(length=len(candidate)):
                with self.assertRaises(M.Refused):
                    M.nomination(candidate, upstream)
        mutations = [
            ("unknown", lambda v: v.update(extra=True)),
            ("bool version", lambda v: v.update(schemaVersion=True)),
            ("wrong repository", lambda v: v["producer"].update(repository="someone/else")),
            ("wrong workflow", lambda v: v["producer"].update(workflow=".github/workflows/release.yml")),
            ("wrong artifact", lambda v: v["producer"].update(artifactName="latest")),
            ("uppercase hash", lambda v: v["producer"].update(sourceCommit="A" * 40)),
            ("short hash", lambda v: v["producer"].update(artifactSha256="a")),
            ("bool ID", lambda v: v["producer"].update(runId=True)),
            ("numeric ID", lambda v: v["producer"].update(runId=123)),
            ("ID leading zero", lambda v: v["producer"].update(runAttempt="01")),
            ("ID length", lambda v: v["producer"].update(artifactId="1" * 21)),
            ("receipt name", lambda v: v["receipt"].update(fileName="other.json")),
            ("receipt size", lambda v: v["receipt"].update(size=M.DOCUMENT_LIMIT + 1)),
            ("bool size", lambda v: v["archives"][0]["derived"].update(size=True)),
            ("member size", lambda v: v["members"][0]["derived"].update(size=M.MEMBER_LIMIT + 1)),
            ("total size", lambda v: [a["derived"].update(size=M.ARCHIVES_LIMIT) for a in v["archives"]]),
        ]
        for label, mutate in mutations:
            with self.subTest(label=label):
                candidate = copy.deepcopy(value)
                mutate(candidate)
                with self.assertRaises(M.Refused):
                    M.nomination(encoded(candidate), upstream)

    def test_capsule_original_bytes_roster_and_receipt_must_match(self):
        value, upstream, receipt, bodies = fixture()
        relation = M.nomination(encoded(value), upstream)
        for changed in (receipt + b"\n", receipt[:-1], bytearray(receipt), b"x" * (M.DOCUMENT_LIMIT + 1)):
            with self.subTest(receiptType=type(changed).__name__, length=len(changed)):
                with self.assertRaisesRegex(M.Refused, "^receipt-original$"):
                    admit(relation, changed, bodies)
        name = M._LAYOUT[0][1]
        mutations = [dict(bodies, other=b"x"), {name: bodies[name]}, dict(bodies, **{name: bodies[name] + b"x"}),
                     dict(bodies, **{name: b"x" * len(bodies[name])}), dict(bodies, **{name: bytearray(bodies[name])})]
        for changed in mutations:
            with self.subTest(names=sorted(changed)):
                with self.assertRaises(M.Refused):
                    admit(relation, receipt, changed)
        with self.assertRaisesRegex(M.Refused, "^nomination-type$"):
            admit(value, receipt, bodies)
        # Re-nominate each altered receipt hash: these must fail the genuine
        # typed envelope, not merely the earlier original-byte comparison.
        envelope = json.loads(receipt)
        mutations = [
            ("source", lambda r: r.update(source="c" * 40)),
            ("tree", lambda r: r.update(sourceTree="c" * 40)),
            ("run", lambda r: r.update(runId="124")),
            ("attempt", lambda r: r.update(runAttempt="2")),
            ("workflow", lambda r: r.update(workflow=r["workflow"].replace("verify/", "other/"))),
            ("original manifest", lambda r: r.update(sourceNominationSha256="f" * 64)),
            ("wrong schema", lambda r: r.update(schemaVersion=True)),
            ("old certificate", lambda r: r["signer"].update(certificateSha1="a" * 40)),
            ("different team", lambda r: r["signer"].update(teamIdentifier="OTHERTEAM1")),
            ("profile", lambda r: r["signer"].update(producerProfileSha256="a" * 64)),
            ("archive reorder", lambda r: r["archives"].reverse()),
            ("archive missing", lambda r: r["archives"].pop()),
            ("original URL", lambda r: r["archives"][0].update(upstreamUrl="https://example.invalid")),
            ("original size", lambda r: r["archives"][0].update(originalBytes=True)),
            ("original hash", lambda r: r["archives"][0].update(originalSha256="a" * 64)),
            ("derived hash", lambda r: r["archives"][0].update(derivedSha256="a" * 64)),
            ("derived inventory", lambda r: r["archives"][0].update(derivedInventorySha256="a" * 64)),
            ("original inventory", lambda r: r["archives"][0].update(originalInventorySha256="unparsed")),
            ("non-native mutation", lambda r: r["archives"][0].update(nonNativeUnchanged=False)),
            ("member reorder", lambda r: r["nativeMembers"].reverse()),
            ("original member", lambda r: r["nativeMembers"][0].update(originalSha256="a" * 64)),
            ("derived member", lambda r: r["nativeMembers"][0].update(signedSha256="a" * 64)),
            ("identifier", lambda r: r["nativeMembers"][0].update(identifier="other")),
            ("runtime purpose", lambda r: r["nativeMembers"][1].update(runtimeRequired=True)),
            ("timestamp", lambda r: r["nativeMembers"][0].update(timestampRequested=False)),
            ("slice count", lambda r: r["nativeMembers"][0]["slices"].pop()),
            ("invented ARM JNA", lambda r: r["nativeMembers"][1]["slices"][0].update(cpuType=16777228)),
            ("bool subtype", lambda r: r["nativeMembers"][0]["slices"][1].update(cpuSubtype=False)),
            ("slice aggregate", lambda r: [s.update(size=r["nativeMembers"][0]["signedBytes"]) for s in r["nativeMembers"][0]["slices"]]),
            ("cms missing", lambda r: r["nativeMembers"][0]["slices"][0].update(cmsPresent=False)),
            ("runtime flag absent", lambda r: r["nativeMembers"][0]["slices"][0].update(codeDirectoryFlags=[0])),
            ("ad-hoc", lambda r: r["nativeMembers"][0]["slices"][0].update(codeDirectoryFlags=[0x10002])),
            ("bool flags", lambda r: r["nativeMembers"][1]["slices"][0].update(codeDirectoryFlags=[False])),
            ("alternate disagreement", lambda r: r["nativeMembers"][0]["slices"][0].update(codeDirectoryFlags=[0x10000, 0x10001])),
            ("flag overflow", lambda r: r["nativeMembers"][0]["slices"][0].update(codeDirectoryFlags=[0x100010000])),
            ("native order", lambda r: r["nativeOriginals"].reverse()),
            ("native missing", lambda r: r["nativeOriginals"].pop()),
            ("native failure", lambda r: r["nativeOriginals"][0].update(returncode=1)),
            ("native bool status", lambda r: r["nativeOriginals"][0].update(returncode=False)),
            ("capture unsettled", lambda r: r["nativeOriginals"][0].update(capturesSettled=False)),
            ("capture hash", lambda r: r["nativeOriginals"][0].update(stdoutSha256="unrecorded")),
            ("credential count", lambda r: r.update(credentialOriginalCount=56)),
            ("credential hash", lambda r: r.update(credentialOriginalsSha256="unrecorded")),
            ("credential order", lambda r: r["credentialContexts"].reverse()),
            ("credential context missing", lambda r: r["credentialContexts"].pop()),
            ("search list changed", lambda r: r["credentialContexts"][0].update(searchRestored=False)),
            ("default changed", lambda r: r["credentialContexts"][0].update(defaultUnchanged=False)),
            ("credential unretired", lambda r: r["credentialContexts"][0].update(retired=False)),
            ("credential unclosed", lambda r: r["credentialContexts"][0].update(closed=False)),
            ("unknown", lambda r: r.update(accepted=True)),
            ("missing", lambda r: r.pop("sourcePost")),
        ]
        mutations += [("finality " + key, lambda r, key=key: r.update({key: False}))
                      for key in ("outerExitRequired", "sourcePost", "inputPost", "originalsClosed", "nonDeliveryScratchRetired")]
        mutations += [("overclaim " + key, lambda r, key=key: r.update({key: True}))
                      for key in ("notarizationQualified", "productReady")]
        for label, mutate in mutations:
            with self.subTest(envelope=label):
                candidate = copy.deepcopy(envelope)
                mutate(candidate)
                changed = encoded(candidate)
                nominated = copy.deepcopy(value)
                nominated["receipt"] = dict(pin(changed), fileName=M.RECEIPT_NAME)
                with self.assertRaises(M.Refused):
                    admit(M.nomination(encoded(nominated), upstream), changed, bodies)
        for raw in (receipt[:-1] + b',"schemaVersion":1}', receipt.replace(b'"schemaVersion":1', b'"schemaVersion":1.0')):
            nominated = copy.deepcopy(value)
            nominated["receipt"] = dict(pin(raw), fileName=M.RECEIPT_NAME)
            with self.assertRaises(M.Refused):
                admit(M.nomination(encoded(nominated), upstream), raw, bodies)
        # Jointly replacing the public profile and its rehashed receipt does
        # not create a new authorized signer recipe.
        for key, field in (("producer_profile_raw", "producerProfileSha256"), ("service_profile_raw", "serviceProfileSha256")):
            candidate_profiles = profiles()
            candidate_profiles[key] = candidate_profiles[key].replace(b"7CGZ2343AA", b"OTHERTEAM1")
            candidate = copy.deepcopy(envelope)
            candidate["signer"][field] = pin(candidate_profiles[key])["sha256"]
            changed = encoded(candidate)
            nominated = copy.deepcopy(value)
            nominated["receipt"] = dict(pin(changed), fileName=M.RECEIPT_NAME)
            with self.assertRaisesRegex(M.Refused, "^fixed-signer-profile$"):
                M.admit_capsule(M.nomination(encoded(nominated), upstream), changed, bodies, **candidate_profiles)


if __name__ == "__main__":
    unittest.main()
