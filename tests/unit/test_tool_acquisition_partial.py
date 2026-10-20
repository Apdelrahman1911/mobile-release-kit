"""Selected-piece wire/service DATA with tiny owned archives and fake HTTP.

No native picker, SourceSlots, executable, vendor TLS, install or qualification.
The genuine fixed extractor/cache implementation is exercised on inert files.
"""
import base64
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from mobile_release import _desktop_tool_acquisition_protocol as wire
from mobile_release._tool_acquisition_spec import COMPONENTS, Component, canonical
from mobile_release.tool_acquisition import ToolAcquisition
from test_desktop_tool_acquisition_protocol import request, parse
from test_tool_acquisition import FixtureOwner, fake_transfer, fixtures


def subset_request(missing):
    value = request(True)
    cache = value["native"]["cache"]
    cache["missing"] = list(missing)
    cache["compatible"] = [part.value for part in COMPONENTS if part.value not in missing]
    bind_intent(value)
    return value


def bind_intent(value):
    cache = value["native"]["cache"]
    cache["intentBase64"] = base64.b64encode(canonical({"schemaVersion": 1,
        "operationId": value["operationId"], "contextSha256": cache["contextSha256"],
        "profile": value["native"]["profile"], "referenceSha256": cache["referenceSha256"],
        "projectionSha256": cache["projectionSha256"], "cacheGeneration": cache["generation"],
        "components": cache["missing"]})).decode("ascii")


def staged(parsed):
    missing = parsed.native["cache"]["missing"]
    groups = []
    for group in ("jdk", "sdk", "gradle"):
        parts = [p.value for p in COMPONENTS if p.group == group and p.value in missing]
        if parts:
            complete = len(parts) == sum(p.group == group for p in COMPONENTS)
            groups.append({"group": group, "components": parts, "allRequiredComponentsStaged": complete,
                "next": "choose-native-source" if complete else "complete-sdk-manually"})
    return {"schemaVersion": 1, "kind": "staged-tool-sources", "operationId": parsed.operation_id,
        **{key: parsed.native["cache"][key] for key in ("contextSha256", "referenceSha256", "projectionSha256")},
        "cacheJob": "tool-" + parsed.operation_id, "lookupScope": "registered-selected-known",
        "reusedArchives": [], "downloadedArchives": missing, "groups": groups,
        "assurance": {"nativeFinality": False, "registered": False, "readyToBuild": False}}


class PartialToolAcquisition(unittest.TestCase):
    def test_all_nonempty_canonical_native_partitions_bind_the_exact_pending_intent(self):
        for mask in range(1, 16):
            missing = [part.value for index, part in enumerate(COMPONENTS) if mask & (1 << index)]
            value = subset_request(missing)
            parsed = parse(value)
            selected, kept = wire.component_partition(parsed.native["cache"]["missing"], parsed.native["cache"]["compatible"])
            self.assertEqual([part.value for part in selected], missing)
            self.assertEqual(set(selected) | set(kept), set(COMPONENTS))
            wire.staged(staged(parsed), parsed)
            changed = copy.deepcopy(value)
            changed["native"]["cache"]["intentBase64"] = request(True)["native"]["cache"]["intentBase64"]
            if mask != 15:
                with self.assertRaises(wire.ProtocolError):
                    parse(changed)

    def test_failed_uncertain_duplicate_and_noncanonical_partitions_cannot_request_downloads(self):
        for missing, compatible in [([], [part.value for part in COMPONENTS]),
            (["gradle"], ["jdk", "sdk-platform", "unknown"]),
            (["sdk-build-tools", "sdk-platform"], ["jdk", "gradle"]),
            (["gradle"], ["jdk", "sdk-platform", "gradle"]),
            (["gradle", "gradle"], ["jdk", "sdk-platform"]),
            (["gradle"], ["jdk", "sdk-platform", None])]:
            value = subset_request(missing)
            value["native"]["cache"]["compatible"] = compatible
            with self.subTest(missing=missing, compatible=compatible), self.assertRaises(wire.ProtocolError):
                parse(value)

    def test_staged_result_may_not_add_kept_components_omit_missing_or_claim_partial_sdk_complete(self):
        parsed = parse(subset_request(["sdk-build-tools", "gradle"]))
        good = staged(parsed)
        wire.staged(good, parsed)
        for edit in (lambda v: v["downloadedArchives"].insert(0, "jdk"),
                     lambda v: v["downloadedArchives"].pop(),
                     lambda v: v["groups"][0].update(allRequiredComponentsStaged=True, next="choose-native-source"),
                     lambda v: v["reusedArchives"].append("sdk-build-tools")):
            value = copy.deepcopy(good); edit(value)
            with self.assertRaises(wire.ProtocolError):
                wire.staged(value, parsed)

    def test_same_engine_downloads_only_missing_two_then_reuses_only_their_checked_cache(self):
        manifest, payloads = fixtures()
        selected, kept = wire.component_partition(["sdk-build-tools", "gradle"], ["jdk", "sdk-platform"])
        self.assertEqual(kept, (Component.JDK, Component.SDK_PLATFORM))
        calls = []
        with tempfile.TemporaryDirectory(prefix="mrk-partial-tools-") as temp:
            root = Path(temp) / "cache"; root.mkdir(mode=0o700)
            # Existing user content is not an extraction destination or a lease.
            existing = Path(temp) / "existing-sdk"; existing.mkdir()
            preserved = existing / "keep-unrelated.txt"; preserved.write_bytes(b"inert unrelated package")
            before = preserved.stat()
            owner = FixtureOwner(root, manifest, missing=selected)
            with patch("mobile_release.tool_acquisition.PublicVendorTransfer", fake_transfer(payloads, calls)):
                service = ToolAcquisition(owner); result = service.run()
            self.assertEqual(calls, list(selected))
            self.assertEqual(owner.ca_calls, 1)
            data = result.to_data()
            self.assertEqual(data["downloadedArchives"], ["sdk-build-tools", "gradle"])
            self.assertEqual(data["groups"][0]["next"], "complete-sdk-manually")
            self.assertFalse(data["groups"][0]["allRequiredComponentsStaged"])
            self.assertEqual((preserved.stat().st_ino, preserved.read_bytes()), (before.st_ino, b"inert unrelated package"))
            owner.settle_for_test(service)  # Explicit FAKE native book finality, not a production receipt.
            second = FixtureOwner(root, manifest, name="operation2", missing=selected, book=owner.book)
            with patch("mobile_release.tool_acquisition.PublicVendorTransfer", side_effect=AssertionError("cache hit must not open transport")):
                reused = ToolAcquisition(second).run().to_data()
            self.assertEqual(second.ca_calls, 0)
            self.assertEqual(reused["reusedArchives"], ["sdk-build-tools", "gradle"])
            self.assertEqual(reused["downloadedArchives"], [])


if __name__ == "__main__":
    unittest.main()
