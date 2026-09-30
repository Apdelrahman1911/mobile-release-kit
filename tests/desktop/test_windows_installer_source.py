"""In-memory Windows installer-source contracts, not MSI/native qualification.

Fixture rows are supplied DATA assertions, never binary or supplier evidence.
No staged payload, executable, installer, service or filesystem fixture is run.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

SOURCE = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "windows_installer_source_data", SOURCE / "desktop/tools/windows_installer_source.py"
)
assert SPEC is not None and SPEC.loader is not None
renderer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(renderer)
staging = renderer.staging
NS = {"w": renderer.XML_NAMESPACE}
PROFILE_SPEC = importlib.util.spec_from_file_location(
    "windows_installer_profile_data", SOURCE / "desktop/tools/windows_installer_profile.py"
)
assert PROFILE_SPEC is not None and PROFILE_SPEC.loader is not None
profile = importlib.util.module_from_spec(PROFILE_SPEC)
PROFILE_SPEC.loader.exec_module(profile)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return staging.preparation.canonical(value) + b"\n"


class WindowsInstallerSourceTests(unittest.TestCase):
    def setUp(self):
        common = {"sourceCommit": "a" * 40, "target": staging.TARGET,
                  "runtimeManifestSha256": "b" * 64, "protocolSha256": "c" * 64, "coreVersion": "0.3.0"}
        self.admission = {"schemaVersion": 1, "purpose": staging.ADMISSION_PURPOSE, **common}
        for role in staging.OPAQUE_OUTPUTS:
            row = {"size": 128, "sha256": digest(("opaque DATA " + role).encode())}
            if role in staging.ARTIFACT_FEATURES:
                row.update(common, profile="release", features=list(staging.ARTIFACT_FEATURES[role]))
            elif role == "webview2":
                row["kind"] = "evergreen-standalone-offline-x64"
            self.admission[role] = row
        self.prefix = "runtime-input/" + staging.TARGET + "/" + common["runtimeManifestSha256"] + "/"
        runtime = {name: (size, sha) for name, size, sha in staging.payload.MEMBERS}
        runtime = {"python/" + name: values for name, values in runtime.items()}
        runtime["python/" + staging.payload.NOTICE_NAME] = (staging.payload.NOTICE_BYTES, staging.payload.NOTICE_SHA256)
        runtime[staging.preparation.GITHUB_CA_NAME] = (staging.payload.GITHUB_CA_BYTES, staging.payload.GITHUB_CA_SHA256)
        for name in ["core.zip", *staging.preparation.BOOTSTRAPS]:
            runtime[name] = (64, digest(("asserted DATA " + name).encode()))
        runtime["manifest.json"] = (128, common["runtimeManifestSha256"])
        rows = [{"path": self.prefix + name, "role": "runtimeInput", "size": size, "sha256": sha}
                for name, (size, sha) in runtime.items()]
        rows.extend({"path": path, "role": role, **{key: self.admission[role][key] for key in ("size", "sha256")}}
                    for role, (path, unused_limit) in staging.OPAQUE_OUTPUTS.items())
        self.inventory = {
            "schemaVersion": 1, "purpose": staging.INVENTORY_PURPOSE, **common,
            "inputAssertions": "supplied-not-observed", "admissionSha256": "d" * 64,
            "runtimeFileCount": 47, "payloadFileCount": 52, "payloadInventorySha256": "e" * 64,
            "files": sorted(rows, key=lambda row: row["path"]), "qualification": dict(staging.QUALIFICATION),
        }

    def arguments(self, inventory=None, admission=None):
        data = copy.deepcopy(self.inventory if inventory is None else inventory)
        assertions = copy.deepcopy(self.admission if admission is None else admission)
        raw_admission = encoded(assertions)
        data["admissionSha256"] = digest(raw_admission)
        data["payloadInventorySha256"] = digest(staging.preparation.canonical(data["files"]))
        raw_inventory = encoded(data)
        return {"inventory": raw_inventory, "admission": raw_admission,
                "expected_inventory": digest(raw_inventory), "expected_admission": digest(raw_admission)}

    def render(self, inventory=None, admission=None):
        return renderer.render_sources(**self.arguments(inventory, admission))

    def documents(self):
        result = self.render()
        return result, *(ET.fromstring(result[name]) for name in renderer.OUTPUT_NAMES[:2])

    def test_complete_deterministic_mapping_is_data_only_with_explicit_unassembled_prerequisite(self):
        before = copy.deepcopy((self.inventory, self.admission))
        with patch.object(staging, "stage", side_effect=AssertionError("Do not stage or execute")), \
                patch.object(staging.preparation, "read_checked", side_effect=AssertionError("No payload IO")):
            first = self.render()
            self.assertEqual(first, self.render())
        self.assertEqual((self.inventory, self.admission), before)
        self.assertEqual(tuple(first), renderer.OUTPUT_NAMES)
        retained, activation = (ET.fromstring(first[name]) for name in renderer.OUTPUT_NAMES[:2])
        retained_files = retained.findall(".//w:File", NS)
        active_files = activation.findall(".//w:File", NS)
        self.assertEqual((len(retained_files), len(active_files)), (50, 2))
        paths = {node.attrib["Source"] for node in retained_files + active_files}
        self.assertEqual(len(paths), 51)
        prerequisite = "stage\\" + staging.OPAQUE_OUTPUTS["webview2"][0].replace("/", "\\")
        self.assertNotIn(prerequisite, paths)
        self.assertEqual(paths | {prerequisite}, {"stage\\" + row["path"].replace("/", "\\") for row in self.inventory["files"]})
        binding = json.loads(first[renderer.OUTPUT_NAMES[2]])
        self.assertEqual(binding["msiPayloadFiles"], 51)
        self.assertEqual(binding["deferredOfflinePrerequisite"], self.admission["webview2"])
        self.assertEqual(binding["inputAssertions"], "supplied-not-observed")
        self.assertTrue(all(value is False for value in binding["qualification"].values()))
        self.assertIs(binding["compiledTablesInspected"], False)
        self.assertIs(binding["stockAbsenceAndAncestorSafetyVerified"], False)
        self.assertIs(binding["bundleAssembled"], False)
        for row in binding["outputs"]:
            self.assertEqual(row, {"path": row["path"], "size": len(first[row["path"]]), "sha256": digest(first[row["path"]])})

    def test_shared_immutable_publisher_and_release_specific_identities_bind_both_packages(self):
        unused_result, retained, activation = self.documents()
        components = [root.find(".//w:Component[@Id='mrkPublisherComponent']", NS) for root in (retained, activation)]
        self.assertEqual(components[0].attrib, components[1].attrib)
        self.assertEqual(components[0].find("w:File", NS).attrib, components[1].find("w:File", NS).attrib)
        self.assertEqual({key: components[0].attrib[key] for key in ("Permanent", "NeverOverwrite", "Bitness")},
                         {"Permanent": "yes", "NeverOverwrite": "yes", "Bitness": "always64"})
        self.assertEqual(components[0].find("w:File", NS).attrib["Id"], "mrkRetainedPublisher")
        for root in (retained, activation):
            self.assertEqual(root.find(".//w:Directory[@Id='mrkHelperImageDigest']", NS).attrib["Name"],
                             self.admission["publisher"]["sha256"])
        codes = [root.find("w:Package", NS).attrib for root in (retained, activation)]
        self.assertNotEqual(codes[0]["ProductCode"], codes[1]["ProductCode"])
        self.assertNotEqual(codes[0]["UpgradeCode"], codes[1]["UpgradeCode"])
        self.assertTrue(all("PackageCode" not in row for row in codes))
        changed_inventory, changed_admission = copy.deepcopy((self.inventory, self.admission))
        for value in (changed_inventory, changed_admission, changed_admission["shell"], changed_admission["publisher"]):
            value["sourceCommit"] = "f" * 40
        changed = self.render(changed_inventory, changed_admission)
        self.assertNotEqual(codes[0]["ProductCode"], ET.fromstring(changed[renderer.OUTPUT_NAMES[0]]).find("w:Package", NS).attrib["ProductCode"])
        with patch.object(renderer, "_guid", return_value="{00000000-0000-5000-8000-000000000001}"):
            with self.assertRaises(renderer.SourceError):
                self.render()
        with patch.object(renderer, "_id", return_value="mrkCollision"):
            with self.assertRaises(renderer.SourceError):
                self.render()

    def test_publisher_gate_is_unconditional_original_file_action_before_active_mutations(self):
        unused_result, retained, activation = self.documents()
        self.assertIsNone(retained.find(".//w:CustomAction[@Id='mrkPublishFixed']", NS))
        action = activation.find(".//w:CustomAction[@Id='mrkPublishFixed']", NS)
        self.assertEqual(action.attrib, {"Id": "mrkPublishFixed", "FileRef": "mrkRetainedPublisher",
                                        "ExeCommand": "", "Execute": "deferred", "Impersonate": "no", "Return": "check"})
        scheduled = activation.find(".//w:InstallExecuteSequence/w:Custom[@Action='mrkPublishFixed']", NS)
        self.assertEqual(scheduled.attrib, {"Action": "mrkPublishFixed", "After": "InstallInitialize", "Condition": "1"})
        self.assertIsNone(activation.find(".//w:Publish", NS))
        shortcuts = activation.findall(".//w:Shortcut", NS)
        self.assertEqual(len(shortcuts), 1)
        self.assertEqual({key: shortcuts[0].attrib[key] for key in ("Advertise", "Directory", "Target")},
                         {"Advertise": "no", "Directory": "mrkMenuDirectory", "Target": "[#mrkShell]"})
        self.assertEqual(retained.findall(".//w:Shortcut", NS), [])
        shell = activation.find(".//w:Component[@Id='mrkShellComponent']", NS)
        self.assertNotIn("Permanent", shell.attrib)  # Only new activation is transaction-owned.

    def test_execute_only_absence_and_every_maintenance_entry_refuse_without_public_success_flags(self):
        unused_result, retained, activation = self.documents()
        for root, roles in ((retained, ["Runtime", "Helper", "Active", "Menu"]), (activation, ["Active", "Menu"])):
            searches = root.findall(".//w:DirectorySearch", NS)
            self.assertEqual([node.attrib["Id"] for node in searches], ["mrk" + role + "DirectorySignature" for role in roles])
            self.assertTrue(all(node.attrib["Depth"] == "0" and "Parent" not in node.attrib for node in searches))
            self.assertTrue(all(node.attrib["Path"].startswith(("[ProgramFiles64Folder]", "[ProgramMenuFolder]")) for node in searches))
            self.assertTrue(all("*" not in node.attrib["Path"] and ".." not in node.attrib["Path"] for node in searches))
            self.assertEqual(root.find(".//w:InstallUISequence/w:AppSearch", NS).attrib, {"Suppress": "yes"})
            self.assertEqual(root.find(".//w:InstallExecuteSequence/w:AppSearch", NS).attrib, {"Before": "CostInitialize"})
            gate = root.find(".//w:InstallExecuteSequence/w:Custom[@Action='mrkRefuseUnsupportedOrOccupied']", NS)
            self.assertEqual(gate.attrib["After"], "CostFinalize")
            self.assertEqual(gate.attrib["Condition"], " OR ".join([renderer.MAINTENANCE, *("mrk" + role + "Present" for role in roles), renderer.FEATURE_REFUSAL]))
            for sequence in ("AdminExecuteSequence", "AdvtExecuteSequence"):
                actions = root.findall(".//w:" + sequence + "/w:Custom", NS)
                self.assertEqual([node.attrib for node in actions], [{"Action": "mrkRefuseOtherEntry", "Before": "CostInitialize", "Condition": "1"}])
            for role in roles:
                prop = root.find(".//w:Property[@Id='mrk" + role + "Present']", NS)
                self.assertNotIn("Value", prop.attrib)
            self.assertIsNotNone(root.find(".//w:EnsureTable[@Id='Signature']", NS))
        helper_path = retained.find(".//w:DirectorySearch[@Id='mrkHelperDirectorySignature']", NS).attrib["Path"]
        self.assertTrue(helper_path.endswith(self.admission["runtimeManifestSha256"]))  # D, not only H.

    def test_retention_graph_has_no_removal_repair_extensions_running_app_or_finish_launch(self):
        result, retained, activation = self.documents()
        forbidden = {"MajorUpgrade", "RemoveExistingProducts", "RemoveFile", "RemoveFolder", "RemoveFolderEx",
                     "Permission", "PermissionEx", "ServiceInstall", "ServiceControl", "CloseApplication",
                     "Binary", "SetProperty", "ExePackage", "Bundle", "Environment", "RegistryValue"}
        for root in (retained, activation):
            self.assertFalse({node.tag.rsplit("}", 1)[-1] for node in root.iter()} & forbidden)
            package = root.find("w:Package", NS)
            self.assertEqual(package.attrib["Scope"], "perMachine")
            self.assertEqual(package.attrib["Version"], self.admission["coreVersion"])
            self.assertTrue(all(node.attrib["Bitness"] == "always64" and node.attrib["NeverOverwrite"] == "yes"
                                for node in root.findall(".//w:Component", NS)))
            self.assertFalse(any(node.attrib.get("Name") == "versions" for node in root.findall(".//w:Directory", NS)))
            refs = [node.attrib["Id"] for node in root.findall(".//w:ComponentRef", NS)]
            self.assertEqual(sorted(refs), sorted(node.attrib["Id"] for node in root.findall(".//w:Component", NS)))
        self.assertTrue(all(node.attrib["Permanent"] == "yes" for node in retained.findall(".//w:Component", NS)))
        self.assertIn(b"&amp;mrkAllRequired &lt;&gt; 3", result[renderer.OUTPUT_NAMES[0]])
        self.assertNotIn(b"<!DOCTYPE", b"".join(result.values()))

    def test_duplicate_traversal_case_separator_and_xml_injection_paths_are_refused_after_rebinding(self):
        original = self.inventory["files"][0]["path"]
        bad_paths = ["../" + original, original.upper(), original.replace("/", "\\"),
                     original + ":stream", "stage/" + original, original + "\"><CustomAction Id='extra'/>"]
        bad_paths.append(self.inventory["files"][1]["path"])
        for value in bad_paths:
            with self.subTest(path=value):
                data = copy.deepcopy(self.inventory)
                data["files"][0]["path"] = value
                with self.assertRaises(renderer.SourceError):
                    self.render(data)

    def test_closed_schema_counts_flags_and_action_overrides_cannot_extend_the_renderer(self):
        for field, value in [("schemaVersion", True), ("runtimeFileCount", 48), ("payloadFileCount", 51),
                             ("inputAssertions", "observed"), ("target", "aarch64-pc-windows-msvc"),
                             ("actions", [{"Id": "arbitrary", "Return": "ignore"}]), ("extensions", ["custom"]),
                             ("INSTALLDIR", "C:\\arbitrary")]:
            with self.subTest(field=field):
                data = copy.deepcopy(self.inventory)
                data[field] = value
                with self.assertRaises(renderer.SourceError):
                    self.render(data)
        for field, value in [("installablePackage", True), ("trustedSupplier", 0), ("unknown", False)]:
            with self.subTest(qualification=field):
                data = copy.deepcopy(self.inventory)
                data["qualification"][field] = value
                with self.assertRaises(renderer.SourceError):
                    self.render(data)

    def test_digest_supplier_artifact_and_feature_bindings_remain_independent(self):
        arguments = self.arguments()
        for key in ("expected_inventory", "expected_admission"):
            with self.subTest(binding=key), self.assertRaises(renderer.SourceError):
                renderer.render_sources(**{**arguments, key: "f" * 64})
        for path in ["python/python.exe", "python/" + staging.payload.NOTICE_NAME, staging.preparation.GITHUB_CA_NAME,
                     "manifest.json"]:
            with self.subTest(runtime=path):
                data = copy.deepcopy(self.inventory)
                next(row for row in data["files"] if row["path"] == self.prefix + path)["sha256"] = "f" * 64
                with self.assertRaises(renderer.SourceError):
                    self.render(data)
        data = copy.deepcopy(self.inventory)
        next(row for row in data["files"] if row["role"] == "shell")["sha256"] = "f" * 64
        with self.assertRaises(renderer.SourceError):
            self.render(data)
        admission = copy.deepcopy(self.admission)
        admission["publisher"]["features"] = ["desktop-shell", "windows-runtime-publisher"]
        with self.assertRaises(renderer.SourceError):
            self.render(admission=admission)

    def test_canonical_bounds_and_version_inputs_fail_closed(self):
        args = self.arguments()
        for raw in [args["inventory"] + b"\n", args["inventory"].replace(b'"schemaVersion":1', b'"schemaVersion":1,"schemaVersion":1'),
                    b'{"a":NaN}\n', b"[1]\n", b" " * (staging.MAX_MANIFEST_BYTES + 1)]:
            with self.subTest(kind=len(raw)), self.assertRaises(renderer.SourceError):
                renderer.render_sources(**{**args, "inventory": raw, "expected_inventory": digest(raw)})
        with self.assertRaises(renderer.SourceError):
            renderer.render_sources(**{**args, "inventory": bytearray(args["inventory"])})
        for version in ["0.3.0-beta", "00.3.0", "256.0.0", "0.0.65536", "1.2.<bad>"]:
            data, admission = copy.deepcopy((self.inventory, self.admission))
            for value in (data, admission, admission["shell"], admission["publisher"]):
                value["coreVersion"] = version
            with self.subTest(version=version), self.assertRaises(renderer.SourceError):
                self.render(data, admission)

    def test_profile_uses_one_existing_validator_and_exact54_acquisition_order(self):
        args = self.arguments()
        with patch.object(profile.source, "_inputs", wraps=profile.source._inputs) as inputs, \
                patch.object(profile.staging, "stage", side_effect=AssertionError("No staging")), \
                patch.object(profile.staging.preparation, "read_checked", side_effect=AssertionError("No payload IO")):
            raw = profile.render_profile(**args)
        inputs.assert_called_once_with(args["inventory"], args["admission"],
                                       args["expected_inventory"], args["expected_admission"])
        self.assertEqual(raw, profile.render_profile(**args))
        value = json.loads(raw)
        self.assertEqual(raw, json.dumps(value, ensure_ascii=True, allow_nan=False,
                                        sort_keys=True, separators=(",", ":")).encode("ascii"))
        self.assertLessEqual(len(raw), profile.MAX_PROFILE_BYTES)
        self.assertFalse(any(byte in raw for byte in (b"\n", b"\r", b"\0")))
        expected = [row for row in self.inventory["files"] if row["role"] == "runtimeInput"]
        expected += [next(row for row in self.inventory["files"] if row["role"] == role)
                     for role in ("publisher", "shell", "webview2", "applicationNotices", "webview2Notices")]
        rows = [{"size": row["size"], "sha256": row["sha256"]} for row in expected]
        rows += [{"size": len(args[name]), "sha256": digest(args[name])} for name in ("admission", "inventory")]
        self.assertEqual(value["inputs"], rows)
        self.assertEqual(len(rows), 54)
        self.assertEqual(rows[7]["sha256"], value["runtimeManifestSha256"])
        self.assertEqual(rows[47]["sha256"], value["publisherSha256"])
        self.assertEqual((rows[52]["sha256"], rows[53]["sha256"]),
                         (value["admissionSha256"], value["inventorySha256"]))
        self.assertEqual({key: value[key] for key in staging.COMMON_BINDINGS},
                         {key: self.admission[key] for key in staging.COMMON_BINDINGS})
        self.assertEqual(value["inputAssertions"], "supplied-not-observed")
        self.assertNotIn("qualification", value)

    def test_profile_cannot_rebind_changed_schema_roster_or_supplier_data(self):
        for kind in ("schema", "roster", "supplier", "qualification"):
            data = copy.deepcopy(self.inventory)
            if kind == "schema":
                data["runtimeOverride"] = "not permitted"
            elif kind == "roster":
                data["files"].pop()
            elif kind == "supplier":
                next(row for row in data["files"] if row["path"].endswith("/python/python.exe"))["sha256"] = "f" * 64
            else:
                data["qualification"]["nativeQualified"] = True
            with self.subTest(kind=kind), self.assertRaises(profile.ProfileError):
                profile.render_profile(**self.arguments(data))
        args = self.arguments()
        for field in ("expected_inventory", "expected_admission"):
            with self.subTest(field=field), self.assertRaises(profile.ProfileError):
                profile.render_profile(**{**args, field: "f" * 64})

    def test_profile_rejects_impossible_downstream_capacity_and_manifest_before_build(self):
        data = copy.deepcopy(self.inventory)
        runtime = [row for row in data["files"] if row["role"] == "runtimeInput"]
        core = next(row for row in runtime if row["path"] == self.prefix + "core.zip")
        core["size"] = staging.MAX_STAGE_BYTES // 2 - sum(row["size"] for row in runtime if row is not core)
        self.assertGreater(core["size"], 0)
        self.assertEqual(len(json.loads(profile.render_profile(**self.arguments(data)))["inputs"]), 54)
        core["size"] += 1
        with self.assertRaisesRegex(profile.ProfileError, "two-read capacity"):
            profile.render_profile(**self.arguments(data))
        data = copy.deepcopy(self.inventory)
        next(row for row in data["files"] if row["path"] == self.prefix + "manifest.json")["size"] = staging.MAX_MANIFEST_BYTES + 1
        with self.assertRaisesRegex(profile.ProfileError, "runtime manifest"):
            profile.render_profile(**self.arguments(data))


if __name__ == "__main__":
    unittest.main()
