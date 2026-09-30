"""Render the first-install Windows MSI source from closed, pinned DATA3 bytes.

This is a pure DATA-to-source API, not an installer, compiler, filesystem writer
or qualification grant. The unchanged DATA3 stager owns input copying. A later
reviewed builder must admit the actual payload/tool, inspect compiled MSI tables
and falsify the native absence/maintenance graph before executing any package.
"""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import re
import uuid
import xml.etree.ElementTree as ET

_SPEC = importlib.util.spec_from_file_location(
    "_mrk_windows_installer_source_staging", Path(__file__).with_name("stage_windows_installer.py")
)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("Fixed Windows DATA3 stager is unavailable")
staging = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(staging)
require = staging.require
SourceError = staging.StagingError

NAMESPACE = uuid.UUID("1ee3d554-1f9f-5ca7-81a3-e33496cd39dd")
XML_NAMESPACE = "http://wixtoolset.org/schemas/v4/wxs"
OUTPUT_NAMES = ("mrk-retained-inputs.wxs", "mrk-first-activation.wxs", "mrk-installer-source.json")
COMMON = set(staging.COMMON_BINDINGS)
INVENTORY_KEYS = {
    "schemaVersion", "purpose", *COMMON, "inputAssertions", "admissionSha256",
    "runtimeFileCount", "payloadFileCount", "payloadInventorySha256", "files", "qualification",
}
MAINTENANCE = "Installed OR Preselected OR REMOVE OR REINSTALL OR ADVERTISE"
FEATURE_REFUSAL = "(&mrkAllRequired <> 3)"


def _data(raw: bytes, expected: str, limit: int) -> dict:
    require(type(raw) is bytes and 0 < len(raw) <= limit, "Bounded DATA bytes are required")
    require(staging._pin(expected) and hashlib.sha256(raw).hexdigest() == expected,
            "DATA bytes differ from their explicit digest")
    return staging._json(raw)


def _inputs(inventory_raw: bytes, admission_raw: bytes,
            expected_inventory: str, expected_admission: str) -> tuple[dict, dict]:
    inventory = _data(inventory_raw, expected_inventory, staging.MAX_MANIFEST_BYTES)
    admission = _data(admission_raw, expected_admission, staging.MAX_ADMISSION_BYTES)
    staging._closed(inventory, INVENTORY_KEYS, "DATA3 inventory schema differs")
    staging._closed(admission, {"schemaVersion", "purpose", *COMMON, *staging.OPAQUE_OUTPUTS},
                    "DATA3 admission schema differs")
    for value, purpose in ((inventory, staging.INVENTORY_PURPOSE), (admission, staging.ADMISSION_PURPOSE)):
        require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
                and value["purpose"] == purpose, "DATA3 schema or purpose differs")
    require(all(inventory[key] == admission[key] for key in COMMON), "DATA3 common bindings differ")
    require(admission["target"] == staging.TARGET and staging._pin(admission["sourceCommit"], 40)
            and staging._pin(admission["runtimeManifestSha256"])
            and staging._pin(admission["protocolSha256"]), "DATA3 source/target/anchors differ")
    version = admission["coreVersion"]
    require(type(version) is str and len(version) <= 16
            and re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version) is not None,
            "The bound core version must be a canonical three-part MSI version")
    require(all(int(part) <= limit for part, limit in zip(version.split("."), (255, 255, 65535))),
            "The bound core version exceeds MSI version limits")
    require(inventory["inputAssertions"] == "supplied-not-observed"
            and inventory["admissionSha256"] == expected_admission, "DATA3 assertion binding differs")
    staging._closed(inventory["qualification"], set(staging.QUALIFICATION), "DATA3 qualification schema differs")
    require(all(value is False for value in inventory["qualification"].values()),
            "DATA3 cannot grant supplier, image, installer or native qualification")
    require(type(inventory["runtimeFileCount"]) is int and inventory["runtimeFileCount"] == 47
            and type(inventory["payloadFileCount"]) is int and inventory["payloadFileCount"] == 52,
            "Only the reviewed DATA3 47/52 profile is supported")
    for role, (unused_path, limit) in staging.OPAQUE_OUTPUTS.items():
        record = admission[role]
        extra = {*COMMON, "profile", "features"} if role in staging.ARTIFACT_FEATURES else (
            {"kind"} if role == "webview2" else set())
        staging._closed(record, {"size", "sha256", *extra}, "DATA3 artifact assertion schema differs")
        staging._file_record(record, limit)
        if role in staging.ARTIFACT_FEATURES:
            require(all(record[key] == admission[key] for key in COMMON)
                    and record["profile"] == "release" and record["features"] == staging.ARTIFACT_FEATURES[role],
                    "DATA3 artifact source/anchor/features differ")
        elif role == "webview2":
            require(record["kind"] == "evergreen-standalone-offline-x64", "Offline x64 prerequisite required")
    preparation, payload = staging.preparation, staging.payload
    runtime_names = sorted({"manifest.json", "core.zip", preparation.GITHUB_CA_NAME,
                            *preparation.BOOTSTRAPS, "python/" + payload.NOTICE_NAME,
                            *("python/" + name for name, unused_size, unused_sha in payload.MEMBERS)})
    require(len(preparation.BOOTSTRAPS) == 6 and len(payload.MEMBERS) == 37 and len(runtime_names) == 47,
            "The fixed Windows47 source profile changed")
    prefix = "runtime-input/" + staging.TARGET + "/" + admission["runtimeManifestSha256"] + "/"
    expected = {prefix + name: "runtimeInput" for name in runtime_names}
    expected.update({path: role for role, (path, unused_limit) in staging.OPAQUE_OUTPUTS.items()})
    files = inventory["files"]
    require(type(files) is list and len(files) == 52, "DATA3 payload roster differs")
    for row in files:
        staging._closed(row, {"path", "role", "size", "sha256"}, "DATA3 payload row differs")
        require(type(row["path"]) is str and row["path"] in expected
                and row["role"] == expected[row["path"]], "Unknown or aliased DATA3 payload path/role")
        staging._file_record(row, preparation.MAX_FILE_BYTES if row["role"] == "runtimeInput"
                             else staging.OPAQUE_OUTPUTS[row["role"]][1])
    paths = [row["path"] for row in files]
    require(paths == sorted(expected) and len(set(path.casefold() for path in paths)) == 52,
            "DATA3 payload paths are duplicate, unordered or aliased")
    require(sum(row["size"] for row in files) <= staging.MAX_STAGE_BYTES
            and staging._pin(inventory["payloadInventorySha256"])
            and preparation.digest(preparation.canonical(files)) == inventory["payloadInventorySha256"],
            "DATA3 payload size or inventory digest differs")
    by_path = {row["path"]: row for row in files}
    for role, (path, unused_limit) in staging.OPAQUE_OUTPUTS.items():
        require(all(by_path[path][key] == admission[role][key] for key in ("size", "sha256")),
                "DATA3 staged artifact differs from its admission")
    require(by_path[prefix + "manifest.json"]["sha256"] == admission["runtimeManifestSha256"],
            "DATA3 staged runtime manifest differs from D")
    fixed = {"python/" + name: (size, digest) for name, size, digest in payload.MEMBERS}
    fixed["python/" + payload.NOTICE_NAME] = (payload.NOTICE_BYTES, payload.NOTICE_SHA256)
    fixed[preparation.GITHUB_CA_NAME] = (payload.GITHUB_CA_BYTES, payload.GITHUB_CA_SHA256)
    require(all((by_path[prefix + name]["size"], by_path[prefix + name]["sha256"]) == value
                for name, value in fixed.items()), "DATA3 fixed supplier/notice/CA binding differs")
    return inventory, admission


def _guid(role: str, identity: str) -> str:
    # Component/product identities are deterministic names, never authentication.
    return "{" + str(uuid.uuid5(NAMESPACE, role + ":" + identity)).upper() + "}"


def _id(role: str, path: str) -> str:
    return "mrk" + role + "_" + hashlib.sha256(path.encode("utf-8")).hexdigest()[:40]


def _node(parent: ET.Element, tag: str, **attributes: str) -> ET.Element:
    return ET.SubElement(parent, tag, attributes)


def _policy(package: ET.Element, admission: dict, *, activation: bool) -> None:
    for name in ("ARPNOREPAIR", "ARPNOMODIFY", "ARPNOREMOVE"):
        _node(package, "Property", Id=name, Value="1")
    _node(package, "EnsureTable", Id="Signature")
    base = "[ProgramFiles64Folder]Mobile Release Kit\\"
    target = staging.TARGET + "\\" + admission["runtimeManifestSha256"]
    searches = [] if activation else [("Runtime", base + "runtime-input\\" + target),
                                      ("Helper", base + "installer-input\\" + target)]
    searches += [("Active", base + "desktop"), ("Menu", "[ProgramMenuFolder]Mobile Release Kit")]
    properties = []
    for role, path in searches:
        name = "mrk" + role + "Present"
        properties.append(name)
        prop = _node(package, "Property", Id=name)
        _node(prop, "DirectorySearch", Id="mrk" + role + "DirectorySignature", Depth="0", Path=path)
    _node(package, "CustomAction", Id="mrkRefuseUnsupportedOrOccupied",
          Error="Installation refused: non-fresh entry, selected feature state, or an occupied dedicated path.")
    _node(package, "CustomAction", Id="mrkRefuseOtherEntry",
          Error="Administrative and advertised installation are not supported.")
    if activation:
        _node(package, "CustomAction", Id="mrkPublishFixed", FileRef="mrkRetainedPublisher",
              ExeCommand="", Execute="deferred", Impersonate="no", Return="check")
    ui = _node(package, "InstallUISequence")
    _node(ui, "AppSearch", Suppress="yes")
    sequence = _node(package, "InstallExecuteSequence")
    _node(sequence, "AppSearch", Before="CostInitialize")
    _node(sequence, "Custom", Action="mrkRefuseUnsupportedOrOccupied", After="CostFinalize",
          Condition=" OR ".join([MAINTENANCE, *properties, FEATURE_REFUSAL]))
    if activation:
        # Before ProcessComponents/InstallFiles/CreateShortcuts, not merely Burn ordering.
        _node(sequence, "Custom", Action="mrkPublishFixed", After="InstallInitialize", Condition="1")
    for name in ("AdminExecuteSequence", "AdvtExecuteSequence"):
        _node(_node(package, name), "Custom", Action="mrkRefuseOtherEntry", Before="CostInitialize", Condition="1")


def _component(parent: ET.Element, row: dict, identity: str, *, component_id: str | None = None,
               file_id: str | None = None, retained: bool = True) -> ET.Element:
    attrs = {"Id": component_id or _id("C", row["path"]),
             "Guid": _guid("component:" + row["path"], identity), "Bitness": "always64", "NeverOverwrite": "yes"}
    if retained:
        attrs["Permanent"] = "yes"
    component = _node(parent, "Component", **attrs)
    _node(component, "File", Id=file_id or _id("F", row["path"]),
          Source="stage\\" + row["path"].replace("/", "\\"), Name=row["path"].rsplit("/", 1)[-1], KeyPath="yes")
    return component


def _xml(root: ET.Element) -> bytes:
    definitions, guids, components, files = set(), set(), set(), set()
    for node in root.iter():
        if "Id" in node.attrib and node.tag != "ComponentRef":
            value = node.attrib["Id"]
            require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]{0,71}", value) is not None
                    and value not in definitions, "Generated MSI identifier collision")
            definitions.add(value)
        if node.tag == "Component":
            require(node.attrib["Guid"] not in guids, "Generated MSI component GUID collision")
            guids.add(node.attrib["Guid"])
            components.add(node.attrib["Id"])
        elif node.tag == "File":
            require(node.attrib["Source"] not in files, "Generated MSI source path collision")
            files.add(node.attrib["Source"])
    refs = [node.attrib["Id"] for node in root.iter("ComponentRef")]
    require(len(refs) == len(set(refs)) and set(refs) == components, "Generated MSI feature closure differs")
    ET.indent(root, space="  ")
    result = ET.tostring(root, encoding="utf-8", xml_declaration=True) + b"\n"
    require(len(result) <= 256 * 1024, "Generated MSI source exceeds its bound")
    return result


def _package(inventory: dict, admission: dict, identity: str, *, activation: bool) -> bytes:
    kind = "activation" if activation else "retained"
    root = ET.Element("Wix", {"xmlns": XML_NAMESPACE})
    codes = [_guid(role + ":" + kind, identity) for role in ("product", "upgrade")]
    require(len(set(codes)) == 2, "Generated MSI product identity collision")
    package = _node(root, "Package", Name="Mobile Release Kit" if activation else "Mobile Release Kit retained inputs",
                    Manufacturer="Mobile Release Kit", Version=admission["coreVersion"], Language="1033",
                    InstallerVersion="500", ProductCode=codes[0], UpgradeCode=codes[1],
                    Scope="perMachine", Compressed="yes")
    _node(package, "MediaTemplate", EmbedCab="yes")
    _policy(package, admission, activation=activation)
    mrk = _node(_node(package, "StandardDirectory", Id="ProgramFiles64Folder"),
                "Directory", Id="mrkProgramRoot", Name="Mobile Release Kit")
    helper_input = _node(mrk, "Directory", Id="mrkInstallerInput", Name="installer-input")
    helper_target = _node(helper_input, "Directory", Id="mrkInstallerTarget", Name=staging.TARGET)
    helper_digest = _node(helper_target, "Directory", Id="mrkInstallerDigest", Name=admission["runtimeManifestSha256"])
    helper = _node(helper_digest, "Directory", Id="mrkHelperImageDigest", Name=admission["publisher"]["sha256"])
    by_path = {row["path"]: row for row in inventory["files"]}
    publisher = by_path[staging.OPAQUE_OUTPUTS["publisher"][0]]
    _component(helper, publisher, identity, component_id="mrkPublisherComponent", file_id="mrkRetainedPublisher")
    if activation:
        active = _node(mrk, "Directory", Id="mrkActiveDirectory", Name="desktop")
        component = _component(active, by_path[staging.OPAQUE_OUTPUTS["shell"][0]], identity,
                               component_id="mrkShellComponent", file_id="mrkShell", retained=False)
        _node(component, "Shortcut", Id="mrkStartMenuShortcut", Name="Mobile Release Kit",
              Directory="mrkMenuDirectory", WorkingDirectory="mrkActiveDirectory", Target="[#mrkShell]", Advertise="no")
        _node(_node(package, "StandardDirectory", Id="ProgramMenuFolder"),
              "Directory", Id="mrkMenuDirectory", Name="Mobile Release Kit")
    else:
        runtime_input = _node(mrk, "Directory", Id="mrkRuntimeInput", Name="runtime-input")
        runtime_target = _node(runtime_input, "Directory", Id="mrkRuntimeTarget", Name=staging.TARGET)
        runtime = _node(runtime_target, "Directory", Id="mrkRuntimeDigest", Name=admission["runtimeManifestSha256"])
        python = _node(runtime, "Directory", Id="mrkPython", Name="python")
        prefix = "runtime-input/" + staging.TARGET + "/" + admission["runtimeManifestSha256"] + "/"
        for row in inventory["files"]:
            if row["role"] == "runtimeInput":
                _component(python if row["path"][len(prefix):].startswith("python/") else runtime, row, identity)
        notices = _node(helper, "Directory", Id="mrkInstallerNotices", Name="notices")
        for role in ("applicationNotices", "webview2Notices"):
            _component(notices, by_path[staging.OPAQUE_OUTPUTS[role][0]], identity)
    component_ids = [node.attrib["Id"] for node in package.iter("Component")]
    require(len(component_ids) == (2 if activation else 50), "Generated MSI payload mapping differs")
    feature = _node(package, "Feature", Id="mrkAllRequired", Title="Required Mobile Release Kit files", Level="1", AllowAdvertise="no")
    for name in sorted(component_ids):
        _node(feature, "ComponentRef", Id=name)
    return _xml(root)


def render_sources(inventory: bytes, admission: bytes, *, expected_inventory: str,
                   expected_admission: str) -> dict[str, bytes]:
    """Return exactly two candidate WiX files and a binding record; perform no IO.

    Source File paths have only the fixed ``stage\\`` prefix plus exact DATA3
    relative names. The later builder owns a separately admitted readonly stage
    and source workspace; this API accepts no path, XML, action or tool override.
    """
    data, assertions = _inputs(inventory, admission, expected_inventory, expected_admission)
    identity = staging.preparation.digest(staging.preparation.canonical({
        "purpose": "mrk-windows-first-install-source-v1",
        "inventorySha256": expected_inventory, "admissionSha256": expected_admission,
    }))
    result = {
        OUTPUT_NAMES[0]: _package(data, assertions, identity, activation=False),
        OUTPUT_NAMES[1]: _package(data, assertions, identity, activation=True),
    }
    binding = {
        "schemaVersion": 1, "purpose": "windows-first-install-source-only", "identity": identity,
        **{key: assertions[key] for key in staging.COMMON_BINDINGS},
        "inventorySha256": expected_inventory, "admissionSha256": expected_admission,
        "inputAssertions": "supplied-not-observed", "candidateWiXVersion": "6.0.2",
        "msiPayloadFiles": 51, "sharedPublisherReferences": 2,
        "deferredOfflinePrerequisite": dict(assertions["webview2"]),
        "deferredOfflinePrerequisitePath": staging.OPAQUE_OUTPUTS["webview2"][0],
        "outputs": [{"path": name, "size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
                    for name, content in result.items()],
        "qualification": dict(staging.QUALIFICATION), "compiledTablesInspected": False,
        "stockAbsenceAndAncestorSafetyVerified": False, "bundleAssembled": False,
    }
    result[OUTPUT_NAMES[2]] = staging.preparation.canonical(binding) + b"\n"
    return result
