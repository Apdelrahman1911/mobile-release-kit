"""Fresh-supplier DATA tests, never a downloaded/executed interpreter or Mac pass.

Pure contract methods use inert dictionaries and mocked I/O. The two filesystem
methods require the reviewed nonroot POSIX DATA owner and use tiny private text
fixtures only. Do not run native/process suites by importing this test module.
"""
from __future__ import annotations

import ast
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from copy import deepcopy
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).absolute().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location("_fresh_python_consumer_" + name,
                                                SOURCE / "desktop/tools" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TOOL = load("stage_macos_installed")
PREPARE = load("prepare_runtime")


def fixture_data(target="aarch64-apple-darwin"):
    """Synthetic source/receipt correspondence, NOT genuine producer evidence."""
    files = {"python/bin/python3": b"INERT TEXT; NEVER EXECUTED\n"}
    notices = []
    required = []
    for index in range(6):
        name = f"python/licenses/synthetic-{index}.txt"
        body = f"SYNTHETIC NOTICE {index}; NO DISTRIBUTION CLAIM\n".encode("ascii")
        files[name] = body
        notices.append(name)
        required.append({"component": "inert", "path": str(index), "bytes": len(body), "sha256": TOOL.digest(body)})
    lock = TOOL.canonical({"schemaVersion": 1, "target": {
        "triple": target, "minimumMacOS": "26.0", "pythonVersion": "3.14.7", "gil": True},
        "requiredPublicNoticeInputs": required}) + b"\n"
    rows = [{"path": name, "size": len(body), "sha256": TOOL.digest(body),
             "mode": 0o555 if name == "python/bin/python3" else 0o444} for name, body in sorted(files.items())]
    receipt = {"schemaVersion": 1, "kind": TOOL.FRESH_SUPPLIER_KIND, "target": target,
        "pythonVersion": "3.14.7", "gil": True, "sourceLockSha256": TOOL.digest(lock),
        "producerSourceSha256": "1" * 64, "recipeSha256": "2" * 64, "toolchainSha256": "3" * 64,
        "inventorySha256": TOOL.digest(TOOL.canonical(rows)), "files": rows, "notices": notices,
        "nativeEvidence": {name: "4" * 64 for name in TOOL.FRESH_EVIDENCE}}
    return files, lock, receipt


def encoded_receipt(value):
    result = deepcopy(value)
    result["inventorySha256"] = TOOL.digest(TOOL.canonical(result["files"]))
    body = TOOL.canonical(result) + b"\n"
    return body, TOOL.digest(body)


def args(root, **changes):
    values = dict(command="describe-current-runtime", archive=None, python_root=root / "supplier",
                  supplier_receipt=root / "supplier-receipt.json", expected_supplier="a" * 64,
                  work=root / "preparation", output=root / "final", expected_source="b" * 64,
                  expected_manifest="c" * 64)
    return SimpleNamespace(**dict(values, **changes))


def aqua_helpers():
    """Only the two real pure predicates; never native main or owner import."""
    source = (SOURCE / "desktop/tools/macos_aqua_qualification.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    names = {"recovery_supplier_route", "recovery_supplier_matches"}
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    if len(nodes) != 2:
        raise AssertionError("missing exact Aqua supplier predicates")
    namespace = {"need": TOOL.need, "re": re}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "<actual-aqua-pure-supplier-predicates>", "exec"), namespace)
    return namespace, source


@contextmanager
def prepared_fixture(target="aarch64-apple-darwin"):
    files, lock, receipt = fixture_data(target)
    helper = (SOURCE / "desktop/tools/prepare_runtime.py").read_bytes()
    with tempfile.TemporaryDirectory(prefix="mrk-fresh-python-data-") as directory:
        root = Path(directory)
        checkout = root / "checkout"
        engine = b"# INERT PROTOCOL SOURCE; NEVER IMPORTED\n"
        inputs = {"src/mobile_release/__init__.py": b'__version__ = "0.1.0"\n',
                  "src/mobile_release/_desktop_engine.py": engine,
                  TOOL.CURRENT_HELPER_SOURCE: helper,
                  TOOL.CURRENT_CA_SOURCE: b"INERT CA DATA; NOT A TRUST STORE\n",
                  TOOL.source_lock_input(target): lock}
        if target == "x86_64-apple-darwin":
            inputs["desktop/macos-installed-inputs/build-release-intel.json"] = TOOL.canonical({
                "schemaVersion": 1, "packageVersion": "0.1.0", "release": "macos26-x86_64-synthetic-01"})
        inputs.update({"desktop/" + name: ("# inert " + name + "\n").encode("ascii") for name in TOOL.CURRENT_BOOTSTRAPS})
        for name, body in inputs.items():
            path = checkout / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(body)
        supplier = root / "supplier"
        supplier.mkdir(mode=0o700)
        for name, body in files.items():
            path = supplier / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(body)
            path.chmod(0o555 if name == "python/bin/python3" else 0o444)
        for name in sorted(TOOL.directories(files), key=lambda x: (x.count("/"), x), reverse=True):
            (supplier / name).chmod(0o555)
        supplier.chmod(0o555)
        receipt_body, receipt_sha = encoded_receipt(receipt)
        receipt_path = root / "supplier-receipt.json"
        with receipt_path.open("xb") as stream:
            stream.write(receipt_body)
        receipt_path.chmod(0o600)
        with (patch.object(TOOL, "DESKTOP", checkout / "desktop"),
              patch.object(TOOL, "CURRENT_PROTOCOL", TOOL.digest(engine)),
              patch.object(TOOL, "reused_runtime", side_effect=AssertionError("fresh route selected historical supplier"))):
            yield SimpleNamespace(target=target, root=root, checkout=checkout, files=files, receipt_sha=receipt_sha,
                                  receipt=receipt, receipt_path=receipt_path, supplier=supplier)


def signed_fixture_data(target="aarch64-apple-darwin"):
    """Inert derivation schema, never an actual credential/signature/probe pass."""
    files, _lock, receipt = fixture_data(target)
    receipt_body, receipt_sha = encoded_receipt(receipt)
    original = {name: (body, 0o555 if name == TOOL.SIGNED_PYTHON_PATH else 0o444)
                for name, body in files.items()}
    signed = files[TOOL.SIGNED_PYTHON_PATH] + b"INERT SIGNATURE DERIVATION DATA\n"
    producer = (b"schema=1\nstate=configured\nteam-identifier=TEST000001\nrsa-bits=2048\n"
        b"leaf-certificate-sha1=" + b"1" * 40 + b"\nleaf-certificate-sha256=" + b"2" * 64
        + b"\nissuer-certificate-sha256=" + b"3" * 64 + b"\nroot-certificate-sha256=" + b"4" * 64
        + b"\npublic-key-pkcs1-sha256=" + b"5" * 64 + b"\n")
    service = (b"schema=1\napp-identifier=dev.mobile-release-kit.desktop\n"
        b"helper-identifier=dev.mobile-release-kit.desktop.android-register\n"
        b"team-identifier=TEST000001\ndeveloper-id-certificate-sha1=" + b"1" * 40 + b"\n")
    empty = (SOURCE / "desktop/packaging/macos-empty-entitlements.plist").read_bytes()
    nomination = dict(TOOL.SIGNED_ORIGINAL_SUPPLIERS[target], receiptSha256=receipt_sha)
    def row(content):
        return {"path": TOOL.SIGNED_PYTHON_PATH, "size": len(content), "mode": 0o555, "sha256": TOOL.digest(content)}
    value = {"schemaVersion": 1, "kind": "mrk-macos-python-signed-derivation-v1", "purpose": "configured-shipping",
        "target": target, "pythonVersion": "3.14.7", "originalSupplier": nomination,
        "originalInventorySha256": receipt["inventorySha256"], "originalPython": row(files[TOOL.SIGNED_PYTHON_PATH]),
        "signedPython": row(signed),
        "signer": {"sourceCommit": "a" * 40,
            "workflow": "Apdelrahman1911/mobile-release-kit/.github/workflows/desktop-macos-python-runtime-signing.yml@refs/heads/verify/desktop-macos-python-runtime-signing-shipping",
            "runId": "123", "runAttempt": "1", "identifier": "dev.mobile-release-kit.desktop.python",
            "teamIdentifier": "TEST000001", "leafCertificateSha1": "1" * 40,
            "producerProfileSha256": TOOL.digest(producer), "serviceProfileSha256": TOOL.digest(service),
            "entitlementsSha256": TOOL.digest(empty), "codeDirectoryFlags": [0x10000], "timestampRequested": True},
        "nativeEvidence": {role: {"stdoutSha256": "6" * 64, "stderrSha256": "7" * 64} for role in (
            "python-sign", "python-verify", "python-modules", "python-loader", "python-tls", "python-cancellation")},
        "originalsKnown": True, "sourcePost": True, "supplierPost": True, "nonimagePost": True,
        "targetRetired": True, "closesKnown": True, "outerExitRequired": True,
        "assurance": "pinned-native-signature-and-probes-not-notarization-or-installed-authority"}
    body = TOOL.canonical(value) + b"\n"
    return SimpleNamespace(target=target, original=original, original_receipt=receipt_body, nomination=nomination,
        signed=signed, producer=producer, service=service, empty=empty, value=value, body=body,
        options=dict(expected_supplier=receipt_sha, expected_signed_python=TOOL.digest(signed),
            expected_signing_receipt=TOOL.digest(body), expected_signing_source="a" * 40,
            expected_signing_run="123", expected_signing_attempt="1"))


@contextmanager
def signed_prepared_fixture(target="aarch64-apple-darwin"):
    with prepared_fixture(target) as fixture:
        derived = signed_fixture_data(target)
        self_same = {name: (body, 0o555 if name == TOOL.SIGNED_PYTHON_PATH else 0o444)
                     for name, body in fixture.files.items()}
        if self_same != derived.original or fixture.receipt_path.read_bytes() != derived.original_receipt:
            raise AssertionError("distinct inert supplier fixtures disagree")
        signed, receipt = fixture.root / "signed-python3", fixture.root / "signing-receipt.json"
        for path, content, mode in ((signed, derived.signed, 0o555), (receipt, derived.body, 0o444)):
            with path.open("xb") as stream:
                stream.write(content)
            path.chmod(mode)
        profiles = fixture.checkout / "desktop/packaging"
        profiles.mkdir(mode=0o700)
        for name, content in (("macos-install-producer-signing.profile", derived.producer),
                              ("macos-android-service-signing.profile", derived.service),
                              ("macos-empty-entitlements.plist", derived.empty)):
            path = profiles / name
            with path.open("xb") as stream:
                stream.write(content)
            path.chmod(0o644)
        fixture.derived = derived
        fixture.signing_options = dict(derived.options, signed_python=signed, signing_receipt=receipt)
        original_nomination = TOOL.SIGNED_ORIGINAL_SUPPLIERS
        try:
            with patch.object(TOOL, "SIGNED_ORIGINAL_SUPPLIERS", {target: derived.nomination}):
                yield fixture
        finally:
            if TOOL.SIGNED_ORIGINAL_SUPPLIERS is not original_nomination:
                raise AssertionError("fixed supplier nomination was not restored")


def configured_binding(derived, source="b" * 64, manifest="c" * 64):
    """Explicitly synthetic public nomination; no credential or future real pin."""
    row = {"state": "configured", "signingSourceCommit": derived.options["expected_signing_source"],
           "signingRunId": derived.options["expected_signing_run"],
           "signingRunAttempt": derived.options["expected_signing_attempt"], "signingArtifactId": "456",
           "signedPythonSha256": derived.options["expected_signed_python"],
           "signingReceiptSha256": derived.options["expected_signing_receipt"],
           "sourceInputsSha256": source, "runtimeManifestSha256": manifest,
           "producerProfileSha256": TOOL.digest(derived.producer), "serviceProfileSha256": TOOL.digest(derived.service)}
    return {"schemaVersion": 1, "targets": {target: row if target == derived.target else {"state": "unconfigured"}
                                            for target in TOOL.MAC_TARGETS}}


def configure_fixture(fixture, source="b" * 64, manifest="c" * 64):
    value = configured_binding(fixture.derived, source, manifest)
    path = fixture.checkout / "desktop" / TOOL.SIGNED_RUNTIME_BINDING
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(TOOL.canonical(value) + b"\n")
    path.chmod(0o644)
    return path, value


def capsule_fixture(fixture):
    root = fixture.root / "capsule-transport"
    root.mkdir(mode=0o700)
    for name, body in (("python3", fixture.derived.signed), ("python-signed-receipt.json", fixture.derived.body)):
        path = root / name
        path.write_bytes(body)
        path.chmod(0o644)
    return SimpleNamespace(target=fixture.target, transport_root=root, output=fixture.root / "capsule-projection")


class MacFreshPythonConsumerData(unittest.TestCase):
    def test_explicit_profiles_cli_and_options_never_fall_back(self):
        argv = ["--source", "/source", "--runtime-root", "/runtime", "--target", "aarch64-apple-darwin"]
        with (patch.object(PREPARE, "prepare", return_value={"profile": "historical"}) as historical,
              patch.object(PREPARE, "prepare_current", return_value={"profile": "current"}) as current,
              redirect_stdout(io.StringIO())):
            PREPARE.main(argv)
            historical.assert_called_once_with(Path("/source"), Path("/runtime"), "aarch64-apple-darwin")
            current.assert_not_called()
            PREPARE.main([*argv, "--profile", "current"])
            current.assert_called_once_with(Path("/source"), Path("/runtime"), "aarch64-apple-darwin")
        root = Path("/inert")
        fresh = args(root)
        self.assertEqual(TOOL.current_supplier_origin(fresh), "fresh-public-source")
        old = SimpleNamespace(archive=root / "historical.zip")
        self.assertEqual(TOOL.current_supplier_origin(old), "historical")
        for changed in (dict(archive=root / "also.zip"), dict(expected_supplier=None),
                        dict(supplier_receipt=None), dict(expected_supplier=True), dict(python_root=None)):
            with self.subTest(changed=changed), self.assertRaises(TOOL.Refused):
                TOOL.current_supplier_origin(args(root, **changed))
        for key in ("supplier_receipt", "expected_supplier"):
            with self.assertRaises(TOOL.Refused):
                TOOL.current_supplier_origin(SimpleNamespace(archive=root / "historical.zip", **{key: "not-empty"}))
        with (patch.object(TOOL.os, "getuid", return_value=501),
              patch.object(TOOL.os, "geteuid", return_value=501),
              patch.object(TOOL, "current_runtime_command", return_value={}) as current,
              redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO())):
            TOOL.main(["describe-current-runtime", "--python-root", "/fresh", "--supplier-receipt", "/receipt",
                       "--expected-supplier", "a" * 64, "--work", "/work"])
            self.assertEqual(TOOL.current_supplier_origin(current.call_args.args[0]), "fresh-public-source")
            with self.assertRaises(SystemExit):
                TOOL.main(["describe-current-runtime", "--archive", "/old", "--python-root", "/fresh", "--work", "/work"])

        with (patch.object(TOOL.os, "getuid", return_value=501), patch.object(TOOL.os, "geteuid", return_value=501),
              patch.object(TOOL, "current_runtime_command", return_value={}) as current, redirect_stdout(io.StringIO())):
            TOOL.main(["describe-current-runtime", "--python-root", "/fresh", "--supplier-receipt", "/receipt",
                       "--expected-supplier", "a" * 64, "--work", "/work", "--target", "x86_64-apple-darwin"])
            self.assertEqual(current.call_args.args[0].target, "x86_64-apple-darwin")
        # Unqualified Intel historical/observer/fixture paths refuse before even
        # their source reads; no data-dependent ARM fallback or partial output.
        intel = "x86_64-apple-darwin"
        refusals = [(TOOL.runtime_command, SimpleNamespace(target=intel)),
            (TOOL.current_runtime_command, args(root, target=intel, archive=root/"old", python_root=None, supplier_receipt=None, expected_supplier=None)),
            (TOOL.preview_command, SimpleNamespace(target=intel)),
            (TOOL.app_command, SimpleNamespace(target=intel, package_role="installed-shell-observation")),
            (TOOL.input_command, SimpleNamespace(target=intel, package_role="installed-shell-observation")),
            (TOOL.scripts_command, SimpleNamespace(target=intel, fixture=True)),
            (TOOL.prepare_package_command, SimpleNamespace(target=intel, fixture=True)),
            (TOOL.audit_command, SimpleNamespace(target=intel, fixture=True)),
            (TOOL.fixture_observation_command, SimpleNamespace(target=intel))]
        with (patch.object(TOOL, "read", side_effect=AssertionError("refused route read source")),
              patch.object(TOOL, "tree", side_effect=AssertionError("refused route opened tree")),
              patch.object(TOOL, "write_tree", side_effect=AssertionError("refused route wrote output"))):
            for action, options in refusals:
                with self.subTest(action=action.__name__), self.assertRaisesRegex(TOOL.Refused, "unqualified-intel-route"):
                    action(options)
            with self.assertRaises(TOOL.Refused): TOOL.runtime_tree(Path("/unused"), "a"*64, target=intel)
            with self.assertRaises(TOOL.Refused): TOOL.observer_cargo_artifact(None, None, None, None, target=intel)
            with self.assertRaises(TOOL.Refused):
                TOOL.installation_metadata_readback(SimpleNamespace(target=intel), Path("/unused"), {}, fixture=True)

        # Signing is an explicit, complete, independently pinned derivation;
        # none of these inert booleans is native or shipping authority.
        for target in TOOL.MAC_TARGETS:
            fixture = signed_fixture_data(target)
            options = args(root, target=target, signed_python=root/"signed", signing_receipt=root/"signing.json",
                           **fixture.options)
            self.assertTrue(TOOL.signed_python_options(options))
            self.assertFalse(TOOL.signed_python_options(args(root)))
            for name in TOOL.SIGNED_OPTIONS:
                changed = SimpleNamespace(**vars(options)); setattr(changed, name, None)
                with self.subTest(target=target, absent=name), self.assertRaises(TOOL.Refused):
                    TOOL.current_supplier_origin(changed)
            for changed in (dict(archive=root/"old.zip"), dict(expected_signed_python=True),
                            dict(expected_signing_source="0"*40), dict(expected_signing_run="01"),
                            dict(expected_signing_attempt=True), dict(signed_python=str(root/"signed"))):
                bad = SimpleNamespace(**dict(vars(options), **changed))
                with self.subTest(options=changed), self.assertRaises(TOOL.Refused): TOOL.signed_python_options(bad)
            with patch.object(TOOL, "SIGNED_ORIGINAL_SUPPLIERS", {target: fixture.nomination}):
                def check(value, *, signed=None, producer=None, service=None, empty=None):
                    body = TOOL.canonical(value) + b"\n"
                    selected = SimpleNamespace(**dict(vars(options), expected_signing_receipt=TOOL.digest(body)))
                    return TOOL.signed_python_receipt(body, fixture.signed if signed is None else signed,
                        selected, fixture.original, fixture.original_receipt,
                        fixture.producer if producer is None else producer,
                        fixture.service if service is None else service, fixture.empty if empty is None else empty)
                self.assertEqual(check(fixture.value), fixture.value)
                mutations = [dict(fixture.value, schemaVersion=True), dict(fixture.value, purpose="engineering-ad-hoc"),
                    dict(fixture.value, target=TOOL.INTEL_TARGET if target == TOOL.ARM_TARGET else TOOL.ARM_TARGET),
                    dict(fixture.value, originalInventorySha256="f"*64), dict(fixture.value, unrelated=True),
                    dict(fixture.value, nativeEvidence={}), dict(fixture.value, assurance="installed-ready")]
                for name in ("originalsKnown", "sourcePost", "supplierPost", "nonimagePost", "targetRetired",
                             "closesKnown", "outerExitRequired"):
                    mutations.extend((dict(fixture.value, **{name: False}), dict(fixture.value, **{name: 1})))
                for name, changed in (("sourceCommit", "b"*40), ("runId", "124"), ("runAttempt", "2"),
                    ("workflow", fixture.value["signer"]["workflow"].replace("-shipping", "-engineering")),
                    ("teamIdentifier", "OTHER00001"), ("leafCertificateSha1", "8"*40),
                    ("producerProfileSha256", "8"*64), ("serviceProfileSha256", "8"*64),
                    ("entitlementsSha256", "8"*64), ("codeDirectoryFlags", [0x10002]),
                    ("codeDirectoryFlags", [True]), ("timestampRequested", 1)):
                    value = deepcopy(fixture.value); value["signer"][name] = changed; mutations.append(value)
                for name, changed in (("tarSha256", "f"*64), ("sourceCommit", "b"*40), ("artifactId", "125")):
                    value = deepcopy(fixture.value); value["originalSupplier"][name] = changed; mutations.append(value)
                for name in ("originalPython", "signedPython"):
                    value = deepcopy(fixture.value); value[name]["sha256"] = "8"*64; mutations.append(value)
                value = deepcopy(fixture.value); value["nativeEvidence"]["python-verify"]["stdoutSha256"] = True
                mutations.append(value)
                for index, value in enumerate(mutations):
                    with self.subTest(target=target, mutation=index), self.assertRaises(TOOL.Refused): check(value)
                for changed in (dict(signed=fixture.signed+b"changed"), dict(producer=b"schema=1\nstate=unconfigured\n"),
                                dict(service=fixture.service.replace(b"TEST000001", b"OTHER00001")), dict(empty=b"not empty")):
                    with self.assertRaises(TOOL.Refused): check(fixture.value, **changed)
                with self.assertRaisesRegex(TOOL.Refused, "signed-python-anchors"):
                    TOOL.signed_python_receipt(fixture.body+b" ", fixture.signed, options, fixture.original,
                                              fixture.original_receipt, fixture.producer, fixture.service, fixture.empty)
        with (patch.object(TOOL.os, "getuid", return_value=501), patch.object(TOOL.os, "geteuid", return_value=501),
              patch.object(TOOL, "current_runtime_command", return_value={}) as current,
              redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO())):
            TOOL.main(["describe-current-runtime", "--python-root", "/fresh", "--supplier-receipt", "/receipt",
                "--expected-supplier", "f"*64, "--work", "/work", "--signed-python", "/signed-python",
                "--signing-receipt", "/signing.json", "--expected-signed-python", "a"*64,
                "--expected-signing-receipt", "b"*64, "--expected-signing-source", "c"*40,
                "--expected-signing-run", "123", "--expected-signing-attempt", "1"])
            self.assertTrue(TOOL.signed_python_options(current.call_args.args[0]))
        source = (SOURCE/"desktop/tools/stage_macos_installed.py").read_text()
        method = source.split("def current_runtime_command(args):", 1)[1].split("\ndef macho(", 1)[0]
        self.assertLess(method.index("read_signed_python("), method.index("preparer.prepare_current("))
        self.assertLess(method.index("preparer.prepare_current("), method.index("manifest_digest = digest("))
        self.assertNotIn("codesign", method)  # No signature mutation after M or at DATA staging.

        for target in TOOL.MAC_TARGETS:
            fixture = signed_fixture_data(target)
            doc = configured_binding(fixture)
            check = lambda value: TOOL.signed_runtime_binding_data(TOOL.canonical(value),
                fixture.producer, fixture.service, target=target)
            row = check(doc)
            self.assertEqual(row, doc["targets"][target])
            self.assertNotEqual(row["signingSourceCommit"], row["sourceInputsSha256"])
            self.assertNotIn("consumingSourceCommit", row)  # No commit/profile digest cycle.
            bad = [dict(doc, schemaVersion=True), dict(doc, extra=True), dict(doc, targets={})]
            for field, changed in (("state", "unconfigured"), ("signingSourceCommit", "0"*40),
                                   ("signingRunId", "01"), ("signingRunAttempt", True),
                                   ("signingArtifactId", "9007199254740992"), ("signedPythonSha256", "0"*64),
                                   ("runtimeManifestSha256", False), ("producerProfileSha256", "f"*64),
                                   ("serviceProfileSha256", "f"*64)):
                value = deepcopy(doc); value["targets"][target][field] = changed; bad.append(value)
            for field in row:
                value = deepcopy(doc); del value["targets"][target][field]; bad.append(value)
            value = deepcopy(doc); value["targets"][target] = {"state": "unconfigured"}; bad.append(value)
            for value in bad:
                with self.subTest(bindingTarget=target, value=value), self.assertRaises(TOOL.Refused): check(value)
            raw = TOOL.canonical(doc)
            for body in (raw[:-1]+b',"schemaVersion":1}', raw+b" "*TOOL.SIGNED_RUNTIME_BINDING_LIMIT):
                with self.assertRaises(TOOL.Refused):
                    TOOL.signed_runtime_binding_data(body, fixture.producer, fixture.service, target=target)
            with self.assertRaises(TOOL.Refused):
                TOOL.signed_runtime_binding_data(raw, b"schema=1\nstate=unconfigured\n", fixture.service, target=target)

            options = args(root, command="current-runtime", target=target, configured_signing=True,
                           signed_python=root/"signed", signing_receipt=root/"receipt", **fixture.options)
            with (patch.object(TOOL, "signed_runtime_inputs", return_value=(row, ())) as reader,
                  patch.object(TOOL, "SIGNED_ORIGINAL_SUPPLIERS", {target: fixture.nomination})):
                self.assertEqual(TOOL.configured_current_binding(options, target), (row, ()))
                for name in ("expected_signed_python", "expected_signing_receipt", "expected_signing_source",
                             "expected_signing_run", "expected_signing_attempt", "expected_source", "expected_manifest"):
                    changed = SimpleNamespace(**vars(options)); setattr(changed, name, "wrong")
                    with self.subTest(configuredArgument=name), self.assertRaises(TOOL.Refused):
                        TOOL.configured_current_binding(changed, target)
                with self.assertRaisesRegex(TOOL.Refused, "configured-signing-required"):
                    TOOL.configured_current_binding(args(root, configured_signing=True), target)
            self.assertIsNot(TOOL.signed_runtime_inputs, reader)
        with (patch.object(TOOL.os, "getuid", return_value=501), patch.object(TOOL.os, "geteuid", return_value=501),
              patch.object(TOOL, "runtime_signing_selection_command", return_value={}) as select,
              patch.object(TOOL, "project_signed_python_command", return_value={}) as project,
              patch.object(TOOL, "current_runtime_command", return_value={}) as current,
              redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO())):
            TOOL.main(["runtime-signing-selection", "--target", TOOL.INTEL_TARGET])
            self.assertEqual(select.call_args.args[0].target, TOOL.INTEL_TARGET)
            TOOL.main(["project-signed-python", "--transport-root", "/capsule", "--output", "/projected"])
            self.assertEqual(project.call_args.args[0].transport_root, Path("/capsule"))
            TOOL.main(["current-runtime", "--python-root", "/fresh", "--supplier-receipt", "/receipt",
                "--expected-supplier", "a"*64, "--work", "/work", "--expected-source", "b"*64,
                "--expected-manifest", "c"*64, "--output", "/output", "--configured-signing"])
            self.assertIs(current.call_args.args[0].configured_signing, True)
            with self.assertRaises(SystemExit):
                TOOL.main(["describe-current-runtime", "--python-root", "/fresh", "--work", "/work", "--configured-signing"])
        self.assertLess(method.index("configured_current_binding("), method.index("parents = current_paths("))
        self.assertIn('"configured-signing-publication-post-changed"', method)


    def test_receipt_profile_requires_anchor_exact_schema_and_native_references(self):
        _, lock, value = fixture_data()
        body, expected = encoded_receipt(value)
        accepted, rows = TOOL.fresh_supplier_receipt(body, expected, lock)
        self.assertEqual(accepted, value)
        self.assertEqual(list(rows), [row["path"] for row in value["files"]])
        with self.assertRaisesRegex(TOOL.Refused, "fresh-receipt-anchor"):
            TOOL.fresh_supplier_receipt(body, "f" * 64, lock)
        for key, changed in (("schemaVersion", True), ("kind", "historical"),
                             ("target", "x86_64-apple-darwin"), ("pythonVersion", "3.14.6"),
                             ("gil", False), ("gil", 1), ("sourceLockSha256", "a" * 64),
                             ("producerSourceSha256", True), ("toolchainSha256", "NOT-A-PIN"),
                             ("nativeEvidence", {}), ("nativeEvidence", dict(value["nativeEvidence"], extra="1"*64))):
            candidate = dict(value, **{key: changed})
            encoded, pin = encoded_receipt(candidate)
            with self.subTest(key=key, value=changed), self.assertRaises(TOOL.Refused):
                TOOL.fresh_supplier_receipt(encoded, pin, lock)
        for candidate in (dict(value, supplierOnlyReuse=True), {key: item for key, item in value.items() if key != "recipeSha256"}):
            encoded, pin = encoded_receipt(candidate)
            with self.assertRaises(TOOL.Refused):
                TOOL.fresh_supplier_receipt(encoded, pin, lock)
        duplicate = body[:-2] + b',"gil":true}\n'
        with self.assertRaisesRegex(TOOL.Refused, "duplicate-json-key"):
            TOOL.fresh_supplier_receipt(duplicate, TOOL.digest(duplicate), lock)
        nonfinite = body.replace(b'"gil":true', b'"gil":NaN')
        with self.assertRaisesRegex(TOOL.Refused, "json-constant"):
            TOOL.fresh_supplier_receipt(nonfinite, TOOL.digest(nonfinite), lock)

        for target, other in (("aarch64-apple-darwin", "x86_64-apple-darwin"), ("x86_64-apple-darwin", "aarch64-apple-darwin")):
            _, selected_lock, selected_receipt = fixture_data(target)
            raw, pin = encoded_receipt(selected_receipt)
            self.assertEqual(TOOL.fresh_supplier_receipt(raw, pin, selected_lock, target=target)[0], selected_receipt)
            with self.assertRaisesRegex(TOOL.Refused, "fresh-receipt-profile"):
                TOOL.fresh_supplier_receipt(raw, pin, selected_lock, target=other)
            _, wrong_lock, _ = fixture_data(other)
            wrong, wrong_pin = encoded_receipt(dict(selected_receipt, sourceLockSha256=TOOL.digest(wrong_lock)))
            with self.assertRaisesRegex(TOOL.Refused, "fresh-source-lock-binding"):
                TOOL.fresh_supplier_receipt(wrong, wrong_pin, wrong_lock, target=target)
        options = args(Path("/inert"), target="x86_64-apple-darwin")
        with (patch.object(TOOL, "packager_ids", return_value=(501, 20)),
              patch.object(TOOL, "read", side_effect=FileNotFoundError) as reader,
              patch.object(TOOL, "parent") as parent):
            with self.assertRaises(FileNotFoundError): TOOL.fresh_supplier(options)
            reader.assert_called_once_with(TOOL.DESKTOP.parent / "desktop/macos-cpython-source-inputs/source-lock-intel.json", TOOL.FRESH_SOURCE_LOCK_LIMIT)
            parent.assert_not_called()

    def test_inventory_reserves_manifest_and_rejects_aliases_modes_and_missing_notices(self):
        _, lock, value = fixture_data()
        body, pin = encoded_receipt(value)
        self.assertEqual(TOOL.FRESH_SUPPLIER_FILES + len(TOOL.CURRENT_BOOTSTRAPS) + 3, 2048)
        self.assertEqual(TOOL.FRESH_SUPPLIER_BYTES + 48*1024*1024, TOOL.MAX_BYTES)
        for key, changed in (("size", True), ("size", TOOL.FRESH_SUPPLIER_BYTES + 1),
                             ("mode", 0o755), ("mode", True), ("path", "python/../python3"),
                             ("path", "core.zip"), ("sha256", "short")):
            candidate = deepcopy(value)
            candidate["files"][0][key] = changed
            encoded, expected = encoded_receipt(candidate)
            with self.subTest(key=key, changed=changed), self.assertRaises(TOOL.Refused):
                TOOL.fresh_supplier_receipt(encoded, expected, lock)
        invalids = []
        for name in ("reversed", "duplicate", "case-alias", "file-parent", "notice-missing", "notice-duplicate", "notice-wrong-bytes"):
            item = deepcopy(value)
            if name == "reversed": item["files"].reverse()
            elif name == "duplicate": item["files"].insert(0, dict(item["files"][0]))
            elif name == "case-alias": item["files"].append(dict(item["files"][1], path="python/licenses/SYNTHETIC-0.txt"))
            elif name == "file-parent": item["files"].append(dict(item["files"][1], path="python/licenses"))
            elif name == "notice-missing": item["notices"].pop()
            elif name == "notice-duplicate": item["notices"].append(item["notices"][-1])
            else: item["files"][1]["sha256"] = "a" * 64
            if name not in ("reversed", "duplicate"): item["files"].sort(key=lambda x: x["path"])
            invalids.append((name,item))
        for name, candidate in invalids:
            encoded, expected = encoded_receipt(candidate)
            with self.subTest(name=name), self.assertRaises(TOOL.Refused):
                TOOL.fresh_supplier_receipt(encoded, expected, lock)
        with patch.object(TOOL, "FRESH_SUPPLIER_FILES", len(value["files"]) - 1), self.assertRaises(TOOL.Refused):
            TOOL.fresh_supplier_receipt(body, pin, lock)
        with patch.object(TOOL, "FRESH_SUPPLIER_BYTES", 100), self.assertRaises(TOOL.Refused):
            TOOL.fresh_supplier_receipt(body, pin, lock)

    def test_fresh_reader_complete_data_correspondence_and_close_failure_propagation(self):
        files, lock, receipt = fixture_data()
        body, pin = encoded_receipt(receipt)
        options = args(Path("/inert"), expected_supplier=pin)
        supplier = {name: (content, 0o555 if name == "python/bin/python3" else 0o444) for name,content in files.items()}
        info = SimpleNamespace(st_uid=501, st_gid=20, st_mode=stat.S_IFREG | 0o600)
        @contextmanager
        def parent(_):
            yield 19, "receipt"
        with (patch.object(TOOL, "packager_ids", return_value=(501,20)),
              patch.object(TOOL, "read", return_value=lock), patch.object(TOOL, "parent", parent),
              patch.object(TOOL, "read_at", return_value=(body,info)) as read,
              patch.object(TOOL, "tree", return_value=supplier) as tree):
            actual = TOOL.fresh_supplier(options)
            self.assertEqual(actual[0], supplier)
            self.assertEqual(actual[1]["supplierReceiptSha256"], pin)
            self.assertEqual(actual[2:], (lock,body))
            tree.assert_called_once_with(options.python_root, max_bytes=TOOL.FRESH_SUPPLIER_BYTES, current_root_mode=0o555)
            for changed in ({name:v for name,v in supplier.items() if name != "python/bin/python3"},
                            dict(supplier, unexpected=(b"extra",0o444)),
                            dict(supplier, **{"python/bin/python3": (b"changed",0o555)}),
                            dict(supplier, **{"python/bin/python3": (files["python/bin/python3"],0o444)})):
                tree.return_value = changed
                with self.assertRaises(TOOL.Refused): TOOL.fresh_supplier(options)
            tree.return_value = supplier
            read.return_value = (body,SimpleNamespace(st_uid=0,st_gid=0,st_mode=stat.S_IFREG | 0o600))
            with self.assertRaisesRegex(TOOL.Refused, "fresh-receipt-owner-mode"): TOOL.fresh_supplier(options)
            read.side_effect = TOOL.Refused("original-close-unknown")
            with self.assertRaisesRegex(TOOL.Refused, "original-close-unknown"): TOOL.fresh_supplier(options)

    def test_aqua_supplier_origin_and_pin_are_explicit_disjoint_and_before_owner(self):
        helpers, source = aqua_helpers()
        route, matches = helpers["recovery_supplier_route"], helpers["recovery_supplier_matches"]
        fresh = {"supplierOrigin": "fresh-public-source", "supplierReceiptSha256": "a"*64,
                 "supplierSourceLockSha256": "b"*64, "supplierProfile": TOOL.FRESH_SUPPLIER_KIND,
                 "pythonVersion": "3.14.7", "gil": True}
        matches(fresh, "fresh-public-source", "a"*64)
        matches({"supplierOnlyReuse": True}, "historical", None)
        for origin,pin in ((None,None),("unknown",None),("fresh-public-source",None),
                           ("fresh-public-source",True),("historical","a"*64)):
            with self.subTest(origin=origin,pin=pin), self.assertRaises(TOOL.Refused): route(origin,pin)
        for origin,pin,value in (("fresh-public-source","c"*64,fresh),("historical",None,fresh),
                                ("fresh-public-source","a"*64,{"supplierOnlyReuse":True})):
            with self.assertRaises(TOOL.Refused): matches(value,origin,pin)
        for key,value in (("supplierOnlyReuse",True),("acceptedArchiveSha256","c"*64),
                          ("gil",1),("pythonVersion","3.14.6"),("supplierSourceLockSha256",False)):
            with self.subTest(key=key), self.assertRaises(TOOL.Refused):
                matches(dict(fresh,**{key:value}),"fresh-public-source","a"*64)
        main = source.split("def main():",1)[1]
        self.assertLess(main.index("recovery_supplier_route("),main.index("owner = load_owner(root)"))
        self.assertIn("supplier_origin=supplier_origin, supplier_receipt_sha256=supplier_receipt_sha",main)
        method = source.split("    def admit_recovery_runtime(",1)[1].split("    def recovery_runtime_paths(",1)[0]
        self.assertLess(method.index("recovery_supplier_route("),method.index("private_json("))
        self.assertLess(method.index("recovery_supplier_matches("),method.index('self._open("/"'))
        self.assertIn('result["supplierSourceLockSha256"] == source_lock_sha',method)

    @unittest.skipIf(not hasattr(os,"geteuid") or os.geteuid() == 0, "requires reviewed nonroot POSIX DATA owner")
    def test_fresh_current_preparation_and_final_publication_preserve_inputs(self):
        for target in ("aarch64-apple-darwin", "x86_64-apple-darwin"):
            with self.subTest(target=target), prepared_fixture(target) as fixture:
                description_args = args(fixture.root,target=target,expected_supplier=fixture.receipt_sha)
                description = TOOL.current_runtime_command(description_args)
                final_args = args(fixture.root,target=target,command="current-runtime",expected_supplier=fixture.receipt_sha,
                    work=fixture.root/"final-preparation",expected_source=description["sourceInputsSha256"],
                    expected_manifest=description["successorManifestSha256"])
                result = TOOL.current_runtime_command(final_args)
                self.assertEqual(result["target"], target)
                self.assertEqual(result["release"], TOOL.RELEASE if target == "aarch64-apple-darwin" else "macos26-x86_64-synthetic-01")
                self.assertEqual(result["qualification"],"current-source-staged-no-native-execution")
                self.assertEqual(result["supplierOrigin"],"fresh-public-source")
                self.assertEqual(result["supplierReceiptSha256"],fixture.receipt_sha)
                self.assertFalse({"supplierOnlyReuse","acceptedArchiveSha256","acceptedTarSha256", "originalManifestSha256","addedNotices"}.intersection(result))
                actual = TOOL.tree(final_args.output,current_root_mode=0o555)
                self.assertEqual(TOOL.decode(actual["manifest.json"][0])["target"], target)
                self.assertEqual(set(actual),set(fixture.files)|TOOL.CURRENT_BOOTSTRAPS|{"core.zip","github-ca.pem","manifest.json"})
                for name,body in fixture.files.items():
                    self.assertEqual(actual[name],(body,0o555 if name=="python/bin/python3" else 0o444))
                self.assertEqual(TOOL.digest(fixture.receipt_path.read_bytes()),fixture.receipt_sha)
                self.assertEqual(TOOL.fresh_supplier(final_args)[1]["supplierSourceLockSha256"],result["supplierSourceLockSha256"])

        for target in TOOL.MAC_TARGETS:
            with self.subTest(signedTarget=target), signed_prepared_fixture(target) as fixture:
                ordinary = TOOL.current_runtime_command(args(fixture.root, target=target,
                    expected_supplier=fixture.receipt_sha, work=fixture.root/"ordinary-description"))
                options = args(fixture.root, target=target, work=fixture.root/"signed-description", **fixture.signing_options)
                before, capsule = TOOL.read_signed_python(options, fixture.derived.original, fixture.derived.original_receipt)
                signed = TOOL.current_runtime_command(options)
                self.assertEqual(signed["sourceInputsSha256"], ordinary["sourceInputsSha256"])
                self.assertEqual(signed["supplierInventorySha256"], ordinary["supplierInventorySha256"])
                self.assertNotEqual(signed["successorManifestSha256"], ordinary["successorManifestSha256"])
                self.assertEqual(signed["signedPythonSha256"], TOOL.digest(fixture.derived.signed))
                self.assertEqual(signed["signingReceiptSha256"], TOOL.digest(fixture.derived.body))
                self.assertEqual(signed["qualification"], "current-source-description-only-not-build-or-install-authority")
                binding_path, binding_value = configure_fixture(fixture, signed["sourceInputsSha256"], signed["successorManifestSha256"])
                original_binding = binding_path.read_bytes()
                selection = TOOL.runtime_signing_selection_command(SimpleNamespace(target=target))
                self.assertIs(selection["nativeAuthority"], False)
                self.assertEqual(selection["nominationSha256"], TOOL.digest(original_binding))
                self.assertEqual(TOOL.current_source()[2], signed["sourceInputsSha256"])
                projection = capsule_fixture(fixture)
                transport_before = {name: (p.read_bytes(), TOOL.signature(p.stat()))
                                    for name in ("python3", "python-signed-receipt.json")
                                    for p in (projection.transport_root/name,)}
                projected = TOOL.project_signed_python_command(projection)
                self.assertEqual(projected["files"], 2)
                self.assertEqual(TOOL.tree(projection.output, current_root_mode=0o555),
                    {"python3": (fixture.derived.signed, 0o555), "python-signed-receipt.json": (fixture.derived.body, 0o444)})
                self.assertEqual({name: (p.read_bytes(), TOOL.signature(p.stat()))
                                  for name in transport_before for p in (projection.transport_root/name,)}, transport_before)
                projected_options = dict(fixture.signing_options, signed_python=projection.output/"python3",
                                         signing_receipt=projection.output/"python-signed-receipt.json")
                final_options = args(fixture.root, command="current-runtime", target=target,
                    work=fixture.root/"signed-final", expected_source=signed["sourceInputsSha256"],
                    expected_manifest=signed["successorManifestSha256"], configured_signing=True, **projected_options)
                final = TOOL.current_runtime_command(final_options)
                result = TOOL.tree(final_options.output, current_root_mode=0o555)
                self.assertEqual(result[TOOL.SIGNED_PYTHON_PATH], (fixture.derived.signed, 0o555))
                for name, body in fixture.files.items():
                    if name != TOOL.SIGNED_PYTHON_PATH:
                        self.assertEqual(result[name], (body, 0o444))
                rows = {row["path"]: row for row in TOOL.decode(result["manifest.json"][0])["files"]}
                self.assertEqual(rows[TOOL.SIGNED_PYTHON_PATH]["sha256"], TOOL.digest(fixture.derived.signed))
                self.assertEqual(final["successorManifestSha256"], TOOL.digest(result["manifest.json"][0]))
                self.assertEqual(final["qualification"], "current-source-staged-no-native-execution")
                self.assertEqual(TOOL.read_signed_python(options, fixture.derived.original, fixture.derived.original_receipt),
                                 (before, capsule))
                self.assertEqual(final["signedRuntimeBindingSha256"], TOOL.digest(original_binding))
                self.assertEqual(final["signingSourceCommit"], "a"*40)
                self.assertEqual(binding_path.read_bytes(), original_binding)
                self.assertEqual(TOOL.tree(fixture.supplier, current_root_mode=0o555), fixture.derived.original)
                self.assertEqual(fixture.receipt_path.read_bytes(), fixture.derived.original_receipt)

    @unittest.skipIf(not hasattr(os,"geteuid") or os.geteuid() == 0, "requires reviewed nonroot POSIX DATA owner")
    def test_overlap_post_mutations_and_publication_failure_preserve_partial_outputs(self):
        with prepared_fixture() as fixture:
            for output in (fixture.supplier/"nested",fixture.receipt_path,fixture.checkout/"nested"):
                with self.subTest(output=output), self.assertRaisesRegex(TOOL.Refused,"current-path-overlap"):
                    TOOL.current_paths(args(fixture.root,work=output))
            self.assertFalse((fixture.root/"preparation").exists())
        for cause in ("receipt","source-lock","payload","close","publication"):
            with self.subTest(cause=cause), prepared_fixture() as fixture:
                description = TOOL.current_runtime_command(args(fixture.root,expected_supplier=fixture.receipt_sha))
                options = args(fixture.root,command="current-runtime",expected_supplier=fixture.receipt_sha,
                    work=fixture.root/"failed-preparation",expected_source=description["sourceInputsSha256"],
                    expected_manifest=description["successorManifestSha256"])
                preparer = TOOL.current_preparer(TOOL.current_source()[0])
                def changed_after_preparation(source,runtime,target):
                    result = preparer.prepare_current(source,runtime,target)
                    if cause == "receipt": fixture.receipt_path.write_bytes(b"changed receipt DATA")
                    elif cause == "source-lock":
                        (fixture.checkout/TOOL.FRESH_SOURCE_LOCK).write_bytes(b"changed nomination DATA")
                    elif cause == "payload":
                        path = fixture.supplier/"python/licenses/synthetic-0.txt"
                        path.chmod(0o600); path.write_bytes(b"changed supplier DATA")
                    return result
                supplier_reader = TOOL.fresh_supplier
                reads = []
                def read_supplier(arguments):
                    reads.append(True)
                    if cause == "close" and len(reads) == 2:
                        raise TOOL.Refused("original-close-unknown")
                    return supplier_reader(arguments)
                writer = TOOL.write_tree
                def write(output,files,**kwargs):
                    if cause == "publication" and output == options.output:
                        output.mkdir(mode=0o700)
                        (output/"partial-data").write_bytes(b"retained owned partial output")
                        raise OSError("inert publication failure")
                    return writer(output,files,**kwargs)
                with (patch.object(TOOL,"current_preparer",return_value=SimpleNamespace(prepare_current=changed_after_preparation)),
                      patch.object(TOOL,"fresh_supplier",side_effect=read_supplier),
                      patch.object(TOOL,"write_tree",side_effect=write)):
                    with self.assertRaises((TOOL.Refused,ValueError,OSError)):
                        TOOL.current_runtime_command(options)
                self.assertTrue((options.work/"runtime/manifest.json").is_file())
                if cause == "publication":
                    self.assertEqual((options.output/"partial-data").read_bytes(),b"retained owned partial output")
                else:
                    self.assertFalse(options.output.exists())

        with signed_prepared_fixture() as fixture:
            for output in (fixture.signing_options["signed_python"], fixture.signing_options["signing_receipt"]):
                with self.assertRaisesRegex(TOOL.Refused, "current-path-overlap"):
                    TOOL.current_paths(args(fixture.root, work=output, **fixture.signing_options))
            bad = args(fixture.root, **dict(fixture.signing_options, expected_signed_python="f"*64))
            with self.assertRaisesRegex(TOOL.Refused, "signed-python-anchors"):
                TOOL.current_runtime_command(bad)
            self.assertFalse(bad.work.exists())
        for cause in ("signed-bytes", "same-bytes-new-inode", "receipt", "profile", "publication-post"):
            with self.subTest(signedFailure=cause), signed_prepared_fixture() as fixture:
                description = TOOL.current_runtime_command(args(fixture.root, work=fixture.root/"describe", **fixture.signing_options))
                options = args(fixture.root, command="current-runtime", work=fixture.root/"failed-signed",
                    expected_source=description["sourceInputsSha256"], expected_manifest=description["successorManifestSha256"],
                    **fixture.signing_options)
                preparer = TOOL.current_preparer(TOOL.current_source()[0])
                def mutate():
                    if cause in ("signed-bytes", "same-bytes-new-inode", "publication-post"):
                        path = options.signed_python
                        if cause == "same-bytes-new-inode":
                            replacement = path.with_name("replacement-inert")
                            replacement.write_bytes(path.read_bytes()); replacement.chmod(0o555)
                            os.replace(replacement, path)
                        else:
                            path.chmod(0o600); path.write_bytes(b"changed inert signature bytes"); path.chmod(0o555)
                    elif cause == "receipt":
                        options.signing_receipt.chmod(0o600); options.signing_receipt.write_bytes(b"changed receipt DATA")
                    else:
                        path = fixture.checkout/"desktop/packaging/macos-install-producer-signing.profile"
                        path.write_bytes(b"schema=1\nstate=unconfigured\n")
                def prepare(source, runtime, target):
                    result = preparer.prepare_current(source, runtime, target)
                    if cause != "publication-post": mutate()
                    return result
                writer = TOOL.write_tree
                def write(output, files, **kwargs):
                    result = writer(output, files, **kwargs)
                    if cause == "publication-post" and output == options.output: mutate()
                    return result
                with (patch.object(TOOL, "current_preparer", return_value=SimpleNamespace(prepare_current=prepare)),
                      patch.object(TOOL, "write_tree", side_effect=write)):
                    with self.assertRaises((TOOL.Refused, ValueError)):
                        TOOL.current_runtime_command(options)
                self.assertTrue((options.work/"runtime/manifest.json").is_file())
                self.assertEqual(options.output.exists(), cause == "publication-post")
                if cause == "publication-post":
                    # Retained bytes after a failed original input POST are not
                    # an accepted output and may never be silently retried.
                    self.assertEqual((options.output/TOOL.SIGNED_PYTHON_PATH).read_bytes(), fixture.derived.signed)
                self.assertEqual(fixture.receipt_path.read_bytes(), fixture.derived.original_receipt)

        for cause in ("unconfigured", "extra", "missing", "directory", "symlink", "hardlink", "owner", "mode", "hash", "overlap", "occupied"):
            with self.subTest(capsuleRefusal=cause), signed_prepared_fixture() as fixture:
                path, doc = configure_fixture(fixture)
                projection = capsule_fixture(fixture)
                if cause == "unconfigured":
                    doc["targets"][fixture.target] = {"state": "unconfigured"}; path.write_bytes(TOOL.canonical(doc))
                elif cause == "extra": (projection.transport_root/"unexpected").write_bytes(b"extra")
                elif cause == "missing": (projection.transport_root/"python3").unlink()
                elif cause == "directory":
                    (projection.transport_root/"python3").unlink(); (projection.transport_root/"python3").mkdir()
                elif cause == "symlink":
                    (projection.transport_root/"python3").unlink(); (projection.transport_root/"python3").symlink_to(fixture.signing_options["signed_python"])
                elif cause == "hardlink": os.link(projection.transport_root/"python3", fixture.root/"extra-hardlink")
                elif cause == "mode": (projection.transport_root/"python3").chmod(0o755)
                elif cause == "hash": (projection.transport_root/"python3").write_bytes(b"changed DATA")
                elif cause == "overlap": projection.output = projection.transport_root/"inside"
                elif cause == "occupied": projection.output.mkdir(mode=0o700)
                original_reader = TOOL.read_at
                def reader(fd, name, limit, **kwargs):
                    body, info = original_reader(fd, name, limit, **kwargs)
                    if cause == "owner" and name == "python3":
                        # Real held/EOF/POST read, then an explicitly foreign
                        # owner observation; no chown or root privilege.
                        info = SimpleNamespace(st_uid=info.st_uid+1, st_gid=info.st_gid, st_mode=info.st_mode)
                    return body, info
                with (patch.object(TOOL, "read_at", side_effect=reader),
                      patch.object(TOOL, "write_tree", side_effect=AssertionError("refused capsule wrote output")) as writer):
                    with self.assertRaises((TOOL.Refused, OSError)):
                        TOOL.project_signed_python_command(projection)
                    writer.assert_not_called()
                self.assertIs(TOOL.read_at, original_reader)
                self.assertEqual(projection.output.exists(), cause == "occupied")

        for cause in ("transport-post", "source-inode-post", "write", "readback", "close"):
            with self.subTest(capsulePost=cause), signed_prepared_fixture() as fixture:
                path, _ = configure_fixture(fixture)
                projection = capsule_fixture(fixture)
                original_writer, original_close, original_tree = TOOL.write_tree, TOOL.close_once, TOOL.tree
                root_identity = (projection.transport_root.stat().st_dev, projection.transport_root.stat().st_ino)
                failed_close = []
                def writer(output, files, **kwargs):
                    if cause == "write":
                        output.mkdir(mode=0o700); (output/"partial").write_bytes(b"retained")
                        raise OSError("inert capsule write failure")
                    original_writer(output, files, **kwargs)
                    if cause == "transport-post":
                        replacement = projection.transport_root/"replacement"
                        replacement.write_bytes(fixture.derived.signed); replacement.chmod(0o644)
                        os.replace(replacement, projection.transport_root/"python3")
                    elif cause == "source-inode-post":
                        replacement = path.with_name("replacement")
                        replacement.write_bytes(path.read_bytes()); replacement.chmod(0o644); os.replace(replacement, path)
                def closer(fd):
                    info = os.fstat(fd)
                    original_close(fd)
                    if cause == "close" and (info.st_dev, info.st_ino) == root_identity:
                        failed_close.append(True)
                        raise TOOL.Refused("original-close-unknown")
                def readback(path, **kwargs):
                    result = original_tree(path, **kwargs)
                    if cause == "readback" and path == projection.output:
                        result = dict(result); result.pop("python3")
                    return result
                with (patch.object(TOOL, "write_tree", side_effect=writer), patch.object(TOOL, "close_once", side_effect=closer),
                      patch.object(TOOL, "tree", side_effect=readback)):
                    with self.assertRaises((TOOL.Refused, OSError)):
                        TOOL.project_signed_python_command(projection)
                self.assertIs(TOOL.write_tree, original_writer)
                self.assertIs(TOOL.close_once, original_close)
                self.assertIs(TOOL.tree, original_tree)
                self.assertTrue(projection.output.exists())  # Refused partial DATA is not silently retired/adopted.
                self.assertEqual(len(failed_close), 1 if cause == "close" else 0)

        for cause in ("before", "prepare-post", "publication-post"):
            with self.subTest(configuredPost=cause), signed_prepared_fixture() as fixture:
                description = TOOL.current_runtime_command(args(fixture.root, work=fixture.root/"describe", **fixture.signing_options))
                path, doc = configure_fixture(fixture, description["sourceInputsSha256"], description["successorManifestSha256"])
                options = args(fixture.root, command="current-runtime", configured_signing=True,
                    work=fixture.root/"configured-work", expected_source=description["sourceInputsSha256"],
                    expected_manifest=description["successorManifestSha256"], **fixture.signing_options)
                preparer = TOOL.current_preparer(TOOL.current_source()[0])
                original_writer = TOOL.write_tree
                def mutate():
                    doc["targets"][fixture.target]["signingArtifactId"] = "457"
                    path.write_bytes(TOOL.canonical(doc))
                def prepare(source, runtime, target):
                    result = preparer.prepare_current(source, runtime, target)
                    if cause == "prepare-post": mutate()
                    return result
                def writer(output, files, **kwargs):
                    result = original_writer(output, files, **kwargs)
                    if cause == "publication-post" and output == options.output: mutate()
                    return result
                if cause == "before":
                    doc["targets"][fixture.target]["runtimeManifestSha256"] = "f"*64
                    path.write_bytes(TOOL.canonical(doc))
                with (patch.object(TOOL, "current_preparer", return_value=SimpleNamespace(prepare_current=prepare)),
                      patch.object(TOOL, "write_tree", side_effect=writer)):
                    with self.assertRaises(TOOL.Refused): TOOL.current_runtime_command(options)
                self.assertEqual(options.work.exists(), cause != "before")
                self.assertEqual(options.output.exists(), cause == "publication-post")
