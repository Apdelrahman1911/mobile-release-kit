from __future__ import annotations

import base64
import ast
import json
import os
import plistlib
import subprocess
import tempfile
import unittest
import zipfile
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mobile_release._profile_callers import first_primary_context
from mobile_release import credentials as credential_module
from mobile_release.build_inputs import BuildInputs, invocation_custody
from mobile_release.config import load_config
from mobile_release.credentials import (
    _open_profile_directory,
    _parse_certificate_datetime,
    _temporary_apple_signing_environment,
    _utc_datetime,
    _validate_android_material,
    credential_values_from_environment,
    credential_findings,
    resolve_credential_values,
    load_credentials_file,
    materialize_build_inputs,
    materialized_profile_specifier,
    requirements,
    store_lane_environment,
)
from mobile_release.errors import CredentialError
from mobile_release.local_signing import local_signing_lease
from mobile_release.owned_process import ProcessError
from mobile_release.metadata import build_metadata_archive, metadata_findings
from mobile_release.reporting import Status

from .helpers import android_config, ios_config, write_project
from .ios_entitlement_helpers import profile as fictional_profile


class CredentialMetadataTests(unittest.TestCase):
    def test_selected_store_material_requires_exact_validated_live_authority(self) -> None:
        # Real selection, scratch, ADC reader and cancellation ownership. No
        # native command or Store authentication is evidence from this table.
        with tempfile.TemporaryDirectory() as temporary:
            private = Path(temporary)
            root = private / "application"
            value = android_config()
            value["ios"] = ios_config()["ios"]
            value["metadata"]["iosLocales"] = ios_config()["metadata"]["iosLocales"]
            config = load_config(write_project(root, value))
            root = config.root
            equal_config = load_config(config.path)
            self.assertEqual(equal_config, config)
            self.assertIsNot(equal_config, config)
            adc = private / "adc.json"
            adc.write_bytes(b'{"type":"authorized_user","client_id":"synthetic",'
                            b'"client_secret":"synthetic","refresh_token":"synthetic"}')
            adc.chmod(0o600)
            invalid_adc = private / "invalid-adc.json"
            invalid_adc.write_bytes(b'{"type":"not-a-google-credential"}')
            invalid_adc.chmod(0o600)
            values = {"GOOGLE_APPLICATION_CREDENTIALS": str(adc)}

            with patch.object(credential_module, "read_external_bytes",
                              wraps=credential_module.read_external_bytes) as reader, \
                    patch.object(credential_module, "_run_private",
                                 side_effect=AssertionError("authority table must not run native commands")) as native:
                def refused(operation):
                    reads = reader.call_count
                    with self.assertRaises(CredentialError):
                        operation()
                    self.assertEqual(reader.call_count, reads)
                    native.assert_not_called()

                def refused_use(material, invocation, platforms=("android",)):
                    refused(lambda: material.require(config=config, platforms=platforms, invocation=invocation))
                    refused(material.lane_environment)

                # Genuine originals are sequential; never bypass the process
                # reservation to fabricate two simultaneously admitted owners.
                with invocation_custody(root, mode="online") as foreign:
                    foreign.require(root=root, cancellation=foreign.cancellation)
                self.assertFalse(foreign.active)

                # Keep the actual outer guard live while testing an ended
                # invocation; the retained selection still cleans up normally.
                with first_primary_context(nullcontext(), expose_owner=True) as (_, guard):
                    with credential_module.ExitStack() as selection_lifetime:
                        with invocation_custody(root, mode="online", cancellation=guard) as invocation:
                            material = selection_lifetime.enter_context(credential_module._selected_store_material(
                                config, values=values, platforms=("android",), invocation=invocation))
                            self.assertIs(type(material._scratch), credential_module.FiniteScratch)
                            self.assertIs(material._scratch.cancellation, invocation.cancellation)
                            with self.subTest(boundary="pending"):
                                refused_use(material, invocation)
                                reader.assert_not_called()
                            self.assertEqual([(item.code, item.status) for item in material.validate()],
                                             [("credential-material.google-adc", Status.PASS)])
                            reader.assert_called_once_with(adc, kind="private-general", project_root=root,
                                                           cancellation=invocation.cancellation)
                            material.require(config=config, platforms=("android",), invocation=invocation)
                            self.assertIn("GOOGLE_APPLICATION_CREDENTIALS", material.lane_environment(platform="android"))
                            for boundary, operation in (
                                ("repeated-validation", material.validate),
                                ("equal-but-distinct-config", lambda: material.require(
                                    config=equal_config, platforms=("android",), invocation=invocation)),
                                ("wrong-platform", lambda: material.require(
                                    config=config, platforms=("ios",), invocation=invocation)),
                                ("added-platform", lambda: material.require(
                                    config=config, platforms=("android", "ios"), invocation=invocation)),
                                ("unselected-lane", lambda: material.lane_environment(platform="ios")),
                                ("foreign-original-invocation", lambda: material.require(
                                    config=config, platforms=("android",), invocation=foreign)),
                            ):
                                with self.subTest(boundary=boundary):
                                    refused(operation)
                            with self.subTest(boundary="changed-nested-configuration"), patch.dict(
                                    config.data["android"], {"applicationId": "com.example.changed"}):
                                refused_use(material, invocation)
                            for name, changed in (("root", private / "other-application"),
                                                  ("path", root / "release/other.json")):
                                original = getattr(config, name)
                                object.__setattr__(config, name, changed)
                                try:
                                    with self.subTest(boundary="changed-configuration-" + name):
                                        refused_use(material, invocation)
                                finally:
                                    object.__setattr__(config, name, original)
                            # Rebind only this module's observation views, not
                            # shared os/threading APIs, owner records or ledgers.
                            for name, view in (("os", SimpleNamespace(getpid=lambda: os.getpid() + 1)),
                                               ("threading", SimpleNamespace(current_thread=lambda: object()))):
                                with self.subTest(boundary="foreign-" + name), patch.object(credential_module, name, view):
                                    refused_use(material, invocation)
                                material.require(config=config, platforms=("android",), invocation=invocation)
                            with self.subTest(boundary="mismatched-cancellation"):
                                reads = reader.call_count
                                # A real but never-installed guard is distinct
                                # even when both invocations borrowed an outer owner.
                                other_guard = type(invocation.cancellation)(credential_module.ProcessCleanupError,
                                                                           "unadmitted test guard")
                                with self.assertRaisesRegex(CredentialError, "cancellation differs"):
                                    with credential_module._selected_store_material(config, values=values,
                                            platforms=("android",), invocation=invocation, cancellation=other_guard):
                                        self.fail("a foreign guard authorized selection")
                                self.assertEqual(reader.call_count, reads)
                            with credential_module._selected_store_material(config,
                                    values={"GOOGLE_APPLICATION_CREDENTIALS": str(invalid_adc)},
                                    platforms=("android",), invocation=invocation) as rejected:
                                with self.subTest(boundary="rejected"):
                                    reads = reader.call_count
                                    self.assertEqual([item.status for item in rejected.validate()], [Status.INVALID])
                                    self.assertEqual(reader.call_count, reads + 1)
                                    refused_use(rejected, invocation)
                                    refused(rejected.validate)
                            material.require(config=config, platforms=("android",), invocation=invocation)
                        with self.subTest(boundary="ended-original-invocation"):
                            self.assertFalse(invocation.active)
                            guard.check()
                            refused_use(material, invocation)
                    with self.subTest(boundary="closed"):
                        refused_use(material, invocation)
                        refused(material.validate)

                with credential_module._selected_store_material(config, values=values,
                        platforms=("android",)) as standalone:
                    with self.subTest(boundary="standalone"):
                        self.assertEqual([item.status for item in standalone.validate()], [Status.PASS])
                        refused_use(standalone, invocation)
                        refused(standalone.validate)
                with invocation_custody(root, mode="build") as build_invocation:
                    with self.subTest(boundary="non-online-invocation"):
                        reads = reader.call_count
                        with self.assertRaises(CredentialError):
                            with credential_module._selected_store_material(config, values=values,
                                    platforms=("android",), invocation=build_invocation):
                                self.fail("a build invocation authorized Store selection")
                        self.assertEqual(reader.call_count, reads)
                        build_invocation.require(root=root, cancellation=build_invocation.cancellation)

                # Only the two-platform tuple row needs a fictional P8 policy
                # projection. It is not a native outcome or finality receipt.
                both = ("android", "ios")
                p8_bytes = b"fictional-tuple-policy-p8"
                both_values = {**values, "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64":
                               base64.b64encode(p8_bytes).decode("ascii")}
                with invocation_custody(root, mode="online") as invocation:
                    def p8_policy(selected_path, *, execution_source=None, cancellation=None):
                        self.assertIsNone(execution_source)
                        self.assertIs(cancellation, invocation.cancellation)
                        self.assertEqual(selected_path().read_bytes(), p8_bytes)
                        cancellation.check()
                        return credential_module.Finding("credential-material.apple-p8", Status.PASS,
                            "Fictional tuple-authority policy only, not cryptographic evidence.")

                    with patch.object(credential_module, "_validate_selected_p8", side_effect=p8_policy) as policy, \
                            credential_module._selected_store_material(config, values=both_values,
                                platforms=both, invocation=invocation) as material:
                        self.assertEqual([item.status for item in material.validate()], [Status.PASS, Status.PASS])
                        material.require(config=config, platforms=both, invocation=invocation)
                        for wrong in (("ios", "android"), ("android",), ("ios",)):
                            with self.subTest(boundary="exact-platform-tuple", supplied=wrong):
                                refused(lambda: material.require(config=config, platforms=wrong, invocation=invocation))
                        android_lane = material.lane_environment(platform="android")
                        ios_lane = material.lane_environment(platform="ios")
                        self.assertIn("GOOGLE_APPLICATION_CREDENTIALS", android_lane)
                        self.assertNotIn("MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64", android_lane)
                        self.assertIn("MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64", ios_lane)
                        self.assertNotIn("GOOGLE_APPLICATION_CREDENTIALS", ios_lane)
                        refused(material.validate)
                        policy.assert_called_once()
                native.assert_not_called()

    def test_materializer_consumes_selected_bytes_and_never_owns_the_external_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            private = Path(temporary)
            root = private / "app"
            config = load_config(write_project(root, android_config()))
            original = private / "selected.jks"
            original.write_bytes(b"selected-before-return")
            original.chmod(0o600)
            reader, reads = credential_module.read_external_bytes, []

            def select(path, **options):
                content = reader(path, **options)
                reads.append(path)
                original.write_bytes(b"external-intervening-edit")
                return content

            with patch.object(credential_module, "read_external_bytes", select):
                with materialize_build_inputs(config, values={"MOBILE_RELEASE_ANDROID_KEYSTORE_PATH": str(original)},
                                              platforms=("android",)) as environment:
                    selected = Path(environment["MOBILE_RELEASE_ANDROID_KEYSTORE_PATH"])
                    self.assertNotEqual(selected, original)
                    self.assertEqual(selected.read_bytes(), b"selected-before-return")
                    self.assertEqual(selected.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(original.read_bytes(), b"external-intervening-edit")
            self.assertEqual(reads, [original])
            self.assertFalse(selected.exists())
            self.assertEqual(original.read_bytes(), b"external-intervening-edit")
            self.assertEqual(original.stat().st_mode & 0o777, 0o600)

    def test_firebase_content_predicate_checks_bounded_typed_identity(self) -> None:
        expected = "com.example.reader"
        android_client = {"client_info": {"android_client_info": {"package_name": expected}}}
        valid = {
            "android": json.dumps({"client": [android_client]}).encode(),
            "ios": plistlib.dumps({"BUNDLE_ID": expected}),
        }
        invalid = {
            "android": (
                b"not-json", b"\xff", b"[]", b'{"client":null}', b'{"client":{}}',
                b'{"client":[]}', b'{"client":[null]}', b'{"client":[{"client_info":null}]}',
                b'{"client":[{"client_info":{"android_client_info":[]}}]}',
                b'{"client":[{"client_info":{"android_client_info":{"package_name":[]}}}]}',
                b'{"client":[{"client_info":{"android_client_info":{"package_name":"com.example.other"}}}]}',
                json.dumps({"client": [android_client, {"client_info": None}]}).encode(),
            ),
            "ios": (
                b"not-plist", b"bplist00\0", b"<plist><dict>",
                b"<plist><dict><key>BUNDLE_ID</key><integer>invalid</integer></dict></plist>",
                plistlib.dumps([]), plistlib.dumps({}), plistlib.dumps({"BUNDLE_ID": []}),
                plistlib.dumps({"BUNDLE_ID": "com.example.other"}),
            ),
        }
        predicate = credential_module._firebase_content_matches_application
        for platform, content in valid.items():
            with self.subTest(platform=platform, case="matching"):
                self.assertTrue(predicate(content, platform=platform, expected_identity=expected))
                for identity in (None, "", 0, [expected]):
                    self.assertFalse(predicate(content, platform=platform, expected_identity=identity))
                for bad_content in (None, b"", bytearray(content)):
                    self.assertFalse(predicate(bad_content, platform=platform, expected_identity=expected))
                with patch.object(credential_module, "SMALL_PRIVATE_MATERIAL_SIZE", len(content) - 1):
                    self.assertFalse(predicate(content, platform=platform, expected_identity=expected))
            settings = {"services": {platform + "Firebase": "required"},
                        platform: {"applicationId" if platform == "android" else "bundleId": expected}}
            config = SimpleNamespace(root=Path("/fictional-project"), section=settings.get)
            name = ("MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64" if platform == "android"
                    else "MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_BASE64")
            for candidate in (content, *invalid[platform]):
                with self.subTest(platform=platform, content=candidate):
                    accepted = candidate == content
                    self.assertEqual(predicate(candidate, platform=platform, expected_identity=expected), accepted)
                    finding = credential_module._validate_firebase_material(
                        config, {name: base64.b64encode(candidate).decode()}, Path("/unused"), platform,
                    )
                    self.assertEqual(finding.status, Status.PASS if accepted else Status.INVALID)
            decoder = "mobile_release.credentials.json.loads" if platform == "android" else "plistlib.loads"
            for error in (KeyboardInterrupt("original cancellation"), SystemExit(23), ProcessError("owned failure")):
                with self.subTest(platform=platform, error=type(error).__name__), patch(decoder, side_effect=error):
                    with self.assertRaises(type(error)) as caught:
                        predicate(content, platform=platform, expected_identity=expected)
                    self.assertIs(caught.exception, error)
        self.assertFalse(predicate(valid["ios"], platform="other", expected_identity=expected))
        self.assertTrue(predicate(plistlib.dumps({"BUNDLE_ID": expected}, fmt=plistlib.FMT_BINARY),
                                  platform="ios", expected_identity=expected))

    def test_firebase_materializer_revalidates_selected_clients_before_publication(self) -> None:
        # Real external readers and input owners; this is hosted materializer
        # coverage, not part of the no-owner pure predicate verification above.
        for changed_platform in ("android", "ios"):
            for change in ("wrong-identity", "malformed", "after-selection"):
                with self.subTest(platform=changed_platform, change=change), tempfile.TemporaryDirectory() as temporary:
                    private = Path(temporary).resolve()
                    root = private / "project"
                    value = android_config()
                    value["ios"] = ios_config()["ios"]
                    value["metadata"]["iosLocales"] = ios_config()["metadata"]["iosLocales"]
                    value["services"] = {"androidFirebase": "required", "iosFirebase": "required"}
                    config = load_config(write_project(root, value))
                    (root / "iosApp").mkdir()
                    marker = root / "iosApp/GoogleService-Info.plist.example"
                    marker.write_bytes(b"public Firebase marker")
                    targets = (root / "app/google-services.json", marker.with_suffix(""))
                    originals = (b"original Android client", b"original iOS client")
                    for target, content in zip(targets, originals):
                        target.write_bytes(content)
                        target.chmod(0o640)
                    identities = [(target.stat().st_ino, target.stat().st_mode & 0o777) for target in targets]
                    selected = {
                        "android": json.dumps({"client": [{"client_info": {"android_client_info": {
                            "package_name": value["android"]["applicationId"]}}}]}).encode(),
                        "ios": plistlib.dumps({"BUNDLE_ID": value["ios"]["bundleId"]}),
                    }
                    sources = {platform: private / (platform + "-client") for platform in selected}
                    names = {"android": "MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_PATH",
                             "ios": "MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_PATH"}
                    values = {names[platform]: str(source) for platform, source in sources.items()}
                    for platform, source in sources.items():
                        source.write_bytes(selected[platform])
                        source.chmod(0o600)
                        finding = credential_module._validate_firebase_material(config, values, private, platform)
                        self.assertEqual(finding.status, Status.PASS)
                    wrong = {
                        "android": b'{"client":[{"client_info":{"android_client_info":{"package_name":"com.example.other"}}}]}',
                        "ios": plistlib.dumps({"BUNDLE_ID": "com.example.other"}),
                    }
                    malformed = {"android": b'{"client":null}', "ios": b"<plist><dict>"}
                    replacement = (malformed if change == "malformed" else wrong)[changed_platform]
                    if change != "after-selection":
                        rotated = private / "rotated-client"
                        rotated.write_bytes(replacement)
                        rotated.chmod(0o600)
                        rotated.replace(sources[changed_platform])
                    reader, replace = credential_module.read_external_bytes, BuildInputs.replace_all
                    reads, batches = [], []

                    def read(path, **options):
                        content = reader(path, **options)
                        reads.append(path)
                        if change == "after-selection" and path == sources[changed_platform]:
                            path.write_bytes(replacement)
                        return content

                    def batch(owner, replacements):
                        batches.append(replacements)
                        return replace(owner, replacements)

                    with patch.object(credential_module, "read_external_bytes", read), \
                            patch.object(BuildInputs, "replace_all", batch), \
                            patch("mobile_release.discovery.discover_project", return_value={}) as discovery, \
                            patch("mobile_release.discovery.selected_android_module", return_value=":app"):
                        if change == "after-selection":
                            with materialize_build_inputs(config, values=values, platforms=("android", "ios")):
                                self.assertEqual(tuple(target.read_bytes() for target in targets),
                                                 (selected["android"], selected["ios"]))
                            self.assertEqual(len(batches), 1)
                        else:
                            with self.assertRaisesRegex(CredentialError, "Firebase"):
                                with materialize_build_inputs(config, values=values, platforms=("android", "ios")):
                                    self.fail("unvalidated client material reached build entry")
                            self.assertEqual(batches, [])
                        stopped_at_android = changed_platform == "android" and change != "after-selection"
                        self.assertEqual(discovery.call_count, 0 if stopped_at_android else 1)
                        self.assertEqual(reads, [sources["android"]] if stopped_at_android else
                                         [sources["android"], sources["ios"]])
                    self.assertEqual(tuple(target.read_bytes() for target in targets), originals)
                    self.assertEqual([(target.stat().st_ino, target.stat().st_mode & 0o777)
                                      for target in targets], identities)
                    self.assertEqual(sources[changed_platform].read_bytes(), replacement)
                    self.assertEqual(sources[changed_platform].stat().st_mode & 0o777, 0o600)

    def test_both_client_inputs_are_selected_before_one_batch_and_restore_original_inodes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = android_config()
            value["ios"] = ios_config()["ios"]
            value["metadata"]["iosLocales"] = ios_config()["metadata"]["iosLocales"]
            value["services"] = {"androidFirebase": "required", "iosFirebase": "required"}
            config = load_config(write_project(root, value))
            (root / "app").mkdir(exist_ok=True)
            (root / "iosApp").mkdir(exist_ok=True)
            marker = root / "iosApp/GoogleService-Info.plist.example"
            marker.write_bytes(b"public marker")
            targets = (root / "app/google-services.json", marker.with_suffix(""))
            originals = (b"android-original", b"ios-original")
            for target, content in zip(targets, originals):
                target.write_bytes(content)
                target.chmod(0o640)
            inodes = [path.stat().st_ino for path in targets]
            selected = (json.dumps({"client": [{"client_info": {"android_client_info": {
                            "package_name": value["android"]["applicationId"]}}}]}).encode(),
                        plistlib.dumps({"BUNDLE_ID": value["ios"]["bundleId"]}))
            values = {"MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64": base64.b64encode(selected[0]).decode(),
                      "MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_BASE64": base64.b64encode(selected[1]).decode()}
            replace, batches = BuildInputs.replace_all, []

            def batch(owner, replacements):
                batches.append(replacements)
                self.assertEqual(tuple(target.read_bytes() for target in targets), originals)
                self.assertEqual(tuple(row.role for row in replacements), ("android-services", "ios-services"))
                return replace(owner, replacements)

            original_error = ValueError("original build failure")
            with patch.object(BuildInputs, "replace_all", batch), \
                    patch("mobile_release.discovery.discover_project", return_value={}), \
                    patch("mobile_release.discovery.selected_android_module", return_value=":app"):
                with self.assertRaises(ValueError) as caught:
                    with materialize_build_inputs(config, values=values, platforms=("android", "ios")):
                        self.assertEqual(tuple(target.read_bytes() for target in targets), selected)
                        raise original_error
                self.assertIs(caught.exception, original_error)
                self.assertEqual(len(batches), 1)
                with self.assertRaisesRegex(CredentialError, "iOS Firebase"):
                    with materialize_build_inputs(config,
                        values={key: value for key, value in values.items() if "ANDROID" in key},
                        platforms=("android", "ios")):
                        self.fail("incomplete second input published a first target")
                self.assertEqual(len(batches), 1)
            self.assertEqual(tuple(target.read_bytes() for target in targets), originals)
            self.assertEqual([path.stat().st_ino for path in targets], inodes)
            self.assertEqual([path.stat().st_mode & 0o777 for path in targets], [0o640, 0o640])

    def test_generated_profile_mapping_requires_the_exact_live_child_and_original_uuid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root, ios_config(), platform="ios"))
            home = root / "home"
            home.mkdir(mode=0o700)
            uuid = "12345678-1234-1234-1234-1234567890AB"
            name = "MOBILE_RELEASE_IOS_PROFILE_SPECIFIER"
            values = {"MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64": base64.b64encode(b"fictional p12").decode(),
                      "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_BASE64": base64.b64encode(b"fictional profile").decode(),
                      "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD": "fictional"}
            # Only the mapping provenance is under test; no authentication or
            # native-success evidence is inferred from this inert signing seam.
            with invocation_custody(root, mode="build") as invocation:
                with local_signing_lease(home=home, cancellation=invocation.cancellation) as lease:
                    with invocation.project(signing_lease=lease), invocation.materialization(signing_lease=lease) as inputs:
                        with patch.object(credential_module, "_temporary_apple_signing_environment",
                                          return_value=nullcontext({name: uuid})), \
                                patch.object(credential_module, "invocation_custody", side_effect=AssertionError("no second invocation")), \
                                patch.object(credential_module, "local_signing_lease", side_effect=AssertionError("no second lease")):
                            with materialize_build_inputs(config, values=values, platforms=("ios",), prepare_ios_signing=True,
                                signing_lease=lease, cancellation=invocation.cancellation, build_inputs=inputs) as environment:
                                self.assertEqual(materialized_profile_specifier(environment, invocation=invocation), uuid)
                                self.assertIsNone(materialized_profile_specifier({}, invocation=invocation))
                                with self.assertRaises(CredentialError):
                                    materialized_profile_specifier(dict(environment), invocation=invocation)
                                environment[name] = "87654321-1234-1234-1234-1234567890AB"
                                with self.assertRaises(CredentialError):
                                    materialized_profile_specifier(environment, invocation=invocation)
                                environment[name] = uuid
                        with self.assertRaises(CredentialError):
                            materialized_profile_specifier(environment, invocation=invocation)
            self.assertNotIn(name, credential_module.ALLOWED_CREDENTIAL_NAMES)

    def test_original_extraction_helpers_retry_only_completed_positive_status_without_output_paths(self) -> None:
        # Actual helper bodies with inert run methods. These observations are
        # retry/argument contracts only, never original native-finality receipts.
        path = Path(credential_module.__file__)
        tree = ast.parse(path.read_text(), str(path))
        helpers = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
                   and node.name in {"extract", "extract_pkcs12"}]
        self.assertEqual(len(helpers), 2)
        for helper in helpers:
            for mode in ("success", "legacy", "signal", "exception", "missing"):
                with self.subTest(helper=helper.name, mode=mode):
                    calls, original = [], KeyboardInterrupt("original interruption")
                    results = ([subprocess.CompletedProcess([], 1, "", "")] if mode == "legacy" else [])
                    results += [None if mode == "missing" else subprocess.CompletedProcess(
                        [], -15 if mode == "signal" else 0, "selected PEM\n", "")]

                    def run(argv, **_options):
                        calls.append(tuple(argv))
                        if mode == "exception":
                            raise original
                        return results.pop(0)

                    namespace = {"scratch": SimpleNamespace(require=lambda _: Path("/selected/input.p12")),
                        "p12": object(), "session": SimpleNamespace(run=run), "_run_private": run,
                        "env": {}, "execution_source": None, "cancellation": object(), "subprocess": subprocess,
                        "ProcessError": ProcessError, "CredentialError": CredentialError}
                    exec(compile(ast.Module(body=[helper], type_ignores=[]), str(path), "exec"), namespace)
                    arguments = (["-clcerts", "-nokeys"], "extract certificate") if helper.name == "extract" else (
                        ["-clcerts", "-nokeys", "-passin", "env:MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD"],)
                    if mode in {"success", "legacy"}:
                        result = namespace[helper.name](*arguments)
                        self.assertEqual(result if helper.name == "extract" else result.stdout.encode("utf-8"), b"selected PEM\n")
                    else:
                        with self.assertRaises({"signal": ProcessError, "exception": KeyboardInterrupt,
                                                "missing": AttributeError}[mode]) as caught:
                            namespace[helper.name](*arguments)
                        if mode == "exception":
                            self.assertIs(caught.exception, original)
                    self.assertEqual(len(calls), 2 if mode == "legacy" else 1)
                    self.assertTrue(all("-out" not in argv for argv in calls))
                    self.assertEqual(sum("-legacy" in argv for argv in calls), int(mode == "legacy"))

    def test_firebase_target_is_restored_when_apple_signing_setup_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = ios_config()
            value["services"]["iosFirebase"] = "required"
            config = load_config(write_project(root, value, platform="ios"))
            marker = root / "iosApp/GoogleService-Info.plist.example"
            marker.write_text("public marker\n", encoding="utf-8")
            target = marker.with_suffix("")
            target.write_bytes(b"original-private-client")
            target.chmod(0o640)
            values = {
                "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64": base64.b64encode(
                    b"p12"
                ).decode("ascii"),
                "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD": "password",
                "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_BASE64": base64.b64encode(
                    b"profile"
                ).decode("ascii"),
                "MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_BASE64": base64.b64encode(
                    plistlib.dumps({"BUNDLE_ID": value["ios"]["bundleId"]})
                ).decode("ascii"),
            }

            class FailingSigningContext:
                def __enter__(self) -> object:
                    raise CredentialError("injected signing setup failure")

                def __exit__(self, *_args: object) -> None:
                    return None

            home = root / "home"
            home.mkdir(mode=0o700)
            with first_primary_context(nullcontext(), expose_owner=True) as (_, guard), patch.dict(
                os.environ, {"MOBILE_RELEASE_IOS_PROFILE_SPECIFIER": ""}, clear=False
            ), patch(
                "mobile_release.credentials._temporary_apple_signing_environment",
                return_value=FailingSigningContext(),
            ), local_signing_lease(home=home, cancellation=guard) as lease:
                with self.assertRaisesRegex(CredentialError, "injected"):
                    with materialize_build_inputs(
                        config,
                        values=values,
                        platforms=("ios",),
                        prepare_ios_signing=True,
                        signing_lease=lease,
                    ):
                        self.fail("signing context unexpectedly entered")
            self.assertEqual(target.read_bytes(), b"original-private-client")
            self.assertEqual(target.stat().st_mode & 0o777, 0o640)

    def test_credential_inputs_reject_unknown_names_and_ignore_unrelated_ambient_paths(self) -> None:
        filtered = credential_values_from_environment(
            {
                "MOBILE_RELEASE_PROJECT_READ_TOKEN": "read-token",
                "GITHUB_EVENT_PATH": "/tmp/event.json",
                "CMAKE_PREFIX_PATH": "/tmp/cmake",
            }
        )
        self.assertEqual(filtered, {"MOBILE_RELEASE_PROJECT_READ_TOKEN": "read-token"})

        with tempfile.TemporaryDirectory() as temporary:
            private_root = Path(temporary).resolve()
            app_root = private_root / "app"
            write_project(app_root, android_config())
            credentials = private_root / "credentials.env"
            credentials.write_text(
                "MOBILE_RELEASE_APPLE_PROVISIONING_PROFIL_PATH=/tmp/typo\n",
                encoding="utf-8",
            )
            credentials.chmod(0o600)
            with self.assertRaisesRegex(CredentialError, "unsupported credential name"):
                load_credentials_file(credentials, app_root)

    def test_store_lane_materializes_documented_p8_path_as_base64(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            private_root = Path(temporary).resolve()
            app_root = private_root / "app"
            config = load_config(write_project(app_root, ios_config(), platform="ios"))
            key = private_root / "AuthKey.p8"
            key.write_bytes(b"private-p8-content")
            key.chmod(0o600)
            environment = store_lane_environment(
                config,
                values={"MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_PATH": str(key)},
                platforms=("ios",),
            )
            self.assertEqual(
                base64.b64decode(environment["MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64"]),
                b"private-p8-content",
            )
            self.assertNotIn("MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_PATH", environment)

    def test_credential_file_precedence_and_ambiguous_material_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            private_root = Path(temporary)
            root = private_root / "app"
            config = load_config(write_project(root, android_config()))
            keystore = private_root / "release.jks"
            keystore.write_bytes(b"keystore")
            keystore.chmod(0o600)
            credentials = private_root / "credentials.env"
            credentials.write_text(
                f"MOBILE_RELEASE_ANDROID_KEYSTORE_PATH={keystore}\n", encoding="utf-8"
            )
            credentials.chmod(0o600)
            resolved = resolve_credential_values(
                config,
                credentials_file=credentials,
                credentials_from_env=True,
                environ={"MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64": base64.b64encode(b"old").decode()},
            )
            self.assertEqual(resolved, {"MOBILE_RELEASE_ANDROID_KEYSTORE_PATH": str(keystore)})
            with self.assertRaisesRegex(CredentialError, "ambiguous"):
                resolve_credential_values(
                    config,
                    credentials_from_env=True,
                    environ={
                        "MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64": "a2V5",
                        "MOBILE_RELEASE_ANDROID_KEYSTORE_PATH": str(keystore),
                    },
                )

    def test_github_inventory_never_accepts_local_path_secret_alternative(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = load_config(write_project(Path(temporary), android_config()))
            secrets = {
                "MOBILE_RELEASE_ANDROID_KEYSTORE_PATH",
                "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD",
                "MOBILE_RELEASE_ANDROID_KEY_PASSWORD",
            }
            variables = {"MOBILE_RELEASE_ANDROID_KEY_ALIAS"}
            with patch(
                "mobile_release.credentials._github_names",
                return_value=(secrets, variables, None),
            ):
                findings = credential_findings(
                    config,
                    stage="candidate",
                    purpose="signing",
                    github=True,
                )
            keystore = next(item for item in findings if "keystore_base64" in item.code)
            self.assertEqual(keystore.status, Status.MISSING)

    def test_materialized_build_environment_contains_only_platform_build_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root, android_config()))
            values = {
                "MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64": base64.b64encode(b"key").decode(),
                "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD": "store-password",
                "MOBILE_RELEASE_ANDROID_KEY_ALIAS": "release",
                "MOBILE_RELEASE_ANDROID_KEY_PASSWORD": "key-password",
                "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64": base64.b64encode(b"p8").decode(),
                "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD": "p12-password",
                "MOBILE_RELEASE_PROJECT_READ_TOKEN": "read-token",
            }
            with materialize_build_inputs(
                config, values=values, platforms=("android",)
            ) as environment:
                path = Path(environment["MOBILE_RELEASE_ANDROID_KEYSTORE_PATH"])
                self.assertTrue(path.is_file())
                self.assertEqual(
                    set(environment),
                    {
                        "MOBILE_RELEASE_ANDROID_KEYSTORE_PATH",
                        "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD",
                        "MOBILE_RELEASE_ANDROID_KEY_ALIAS",
                        "MOBILE_RELEASE_ANDROID_KEY_PASSWORD",
                        "MOBILE_RELEASE_PROJECT_READ_TOKEN",
                    },
                )
            self.assertFalse(path.exists())

    def test_android_firebase_never_writes_through_symlinked_module(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = android_config()
            value["services"]["androidFirebase"] = "required"
            config = load_config(write_project(root, value))
            target = root / "tracked-module"
            target.mkdir()
            sentinel = target / "keep.txt"
            sentinel.write_text("keep\n", encoding="utf-8")
            (root / "linked").symlink_to(target, target_is_directory=True)
            values = {
                "MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64": base64.b64encode(
                    json.dumps({"client": [{"client_info": {"android_client_info": {
                        "package_name": value["android"]["applicationId"]}}}]}).encode()
                ).decode()
            }
            with patch(
                "mobile_release.discovery.selected_android_module", return_value=":linked"
            ), patch("mobile_release.discovery.discover_project", return_value={}):
                with self.assertRaisesRegex(CredentialError, "symbolic link"):
                    with materialize_build_inputs(
                        config, values=values, platforms=("android",)
                    ):
                        self.fail("unsafe Firebase destination was entered")
            self.assertFalse((target / "google-services.json").exists())
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep\n")

    def test_local_apple_signing_material_is_installed_and_cleaned_ephemerally(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            home.mkdir(mode=0o700)
            private = root / "private"
            private.mkdir(mode=0o700)
            p12 = private / "distribution.p12"
            profile = private / "profile.mobileprovision"
            p12.write_bytes(b"p12")
            profile.write_bytes(b"profile")
            p12.chmod(0o600)
            profile.chmod(0o600)
            project = root / "application"
            project.mkdir(mode=0o700)
            profile_uuid = "12345678-1234-1234-1234-1234567890AB"
            calls: list[list[str]] = []

            from .local_signing_helpers import NativeSigningModel, fictional_signing_profile
            model = NativeSigningModel(home)
            calls = model.calls
            fake_private_run = model

            with patch("mobile_release.credentials._authenticated_signing_profile", side_effect=fictional_signing_profile), patch(
                "mobile_release.credentials._run_private", side_effect=fake_private_run
            ):
                with _temporary_apple_signing_environment(
                    p12=p12,
                    password="private-password",
                    profile=profile,
                    directory=private,
                    home=home,
                    project_root=project,
                ) as updates:
                    installed = (
                        home
                        / "Library/MobileDevice/Provisioning Profiles"
                        / f"{profile_uuid}.mobileprovision"
                    )
                    self.assertEqual(
                        updates["MOBILE_RELEASE_IOS_PROFILE_SPECIFIER"], profile_uuid
                    )
                    self.assertEqual(installed.read_bytes(), b"profile")
                self.assertFalse(installed.exists())
            self.assertTrue(any(command[1] == "import" for command in calls))
            self.assertTrue(any(command[1] == "delete-keychain" for command in calls))
            activation = next(
                command
                for command in calls
                if command[1:5] == ["list-keychains", "-d", "user", "-s"]
                and "signing.keychain-db" in " ".join(command)
            )
            self.assertEqual(len(activation), 6)
            restored_search = next(
                command
                for command in calls
                if command[1:5] == ["list-keychains", "-d", "user", "-s"]
                and "signing.keychain-db" not in " ".join(command)
            )
            self.assertEqual(
                restored_search[-2:],
                model.original["search"],
            )

    def test_apple_profile_install_rejects_symlinked_parent_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            outside = Path(temporary) / "outside"
            home.mkdir()
            outside.mkdir()
            (home / "Library").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(CredentialError, "symbolic link"):
                _open_profile_directory(home)
            self.assertEqual(list(outside.iterdir()), [])

    def test_certificate_validity_parsing_rejects_future_android_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root / "app", android_config()))
            values = {
                "MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64": base64.b64encode(b"key").decode(),
                "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD": "store-password",
                "MOBILE_RELEASE_ANDROID_KEY_ALIAS": "release",
                "MOBILE_RELEASE_ANDROID_KEY_PASSWORD": "key-password",
            }
            fingerprint = ":".join(["AA"] * 32)
            output = (
                "Entry type: PrivateKeyEntry\n"
                f"SHA256: {fingerprint}\n"
                "Valid from: Thu Aug 20 00:00:00 UTC 2099 until: Fri Aug 20 00:00:00 UTC 2100\n"
            )
            result = subprocess.CompletedProcess([], 0, stdout=output, stderr="")
            with patch("mobile_release.credentials._run_private", return_value=result):
                finding = _validate_android_material(config, values, root)
            self.assertEqual(finding.status, Status.INVALID)
            self.assertIn("not currently valid", finding.message)

    def test_aware_certificate_dates_are_converted_to_utc(self) -> None:
        parsed = _parse_certificate_datetime("Aug 20 03:00:00 2026 +0300")
        self.assertEqual(parsed.hour, 0)
        self.assertEqual(_utc_datetime(parsed), parsed)

    def test_stage_and_capability_requirements_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = load_config(write_project(Path(temporary), ios_config(demo=True), platform="ios"))
            external = requirements(config, "external-testing")
            names = {item.name for item in external}
            self.assertIn("MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64", names)
            self.assertIn("MOBILE_RELEASE_APPLE_REVIEW_CONTACT_FIRST_NAME", names)
            self.assertIn("MOBILE_RELEASE_APPLE_DEMO_ACCOUNT_USERNAME", names)
            self.assertTrue(all(item.stage == "external-testing" for item in external))
            signing = {item.name for item in requirements(config, "candidate", purpose="signing")}
            self.assertIn("MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64", signing)
            self.assertNotIn("MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64", signing)
            store = {item.name for item in requirements(config, "candidate", purpose="store")}
            self.assertIn("MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64", store)
            self.assertNotIn("MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64", store)

    def test_private_path_inside_repository_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root, android_config()))
            private = root / "secret.jks"
            private.write_bytes(b"not-a-keystore")
            findings = credential_findings(
                config,
                stage="candidate",
                purpose="signing",
                credentials_from_env=True,
                environ={
                    "MOBILE_RELEASE_ANDROID_KEYSTORE_PATH": str(private),
                    "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD": "x",
                    "MOBILE_RELEASE_ANDROID_KEY_ALIAS": "release",
                    "MOBILE_RELEASE_ANDROID_KEY_PASSWORD": "x",
                },
            )
            key = next(item for item in findings if "keystore_base64" in item.code)
            self.assertEqual(key.status, Status.INVALID)
            self.assertNotIn(str(private), key.message)

    def test_metadata_rejects_hidden_junk_and_archive_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root, android_config()))
            metadata_root = root / "release/store"
            (metadata_root / "android/.DS_Store").write_bytes(b"junk")
            findings = metadata_findings(config, platforms=("android",))
            self.assertTrue(any(item.status == Status.INVALID for item in findings))
            (metadata_root / "android/.DS_Store").unlink()
            (metadata_root / ".gitkeep").write_text("", encoding="utf-8")
            first = root / "first.zip"
            second = root / "second.zip"
            self.assertEqual(
                build_metadata_archive(metadata_root, first),
                build_metadata_archive(metadata_root, second),
            )
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                self.assertTrue(
                    all(item.compress_type == zipfile.ZIP_STORED for item in archive.infolist())
                )

    def test_android_metadata_isolated_from_ios_changes_and_secret_patterns(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root, android_config()))
            metadata_root = root / "release/store"
            ios = metadata_root / "ios/en-US"
            ios.mkdir(parents=True)
            foreign = ios / "notes.txt"
            foreign.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic\n")
            first = root / "android-first.zip"
            second = root / "android-second.zip"
            first_hash = build_metadata_archive(metadata_root, first, platform="android")
            foreign.write_text("\"client_secret\": \"synthetic-secret-value\"\n")
            second_hash = build_metadata_archive(metadata_root, second, platform="android")
            self.assertEqual(first_hash, second_hash)
            self.assertFalse(
                any(item.status in {Status.FAIL, Status.INVALID} for item in metadata_findings(
                    config, platforms=("android",)
                ))
            )

            android_text = metadata_root / "android/en-US/full_description.txt"
            android_text.write_text("-----BEGIN ENCRYPTED PRIVATE KEY-----\nsynthetic\n")
            findings = metadata_findings(config, platforms=("android",))
            self.assertTrue(any(item.code == "metadata.secret-pattern" for item in findings))

    def test_asset_only_locale_cannot_pass_store_metadata_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root, android_config()))
            locale = root / "release/store/android/en-US"
            for path in locale.glob("*.txt"):
                path.unlink()
            (locale / "feature.png").write_bytes(
                b"\x89PNG\r\n\x1a\n" + b"\x00" * 8 + b"\x00\x00\x00\x01\x00\x00\x00\x01"
            )
            findings = metadata_findings(config, platforms=("android",))
            required = next(
                item for item in findings if item.code.endswith(".required-text")
            )
            self.assertEqual(required.status, Status.MISSING)

    def test_ios_metadata_requires_testflight_copy_and_safe_https_urls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root, ios_config(), platform="ios"))
            metadata_root = root / "release/store"
            what_to_test = metadata_root / "testflight/what-to-test.txt"
            what_to_test.unlink()
            findings = metadata_findings(config, platforms=("ios",))
            self.assertTrue(
                any(
                    item.status == Status.MISSING and "what-to-test.txt" in item.message
                    for item in findings
                )
            )

            what_to_test.write_text("x" * 4001, encoding="utf-8")
            (metadata_root / "ios/en-US/privacy_url.txt").write_text(
                "http://user:password@example.test/privacy\n", encoding="utf-8"
            )
            findings = metadata_findings(config, platforms=("ios",))
            self.assertTrue(
                any(item.code == "metadata.url" and item.status == Status.INVALID for item in findings)
            )
            self.assertTrue(
                any(
                    item.code == "metadata.length"
                    and "what-to-test.txt" in item.message
                    for item in findings
                )
            )
            (metadata_root / "ios/en-US/privacy_url.txt").write_text(
                "https://example.test/privacy?token=synthetic#fragment\n", encoding="utf-8"
            )
            findings = metadata_findings(config, platforms=("ios",))
            self.assertTrue(any(item.code == "metadata.url" for item in findings))


if __name__ == "__main__":
    unittest.main()
