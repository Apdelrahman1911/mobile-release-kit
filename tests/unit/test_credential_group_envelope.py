"""Synthetic input-group/consumer contracts; no native, Store or auth calls."""
from __future__ import annotations

import base64
import io
import json
import os
import tempfile
import unittest
from collections.abc import Mapping
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mobile_release import credentials, preflight, stores, workflow
from mobile_release.config import ReleaseConfig
from mobile_release.credential_group_envelope import (
    INPUT_GROUPS, INPUT_GROUP_ENVIRONMENT_NAMES, INPUT_GROUP_MAX_BYTES,
    INPUT_GROUP_PROTOCOL, decode_group_envelope, encode_group_envelope,
    google_wif_inputs, group_mask_commands, groups_for_requirements, input_group,
    validate_input_field,
)
from mobile_release.credential_requirements import ENVIRONMENT_INPUT_TYPES, Requirement, requirements
from mobile_release.errors import CredentialError
from mobile_release.reporting import Report, Status

SOURCE = Path(__file__).resolve().parents[2]
WIF = {"provider": "projects/123/locations/global/workloadIdentityPools/example/providers/example",
       "serviceAccount": "synthetic@example.iam.gserviceaccount.com"}
KEYSTORE = {"file": base64.b64encode(b"synthetic-keystore").decode(), "storePassword": "synthetic-store-password",
            "keyAlias": "upload", "keyPassword": "synthetic-key-password"}


def config(*, demo=True, firebase=True, project_token=True):
    return ReleaseConfig(Path("/synthetic-unopened/mobile-release.json"), Path("/synthetic-unopened"), {
        "android": {"enabled": True},
        "ios": {"enabled": True, "review": {"demoAccountRequired": demo}},
        "services": {"androidFirebase": "required" if firebase else "disabled",
                     "iosFirebase": "required" if firebase else "disabled"},
        "source": {"projectReadTokenRequired": project_token},
    })


def envelope(kind, values):
    return encode_group_envelope(kind, values).decode()


def canonical(kind, values):
    return {field.name: values[field.id] for field in input_group(kind).fields}


class StatefulEnvironment(Mapping):
    """A synthetic Mapping that refuses ambient enumeration and changes reads."""
    def __init__(self, initial, later):
        self.initial = initial
        self.later = later
        self.reads = {}

    def __getitem__(self, name):
        self.reads[name] = self.reads.get(name, 0) + 1
        return (self.initial if self.reads[name] == 1 else self.later)[name]

    def __iter__(self):
        raise AssertionError("Ambient environment enumeration is not admitted")

    def __len__(self):
        raise AssertionError("Ambient environment enumeration is not admitted")


class CredentialGroupEnvelopeTests(unittest.TestCase):
    def test_environment_observation_is_bounded_once_before_whole_file_override(self):
        group = input_group("android-keystore")
        required = [Requirement(field.name, ENVIRONMENT_INPUT_TYPES[field.name], "candidate", "android")
                    for field in group.fields]
        legacy = canonical(group.kind, {**KEYSTORE, "storePassword": "legacy-store"})
        partial = {"MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD": "file-store"}
        allowed = credentials.ALLOWED_CREDENTIAL_NAMES | {"GITHUB_ACTIONS", group.secret_name}
        for present in (False, True):
            initial = {**legacy, **({group.secret_name: envelope(group.kind, KEYSTORE)} if present else {})}
            later = {**legacy, **({} if present else {group.secret_name: envelope(group.kind, KEYSTORE)})}
            observed = StatefulEnvironment(initial, later)
            with self.subTest(present=present), patch.object(credentials, "load_credentials_file", return_value=partial):
                if present:
                    with self.assertRaisesRegex(CredentialError, "complete android-keystore"):
                        credentials.resolve_credential_values(config(), credentials_file=Path("/synthetic-file"),
                            credentials_from_env=True, environ=observed, required=required)
                else:
                    self.assertEqual(credentials.resolve_credential_values(config(), credentials_file=Path("/synthetic-file"),
                        credentials_from_env=True, environ=observed, required=required), {**legacy, **partial})
            self.assertEqual(set(observed.reads), allowed)
            self.assertEqual(set(observed.reads.values()), {1})
        direct = StatefulEnvironment({group.secret_name: envelope(group.kind, KEYSTORE)}, {group.secret_name: ""})
        self.assertEqual(credentials.credential_values_from_environment(direct, required=required), canonical(group.kind, KEYSTORE))
        self.assertEqual(set(direct.reads), allowed)
        self.assertEqual(set(direct.reads.values()), {1})
        unused = INPUT_GROUP_ENVIRONMENT_NAMES - {group.secret_name}
        self.assertFalse(unused & direct.reads.keys())

    def test_wif_observes_only_its_three_fixed_keys_once(self):
        group = input_group("google-wif")
        legacy_pair = {**WIF, "serviceAccount": "legacy@example.iam.gserviceaccount.com"}
        for state in ("absent", "valid", "malformed"):
            initial = canonical(group.kind, legacy_pair)
            if state != "absent":
                initial[group.secret_name] = envelope(group.kind, WIF) if state == "valid" else "malformed-synthetic"
            observed = StatefulEnvironment(initial, {group.secret_name: envelope(group.kind, WIF)})
            with self.subTest(state=state):
                if state == "malformed":
                    with self.assertRaises(CredentialError):
                        google_wif_inputs(observed)
                else:
                    pair = WIF if state == "valid" else legacy_pair
                    self.assertEqual(google_wif_inputs(observed), {"provider": pair["provider"],
                                                                 "service_account": pair["serviceAccount"]})
            self.assertEqual(set(observed.reads), {group.secret_name, *(field.name for field in group.fields)})
            self.assertEqual(set(observed.reads.values()), {1})

    def test_closed_groups_match_all_guide_fields_and_core_classifications(self):
        guide = json.loads((SOURCE / "src/mobile_release/api/data/credential-guide-v1.json").read_bytes())
        actual = {group.kind: [(field.id, field.name, field.input) for field in group.fields] for group in INPUT_GROUPS}
        expected = {kind["id"]: [(field["id"], field["requirement"], field["input"]) for field in kind["fields"]]
                    for kind in guide["kinds"]}
        self.assertEqual(actual, expected)
        self.assertEqual((len(INPUT_GROUPS), sum(len(group.fields) for group in INPUT_GROUPS)), (11, 23))
        self.assertEqual({field.name for group in INPUT_GROUPS for field in group.fields}, set(ENVIRONMENT_INPUT_TYPES))
        self.assertEqual(len(INPUT_GROUP_ENVIRONMENT_NAMES), 11)
        for group in INPUT_GROUPS:
            self.assertEqual(group.secret_name, "MOBILE_RELEASE_INPUT_" + group.kind.upper().replace("-", "_") + "_V1")
            for field in group.fields:
                self.assertEqual(ENVIRONMENT_INPUT_TYPES[field.name], "variable" if field.input == "text" else "secret")

    def test_exact_schema_duplicates_and_invalid_values_never_reflect_input(self):
        good = {"protocol": INPUT_GROUP_PROTOCOL, "kind": "android-keystore", "values": dict(KEYSTORE)}
        variants = [
            {**good, "extra": "synthetic-private-marker"},
            {**good, "protocol": "wrong"},
            {**good, "kind": "apple-p12"},
            {**good, "values": []},
            {key: value for key, value in good.items() if key != "protocol"},
        ]
        for changed in (
            {key: value for key, value in KEYSTORE.items() if key != "keyPassword"},
            {**KEYSTORE, "path": "/synthetic-private-marker"},
            {**KEYSTORE, "keyPassword": "synthetic-private-marker\x00"},
            {**KEYSTORE, "storePassword": ""},
            {**KEYSTORE, "storePassword": "\ud800"},
            {**KEYSTORE, "keyAlias": None},
            {**KEYSTORE, "file": "Zh=="},  # decodes, but is not canonical Base64
            {**KEYSTORE, "file": ""},
        ):
            variants.append({**good, "values": changed})
        texts = [json.dumps(item) for item in variants]
        texts.extend((
            '{"protocol":"mrk-github-input-group/1","protocol":"mrk-github-input-group/1","kind":"android-keystore","values":{}}',
            '{"protocol":"mrk-github-input-group/1","kind":"android-keystore","values":{"file":"Zg==","file":"Zg=="}}',
            '{"protocol":"mrk-github-input-group/1","kind":"android-keystore","values":NaN}',
            " " * (INPUT_GROUP_MAX_BYTES + 1), "not-json-synthetic-private-marker",
        ))
        for index, text in enumerate(texts):
            with self.subTest(case=index), self.assertRaises(CredentialError) as caught:
                decode_group_envelope("android-keystore", text)
            self.assertNotIn("synthetic-private-marker", str(caught.exception))
        self.assertEqual(decode_group_envelope("android-keystore", json.dumps(good)), canonical("android-keystore", KEYSTORE))

    def test_public_and_commitment_formats_reuse_core_policy(self):
        for kind, field_id, invalid in (
            ("android-keystore", "keyAlias", "contains space"),
            ("asc-p8", "keyId", "short"),
            ("asc-p8", "issuerId", "not-a-uuid"),
            ("google-wif", "provider", WIF["provider"] + "\nextra"),
            ("google-wif", "serviceAccount", "not-an-email"),
            ("apple-review-contact", "email", "not-an-email"),
            ("apple-operation-commitment", "keyBase64", base64.b64encode(b"short").decode()),
            ("apple-operation-commitment", "keyVersion", "version with space"),
        ):
            group = input_group(kind)
            field = next(field for field in group.fields if field.id == field_id)
            with self.subTest(kind=kind, field=field_id), self.assertRaises(CredentialError):
                validate_input_field(group, field, invalid)

    def test_exact_encoded_plaintext_limit_including_multibyte_text(self):
        overhead = len(encode_group_envelope("project-read-token", {"token": "x"})) - 1
        available = INPUT_GROUP_MAX_BYTES - overhead
        for value in ("x" * available, "é" * (available // 2) + "x" * (available % 2)):
            encoded = encode_group_envelope("project-read-token", {"token": value})
            self.assertEqual(len(encoded), INPUT_GROUP_MAX_BYTES)
            self.assertEqual(decode_group_envelope("project-read-token", encoded.decode()),
                             {"MOBILE_RELEASE_PROJECT_READ_TOKEN": value})
            with self.assertRaises(CredentialError):
                encode_group_envelope("project-read-token", {"token": value + "x"})
        with self.assertRaises(CredentialError):
            decode_group_envelope("project-read-token", encoded.decode() + " ")

    def test_core_stage_platform_purpose_and_disabled_groups_select_whole_groups(self):
        complete = config()
        cases = (
            ("candidate", "signing", ("android",), {"android-keystore", "android-firebase", "project-read-token"}),
            ("candidate", "store", ("ios",), {"asc-p8"}),
            ("external-testing", "store", ("android",), {"google-wif"}),
            ("production", "store", ("ios",), {"asc-p8", "apple-review-contact", "apple-review-demo-account", "apple-operation-commitment"}),
        )
        for stage, purpose, platforms, expected in cases:
            with self.subTest(stage=stage, purpose=purpose):
                selected = groups_for_requirements(requirements(complete, stage, purpose=purpose, platforms=platforms))
                self.assertEqual({group.kind for group in selected}, expected)
        restricted = config(demo=False, firebase=False, project_token=False)
        self.assertEqual({group.kind for group in groups_for_requirements(requirements(restricted))},
                         {"android-keystore", "apple-p12", "apple-profile", "asc-p8", "google-wif",
                          "apple-review-contact", "apple-operation-commitment"})
        with self.assertRaises(CredentialError):
            groups_for_requirements([Requirement("MOBILE_RELEASE_ANDROID_KEY_ALIAS", "variable", "candidate", "android")])

    def test_envelope_replaces_the_whole_legacy_group_and_stale_path(self):
        group = input_group("android-keystore")
        source = {**canonical(group.kind, {**KEYSTORE, "storePassword": "legacy-store"}),
                  "MOBILE_RELEASE_ANDROID_KEYSTORE_PATH": "/synthetic-unopened/legacy.jks",
                  group.secret_name: envelope(group.kind, KEYSTORE), "UNRELATED": "untouched"}
        before = dict(source)
        resolved = credentials.resolve_credential_values(config(), credentials_from_env=True, environ=source)
        self.assertEqual(resolved, canonical(group.kind, KEYSTORE))
        self.assertEqual(source, before)
        self.assertTrue(all(name not in resolved for name in INPUT_GROUP_ENVIRONMENT_NAMES))

    def test_unused_envelopes_and_environment_mode_do_not_acquire_authority(self):
        source = {name: "malformed-synthetic" for name in INPUT_GROUP_ENVIRONMENT_NAMES}
        self.assertEqual(credentials.resolve_credential_values(config(), environ=source), {})
        self.assertEqual(credentials.credential_values_from_environment(source), {})
        required = requirements(config(), "external-testing", purpose="store", platforms=("android",))
        source[input_group("google-wif").secret_name] = envelope("google-wif", WIF)
        self.assertEqual(credentials.resolve_credential_values(config(), credentials_from_env=True, environ=source,
                                                              required=required), canonical("google-wif", WIF))
        disabled = config(demo=False, firebase=False, project_token=False)
        ignored = {input_group(kind).secret_name: "malformed-synthetic" for kind in
                   ("apple-review-demo-account", "android-firebase", "ios-firebase", "project-read-token")}
        self.assertEqual(credentials.resolve_credential_values(disabled, credentials_from_env=True, environ=ignored), {})

    def test_malformed_applicable_envelope_refuses_before_explicit_file_read(self):
        source = {input_group("android-keystore").secret_name: "malformed-synthetic"}
        with patch.object(credentials, "load_credentials_file", return_value=canonical("android-keystore", KEYSTORE)) as read:
            with self.assertRaises(CredentialError):
                credentials.resolve_credential_values(config(), credentials_file=Path("/synthetic-file"),
                                                      credentials_from_env=True, environ=source)
            read.assert_not_called()
            self.assertEqual(credentials.resolve_credential_values(config(), credentials_file=Path("/synthetic-file"),
                                                                   environ=source), canonical("android-keystore", KEYSTORE))

    def test_complete_file_override_and_partial_file_refusal_preserve_legacy_behavior(self):
        group = input_group("android-keystore")
        source = {group.secret_name: envelope(group.kind, KEYSTORE)}
        partial = {"MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD": "replacement"}
        with patch.object(credentials, "load_credentials_file", return_value=partial):
            with self.assertRaisesRegex(CredentialError, "complete android-keystore"):
                credentials.resolve_credential_values(config(), credentials_file=Path("/synthetic-file"),
                                                      credentials_from_env=True, environ=source)
            old = canonical(group.kind, KEYSTORE)
            resolved = credentials.resolve_credential_values(config(), credentials_file=Path("/synthetic-file"),
                                                             credentials_from_env=True, environ=old)
            self.assertEqual(resolved, {**old, **partial})
        whole = canonical(group.kind, {**KEYSTORE, "storePassword": "replacement", "keyAlias": "replacement"})
        with patch.object(credentials, "load_credentials_file", return_value=whole):
            self.assertEqual(credentials.resolve_credential_values(config(), credentials_file=Path("/synthetic-file"),
                                                                   credentials_from_env=True, environ=source), whole)
        invalid = {**whole, "MOBILE_RELEASE_ANDROID_KEY_ALIAS": "bad alias"}
        with patch.object(credentials, "load_credentials_file", return_value=invalid), self.assertRaises(CredentialError):
            credentials.resolve_credential_values(config(), credentials_file=Path("/synthetic-file"),
                                                  credentials_from_env=True, environ=source)

    def test_complete_file_path_override_keeps_the_original_path_validation_boundary(self):
        group = input_group("android-keystore")
        whole = canonical(group.kind, KEYSTORE)
        del whole["MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64"]
        path = "/synthetic-unopened/selected.jks"
        whole["MOBILE_RELEASE_ANDROID_KEYSTORE_PATH"] = path
        with patch.object(credentials, "load_credentials_file", return_value=whole), \
             patch.object(credentials, "_private_path_error", return_value=None) as private:
            resolved = credentials.resolve_credential_values(config(), credentials_file=Path("/synthetic-file"),
                credentials_from_env=True, environ={group.secret_name: envelope(group.kind, KEYSTORE)})
            self.assertEqual(resolved, whole)
            private.assert_called_once_with(path, config().root, cancellation=None)
        # Only routing is tested above; a rejected original reader is not bypassed.
        with patch.object(credentials, "load_credentials_file", return_value=whole), \
             patch.object(credentials, "_private_path_error", return_value="synthetic invalid source"), \
             self.assertRaises(CredentialError):
            credentials.resolve_credential_values(config(), credentials_file=Path("/synthetic-file"),
                credentials_from_env=True, environ={group.secret_name: envelope(group.kind, KEYSTORE)})

    def test_masking_is_explicit_private_single_line_and_all_groups_validate_first(self):
        group = input_group("apple-review-demo-account")
        values = {"username": "synthetic-user", "password": "synthetic%\r\n::warning::payload"}
        commands = group_mask_commands(group, canonical(group.kind, values))
        self.assertEqual(commands, ("::add-mask::synthetic-user", "::add-mask::synthetic%25%0D%0A::warning::payload"))
        self.assertEqual(group_mask_commands(input_group("google-wif"), canonical("google-wif", WIF)), ())
        source = {"GITHUB_ACTIONS": "true", group.secret_name: envelope(group.kind, values)}
        output = io.StringIO()
        with redirect_stdout(output):
            credentials.resolve_credential_values(config(), credentials_from_env=True, environ=source)
        self.assertEqual(output.getvalue(), "\n".join(commands) + "\n")
        output = io.StringIO()
        source[input_group("apple-p12").secret_name] = "malformed-synthetic"
        with redirect_stdout(output), self.assertRaises(CredentialError):
            credentials.resolve_credential_values(config(), credentials_from_env=True, environ=source)
        self.assertEqual(output.getvalue(), "")
        output = io.StringIO()
        with redirect_stdout(output):
            credentials.resolve_credential_values(config(), credentials_from_env=True,
                environ={group.secret_name: envelope(group.kind, values)})
        self.assertEqual(output.getvalue(), "")  # no terminal/passive-transport mask output

    def test_every_envelope_name_is_scrubbed_before_project_or_artifact_tools(self):
        source = {name: "synthetic-private" for name in INPUT_GROUP_ENVIRONMENT_NAMES}
        source.update({"PATH": "/synthetic-path", "LANG": "C"})
        self.assertTrue(all(credentials.is_credential_capability_name(name) for name in INPUT_GROUP_ENVIRONMENT_NAMES))
        self.assertEqual(credentials.scrub_credential_capabilities(source), {"PATH": "/synthetic-path", "LANG": "C"})
        self.assertFalse(INPUT_GROUP_ENVIRONMENT_NAMES & credentials.artifact_validation_environment(source).keys())

    def test_remote_name_inventory_recognizes_group_secret_without_claiming_content_validity(self):
        group = input_group("google-wif")
        with patch.object(credentials, "_github_names", return_value=({group.secret_name}, set(), None)) as query:
            rows = credentials.credential_findings(config(), stage="candidate", purpose="store",
                                                   platforms=("android",), github=True)
        query.assert_called_once_with(config().root, "mobile-candidate")
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row.status == Status.CONFIGURED and row.details["configuredName"] == group.secret_name for row in rows))
        self.assertTrue(all("content is not inspected" in row.remediation for row in rows))

    def test_preflight_actual_call_selects_only_its_mode_before_any_private_consumer(self):
        # Argument routing only: all earlier diagnostics are inert, and the
        # actual resolver boundary raises before any signing/build/Store work.
        for mode, expected in (("offline", {"project-read-token"}),
                               ("signing", {"android-keystore", "android-firebase", "project-read-token"}),
                               ("online", set())):
            seen = []
            original_stop = RuntimeError("synthetic stop at credential resolver")

            def capture(_config, **kwargs):
                seen.append({group.kind for group in groups_for_requirements(kwargs["required"])})
                raise original_stop

            invocation = SimpleNamespace(cancellation=object(), require=lambda **_kwargs: None)
            with self.subTest(mode=mode), patch.object(preflight, "doctor", return_value=Report(command="doctor")), \
                 patch.object(preflight, "metadata_findings", return_value=[]), \
                 patch.object(preflight, "resolve_credential_values", side_effect=capture), \
                 self.assertRaises(RuntimeError) as caught:
                preflight._preflight(config(), mode=mode, platforms=("android",), run_builds=False, invocation=invocation)
            self.assertIs(caught.exception, original_stop)
            self.assertEqual(seen, [expected])

    def test_store_consumer_maps_production_and_ignores_other_capability_groups(self):
        fixtures = {
            "google-wif": WIF,
            "asc-p8": {"file": base64.b64encode(b"synthetic-p8").decode(), "keyId": "ABCD123456",
                       "issuerId": "11111111-2222-3333-4444-555555555555"},
            "apple-review-contact": {"firstName": "Synthetic", "lastName": "Reviewer",
                                    "email": "synthetic@example.test", "phone": "+10000000000"},
            "apple-operation-commitment": {"keyBase64": base64.b64encode(b"s" * 32).decode(), "keyVersion": "v1"},
        }
        for stage, platform, expected in (
            ("candidate", "ios", {"asc-p8"}),
            ("external-testing", "ios", {"asc-p8", "apple-review-contact", "apple-operation-commitment"}),
            ("production-submit", "ios", {"asc-p8", "apple-review-contact", "apple-operation-commitment"}),
            ("candidate", "android", set()),
        ):
            source = {name: "malformed-unused-synthetic" for name in INPUT_GROUP_ENVIRONMENT_NAMES}
            wanted = {}
            for kind in expected:
                source[input_group(kind).secret_name] = envelope(kind, fixtures[kind])
                wanted.update(canonical(kind, fixtures[kind]))
            if platform == "android":
                source["GOOGLE_APPLICATION_CREDENTIALS"] = "/synthetic-unopened/adc.json"
                wanted["GOOGLE_APPLICATION_CREDENTIALS"] = source["GOOGLE_APPLICATION_CREDENTIALS"]
            before = dict(source)
            with self.subTest(stage=stage, platform=platform):
                result = stores._store_credential_values(config(demo=False),
                    SimpleNamespace(stage=stage, platform=platform), source)
                self.assertEqual(result, wanted)
                self.assertEqual(source, before)

    def test_wif_legacy_pair_validates_together_and_envelope_never_partially_falls_back(self):
        legacy = canonical("google-wif", WIF)
        self.assertEqual(google_wif_inputs(legacy), {"provider": WIF["provider"], "service_account": WIF["serviceAccount"]})
        for source in ({}, {"MOBILE_RELEASE_GOOGLE_WIF_PROVIDER": WIF["provider"]},
                       {**legacy, "MOBILE_RELEASE_GOOGLE_SERVICE_ACCOUNT": "invalid"},
                       {**legacy, input_group("google-wif").secret_name: '{"protocol":"wrong"}'}):
            with self.subTest(case=tuple(source)), self.assertRaises(CredentialError):
                google_wif_inputs(source)
        modern = {**WIF, "serviceAccount": "replacement@example.iam.gserviceaccount.com"}
        self.assertEqual(google_wif_inputs({**legacy, input_group("google-wif").secret_name: envelope("google-wif", modern)}),
                         {"provider": modern["provider"], "service_account": modern["serviceAccount"]})
        self.assertEqual(google_wif_inputs({**legacy, input_group("google-wif").secret_name: ""}),
                         google_wif_inputs(legacy))

    def test_workflow_command_only_appends_two_valid_public_outputs_without_release_authority(self):
        with tempfile.TemporaryDirectory(prefix="mrk-input-group-output-") as temporary:
            output = Path(temporary).resolve() / "runner-output"
            output.write_text("", encoding="utf-8")
            source = {input_group("google-wif").secret_name: envelope("google-wif", WIF), "GITHUB_OUTPUT": str(output)}
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.dict(os.environ, source, clear=True), \
                 patch.object(workflow.Context, "current", side_effect=AssertionError("unexpected release authority")), \
                 redirect_stdout(stdout), redirect_stderr(stderr):
                self.assertEqual(workflow.main(["google-wif-inputs"]), 0)
            expected = {"provider": WIF["provider"], "service_account": WIF["serviceAccount"]}
            self.assertEqual(json.loads(stdout.getvalue()), expected)
            self.assertEqual(output.read_text(), "".join(f"{key}={value}\n" for key, value in expected.items()))
            self.assertEqual(stderr.getvalue(), "")
            before = output.read_bytes()
            source[input_group("google-wif").secret_name] = "synthetic-private-invalid"
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.dict(os.environ, source, clear=True), redirect_stdout(stdout), redirect_stderr(stderr):
                self.assertEqual(workflow.main(["google-wif-inputs"]), 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(output.read_bytes(), before)
            self.assertIn("Google WIF", stderr.getvalue())
            self.assertNotIn("synthetic-private-invalid", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
