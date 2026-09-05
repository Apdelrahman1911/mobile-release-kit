from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mobile_release.errors import ValidationError
from mobile_release.provenance import (
    validate_create_retry_inventory,
    validate_receipt_chain,
    validate_receipt_raw_binding,
)

from unit.apple_contract_helpers import apple_samples, wrap_apple_contracts

try:
    import jsonschema
except ImportError:  # an explicit optional-test limitation, never a full-gate pass
    jsonschema = None


ROOT = Path(__file__).resolve().parents[2]
CASES = {
    "candidate", "candidate-retry", "external", "external-retry", "external-available", "production",
    "production-retry", "production-receipt-recovery", "production-screenshot-retry",
    "production-automatic-appinfo-retry",
}


class AppleContractTests(unittest.TestCase):
    """Cross the real Ruby JSON boundary, not a reimplementation of its states.

    The lane exporter uses the pinned SDK and synthetic HTTP transport. Python
    supplies only the additional repository/artifact envelopes absent from those
    deliberately minimal lane fixtures. This does not claim Store authentication,
    Apple-signed artifact validation, or live service compatibility.
    """

    def validate_samples(self, samples: dict, root: Path) -> dict:
        self.assertEqual(set(samples), CASES)
        config, documents = wrap_apple_contracts(root, samples=samples)
        schemas = {
            kind: json.loads((ROOT / "schemas" / name).read_text())
            for kind, name in {
                "intent": "store-operation-intent.schema.json",
                "receipt": "receipt.schema.json", "candidate": "candidate.schema.json",
            }.items()
        }
        if jsonschema is None and os.environ.get("MOBILE_RELEASE_REQUIRE_RUBY_CONTRACTS") == "1":
            self.fail("the required Ruby/Python/schema contract gate requires jsonschema")
        for name, value in documents.items():
            with self.subTest(case=name), patch.dict(os.environ, {}, clear=True):
                receipt, intent, candidate = value["receipt"], value["intent"], value["candidate"]
                stage = receipt["stage"]
                validate_receipt_raw_binding(receipt, store_receipt=value["raw"], operation_intent=intent, candidate_manifest=candidate)
                validate_receipt_chain(
                    candidate_manifest=candidate,
                    candidate_receipt=receipt if stage == "candidate" else documents["candidate"]["receipt"],
                    external_receipt=receipt if stage == "external-testing" else documents["external-available"]["receipt"] if stage == "production-submit" else None,
                    production_receipt=receipt if stage == "production-submit" else None,
                    candidate_intent=intent if stage == "candidate" else documents["candidate"]["intent"],
                    external_intent=intent if stage == "external-testing" else documents["external-available"]["intent"] if stage == "production-submit" else None,
                    production_intent=intent if stage == "production-submit" else None,
                    platform="ios", config=config,
                )
                if jsonschema is not None:
                    for kind, schema in schemas.items():
                        jsonschema.Draft202012Validator(schema).validate(value[kind])
                original_raw = samples[name]["receipt"]
                self.assertEqual(original_raw["schemaVersion"], 3)
                # The envelope helper must not rewrite observed state to fit the
                # Python consumer. Only synthetic outer intent hashes change.
                for field in set(original_raw) - {"operationIntentSha256", "createRetry"}:
                    self.assertEqual(value["raw"][field], original_raw[field], field)
                self.assertEqual(receipt["readback"]["state"], original_raw["state"])
                self.assertEqual(receipt["readback"]["observedAt"], original_raw["observedAt"])
                if stage == "external-testing":
                    external = intent["storePrecondition"]["snapshot"]["external"]
                    before = {item["locale"]: item for item in external["localizations"]}
                    target = {item["locale"]: item["whatsNew"] for item in external["targetLocalizations"]}
                    self.assertEqual(before["ja"]["id"], "locale-unconfigured")
                    self.assertEqual(target["ja"], "  Unconfigured 日本語 <keep> 🧪\n\n")
                    self.assertEqual(target["ja"], before["ja"]["whatsNew"])
                    self.assertEqual(set(target), {"en-US", "fr-FR", "de-DE", "ja"})
                    for locale in config.section("metadata")["iosLocales"]:
                        self.assertEqual(target[locale], "Test the fictional workflow")
                if stage == "production-submit":
                    self.assertIs(receipt["destination"]["automaticRelease"], False)
        self.assertEqual(documents["production-receipt-recovery"]["receipt"]["outcome"], "reconciled")
        self.assertEqual(documents["candidate-retry"]["receipt"]["outcome"], "operator-authorized-retry")
        self.assertEqual(documents["external-retry"]["receipt"]["outcome"], "operator-authorized-create-retry")
        self.assertEqual(documents["external"]["receipt"]["readback"]["state"], "submitted-for-review")
        self.assertEqual(documents["external-available"]["receipt"]["readback"]["state"], "available-to-testers")
        with self.assertRaisesRegex(ValidationError, "available-to-testers"):
            validate_receipt_chain(
                candidate_manifest=documents["candidate"]["candidate"],
                candidate_receipt=documents["candidate"]["receipt"],
                external_receipt=documents["external"]["receipt"],
                candidate_intent=documents["candidate"]["intent"],
                external_intent=documents["external"]["intent"],
                platform="ios", config=config, require_production_eligible_external=True,
            )
        return documents

    def test_checked_in_actual_lane_samples_validate_python_and_schema_contracts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            self.validate_samples(apple_samples(), Path(temporary))

    def test_real_lane_export_is_deterministic_and_matches_checked_in_contract(self) -> None:
        required = os.environ.get("MOBILE_RELEASE_REQUIRE_RUBY_CONTRACTS") == "1"

        def unavailable(reason: str) -> None:
            if required:
                self.fail(reason)
            self.skipTest(reason)

        if not shutil.which("ruby") or not shutil.which("bundle"):
            unavailable("Ruby 3.3 and the locked Fastlane bundle are unavailable")
        # Never pass Store/signing/GitHub credentials, user-controlled preload
        # flags or caller Gemfiles into the credential-free simulation.
        names = {"PATH", "HOME", "GEM_HOME", "GEM_PATH", "BUNDLE_PATH", "LANG", "LC_ALL", "TMPDIR"}
        env = {name: os.environ[name] for name in names if os.environ.get(name)}
        env.update({
            "BUNDLE_GEMFILE": str(ROOT / "Gemfile"), "BUNDLE_FROZEN": "true",
            "FASTLANE_SKIP_UPDATE_CHECK": "true", "FASTLANE_OPT_OUT_USAGE": "true",
        })
        ruby = subprocess.run(["ruby", "-e", "print RUBY_VERSION"], cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
        if ruby.returncode or not ruby.stdout.startswith("3.3."):
            unavailable("the actual lane contract requires the repository's Ruby 3.3.x")
        bundle = subprocess.run(["bundle", "check"], cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
        if bundle.returncode:
            unavailable("the actual lane contract requires bundle install from the pinned lockfile")
        with tempfile.TemporaryDirectory(prefix="mrk-apple-contract-") as temporary:
            root = Path(temporary)
            outputs = [root / f"export-{index}.json" for index in range(2)]
            for output in outputs:
                completed = subprocess.run(
                    ["bundle", "exec", "ruby", "tests/workflow/export_apple_contract_fixtures.rb", str(output)],
                    cwd=ROOT, env=env, capture_output=True, text=True, timeout=180,
                )
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                self.assertTrue(output.is_file(), "the exporter exited without producing its contract")
            self.assertEqual(outputs[0].read_bytes(), outputs[1].read_bytes())
            generated = json.loads(outputs[0].read_text())
            self.assertEqual(generated["format"], "mrk-synthetic-apple-contract-v1")
            self.assertEqual(generated["cases"], apple_samples(), "regenerate and review the actual lane fixture after contract changes")
            self.validate_samples(generated["cases"], root / "python-consumer")

    def test_retry_graph_rejects_wrong_targets_parents_and_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _, documents = wrap_apple_contracts(Path(temporary))
        checked = 0
        for case, value in documents.items():
            if "createRetry" not in value["raw"]:
                continue
            original = value["raw"]["createRetry"]["inventory"]
            intent = value["intent"]
            validate_create_retry_inventory(original, operation_intent=intent)
            for index, node in enumerate(original["creates"]):
                mutations = [lambda item: item.update(targetSha256="f" * 64)]
                parent = node["parent"]
                if parent["mode"] == "present" and parent["resourceType"] in {"apps", "builds", "appInfos"}:
                    mutations.append(lambda item: item["parent"].update(id="unrelated-parent"))
                elif parent["mode"] == "missing":
                    mutations.append(lambda item: item["parent"].update(logicalKeySha256="e" * 64))
                elif parent["mode"] == "automatic":
                    mutations.append(lambda item: item["parent"].update(referenceSha256="e" * 64))
                if node["dependencies"]:
                    mutations.append(lambda item: item.update(dependencies=[]))
                else:
                    mutations.append(lambda item: item.update(dependencies=[item["logicalKeySha256"]]))
                for mutate in mutations:
                    changed = copy.deepcopy(original)
                    mutate(changed["creates"][index])
                    with self.subTest(case=case, resource=node["resourceType"]), self.assertRaises(ValidationError):
                        validate_create_retry_inventory(changed, operation_intent=intent)
                    checked += 1
        self.assertGreater(checked, 70)


if __name__ == "__main__":
    unittest.main()
