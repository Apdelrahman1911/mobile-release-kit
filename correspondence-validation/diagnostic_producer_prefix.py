"""Disabled hosted-only producer prefix for a separate correspondence diagnostic.

The producer_prefix body reuses the frozen package_install prefix, omitting
only its downstream readback-module preload and renaming the method. It ends
after authenticated producer emission.
No ordinary Installer, distribution image, observation or carrier success.
"""
import argparse
import os
import platform
import sys
import time
from pathlib import Path
from desktop.tools import macos_android_helper_package as helper

EXECUTION_BINDING = None
need = helper.need
digest = helper.digest
build_environment = helper.build_environment
package_timeout_data = helper.package_timeout_data
REMOVAL_REF = helper.REMOVAL_REF


class PrefixOwner(helper.Operation):
    def package_compiler_seconds(self):
        # This separately bound diagnostic consumer is deliberately NOT marked
        # native-compatible with the signed product. Its compiler still uses
        # the same frozen producer graph on a cold hosted runner. Select the
        # existing prepared producer budget without widening Installer clocks.
        binding = EXECUTION_BINDING
        prepared = self.prepared_binding
        need(type(binding) is dict and binding.get("executionApproved") is True
             and self.phase == "package-install" and self.target == helper.ARM_TARGET
             and self.checkout == Path("/Users/runner/work/mobile-release-kit/mobile-release-kit/prepared-built-source")
             and prepared is not None and prepared.source == binding["productSource"]
             and prepared.origin == binding["preparedOrigin"]
             and prepared.manifest["packageRole"] == "ordinary-image"
             and "nativeScope" not in prepared.origin
             and self.environment.get("GITHUB_SHA") == self.environment.get("GITHUB_WORKFLOW_SHA") == binding["runnerSourceCommit"]
             and self.environment.get("GITHUB_REF") == "refs/heads/" + binding["runnerBranch"]
             and self.environment.get("GITHUB_JOB") == "correspondence-diagnostic",
             "diagnostic-producer-cold-profile-binding")
        return 900

    def producer_prefix(self):
        self.stage = "package-final-audit"
        if self.app_absence is None:
            self.package_started = self.package_observed = time.monotonic_ns()
            self.package_endpoint = self.package_started + (990 + self.package_compiler_seconds() - 480) * 1_000_000_000
        self.package_clock()
        if self.environment.get("GITHUB_REF") == REMOVAL_REF:
            self.removal_baseline_admit()
        inventory_hash, manifest_hash = (self.environment.get(name) for name in
            ("MRK_MACOS_INSTALL_INVENTORY_SHA256", "MRK_BUNDLED_RUNTIME_MANIFEST_SHA256"))
        need(self.stager.maintenance_hex(inventory_hash, 64) and self.stager.maintenance_hex(manifest_hash, 64), "package-compiled-bindings")
        selection = self.stager.BuildSelection(self.target, self.stager.build_release_data(self.read(self.release_entry), target=self.target)["packageVersion"], self.image_release)
        # Producer-only scope has no later observation/readback consumer.
        # Omit the ordinary route's downstream readback-module preload here.
        source = self.stager.packaging_signing_data(self.producer_profile, self.service_profile)
        need(self.signing == (source.team, source.leaf_sha1), "package-source-signing-selection")
        original = self.original(self.directory(self.work_entry, "package-final", "package-final"), "MobileReleaseKit.pkg",
                                 "final-package-original", self.stager.MAX_BYTES, (0o444,))
        body = self.read(original)
        finalization = self.package_finalization_input(original, body)
        audit = self.package_stager_io("final-audit", argparse.Namespace(target=self.target, fixture=False,
            store_runtime=self.selected_package_store(),
            scripts=self.work / "scripts", package=self.work / "package-final/MobileReleaseKit.pkg",
            original_package=self.work / "MobileReleaseKit-original.pkg"))
        need(audit["packageSha256"] == digest(body) and audit["packageSize"] == len(body)
             and self.read(original) == body
             and all(audit[key] == finalization[key] for key in ("originalPackageSha256", "packageInfoSha256", "scriptFileCount")),
             "package-final-audit-original")
        self.package_outputs.append((original, digest(body)))
        self.publish("package-audit.json", self.stager.canonical(audit) + b"\n")
        self.package_clock()
        history_entry = self.source_original("desktop/macos-installed-inputs/producer-history.json", "source-producer-history", self.stager.PRODUCER_DESCRIPTOR_BYTES)
        history = self.read(history_entry)
        self.package_sources.append((history_entry, history))
        for name in ("leaf.der", "issuer.der", "root.der"):
            entry = self.source_original("desktop/packaging/macos-install-producer-certificates/" + name, "source-producer-" + name, 16384)
            self.package_sources.append((entry, self.read(entry)))
        source_inventory = self.original(self.directory(self.work_entry, "input", "package-input"), self.stager.INSTALLATION_INVENTORY_NAME,
            "package-source-inventory", self.stager.INVENTORY_BYTES, (0o444,))
        inventory = self.read(source_inventory)
        self.stager.observation_inventory_bytes(inventory, inventory_hash, manifest_hash, selection=selection)
        self.package_outputs.append((source_inventory, digest(inventory)))
        descriptor = self.stager.packaging_descriptor_data(history, source, selection, source_commit=self.image_source,
            manifest=manifest_hash, inventory=inventory_hash, package=digest(body))
        root = self.package_directory("producer-root")
        self.package_file(root, "Install.pkg", body)
        self.package_file(self.work_entry, "producer-descriptor-input.json", descriptor)
        self.package_post()
        self.stage = "package-explicit-producer-compiler"
        environment = build_environment(self.environment, self.work, self.image_release, target=self.target)
        environment.update(CARGO_TARGET_DIR=str(self.work / self.target_name), TMPDIR=str(self.work / self.target_name / "tmp"),
            MRK_BUNDLED_RUNTIME_MANIFEST_SHA256=manifest_hash, MRK_MACOS_INSTALL_INVENTORY_SHA256=inventory_hash)
        if self.prepared_binding is not None:
            # Compile only the existing producer from its actual built SOURCE;
            # the real consumer GITHUB_* identity is never relabeled.
            environment["MRK_MACOS_INSTALL_SOURCE_COMMIT"] = self.prepared_binding.source
        binary = self.package_producer_compile(environment)
        binary_dir = self.descend(self.target_entry, (self.target, "release", "examples"))
        executable = self.original(binary_dir, binary.name, "producer-compiled-example", 64 * 1024 * 1024, (0o700, 0o755), alias=True)
        executable_body = self.read(executable)
        self.stager.macho(executable_body, system_only=True, target=self.target)
        # Cargo may retain an alias. Execute only a fresh single-link copy, not
        # either compiler-owned name; keep the original through copy POST.
        producer = self.producer_signing_copy(executable, executable_body)
        with self.credential_scope("producer", producer=producer):
            self.stage = "package-producer-emission"
            need(package_timeout_data(self.package_clock(), self.package_endpoint, 123) == 123, "producer-original-clock-reserve")
            emitted = self.package_call("producer-emitter", [str(self.work / "macos-package-producer"), "--package-root", str(self.work / "producer-root"),
                "--descriptor-input", str(self.work / "producer-descriptor-input.json")], timeout=123, limit=4096)
            signed_entry = self.original(root, "producer.sig", "producer-original-signature", self.stager.PRODUCER_SIGNATURE_BYTES, (0o444,))
            descriptor_entry = self.original(root, "producer.json", "producer-original-descriptor", self.stager.PRODUCER_DESCRIPTOR_BYTES, (0o444,))
            signed, actual_descriptor = self.read(signed_entry), self.read(descriptor_entry)
            need(actual_descriptor == descriptor, "producer-exact-descriptor-emission")
            summary = self.stager.emitted_package_data(emitted.stdout, emitted.stderr, emitted.returncode, body, actual_descriptor, signed, target=self.target)
            self.package_outputs.extend(((signed_entry, digest(signed)), (descriptor_entry, digest(descriptor))))
        # Existing held originals POST after the complete credential context.
        expected = {"Install.pkg": body, "producer.json": descriptor, "producer.sig": signed}
        self.stager.distribution_layout_data(os.listdir(root["fd"]), "Install.pkg", expected,
            {name: (value, 0o444) for name, value in expected.items()})
        self.package_roots.append((root, set(expected)))
        self.package_post()
        self.prefix_inputs = expected
        self.prefix_summary = summary
        self.sha256 = digest(body)
        self.prefix_complete = True

    def execute_prefix(self):
        binding = EXECUTION_BINDING
        # Refuse before self.open(), platform native calls or credential access.
        need(type(binding) is dict and binding.get("executionApproved") is True,
             "diagnostic-prefix-not-reviewed")
        environment = self.environment
        need(sys.platform == "darwin" and platform.machine() == "arm64"
             and environment.get("GITHUB_ACTIONS") == "true"
             and environment.get("RUNNER_ENVIRONMENT") == "github-hosted"
             and environment.get("RUNNER_OS") == "macOS"
             and environment.get("RUNNER_ARCH") == "ARM64"
             and environment.get("GITHUB_REPOSITORY") == "Apdelrahman1911/mobile-release-kit"
             and environment.get("GITHUB_EVENT_NAME") == "push"
             and environment.get("GITHUB_REF") == "refs/heads/" + binding["runnerBranch"]
             and environment.get("GITHUB_SHA") == environment.get("GITHUB_WORKFLOW_SHA") == binding["runnerSourceCommit"]
             and environment.get("GITHUB_JOB") == "correspondence-diagnostic"
             and self.checkout == Path("/Users/runner/work/mobile-release-kit/mobile-release-kit/prepared-built-source")
             and self.phase == "package-install" and self.target == helper.ARM_TARGET
             and self.prepared_binding is not None
             and self.prepared_binding.source == binding["productSource"]
             and self.prepared_binding.origin == binding["preparedOrigin"], "diagnostic-prefix-fixed-host")
        need(self.app_absence is None and self.update is None and self.candidate_removal_context is None
             and getattr(self, "candidate_restore_context", None) is None and not self.setup_verify
             and self.store_signing is None and self.android_support is None,
             "diagnostic-prefix-one-purpose")
        self.prefix_inputs = None
        self.prefix_summary = None
        self.prefix_complete = False
        self.receipt.update(scope="correspondence-diagnostic-producer-prefix", ordinaryCarrier=False,
            ordinaryInstaller=False, installationQualified=False, signedInputPairReady=False)
        primary = None
        try:
            self.open()
            head = self.source_original(".git/HEAD", "prepared-built-source-head", 64)
            body = self.read(head)
            need(body == (self.prepared_binding.source + "\n").encode("ascii"), "prepared-built-source-head")
            self.package_sources.append((head, body))
            self.profile_entry = self.source_original(helper.PROFILE, "source-signing-profile", 1024)
            self.service_profile = self.read(self.profile_entry)
            self.signing = self.stager.service_signing_data(self.service_profile)
            self.producer_profile_entry = self.source_original(helper.PRODUCER_PROFILE, "source-producer-profile", 1024)
            self.producer_profile = self.read(self.producer_profile_entry)
            selection = self.stager.packaging_signing_data(self.producer_profile, self.service_profile,
                allow_unconfigured=False)
            need((selection is None) == (self.signing is None), "source-signing-profile-pair")
            self.package_sources.extend(((self.profile_entry, self.service_profile),
                                         (self.producer_profile_entry, self.producer_profile)))
            need(self.environment.get("MRK_MACOS_PACKAGE_ROLE") == "ordinary-image", "source-package-role")
            release_body = self.image_binding()
            self.package_sources.append((self.release_entry, release_body))
            self.producer_prefix()
            need(self.read(self.profile_entry) == self.service_profile
                 and self.read(self.producer_profile_entry) == self.producer_profile,
                 "source-signing-profile-changed")
            need(self.read(self.release_entry) == release_body, "source-image-release-changed")
            need(self.sha256 == binding["package"]["sha256"]
                 and len(self.prefix_inputs["Install.pkg"]) == binding["package"]["bytes"],
                 "diagnostic-prefix-same-package")
            self.package_clock()
        except BaseException as error:
            primary = error
            try:
                self.diagnostic_failure = helper.failure_exception(error, self.stager_failure_module)
            except BaseException:
                pass  # Do not replace the same original failure or its cleanup.
            try:
                self.stager_failure_line = helper.failure_stager_line(error, self.stager_failure_module)
            except BaseException:
                pass  # Location is optional and never changes original finality.
            self.receipt["failure"] = {"stage": self.stage, "type": type(error).__name__,
                                       "reason": str(error) if type(error) is helper.Refused else "original-operation-refused"}
            captured = self.diagnostic_failure
            if (type(self.stager_failure_module) is type(sys) and type(error) is self.stager_failure_module.__dict__.get("Refused")
                    and type(captured) is dict and all(type(key) is str for key in captured)
                    and tuple(captured) == ("type", "reason", "errno")
                    and type(captured["type"]) is str and captured["type"] == "stager-refused"
                    and type(captured["reason"]) is str
                    and (captured["reason"] in helper.DISTRIBUTION_STAGER_REASONS
                         or self.phase in helper.FINAL_IMAGE_PHASES and self.stage in helper.FINAL_IMAGE_INPUT_STAGES
                         and captured["reason"] in helper.FINAL_IMAGE_INPUT_STAGER_REASONS)
                    and captured["errno"] is None):
                self.receipt["failure"]["reason"] = captured["reason"]
            if isinstance(error, OSError):
                number = OSError.errno.__get__(error)
                if type(number) is int and 0 < number < 65536:
                    self.receipt["failure"]["errno"] = number
        finally:
            # Existing owner consumes original process/capture/artifact closes,
            # credential cleanup, and its own compiler target retirement.
            self.finish()
        credential_roles = (("producer-adhoc", "producer-adhoc-verify", "producer-cdhash")
            + helper.CREDENTIAL_ROLES[:17] + ("search-final", "default-after"))
        passed = (primary is None and self.prefix_complete and self.package_settled()
            and self.receipt["originalClosesKnown"] and self.receipt["targetRetired"]
            and tuple(row["role"] for row in self.calls) == ("producer-tests", "producer-build", "producer-emitter")
            and all(row["returned"] and row.get("capturesSettled") is True and row["returncode"] == 0 for row in self.calls)
            and tuple(row["role"] for row in self.credential_calls) == credential_roles
            and all(row["status"] == 0 for row in self.credential_calls)
            and tuple(row["purpose"] for row in self.credential_contexts) == ("producer",)
            and all(all(row[key] is True for key in ("retired", "closed", "searchRestored", "defaultUnchanged"))
                    for row in self.credential_contexts)
            and not self.credential_failed and self.credential_active is None
            and not self.mount_entered and not self.installer_entered and not self.installer_zero
            and not self.installation_readback)
        self.receipt["passed"] = bool(passed)
        self.receipt["signedInputPairReady"] = bool(passed)
        if passed:
            self.receipt["inputEvidence"] = {name: {"bytes": len(body), "sha256": digest(body)}
                                           for name, body in self.prefix_inputs.items()}
            self.receipt["producerSummary"] = self.prefix_summary
            self.package_clock()
        try:
            self.publish_receipt()
        except BaseException as publication_error:
            try:
                helper.emit_failure_diagnostic(primary if primary is not None else publication_error,
                    phase=self.phase, target=self.target, main_stage="operation-execute", operation=self, stager=self.stager)
            except BaseException:
                pass
            raise
        if passed:
            self.package_clock()
            return self.prefix_inputs, self.receipt
        error = primary if primary is not None else helper.Refused("diagnostic-prefix-finality-incomplete")
        # Same bounded ordinary failure projection; no additional native calls.
        try:
            helper.emit_failure_diagnostic(error, phase=self.phase, target=self.target,
                main_stage="operation-execute", operation=self, stager=self.stager)
        except BaseException:
            pass
        raise error
