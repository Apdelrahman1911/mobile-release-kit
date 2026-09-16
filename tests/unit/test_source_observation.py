"""Fresh source authority is observed, not copied from dispatch metadata.

ObservedSourceContractTests replaces only the owned command/read seams and is
inert. ObservedSourceGitTests executes real Git through the existing command
owner and requires the reviewed disposable/native test domain. It must not be
run as a raw suite on a shared host. No Store or network operation is performed.
"""
from __future__ import annotations

import io
import json
import os
import stat
import unittest
from contextlib import ExitStack, redirect_stdout
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mobile_release import discovery, provenance
from mobile_release.errors import MutationGuardError, ValidationError
from mobile_release.owned_process import ProcessCleanupError, ProcessError, run_owned

from .evidence_helpers import git_identity, workflow_environment
from .test_owned_process_callers import settled_native_fixture


HEAD = ["git", "rev-parse", "--verify", "HEAD"]


class ObservedSourceContractTests(unittest.TestCase):
    def guard(self, source):
        from mobile_release.config import ReleaseConfig, ReleaseVersion
        from mobile_release.stores import StoreRequest, guard_ci_mutation
        from .helpers import android_config

        root = Path("/fictional/project")
        config = ReleaseConfig(root / "release/mobile-release.json", root, android_config())
        request = StoreRequest("candidate", "android", "candidate:android:1.2.3:42", True, root)
        # No filesystem/config loading, authentication, native command or Store
        # access: this calls the actual pure guard with an exact source context.
        return guard_ci_mutation(request=request, config=config, release=ReleaseVersion("1.2.3", 42),
                                 git=source, environ=workflow_environment(head=source.commit))

    def observe(self, *, head="2" * 40, tree="3" * 40, status="", end="2" * 40):
        reads = []
        heads = iter((head, end))

        def read(root, argv, **kwargs):
            reads.append(tuple(argv))
            if argv == HEAD:
                return next(heads)
            if argv[:3] == ["git", "rev-parse", "--verify"]:
                self.assertEqual(argv, ["git", "rev-parse", "--verify", f"{head}^{{tree}}"])
                return tree
            if argv[:2] == ["git", "status"]:
                return status
            if argv == ["git", "branch", "--show-current"]:
                return ""  # A detached checkout still has its dispatch ref.
            self.fail(f"unexpected source-observation command: {argv!r}")

        env = workflow_environment(head="a" * 40)
        with patch.object(discovery, "_run", side_effect=read):
            source = discovery.git_context(Path("/fictional/project"), env)
        return source, reads

    def test_source_predicate_and_fresh_provenance_require_full_ids_and_exact_clean(self):
        valid = git_identity()
        self.assertTrue(discovery.valid_observed_source(valid))
        self.guard(valid)
        self.assertEqual(provenance._source(valid, include_ref=True), {
            "commit": valid.commit, "tree": valid.tree, "ref": valid.ref,
        })
        cases = [replace(valid, **{field: value})
                 for field in ("commit", "tree")
                 for value in (None, "", "2" * 39, "2" * 41, "g" * 40, "2" * 40 + "\n", 7)]
        cases += [replace(valid, dirty=value) for value in (None, True, 0, "")]
        for source in cases:
            with self.subTest(source=source):
                self.assertFalse(discovery.valid_observed_source(source))
                with self.assertRaisesRegex(ValidationError, "observed.*provably clean"):
                    provenance._source(source, include_ref=False)
                with self.assertRaisesRegex(MutationGuardError,
                        "source identity is incomplete|observed full Git commit/tree"):
                    self.guard(source)

    def test_observed_source_is_independent_of_hint_and_detached_dispatch_ref(self):
        source, reads = self.observe()
        self.assertTrue(discovery.valid_observed_source(source))
        self.assertEqual((source.commit, source.tree), ("2" * 40, "3" * 40))
        self.assertEqual((source.ref, source.branch), ("refs/heads/main", ""))
        self.assertEqual(reads[:4], [tuple(HEAD),
            ("git", "rev-parse", "--verify", "2" * 40 + "^{tree}"),
            ("git", "status", "--porcelain=v1", "--untracked-files=normal", "--ignore-submodules=none"),
            tuple(HEAD)])
        self.assertEqual(set(source.as_dict()), {
            "repository", "repositoryId", "commit", "tree", "ref", "branch", "dirty",
        })

    def test_missing_malformed_dirty_or_drifting_reads_never_borrow_dispatch_authority(self):
        cases = [dict(head=value) for value in (None, "", "bad", "2" * 39, "2" * 41)]
        cases += [dict(tree=value) for value in (None, "", "not-a-tree", "3" * 39)]
        cases += [dict(status=value) for value in (None, " M tracked.txt", "?? new.txt")]
        cases += [dict(end=value) for value in (None, "", "bad", "b" * 40)]
        for values in cases:
            with self.subTest(reads=values):
                source, reads = self.observe(**values)
                self.assertFalse(discovery.valid_observed_source(source))
                with self.assertRaises(ValidationError):
                    provenance._source(source, include_ref=True)
                with self.assertRaisesRegex(MutationGuardError,
                        "source identity is incomplete|observed full Git commit/tree"):
                    self.guard(source)
                if "head" in values or "end" in values:
                    self.assertIsNone(source.commit)
                    self.assertIsNone(source.tree)
                if "head" in values:
                    self.assertFalse(any(read[-1].endswith("^{tree}") for read in reads))
                if values.get("status", "") is None:
                    self.assertIsNone(source.dirty)
                self.assertNotEqual(source.commit, "a" * 40)

    def test_git_runtime_removes_routing_config_and_credentials_but_preserves_owner(self):
        ambient = {
            "PATH": "/usr/bin:/bin", "HOME": "/fictional/home",
            "XDG_CONFIG_HOME": "/fictional/config", "GIT_DIR": "/other/.git",
            "GIT_COMMON_DIR": "/other/.git", "GIT_WORK_TREE": "/other",
            "GIT_INDEX_FILE": "/other/index", "GIT_OBJECT_DIRECTORY": "/other/objects",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/other/alternate",
            "GIT_CONFIG": "/other/config", "GIT_CONFIG_SYSTEM": "/other/system",
            "GIT_CONFIG_GLOBAL": "/other/global", "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.bare", "GIT_CONFIG_VALUE_0": "true",
            "GIT_CONFIG_PARAMETERS": "'core.bare=true'", "GIT_EXEC_PATH": "/other/bin",
            "GIT_PAGER": "/other/pager", "GIT_SSH_COMMAND": "/other/ssh",
            "GIT_TRACE": "/other/trace", "GIT_NO_LAZY_FETCH": "0",
            "GIT_ALLOW_PROTOCOL": "https:ssh",
            "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64": "fictional",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "fictional",
            "GOOGLE_APPLICATION_CREDENTIALS": "/fictional/adc",
        }
        result = SimpleNamespace(returncode=0, stdout="2" * 40 + "\n")
        scope, guard = object(), object()
        source = SimpleNamespace(new_scope=Mock(return_value=scope))
        root = Path("/fictional/project")
        with patch.dict(os.environ, ambient, clear=True), \
             patch.object(discovery, "run_owned", return_value=result) as run:
            self.assertEqual(discovery._run(root, HEAD, execution_source=source,
                                           cancellation=guard), "2" * 40)
            self.assertEqual(dict(os.environ), ambient)
        source.new_scope.assert_called_once_with()
        argv = run.call_args.args[0]
        self.assertEqual(argv, ["git", "--no-pager", "--no-replace-objects",
            "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull,
            "-c", "core.untrackedCache=false", "-c", "protocol.allow=never", *HEAD[1:]])
        self.assertEqual(run.call_args.kwargs["environ"], {
            "PATH": ambient["PATH"], "LANG": "C", "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
            "GIT_ALLOW_PROTOCOL": "", "GIT_PAGER": "cat",
        })
        self.assertIs(run.call_args.kwargs["execution_scope"], scope)
        self.assertIs(run.call_args.kwargs["cancellation"], guard)
        self.assertEqual(run.call_args.kwargs["cwd"], root)
        self.assertEqual(run.call_args.kwargs["timeout"], 10)
        self.assertEqual(run.call_args.kwargs["output_limit"], discovery.OUTPUT_LIMIT)
        self.assertTrue(run.call_args.kwargs["capture"])

    def test_fatal_owner_errors_and_original_interruptions_stop_further_reads(self):
        errors = (ProcessCleanupError("fictional cleanup", dispatched=True),
                  ProcessError("fictional containment", dispatched=True, contained=False),
                  KeyboardInterrupt(), SystemExit(73))
        for error in errors:
            with self.subTest(kind=type(error).__name__), \
                 patch.object(discovery, "run_owned", side_effect=error) as run, \
                 self.assertRaises(type(error)) as raised:
                discovery.git_context(Path("/fictional/project"), workflow_environment())
            self.assertIs(raised.exception, error)
            run.assert_called_once()

    def test_contained_unavailable_read_is_unknown_and_empty_success_remains_distinct(self):
        root = Path("/fictional/project")
        with patch.object(discovery, "run_owned", side_effect=ProcessError("fictional unavailable")):
            self.assertIsNone(discovery._run(root, HEAD))
        for code, text, expected in ((1, "2" * 40, None), (0, "", "")):
            with self.subTest(code=code), patch.object(discovery, "run_owned",
                    return_value=SimpleNamespace(returncode=code, stdout=text)):
                self.assertEqual(discovery._run(root, HEAD), expected)


class ObservedSourceGitTests(unittest.TestCase):
    """Actual owner/Git evidence, only in the reviewed disposable test domain."""

    def git(self, root, *args):
        env = {"PATH": os.environ.get("PATH", os.defpath), "LANG": "C", "LC_ALL": "C",
               "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
               "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1"}
        result = run_owned(["git", "--no-pager", "-c", "core.hooksPath=" + os.devnull,
                            "-c", "core.fsmonitor=false", "-c", "commit.gpgSign=false",
                            "-c", "user.name=Fictional Fixture",
                            "-c", "user.email=fixture@example.invalid", *args],
                           cwd=root, environ=env, timeout=15)
        self.assertEqual(result.returncode, 0, "owned fictional Git setup did not complete")
        return result.stdout.strip()

    def repository(self, parent, *, release_project=False):
        root = parent / "project"
        root.mkdir(mode=0o700)
        if release_project:
            from .helpers import android_config, write_project

            write_project(root, android_config())
            # The existing lifecycle helper writes only these fixture artifacts;
            # they are intentionally outside the committed application source.
            with (root / ".gitignore").open("a", encoding="utf-8") as ignored:
                ignored.write("/app.aab\n/store-metadata.zip\n/validation-report.json\n")
        self.git(root, "init", "-q", "--initial-branch=main")
        (root / "source.txt").write_text("source A\n", encoding="utf-8")
        self.git(root, "add", ".")
        self.git(root, "commit", "-qm", "Source A")
        first = self.git(root, "rev-parse", "--verify", "HEAD")
        first_tree = self.git(root, "rev-parse", "--verify", "HEAD^{tree}")
        (root / "source.txt").write_text("source B\n", encoding="utf-8")
        self.git(root, "commit", "-qam", "Source B")
        second = self.git(root, "rev-parse", "--verify", "HEAD")
        second_tree = self.git(root, "rev-parse", "--verify", "HEAD^{tree}")
        self.assertNotEqual(first, second)
        self.assertNotEqual(first_tree, second_tree)
        return root, first, first_tree, second, second_tree

    def snapshot(self, directory):
        result = {}
        for path in sorted(directory.rglob("*")):
            value = path.lstat()
            self.assertTrue(stat.S_ISREG(value.st_mode) or stat.S_ISDIR(value.st_mode))
            result[path.relative_to(directory)] = (
                value.st_ino, stat.S_IMODE(value.st_mode), value.st_mtime_ns,
                path.read_bytes() if stat.S_ISREG(value.st_mode) else None,
            )
        return result

    def cli_arguments(self, root, stage, mode, output, *extra):
        from mobile_release import cli

        return cli.build_parser().parse_args([
            "ci", stage, "--config", str(root / "release/mobile-release.json"),
            "--platform", "android", "--confirm", f"{stage}:android:1.2.3:42",
            "--output-dir", str(output), "--" + mode, *extra,
        ])

    def assert_cli_rejects_unavailable_head_before_effects(self, root, first):
        from mobile_release import cli, credentials, stores

        output = root / ".mobile-release" / "source-gate"
        output.mkdir(parents=True, mode=0o700)
        retained = output / "original-evidence.json"
        retained.write_bytes(b'{"fictional":"preserve this original"}\n')
        retained.chmod(0o640)
        before = self.snapshot(output)
        original_read, original_policy = discovery._run, cli._require_ci_policy
        with ExitStack() as boundary:
            forbidden = []
            for module, names in (
                (cli, ("authenticate_operation_intent", "_parse_artifacts", "_set_artifact_environment",
                       "build_metadata_archive", "prepare_store_operation", "execute_store_operation",
                       "build_operation_intent", "build_candidate_manifest", "build_receipt",
                       "write_evidence", "copy_immutable_file")),
                (credentials, ("credential_values_from_environment",)),
                (stores, ("credential_values_from_environment", "_selected_store_material")),
            ):
                for name in names:
                    forbidden.append(boundary.enter_context(patch.object(
                        module, name, side_effect=AssertionError("source gate reached " + name))))
            for stage in ("candidate", "external-testing", "production-submit"):
                for mode in ("prepare-operation", "validate-operation-intent", "execute-store"):
                    armed, injected, delegated = [], [], []

                    def policy(*args, **kwargs):
                        # The actual policy/doctor also observes Git. Keep those
                        # reads real; fail only the later authority observation.
                        result = original_policy(*args, **kwargs)
                        armed.append(True)
                        return result

                    def unavailable_once(path, argv, **kwargs):
                        if armed:
                            if argv == HEAD and not injected:
                                injected.append(tuple(argv))
                                return None
                            delegated.append(tuple(argv))
                        return original_read(path, argv, **kwargs)

                    args = self.cli_arguments(root, stage, mode, output)
                    with self.subTest(stage=stage, mode=mode), \
                         patch.dict(os.environ, workflow_environment(stage, head=first), clear=True), \
                         patch.object(cli, "_require_ci_policy", side_effect=policy), \
                         patch.object(discovery, "_run", side_effect=unavailable_once), \
                         self.assertRaisesRegex(MutationGuardError, "source identity is incomplete"):
                        cli._ci(args)
                    self.assertEqual(armed, [True])
                    self.assertEqual(injected, [tuple(HEAD)])
                    self.assertEqual(delegated.count(tuple(HEAD)), 1)
                    self.assertTrue(any(read[:2] == ("git", "status") for read in delegated))
                    self.assertFalse(any(read[-1].endswith("^{tree}") for read in delegated))
                    self.assertEqual(self.snapshot(output), before)
            for forbidden_call in forbidden:
                forbidden_call.assert_not_called()

    def assert_original_source_recovery_and_authenticated_final_reuse(self, root, config, first, first_tree,
                                                                    second, second_source):
        from mobile_release import cli, stores
        from . import evidence_helpers

        self.git(root, "checkout", "--detach", first)
        recovery_env = workflow_environment(run_id="9000000000", head=second)
        recovery_env["TMPDIR"] = str(root.parent)
        source = discovery.git_context(root, recovery_env)
        self.assertEqual((source.commit, source.tree, source.branch), (first, first_tree, ""))
        self.assertTrue(discovery.valid_observed_source(source))
        # Existing offline document fixture, never a claimed Store result or
        # GitHub authentication. Its source IDs come from the actual checkout.
        with patch.dict(os.environ, {"PATH": os.environ.get("PATH", os.defpath)}, clear=True), \
             patch.object(evidence_helpers, "git_identity", return_value=source), \
             patch.object(evidence_helpers, "workflow_environment",
                          side_effect=lambda stage: workflow_environment(stage, head=first)):
            documents = evidence_helpers.build_lifecycle(config)
        intent = documents["candidate_intent"]
        raw = evidence_helpers.raw_receipt(intent)
        output = root / ".mobile-release" / "original-candidate"
        output.mkdir(mode=0o700)
        files = {"candidate-operation-intent.json": intent,
                 "candidate-manifest.json": documents["candidate"],
                 "candidate-receipt.json": documents["candidate_receipt"], "raw-store-receipt.json": raw}
        for name, value in files.items():
            path = output / name
            path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
            path.chmod(0o600)
        before = self.snapshot(output)
        request = stores.StoreRequest("candidate", "android", "candidate:android:1.2.3:42", True,
                                      output, recovery_run_id=intent["authorizedBy"]["runId"])
        context = dict(config=config, release=config.release_version(), git=source, stage="candidate",
                       platform="android", confirmation=request.confirmation,
                       metadata_sha256=documents["metadata_sha256"], artifacts=documents["records"],
                       recovery_run_id=request.recovery_run_id)
        with patch.dict(os.environ, recovery_env, clear=True):
            stores.guard_ci_mutation(request=request, config=config, release=config.release_version(), git=source)
            with self.assertRaisesRegex(MutationGuardError, "GITHUB_SHA"):
                stores.guard_ci_mutation(request=replace(request, recovery_run_id=None), config=config,
                                         release=config.release_version(), git=source)
            accepted = provenance.validate_operation_intent_context(intent, **context)
            self.assertEqual(accepted["operationSource"], {"commit": first, "tree": first_tree, "ref": source.ref})
            with self.assertRaisesRegex(ValidationError, "checked-out operation source"):
                provenance.validate_operation_intent_context(intent, **{**context, "git": second_source})
            manifest = provenance.build_candidate_manifest(
                config=config, release=config.release_version(), git=source, platform="android",
                artifacts=documents["records"], store_receipt=raw,
                metadata_sha256=documents["metadata_sha256"], operation_intent=intent)
            receipt = provenance.build_receipt(stage="candidate", platform="android", candidate_manifest=manifest,
                                               store_receipt=raw, operation_intent=intent)
        for value in (manifest, receipt):
            self.assertEqual(value["source"]["commit"], first)
            self.assertEqual(value["authorizedBy"], intent["authorizedBy"])
            self.assertEqual(value["executedBy"], intent["authorizedBy"])
            self.assertEqual((value["producedBy"]["headSha"], value["producedBy"]["runId"]),
                             (second, recovery_env["GITHUB_RUN_ID"]))

        # The generic recovery guard permits B as an observed source, but the
        # external-testing caller must still require the actual candidate A.
        self.git(root, "checkout", "--detach", second)
        wrong_output = root / ".mobile-release" / "wrong-external-source"
        external = self.cli_arguments(root, "external-testing", "execute-store", wrong_output,
                                      "--candidate-manifest", str(output / "candidate-manifest.json"))
        external.recovery_run_id = documents["external_intent"]["authorizedBy"]["runId"]
        with patch.dict(os.environ, workflow_environment("external-testing", run_id="9000000001", head=second),
                        clear=True), ExitStack() as boundary:
            forbidden = [boundary.enter_context(patch.object(cli, name,
                         side_effect=AssertionError("wrong external source reached " + name)))
                         for name in ("authenticate_operation_intent", "_parse_artifacts", "build_metadata_archive",
                                      "prepare_store_operation", "execute_store_operation", "write_evidence")]
            with self.assertRaisesRegex(ValidationError, "exact candidate source commit/tree"):
                cli._ci(external)
            for forbidden_call in forbidden:
                forbidden_call.assert_not_called()
        self.assertFalse(wrong_output.exists())
        self.assertEqual(self.snapshot(output), before)
        self.git(root, "checkout", "--detach", first)

        args = self.cli_arguments(root, "candidate", "execute-store", output,
                                  "--artifact", "android-aab=" + str(root / "app.aab"),
                                  "--artifact", "validation-report=" + str(root / "validation-report.json"))
        args.recovery_run_id = request.recovery_run_id
        with ExitStack() as boundary:
            forbidden = [boundary.enter_context(patch.object(cli, name,
                         side_effect=AssertionError("complete final reuse reached " + name)))
                         for name in ("prepare_store_operation", "execute_store_operation", "validate_aab",
                                      "build_operation_intent", "build_candidate_manifest", "build_receipt",
                                      "write_evidence", "copy_immutable_file")]
            # This is a source/history test, not native AAB validation. Keep the
            # existing explicit artifact-shape and authentication boundary seams;
            # real Git/guard/context/chain/copy/final-reuse decisions stay actual.
            structure = boundary.enter_context(patch.object(cli, "validate_aab_structure", return_value=[]))
            missing = ValidationError("original authenticated artifact is unavailable")
            authentication = boundary.enter_context(patch.object(cli, "authenticate_operation_intent",
                                                                  side_effect=missing))
            with patch.dict(os.environ, recovery_env, clear=True), self.assertRaises(ValidationError) as failed:
                cli._ci(args)
            self.assertIs(failed.exception, missing)
            authentication.assert_called_once_with(output / "candidate-operation-intent.json",
                                                    stage="candidate", platform="android")
            structure.assert_not_called()
            self.assertEqual(self.snapshot(output), before)
            authentication.reset_mock()
            authenticated = []
            original_read = discovery._run

            def authenticate(path, **_):
                authenticated.append(True)
                return provenance.load_operation_intent(path)

            def no_late_source_read(*args, **kwargs):
                self.assertFalse(authenticated, "source was re-observed after authentication/effects")
                return original_read(*args, **kwargs)

            authentication.side_effect = authenticate
            stream = io.StringIO()
            with patch.dict(os.environ, recovery_env, clear=True), redirect_stdout(stream), \
                 patch.object(discovery, "_run", side_effect=no_late_source_read):
                self.assertEqual(cli._ci(args), 0)
            self.assertEqual(authenticated, [True])
            self.assertTrue(json.loads(stream.getvalue())["reused"])
            authentication.assert_called_once_with(output / "candidate-operation-intent.json",
                                                    stage="candidate", platform="android")
            structure.assert_called_once_with(root / "app.aab")
            for forbidden_call in forbidden:
                forbidden_call.assert_not_called()
        # Completing a formerly partial operation may publish current dispatch B;
        # reusing an already complete authenticated final must NOT reissue it.
        self.assertEqual(documents["candidate"]["producedBy"]["headSha"], first)
        self.assertEqual(self.snapshot(output), before)

    def test_real_two_commit_checkout_and_single_unavailable_head_never_use_hint(self):
        from mobile_release.config import load_config
        from mobile_release.stores import StoreRequest, guard_ci_mutation

        with settled_native_fixture("mrk-observed-source-") as parent:
            root, first, first_tree, second, second_tree = self.repository(parent, release_project=True)
            config = load_config(root / "release/mobile-release.json")
            request = StoreRequest("candidate", "android", "candidate:android:1.2.3:42", True, root)
            env = workflow_environment(head=first)
            positive = discovery.git_context(root, env)
            self.assertTrue(discovery.valid_observed_source(positive))
            self.assertEqual((positive.commit, positive.tree), (second, second_tree))
            self.assertEqual(provenance._source(positive, include_ref=False), {
                "commit": second, "tree": second_tree,
            })
            with self.assertRaisesRegex(MutationGuardError, "GITHUB_SHA"):
                guard_ci_mutation(request=request, config=config, release=config.release_version(),
                                  git=positive, environ=env)
            guard_ci_mutation(request=request, config=config, release=config.release_version(),
                              git=positive, environ=workflow_environment(head=second))
            original, injected, delegated = discovery._run, [], []

            def unavailable_once(path, argv, **kwargs):
                if argv == HEAD and not injected:
                    injected.append(tuple(argv))
                    return None
                delegated.append(tuple(argv))
                return original(path, argv, **kwargs)

            with patch.object(discovery, "_run", side_effect=unavailable_once):
                unavailable = discovery.git_context(root, env)
            self.assertEqual(injected, [tuple(HEAD)])
            self.assertIn(tuple(HEAD), delegated)  # The final actual HEAD read ran.
            self.assertTrue(any(read[:2] == ("git", "status") for read in delegated))
            self.assertIsNone(unavailable.commit)
            self.assertIsNone(unavailable.tree)
            self.assertIs(unavailable.dirty, False)
            self.assertFalse(discovery.valid_observed_source(unavailable))
            with self.assertRaisesRegex(ValidationError, "observed"):
                provenance._source(unavailable, include_ref=True)
            with self.assertRaisesRegex(MutationGuardError, "source identity is incomplete"):
                guard_ci_mutation(request=request, config=config, release=config.release_version(),
                                  git=unavailable, environ=env)
            for untracked in (False, True):
                changed = root / ("untracked-source.txt" if untracked else "source.txt")
                original_bytes = None if untracked else changed.read_bytes()
                changed.write_bytes(b"unreviewed fixture source\n")
                dirty = discovery.git_context(root, workflow_environment(head=second))
                self.assertIs(dirty.dirty, True)
                with self.assertRaisesRegex(MutationGuardError, "provably clean"):
                    guard_ci_mutation(request=request, config=config, release=config.release_version(),
                                      git=dirty, environ=workflow_environment(head=second))
                # Reset only our own known fixture change after its assertions;
                # an unexpected failure leaves it for the native case owner.
                if untracked:
                    changed.unlink()
                else:
                    changed.write_bytes(original_bytes)
            self.assert_cli_rejects_unavailable_head_before_effects(root, first)
            self.assert_original_source_recovery_and_authenticated_final_reuse(
                root, config, first, first_tree, second, positive)

    def test_real_linked_detached_checkout_ignores_ambient_routing_and_fsmonitor(self):
        with settled_native_fixture("mrk-observed-routing-") as parent:
            root, first, first_tree, second, _second_tree = self.repository(parent)
            linked = parent / "linked"
            self.git(root, "worktree", "add", "--detach", str(linked), first)
            # Deliberately unavailable, not executable: ordinary discovery must
            # disable this configuration, not execute a configured hook safely.
            self.git(root, "config", "core.fsmonitor", str(parent / "must-not-run"))
            ambient = {
                "GIT_DIR": str(root / ".git"), "GIT_COMMON_DIR": str(root / ".git"),
                "GIT_WORK_TREE": str(root), "GIT_INDEX_FILE": str(root / ".git/index"),
                "GIT_OBJECT_DIRECTORY": str(root / ".git/objects"),
                "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.bare",
                "GIT_CONFIG_VALUE_0": "true", "GIT_CONFIG_PARAMETERS": "'core.bare=true'",
            }
            with patch.dict(os.environ, ambient, clear=False):
                source = discovery.git_context(linked, workflow_environment(head=second))
            self.assertTrue((linked / ".git").is_file(), "fixture must be a linked worktree")
            self.assertTrue(discovery.valid_observed_source(source))
            self.assertEqual((source.commit, source.tree), (first, first_tree))
            self.assertEqual((source.ref, source.branch), ("refs/heads/main", ""))
