"""Retained original Android build inputs, NOT local Store authority.

This optional internal seam starts before the existing signed build runs. It
retains the SAME exclusive artifact snapshot, not a renderer path/report or a
second AAB copy. Core producer finality is distinct from external native parent
and transport finality. Source/freshness, metadata, intent and consent still
need their original owners; none are inferred from a successful build.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
import stat
import sys
import threading
import time

from ._desktop_android_build_files import OriginalAndroidArtifact, MAX_AAB_BYTES
from ._desktop_android_build_protocol import is_signed, validate_result, _encode, RESPONSE_LIMIT
from .build_inputs import _file
from .cancellation import CleanupScope
from .checked_files import _Reader, _Policy
from .config import MAX_CONFIG_BYTES, MAX_VERSION_BYTES
from .errors import ValidationError

MAX_HANDOFF_FDS = 48
READ_CHUNK = 64 * 1024
COMPOSITION_FDS = 256
BUILD_ROLES = ("keytool-input", "gradle", "aab-sign", "bundletool", "jarsigner", "keytool")


class LocalCandidateError(ValidationError):
    """Finite non-reflective failure; no private path, finding text or key."""


def _need(value):
    if not value:
        raise LocalCandidateError("Original local Android build inputs are unavailable")


class LocalAndroidBuildHandoff:
    """One live read-only retention registered before the original producer.

    Neither construction nor observation authorizes preparation/Store access.
    The caller owns this scope across the existing producer's terminal and
    subsequent bounded input use. Closing it never deletes the retained AAB.
    """
    def __init__(self, run):
        from .desktop_android_build import AndroidBuildRun
        _need(type(run) is AndroidBuildRun and not run._run_claimed and not run._close_claimed
              and run.primary is None and getattr(run, "_local_handoff", None) is None
              and is_signed(run.request.context) and run.operation.signing is not None)
        run.operation.owner()
        self.run, self.guard = run, run.guard
        self.pid, self.thread = os.getpid(), threading.current_thread()
        self.reader = self.node = None
        self.failed = self.closed = self.captured = self.producer_joined = False
        self._capturing = self._reading = False
        self._read_bytes = 0
        self._completed_reads = 0
        self._result = self._config = self._version = None
        self._size = self._sha256 = None
        run._local_handoff = self  # Root receiver before any original acquisition.

    def _owner(self):
        _need(self.pid == os.getpid() and self.thread is threading.current_thread()
              and self.run._local_handoff is self)

    def _point(self):
        self._owner()
        try:
            _need(not self.closed and not self.failed)
            self.guard.check()
            _need(time.monotonic() < self.run.source.work_end)
        except BaseException:
            self.failed = True
            raise

    def _fail(self):
        self._owner()
        self.failed = True

    def _capture(self, run, artifact):
        self._point()
        _need(run is self.run and run._run_claimed and not run._close_claimed
              and run.primary is None and not self.captured and self.reader is None)
        operation = run.operation
        operation.checkpoint()
        _need(type(artifact) is OriginalAndroidArtifact and artifact is operation._artifact
              and artifact.files is operation.files and operation.files.artifact is artifact
              and operation.inputs is not None and operation.inputs.check_signer
              and operation.signing is not None and operation._signature_passed
              and operation.work_finish_attempted and not operation.close_claimed
              and operation.commands_settled() and not artifact._native and artifact._reader is None)
        validate_result(run._candidate)
        result = _encode(run._candidate)
        _need(len(result) <= RESPONSE_LIMIT and run._candidate.get("signing") == "local-upload-key")
        selected = run._candidate["artifacts"][0]
        _need((selected["size"], selected["sha256"]) == (artifact.size, artifact.sha256)
              and selected["freshness"] == "not-established"
              and run._candidate["assurances"]["sourceBinding"] == "not-established")
        saved = operation.inputs.saved
        config, version = saved.configuration.raw, saved.version_raw
        _need(type(config) is bytes and 0 < len(config) <= MAX_CONFIG_BYTES
              and type(version) is bytes and 0 < len(version) <= MAX_VERSION_BYTES)
        for body, row in ((config, run._candidate["usedConfig"]), (version, run._candidate["usedVersion"])):
            _need((len(body), hashlib.sha256(body).hexdigest()) == (row["bytes"], row["sha256"]))
        path = artifact.path  # Genuine original getter, not a supplied pathname.
        quote = len(path.parts) + 2  # Existing checked-reader Darwin alias ancestors.
        _need(path.is_absolute() and 1 < len(path.parts) and quote <= MAX_HANDOFF_FDS)
        operation.charge("local-handoff-fds", quote, MAX_HANDOFF_FDS)
        operation.charge("local-handoff-retained-bytes", len(config) + len(version) + len(result),
                         MAX_CONFIG_BYTES + MAX_VERSION_BYTES + RESPONSE_LIMIT)
        self.reader = _Reader(self.guard)
        self._capturing = True
        try:
            self.node = self.reader.acquire(path, _Policy(False, 1, MAX_AAB_BYTES), None)
            _need(len(self.reader.descriptors) <= quote
                  and _file(self.node.observed) == artifact._snapshot.identity
                  and self.node.observed.st_uid == os.geteuid() and self.node.observed.st_nlink == 1
                  and stat.S_IMODE(self.node.observed.st_mode) == 0o600)
            self._size, self._sha256 = artifact.size, artifact.sha256
            # Fixed chunks, not _Reader.read's whole-file allocation. The
            # retained byte identity is checked before/after the original hash.
            for _ in self._blocks():
                pass
            artifact.check()
            operation.check_inputs()
            operation.checkpoint()
            self._config, self._version, self._result = config, version, result
            self.captured = True
        except BaseException:
            self.failed = True
            raise
        finally:
            self._capturing = False

    def _blocks(self):
        self._point()
        _need(self.node is not None and not self._reading
              and (self._capturing or self.producer_joined))
        self._reading = True
        complete = False
        try:
            self.reader.terminal()
            digest, consumed = hashlib.sha256(), 0
            number = self.reader._number(self.node.slot)
            while consumed < self._size:
                self._point()
                amount = min(READ_CHUNK, self._size - consumed)
                _need(self._read_bytes <= 3 * self._size - amount)
                self._read_bytes += amount
                body = os.pread(number, amount, consumed)
                _need(type(body) is bytes and len(body) == amount)
                consumed += len(body)
                digest.update(body)
                self._point()
                yield body
            self._point()
            _need(not os.pread(number, 1, consumed) and digest.hexdigest() == self._sha256)
            self.reader.terminal()
            self._completed_reads += 1
            complete = True
        finally:
            self._reading = False
            if not complete:
                self.failed = True

    def _terminal(self, run, terminal):
        try:
            self._join_terminal(run, terminal)
        except BaseException:
            self.failed = True
            raise

    def _join_terminal(self, run, terminal):
        self._owner()
        _need(run is self.run)
        # Unknown/early/negative observations are absorbing for this handoff,
        # even if a later caller supplies a success-shaped result dictionary.
        if self.failed or terminal["outcome"] != "complete":
            self.failed = True
            return
        self._point()
        verdict = self.guard.lifetime_ledger.verdict()
        _need(self.captured and not self._reading and run.primary is None and run._close_claimed
              and run.operation.closed() and run.source.closed and self.guard.handler_state == "RESTORED"
              and verdict.complete and verdict.cleanup_complete and verdict.contained and not verdict.fatal
              and _encode(terminal["result"]) == self._result)
        self.reader.terminal()
        self.producer_joined = True

    def observation(self):
        """Detached bounded DATA, not a prepared intent or artifact capability."""
        self._point()
        _need(self.producer_joined and not self._reading)
        try:
            self.reader.terminal()
        except BaseException:
            self.failed = True
            raise
        return {"origin": "local-desktop", "scope": "retained-android-build-inputs",
                "producerCoreSettled": True, "outerTransportFinality": "not-established",
                "storeAuthorized": False, "candidatePrepared": False,
                "inspection": json.loads(self._result)}

    def saved_inputs(self):
        self.observation()
        return self._config, self._version

    @contextmanager
    def artifact_blocks(self):
        """At most two full retained reads after capture, under its endpoint.

        Early abandonment is a failed handoff, never successful consumption.
        No descriptor or reopenable pathname is exposed by this interface.
        """
        self.observation()
        blocks = self._blocks()
        before = self._completed_reads
        try:
            yield blocks
        except BaseException:
            self.failed = True
            raise
        finally:
            blocks.close()
            if self._completed_reads != before + 1:
                self.failed = True
        _need(not self.failed)

    def _close(self):
        self._owner()
        if self.closed:
            return
        self.closed = True
        if self._reading or not self.producer_joined:
            self.failed = True
        if self.reader is not None:
            try:
                self.reader.close()
                self.reader.assert_closed()
            except BaseException:
                self.failed = True
                raise


@contextmanager
def retain_android_build_inputs(run):
    """Internal optional handoff. Existing engine/default service never calls it."""
    handoff = LocalAndroidBuildHandoff(run)
    scope = CleanupScope(handoff.guard, handoff._close, owns_cancellation=False,
                         fork_cleanup=lambda: handoff.reader.after_fork_child() if handoff.reader else None,
                         first_primary=True)
    try:
        try:
            with scope:
                yield handoff
        finally:
            scope.__exit__(*sys.exc_info())
    except BaseException:
        handoff.failed = True
        raise


def composition_fd_quote(*, project, source, bound_files, module_depth, root_depth, firebase):
    """Closed owned-Python peak, not ambient/native-parent headroom evidence."""
    values = (project, source, bound_files, module_depth, root_depth)
    _need(all(type(n) is int and 0 <= n <= 96 for n in values) and type(firebase) is bool)
    normal = bound_files + 2 * module_depth + 18
    # BuildInputs pins project/.mobile-release/pending as the scratch parent.
    signing = root_depth + 2 + 2 + 1 + 2 + 1 + 2 + 4
    if firebase:
        signing += root_depth + module_depth + 2
    handoff = root_depth + 5 + 2  # namespace3/artifacts/leaf + checked alias allowance.
    # Independent work cleanup still runs when signing.close loses its return.
    # Keep that entire workspace alongside possibly unclosed signing/native IO.
    workspace = max(signing + 20 + 67, handoff + 20)
    total = project + source + normal + 3 + 64 + 2 + 8 + workspace
    _need(total <= COMPOSITION_FDS)
    return {"project": project, "source": source, "normalFiles": normal, "normalIterators": 2,
            "namespace": 3, "tools": 64, "baseline": 8, "signingWithCommand": signing + 20,
            "cleanup": 67, "handoffWithPostCommand": handoff + 20, "total": total,
            "handoff": handoff}


OUTPUT_REFUSALS = {
    "preexisting-output": "Previous Android output is preserved. Use reviewed output preparation before starting a local candidate.",
    "module-missing": "The configured Android module directory is missing; no build or output cleanup was started.",
    "output-changed": "Android output changed before the build. Preserve it and review output preparation before another candidate.",
}


class LocalAndroidCandidateComposition:
    """Internal original source/build join; deliberately not a native wire API.

    No constructor/draft/observation grants Store authority. Ordinary Android
    protocol validators still reject this distinct terminal envelope.
    """
    def __init__(self, run):
        from .desktop_android_build import AndroidBuildRun
        _need(type(run) is AndroidBuildRun and not run._run_claimed and not run._close_claimed
              and run.primary is None and getattr(run, "_local_composition", None) is None
              and getattr(run.operation, "_local_composition", None) is None
              and run.request.native["toolchain"]["profile"] in
                  ("android-registered-macos-arm64-v1", "android-registered-macos-x86_64-v1"))
        self.run = run
        self.handoff = LocalAndroidBuildHandoff(run)
        self.source = None
        self.quote = self.source_binding = None
        self.failed = self.closed = self.source_closed = self.joined = False
        self._source_pending = None
        self._source_rows = []
        self._build_errors = {}
        self.source_failure = None
        self._output = self._output_data = None
        self.output_failure = None
        run._local_composition = run.operation._local_composition = self

    def _owner(self):
        self.run.operation.owner()
        _need(self.run._local_composition is self and self.run.operation._local_composition is self)

    def _fail(self, error=None):
        self._owner()
        self.failed = True
        self.handoff._fail()
        from .local_release_source import LocalSourceError
        if type(error) is LocalSourceError and self.source_failure is None and self.output_failure is None:
            self.source_failure = error.reason

    def _refuse_output(self, reason):
        self._owner()
        _need(reason in OUTPUT_REFUSALS)
        if self.output_failure is None:
            self.output_failure = reason
        self._fail()
        raise LocalCandidateError(OUTPUT_REFUSALS[reason])

    def _gradle_arguments(self, argv):
        self._owner()
        flags = ("--no-build-cache", "--no-configuration-cache", "--rerun-tasks")
        _need(self._output is not None and self._output.prepared and not self._output.armed
              and not self._output.arguments_selected
              and not self.failed and not self.closed and type(argv) is tuple and argv
              and argv[-1] == self.run.operation.inputs.task
              and not any(flag in argv for flag in flags))
        # Only the actual tool owner's selected task is retained; flags are
        # supplemental. The saved dispatcher repeats original output PRE.
        self._output.arguments_selected = True
        return (*argv[:-1], *flags, argv[-1])

    def _settled_source_calls(self):
        return sum(row["settled"] for row in self._source_rows)

    def _source_calls_for_build(self):
        self._owner()
        _need(not self.failed and not self.closed and self._source_pending is None
              and self.source is not None and not self.source.closed
              and all(row["returned"] and row["code"] == 0 for row in self._source_rows))
        return self._settled_source_calls()

    def _arm_source(self, source, arguments, timeout, limit):
        self._owner()
        op = self.run.operation
        _need(source is self.source and source._composition is self and source.execution_source is None
              and source.endpoint == self.run.source.work_end and not self.failed and not self.closed
              and self._source_pending is None and op._pending is None and len(self._source_rows) < 12
              and (all(state == "new" for state in op._roles.values())
                   or (op._signature_passed and all(op._roles.get(role) == "returned"
                       and op._returned.get(role) in ((0, 4) if role == "jarsigner" else (0,))
                       for role in BUILD_ROLES))))
        initial = (("config", ["config", "--local", "--no-includes", "--null", "--list"], 65536),
            ("identity", ["rev-parse", "--shared-index-path", "HEAD", "HEAD^{tree}"], 1024),
            ("index", ["ls-files", "--stage", "-z"], 2 << 20),
            ("flags", ["ls-files", "-v", "-z"], 2 << 20))
        index = len(self._source_rows)
        if index < 4:
            role, expected, cap = initial[index]
            _need(arguments == expected and limit == cap)
        elif index == 4:
            import re
            role = "tree"
            _need(len(arguments) == 5 and arguments[:4] == ["ls-tree", "-r", "-z", "--full-tree"]
                  and type(arguments[4]) is str and re.fullmatch(r"[0-9a-f]{40}", arguments[4])
                  and limit == 2 << 20)
        else:
            role = "status"
            _need(arguments == ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"]
                  and limit == 2 << 20)
        facts = self.run.guard.lifetime_ledger.verdict()
        _need(facts.complete and facts.cleanup_complete and facts.contained and not facts.fatal
              and facts.profile_calls == 0 and facts.commands == self._settled_source_calls() + len(op._returned))
        row = {"role": role, "before": facts.commands, "attempted": False, "returned": False,
               "settled": False, "code": None}
        self._source_rows.append(row)
        self._source_pending = (row, timeout, limit)

    def _source_limits(self, timeout, capture, output_limit):
        self._owner()
        _need(not self.failed and not self.closed and self._source_pending is not None)
        row, requested, cap = self._source_pending
        _need(not row["attempted"] and capture is True and type(timeout) is int
              and 1 <= timeout <= requested <= 10 and output_limit == cap)
        row["attempted"] = True
        return timeout, cap

    def _source_returned(self, source, result):
        self._owner()
        _need(source is self.source and self._source_pending is not None)
        row = self._source_pending[0]
        facts = self.run.guard.lifetime_ledger.verdict()
        _need(row["attempted"] and facts.complete and facts.cleanup_complete and facts.contained
              and not facts.fatal and facts.commands == row["before"] + 1 and facts.profile_calls == 0
              and type(result.returncode) is int)
        row.update(returned=True, settled=True, code=result.returncode)
        self._source_pending = None
        if result.returncode != 0:
            self._fail()

    def _source_error(self, source, error):
        self._owner()
        _need(source is self.source and self._source_pending is not None)
        row = self._source_pending[0]
        facts = self.run.guard.lifetime_ledger.verdict()
        row["settled"] = bool(row["attempted"] and facts.complete and facts.cleanup_complete
                              and facts.contained and not facts.fatal and facts.commands == row["before"] + 1)
        self._source_pending = None
        self._fail(error)

    def _build_error(self, role):
        self._owner()
        op = self.run.operation
        facts = self.run.guard.lifetime_ledger.verdict()
        before = op._command_before.get(role)
        self._build_errors[role] = bool(type(before) is int and facts.complete
            and facts.cleanup_complete and facts.contained and not facts.fatal and facts.commands == before + 1)
        self._fail()

    def _build_facts(self):
        self._owner()
        op = self.run.operation
        _need(tuple(op._roles) == BUILD_ROLES)
        completed = set(op._returned) | {role for role, settled in self._build_errors.items() if settled}
        _need(completed <= set(BUILD_ROLES))
        dispatched = True if op._returned else None if any(state != "new" for state in op._roles.values()) else False
        return len(completed), dispatched

    def _charge(self, name, amount):
        # Called before ordinary slot allocation. No recursive project/clock
        # check: the original operation already performed that checkpoint.
        if self.quote is None or name not in ("file-slots", "file-iterators"):
            return
        files = self.run.operation.files
        slots = files.slots if name == "file-slots" else files.iterators
        count = sum(slot.close_state != "CLOSED" for slot in slots)
        cap = self.quote["normalFiles" if name == "file-slots" else "normalIterators"]
        _need(type(amount) is int and 0 <= amount and count + amount <= cap)

    @contextmanager
    def _source_scope(self, bound):
        from .local_release_source import LocalSourceObservation, _retain_source
        import resource
        self._owner()
        op = self.run.operation
        _need(self.source is None and not self.failed and not self.closed and op.inputs is bound
              and op.invocation.project_owner is op.invocation._original_project)
        source = LocalSourceObservation(op.invocation, bound.saved.configuration.raw, bound.saved.version_raw,
                                        self.run.source.work_end, None)
        self.source = source  # Root before original source opens.
        source._composition = self
        project = op.invocation.project_owner
        module_depth = len(bound.saved.configuration.module.lstrip(":").split(":")) if bound.saved.configuration.module != ":" else 0
        self.quote = composition_fd_quote(project=len(project.directory.slots) + 1,
            source=source.descriptor_quote(), bound_files=sum(s.close_state != "CLOSED" for s in op.files.slots),
            module_depth=module_depth, root_depth=len(op.root.parts),
            firebase=bound.config.section("services").get("androidFirebase") == "required")
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        _need(soft == resource.RLIM_INFINITY or soft >= COMPOSITION_FDS)
        try:
            with _retain_source(source):
                observed = source.observed
                self.source_binding = {"commit": observed.commit, "tree": observed.tree,
                                       "ref": observed.ref, "branch": observed.branch}
                self._output = op.files.prepare_candidate_output(self)
                try:
                    yield
                except BaseException as error:
                    self._fail(error)  # First failure before independent source closes.
                    raise
            _need(source.closed and all(reader.assert_closed() is None for reader in source.readers))
            self._output.check_final(op._artifact)  # Last output POST before producer close.
            self.source_closed = True
        except BaseException as error:
            self._fail(error)
            raise

    def _before_capture(self, artifact):
        self._owner()
        _need(self.source is not None and self.quote is not None and not self.failed
              and self.run.operation.work_finish_attempted)
        self.source.check()
        _need(self._output is not None and self._output_data is None)
        self._output_data = self._output.data(artifact)
        path = self.run.operation.root / ".mobile-release" / "desktop-android-build" / self.run.operation.operation_id / "artifacts" / "app-release.aab"
        _need(artifact.path == path and len(path.parts) + 2 <= self.quote["handoff"])

    def _terminal(self, terminal):
        try:
            return self._terminal_data(terminal)
        except BaseException as error:
            self._fail(error)
            raise

    def _terminal_data(self, terminal):
        from ._desktop_android_build_protocol import _validate_composed_terminal
        _validate_composed_terminal(terminal, self.run.request, self)
        if terminal["outcome"] == "complete":
            _need(not self.failed and self.source_closed and self.source_binding is not None
                  and self._output_data is not None
                  and self._output_data["signedArtifact"] == {"bytes": self.handoff._size, "sha256": self.handoff._sha256}
                  and self._source_pending is None and len(self._source_rows) == 8
                  and all(row["returned"] and row["code"] == 0 for row in self._source_rows))
        if terminal["outcome"] != "complete":
            self._fail()
        self.handoff._terminal(self.run, terminal)
        self.joined = terminal["outcome"] == "complete" and self.handoff.producer_joined
        return {"origin": "local-desktop", "scope": "source-bound-android-build-composition",
                "build": terminal, "source": self.source_binding, "sourceCalls": [dict(row) for row in self._source_rows],
                "sourceOriginalsClosed": self.source_closed, "sourceFailure": self.source_failure,
                "outputFailure": self.output_failure, "outputGuidance": OUTPUT_REFUSALS.get(self.output_failure),
                "outputFreshness": json.loads(json.dumps(self._output_data)) if self.joined else None,
                "ownedPythonDescriptorQuote": self.quote,
                # Serialized payload/row bounds, not a Python heap or OS-wide
                # memory proof. No AAB body is retained in memory.
                "additionalDataBounds": {"sourceRetainedPayloadBytes": MAX_CONFIG_BYTES + MAX_VERSION_BYTES
                    + 65536 + 1024 + 128 + 2 * (2 << 20), "sourceCommandStreamBytes": 2 << 20,
                    "sourceTrackedRowsPerTable": 32768, "sourceTrackedTables": 2,
                    "handoffSavedBytes": MAX_CONFIG_BYTES + MAX_VERSION_BYTES,
                    "handoffResultBytes": RESPONSE_LIMIT, "artifactReadChunkBytes": READ_CHUNK},
                "outerTransportFinality": "not-established",
                "freshness": "not-established", "candidatePrepared": False, "storeAuthorized": False}

    def observation(self):
        self._owner()
        _need(self.joined and not self.closed and not self.failed)
        return {**self.handoff.observation(), "sourceCorrespondence": dict(self.source_binding),
                "outputFreshness": json.loads(json.dumps(self._output_data))}

    def artifact_blocks(self):
        self.observation()
        return self.handoff.artifact_blocks()

    def _close(self):
        self._owner()
        self.closed = True
        self.handoff._close()


@contextmanager
def retain_local_android_candidate(run):
    """No engine/wire caller yet; original internal composition only."""
    owner = LocalAndroidCandidateComposition(run)
    scope = CleanupScope(run.guard, owner._close, owns_cancellation=False,
        fork_cleanup=lambda: owner.handoff.reader.after_fork_child() if owner.handoff.reader else None,
        first_primary=True)
    try:
        try:
            with scope:
                yield owner
        finally:
            scope.__exit__(*sys.exc_info())
    except BaseException as error:
        owner._fail(error)
        raise
