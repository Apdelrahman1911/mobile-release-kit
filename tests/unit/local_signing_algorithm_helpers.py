"""Actual profile algorithms with deliberately non-recoverable fixture DATA.

No result/receipt factories or native model are used here.  The normal private
account, installer, descriptors and writer stay real; DATA never authorizes a
signing command, terminal cleanup or a new recovery invocation.
"""
from __future__ import annotations

import hashlib
from contextlib import ExitStack, contextmanager
from types import SimpleNamespace
from unittest.mock import patch

from mobile_release import _command_process as command
from mobile_release import credentials, local_signing as signing, owned_process


@contextmanager
def refuse_signing_execution():
    """Fail on attempted execution/authority, even if its caller catches it."""
    attempts = []

    def refusal(label):
        def refused(*_args, **_kwargs):
            attempts.append(label)
            raise AssertionError("profile algorithm attempted " + label)
        return refused

    with ExitStack() as stack:
        for owner, names in (
            (signing, ("run_owned", "recover_signing")),
            (credentials, ("_run_private",)),
            (owned_process, ("run_owned",)),
            (signing.SigningSession, ("prepare", "_call", "_new_scope", "_original_outcome",
                                      "_settle_operation", "finish", "finish_terminal", "load_snapshot")),
            (signing._RecoveryAttempt, ("__init__",)),
            (command.AccountExecutionSource, ("new_scope",)),
            (command, ("_issue_journal_binding", "run_command")),
            (command.OriginalCommandOutcome, ("__init__",)),
            (command.NoTargetProof, ("__init__",)),
            (command.FenceWriter, ("publish",)),
        ):
            for name in names:
                stack.enter_context(patch.object(owner, name, new=refusal(name)))
        try:
            yield attempts
        finally:
            assert not attempts, {"forbiddenAlgorithmAttempts": attempts}


@contextmanager
def profile_algorithm_session(home, content, profile_uuid):
    """Derive profile identities from a real installer, never fake history.

    Only cleanup_profile's algorithm inputs exist.  The marker and absent full
    version/token/account/native schema intentionally make any written state
    unusable as recovery history.  Its checkpoint still uses the actual writer.
    """
    with refuse_signing_execution() as attempts, signing.local_signing_lease(home=home) as lease:
        session = lease.session()
        session.open(create=True)
        with lease.profile_directory() as descriptor:
            before = (None if descriptor is None else signing._profile_snapshot(
                descriptor, profile_uuid + ".mobileprovision", cancellation=lease.cancellation))
        marker = "profile-policy-only-not-signing-history"
        session.intent = {"fixtureAlgorithmData": marker, "profile": {
            "uuid": profile_uuid, "sha256": hashlib.sha256(content).hexdigest(),
            "before": before, "stage": ".mobile-release-profile-" + session.token,
        }}
        session.state = {"fixtureAlgorithmData": marker, "revision": 0,
                         "inflight": None, "conflict": False, "profile": {
            "phase": "not-started", "stageIdentity": None, "ownedIdentity": None,
            "reused": False, "borrowed": None,
        }}
        events = []

        def observe(phase, **values):
            events.append(phase)
            session.profile_event(phase, **values)

        with credentials._temporary_profile_installation(
            content, profile_uuid, home, cancellation=lease.cancellation, observer=observe,
            reserved_stage=session.intent["profile"]["stage"], retain=lambda: True,
        ):
            pass
        try:
            yield SimpleNamespace(session=session, lease=lease, events=events, attempts=attempts)
        finally:
            assert session._command_scope is None and session._command_binding is None
            assert session._recovery_attempt is None and session.completed is None
            assert session.runner is None and not attempts
            assert "version" not in session.intent and "version" not in session.state
            assert session.intent["fixtureAlgorithmData"] == session.state["fixtureAlgorithmData"] == marker
            assert not (signing._names(session.fd) & (signing.FENCE_CONTROLS | {"intent.json", "completed.json"}))
