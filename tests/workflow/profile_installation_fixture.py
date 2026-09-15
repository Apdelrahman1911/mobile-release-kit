"""Real default signals at local profile ownership boundaries.

The parent chooses the package under test (including an installed wheel). Every
file/descriptor is fixture-owned, and cleanup assertions precede fallback.
Signing effects are fictional; their commands use the genuine bounded owner.
This fixture therefore requires the reviewed disposable verification boundary.
"""
from __future__ import annotations

import base64
import inspect
import json
import os
import shutil
import signal
import stat
import sys
import tempfile
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if __name__ == "__main__":
    sys.path[:0] = [sys.argv.pop(1), str(ROOT / "tests")]
    _mode, _temporary_parent = sys.argv[1:]
    assert Path(_temporary_parent).is_absolute() and all(
        os.environ.get(name) == _temporary_parent for name in ("TMPDIR", "TMP", "TEMP")
    ), "profile fixture requires its exact selected temporary parent"
    # Pin before imports/work: materialized variants also use default tempfile
    # allocation. No unrelated fallback directory may replace the G selection.
    tempfile.tempdir = _temporary_parent

from mobile_release import credentials, local_signing
from mobile_release.cancellation import CleanupScope, DefaultCancellation
from mobile_release.config import load_config
from mobile_release.owned_process import ProcessError
from unit.helpers import ios_config, write_project
from unit.ios_entitlement_helpers import profile
from unit.local_signing_helpers import NativeSigningModel, fictional_signing_profile, model_result
from unit.local_signing_persistent import _materializer_directory


@contextmanager
def completed_case_directory(parent: Path):
    """Remove only a successful case, never finalize uncertain native work."""
    root = Path(tempfile.mkdtemp(prefix="mrk-profile-signal-", dir=parent))
    before = root.lstat()
    assert stat.S_ISDIR(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o700
    yield root
    # Any exception keeps this namespace for the enclosing original verification
    # owner. Normal return follows the assertions below, including real account
    # recovery where needed; an error flag or a case-group receipt is not enough.
    after = root.lstat()
    assert (after.st_dev, after.st_ino, after.st_mode, after.st_uid) == (
        before.st_dev, before.st_ino, before.st_mode, before.st_uid)
    shutil.rmtree(root)


def observe_live_post_result_finality(options, result):
    """Observe a genuine returned command; never settle or retire its journal."""
    from mobile_release._command_process import (
        AccountExecutionScope, JournalledCommandBinding, OriginalCommandFinality,
        OriginalCommandOutcome, RouteHistory,
    )

    scope, binding = options.get("execution_scope"), options.get("journal_binding")
    assert type(scope) is AccountExecutionScope, "post-result callback lacks its original scope"
    outcome = scope.outcome.read()
    assert type(outcome) is OriginalCommandOutcome, "post-result callback lacks an original outcome"
    assert type(binding) is JournalledCommandBinding and binding._scope is scope \
        and outcome.matches(scope, binding), "post-result callback has a foreign binding or outcome"
    assert outcome.no_target is None and not outcome.execution_unknown \
        and outcome.termination == "normal-exit" and type(outcome.returncode) is int \
        and outcome.returncode == 0 and type(result.returncode) is int and result.returncode == 0 \
        and outcome.result_integrity == "complete", "post-result callback lacks a complete normal result"
    assert type(outcome.original_finality) is OriginalCommandFinality \
        and outcome.original_finality._engine is outcome._engine, "post-result original finality is missing"
    assert all(type(route) is RouteHistory and route.attempted is True and route.retired is True
               for route in (outcome.create_w, outcome.run_tool)), "post-result routes are not retired"
    outcome.require_binding(binding)
    session = binding._session
    assert type(session) is local_signing.SigningSession and session._command_scope is scope \
        and session._command_binding is binding and scope._source._lease is session.lease \
        and scope._used is True and session._command_finished is False \
        and not session.unresolved and not session.journal_failed, "post-result journal is not the live original"
    session.assert_owner()
    operation = session.state["inflight"]
    assert type(operation) is dict and operation["phase"] == "ARMED" \
        and operation["nonce"] == scope.nonce.hex(), "post-result original command is not armed"
    # This only reads the producer's actual identity-bound fence. The product's
    # exception path, not this callback, must perform settlement and retirement.
    assert session._read_fence_pair(operation)["outcome"] == "producer-settled", \
        "post-result producer fence is missing"
    return scope, binding, outcome


def run_case(mode: str, parent: Path) -> dict:
    requested_mode = mode
    mode, _, selected_signal = mode.partition(":")
    default_signal = signal.SIGTERM if selected_signal == "TERM" else signal.SIGINT
    standalone, materialized = mode.startswith("standalone-"), mode.startswith("material-")
    mode = mode.removeprefix("standalone-").removeprefix("material-")
    real_open, real_close, real_fstat, real_fdopen = os.open, os.close, os.fstat, os.fdopen
    real_temporary_directory = tempfile.TemporaryDirectory
    real_signal = signal.signal
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    assert previous == {signal.SIGINT: signal.default_int_handler, signal.SIGTERM: signal.SIG_DFL}
    captured, references, native_calls = {}, [], []
    post_result_cleanup = []
    material_directories = []
    signals, reached, visits, cleanup_calls, target_scopes = [], [], [], [], []
    installation_code = credentials._temporary_profile_installation.__wrapped__.__code__
    signing_code = credentials._temporary_apple_signing_environment.__wrapped__.__code__
    target_function = credentials._temporary_profile_installation if standalone else (
        local_signing.local_signing_lease if mode in {"open-home", "partial-install", "restore-entry", "restore-active", "restore-term", "restore-int"}
        else credentials._temporary_apple_signing_environment)
    target_code = target_function.__wrapped__.__code__
    lines, first = inspect.getsourcelines(target_function)
    owner_line = next(first + index for index, text in enumerate(lines) if text.strip() == "with scope:")
    yield_line = next(first + index for index, text in enumerate(lines) if text.strip().startswith("yield"))
    lines, first = inspect.getsourcelines(CleanupScope._exit_owned)
    exit_line = next(first + index for index, text in enumerate(lines) if "if self.claimed:" in text)
    lines, first = inspect.getsourcelines(DefaultCancellation.restore)
    restore_lines = {phase: next(first + index for index, text in enumerate(lines) if token in text)
                     for phase, token in (("restore-entry", "self.depth += 1"), ("restore-active", "failed = False"))}
    lines, first = inspect.getsourcelines(credentials._temporary_profile_installation)
    anchors = {phase: next(first + index for index, text in enumerate(lines) if token in text)
               for phase, token in (("assigned-open", "created = True"), ("before-fstat", "details = os.fstat(descriptor)"))}
    lines, first = inspect.getsourcelines(ExitStack.enter_context)
    handoff = next(first + index for index, text in enumerate(lines) if "self._push_cm_exit(cm, _exit)" in text)

    def remember(fd):
        if type(fd) is int:
            try:
                details = real_fstat(fd)
            except OSError:
                return
            captured[(fd, details.st_dev, details.st_ino)] = True

    def send(phase, signum=None):
        signum = default_signal if signum is None else signum
        reached.append(phase)
        signals.append(signum)
        os.kill(os.getpid(), signum)

    def observe_cleanup(frame, event, arg):
        # CPython disables a trace hook when the injected signal raises out of
        # it. An independent non-raising profiler observes the actual unwind.
        if event == "call" and target_scopes and frame.f_code is target_scopes[0].cleanup.__code__:
            cleanup_calls.append(True)

    def trace(frame, event, arg):
        if event == "line":
            if frame.f_code is target_code and frame.f_lineno == owner_line:
                visits.append(True)
                if not target_scopes:
                    target_scopes.append(frame.f_locals["scope"])
                if mode == "cleanup-dispatch" and len(visits) == 2 and not reached:
                    assert not target_scopes[0].claimed
                    send(mode)
            if target_scopes:
                target = target_scopes[0]
                if frame.f_code is CleanupScope._exit_owned.__code__ and frame.f_locals["self"] is target and frame.f_lineno == exit_line:
                    if mode == "cleanup-entry" and not reached:
                        send(mode)
                    elif mode == "partial-install" and len(signals) == 1:
                        send("partial-install-cleanup", signal.SIGINT)
                if (mode in restore_lines and not reached and frame.f_code is DefaultCancellation.restore.__code__
                        and frame.f_locals["self"] is target.cancellation and frame.f_lineno == restore_lines[mode]):
                    send(mode)
            if mode == "pre-yield" and not reached and frame.f_code is target_code and frame.f_lineno == yield_line:
                send(mode)
            if frame.f_code in (installation_code, credentials._open_profile_directory.__code__, credentials._read_regular_at.__code__):
                for name in ("descriptor", "child", "directory"):
                    remember(frame.f_locals.get(name))
            if not reached and mode in anchors and frame.f_code is installation_code and frame.f_lineno == anchors[mode]:
                send(mode)
            if mode == "handoff" and not reached and frame.f_code is ExitStack.enter_context.__code__ and frame.f_lineno == handoff:
                cm = frame.f_locals.get("cm")
                if getattr(getattr(cm, "gen", None), "gi_code", None) is installation_code:
                    references.append(cm)  # GC must not masquerade as production cleanup.
                    assert not frame.f_locals["self"]._exit_callbacks
                    send(mode)
        return trace

    def change_handler(signum, handler):
        result = real_signal(signum, handler)
        if target_scopes and not reached:
            guard = target_scopes[0].cancellation
            if mode == "partial-install" and signum == signal.SIGINT and getattr(handler, "__self__", None) is guard:
                send(mode, signal.SIGINT)
            if ((mode == "restore-term" and signum == signal.SIGTERM)
                    or (mode == "restore-int" and signum == signal.SIGINT)) and handler == previous[signum]:
                send(mode, signal.SIGINT)
        return result

    with completed_case_directory(parent) as root:
        home = root / "home"; home.mkdir(mode=0o700)
        private = root / "private"; private.mkdir(mode=0o700)
        p12, supplied = private / "fake.p12", private / "profile"
        p12.write_bytes(b"fictional p12; never an identity")
        supplied.write_bytes(b"fictional authenticated profile bytes")
        destination = home / "Library/MobileDevice/Provisioning Profiles" / (profile()["UUID"] + ".mobileprovision")
        stage_fds = set()

        def opening(path, *args, **kwargs):
            fd = real_open(path, *args, **kwargs)
            remember(fd)
            if str(path).startswith(".mobile-release-profile-"):
                stage_fds.add(fd)
                if mode == "open-stage" and not reached:
                    send(mode)
            elif mode == "open-home" and Path(path) == home.resolve() and not reached:
                send(mode, signal.SIGTERM)
            elif mode == "open-child" and path == "MobileDevice" and not reached:
                send(mode)
            return fd  # Real pending signal, not a callee discarding its FD.

        def stating(fd):
            result = real_fstat(fd)
            if mode == "fstat" and fd in stage_fds and not reached:
                send(mode, signal.SIGTERM)
            return result

        def file_object(fd, *args, **kwargs):
            result = real_fdopen(fd, *args, **kwargs)
            if mode == "fdopen" and fd in stage_fds and not reached:
                send(mode)
            return result

        def closing(fd):
            result = real_close(fd)
            if mode == "close" and fd in stage_fds and not reached:
                send(mode)
            return result

        model = NativeSigningModel(home)
        native_calls = model.calls
        def restores_search(argv):
            return (Path(argv[0]).name == "security" and argv[1] == "list-keychains" and "-s" in argv
                    and argv[argv.index("-s") + 1:] == model.original["search"])

        def native_result_policy(argv):
            if mode == "cleanup-error-signal" and restores_search(argv):
                # The genuine target produces this exit. A callback must never
                # turn an already observed command result into another result.
                return model_result(returncode=1)
            return None

        def after_native(argv, kwargs, result):
            if restores_search(argv):
                if mode == "body-repeat":
                    send("enclosing-cleanup", signal.SIGTERM)
                elif mode == "unexpected-cleanup":
                    assert not post_result_cleanup, "post-result cleanup callback was retried"
                    post_result_cleanup.append(observe_live_post_result_finality(kwargs, result))
                    reached.append(mode)
                    raise RuntimeError("synthetic native cleanup failure")
                elif mode == "cleanup-error-signal":
                    send(mode)
            if not reached and ((mode == "mutation-create" and argv[1] == "create-keychain")
                    or (mode == "mutation-search" and argv[1] == "list-keychains" and "-s" in argv)
                    or (mode == "mutation-default" and argv[1] == "default-keychain" and "-s" in argv)):
                send(mode, signal.SIGTERM)
            return result
        model.after = after_native
        model.result_policy = native_result_policy
        native = model

        try:
            with ExitStack() as stack:
                stack.enter_context(patch.object(credentials, "_authenticated_signing_profile", side_effect=fictional_signing_profile))
                stack.enter_context(patch.object(credentials, "_run_private", side_effect=native))
                stack.enter_context(patch("mobile_release.cancellation.signal.signal", side_effect=change_handler))
                if mode not in {*anchors, "handoff"}:
                    stack.enter_context(patch.object(credentials.os, "open", side_effect=opening))
                    stack.enter_context(patch.object(credentials.os, "fstat", side_effect=stating))
                    stack.enter_context(patch.object(credentials.os, "fdopen", side_effect=file_object))
                    stack.enter_context(patch.object(credentials.os, "close", side_effect=closing))
                sys.setprofile(observe_cleanup)
                sys.settrace(trace)
                try:
                    if standalone:
                        context = credentials._temporary_profile_installation(supplied.read_bytes(), profile()["UUID"], home)
                    elif materialized:
                        config = load_config(write_project(home / "project", ios_config(), platform="ios"))
                        values = {"MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64": base64.b64encode(p12.read_bytes()).decode(),
                                  "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_BASE64": base64.b64encode(supplied.read_bytes()).decode(),
                                  "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD": "fictional-password"}
                        stack.enter_context(patch.object(credentials.tempfile, "TemporaryDirectory",
                            side_effect=lambda *args, **kwargs: _materializer_directory(
                                real_temporary_directory, private, material_directories, *args, **kwargs)))
                        stack.enter_context(patch.object(credentials, "local_signing_lease", side_effect=lambda **_kwargs: local_signing.local_signing_lease(home=home)))
                        context = credentials.materialize_build_inputs(config, values=values, platforms=("ios",), prepare_ios_signing=True)
                    else:
                        context = credentials._temporary_apple_signing_environment(
                            p12=p12, password="fictional-password", profile=supplied, directory=private, home=home,
                        )
                    references.append(context)
                    with context:
                        assert mode in {"body", "body-repeat", "unexpected-cleanup", "cleanup-entry", "cleanup-dispatch",
                                        "restore-entry", "restore-active", "restore-term", "restore-int", "cleanup-error-signal"}, "cancelled setup entered signing body"
                        assert destination.read_bytes() == supplied.read_bytes()
                        if mode in {"body", "body-repeat"}:
                            send("body")
                            raise AssertionError("code after body cancellation executed")
                    raise AssertionError("cancelled/failed signing reported success")
                except KeyboardInterrupt as error:
                    references.append(error)
                    assert mode not in {"unexpected-cleanup", "cleanup-error-signal"}
                except ProcessError as error:
                    references.append(error)
                    # Complete cleanup projects its actual fatal ledger instead
                    # of exposing incidental callback text. A deferred signal
                    # cannot replace the first owned-cleanup failure.
                    assert mode in {"unexpected-cleanup", "cleanup-error-signal"}
                    assert mode in reached and error.fatal
                finally:
                    sys.settrace(None)
                    sys.setprofile(None)
            assert reached, "dangerous boundary was never reached"
            assert len(material_directories) == int(materialized), "materializer allocation count changed"
            assert all(path.parent == private and not os.path.lexists(path) for path in material_directories), \
                "original materializer did not remove its private directory"
            if mode in {"unexpected-cleanup", "cleanup-error-signal"}:
                status = local_signing.signing_status(home=home)
                assert status["status"] == "pending", "ambiguous/failed cleanup must retain original authority"
                if mode == "unexpected-cleanup":
                    # The callback saw real original finality, not an ambiguous
                    # consumer. Only the product catch may have settled its
                    # journal; independently safe profile cleanup must complete.
                    (scope, binding, outcome), = post_result_cleanup
                    assert scope.outcome.read() is outcome and outcome.matches(scope, binding)
                    session = binding._session
                    assert status["session"] == session.token and session.state["inflight"] is None
                    assert json.loads((session.path / "state.json").read_bytes())["inflight"] is None
                    assert (session.path / "intent.json").read_bytes() == session._committed_controls["intent.json"]
                    assert not local_signing.FENCE_CONTROLS.intersection(path.name for path in session.path.iterdir())
                    assert not list(destination.parent.iterdir()), "settled profile cleanup did not finish independently"
                model.after = None
                model.result_policy = None
                recovered = local_signing.recover_signing(status["session"], local_signing.CONFIRMATION, home=home, runner=model)
                assert recovered["status"] in {"recovered", "recovered-with-conflict"}
            assert local_signing.signing_status(home=home)["status"] == "idle"
            assert not destination.exists()
            assert not list(destination.parent.iterdir()) if destination.parent.exists() else True
            for fd, device, inode in captured:
                try:
                    details = real_fstat(fd)
                except OSError:
                    continue
                assert (details.st_dev, details.st_ino) != (device, inode), "owned descriptor survived before fallback"
            assert {sig: signal.getsignal(sig) for sig in previous} == previous
            assert len(cleanup_calls) == 1, "cleanup was skipped or a claimed attempt was replayed"
            if standalone:
                assert not native_calls
            elif mode in {"body", "body-repeat", "mutation-create", "mutation-search", "mutation-default", "pre-yield",
                          "cleanup-entry", "cleanup-dispatch", "restore-entry", "restore-active", "restore-term", "restore-int", "cleanup-error-signal"}:
                assert any(argv[1] == "delete-keychain" for argv in native_calls)
            elif mode != "unexpected-cleanup":
                assert all(call[1] in {"list-keychains", "default-keychain"} and "-s" not in call for call in native_calls), "early cancellation must precede shared mutation"
            if mode == "body-repeat":
                assert len(signals) == 2
                assert any(argv[1] == "default-keychain" and "-s" in argv and argv[-1] == model.original["default"] for argv in native_calls)
            if mode == "partial-install":
                assert len(signals) == 2 and not native_calls
            return {"mode": requested_mode, "boundaries": reached, "signalCount": len(signals), "cleanupAttempts": len(cleanup_calls),
                    "ownedFilesAndDescriptorsGoneBeforeFallback": True, "handlersRestored": True,
                    "signingEffectsSynthetic": True, "nativeCallCount": len(native_calls),
                    "commandReceiptsSynthetic": False}
        finally:
            sys.settrace(None)
            sys.setprofile(None)
            # A failed assertion must not close a remembered FD that a live
            # native owner may still need. The original verification domain
            # disposes failed cases; successful cases proved all tracked FDs
            # gone above, before dropping these observation-only references.
            references.clear()


if __name__ == "__main__":
    print(json.dumps(run_case(_mode, Path(_temporary_parent))))
