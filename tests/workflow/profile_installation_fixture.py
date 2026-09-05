"""Real default signals at local profile ownership boundaries; no native calls.

The parent chooses the package under test (including an installed wheel). Every
file/descriptor is fixture-owned, and cleanup assertions precede fallback.
"""
from __future__ import annotations

import base64
import inspect
import json
import os
import signal
import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if __name__ == "__main__":
    sys.path[:0] = [sys.argv.pop(1), str(ROOT / "tests")]

from mobile_release import credentials
from mobile_release.cancellation import CleanupScope, DefaultCancellation
from mobile_release.config import load_config
from mobile_release.errors import CredentialError
from unit.helpers import ios_config, write_project
from unit.ios_entitlement_helpers import profile


def run_case(mode: str) -> dict:
    requested_mode = mode
    mode, _, selected_signal = mode.partition(":")
    default_signal = signal.SIGTERM if selected_signal == "TERM" else signal.SIGINT
    standalone, materialized = mode.startswith("standalone-"), mode.startswith("material-")
    mode = mode.removeprefix("standalone-").removeprefix("material-")
    real_open, real_close, real_fstat, real_fdopen = os.open, os.close, os.fstat, os.fdopen
    real_signal = signal.signal
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    assert previous == {signal.SIGINT: signal.default_int_handler, signal.SIGTERM: signal.SIG_DFL}
    captured, references, native_calls = {}, [], []
    signals, reached, visits, cleanup_calls, target_scopes = [], [], [], [], []
    installation_code = credentials._temporary_profile_installation.__wrapped__.__code__
    signing_code = credentials._temporary_apple_signing_environment.__wrapped__.__code__
    target_code = installation_code if standalone else signing_code
    lines, first = inspect.getsourcelines(credentials._temporary_profile_installation if standalone else credentials._temporary_apple_signing_environment)
    owner_line = next(first + index for index, text in enumerate(lines) if text.strip() == "with scope:")
    yield_line = next(first + index for index, text in enumerate(lines) if text.strip().startswith("yield"))
    lines, first = inspect.getsourcelines(CleanupScope.__exit__)
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
                if frame.f_code is CleanupScope.__exit__.__code__ and frame.f_locals["self"] is target and frame.f_lineno == exit_line:
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

    with tempfile.TemporaryDirectory(prefix="mrk-profile-signal-") as name:
        home = Path(name)
        private = home / "private"; private.mkdir()
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

        def native(argv, **kwargs):
            native_calls.append(argv)
            if argv[0] == "openssl" and "-out" in argv:
                Path(argv[argv.index("-out") + 1]).write_bytes(b"synthetic extracted material")
            restores_search = argv[:2] == ["security", "list-keychains"] and "-s" in argv and argv[-1] == "/fictional/login.keychain-db"
            if restores_search:
                if mode == "body-repeat":
                    send("enclosing-cleanup", signal.SIGTERM)
                elif mode == "unexpected-cleanup":
                    reached.append(mode)
                    raise RuntimeError("synthetic native cleanup failure")
                elif mode == "cleanup-error-signal":
                    send(mode)
                    return SimpleNamespace(returncode=1, stdout="", stderr="")
            if not reached and ((mode == "mutation-create" and argv[1] == "create-keychain")
                    or (mode == "mutation-search" and argv[1] == "list-keychains" and "-s" in argv)
                    or (mode == "mutation-default" and argv[1] == "default-keychain" and "-s" in argv)):
                send(mode, signal.SIGTERM)
            output = '"/fictional/login.keychain-db"\n' if argv[1] in {"default-keychain", "list-keychains"} and "-s" not in argv else ""
            return SimpleNamespace(returncode=0, stdout=output, stderr="")

        try:
            with ExitStack() as stack:
                stack.enter_context(patch("mobile_release.ios_profiles.decode_authenticated_profile", return_value=profile()))
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
                        stack.enter_context(patch.object(credentials.Path, "home", return_value=home))
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
                    assert mode != "unexpected-cleanup"
                except RuntimeError as error:
                    references.append(error)
                    assert mode == "unexpected-cleanup" and "synthetic native cleanup" in str(error)
                except CredentialError as error:
                    references.append(error)
                    assert mode == "cleanup-error-signal" and "could not be completely cleaned up" in str(error)
                finally:
                    sys.settrace(None)
                    sys.setprofile(None)
            assert reached, "dangerous boundary was never reached"
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
                assert not native_calls, "setup cancellation must precede keychain access"
            if mode == "body-repeat":
                assert len(signals) == 2
                assert any(argv[:2] == ["security", "default-keychain"] and "-s" in argv and argv[-1] == "/fictional/login.keychain-db" for argv in native_calls)
            if mode == "partial-install":
                assert len(signals) == 2 and not native_calls
            return {"mode": requested_mode, "boundaries": reached, "signalCount": len(signals), "cleanupAttempts": len(cleanup_calls),
                    "ownedFilesAndDescriptorsGoneBeforeFallback": True, "handlersRestored": True,
                    "nativeBoundarySynthetic": True}
        finally:
            sys.settrace(None)
            sys.setprofile(None)
            # Exact fixture-owned fallback; never enumerate/close arbitrary FDs.
            for fd, device, inode in captured:
                try:
                    details = real_fstat(fd)
                    if (details.st_dev, details.st_ino) == (device, inode):
                        real_close(fd)
                except OSError:
                    pass
            references.clear()


if __name__ == "__main__":
    print(json.dumps(run_case(sys.argv[1])))
