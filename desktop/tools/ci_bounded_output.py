"""Bound one CI child's combined output without limiting its private file writes."""
import os
import selectors
import subprocess
import time


def run_bounded(argv, *, capture_path, cwd, env, timeout, limit):
    """Capture at most limit bytes; settle the original child on every exit.

    The single run deadline also covers EOF-before-exit and exit-before-EOF.
    Failure cleanup has at most two further seconds for the original wait; it
    cannot produce success or replace the primary failure. This is not a
    descendant supervisor: the fixed resolver retains its own command owner.
    """
    deadline = time.monotonic() + timeout
    output = selector = process = None
    failure = None
    try:
        output = open(capture_path, "xb")
        selector = selectors.DefaultSelector()
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   cwd=cwd, env=env)
        selector.register(process.stdout, selectors.EVENT_READ)
        used = 0
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, timeout)
            for key, _ in selector.select(remaining):
                chunk = os.read(key.fd, min(65536, limit - used + 1))
                if not chunk:
                    selector.unregister(process.stdout)
                    break
                room = limit - used
                output.write(chunk[:room])
                used += min(len(chunk), room)
                if len(chunk) > room:
                    raise ValueError("capture-output-bound")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(argv, timeout)
        returncode = process.wait(timeout=remaining)
        if returncode:
            raise subprocess.CalledProcessError(returncode, argv)
    except BaseException as error:
        failure = error
    finally:
        # Independent closes still run when kill/wait fails. Keep only finite
        # cleanup exception types as notes, not child arguments or private data.
        actions = []
        if process is not None:
            actions.extend((lambda: process.kill() if process.poll() is None else None,
                            lambda: process.wait(timeout=2)))
            if process.stdout is not None:
                actions.append(process.stdout.close)
        if selector is not None:
            actions.append(selector.close)
        if output is not None:
            actions.append(output.close)
        for close in actions:
            try:
                close()
            except BaseException as error:
                if failure is None:
                    failure = error
                else:
                    failure.add_note("capture-cleanup:" + type(error).__name__)
    if failure is not None:
        raise failure
    return returncode
