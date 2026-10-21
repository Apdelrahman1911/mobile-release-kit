"""Fixed create-only expectations for the SAME installed Push Fixtures.

No runner, runtime, process, credential or finality owner is created here.
The original common setup is reused, but never invents a tracking reference.
"""
import os
import re

SCOPE = "git-push-create-native"
CASES = ("git-push-create-empty", "git-push-create-equal", "git-push-create-stale",
         "git-push-create-race", "git-push-create-held")
ORIGINALS = ("HEAD", "config", "index", "refs/heads/main", "logs/HEAD", "logs/refs/heads/main",
             "mrk-push-observation.json")


def configuration(case, need):
    need(type(case) is str and case in CASES, "push-create-fixture-case")
    return ("[core]\nrepositoryformatversion = 0\nfilemode = true\nbare = false\nlogallrefupdates = true\n"
            "[user]\nname = MRK Push Fixture\nemail = push-fixture@example.invalid\n").encode("ascii")


def absence(f, git, signature, scan, need):
    """Exact original parent rosters, not a pretend missing-file snapshot."""
    rows = []
    for parent, names in (("refs", ("heads", "tags")), ("logs/refs", ("heads",))):
        from contextlib import ExitStack
        with ExitStack() as held:
            fd = git
            for part in parent.split("/"):
                fd = held.enter_context(f._temporary(f._open(part, fd, directory=True)))
            before = signature(os.fstat(fd))
            need(scan(f, fd, 4) == names, "push-create-tracking-not-absent")
            need(signature(os.fstat(fd)) == before, "push-create-absence-parent-changed")
            rows.append((parent, before))
    return tuple(rows)


def report(value, case, need):
    fields = {"mechanism", "case", "syntheticProviderBytes", "connectionOriginalJoined", "readOriginalJoined",
              "prepareOriginalJoined", "applyRequested", "applyOriginalJoined", "connectionRetired", "remoteReturned",
              "helperRefusedBeforeAllCopyEof", "producerPendingBeforeStop", "sameTicketStop", "toolSha256",
              "normalQuitOriginal", "allOriginalsSettled", "worktreePreserved", "shippingNominationEnabled",
              "tlsQualified", "liveAccountQualified", "productionQualified"}
    need(type(value) is dict and value.keys() == fields and type(case) is str and case in CASES
         and value["case"] == case and value["mechanism"] == "same-original-git-push-create-v1",
         "push-create-observer-report")
    for key in ("syntheticProviderBytes", "connectionOriginalJoined", "readOriginalJoined", "prepareOriginalJoined",
                "connectionRetired", "allOriginalsSettled", "worktreePreserved"):
        need(value[key] is True, "push-create-originals-not-settled")
    for key in ("shippingNominationEnabled", "tlsQualified", "liveAccountQualified", "productionQualified"):
        need(value[key] is False, "push-create-nonshipping-scope")
    requested = case != CASES[1]
    need(value["applyRequested"] is requested and value["applyOriginalJoined"] is requested
         and value["remoteReturned"] is (case == CASES[0])
         and type(value["normalQuitOriginal"]) is int and value["normalQuitOriginal"] == 2
         and type(value["toolSha256"]) is str and re.fullmatch("[0-9a-f]{64}", value["toolSha256"]),
         "push-create-original-report-fields")
    for key in ("helperRefusedBeforeAllCopyEof", "producerPendingBeforeStop", "sameTicketStop"):
        need(value[key] is (case == CASES[4]), "push-create-helper-stop-window")
    return value
