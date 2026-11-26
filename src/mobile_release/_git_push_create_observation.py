"""Five fixed create-only cases in the existing nonshipping Push observer.

Only provider bytes and comparison predicates live here. The existing Entry,
body sender, FD8 channel, native state and invocation owners remain original.
A synthetic `ng` response is not a real server's compare-and-swap proof.
"""
from __future__ import annotations

from . import git_push_new_branch as first

SCOPE = "git-push-create-native"
CASES = ("git-push-create-empty", "git-push-create-equal", "git-push-create-stale",
         "git-push-create-race", "git-push-create-held")
OTHER_REF = "refs/heads/fixture-peer"


def selection(value):
    from . import _git_push_observation_data as data
    data.need(type(value) is data.Transcript and value.case in CASES)
    return first.Selection(data.REFERENCE, data.REFERENCE, first.ZERO, value.target)


def binding_matches(binding, value):
    from . import _git_push_observation_data as data
    return (type(value) is data.Transcript and value.case in CASES
            and binding.remote is None and type(binding.target.selected) is first.Selection
            and binding.target.selected == selection(value))


def held_binding(binding):
    from . import _git_push_observation_data as data
    return (binding.mode == "apply" and binding.remote is None
            and type(binding.target.selected) is first.Selection
            and binding.target.repository == data.coordinate(CASES[4]))


def advertisement(value, mode, *, after=False):
    from . import _git_push_observation_data as data
    data.need(type(value) is data.Transcript and value.case in CASES
              and mode in ("review", "apply") and type(after) is bool
              and (not after or mode == "apply" and value.case == CASES[0]))
    reference, tip = data.REFERENCE, value.target
    if not after:
        if value.case == CASES[1]:
            pass  # Already equal is still occupied, never Up to date/create.
        elif value.case == CASES[2] and mode == "apply":
            tip = value.other
        elif value.case in (CASES[2], CASES[4]):
            reference, tip = OTHER_REF, value.other  # Target absent, not an empty repository.
        else:
            reference, tip = "capabilities^{}", first.ZERO
    row = (tip + " " + reference).encode("ascii") + b"\0report-status ofs-delta object-format=sha1\n"
    return data.packet(b"# service=git-receive-pack\n") + b"0000" + data.packet(row) + b"0000"


def receive_status(value):
    from . import _git_push_observation_data as data
    data.need(type(value) is data.Transcript and value.case in (CASES[0], CASES[3], CASES[4]))
    start = data.packet(b"unpack ok\n")
    if value.case == CASES[3]:
        return start + data.packet(("ng " + data.REFERENCE + " already exists\n").encode("ascii")) + b"0000"
    end = data.packet(("ok " + data.REFERENCE + "\n").encode("ascii"))
    return start + end[:-1] if value.case == CASES[4] else start + end + b"0000"


def next_response(supplier, case, method, path, role, private_body, budget, phase):
    """Called by the SAME Supplier after its ordinary role/body/clock checks."""
    from . import _git_push_observation_data as data
    from . import _git_push_observation_http as provider
    from . import git_push_body as bodies
    from . import git_push_transport as push
    binding, value = supplier.entry.binding, supplier.transcript
    data.need(case in CASES and binding_matches(binding, value)
              and binding.target.repository == data.coordinate(case)
              and binding.target.login == data.ACCOUNT
              and binding.target.account_id == data.ACCOUNT_ID
              and binding.target.repository_id == data.REPOSITORY_ID)
    apply = binding.mode == "apply"
    roles = ((push.ACCOUNT, push.REPOSITORY, push.ADVERTISEMENT, push.SEND,
              push.ACCOUNT, push.REPOSITORY, push.ADVERTISEMENT) if apply else
             (push.ACCOUNT, push.REPOSITORY, push.ADVERTISEMENT, push.ACCOUNT, push.REPOSITORY))
    data.need(phase < len(roles) and role == roles[phase])
    push.validate_endpoint(role, method, path)
    coordinate = data.coordinate(case)
    expected = ("/user" if role == push.ACCOUNT else "/repos/" + coordinate if role == push.REPOSITORY
                else "/" + coordinate + (".git/info/refs?service=git-receive-pack"
                                         if role == push.ADVERTISEMENT else ".git/git-receive-pack"))
    data.need(path == expected)
    if role == push.SEND:
        entry, helper = supplier.entry, supplier.entry.helper
        data.need(apply and case in (CASES[0], CASES[3], CASES[4]) and supplier.posts == 0
                  and supplier.sink is None and type(private_body) is bodies._PushBody
                  and private_body is helper.body and private_body.io is entry.body_io
                  and private_body.selected is binding.target.selected
                  and entry.send_returned and helper.send_point_returned and helper.pack_eof
                  and not private_body.request.sideband and not private_body.request.status_v2)
        # `_PushBody` already parsed the stock command against exact Selection.
        # Recheck its bounded prefix, never infer ZERO from an absent local ref.
        data.need(private_body.request.raw[4:].startswith(
            (first.ZERO + " " + value.target + " " + data.REFERENCE + "\0 ").encode("ascii")))
        if case == CASES[3]:
            supplier.tip = value.other  # Synthetic competing server DATA, before send.
        supplier.posts = 1  # Absorbing before the actual original body send.
        supplier.sink = provider._Sink(private_body)
        supplier.sink.send(budget.remaining)
        if case != CASES[3]:
            supplier.tip = value.target  # Does NOT prove real remote publication.
        return receive_status(value)
    data.need(private_body is None)
    if apply and phase > 3:
        data.need(case == CASES[0] and supplier.posts == 1 and supplier.sink is not None
                  and supplier.sink.complete and supplier.tip == value.target)
    if role == push.ACCOUNT:
        return data.account()
    if role == push.REPOSITORY:
        return data.repository(case)
    return advertisement(value, binding.mode, after=apply and phase == 6)


def audit(entry, supplier):
    """Bounded comparisons after the real helper, not a receipt or cleanup."""
    from . import _git_push_observation_data as data
    from ._desktop_git_push_helper import _Helper, _ReviewHelper
    data.need(binding_matches(entry.binding, supplier.transcript))
    mode, case = entry.binding.mode, supplier.transcript.case
    remote, helper = entry.transport, entry.helper
    refusal = mode == "review" and case == CASES[1] or mode == "apply" and case == CASES[2]
    if refusal:
        data.need(type(helper) is (_ReviewHelper if mode == "review" else _Helper)
                  and helper.failed and not helper.finished and not helper.entered
                  and getattr(helper, "body", None) is None and remote.failed and not remote.finished
                  and remote.offered is remote.posted is None and remote.phase == 3
                  and supplier.calls == supplier.phase == entry.budget.requests == 3
                  and supplier.posts == 0 and supplier.sink is None and not entry.send_entered
                  and getattr(entry.primary, "reason", None) == "target-changed")
        return
    data.need(case != CASES[1])
    if mode == "review":
        data.need(type(helper) is _ReviewHelper and helper.finished and helper.input_eof and not helper.failed
                  and remote.finished and not remote.failed and remote.phase == 5
                  and supplier.calls == supplier.phase == entry.budget.requests == 5
                  and supplier.posts == 0 and supplier.sink is None and remote.posted is None
                  and entry.body_io is None and not entry.send_entered and entry.primary is None)
        return
    data.need(mode == "apply" and case in (CASES[0], CASES[3], CASES[4])
              and type(helper) is _Helper and not helper.entered and supplier.sink is not None
              and entry.send_returned and helper.pack_eof and helper.send_point_returned
              and helper.body is supplier.sink.body and supplier.sink.complete and not supplier.sink.failed
              and helper.body.phase == "sent" and helper.body.sent == supplier.sink.count
              and supplier.posts == 1)
    if case == CASES[0]:
        data.need(supplier.tip == supplier.transcript.target and helper.finished and not helper.failed
                  and remote.finished and not remote.failed and remote.phase == 7
                  and supplier.calls == supplier.phase == entry.budget.requests == 7
                  and remote.posted.complete and remote.posted.value.outcome == "ok"
                  and remote.readback is not None and entry.primary is None)
        return
    reason = "remote-rejected" if case == CASES[3] else "response-invalid"
    data.need(supplier.tip == (supplier.transcript.other if case == CASES[3] else supplier.transcript.target)
              and helper.failed and not helper.finished and remote.failed and not remote.finished
              and remote.phase == 4 and supplier.calls == supplier.phase == entry.budget.requests == 4
              and remote.posted.failed and remote.readback is None
              and remote.posted.raw == receive_status(supplier.transcript)
              and getattr(entry.primary, "reason", None) == reason
              and entry.first_failure_ns is not None and entry.cleanup_end_ns is not None)
    data.need(remote.posted.value is None if case == CASES[4] else
              remote.posted.value is not None and remote.posted.value.outcome == "rejected")
