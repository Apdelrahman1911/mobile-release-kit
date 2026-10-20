"""Push phase facet of the SAME original pair/Acquisition/C-A-W channel.

Only the closed source/operation pair may select this facet. Acquisition, map2
export, STOP, all-copy EOF and actual descriptor close remain the existing
OriginalInputChannel implementation. No fresh listener, thread or FD owner.
"""
from __future__ import annotations

from . import _git_push_private_protocol as wire
from . import _git_remote_input_channel as original
from . import git_push_body as bodies
from . import git_push_transaction as transaction
from . import git_service as core


def is_original(channel, source):
    from ._desktop_git_push_control import GitPushInput
    return type(channel) is PushInputChannel and type(source) is GitPushInput


class _Refusal(core.GitError):
    def __init__(self, value):
        original._require(type(value) is wire.Returned and value.status == "refused")
        super().__init__("command-failed")
        self.reason = value.reason


class PushInputChannel(original.OriginalInputChannel):
    returned_type = wire.Returned
    refusal_type = _Refusal

    def __init__(self, source):
        super().__init__(source)
        self.hook_entered = self.hook_returned = self.send_entered = self.send_returned = False

    def _binding(self, initial, nonce, identity):
        operation = self.source.require_operation()
        tx = operation.repository._transaction
        original._require(type(tx) is transaction.PushTransaction and tx.running and tx.view is not None
                          and tx.session.repository is operation.repository and nonce == bytes.fromhex(initial.digest[:32]))
        tx.check_original(); tx.view.check()
        return wire.Binding(initial.id, wire.Clock(initial.digest, initial.work_end_ns, initial.hard_end_ns),
            tx.mode, tx.review_digest, tx.plan.remote, initial.target, identity, tx.view.root,
            bodies._stamp(tx.view.root.lstat()), tx.view.body_initial)

    def _transaction(self):
        operation = self.source.require_operation()
        tx = operation.repository._transaction
        original._require(type(tx) is transaction.PushTransaction and tx.running and tx.entered
                          and tx.session.repository is operation.repository and self.source.channel is self
                          and self.binding.review_digest == tx.review_digest and self.binding.mode == tx.mode
                          and self.binding.target == tx.plan.target and self.source.initial.digest == self.binding.digest)
        return tx

    def _accept_block(self, block, *, finishing):
        original._require(type(block) is bytes and type(finishing) is bool)
        if block == b"":
            original._require(finishing and self.producer_returned and self.client.state == "CLOSED"
                              and not self.incoming and not self.outgoing and self.get_sent
                              and type(self.helper_return) is wire.Returned)
            self.eof = True
            return
        original._require(not self.eof and self.helper_return is None)
        self.received += len(block)
        original._require(self.received <= wire.FRAME_LIMIT)
        self.incoming.extend(block)
        while b"\n" in self.incoming:
            original._require(not self.outgoing and self.helper_return is None)
            raw, _, tail = self.incoming.partition(b"\n")
            value = self.binding.accept_message(bytes(raw + b"\n"))
            self.incoming[:] = tail
            if type(value) is wire.Returned:
                original._require(self.get_entered and self.get_sent and not self.incoming)
                # Retain known response/control before later clock/closure
                # errors. This does not mint a receipt or mark a child joined.
                self.helper_return = value
                tx = self._transaction()
                if value.response is not None:
                    original._require(self.send_returned and tx.send_consumed)
                    tx.observe_status(value.response)
                self.source.helper_returned(self, value)
                continue
            original._require(not finishing)
            self.requests += 1
            original._require(self.requests <= 3)
            if value == "get":
                original._require(not self.get_entered and not self.hook_entered and not self.send_entered)
                self.get_entered = True
                self.source.require_operation().credential_current(self)
                self._current()
                token = self.source.take_helper_token(self)
                self.outgoing.extend(self.binding.grant(token))
                token = None
                self.outgoing_secret = True
                self._current()
            elif type(value) is wire.Hook:
                original._require(self.get_sent and not self.hook_entered and not self.send_entered)
                self.hook_entered = True
                self._current()
                tx = self._transaction()
                tx.hook(value.line, value.remote, value.url)
                self._current()
                self.hook_returned = True
                self.outgoing.extend(value.reply())
            else:
                original._require(type(value) is wire.Send and self.binding.mode == "apply"
                                  and self.get_sent and self.hook_returned and not self.send_entered)
                self.send_entered = True
                self._current()
                self._transaction().consume_send(value.body, value.stamp)
                self._current()
                self.send_returned = True
                self.outgoing.extend(self.binding.send_reply(value.body))
        original._require(self.helper_return is None or not self.incoming)

    def accept_return(self, operation, result):
        # The base gates actual C/A/W return + own client close + ALL-copy EOF
        # + peer close. Merely parsing any returned DATA above is insufficient.
        super().accept_return(operation, result)
        value, tx = self.helper_return, self._transaction()
        original._require(type(value) is wire.Returned and value.status == "ok"
                          and self.hook_returned and tx.hook_returned)
        if self.binding.mode == "apply":
            original._require(self.send_returned and tx.send_consumed)
        tx.observe_return(transaction.Returned(self.binding.mode, self.binding.target.selected,
            value.advertisement_sha256, tx.body_digest, value.response, value.after_sha256))
