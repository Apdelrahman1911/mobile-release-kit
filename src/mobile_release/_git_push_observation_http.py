"""Closed nonshipping provider BYTES on the real Connection/Push parsers.

No sockets, credential API, general exchange, native admission or retry. The
one POST calls the actual original _PushBody.send into a count/hash-only sink.
BytesIO close and synthetic receive-status are NOT TLS/server-CAS qualification.
"""
from __future__ import annotations

import hashlib
import io
import json

from . import _git_push_observation_data as data
from . import _github_connection_transport as http
from . import git_push_body as bodies
from . import git_push_transport as push
from . import git_push_wire as wire


class _Sink:
    """One retained send attempt, no PACK backing or returned byte log."""
    __slots__ = ("body", "count", "digest", "prefix", "entered", "complete", "failed")

    def __init__(self, body):
        data.need(type(body) is bodies._PushBody and body.phase == "send-claimed"
                  and type(body.request) is wire.Command and 0 < len(body.request.raw) <= data.DATA_LIMIT)
        self.body, self.count, self.digest = body, 0, hashlib.sha256()
        self.prefix = bytearray()
        self.entered = self.complete = self.failed = False

    def write(self, block):
        data.need(self.entered and not self.complete and not self.failed and self.body.phase == "sending"
                  and type(block) is bytes and 0 < len(block) <= bodies.SEND_CHUNK
                  and len(block) <= self.body.digest.body_bytes - self.count)
        left = len(self.body.request.raw) - len(self.prefix)
        if left:
            self.prefix.extend(memoryview(block)[:left])
        self.count += len(block)
        self.digest.update(block)

    def send(self, before_write):
        data.need(not self.entered and not self.complete and not self.failed and callable(before_write))
        self.entered = True  # Retained before the first actual original read/send.
        try:
            self.body.send(self.write, before_write)
            data.need(self.body.phase == "sent" and not self.body.failed
                      and self.count == self.body.sent == self.body.digest.body_bytes
                      and self.digest.hexdigest() == self.body.digest.body_sha256
                      and self.prefix == self.body.request.raw)
            self.complete = True
        except BaseException:
            self.failed = True
            raise


class Supplier:
    def __init__(self, *, entry=None):
        self.entry, self.transcript, self.sink = entry, None, None
        self.entered = self.failed = False
        self.calls = self.phase = self.posts = 0
        self.tip = None

    def factory(self, token, *, started, runtime_dir, api_version,
                _profile=http._ExchangeProfile.STANDARD, _setup_budget=None,
                _git_remote_login=None, _git_remote_current=None,
                _git_remote_failure=None, _git_remote_control=None):
        data.need(not self.entered and not self.failed)
        self.entered = True
        case = data.token_case(token)
        selected = _profile is http._ExchangeProfile.GIT_PUSH
        data.need(selected or _profile is http._ExchangeProfile.STANDARD)
        data.need(api_version == ("2026-03-10" if selected else "2022-11-28"))
        if selected:
            from .desktop_git_push_helper import _Entry
            from ._git_push_private_protocol import Binding
            from ._git_push_observation_entry import read_transcript
            data.need(type(self.entry) is _Entry and type(self.entry.binding) is Binding
                      and _setup_budget is self.entry.budget and _git_remote_login == data.ACCOUNT
                      and _git_remote_current is self.entry._current_callback
                      and _git_remote_failure is self.entry._failure_callback
                      and callable(_git_remote_control))
            self.transcript = read_transcript(self.entry, case)
            self.tip = None if case in data.create.CASES else self.transcript.base
            budget = _setup_budget  # Original raw-clock bridge, not helper +45s.
        else:
            data.need(self.entry is None and _setup_budget is None
                      and _git_remote_login is _git_remote_current is _git_remote_failure is _git_remote_control is None)
            budget = http._Budget(started)
        data.need(type(budget) is http._Budget and budget.profile is _profile and budget.started == started)
        budget.remaining()

        def exchange(method, path, body=None, *, _role=http._ResponseRole.STANDARD,
                     _remote_delivery=None, _push_body=None, _push_delivery=None):
            data.need(not self.failed and self.calls < (7 if selected else 4))
            self.calls += 1
            try:
                if selected:
                    _git_remote_current()
                budget.remaining()
                data.need(_remote_delivery is None)
                http._request_limits(_profile, _role, method, path)
                if selected:
                    push.validate_body(_role.value, body, _push_body)
                    if _role.value in push.BINARY_ROLES:
                        data.need(type(_push_delivery) is push._Delivery)
                        _push_delivery.claim(_role.value, _push_body)
                    else:
                        data.need(_push_delivery is None)
                else:
                    data.need(body is _push_body is _push_delivery is None)
                budget.claim_request()
                response = self._next(case, method, path, body, _role.value, selected,
                                      _push_body, budget)
                media = push.response_media(_role.value) if selected and _role.value in push.BINARY_ROLES else "application/json"
                if type(response) is dict:
                    response = json.dumps(response, sort_keys=True, separators=(",", ":")).encode("ascii")
                data.need(type(response) is bytes and len(response) <= data.DATA_LIMIT)
                raw = (b"HTTP/1.1 200 Fixture\r\nContent-Type: " + media.encode("ascii")
                       + f"\r\nContent-Length: {len(response)}\r\n\r\n".encode("ascii") + response)
                data.need(len(raw) <= data.DATA_LIMIT + 512)
                source = io.BytesIO(raw)
                try:
                    parsed = http._ResponseBody(source, budget, _role=_role)
                    if selected:
                        parsed.control = http._header_control(parsed.head, budget, _role=_role)
                        if parsed.control is not None:
                            _git_remote_control(parsed.control)
                    result = http._response_result(parsed, budget, _push_delivery=_push_delivery,
                                                   _remote_failure=_git_remote_failure)
                    if selected:
                        _git_remote_control(result.control)
                        if result.observation.get("failure") not in (None, "none"):
                            _git_remote_failure(result.observation["failure"])
                    return result
                finally:
                    source.close()  # Real BytesIO close; no HTTP/TLS close claim.
            except BaseException as error:
                self.failed = True
                if selected:
                    _git_remote_failure(push.failure_reason(error))
                raise

        return exchange

    def _next(self, case, method, path, body, role, selected, private_body, budget):
        p = self.phase
        self.phase += 1  # No reentry or retry after an invalid/partial call.
        coordinate = data.coordinate(case)
        if not selected:
            routes = ("/user", "/repos/" + coordinate,
                      "/repos/" + coordinate + "/actions/workflows?per_page=100&page=1", "/repos/" + coordinate)
            data.need(p < len(routes) and role == "standard" and method == "GET" and path == routes[p]
                      and body is private_body is None)
            return data.account() if p == 0 else {"total_count": 0, "workflows": []} if p == 2 else data.repository(case)
        if case in data.create.CASES:
            return data.create.next_response(self, case, method, path, role, private_body, budget, p)
        binding, value = self.entry.binding, self.transcript
        data.need(binding.target.repository == coordinate and binding.target.login == data.ACCOUNT
                  and binding.target.account_id == data.ACCOUNT_ID and binding.target.repository_id == data.REPOSITORY_ID
                  and binding.target.selected == wire.Selection(data.REFERENCE, data.REFERENCE, value.base, value.target))
        apply = binding.mode == "apply"
        roles = ((push.ACCOUNT, push.REPOSITORY, push.ADVERTISEMENT, push.SEND,
                  push.ACCOUNT, push.REPOSITORY, push.ADVERTISEMENT) if apply else
                 (push.ACCOUNT, push.REPOSITORY, push.ADVERTISEMENT, push.ACCOUNT, push.REPOSITORY))
        data.need(p < len(roles) and role == roles[p])
        push.validate_endpoint(role, method, path)
        expected = ("/user" if role == push.ACCOUNT else "/repos/" + coordinate if role == push.REPOSITORY
                    else "/" + coordinate + (".git/info/refs?service=git-receive-pack" if role == push.ADVERTISEMENT else ".git/git-receive-pack"))
        data.need(path == expected)
        if role == push.SEND:
            data.need(apply and case != data.CASES[1] and self.posts == 0 and self.sink is None
                      and type(private_body) is bodies._PushBody and private_body is self.entry.helper.body
                      and private_body.io is self.entry.body_io and private_body.selected is binding.target.selected
                      and self.entry.send_returned and self.entry.helper.send_point_returned
                      and self.entry.helper.pack_eof and not private_body.request.sideband
                      and not private_body.request.status_v2)
            self.posts = 1
            self.sink = _Sink(private_body)
            self.sink.send(budget.remaining)  # Actual same-FD sender; no phase/receipt assignment.
            self.tip = value.target  # Synthetic peer DATA only after full actual send.
            return data.receive_status(value)
        data.need(private_body is None)
        if apply and p > 3:
            data.need(case == data.CASES[0] and self.posts == 1 and self.sink is not None
                      and self.sink.complete and self.tip == value.target)
        if role == push.ACCOUNT:
            return data.account()
        if role == push.REPOSITORY:
            return data.repository(case)
        return data.advertisement(value, binding.mode, after=apply and p == 6)
