"""Two closed in-memory response transcripts, never an HTTP implementation.

The fixed nonshipping entries install this supplier before the unchanged
Connection reader or remote Entry factory. Original budgets, parsing/schedules,
private pipe/FD8 IO and native joins remain real. BytesIO is deliberately NOT
socket/TLS/remote-account qualification. No endpoint, token or callback is
accepted from a renderer and there is no network fallback.
"""
from __future__ import annotations

import io
import json

from . import _git_fetch_observation_data as data
from . import _github_connection_transport as http
from . import git_remote_transport as remote


class Supplier:
    def __init__(self, *, entry=None):
        # Entry is the actual helper instance, before acquire(). It supplies
        # only the held fixture DATA read, not currentness or a made-up lease.
        self.entry = entry
        self.entered = False
        self.transcript = None
        self.phase = 0
        self.failed = False
        self.calls = 0

    def factory(self, token, *, started, runtime_dir, api_version,
                _profile=http._ExchangeProfile.STANDARD, _setup_budget=None,
                _git_remote_login=None, _git_remote_current=None,
                _git_remote_failure=None, _git_remote_control=None):
        data.need(not self.entered and not self.failed)
        self.entered = True  # Before any original callback or fixture file IO.
        case = data.token_case(token)
        selected = _profile is http._ExchangeProfile.GIT_REMOTE
        data.need(selected or _profile is http._ExchangeProfile.STANDARD)
        data.need(api_version == ("2026-03-10" if selected else "2022-11-28"))
        if selected:
            data.need(self.entry is not None and _setup_budget is self.entry.budget
                      and _git_remote_login == data.ACCOUNT
                      and _git_remote_current is self.entry._current_callback
                      and _git_remote_failure is self.entry._failure_callback
                      and callable(_git_remote_control))
            from ._git_fetch_observation_entry import read_transcript
            self.transcript = read_transcript(self.entry, case)
            budget = _setup_budget  # SAME raw-clock bridge, never helper-launch +45.
        else:
            data.need(self.entry is None and _setup_budget is None
                      and _git_remote_login is _git_remote_current is _git_remote_failure is _git_remote_control is None)
            budget = http._Budget(started)  # Original Connection's supplied start.
        data.need(type(budget) is http._Budget and budget.profile is _profile and budget.started == started)
        budget.remaining()

        def exchange(method, path, body=None, *, _role=http._ResponseRole.STANDARD, _remote_delivery=None):
            data.need(not self.failed and self.calls < (7 if selected else 4))
            self.calls += 1
            try:
                if selected:
                    _git_remote_current()
                budget.remaining()
                http._request_limits(_profile, _role, method, path)
                response = self._next(case, method, path, body, _role.value, selected)
                if _remote_delivery is not None:
                    data.need(selected and _role.value in remote.BINARY_ROLES)
                    _remote_delivery.claim(_role.value, body)
                budget.claim_request()
                media = remote.response_media(_role.value) if selected and _role.value in remote.BINARY_ROLES else "application/json"
                if type(response) is dict:
                    response = json.dumps(response, sort_keys=True, separators=(",", ":")).encode("ascii")
                raw = (b"HTTP/1.1 200 Fixture\r\nContent-Type: " + media.encode("ascii")
                    + f"\r\nContent-Length: {len(response)}\r\n\r\n".encode("ascii") + response)
                # One <=64KiB fixture body, no pack spool or native socket.
                data.need(len(raw) <= data.DATA_LIMIT)
                source = io.BytesIO(raw)
                try:
                    parsed = http._ResponseBody(source, budget, _role=_role)
                    if selected:
                        # Real control parser, no supplied expiry/cooldown or
                        # replacement first-F timestamp from the fixture.
                        parsed.control = http._header_control(parsed.head, budget, _role=_role)
                        if parsed.control is not None:
                            _git_remote_control(parsed.control)
                    result = http._response_result(parsed, budget, _remote_delivery=_remote_delivery,
                        _remote_failure=_git_remote_failure)
                    if selected:
                        _git_remote_control(result.control)
                        if result.observation.get("failure") not in (None, "none"):
                            _git_remote_failure(result.observation["failure"])
                    return result
                except BaseException as error:
                    if selected:
                        _git_remote_failure(remote.failure_reason(error))
                    raise
                finally:
                    source.close()  # Actual BytesIO close, NOT TLS/HTTP finality.
            except BaseException as error:
                self.failed = True
                if selected:
                    _git_remote_failure(remote.failure_reason(error))
                raise

        return exchange

    def _next(self, case, method, path, body, role, selected):
        p = self.phase
        self.phase += 1
        coordinate = data.coordinate(case)
        if not selected:
            routes = ("/user", "/repos/" + coordinate,
                      "/repos/" + coordinate + "/actions/workflows?per_page=100&page=1", "/repos/" + coordinate)
            data.need(p < len(routes) and role == "standard" and method == "GET" and path == routes[p] and body is None)
            return data.account() if p == 0 else {"total_count": 0, "workflows": []} if p == 2 else data.repository(case)
        data.need(self.entry.binding.target.repository == coordinate and self.entry.binding.target.login == data.ACCOUNT
                  and self.entry.binding.target.account_id == data.ACCOUNT_ID
                  and self.entry.binding.target.repository_id == data.REPOSITORY_ID
                  and self.entry.binding.target.selected.reference == data.REFERENCE)
        apply = self.entry.binding.target.selected.oid is not None
        roles = (remote.ACCOUNT, remote.REPOSITORY, remote.ADVERTISEMENT, remote.LS_REFS,
                 *((remote.FETCH,) if apply else ()), remote.ACCOUNT, remote.REPOSITORY)
        data.need(p < len(roles) and role == roles[p])
        remote.validate_endpoint(role, method, path)
        remote.validate_body(role, body)
        expected = ("/user" if role == remote.ACCOUNT else "/repos/" + coordinate if role == remote.REPOSITORY
                    else "/" + coordinate + (".git/info/refs?service=git-upload-pack" if role == remote.ADVERTISEMENT else ".git/git-upload-pack"))
        data.need(path == expected and (not apply or self.entry.binding.target.selected.oid == self.transcript.target))
        if role == remote.ACCOUNT:
            return data.account()
        if role == remote.REPOSITORY:
            return data.repository(case)
        if role == remote.ADVERTISEMENT:
            return data.advertisement()
        if role == remote.LS_REFS:
            return data.refs(self.transcript)
        return data.fetch(self.transcript)
