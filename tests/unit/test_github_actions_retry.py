"""Synthetic DATA/BytesIO/fake HTTP only; no credentials, processes or network."""
import copy
import hashlib
import io
import unittest
from unittest.mock import patch

from mobile_release import github_actions_retry as p
from mobile_release import _desktop_github_actions_retry as wire
from mobile_release import _github_actions_retry_transport as transport
from mobile_release._github_actions_retry_journal import Journal
from mobile_release._github_connection_transport import (_Budget, _ExchangeProfile, _ResponseRole,
    _ResponseBody, _response_result, _control, _role_limits, ReadFailure, ReadResult)
from mobile_release.github_preflight import HttpRequest


def target(*, attempt=1, marker="b" * 32, account="11", repository="22", binding="a" * 64):
    return p.Target.parse({"scope": {"projectBinding": binding, "repository": "owner/app", "accountId": account, "repositoryId": repository},
        "selection": {"runId": "33", "attempt": attempt, "headSha": "c" * 40, "marker": marker}})


def repo():
    return {"id": 22, "full_name": "owner/app", "archived": False, "disabled": False, "permissions": {"push": True}}


def run(attempt=1):
    return {"id": 33, "run_attempt": attempt, "name": "Build and release", "workflow_id": 44,
        "path": ".github/workflows/release.yml", "status": "completed", "conclusion": "failure",
        "head_sha": "c" * 40, "head_branch": "main", "head_repository": repo(), "repository": repo(),
        "event": "workflow_dispatch", "created_at": "2026-10-01T12:00:00Z", "updated_at": "2026-10-01T12:10:00Z",
        "logs_url": "https://PRIVATE.invalid", "referenced_workflows": [{"private": "not projected"}]}


class Exchange:
    def __init__(self, change=None, *, attempt=1):
        self.calls = []; self.change = change; self.attempt = attempt; self.control = _control()

    def __call__(self, request):
        self.calls.append(request)
        status = 201 if request.method == "POST" else 200
        if request.method == "POST": body = None
        elif request.path == "/user": body = {"id": 11, "type": "User", "login": "owner"}
        elif request.path == "/repos/owner/app": body = repo()
        else: body = run(self.attempt)
        if self.change: status, body = self.change(request, len(self.calls), status, body)
        return ReadResult({"status": status, "body": body, "failure": "none"}, _control())


class MemoryJournal(Journal):
    """Real fixed journal logic with inert map storage, not filesystem custody."""
    def __init__(self, files=None):
        super().__init__("/inert-task-home", end=60)
        self.files = {} if files is None else files
    def _names(self): return set(self.files)
    def _read(self, name): return self.files[name]
    def _create(self, name, data):
        if name in self.files: raise OSError("inert exclusive create")
        self.files[name] = data
    def _post(self): pass


def prepared(*, attempt=1, marker="b" * 32):
    return p.prepare(target(attempt=attempt, marker=marker), Exchange(attempt=attempt))[0]


class ActionsRetryTests(unittest.TestCase):
    def test_review_reads_latest_run_and_discloses_dependent_jobs_external_effects_and_no_cas(self):
        e = Exchange(); review, _ = p.prepare(target(), e)
        self.assertEqual([c.path for c in e.calls], ["/user", "/repos/owner/app", "/repos/owner/app/actions/runs/33"])
        self.assertTrue(all(c.method == "GET" for c in e.calls))
        self.assertEqual(review.run["workflowId"], "44"); self.assertEqual(review.account_login, "owner")
        for word in ("dependent", "latest attempt", "immutable run", "publish", "existing privileges"):
            self.assertIn(word, review.value()["confirmation"])
        self.assertEqual(review.value()["retryPermission"], "not-proven")
        self.assertNotIn("PRIVATE", str(review.value()))
        self.assertEqual(p.digest(review), hashlib.sha256(p.canonical(review.value())).hexdigest())

    def test_one_exact_post_after_durable_claim_and_final_fresh_check(self):
        journal = MemoryJournal()
        def check(req, count, status, body):
            if req.method == "POST":
                self.assertEqual(count, 5)
                self.assertTrue(journal.attempts["b" * 32]["data"]["claimed"])
                self.assertEqual(req.path, "/repos/owner/app/actions/runs/33/rerun-failed-jobs")
                self.assertEqual(req.body, b'{"enable_debug_logging":false}')
            return status, body
        e = Exchange(check); result = p.retry(prepared(), e, journal)
        self.assertEqual(result["effect"], "accepted"); self.assertEqual(len(e.calls), 7)
        self.assertEqual([c.method for c in e.calls].count("POST"), 1)
        p.action_result(result, prepared(), "retry")
        self.assertTrue(journal.attempts["b" * 32]["data"]["acknowledged"])
        self.assertEqual(result["observed"]["attempt"], 1)  # Acceptance is not completion or observed advancement.

    def test_historical_attempt_running_success_and_new_source_never_post(self):
        for variant in ("account", "repository", "permission", "attempt", "sha", "success", "running", "workflow", "late-attempt"):
            with self.subTest(variant=variant):
                def change(req, n, status, body):
                    if variant == "account" and n == 1: body["id"] = 99
                    if variant == "repository" and n == 2: body["id"] = 99
                    if variant == "permission" and n == 2: body["permissions"]["push"] = False
                    if n == 3:
                        if variant == "attempt": body["run_attempt"] = 2
                        if variant == "sha": body["head_sha"] = "d" * 40
                        if variant == "success": body["conclusion"] = "success"
                        if variant == "running": body.update(status="in_progress", conclusion=None)
                        if variant == "workflow": body["workflow_id"] = 99
                    if variant == "late-attempt" and n == 4: body["run_attempt"] = 2
                    return status, body
                e = Exchange(change); j = MemoryJournal(); result = p.retry(prepared(), e, j)
                self.assertEqual(result["effect"], "not-sent")
                self.assertFalse(any(c.method == "POST" for c in e.calls))
                self.assertFalse(any(v["data"]["claimed"] for v in j.attempts.values()))

    def test_provider_may_choose_newer_attempt_without_changing_approved_run_source(self):
        def changed(req, n, status, body):
            if n == 6: body["run_attempt"] = 3
            return status, body
        result = p.retry(prepared(), Exchange(changed), MemoryJournal())
        self.assertEqual(result["effect"], "accepted"); self.assertEqual(result["observed"]["attempt"], 3)
        p.action_result(result, prepared(), "retry")

    def test_lost_post_reconcile_is_get_only_and_advancement_cannot_attribute_or_unfence(self):
        def lost(req, n, status, body):
            if req.method == "POST": raise ReadFailure("network-unavailable")
            return status, body
        j = MemoryJournal(); result = p.retry(prepared(), Exchange(lost), j)
        self.assertEqual(result["effect"], "potentially-applied")
        reload = MemoryJournal(j.files); reload._load(); row = reload.pending(target())[0]
        e = Exchange(attempt=2); result = p.reconcile(row, e)
        self.assertEqual(result["effect"], "advanced-unattributed")
        self.assertTrue(all(c.method == "GET" for c in e.calls)); self.assertFalse(result["acknowledged"])
        p.action_result(result, prepared(), "reconcile")
        with self.assertRaises(p.Refused): reload.create_intent(prepared(attempt=2, marker="e" * 32).value())
        with self.assertRaises(p.Refused): reload.claim()
        self.assertIsNone(reload.selected)

    def test_no_advancement_is_not_evidence_of_no_send(self):
        j = MemoryJournal(); j.create_intent(prepared().value()); j.claim()
        result = p.reconcile(j.pending(target())[0], Exchange())
        self.assertEqual(result["effect"], "unresolved"); self.assertIsNone(result["observed"])

    def test_accepted_older_attempt_allows_only_genuinely_new_explicit_review(self):
        j = MemoryJournal(); p.retry(prepared(), Exchange(), j)
        for n in (1,):
            again = MemoryJournal(j.files); again._load()
            with self.assertRaises(p.Refused): again.create_intent(prepared(attempt=n, marker="e" * 32).value())
        newer = MemoryJournal(j.files); newer._load()
        newer.create_intent(prepared(attempt=2, marker="e" * 32).value())
        self.assertEqual(newer.selected, "e" * 32)
        self.assertEqual(len([name for name in newer.files if name.endswith(".intent.json")]), 2)

    def test_unknown_cannot_be_bypassed_by_account_or_project_marker_alias(self):
        j = MemoryJournal(); j.create_intent(prepared().value()); j.claim()
        for changed in ({"accountId": "99"}, {"projectBinding": "d" * 64}):
            value = prepared(attempt=2, marker="e" * 32).value()
            value["target"]["scope"].update(changed)
            other = p.Prepared.parse(value)
            reload = MemoryJournal(j.files); reload._load()
            with self.assertRaises(p.Refused): reload.create_intent(other.value())

    def test_original_201_survives_journal_receipt_or_followup_read_failure(self):
        class LostReceipt(MemoryJournal):
            def record_accepted(self): raise p.Refused("journal-unavailable")
        result = p.retry(prepared(), Exchange(), LostReceipt())
        self.assertEqual(result["effect"], "accepted-unconfirmed"); self.assertTrue(result["acknowledged"])
        p.action_result(result, prepared(), "retry")
        def unavailable(req, n, s, b):
            if n == 6: raise ReadFailure("network-unavailable")
            return s, b
        j = MemoryJournal(); result = p.retry(prepared(), Exchange(unavailable), j)
        self.assertEqual(result["effect"], "accepted-unconfirmed")
        reload = MemoryJournal(j.files); reload._load()
        self.assertTrue(reload.pending(target())[0]["acknowledged"])
        recovered = p.reconcile(reload.pending(target())[0], Exchange(attempt=2))
        self.assertEqual(recovered["effect"], "accepted")

    def test_journal_failed_claim_and_invalid_restart_preserve_no_retry(self):
        class LostClaim(MemoryJournal):
            def _create(self, name, data):
                super()._create(name, data)
                if name.endswith(".claim.json"): raise OSError("injected receipt loss")
        j = LostClaim(); e = Exchange(); result = p.retry(prepared(), e, j)
        self.assertEqual(result["effect"], "not-sent"); self.assertFalse(any(c.method == "POST" for c in e.calls))
        reload = MemoryJournal(j.files); reload._load()
        self.assertTrue(reload.pending(target())[0]["claimed"])
        with self.assertRaises(p.Refused): reload.create_intent(prepared(attempt=2, marker="e" * 32).value())
        bad = dict(j.files); bad["b" * 32 + ".receipt.json"] = b'{"accepted":true,"status":201}\n'
        with self.assertRaises(ValueError): MemoryJournal(bad)._load()

    def test_capacity_is_explicit_no_eviction_or_file_deletion(self):
        j = MemoryJournal()
        for n in range(p.MAX_RECORDS):
            value = prepared(marker=f"{n+1:032x}").value(); value["target"]["scope"]["repositoryId"] = str(n+100)
            value["run"]["headRepositoryId"] = str(n+100)
            value = p.Prepared.parse(value)
            j.selected = None; j.create_intent(value.value())
        original = dict(j.files)
        j.selected = None
        with self.assertRaisesRegex(p.Refused, "unavailable") as failure: j.create_intent(prepared(marker="e"*32).value())
        self.assertEqual(failure.exception.reason, "journal-full"); self.assertEqual(j.files, original)

    def test_fixed_endpoint_body_budget_and_no_second_post(self):
        t = target(); path = "/repos/owner/app/actions/runs/33/rerun-failed-jobs"
        transport.request_role(t, HttpRequest("POST", path, p.POST_BODY))
        for bad in (path.replace("33", "34"), path.replace("rerun-failed-jobs", "rerun"), path+"?x=1", "/user"):
            with self.assertRaises(ValueError): transport.request_role(t, HttpRequest("POST", bad, p.POST_BODY))
        for body in (None, b"{}", b'{"enable_debug_logging":true}', p.POST_BODY+b" "):
            with self.assertRaises(ValueError): transport.request_role(t, HttpRequest("POST", path, body))
        b = _Budget(100.0, monotonic=lambda:100.1, _profile=_ExchangeProfile.ACTIONS_RETRY)
        self.assertEqual((b.end, b.body_total_limit), (160.0, 2*1024*1024))
        self.assertEqual(_role_limits(_ExchangeProfile.ACTIONS_RETRY, _ResponseRole.ACTIONS_RETRY_READ), (256*1024,1024))
        with self.assertRaises(ValueError): _role_limits(_ExchangeProfile.ACTIVITY, _ResponseRole.ACTIONS_RETRY_WRITE)
        with patch.object(transport, "_make_live_exchange", return_value=lambda *a, **k: ReadResult({"status":201,"body":None,"failure":"none"},_control())):
            send = transport.make_exchange(t,"SYNTHETIC",started=100.0,runtime_dir="/inert",budget=b,checkpoint=lambda:None)
            send(HttpRequest("POST",path,p.POST_BODY))
            with self.assertRaises(p.Refused): send(HttpRequest("POST",path,p.POST_BODY))
        for _ in range(8): b.claim_request()
        with self.assertRaises(ReadFailure): b.claim_request()

    def test_actual_transport_empty_201_framing_not_json_or_extra_bytes(self):
        for raw, success in [
            (b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n", True),
            (b"HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", True),
            (b"HTTP/1.1 201 Created\r\n\r\n", True),
            (b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\n{}", False),
            (b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\nx", False),
            (b"HTTP/1.1 201 Created\r\nContent-Type: text/html\r\n\r\n", False),
            (b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n", False),
        ]:
            with self.subTest(raw=raw):
                b=_Budget(100.0,monotonic=lambda:100.1,_profile=_ExchangeProfile.ACTIONS_RETRY)
                response=_ResponseBody(io.BytesIO(raw),b,_role=_ResponseRole.ACTIONS_RETRY_WRITE)
                result=_response_result(response,b)
                self.assertEqual(result.observation["failure"]=="none",success)
                if success: self.assertEqual(result.observation, {"status":201,"body":None,"failure":"none"})

    def test_private_codec_rejects_authority_injection_mismatches_and_duplicates(self):
        review=prepared(); action={"kind":"retry","target":target().value(),"home":"/inert-task-home","preparedSha256":p.digest(review)}
        raw=p.canonical({"protocol":p.PROTOCOL,"id":"actions-retry-1","action":action})+b"\n"
        initial=wire.parse_initial(raw)
        go={"protocol":p.PROTOCOL,"id":initial.id,"go":{"requestSha256":initial.digest,"token":"SYNTHETIC","prepared":review.value()}}
        self.assertEqual(wire.parse_go(p.canonical(go)+b"\n",initial)[1],review)
        for field in ("root","url","argv","retryAll","expectedAttemptCAS"):
            altered=copy.deepcopy(go); altered["go"][field]="forged"
            with self.assertRaises(ValueError): wire.parse_go(p.canonical(altered)+b"\n",initial)
        bad=copy.deepcopy(go); bad["go"]["prepared"]["run"]["headSha"]="f"*40
        with self.assertRaises(ValueError): wire.parse_go(p.canonical(bad)+b"\n",initial)
        with self.assertRaises(ValueError): wire.parse_initial(b'{"protocol":"x","protocol":"y"}\n')

    def test_result_codec_does_not_promote_uncertain_acceptance_to_native_or_ci_success(self):
        review=prepared(); e=Exchange(); j=MemoryJournal(); outcome=p.retry(review,e,j)
        raw=p.canonical({"protocol":p.PROTOCOL,"id":"actions-retry-1","action":{"kind":"retry","target":target().value(),"home":"/inert-task-home","preparedSha256":p.digest(review)}})+b"\n"
        initial=wire.parse_initial(raw)
        result={"schemaVersion":1,"kind":"retry","reason":"none","prepared":None,"retry":outcome,"pending":None,"control":_control()}
        encoded=wire.encode_result(initial,result,review)
        self.assertNotIn(b"SYNTHETIC",encoded); self.assertNotIn(b"workflowSuccess",encoded)
        for changed in ({"acknowledged":False},{"claimed":False},{"observed":None},{"effect":"succeeded"}):
            invalid=copy.deepcopy(outcome); invalid.update(changed)
            with self.assertRaises(ValueError): p.action_result(invalid,review,"retry")


if __name__ == "__main__": unittest.main()
