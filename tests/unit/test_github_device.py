"""Inert device protocol + actual shared HTTP delegates with all IO faked.

No provider, token, syscall/CA, native clock, child or keyring is exercised.
"""
from __future__ import annotations
import json
import unittest
from unittest.mock import patch
from mobile_release import github_device_protocol as w
from mobile_release import _desktop_github_device as d
from mobile_release import _github_connection_transport as h
from mobile_release.cancellation import DefaultCancellation
from mobile_release.owned_process import ProcessCleanupError
from test_git_remote_transport import FakeLive, raw_http


def request(role='start', **changes):
    value = dict(protocol=w.PROTOCOL, id='child-1', role=role,
        context=dict(operationId='device-1', projectId='project', repository='owner/repo', generation=1, sequence=0 if role=='start' else 1),
        clientId='INERT-PUBLIC-CLIENT', deviceCode=None if role=='start' else 'INERT-DEVICE', clock=dict(workEndNs=1, hardEndNs=2))
    value.update(changes)
    return value

CODE = dict(device_code='INERT-DEVICE', user_code='ABCD-1234', verification_uri=w.VERIFICATION_URI, expires_in=900, interval=5)
TOKEN = dict(access_token='INERT-NOT-A-CREDENTIAL', token_type='bearer', scope='repo')

class DeviceProtocolTests(unittest.TestCase):
    def test_exact_request_context_role_clock_and_secret_fields(self):
        for role in ('start','poll'):
            value=w.parse_request(w.encode(request(role)));self.assertEqual(value.role,role)
            self.assertNotEqual(w.ready(value),w.go(value));self.assertNotIn(b'INERT-DEVICE',w.ready(value))
        for change in ({'id':'bad.id'},{'id':'x'*65},{'role':'refresh'}, {'clientSecret':'private'}, {'clock':dict(workEndNs=1,hardEndNs=2**63)}, {'deviceCode':'unexpected'}):
            with self.subTest(change=change),self.assertRaises(w.ProtocolError):w.parse_request(w.encode(request(**change)))
        raw=w.encode(request())
        for bad in (raw+b'\n',raw.replace(b'"start"',b'"start","role":"poll"',1),raw[:-1]):
            with self.assertRaises(w.ProtocolError):w.parse_request(bad)
    def test_form_exact_no_scope_escalation_or_alternate_grant(self):
        for role,code in (('start',None),('poll','INERT-+&CODE')):
            raw=w.form(role,'INERT',code);w.validate_body('device-'+role,raw)
            for bad in (raw+b'&client_id=other',raw+b'&redirect_uri=https%3A%2F%2Fevil',raw.replace(b'repo',b'repo%20workflow'),raw+b'&scope=repo'):
                if bad==raw:continue
                with self.assertRaises(w.ProtocolError):w.validate_body('device-'+role,bad)
    def test_code_provider_expiry_fixed_url_and_bounds(self):
        got=w.provider_reply('start',CODE);self.assertEqual((got['kind'],got['expiresIn'],got['interval']),('code',900,5))
        self.assertEqual(w.provider_reply('start',{k:v for k,v in CODE.items() if k!='interval'})['interval'],5)
        for field,value in [('expires_in',True),('expires_in',901),('interval',0),('device_code','x'*1025),('user_code','bad'),('verification_uri',w.VERIFICATION_URI+'?code=ABCD-1234')]:
            with self.subTest(field=field),self.assertRaises(w.ProtocolError):w.provider_reply('start',{**CODE,field:value})
    def test_pending_slowdown_is_same_private_continuation_not_failure(self):
        for upstream,kind in [('authorization_pending','pending'),('slow_down','slow-down')]:
            got=w.provider_reply('poll',{'error':upstream,'error_description':'Discard me'});self.assertEqual(got,{'kind':kind})
            req=w.parse_request(w.encode(request('poll')));frame=w.terminal(req,'ok',got)
            self.assertIsNone(w.decode(frame)['firstFailureNs']);self.assertNotIn(b'Discard',frame)
        with self.assertRaises(w.ProtocolError):w.provider_reply('start',{'error':'authorization_pending'})
    def test_token_strict_bearer_scopes_expiry_and_mixed_reply(self):
        self.assertIsNone(w.provider_reply('poll',TOKEN)['expiresIn'])
        for extra in ({'token_type':'Basic'},{'scope':'repo,repo'},{'scope':'repo workflow'},{'expires_in':0},{'expires_in':True},{'expires_in':2**32},{'refresh_token':'private'},{'error':'authorization_pending'},{'access_token':'x'*4097}):
            with self.subTest(extra=extra),self.assertRaises(w.ProtocolError):w.provider_reply('poll',{**TOKEN,**extra})
    def test_raw_size_duplicate_depth_and_first_failure(self):
        for raw in (b'{"error":"slow_down","error":"authorization_pending"}',b' '*16385,b'['*8+b'0'+b']'*8):
            with self.assertRaises(w.ProtocolError):w.decode(raw)
        req=w.parse_request(w.encode(request('poll')))
        self.assertEqual(w.decode(w.terminal(req,'refused',None,7))['firstFailureNs'],7)
        with self.assertRaises(w.ProtocolError):w.terminal(req,'ok',{'kind':'pending'},7)
        with self.assertRaises(w.ProtocolError):w.terminal(req,'refused',None,2**63)
    def test_no_child_execution_and_missing_original_not_an_empty_receipt(self):
        source=d.DeviceInput(0.0)
        with self.assertRaises(w.ProtocolError):source.command_limits(1,True,100)
        operation=object.__new__(d.DeviceOperation);operation.entered=True;operation.returned=False;operation.unknown=False
        operation.cleanup();self.assertTrue(operation.unknown);self.assertFalse(operation.closed)
        operation.entered=False;operation.unknown=False;operation.cleanup();self.assertTrue(operation.closed)

class DeviceTransportTests(unittest.TestCase):
    def original(self,world,role='start'):
        # Exact production objects/claim checks, with only original syscall and
        # clock returns inert. Does not forge a native receipt/qualification.
        req=w.parse_request(w.encode(request(role)));source=d.DeviceInput(0.0)
        guard=DefaultCancellation(ProcessCleanupError,'inert')
        source.initial=req;source.guard=guard;source.go_returned=True
        operation=d.DeviceOperation(req,source,guard)
        self.enterContext(patch.object(guard,'check',return_value=None))
        self.enterContext(patch.object(guard,'_saved_command_input',return_value=source))
        self.enterContext(patch.object(d.time,'monotonic',return_value=1.0))
        clock=h._Budget(0.0,monotonic=lambda:1.0,_profile=h._ExchangeProfile.DEVICE)
        operation.entered=True;operation.budget=clock
        exchange=h._make_live_exchange(None,started=0.0,runtime_dir='/inert',api_version='2022-11-28',
            _profile=h._ExchangeProfile.DEVICE,_setup_budget=clock,_device_owner=operation)
        return source,operation,clock,exchange
    def test_same_fixed_factory_headers_single_post_and_actual_close_order(self):
        world=FakeLive(self,[raw_http(h._ResponseRole.STANDARD,CODE)])
        source,op,clock,exchange=self.original(world)
        result=exchange('POST','/login/device/code',w.form('start','INERT-PUBLIC-CLIENT',None),_role=h._ResponseRole.DEVICE_START)
        self.assertEqual(w.provider_reply('start',result.observation['body'])['kind'],'code')
        self.assertEqual(world.closes,['response','connection']);self.assertIsNone(source.first_failure)
        method,path,headers,body=world.calls[0]
        self.assertEqual((method,path,headers['Host']),('POST','/login/device/code','github.com'))
        self.assertNotIn('Authorization',headers);self.assertNotIn('X-GitHub-Api-Version',headers)
        self.assertEqual(headers['Content-Type'],'application/x-www-form-urlencoded')
        self.assertEqual(world.wraps[0]['server_hostname'],'github.com')
        with self.assertRaises(h.ReadFailure):exchange('POST',path,body,_role=h._ResponseRole.DEVICE_START)
        self.assertEqual(len(world.calls),1)
    def test_healthy400_pending_not_first_failure_and_no_credentials_header(self):
        world=FakeLive(self,[raw_http(h._ResponseRole.STANDARD,{'error':'authorization_pending'},status=400)])
        source,op,clock,exchange=self.original(world,'poll')
        result=exchange('POST','/login/oauth/access_token',w.form('poll','INERT','INERT-DEVICE'),_role=h._ResponseRole.DEVICE_POLL)
        self.assertEqual(w.provider_reply('poll',result.observation['body']),{'kind':'pending'})
        self.assertIsNone(source.first_failure);self.assertEqual(world.closes,['response','connection'])
    def test_same_original_owner_required_before_ca_or_network_and_old_profile_refuses(self):
        with patch.object(h,'_fixed_ca',side_effect=AssertionError('must not enter')):
            with self.assertRaises(ValueError):h._make_live_exchange(None,started=0.0,runtime_dir='/inert',api_version='2022-11-28',_profile=h._ExchangeProfile.DEVICE)
        for profile in (h._ExchangeProfile.STANDARD,h._ExchangeProfile.GIT_REMOTE,h._ExchangeProfile.SETUP):
            with self.assertRaises(ValueError):h._request_limits(profile,h._ResponseRole.DEVICE_START,'POST','/login/device/code')
        for method,path in [('GET','/login/device/code'),('POST','https://github.com/login/device/code'),('POST','/user')]:
            with self.assertRaises(ValueError):h._request_limits(h._ExchangeProfile.DEVICE,h._ResponseRole.DEVICE_START,method,path)
    def test_invalid_response_failure_precedes_real_fake_close_and_no_retry(self):
        world=FakeLive(self,[raw_http(h._ResponseRole.STANDARD,{},status=302)])
        source,op,clock,exchange=self.original(world)
        events=[]
        def failure(reason):events.append((reason,list(world.closes)));source.first_failure=1.0
        with patch.object(op,'failure',side_effect=failure):
            exchange('POST','/login/device/code',w.form('start','INERT',None),_role=h._ResponseRole.DEVICE_START)
        self.assertTrue(events);self.assertEqual(events[0][1],[]);self.assertEqual(len(world.calls),1)
    def test_original_close_failure_unknown_and_16k_limit_not_ordinary_limit(self):
        world=FakeLive(self,[raw_http(h._ResponseRole.STANDARD,CODE)])
        source,op,clock,exchange=self.original(world);world.fail_close=OSError('synthetic-close')
        with self.assertRaises(h._CloseFailure):exchange('POST','/login/device/code',w.form('start','INERT',None),_role=h._ResponseRole.DEVICE_START)
        self.assertTrue(op.unknown);self.assertEqual(world.closes,['response','connection'])
        self.assertEqual(h._role_limits(h._ExchangeProfile.DEVICE,h._ResponseRole.DEVICE_POLL)[0],16384)
        self.assertEqual(clock.body_total_limit,16384)
        self.assertEqual(h._role_limits(h._ExchangeProfile.STANDARD,h._ResponseRole.STANDARD)[0],h.MAX_BODY_BYTES)

    def test_first_failure_callback_exception_does_not_skip_either_original_close(self):
        world=FakeLive(self,[raw_http(h._ResponseRole.STANDARD,{},status=302)])
        source,op,clock,exchange=self.original(world)
        events=[]
        def broken(reason):
            events.append((reason,list(world.closes)))
            raise RuntimeError('inert original recorder failure')
        with patch.object(op,'failure',side_effect=broken),self.assertRaises(h._CloseFailure):
            exchange('POST','/login/device/code',w.form('start','INERT',None),_role=h._ResponseRole.DEVICE_START)
        self.assertTrue(events);self.assertEqual(events[0][1],[])
        self.assertEqual(world.closes,['response','connection'])
        self.assertEqual(len(world.calls),1)

    def test_uncaught_private_guard_failure_is_recorded_before_original_closes(self):
        world=FakeLive(self,[raw_http(h._ResponseRole.STANDARD,CODE)])
        source,op,clock,exchange=self.original(world)
        events=[]
        def failure(reason):events.append((reason,list(world.closes)))
        with patch.object(op,'failure',side_effect=failure),patch.object(h,'_response_result',side_effect=w.ProtocolError('inert guard')):
            with self.assertRaises(w.ProtocolError):
                exchange('POST','/login/device/code',w.form('start','INERT',None),_role=h._ResponseRole.DEVICE_START)
        self.assertTrue(events);self.assertEqual(events[0],('response-invalid',[]))
        self.assertEqual(world.closes,['response','connection']);self.assertEqual(len(world.calls),1)
