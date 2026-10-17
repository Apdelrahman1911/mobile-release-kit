"""Inert candidate UI composition tests; no native process, app or Store work."""
from copy import deepcopy
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from desktop.tools import macos_candidate_ui as U
from desktop.tools import macos_normal_ui_runner as N
from desktop.tools import macos_fixed_carrier_resume as R

WORK = Path('/Users/runner/work/_temp/mrk-macos-installed.ABCDEFGH')


def fixture(target=R.TARGETS[0]):
    selected = dict(source='a'*40, tree='b'*40, target=target, runId='17', runAttempt='2', jobId='19',
                    artifactId='23', artifactBytes=4096, artifactSha256='c'*64)
    context = dict(helperSource='d'*40, target=target, runId='31', runAttempt='1', work=WORK/'resume-carrier')
    install = dict(scope='candidate-fresh-installer-observation', target=target, producerSource=selected['source'],
        producerTree=selected['tree'], artifactId='23', artifactSha256='c'*64, producerRunId='17', producerRunAttempt='2',
        producerJobId='19', helperSource='d'*40, helperTree='e'*40, consumerRunId='31', consumerRunAttempt='1',
        originalInstallerReturnedZero=True, sameRequestReadback=True, originalMountDetached=True, originalClosesKnown=True,
        workloadsKnownSettled=True, privateOutputsRetired=True, productReady=False, uiQualified=False, p0Qualified=False)
    return selected, context, install


def persistence_body():
    method='-[MRKNormalAppUITests.NormalAppUITests testSyntheticPersistentCredentials]'
    return ('\n'.join(["Test Case '"+method+"' started.",
        'MRK_MACOS_PERSISTENCE_LIFETIME=phase=1'+U.LIFETIME_SUFFIX,
        'MRK_MACOS_PERSISTENCE_LIFETIME=phase=2'+U.LIFETIME_SUFFIX,
        U.PERSISTENCE_MARKER, "Test Case '"+method+"' passed (1.0 seconds).", ''])).encode()


def saved_checks_body(reverse=False):
    methods=[('testSyntheticProjectSavedOfflineChecks',
        ['MRK_MACOS_NORMAL_OFFLINE_UI=ordinary-ui-observed-saved-offline-report-and-settled-projection;'
         'missing=2;skipped=1;releaseReadiness=not-assessed;cleanExitStatus=unavailable;allWorkerFinality=unavailable']),
        ('testSyntheticProjectEmptyBuildInputInspection',[U.RECOVERY_IDLE_MARKER,U.STORE_ENTRY_MARKER])]
    lines=[]
    for method,markers in reversed(methods) if reverse else methods:
        name='-[MRKNormalAppUITests.NormalAppUITests '+method+']'
        lines.extend(["Test Case '"+name+"' started.", N.ORIGINAL_MARKER, *markers,
                      "Test Case '"+name+"' passed (1.0 seconds)."])
    return ('\n'.join([*lines,''])).encode()


def diagnostics_body():
    method='-[MRKNormalAppUITests.NormalAppUITests testSyntheticProjectBuildToolDiagnostics]'
    return ('\n'.join(["Test Case '"+method+"' started.",N.ORIGINAL_MARKER,
        'MRK_MACOS_NORMAL_DIAGNOSTICS_UI=ordinary-ui-observed-original-diagnostics-report-and-settled-projection;'
        'commandsAttempted=4;cleanExitStatus=unavailable;allWorkerFinality=unavailable',
        "Test Case '"+method+"' passed (1.0 seconds).",''])).encode()


def ios_body():
    value=dict(schemaVersion=1,scope='one-ordinary-local-unsigned-ios-archive',sourceCommit='a'*40,
        savedVersion='1.2.3',savedBuild=7,inputFiles=9,inputBytes=7264,topLevelDirectories=4,
        archiveDescendantsObserved=False,nativeResultDisplayed=True,outputPostMatched=True,originalsClosed=True,
        normalQuitObserved=True,successBeforeCutoff=True,signed=False,ipaExported=False,releaseQualified=False,
        parentReturncodeRequired=0,operationId='1'*32,ownerGeneration='2'*32,originalEntries=8,originalBytes=999)
    method='-[MRKNormalAppUITests.NormalAppUITests '+N.IOS_UNSIGNED_METHOD+']'
    return ('\n'.join(["Test Case '"+method+"' started.",N.ORIGINAL_MARKER,
        N.IOS_UNSIGNED_PREFIX.decode()+N.encoded(value).decode(),"Test Case '"+method+"' passed (1.0 seconds).",''])).encode()



def saved_document_body(name):
    method, marker = {
        'release-evidence-test': ('testSyntheticProjectSavedReleaseEvidence',
            'MRK_MACOS_NORMAL_RELEASE_EVIDENCE_UI=ordinary-picker-candidate-documents-only-shared-guidance-stage-retained-replacement-cancel-stale-release-inputs-empty-originals-preserved;cleanExitStatus=unavailable;allWorkerFinality=unavailable;remoteRelease=not-attempted'),
        'workflow-refusal-test': ('testSyntheticProjectManagedWorkflowRefusal',
            'MRK_MACOS_NORMAL_WORKFLOW_REFUSAL_UI=ordinary-preview-customized-candidate-whole-bundle-refused-originals-preserved;cleanExitStatus=unavailable;allWorkerFinality=unavailable'),
    }[name]
    selected = '-[MRKNormalAppUITests.NormalAppUITests ' + method + ']'
    return ('\n'.join(["Test Case '" + selected + "' started.", N.ORIGINAL_MARKER, marker,
                       "Test Case '" + selected + "' passed (1.0 seconds).", ''])).encode()

def saved_version_body():
    method = '-[MRKNormalAppUITests.NormalAppUITests testSyntheticProjectSavedVersionRecovery]'
    return ('\n'.join(["Test Case '"+method+"' started.",N.ORIGINAL_MARKER,N.SAVED_VERSION_MARKER,
                       "Test Case '"+method+"' passed (1.0 seconds).",''])).encode()


def saved_version_recovery(target):
    value={k:'9'*64 for k in ('sourceInputsSha256','runtimeManifestSha256','sourceClosureSha256',
        'fixtureDataSha256','producerSha256','producerFramesSha256','handoffSha256')}
    value.update(producerReturncode=86,publicOriginalCount=13,readyJournalFileCount=6,
        interruptedGuiSaveObserved=False,originalFixtureRestored=True,unrelatedOriginalsUnchanged=True,
        readyJournalRemoved=True,sourcePrePostMatched=True,uiOriginalMarkersObserved=True,originalClosesCompleted=True,
        currentRuntimeWitness=dict(scope=U.SAVED_VERSION_SCOPE,applicationSourceCommit='a'*40,harnessSourceCommit='d'*40,
            target=target,release='macos26-'+('arm64' if target==N.ARM_TARGET else 'x86_64')+'-current-test',
            installedCoreMatched=True,installedWrappersMatched=True))
    return value


def phase_fixture(name, target=R.TARGETS[0], *, ios_tools=False, saved_files=False, saved_version=False):
    selected, context, install=fixture(target)
    args, req=U.phase_request(N,name,target,WORK,ios_tools=ios_tools,saved_files=saved_files,saved_version=saved_version)
    mode=req['phase']; result=None if req['result'] is None else req['result'].name
    out=(saved_version_body() if name=='saved-version-recovery-test' else saved_document_body(name) if name in ('release-evidence-test','workflow-refusal-test') else diagnostics_body() if name=='diagnostics-test' else ios_body() if name=='ios-unsigned-archive-test' else
         persistence_body() if name=='persistence-test' else saved_checks_body() if name=='saved-checks-test' else
         R.canonical(dict(totalTestCount=2 if name in ('project-summary','saved-checks-summary') else 1,
            passedTests=2 if name in ('project-summary','saved-checks-summary') else 1,failedTests=0,skippedTests=0,expectedFailures=0))
         if mode=='summary' else b'inert returned native output\n')
    row=dict(scope='actual-generated-xctrunner-admission-only' if mode=='test' else 'normal-ui-original-command-admission-only',
        sourceCommit=selected['source'],target=target,sourcePrePostMatched=True,originalCommandReturned=True,
        resultBundle=result,receiptPolicy='exclusive0600-readback-consuming-close',sourceRosterSha256='f'*64,
        fileLimitBytes=[32<<30,32<<30] if mode=='build' else [1<<30,1<<30],
        phaseClock=dict(startNs='1',deadlineNs=str(1+req['phaseSeconds']*10**9),beforePublicationNs='2',postCloseDeadlineRequired=True))
    if saved_version:
        row.update(sourceCommit=context['helperSource'],applicationSourceCommit=selected['source'],currentCandidateScope=U.SAVED_VERSION_SCOPE)
        if mode=='test':row['savedVersionRecovery']=saved_version_recovery(target)
    row['normalPhase' if mode=='test' else 'phase']=mode
    row['originalTestReturncode' if mode=='test' else 'originalReturncode']=0
    if mode=='test':
        row.update(originalClosesCompleted=True,originalProductsPrePostMatched=True,strictCodesignOriginalZero=True,reSignedOrRepaired=False)
        if name=='project-test':row.update(projectFieldAndEditMarkersObserved=True,androidToolSourceBrowseMarkerObserved=True)
        if name=='applications-test':row['applicationsLaunchObservationMarker']=True
        if name=='release-evidence-test':row['savedReleaseEvidenceMarkerObserved']=True
        if name=='workflow-refusal-test':row['managedWorkflowRefusalMarkerObserved']=True
    if name=='ios-unsigned-archive-test':row['iosUnsignedObservation']=N.ios_unsigned_marker(out,source=selected['source'])
    if name=='ios-unsigned-archive-summary':row['iosUnsignedTestCounts']=N.ios_unsigned_summary(out)
    src=('normal-ui-source-roster',15,1048576)
    roles=([src,*[('normal-toolchain-'+k,15,4096) for k in ('xcode','sdkPath','sdkVersion','sdkBuild')],
        ('normal-ui-build',240,1048576),src] if mode=='build' else
        [src,('verify-generated-runner',30,1048576),('generated-runner-entitlements',30,1048576),
         ('one-admitted-ui-test',req['timeout'],1048576),src] if mode=='test' else
        [src,('normal-ui-summary',30,262144),src])
    if saved_version and mode=='test':roles[1:1]=[('saved-version-source-roster',15,65536),('saved-version-core-interrupt',20,65536)]
    commands=[]
    for index,(role,cap,limit) in enumerate(roles):
        stdout=out if index==len(roles)-2 else b'inert source roster'
        commands.append(dict(role=role,returncode=86 if role=='saved-version-core-interrupt' else 0,timeoutSeconds=cap,roleCapSeconds=cap,outputLimitBytes=limit,
            argvSha256='a'*64,stdoutBytes=len(stdout),stdoutSha256=R.sha(stdout),stderrBytes=0,stderrSha256=R.sha(b'')))
    row['commands']=commands
    return selected,context,install,args,req,row,out


class CandidateUITests(unittest.TestCase):
    def test_same_job_install_handoff_is_not_legacy_or_forged_finality(self):
        for target in (N.ARM_TARGET,N.INTEL_TARGET):
            selected,context,value=fixture(target)
            self.assertEqual(U.install_admission_data(value,selected,context),value)
            for key,bad in [('originalClosesKnown',False),('originalInstallerReturnedZero',1),('uiQualified',True),
                ('producerSource','d'*40),('helperSource','a'*40),('consumerRunAttempt','2'),('helperTree','0'*40)]:
                changed=dict(value);changed[key]=bad
                with self.subTest(target=target,key=key),self.assertRaises(R.Refused):U.install_admission_data(changed,selected,context)
            with self.assertRaises(R.Refused):U.install_admission_data(dict(value,fixedCarrierResumeScope='fixed-ce644'),selected,context)

    def test_only_existing_same_source_phases_targets_and_clean_environment(self):
        for target in (N.ARM_TARGET,N.INTEL_TARGET):
            selected,_,_=fixture(target)
            for name in U.PHASES:
                args,req=U.phase_request(N,name,target,WORK)
                self.assertEqual(N.normal_request(args,str(WORK/'normal-ui/tmp')+'/'),req)
                self.assertEqual(req['phaseSeconds'],450 if name=='build' else 90 if name.endswith('summary') else
                                 885 if name in ('project-test','saved-checks-test') else 345 if name=='applications-test' else 585)
            env=U.clean_environment(N,selected,WORK)
            self.assertEqual(env['TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE'],selected['source'])
            self.assertEqual(env['TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE'],selected['source'])
            self.assertNotIn('GITHUB_TOKEN',env);self.assertNotIn('GITHUB_SHA',env)
            self.assertFalse(any('FIXED' in k or 'CREDENTIAL' in k or 'SIGNING' in k for k in env))
        for name in ('remove','sign','ios-unsigned-archive-test','saved-version-recovery-test','--normal-build'):
            with self.assertRaises(R.Refused):U.phase_request(N,name,N.ARM_TARGET,WORK)

    def test_closed_ios_cohort_reuses_original_requests_markers_and_counts(self):
        for target in (N.ARM_TARGET,N.INTEL_TARGET):
            for phase in U.IOS_TOOL_PHASES:
                selected,_,_,args,request,row,body=phase_fixture(phase,target,ios_tools=True)
                self.assertEqual(N.normal_request(args,str(WORK/'normal-ui/tmp')+'/'),request)
                self.assertEqual(U.phase_admission_data(row,request,selected['source'],body,b'',normal=N),'f'*64)
                if phase=='ios-unsigned-archive-test':
                    self.assertEqual(args[-1],'--normal-ios-unsigned-archive-test')
                    self.assertEqual((request['allowance'],request['timeout'],request['phaseSeconds']),(900,1020,1245))
                    for key,bad in (('signed',True),('schemaVersion',True)):
                        wrong=deepcopy(row);wrong['iosUnsignedObservation'][key]=bad
                        with self.assertRaises((R.Refused,N.Refused)):U.phase_admission_data(wrong,request,selected['source'],body,b'',normal=N)
                if phase=='ios-unsigned-archive-summary':
                    wrong=deepcopy(row);wrong['iosUnsignedTestCounts']['totalTestCount']=True
                    with self.assertRaises((R.Refused,N.Refused)):U.phase_admission_data(wrong,request,selected['source'],body,b'',normal=N)
            for phase in ('project-test','persistence-test','saved-checks-test','applications-test'):
                with self.assertRaises(R.Refused):U.phase_request(N,phase,target,WORK,ios_tools=True)
        for args in (['--ios-tools'],['--ios-tools','project-test'],['--other','build'],['--ios-tools','build','extra']):
            with mock.patch.object(sys,'argv',['helper',*args]),mock.patch.object(U.consumer,'entry_context') as entry:
                with self.assertRaises(R.Refused):U.main()
                entry.assert_not_called()
        body=diagnostics_body()
        for changed in (body.replace(b'commandsAttempted=4',b'commandsAttempted=0'),
                body.replace(b'commandsAttempted=4',b'commandsAttempted=5'),body+body,
                body.replace(b'originalTerminated=1',b'originalTerminated=0'),body.replace(b' passed (',b' skipped ('),
                body+b'MRK_MACOS_UI_FAILURE_CLEANUP=1\n'):
            with self.assertRaises(R.Refused):U.diagnostics_markers(changed)

    def test_saved_files_cohort_exact_existing_selectors_and_marker_boundaries(self):
        self.assertEqual(U.SAVED_FILE_PHASES, ('build','release-evidence-test','release-evidence-summary',
            'workflow-refusal-test','workflow-refusal-summary'))
        for target in (N.ARM_TARGET,N.INTEL_TARGET):
            for phase in U.SAVED_FILE_PHASES:
                selected,_,_,args,request,row,body=phase_fixture(phase,target,saved_files=True)
                self.assertEqual(N.normal_request(args,str(WORK/'normal-ui/tmp')+'/'),request)
                self.assertEqual(request['phaseSeconds'],450 if phase=='build' else 90 if phase.endswith('summary') else 585)
                self.assertEqual(U.phase_admission_data(row,request,selected['source'],body,b'',normal=N),'f'*64)
                if phase.endswith('-test'):
                    self.assertEqual(request['methods'],tuple(N.CLASS+m for m in N.NORMAL_SELECTIONS[phase+'.xcresult'][0]))
                    for replacement in (body.replace(b' passed (',b' skipped ('), body+body,
                                        body.replace(b'originalTerminated=1',b'originalTerminated=0')):
                        wrong=deepcopy(row); command=wrong['commands'][-2]
                        command.update(stdoutBytes=len(replacement),stdoutSha256=R.sha(replacement))
                        with self.assertRaises((R.Refused,N.Refused)):
                            U.phase_admission_data(wrong,request,selected['source'],replacement,b'',normal=N)
            for phase in ('project-test','saved-checks-test','ios-unsigned-archive-test','saved-version-recovery-test'):
                with self.assertRaises(R.Refused):U.phase_request(N,phase,target,WORK,saved_files=True)
            with self.assertRaises(R.Refused):U.phase_request(N,'build',target,WORK,ios_tools=True,saved_files=True)
        for args in (['--saved-files'],['--saved-files','project-test'],['--saved-files','--ios-tools','build']):
            with mock.patch.object(sys,'argv',['helper',*args]),mock.patch.object(U.consumer,'entry_context') as entry:
                with self.assertRaises(R.Refused):U.main()
                entry.assert_not_called()

    def test_current_saved_version_exact_source_roles_and_refusals(self):
        for target in (N.ARM_TARGET,N.INTEL_TARGET):
            selected,context,_=fixture(target)
            env=U.clean_environment(N,selected,WORK,helper_source=context['helperSource'])
            self.assertEqual(env['TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE'],selected['source'])
            self.assertEqual(env['TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE'],context['helperSource'])
            self.assertEqual(env[N.SAVED_VERSION_CURRENT_ENV],N.SAVED_VERSION_CURRENT_SCOPE)
            self.assertNotIn(N.SAVED_VERSION_CURRENT_ENV,U.clean_environment(N,selected,WORK))
            for phase in U.SAVED_VERSION_PHASES:
                _,_,_,args,req,row,body=phase_fixture(phase,target,saved_version=True)
                self.assertEqual(req,N.normal_request(args,str(WORK/'normal-ui/tmp')+'/'))
                self.assertEqual(U.phase_admission_data(row,req,selected['source'],body,b'',normal=N,
                    helper_source=context['helperSource']),'f'*64)
                with self.assertRaises(R.Refused):U.phase_admission_data(row,req,selected['source'],body,b'',normal=N)
                for key,bad in [('sourceCommit',selected['source']),('applicationSourceCommit','8'*40),('currentCandidateScope','foreign')]:
                    changed=deepcopy(row);changed[key]=bad
                    with self.assertRaises(R.Refused):U.phase_admission_data(changed,req,selected['source'],body,b'',normal=N,helper_source=context['helperSource'])
                if phase.endswith('-test'):
                    self.assertEqual([x['returncode'] for x in row['commands']],[0,0,86,0,0,0,0])
                    for edit in ('zero','unknown','wrong-role','close','wrong-app','extra-receipt','late'):
                        changed=deepcopy(row)
                        if edit in ('zero','unknown'):changed['commands'][2]['returncode']=0 if edit=='zero' else None
                        elif edit=='wrong-role':changed['commands'][1]['role']='normal-ui-source-roster'
                        elif edit=='close':changed['savedVersionRecovery']['originalClosesCompleted']=False
                        elif edit=='wrong-app':changed['savedVersionRecovery']['currentRuntimeWitness']['applicationSourceCommit']='8'*40
                        elif edit=='extra-receipt':changed['savedVersionRecovery']['runtimeResultSha256']='9'*64
                        else:changed['phaseClock']['beforePublicationNs']=changed['phaseClock']['deadlineNs']
                        with self.subTest(edit=edit),self.assertRaises(R.Refused):
                            U.phase_admission_data(changed,req,selected['source'],body,b'',normal=N,helper_source=context['helperSource'])
                    for bad in (body+body,body.replace(b'originalTerminated=1',b'originalTerminated=0')):
                        changed=deepcopy(row);changed['commands'][-2].update(stdoutBytes=len(bad),stdoutSha256=R.sha(bad))
                        with self.assertRaises((R.Refused,N.Refused)):
                            U.phase_admission_data(changed,req,selected['source'],bad,b'',normal=N,helper_source=context['helperSource'])
            for phase in ('project-test','release-evidence-test','ios-unsigned-archive-test'):
                with self.assertRaises(R.Refused):U.phase_request(N,phase,target,WORK,saved_version=True)
            with self.assertRaises(R.Refused):U.phase_request(N,'build',target,WORK,saved_version=True,saved_files=True)
            with self.assertRaises(R.Refused):U.clean_environment(N,selected,WORK,helper_source=selected['source'])
        for args in (['--saved-version'],['--saved-version','project-test'],['--saved-version','--saved-files','build']):
            with mock.patch.object(sys,'argv',['helper',*args]),mock.patch.object(U.consumer,'entry_context') as entry:
                with self.assertRaises(R.Refused):U.main()
                entry.assert_not_called()

    def test_restart_requires_both_original_lifetimes_one_attempt_and_no_failure_cleanup(self):
        body=persistence_body();self.assertTrue(U.persistence_markers(body))
        changes=[body.replace(b'phase=1',b'phase=2'),body.replace(b'phase=2',b'phase=3'),
            body.replace(b'originalTerminated=1',b'originalTerminated=0',1),body+body,
            body+b'MRK_MACOS_UI_FAILURE_CLEANUP=1\n',body.replace(b' passed (',b' failed (')]
        for changed in changes:
            with self.assertRaises(R.Refused):U.persistence_markers(changed)

    def test_saved_checks_require_two_originals_and_same_build_no_effect_marker(self):
        body=saved_checks_body()
        self.assertTrue(U.saved_checks_markers(body));self.assertTrue(U.saved_checks_markers(saved_checks_body(True)))
        changes=[body.replace(b'missing=2',b'missing=1'),body.replace(b'missing=2',b'missing=129'),
            body.replace(b'storeActions=not-run',b'storeActions=passed'),
            body.replace(U.STORE_ENTRY_MARKER.encode()+b'\n',b''),body+U.STORE_ENTRY_MARKER.encode()+b'\n',
            body.replace(b'originalTerminated=1',b'originalTerminated=0',1),
            body.replace(b'testSyntheticProjectSavedOfflineChecks',b'testSyntheticProjectEmptyBuildInputInspection'),
            body.replace(b' passed (',b' failed (',1),body+b'MRK_MACOS_UI_FAILURE_CLEANUP=1\n']
        for changed in changes:
            with self.subTest(body=changed[:32]),self.assertRaises(R.Refused):U.saved_checks_markers(changed)

    def test_exact_native_admission_and_counts_do_not_accept_zero_test_or_fixed_profile(self):
        for target in (N.ARM_TARGET,N.INTEL_TARGET):
            for name in U.PHASES:
                selected,_,_,_,req,row,out=phase_fixture(name,target)
                self.assertEqual(U.phase_admission_data(row,req,selected['source'],out,b''),'f'*64)
                for mutate in (lambda r:r.update(fixedCarrierResumeScope='fixed-ce644'),
                    lambda r:r.update(sourceCommit='d'*40),lambda r:r['commands'][-1].update(returncode=1),
                    lambda r:r['commands'][-2].update(stdoutSha256='0'*64),
                    lambda r:r['phaseClock'].update(deadlineNs='2'),lambda r:r.update(fileLimitBytes=[1,1])):
                    changed=deepcopy(row);mutate(changed)
                    with self.assertRaises(R.Refused):U.phase_admission_data(changed,req,selected['source'],out,b'')
                if name.endswith('summary'):
                    wrong=R.canonical(dict(totalTestCount=0,passedTests=0,failedTests=0,skippedTests=0,expectedFailures=0))
                    changed=deepcopy(row);changed['commands'][1].update(stdoutBytes=len(wrong),stdoutSha256=R.sha(wrong))
                    with self.assertRaises(R.Refused):U.phase_admission_data(changed,req,selected['source'],wrong,b'')

    def test_actual_owned_wrapper_known_nonzero_unknown_and_changed_post_never_publish_status(self):
        for fault in (None,'nonzero','unknown','post'):
            selected,context,_,_,req,row,out=phase_fixture('project-test')
            events=[]
            class Book:
                def __init__(self):self.entries=[];self.directories={WORK/'normal-ui':{}}
                def check(self):events.append('check')
                def publish(self,path,body):self.entries.append({'path':path});events.append(('publish',path.name))
                def file(self,path,limit,**kw):self.entries.append({'path':path});return self.entries[-1],R.canonical(row)
                def finish(self):return True
            class Owner:
                def run_owned(self,argv,**kw):
                    events.append('entered')
                    self.kw=kw;self.argv=argv
                    if fault=='unknown':raise RuntimeError('inert unknown native owner')
                    failure = R.canonical(dict(schemaVersion=1,scope='generated-ui-runner-refused',productReady=False,
                        error='runner-admission-or-owner-error',stage='execute',exceptionClass='Refused',
                        sourceFrames=[],commands=[],ownerFailure=dict(dispatched=True,contained=True,cleanupComplete=True),
                        unknownStateRetained=True)) if fault=='nonzero' else b''
                    return subprocess.CompletedProcess(argv,1 if fault=='nonzero' else 0,out,failure)
            count=0
            def verify():
                nonlocal count
                count+=1;events.append('source'+str(count))
                if fault=='post' and count==2:raise R.Refused('inert source POST')
            quota=R.OriginalQuota();book=quota.book(Book);owner=Owner()
            clock=N.PhaseClock(req['phaseSeconds']+180,now=lambda:1,started=1)
            call=lambda:U.run_phase(N,owner,book,quota,context,selected,'project-test',clock,verify)
            if fault is None:self.assertEqual(call(),'f'*64)
            else:
                with self.assertRaises((R.Refused,RuntimeError)):call()
            self.assertFalse(any(isinstance(e,tuple) and e[1].endswith('.status') for e in events))
            self.assertLess(events.index('source1'),events.index('entered'))
            if fault=='unknown':self.assertFalse(any(isinstance(e,tuple) for e in events))
            if fault=='nonzero':
                self.assertNotIn('source2',events)
                self.assertEqual(U.NATIVE_DIAGNOSTIC['status'],'observed-exception-only')
                self.assertEqual(U.NATIVE_DIAGNOSTIC['stage'],'execute')
                self.assertEqual(U.NATIVE_DIAGNOSTIC['exceptionClass'],'Refused')
            self.assertEqual(owner.kw['timeout'],req['phaseSeconds']+15)
            self.assertEqual(owner.kw['environ'],U.clean_environment(N,selected,WORK))
            self.assertEqual(owner.kw['cwd'],U.consumer.CANDIDATE_ROOT)

    def test_prior_caller_status_is_required_even_after_success_shaped_inner_receipt(self):
        selected,_,_,_,_,row,out=phase_fixture('build')
        contents={'build.status':b'0\n','build.command-admission.json':R.canonical(row),'build.stdout':out,'build.stderr':b''}
        read=lambda path,cap:contents[path.name]
        self.assertEqual(U.read_phase(read,N,'build',selected,WORK),'f'*64)
        for status in (b'1\n',b'',b'0',b'0\n1\n'):
            contents['build.status']=status
            with self.assertRaises(R.Refused):U.read_phase(read,N,'build',selected,WORK)

    def test_actual_main_refuses_handoff_before_loading_code_and_attempts_original_closes(self):
        selected,context,value=fixture();value['originalClosesKnown']=False
        book=SimpleNamespace(entries=[],directories={},finish=mock.Mock(return_value=False))
        def file(path,*a,**kw):
            return {},R.canonical({'schemaVersion':1,'targets':{selected['target']:selected}}) if path.name.endswith('selection.json') else R.canonical(value)
        book.file=file
        with mock.patch('resource.setrlimit'),mock.patch.object(U.consumer,'entry_context',return_value=context),mock.patch.object(U,'ROOT',U.consumer.HELPER_ROOT),\
             mock.patch.object(U.Path,'cwd',return_value=U.consumer.CANDIDATE_ROOT),mock.patch.object(U.resume,'bootstrap_originals',return_value=lambda:book),\
             mock.patch.object(U.resume.OriginalQuota,'call',side_effect=lambda b,m,p,*a,**kw:getattr(b,m)(p,*a,**kw)),\
             mock.patch.object(U.resume,'load_module') as load,mock.patch.object(sys,'argv',['candidate-ui','build']):
            with self.assertRaisesRegex(R.Refused,'candidate-ui-install-handoff') as caught:U.main()
            load.assert_not_called();book.finish.assert_called_once()
            self.assertIn('candidate-ui-original-final-closes',caught.exception.__notes__)



class CandidateUIMainTests(unittest.TestCase):
    def exercise(self, name, target, unknown_close=False, *, ios_tools=False, saved_files=False, saved_version=False, native_fault=None):
        import os, stat
        selected,context,install=fixture(target)
        files={};directories=set();books=[];effects=[];modes={}
        root=U.consumer.HELPER_ROOT
        sources=tuple(dict.fromkeys((*U.consumer.HELPER_SOURCE_INPUTS,U.consumer.CONSUMER_PATH,
            U.consumer.LEGACY_PATH,U.consumer.PARSER_PATH,U.RUNNER,'desktop/tools/macos_candidate_ui.py')))
        for path in sources:
            actual=ROOT/path
            files[root/path]=actual.read_bytes() if actual.exists() else b'inert source\n'
            modes[root/path]=0o644
        files[root/U.consumer.SELECTION_PATH]=R.canonical({'schemaVersion':1,'targets':{target:selected}})
        modes[root/U.consumer.SELECTION_PATH]=0o644
        files[U.consumer.CANDIDATE_ROOT/U.RUNNER]=files[root/U.RUNNER];modes[U.consumer.CANDIDATE_ROOT/U.RUNNER]=0o644
        files[WORK/'consumer-result.json']=R.canonical(install)
        host=WORK/'host-python';base=Path('/inert-base/bin/python3');binary=b'inert python never executed'
        cfg=('home = /inert-base/bin\ninclude-system-site-packages = false\nversion = 3.14.7\n'
             'executable = /inert-base/bin/python3\ncommand = /inert-base/bin/python3 -m venv --copies '
             '--without-pip --without-scm-ignore-files '+str(host)+'\n').encode()
        for relative in (*R.HOST_FILES,R.HOST_OPTIONAL):
            executable=relative in ('bin/python','bin/python3','bin/python3.14',R.HOST_OPTIONAL)
            files[host/relative]=binary if executable else cfg if relative=='pyvenv.cfg' else b'inert activation'
            modes[host/relative]=0o755 if executable else 0o644
        files[base]=binary;modes[base]=0o755
        for relative in R.HOST_DIRS:directories.add(host/relative)
        files[Path('/usr/bin/git')]=b'inert system tool';modes[Path('/usr/bin/git')]=0o755
        def info(path):
            path=Path(path)
            return SimpleNamespace(st_dev=1,st_ino=int.from_bytes(__import__('hashlib').sha256(str(path).encode()).digest()[:6],'big'),
                st_mode=(stat.S_IFREG|modes.get(path,0o600)) if path in files else stat.S_IFDIR|0o700,
                st_uid=0 if str(path).startswith('/usr') else os.getuid(),st_gid=0 if str(path).startswith('/usr') else os.getgid(),
                st_nlink=1,st_size=len(files[path]) if path in files else 0,st_mtime_ns=1,st_ctime_ns=1)
        def children(path):
            return sorted({p.relative_to(path).parts[0] for p in (*files,*directories) if p!=path and p.is_relative_to(path)})
        basevalue=dict(launcherPath=str(base),executable=str(base),copyPath=str(base),copyExecutable=str(base),prefix='/inert-base',
                       identity=list(R.identity(info(base))),sha256=R.sha(binary))
        snapshot,_=R.host_snapshot(host,lambda p:(R.identity(info(p)),children(p)),lambda p,n:(R.identity(info(p)),files[p]))
        files[host/'host-binding.json']=R.canonical(dict(schemaVersion=1,source=context['helperSource'],runId='31',runAttempt='1',
            base=basevalue,prefix=str(host),basePrefix='/inert-base',baseExecutable=str(base),**snapshot,retainedUntilHostedTeardown=True))
        phases=U.selected_phases(ios_tools=ios_tools,saved_files=saved_files,saved_version=saved_version)
        arguments=['candidate-ui',*(['--saved-version'] if saved_version else ['--saved-files'] if saved_files else ['--ios-tools'] if ios_tools else []),name]
        previous=phases if name=='result' else phases[:phases.index(name)]
        if name!='build':directories.add(WORK/'normal-ui');directories.add(WORK/'normal-ui/tmp')
        for phase in previous:
            _,_,_,_,_,row,out=phase_fixture(phase,target,ios_tools=ios_tools,saved_files=saved_files,saved_version=saved_version)
            for suffix,body in (('.status',b'0\n'),('.stdout',out),('.stderr',b'')):
                files[WORK/'normal-ui'/(phase+suffix)]=body
            files[WORK/'normal-ui'/U.admission_name(phase)]=R.canonical(row)
        class Book:
            def __init__(self):self.entries=[];self.directories={};self.attempts=[];books.append(self)
            def directory(self,path):
                path=Path(path)
                if path not in self.directories:
                    if path!=Path('/'):self.directory(path.parent)
                    directories.add(path);entry=dict(path=path,kind='directory',identity=R.identity(info(path))[:5],fd=len(self.entries)+100,closed=False)
                    self.entries.append(entry);self.directories[path]=entry
                return self.directories[path]
            def file(self,path,limit,**kw):
                path=Path(path);self.directory(path.parent)
                if len(files[path])>limit:raise R.Refused('inert cap')
                if 'modes' in kw and stat.S_IMODE(info(path).st_mode) not in kw['modes']:raise R.Refused('inert mode')
                entry=dict(path=path,kind='file',identity=R.identity(info(path)),fd=len(self.entries)+100,closed=False)
                self.entries.append(entry);return entry,files[path]
            def publish(self,path,body):
                if path in files:raise R.Refused('inert collision')
                self.directory(path.parent);files[path]=body;self.entries.append(dict(path=path,kind='output',identity=R.identity(info(path)),fd=None,closed=True))
            def check(self):pass
            def finish(self):
                for entry in self.entries:
                    if entry['fd'] is not None:
                        self.attempts.append(entry['path']);entry['fd']=None
                        entry['closed']=not(unknown_close and entry['path']==WORK/'consumer-result.json')
                return all(entry['closed'] for entry in self.entries)
        class Owner:
            def run_owned(self,argv,**kw):
                if argv[0]=='/usr/bin/git':
                    gitroot=Path(argv[argv.index('-C')+1]);helper=gitroot==root
                    if 'rev-parse' in argv:out=((context['helperSource']+'\n'+install['helperTree']) if helper else (selected['source']+'\n'+selected['tree'])).encode()+b'\n'
                    else:
                        names=argv[argv.index('--')+1:]
                        out=b''.join(b'100644 blob '+__import__('hashlib').sha1(b'blob '+str(len(files[gitroot/p])).encode()+b'\0'+files[gitroot/p]).hexdigest().encode()+b'\t'+p.encode()+b'\0' for p in names)
                    return subprocess.CompletedProcess(argv,0,out,b'')
                effects.append('native-cli')
                child_root=root if saved_version else U.consumer.CANDIDATE_ROOT
                assert argv[4]==str(child_root/U.RUNNER) and kw['cwd']==child_root
                assert kw['environ']==U.clean_environment(N,selected,WORK,helper_source=context['helperSource'] if saved_version else None)
                _,_,_,_,_,row,out=phase_fixture(name,target,ios_tools=ios_tools,saved_files=saved_files,saved_version=saved_version)
                if native_fault=='unknown':raise RuntimeError('inert unknown native original')
                files[WORK/'normal-ui'/U.admission_name(name)]=R.canonical(row)
                return subprocess.CompletedProcess(argv,86 if native_fault=='nonzero' else 0,out,b'')
        def mkdir(path,mode):
            if Path(path) in directories:raise FileExistsError()
            directories.add(Path(path))
        def listdir(fd):
            entry=next(e for b in books for e in b.entries if e['fd']==fd)
            return children(entry['path'])
        original_quota=R.OriginalQuota
        quotas=[]
        def quota_factory():
            q=original_quota();quotas.append(q);return q
        from contextlib import ExitStack
        with ExitStack() as stack:
            for patch in (mock.patch('resource.setrlimit'),mock.patch.object(U.consumer,'entry_context',side_effect=lambda actual:(self.assertEqual(actual,tuple(arguments[1:])),context)[1]),
                mock.patch.object(U,'ROOT',root),mock.patch.object(U.Path,'cwd',return_value=U.consumer.CANDIDATE_ROOT),
                mock.patch.object(U.Path,'resolve',lambda p:p),mock.patch.object(U.resume,'bootstrap_originals',return_value=Book),
                mock.patch.object(U.resume,'load_module',return_value=N),mock.patch.object(U.resume,'OriginalQuota',side_effect=quota_factory),
                mock.patch.object(N,'load_normal_owner',return_value=Owner()),mock.patch.object(U.os,'stat',side_effect=lambda p,**kw:info(p)),
                mock.patch.object(U.os,'mkdir',side_effect=mkdir),mock.patch.object(U.os,'listdir',side_effect=listdir),
                mock.patch.object(sys,'argv',arguments),mock.patch.object(sys,'executable',str(host/'bin/python3')),
                mock.patch.object(sys,'prefix',str(host)),mock.patch.object(sys,'base_prefix','/inert-base'),
                mock.patch.object(sys,'_base_executable',str(base))):stack.enter_context(patch)
            if unknown_close:
                with self.assertRaisesRegex(R.Refused,'candidate-ui-original-final-closes'):U.main()
                value=None
            elif native_fault:
                with self.assertRaises((R.Refused,RuntimeError)):U.main()
                value=None
            else:value=U.main()
        self.assertLessEqual(quotas[0].reserved,96)
        self.assertEqual(len(books[0].attempts),len(set(books[0].attempts)))
        self.assertFalse(any(p.name==name+'.status' for p in files if name not in previous))
        return value,effects,quotas[0].reserved

    def test_actual_main_both_targets_first_and_full_result_with_lifetime_quota(self):
        for target in (N.ARM_TARGET,N.INTEL_TARGET):
            value,effects,_=self.exercise('build',target)
            self.assertEqual(effects,['native-cli']);self.assertTrue(value['originalClosesKnown'])
            value,effects,count=self.exercise('result',target)
            self.assertEqual(value['totalTests'],6);self.assertEqual(effects,[])
            self.assertEqual(count,93)
            self.assertTrue(value['storeEntryRefusalObserved'])
            self.assertEqual(value['savedOfflineChecksTests'],1)
            self.assertEqual(value['emptyBuildInputInspectionTests'],1)

    def test_actual_ios_cohort_main_both_targets_77_originals_and_late_unknown(self):
        for target in (N.ARM_TARGET,N.INTEL_TARGET):
            for phase in ('build','diagnostics-test','ios-unsigned-archive-test','result'):
                value,effects,count=self.exercise(phase,target,ios_tools=True)
                self.assertEqual(value['cohort'],'ios-tools')
                self.assertEqual(effects,[] if phase=='result' else ['native-cli'])
                if phase=='result':
                    self.assertEqual(count,77);self.assertEqual(value['totalTests'],2)
                    self.assertEqual(value['unsignedIosArchiveTests'],1)
                    self.assertEqual(value['androidBuildToolDiagnosticsTests'],1)
                    self.assertFalse(value['signed'] or value['ipaExported'] or value['fullDoctorQualified'])
                    self.assertNotIn('storeEntryRefusalObserved',value)
            value,effects,_=self.exercise('ios-unsigned-archive-summary',target,unknown_close=True,ios_tools=True)
            self.assertIsNone(value);self.assertEqual(effects,['native-cli'])

    def test_actual_saved_files_main_77_originals_and_unknown_close(self):
        for target in (N.ARM_TARGET,N.INTEL_TARGET):
            for phase in ('build','release-evidence-test','workflow-refusal-test','result'):
                value,effects,count=self.exercise(phase,target,saved_files=True)
                self.assertEqual(value['cohort'],'saved-files')
                self.assertEqual(effects,[] if phase=='result' else ['native-cli'])
                if phase=='result':
                    self.assertEqual((count,value['totalTests']),(77,2))
                    self.assertEqual((value['savedReleaseEvidenceTests'],value['managedWorkflowRefusalTests']),(1,1))
                    self.assertFalse(value['savedVersionRecoveryQualified'] or value['remoteReleaseAttempted'])
                    self.assertNotIn('unsignedIosArchiveTests',value)
            value,effects,_=self.exercise('workflow-refusal-summary',target,unknown_close=True,saved_files=True)
            self.assertIsNone(value);self.assertEqual(effects,['native-cli'])

    def test_actual_saved_version_main_helper_route_and_unknown_close(self):
        for target in (N.ARM_TARGET,N.INTEL_TARGET):
            for phase in (*U.SAVED_VERSION_PHASES,'result'):
                value,effects,count=self.exercise(phase,target,saved_version=True)
                self.assertEqual(value['cohort'],'saved-version')
                self.assertEqual(value['applicationSource'],'a'*40)
                self.assertEqual(value['harnessSource'],'d'*40)
                self.assertEqual(effects,[] if phase=='result' else ['native-cli'])
                if phase=='result':
                    self.assertEqual((count,value['totalTests'],value['savedVersionRecoveryTests']),(69,1,1))
                    self.assertFalse(value['interruptedGuiSaveObserved'])
            value,effects,_=self.exercise('saved-version-recovery-summary',target,unknown_close=True,saved_version=True)
            self.assertIsNone(value);self.assertEqual(effects,['native-cli'])
            for fault in ('unknown','nonzero'):
                value,effects,_=self.exercise('saved-version-recovery-test',target,saved_version=True,native_fault=fault)
                self.assertIsNone(value);self.assertEqual(effects,['native-cli'])

    def test_actual_main_late_consuming_close_prevents_success_and_status(self):
        for name in ('project-test','saved-checks-summary'):
            value,effects,_=self.exercise(name,N.ARM_TARGET,unknown_close=True)
            self.assertIsNone(value);self.assertEqual(effects,['native-cli'])


class CandidateUICleanupTests(unittest.TestCase):
    def test_finite_failure_diagnostic_rejects_raw_secret_suffix_paths_and_foreign_exception(self):
        for error in (R.Refused('candidate-ui-original-cli-nonzero-PRIVATE_SENTINEL'),ValueError('/private/PRIVATE_SENTINEL'),
                      RuntimeError('PRIVATE_SENTINEL')):
            data=U.failure_data(error,'PRIVATE_SENTINEL')
            self.assertIsNone(data['reason']);self.assertIsNone(data['phase'])
            self.assertNotIn('PRIVATE_SENTINEL',R.canonical(data).decode())
        self.assertEqual(U.failure_data(R.Refused('candidate-ui-original-cli-nonzero'),'project-test')['reason'],
                         'candidate-ui-original-cli-nonzero')

    def test_real_ios_cohort_cleanup_retires_only_its_original_harness_outputs(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'normal-ui';root.mkdir(mode=0o700)
            for name in ('DerivedData','tmp','diagnostics-test.xcresult','ios-unsigned-archive-test.xcresult'):
                (root/name).mkdir();(root/name/'inert').write_bytes(b'DATA')
            for phase in U.IOS_TOOL_PHASES:
                for suffix in ('.stdout','.stderr'):(root/(phase+suffix)).write_bytes(b'inert')
            for name in ('ios-unsigned-archive.facts.json','project-test.xcresult'):
                (root/name).write_bytes(b'not selected for cleanup')
            U.cleanup_outputs(root,R.identity(root.stat())[:5],N.PhaseClock(30),ios_tools=True)
            self.assertEqual(sorted(p.name for p in root.iterdir()),['ios-unsigned-archive.facts.json','project-test.xcresult'])

    def test_real_saved_files_cleanup_keeps_unselected_results(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'normal-ui';root.mkdir(mode=0o700)
            for name in ('DerivedData','tmp','release-evidence-test.xcresult','workflow-refusal-test.xcresult'):
                (root/name).mkdir();(root/name/'inert').write_bytes(b'DATA')
            for phase in U.SAVED_FILE_PHASES:
                for suffix in ('.stdout','.stderr'):(root/(phase+suffix)).write_bytes(b'inert')
            for name in ('saved-version-recovery-fixture.json','project-test.xcresult'):
                (root/name).write_bytes(b'not selected for cleanup')
            U.cleanup_outputs(root,R.identity(root.stat())[:5],N.PhaseClock(30),saved_files=True)
            self.assertEqual(sorted(p.name for p in root.iterdir()),['project-test.xcresult','saved-version-recovery-fixture.json'])

    def test_real_saved_version_cleanup_preserves_handoff_and_unselected_outputs(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'normal-ui';root.mkdir(mode=0o700)
            for name in ('DerivedData','tmp','saved-version-recovery-test.xcresult'):
                (root/name).mkdir();(root/name/'inert').write_bytes(b'DATA')
            for phase in U.SAVED_VERSION_PHASES:
                for suffix in ('.stdout','.stderr'):(root/(phase+suffix)).write_bytes(b'inert')
            for name in ('saved-version-recovery-fixture.json','project-test.xcresult'):(root/name).write_bytes(b'retained')
            U.cleanup_outputs(root,R.identity(root.stat())[:5],N.PhaseClock(30),saved_version=True)
            self.assertEqual(sorted(p.name for p in root.iterdir()),['project-test.xcresult','saved-version-recovery-fixture.json'])

    def test_real_inert_cleanup_only_known_outputs_and_foreign_link_refusal(self):
        import os,tempfile
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'normal-ui';root.mkdir(mode=0o700)
            for name in ('DerivedData','tmp','applications-test.xcresult','project-test.xcresult','persistence-test.xcresult','saved-checks-test.xcresult'):
                (root/name).mkdir();(root/name/'inert').write_bytes(b'DATA')
            for phase in U.PHASES:
                for suffix in ('.stdout','.stderr'):(root/(phase+suffix)).write_bytes(b'inert')
            (root/'result.json').write_bytes(b'retained small observation')
            U.cleanup_outputs(root,R.identity(root.stat())[:5],N.PhaseClock(30))
            self.assertEqual([p.name for p in root.iterdir()],['result.json'])
            foreign=Path(d)/'foreign';foreign.mkdir();(foreign/'keep').write_bytes(b'unchanged')
            (root/'DerivedData').symlink_to(foreign,target_is_directory=True)
            with self.assertRaisesRegex(R.Refused,'candidate-ui-cleanup-directory'):
                U.cleanup_outputs(root,R.identity(root.stat())[:5],N.PhaseClock(30))
            self.assertEqual((foreign/'keep').read_bytes(),b'unchanged')


if __name__=='__main__':unittest.main()
