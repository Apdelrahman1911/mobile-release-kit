"""Narrow disposable Windows compiler command owner, not installation authority.
Launch suspended, assign original to kill-on-close job before execution, require
original exit and zero active descendants. Persist every original outcome.
"""
import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

class Startup(c.Structure):
 _fields_=[('cb',w.DWORD),('reserved',w.LPWSTR),('desktop',w.LPWSTR),('title',w.LPWSTR),('x',w.DWORD),('y',w.DWORD),('xs',w.DWORD),('ys',w.DWORD),('xc',w.DWORD),('yc',w.DWORD),('fill',w.DWORD),('flags',w.DWORD),('show',w.WORD),('reservedBytes',w.WORD),('reservedPtr',c.POINTER(c.c_ubyte)),('stdin',w.HANDLE),('stdout',w.HANDLE),('stderr',w.HANDLE)]
class StartupEx(c.Structure):_fields_=[('base',Startup),('attributes',c.c_void_p)]
class Process(c.Structure):_fields_=[('process',w.HANDLE),('thread',w.HANDLE),('pid',w.DWORD),('tid',w.DWORD)]
class BasicLimit(c.Structure):
 _fields_=[('processTime',c.c_longlong),('jobTime',c.c_longlong),('flags',w.DWORD),('minWorking',c.c_size_t),('maxWorking',c.c_size_t),('activeLimit',w.DWORD),('affinity',c.c_size_t),('priority',w.DWORD),('scheduling',w.DWORD)]
class Io(c.Structure):_fields_=[(name,c.c_ulonglong) for name in ('read','write','other','readBytes','writeBytes','otherBytes')]
class Limits(c.Structure):_fields_=[('basic',BasicLimit),('io',Io),('processMemory',c.c_size_t),('jobMemory',c.c_size_t),('peakProcess',c.c_size_t),('peakJob',c.c_size_t)]
class Accounting(c.Structure):_fields_=[(name,c.c_longlong) for name in ('user','kernel','periodUser','periodKernel')]+[(name,w.DWORD) for name in ('faults','total','active','terminated')]

def run_owned(name,args,*,cwd,env,logs,timeout,limit=32*1024*1024):
 if os.name!='nt':raise RuntimeError('Windows build owner only')
 import msvcrt
 logs=Path(logs);logs.mkdir(exist_ok=True)
 receipt=logs/(name+'.result.json')
 if receipt.exists():raise RuntimeError('command result already exists')
 result={'schema':1,'command':name,'argv':list(args),'timeoutSeconds':timeout,'outputLimitBytes':limit,
         'started':False,'resumed':False,'originalExit':None,'originalSignaled':False,'treeSettled':False,
         'deadlineExceeded':False,'outputExceeded':False,'cleanupSettled':False,'handlesClosed':False,'success':False,'errors':[]}
 k=c.WinDLL('kernel32',use_last_error=True)
 signatures={'CreateJobObjectW':([c.c_void_p,w.LPCWSTR],w.HANDLE),'SetInformationJobObject':([w.HANDLE,c.c_int,c.c_void_p,w.DWORD],w.BOOL),
 'QueryInformationJobObject':([w.HANDLE,c.c_int,c.c_void_p,w.DWORD,c.c_void_p],w.BOOL),'TerminateJobObject':([w.HANDLE,w.UINT],w.BOOL),
 'InitializeProcThreadAttributeList':([c.c_void_p,w.DWORD,w.DWORD,c.POINTER(c.c_size_t)],w.BOOL),
 'UpdateProcThreadAttribute':([c.c_void_p,w.DWORD,c.c_size_t,c.c_void_p,c.c_size_t,c.c_void_p,c.c_void_p],w.BOOL),
 'DeleteProcThreadAttributeList':([c.c_void_p],None),'CreateProcessW':([w.LPCWSTR,w.LPWSTR,c.c_void_p,c.c_void_p,w.BOOL,w.DWORD,c.c_void_p,w.LPCWSTR,c.POINTER(StartupEx),c.POINTER(Process)],w.BOOL),
 'ResumeThread':([w.HANDLE],w.DWORD),'WaitForSingleObject':([w.HANDLE,w.DWORD],w.DWORD),'GetExitCodeProcess':([w.HANDLE,c.POINTER(w.DWORD)],w.BOOL),
 'TerminateProcess':([w.HANDLE,w.UINT],w.BOOL),'CloseHandle':([w.HANDLE],w.BOOL)}
 for key,(params,ret) in signatures.items():getattr(k,key).argtypes=params;getattr(k,key).restype=ret
 def need(ok,phase):
  if not ok:
   code=c.get_last_error();result['errors'].append({'phase':phase,'win32':code});raise RuntimeError('build native owner refused: '+phase)
 job=process=thread=None;attributes=None;attributesInitialized=False;files=[];assigned=False;failure=None
 started=time.monotonic()
 def observe():
  wait=k.WaitForSingleObject(process,0);result['lastOriginalWait']=wait
  if wait not in (0,258):
   result['errors'].append({'phase':'wait-original','win32':c.get_last_error() if wait==0xffffffff else wait});raise RuntimeError('original wait failed')
  signaled=wait==0
  account=Accounting();need(k.QueryInformationJobObject(job,1,c.byref(account),c.sizeof(account),None),'query-tree')
  result.update(originalSignaled=signaled,treeSettled=account.active==0,activeProcesses=account.active)
  if signaled:
   code=w.DWORD();need(k.GetExitCodeProcess(process,c.byref(code)),'original-exit');result['originalExit']=code.value
  return signaled and account.active==0
 try:
  stdout=(logs/(name+'.stdout')).open('xb',buffering=0);files.append(stdout)
  stderr=(logs/(name+'.stderr')).open('xb',buffering=0);files.append(stderr)
  stdin=open(os.devnull,'rb',buffering=0);files.append(stdin)
  handles=(w.HANDLE*3)(*[msvcrt.get_osfhandle(f.fileno()) for f in (stdin,stdout,stderr)])
  for handle in handles:os.set_handle_inheritable(handle,True)
  job=k.CreateJobObjectW(None,None);need(job,'create-job');limits=Limits();limits.basic.flags=0x2000
  need(k.SetInformationJobObject(job,9,c.byref(limits),c.sizeof(limits)),'job-kill-on-close')
  size=c.c_size_t();k.InitializeProcThreadAttributeList(None,1,0,c.byref(size));need(0<size.value<=16384,'attribute-size')
  attributeBuffer=c.create_string_buffer(size.value);attributes=c.cast(attributeBuffer,c.c_void_p)
  need(k.InitializeProcThreadAttributeList(attributes,1,0,c.byref(size)),'attribute-init');attributesInitialized=True
  need(k.UpdateProcThreadAttribute(attributes,0,0x20002,handles,c.sizeof(handles),None,None),'handle-whitelist')
  selected=shutil.which(args[0],path=env.get('PATH'))
  if selected is None:
   result['failureCategory']='command-resolution';raise RuntimeError('command resolution refused')
  command=subprocess.list2cmdline([selected,*args[1:]])
  if selected.lower().endswith(('.cmd','.bat')):
   if any(any(ch in str(arg) for ch in '&|<>^%!\r\n') for arg in (selected,*args[1:])):raise RuntimeError('fixed batch argv contains shell metacharacter')
   selected=str(Path(os.environ['SystemRoot'])/'System32/cmd.exe');command='"'+selected+'" /d /s /c "'+command+'"'
  si=StartupEx();si.base.cb=c.sizeof(si);si.base.flags=0x100;si.base.stdin=handles[0];si.base.stdout=handles[1];si.base.stderr=handles[2];si.attributes=attributes
  pi=Process();environment=c.create_unicode_buffer('\0'.join(key+'='+value for key,value in sorted(env.items(),key=lambda item:item[0].upper()))+'\0\0')
  need(k.CreateProcessW(selected,c.create_unicode_buffer(command),None,None,True,0x4|0x400|0x80000,c.cast(environment,c.c_void_p),str(cwd),c.byref(si),c.byref(pi)),'create-suspended')
  process,thread=pi.process,pi.thread;result.update(started=True,originalPid=pi.pid)
  # Declare after creation only to keep the narrow signature table easy to audit.
  k.AssignProcessToJobObject.argtypes=[w.HANDLE,w.HANDLE];k.AssignProcessToJobObject.restype=w.BOOL
  need(k.AssignProcessToJobObject(job,process),'assign-job');assigned=True
  previous=k.ResumeThread(thread);need(previous!=0xffffffff,'resume-original');need(previous==1,'original-suspend-count');result['resumed']=True
  while True:
   settled=observe()
   size=os.fstat(stdout.fileno()).st_size+os.fstat(stderr.fileno()).st_size;result['outputBytes']=size
   if size>limit:result['outputExceeded']=True;raise RuntimeError('command output bound exceeded')
   if result['originalSignaled'] and result['originalExit']!=0:raise RuntimeError('original command returned failure')
   if settled:break
   if time.monotonic()-started>=timeout:result['deadlineExceeded']=True;raise RuntimeError('command deadline exceeded')
   time.sleep(.1)
  result['cleanupSettled']=True
 except BaseException as error:
  failure=type(error).__name__;result['failureKind']=failure
  if 'failureCategory' not in result:
   if result['outputExceeded']:category='output-bound'
   elif result['deadlineExceeded']:category='deadline'
   elif result['errors']:category='native-'+result['errors'][0]['phase']
   elif result['originalSignaled'] and result['originalExit']!=0:category='original-nonzero'
   elif isinstance(error,RuntimeError):category='fixed-argv-policy'
   elif isinstance(error,OSError):category='host-io'
   else:category='supervisor-exception'
   result['failureCategory']=category
  if isinstance(error,OSError):result['hostErrorCode']=getattr(error,'winerror',None) or error.errno
 finally:
  if process and not result['cleanupSettled']:
   try:
    result['originalExitBeforeCleanup']=result['originalExit'];result['terminationRequested']=True
    if assigned:need(k.TerminateJobObject(job,0xe0000001),'terminate-tree')
    else:need(k.TerminateProcess(process,0xe0000001),'terminate-suspended-original')
    cleanupEnd=time.monotonic()+10
    while time.monotonic()<cleanupEnd:
     if assigned:
      if observe():result['cleanupSettled']=True;break
     elif k.WaitForSingleObject(process,0)==0:
      code=w.DWORD();need(k.GetExitCodeProcess(process,c.byref(code)),'cleanup-original-exit');result.update(originalSignaled=True,originalExit=code.value,cleanupSettled=True);break
     time.sleep(.1)
   except BaseException as error:result['cleanupFailure']=type(error).__name__
  if attributesInitialized:k.DeleteProcThreadAttributeList(attributes)
  closeOk=True
  for phase,handle in (('thread',thread),('process',process),('job',job)):
   if handle and not k.CloseHandle(handle):
    result['errors'].append({'phase':'close-'+phase,'win32':c.get_last_error()});closeOk=False
  for f in files:
   try:f.close()
   except BaseException as error:result['errors'].append({'phase':'log-close','kind':type(error).__name__});closeOk=False
  result['handlesClosed']=closeOk;result['durationSeconds']=round(time.monotonic()-started,3)
  result['success']=failure is None and result['originalExit']==0 and result['treeSettled'] and result['cleanupSettled'] and closeOk
  receipt.write_text(json.dumps(result,indent=2)+'\n')
 if not result['success']:raise RuntimeError('Windows build command refused; original outcome: '+name+'.result.json')
 return result
