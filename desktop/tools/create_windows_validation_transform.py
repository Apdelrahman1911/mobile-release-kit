"""Create an external disposable-only MST; never changes the original MSI.
The sole table mutation removes generated LaunchCondition Condition='0'.
This explicitly altered validation session is NOT shipping MSI acceptance.
"""
import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import shutil

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--msi',type=Path,required=True);p.add_argument('--transform',type=Path,required=True);a=p.parse_args()
 if os.name!='nt' or os.environ.get('GITHUB_ACTIONS')!='true':raise RuntimeError('disposable Windows CI only')
 original=a.msi.resolve();transform=a.transform.absolute();working=transform.with_suffix('.validation-database.msi')
 if transform.exists() or working.exists():raise RuntimeError('fresh transform output required')
 digest=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
 before=digest(original);shutil.copyfile(original,working)
 m=c.WinDLL('msi',use_last_error=True)
 signatures={'MsiOpenDatabaseW':([w.LPCWSTR,c.c_void_p,c.POINTER(w.UINT)],w.UINT),
 'MsiRecordGetStringW':([w.UINT,w.UINT,w.LPWSTR,c.POINTER(w.DWORD)],w.UINT),'MsiCloseHandle':([w.UINT],w.UINT),'MsiDatabaseOpenViewW':([w.UINT,w.LPCWSTR,c.POINTER(w.UINT)],w.UINT),
 'MsiViewClose':([w.UINT],w.UINT),'MsiViewExecute':([w.UINT,w.UINT],w.UINT),'MsiViewFetch':([w.UINT,c.POINTER(w.UINT)],w.UINT),
 'MsiDatabaseCommit':([w.UINT],w.UINT),'MsiDatabaseGenerateTransformW':([w.UINT,w.UINT,w.LPCWSTR,w.INT,w.INT],w.UINT),
 'MsiCreateTransformSummaryInfoW':([w.UINT,w.UINT,w.LPCWSTR,w.INT,w.INT],w.UINT)}
 for name,(args,result) in signatures.items():getattr(m,name).argtypes=args;getattr(m,name).restype=result
 handles=[]
 def check(code):
  if code:raise RuntimeError('Windows Installer API refused: '+str(code))
 def database(path,mode):
  h=w.UINT();check(m.MsiOpenDatabaseW(str(path),c.c_void_p(mode),c.byref(h)));handles.append(h.value);return h.value
 def view(db,sql):
  h=w.UINT();check(m.MsiDatabaseOpenViewW(db,sql,c.byref(h)));handles.append(h.value);check(m.MsiViewExecute(h,0));return h.value
 try:
  reference=database(original,0);changed=database(working,1)
  v=view(changed,"SELECT `Condition`, `Description` FROM `LaunchCondition` WHERE `Condition`='0'")
  row=w.UINT();check(m.MsiViewFetch(v,c.byref(row)));handles.append(row.value)
  deleted={}
  for index,key in ((1,'Condition'),(2,'Description')):
   buffer=c.create_unicode_buffer(4096);length=w.DWORD(4096)
   check(m.MsiRecordGetStringW(row,index,buffer,c.byref(length)));deleted[key]=buffer.value
  extra=w.UINT()
  if m.MsiViewFetch(v,c.byref(extra))!=259:raise RuntimeError('exactly one refusal row required')
  check(m.MsiViewClose(v))
  view(changed,"DELETE FROM `LaunchCondition` WHERE `Condition`='0'");check(m.MsiDatabaseCommit(changed))
  verify=view(changed,"SELECT `Condition` FROM `LaunchCondition` WHERE `Condition`='0'")
  missing=w.UINT()
  if m.MsiViewFetch(verify,c.byref(missing))!=259:raise RuntimeError('refusal row was not removed')
  check(m.MsiViewClose(verify))
  check(m.MsiDatabaseGenerateTransformW(changed,reference,str(transform),0,0))
  # Validate language/product/platform and every product version field.
  check(m.MsiCreateTransformSummaryInfoW(changed,reference,str(transform),0,0x3f))
 finally:
  for h in reversed(handles):m.MsiCloseHandle(h)
 if digest(original)!=before:raise RuntimeError('original MSI changed')
 # Do not retain an installable copy with the shipping refusal removed.
 changed_database_sha256=digest(working);working.unlink()
 transform.with_suffix('.json').write_text(json.dumps({'schema':1,'originalMsiSha256':before,
   'transformSha256':digest(transform),'temporaryChangedDatabaseSha256':changed_database_sha256,'temporaryChangedDatabaseRemoved':True,'mutation':"DELETE LaunchCondition WHERE Condition='0'",'databaseDiff':{'deletedRows':[{'table':'LaunchCondition',**deleted}],'insertedRows':[],'updatedRows':[]},
   'originalShippingRefusalPreserved':True,'shippingAcceptance':False},indent=2)+'\n')
if __name__=='__main__':main()
