// Fixed, privileged, synchronous MSI transaction owner. No user supplied paths.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <msiquery.h>
#include <shlobj.h>
#include <sddl.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <algorithm>
#include <cstdio>
#include <array>
#include <stdexcept>
#include <string>
#include <vector>
#include "binding.h"
#pragma comment(lib,"msi.lib")
#pragma comment(lib,"uuid.lib")
#pragma comment(lib,"shell32.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"bcrypt.lib")
namespace {
// Closed first-failure DATA only. Capture before unwinding/cleanup changes GLE.
struct Failure {const char* phase="exception";unsigned predicate=0;const char* domain="exception";DWORD code=0;bool present=false;};
thread_local Failure firstFailure;
void clear_failure(){firstFailure=Failure{};}
void 
remember_failure(const char* phase,unsigned predicate,const char* domain,DWORD code){if(!firstFailure.present)firstFailure={phase,predicate,domain,code,true};}
void 
checked(bool ok,const char* phase,unsigned predicate,const char* domain,DWORD code){if(!ok){
remember_failure(phase,predicate,domain,code);throw std::runtime_error("native refusal");}}
void expected_error(DWORD expected,const char* phase,unsigned predicate){DWORD actual=GetLastError();
checked(actual==expected,phase,predicate,"win32",actual);}
#define need(condition) checked(bool(condition),__func__,__LINE__,"policy",0)
#define win32_need(condition) do{bool nativeOk=bool(condition);DWORD nativeError=nativeOk?0:GetLastError();checked(nativeOk,__func__,__LINE__,"win32",nativeError);}while(false)
#define status_need(expression,domain) do{auto nativeStatus=(expression);checked(nativeStatus==0,__func__,__LINE__,domain,static_cast<DWORD>(nativeStatus));}while(false)
#define last_error_need(expected) expected_error(expected,__func__,__LINE__)
#define wait_need(expression,expected) do{DWORD nativeWait=(expression);DWORD nativeError=nativeWait==WAIT_FAILED?GetLastError():nativeWait;checked(nativeWait==(expected),__func__,__LINE__,nativeWait==WAIT_FAILED?"win32":"wait",nativeError);}while(false)
void emit_failure(MSIHANDLE session) noexcept {
 // This bounded sink never changes the already-selected failure result.
 char line[192]{};int length=std::snprintf(line,sizeof(line),"MRK_NATIVE_REFUSAL phase=%s predicate=P%u domain=%s code=%lu",firstFailure.phase,firstFailure.predicate,firstFailure.domain,static_cast<unsigned long>(firstFailure.code));
 if(length<0)return;DWORD bytes=static_cast<DWORD>(std::min<size_t>(static_cast<size_t>(length),sizeof(line)-2));line[bytes++]='\n';
 if(session){MSIHANDLE record=MsiCreateRecord(0);if(record){MsiRecordSetStringA(record,0,line);MsiProcessMessage(session,INSTALLMESSAGE_INFO,record);MsiCloseHandle(record);}}
 else{DWORD written=0;WriteFile(GetStdHandle(STD_ERROR_HANDLE),line,bytes,&written,nullptr);}
}
struct Handle {
 HANDLE h=INVALID_HANDLE_VALUE;
 explicit Handle(HANDLE v=INVALID_HANDLE_VALUE):h(v){}
 Handle(const Handle&)=delete; Handle& operator=(const Handle&)=delete;
 Handle(Handle&& o) noexcept:h(o.h){o.h=INVALID_HANDLE_VALUE;}
 void settled(){HANDLE original=h;
need(original && original!=INVALID_HANDLE_VALUE);h=INVALID_HANDLE_VALUE;
win32_need(CloseHandle(original)!=FALSE);}
 ~Handle(){if(h!=INVALID_HANDLE_VALUE && h) CloseHandle(h);}
};
void settle(std::vector<Handle>& owners){for(auto i=owners.rbegin();i!=owners.rend();++i)i->settled();}
struct Search {HANDLE h;explicit Search(HANDLE value):h(value){};void settled(){HANDLE original=h;h=INVALID_HANDLE_VALUE;
win32_need(FindClose(original)!=FALSE);}~Search(){if(h!=INVALID_HANDLE_VALUE)FindClose(h);}};
struct Local {void* p=nullptr; ~Local(){if(p) LocalFree(p);}};
std::wstring known(REFKNOWNFOLDERID id) {PWSTR p=nullptr; 
status_need(SHGetKnownFolderPath(id,KF_FLAG_DEFAULT,nullptr,&p),"hresult");std::wstring s(p);CoTaskMemFree(p);
need(s.size()>3 && s[1]==L':' && s[2]==L'\\');return s;}
std::wstring child(const std::wstring& p,const std::wstring& n){
need(n.find(L"..") == std::wstring::npos);return p+L"\\"+n;}
bool absent(const std::wstring& p){DWORD a=GetFileAttributesW(p.c_str());if(a!=INVALID_FILE_ATTRIBUTES)return false;DWORD error=GetLastError();
checked(error==ERROR_FILE_NOT_FOUND || error==ERROR_PATH_NOT_FOUND,__func__,__LINE__,"win32",error);return true;}
void security(HANDLE h,bool privateOnly,bool directory=false,bool ancestor=false){
 Local sd; PSID owner=nullptr; PACL acl=nullptr;
 
status_need(GetSecurityInfo(h,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,nullptr,&acl,nullptr,&sd.p),"win32-return");
 
need(owner && acl); BYTE sy[SECURITY_MAX_SID_SIZE],ad[SECURITY_MAX_SID_SIZE];DWORD ns=sizeof(sy),na=sizeof(ad);
 
win32_need(CreateWellKnownSid(WinLocalSystemSid,nullptr,sy,&ns) && CreateWellKnownSid(WinBuiltinAdministratorsSid,nullptr,ad,&na));
 Local ti;
win32_need(ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",&ti.p));
 
need(EqualSid(owner,sy)||EqualSid(owner,ad)||(!privateOnly && EqualSid(owner,ti.p)));
 SECURITY_DESCRIPTOR_CONTROL ctrl=0;DWORD rev=0;
win32_need(GetSecurityDescriptorControl(sd.p,&ctrl,&rev));
 if(privateOnly)
need((ctrl&SE_DACL_PROTECTED)!=0);
 DWORD writes=FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_WRITE_EA|FILE_WRITE_ATTRIBUTES|DELETE|WRITE_DAC|WRITE_OWNER|FILE_DELETE_CHILD|GENERIC_WRITE|GENERIC_ALL;
 if(directory && ancestor && !privateOnly)writes &= ~(FILE_WRITE_DATA|FILE_APPEND_DATA);
 for(DWORD i=0;i<acl->AceCount;++i){void* ace=nullptr;
win32_need(GetAce(acl,i,&ace)!=FALSE);auto head=static_cast<ACE_HEADER*>(ace);
  
need(head->AceType==ACCESS_ALLOWED_ACE_TYPE || head->AceType==ACCESS_DENIED_ACE_TYPE);
  if(!privateOnly && (head->AceFlags&INHERIT_ONLY_ACE))continue;
  if(head->AceType==ACCESS_ALLOWED_ACE_TYPE){auto a=static_cast<ACCESS_ALLOWED_ACE*>(ace);PSID sid=&a->SidStart;
need(IsValidSid(sid));
   bool privileged=EqualSid(sid,sy)||EqualSid(sid,ad)||(!privateOnly && EqualSid(sid,ti.p));
   
need(privileged || (!privateOnly && !(a->Mask&writes)));
  }
 }
}
Handle open(const std::wstring& p,bool dir,bool priv=false,DWORD access=GENERIC_READ,bool ancestor=false){
 Handle h(CreateFileW(p.c_str(),access|READ_CONTROL,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|(dir?FILE_FLAG_BACKUP_SEMANTICS:FILE_FLAG_SEQUENTIAL_SCAN),nullptr));
 
win32_need(h.h!=INVALID_HANDLE_VALUE);BY_HANDLE_FILE_INFORMATION i{};
win32_need(GetFileInformationByHandle(h.h,&i));
 constexpr DWORD allowed=FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_NORMAL|FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
 
need(GetFileType(h.h)==FILE_TYPE_DISK && (i.dwFileAttributes&~allowed)==0);
need(bool(i.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)==dir);if(!dir)
need(i.nNumberOfLinks==1);
 security(h.h,priv,dir,ancestor);return h;
}
// Every ancestor remains held without write/delete sharing during the operation.
void chain(const std::wstring& p,std::vector<Handle>& keep){
need(p.size()>3 && p.size()<240 && p[1]==L':');std::wstring volume=p.substr(0,3);wchar_t fs[32]{};
need(GetDriveTypeW(volume.c_str())==DRIVE_FIXED);
win32_need(GetVolumeInformationW(volume.c_str(),nullptr,0,nullptr,nullptr,nullptr,fs,32));
need(std::wstring(fs)==L"NTFS");keep.push_back(open(volume,true,false,GENERIC_READ,true));for(size_t i=4;i<=p.size();++i)if(i==p.size()||p[i]==L'\\')keep.push_back(open(p.substr(0,i),true,false,GENERIC_READ,true));}
void make_private(const std::wstring& p){Local sd;
win32_need(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",SDDL_REVISION_1,&sd.p,nullptr));SECURITY_ATTRIBUTES sa{sizeof(sa),sd.p,FALSE};if(!CreateDirectoryW(p.c_str(),&sa))
last_error_need(ERROR_ALREADY_EXISTS);}
std::string read(HANDLE h){LARGE_INTEGER s{};
win32_need(GetFileSizeEx(h,&s));
need(s.QuadPart>0&&s.QuadPart<=16384);std::string out(size_t(s.QuadPart),'\0');DWORD n=0;
win32_need(ReadFile(h,out.data(),DWORD(out.size()),&n,nullptr));
need(n==out.size());return out;}
std::string hex(const unsigned char* p,size_t n){const char* d="0123456789abcdef";std::string s;for(size_t i=0;i<n;++i){s+=d[p[i]>>4];s+=d[p[i]&15];}return s;}
std::string identity(HANDLE h){FILE_ID_INFO id{};
win32_need(GetFileInformationByHandleEx(h,FileIdInfo,&id,sizeof(id))!=FALSE);return hex(reinterpret_cast<const unsigned char*>(&id.VolumeSerialNumber),sizeof(id.VolumeSerialNumber))+":"+hex(id.FileId.Identifier,sizeof(id.FileId.Identifier));}
std::string durable(const std::wstring& p,const std::string& value,const char* kind){
 Local sd;
win32_need(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)",SDDL_REVISION_1,&sd.p,nullptr));SECURITY_ATTRIBUTES sa{sizeof(sa),sd.p,FALSE};
 Handle h(CreateFileW(p.c_str(),GENERIC_WRITE|READ_CONTROL|FILE_READ_ATTRIBUTES,FILE_SHARE_READ,&sa,CREATE_NEW,FILE_FLAG_WRITE_THROUGH|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
win32_need(h.h!=INVALID_HANDLE_VALUE);security(h.h,true);
 auto record=value+kind+identity(h.h)+"\n";
need(record.size()<16384);DWORD n=0;
win32_need(WriteFile(h.h,record.data(),DWORD(record.size()),&n,nullptr));
need(n==record.size());
win32_need(FlushFileBuffers(h.h));h.settled();return record;
}
std::string hash(HANDLE h,unsigned long long expected){
 LARGE_INTEGER size{};
win32_need(GetFileSizeEx(h,&size));
need(size.QuadPart>=0&&static_cast<unsigned long long>(size.QuadPart)==expected);BCRYPT_ALG_HANDLE alg=nullptr;BCRYPT_HASH_HANDLE hs=nullptr;
 
status_need(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0),"ntstatus");
 struct Clean {BCRYPT_ALG_HANDLE a;BCRYPT_HASH_HANDLE& h;~Clean(){if(h)BCryptDestroyHash(h);if(a)BCryptCloseAlgorithmProvider(a,0);}void settled(){auto original=h;h=nullptr;
status_need(BCryptDestroyHash(original),"ntstatus");auto provider=a;a=nullptr;
status_need(BCryptCloseAlgorithmProvider(provider,0),"ntstatus");}} clean{alg,hs};
 
status_need(BCryptCreateHash(alg,&hs,nullptr,0,nullptr,0,0),"ntstatus");std::array<unsigned char,65536> bytes{};unsigned long long count=0;
 while(true){DWORD n=0;
win32_need(ReadFile(h,bytes.data(),DWORD(bytes.size()),&n,nullptr));if(!n)break;count+=n;
need(count<=expected);
status_need(BCryptHashData(hs,bytes.data(),n,0),"ntstatus");}
need(count==expected);unsigned char digest[32];
status_need(BCryptFinishHash(hs,digest,32,0),"ntstatus");auto result=hex(digest,32);clean.settled();return result;
}
void enumerate(const std::wstring& p,std::vector<std::wstring>& actual,const std::wstring& prefix=L""){
 WIN32_FIND_DATAW d{};HANDLE raw=FindFirstFileW((p+L"\\*").c_str(),&d);
win32_need(raw!=INVALID_HANDLE_VALUE);Search f(raw);
 do{std::wstring n=d.cFileName;if(n==L"."||n==L"..")continue;
need(actual.size()<48 && !(d.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT));if(d.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY){
need(prefix.empty()&&n==L"python");enumerate(child(p,n),actual,L"python\\");}else actual.push_back(prefix+n);}while(FindNextFileW(raw,&d));
last_error_need(ERROR_NO_MORE_FILES);f.settled();
}
std::string fullwalk(const std::wstring& root){
 std::vector<Handle> held;chain(root,held);held.push_back(open(root,true));std::string identities="ROOT "+identity(held.back().h)+"\n";held.push_back(open(child(root,L"python"),true));identities+="PYTHON "+identity(held.back().h)+"\n";std::vector<std::wstring> actual;enumerate(root,actual);std::sort(actual.begin(),actual.end());
need(actual.size()==RuntimeFiles.size());
 for(const auto& f:RuntimeFiles){
need(std::binary_search(actual.begin(),actual.end(),std::wstring(f.path)));held.push_back(open(child(root,f.path),false));auto h=held.back().h;
  // Reject every named stream; the unnamed stream is the only admitted one.
  WIN32_FIND_STREAM_DATA stream{};HANDLE raw=FindFirstStreamW(child(root,f.path).c_str(),FindStreamInfoStandard,&stream,0);
win32_need(raw!=INVALID_HANDLE_VALUE);Search fs(raw);
need(std::wstring(stream.cStreamName)==L"::$DATA");
need(!FindNextStreamW(raw,&stream));
last_error_need(ERROR_HANDLE_EOF);fs.settled();
  
need(hash(h,f.size)==f.sha256);identities+="FILE "+identity(h)+"\n";
 }
 settle(held);return identities;
}
std::string prefix(){return std::string("MRK-MSI-COMPLETION-1\n")+AssemblyBinding+"\n"+SourceCommit+"\n"+SourceTree+"\n"+RuntimeManifest+"\n";}
struct Paths {std::wstring app,root,control,start,complete,pending;Paths(){app=child(known(FOLDERID_ProgramFiles),L"Mobile Release Kit");root=child(app,std::wstring(L"versions\\x86_64-pc-windows-msvc\\")+RuntimeManifestW);control=child(known(FOLDERID_ProgramData),L"Mobile Release Kit Installer");start=child(control,std::wstring(RuntimeManifestW)+L".started");complete=child(control,std::wstring(RuntimeManifestW)+L".complete");pending=child(control,std::wstring(RuntimeManifestW)+L".pending");}};
struct Lock {Handle h;bool owned=false;Lock():h(CreateMutexW(nullptr,FALSE,L"Global\\MobileReleaseKit.MSI.Transaction.v1")){
win32_need(h.h && h.h!=INVALID_HANDLE_VALUE);
wait_need(WaitForSingleObject(h.h,0),WAIT_OBJECT_0);owned=true;}void settled(){
need(owned);
win32_need(ReleaseMutex(h.h));owned=false;h.settled();}~Lock(){if(owned)ReleaseMutex(h.h);}};
std::string completed(Paths& p){
 if(absent(p.complete)){
need(absent(p.start)&&absent(p.pending));return {};}
 
need(absent(p.pending));auto c=open(p.complete,false,true);auto s=open(p.start,false,true);auto begin=read(s.h),end=read(c.h);auto fixed=prefix();
 
need(begin.size()>fixed.size()+65 && begin.compare(0,fixed.size(),fixed)==0);
 auto nonce=begin.substr(fixed.size(),64);
need(std::all_of(nonce.begin(),nonce.end(),[](char v){return (v>='0'&&v<='9')||(v>='a'&&v<='f');}));
 
need(begin==fixed+nonce+"\nSTART-ID "+identity(s.h)+"\n");
 auto originalRecord=identity(c.h);auto nativeIdentities=fullwalk(p.root);
 
need(end==begin+"ORIGINAL_EXIT_0_SETTLED\n"+nativeIdentities+"COMPLETE-ID "+originalRecord+"\n");
 s.settled();c.settled();return begin;
}
std::string publisher(Paths& p){
 // The executable's exact reviewed bytes are compiled into this DLL. Its own
 // native Publication owner supplies exit0 only after every original settles.
 std::vector<Handle> ancestors;chain(p.app,ancestors);ancestors.push_back(open(p.app,true));
 auto exe=child(p.app,L"mrk-windows-runtime-publish.exe");auto image=open(exe,false);
need(hash(image.h,PublisherSize)==PublisherSha256);
 Handle job(CreateJobObjectW(nullptr,nullptr));
win32_need(job.h!=nullptr);JOBOBJECT_EXTENDED_LIMIT_INFORMATION limit{};limit.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_ACTIVE_PROCESS;limit.BasicLimitInformation.ActiveProcessLimit=1;
win32_need(SetInformationJobObject(job.h,JobObjectExtendedLimitInformation,&limit,sizeof(limit)));
 SECURITY_ATTRIBUTES pipeSecurity{sizeof(pipeSecurity),nullptr,TRUE};HANDLE inputRaw=nullptr,outputRaw=nullptr;
 
win32_need(CreatePipe(&inputRaw,&outputRaw,&pipeSecurity,4096)!=FALSE);Handle pipeRead(inputRaw),pipeWrite(outputRaw);
 
win32_need(SetHandleInformation(pipeRead.h,HANDLE_FLAG_INHERIT,0)!=FALSE);
 Handle nullInput(CreateFileW(L"NUL",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,&pipeSecurity,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr));
win32_need(nullInput.h!=INVALID_HANDLE_VALUE);
 SIZE_T attributeBytes=0;InitializeProcThreadAttributeList(nullptr,1,0,&attributeBytes);
need(attributeBytes>0 && attributeBytes<=16384);
 std::vector<unsigned char> attributeStorage(attributeBytes);auto attributes=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributeStorage.data());
 
win32_need(InitializeProcThreadAttributeList(attributes,1,0,&attributeBytes)!=FALSE);
 struct Attributes {LPPROC_THREAD_ATTRIBUTE_LIST p;~Attributes(){DeleteProcThreadAttributeList(p);}} attributeOwner{attributes};
 HANDLE inherited[]={pipeWrite.h,nullInput.h};
win32_need(UpdateProcThreadAttribute(attributes,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,inherited,sizeof(inherited),nullptr,nullptr)!=FALSE);
 STARTUPINFOEXW si{};si.StartupInfo.cb=sizeof(si);si.StartupInfo.dwFlags=STARTF_USESTDHANDLES;si.StartupInfo.hStdInput=nullInput.h;si.StartupInfo.hStdOutput=pipeWrite.h;si.StartupInfo.hStdError=pipeWrite.h;si.lpAttributeList=attributes;
 PROCESS_INFORMATION pi{};std::wstring command=L"\""+exe+L"\"";
 
win32_need(CreateProcessW(exe.c_str(),command.data(),nullptr,nullptr,TRUE,CREATE_SUSPENDED|CREATE_NO_WINDOW|EXTENDED_STARTUPINFO_PRESENT,nullptr,p.app.c_str(),&si.StartupInfo,&pi));Handle process(pi.hProcess),thread(pi.hThread);
 if(!AssignProcessToJobObject(job.h,process.h)){
remember_failure(__func__,__LINE__,"win32",GetLastError());TerminateProcess(process.h,1);WaitForSingleObject(process.h,10000);
need(false);}
 pipeWrite.settled();nullInput.settled();DWORD previous=ResumeThread(thread.h);
win32_need(previous!=DWORD(-1));
need(previous==1);
 // Timeout is always UNKNOWN. Closing the kill-on-close job terminates the
 // child; the durable started record survives and forbids adoption/retry.
 
wait_need(WaitForSingleObject(process.h,120000),WAIT_OBJECT_0);DWORD exit=STILL_ACTIVE;
win32_need(GetExitCodeProcess(process.h,&exit));
need(exit==0);
 JOBOBJECT_BASIC_ACCOUNTING_INFORMATION account{};
win32_need(QueryInformationJobObject(job.h,JobObjectBasicAccountingInformation,&account,sizeof(account),nullptr));
need(account.ActiveProcesses==0);
 std::string originalIdentities;std::array<char,4096> output{};
 while(true){DWORD count=0;if(!ReadFile(pipeRead.h,output.data(),DWORD(output.size()),&count,nullptr)){
last_error_need(ERROR_BROKEN_PIPE);break;}
need(count>0 && originalIdentities.size()+count<4096);originalIdentities.append(output.data(),count);}
 pipeRead.settled();thread.settled();process.settled();job.settled();image.settled();settle(ancestors);return originalIdentities;
}
void stage_publication(Paths& p,std::vector<Handle>& roots,Lock& lock){
 unsigned char nonce[32];
status_need(BCryptGenRandom(nullptr,nonce,sizeof(nonce),BCRYPT_USE_SYSTEM_PREFERRED_RNG),"ntstatus");
 auto begin=durable(p.start,prefix()+hex(nonce,sizeof(nonce))+"\n","START-ID ");
 auto originalIdentities=publisher(p);auto nativeIdentities=fullwalk(p.root);
need(nativeIdentities==originalIdentities);
 durable(p.pending,begin+"ORIGINAL_EXIT_0_SETTLED\n"+nativeIdentities,"COMPLETE-ID ");
 // The pending record cannot authenticate completion. Every coordinator-owned
 // critical original must close successfully BEFORE terminal name exposure.
 settle(roots);lock.settled();
}
UINT run(bool publish,MSIHANDLE session=0){clear_failure();try{Lock lock;Paths p;std::vector<Handle> roots;chain(known(FOLDERID_ProgramData),roots);make_private(p.control);roots.push_back(open(p.control,true,true));
 if(!completed(p).empty()){settle(roots);lock.settled();return ERROR_SUCCESS;}
 
need(absent(p.root));if(!publish){settle(roots);lock.settled();return ERROR_SUCCESS;}
 stage_publication(p,roots,lock);
 
win32_need(MoveFileExW(p.pending.c_str(),p.complete.c_str(),MOVEFILE_WRITE_THROUGH)!=FALSE);
 return ERROR_SUCCESS;
 }catch(...){emit_failure(session);return ERROR_INSTALL_FAILURE;}}

}
namespace {
bool msi_context(MSIHANDLE h){
 if(!h || !MsiGetMode(h,MSIRUNMODE_SCHEDULED) || MsiGetMode(h,MSIRUNMODE_ROLLBACK) || MsiGetMode(h,MSIRUNMODE_COMMIT)){
remember_failure(__func__,__LINE__,"policy",0);return false;}
 wchar_t product[40]{};DWORD size=40;
 DWORD propertyStatus=MsiGetPropertyW(h,L"ProductCode",product,&size);if(propertyStatus!=ERROR_SUCCESS){
remember_failure(__func__,__LINE__,"win32-return",propertyStatus);return false;}if(std::wstring(product)!=ProductCodeW){
remember_failure(__func__,__LINE__,"policy",0);return false;}
 Handle token;HANDLE raw=nullptr;
win32_need(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&raw));token.h=raw;
 alignas(TOKEN_USER) BYTE data[512]{};DWORD count=0;
win32_need(GetTokenInformation(token.h,TokenUser,data,sizeof(data),&count));
 BYTE system[SECURITY_MAX_SID_SIZE]{};DWORD ns=sizeof(system);
win32_need(CreateWellKnownSid(WinLocalSystemSid,nullptr,system,&ns));
 bool systemToken=EqualSid(reinterpret_cast<TOKEN_USER*>(data)->User.Sid,system)!=FALSE;token.settled();
need(systemToken);return true;
}
}
extern "C" __declspec(dllexport) UINT __stdcall MrkGuard(MSIHANDLE h){clear_failure();try{if(msi_context(h))return run(false,h);
remember_failure("msi_context",1,"policy",0);emit_failure(h);return ERROR_INSTALL_FAILURE;}catch(...){emit_failure(h);return ERROR_INSTALL_FAILURE;}}
extern "C" __declspec(dllexport) UINT __stdcall MrkPublish(MSIHANDLE h){clear_failure();try{if(msi_context(h))return run(true,h);
remember_failure("msi_context",1,"policy",0);emit_failure(h);return ERROR_INSTALL_FAILURE;}catch(...){emit_failure(h);return ERROR_INSTALL_FAILURE;}}
