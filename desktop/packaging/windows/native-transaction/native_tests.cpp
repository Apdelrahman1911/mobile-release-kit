// Compile and run elevated on a disposable Windows x64 runner. Tests exercise
// production native record/open/hash primitives; do not touch the installed app.
#include "transaction.cpp"
int wmain(int argc,wchar_t** argv){clear_failure();try{
 if(argc==2){std::wstring action=argv[1];if(action==L"guard")return int(run(false));if(action==L"publish")return int(run(true));if(action==L"fullwalk"){Paths p;fullwalk(p.root);return 0;}if(action==L"crash-after-pending"){Lock lock;Paths p;std::vector<Handle> roots;chain(known(FOLDERID_ProgramData),roots);make_private(p.control);roots.push_back(open(p.control,true,true));
need(completed(p).empty()&&absent(p.root));stage_publication(p,roots,lock);ExitProcess(77);}if(action==L"crash-after-start"){Lock lock;Paths p;std::vector<Handle> roots;chain(known(FOLDERID_ProgramData),roots);make_private(p.control);roots.push_back(open(p.control,true,true));
need(completed(p).empty()&&absent(p.root));durable(p.start,prefix()+std::string(64,'a')+"\n","START-ID ");ExitProcess(77);}
need(false);}

 
need(MrkGuard(0)==ERROR_INSTALL_FAILURE && MrkPublish(0)==ERROR_INSTALL_FAILURE);clear_failure();
 auto base=known(FOLDERID_ProgramData);std::vector<Handle> chainHeld;chain(base,chainHeld);
 unsigned char nonce[16];
need(BCryptGenRandom(nullptr,nonce,sizeof(nonce),BCRYPT_USE_SYSTEM_PREFERRED_RNG)==0);
 auto name=hex(nonce,sizeof(nonce));std::wstring root=child(base,L"MRK-Native-Test-"+std::wstring(name.begin(),name.end()));
 make_private(root);auto directory=open(root,true,true);
 auto record=child(root,L"started");const std::string value=prefix()+std::string(64,'a')+"\n";
 auto original=durable(record,value,"START-ID ");{auto h=open(record,false,true);
need(read(h.h)==original);h.settled();}
 bool refused=false;try{durable(record,value,"START-ID ");}catch(...){refused=true;}clear_failure();
need(refused);
 // Partial/unknown records are never completed by read success or byte equality.
 auto partial=child(root,L"partial");durable(partial,"UNKNOWN\n","PARTIAL-ID ");{auto h=open(partial,false,true);
need(read(h.h)!=value);h.settled();}
 auto data=child(root,L"data");{Handle output(CreateFileW(data.c_str(),GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_NEW,FILE_FLAG_WRITE_THROUGH,nullptr));
need(output.h!=INVALID_HANDLE_VALUE);DWORD n=0;
need(WriteFile(output.h,"abc",3,&n,nullptr)&&n==3&&FlushFileBuffers(output.h));output.settled();}{auto h=open(data,false);
need(hash(h.h,3)=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  Handle writer(CreateFileW(data.c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,0,nullptr));
need(writer.h==INVALID_HANDLE_VALUE);h.settled();}
 bool unknown=false;Handle retired(CreateEventW(nullptr,TRUE,FALSE,nullptr));
need(retired.h && retired.h!=INVALID_HANDLE_VALUE);
need(CloseHandle(retired.h)!=FALSE);try{retired.settled();}catch(...){unknown=true;}clear_failure();
need(unknown && retired.h==INVALID_HANDLE_VALUE);
 directory.settled();settle(chainHeld);
 // The test retains its private evidence directory; no repair/cleanup authority.
 return 0;
}catch(...){emit_failure(0);return 1;}}
