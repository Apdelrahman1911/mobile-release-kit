// Fixed helper reverse caller admission. Exact CodeDirectory identity is NOT
// proof of executing-file location: a byte-identical copy is identity-equivalent.
#include "vault_helper_control.h"
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifndef MRK_WRAPPING_VAULT_HELPER
#error helper authentication must not be linked into the ordinary app role
#endif
#ifndef MRK_VAULT_APP_PATH
#error fixed installed app path is required
#endif
enum { MRK_A_SLOTS=18 };
typedef struct {
    uint32_t version,entered,admitted,rechecked,failed,unknown;
    uint32_t state[MRK_A_SLOTS]; //0unused,1entered,2owned,3closing,4closed/null,5unknown
    uint32_t calls,returned,first_call;
    int32_t first_status;
} MRKAuthFacts;
typedef struct {
    MRKAuthFacts facts;
    CFTypeRef value[MRK_A_SLOTS];
    pid_t pid,parent;
    uint32_t final_spent;
} MRKAuthBook;
extern uint32_t mrk_wrapping_vault_helper_role(void) __attribute__((weak_import));
static int original(MRKAuthBook *b) {
    return b && pthread_main_np()==1 && b->pid==getpid()
        && mrk_wrapping_vault_helper_role && mrk_wrapping_vault_helper_role()==3;
}
static int fail(MRKAuthBook *b,int32_t status) {
    mrk_vault_control_failure();
    if (!b) return 0;
    if (!b->facts.failed) { b->facts.first_call=b->facts.calls; b->facts.first_status=status; }
    b->facts.failed=1;return 0;
}
static int before(MRKAuthBook *b,uint32_t slot) {
    if (!original(b) || b->facts.failed || getppid()!=b->parent || slot>=MRK_A_SLOTS
        || b->facts.state[slot]!=0 || mrk_vault_control_admit(0)!=1) return fail(b,-1);
    b->facts.state[slot]=1;b->facts.calls++;return 1;
}
static int got(MRKAuthBook *b,uint32_t slot,CFTypeRef value,OSStatus status) {
    b->facts.returned++;b->value[slot]=value;b->facts.state[slot]=value?2:4;
    if (status!=errSecSuccess || !value) return fail(b,(int32_t)status);
    if (mrk_vault_control_admit(0)!=1 || getppid()!=b->parent) return fail(b,-2);
    return 1;
}
static int number(CFDictionaryRef info,CFStringRef key,uint32_t *out) {
    CFTypeRef object=CFDictionaryGetValue(info,key);int64_t value=0;
    if (!object || CFGetTypeID(object)!=CFNumberGetTypeID()
        || CFNumberIsFloatType((CFNumberRef)object)
        || !CFNumberGetValue((CFNumberRef)object,kCFNumberSInt64Type,&value)
        || value<0 || value>UINT32_MAX) return 0;
    *out=(uint32_t)value;return 1;
}
static int hardened(CFDictionaryRef info,int dynamic) {
    if (!info || CFGetTypeID(info)!=CFDictionaryGetTypeID() || CFDictionaryGetCount(info)>128) return 0;
    uint32_t flags=0,status=0;
    if (!number(info,kSecCodeInfoFlags,&flags) || !(flags&kSecCodeSignatureRuntime)) return 0;
    CFTypeRef ent=CFDictionaryGetValue(info,kSecCodeInfoEntitlementsDict);
    CFTypeRef raw=CFDictionaryGetValue(info,kSecCodeInfoEntitlements);
    if (ent) {
        if (CFGetTypeID(ent)!=CFDictionaryGetTypeID() || CFDictionaryGetCount((CFDictionaryRef)ent)!=0) return 0;
    } else if (raw) return 0; // Unrecognized blob is not "empty entitlements".
    if (raw && (CFGetTypeID(raw)!=CFDataGetTypeID() || CFDataGetLength((CFDataRef)raw)>4096)) return 0;
    if (dynamic && (!number(info,kSecCodeInfoStatus,&status) || !(status&kSecCodeStatusValid)
        || (status&kSecCodeStatusDebugged))) return 0;
    return 1;
}
static int static_code(MRKAuthBook *b,uint32_t base,const char *path,int directory) {
    if (!before(b,base)) return 0;
    CFURLRef url=CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault,(const UInt8 *)path,strlen(path),directory);
    if (!got(b,base,url,0) || !before(b,base+1)) return 0;
    SecStaticCodeRef code=NULL;OSStatus status=SecStaticCodeCreateWithPath(url,kSecCSDefaultFlags,&code);
    if (!got(b,base+1,code,status)) return 0;
    b->facts.calls++;
    status=SecStaticCodeCheckValidity(code,kSecCSStrictValidate|kSecCSCheckAllArchitectures,NULL);
    b->facts.returned++;if(status!=errSecSuccess)return fail(b,status);
    if (!before(b,base+2))return 0;
    CFDictionaryRef info=NULL;status=SecCodeCopySigningInformation(code,kSecCSSigningInformation,&info);
    if (!got(b,base+2,info,status) || !hardened(info,0))return fail(b,-3);
    CFTypeRef unique=CFDictionaryGetValue(info,kSecCodeInfoUnique);
    if (!unique || CFGetTypeID(unique)!=CFDataGetTypeID()) return fail(b,-4);
    // The documented exact identifier is opaque. Only the supported current
    //20-byte cdhash grammar is admitted; unknown sizes refuse, never truncate.
    if (CFDataGetLength((CFDataRef)unique)!=20) return fail(b,-5);
    const UInt8 *hash=CFDataGetBytePtr((CFDataRef)unique);if(!hash)return fail(b,-6);
    char requirement[51];memcpy(requirement,"cdhash H\"",9);
    const char hex[]="0123456789abcdef";
    for(unsigned i=0;i<20;i++){requirement[9+2*i]=hex[hash[i]>>4];requirement[10+2*i]=hex[hash[i]&15];}
    requirement[49]='"';requirement[50]=0;
    if(!before(b,base+3))return 0;
    CFStringRef text=CFStringCreateWithCString(kCFAllocatorDefault,requirement,kCFStringEncodingASCII);
    if(!got(b,base+3,text,0) || !before(b,base+4))return 0;
    SecRequirementRef exact=NULL;status=SecRequirementCreateWithString(text,kSecCSDefaultFlags,&exact);
    return got(b,base+4,exact,status);
}
static int dynamic_check(MRKAuthBook *b,uint32_t code_slot,uint32_t requirement_slot,uint32_t info_slot) {
    if(!original(b) || getppid()!=b->parent || mrk_vault_control_admit(0)!=1)return fail(b,-7);
    SecCodeRef code=(SecCodeRef)b->value[code_slot];SecRequirementRef exact=(SecRequirementRef)b->value[requirement_slot];
    if(!code || !exact)return fail(b,-8);
    b->facts.calls++;OSStatus status=SecCodeCheckValidity(code,kSecCSDefaultFlags,exact);b->facts.returned++;
    if(status!=errSecSuccess)return fail(b,status);
    if(!before(b,info_slot))return 0;
    CFDictionaryRef info=NULL;
    status=SecCodeCopySigningInformation((SecStaticCodeRef)code,kSecCSSigningInformation|kSecCSDynamicInformation,&info);
    if(!got(b,info_slot,info,status) || !hardened(info,1))return fail(b,-9);
    return getppid()==b->parent && mrk_vault_control_admit(0)==1 ? 1 : fail(b,-10);
}
size_t mrk_vault_auth_bytes(void){return sizeof(MRKAuthBook);}
void *mrk_vault_auth_new(void) {
    if(pthread_main_np()!=1 || !mrk_wrapping_vault_helper_role || mrk_wrapping_vault_helper_role()!=3)return NULL;
    MRKAuthBook *b=calloc(1,sizeof(*b));
    if(b){b->facts.version=1;b->pid=getpid();b->parent=getppid();}return b;
}
int mrk_vault_auth_begin(void *pointer) {
    MRKAuthBook *b=pointer;
    if(!original(b) || b->facts.entered)return 0;b->facts.entered=1;
    @try {
        if(b->parent<=1 || getuid()==0 || getuid()!=geteuid() || getgid()!=getegid())return fail(b,-11);
        if(!static_code(b,0,MRK_VAULT_APP_PATH,1)
            || !static_code(b,5,MRK_VAULT_APP_PATH "/Contents/Helpers/mrk-vault-keychain",0))return 0;
        if(!before(b,10))return 0;
        int32_t parent=b->parent;CFNumberRef pid=CFNumberCreate(kCFAllocatorDefault,kCFNumberSInt32Type,&parent);
        if(!got(b,10,pid,0) || !before(b,11))return 0;
        const void *keys[]={kSecGuestAttributePid};const void *values[]={pid};
        CFDictionaryRef attrs=CFDictionaryCreate(kCFAllocatorDefault,keys,values,1,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
        if(!got(b,11,attrs,0) || !before(b,12))return 0;
        SecCodeRef actual=NULL;OSStatus status=SecCodeCopyGuestWithAttributes(NULL,attrs,kSecCSDefaultFlags,&actual);
        if(!got(b,12,actual,status) || !dynamic_check(b,12,4,13) || !before(b,14))return 0;
        SecCodeRef self=NULL;status=SecCodeCopySelf(kSecCSDefaultFlags,&self);
        if(!got(b,14,self,status) || !dynamic_check(b,14,9,15))return 0;
        b->facts.admitted=1;return 1;
    } @catch (...) {b->facts.unknown=1;return fail(b,-12);}
}
int mrk_vault_auth_parent_current(void *pointer) {
    MRKAuthBook *b=pointer;
    if(!original(b) || !b->facts.admitted || b->facts.failed || getppid()!=b->parent)return b?fail(b,-13):0;
    return 1;
}
int mrk_vault_auth_recheck(void *pointer) {
    MRKAuthBook *b=pointer;
    if(!original(b) || !b->facts.admitted || b->facts.failed || b->final_spent)return 0;
    b->final_spent=1;
    @try {
        if(!dynamic_check(b,12,4,16) || !dynamic_check(b,14,9,17))return 0;
        b->facts.rechecked=1;return 1;
    } @catch (...) {b->facts.unknown=1;return fail(b,-14);}
}
int mrk_vault_auth_read(void *pointer,MRKAuthFacts *facts) {
    MRKAuthBook *b=pointer;if(!original(b) || !facts)return 0;*facts=b->facts;return 1;
}
int mrk_vault_auth_release_one(void *pointer,uint32_t slot) {
    MRKAuthBook *b=pointer;
    if(!original(b) || slot>=MRK_A_SLOTS || b->facts.state[slot]!=2 || !b->value[slot]
        || mrk_vault_control_admit(1)!=1)return 0;
    b->facts.state[slot]=3;
    @try{CFRelease(b->value[slot]);b->value[slot]=NULL;b->facts.state[slot]=4;return 1;}
    @catch(...){b->facts.state[slot]=5;b->facts.unknown=1;return fail(b,-15);}
}
int mrk_vault_auth_retire(void *pointer) {
    MRKAuthBook *b=pointer;if(!original(b) || b->facts.unknown)return 0;
    if(b->facts.calls!=b->facts.returned)return 0;
    for(unsigned i=0;i<MRK_A_SLOTS;i++)if(b->value[i] || (b->facts.state[i]!=0 && b->facts.state[i]!=4))return 0;
    free(b);return 1;
}
