// Fixed normal-app SMAppService phases. No generic service/path, unregister,
// restart, automatic approval, callback scheduler or app-owned autorelease pool.
// The original app owner queues this onto its verified AppKit event callback.
#import <Foundation/Foundation.h>
#import <ServiceManagement/ServiceManagement.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if !defined(MRK_ANDROID_REGISTRATION_HELPER) && !defined(MRK_WRAPPING_VAULT_HELPER)
extern int mrk_android_identity_available(void);
#define MRK_ANDROID_MANAGEMENT_MAGIC UINT64_C(0x4d524b41534d4732)
#define MRK_ANDROID_SERVICE_PLIST @"dev.mobile-release-kit.desktop.android-register.plist"
#ifndef MRK_ANDROID_APP_PATH
#error fixed installed Android app path is required
#endif
#ifndef MRK_ANDROID_APP_REQUIREMENT
#define MRK_ANDROID_APP_REQUIREMENT ""
#endif
#ifndef MRK_ANDROID_HELPER_REQUIREMENT
#define MRK_ANDROID_HELPER_REQUIREMENT ""
#endif
enum {
    MRK_SERVICE_ACQUIRE=2, MRK_SERVICE_STATUS=3, MRK_SERVICE_MUTATE=4,
    MRK_SERVICE_RESULT=5, MRK_SERVICE_RELEASE=6
};
typedef struct {
    uint32_t version,action,status,outcome,entered,returned,cleanup_known,unknown;
    uint32_t phase,service_state,called,reserved;
} mrk_android_management_report;
typedef struct {
    uint64_t magic;
    id service; // explicit original +1 reference, NEVER a pool or borrowed NSError
    mrk_android_management_report report;
} mrk_android_management;
_Static_assert(sizeof(mrk_android_management)<=1024u,"supplied cell, not framework heap");
_Static_assert(sizeof(mrk_android_management_report)==48u,"Rust/C phase report layout");
static int manager_valid(mrk_android_management *original) {
    return original && original->magic==MRK_ANDROID_MANAGEMENT_MAGIC && pthread_main_np()==1;
}
static void manager_unknown(mrk_android_management *original) {
    original->report.unknown=1;original->report.outcome=8;original->report.cleanup_known=0;
    if (original->report.service_state==1 || original->report.service_state==3)
        original->report.service_state=5;
}
static uint32_t status_data(SMAppService *service) {
    switch ([service status]) {
        case SMAppServiceStatusNotRegistered:return 0;
        case SMAppServiceStatusEnabled:return 1;
        case SMAppServiceStatusRequiresApproval:return 2;
        case SMAppServiceStatusNotFound:return 3;
        default:return 5;
    }
}
void *mrk_android_management_new(uint32_t action) {
    if (action>2 || pthread_main_np()!=1 || getuid()==0 || geteuid()!=getuid()
        || !mrk_android_identity_available()) return NULL;
    mrk_android_management *original=calloc(1,sizeof(*original));
    if (!original) return NULL;
    original->magic=MRK_ANDROID_MANAGEMENT_MAGIC;
    original->report.version=2;original->report.action=action;original->report.status=4;
    return original;
}
static int phase_admitted(mrk_android_management *original,uint32_t phase) {
    const mrk_android_management_report *report=&original->report;
    if (report->unknown || report->cleanup_known) return 0;
    switch (phase) {
        case MRK_SERVICE_ACQUIRE:
            return !report->called && report->phase==0 && report->service_state==0 && !original->service;
        case MRK_SERVICE_STATUS:
            return report->called && report->phase==MRK_SERVICE_ACQUIRE
                && report->service_state==2 && original->service && report->outcome==0;
        case MRK_SERVICE_MUTATE:
            return report->called && report->phase==MRK_SERVICE_STATUS
                && report->service_state==2 && original->service && report->outcome==0
                && (report->action==2 || (report->action==1 && report->status==0));
        case MRK_SERVICE_RESULT:
            return report->called && report->phase==MRK_SERVICE_MUTATE
                && report->action==1 && report->entered && report->returned
                && report->service_state==2 && original->service;
        case MRK_SERVICE_RELEASE:
            return report->called && report->phase>=MRK_SERVICE_ACQUIRE
                && report->phase<=MRK_SERVICE_RESULT
                && ((report->service_state==2 && original->service)
                    || (report->service_state==4 && !original->service));
        default:return 0;
    }
}
static uint32_t registration_outcome(BOOL accepted,NSError *error) {
    if (accepted && !error) return 2;
    if (error && [[error domain] isEqualToString:SMAppServiceErrorDomain]) {
        switch ([error code]) {
            case kSMErrorAlreadyRegistered:return 3;
            case kSMErrorLaunchDeniedByUser:return 9;
            default:return 7;
        }
    }
    return 7;
}
// One fixed phase only. Rust applies original W/H/F before entry and imports the
// actual return before ANY next phase. Native entry/consumption is not inferred
// from a gate or a dropped Rust future.
int mrk_android_management_step(void *raw,uint32_t phase,mrk_android_management_report *output) {
    mrk_android_management *original=raw;
    if (!manager_valid(original) || !output || !phase_admitted(original,phase)) return 0;
    original->report.phase=phase;
    @try {
        switch (phase) {
            case MRK_SERVICE_ACQUIRE: {
                original->report.called=1;original->report.service_state=1;
                // Record original identity before taking ownership. If retain
                // has an uncertain return the slot is Unknown, never reused or
                // dereferenced after returning to the framework's own pool.
                original->service=[SMAppService daemonServiceWithPlistName:MRK_ANDROID_SERVICE_PLIST];
                if (!original->service) {
                    original->report.service_state=4;original->report.outcome=7;break;
                }
                [original->service retain];original->report.service_state=2;break;
            }
            case MRK_SERVICE_STATUS: {
                original->report.status=status_data((SMAppService *)original->service);
                if (original->report.status==5) original->report.outcome=7;
                else if (original->report.action==0) original->report.outcome=1;
                else if (original->report.action==1) {
                    if (original->report.status==1) original->report.outcome=3;
                    else if (original->report.status==2) original->report.outcome=4;
                    else if (original->report.status==3) original->report.outcome=6;
                }
                break;
            }
            case MRK_SERVICE_MUTATE: {
                // The app's private matching native consent is independently
                // checked at action admission. This flag records the REAL
                // selector entry, not admission, service creation or status.
                if (original->report.action==2) {
                    original->report.entered=1;
                    [SMAppService openSystemSettingsLoginItems];
                    original->report.returned=1;original->report.outcome=5;
                } else {
                    NSError *error=nil;original->report.entered=1;
                    const BOOL accepted=[(SMAppService *)original->service registerAndReturnError:&error];
                    original->report.returned=1;
                    original->report.outcome=registration_outcome(accepted,error);
                }
                break;
            }
            case MRK_SERVICE_RESULT:
                original->report.status=status_data((SMAppService *)original->service);
                if (original->report.status==5) original->report.outcome=7;
                break;
            case MRK_SERVICE_RELEASE:
                if (original->report.service_state==2) {
                    original->report.service_state=3;
                    [original->service release];
                    original->service=nil;original->report.service_state=4;
                }
                original->report.cleanup_known=1;break;
            default:return 0;
        }
    } @catch (NSException *exception) {
        (void)exception;manager_unknown(original);
    }
    *output=original->report;return 1;
}
// A cell whose action never entered can retire WITHOUT manufacturing a call or
// service release. Both branches require empty, known original slots.
int mrk_android_management_retire(void *raw,uint32_t unentered) {
    mrk_android_management *original=raw;
    if (!manager_valid(original) || unentered>1 || original->report.unknown || original->service) return 0;
    if (unentered) {
        if (original->report.called || original->report.phase || original->report.service_state
            || original->report.entered || original->report.returned || original->report.cleanup_known) return 0;
    } else if (!original->report.called || original->report.phase!=MRK_SERVICE_RELEASE
        || !original->report.cleanup_known || original->report.service_state!=4) return 0;
    original->magic=0;free(original);return 1;
}

// Signature originals are separate from both filesystem custody and service
// management. Only a non-main original worker enters these fixed phases. All
// twelve CF references remain owned until their actual consuming returns; no
// pool, temporary bool, ambient requirement or native Drop cleanup is used.
#define MRK_ANDROID_IDENTITY_MAGIC UINT64_C(0x4d524b4149444e31)
enum { MRK_IDENTITY_SLOTS=12, MRK_IDENTITY_STEPS=17, MRK_IDENTITY_RELEASE=32 };
typedef struct {
    uint32_t version,phase,calls,returned,verified,failed,unknown,reserved;
    uint32_t states[MRK_IDENTITY_SLOTS];
} mrk_android_identity_report;
typedef struct {
    uint64_t magic;
    pthread_t worker;
    pid_t process;
    CFTypeRef values[MRK_IDENTITY_SLOTS];
    mrk_android_identity_report report;
} mrk_android_identity;
_Static_assert(sizeof(mrk_android_identity)<=1024u,"supplied signature cell, not framework heap");
_Static_assert(sizeof(mrk_android_identity_report)==80u,"Rust/C fixed identity report");
static int identity_original(mrk_android_identity *book) {
    return book && book->magic==MRK_ANDROID_IDENTITY_MAGIC && pthread_main_np()==0
        && book->process==getpid() && pthread_equal(book->worker,pthread_self());
}
static void identity_failed(mrk_android_identity *book) { book->report.failed=1; }
static void identity_unknown(mrk_android_identity *book) {
    book->report.failed=1;book->report.unknown=1;
    for (unsigned i=0;i<MRK_IDENTITY_SLOTS;i++)
        if (book->report.states[i]==1 || book->report.states[i]==3) book->report.states[i]=5;
}
static void identity_got(mrk_android_identity *book,unsigned slot,CFTypeRef value,OSStatus status) {
    book->values[slot]=value;book->report.states[slot]=value?2:4;
    if (!value || status!=errSecSuccess) identity_failed(book);
}
static int identity_number(CFDictionaryRef info,CFStringRef name,uint32_t *out) {
    CFTypeRef value=CFDictionaryGetValue(info,name);int64_t number=0;
    if (!value || CFGetTypeID(value)!=CFNumberGetTypeID() || CFNumberIsFloatType((CFNumberRef)value)
        || !CFNumberGetValue((CFNumberRef)value,kCFNumberSInt64Type,&number) || number<0 || number>UINT32_MAX) return 0;
    *out=(uint32_t)number;return 1;
}
static int identity_hardened(CFDictionaryRef info,int dynamic) {
    if (!info || CFGetTypeID(info)!=CFDictionaryGetTypeID() || CFDictionaryGetCount(info)>128) return 0;
    uint32_t flags=0,status=0;
    if (!identity_number(info,kSecCodeInfoFlags,&flags) || !(flags&kSecCodeSignatureRuntime)) return 0;
    CFTypeRef ent=CFDictionaryGetValue(info,kSecCodeInfoEntitlementsDict);
    CFTypeRef raw=CFDictionaryGetValue(info,kSecCodeInfoEntitlements);
    if (ent && (CFGetTypeID(ent)!=CFDictionaryGetTypeID() || CFDictionaryGetCount((CFDictionaryRef)ent)!=0)) return 0;
    if ((!ent && raw) || (raw && (CFGetTypeID(raw)!=CFDataGetTypeID() || CFDataGetLength((CFDataRef)raw)>4096))) return 0;
    return !dynamic || (identity_number(info,kSecCodeInfoStatus,&status) && (status&kSecCodeStatusValid)
        && !(status&kSecCodeStatusDebugged));
}
static int identity_same_code(CFDictionaryRef app,CFDictionaryRef actual) {
    CFTypeRef left=CFDictionaryGetValue(app,kSecCodeInfoUnique),right=CFDictionaryGetValue(actual,kSecCodeInfoUnique);
    // The supported CodeDirectory identity is compared in full, never truncated
    // or used as a replacement for the retained executing-file location proof.
    return left && right && CFGetTypeID(left)==CFDataGetTypeID() && CFGetTypeID(right)==CFDataGetTypeID()
        && CFDataGetLength((CFDataRef)left)==20 && CFDataGetLength((CFDataRef)right)==20 && CFEqual(left,right);
}
void *mrk_android_signing_new(void) {
    if (pthread_main_np()!=0 || getuid()==0 || geteuid()!=getuid() || getegid()!=getgid()
        || !mrk_android_identity_available()) return NULL;
    mrk_android_identity *book=calloc(1,sizeof(*book));
    if (book) { book->magic=MRK_ANDROID_IDENTITY_MAGIC;book->worker=pthread_self();
        book->process=getpid();book->report.version=1; }
    return book;
}
int mrk_android_signing_step(void *raw,uint32_t phase,mrk_android_identity_report *out) {
    mrk_android_identity *book=raw;
    if (!identity_original(book) || !out || book->report.unknown || phase<1 || phase>MRK_IDENTITY_STEPS
        || phase!=book->report.phase+1 || book->report.failed) return 0;
    unsigned slot=MRK_IDENTITY_SLOTS;
    switch (phase) {
        case 1:slot=0;break;case 2:slot=1;break;case 3:slot=2;break;case 4:slot=3;break;case 6:slot=4;break;
        case 7:slot=5;break;case 8:slot=6;break;case 9:slot=7;break;case 10:slot=8;break;case 12:slot=9;break;
        case 13:slot=10;break;case 15:slot=11;break;default:break;
    }
    if (slot<MRK_IDENTITY_SLOTS && (book->report.states[slot] || book->values[slot])) return 0;
    book->report.phase=phase;book->report.calls++;
    if (slot<MRK_IDENTITY_SLOTS) book->report.states[slot]=1;
    @try {
        OSStatus status=errSecSuccess;
        switch (phase) {
            case 1:case 7: {
                const char *path=phase==1 ? MRK_ANDROID_APP_PATH : MRK_ANDROID_APP_PATH "/Contents/Helpers/mrk-android-register";
                CFURLRef value=CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault,(const UInt8 *)path,strlen(path),phase==1);
                identity_got(book,slot,value,errSecSuccess);break;
            }
            case 2:case 8: {
                SecStaticCodeRef value=NULL;
                status=SecStaticCodeCreateWithPath((CFURLRef)book->values[phase==2?0:5],kSecCSDefaultFlags,&value);
                identity_got(book,slot,value,status);break;
            }
            case 3:case 9: {
                CFStringRef value=CFStringCreateWithCString(kCFAllocatorDefault,
                    phase==3?MRK_ANDROID_APP_REQUIREMENT:MRK_ANDROID_HELPER_REQUIREMENT,kCFStringEncodingASCII);
                identity_got(book,slot,value,errSecSuccess);break;
            }
            case 4:case 10: {
                SecRequirementRef value=NULL;
                status=SecRequirementCreateWithString((CFStringRef)book->values[phase==4?2:7],kSecCSDefaultFlags,&value);
                identity_got(book,slot,value,status);break;
            }
            case 5:case 11:
                status=SecStaticCodeCheckValidity((SecStaticCodeRef)book->values[phase==5?1:6],
                    kSecCSStrictValidate|kSecCSCheckAllArchitectures|kSecCSCheckNestedCode|kSecCSNoNetworkAccess,
                    (SecRequirementRef)book->values[phase==5?3:8]);
                if (status!=errSecSuccess) identity_failed(book);break;
            case 6:case 12:case 15: {
                CFDictionaryRef value=NULL;
                status=SecCodeCopySigningInformation((SecStaticCodeRef)book->values[phase==6?1:phase==12?6:10],
                    kSecCSSigningInformation|(phase==15?kSecCSDynamicInformation:0),&value);
                identity_got(book,slot,value,status);
                if (!book->report.failed && !identity_hardened(value,phase==15)) identity_failed(book);
                break;
            }
            case 13: {
                SecCodeRef value=NULL;status=SecCodeCopySelf(kSecCSDefaultFlags,&value);
                identity_got(book,slot,value,status);break;
            }
            case 14:
                status=SecCodeCheckValidity((SecCodeRef)book->values[10],kSecCSNoNetworkAccess,(SecRequirementRef)book->values[3]);
                if (status!=errSecSuccess) identity_failed(book);break;
            case 16:
                if (!identity_same_code((CFDictionaryRef)book->values[4],(CFDictionaryRef)book->values[11])) identity_failed(book);
                break;
            case 17:
                // A final fresh dynamic validity query, while the same fixed
                // filesystem and CF originals are still retained by this worker.
                status=SecCodeCheckValidity((SecCodeRef)book->values[10],kSecCSNoNetworkAccess,(SecRequirementRef)book->values[3]);
                if (status!=errSecSuccess) identity_failed(book);else book->report.verified=1;
                break;
            default:return 0;
        }
        book->report.returned++;
    } @catch (...) { identity_unknown(book); }
    *out=book->report;return 1;
}
int mrk_android_signing_release(void *raw,uint32_t slot,mrk_android_identity_report *out) {
    mrk_android_identity *book=raw;
    if (!identity_original(book) || !out || slot>=MRK_IDENTITY_SLOTS || book->report.unknown
        || book->report.calls!=book->report.returned || book->report.states[slot]!=2 || !book->values[slot]) return 0;
    book->report.phase=MRK_IDENTITY_RELEASE+slot;book->report.states[slot]=3;book->report.calls++;
    @try {
        CFRelease(book->values[slot]);book->values[slot]=NULL;book->report.states[slot]=4;book->report.returned++;
    } @catch (...) { identity_unknown(book); }
    *out=book->report;return 1;
}
int mrk_android_signing_retire(void *raw) {
    mrk_android_identity *book=raw;
    if (!identity_original(book) || book->report.unknown || book->report.calls!=book->report.returned) return 0;
    for (unsigned i=0;i<MRK_IDENTITY_SLOTS;i++)
        if (book->values[i] || (book->report.states[i]!=0 && book->report.states[i]!=4)) return 0;
    book->magic=0;free(book);return 1;
}
#endif
