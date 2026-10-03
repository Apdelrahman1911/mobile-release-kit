// Fixed normal-app SMAppService phases. No generic service/path, unregister,
// restart, automatic approval, callback scheduler or app-owned autorelease pool.
// The original app owner queues this onto its verified AppKit event callback.
#import <Foundation/Foundation.h>
#import <ServiceManagement/ServiceManagement.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#if !defined(MRK_ANDROID_REGISTRATION_HELPER) && !defined(MRK_WRAPPING_VAULT_HELPER)
extern int mrk_android_identity_available(void);
#define MRK_ANDROID_MANAGEMENT_MAGIC UINT64_C(0x4d524b41534d4732)
#define MRK_ANDROID_SERVICE_PLIST @"dev.mobile-release-kit.desktop.android-register.plist"
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
            case kSMErrorLaunchDeniedByUser:return 4;
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
#endif
