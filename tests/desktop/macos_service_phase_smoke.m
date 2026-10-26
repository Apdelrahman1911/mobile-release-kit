// Executes the real Objective-C phase implementation with inert service/gate
// edges. Never registers a service, reads an installation or changes settings.
#import <Foundation/Foundation.h>
#import <ServiceManagement/ServiceManagement.h>
#include <assert.h>
#include <stdio.h>
static unsigned registrations, statuses;
static BOOL accepted;
static NSError *returned_error;
static int reservation_matches=1;
@interface MRKPhaseService : NSObject
+ (instancetype)daemonServiceWithPlistName:(NSString *)name;
+ (void)openSystemSettingsLoginItems;
- (SMAppServiceStatus)status;
- (BOOL)registerAndReturnError:(NSError **)error;
- (BOOL)unregisterAndReturnError:(NSError **)error;
@end
@implementation MRKPhaseService
+ (instancetype)daemonServiceWithPlistName:(NSString *)name {
    assert([name isEqualToString:@"dev.mobile-release-kit.desktop.android-register.plist"]);
    return [[[self alloc] init] autorelease];
}
+ (void)openSystemSettingsLoginItems {assert(0);}
- (SMAppServiceStatus)status {statuses++;return registrations && accepted && !returned_error
    ? SMAppServiceStatusEnabled : SMAppServiceStatusNotFound;}
- (BOOL)registerAndReturnError:(NSError **)error {registrations++;*error=returned_error;return accepted;}
- (BOOL)unregisterAndReturnError:(NSError **)error {(void)error;assert(0);return NO;}
@end
#define SMAppService MRKPhaseService
#define MRK_ANDROID_APP_PATH "/nonexistent-mrk-phase-fixture"
#include "../../desktop/native/macos-installed-native/src/android_service_management.m"
#undef SMAppService
int mrk_android_identity_available(void) {return 1;}
void mrk_entry_init(mrk_entry_book *book) {memset(book,0,sizeof(*book));}
int mrk_entry_root(mrk_entry_book *book) {(void)book;return 1;}
int mrk_entry_open_registration(mrk_entry_book *book) {(void)book;return 1;}
int mrk_registration_acquire_shared(mrk_entry_book *book) {book->registration_held=1;return 1;}
int mrk_entry_gate_matches(mrk_entry_book *book,int flags) {(void)book;assert(flags==FD_CLOEXEC);return reservation_matches;}
int mrk_registration_retire(mrk_entry_book *book) {book->registration_held=0;return 1;}
static void run(BOOL result,NSError *error,unsigned category,unsigned outcome,int held) {
    registrations=0;statuses=0;accepted=result;returned_error=error;reservation_matches=held;
    void *manager=mrk_android_management_new(1);assert(manager);
    mrk_android_management_report report={0};
    assert(mrk_android_management_step(manager,2,&report));
    assert(mrk_android_management_step(manager,3,&report));
    assert(report.status==3 && report.outcome==0 && !report.entered);
    assert(mrk_android_management_step(manager,4,&report));
    assert(registrations==(held?1u:0u) && report.entered==(unsigned)held
        && report.returned==(unsigned)held && report.outcome==(held?outcome:6));
#if defined(MRK_INSTALLED_OBSERVATION)
    assert(report.version==4 && report.reserved==(held?(1u|(result?2u:0u)|(error?4u:0u)|(category<<8)):0));
#else
    assert(report.version==2 && report.reserved==0);
#endif
    if (held && outcome==2) {
        assert(mrk_android_management_step(manager,5,&report));
        assert(report.status==1 && statuses==2);
    }
    unsigned diagnostic=report.reserved;
    assert(mrk_android_management_step(manager,6,&report));
    assert(report.cleanup_known && report.reserved==diagnostic);
    assert(!mrk_android_management_step(manager,4,&report));
    assert(mrk_android_management_retire(manager,0));
}
int main(void) {
    @autoreleasepool {
        run(YES,nil,0,2,1);run(NO,nil,0,7,1);run(YES,nil,0,2,0);
        for (NSInteger code=kSMErrorInternalFailure;code<=kSMErrorAlreadyRegistered;code++) {
            NSError *error=[NSError errorWithDomain:SMAppServiceErrorDomain code:code userInfo:nil];
            unsigned outcome=code==kSMErrorAlreadyRegistered?3:code==kSMErrorLaunchDeniedByUser?9:7;
            run(NO,error,(unsigned)(code-kSMErrorInternalFailure+1),outcome,1);
        }
        run(NO,[NSError errorWithDomain:SMAppServiceErrorDomain code:999 userInfo:nil],12,7,1);
        run(NO,[NSError errorWithDomain:NSPOSIXErrorDomain code:1 userInfo:nil],13,7,1);
    }
    puts("16 actual Objective-C phase cases passed; service and gate edges inert");
    return 0;
}
