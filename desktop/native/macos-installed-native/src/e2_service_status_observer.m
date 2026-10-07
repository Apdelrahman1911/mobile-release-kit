/* Fixed diagnostic only: public daemon factory/status, never registration.
 * Python holds and checks the exact installed inputs before/after this call.
 * A returned observation is not absence, service ownership or qualification.
 */
#import <Foundation/Foundation.h>
#import <ServiceManagement/ServiceManagement.h>
#import <CoreFoundation/CoreFoundation.h>
#if defined(MRK_E2_SERVICE_COCOA_STARTUP)
#import <AppKit/AppKit.h>
#import <Security/AuthSession.h>
#endif
#include <mach-o/dyld.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if !defined(__APPLE__) || !defined(__arm64__) || !defined(MRK_E2_SERVICE_LAYOUT_DIAGNOSTIC)
#error This observer is only the fixed ARM macOS fixture diagnostic.
#endif
#ifndef MRK_IMAGE_SOURCE_COMMIT
#error A source-bound compile is required.
#endif
#ifndef MRK_OBSERVER_SOURCE_SHA256
#error The original observer source digest is required.
#endif
_Static_assert(sizeof(void *) == 8 && sizeof(long) == 8, "LP64 required");
_Static_assert(sizeof(MRK_IMAGE_SOURCE_COMMIT) == 41, "source width");
_Static_assert(sizeof(MRK_OBSERVER_SOURCE_SHA256) == 65, "observer width");

#define ROOT "/Library/Application Support/MobileReleaseKit-E2NativeFixture/service-status-layout/"
#define SINGLE ROOT "Single/MRK E2 Status Client.app"
#define NESTED ROOT "Nested/MRK E2 Status Host.app/Contents/Helpers/MRK E2 Status Client.app"
#define EXECUTABLE "/Contents/MacOS/mrk-e2-status-observer"
#define SERVICE "dev.mobile-release-kit.fixture.e2.status-observation.resident"
#define CLIENT_ID "dev.mobile-release-kit.fixture.e2.status-observation.client"
#define PLIST "/Contents/Library/LaunchDaemons/" SERVICE ".plist"

static const char *const bundle_paths[] = {SINGLE, NESTED};
static const char *const executable_paths[] = {SINGLE EXECUTABLE, NESTED EXECUTABLE};
static const char *const plist_paths[] = {SINGLE PLIST, NESTED PLIST};
#if !defined(MRK_E2_SERVICE_COCOA_STARTUP)
static const char *const cases[] = {"single", "nested"};
#endif

static int clock_ns(uint64_t *value) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0 || now.tv_nsec < 0 ||
        now.tv_nsec >= 1000000000 || (uint64_t)now.tv_sec > ((UINT64_C(1) << 61) - 1) / 1000000000)
        return 0;
    *value = (uint64_t)now.tv_sec * 1000000000 + (uint64_t)now.tv_nsec;
    return *value > 0 && *value < (UINT64_C(1) << 61);
}

#if defined(MRK_E2_SERVICE_COCOA_STARTUP)
/* One process, one fixed installed client and two read-only status originals.
 * Cocoa startup is the ONLY changed entry condition. No window or service
 * registration API is present, and a transition is never lifecycle authority.
 */
typedef struct {
    const char *status;
    uint64_t started, finished;
    int factory_returned, retain_returned, status_returned, release_returned;
} CocoaStatus;

typedef struct {
    NSApplication *application; /* Borrowed only while main holds its original. */
    CocoaStatus initial, startup;
    int uncertain, callback_count, did_finish, run_entered, run_returned;
    int stop_scheduled, schedule_returned, stop_entered, stop_returned, wake_posted;
    int callbacks_cancelled, delegate_cleared, delegate_release, application_release;
    int pool_drain, no_windows;
} CocoaState;

static int cocoa_status(CocoaStatus *row, int *uncertain) {
    SMAppService *service = nil;
    int pending = 0, ready = 0;
    if (!clock_ns(&row->started)) return 0;
    @try {
        do {
            pending = 1;
            SMAppService *original = [SMAppService daemonServiceWithPlistName:@SERVICE ".plist"];
            row->factory_returned = 1;
            pending = 0;
            if (original == nil) break;
            pending = 1;
            service = [original retain];
            row->retain_returned = 1;
            pending = 0;
            if (service != original) { *uncertain = 1; service = nil; break; }
            ready = 1;
            SMAppServiceStatus actual_status = service.status;
            row->status_returned = 1;
            switch (actual_status) {
                case SMAppServiceStatusNotRegistered: row->status = "not-registered"; break;
                case SMAppServiceStatusEnabled: row->status = "enabled"; break;
                case SMAppServiceStatusRequiresApproval: row->status = "requires-approval"; break;
                case SMAppServiceStatusNotFound: row->status = "not-found"; break;
                default: break;
            }
        } while (0);
    } @catch (__unused NSException *exception) {
        if (pending) *uncertain = 1;
    }
    if (ready) {
        SMAppService *original = service;
        service = nil;
        ready = 0;
        @try { [original release]; row->release_returned = 1; }
        @catch (__unused NSException *exception) { *uncertain = 1; }
    }
    return !pending && !*uncertain && row->status != NULL && row->factory_returned &&
        row->retain_returned && row->status_returned && row->release_returned &&
        clock_ns(&row->finished) && row->finished >= row->started;
}

@interface MRKCocoaStatusDelegate : NSObject <NSApplicationDelegate> {
@public
    CocoaState *state;
}
- (void)stopAfterObservation:(id)sender;
@end

@implementation MRKCocoaStatusDelegate
- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    if (state == NULL) return;
    @try {
        if (state->callback_count != 0 || !state->run_entered || state->run_returned ||
            ![NSThread isMainThread] || notification.object != state->application) {
            state->uncertain = 1;
            return;
        }
        state->callback_count = 1;
        state->did_finish = 1;
        /* Stop on the next actual run-loop turn, including a refused status.
         * There is one scheduled callback, never a retry or external process. */
        state->stop_scheduled = 1;
        [self performSelector:@selector(stopAfterObservation:) withObject:nil afterDelay:0];
        state->schedule_returned = 1;
        if ([state->application.windows count] != 0 ||
            !cocoa_status(&state->startup, &state->uncertain)) state->uncertain = 1;
    } @catch (__unused NSException *exception) {
        state->uncertain = 1;
    }
}

- (void)stopAfterObservation:(__unused id)sender {
    if (state == NULL) return;
    @try {
        if (!state->stop_scheduled || state->stop_entered || state->callback_count != 1 ||
            ![NSThread isMainThread] || !state->run_entered || state->run_returned) {
            state->uncertain = 1;
            return;
        }
        state->stop_entered = 1;
        [state->application stop:self];
        state->stop_returned = 1;
        /* stop: does not wake a blocked nextEventMatchingMask:. This private
         * application-defined event wakes the SAME run loop; it creates no UI. */
        NSEvent *wake = [NSEvent otherEventWithType:NSEventTypeApplicationDefined
                                         location:NSZeroPoint modifierFlags:0 timestamp:0
                                     windowNumber:0 context:nil subtype:0 data1:0 data2:0];
        if (wake == nil) { state->uncertain = 1; return; }
        [state->application postEvent:wake atStart:YES];
        state->wake_posted = 1;
    } @catch (__unused NSException *exception) {
        state->uncertain = 1;
    }
}
@end

static int cocoa_main(int argc, char **argv) {
    (void)argv;
    if (argc != 1 || getuid() == 0 || getuid() != geteuid() || getgid() != getegid()) return 77;
    char executable[1024];
    uint32_t executable_size = sizeof(executable);
    if (_NSGetExecutablePath(executable, &executable_size) != 0 ||
        strcmp(executable, SINGLE EXECUTABLE) != 0) return 77;
    const int selected = 0; /* The nested/host/target copies cannot enter. */
    uint64_t started = 0, finished = 0;
    if (!clock_ns(&started)) return 77;
    SecuritySessionId session = 0;
    SessionAttributeBits attributes = (SessionAttributeBits)0;
    /* Query our existing session only; never create or change one. Distinct
     * refusing exits let the owner distinguish this precondition without IDs. */
    if (SessionGetInfo(callerSecuritySession, &session, &attributes) != 0) return 79;
    if (!(attributes & sessionHasGraphicAccess)) return 78;
    CocoaState state = {0};
    NSAutoreleasePool *pool = nil;
    NSApplication *application = nil;
    MRKCocoaStatusDelegate *delegate = nil;
    int pending = 0, pool_ready = 0, application_ready = 0, delegate_ready = 0;
    int delegate_attached = 0, delegate_set_entered = 0, observed = 0;
    @try {
        do {
            pending = 1;
            NSAutoreleasePool *allocated = [NSAutoreleasePool alloc];
            pending = 0;
            if (allocated == nil) break;
            pending = 1;
            pool = [allocated init];
            pending = 0;
            if (pool != allocated) { state.uncertain = 1; pool = nil; break; }
            pool_ready = 1;
            if (![NSThread isMainThread] || [NSProcessInfo processInfo].operatingSystemVersion.majorVersion != 26)
                break;
            NSBundle *bundle = [NSBundle mainBundle];
            NSString *expected_bundle = [NSString stringWithUTF8String:bundle_paths[selected]];
            NSString *expected_executable = [NSString stringWithUTF8String:executable_paths[selected]];
            if (bundle == nil || ![bundle.bundlePath isEqualToString:expected_bundle] ||
                ![bundle.executablePath isEqualToString:expected_executable] ||
                ![bundle.bundleIdentifier isEqualToString:@CLIENT_ID]) break;

            NSURL *plist_url = [[bundle.bundleURL URLByAppendingPathComponent:@"Contents/Library/LaunchDaemons"
                                                                  isDirectory:YES]
                               URLByAppendingPathComponent:@SERVICE ".plist" isDirectory:NO];
            if (!plist_url.isFileURL || ![plist_url.path isEqualToString:
                                         [NSString stringWithUTF8String:plist_paths[selected]]]) break;
            /* The owner already holds this exact, small immutable plist. This
             * convenience API is not itself a bounded or no-follow reader. */
            NSError *error = nil;
            NSData *data = [NSData dataWithContentsOfURL:plist_url options:0 error:&error];
            if (data == nil || error != nil || data.length == 0 || data.length > 4096) break;
            NSPropertyListFormat format = NSPropertyListXMLFormat_v1_0;
            id plist = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable
                                                                  format:&format error:&error];
            if (error != nil || format != NSPropertyListXMLFormat_v1_0 ||
                ![plist isKindOfClass:[NSDictionary class]] || [plist count] != 3 ||
                ![[plist objectForKey:@"Label"] isEqual:@SERVICE] ||
                ![[plist objectForKey:@"BundleProgram"] isEqual:@"Contents/Helpers/mrk-e2-status-target"]) break;
            id services = [plist objectForKey:@"MachServices"];
            if (![services isKindOfClass:[NSDictionary class]] || [services count] != 1) break;
            id enabled = [services objectForKey:@SERVICE];
            if (enabled == nil || ![enabled isKindOfClass:[NSNumber class]] ||
                CFGetTypeID((CFTypeRef)enabled) != CFBooleanGetTypeID() || ![enabled boolValue]) break;

            /* The first original precedes sharedApplication and app startup. */
            if (!cocoa_status(&state.initial, &state.uncertain)) break;
            pending = 1;
            NSApplication *original_app = [NSApplication sharedApplication];
            pending = 0;
            if (original_app == nil) break;
            pending = 1;
            application = [original_app retain];
            pending = 0;
            if (application != original_app) { state.uncertain = 1; application = nil; break; }
            application_ready = 1;
            state.application = application;
            if (application != NSApp || application.delegate != nil || application.running ||
                [application.windows count] != 0) break;
            pending = 1;
            MRKCocoaStatusDelegate *allocated_delegate = [MRKCocoaStatusDelegate alloc];
            pending = 0;
            if (allocated_delegate == nil) break;
            pending = 1;
            delegate = [allocated_delegate init];
            pending = 0;
            if (delegate != allocated_delegate) { state.uncertain = 1; delegate = nil; break; }
            delegate_ready = 1;
            delegate->state = &state;
            delegate_attached = 1; /* A throwing setter may have attached it. */
            delegate_set_entered = 1;
            application.delegate = delegate;
            if (application.delegate != delegate) { state.uncertain = 1; break; }
            state.run_entered = 1;
            [application run];
            state.run_returned = 1;
            state.no_windows = [application.windows count] == 0;
            observed = !application.running && state.did_finish && state.callback_count == 1 &&
                state.schedule_returned && state.stop_entered && state.stop_returned &&
                state.wake_posted && state.no_windows && state.startup.status != NULL;
        } while (0);
    } @catch (__unused NSException *exception) {
        observed = 0;
        if (pending) state.uncertain = 1;
    }
    /* Clear any callback and borrowed delegate before releasing our originals.
     * A failed clear cannot authorize releasing a still-borrowed delegate. */
    if (delegate_ready) {
        @try { [NSObject cancelPreviousPerformRequestsWithTarget:delegate]; state.callbacks_cancelled = 1; }
        @catch (__unused NSException *exception) { state.uncertain = 1; }
    }
    if (delegate_attached) {
        delegate_attached = 0;
        @try {
            application.delegate = nil;
            state.delegate_cleared = application.delegate == nil;
            if (!state.delegate_cleared) state.uncertain = 1;
        } @catch (__unused NSException *exception) { state.uncertain = 1; }
    }
    if (delegate_ready && state.callbacks_cancelled && (!delegate_set_entered || state.delegate_cleared)) {
        MRKCocoaStatusDelegate *original = delegate;
        delegate = nil;
        delegate_ready = 0;
        original->state = NULL;
        @try { [original release]; state.delegate_release = 1; }
        @catch (__unused NSException *exception) { state.uncertain = 1; }
    }
    if (application_ready) {
        NSApplication *original = application;
        application = nil;
        application_ready = 0;
        state.application = nil;
        @try { [original release]; state.application_release = 1; }
        @catch (__unused NSException *exception) { state.uncertain = 1; }
    }
    if (pool_ready) {
        NSAutoreleasePool *original = pool;
        pool = nil;
        pool_ready = 0;
        @try { [original drain]; state.pool_drain = 1; }
        @catch (__unused NSException *exception) { state.uncertain = 1; }
    }
    /* Only C values below; no borrowed Objective-C object survives publication. */
    if (state.uncertain || pending || !observed || !state.callbacks_cancelled || !state.delegate_cleared ||
        !state.delegate_release || !state.application_release || !state.pool_drain ||
        !clock_ns(&finished) || started > state.initial.started ||
        state.initial.finished > state.startup.started || state.startup.finished > finished ||
        finished < started || finished - started > UINT64_C(15000000000)) return 77;
    char output[2048];
    int size = snprintf(output, sizeof(output),
        "{\"schemaVersion\":1,\"type\":\"mrk-e2-service-cocoa-status-v1\","
        "\"sourceCommit\":\"%s\",\"observerSourceSha256\":\"%s\",\"case\":\"single\","
        "\"outcome\":\"observed\",\"startedNs\":\"%" PRIu64 "\",\"finishedNs\":\"%" PRIu64 "\","
        "\"bundle\":\"expected-client\",\"executable\":\"expected-client\","
        "\"identifier\":\"expected-client\",\"plist\":\"expected-daemon\","
        "\"observations\":[{\"stage\":\"before-cocoa\",\"status\":\"%s\","
        "\"startedNs\":\"%" PRIu64 "\",\"finishedNs\":\"%" PRIu64 "\","
        "\"factoryReturned\":true,\"retainReturned\":true,\"statusReturned\":true,\"serviceReleaseReturned\":true},"
        "{\"stage\":\"did-finish-launching\",\"status\":\"%s\","
        "\"startedNs\":\"%" PRIu64 "\",\"finishedNs\":\"%" PRIu64 "\","
        "\"factoryReturned\":true,\"retainReturned\":true,\"statusReturned\":true,\"serviceReleaseReturned\":true}],"
        "\"graphicSessionVerified\":true,\"didFinishLaunching\":true,\"callbackCount\":1,"
        "\"stopReturned\":true,\"wakeEventPosted\":true,"
        "\"runReturned\":true,\"callbacksCancelled\":true,\"delegateCleared\":true,"
        "\"delegateReleaseReturned\":true,\"applicationReleaseReturned\":true,\"poolDrainReturned\":true,"
        "\"windowsObserved\":0,\"finalityKnown\":true,\"registrationEntered\":false}\n",
        MRK_IMAGE_SOURCE_COMMIT, MRK_OBSERVER_SOURCE_SHA256, started, finished,
        state.initial.status, state.initial.started, state.initial.finished,
        state.startup.status, state.startup.started, state.startup.finished);
    if (size <= 0 || (size_t)size >= sizeof(output) || write(STDOUT_FILENO, output, (size_t)size) != size) return 77;
    return 0;
}
#endif

int main(int argc, char **argv) {
#if defined(MRK_E2_SERVICE_COCOA_STARTUP)
    return cocoa_main(argc, argv);
#else
    (void)argv;
    if (argc != 1 || getuid() == 0 || getuid() != geteuid() || getgid() != getegid()) return 77;
    char executable[1024];
    uint32_t executable_size = sizeof(executable);
    if (_NSGetExecutablePath(executable, &executable_size) != 0) return 77;
    int selected = -1;
    for (int i = 0; i < 2; ++i) if (strcmp(executable, executable_paths[i]) == 0) selected = i;
    /* The target and host copies cannot become service executables. */
    if (selected < 0) return 77;
    uint64_t started = 0, finished = 0;
    if (!clock_ns(&started)) return 77;

    NSAutoreleasePool *pool = nil;
    SMAppService *service = nil;
    int pending_acquisition = 0, uncertain = 0, observed = 0;
    int pool_ready = 0, service_ready = 0, factory_returned = 0, retain_returned = 0;
    int status_returned = 0, release_returned = 0, drain_returned = 0;
    const char *status = NULL;
    @try {
        do {
            pending_acquisition = 1;
            NSAutoreleasePool *allocated = [NSAutoreleasePool alloc];
            pending_acquisition = 0;
            if (allocated == nil) break;
            pending_acquisition = 1;
            pool = [allocated init];
            pending_acquisition = 0;
            if (pool != allocated) { uncertain = 1; pool = nil; break; }
            pool_ready = 1;
            if (![NSThread isMainThread] || [NSProcessInfo processInfo].operatingSystemVersion.majorVersion != 26)
                break;

            NSBundle *bundle = [NSBundle mainBundle];
            NSString *expected_bundle = [NSString stringWithUTF8String:bundle_paths[selected]];
            NSString *expected_executable = [NSString stringWithUTF8String:executable_paths[selected]];
            if (bundle == nil || ![bundle.bundlePath isEqualToString:expected_bundle] ||
                ![bundle.executablePath isEqualToString:expected_executable] ||
                ![bundle.bundleIdentifier isEqualToString:@CLIENT_ID]) break;

            NSURL *plist_url = [[bundle.bundleURL URLByAppendingPathComponent:@"Contents/Library/LaunchDaemons"
                                                                  isDirectory:YES]
                               URLByAppendingPathComponent:@SERVICE ".plist" isDirectory:NO];
            if (!plist_url.isFileURL || ![plist_url.path isEqualToString:
                                         [NSString stringWithUTF8String:plist_paths[selected]]]) break;
            /* The owner already holds this exact, small immutable plist. This
             * convenience API is not itself a bounded or no-follow reader. */
            NSError *error = nil;
            NSData *data = [NSData dataWithContentsOfURL:plist_url options:0 error:&error];
            if (data == nil || error != nil || data.length == 0 || data.length > 4096) break;
            NSPropertyListFormat format = NSPropertyListXMLFormat_v1_0;
            id plist = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable
                                                                  format:&format error:&error];
            if (error != nil || format != NSPropertyListXMLFormat_v1_0 ||
                ![plist isKindOfClass:[NSDictionary class]] || [plist count] != 3 ||
                ![[plist objectForKey:@"Label"] isEqual:@SERVICE] ||
                ![[plist objectForKey:@"BundleProgram"] isEqual:@"Contents/Helpers/mrk-e2-status-target"]) break;
            id services = [plist objectForKey:@"MachServices"];
            if (![services isKindOfClass:[NSDictionary class]] || [services count] != 1) break;
            id enabled = [services objectForKey:@SERVICE];
            if (enabled == nil || ![enabled isKindOfClass:[NSNumber class]] ||
                CFGetTypeID((CFTypeRef)enabled) != CFBooleanGetTypeID() || ![enabled boolValue]) break;

            pending_acquisition = 1;
            SMAppService *original = [SMAppService daemonServiceWithPlistName:@SERVICE ".plist"];
            factory_returned = 1;
            pending_acquisition = 0;
            if (original == nil) break;
            pending_acquisition = 1;
            service = [original retain];
            retain_returned = 1;
            pending_acquisition = 0;
            if (service != original) { uncertain = 1; service = nil; break; }
            service_ready = 1;
            SMAppServiceStatus actual_status = service.status;
            status_returned = 1;
            switch (actual_status) {
                case SMAppServiceStatusNotRegistered: status = "not-registered"; break;
                case SMAppServiceStatusEnabled: status = "enabled"; break;
                case SMAppServiceStatusRequiresApproval: status = "requires-approval"; break;
                case SMAppServiceStatusNotFound: status = "not-found"; break;
                default: break;
            }
            observed = status != NULL;
        } while (0);
    } @catch (__unused NSException *exception) {
        observed = 0;
        if (pending_acquisition) uncertain = 1;
    }
    /* Consume each known original once, before its close dispatch. An exception
     * can never manufacture a successful return or authorize a retry. */
    if (service_ready) {
        SMAppService *original = service;
        service = nil;
        service_ready = 0;
        @try { [original release]; release_returned = 1; }
        @catch (__unused NSException *exception) { uncertain = 1; }
    }
    if (pool_ready) {
        NSAutoreleasePool *original = pool;
        pool = nil;
        pool_ready = 0;
        @try { [original drain]; drain_returned = 1; }
        @catch (__unused NSException *exception) { uncertain = 1; }
    }
    /* Nothing below accesses an Objective-C object or a borrowed NSString. */
    if (uncertain || pending_acquisition || !observed || !factory_returned || !retain_returned ||
        !status_returned || !release_returned || !drain_returned || !clock_ns(&finished) ||
        finished < started || finished - started > UINT64_C(15000000000)) return 77;
    char output[2048];
    int size = snprintf(output, sizeof(output),
        "{\"schemaVersion\":1,\"type\":\"mrk-e2-service-status-observation-v1\","
        "\"sourceCommit\":\"%s\",\"observerSourceSha256\":\"%s\",\"case\":\"%s\","
        "\"outcome\":\"observed\",\"startedNs\":\"%" PRIu64 "\",\"finishedNs\":\"%" PRIu64 "\","
        "\"bundle\":\"expected-client\",\"executable\":\"expected-client\","
        "\"identifier\":\"expected-client\",\"plist\":\"expected-daemon\",\"status\":\"%s\","
        "\"factoryReturned\":true,\"retainReturned\":true,\"statusReturned\":true,"
        "\"serviceReleaseReturned\":true,\"poolDrainReturned\":true,\"finalityKnown\":true,"
        "\"registrationEntered\":false}\n",
        MRK_IMAGE_SOURCE_COMMIT, MRK_OBSERVER_SOURCE_SHA256, cases[selected], started, finished, status);
    if (size <= 0 || (size_t)size >= sizeof(output) || write(STDOUT_FILENO, output, (size_t)size) != size) return 77;
    return 0;
#endif
}
