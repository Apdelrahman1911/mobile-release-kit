/* Fixed diagnostic only: public daemon factory/status, never registration.
 * Python holds and checks the exact installed inputs before/after this call.
 * A returned observation is not absence, service ownership or qualification.
 */
#import <Foundation/Foundation.h>
#import <ServiceManagement/ServiceManagement.h>
#import <CoreFoundation/CoreFoundation.h>
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
static const char *const cases[] = {"single", "nested"};

static int clock_ns(uint64_t *value) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0 || now.tv_nsec < 0 ||
        now.tv_nsec >= 1000000000 || (uint64_t)now.tv_sec > ((UINT64_C(1) << 61) - 1) / 1000000000)
        return 0;
    *value = (uint64_t)now.tv_sec * 1000000000 + (uint64_t)now.tv_nsec;
    return *value > 0 && *value < (UINT64_C(1) << 61);
}

int main(int argc, char **argv) {
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
}
