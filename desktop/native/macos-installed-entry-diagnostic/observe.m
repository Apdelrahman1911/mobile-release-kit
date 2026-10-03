/* One ordinary public launch, retained-original cleanup, diagnostic only.
 * This control is not an application entry or a payload/normal-Quit qualifier. */
#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#include <dispatch/dispatch.h>
#include <stdatomic.h>
#include <sys/file.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "gate.h"
#include "diagnostic_source.h"

#define ENTRY_APP @"/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app"
#define PAYLOAD_APP ENTRY_APP @"/Contents/Helpers/MobileReleaseKitPayload.app"
#define ENTRY_ID @"dev.mobile-release-kit.desktop.entry"
#define PAYLOAD_ID @"dev.mobile-release-kit.desktop"

static _Atomic unsigned callback_entered, callback_body_end;
static unsigned handoffs;
static NSRunningApplication *original_app;
static BOOL callback_error;
static NSString *error_domain = @"none";
static NSNumber *error_code;
static BOOL clock_unavailable, work_expired, probes_closed = YES;
static uint64_t previous_time;

static NSNumber *truth(BOOL value) { return value ? @YES : @NO; }
static void first(NSString **failure, NSString *value) {
    if ([*failure isEqualToString:@"none"]) *failure = value;
}
static unsigned counted(_Atomic unsigned *counter) {
    /* Apple's callback is once-only; duplicate means failure, not another app.
     * Saturate public counts, never turn a wrapped count into acceptance. */
    unsigned value = atomic_load_explicit(counter, memory_order_acquire);
    while (value < 2 && !atomic_compare_exchange_weak_explicit(counter, &value, value + 1,
            memory_order_acq_rel, memory_order_acquire)) {}
    return value < 2 ? value + 1 : 2;
}
static BOOL now_ns(uint64_t *value) {
    struct timespec stamp;
    if (clock_unavailable || clock_gettime(CLOCK_MONOTONIC, &stamp)
        || stamp.tv_sec < 0 || stamp.tv_nsec < 0 || stamp.tv_nsec >= 1000000000
        || (uint64_t)stamp.tv_sec > (UINT64_MAX - (uint64_t)stamp.tv_nsec) / 1000000000ULL) {
        clock_unavailable = YES; return NO;
    }
    uint64_t actual = (uint64_t)stamp.tv_sec * 1000000000ULL + (uint64_t)stamp.tv_nsec;
    if (actual < previous_time) { clock_unavailable = YES; return NO; }
    previous_time = actual; *value = actual; return YES;
}
static BOOL before(uint64_t deadline) {
    uint64_t actual = 0;
    return now_ns(&actual) && actual < deadline;
}
static BOOL work_before(uint64_t deadline) {
    if (work_expired || !before(deadline)) { work_expired = YES; return NO; }
    return YES;
}
static void progress(void) { (void)CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.05, true); }
static BOOL close_gate(mrk_entry_book *book) {
    int fd = book->gate; book->gate = -1;
    if (fd >= 0 && close(fd)) { book->failed = 1; probes_closed = NO; return NO; }
    return YES;
}
static NSString *probe(mrk_entry_book *book) {
    NSString *answer = @"error";
    if (mrk_entry_open_gate(book)) {
        if (flock(book->gate, LOCK_EX | LOCK_NB) == 0) answer = @"free";
        else if (errno == EWOULDBLOCK) answer = @"busy";
        if (!mrk_entry_gate_matches(book, FD_CLOEXEC)) answer = @"error";
    }
    if (!close_gate(book)) answer = @"error";
    return answer;
}
static NSString *identity(NSString *actual, NSString *entry, NSString *payload) {
    if (!actual) return @"unavailable";
    if ([actual isEqualToString:entry]) return @"entry";
    if ([actual isEqualToString:payload]) return @"payload";
    return @"other";
}
static NSString *domain(NSError *error) {
    if (!error) return @"none";
    if ([error.domain isEqualToString:NSCocoaErrorDomain]) return @"cocoa";
    if ([error.domain isEqualToString:NSOSStatusErrorDomain]) return @"osstatus";
    if ([error.domain isEqualToString:NSPOSIXErrorDomain]) return @"posix";
    if ([error.domain isEqualToString:NSURLErrorDomain]) return @"url";
    return @"other";
}
static BOOL allowed(NSString *value) {
    return [value isEqualToString:@"entry"] || [value isEqualToString:@"payload"];
}

int main(int argc, char **argv) {
    (void)argv;
    @autoreleasepool {
        NSString *failure = @"none";
        uint64_t started = 0, work_end = 0, grace_end = 0, final_end = 0;
        mrk_entry_book book; mrk_entry_init(&book);
        BOOL requested = NO, normal_requested = NO, force_requested = NO, terminated = NO;
        BOOL ancestors_closed = NO, timely = NO;
        NSNumber *normal_returned = nil, *force_returned = nil;
        NSNumber *terminated_at_work = nil, *finished = nil, *active = nil;
        NSString *bundle = @"unavailable", *identifier = @"unavailable", *executable = @"unavailable";
        NSString *gate_before = @"unobserved", *gate_live = @"unobserved", *gate_after = @"unobserved";
        uint32_t uid = 0;
        if (!now_ns(&started) || started > UINT64_MAX - 45000000000ULL) {
            clock_unavailable = YES; first(&failure, @"clock");
        } else {
            work_end = started + 15000000000ULL;
            grace_end = started + 20000000000ULL;
            final_end = started + 45000000000ULL;
        }
        if (argc != 1 || pthread_main_np() != 1 || mrk_user(&uid)) first(&failure, @"account");
        @try {
            if ([failure isEqualToString:@"none"]) {
                if (!mrk_entry_root(&book)) first(&failure, @"gate-baseline");
                else {
                    gate_before = probe(&book);
                    if (![gate_before isEqualToString:@"free"]) first(&failure, @"gate-baseline");
                }
            }
            if ([failure isEqualToString:@"none"] && work_before(work_end)) {
                NSWorkspaceOpenConfiguration *config = [NSWorkspaceOpenConfiguration configuration];
                config.activates = YES;
                config.addsToRecentItems = NO;
                config.createsNewApplicationInstance = YES;
                config.allowsRunningApplicationSubstitution = NO;
                config.promptsUserIfNeeded = NO;
                config.arguments = @[];
                /* The production entry, unchanged, establishes its own clean
                 * payload environment. No diagnostic app environment is added. */
                NSURL *entry = [NSURL fileURLWithPath:ENTRY_APP isDirectory:YES];
                if (work_before(work_end)) {
                    requested = YES;
                    @try {
                        [NSWorkspace.sharedWorkspace openApplicationAtURL:entry configuration:config
                            completionHandler:^(NSRunningApplication *app, NSError *error) {
                                counted(&callback_entered);
                                BOOL has_error = error != nil;
                                NSString *kind = domain(error);
                                NSInteger code = error ? error.code : 0;
                                NSNumber *number = error && code >= INT32_MIN && code <= INT32_MAX ? @(code) : nil;
                                dispatch_async(dispatch_get_main_queue(), ^{
                                    if (handoffs < 2) ++handoffs;
                                    if (handoffs == 1) {
                                        original_app = app; callback_error = has_error;
                                        error_domain = kind; error_code = number;
                                    }
                                });
                                counted(&callback_body_end);
                            }];
                    } @catch (...) { first(&failure, @"launch-exception"); }
                }
                while ([failure isEqualToString:@"none"] && work_before(work_end)) {
                    progress();
                    if (!work_before(work_end)) break;
                    unsigned entered = atomic_load_explicit(&callback_entered, memory_order_acquire);
                    unsigned ended = atomic_load_explicit(&callback_body_end, memory_order_acquire);
                    if (entered > 1 || ended > 1 || handoffs > 1) { first(&failure, @"duplicate-completion"); break; }
                    if (handoffs != 1 || ended != 1) continue;
                    if (callback_error || !original_app) { first(&failure, @"launch-completion"); break; }
                    gate_live = @"unobserved";
                    terminated_at_work = truth(original_app.terminated);
                    if (original_app.terminated) { first(&failure, @"original-terminated"); break; }
                    finished = truth(original_app.finishedLaunching);
                    active = truth(original_app.active);
                    bundle = identity(original_app.bundleURL.path, ENTRY_APP, PAYLOAD_APP);
                    identifier = identity(original_app.bundleIdentifier, ENTRY_ID, PAYLOAD_ID);
                    executable = identity(original_app.executableURL.path,
                        @MRK_ENTRY_EXECUTABLE, @MRK_PAYLOAD_EXECUTABLE);
                    NSString *observed = probe(&book);
                    if (!work_before(work_end)) break;
                    if (original_app.terminated) { terminated_at_work = @YES; first(&failure, @"original-terminated"); break; }
                    gate_live = observed;
                    if (![gate_live isEqualToString:@"busy"] || !allowed(bundle)
                        || !allowed(identifier) || !allowed(executable)) {
                        first(&failure, @"launch-completion"); break;
                    }
                    /* Fixed NSRunningApplication properties may remain outer
                     * after exec. This is intentionally not a payload gate. */
                    if (finished.boolValue || !before(started + 2000000000ULL)) break;
                }
            }
            if ((work_expired || !requested) && [failure isEqualToString:@"none"])
                first(&failure, clock_unavailable ? @"clock" : @"observation-deadline");
        } @catch (...) { first(&failure, @"native-exception"); }

        @try {
            /* Late handoff is accepted only for original-reference cleanup.
             * Never launch/activate another app or renew the original work. */
            while (requested && !handoffs && before(final_end)) progress();
            if (original_app && !original_app.terminated && before(final_end)) {
                normal_requested = YES;
                normal_returned = truth([original_app terminate]);
            }
            while (original_app && !original_app.terminated && before(grace_end)) progress();
            if (original_app && !original_app.terminated && before(final_end)) {
                force_requested = YES;
                force_returned = truth([original_app forceTerminate]);
            }
            while (original_app && !original_app.terminated && before(final_end)) progress();
            terminated = original_app != nil && original_app.terminated;
            if (terminated && before(final_end)) {
                gate_after = probe(&book);
                if (![gate_after isEqualToString:@"free"]) first(&failure, @"gate-postprobe");
            }
            if (requested && !terminated) first(&failure, @"termination-unobserved");
        } @catch (...) { first(&failure, @"cleanup-exception"); }
        /* Admission failure never prevents finite, consuming original closes. */
        (void)close_gate(&book);
        ancestors_closed = mrk_entry_close_ancestors(&book) != 0;
        if (!ancestors_closed || !probes_closed) first(&failure, @"descriptor-close");
        unsigned entered = atomic_load_explicit(&callback_entered, memory_order_acquire);
        unsigned ended = atomic_load_explicit(&callback_body_end, memory_order_acquire);
        if (entered > 1 || ended > 1 || handoffs > 1) first(&failure, @"duplicate-completion");
        if (clock_unavailable) first(&failure, @"clock");
        timely = final_end != 0 && before(final_end);
        if (!timely) first(&failure, @"final-deadline");
        BOOL complete = [failure isEqualToString:@"none"] && !work_expired && !clock_unavailable && timely
            && requested && original_app && !callback_error && entered == 1 && ended == 1 && handoffs == 1
            && terminated_at_work && !terminated_at_work.boolValue && finished != nil
            && allowed(bundle) && allowed(identifier) && allowed(executable)
            && [gate_before isEqualToString:@"free"] && [gate_live isEqualToString:@"busy"]
            && terminated && [gate_after isEqualToString:@"free"] && ancestors_closed && probes_closed;
        NSDictionary *report = @{
            @"schemaVersion": @1, @"scope": @"ordinary-installed-entry-launch-diagnostic-v1",
            @"diagnosticSource": @MRK_DIAGNOSTIC_SOURCE, @"applicationSource": @MRK_APPLICATION_SOURCE,
            @"launchRequested": truth(requested), @"launchReferenceReturned": truth(original_app != nil),
            @"launchErrorReported": truth(callback_error), @"workDeadlineFailed": truth(work_expired),
            @"clockUnavailable": truth(clock_unavailable), @"normalTerminateRequested": truth(normal_requested),
            @"forceTerminateRequested": truth(force_requested), @"terminationObserved": truth(terminated),
            @"ancestorCloseReturned": truth(ancestors_closed), @"probeClosesReturned": truth(probes_closed),
            @"finalDeadlineMet": truth(timely), @"referenceTerminatedAtObservation": terminated_at_work ?: NSNull.null,
            @"referenceFinishedLaunching": finished ?: NSNull.null, @"referenceActive": active ?: NSNull.null,
            @"normalTerminateReturned": normal_returned ?: NSNull.null, @"forceTerminateReturned": force_returned ?: NSNull.null,
            @"completionCount": @(entered), @"completionBodyDoneCount": @(ended), @"completionHandoffCount": @(handoffs),
            @"referenceBundle": bundle, @"referenceBundleIdentifier": identifier, @"referenceExecutable": executable,
            @"gateBefore": gate_before, @"gateWhileOriginalLive": gate_live, @"gateAfterTermination": gate_after,
            @"launchErrorDomain": error_domain, @"launchErrorCode": error_code ?: NSNull.null,
            @"originalAppExitStatus": NSNull.null, @"allWorkerFinality": @"not-established",
            @"normalQuitQualified": @NO, @"fullUIQualified": @NO, @"fullM2Qualified": @NO, @"productReady": @NO,
            @"firstFailure": failure, @"observationComplete": truth(complete)
        };
        NSError *error = nil;
        NSData *body = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingSortedKeys error:&error];
        if (!body || error || body.length > 8192) return 70;
        NSMutableData *line = [[@"MRK_INSTALLED_ENTRY_DIAGNOSTIC=" dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
        [line appendData:body]; [line appendBytes:"\n" length:1];
        const unsigned char *bytes = line.bytes; size_t offset = 0;
        while (offset < line.length) {
            if (!before(final_end)) return 71;
            ssize_t count = write(STDOUT_FILENO, bytes + offset, line.length - offset);
            if (count <= 0) return 71;
            offset += (size_t)count;
        }
        /* The actual original return status, not an earlier JSON boolean,
         * establishes whether publication completed inside the final budget. */
        return complete && before(final_end) ? 0 : 1;
    }
}
