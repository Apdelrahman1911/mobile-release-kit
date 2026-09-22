#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#include <Block.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <sys/attr.h>
#include <sys/vnode.h>
#include <sys/utsname.h>
#include <sys/sysctl.h>
#include <sys/xattr.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

int mrk_platform(void) {
    struct utsname u; char version[64] = {0}; size_t length = sizeof(version);
    if (uname(&u) || strcmp(u.sysname, "Darwin") || strcmp(u.machine, "arm64")) return ENOTSUP;
    if (sysctlbyname("kern.osproductversion", version, &length, NULL, 0) || length == 0 || length >= sizeof(version)
        || strncmp(version, "26.", 3)) return ENOTSUP;
    return 0;
}
int mrk_user(uint32_t *uid) {
    if (!uid || getuid() == 0 || getuid() != geteuid() || getgid() != getegid() || issetugid()) return EPERM;
    int platform = mrk_platform(); if (platform) return platform;
    *uid = getuid(); return 0;
}
// Closed first-party diagnostic ABI, shared with Rust and the fixed probe.
// 1 allocation; 2 snapshot; 3/4/5 owner/group/mode completeness; 6 presence;
// 7 conversion; 8 object; 9 validation; 10 first entry; 11 ACE; 12 free.
// Values are saved observations, not accepted-error or ownership capabilities.
static int mrk_acl_failure(int at, int returned, int observed_errno,
                           int *phase, int *call_result, int *native_errno) {
    *phase = at; *call_result = returned; *native_errno = observed_errno;
    return observed_errno ? observed_errno : EIO;
}
int mrk_acl_empty(int fd, int *phase, int *call_result, int *native_errno,
                  int *free_result, int *free_errno) {
    if (!phase || !call_result || !native_errno || !free_result || !free_errno) return EINVAL;
    *phase = *call_result = *native_errno = *free_result = *free_errno = 0;
    errno = 0;
    filesec_t fsec = filesec_init();
    if (!fsec) return mrk_acl_failure(1, 0, errno, phase, call_result, native_errno);
    acl_t acl = NULL; int owned_acl = 0, saved = 0, rc = 0, observed_errno = 0;
    struct stat snapshot = {0}; uid_t owner = 0; gid_t group = 0; mode_t mode = 0; int present = 0;
    // acl_get_fd_np collapses a genuinely absent ACL to NULL/ENOENT. Observe
    // successful same-FD snapshot + explicit presence instead, never errno alone.
    errno = 0; rc = fstatx_np(fd, &snapshot, fsec); observed_errno = errno;
    if (rc != 0) { saved = mrk_acl_failure(2, rc, observed_errno, phase, call_result, native_errno); goto done; }
    // A fresh but unpopulated filesec is not proof of absence, including after
    // libc allocation/early-out paths. All three ordinary properties must exist.
    errno = 0; rc = filesec_get_property(fsec, FILESEC_OWNER, &owner); observed_errno = errno;
    if (rc != 0 || owner != snapshot.st_uid) { saved = mrk_acl_failure(3, rc, rc ? observed_errno : 0, phase, call_result, native_errno); goto done; }
    errno = 0; rc = filesec_get_property(fsec, FILESEC_GROUP, &group); observed_errno = errno;
    if (rc != 0 || group != snapshot.st_gid) { saved = mrk_acl_failure(4, rc, rc ? observed_errno : 0, phase, call_result, native_errno); goto done; }
    errno = 0; rc = filesec_get_property(fsec, FILESEC_MODE, &mode); observed_errno = errno;
    if (rc != 0 || mode != snapshot.st_mode) { saved = mrk_acl_failure(5, rc, rc ? observed_errno : 0, phase, call_result, native_errno); goto done; }
    errno = 0; rc = filesec_query_property(fsec, FILESEC_ACL, &present); observed_errno = errno;
    if (rc != 0) { saved = mrk_acl_failure(6, rc, observed_errno, phase, call_result, native_errno); goto done; }
    if (!present) goto done; // Successful, complete snapshot: there is no ACL.
    // Presence is a zero/nonzero flag, not necessarily the integer1 on Darwin.
    errno = 0; rc = filesec_get_property(fsec, FILESEC_ACL, &acl); observed_errno = errno;
    if (rc != 0) { saved = mrk_acl_failure(7, rc, observed_errno, phase, call_result, native_errno); goto done; }
    if (!acl || (void *)acl == _FILESEC_REMOVE_ACL || (void *)acl == _FILESEC_UNSET_PROPERTY) {
        saved = mrk_acl_failure(8, 0, 0, phase, call_result, native_errno); goto done;
    }
    owned_acl = 1;
    errno = 0; rc = acl_valid(acl); observed_errno = errno;
    if (rc != 0) { saved = mrk_acl_failure(9, rc, observed_errno, phase, call_result, native_errno); goto done; }
    acl_entry_t entry;
    errno = 0; rc = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry); observed_errno = errno;
    // Darwin success0 means an ACE exists. Only -1/EINVAL on a valid ACL is
    // an empty first entry. Principal, rights and inheritance never allow an ACE.
    if (rc == 0) { *phase = 11; *call_result = 0; *native_errno = 0; saved = EPERM; }
    else if (!(rc == -1 && observed_errno == EINVAL)) {
        saved = mrk_acl_failure(10, rc, observed_errno, phase, call_result, native_errno);
    }
done:
    if (owned_acl) {
        errno = 0; rc = acl_free(acl); observed_errno = errno;
        if (rc != 0) {
            *free_result = rc; *free_errno = observed_errno;
            if (!saved) (void)mrk_acl_failure(12, rc, observed_errno, phase, call_result, native_errno);
            saved = observed_errno ? observed_errno : EIO; // Free failure vetoes even an otherwise empty ACL.
        }
    }
    filesec_free(fsec); // Exactly once; void API must actually return. No FD ownership transfer.
    return saved;
}
int mrk_no_xattrs(int fd) {
    ssize_t count = flistxattr(fd, NULL, 0, 0);
    return count < 0 ? (errno ? errno : EIO) : count == 0 ? 0 : EPERM;
}
// Public bulk attributes are four-byte packed, NOT a padded C struct.
// The same pure decoder is exercised by the native crate's cfg(test) FFI.
#define MRK_DIRECTORY_ATTRS (ATTR_CMN_NAME | ATTR_CMN_OBJTYPE | ATTR_CMN_FILEID | ATTR_CMN_RETURNED_ATTRS)
_Static_assert(sizeof(attribute_set_t) == 20 && sizeof(attrreference_t) == 8
               && sizeof(fsobj_type_t) == 4 && sizeof(uint64_t) == 8,
               "fixed public Darwin bulk-attribute field widths required");
int mrk_decode_directory_entries(const uint8_t *block, size_t bytes, int count,
                                 uint8_t *out, size_t capacity, size_t *used) {
    if (!used) return EINVAL;
    *used = 0;
    const size_t name_field = sizeof(uint32_t) + sizeof(attribute_set_t);
    const size_t type_field = name_field + sizeof(attrreference_t);
    const size_t inode_field = type_field + sizeof(fsobj_type_t);
    const size_t fixed = inode_field + sizeof(uint64_t);
    if (!block || !out || bytes > 65536 || capacity > 65536 || count < 0
        || (size_t)count > bytes / fixed) return EINVAL;
    size_t offset = 0, written = 0;
    for (int n = 0; n < count; ++n) {
        if (bytes - offset < sizeof(uint32_t)) return EIO;
        uint32_t length; memcpy(&length, block + offset, sizeof(length));
        if (length < fixed + 2 || length % 4 || length > bytes - offset) return EIO;
        const uint8_t *entry = block + offset;
        attribute_set_t actual; memcpy(&actual, entry + sizeof(uint32_t), sizeof(actual));
        if (actual.commonattr != MRK_DIRECTORY_ATTRS || actual.volattr || actual.dirattr
            || actual.fileattr || actual.forkattr) return EIO;
        attrreference_t name; fsobj_type_t kind; uint64_t inode;
        memcpy(&name, entry + name_field, sizeof(name));
        memcpy(&kind, entry + type_field, sizeof(kind));
        memcpy(&inode, entry + inode_field, sizeof(inode));
        if (name.attr_dataoffset < (int32_t)(fixed - name_field)
            || (uint32_t)name.attr_dataoffset > length - name_field
            || name.attr_length < 2 || name.attr_length > 256 || !inode
            || (kind != VREG && kind != VDIR)) return EIO;
        // attr_dataoffset is relative to the name reference itself.
        size_t name_at = name_field + (uint32_t)name.attr_dataoffset;
        if (name.attr_length > length - name_at) return EIO;
        uint16_t name_length = (uint16_t)(name.attr_length - 1);
        const uint8_t *text = entry + name_at;
        if (text[name_length] || memchr(text, 0, name_length) || memchr(text, '/', name_length)) return EIO;
        if (capacity - written < 11 || name_length > capacity - written - 11) return EOVERFLOW;
        memcpy(out + written, &inode, sizeof(inode));
        out[written + 8] = kind == VDIR ? DT_DIR : DT_REG;
        memcpy(out + written + 9, &name_length, sizeof(name_length));
        memcpy(out + written + 11, text, name_length);
        written += 11 + name_length;
        offset += length;
    }
    // Unused native-buffer tail is not a record. Never publish partial success.
    *used = written;
    return 0;
}
int mrk_entries(int fd, uint8_t *out, size_t capacity, size_t *used) {
    uint8_t block[65536] = {0};
    if (!out || !used || capacity != sizeof(block)) return EINVAL;
    *used = 0;
    struct attrlist request = { .bitmapcount = ATTR_BIT_MAP_COUNT,
                               .commonattr = MRK_DIRECTORY_ATTRS };
    // Same original borrowed FD/cursor. No dup, DIR allocation, reopen,
    // private inode symbol, ABI override, retry, rewind or extra close owner.
    int count = getattrlistbulk(fd, &request, block, sizeof(block), 0);
    if (count < 0) return errno ? errno : EIO;
    return mrk_decode_directory_entries(block, sizeof(block), count, out, capacity, used);
}
int mrk_sync(int fd, int file) {
    if (fsync(fd)) return errno ? errno : EIO;
    if (file && fcntl(fd, F_FULLFSYNC)) return errno ? errno : EIO;
    return 0;
}
int mrk_publish(int from, const char *source, int to, const char *destination) {
    if (renameatx_np(from, source, to, destination, RENAME_EXCL)) return errno ? errno : EIO;
    return 0;
}
int mrk_main_thread(void) { return pthread_main_np(); }

// Closed ABI result: Other=0, Accept=1, Decline=2. This same pure mapping is
// exercised by narrow native-crate test definitions; no panel is fabricated.
int mrk_panel_response(int kind, int64_t code, int programmatic) {
    if (programmatic) return 0;
    if (kind == 1) {
        if (code == NSModalResponseOK) return 1;
        if (code == NSModalResponseCancel) return 2;
    } else if (kind == 2) {
        if (code == NSAlertSecondButtonReturn) return 1;
        if (code == NSAlertFirstButtonReturn) return 2;
    }
    return 0; // Stop/Abort/unknown are never evidence of genuine user Cancel.
}

@interface MRKInstalledPanel : NSObject {
@public
    NSWindow *parent;
    NSWindow *window;
    NSAlert *alert;
    void (^completion)(NSModalResponse);
    BOOL attempted, started, responded, reported, callbackActive, closeAttempted, closed, unknown;
    int kind, response;
    char selected[4097];
#ifdef MRK_INSTALLED_OBSERVATION
    // Instrumentation only; never callback/cleanup/selection authority.
    BOOL observationDirectoryReturned, observationActionAttempted, observationActionReturned;
    char observationDirectory[4097];
#endif
}
@end
@implementation MRKInstalledPanel
@end

void *mrk_panel_reserve(void) {
    if (!pthread_main_np()) return NULL;
    @try { return [[MRKInstalledPanel alloc] init]; } @catch (NSException *e) { (void)e; return NULL; }
}
int mrk_panel_start(void *opaque, int kind) {
    if (!pthread_main_np() || !opaque || (kind != 1 && kind != 2)) return EINVAL;
    MRKInstalledPanel *s = opaque;
    if (s->attempted || s->unknown) return EALREADY;
    s->attempted = YES; s->kind = kind;
    @try {
        // This application has exactly one normal window; never attach to a
        // picker, another sheet or a renderer-supplied object/path.
        NSWindow *main = [NSApp mainWindow];
        if (!main || [main isKindOfClass:[NSPanel class]] || [main attachedSheet]) return EPERM;
        s->started = YES;
        s->parent = [main retain];
        if (kind == 1) {
            NSOpenPanel *panel = [NSOpenPanel openPanel]; s->window = [panel retain];
            [panel setTitle:@"Choose a mobile project folder"];
            [panel setCanChooseFiles:NO]; [panel setCanChooseDirectories:YES];
            [panel setAllowsMultipleSelection:NO]; [panel setCanCreateDirectories:NO];
            [panel setResolvesAliases:NO]; [panel setTreatsFilePackagesAsDirectories:NO];
        } else {
            s->alert = [[NSAlert alloc] init];
            [s->alert setMessageText:@"Quit and discard unsaved drafts?"];
            [s->alert setInformativeText:@"Cancel keeps working. Quit stops owned operations and waits for their original cleanup. A Save already accepted may still commit; quitting does not undo committed files."];
            [s->alert setAlertStyle:NSAlertStyleWarning];
            [[s->alert addButtonWithTitle:@"Cancel"] setKeyEquivalent:@"\r"];
            [[s->alert addButtonWithTitle:@"Quit"] setKeyEquivalent:@""];
            s->window = [[s->alert window] retain];
        }
        [s->window setReleasedWhenClosed:NO];
        // The original state is retained by the copied native completion. No
        // raw Rust callback or path publication can outlive the real document.
        s->completion = Block_copy(^(NSModalResponse code) {
            s->callbackActive = YES;
            @try {
                if (s->responded) { s->unknown = YES; }
                else {
                    // closeAttempted was recorded BEFORE any programmatic
                    // endSheet/close. Its Cancel-shaped callback remains Other.
                    s->response = mrk_panel_response(kind, code, s->closeAttempted);
                    if (s->response == 1 && kind == 1) {
                        NSURL *url = [(NSOpenPanel *)s->window URL];
                        const char *path = url && [url isFileURL] ? [url fileSystemRepresentation] : NULL;
                        if (!path || path[0] != '/' || strnlen(path, sizeof(s->selected)) >= sizeof(s->selected)) s->unknown = YES;
                        else memcpy(s->selected, path, strlen(path) + 1);
                    }
                    s->responded = YES;
                }
            } @catch (NSException *e) { (void)e; s->unknown = YES; }
            // No native call/run-loop pumping after this final completion fact.
            s->callbackActive = NO;
        });
        if (kind == 1) [(NSOpenPanel *)s->window beginSheetModalForWindow:s->parent completionHandler:s->completion];
        else [s->alert beginSheetModalForWindow:s->parent completionHandler:s->completion];
        return 0;
    } @catch (NSException *e) { (void)e; s->unknown = YES; return EIO; }
}
int mrk_panel_poll(void *opaque, int *result, uint8_t *path, size_t capacity) {
    if (!pthread_main_np() || !opaque || !result || !path || capacity != 4097) return -1;
    MRKInstalledPanel *s = opaque;
    if (s->unknown) return -1;
    @try {
        // Main-loop serialization observes the actual completion return, not
        // just a flag sampled concurrently with an executing callback.
        if (s->closed) return 2;
        if (s->responded && !s->reported && !s->callbackActive) {
            s->reported = YES; *result = s->response;
            memcpy(path, s->selected, sizeof(s->selected)); return 1;
        }
        if (s->closeAttempted && s->responded && !s->callbackActive && ![s->window isVisible] && ![s->window sheetParent]) {
            s->closed = YES; return 2;
        }
        if (s->responded && !s->callbackActive) {
            *result = s->response; memcpy(path, s->selected, sizeof(s->selected)); return 1;
        }
        return 0;
    } @catch (NSException *e) { (void)e; s->unknown = YES; return -1; }
}
int mrk_panel_close(void *opaque) {
    if (!pthread_main_np() || !opaque) return EINVAL;
    MRKInstalledPanel *s = opaque;
    if (s->closeAttempted) return EALREADY;
    s->closeAttempted = YES;
    @try {
        if (!s->started && !s->window && !s->parent && !s->alert && !s->completion) { s->closed = YES; return 0; }
        if (!s->responded && s->window && [s->window sheetParent]) [s->parent endSheet:s->window returnCode:NSModalResponseCancel];
        if (s->window) { [s->window orderOut:nil]; [s->window close]; }
        return s->unknown ? EIO : 0;
    } @catch (NSException *e) { (void)e; s->unknown = YES; return EIO; }
}
int mrk_panel_release(void *opaque) {
    if (!pthread_main_np() || !opaque) return EINVAL;
    MRKInstalledPanel *s = opaque;
    if (s->unknown || s->callbackActive || !s->closed) return EBUSY;
    @try {
        // Only original references, after original close/completion returned.
        // Unknown retains the object; there is no replacement or Drop fallback.
        if (s->completion) { Block_release(s->completion); s->completion = NULL; }
        [s->window release]; s->window = nil; [s->alert release]; s->alert = nil;
        [s->parent release]; s->parent = nil; [s release]; return 0;
    } @catch (NSException *e) { (void)e; return EIO; }
}

#ifdef MRK_INSTALLED_OBSERVATION
// No separate window lookup: sample only the retained originals. Presence
// bits distinguish an unqueried relationship from a measured false result.
enum { MRK_PARENT_PRESENT = 1u << 12, MRK_PANEL_PRESENT = 1u << 13,
    MRK_PARENT_REFERENCES_PANEL = 1u << 14, MRK_PANEL_REFERENCES_PARENT = 1u << 15,
    MRK_PANEL_VISIBLE = 1u << 16, MRK_ATTACHMENT_ALL = 0x1f000u };
static uint32_t mrk_observation_attachment(MRKInstalledPanel *s) {
    uint32_t sample = (s->parent ? MRK_PARENT_PRESENT : 0u) | (s->window ? MRK_PANEL_PRESENT : 0u);
    if (s->parent && s->window) {
        if ([s->parent attachedSheet] == s->window) sample |= MRK_PARENT_REFERENCES_PANEL;
        if ([s->window sheetParent] == s->parent) sample |= MRK_PANEL_REFERENCES_PARENT;
    }
    if (s->window && [s->window isVisible]) sample |= MRK_PANEL_VISIBLE;
    return sample;
}
static BOOL mrk_observation_attached(MRKInstalledPanel *s) {
    return mrk_observation_attachment(s) == MRK_ATTACHMENT_ALL;
}
static BOOL mrk_observation_directory_ready(MRKInstalledPanel *s) {
    if (s->kind != 1 || !s->window || !s->observationDirectoryReturned || !s->observationDirectory[0]) return NO;
    NSURL *url = [(NSOpenPanel *)s->window directoryURL];
    const char *path = url && [url isFileURL] ? [url fileSystemRepresentation] : NULL;
    return path && strnlen(path, sizeof(s->observationDirectory)) < sizeof(s->observationDirectory)
        && strcmp(path, s->observationDirectory) == 0;
}
int mrk_panel_observe(void *opaque, int *kind, uint32_t *flags, int *response, uint8_t *path, size_t capacity) {
    if (!pthread_main_np() || !opaque || !kind || !flags || !response || !path || capacity != 4097) return EINVAL;
    MRKInstalledPanel *s = opaque;
    if (s->unknown) return EIO;
    @try {
        // Closed seventeen-bit ABI with the Rust PanelObservation decoder. Reads
        // do not set reported, manufacture completion, or authorize retirement.
        uint32_t attachment = mrk_observation_attachment(s);
        *kind = s->kind; *response = s->response;
        *flags = attachment | (s->started ? 1u : 0u) | (attachment == MRK_ATTACHMENT_ALL ? 2u : 0u)
            | (s->observationDirectory[0] ? 4u : 0u) | (s->observationDirectoryReturned ? 8u : 0u)
            | (mrk_observation_directory_ready(s) ? 16u : 0u) | (s->observationActionAttempted ? 32u : 0u)
            | (s->observationActionReturned ? 64u : 0u) | (s->responded ? 128u : 0u)
            | (s->responded && !s->callbackActive ? 256u : 0u) | (s->closeAttempted ? 512u : 0u)
            | (s->window && ![s->window isVisible] && ![s->window sheetParent] ? 1024u : 0u)
            | (s->closed ? 2048u : 0u);
        memcpy(path, s->selected, sizeof(s->selected)); return 0;
    } @catch (NSException *e) { (void)e; s->unknown = YES; return EIO; }
}
int mrk_panel_observe_action(void *opaque, int action, const char *directory) {
    if (!pthread_main_np() || !opaque || action < 1 || action > 5 || ((action == 2) != (directory != NULL))) return EINVAL;
    MRKInstalledPanel *s = opaque;
    if (s->unknown) return EIO;
    if (!s->started || !s->window || !s->parent || !s->completion || s->responded || s->callbackActive
        || s->closeAttempted || s->closed || s->observationActionAttempted) return EPERM;
    if ((action <= 3 && s->kind != 1) || (action >= 4 && s->kind != 2)) return EPERM;
    @try {
        // EAGAIN is only pre-action readiness, never permission to repeat an
        // attempted action. The caller's original endpoint is not renewed.
        if (!mrk_observation_attached(s)) return EAGAIN;
        if (action == 2) {
            if (s->observationDirectory[0]) return EPERM;
            size_t length = strnlen(directory, sizeof(s->observationDirectory));
            if (length == 0 || length >= sizeof(s->observationDirectory) || directory[0] != '/') return EINVAL;
            NSString *text = [NSString stringWithUTF8String:directory];
            NSURL *url = text ? [NSURL fileURLWithPath:text isDirectory:YES] : nil;
            if (!url) return EINVAL;
            memcpy(s->observationDirectory, directory, length + 1);
            [(NSOpenPanel *)s->window setDirectoryURL:url];
            s->observationDirectoryReturned = YES; return 0;
        }
        if (action == 3) {
            if (!s->observationDirectory[0] || !s->observationDirectoryReturned) return EPERM;
            if (!mrk_observation_directory_ready(s)) return EAGAIN;
        }
        NSButton *button = nil;
        if (action >= 4) {
            NSArray<NSButton *> *buttons = [s->alert buttons];
            if (!s->alert || [buttons count] != 2) return EPERM;
            button = [buttons objectAtIndex:action == 4 ? 0 : 1];
            if ([button window] != s->window) return EPERM;
            if (![button isEnabled] || [button isHidden]) return EAGAIN;
        }
        s->observationActionAttempted = YES;
        if (action == 1) [(NSOpenPanel *)s->window cancel:nil];
        else if (action == 3) [(NSOpenPanel *)s->window ok:nil];
        else [button performClick:nil];
        s->observationActionReturned = YES;
        // No call of s->completion, endSheet:, close_once or selected-path
        // mutation. Only AppKit's original completion supplies the outcome.
        return 0;
    } @catch (NSException *e) { (void)e; s->unknown = YES; return EIO; }
}
#endif
