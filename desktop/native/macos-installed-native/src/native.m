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
#ifdef MRK_INSTALLED_OBSERVATION
#import <ApplicationServices/ApplicationServices.h>
#include <math.h>
#endif

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

#ifdef MRK_INSTALLED_OBSERVATION
// Saved scalar DATA only. Zero means unobserved, not a nil getter result.
typedef struct {
    uint32_t flags, configuration_parent, configuration_panel, binding_parent, binding_panel, phase, site, error;
} MRKIdentityWire;
enum { MRK_ID_ARMED = 1u, MRK_ID_CONFIG_ATTEMPTED = 2u, MRK_ID_PARENT_ENTERED = 4u,
    MRK_ID_PARENT_RETURNED = 8u, MRK_ID_PANEL_ENTERED = 16u, MRK_ID_PANEL_RETURNED = 32u,
    MRK_ID_BINDING_ATTEMPTED = 64u, MRK_ID_CONFIG_COMPLETE = 128u };
enum { MRK_ID_CONFIGURATION = 1u, MRK_ID_BINDING = 2u };
enum { MRK_ID_OBJECTS = 1u, MRK_ID_TAGS, MRK_ID_PARENT_SET, MRK_ID_PANEL_SET,
    MRK_ID_PARENT_GET, MRK_ID_PANEL_GET, MRK_ID_COMPLETE };
enum { MRK_ID_UNOBSERVED, MRK_ID_NIL, MRK_ID_MATCH, MRK_ID_DIFFERENT, MRK_ID_TYPE_INVALID };
#endif

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
    BOOL observationIdentityAttempted;
    char observationDirectory[4097];
    char observationParentTag[64], observationPanelTag[64];
    MRKIdentityWire observationIdentity;
#endif
}
@end
@implementation MRKInstalledPanel
@end
#ifdef MRK_INSTALLED_OBSERVATION
static BOOL mrk_panel_configure_open_identity(MRKInstalledPanel *s);
#endif

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
#ifdef MRK_INSTALLED_OBSERVATION
        if ((s->observationIdentity.flags & MRK_ID_ARMED) && !mrk_panel_configure_open_identity(s)) {
            // Objects already exist. This is never the pre-construction EPERM.
            s->unknown = YES; return EIO;
        }
#endif
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
// Closed DATA from this one original return. No exception object, subsequent
// query, native status replacement, or permission is carried by these sites.
enum {
    MRK_ACTION_THREAD = 1, MRK_ACTION_POINTER, MRK_ACTION_CODE, MRK_ACTION_ARGUMENT,
    MRK_ACTION_UNKNOWN, MRK_ACTION_STARTED, MRK_ACTION_WINDOW, MRK_ACTION_PARENT,
    MRK_ACTION_COMPLETION, MRK_ACTION_RESPONDED, MRK_ACTION_CALLBACK,
    MRK_ACTION_CLOSE_ATTEMPTED, MRK_ACTION_CLOSED, MRK_ACTION_ATTEMPTED, MRK_ACTION_KIND,
    MRK_ACTION_ATTACHMENT, MRK_ACTION_DIRECTORY_BOUND, MRK_ACTION_DIRECTORY_PATH,
    MRK_ACTION_DIRECTORY_TEXT, MRK_ACTION_DIRECTORY_URL, MRK_ACTION_DIRECTORY_SET,
    MRK_ACTION_DIRECTORY_UNBOUND, MRK_ACTION_DIRECTORY_RETURNED, MRK_ACTION_DIRECTORY_READY,
    MRK_ACTION_ALERT_BUTTONS, MRK_ACTION_ALERT, MRK_ACTION_BUTTON_COUNT, MRK_ACTION_BUTTON_INDEX,
    MRK_ACTION_BUTTON_WINDOW, MRK_ACTION_BUTTON_ENABLED, MRK_ACTION_BUTTON_HIDDEN,
    MRK_ACTION_PROJECT_CANCEL, MRK_ACTION_PROJECT_OPEN, MRK_ACTION_QUIT_CANCEL, MRK_ACTION_QUIT_CONFIRM
};
_Static_assert(EPERM == 1 && EIO == 5 && EINVAL == 22 && EAGAIN == 35 && EALREADY == 37, "Darwin action diagnostic errno ABI");
static int mrk_observation_action_return(uint32_t *diagnostic, uint32_t domain, uint32_t site, int status) {
    if (diagnostic) *diagnostic = (domain << 16) | site;
    return status; // The original status, not a diagnostic classification.
}
int mrk_panel_observe_action(void *opaque, int action, const char *directory, uint32_t *diagnostic) {
    if (diagnostic) *diagnostic = 0;
    volatile uint32_t site = MRK_ACTION_THREAD;
#define MRK_ACTION_RETURN(status) return mrk_observation_action_return(diagnostic, 1u, site, (status))
    // Split only the existing short-circuit predicates, in their original order.
    if (!pthread_main_np()) MRK_ACTION_RETURN(EINVAL);
    site = MRK_ACTION_POINTER; if (!opaque) MRK_ACTION_RETURN(EINVAL);
    site = MRK_ACTION_CODE; if (action < 1 || action > 5 || action == 3) MRK_ACTION_RETURN(EINVAL);
    site = MRK_ACTION_ARGUMENT; if ((action == 2) != (directory != NULL)) MRK_ACTION_RETURN(EINVAL);
    MRKInstalledPanel *s = opaque;
    site = MRK_ACTION_UNKNOWN; if (s->unknown) MRK_ACTION_RETURN(EIO);
    site = MRK_ACTION_STARTED; if (!s->started) MRK_ACTION_RETURN(EPERM);
    site = MRK_ACTION_WINDOW; if (!s->window) MRK_ACTION_RETURN(EPERM);
    site = MRK_ACTION_PARENT; if (!s->parent) MRK_ACTION_RETURN(EPERM);
    site = MRK_ACTION_COMPLETION; if (!s->completion) MRK_ACTION_RETURN(EPERM);
    site = MRK_ACTION_RESPONDED; if (s->responded) MRK_ACTION_RETURN(EPERM);
    site = MRK_ACTION_CALLBACK; if (s->callbackActive) MRK_ACTION_RETURN(EPERM);
    site = MRK_ACTION_CLOSE_ATTEMPTED; if (s->closeAttempted) MRK_ACTION_RETURN(EPERM);
    site = MRK_ACTION_CLOSED; if (s->closed) MRK_ACTION_RETURN(EPERM);
    site = MRK_ACTION_ATTEMPTED; if (s->observationActionAttempted) MRK_ACTION_RETURN(EPERM);
    site = MRK_ACTION_KIND;
    if ((action <= 3 && s->kind != 1) || (action >= 4 && s->kind != 2)) MRK_ACTION_RETURN(EPERM);
    @try {
        // EAGAIN is only pre-action readiness, never permission to repeat an
        // attempted action. The caller's original endpoint is not renewed.
        site = MRK_ACTION_ATTACHMENT; if (!mrk_observation_attached(s)) MRK_ACTION_RETURN(EAGAIN);
        if (action == 2) {
            site = MRK_ACTION_DIRECTORY_BOUND; if (s->observationDirectory[0]) MRK_ACTION_RETURN(EPERM);
            site = MRK_ACTION_DIRECTORY_PATH;
            size_t length = strnlen(directory, sizeof(s->observationDirectory));
            if (length == 0 || length >= sizeof(s->observationDirectory) || directory[0] != '/') MRK_ACTION_RETURN(EINVAL);
            site = MRK_ACTION_DIRECTORY_TEXT;
            NSString *text = [NSString stringWithUTF8String:directory];
            NSURL *url = nil;
            if (text) { site = MRK_ACTION_DIRECTORY_URL; url = [NSURL fileURLWithPath:text isDirectory:YES]; }
            if (!url) MRK_ACTION_RETURN(EINVAL);
            memcpy(s->observationDirectory, directory, length + 1);
            site = MRK_ACTION_DIRECTORY_SET;
            [(NSOpenPanel *)s->window setDirectoryURL:url];
            s->observationDirectoryReturned = YES; MRK_ACTION_RETURN(0);
        }
        NSButton *button = nil;
        if (action >= 4) {
            site = MRK_ACTION_ALERT_BUTTONS;
            NSArray<NSButton *> *buttons = [s->alert buttons];
            site = MRK_ACTION_ALERT; if (!s->alert) MRK_ACTION_RETURN(EPERM);
            site = MRK_ACTION_BUTTON_COUNT; if ([buttons count] != 2) MRK_ACTION_RETURN(EPERM);
            site = MRK_ACTION_BUTTON_INDEX;
            button = [buttons objectAtIndex:action == 4 ? 0 : 1];
            site = MRK_ACTION_BUTTON_WINDOW; if ([button window] != s->window) MRK_ACTION_RETURN(EPERM);
            site = MRK_ACTION_BUTTON_ENABLED; if (![button isEnabled]) MRK_ACTION_RETURN(EAGAIN);
            site = MRK_ACTION_BUTTON_HIDDEN; if ([button isHidden]) MRK_ACTION_RETURN(EAGAIN);
        }
        s->observationActionAttempted = YES;
        if (action == 1) { site = MRK_ACTION_PROJECT_CANCEL; [(NSOpenPanel *)s->window cancel:nil]; }
        else { site = action == 4 ? MRK_ACTION_QUIT_CANCEL : MRK_ACTION_QUIT_CONFIRM; [button performClick:nil]; }
        s->observationActionReturned = YES;
        // No call of s->completion, endSheet:, close_once or selected-path
        // mutation. Only AppKit's original completion supplies the outcome.
        MRK_ACTION_RETURN(0);
    } @catch (NSException *e) {
        (void)e; s->unknown = YES;
        return mrk_observation_action_return(diagnostic, 2u, site, EIO);
    }
#undef MRK_ACTION_RETURN
}

// Public AX input is a separate, synchronous off-main operation. None of this
// ABI carries an AppKit object, native BOOL, title, path or private identifier.
enum { MRK_AX_NONE, MRK_AX_THREAD, MRK_AX_INPUT, MRK_AX_INELIGIBLE, MRK_AX_UNSUPPORTED,
    MRK_AX_AMBIGUOUS, MRK_AX_MALFORMED, MRK_AX_LIMIT, MRK_AX_DEADLINE, MRK_AX_CUSTODY,
    MRK_AX_INVALID_ELEMENT, MRK_AX_CANNOT_COMPLETE, MRK_AX_OTHER, MRK_AX_CHANGED,
    MRK_AX_EXCEPTION, MRK_AX_CLEANUP_UNKNOWN };
enum { MRK_AX_BINDING = 1, MRK_AX_ENTRY, MRK_AX_APPLICATION, MRK_AX_WINDOWS,
    MRK_AX_PARENT_ID, MRK_AX_CHILDREN, MRK_AX_PANEL_ID, MRK_AX_PANEL_ROLE, MRK_AX_PANEL_PARENT,
    MRK_AX_DEFAULT, MRK_AX_BUTTON_ROLE, MRK_AX_ENABLED, MRK_AX_ANCESTRY, MRK_AX_RECHECK,
    MRK_AX_PRESS, MRK_AX_CLEANUP };
enum { MRK_AX_IDENTITY = 1u, MRK_AX_CONTROL = 2u, MRK_AX_ATTEMPTED = 4u,
    MRK_AX_PRESS_RETURNED = 8u, MRK_AX_CLEANED = 16u, MRK_AX_CALL_LIMIT = 64 };
typedef struct { float seconds; uint64_t required_ns; } MRKAXTimeout;
typedef struct { uint32_t site, error, flags; } MRKAXResult;
typedef int (*MRKAXAdmission)(void *, uint64_t, int, MRKAXTimeout *);

int mrk_observation_ax_trusted(void) {
    if (!pthread_main_np()) return -1;
    CFDictionaryRef options = NULL; int trusted = -1;
    @try {
        const void *keys[] = { kAXTrustedCheckOptionPrompt };
        const void *values[] = { kCFBooleanFalse };
        options = CFDictionaryCreate(NULL, keys, values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        if (options) trusted = AXIsProcessTrustedWithOptions(options) ? 1 : 0;
    } @catch (NSException *e) { (void)e; trusted = -1; }
    @try { if (options) CFRelease(options); }
    @catch (NSException *e) { (void)e; trusted = -1; }
    return trusted; // A false result never prompts, waits, or opens a panel.
}

int mrk_panel_observe_arm_open_identity(void *opaque) {
    if (!pthread_main_np() || !opaque) return EINVAL;
    MRKInstalledPanel *s = opaque;
    if (s->attempted || s->unknown || s->observationIdentity.flags) return EALREADY;
    s->observationIdentity.flags = MRK_ID_ARMED; // Passive: no AppKit message or tag generation.
    return 0;
}
void mrk_panel_observe_identity_data(void *opaque, MRKIdentityWire *data) {
    // Used immediately after an original FFI return, while its retained Panel
    // is still borrowed. No usable()/AppKit query, release or ownership change.
    if (opaque && data) memcpy(data, &((MRKInstalledPanel *)opaque)->observationIdentity, sizeof(*data));
}
static BOOL mrk_identity_tag(const char tag[64], const char *prefix) {
    size_t offset = strlen(prefix), length = offset + 36;
    if (length >= 64 || strnlen(tag, 64) != length || memcmp(tag, prefix, offset)) return NO;
    for (size_t i = 0; i < 36; i++) {
        char c = tag[offset + i];
        if (i == 8 || i == 13 || i == 18 || i == 23) { if (c != '-') return NO; }
        else if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))) return NO;
    }
    for (size_t i = length; i < 64; i++) if (tag[i]) return NO;
    return YES;
}
static uint32_t mrk_identity_class(id value, NSString *tag) {
    if (!value) return MRK_ID_NIL;
    if (![value isKindOfClass:[NSString class]]) return MRK_ID_TYPE_INVALID;
    return [(NSString *)value isEqualToString:tag] ? MRK_ID_MATCH : MRK_ID_DIFFERENT;
}
static BOOL mrk_panel_configure_open_identity(MRKInstalledPanel *s) {
    MRKIdentityWire *d = &s->observationIdentity;
    d->flags |= MRK_ID_CONFIG_ATTEMPTED; d->phase = MRK_ID_CONFIGURATION; d->site = MRK_ID_OBJECTS;
    d->error = MRK_AX_INELIGIBLE;
    if (!s->parent || !s->window || s->kind != 1 || s->unknown || s->responded
        || s->callbackActive || s->closeAttempted || s->closed) return NO;
    @try {
        d->site = MRK_ID_TAGS; d->error = MRK_AX_INPUT;
        NSString *parentTag = [@"mrk-parent-" stringByAppendingString:[[NSUUID UUID] UUIDString]];
        NSString *panelTag = [@"mrk-panel-" stringByAppendingString:[[NSUUID UUID] UUIDString]];
        if (![parentTag getCString:s->observationParentTag maxLength:64 encoding:NSASCIIStringEncoding]
            || ![panelTag getCString:s->observationPanelTag maxLength:64 encoding:NSASCIIStringEncoding]
            || !mrk_identity_tag(s->observationParentTag, "mrk-parent-")
            || !mrk_identity_tag(s->observationPanelTag, "mrk-panel-")) return NO;
        d->site = MRK_ID_PARENT_SET; d->flags |= MRK_ID_PARENT_ENTERED;
        [s->parent setAccessibilityIdentifier:parentTag];
        d->flags |= MRK_ID_PARENT_RETURNED;
        d->site = MRK_ID_PANEL_SET; d->flags |= MRK_ID_PANEL_ENTERED;
        [s->window setAccessibilityIdentifier:panelTag];
        d->flags |= MRK_ID_PANEL_RETURNED;
        d->site = MRK_ID_PARENT_GET;
        d->configuration_parent = mrk_identity_class([s->parent accessibilityIdentifier], parentTag);
        d->site = MRK_ID_PANEL_GET;
        d->configuration_panel = mrk_identity_class([s->window accessibilityIdentifier], panelTag);
        // Early publication timing is not an identity proof or equality veto.
        // Both normal classes are DATA; late exact local AND remote matches
        // remain mandatory before the sole input attempt.
        d->flags |= MRK_ID_CONFIG_COMPLETE; d->site = MRK_ID_COMPLETE; d->error = MRK_AX_NONE;
        return YES;
    } @catch (NSException *e) {
        (void)e; d->error = MRK_AX_EXCEPTION;
        @throw; // The SAME original start catch records unknown/EIO.
    }
}
int mrk_panel_observe_open_identity(void *opaque, uint8_t *parent, uint8_t *panel, size_t capacity) {
    if (!pthread_main_np()) return MRK_AX_THREAD;
    if (!opaque || !parent || !panel || capacity != 64) return MRK_AX_INPUT;
    memset(parent, 0, capacity); memset(panel, 0, capacity);
    MRKInstalledPanel *s = opaque;
    MRKIdentityWire *d = &s->observationIdentity;
    if (d->phase == MRK_ID_BINDING) return MRK_AX_INELIGIBLE; // Never replace the first binding DATA.
    d->phase = MRK_ID_BINDING; d->site = MRK_ID_OBJECTS; d->error = MRK_AX_INELIGIBLE;
    d->binding_parent = d->binding_panel = MRK_ID_UNOBSERVED;
    if (s->unknown || !s->started || s->kind != 1 || !s->parent || !s->window || !s->completion
        || s->responded || s->callbackActive || s->closeAttempted || s->closed
        || s->observationActionAttempted || s->observationActionReturned || s->observationIdentityAttempted
        || (d->flags & (MRK_ID_ARMED | MRK_ID_CONFIG_COMPLETE)) != (MRK_ID_ARMED | MRK_ID_CONFIG_COMPLETE))
        return MRK_AX_INELIGIBLE;
    s->observationIdentityAttempted = YES; d->flags |= MRK_ID_BINDING_ATTEMPTED;
    @try {
        if (!mrk_observation_attached(s) || !mrk_observation_directory_ready(s)) return MRK_AX_INELIGIBLE;
        d->site = MRK_ID_TAGS; d->error = MRK_AX_INPUT;
        if (!mrk_identity_tag(s->observationParentTag, "mrk-parent-")
            || !mrk_identity_tag(s->observationPanelTag, "mrk-panel-")) return MRK_AX_INPUT;
        NSString *parentTag = [NSString stringWithCString:s->observationParentTag encoding:NSASCIIStringEncoding];
        NSString *panelTag = [NSString stringWithCString:s->observationPanelTag encoding:NSASCIIStringEncoding];
        if (!parentTag || !panelTag) return MRK_AX_INPUT;
        d->site = MRK_ID_PARENT_GET;
        d->binding_parent = mrk_identity_class([s->parent accessibilityIdentifier], parentTag);
        d->site = MRK_ID_PANEL_GET;
        d->binding_panel = mrk_identity_class([s->window accessibilityIdentifier], panelTag);
        if (d->binding_parent != MRK_ID_MATCH || d->binding_panel != MRK_ID_MATCH) {
            d->site = d->binding_parent != MRK_ID_MATCH ? MRK_ID_PARENT_GET : MRK_ID_PANEL_GET;
            d->error = MRK_AX_UNSUPPORTED; return MRK_AX_UNSUPPORTED;
        }
        d->site = MRK_ID_OBJECTS; d->error = MRK_AX_INELIGIBLE;
        if (s->responded || s->callbackActive || s->closeAttempted || s->closed
            || !mrk_observation_attached(s) || !mrk_observation_directory_ready(s)) return MRK_AX_INELIGIBLE;
        memcpy(parent, s->observationParentTag, capacity); memcpy(panel, s->observationPanelTag, capacity);
        d->site = MRK_ID_COMPLETE; d->error = MRK_AX_NONE;
        return MRK_AX_NONE; // Preparation is NOT an action attempt or return.
    } @catch (NSException *e) { (void)e; s->unknown = YES; d->error = MRK_AX_EXCEPTION; return MRK_AX_EXCEPTION; }
}

typedef union { CFTypeRef value; CFArrayRef array; } MRKAXOwned;
typedef struct {
    MRKAXAdmission admit; void *context; MRKAXResult result;
    MRKAXOwned owned[80]; size_t count; unsigned calls; BOOL cleanupKnown;
} MRKAX;
static BOOL mrk_ax_fail(MRKAX *s, uint32_t error) {
    if (!s->result.error) s->result.error = error;
    return NO;
}
static BOOL mrk_ax_status(MRKAX *s, AXError error) {
    if (error == kAXErrorSuccess) return YES;
    switch (error) {
        case kAXErrorAttributeUnsupported: case kAXErrorActionUnsupported: case kAXErrorNoValue:
        case kAXErrorNotImplemented: case kAXErrorAPIDisabled: return mrk_ax_fail(s, MRK_AX_UNSUPPORTED);
        case kAXErrorInvalidUIElement: return mrk_ax_fail(s, MRK_AX_INVALID_ELEMENT);
        case kAXErrorIllegalArgument: return mrk_ax_fail(s, MRK_AX_INPUT);
        case kAXErrorCannotComplete: return mrk_ax_fail(s, MRK_AX_CANNOT_COMPLETE);
        default: return mrk_ax_fail(s, MRK_AX_OTHER);
    }
}
static MRKAXOwned *mrk_ax_slot(MRKAX *s) {
    if (s->count == sizeof(s->owned) / sizeof(s->owned[0])) { mrk_ax_fail(s, MRK_AX_LIMIT); return NULL; }
    // Reserve before Create/Copy, including an exception after writing its out
    // parameter. Arrays stay owned until final cleanup; members are borrowed.
    return &s->owned[s->count++];
}
static BOOL mrk_ax_admit(MRKAX *s, uint64_t required_ns, int after_press, MRKAXTimeout *timeout) {
    int result = s->admit(s->context, required_ns, after_press, timeout);
    if (!result) return YES;
    if (result != MRK_AX_DEADLINE && result != MRK_AX_INELIGIBLE && result != MRK_AX_CUSTODY) {
        s->cleanupKnown = NO; result = MRK_AX_CUSTODY;
    }
    return mrk_ax_fail(s, (uint32_t)result);
}
static BOOL mrk_ax_before(MRKAX *s, AXUIElementRef element) {
    // Count BOTH the timeout setter and intended IPC, including final Press.
    if (s->calls > MRK_AX_CALL_LIMIT - 2) return mrk_ax_fail(s, MRK_AX_LIMIT);
    MRKAXTimeout timeout = {0};
    if (!mrk_ax_admit(s, 0, 0, &timeout)) return NO;
    if (!isfinite(timeout.seconds) || timeout.seconds <= 0 || (double)timeout.seconds > 0.1
        || timeout.required_ns == 0 || timeout.required_ns > 100000000
        || timeout.required_ns != (uint64_t)ceil((double)timeout.seconds * 1000000000.0))
        return mrk_ax_fail(s, MRK_AX_INPUT);
    s->calls++;
    BOOL installed = mrk_ax_status(s, AXUIElementSetMessagingTimeout(element, timeout.seconds));
    // Recheck the SAME Eax after the setter AND all callback lock waits. A new
    // use always installs a fresh downward-rounded timeout on this exact ref.
    BOOL admitted = mrk_ax_admit(s, timeout.required_ns, 0, NULL);
    return installed && admitted;
}
static CFTypeRef mrk_ax_copy(MRKAX *s, AXUIElementRef element, CFStringRef attribute, uint32_t site) {
    s->result.site = site;
    MRKAXOwned *slot = mrk_ax_slot(s); if (!slot || !mrk_ax_before(s, element)) return NULL;
    s->calls++;
    BOOL copied = mrk_ax_status(s, AXUIElementCopyAttributeValue(element, attribute, &slot->value));
    BOOL admitted = mrk_ax_admit(s, 0, 0, NULL); // Also after an error return; no query retry.
    if (!copied || !admitted) return NULL;
    if (!slot->value) { mrk_ax_fail(s, MRK_AX_UNSUPPORTED); return NULL; }
    return slot->value;
}
static BOOL mrk_ax_type(MRKAX *s, CFTypeRef value, CFTypeID type) {
    return value && CFGetTypeID(value) == type ? YES : mrk_ax_fail(s, MRK_AX_MALFORMED);
}
static CFArrayRef mrk_ax_array(MRKAX *s, AXUIElementRef element, CFStringRef attribute, CFIndex limit, uint32_t site) {
    s->result.site = site;
    MRKAXOwned *slot = mrk_ax_slot(s); if (!slot || !mrk_ax_before(s, element)) return NULL;
    s->calls++;
    BOOL copied = mrk_ax_status(s, AXUIElementCopyAttributeValues(element, attribute, 0, limit + 1, &slot->array));
    BOOL admitted = mrk_ax_admit(s, 0, 0, NULL);
    if (!copied || !admitted || !mrk_ax_type(s, slot->value, CFArrayGetTypeID())) return NULL;
    CFIndex count = CFArrayGetCount(slot->array);
    if (count < 0 || count >= limit + 1) { mrk_ax_fail(s, MRK_AX_LIMIT); return NULL; }
    for (CFIndex i = 0; i < count; i++) {
        if (!mrk_ax_type(s, CFArrayGetValueAtIndex(slot->array, i), AXUIElementGetTypeID())) return NULL;
    }
    return slot->array;
}
static AXUIElementRef mrk_ax_identified(MRKAX *s, CFArrayRef candidates, CFStringRef tag, uint32_t site) {
    s->result.site = site;
    AXUIElementRef found = NULL;
    for (CFIndex i = 0; i < CFArrayGetCount(candidates); i++) {
        AXUIElementRef element = (AXUIElementRef)CFArrayGetValueAtIndex(candidates, i);
        CFTypeRef value = mrk_ax_copy(s, element, kAXIdentifierAttribute, site);
        if (!value || !mrk_ax_type(s, value, CFStringGetTypeID())) return NULL;
        if (CFStringGetLength(value) >= 64) { mrk_ax_fail(s, MRK_AX_LIMIT); return NULL; }
        if (CFEqual(value, tag)) {
            if (found) { mrk_ax_fail(s, MRK_AX_AMBIGUOUS); return NULL; }
            found = element;
        }
    }
    if (!found) mrk_ax_fail(s, MRK_AX_UNSUPPORTED);
    return found;
}
static void mrk_ax_open(MRKAX *s, const uint8_t *parent_tag, const uint8_t *panel_tag) {
    if (!mrk_ax_admit(s, 0, 0, NULL)) return;
    MRKAXOwned *parent_text = mrk_ax_slot(s), *panel_text = mrk_ax_slot(s), *application = mrk_ax_slot(s);
    if (!parent_text || !panel_text || !application) return;
    s->result.site = MRK_AX_APPLICATION;
    parent_text->value = CFStringCreateWithCString(NULL, (const char *)parent_tag, kCFStringEncodingASCII);
    panel_text->value = CFStringCreateWithCString(NULL, (const char *)panel_tag, kCFStringEncodingASCII);
    application->value = AXUIElementCreateApplication(getpid()); // THIS installed process only.
    if (!mrk_ax_type(s, parent_text->value, CFStringGetTypeID()) || !mrk_ax_type(s, panel_text->value, CFStringGetTypeID())
        || !mrk_ax_type(s, application->value, AXUIElementGetTypeID())) return;
    CFArrayRef windows = mrk_ax_array(s, (AXUIElementRef)application->value, kAXWindowsAttribute, 4, MRK_AX_WINDOWS);
    if (!windows) return;
    AXUIElementRef parent = mrk_ax_identified(s, windows, parent_text->value, MRK_AX_PARENT_ID);
    if (!parent) return;
    CFArrayRef children = mrk_ax_array(s, parent, kAXChildrenAttribute, 16, MRK_AX_CHILDREN);
    if (!children) return;
    AXUIElementRef panel = mrk_ax_identified(s, children, panel_text->value, MRK_AX_PANEL_ID);
    if (!panel) return;
    CFTypeRef role = mrk_ax_copy(s, panel, kAXRoleAttribute, MRK_AX_PANEL_ROLE);
    if (!role || !mrk_ax_type(s, role, CFStringGetTypeID())) return;
    if (!CFEqual(role, kAXSheetRole)) { mrk_ax_fail(s, MRK_AX_UNSUPPORTED); return; }
    CFTypeRef link = mrk_ax_copy(s, panel, kAXParentAttribute, MRK_AX_PANEL_PARENT);
    if (!link || !mrk_ax_type(s, link, AXUIElementGetTypeID())) return;
    if (!CFEqual(link, parent)) { mrk_ax_fail(s, MRK_AX_CHANGED); return; }
    s->result.flags |= MRK_AX_IDENTITY;
    CFTypeRef control = mrk_ax_copy(s, panel, kAXDefaultButtonAttribute, MRK_AX_DEFAULT);
    if (!control || !mrk_ax_type(s, control, AXUIElementGetTypeID())) return;
    role = mrk_ax_copy(s, (AXUIElementRef)control, kAXRoleAttribute, MRK_AX_BUTTON_ROLE);
    if (!role || !mrk_ax_type(s, role, CFStringGetTypeID())) return;
    if (!CFEqual(role, kAXButtonRole)) { mrk_ax_fail(s, MRK_AX_UNSUPPORTED); return; }
    CFTypeRef enabled = mrk_ax_copy(s, (AXUIElementRef)control, kAXEnabledAttribute, MRK_AX_ENABLED);
    if (!enabled || !mrk_ax_type(s, enabled, CFBooleanGetTypeID())) return;
    if (!CFBooleanGetValue(enabled)) { mrk_ax_fail(s, MRK_AX_INELIGIBLE); return; }
    CFTypeRef chain[9] = {control}; size_t length = 1; BOOL reached = NO;
    for (unsigned edge = 0; edge < 8; edge++) {
        link = mrk_ax_copy(s, (AXUIElementRef)chain[length - 1], kAXParentAttribute, MRK_AX_ANCESTRY);
        if (!link || !mrk_ax_type(s, link, AXUIElementGetTypeID())) return;
        for (size_t i = 0; i < length; i++) {
            if (CFEqual(link, chain[i])) { mrk_ax_fail(s, MRK_AX_MALFORMED); return; }
        }
        chain[length++] = link;
        if (CFEqual(link, panel)) { reached = YES; break; }
    }
    if (!reached) { mrk_ax_fail(s, MRK_AX_LIMIT); return; }
    CFTypeRef repeated = mrk_ax_copy(s, panel, kAXDefaultButtonAttribute, MRK_AX_RECHECK);
    if (!repeated || !mrk_ax_type(s, repeated, AXUIElementGetTypeID())) return;
    if (!CFEqual(repeated, control)) { mrk_ax_fail(s, MRK_AX_CHANGED); return; }
    s->result.flags |= MRK_AX_CONTROL;
    s->result.site = MRK_AX_PRESS;
    if (!mrk_ax_before(s, (AXUIElementRef)control)) return;
    // No query, wait or lock after that last scoped admission. Every return,
    // including CannotComplete (which MAY have acted), spends this one attempt.
    s->calls++; s->result.flags |= MRK_AX_ATTEMPTED;
    AXError result = AXUIElementPerformAction((AXUIElementRef)control, kAXPressAction);
    s->result.flags |= MRK_AX_PRESS_RETURNED;
    mrk_ax_status(s, result);
    mrk_ax_admit(s, 0, 1, NULL); // Real callback/close may already have happened.
}
void mrk_observation_ax_press(const uint8_t *parent, const uint8_t *panel, size_t capacity,
    MRKAXAdmission admission, void *context, MRKAXResult *out) {
    if (!out) return;
    MRKAX s = {0}; s.admit = admission; s.context = context; s.cleanupKnown = YES; s.result.site = MRK_AX_ENTRY;
    @try {
        if (pthread_main_np()) mrk_ax_fail(&s, MRK_AX_THREAD);
        else if (!parent || !panel || capacity != 64 || !admission || !context
            || !parent[0] || !panel[0] || strnlen((const char *)parent, capacity) >= capacity
            || strnlen((const char *)panel, capacity) >= capacity || !strcmp((const char *)parent, (const char *)panel))
            mrk_ax_fail(&s, MRK_AX_INPUT);
        else mrk_ax_open(&s, parent, panel);
    } @catch (NSException *e) { (void)e; mrk_ax_fail(&s, MRK_AX_EXCEPTION); s.cleanupKnown = NO; }
    while (s.count) {
        CFTypeRef original = s.owned[--s.count].value; s.owned[s.count].value = NULL;
        @try { if (original) CFRelease(original); }
        @catch (NSException *e) {
            (void)e; s.cleanupKnown = NO;
            if (!s.result.error) { s.result.site = MRK_AX_CLEANUP; mrk_ax_fail(&s, MRK_AX_CLEANUP_UNKNOWN); }
        }
    }
    // Cleanup and any final callback waits also spend the one original Eax.
    if (!pthread_main_np() && admission && context) mrk_ax_admit(&s, 0, (s.result.flags & MRK_AX_ATTEMPTED) != 0, NULL);
    if (s.cleanupKnown) s.result.flags |= MRK_AX_CLEANED;
    *out = s.result; // No CF handle is handed off; CLEANED requires every release to return.
}
#endif
