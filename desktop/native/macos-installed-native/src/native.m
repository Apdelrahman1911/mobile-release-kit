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

#ifdef MRK_INSTALLED_OBSERVATION
// Closed result: 0=returned snapshot, 1=entry refused, 2=AppKit read error.
// The supplied address is comparison DATA, never an object to dereference.
int mrk_observation_original_window(uintptr_t original, uint32_t *flags) {
    if (!flags) return 1;
    *flags = 0;
    if (!pthread_main_np() || !original) return 1;
    @try {
        NSApplication *app = NSApp; // Do not initialize or activate an application.
        if (!app) return 0;
        uint32_t observed = 1u; // application present
        if ([app isActive]) observed |= 2u;
        NSWindow *main = [app mainWindow];
        if (main) {
            observed |= 4u;
            if ((uintptr_t)(void *)main == original) observed |= 8u;
            if (![main isKindOfClass:[NSPanel class]]) observed |= 16u;
            if (![main attachedSheet]) observed |= 32u;
        }
        *flags = observed; // Publish no partial flags if an AppKit read throws.
        return 0;
    } @catch (NSException *e) { (void)e; return 2; }
}
#endif

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
    uint32_t flags, checked, matched, parent, panel, children, originals, site, error;
} MRKIdentityProof;
typedef struct { uint32_t flags, checked, matched, site, error; } MRKConfirmProof;
_Static_assert(sizeof(MRKConfirmProof) == 20, "Confirm proof ABI");
typedef struct {
    uint32_t flags, parent, site, error;
    MRKIdentityProof binding;
} MRKIdentityWire;
enum { MRK_ID_ARMED = 1u, MRK_ID_CONFIG_ATTEMPTED = 2u, MRK_ID_PARENT_ENTERED = 4u,
    MRK_ID_PARENT_RETURNED = 8u, MRK_ID_CONFIG_COMPLETE = 16u };
enum { MRK_ID_OBJECTS = 1u, MRK_ID_TAGS, MRK_ID_PARENT_SET, MRK_ID_PARENT_GET, MRK_ID_COMPLETE };
enum { MRK_ID_UNOBSERVED, MRK_ID_NIL, MRK_ID_MATCH, MRK_ID_DIFFERENT, MRK_ID_TYPE_INVALID };
enum { MRK_PANEL_ID_UNOBSERVED, MRK_PANEL_ID_NIL, MRK_PANEL_ID_TYPE_INVALID, MRK_PANEL_ID_EMPTY,
    MRK_PANEL_ID_LIMIT, MRK_PANEL_ID_NUL, MRK_PANEL_ID_ENCODING, MRK_PANEL_ID_VALID,
    MRK_PANEL_ID_MATCH, MRK_PANEL_ID_DIFFERENT };
enum { MRK_PROOF_OBJECTS = 1u, MRK_PROOF_ATTACHMENT, MRK_PROOF_DIRECTORY, MRK_PROOF_PARENT_ID,
    MRK_PROOF_PANEL_ID, MRK_PROOF_PARENT_SHEETS, MRK_PROOF_PANEL_SHEETS, MRK_PROOF_PANEL_SHEET,
    MRK_PROOF_CHILDREN, MRK_PROOF_PARENT, MRK_PROOF_ROLE, MRK_PROOF_STABLE,
    MRK_PROOF_FINAL, MRK_PROOF_COMPLETE, MRK_PROOF_ALL = 0xfffu };
enum { MRK_CONFIRM_OBJECTS = 1u, MRK_CONFIRM_PANEL, MRK_CONFIRM_CAPABILITY,
    MRK_CONFIRM_ALLOWED, MRK_CONFIRM_STABLE, MRK_CONFIRM_COMPLETE };
enum { MRK_CONFIRM_ATTEMPTED = 1u };
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
    char observationDirectory[4097];
    char observationParentTag[64], observationPanelTag[64];
    MRKIdentityWire observationIdentity;
    // Confirm uses the already-retained original window; no extra element owner.
    BOOL observationConfirmBodyAttempted;
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

// Public original-panel Confirm is one synchronous main-thread operation. None of this
// ABI carries an AppKit object, native BOOL, title, path or private identifier.
enum { MRK_OPEN_NONE, MRK_OPEN_THREAD, MRK_OPEN_INPUT, MRK_OPEN_INELIGIBLE, MRK_OPEN_UNSUPPORTED,
    MRK_OPEN_AMBIGUOUS, MRK_OPEN_MALFORMED, MRK_OPEN_LIMIT, MRK_OPEN_DEADLINE, MRK_OPEN_CUSTODY,
    MRK_OPEN_NOT_TRIGGERED, MRK_OPEN_CHANGED = 13, MRK_OPEN_EXCEPTION = 14 };
enum { MRK_OPEN_ENTRY = 1u, MRK_OPEN_CONFIRM_ELIGIBILITY, MRK_OPEN_PROOF, MRK_OPEN_CONFIRM_RECHECK,
    MRK_OPEN_ADMISSION, MRK_OPEN_CONFIRM, MRK_OPEN_INITIAL_PROOF };
enum { MRK_OPEN_ATTEMPTED = 1u, MRK_OPEN_RETURNED = 2u, MRK_OPEN_TRIGGERED = 4u, MRK_OPEN_KNOWN = 8u };
typedef struct {
    uint32_t flags, site, error;
    MRKIdentityProof initial_proof, proof;
    MRKConfirmProof eligibility, recheck;
} MRKOpenResult;
_Static_assert(sizeof(MRKOpenResult) == 124, "fixed original/Confirm scalar result ABI required");
typedef int (*MRKOpenAdmission)(void *, int);

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
// Strict bounded UTF-8, independently checked again by Rust and CF creation.
// No lossy/ASCII conversion, interior NUL, overlong form or nonzero padding.
static BOOL mrk_identity_utf8(const uint8_t bytes[64]) {
    size_t length = strnlen((const char *)bytes, 64);
    if (!length || length >= 64) return NO;
    for (size_t i = length; i < 64; i++) if (bytes[i]) return NO;
    for (size_t i = 0; i < length;) {
        uint32_t value = bytes[i++], minimum = 0; unsigned remaining = 0;
        if (value < 0x80) continue;
        if (value >= 0xc2 && value <= 0xdf) { value &= 0x1f; remaining = 1; minimum = 0x80; }
        else if (value >= 0xe0 && value <= 0xef) { value &= 0x0f; remaining = 2; minimum = 0x800; }
        else if (value >= 0xf0 && value <= 0xf4) { value &= 7; remaining = 3; minimum = 0x10000; }
        else return NO;
        if (remaining > length - i) return NO;
        while (remaining--) {
            uint8_t next = bytes[i++]; if ((next & 0xc0) != 0x80) return NO;
            value = (value << 6) | (next & 0x3f);
        }
        if (value < minimum || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) return NO;
    }
    return YES;
}
static uint32_t mrk_original_identifier(id value, uint8_t bytes[64]) {
    memset(bytes, 0, 64);
    if (!value) return MRK_PANEL_ID_NIL;
    if (![value isKindOfClass:[NSString class]]) return MRK_PANEL_ID_TYPE_INVALID;
    NSString *text = value; NSUInteger length = [text length];
    if (!length) return MRK_PANEL_ID_EMPTY;
    if (length > 63) return MRK_PANEL_ID_LIMIT;
    for (NSUInteger i = 0; i < length; i++) if ([text characterAtIndex:i] == 0) return MRK_PANEL_ID_NUL;
    NSUInteger bytes_needed = [text lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    if (!bytes_needed) return MRK_PANEL_ID_ENCODING;
    if (bytes_needed > 63) return MRK_PANEL_ID_LIMIT;
    NSUInteger used = 0; NSRange remainder = NSMakeRange(0, length);
    if (![text getBytes:bytes maxLength:63 usedLength:&used encoding:NSUTF8StringEncoding
        options:0 range:NSMakeRange(0, length) remainingRange:&remainder]
        || remainder.length || used != bytes_needed || !mrk_identity_utf8(bytes)) return MRK_PANEL_ID_ENCODING;
    NSString *roundtrip = [[[NSString alloc] initWithBytes:bytes length:used encoding:NSUTF8StringEncoding] autorelease];
    return roundtrip && [roundtrip isEqualToString:text] ? MRK_PANEL_ID_VALID : MRK_PANEL_ID_ENCODING;
}
static BOOL mrk_panel_configure_open_identity(MRKInstalledPanel *s) {
    MRKIdentityWire *d = &s->observationIdentity;
    d->flags |= MRK_ID_CONFIG_ATTEMPTED; d->site = MRK_ID_OBJECTS;
    d->error = MRK_OPEN_INELIGIBLE;
    if (!s->parent || !s->window || s->kind != 1 || s->unknown || s->responded
        || s->callbackActive || s->closeAttempted || s->closed) return NO;
    @try {
        d->site = MRK_ID_TAGS; d->error = MRK_OPEN_INPUT;
        NSString *parentTag = [@"mrk-parent-" stringByAppendingString:[[NSUUID UUID] UUIDString]];
        if (![parentTag getCString:s->observationParentTag maxLength:64 encoding:NSASCIIStringEncoding]
            || !mrk_identity_tag(s->observationParentTag, "mrk-parent-")) return NO;
        d->site = MRK_ID_PARENT_SET; d->flags |= MRK_ID_PARENT_ENTERED;
        [s->parent setAccessibilityIdentifier:parentTag];
        d->flags |= MRK_ID_PARENT_RETURNED;
        d->site = MRK_ID_PARENT_GET;
        d->parent = mrk_identity_class([s->parent accessibilityIdentifier], parentTag);
        // Parent-only setter DATA. No panel setter or invented setter return;
        // its actual public identifier is read only at admitted preparation.
        d->flags |= MRK_ID_CONFIG_COMPLETE; d->site = MRK_ID_COMPLETE; d->error = MRK_OPEN_NONE;
        return YES;
    } @catch (NSException *e) {
        (void)e; d->error = MRK_OPEN_EXCEPTION;
        @throw; // The SAME original start catch records unknown/EIO.
    }
}
static BOOL mrk_original_eligible(MRKInstalledPanel *s) {
    return !s->unknown && s->started && s->kind == 1 && s->parent && s->window && s->completion
        && !s->responded && !s->callbackActive && !s->closeAttempted && !s->closed
        && !s->observationActionAttempted && !s->observationActionReturned
        && (s->observationIdentity.flags & (MRK_ID_ARMED | MRK_ID_CONFIG_COMPLETE)) == (MRK_ID_ARMED | MRK_ID_CONFIG_COMPLETE);
}
static BOOL mrk_proof_check(MRKIdentityProof *p, unsigned bit, BOOL matched, uint32_t error) {
    p->checked |= 1u << bit;
    if (matched) { p->matched |= 1u << bit; return YES; }
    p->matched &= ~(1u << bit); p->error = error; return NO;
}
static BOOL mrk_original_topology(MRKInstalledPanel *s, MRKIdentityProof *p) {
    p->site = MRK_PROOF_PARENT_SHEETS;
    id sheets = [s->parent sheets];
    if (![sheets isKindOfClass:[NSArray class]]) return mrk_proof_check(p, 5, NO, MRK_OPEN_MALFORMED);
    NSUInteger count = [sheets count];
    if (!mrk_proof_check(p, 5, count == 1 && [sheets objectAtIndex:0] == s->window,
        count > 1 ? MRK_OPEN_AMBIGUOUS : MRK_OPEN_CHANGED)) return NO;
    p->site = MRK_PROOF_PANEL_SHEETS;
    sheets = [s->window sheets];
    if (![sheets isKindOfClass:[NSArray class]]) return mrk_proof_check(p, 6, NO, MRK_OPEN_MALFORMED);
    if ([sheets count]) return mrk_proof_check(p, 6, NO, MRK_OPEN_AMBIGUOUS);
    p->site = MRK_PROOF_PANEL_SHEET;
    if (!mrk_proof_check(p, 6, [s->window attachedSheet] == nil, MRK_OPEN_AMBIGUOUS)) return NO;
    p->site = MRK_PROOF_CHILDREN;
    id children = [s->parent accessibilityChildren];
    if (![children isKindOfClass:[NSArray class]]) return mrk_proof_check(p, 7, NO, MRK_OPEN_MALFORMED);
    count = [children count]; p->children = (uint32_t)(count > 16 ? 17 : count) + 1;
    if (count > 16) return mrk_proof_check(p, 7, NO, MRK_OPEN_LIMIT);
    unsigned originals = 0;
    for (NSUInteger i = 0; i < count; i++) if ([children objectAtIndex:i] == s->window) originals++;
    p->originals = originals == 0 ? 1 : originals == 1 ? 2 : 3;
    if (!mrk_proof_check(p, 7, originals == 1, originals > 1 ? MRK_OPEN_AMBIGUOUS : MRK_OPEN_UNSUPPORTED)) return NO;
    p->site = MRK_PROOF_PARENT;
    if (!mrk_proof_check(p, 8, [s->window accessibilityParent] == s->parent, MRK_OPEN_UNSUPPORTED)) return NO;
    p->site = MRK_PROOF_ROLE;
    id role = [s->window accessibilityRole];
    if (![role isKindOfClass:[NSString class]]) return mrk_proof_check(p, 9, NO, MRK_OPEN_MALFORMED);
    return mrk_proof_check(p, 9, [role isEqualToString:NSAccessibilitySheetRole], MRK_OPEN_UNSUPPORTED);
}
static int mrk_original_proof(MRKInstalledPanel *s, MRKIdentityProof *p, BOOL freeze) {
    p->flags = 1; p->site = MRK_PROOF_OBJECTS; p->error = MRK_OPEN_INELIGIBLE;
    if (!mrk_proof_check(p, 0, mrk_original_eligible(s), MRK_OPEN_INELIGIBLE)) return p->error;
    @try {
        p->site = MRK_PROOF_ATTACHMENT;
        if (!mrk_proof_check(p, 1, mrk_observation_attached(s), MRK_OPEN_INELIGIBLE)) return p->error;
        p->site = MRK_PROOF_DIRECTORY;
        if (!mrk_proof_check(p, 2, mrk_observation_directory_ready(s), MRK_OPEN_INELIGIBLE)) return p->error;
        p->site = MRK_PROOF_PARENT_ID;
        if (!mrk_identity_tag(s->observationParentTag, "mrk-parent-")) { p->error = MRK_OPEN_INPUT; return p->error; }
        NSString *parentTag = [NSString stringWithCString:s->observationParentTag encoding:NSASCIIStringEncoding];
        p->parent = mrk_identity_class([s->parent accessibilityIdentifier], parentTag);
        if (!mrk_proof_check(p, 3, p->parent == MRK_ID_MATCH, MRK_OPEN_UNSUPPORTED)) return p->error;
        p->site = MRK_PROOF_PANEL_ID; uint8_t current[64] = {0};
        p->panel = mrk_original_identifier([s->window accessibilityIdentifier], current);
        if (!mrk_proof_check(p, 4, p->panel == MRK_PANEL_ID_VALID,
            p->panel == MRK_PANEL_ID_LIMIT ? MRK_OPEN_LIMIT : MRK_OPEN_UNSUPPORTED)) return p->error;
        if (!memcmp(current, s->observationParentTag, 64)) {
            p->panel = MRK_PANEL_ID_DIFFERENT; mrk_proof_check(p, 4, NO, MRK_OPEN_INPUT); return p->error;
        }
        if (freeze) memcpy(s->observationPanelTag, current, 64); // First valid value; never retag/rebind.
        else {
            p->panel = !memcmp(current, s->observationPanelTag, 64) ? MRK_PANEL_ID_MATCH : MRK_PANEL_ID_DIFFERENT;
            if (!mrk_proof_check(p, 4, p->panel == MRK_PANEL_ID_MATCH, MRK_OPEN_CHANGED)) return p->error;
        }
        if (!mrk_original_topology(s, p)) return p->error;
        // One fixed final native proof, not a retry. Reads may reenter; original
        // custody and every public edge must still hold on actual return.
        p->site = MRK_PROOF_ATTACHMENT;
        if (!mrk_proof_check(p, 1, mrk_observation_attached(s), MRK_OPEN_CHANGED)) return p->error;
        p->site = MRK_PROOF_DIRECTORY;
        if (!mrk_proof_check(p, 2, mrk_observation_directory_ready(s), MRK_OPEN_CHANGED)) return p->error;
        if (!mrk_original_topology(s, p)) return p->error;
        p->site = MRK_PROOF_PARENT_ID;
        p->parent = mrk_identity_class([s->parent accessibilityIdentifier], parentTag);
        if (!mrk_proof_check(p, 3, p->parent == MRK_ID_MATCH, MRK_OPEN_CHANGED)) return p->error;
        p->site = MRK_PROOF_STABLE;
        p->panel = mrk_original_identifier([s->window accessibilityIdentifier], current);
        if (p->panel == MRK_PANEL_ID_VALID)
            p->panel = !memcmp(current, s->observationPanelTag, 64) ? MRK_PANEL_ID_MATCH : MRK_PANEL_ID_DIFFERENT;
        BOOL stable = p->panel == MRK_PANEL_ID_MATCH;
        // Bit4 records the first validated/frozen value. Preserve that fact
        // if this later getter changes; bit10 and the final class say why.
        if (!mrk_proof_check(p, 10, stable, MRK_OPEN_CHANGED)) return p->error;
        p->site = MRK_PROOF_FINAL;
        if (!mrk_proof_check(p, 11, mrk_original_eligible(s), MRK_OPEN_INELIGIBLE)) return p->error;
        p->site = MRK_PROOF_COMPLETE; p->error = MRK_OPEN_NONE; return MRK_OPEN_NONE;
    } @catch (NSException *e) { (void)e; s->unknown = YES; p->error = MRK_OPEN_EXCEPTION; return MRK_OPEN_EXCEPTION; }
}
static BOOL mrk_confirm_check(MRKConfirmProof *p, unsigned bit, BOOL matched, uint32_t error) {
    p->checked |= 1u << bit;
    if (matched) { p->matched |= 1u << bit; return YES; }
    p->error = error; return NO;
}
static BOOL mrk_confirm_originals(MRKInstalledPanel *s, NSWindow *parent, NSWindow *panel,
    void (^completion)(NSModalResponse)) {
    // Borrowed aliases of existing main-only originals, never extra owners or
    // lookup results. A changed slot cannot authorize messages to a replacement.
    return parent && panel && completion && s->parent == parent && s->window == panel && s->completion == completion;
}
static int mrk_confirm_proof(MRKInstalledPanel *s, MRKConfirmProof *p,
    NSWindow *parent, NSWindow *panel, void (^completion)(NSModalResponse)) {
    p->flags = MRK_CONFIRM_ATTEMPTED; p->site = MRK_CONFIRM_OBJECTS;
    if (!mrk_confirm_originals(s, parent, panel, completion)) {
        s->unknown = YES; mrk_confirm_check(p, 0, NO, MRK_OPEN_CUSTODY); return p->error;
    }
    if (!mrk_confirm_check(p, 0, mrk_original_eligible(s), MRK_OPEN_INELIGIBLE)) return p->error;
    @try {
        p->site = MRK_CONFIRM_PANEL;
        if (!mrk_confirm_check(p, 1, [panel isKindOfClass:[NSOpenPanel class]], MRK_OPEN_UNSUPPORTED)) return p->error;
        p->site = MRK_CONFIRM_CAPABILITY;
        if (!mrk_confirm_check(p, 2, [panel respondsToSelector:@selector(isAccessibilitySelectorAllowed:)]
            && [panel respondsToSelector:@selector(accessibilityPerformConfirm)], MRK_OPEN_UNSUPPORTED)) return p->error;
        p->site = MRK_CONFIRM_ALLOWED;
        if (!mrk_confirm_check(p, 3, [panel isAccessibilitySelectorAllowed:@selector(accessibilityPerformConfirm)],
            MRK_OPEN_INELIGIBLE)) return p->error;
        p->site = MRK_CONFIRM_STABLE;
        if (!mrk_confirm_originals(s, parent, panel, completion)) {
            s->unknown = YES; mrk_confirm_check(p, 4, NO, MRK_OPEN_CUSTODY); return p->error;
        }
        if (!mrk_confirm_check(p, 4, mrk_original_eligible(s), MRK_OPEN_INELIGIBLE)) return p->error;
        p->site = MRK_CONFIRM_COMPLETE; p->error = MRK_OPEN_NONE; return MRK_OPEN_NONE;
    } @catch (NSException *e) {
        (void)e; s->unknown = YES; p->error = MRK_OPEN_EXCEPTION; return p->error;
    }
}
int mrk_panel_observe_open_identity(void *opaque, uint8_t *parent, uint8_t *panel, size_t capacity) {
    if (!pthread_main_np()) return MRK_OPEN_THREAD;
    if (!opaque || !parent || !panel || capacity != 64) return MRK_OPEN_INPUT;
    memset(parent, 0, capacity); memset(panel, 0, capacity);
    MRKInstalledPanel *s = opaque; MRKIdentityProof *p = &s->observationIdentity.binding;
    if (p->site) return MRK_OPEN_INELIGIBLE;
    int status = mrk_original_proof(s, p, YES);
    if (!status) { memcpy(parent, s->observationParentTag, capacity); memcpy(panel, s->observationPanelTag, capacity); }
    return status; // Original-only preparation; Confirm eligibility is timed later.
}
static void mrk_confirm_body(MRKInstalledPanel *s, const uint8_t *parent, const uint8_t *panel,
    MRKOpenAdmission admit, void *context, MRKOpenResult *r) {
    if (s->observationConfirmBodyAttempted || s->unknown
        || s->observationIdentity.binding.site != MRK_PROOF_COMPLETE || s->observationIdentity.binding.error
        || memcmp(parent, s->observationParentTag, 64) || memcmp(panel, s->observationPanelTag, 64)) {
        r->error = MRK_OPEN_CUSTODY; s->unknown = YES; return;
    }
    s->observationConfirmBodyAttempted = YES;
    NSWindow *const originalParent = s->parent;
    NSWindow *const originalPanel = s->window;
    void (^const originalCompletion)(NSModalResponse) = s->completion;
    r->error = admit(context, 0); if (r->error) return;
    // Preparation's saved proof does not authorize later Confirm eligibility.
    // Preserve this fresh full original proof independently from final proof.
    r->site = MRK_OPEN_INITIAL_PROOF;
    r->error = mrk_original_proof(s, &r->initial_proof, NO); if (r->error) return;
    r->site = MRK_OPEN_ADMISSION;
    r->error = admit(context, 0); if (r->error) return;
    r->site = MRK_OPEN_CONFIRM_ELIGIBILITY;
    r->error = mrk_confirm_proof(s, &r->eligibility, originalParent, originalPanel, originalCompletion); if (r->error) return;
    // A slow getter cannot permit a later action or restart this endpoint.
    r->site = MRK_OPEN_ADMISSION;
    r->error = admit(context, 0); if (r->error) return;
    r->site = MRK_OPEN_PROOF;
    r->error = mrk_original_proof(s, &r->proof, NO); if (r->error) return;
    r->site = MRK_OPEN_ADMISSION;
    r->error = admit(context, 0); if (r->error) return;
    r->site = MRK_OPEN_CONFIRM_RECHECK;
    r->error = mrk_confirm_proof(s, &r->recheck, originalParent, originalPanel, originalCompletion); if (r->error) return;
    // All returned AppKit getters precede this final scoped owner/clock gate.
    // No lock, getter, lookup, replacement or renewed clock follows its permit.
    r->site = MRK_OPEN_ADMISSION;
    r->error = admit(context, 0); if (r->error) return;
    r->site = MRK_OPEN_CONFIRM;
    s->observationActionAttempted = YES; r->flags |= MRK_OPEN_ATTEMPTED;
    BOOL triggered = [originalPanel accessibilityPerformConfirm];
    s->observationActionReturned = YES; r->flags |= MRK_OPEN_RETURNED;
    if (triggered) r->flags |= MRK_OPEN_TRIGGERED; else r->error = MRK_OPEN_NOT_TRIGGERED;
    // A real callback may already have happened: custody, not pre-action
    // no-response eligibility, is required after actual selector return.
    if (!mrk_confirm_originals(s, originalParent, originalPanel, originalCompletion)
        || s->unknown || s->callbackActive || !s->started || s->kind != 1 || s->closeAttempted || s->closed) {
        s->unknown = YES; r->error = MRK_OPEN_CUSTODY; return;
    }
    int after = admit(context, 1); if (!r->error || after == MRK_OPEN_CUSTODY) r->error = after;
}
void mrk_panel_observe_confirm(void *opaque, const uint8_t *parent, const uint8_t *panel, size_t capacity,
    MRKOpenAdmission admit, void *context, MRKOpenResult *out) {
    if (!out) return;
    MRKOpenResult r = {0}; r.site = MRK_OPEN_ENTRY;
    MRKInstalledPanel *s = opaque;
    @try {
        if (!pthread_main_np()) r.error = MRK_OPEN_THREAD;
        else if (!s || !parent || !panel || capacity != 64 || !admit || !context
            || !mrk_identity_tag((const char *)parent, "mrk-parent-") || !mrk_identity_utf8(panel)
            || !memcmp(parent, panel, capacity)) r.error = MRK_OPEN_INPUT;
        else mrk_confirm_body(s, parent, panel, admit, context, &r);
    } @catch (NSException *e) { (void)e; if (s) s->unknown = YES; r.error = MRK_OPEN_EXCEPTION; }
    if (pthread_main_np() && s && !s->unknown && r.error != MRK_OPEN_CUSTODY && r.error != MRK_OPEN_EXCEPTION)
        r.flags |= MRK_OPEN_KNOWN;
    *out = r; // Scalar actual-return DATA only. No element/CF pointer or cleanup receipt.
}
#endif
