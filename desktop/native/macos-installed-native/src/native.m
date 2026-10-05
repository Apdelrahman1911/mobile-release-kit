#ifndef MRK_ENTRY_METADATA_ONLY
#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#include <Block.h>
#endif
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
#include <stdatomic.h>
#include <stdlib.h>
#include <time.h>
#endif

#if !defined(__APPLE__) || !defined(__LP64__) || !defined(__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__)
#error "the installed native seam requires macOS LP64"
#endif
#if defined(__arm64__) && !defined(__x86_64__)
#define MRK_NATIVE_MACHINE "arm64"
#elif defined(__x86_64__) && !defined(__arm64__)
#define MRK_NATIVE_MACHINE "x86_64"
#else
#error "the installed native seam requires exactly one supported Mac architecture"
#endif
_Static_assert(sizeof(int) == 4 && sizeof(void *) == 8 && sizeof(size_t) == 8,
    "documented macOS int32 and LP64 scalar widths required");

// Private query-free DATA predicate, shared only with the cfg(test) Rust FFI.
// These supplied scalars never replace the actual zero-argument observation.
int mrk_platform_native_data(const char *sysname, const char *machine, int returned,
                             int observed_errno, size_t length, int translated) {
    if (!sysname || !machine || strcmp(sysname, "Darwin") || strcmp(machine, MRK_NATIVE_MACHINE)) return ENOTSUP;
    // errno is unspecified on success. Failed-call output cells are not facts.
    if (returned == 0) return length == sizeof(int) && translated == 0 ? 0 : ENOTSUP;
    // Apple's documented absent-key native case, after compiled-machine match.
    return returned == -1 && observed_errno == ENOENT ? 0 : ENOTSUP;
}
int mrk_platform(void) {
    struct utsname u; char version[64] = {0}; size_t length = sizeof(version);
    if (uname(&u) || strcmp(u.sysname, "Darwin") || strcmp(u.machine, MRK_NATIVE_MACHINE)) return ENOTSUP;
    if (sysctlbyname("kern.osproductversion", version, &length, NULL, 0) || length == 0 || length >= sizeof(version)
        || strncmp(version, "26.", 3)) return ENOTSUP;
    int translated = 0; size_t translated_length = sizeof(translated);
    errno = 0;
    int returned = sysctlbyname("sysctl.proc_translated", &translated, &translated_length, NULL, 0);
    int observed_errno = errno;
    return mrk_platform_native_data(u.sysname, u.machine, returned, observed_errno, translated_length, translated);
}
int mrk_user(uint32_t *uid) {
    if (!uid || getuid() == 0 || getuid() != geteuid() || getgid() != getegid() || issetugid()) return EPERM;
    int platform = mrk_platform(); if (platform) return platform;
    *uid = getuid(); return 0;
}
// One ordinary-user request at a fixed URL. The framework owns Finder; this
// function creates no application worker or completion callback. A returned zero
// means only that the void AppKit request returned, not that Finder was visible.
#ifndef MRK_ENTRY_METADATA_ONLY
int mrk_reveal_installation(void) {
    uint32_t uid = 0;
    int admitted = mrk_user(&uid); if (admitted) return admitted;
    @try {
        @autoreleasepool {
            NSURL *application = [NSURL fileURLWithPath:@"/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app" isDirectory:YES];
            NSWorkspace *workspace = [NSWorkspace sharedWorkspace];
            if (!application || !workspace) return ENOMEM;
            [workspace activateFileViewerSelectingURLs:@[application]];
        }
        return 0;
    } @catch (NSException *exception) {
        (void)exception;
        return EIO; // The request might already have reached Finder.
    }
}
#endif

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
#ifndef MRK_ENTRY_METADATA_ONLY
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
            || (kind != VREG && kind != VDIR && kind != VLNK)) return EIO;
        // attr_dataoffset is relative to the name reference itself.
        size_t name_at = name_field + (uint32_t)name.attr_dataoffset;
        if (name.attr_length > length - name_at) return EIO;
        uint16_t name_length = (uint16_t)(name.attr_length - 1);
        const uint8_t *text = entry + name_at;
        if (text[name_length] || memchr(text, 0, name_length) || memchr(text, '/', name_length)) return EIO;
        if (capacity - written < 11 || name_length > capacity - written - 11) return EOVERFLOW;
        memcpy(out + written, &inode, sizeof(inode));
        // Report link metadata only; consumers still decide which kinds they
        // admit. This decoder never opens or follows a reported entry.
        out[written + 8] = kind == VDIR ? DT_DIR : (kind == VLNK ? DT_LNK : DT_REG);
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
static BOOL mrk_panel_project_field(int kind) { return kind >= 4 && kind <= 7; }
static BOOL mrk_panel_open_kind(int kind) { return kind == 1 || kind == 3 || kind == 8 || kind == 9 || (kind >= 10 && kind <= 12) || mrk_panel_project_field(kind); }
int mrk_panel_response(int kind, int64_t code, int programmatic) {
    if (programmatic) return 0;
    if (mrk_panel_open_kind(kind)) {
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
enum { MRK_OPEN_NONE, MRK_OPEN_THREAD, MRK_OPEN_INPUT, MRK_OPEN_INELIGIBLE, MRK_OPEN_UNSUPPORTED,
    MRK_OPEN_AMBIGUOUS, MRK_OPEN_MALFORMED, MRK_OPEN_LIMIT, MRK_OPEN_DEADLINE, MRK_OPEN_CUSTODY,
    MRK_OPEN_INVALID_ELEMENT, MRK_OPEN_CANNOT_COMPLETE, MRK_OPEN_OTHER,
    MRK_OPEN_CHANGED, MRK_OPEN_EXCEPTION, MRK_OPEN_CLEANUP_UNKNOWN };
typedef struct {
    uint32_t flags, checked, matched, parent, panel, children, originals, site, error;
} MRKIdentityProof;
typedef struct {
    uint32_t flags, parent, prompt, site, error;
    MRKIdentityProof binding;
} MRKIdentityWire;
_Static_assert(sizeof(MRKIdentityWire) == 56, "fixed original identity scalar ABI");
enum { MRK_ID_ARMED = 1u, MRK_ID_CONFIG_ATTEMPTED = 2u, MRK_ID_PARENT_ENTERED = 4u,
    MRK_ID_PARENT_RETURNED = 8u, MRK_ID_CONFIG_COMPLETE = 16u,
    MRK_ID_PROMPT_ENTERED = 32u, MRK_ID_PROMPT_RETURNED = 64u,
    MRK_ID_DIRECTORY_ENTERED = 128u, MRK_ID_DIRECTORY_RETURNED = 256u,
    MRK_ID_FILE_PANEL = 512u, MRK_ID_NAME_ENTERED = 1024u, MRK_ID_NAME_RETURNED = 2048u };
enum { MRK_ID_OBJECTS = 1u, MRK_ID_TAGS, MRK_ID_PARENT_SET, MRK_ID_PARENT_GET, MRK_ID_COMPLETE,
    MRK_ID_PROMPT_SET, MRK_ID_PROMPT_GET, MRK_ID_DIRECTORY_URL, MRK_ID_DIRECTORY_SET, MRK_ID_NAME_SET, MRK_ID_NAME_GET,
    MRK_ID_INITIAL_CLOSE };
enum { MRK_ID_UNOBSERVED, MRK_ID_NIL, MRK_ID_MATCH, MRK_ID_DIFFERENT, MRK_ID_TYPE_INVALID };
enum { MRK_PANEL_ID_UNOBSERVED, MRK_PANEL_ID_NIL, MRK_PANEL_ID_TYPE_INVALID, MRK_PANEL_ID_EMPTY,
    MRK_PANEL_ID_LIMIT, MRK_PANEL_ID_NUL, MRK_PANEL_ID_ENCODING, MRK_PANEL_ID_VALID,
    MRK_PANEL_ID_MATCH, MRK_PANEL_ID_DIFFERENT };
enum { MRK_PROOF_OBJECTS = 1u, MRK_PROOF_ATTACHMENT, MRK_PROOF_DIRECTORY, MRK_PROOF_PARENT_ID,
    MRK_PROOF_PANEL_ID, MRK_PROOF_PARENT_SHEETS, MRK_PROOF_PANEL_SHEETS, MRK_PROOF_PANEL_SHEET,
    MRK_PROOF_CHILDREN, MRK_PROOF_PARENT, MRK_PROOF_ROLE, MRK_PROOF_STABLE,
    MRK_PROOF_FINAL, MRK_PROOF_COMPLETE, MRK_PROOF_ALL = 0xfffu };
// The genuine original completion owns this fixed DATA. No NSURL/NSArray or
// additional native owner survives the callback; zero means not observed.
typedef struct { uint32_t flags, response, selection; } MRKCompletionWire;
_Static_assert(sizeof(MRKCompletionWire) == 12, "fixed original completion scalar ABI");
enum { MRK_COMPLETION_ENTERED = 1u, MRK_COMPLETION_URLS_ENTERED = 2u,
    MRK_COMPLETION_URLS_RETURNED = 4u, MRK_COMPLETION_RETURNED = 8u,
    MRK_COMPLETION_DUPLICATE = 16u, MRK_COMPLETION_UNKNOWN = 32u };
enum { MRK_COMPLETION_UNOBSERVED, MRK_COMPLETION_ACCEPT, MRK_COMPLETION_DECLINE, MRK_COMPLETION_OTHER };
enum { MRK_SELECTION_UNOBSERVED, MRK_SELECTION_EMPTY, MRK_SELECTION_MALFORMED,
    MRK_SELECTION_MULTIPLE, MRK_SELECTION_DIFFERENT, MRK_SELECTION_DISAGREES, MRK_SELECTION_MATCH };
#endif

@interface MRKInstalledPanel : NSObject {
@public
    NSWindow *parent;
    NSWindow *window;
    NSAlert *alert;
    // P2-only synchronous start temporaries stay on the SAME native original
    // until their consuming releases return. Uncertain release is never retried.
    NSString *initialPath;
    NSURL *initialDirectory;
    void (^completion)(NSModalResponse);
    BOOL attempted, started, responded, reported, callbackActive, closeAttempted, closed, unknown;
    int kind, response;
    char selected[4097];
#ifdef MRK_INSTALLED_OBSERVATION
    // Instrumentation only; never callback/cleanup/selection authority.
    BOOL observationDirectoryReturned, observationActionAttempted, observationActionReturned;
    char observationTarget[4097];
    // Copied only from the production start's original ProjectPathBinding.
    // It is distinct from the later synthetic navigation target.
    char observationInitialRoot[4097];
    uint32_t observationProjectField, observationNamePhase;
    uint32_t observationSample, observationParentSample, observationSelectionSample;
    uint32_t observationFileFilter; // One initial-options DATA sample, never readiness authority.
    BOOL observationSelectionBound, observationSelectionParentChecked;
    NSString *observationFieldName;
    char observationParentTag[64], observationPanelTag[64];
    char observationPrompt[8];
    MRKIdentityWire observationIdentity;
    MRKCompletionWire observationCompletion;
    unsigned observationRechecks;
#endif
}
@end
@implementation MRKInstalledPanel
@end
// Only purpose9 reserves this subclass. Purposes1–8 keep their exact original
// instance layout; a dormant image batch is not charged to Project/Evidence/Quit.
// All storage belongs to the SAME retained native object and existing release;
// there is no second allocation, callback owner or independent free obligation.
@interface MRKInstalledImagePanel : MRKInstalledPanel {
@public
    // 0=no selection,1=complete,2=count refusal,3=path refusal.
    int imageSelection;
    size_t imageCount;
    char selectedImages[10][4097];
}
@end
@implementation MRKInstalledImagePanel
@end
_Static_assert(sizeof(((MRKInstalledImagePanel *)0)->selectedImages) == 10 * 4097, "bounded original public-image result");
#ifdef MRK_INSTALLED_OBSERVATION
static BOOL mrk_panel_configure_open_identity(MRKInstalledPanel *s);
static void mrk_panel_completion_selection(MRKInstalledPanel *s);
#endif

void *mrk_panel_reserve(void) {
    if (!pthread_main_np()) return NULL;
    @try { return [[MRKInstalledPanel alloc] init]; } @catch (NSException *e) { (void)e; return NULL; }
}
void *mrk_panel_reserve_images(void) {
    if (!pthread_main_np()) return NULL;
    @try { return [[MRKInstalledImagePanel alloc] init]; } @catch (NSException *e) { (void)e; return NULL; }
}
static int mrk_panel_selected_images(MRKInstalledImagePanel *s) {
    NSArray *urls = [(NSOpenPanel *)s->window URLs];
    if (!urls || ![urls isKindOfClass:[NSArray class]]) return 2;
    NSUInteger count = [urls count];
    if (count < 1 || count > 10) return 2; // no prefix is copied for an over-limit choice
    for (NSUInteger index = 0; index < count; ++index) {
        NSURL *url = [urls objectAtIndex:index];
        if (!url || ![url isKindOfClass:[NSURL class]] || ![url isFileURL]) return 3;
        // Check the complete NSString, not just strlen on a possibly embedded
        // NUL. The bounded file-system bytes are copied only after both checks.
        NSString *name = [url path];
        NSUInteger characters = name ? [name length] : 0;
        if (!characters || characters > 4096 || [name characterAtIndex:0] != '/') return 3;
        for (NSUInteger offset = 0; offset < characters; ++offset) {
            if ([name characterAtIndex:offset] == 0) return 3;
        }
        const char *path = [url fileSystemRepresentation];
        size_t length = path ? strnlen(path, 4097) : 0;
        if (!length || length > 4096 || path[0] != '/') return 3;
        memcpy(s->selectedImages[index], path, length + 1);
    }
    s->imageCount = (size_t)count; return 1;
}
static int mrk_panel_initial_directory(MRKInstalledPanel *s, const uint8_t *bytes, size_t length) {
    int result = EIO;
#ifdef MRK_INSTALLED_OBSERVATION
    BOOL observed = (s->observationIdentity.flags & MRK_ID_ARMED) != 0;
    if (observed) { s->observationIdentity.site = MRK_ID_DIRECTORY_URL; s->observationIdentity.error = MRK_OPEN_INPUT; }
#endif
    @try {
        s->initialPath = [[NSString alloc] initWithBytes:bytes length:length encoding:NSUTF8StringEncoding];
        if (!s->initialPath) result = EINVAL;
        else {
            s->initialDirectory = [[NSURL alloc] initFileURLWithPath:s->initialPath isDirectory:YES];
            if (s->initialDirectory && [s->initialDirectory isFileURL]) {
#ifdef MRK_INSTALLED_OBSERVATION
                memcpy(s->observationInitialRoot, bytes, length);
                s->observationInitialRoot[length] = 0;
                if (observed) {
                    s->observationIdentity.site = MRK_ID_DIRECTORY_SET;
                    s->observationIdentity.flags |= MRK_ID_DIRECTORY_ENTERED;
                }
#endif
                [(NSOpenPanel *)s->window setDirectoryURL:s->initialDirectory];
#ifdef MRK_INSTALLED_OBSERVATION
                s->observationDirectoryReturned = YES;
                if (observed) s->observationIdentity.flags |= MRK_ID_DIRECTORY_RETURNED;
#endif
                result = 0;
            }
        }
    } @catch (NSException *e) {
        (void)e; s->unknown = YES; result = EIO;
#ifdef MRK_INSTALLED_OBSERVATION
        if (observed) s->observationIdentity.error = MRK_OPEN_EXCEPTION;
#endif
    }
    // Independent one-use releases; an uncertain first close cannot suppress
    // the other safe close or erase either original pointer.
    @try { if (s->initialDirectory) { [s->initialDirectory release]; s->initialDirectory = nil; } }
    @catch (NSException *e) {
        (void)e; s->unknown = YES; result = EIO;
#ifdef MRK_INSTALLED_OBSERVATION
        if (observed) { s->observationIdentity.site = MRK_ID_INITIAL_CLOSE; s->observationIdentity.error = MRK_OPEN_CLEANUP_UNKNOWN; }
#endif
    }
    @try { if (s->initialPath) { [s->initialPath release]; s->initialPath = nil; } }
    @catch (NSException *e) {
        (void)e; s->unknown = YES; result = EIO;
#ifdef MRK_INSTALLED_OBSERVATION
        if (observed) { s->observationIdentity.site = MRK_ID_INITIAL_CLOSE; s->observationIdentity.error = MRK_OPEN_CLEANUP_UNKNOWN; }
#endif
    }
    return result;
}
static int mrk_panel_start_inner(void *opaque, int kind, const uint8_t *initial, size_t length) {
    if (!pthread_main_np() || !opaque || (!mrk_panel_open_kind(kind) && kind != 2)) return EINVAL;
    if (mrk_panel_project_field(kind)) {
        if (!initial || !length || length > 4096 || initial[0] != '/' || memchr(initial, 0, length)) return EINVAL;
    } else if (initial || length) return EINVAL;
    MRKInstalledPanel *s = opaque;
    if (s->attempted || s->unknown) return EALREADY;
    s->attempted = YES; s->kind = kind;
    @try {
        // An original reservation cannot switch between singleton and batch.
        // Check before creating/retaining the native parent or window.
        if ((kind == 9) != [s isKindOfClass:[MRKInstalledImagePanel class]]) return EINVAL;
        // This application has exactly one normal window; never attach to a
        // picker, another sheet or a renderer-supplied object/path.
        NSWindow *main = [NSApp mainWindow];
        if (!main || [main isKindOfClass:[NSPanel class]] || [main attachedSheet]) return EPERM;
        s->started = YES;
        s->parent = [main retain];
        if (mrk_panel_open_kind(kind)) {
            NSOpenPanel *panel = [NSOpenPanel openPanel]; s->window = [panel retain];
            NSString *title = kind == 1 ? @"Choose a mobile project folder" : kind == 8 ? @"Choose a release evidence folder"
                : kind == 10 ? @"Choose an installed Java 17 JDK folder"
                : kind == 11 ? @"Choose the Android SDK folder"
                : kind == 12 ? @"Choose an extracted Gradle distribution folder"
                : kind == 9 ? @"Choose up to 10 public PNG or JPEG listing images"
                : kind == 3 ? @"Choose a signing or iOS build-input file"
                : kind == 4 ? @"Choose an existing version source inside the project" : kind == 5 ? @"Choose an existing Xcode project directory"
                : kind == 6 ? @"Choose an existing Xcode workspace directory" : @"Choose an existing metadata directory inside the project";
            [panel setTitle:title];
            // The message displays the purpose inside the sheet; its window title may not.
            [panel setMessage:title];
            [panel setCanChooseFiles:kind == 3 || kind == 4 || kind == 9];
            [panel setCanChooseDirectories:kind == 1 || kind == 8 || (kind >= 5 && kind <= 7) || (kind >= 10 && kind <= 12)];
            [panel setAllowsMultipleSelection:kind == 9]; [panel setCanCreateDirectories:NO];
            [panel setResolvesAliases:NO]; [panel setTreatsFilePackagesAsDirectories:(kind >= 5 && kind <= 7) || kind == 10];
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
        // This production setter is shared by observed and ordinary P2. Its
        // sole source is the original binding. In the instrumented path the
        // existing parent/prompt tags precede it, preserving the same ordered
        // partial-return decoder as Project/File. No observation setter is used.
        if (mrk_panel_project_field(kind)) {
            int configured = mrk_panel_initial_directory(s, initial, length);
            if (configured != 0 || s->unknown) { s->unknown = YES; return EIO; }
#ifdef MRK_INSTALLED_OBSERVATION
            if (s->observationIdentity.flags & MRK_ID_ARMED) {
                s->observationIdentity.flags |= MRK_ID_CONFIG_COMPLETE;
                s->observationIdentity.site = MRK_ID_COMPLETE;
                s->observationIdentity.error = MRK_OPEN_NONE;
            }
#endif
        }
        // The original state is retained by the copied native completion. No
        // raw Rust callback or path publication can outlive the real document.
        s->completion = Block_copy(^(NSModalResponse code) {
#ifdef MRK_INSTALLED_OBSERVATION
            BOOL observed = (s->observationIdentity.flags & MRK_ID_ARMED) != 0;
            if (observed) {
                if (s->observationCompletion.flags & MRK_COMPLETION_ENTERED) {
                    // Duplicate/reentrant callbacks cannot re-read URLs or
                    // overwrite the first response/path/selection witness.
                    s->observationCompletion.flags |= MRK_COMPLETION_DUPLICATE;
                    s->unknown = YES; return;
                }
                s->observationCompletion.flags |= MRK_COMPLETION_ENTERED;
            }
#endif
            s->callbackActive = YES;
            @try {
                if (s->responded) { s->unknown = YES; }
                else {
                    // closeAttempted was recorded BEFORE any programmatic
                    // endSheet/close. Its Cancel-shaped callback remains Other.
                    s->response = mrk_panel_response(kind, code, s->closeAttempted);
#ifdef MRK_INSTALLED_OBSERVATION
                    if (observed) s->observationCompletion.response = s->response == 1 ? MRK_COMPLETION_ACCEPT
                        : s->response == 2 ? MRK_COMPLETION_DECLINE : MRK_COMPLETION_OTHER;
#endif
                    if (s->response == 1 && kind == 9) {
                        MRKInstalledImagePanel *images = (MRKInstalledImagePanel *)s;
                        images->imageSelection = mrk_panel_selected_images(images);
                        if (images->imageSelection != 1) {
                            // Known input refusal keeps the genuine Accept. No
                            // partial batch escapes and ordinary cleanup remains possible.
                            images->imageCount = 0; memset(images->selectedImages, 0, sizeof(images->selectedImages));
                        }
                    } else if (s->response == 1 && mrk_panel_open_kind(kind)) {
                        NSURL *url = [(NSOpenPanel *)s->window URL];
                        const char *path = url && [url isFileURL] ? [url fileSystemRepresentation] : NULL;
                        if (!path || path[0] != '/' || strnlen(path, sizeof(s->selected)) >= sizeof(s->selected)) s->unknown = YES;
                        else memcpy(s->selected, path, strlen(path) + 1);
#ifdef MRK_INSTALLED_OBSERVATION
                        // The ordinary URL/path copy above stays authoritative
                        // and unchanged. This separate witness never writes it.
                        if (observed) mrk_panel_completion_selection(s);
#endif
                    }
                    s->responded = YES;
                }
            } @catch (NSException *e) { (void)e; s->unknown = YES; }
#ifdef MRK_INSTALLED_OBSERVATION
            if (observed) s->observationCompletion.flags |= MRK_COMPLETION_RETURNED;
#endif
            // No native call/run-loop pumping after this final completion fact.
            s->callbackActive = NO;
        });
        if (mrk_panel_open_kind(kind)) [(NSOpenPanel *)s->window beginSheetModalForWindow:s->parent completionHandler:s->completion];
        else [s->alert beginSheetModalForWindow:s->parent completionHandler:s->completion];
        return 0;
    } @catch (NSException *e) { (void)e; s->unknown = YES; return EIO; }
}
int mrk_panel_start(void *opaque, int kind) {
    if (mrk_panel_project_field(kind)) return EINVAL;
    return mrk_panel_start_inner(opaque, kind, NULL, 0);
}
int mrk_panel_start_project_field(void *opaque, int kind, const uint8_t *initial, size_t length) {
    if (!mrk_panel_project_field(kind)) return EINVAL;
    return mrk_panel_start_inner(opaque, kind, initial, length);
}
int mrk_panel_poll(void *opaque, int *result, uint8_t *path, size_t capacity) {
    if (!pthread_main_np() || !opaque || !result || !path || capacity != 4097) return -1;
    MRKInstalledPanel *s = opaque;
    if (s->unknown || s->kind == 9) return -1;
    @try {
        if ([s isKindOfClass:[MRKInstalledImagePanel class]]) return -1;
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
int mrk_panel_poll_images(void *opaque, int *result, int *selection, size_t *count, uint8_t *paths, size_t capacity) {
    if (!pthread_main_np() || !opaque || !result || !selection || !count || !paths || capacity != 10 * 4097) return -1;
    *result = 0; *selection = 0; *count = 0; memset(paths, 0, capacity);
    MRKInstalledPanel *s = opaque;
    if (s->unknown) return -1;
    @try {
        // Even STOP-before-start uses the exact purpose9 reservation. An empty
        // singleton is not an image original and cannot cross this entry point.
        if (![s isKindOfClass:[MRKInstalledImagePanel class]]) return -1;
        MRKInstalledImagePanel *images = (MRKInstalledImagePanel *)s;
        if (s->kind != 9) {
            if (s->kind || s->attempted || s->started || s->responded || s->reported || s->callbackActive
                || s->window || s->parent || s->alert || s->completion || s->initialPath || s->initialDirectory
                || images->imageSelection || images->imageCount) return -1;
            return s->closed ? 2 : 0;
        }
        if (s->closed) return 2;
        if (s->responded && !s->reported && !s->callbackActive) {
            s->reported = YES;
            *result = s->response; *selection = images->imageSelection; *count = images->imageCount;
            memcpy(paths, images->selectedImages, sizeof(images->selectedImages)); return 1;
        }
        if (s->closeAttempted && s->responded && !s->callbackActive && ![s->window isVisible] && ![s->window sheetParent]) {
            s->closed = YES; return 2;
        }
        // Unlike historical singleton polling, never publish the batch again
        // while its same original close is pending. The coordinator owns it.
        return 0;
    } @catch (NSException *e) { (void)e; s->unknown = YES; return -1; }
}
int mrk_panel_close(void *opaque) {
    if (!pthread_main_np() || !opaque) return EINVAL;
    MRKInstalledPanel *s = opaque;
    if (s->closeAttempted) return EALREADY;
    s->closeAttempted = YES;
    @try {
        if (!s->started && !s->window && !s->parent && !s->alert && !s->completion
            && !s->initialPath && !s->initialDirectory) { s->closed = YES; return 0; }
        if (!s->responded && s->window && [s->window sheetParent]) [s->parent endSheet:s->window returnCode:NSModalResponseCancel];
        if (s->window) { [s->window orderOut:nil]; [s->window close]; }
        return s->unknown ? EIO : 0;
    } @catch (NSException *e) { (void)e; s->unknown = YES; return EIO; }
}
int mrk_panel_release(void *opaque) {
    if (!pthread_main_np() || !opaque) return EINVAL;
    MRKInstalledPanel *s = opaque;
    if (s->unknown || s->callbackActive || !s->closed || s->initialPath || s->initialDirectory) return EBUSY;
#ifdef MRK_INSTALLED_OBSERVATION
    if (s->observationFieldName) return EBUSY;
#endif
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
static BOOL mrk_target_path(const char *path) {
    size_t length = strnlen(path, 4097);
    if (!length || length > 4096 || path[0] != '/') return NO;
    if (length == 1) return YES;
    for (size_t start = 1, end = 1; end <= length; ++end) {
        if (end != length && path[end] != '/') continue;
        size_t count = end - start;
        if (!count || count > 255 || (count == 1 && path[start] == '.')
            || (count == 2 && path[start] == '.' && path[start + 1] == '.')) return NO;
        start = end + 1;
    }
    return YES;
}
static void mrk_panel_completion_selection(MRKInstalledPanel *s) {
    MRKCompletionWire *d = &s->observationCompletion;
    if (d->flags & MRK_COMPLETION_URLS_ENTERED) {
        d->flags |= MRK_COMPLETION_DUPLICATE; s->unknown = YES; return;
    }
    // At most one observation-only URLs read, in the genuine armed OK callback.
    // Latch return BEFORE classification; an exception preserves partial history
    // and reaches the same original completion catch/Unknown path.
    d->flags |= MRK_COMPLETION_URLS_ENTERED;
    id urls = [(NSOpenPanel *)s->window URLs];
    d->flags |= MRK_COMPLETION_URLS_RETURNED;
    if (!urls) d->selection = MRK_SELECTION_EMPTY;
    else if (![urls isKindOfClass:[NSArray class]]) d->selection = MRK_SELECTION_MALFORMED;
    else {
        NSUInteger count = [urls count];
        if (!count) d->selection = MRK_SELECTION_EMPTY;
        else if (count != 1) d->selection = MRK_SELECTION_MULTIPLE;
        else {
            id url = [urls objectAtIndex:0];
            const char *path = [url isKindOfClass:[NSURL class]] && [url isFileURL] ? [url fileSystemRepresentation] : NULL;
            d->selection = !path || !mrk_target_path(path) ? MRK_SELECTION_MALFORMED
                : strcmp(path, s->observationTarget) != 0 ? MRK_SELECTION_DIFFERENT
                : strcmp(path, s->selected) != 0 ? MRK_SELECTION_DISAGREES : MRK_SELECTION_MATCH;
        }
    }
    // Known nonmatches are failed selection DATA, not unknown native lifetime.
    // Never clear an existing Unknown, change the response, or insert a path.
}
// Closed DATA from the original readiness evaluation, never an action receipt.
// Tag2 is kind-specific: File name text, VersionSource actual selected URLs.
// Missing/non-file/overlong values never match; no path is exposed.
enum { MRK_DIRECTORY_NOT_READY, MRK_DIRECTORY_NOT_MATCHED, MRK_FILE_NOT_MATCHED, MRK_DIRECTORY_READY };
enum { MRK_VERSION_SOURCE_PARENT_READY = 1u << 19, MRK_VERSION_SOURCE_SELECTION_READY = 1u << 20 };
enum { MRK_NAME_PHASE_ENTERED = 1u, MRK_NAME_PARENT_ADMITTED = 2u,
    MRK_NAME_SET_ENTERED = 4u, MRK_NAME_SET_RETURNED = 8u, MRK_NAME_RETIRED = 16u, MRK_NAME_ALL = 31u };
// Scalar original-state check only. No additional directory/filename query.
static BOOL mrk_version_source_name_state(MRKInstalledPanel *s, uint32_t sample, uint32_t phase) {
    return s->kind == 4 && s->started && s->parent && s->window && s->completion
        && !s->unknown && !s->responded && !s->callbackActive && !s->closeAttempted && !s->closed && !s->selected[0]
        && !s->observationActionAttempted && !s->observationActionReturned
        && !s->initialPath && !s->initialDirectory && s->observationDirectoryReturned
        && s->observationProjectField == 6143u && s->observationNamePhase == phase
        && sample && s->observationSample == sample
        && mrk_target_path(s->observationInitialRoot) && mrk_target_path(s->observationTarget)
        && (s->observationIdentity.flags & (MRK_ID_ARMED | MRK_ID_CONFIG_COMPLETE)) == (MRK_ID_ARMED | MRK_ID_CONFIG_COMPLETE);
}
static BOOL mrk_observation_directory_ready(MRKInstalledPanel *s, uint32_t *readiness, BOOL *versionSourceParentReady, BOOL *selectionReady) {
    if (readiness) *readiness = MRK_DIRECTORY_NOT_READY;
    if (versionSourceParentReady) *versionSourceParentReady = NO;
    if (selectionReady) *selectionReady = NO;
    // Actual pre-presentation setter return + current ROOT browsing, not selection.
    if (!mrk_panel_open_kind(s->kind) || !s->window || !s->observationDirectoryReturned
        || !mrk_target_path(s->observationTarget)) return NO;
    // P2's actual displayed initial root is observed before the separate,
    // one-use synthetic navigation. Neither substitutes for the other.
    if (mrk_panel_project_field(s->kind) && !(s->observationProjectField & 1024u)) return NO;
    NSURL *url = [(NSOpenPanel *)s->window directoryURL];
    const char *path = url && [url isFileURL] ? [url fileSystemRepresentation] : NULL;
    // Preserve the original Project proof. Only file-like panels need the
    // parent transformation and their additional readiness getters.
    if (s->kind != 3 && s->kind != 4) {
        BOOL ready = path && strnlen(path, sizeof(s->observationTarget)) < sizeof(s->observationTarget)
            && strcmp(path, s->observationTarget) == 0;
        if (readiness) *readiness = ready ? MRK_DIRECTORY_READY : MRK_DIRECTORY_NOT_MATCHED;
        return ready;
    }
    NSString *target = [NSString stringWithUTF8String:s->observationTarget];
    NSString *directory = [target stringByDeletingLastPathComponent];
    const char *expected = [directory fileSystemRepresentation];
    // Split only the existing short circuit, in the same getter/predicate order.
    if (!(path && expected && strnlen(path, sizeof(s->observationTarget)) < sizeof(s->observationTarget)
        && strcmp(path, expected) == 0)) {
        if (readiness) *readiness = MRK_DIRECTORY_NOT_MATCHED;
        return NO;
    }
    // This intermediate fact permits only the separate one-use name phase.
    // It is never full readiness, and it comes from the same comparison above.
    if (versionSourceParentReady && s->kind == 4 && s->observationProjectField == 6143u
        && !s->observationNamePhase) *versionSourceParentReady = YES;
    if (!(s->kind == 4 ? s->observationNamePhase == MRK_NAME_ALL
        : (s->observationIdentity.flags & (MRK_ID_NAME_ENTERED | MRK_ID_NAME_RETURNED)) == (MRK_ID_NAME_ENTERED | MRK_ID_NAME_RETURNED))) return NO;
    if (selectionReady && s->kind == 4 && s->observationProjectField == 6143u
        && s->observationNamePhase == MRK_NAME_ALL && !s->observationSelectionBound) *selectionReady = YES;
    BOOL ready = NO;
    if (s->kind == 4) {
        // The inherited save-name setter is preparation, not selection proof.
        // Borrow only this original panel's actual selected URLs. No object or
        // path survives this query; genuine completion still validates anew.
        id urls = [(NSOpenPanel *)s->window URLs];
        if (urls && [urls isKindOfClass:[NSArray class]] && [urls count] == 1) {
            id selected = [urls objectAtIndex:0];
            const char *selectedPath = [selected isKindOfClass:[NSURL class]] && [selected isFileURL]
                ? [selected fileSystemRepresentation] : NULL;
            ready = selectedPath && mrk_target_path(selectedPath) && strcmp(selectedPath, s->observationTarget) == 0;
        }
    } else {
        // The distinct kind3 pre-presentation File contract is unchanged.
        ready = [[(NSOpenPanel *)s->window nameFieldStringValue] isEqualToString:[target lastPathComponent]];
    }
    if (readiness) *readiness = ready ? MRK_DIRECTORY_READY : MRK_FILE_NOT_MATCHED;
    return ready;
}
// Only selection admission uses this predicate. It never claims file-ready or
// replaces either full Open proof; the original target/31 history remain fixed.
static BOOL mrk_observation_selection_parent(MRKInstalledPanel *s) {
    if (s->kind != 4 || !s->observationSelectionBound || !s->observationDirectoryReturned
        || s->observationProjectField != 6143u || s->observationNamePhase != MRK_NAME_ALL
        || !mrk_target_path(s->observationTarget)) return NO;
    NSURL *url = [(NSOpenPanel *)s->window directoryURL];
    const char *path = url && [url isFileURL] ? [url fileSystemRepresentation] : NULL;
    NSString *target = [NSString stringWithUTF8String:s->observationTarget];
    const char *parent = [[target stringByDeletingLastPathComponent] fileSystemRepresentation];
    return path && parent && mrk_target_path(path) && strcmp(path, parent) == 0;
}
int mrk_panel_observe(void *opaque, int *kind, uint32_t *flags, int *response, uint8_t *path, size_t capacity, uint32_t *nameSample) {
    if (!pthread_main_np() || !opaque || !kind || !flags || !response || !path || capacity != 4097 || !nameSample) return EINVAL;
    MRKInstalledPanel *s = opaque; *nameSample = 0;
    // Every existing original observation invalidates any older parent sample.
    s->observationParentSample = 0; s->observationSelectionSample = 0;
    if (s->unknown) return EIO;
    if (s->kind == 4) {
        if (s->observationSample == UINT32_MAX) { s->unknown = YES; return EOVERFLOW; }
        ++s->observationSample; // Bounded comparison DATA, never a new poll/owner.
    }
    @try {
        // Closed twenty-one-bit ABI with the Rust PanelObservation decoder. Reads
        // do not set reported, manufacture completion, or authorize retirement.
        uint32_t attachment = mrk_observation_attachment(s);
        uint32_t readiness = MRK_DIRECTORY_NOT_READY; BOOL parentReady = NO, selectionReady = NO;
        *kind = s->kind; *response = s->response;
        *flags = attachment | (s->started ? 1u : 0u) | (attachment == MRK_ATTACHMENT_ALL ? 2u : 0u)
            | (s->observationTarget[0] || s->observationInitialRoot[0] ? 4u : 0u) | (s->observationDirectoryReturned ? 8u : 0u)
            | (mrk_observation_directory_ready(s, &readiness, &parentReady, &selectionReady) ? 16u : 0u) | (s->observationActionAttempted ? 32u : 0u)
            | (s->observationActionReturned ? 64u : 0u) | (s->responded ? 128u : 0u)
            | (s->responded && !s->callbackActive ? 256u : 0u) | (s->closeAttempted ? 512u : 0u)
            | (s->window && ![s->window isVisible] && ![s->window sheetParent] ? 1024u : 0u)
            | (s->closed ? 2048u : 0u);
        // Sequence the tag read AFTER the helper writes it in the expression above.
        *flags |= readiness << 17;
        if (parentReady && *flags == 0x1f00fu && !s->observationFieldName
            && mrk_version_source_name_state(s, s->observationSample, 0)) {
            *flags |= MRK_VERSION_SOURCE_PARENT_READY;
            s->observationParentSample = s->observationSample;
            *nameSample = s->observationParentSample;
        }
        if (selectionReady && (*flags == 0x5f00fu || *flags == 0x7f01fu)
            && !s->observationFieldName && !s->observationSelectionBound
            && mrk_version_source_name_state(s, s->observationSample, MRK_NAME_ALL)) {
            *flags |= MRK_VERSION_SOURCE_SELECTION_READY;
            s->observationSelectionSample = s->observationSample;
            *nameSample = s->observationSelectionSample;
        }
        memcpy(path, s->selected, sizeof(s->selected)); return 0;
    } @catch (NSException *e) {
        (void)e; s->observationParentSample = 0; s->observationSelectionSample = 0; *nameSample = 0; s->unknown = YES; return EIO;
    }
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
    MRK_ACTION_PROJECT_CANCEL, MRK_ACTION_PROJECT_OPEN, MRK_ACTION_QUIT_CANCEL, MRK_ACTION_QUIT_CONFIRM, MRK_ACTION_FILE_CANCEL
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
    site = MRK_ACTION_CODE; if (action != 1 && action != 4 && action != 5 && action != 6) MRK_ACTION_RETURN(EINVAL);
    site = MRK_ACTION_ARGUMENT; if (directory != NULL) MRK_ACTION_RETURN(EINVAL);
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
    if ((action <= 3 && s->kind != 1 && !(s->kind >= 5 && s->kind <= 7))
        || ((action == 4 || action == 5) && s->kind != 2) || (action == 6 && s->kind != 3 && s->kind != 4)) MRK_ACTION_RETURN(EPERM);
    @try {
        // EAGAIN is only pre-action readiness, never permission to repeat an
        // attempted action. The caller's original endpoint is not renewed.
        site = MRK_ACTION_ATTACHMENT; if (!mrk_observation_attached(s)) MRK_ACTION_RETURN(EAGAIN);
        NSButton *button = nil;
        if (action == 4 || action == 5) {
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
        if (action == 1 || action == 6) { site = action == 1 ? MRK_ACTION_PROJECT_CANCEL : MRK_ACTION_FILE_CANCEL; [(NSOpenPanel *)s->window cancel:nil]; }
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

// Observation-only preparation of one real P2 panel. The production initial
// directory/options are sampled while visible/attached BEFORE any navigation.
// This never creates a panel, publishes selection, or invokes its completion.
// Bits0..8 are the latched initial proof;9/10 navigation entry/return;11 name
// return;12 all same-call temporary closes returned. The native original owns
// the latch and conversion pointers; an uncertain entered call is not retried.
// Public getter DATA from the same original initial-options call. No UTI
// strings, enumeration, setters or retained native objects leave this scope.
static BOOL mrk_panel_observe_file_filter(MRKInstalledPanel *s, NSOpenPanel *panel) {
    if (s->kind != 4) return YES;
    if (s->observationFileFilter) return NO;
    s->observationFileFilter = 1u;
    id types = [panel allowedContentTypes];
    s->observationFileFilter |= 2u;
    if (types && ![types isKindOfClass:[NSArray class]]) return NO;
    s->observationFileFilter |= !types || [types count] == 0 ? 4u : 8u;
    BOOL other = [panel allowsOtherFileTypes];
    s->observationFileFilter |= 16u | (other ? 32u : 0u);
    return YES;
}
int mrk_panel_observe_project_field(void *opaque, int navigate, uint32_t *facts, uint32_t *filter) {
    if (!pthread_main_np() || !opaque || !facts || !filter || (navigate != 0 && navigate != 1)) return EINVAL;
    MRKInstalledPanel *s = opaque; *facts = s->observationProjectField; *filter = s->observationFileFilter;
    if (s->unknown) return EIO;
    if (!mrk_panel_project_field(s->kind) || !s->started || !s->parent || !s->window || !s->completion
        || s->responded || s->callbackActive || s->closeAttempted || s->closed || s->observationActionAttempted
        || s->observationActionReturned || s->initialPath || s->initialDirectory || s->observationFieldName
        || !s->observationDirectoryReturned || !mrk_target_path(s->observationInitialRoot)) return EPERM;
    if (s->observationProjectField) return EALREADY;
    if (navigate && (!mrk_target_path(s->observationTarget)
        || (s->observationIdentity.flags & (MRK_ID_ARMED | MRK_ID_CONFIG_COMPLETE)) != (MRK_ID_ARMED | MRK_ID_CONFIG_COMPLETE))) return EPERM;
    int result = EIO;
    @try {
        if (!mrk_observation_attached(s)) return EAGAIN; // No attempted proof or setter yet.
        s->observationProjectField = 1u | 256u;
        NSOpenPanel *panel = (NSOpenPanel *)s->window;
        NSURL *url = [panel directoryURL];
        const char *path = url && [url isFileURL] ? [url fileSystemRepresentation] : NULL;
        if (path && strnlen(path, 4097) < 4097 && strcmp(path, s->observationInitialRoot) == 0) s->observationProjectField |= 2u;
        if ([panel canChooseFiles] == (s->kind == 4)) s->observationProjectField |= 4u;
        if ([panel canChooseDirectories] == (s->kind >= 5)) s->observationProjectField |= 8u;
        if ([panel treatsFilePackagesAsDirectories] == (s->kind >= 5)) s->observationProjectField |= 16u;
        if (![panel allowsMultipleSelection]) s->observationProjectField |= 32u;
        if (![panel canCreateDirectories]) s->observationProjectField |= 64u;
        if (![panel resolvesAliases]) s->observationProjectField |= 128u;
        if (s->observationProjectField != 511u || !mrk_panel_observe_file_filter(s, panel)) result = EPERM;
        else if (!navigate) result = 0;
        else {
            size_t length = strlen(s->observationTarget);
            const char *leaf = s->kind == 4 ? strrchr(s->observationTarget, '/') + 1 : NULL;
            size_t directoryLength = leaf ? (size_t)(leaf - s->observationTarget - 1) : length;
            if (!directoryLength) directoryLength = 1;
            s->initialPath = [[NSString alloc] initWithBytes:s->observationTarget length:directoryLength encoding:NSUTF8StringEncoding];
            if (s->initialPath) s->initialDirectory = [[NSURL alloc] initFileURLWithPath:s->initialPath isDirectory:YES];
            if (s->initialDirectory && [s->initialDirectory isFileURL]) {
                s->observationProjectField |= 512u;
                [panel setDirectoryURL:s->initialDirectory];
                s->observationProjectField |= 1024u;
                result = 0;
            }
        }
    } @catch (NSException *e) { (void)e; s->unknown = YES; result = EIO; }
    @try { if (s->initialDirectory) { [s->initialDirectory release]; s->initialDirectory = nil; } }
    @catch (NSException *e) { (void)e; s->unknown = YES; result = EIO; }
    @try { if (s->initialPath) { [s->initialPath release]; s->initialPath = nil; } }
    @catch (NSException *e) { (void)e; s->unknown = YES; result = EIO; }
    if (!s->unknown && !s->initialDirectory && !s->initialPath && !s->observationFieldName) s->observationProjectField |= 4096u;
    *facts = s->observationProjectField; *filter = s->observationFileFilter; return result;
}

int mrk_panel_observe_version_source_name(void *opaque, uint32_t sample, uint32_t *facts) {
    if (!pthread_main_np() || !opaque || !facts) return EINVAL;
    MRKInstalledPanel *s = opaque; *facts = s->observationNamePhase;
    uint32_t granted = s->observationParentSample;
    s->observationParentSample = 0; // Consume once, including a refused/stale call.
    if (s->unknown) return EIO;
    if (s->observationNamePhase) return EALREADY;
    if (!sample || sample != granted || s->observationFieldName
        || !mrk_version_source_name_state(s, sample, 0)) return EPERM;
    s->observationNamePhase = MRK_NAME_PHASE_ENTERED;
    int result = EPERM;
    @try {
        // Same original attachment recheck, not another directory getter.
        // Refusal after phase entry is terminal; it is never an EAGAIN retry.
        if (mrk_observation_attached(s) && mrk_version_source_name_state(s, sample, MRK_NAME_PHASE_ENTERED)) {
            s->observationNamePhase |= MRK_NAME_PARENT_ADMITTED;
            const char *leaf = strrchr(s->observationTarget, '/') + 1;
            if (*leaf) s->observationFieldName = [[NSString alloc] initWithBytes:leaf length:strlen(leaf) encoding:NSUTF8StringEncoding];
            if (s->observationFieldName && mrk_version_source_name_state(s, sample, MRK_NAME_PHASE_ENTERED | MRK_NAME_PARENT_ADMITTED)) {
                s->observationNamePhase |= MRK_NAME_SET_ENTERED;
                [(NSOpenPanel *)s->window setNameFieldStringValue:s->observationFieldName];
                s->observationNamePhase |= MRK_NAME_SET_RETURNED;
                result = 0;
            } else result = EIO;
        }
    } @catch (NSException *e) { (void)e; s->unknown = YES; result = EIO; }
    @try { if (s->observationFieldName) { [s->observationFieldName release]; s->observationFieldName = nil; } }
    @catch (NSException *e) { (void)e; s->unknown = YES; result = EIO; }
    // Retain known consuming cleanup even after another phase failed. It cannot
    // erase Unknown or turn a partial/failed setter into a successful phase.
    if (!s->observationFieldName) s->observationNamePhase |= MRK_NAME_RETIRED;
    if (result == 0 && !mrk_version_source_name_state(s, sample, MRK_NAME_ALL)) { s->unknown = YES; result = EIO; }
    *facts = s->observationNamePhase; return result;
}

// Main-only original proof and off-main public AX input have separate ABIs.
// Only copied bounded identity/control DATA crosses threads; never an AppKit object.
enum { MRK_OPEN_ENTRY = 1u, MRK_OPEN_APPLICATION, MRK_OPEN_WINDOWS, MRK_OPEN_PARENT_ID,
    MRK_OPEN_SHEET, MRK_OPEN_TOPOLOGY, MRK_OPEN_CONTROL_PROJECTION, MRK_OPEN_BUTTON, MRK_OPEN_CONTROL_RECHECK,
    MRK_OPEN_INITIAL_PROOF, MRK_OPEN_FINAL_PROOF, MRK_OPEN_ADMISSION, MRK_OPEN_PRESS, MRK_OPEN_CLEANUP,
    MRK_OPEN_CONTROL_TITLE_LIMIT, MRK_OPEN_CONTROL_CHILD_COUNT_LIMIT, MRK_OPEN_CONTROL_CHILD_COPY_LIMIT,
    MRK_OPEN_CONTROL_NODE_LIMIT, MRK_OPEN_CONTROL_DEPTH_LIMIT,
    MRK_OPEN_SELECTION_PARENT, MRK_OPEN_SELECTION_PROJECTION, MRK_OPEN_SELECTION_RECHECK,
    MRK_OPEN_SELECTION_SETTABLE, MRK_OPEN_SELECTION_WRITE, MRK_OPEN_SELECTION_READBACK };
enum { MRK_OPEN_ATTEMPTED = 1u, MRK_OPEN_RETURNED = 2u, MRK_OPEN_TRIGGERED = 4u, MRK_OPEN_KNOWN = 8u };
enum { MRK_ROLE_NOT_READ, MRK_ROLE_SHEET, MRK_ROLE_GROUP, MRK_ROLE_SPLIT_GROUP, MRK_ROLE_BUTTON,
    MRK_ROLE_BROWSER, MRK_ROLE_TABLE, MRK_ROLE_OUTLINE, MRK_ROLE_SCROLL_AREA, MRK_ROLE_OPAQUE };
// Closed first-fault diagnostics only; these scalar tags never authorize an AX call.
enum { MRK_AX_OP_NONE = 0, MRK_AX_OP_SET_MESSAGING_TIMEOUT = 1, MRK_AX_OP_COPY_ATTRIBUTE_VALUE = 2,
    MRK_AX_OP_GET_ATTRIBUTE_VALUE_COUNT = 3, MRK_AX_OP_COPY_ATTRIBUTE_VALUES = 4, MRK_AX_OP_COPY_ACTION_NAMES = 5,
    MRK_AX_OP_IS_ATTRIBUTE_SETTABLE = 6, MRK_AX_OP_SET_ATTRIBUTE_VALUE = 7, MRK_AX_OP_PERFORM_ACTION = 8,
    MRK_AX_OP_COPY_MULTIPLE_ATTRIBUTE_VALUES = 9 };
enum { MRK_AX_ATTR_NONE = 0, MRK_AX_ATTR_PARENT = 1, MRK_AX_ATTR_ROLE = 2, MRK_AX_ATTR_IDENTIFIER = 3,
    MRK_AX_ATTR_TITLE = 4, MRK_AX_ATTR_VALUE = 5, MRK_AX_ATTR_ENABLED = 6, MRK_AX_ATTR_WINDOWS = 7,
    MRK_AX_ATTR_CHILDREN = 8, MRK_AX_ATTR_ROWS = 9, MRK_AX_ATTR_SELECTED_CHILDREN = 10, MRK_AX_ATTR_SELECTED_ROWS = 11 };
enum { MRK_SELECT_SAMPLES = 8, MRK_SELECT_PENDING = MRK_SELECT_SAMPLES - 1 };
// Each entry is immutable after its completed zero-match sample and sole wait.
// Opaque CF objects remain in the one original append-only ownership ledger.
typedef struct {
    uint32_t ordinal, calls_before, calls_after, cf_before, cf_after, nodes, depth, role,
        entries, fixture_mask, relations, checks, matches, flags, error, wait;
} MRKContentPending;
// One diagnostic at the first completed zero-match census; never selection authority.
typedef struct {
    uint32_t version, state, normal_fixture_mask, calls_before, calls_after, cf_before, cf_after,
        eligible_frontiers, attempted_frontiers, added_nodes, max_depth, alternate_value_mask,
        frontier_label_mask, outside_field_mask, alternate_role_mask, frontier_role_mask,
        unavailable, omissions, duplicates, non_string_values;
} MRKProjectionDiagnostic;
typedef struct { uint32_t flags, site, error, checks, calls, initial_nodes_examined, recheck_nodes_examined, owned, released;
    int32_t ax_error; uint32_t last_role, last_depth;
    uint32_t selection_mode, selection_checks, selection_flags, selection_nodes, selection_matches,
        selection_attribute, selection_last_role, selection_depth;
    // Zero predicate means no observed refusal; queued/children zero means
    // unreached (their observed domains start at one), never an observed zero.
    uint32_t selection_limit, selection_limit_cap, selection_limit_queued, selection_limit_children;
    int64_t selection_limit_observed;
    uint32_t ax_failure_operation, ax_failure_attribute;
    // Diagnostic-only roster observations: zero version is unentered, not an observed empty roster.
    uint32_t selection_summary_version, selection_table_roles, selection_outline_roles, selection_list_roles,
        selection_entry_roots, selection_title_present, selection_title_absent, selection_value_present,
        selection_outside_entry_role_mask, selection_fixture_label_mask, selection_expected_label_relations,
        selection_expected_label_role_mask;
    uint32_t selection_sample, selection_calls_before, selection_cf_before, selection_wait;
    MRKContentPending selection_pending[MRK_SELECT_PENDING];
    MRKProjectionDiagnostic selection_projection_diagnostic;
} MRKOpenResult;
typedef struct { uint32_t known, error, prompt; MRKIdentityProof proof; } MRKOpenRecheck;
_Static_assert(sizeof(MRKOpenResult) == 704 && sizeof(MRKOpenRecheck) == 48, "fixed original Press scalar ABI");
_Static_assert(sizeof(MRKProjectionDiagnostic) == 80 && offsetof(MRKOpenResult, selection_projection_diagnostic) == 624,
    "fixed first-zero projection diagnostic ABI");
_Static_assert(sizeof(MRKContentPending) == 64 && offsetof(MRKOpenResult, selection_sample) == 160
    && offsetof(MRKOpenResult, selection_pending) == 176, "fixed bounded content-readiness history ABI");
_Static_assert(sizeof(CFIndex) == sizeof(int64_t) && offsetof(MRKOpenResult, selection_limit_observed) == 96,
    "lossless original selection count ABI");
_Static_assert(offsetof(MRKOpenResult, ax_failure_operation) == 104 && offsetof(MRKOpenResult, ax_failure_attribute) == 108,
    "fixed first AX-fault diagnostic ABI");
_Static_assert(offsetof(MRKOpenResult, selection_summary_version) == 112
    && offsetof(MRKOpenResult, selection_table_roles) == 116
    && offsetof(MRKOpenResult, selection_outline_roles) == 120
    && offsetof(MRKOpenResult, selection_list_roles) == 124
    && offsetof(MRKOpenResult, selection_entry_roots) == 128
    && offsetof(MRKOpenResult, selection_title_present) == 132
    && offsetof(MRKOpenResult, selection_title_absent) == 136
    && offsetof(MRKOpenResult, selection_value_present) == 140
    && offsetof(MRKOpenResult, selection_outside_entry_role_mask) == 144
    && offsetof(MRKOpenResult, selection_fixture_label_mask) == 148
    && offsetof(MRKOpenResult, selection_expected_label_relations) == 152
    && offsetof(MRKOpenResult, selection_expected_label_role_mask) == 156,
    "fixed selection projection summary ABI");
typedef struct { float seconds; uint64_t required_ns; } MRKOpenTimeout;
typedef int (*MRKOpenAdmission)(void *, uint64_t, int, MRKOpenTimeout *);
typedef int (*MRKOpenRecheckCall)(void *, int);

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

int mrk_panel_observe_arm_open_identity(void *opaque, const uint8_t *target, size_t capacity) {
    if (!pthread_main_np() || !opaque || !target || capacity != 4097) return EINVAL;
    MRKInstalledPanel *s = opaque;
    if (s->attempted || s->unknown || s->observationIdentity.flags) return EALREADY;
    size_t length = strnlen((const char *)target, capacity);
    if (length < 2 || !mrk_target_path((const char *)target)) return EINVAL;
    for (size_t i = length; i < capacity; ++i) if (target[i]) return EINVAL;
    memcpy(s->observationTarget, target, capacity);
    s->observationIdentity.flags = MRK_ID_ARMED; // Passive bounded DATA copy; no AppKit message.
    return 0;
}
void mrk_panel_observe_identity_data(void *opaque, MRKIdentityWire *data) {
    // Used immediately after an original FFI return, while its retained Panel
    // is still borrowed. No usable()/AppKit query, release or ownership change.
    if (opaque && data) memcpy(data, &((MRKInstalledPanel *)opaque)->observationIdentity, sizeof(*data));
}
void mrk_panel_observe_completion_data(void *opaque, MRKCompletionWire *data) {
    // Immediately after an ACTUALLY returned original poll, including -1. This
    // is saved scalar DATA only, not another poll/read, retry or cleanup permit.
    if (opaque && data) {
        MRKInstalledPanel *s = opaque;
        memcpy(data, &s->observationCompletion, sizeof(*data));
        if (s->unknown) data->flags |= MRK_COMPLETION_UNKNOWN;
    }
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
    if (s->kind == 3) d->flags |= MRK_ID_FILE_PANEL;
    d->error = MRK_OPEN_INELIGIBLE;
    if (!s->parent || !s->window || !mrk_panel_open_kind(s->kind) || s->unknown || s->responded
        || s->callbackActive || s->closeAttempted || s->closed) return NO;
    @try {
        d->site = MRK_ID_TAGS; d->error = MRK_OPEN_INPUT;
        NSString *parentTag = [@"mrk-parent-" stringByAppendingString:[[NSUUID UUID] UUIDString]];
        if (![parentTag getCString:s->observationParentTag maxLength:64 encoding:NSASCIIStringEncoding]
            || !mrk_identity_tag(s->observationParentTag, "mrk-parent-")) return NO;
        // NSSavePanel.prompt identifies the real default Open button. This
        // observation-only short title is not identity/authentication authority.
        memcpy(s->observationPrompt, "MRK", 3);
        memcpy(s->observationPrompt + 3, s->observationParentTag + strlen("mrk-parent-"), 4);
        for (unsigned i = 3; i < 7; ++i)
            if (s->observationPrompt[i] >= 'a' && s->observationPrompt[i] <= 'f') s->observationPrompt[i] -= 'a' - 'A';
        NSString *prompt = [NSString stringWithCString:s->observationPrompt encoding:NSASCIIStringEncoding];
        if (!prompt) return NO;
        d->site = MRK_ID_PARENT_SET; d->flags |= MRK_ID_PARENT_ENTERED;
        [s->parent setAccessibilityIdentifier:parentTag];
        d->flags |= MRK_ID_PARENT_RETURNED;
        d->site = MRK_ID_PARENT_GET;
        d->parent = mrk_identity_class([s->parent accessibilityIdentifier], parentTag);
        d->site = MRK_ID_PROMPT_SET; d->flags |= MRK_ID_PROMPT_ENTERED;
        [(NSOpenPanel *)s->window setPrompt:prompt]; d->flags |= MRK_ID_PROMPT_RETURNED;
        d->site = MRK_ID_PROMPT_GET;
        d->prompt = mrk_identity_class([(NSOpenPanel *)s->window prompt], prompt);
        if (d->prompt != MRK_ID_MATCH) { d->error = MRK_OPEN_CHANGED; return NO; }
        if (mrk_panel_project_field(s->kind)) {
            // Do not navigate to the observation target. The SAME production
            // start now configures its original bound root exactly once, then
            // marks this ordered configuration complete before presentation.
            if (s->observationDirectoryReturned || s->observationInitialRoot[0]
                || (d->flags & (MRK_ID_DIRECTORY_ENTERED | MRK_ID_DIRECTORY_RETURNED))) return NO;
            return YES;
        }
        d->site = MRK_ID_DIRECTORY_URL; d->error = MRK_OPEN_INPUT;
        if (!mrk_target_path(s->observationTarget) || s->observationDirectoryReturned) return NO;
        NSString *target = [NSString stringWithUTF8String:s->observationTarget];
        NSString *directory = s->kind == 3 ? [target stringByDeletingLastPathComponent] : target;
        NSURL *url = directory ? [NSURL fileURLWithPath:directory isDirectory:YES] : nil;
        if (!url) return NO;
        // The one actual initial-directory setter precedes beginSheet. No late
        // navigation, row selection or inference that browsing is selection.
        d->site = MRK_ID_DIRECTORY_SET; d->flags |= MRK_ID_DIRECTORY_ENTERED;
        [(NSOpenPanel *)s->window setDirectoryURL:url];
        d->flags |= MRK_ID_DIRECTORY_RETURNED; s->observationDirectoryReturned = YES;
        if (s->kind == 3) {
            // Genuine file panel only, before beginSheet. Prefilling is not a
            // callback or selection: the exact singleton URL is checked later.
            d->site = MRK_ID_NAME_SET; d->flags |= MRK_ID_NAME_ENTERED;
            [(NSOpenPanel *)s->window setNameFieldStringValue:[target lastPathComponent]];
            d->flags |= MRK_ID_NAME_RETURNED; d->site = MRK_ID_NAME_GET;
            if (![[(NSOpenPanel *)s->window nameFieldStringValue] isEqualToString:[target lastPathComponent]]) {
                d->error = MRK_OPEN_CHANGED; return NO;
            }
        }
        // Only the parent identifier is set. No panel-identifier setter or
        // invented identifier return; that value is read at admitted preparation.
        d->flags |= MRK_ID_CONFIG_COMPLETE; d->site = MRK_ID_COMPLETE; d->error = MRK_OPEN_NONE;
        return YES;
    } @catch (NSException *e) {
        (void)e; d->error = MRK_OPEN_EXCEPTION;
        @throw; // The SAME original start catch records unknown/EIO.
    }
}
static BOOL mrk_original_eligible(MRKInstalledPanel *s) {
    return !s->unknown && s->started && mrk_panel_open_kind(s->kind) && s->parent && s->window && s->completion
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
static int mrk_original_proof(MRKInstalledPanel *s, MRKIdentityProof *p, BOOL freeze, BOOL selection_parent) {
    // Bit2 is a different authority domain, never a successful full Open proof.
    p->flags = selection_parent ? 3u : 1u; p->site = MRK_PROOF_OBJECTS; p->error = MRK_OPEN_INELIGIBLE;
    if (!mrk_proof_check(p, 0, mrk_original_eligible(s)
        && (!selection_parent || (s->kind == 4 && s->observationSelectionBound)), MRK_OPEN_INELIGIBLE)) return p->error;
    @try {
        p->site = MRK_PROOF_ATTACHMENT;
        if (!mrk_proof_check(p, 1, mrk_observation_attached(s), MRK_OPEN_INELIGIBLE)) return p->error;
        p->site = MRK_PROOF_DIRECTORY;
        if (!mrk_proof_check(p, 2, (selection_parent ? mrk_observation_selection_parent(s) : mrk_observation_directory_ready(s, NULL, NULL, NULL)), MRK_OPEN_INELIGIBLE)) return p->error;
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
        if (!mrk_proof_check(p, 2, (selection_parent ? mrk_observation_selection_parent(s) : mrk_observation_directory_ready(s, NULL, NULL, NULL)), MRK_OPEN_CHANGED)) return p->error;
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
static BOOL mrk_prompt_valid(const uint8_t *parent, const uint8_t *prompt) {
    if (!prompt || memcmp(prompt, "MRK", 3) || prompt[7]) return NO;
    for (unsigned i = 0; i < 4; ++i) {
        char c = parent[strlen("mrk-parent-") + i];
        if (c >= 'a' && c <= 'f') c -= 'a' - 'A';
        if (prompt[3 + i] != c) return NO;
    }
    return YES;
}
int mrk_panel_observe_open_identity(void *opaque, uint8_t *parent, uint8_t *panel, uint8_t *prompt, size_t capacity,
    uint8_t *target, size_t target_capacity, uint32_t selectionSample) {
    if (!pthread_main_np()) return MRK_OPEN_THREAD;
    if (!opaque || !parent || !panel || !prompt || capacity != 64 || !target || target_capacity != 4097) return MRK_OPEN_INPUT;
    memset(parent, 0, capacity); memset(panel, 0, capacity); memset(prompt, 0, 8);
    memset(target, 0, target_capacity);
    MRKInstalledPanel *s = opaque; MRKIdentityProof *p = &s->observationIdentity.binding;
    if (p->site) return MRK_OPEN_INELIGIBLE;
    BOOL selection = s->kind == 4;
    if (selection) {
        uint32_t original = s->observationSelectionSample;
        s->observationSelectionSample = 0; // Spend this original ticket before any proof.
        if (!selectionSample || original != selectionSample || s->observationSelectionBound
            || !mrk_version_source_name_state(s, selectionSample, MRK_NAME_ALL)) return MRK_OPEN_CUSTODY;
        s->observationSelectionBound = YES;
    } else if (selectionSample) return MRK_OPEN_INPUT;
    int status = mrk_original_proof(s, p, YES, selection);
    if (!status) {
        memcpy(parent, s->observationParentTag, capacity); memcpy(panel, s->observationPanelTag, capacity);
        memcpy(prompt, s->observationPrompt, 8);
        memcpy(target, s->observationTarget, target_capacity);
    }
    return status;
}
void mrk_panel_observe_open_recheck(void *opaque, const uint8_t *parent, const uint8_t *panel,
    const uint8_t *prompt, const uint8_t *target, size_t target_capacity, unsigned selection, unsigned stage, MRKOpenRecheck *out) {
    if (!out) return;
    MRKOpenRecheck r = {0}; r.error = MRK_OPEN_CUSTODY;
    MRKInstalledPanel *s = opaque;
    @try {
        if (!pthread_main_np() || !s || !parent || !panel || !prompt || !target || target_capacity != 4097
            || selection > 1 || stage > 2 || (!selection && !stage)) goto done;
        if (s->unknown || memcmp(parent, s->observationParentTag, 64) || memcmp(panel, s->observationPanelTag, 64)
            || memcmp(prompt, s->observationPrompt, 8) || memcmp(target, s->observationTarget, target_capacity)
            || selection != (unsigned)(s->kind == 4) || (selection && !s->observationSelectionBound)
            || (!stage ? s->observationSelectionParentChecked || s->observationRechecks != 0
                : s->observationRechecks != stage - 1 || (selection && !s->observationSelectionParentChecked))) {
            s->unknown = YES; goto done;
        }
        if (!stage) s->observationSelectionParentChecked = YES; // Spend0 even on a refused proof.
        else s->observationRechecks = stage;
        r.error = mrk_original_proof(s, &r.proof, NO, stage == 0);
        if (!r.error) {
            NSString *expected = [NSString stringWithCString:s->observationPrompt encoding:NSASCIIStringEncoding];
            id actual = [(NSOpenPanel *)s->window prompt];
            r.prompt = mrk_identity_class(actual, expected) == MRK_ID_MATCH ? 1u : 2u;
            if (r.prompt != 1) r.error = MRK_OPEN_CHANGED;
        }
        if (!r.error && stage == 2) {
            // Prompt/proof reads can reenter. Both full kind4 proofs already
            // read exact singleton URLs; completion independently validates again.
            if (!mrk_observation_attached(s) || !mrk_original_eligible(s)) r.error = MRK_OPEN_INELIGIBLE;
            if (s->unknown) r.error = MRK_OPEN_CUSTODY;
        }
        if (!s->unknown && r.error != MRK_OPEN_CUSTODY && r.error != MRK_OPEN_EXCEPTION) r.known = 1;
    } @catch (NSException *e) { (void)e; if (s) s->unknown = YES; r.error = MRK_OPEN_EXCEPTION; }
done:
    *out = r; // The actual main/TLS guard is released by Rust before its receipt.
}

enum { MRK_PROMPT_CALLS = 512, MRK_PROMPT_CF = 256, MRK_CONTROL_NODES = 17, MRK_CONTROL_DEPTH = 8,
    MRK_SELECT_NODES = 256, MRK_SELECT_ROWS = 32, MRK_SELECT_CALLS = 3072, MRK_SELECT_CF = 1024,
    MRK_SELECT_TOTAL_CALLS = MRK_SELECT_SAMPLES * MRK_SELECT_CALLS,
    MRK_SELECT_TOTAL_CF = MRK_SELECT_SAMPLES * MRK_SELECT_CF };
// Complete selecting original: both window/control projections, original
// chains, one selection/readback and final Press. Charge every AX operation
// its own timeout setter; successful-path bounds do not depend on reuse.
_Static_assert(MRK_SELECT_CF >= 3u * MRK_SELECT_NODES + 8u * MRK_CONTROL_NODES + 6u * MRK_CONTROL_DEPTH + 64u,
    "selection CF envelope covers the complete original");
_Static_assert(MRK_SELECT_CALLS >= 8u * MRK_SELECT_NODES + 20u * MRK_CONTROL_NODES + 12u * MRK_CONTROL_DEPTH + 132u,
    "selection AX envelope covers the complete original");
_Static_assert(MRK_PROMPT_CF <= MRK_SELECT_CF, "ordinary original fits the retained ledger");
enum { MRK_SELECT_COLUMN = 10, MRK_SELECT_LIST, MRK_SELECT_ROW, MRK_SELECT_CELL,
    MRK_SELECT_IMAGE, MRK_SELECT_TEXT, MRK_SELECT_FIELD };
enum { MRK_SELECT_LIMIT_NONE, MRK_SELECT_LIMIT_LABEL, MRK_SELECT_LIMIT_CHILD_COUNT,
    MRK_SELECT_LIMIT_CHILD_COPY, MRK_SELECT_LIMIT_QUEUE, MRK_SELECT_LIMIT_DEPTH,
    MRK_SELECT_LIMIT_AX_CALLS, MRK_SELECT_LIMIT_CF_SLOTS };
typedef struct {
    AXUIElementRef nodes[MRK_SELECT_NODES];
    unsigned parents[MRK_SELECT_NODES], depths[MRK_SELECT_NODES], roles[MRK_SELECT_NODES], entries[MRK_SELECT_NODES];
    BOOL matches[MRK_SELECT_NODES]; unsigned candidate, label;
    CFStringRef label_attribute; // Public constant only; all objects are owned by the original CF ledger.
    uint32_t label_attribute_code; // The same public constant, not another observation.
} MRKSelectionPass;
enum { MRK_DIAG_FRONTIERS = 64, MRK_DIAG_NODES = 64, MRK_DIAG_CALLS = 1024, MRK_DIAG_CF = 512 };
enum { MRK_DIAG_CHILD_COUNT = 1u, MRK_DIAG_CHILD_COPY = 2u, MRK_DIAG_ROLE = 4u,
    MRK_DIAG_PARENT = 8u, MRK_DIAG_TITLE = 16u, MRK_DIAG_VALUE = 32u };
enum { MRK_DIAG_OMIT_FRONTIERS = 1u, MRK_DIAG_OMIT_CHILDREN = 2u, MRK_DIAG_OMIT_NEW_NODES = 4u,
    MRK_DIAG_OMIT_COMBINED_NODES = 8u, MRK_DIAG_OMIT_DEPTH = 16u, MRK_DIAG_OMIT_CALLS = 32u,
    MRK_DIAG_OMIT_CF = 64u, MRK_DIAG_OMIT_EDGE = 128u, MRK_DIAG_OMIT_ROLE = 256u, MRK_DIAG_OMIT_LABEL = 512u };
typedef struct {
    // Borrowed only from the SAME original append-only CF ledger; no new owners.
    AXUIElementRef nodes[MRK_DIAG_NODES], parents[MRK_DIAG_NODES];
    unsigned depths[MRK_DIAG_NODES], roles[MRK_DIAG_NODES];
} MRKProjectionScratch;
typedef union { CFTypeRef value; CFArrayRef array; } MRKPromptOwned;
typedef struct {
    AXUIElementRef nodes[MRK_CONTROL_NODES];
    unsigned parents[MRK_CONTROL_NODES], depths[MRK_CONTROL_NODES], roles[MRK_CONTROL_NODES];
    unsigned chain[MRK_CONTROL_DEPTH + 1], chain_count, candidate;
} MRKControlPass;
typedef struct {
    MRKOpenAdmission admit; MRKOpenRecheckCall recheck; void *context; MRKOpenResult result;
    CFTypeID elementType;
    MRKPromptOwned owned[MRK_SELECT_TOTAL_CF]; unsigned count;
    AXUIElementRef button; // Borrowed only from the first pass's retained original CFArray.
    BOOL cleanupKnown;
    MRKSelectionPass selection[MRK_SELECT_SAMPLES]; // Every sampled chain remains immutable and retained.
    MRKProjectionScratch projection_diagnostic; // Separate DATA, never a candidate/label chain.
    unsigned selection_queued; // Same original loop's bounded queue, not another AX observation.
    CFArrayRef selection_attributes; // Borrowed from this original's registered CF slot.
    AXUIElementRef timeout_element; // Exact retained pointer, not CFEqual or proof authority.
    MRKOpenTimeout installed_timeout; // Known setter result only; every call still re-admits.
} MRKPrompt;
// At most eight different genuine panels, one registered worker at a time.
// Every original ledger remains retained for process lifetime, never reused.
// Unknown CF/control custody permanently forbids any successor, not just reuse.
// Project selection plus the eight accepted P2 choices. Slots are never
// recycled; Cancel does not consume a Press original.
enum { MRK_PROMPT_ORIGINALS = 9 };
static MRKPrompt mrk_prompt_originals[MRK_PROMPT_ORIGINALS];
// 9 complete original arenas: 8192 registered CF slots, 8 immutable256-node
// pass arrays and the complete scalar history in EACH arena. This bounds the
// first-party backing, not opaque CF allocations made by public AX APIs.
_Static_assert(sizeof(mrk_prompt_originals) <= 1152u * 1024u,
    "bounded original prompt arenas including all content samples");
static atomic_uint mrk_prompt_next = 0;
static atomic_flag mrk_prompt_active = ATOMIC_FLAG_INIT;
static atomic_bool mrk_prompt_unknown = false;
static BOOL mrk_ax_fail(MRKPrompt *s, uint32_t error) {
    if (!s->result.error) s->result.error = error;
    return NO;
}
static BOOL mrk_ax_selecting(MRKPrompt *s) {
    return s->result.selection_mode && s->result.site >= MRK_OPEN_SELECTION_PROJECTION
        && s->result.site <= MRK_OPEN_SELECTION_READBACK;
}
static BOOL mrk_ax_selection_limit(MRKPrompt *s, uint32_t predicate, int64_t observed, uint32_t cap, uint32_t children) {
    // Only the FIRST failed original predicate. No queries, retries, strings,
    // or fabricated counts: all arguments belong to the already-entered branch.
    if (!s->result.error && mrk_ax_selecting(s)) {
        s->result.selection_limit = predicate; s->result.selection_limit_observed = observed;
        s->result.selection_limit_cap = cap; s->result.selection_limit_children = children;
        s->result.selection_limit_queued = s->result.site == MRK_OPEN_SELECTION_PROJECTION ? s->selection_queued : 0;
    }
    return mrk_ax_fail(s, MRK_OPEN_LIMIT);
}
static BOOL mrk_ax_control_limit(MRKPrompt *s, uint32_t site) {
    // Shared array callers outside either control pass and an earlier failure
    // keep their site. Cleanup preserves the first phase and both counters.
    if ((s->result.site == MRK_OPEN_CONTROL_PROJECTION || s->result.site == MRK_OPEN_CONTROL_RECHECK)
        && !s->result.error) s->result.site = site;
    return mrk_ax_fail(s, MRK_OPEN_LIMIT);
}
static uint32_t mrk_ax_role(CFStringRef role) {
    if (CFEqual(role, kAXSheetRole)) return MRK_ROLE_SHEET;
    if (CFEqual(role, kAXGroupRole)) return MRK_ROLE_GROUP;
    if (CFEqual(role, kAXSplitGroupRole)) return MRK_ROLE_SPLIT_GROUP;
    if (CFEqual(role, kAXButtonRole)) return MRK_ROLE_BUTTON;
    if (CFEqual(role, kAXBrowserRole)) return MRK_ROLE_BROWSER;
    if (CFEqual(role, kAXTableRole)) return MRK_ROLE_TABLE;
    if (CFEqual(role, kAXOutlineRole)) return MRK_ROLE_OUTLINE;
    if (CFEqual(role, kAXScrollAreaRole)) return MRK_ROLE_SCROLL_AREA;
    return MRK_ROLE_OPAQUE;
}
static BOOL mrk_ax_status(MRKPrompt *s, AXError error, uint32_t operation_code, uint32_t attribute_code) {
    if (error == kAXErrorSuccess) return YES;
    // Actual first failing AX return, even after an earlier deadline.
    if (!s->result.ax_error) {
        s->result.ax_error = error;
        s->result.ax_failure_operation = operation_code;
        s->result.ax_failure_attribute = attribute_code;
    }
    switch (error) {
        case kAXErrorAttributeUnsupported: case kAXErrorActionUnsupported: case kAXErrorNoValue:
        case kAXErrorNotImplemented: case kAXErrorAPIDisabled: return mrk_ax_fail(s, MRK_OPEN_UNSUPPORTED);
        case kAXErrorInvalidUIElement: return mrk_ax_fail(s, MRK_OPEN_INVALID_ELEMENT);
        case kAXErrorIllegalArgument: return mrk_ax_fail(s, MRK_OPEN_INPUT);
        case kAXErrorCannotComplete: return mrk_ax_fail(s, MRK_OPEN_CANNOT_COMPLETE);
        default: return mrk_ax_fail(s, MRK_OPEN_OTHER);
    }
}
static MRKPromptOwned *mrk_ax_slot(MRKPrompt *s) {
    // The entry's frozen mode covers this whole original, not its current site.
    const unsigned cap = s->result.selection_mode == 1 ? MRK_SELECT_CF : MRK_PROMPT_CF;
    unsigned before = s->result.selection_mode == 1 ? s->result.selection_cf_before : 0;
    unsigned total_cap = s->result.selection_mode == 1 ? MRK_SELECT_TOTAL_CF : MRK_PROMPT_CF;
    if (before > s->count || s->count > total_cap) {
        s->cleanupKnown = NO; mrk_ax_fail(s, MRK_OPEN_CUSTODY); return NULL;
    }
    unsigned used = s->count - before;
    if (used == cap || s->count == total_cap) {
        mrk_ax_selection_limit(s, MRK_SELECT_LIMIT_CF_SLOTS, used, cap, 0); return NULL;
    }
    if (used > cap) { s->cleanupKnown = NO; mrk_ax_fail(s, MRK_OPEN_CUSTODY); return NULL; }
    return &s->owned[s->count++]; // Register actual out-slot BEFORE every Create/Copy.
}
static BOOL mrk_ax_admit(MRKPrompt *s, uint64_t required_ns, int after, MRKOpenTimeout *timeout) {
    int result = s->admit(s->context, required_ns, after, timeout);
    if (!result) return YES;
    if (result != MRK_OPEN_DEADLINE && result != MRK_OPEN_INELIGIBLE && result != MRK_OPEN_CUSTODY) {
        s->cleanupKnown = NO; result = MRK_OPEN_CUSTODY;
    }
    if (result == MRK_OPEN_CUSTODY) s->cleanupKnown = NO;
    return mrk_ax_fail(s, (uint32_t)result);
}
static BOOL mrk_ax_before(MRKPrompt *s, AXUIElementRef element) {
    const unsigned cap = s->result.selection_mode == 1 ? MRK_SELECT_CALLS : MRK_PROMPT_CALLS;
    unsigned before = s->result.selection_mode == 1 ? s->result.selection_calls_before : 0;
    unsigned total_cap = s->result.selection_mode == 1 ? MRK_SELECT_TOTAL_CALLS : MRK_PROMPT_CALLS;
    if (before > s->result.calls || s->result.calls > total_cap) {
        s->cleanupKnown = NO; return mrk_ax_fail(s, MRK_OPEN_CUSTODY);
    }
    unsigned used = s->result.calls - before;
    if (used > cap - 2 || s->result.calls > total_cap - 2)
        return mrk_ax_selection_limit(s, MRK_SELECT_LIMIT_AX_CALLS, used, cap, 0);
    MRKOpenTimeout timeout = {0};
    if (!mrk_ax_admit(s, 0, 0, &timeout)) return NO;
    if (!isfinite(timeout.seconds) || timeout.seconds <= 0 || (double)timeout.seconds > 0.1
        || timeout.required_ns == 0 || timeout.required_ns > 100000000
        || timeout.required_ns != (uint64_t)ceil((double)timeout.seconds * 1000000000.0))
        return mrk_ax_fail(s, MRK_OPEN_INPUT);
    // Only this selecting original may reuse its exact pointer's known timeout.
    // Equal-but-distinct AX objects do not share a per-object messaging timeout.
    BOOL reuse = s->result.selection_mode == 1 && s->timeout_element == element
        && s->installed_timeout.required_ns && s->installed_timeout.required_ns <= timeout.required_ns;
    BOOL installed = YES;
    if (reuse) timeout = s->installed_timeout;
    else {
        s->timeout_element = NULL; s->installed_timeout = (MRKOpenTimeout){0};
        s->result.calls++;
        installed = mrk_ax_status(s, AXUIElementSetMessagingTimeout(element, timeout.seconds), MRK_AX_OP_SET_MESSAGING_TIMEOUT, MRK_AX_ATTR_NONE);
        if (installed && s->result.selection_mode == 1) {
            s->timeout_element = element; s->installed_timeout = timeout;
        }
    }
    // BOTH paths freshly admit the installed allowance immediately before the
    // operation. Reuse is never a cached permit or an extension of the endpoint.
    BOOL admitted = mrk_ax_admit(s, timeout.required_ns, 0, NULL);
    return installed && admitted;
}
static BOOL mrk_ax_type(MRKPrompt *s, CFTypeRef value, CFTypeID type) {
    return value && CFGetTypeID(value) == type ? YES : mrk_ax_fail(s, MRK_OPEN_MALFORMED);
}
static CFTypeRef mrk_ax_copy(MRKPrompt *s, AXUIElementRef element, CFStringRef attribute, BOOL optional, uint32_t attribute_code) {
    MRKPromptOwned *slot = mrk_ax_slot(s); if (!slot || !mrk_ax_before(s, element)) return NULL;
    s->result.calls++;
    AXError status = AXUIElementCopyAttributeValue(element, attribute, &slot->value);
    // Optional Title exists only for labelled objects. An actual absent value
    // with no returned object is a nonmatch; IPC/malformed errors are not absence.
    BOOL absent = optional && !slot->value && (status == kAXErrorNoValue || status == kAXErrorAttributeUnsupported);
    BOOL returned = absent || mrk_ax_status(s, status, MRK_AX_OP_COPY_ATTRIBUTE_VALUE, attribute_code), admitted = mrk_ax_admit(s, 0, 0, NULL);
    if (!returned || !admitted || absent) return NULL;
    if (!slot->value) { mrk_ax_fail(s, MRK_OPEN_MALFORMED); return NULL; }
    return slot->value;
}
static CFArrayRef mrk_ax_array(MRKPrompt *s, AXUIElementRef element, CFStringRef attribute, CFIndex limit, BOOL allow_empty, uint32_t attribute_code) {
    // A returned zero count is an ordinary empty array, not an illegal index0
    // Copy converted to absence. Count and bounded Copy both spend the common
    // timeout/call budget; a changed or truncated array cannot prove a search.
    if (!mrk_ax_before(s, element)) return NULL;
    CFIndex expected = -1; s->result.calls++;
    AXError count_status = AXUIElementGetAttributeValueCount(element, attribute, &expected);
    BOOL counted = mrk_ax_status(s, count_status, MRK_AX_OP_GET_ATTRIBUTE_VALUE_COUNT, attribute_code), admitted = mrk_ax_admit(s, 0, 0, NULL);
    if (!counted || !admitted) return NULL;
    if (expected < 0) { mrk_ax_fail(s, MRK_OPEN_MALFORMED); return NULL; }
    if (expected > limit) {
        if (mrk_ax_selecting(s)) mrk_ax_selection_limit(s, MRK_SELECT_LIMIT_CHILD_COUNT, expected, (uint32_t)limit, 0);
        else mrk_ax_control_limit(s, MRK_OPEN_CONTROL_CHILD_COUNT_LIMIT);
        return NULL;
    }
    if (!expected) { if (!allow_empty) mrk_ax_fail(s, MRK_OPEN_UNSUPPORTED); return NULL; }
    MRKPromptOwned *slot = mrk_ax_slot(s); if (!slot || !mrk_ax_before(s, element)) return NULL;
    s->result.calls++;
    AXError status = AXUIElementCopyAttributeValues(element, attribute, 0, limit + 1, &slot->array);
    BOOL copied = mrk_ax_status(s, status, MRK_AX_OP_COPY_ATTRIBUTE_VALUES, attribute_code); admitted = mrk_ax_admit(s, 0, 0, NULL);
    if (!copied || !admitted || !mrk_ax_type(s, slot->value, CFArrayGetTypeID())) return NULL;
    CFIndex count = CFArrayGetCount(slot->array);
    if (count < 0 || count > limit) {
        if (mrk_ax_selecting(s)) mrk_ax_selection_limit(s, MRK_SELECT_LIMIT_CHILD_COPY, count, (uint32_t)limit, 0);
        else mrk_ax_control_limit(s, MRK_OPEN_CONTROL_CHILD_COPY_LIMIT);
        return NULL;
    }
    if (count != expected) { mrk_ax_fail(s, MRK_OPEN_CHANGED); return NULL; }
    // Each caller validates an element when that node begins. In the control
    // pass this keeps a failed type/parent/role read paired with its own counter,
    // depth and cleared role, never a previous sibling's diagnostic state.
    return slot->array;
}
static BOOL mrk_ax_equal_attribute(MRKPrompt *s, AXUIElementRef element, CFStringRef attribute, CFTypeRef expected, uint32_t attribute_code) {
    CFTypeRef actual = mrk_ax_copy(s, element, attribute, NO, attribute_code);
    if (!actual || !mrk_ax_type(s, actual, CFGetTypeID(expected))) return NO;
    return CFEqual(actual, expected) ? YES : mrk_ax_fail(s, MRK_OPEN_CHANGED);
}
static CFTypeRef mrk_ax_selection_pair(MRKPrompt *s, AXUIElementRef element, AXUIElementRef expected_parent) {
    if (!s->selection_attributes) {
        MRKPromptOwned *attributes = mrk_ax_slot(s); if (!attributes) return NULL;
        const void *names[] = { kAXParentAttribute, kAXRoleAttribute };
        attributes->array = CFArrayCreate(NULL, names, 2, &kCFTypeArrayCallBacks);
        if (!mrk_ax_type(s, attributes->value, CFArrayGetTypeID())) return NULL;
        s->selection_attributes = attributes->array;
    }
    MRKPromptOwned *slot = mrk_ax_slot(s); if (!slot || !mrk_ax_before(s, element)) return NULL;
    s->result.calls++;
    AXError status = AXUIElementCopyMultipleAttributeValues(element, s->selection_attributes,
        kAXCopyMultipleAttributeOptionStopOnError, &slot->array);
    BOOL copied = mrk_ax_status(s, status, MRK_AX_OP_COPY_MULTIPLE_ATTRIBUTE_VALUES, MRK_AX_ATTR_NONE),
        admitted = mrk_ax_admit(s, 0, 0, NULL);
    // The archived public SDK contract permits partial/error/CFNull positions.
    // StopOnError never authorizes them: retain every out-slot and reject it.
    if (!copied || !admitted || !mrk_ax_type(s, slot->value, CFArrayGetTypeID())) return NULL;
    if (CFArrayGetCount(slot->array) != 2) { mrk_ax_fail(s, MRK_OPEN_MALFORMED); return NULL; }
    CFTypeRef parent = CFArrayGetValueAtIndex(slot->array, 0);
    if (!mrk_ax_type(s, parent, s->elementType)) return NULL;
    if (!CFEqual(parent, expected_parent)) { mrk_ax_fail(s, MRK_OPEN_CHANGED); return NULL; }
    CFTypeRef role = CFArrayGetValueAtIndex(slot->array, 1);
    return mrk_ax_type(s, role, CFStringGetTypeID()) ? role : NULL;
}
static BOOL mrk_ax_projection(MRKPrompt *s, AXUIElementRef app, CFStringRef parent_text, CFStringRef panel_text,
    AXUIElementRef *parent, AXUIElementRef *sheet) {
    s->result.last_depth = 0; s->result.last_role = MRK_ROLE_NOT_READ;
    s->result.site = MRK_OPEN_WINDOWS;
    CFArrayRef windows = mrk_ax_array(s, app, kAXWindowsAttribute, 4, NO, MRK_AX_ATTR_WINDOWS); if (!windows) return NO;
    AXUIElementRef found_parent = NULL, found_sheet = NULL;
    s->result.site = MRK_OPEN_PARENT_ID;
    for (CFIndex i = 0; i < CFArrayGetCount(windows); ++i) {
        AXUIElementRef candidate = (AXUIElementRef)CFArrayGetValueAtIndex(windows, i);
        s->result.last_depth = 0; s->result.last_role = MRK_ROLE_NOT_READ;
        if (!mrk_ax_type(s, candidate, s->elementType)) return NO;
        CFTypeRef name = mrk_ax_copy(s, candidate, kAXIdentifierAttribute, NO, MRK_AX_ATTR_IDENTIFIER);
        if (!name || !mrk_ax_type(s, name, CFStringGetTypeID())) return NO;
        if (CFStringGetLength(name) >= 64) return mrk_ax_fail(s, MRK_OPEN_LIMIT);
        if (CFEqual(name, parent_text)) {
            if (found_parent) return mrk_ax_fail(s, MRK_OPEN_AMBIGUOUS);
            found_parent = candidate;
        }
    }
    if (!found_parent) return mrk_ax_fail(s, MRK_OPEN_UNSUPPORTED);
    if (*parent && !CFEqual(*parent, found_parent)) return mrk_ax_fail(s, MRK_OPEN_CHANGED);
    s->result.checks |= 1u; s->result.site = MRK_OPEN_SHEET;
    CFArrayRef children = mrk_ax_array(s, found_parent, kAXChildrenAttribute, 16, NO, MRK_AX_ATTR_CHILDREN); if (!children) return NO;
    for (CFIndex i = 0; i < CFArrayGetCount(children); ++i) {
        AXUIElementRef candidate = (AXUIElementRef)CFArrayGetValueAtIndex(children, i);
        s->result.last_depth = 0; s->result.last_role = MRK_ROLE_NOT_READ;
        if (!mrk_ax_type(s, candidate, s->elementType)) return NO;
        CFTypeRef role = mrk_ax_copy(s, candidate, kAXRoleAttribute, NO, MRK_AX_ATTR_ROLE);
        if (!role || !mrk_ax_type(s, role, CFStringGetTypeID())) return NO;
        s->result.last_role = mrk_ax_role(role);
        if (CFEqual(role, kAXSheetRole)) {
            if (found_sheet) return mrk_ax_fail(s, MRK_OPEN_AMBIGUOUS);
            found_sheet = candidate;
        }
    }
    if (!found_sheet) return mrk_ax_fail(s, MRK_OPEN_UNSUPPORTED);
    if (*sheet && !CFEqual(*sheet, found_sheet)) return mrk_ax_fail(s, MRK_OPEN_CHANGED);
    s->result.site = MRK_OPEN_TOPOLOGY;
    s->result.last_depth = 0; s->result.last_role = MRK_ROLE_NOT_READ;
    if (!mrk_ax_equal_attribute(s, found_sheet, kAXIdentifierAttribute, panel_text, MRK_AX_ATTR_IDENTIFIER)
        || !mrk_ax_equal_attribute(s, found_sheet, kAXParentAttribute, found_parent, MRK_AX_ATTR_PARENT)) return NO;
    s->result.checks |= 2u; *parent = found_parent; *sheet = found_sheet; return YES;
}
static BOOL mrk_ax_control_roster(MRKPrompt *s, AXUIElementRef sheet, CFStringRef prompt, BOOL rechecking, MRKControlPass *pass) {
    // Only Sheet -> (Group|SplitGroup)* -> Button is eligible. Other roles are
    // outside this projection, never observed-empty or expandable subtrees.
    pass->nodes[0] = sheet;
    unsigned queued = 1, matches = 0;
    uint32_t *examined = rechecking ? &s->result.recheck_nodes_examined : &s->result.initial_nodes_examined;
    for (unsigned at = 0; at < queued; ++at) {
        AXUIElementRef node = pass->nodes[at];
        s->result.last_depth = pass->depths[at]; s->result.last_role = MRK_ROLE_NOT_READ;
        if (at) (*examined)++; // Once per begun nonroot node of this pass only.
        if (!mrk_ax_type(s, node, s->elementType)) return NO;
        for (unsigned previous = 0; previous < queued; ++previous)
            if (previous != at && pass->nodes[previous] && CFEqual(node, pass->nodes[previous]))
                return mrk_ax_fail(s, MRK_OPEN_MALFORMED);
        CFTypeRef role = mrk_ax_copy(s, node, kAXRoleAttribute, NO, MRK_AX_ATTR_ROLE);
        if (!role || !mrk_ax_type(s, role, CFStringGetTypeID())) return NO;
        pass->roles[at] = s->result.last_role = mrk_ax_role(role);
        if (!at && pass->roles[at] != MRK_ROLE_SHEET) return mrk_ax_fail(s, MRK_OPEN_CHANGED);
        // Prove exclusion from the actual Role, never from a failed Parent read.
        // Every eligible ancestor/control still binds its Parent before use.
        if (at && !CFEqual(role, kAXGroupRole) && !CFEqual(role, kAXSplitGroupRole)
            && !CFEqual(role, kAXButtonRole)) continue;
        if (at && !mrk_ax_equal_attribute(s, node, kAXParentAttribute, pass->nodes[pass->parents[at]], MRK_AX_ATTR_PARENT)) return NO;
        if (CFEqual(role, kAXButtonRole)) {
            CFTypeRef title = mrk_ax_copy(s, node, kAXTitleAttribute, YES, MRK_AX_ATTR_TITLE);
            if (s->result.error) return NO;
            if (title) {
                if (!mrk_ax_type(s, title, CFStringGetTypeID())) return NO;
                if (CFStringGetLength(title) > 512) return mrk_ax_control_limit(s, MRK_OPEN_CONTROL_TITLE_LIMIT);
                if (CFEqual(title, prompt)) { matches++; pass->candidate = at; }
            }
        }
        if (at && !CFEqual(role, kAXGroupRole) && !CFEqual(role, kAXSplitGroupRole)) continue;
        CFArrayRef children = mrk_ax_array(s, node, kAXChildrenAttribute, 16, at != 0, MRK_AX_ATTR_CHILDREN);
        if (!children) { if (s->result.error) return NO; continue; } // Only actual Count0 may be empty.
        CFIndex count = CFArrayGetCount(children);
        if (pass->depths[at] == MRK_CONTROL_DEPTH) return mrk_ax_control_limit(s, MRK_OPEN_CONTROL_DEPTH_LIMIT);
        if ((unsigned)count > MRK_CONTROL_NODES - queued) return mrk_ax_control_limit(s, MRK_OPEN_CONTROL_NODE_LIMIT);
        for (CFIndex child = 0; child < count; ++child) {
            pass->nodes[queued] = (AXUIElementRef)CFArrayGetValueAtIndex(children, child);
            pass->parents[queued] = at; pass->depths[queued] = pass->depths[at] + 1; queued++;
        }
    }
    s->result.checks |= 4u; // Entire eligible control projection, never a first-match exit.
    if (matches != 1) return mrk_ax_fail(s, matches ? MRK_OPEN_AMBIGUOUS : MRK_OPEN_UNSUPPORTED);
    for (unsigned node = pass->candidate; ; node = pass->parents[node]) {
        if (pass->chain_count == MRK_CONTROL_DEPTH + 1) return mrk_ax_fail(s, MRK_OPEN_MALFORMED);
        pass->chain[pass->chain_count++] = node;
        if (!node) break;
    }
    s->result.checks |= 8u; return YES;
}
static BOOL mrk_ax_control_path(MRKPrompt *s, AXUIElementRef parent, const MRKControlPass *original) {
    for (unsigned left = original->chain_count; left; --left) {
        unsigned at = original->chain[left - 1]; AXUIElementRef node = original->nodes[at];
        s->result.last_depth = original->depths[at]; s->result.last_role = MRK_ROLE_NOT_READ;
        if (!mrk_ax_type(s, node, s->elementType)) return NO;
        if (!mrk_ax_equal_attribute(s, node, kAXParentAttribute, at ? original->nodes[original->parents[at]] : parent, MRK_AX_ATTR_PARENT)) return NO;
        CFTypeRef role = mrk_ax_copy(s, node, kAXRoleAttribute, NO, MRK_AX_ATTR_ROLE);
        if (!role || !mrk_ax_type(s, role, CFStringGetTypeID())) return NO;
        s->result.last_role = mrk_ax_role(role);
        if (s->result.last_role != original->roles[at]
            || (!at ? s->result.last_role != MRK_ROLE_SHEET : at == original->candidate ? s->result.last_role != MRK_ROLE_BUTTON
                : s->result.last_role != MRK_ROLE_GROUP && s->result.last_role != MRK_ROLE_SPLIT_GROUP))
            return mrk_ax_fail(s, MRK_OPEN_CHANGED);
    }
    return YES;
}
static BOOL mrk_ax_button(MRKPrompt *s, AXUIElementRef parent, const MRKControlPass *original, CFStringRef prompt) {
    AXUIElementRef button = s->button;
    if (!CFEqual(button, original->nodes[original->candidate])) return mrk_ax_fail(s, MRK_OPEN_CHANGED);
    if (!mrk_ax_control_path(s, parent, original) || !mrk_ax_equal_attribute(s, button, kAXTitleAttribute, prompt, MRK_AX_ATTR_TITLE)) return NO;
    CFTypeRef enabled = mrk_ax_copy(s, button, kAXEnabledAttribute, NO, MRK_AX_ATTR_ENABLED);
    if (!enabled || !mrk_ax_type(s, enabled, CFBooleanGetTypeID())) return NO;
    if (!CFBooleanGetValue(enabled)) return mrk_ax_fail(s, MRK_OPEN_INELIGIBLE);
    s->result.checks |= 16u;
    MRKPromptOwned *slot = mrk_ax_slot(s); if (!slot || !mrk_ax_before(s, button)) return NO;
    s->result.calls++;
    AXError status = AXUIElementCopyActionNames(button, &slot->array);
    // This public API has no range-limited variant. Its <=16 bound is expressly
    // post-return, not a preallocation promise; its out-slot is already owned.
    BOOL copied = mrk_ax_status(s, status, MRK_AX_OP_COPY_ACTION_NAMES, MRK_AX_ATTR_NONE), admitted = mrk_ax_admit(s, 0, 0, NULL);
    if (!copied || !admitted
        || !mrk_ax_type(s, slot->value, CFArrayGetTypeID())) return NO;
    CFIndex count = CFArrayGetCount(slot->array); unsigned presses = 0;
    if (count < 0 || count > 16) return mrk_ax_fail(s, MRK_OPEN_LIMIT);
    for (CFIndex i = 0; i < count; ++i) {
        CFTypeRef action = CFArrayGetValueAtIndex(slot->array, i);
        if (!mrk_ax_type(s, action, CFStringGetTypeID())) return NO;
        if (CFEqual(action, kAXPressAction)) presses++;
    }
    if (presses != 1) return mrk_ax_fail(s, presses ? MRK_OPEN_AMBIGUOUS : MRK_OPEN_UNSUPPORTED);
    s->result.checks |= 32u;
    return YES;
}
static BOOL mrk_ax_original(MRKPrompt *s, int stage) {
    s->result.site = stage == 0 ? MRK_OPEN_SELECTION_PARENT : stage == 1 ? MRK_OPEN_INITIAL_PROOF : MRK_OPEN_FINAL_PROOF;
    int code = s->recheck(s->context, stage);
    if (code == MRK_OPEN_CUSTODY) s->cleanupKnown = NO;
    return code ? mrk_ax_fail(s, (uint32_t)code) : YES;
}
// Diagnostic comparisons of an ALREADY retained, typed and bounded label only.
// Fixed synthetic labels are never supplemented by raw labels, URLs or paths.
// None of these bits participates in candidate choice, selection or Open proof.
static void mrk_ax_selection_label_summary(MRKPrompt *s, CFStringRef value, CFStringRef expected,
    unsigned role, BOOL exact) {
    static const CFStringRef fixture_labels[] = {
        CFSTR("VERSION"), CFSTR("link-input"), CFSTR("kind-input"), CFSTR("inputs"), CFSTR("version.properties")
    };
    for (unsigned i = 0; i < 5; ++i)
        if (CFEqual(value, fixture_labels[i])) s->result.selection_fixture_label_mask |= 1u << i;
    // bit0 exact; bit1 unequal but case-insensitive equal; bit2 unequal but
    // containing the literal expected basename. An aggregate can hold all3.
    uint32_t relations = exact ? 1u : 0u;
    if (!exact) {
        if (CFStringCompare(value, expected, kCFCompareCaseInsensitive) == kCFCompareEqualTo) relations |= 2u;
        if (CFStringFind(value, expected, 0).location != kCFNotFound) relations |= 4u;
    }
    s->result.selection_expected_label_relations |= relations;
    if (relations) s->result.selection_expected_label_role_mask |= 1u << role;
}
static unsigned mrk_ax_selection_role(CFStringRef role) {
    if (CFEqual(role, kAXColumnRole)) return MRK_SELECT_COLUMN;
    if (CFEqual(role, kAXListRole)) return MRK_SELECT_LIST;
    if (CFEqual(role, kAXRowRole)) return MRK_SELECT_ROW;
    if (CFEqual(role, kAXCellRole)) return MRK_SELECT_CELL;
    if (CFEqual(role, kAXImageRole)) return MRK_SELECT_IMAGE;
    if (CFEqual(role, kAXStaticTextRole)) return MRK_SELECT_TEXT;
    if (CFEqual(role, kAXTextFieldRole)) return MRK_SELECT_FIELD;
    return mrk_ax_role(role);
}
// Diagnostic-only reads use the original timeout/admission and CF custody.
// A credit refusal records an omitted probe, not fresh budget or an action permit.
static BOOL mrk_ax_diag_stopped(MRKPrompt *s) {
    return s->result.error || (s->result.selection_projection_diagnostic.omissions
        & (MRK_DIAG_OMIT_CALLS | MRK_DIAG_OMIT_CF));
}
static BOOL mrk_ax_diag_credit(MRKPrompt *s, unsigned calls, unsigned slots) {
    MRKProjectionDiagnostic *d = &s->result.selection_projection_diagnostic;
    if (mrk_ax_diag_stopped(s)) return NO;
    if (s->result.calls < d->calls_before || s->count < d->cf_before
        || s->result.calls < s->result.selection_calls_before || s->count < s->result.selection_cf_before
        || s->result.calls > MRK_SELECT_TOTAL_CALLS || s->count > MRK_SELECT_TOTAL_CF) {
        s->cleanupKnown = NO; return mrk_ax_fail(s, MRK_OPEN_CUSTODY);
    }
    // Reserve the worst case, INCLUDING the guarded primitive's timeout setter.
    // Also stop before exhausting shared credit; do not manufacture a selection
    // limit at a completed census or relax the original sample/aggregate limits.
    if (s->result.calls - d->calls_before > MRK_DIAG_CALLS - calls
        || s->result.calls - s->result.selection_calls_before > MRK_SELECT_CALLS - calls
        || s->result.calls > MRK_SELECT_TOTAL_CALLS - calls) d->omissions |= MRK_DIAG_OMIT_CALLS;
    if (s->count - d->cf_before > MRK_DIAG_CF - slots
        || s->count - s->result.selection_cf_before > MRK_SELECT_CF - slots
        || s->count > MRK_SELECT_TOTAL_CF - slots) d->omissions |= MRK_DIAG_OMIT_CF;
    return !mrk_ax_diag_stopped(s);
}
static CFTypeRef mrk_ax_diag_copy(MRKPrompt *s, AXUIElementRef node, CFStringRef attribute,
    uint32_t attribute_code, uint32_t unavailable) {
    if (!mrk_ax_diag_credit(s, 2, 1)) return NULL;
    // Optional Title, Value, Role and Parent all use this documented primitive.
    // Only NoValue/AttributeUnsupported with no object is absence. All other
    // errors keep mrk_ax_copy's original fatal status and post-call admission.
    CFTypeRef value = mrk_ax_copy(s, node, attribute, YES, attribute_code);
    if (!value && !s->result.error) s->result.selection_projection_diagnostic.unavailable |= unavailable;
    return value;
}
static BOOL mrk_ax_diag_label(MRKPrompt *s, AXUIElementRef node, unsigned role, CFStringRef attribute,
    uint32_t attribute_code, uint32_t unavailable, uint32_t *mask, uint32_t *roles) {
    CFTypeRef value = mrk_ax_diag_copy(s, node, attribute, attribute_code, unavailable);
    if (!value) return !mrk_ax_diag_stopped(s);
    MRKProjectionDiagnostic *d = &s->result.selection_projection_diagnostic;
    if (CFGetTypeID(value) != CFStringGetTypeID()) {
        if (attribute_code == MRK_AX_ATTR_VALUE) d->non_string_values++;
        else d->omissions |= MRK_DIAG_OMIT_LABEL;
        return YES; // Never format, traverse or coerce a non-string.
    }
    if (CFStringGetLength(value) > 512) { d->omissions |= MRK_DIAG_OMIT_LABEL; return YES; }
    static const CFStringRef fixture_labels[] = {
        CFSTR("VERSION"), CFSTR("link-input"), CFSTR("kind-input"), CFSTR("inputs"), CFSTR("version.properties")
    };
    for (unsigned i = 0; i < 5; ++i) {
        if (CFEqual(value, fixture_labels[i])) {
            *mask |= 1u << i;
            if (roles) *roles |= 1u << role;
        }
    }
    return YES;
}
static BOOL mrk_ax_diag_children(MRKPrompt *s, const MRKSelectionPass *p, unsigned original_count,
    AXUIElementRef node, unsigned depth) {
    MRKProjectionDiagnostic *d = &s->result.selection_projection_diagnostic;
    MRKProjectionScratch *q = &s->projection_diagnostic;
    if (!mrk_ax_diag_credit(s, 2, 0) || !mrk_ax_before(s, node)) return NO;
    CFIndex expected = -1; s->result.calls++;
    AXError status = AXUIElementGetAttributeValueCount(node, kAXChildrenAttribute, &expected);
    BOOL absent = status == kAXErrorNoValue || status == kAXErrorAttributeUnsupported;
    BOOL counted = absent || mrk_ax_status(s, status, MRK_AX_OP_GET_ATTRIBUTE_VALUE_COUNT, MRK_AX_ATTR_CHILDREN);
    BOOL admitted = mrk_ax_admit(s, 0, 0, NULL);
    if (absent) d->unavailable |= MRK_DIAG_CHILD_COUNT;
    if (!counted || !admitted) return NO;
    if (absent) return YES;
    if (expected < 0) return mrk_ax_fail(s, MRK_OPEN_MALFORMED);
    if (expected > MRK_SELECT_ROWS) { d->omissions |= MRK_DIAG_OMIT_CHILDREN; return YES; }
    if (!expected) return YES;
    if (depth >= MRK_CONTROL_DEPTH) { d->omissions |= MRK_DIAG_OMIT_DEPTH; return YES; }
    if (!mrk_ax_diag_credit(s, 2, 1)) return NO;
    MRKPromptOwned *slot = mrk_ax_slot(s); if (!slot || !mrk_ax_before(s, node)) return NO;
    s->result.calls++;
    status = AXUIElementCopyAttributeValues(node, kAXChildrenAttribute, 0, MRK_SELECT_ROWS + 1, &slot->array);
    absent = !slot->value && (status == kAXErrorNoValue || status == kAXErrorAttributeUnsupported);
    BOOL copied = absent || mrk_ax_status(s, status, MRK_AX_OP_COPY_ATTRIBUTE_VALUES, MRK_AX_ATTR_CHILDREN);
    admitted = mrk_ax_admit(s, 0, 0, NULL);
    if (absent) d->unavailable |= MRK_DIAG_CHILD_COPY;
    if (!copied || !admitted) return NO;
    if (absent) return YES;
    if (!mrk_ax_type(s, slot->value, CFArrayGetTypeID())) return NO;
    CFIndex count = CFArrayGetCount(slot->array);
    if (count < 0) return mrk_ax_fail(s, MRK_OPEN_MALFORMED);
    if (count > MRK_SELECT_ROWS) { d->omissions |= MRK_DIAG_OMIT_CHILDREN; return YES; }
    if (count != expected) { d->omissions |= MRK_DIAG_OMIT_EDGE; return YES; }
    for (CFIndex i = 0; i < count; ++i) {
        AXUIElementRef child = (AXUIElementRef)CFArrayGetValueAtIndex(slot->array, i);
        if (!mrk_ax_type(s, child, s->elementType)) return NO;
        BOOL known = NO;
        for (unsigned at = 0; at < original_count; ++at) {
            if (!CFEqual(child, p->nodes[at])) continue;
            known = YES; d->duplicates++;
            if (!at || !CFEqual(node, p->nodes[p->parents[at]])) d->omissions |= MRK_DIAG_OMIT_EDGE;
            break;
        }
        if (!known) for (unsigned at = 0; at < d->added_nodes; ++at) {
            if (!CFEqual(child, q->nodes[at])) continue;
            known = YES; d->duplicates++;
            if (!CFEqual(node, q->parents[at])) d->omissions |= MRK_DIAG_OMIT_EDGE;
            break;
        }
        if (known) continue; // Retained by the returned array; never re-enqueued.
        if (d->added_nodes == MRK_DIAG_NODES) { d->omissions |= MRK_DIAG_OMIT_NEW_NODES; continue; }
        if (original_count + d->added_nodes == MRK_SELECT_NODES) {
            d->omissions |= MRK_DIAG_OMIT_COMBINED_NODES; continue;
        }
        CFTypeRef parent = mrk_ax_diag_copy(s, child, kAXParentAttribute, MRK_AX_ATTR_PARENT, MRK_DIAG_PARENT);
        if (!parent) { if (mrk_ax_diag_stopped(s)) return NO; continue; }
        if (!mrk_ax_type(s, parent, s->elementType)) return NO;
        if (!CFEqual(parent, node)) { d->omissions |= MRK_DIAG_OMIT_EDGE; continue; }
        CFTypeRef role = mrk_ax_diag_copy(s, child, kAXRoleAttribute, MRK_AX_ATTR_ROLE, MRK_DIAG_ROLE);
        if (!role) { if (mrk_ax_diag_stopped(s)) return NO; continue; }
        if (!mrk_ax_type(s, role, CFStringGetTypeID())) return NO;
        unsigned at = d->added_nodes++;
        q->nodes[at] = child; q->parents[at] = node; q->depths[at] = depth + 1;
        q->roles[at] = mrk_ax_selection_role(role);
        if (q->depths[at] > d->max_depth) d->max_depth = q->depths[at];
    }
    return YES;
}
static BOOL mrk_ax_diag_frontier(const MRKSelectionPass *p, unsigned at) {
    return !p->entries[at] && (p->roles[at] == MRK_ROLE_TABLE || p->roles[at] == MRK_ROLE_OUTLINE
        || p->roles[at] == MRK_ROLE_OPAQUE);
}
static void mrk_ax_projection_diagnostic_probe(MRKPrompt *s, const MRKSelectionPass *p, unsigned original_count) {
    MRKProjectionDiagnostic *d = &s->result.selection_projection_diagnostic;
    MRKProjectionScratch *q = &s->projection_diagnostic;
    // Omitted structural routes first; never let an ancestor's alternate labels
    // consume all diagnostic credit before reaching its frontier.
    for (unsigned at = 0; at < original_count; ++at) {
        if (!mrk_ax_diag_frontier(p, at)) continue;
        if (d->attempted_frontiers == MRK_DIAG_FRONTIERS) { d->omissions |= MRK_DIAG_OMIT_FRONTIERS; break; }
        d->attempted_frontiers++;
        if (!mrk_ax_diag_children(s, p, original_count, p->nodes[at], p->depths[at])) return;
    }
    for (unsigned at = 0; at < d->added_nodes; ++at) {
        unsigned role = q->roles[at];
        BOOL text = role == MRK_SELECT_TEXT || role == MRK_SELECT_FIELD;
        BOOL entry = role == MRK_ROLE_GROUP || role == MRK_SELECT_ROW || role == MRK_SELECT_CELL || role == MRK_SELECT_IMAGE;
        BOOL button = role == MRK_ROLE_BUTTON;
        if ((entry || button) && !mrk_ax_diag_label(s, q->nodes[at], role, kAXTitleAttribute, MRK_AX_ATTR_TITLE,
            MRK_DIAG_TITLE, &d->frontier_label_mask, &d->frontier_role_mask)) return;
        if ((text || entry || button) && !mrk_ax_diag_label(s, q->nodes[at], role, kAXValueAttribute, MRK_AX_ATTR_VALUE,
            MRK_DIAG_VALUE, &d->frontier_label_mask, &d->frontier_role_mask)) return;
        if (text || role == MRK_SELECT_IMAGE) continue;
        // Added Button labels/children are diagnostic only, never selection eligibility.
        if (!mrk_ax_diag_children(s, p, original_count, q->nodes[at], q->depths[at])) return;
    }
    for (unsigned at = 0; at < original_count; ++at) {
        unsigned role = p->roles[at];
        if (p->entries[at] && (role == MRK_ROLE_GROUP || role == MRK_SELECT_ROW
            || role == MRK_SELECT_CELL || role == MRK_SELECT_IMAGE)) {
            if (!mrk_ax_diag_label(s, p->nodes[at], role, kAXValueAttribute, MRK_AX_ATTR_VALUE,
                MRK_DIAG_VALUE, &d->alternate_value_mask, &d->alternate_role_mask)) return;
        } else if (!p->entries[at] && (role == MRK_SELECT_TEXT || role == MRK_SELECT_FIELD)) {
            // A prefilled VERSION name field is NOT target-directory evidence.
            if (!mrk_ax_diag_label(s, p->nodes[at], role, kAXValueAttribute, MRK_AX_ATTR_VALUE,
                MRK_DIAG_VALUE, &d->outside_field_mask, NULL)) return;
        }
    }
}
static void mrk_ax_first_zero_diagnostic(MRKPrompt *s, AXUIElementRef sheet) {
    MRKProjectionDiagnostic *d = &s->result.selection_projection_diagnostic;
    if (d->version) return; // A returned or interrupted diagnostic is never retried.
    const MRKSelectionPass *p = &s->selection[0];
    if (s->result.selection_mode != 1 || s->result.selection_sample != 1
        || s->result.selection_checks != 1 || s->result.selection_matches || s->result.selection_flags
        || s->result.flags || s->result.error || s->result.selection_nodes >= MRK_SELECT_NODES
        || s->selection_queued != s->result.selection_nodes + 1 || p->nodes[0] != sheet) {
        s->cleanupKnown = NO; mrk_ax_fail(s, MRK_OPEN_CUSTODY); return;
    }
    d->version = 1u; d->state = 1u; // Latch BEFORE the first extra AX observation.
    d->normal_fixture_mask = s->result.selection_fixture_label_mask;
    d->calls_before = d->calls_after = s->result.calls;
    d->cf_before = d->cf_after = s->count;
    unsigned original_count = s->result.selection_nodes + 1;
    for (unsigned at = 0; at < original_count; ++at)
        if (mrk_ax_diag_frontier(p, at)) d->eligible_frontiers++;
    BOOL returned = NO;
    @try {
        mrk_ax_projection_diagnostic_probe(s, p, original_count);
        returned = YES;
    } @finally {
        // Snapshot on an exception as well; do not catch/clear the original error
        // or claim a return. The existing outer owner still governs finality.
        d->calls_after = s->result.calls; d->cf_after = s->count;
        if (returned) d->state = s->result.error || d->unavailable || d->omissions || d->non_string_values
            || d->attempted_frontiers != d->eligible_frontiers ? 3u : 2u;
    }
}
static BOOL mrk_ax_selection_label(MRKPrompt *s, MRKSelectionPass *p, unsigned at,
    CFStringRef attribute, BOOL optional, CFStringRef expected, uint32_t attribute_code) {
    CFTypeRef value = mrk_ax_copy(s, p->nodes[at], attribute, optional, attribute_code);
    if (s->result.error) return NO;
    if (!value) {
        if (optional) s->result.selection_title_absent++;
        return optional;
    }
    if (!mrk_ax_type(s, value, CFStringGetTypeID())) return NO;
    CFIndex length = CFStringGetLength(value);
    if (length > 512) return mrk_ax_selection_limit(s, MRK_SELECT_LIMIT_LABEL, length, 512, 0);
    // Count only the already-returned, typed and bounded string; never its bytes.
    if (optional) s->result.selection_title_present++;
    else s->result.selection_value_present++;
    BOOL exact = CFEqual(value, expected);
    if (exact) {
        unsigned entry = p->entries[at];
        if (!entry) return mrk_ax_fail(s, MRK_OPEN_MALFORMED);
        if (!p->matches[entry]) {
            p->matches[entry] = YES;
            if (s->result.selection_matches < 2) s->result.selection_matches++;
            if (s->result.selection_matches == 1) { p->candidate = entry; p->label = at; p->label_attribute = attribute; p->label_attribute_code = attribute_code; }
        }
    }
    mrk_ax_selection_label_summary(s, value, expected, p->roles[at], exact);
    return YES;
}
static BOOL mrk_ax_selection_roster(MRKPrompt *s, AXUIElementRef sheet, CFStringRef expected) {
    if (!s->result.selection_sample || s->result.selection_sample > MRK_SELECT_SAMPLES) {
        s->cleanupKnown = NO; return mrk_ax_fail(s, MRK_OPEN_CUSTODY);
    }
    MRKSelectionPass *p = &s->selection[s->result.selection_sample - 1];
    if (p->nodes[0]) { s->cleanupKnown = NO; return mrk_ax_fail(s, MRK_OPEN_CUSTODY); }
    p->nodes[0] = sheet; unsigned queued = 1;
    s->result.site = MRK_OPEN_SELECTION_PROJECTION;
    s->result.selection_summary_version = 2u;
    for (unsigned at = 0; at < queued; ++at) {
        s->selection_queued = queued;
        AXUIElementRef node = p->nodes[at];
        s->result.selection_depth = p->depths[at]; s->result.selection_last_role = MRK_ROLE_NOT_READ;
        if (at) s->result.selection_nodes++;
        if (!mrk_ax_type(s, node, s->elementType)) return NO;
        for (unsigned other = 0; other < queued; ++other)
            if (other != at && p->nodes[other] && CFEqual(node, p->nodes[other])) return mrk_ax_fail(s, MRK_OPEN_MALFORMED);
        CFTypeRef role = at ? mrk_ax_selection_pair(s, node, p->nodes[p->parents[at]])
            : mrk_ax_copy(s, node, kAXRoleAttribute, NO, MRK_AX_ATTR_ROLE);
        if (!role || !mrk_ax_type(s, role, CFStringGetTypeID())) return NO;
        // Roles outside the small button grammar keep a separate selector meaning.
        unsigned kind = p->roles[at] = s->result.selection_last_role = mrk_ax_selection_role(role);
        if (!at && kind != MRK_ROLE_SHEET) return mrk_ax_fail(s, MRK_OPEN_CHANGED);
        // Typed observed roles, including a role later refused by the entry grammar.
        if (kind == MRK_ROLE_TABLE) s->result.selection_table_roles++;
        else if (kind == MRK_ROLE_OUTLINE) s->result.selection_outline_roles++;
        else if (kind == MRK_SELECT_LIST) s->result.selection_list_roles++;
        unsigned entry = p->entries[at];
        if (entry) {
            if (entry == at) {
                unsigned container = p->roles[p->parents[at]];
                BOOL rows = container == MRK_ROLE_TABLE || container == MRK_ROLE_OUTLINE;
                if (rows ? kind != MRK_SELECT_ROW : container != MRK_SELECT_LIST
                    || !(kind == MRK_SELECT_ROW || kind == MRK_SELECT_CELL || kind == MRK_ROLE_GROUP
                        || kind == MRK_SELECT_IMAGE || kind == MRK_SELECT_TEXT)) return mrk_ax_fail(s, MRK_OPEN_UNSUPPORTED);
                s->result.selection_entry_roots++;
            } else if (!(kind == MRK_ROLE_GROUP || kind == MRK_SELECT_CELL || kind == MRK_SELECT_IMAGE
                || kind == MRK_SELECT_TEXT || kind == MRK_SELECT_FIELD)) return mrk_ax_fail(s, MRK_OPEN_UNSUPPORTED);
            if (kind == MRK_SELECT_TEXT || kind == MRK_SELECT_FIELD) {
                if (!mrk_ax_selection_label(s, p, at, kAXValueAttribute, NO, expected, MRK_AX_ATTR_VALUE)) return NO;
            } else if (!mrk_ax_selection_label(s, p, at, kAXTitleAttribute, YES, expected, MRK_AX_ATTR_TITLE)) return NO;
            if (kind == MRK_SELECT_IMAGE || kind == MRK_SELECT_TEXT || kind == MRK_SELECT_FIELD) continue;
        }
        BOOL rows = !entry && (kind == MRK_ROLE_TABLE || kind == MRK_ROLE_OUTLINE);
        BOOL list = !entry && kind == MRK_SELECT_LIST;
        BOOL structural = !entry && (kind == MRK_ROLE_SHEET || kind == MRK_ROLE_GROUP || kind == MRK_ROLE_SPLIT_GROUP
            || kind == MRK_ROLE_SCROLL_AREA || kind == MRK_ROLE_BROWSER || kind == MRK_SELECT_COLUMN);
        if (!entry && !rows && !list && !structural) {
            if (kind == MRK_SELECT_ROW || kind == MRK_SELECT_CELL) return mrk_ax_fail(s, MRK_OPEN_UNSUPPORTED);
            // Closed role bits only: Button, opaque, Image, StaticText, TextField.
            s->result.selection_outside_entry_role_mask |= 1u << kind;
            continue; // Toolbar/nonselectable leaves are outside this fixed projection.
        }
        CFArrayRef children = mrk_ax_array(s, node, rows ? kAXRowsAttribute : kAXChildrenAttribute,
            rows || list ? MRK_SELECT_ROWS : 16, at != 0, rows ? MRK_AX_ATTR_ROWS : MRK_AX_ATTR_CHILDREN);
        if (!children) { if (s->result.error) return NO; continue; }
        CFIndex count = CFArrayGetCount(children);
        // Preserve the original depth-first short circuit and both unchanged caps.
        if (p->depths[at] == MRK_CONTROL_DEPTH)
            return mrk_ax_selection_limit(s, MRK_SELECT_LIMIT_DEPTH, p->depths[at], MRK_CONTROL_DEPTH, (uint32_t)count);
        if ((unsigned)count > MRK_SELECT_NODES - queued)
            return mrk_ax_selection_limit(s, MRK_SELECT_LIMIT_QUEUE, queued, MRK_SELECT_NODES, (uint32_t)count);
        for (CFIndex child = 0; child < count; ++child) {
            p->nodes[queued] = (AXUIElementRef)CFArrayGetValueAtIndex(children, child);
            p->parents[queued] = at; p->depths[queued] = p->depths[at] + 1;
            p->entries[queued] = rows || list ? queued : entry; queued++;
        }
    }
    s->result.selection_checks |= 1u; // Complete, never truncated or first-match.
    if (s->result.selection_matches > 1) return mrk_ax_fail(s, MRK_OPEN_AMBIGUOUS);
    if (s->result.selection_matches == 1) s->result.selection_checks |= 2u;
    return YES; // Complete zero-match is only pending, never permission to write.
}
static BOOL mrk_ax_content_wait(MRKPrompt *s) {
    if (s->result.error || s->result.selection_checks != 1 || s->result.selection_matches
        || s->result.selection_flags || s->result.flags || s->result.selection_wait
        || !s->result.selection_sample || s->result.selection_sample >= MRK_SELECT_SAMPLES) {
        s->cleanupKnown = NO; return mrk_ax_fail(s, MRK_OPEN_CUSTODY);
    }
    // One ordinary off-main wait per complete pending sample. The caller's
    // original2s/45s endpoint admits it; no deadline, timer or owner is made.
    if (!mrk_ax_admit(s, 50000000u, 0, NULL)) return NO;
    s->result.selection_wait = 1u;
    const struct timespec interval = { .tv_sec = 0, .tv_nsec = 50000000 };
    int status = nanosleep(&interval, NULL); // A returned EINTR is terminal, never retried.
    s->result.selection_wait = status == 0 ? 2u : 3u;
    BOOL returned = status == 0 || mrk_ax_fail(s, MRK_OPEN_OTHER);
    BOOL admitted = mrk_ax_admit(s, 0, 0, NULL);
    return returned && admitted;
}
static BOOL mrk_ax_next_content_sample(MRKPrompt *s) {
    unsigned ordinal = s->result.selection_sample;
    if (!ordinal || ordinal >= MRK_SELECT_SAMPLES || s->result.error || s->result.selection_checks != 1
        || s->result.selection_matches || s->result.selection_flags || s->result.flags
        || s->result.selection_wait != 2 || s->result.selection_pending[ordinal - 1].ordinal
        || s->result.calls < s->result.selection_calls_before || s->count < s->result.selection_cf_before
        || s->result.calls - s->result.selection_calls_before > MRK_SELECT_CALLS
        || s->count - s->result.selection_cf_before > MRK_SELECT_CF) {
        s->cleanupKnown = NO; return mrk_ax_fail(s, MRK_OPEN_CUSTODY);
    }
    s->result.selection_pending[ordinal - 1] = (MRKContentPending){
        ordinal, s->result.selection_calls_before, s->result.calls, s->result.selection_cf_before, s->count,
        s->result.selection_nodes, s->result.selection_depth, s->result.selection_last_role,
        s->result.selection_entry_roots, s->result.selection_fixture_label_mask, s->result.selection_expected_label_relations,
        s->result.selection_checks, s->result.selection_matches, s->result.selection_flags, s->result.error, s->result.selection_wait };
    // New, separately retained pass DATA only. Never clear an error, cumulative
    // calls/CF ownership, or an attempted action; all previous records stay fixed.
    s->result.selection_sample = ordinal + 1;
    s->result.selection_calls_before = s->result.calls; s->result.selection_cf_before = s->count;
    s->result.selection_wait = 0; s->selection_queued = 0;
    s->result.selection_checks = 0; s->result.selection_nodes = 0;
    s->result.selection_last_role = 0; s->result.selection_depth = 0;
    s->result.selection_summary_version = 0;
    s->result.selection_table_roles = s->result.selection_outline_roles = s->result.selection_list_roles = 0;
    s->result.selection_entry_roots = s->result.selection_title_present = s->result.selection_title_absent = 0;
    s->result.selection_value_present = s->result.selection_outside_entry_role_mask = 0;
    s->result.selection_fixture_label_mask = s->result.selection_expected_label_relations = s->result.selection_expected_label_role_mask = 0;
    return YES;
}
static BOOL mrk_ax_select_entry(MRKPrompt *s, AXUIElementRef parent, CFStringRef expected) {
    if (!s->result.selection_sample || s->result.selection_sample > MRK_SELECT_SAMPLES) {
        s->cleanupKnown = NO; return mrk_ax_fail(s, MRK_OPEN_CUSTODY);
    }
    MRKSelectionPass *p = &s->selection[s->result.selection_sample - 1];
    if (s->result.selection_flags || s->result.selection_checks != 3 || !p->candidate || !p->label || !p->label_attribute) {
        s->cleanupKnown = NO; return mrk_ax_fail(s, MRK_OPEN_CUSTODY);
    }
    s->result.site = MRK_OPEN_SELECTION_RECHECK;
    for (unsigned at = p->label;; at = p->parents[at]) {
        if (!mrk_ax_equal_attribute(s, p->nodes[at], kAXParentAttribute, at ? p->nodes[p->parents[at]] : parent, MRK_AX_ATTR_PARENT)) return NO;
        CFTypeRef role = mrk_ax_copy(s, p->nodes[at], kAXRoleAttribute, NO, MRK_AX_ATTR_ROLE);
        if (!role || !mrk_ax_type(s, role, CFStringGetTypeID())) return NO;
        if (mrk_ax_selection_role(role) != p->roles[at]) return mrk_ax_fail(s, MRK_OPEN_CHANGED);
        if (!at) break;
    }
    if (!mrk_ax_equal_attribute(s, p->nodes[p->label], p->label_attribute, expected, p->label_attribute_code)) return NO;
    unsigned container_at = p->parents[p->candidate];
    if (p->entries[p->label] != p->candidate || p->entries[p->candidate] != p->candidate)
        return mrk_ax_fail(s, MRK_OPEN_CHANGED);
    unsigned kind = p->roles[container_at];
    CFStringRef attribute = kind == MRK_ROLE_TABLE || kind == MRK_ROLE_OUTLINE ? kAXSelectedRowsAttribute
        : kind == MRK_SELECT_LIST ? kAXSelectedChildrenAttribute : NULL;
    if (!attribute) return mrk_ax_fail(s, MRK_OPEN_UNSUPPORTED);
    uint32_t attribute_code = kind == MRK_SELECT_LIST ? MRK_AX_ATTR_SELECTED_CHILDREN : MRK_AX_ATTR_SELECTED_ROWS;
    s->result.selection_attribute = kind == MRK_SELECT_LIST ? 2u : 1u;
    s->result.selection_checks |= 4u;
    AXUIElementRef container = p->nodes[container_at], entry = p->nodes[p->candidate];
    s->result.site = MRK_OPEN_SELECTION_SETTABLE;
    if (!mrk_ax_before(s, container)) return NO;
    Boolean settable = false; s->result.calls++;
    AXError status = AXUIElementIsAttributeSettable(container, attribute, &settable);
    BOOL returned = mrk_ax_status(s, status, MRK_AX_OP_IS_ATTRIBUTE_SETTABLE, attribute_code), admitted = mrk_ax_admit(s, 0, 0, NULL);
    if (!returned || !admitted) return NO;
    if (!settable) return mrk_ax_fail(s, MRK_OPEN_UNSUPPORTED);
    s->result.selection_checks |= 8u;
    MRKPromptOwned *selected = mrk_ax_slot(s); if (!selected) return NO;
    const void *entries[] = { entry };
    selected->array = CFArrayCreate(NULL, entries, 1, &kCFTypeArrayCallBacks);
    if (!mrk_ax_type(s, selected->value, CFArrayGetTypeID()) || !mrk_ax_before(s, container)) return NO;
    s->result.site = MRK_OPEN_SELECTION_WRITE; s->result.calls++; s->result.selection_flags |= 1u;
    status = AXUIElementSetAttributeValue(container, attribute, selected->array); // Exactly one selection, never row Press/value write.
    s->result.selection_flags |= 2u;
    if (status == kAXErrorSuccess) s->result.selection_flags |= 4u;
    returned = mrk_ax_status(s, status, MRK_AX_OP_SET_ATTRIBUTE_VALUE, attribute_code); admitted = mrk_ax_admit(s, 0, 0, NULL);
    if (!returned || !admitted) return NO;
    s->result.site = MRK_OPEN_SELECTION_READBACK;
    CFArrayRef actual = mrk_ax_array(s, container, attribute, MRK_SELECT_ROWS, NO, attribute_code);
    if (!actual) return NO;
    if (CFArrayGetCount(actual) != 1) return mrk_ax_fail(s, MRK_OPEN_CHANGED);
    CFTypeRef value = CFArrayGetValueAtIndex(actual, 0);
    if (!mrk_ax_type(s, value, s->elementType)) return NO;
    if (!CFEqual(value, entry)) return mrk_ax_fail(s, MRK_OPEN_CHANGED);
    s->result.selection_checks |= 16u; return YES;
}
static void mrk_ax_open(MRKPrompt *s, const uint8_t *parent_tag, const uint8_t *panel_tag, const uint8_t *prompt, const uint8_t *target) {
    if (!mrk_ax_admit(s, 0, 0, NULL) || !mrk_ax_original(s, s->result.selection_mode ? 0 : 1)) return;
    if (s->result.selection_mode) s->result.selection_sample = 1; // Setup belongs to this first sample's budget.
    s->result.calls++; s->elementType = AXUIElementGetTypeID(); // Count and reuse this local AX API too.
    MRKPromptOwned *parent_text = mrk_ax_slot(s), *panel_text = mrk_ax_slot(s), *prompt_text = mrk_ax_slot(s), *application = mrk_ax_slot(s);
    if (!parent_text || !panel_text || !prompt_text || !application) return;
    s->result.site = MRK_OPEN_APPLICATION;
    parent_text->value = CFStringCreateWithCString(NULL, (const char *)parent_tag, kCFStringEncodingASCII);
    panel_text->value = CFStringCreateWithBytes(NULL, panel_tag, (CFIndex)strnlen((const char *)panel_tag, 64), kCFStringEncodingUTF8, false);
    prompt_text->value = CFStringCreateWithCString(NULL, (const char *)prompt, kCFStringEncodingASCII);
    s->result.calls++; application->value = AXUIElementCreateApplication(getpid()); // THIS PID only.
    if (!mrk_ax_type(s, parent_text->value, CFStringGetTypeID()) || !mrk_ax_type(s, panel_text->value, CFStringGetTypeID())
        || !mrk_ax_type(s, prompt_text->value, CFStringGetTypeID()) || !mrk_ax_type(s, application->value, s->elementType)) return;
    AXUIElementRef parent = NULL, sheet = NULL;
    if (!mrk_ax_projection(s, (AXUIElementRef)application->value, parent_text->value, panel_text->value, &parent, &sheet)) return;
    if (s->result.selection_mode) {
        MRKPromptOwned *filename = mrk_ax_slot(s); if (!filename) return;
        const char *leaf = strrchr((const char *)target, '/');
        if (!leaf || !leaf[1]) { mrk_ax_fail(s, MRK_OPEN_INPUT); return; }
        filename->value = CFStringCreateWithCString(NULL, leaf + 1, kCFStringEncodingUTF8);
        if (!mrk_ax_type(s, filename->value, CFStringGetTypeID())) return;
        for (;;) {
            if (!mrk_ax_selection_roster(s, sheet, filename->value)) return;
            if (s->result.selection_matches == 1) break;
            if (s->result.selection_sample == 1 && s->result.selection_checks == 1
                && !s->result.selection_matches && !s->result.selection_flags && !s->result.flags && !s->result.error) {
                mrk_ax_first_zero_diagnostic(s, sheet);
                if (s->result.error) return;
            }
            if (s->result.selection_sample == MRK_SELECT_SAMPLES) {
                mrk_ax_fail(s, MRK_OPEN_UNSUPPORTED); return; // Bounded no-content failure, not readiness.
            }
            if (!mrk_ax_content_wait(s) || !mrk_ax_next_content_sample(s)) return;
            // Same original AX application/parent/sheet. Projection itself
            // requires CFEqual with both retained originals; stage0 is NOT repeated.
            if (!mrk_ax_projection(s, (AXUIElementRef)application->value, parent_text->value, panel_text->value, &parent, &sheet)) return;
        }
        if (!mrk_ax_select_entry(s, parent, filename->value)) return;
        // Selector/readback are NOT URL identity. Original full proof1 and the
        // second full proof below both still require actual singleton URLs.
        if (!mrk_ax_original(s, 1)) return;
    }
    s->result.site = MRK_OPEN_CONTROL_PROJECTION;
    MRKControlPass initial = {0}, rechecked = {0}; // Separate immutable first-chain backing; no scratch reuse.
    if (!mrk_ax_control_roster(s, sheet, prompt_text->value, NO, &initial)) return;
    s->button = initial.nodes[initial.candidate]; // Assigned once; original CFArray ledger owns all ancestors too.
    s->result.site = MRK_OPEN_BUTTON;
    if (!mrk_ax_button(s, parent, &initial, prompt_text->value)) return;
    if (!mrk_ax_projection(s, (AXUIElementRef)application->value, parent_text->value, panel_text->value, &parent, &sheet)) return;
    s->result.site = MRK_OPEN_CONTROL_RECHECK;
    if (!mrk_ax_control_roster(s, sheet, prompt_text->value, YES, &rechecked)) return;
    if (initial.chain_count != rechecked.chain_count) { mrk_ax_fail(s, MRK_OPEN_CHANGED); return; }
    for (unsigned i = 0; i < initial.chain_count; ++i)
        if (!CFEqual(initial.nodes[initial.chain[i]], rechecked.nodes[rechecked.chain[i]])
            || initial.roles[initial.chain[i]] != rechecked.roles[rechecked.chain[i]]) {
            mrk_ax_fail(s, MRK_OPEN_CHANGED); return;
        }
    if (!mrk_ax_button(s, parent, &initial, prompt_text->value)) return;
    s->result.checks |= 64u; // Complete second projection, same original chain and revalidated eligibility.
    if (!mrk_ax_original(s, 2)) return;
    s->result.site = MRK_OPEN_ADMISSION;
    AXUIElementRef button = s->button;
    if (!mrk_ax_before(s, button)) return;
    // Last permit is atomic/clock-only. No query, wait, lock or replacement
    // follows it. Every error (even CannotComplete) permanently spends Press.
    s->result.site = MRK_OPEN_PRESS; s->result.calls++; s->result.flags |= MRK_OPEN_ATTEMPTED;
    AXError status = AXUIElementPerformAction(button, kAXPressAction);
    s->result.flags |= MRK_OPEN_RETURNED;
    if (status == kAXErrorSuccess) s->result.flags |= MRK_OPEN_TRIGGERED;
    mrk_ax_status(s, status, MRK_AX_OP_PERFORM_ACTION, MRK_AX_ATTR_NONE); mrk_ax_admit(s, 0, 1, NULL);
}
void mrk_observation_prompt_press(const uint8_t *parent, const uint8_t *panel, const uint8_t *prompt, size_t capacity,
    const uint8_t *target, size_t target_capacity, uint32_t selection,
    MRKOpenAdmission admission, MRKOpenRecheckCall recheck, void *context, MRKOpenResult *out) {
    if (!out) return;
    MRKOpenResult refused = {0}; refused.site = MRK_OPEN_ENTRY; refused.selection_mode = selection;
    if (pthread_main_np()) { refused.error = MRK_OPEN_THREAD; *out = refused; return; }
    if (!parent || !panel || !prompt || capacity != 64 || !target || target_capacity != 4097 || selection > 1 || !admission || !recheck || !context
        || !mrk_identity_tag((const char *)parent, "mrk-parent-") || !mrk_identity_utf8(panel)
        || !memcmp(parent, panel, capacity) || !mrk_prompt_valid(parent, prompt) || !mrk_target_path((const char *)target)) {
        refused.error = MRK_OPEN_INPUT; *out = refused; return;
    }
    size_t target_length = strnlen((const char *)target, target_capacity);
    if (target_length < 2) { refused.error = MRK_OPEN_INPUT; *out = refused; return; }
    for (size_t i = target_length; i < target_capacity; ++i)
        if (target[i]) { refused.error = MRK_OPEN_INPUT; *out = refused; return; }
    if (atomic_load(&mrk_prompt_unknown) || atomic_flag_test_and_set(&mrk_prompt_active)) {
        // Overlapping claims violate the same-original one-worker invariant;
        // do not let a later clear by the first worker authorize a successor.
        atomic_store(&mrk_prompt_unknown, true);
        refused.error = MRK_OPEN_CUSTODY; *out = refused; return;
    }
    unsigned index = atomic_load(&mrk_prompt_next);
    if (index >= MRK_PROMPT_ORIGINALS || !atomic_compare_exchange_strong(&mrk_prompt_next, &index, index + 1)) {
        atomic_store(&mrk_prompt_unknown, true); refused.error = MRK_OPEN_CUSTODY; *out = refused; return;
    }
    MRKPrompt *s = &mrk_prompt_originals[index]; s->admit = admission; s->recheck = recheck; s->context = context;
    s->cleanupKnown = YES; s->result.site = MRK_OPEN_ENTRY; s->result.selection_mode = selection;
    @try { mrk_ax_open(s, parent, panel, prompt, target); }
    @catch (NSException *e) { (void)e; mrk_ax_fail(s, MRK_OPEN_EXCEPTION); s->cleanupKnown = NO; }
    s->selection_attributes = NULL; s->timeout_element = NULL; s->installed_timeout = (MRKOpenTimeout){0};
    s->result.owned = s->count; // Reserved original slots, NOT a fabricated CFRelease count.
    if (s->cleanupKnown) {
        for (unsigned left = s->count; left; --left) {
            // Deadline8 still permits same-original late cleanup before45s.
            // Custody9 (including original45s expiry) retains every remaining
            // slot instead of beginning another release after its owner ends.
            mrk_ax_admit(s, 0, (s->result.flags & MRK_OPEN_ATTEMPTED) != 0, NULL);
            if (!s->cleanupKnown) break;
            MRKPromptOwned *slot = &s->owned[left - 1];
            @try { if (slot->value) CFRelease(slot->value); slot->value = NULL; s->result.released++; }
            @catch (NSException *e) {
                (void)e; s->cleanupKnown = NO;
                if (!s->result.error) { s->result.site = MRK_OPEN_CLEANUP; mrk_ax_fail(s, MRK_OPEN_CLEANUP_UNKNOWN); }
                break; // This release is never retried; remaining ledger stays retained.
            }
        }
    }
    mrk_ax_admit(s, 0, (s->result.flags & MRK_OPEN_ATTEMPTED) != 0, NULL);
    if (s->cleanupKnown && s->result.released == s->result.owned) s->result.flags |= MRK_OPEN_KNOWN;
    s->admit = NULL; s->recheck = NULL; s->context = NULL; // No dangling worker-stack callback in the retained CF ledger.
    *out = s->result; // All ordinary CF releases returned, or exact originals stay registered above.
    if (!(s->result.flags & MRK_OPEN_KNOWN)) atomic_store(&mrk_prompt_unknown, true);
    // Rust still requires the actual worker/main-recheck joins and exact old
    // panel completion before it may construct/dispatch a successor original.
    atomic_flag_clear(&mrk_prompt_active);
}
#endif

#endif /* !MRK_ENTRY_METADATA_ONLY: no Cocoa in the ordinary C entry. */
