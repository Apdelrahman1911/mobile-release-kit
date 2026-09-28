// Included ONLY below the accepted K1 implementation in its checked debug cfg.
// This finite fixture is not a worker/clock/process owner. The original native
// test caller owns admission, the one cutoff, all material and every real return.
// No pathname/password is accepted from an environment, argument or renderer.
// No item/default/search setter, preference restoration or recursive removal.
#if !defined(MRK_WRAPPING_KEYCHAIN_QUALIFICATION) || MRK_WRAPPING_KEYCHAIN_QUALIFICATION != 1
#error "private fixture requires the checked qualification compilation"
#endif
#include <stdio.h>
#include <limits.h>

#define MRK_Q_ACTIONS 17u
#define MRK_Q_CALLS 1024u
#define MRK_Q_REFS 10u
#define MRK_Q_SELECTIONS 4u
#define MRK_Q_MEMBERS 64u
#define MRK_Q_DIRECTORY_BOUND 8u
enum {
    MRK_Q_ENTROPY = 1, MRK_Q_CREATE, MRK_Q_DENY_READ, MRK_Q_RESTORE_DENY,
    MRK_Q_FOREIGN_USER, MRK_Q_RESTORE_USER, MRK_Q_FOREIGN_GROUP, MRK_Q_RESTORE_GROUP,
    MRK_Q_POSIX, MRK_Q_RESTORE_POSIX, MRK_Q_SYMLINK, MRK_Q_RESTORE_SYMLINK,
    MRK_Q_POST_ADD, MRK_Q_RESTORE_POST_ADD, MRK_Q_LOCK, MRK_Q_UNLOCK, MRK_Q_RETIRE
};
enum {
    MRK_Q_RANDOM = 1, MRK_Q_FGETPATH, MRK_Q_ABSENCE, MRK_Q_MKDIR,
    MRK_Q_SEARCH, MRK_Q_DEFAULT, MRK_Q_GETPATH, MRK_Q_REALPATH,
    MRK_Q_LSTAT, MRK_Q_EQUAL, MRK_Q_KEYCHAIN_CREATE, MRK_Q_ARRAY_COUNT,
    MRK_Q_USER_UUID, MRK_Q_GROUP_UUID, MRK_Q_FILESEC_INIT, MRK_Q_FSTATX,
    MRK_Q_ACL_PRESENT, MRK_Q_ACL_EXPORT, MRK_Q_ACL_VALID, MRK_Q_ACL_INIT,
    MRK_Q_ACL_ENTRY, MRK_Q_ACL_TAG, MRK_Q_ACL_QUALIFIER, MRK_Q_ACL_RIGHTS,
    MRK_Q_ACL_FLAGS, MRK_Q_ACL_ADD_FLAG, MRK_Q_ACL_SET_FLAGS, MRK_Q_ACL_SET,
    MRK_Q_ACL_DELETE, MRK_Q_ACL_FREE, MRK_Q_FILESEC_FREE, MRK_Q_CHMOD,
    MRK_Q_RENAME, MRK_Q_SYMLINK_CALL, MRK_Q_LINK_STAT, MRK_Q_READLINK,
    MRK_Q_UNLINK_LINK, MRK_Q_KEYCHAIN_LOCK, MRK_Q_KEYCHAIN_UNLOCK,
    MRK_Q_SYNC_COPY, MRK_Q_SYNC_COUNT, MRK_Q_KEYCHAIN_DELETE, MRK_Q_RMDIR,
    MRK_Q_OWNER_PROPERTY, MRK_Q_GROUP_PROPERTY, MRK_Q_MODE_PROPERTY
};
// result is the actual integral result/status, or pointer nonnull0/1 for the
// documented pointer-return kinds. FILESEC_FREE records0 after the void return.
// errno is sampled immediately, even when0; it is never a replacement status.
typedef struct {
    uint32_t kind, entered, returned;
    int32_t actual_errno;
    int64_t result;
} MRKQCall;
typedef struct {
    uint32_t kind, entered, returned, completed, first_call, end_call;
} MRKQAction;
typedef struct {
    uint32_t entered, returned, search_typed, default_kind, count;
    uint32_t members_entered, members_returned, members_typed;
    uint32_t paths_entered, paths_returned, identities_admitted;
    uint32_t comparisons_entered, comparisons_returned, unchanged, fixture_absent;
} MRKQSelection;
typedef struct {
    uint32_t version, bytes, action_count, call_count, ref_count;
    uint32_t failed, unknown, stopped, exception, callbacks_cleared;
    uint32_t material_generated, root_created, root_removed, create_effect;
    uint32_t provider_deleted, sync_entered, sync_returned, sync_absent_empty, finalized, reserved;
    MRKQAction actions[MRK_Q_ACTIONS];
    MRKQCall calls[MRK_Q_CALLS];
    MRKWrappingReference references[MRK_Q_REFS];
    MRKQSelection selections[MRK_Q_SELECTIONS];
    MRKWrappingResult namespace;
} MRKQResult;
_Static_assert(sizeof(MRKQCall) == 24, "fixture actual scalar call ABI");
_Static_assert(sizeof(MRKQAction) == 24, "fixture fixed action ABI");
_Static_assert(sizeof(MRKQSelection) == 60, "fixture selection observation ABI");
_Static_assert(sizeof(MRKQResult) == 29384, "fixture scalar result ABI");
typedef uint32_t (*MRKQAdmission)(void *, const MRKQResult *, uint32_t);
typedef struct {
    CFTypeRef value;
    union { CFArrayRef array; SecKeychainRef keychain; CFPropertyListRef preference; } pending;
    uint32_t known_owned;
} MRKQOwned;
typedef struct {
    MRKWrappingIdentity identities[MRK_Q_MEMBERS + 1];
    uint32_t search_slot, default_slot;
} MRKQSelectionCell;
typedef struct {
    filesec_t filesec;
    acl_t original, replacement;
    acl_entry_t entry;
    acl_flagset_t flags;
    int present;
    uid_t owner; gid_t group; mode_t mode;
    uint32_t saved, changed, restored;
    struct stat snapshot;
} MRKQMutation;
typedef struct {
    MRKWrappingFrame ns;
    MRKQResult result;
    MRKQOwned owned[MRK_Q_REFS];
    MRKQSelectionCell selection[MRK_Q_SELECTIONS];
    MRKQMutation mutations[3];
    MRKQAdmission admission;
    void *context;
    uint32_t running, spent_free, root_index, active_acl, active_mode;
    uint32_t link_changed, link_unlinked, created_slot, active_action;
    uint32_t saved_name_offset, material_issued, binding_issued;
    MRKWrappingQualificationFixture pin;
    uint8_t token[16], key[32], ids[128], password[32];
    uuid_t foreign_user, foreign_group;
    char root_name[64], native_path[MRK_W_PATH], canonical_path[MRK_W_PATH];
    char observed[MRK_W_PATH], canonical[MRK_W_PATH], link_text[64];
    struct stat metadata, link_identity;
} MRKQFixture;
_Static_assert(sizeof(MRKQFixture) <= 196608, "bounded private fixture frame");
static const char mrk_q_leaf[] = "synthetic.keychain-db";
static const char mrk_q_demunged[] = "synthetic.keychain";
static const char mrk_q_saved[] = "saved-synthetic.keychain-db";

static int mrk_q_fail(MRKQFixture *f) { f->result.failed = 1; return 0; }
static void mrk_q_unknown(MRKQFixture *f) {
    f->result.failed = f->result.unknown = 1;
    mrk_w_unknown(&f->ns, MRK_W_CUSTODY);
}
static void mrk_q_snapshot(MRKQFixture *f) {
    f->result.namespace = f->ns.result;
    f->result.callbacks_cleared = f->admission == NULL && f->context == NULL
        && f->ns.admission == NULL && f->ns.context == NULL;
}
static int mrk_q_admit(MRKQFixture *f, uint32_t checkpoint) {
    if (f->result.unknown || !f->admission || !f->context) return 0;
    mrk_q_snapshot(f);
    uint32_t reply = f->admission(f->context, &f->result, checkpoint);
    if (reply == MRK_W_CUTOFF) { f->result.stopped = 1; return mrk_q_fail(f); }
    if (reply != MRK_W_CONTINUE) { mrk_q_unknown(f); return 0; }
    return 1;
}
static uint32_t mrk_q_namespace_admission(void *context, const MRKWrappingResult *raw, uint32_t checkpoint) {
    MRKQFixture *f = context;
    if (!f || raw != &f->ns.result) return MRK_W_RETAIN;
    // In a returned-failed-close state the common implementation alone decides
    // which remaining original descriptor numbers are independent eligible work.
    return mrk_q_admit(f, checkpoint) ? MRK_W_CONTINUE
        : f->result.stopped && !f->result.unknown ? MRK_W_CUTOFF : MRK_W_RETAIN;
}
static MRKQCall *mrk_q_call(MRKQFixture *f, uint32_t kind, uint32_t checkpoint) {
    if (!mrk_q_admit(f, checkpoint)) return NULL;
    if (f->result.call_count >= MRK_Q_CALLS
        || (f->result.call_count && !f->result.calls[f->result.call_count - 1].returned)) {
        mrk_q_unknown(f); return NULL;
    }
    MRKQCall *call = &f->result.calls[f->result.call_count++];
    call->kind = kind; call->entered = 1;
    return call;
}
static void mrk_q_return(MRKQCall *call, int64_t result, int actual_errno) {
    call->result = result; call->actual_errno = actual_errno; call->returned = 1;
}
#define MRK_Q_SCALAR(kind, expression, predicate) do { \
    MRKQCall *q_call = mrk_q_call(f, (kind), MRK_W_BEFORE_CALL); if (!q_call) return 0; \
    errno = 0; int64_t q_rc = (int64_t)(expression); int q_errno = errno; \
    mrk_q_return(q_call, q_rc, q_errno); \
    if (!(predicate)) return mrk_q_fail(f); \
    if (!mrk_q_admit(f, MRK_W_AFTER_CALL)) return 0; \
} while (0)
static int mrk_q_nonzero(const uint8_t *bytes, size_t count) {
    uint8_t bits = 0;
    for (size_t i = 0; i < count; ++i) bits |= bytes[i];
    return bits != 0;
}
static int mrk_q_spelling(const char *path) {
    size_t n = strnlen(path, MRK_W_PATH);
    if (n < 2 || n == MRK_W_PATH || path[0] != '/' || path[n - 1] == '/') return 0;
    size_t start = 1;
    for (size_t i = 0; i < n; ++i) {
        unsigned char byte = (unsigned char)path[i];
        // Deliberately narrower than production: refuse Unicode/case-alias
        // uncertainty rather than implement a second filesystem normalizer.
        if (byte < 32 || byte > 126) return 0;
        if (i && path[i] == '/') {
            size_t width = i - start;
            if (!width || width > 255 || (width == 1 && path[start] == '.')
                || (width == 2 && path[start] == '.' && path[start + 1] == '.')) return 0;
            start = i + 1;
        }
    }
    size_t width = n - start;
    return width && width <= 255 && !(width == 1 && path[start] == '.')
        && !(width == 2 && path[start] == '.' && path[start + 1] == '.');
}
static unsigned char mrk_q_lower(unsigned char c) { return c >= 'A' && c <= 'Z' ? (unsigned char)(c + ('a' - 'A')) : c; }
static int mrk_q_contains_folded(const char *path, const char *needle) {
    size_t n = strlen(path), m = strlen(needle);
    for (size_t at = 0; at + m <= n; ++at) {
        size_t i = 0;
        while (i < m && mrk_q_lower((unsigned char)path[at + i]) == (unsigned char)needle[i]) ++i;
        if (i == m) return 1;
    }
    return 0;
}
static int mrk_q_private_spelling(const char *path) {
    // StorageManager tests the ENTIRE pathname, not just its final component.
    // This conservative refusal also rejects System/login case aliases in any
    // ancestor. It happens before Create, never as restore-after-mutation.
    return mrk_q_spelling(path) && !mrk_q_contains_folded(path, "/login.keychain")
        && !mrk_q_contains_folded(path, "/system.keychain");
}
static size_t mrk_q_unmunged_length(const char *path) {
    size_t n = strlen(path);
    return n >= 3 && path[n - 3] == '-' && mrk_q_lower((unsigned char)path[n - 2]) == 'd'
        && mrk_q_lower((unsigned char)path[n - 1]) == 'b' ? n - 3 : n;
}
static int mrk_q_equivalent_spelling(const char *left, const char *right) {
    size_t a = mrk_q_unmunged_length(left), b = mrk_q_unmunged_length(right);
    if (a != b) return 0;
    for (size_t i = 0; i < a; ++i)
        if (mrk_q_lower((unsigned char)left[i]) != mrk_q_lower((unsigned char)right[i])) return 0;
    return 1;
}
static int mrk_q_fgetpath(MRKQFixture *f, int fd, char *out) {
    memset(out, 0, MRK_W_PATH);
    MRK_Q_SCALAR(MRK_Q_FGETPATH, fcntl(fd, F_GETPATH, out), q_rc == 0);
    return mrk_q_private_spelling(out) ? 1 : mrk_q_fail(f);
}
static int mrk_q_pair(MRKQFixture *f, MRKWrappingFd *slot, MRKWrappingIdentity expected) {
    if (!mrk_w_held(&f->ns, slot, &f->ns.held_stat) || !mrk_w_named(&f->ns, slot, &f->ns.named_stat))
        return mrk_q_fail(f);
    return mrk_w_same(expected, mrk_w_identity(&f->ns.held_stat))
        && mrk_w_same(expected, mrk_w_identity(&f->ns.named_stat)) ? 1 : mrk_q_fail(f);
}
static int mrk_q_ancestry(MRKQFixture *f) {
    MRKWrappingFrame *s = &f->ns;
    if (!s->result.directory_count || s->result.directory_count > MRK_Q_DIRECTORY_BOUND) return mrk_q_fail(f);
    for (uint32_t i = 0; i < s->result.directory_count; ++i) {
        MRKWrappingFd *slot = &s->fds[i];
        if (i == f->root_index && (f->active_acl || f->active_mode)) {
            // Only a separately recorded still-owned task-root mutation gets
            // this restoration check. It is NOT an adapter admission or pass.
            if (!mrk_q_pair(f, slot, slot->identity) || !mrk_w_filesystem(s, slot)) return mrk_q_fail(f);
        } else if (!mrk_w_fd_check(s, i)) return mrk_q_fail(f);
    }
    return 1;
}
static int mrk_q_absent(MRKQFixture *f, int parent, const char *name) {
    MRKQCall *call = mrk_q_call(f, MRK_Q_ABSENCE, MRK_W_BEFORE_CALL); if (!call) return 0;
    memset(&f->metadata, 0, sizeof(f->metadata));
    errno = 0; int rc = fstatat(parent, name, &f->metadata, AT_SYMLINK_NOFOLLOW); int saved = errno;
    mrk_q_return(call, rc, saved);
    if (rc != -1 || saved != ENOENT) return mrk_q_fail(f);
    return mrk_q_admit(f, MRK_W_AFTER_CALL);
}
static MRKQOwned *mrk_q_slot(MRKQFixture *f, uint32_t *index) {
    if (f->result.ref_count >= MRK_Q_REFS) { mrk_q_unknown(f); return NULL; }
    *index = f->result.ref_count++;
    f->result.references[*index].reserved = 1;
    return &f->owned[*index];
}
static void mrk_q_cf_enter(MRKQFixture *f, uint32_t index) { f->result.references[index].call_entered = 1; }
static void mrk_q_cf_return(MRKQFixture *f, uint32_t index, int owned) {
    MRKWrappingReference *r = &f->result.references[index];
    r->call_returned = 1; r->nonnull_returned = f->owned[index].value != NULL;
    f->owned[index].known_owned = owned && r->nonnull_returned;
    if (r->nonnull_returned && !owned) mrk_q_unknown(f);
}
static int mrk_q_release(MRKQFixture *f, uint32_t index) {
    MRKWrappingReference *r = &f->result.references[index]; MRKQOwned *slot = &f->owned[index];
    if (!r->nonnull_returned) return r->call_entered == r->call_returned ? 1 : mrk_q_fail(f);
    if (!slot->known_owned || !slot->value || r->release_entered) { mrk_q_unknown(f); return 0; }
    if (!mrk_q_admit(f, MRK_W_BEFORE_RELEASE)) return 0;
    r->release_entered = 1;
    @try {
        CFRelease(slot->value);
        r->release_returned = 1; slot->value = NULL; slot->known_owned = 0;
    } @catch (NSException *exception) {
        (void)exception; f->result.exception = 1; mrk_q_unknown(f); return 0;
    }
    return 1;
}
static int mrk_q_getpath(MRKQFixture *f, SecKeychainRef keychain) {
    memset(f->observed, 0, sizeof(f->observed));
    UInt32 bytes = sizeof(f->observed);
    MRKQCall *call = mrk_q_call(f, MRK_Q_GETPATH, MRK_W_BEFORE_CALL); if (!call) return 0;
    errno = 0; OSStatus rc = SecKeychainGetPath(keychain, &bytes, f->observed); int saved = errno;
    mrk_q_return(call, rc, saved);
    size_t length = strnlen(f->observed, sizeof(f->observed));
    if (rc != errSecSuccess || !bytes || bytes > sizeof(f->observed) || length == sizeof(f->observed)
        || (bytes != length && bytes != length + 1) || !mrk_q_spelling(f->observed)) return mrk_q_fail(f);
    return mrk_q_admit(f, MRK_W_AFTER_CALL);
}
static int mrk_q_selection_identity(MRKQFixture *f, SecKeychainRef keychain,
    MRKWrappingIdentity *out, const MRKWrappingIdentity *fixture_leaf) {
    if (!keychain || CFGetTypeID(keychain) != SecKeychainGetTypeID() || !mrk_q_getpath(f, keychain)) return mrk_q_fail(f);
    if (mrk_q_equivalent_spelling(f->observed, f->native_path)
        || mrk_q_equivalent_spelling(f->observed, f->canonical_path)) return mrk_q_fail(f);
    // A returned spelling alone or CF pointer inequality is not nonmembership.
    // Resolve bounded metadata for the actual returned selection and require a
    // presently existing regular object. A missing/munged/uncertain alias refuses;
    // we do not open another Keychain, try another provider path or query items.
    MRKQCall *call = mrk_q_call(f, MRK_Q_REALPATH, MRK_W_BEFORE_CALL); if (!call) return 0;
    memset(f->canonical, 0, sizeof(f->canonical));
    errno = 0; char *resolved = realpath(f->observed, f->canonical); int saved = errno;
    mrk_q_return(call, resolved != NULL, saved);
    if (resolved != f->canonical || !mrk_q_spelling(f->canonical)
        || mrk_q_equivalent_spelling(f->canonical, f->native_path)
        || mrk_q_equivalent_spelling(f->canonical, f->canonical_path)) return mrk_q_fail(f);
    if (!mrk_q_admit(f, MRK_W_AFTER_CALL)) return 0;
    memset(&f->metadata, 0, sizeof(f->metadata));
    MRK_Q_SCALAR(MRK_Q_LSTAT, lstat(f->canonical, &f->metadata), q_rc == 0);
    if (!S_ISREG(f->metadata.st_mode)) return mrk_q_fail(f);
    *out = mrk_w_identity(&f->metadata);
    if (fixture_leaf && out->dev == fixture_leaf->dev && out->ino == fixture_leaf->ino) return mrk_q_fail(f);
    if (f->result.create_effect == 1) {
        call = mrk_q_call(f, MRK_Q_EQUAL, MRK_W_BEFORE_CALL); if (!call) return 0;
        errno = 0; Boolean equal = CFEqual(keychain, f->owned[f->created_slot].value); saved = errno;
        mrk_q_return(call, equal != 0, saved);
        if (equal || !mrk_q_admit(f, MRK_W_AFTER_CALL)) return mrk_q_fail(f);
    }
    return 1;
}
static int mrk_q_selection(MRKQFixture *f, uint32_t which, const MRKWrappingIdentity *fixture_leaf) {
    if (which >= MRK_Q_SELECTIONS || f->result.selections[which].entered) return mrk_q_fail(f);
    MRKQSelection *r = &f->result.selections[which]; MRKQSelectionCell *cell = &f->selection[which];
    r->entered = 1;
    MRKQOwned *search = mrk_q_slot(f, &cell->search_slot); if (!search) return 0;
    MRKQCall *call = mrk_q_call(f, MRK_Q_SEARCH, MRK_W_BEFORE_CALL); if (!call) return 0;
    mrk_q_cf_enter(f, cell->search_slot);
    errno = 0; OSStatus rc = SecKeychainCopySearchList(&search->pending.array); int saved = errno;
    search->value = search->pending.array; mrk_q_return(call, rc, saved);
    mrk_q_cf_return(f, cell->search_slot, rc == errSecSuccess);
    if (rc != errSecSuccess || !search->value || f->result.unknown || !mrk_q_admit(f, MRK_W_AFTER_CALL)) return mrk_q_fail(f);
    if (CFGetTypeID(search->value) != CFArrayGetTypeID()) return mrk_q_fail(f);
    r->search_typed = 1;
    call = mrk_q_call(f, MRK_Q_ARRAY_COUNT, MRK_W_BEFORE_CALL); if (!call) return 0;
    errno = 0; CFIndex count = CFArrayGetCount((CFArrayRef)search->value); saved = errno;
    mrk_q_return(call, (int64_t)count, saved);
    // Before any caller member traversal/retention. This says nothing about the
    // getter's internal allocation or traversal capacity before its return.
    if (count < 0 || count > MRK_Q_MEMBERS) return mrk_q_fail(f);
    r->count = (uint32_t)count;
    if (!mrk_q_admit(f, MRK_W_AFTER_CALL)) return 0;
    MRKQOwned *def = mrk_q_slot(f, &cell->default_slot); if (!def) return 0;
    call = mrk_q_call(f, MRK_Q_DEFAULT, MRK_W_BEFORE_CALL); if (!call) return 0;
    mrk_q_cf_enter(f, cell->default_slot);
    errno = 0; rc = SecKeychainCopyDefault(&def->pending.keychain); saved = errno;
    def->value = def->pending.keychain; mrk_q_return(call, rc, saved);
    mrk_q_cf_return(f, cell->default_slot, rc == errSecSuccess);
    if (f->result.unknown || !mrk_q_admit(f, MRK_W_AFTER_CALL)) return 0;
    if (rc == errSecNoDefaultKeychain && !def->value) r->default_kind = 1;
    else if (rc == errSecSuccess && def->value && CFGetTypeID(def->value) == SecKeychainGetTypeID()) r->default_kind = 2;
    else return mrk_q_fail(f);
    for (uint32_t i = 0; i < r->count; ++i) {
        ++r->members_entered;
        CFTypeRef item = CFArrayGetValueAtIndex((CFArrayRef)search->value, (CFIndex)i);
        ++r->members_returned;
        if (!item || CFGetTypeID(item) != SecKeychainGetTypeID()) return mrk_q_fail(f);
        ++r->members_typed; ++r->paths_entered;
        if (!mrk_q_selection_identity(f, (SecKeychainRef)item, &cell->identities[i], fixture_leaf)) return 0;
        ++r->paths_returned; ++r->identities_admitted;
    }
    if (r->default_kind == 2) {
        ++r->paths_entered;
        if (!mrk_q_selection_identity(f, (SecKeychainRef)def->value, &cell->identities[MRK_Q_MEMBERS], fixture_leaf)) return 0;
        ++r->paths_returned; ++r->identities_admitted;
    }
    r->fixture_absent = 1; r->returned = 1;
    return 1;
}
static int mrk_q_selection_unchanged(MRKQFixture *f, uint32_t which) {
    MRKQSelection *before = &f->result.selections[0], *after = &f->result.selections[which];
    MRKQSelectionCell *a = &f->selection[0], *b = &f->selection[which];
    if (!before->returned || !after->returned || before->count != after->count || before->default_kind != after->default_kind)
        return mrk_q_fail(f);
    for (uint32_t i = 0; i < before->count + (before->default_kind == 2); ++i) {
        uint32_t position = i < before->count ? i : MRK_Q_MEMBERS;
        CFTypeRef left = position == MRK_Q_MEMBERS ? f->owned[a->default_slot].value
            : CFArrayGetValueAtIndex((CFArrayRef)f->owned[a->search_slot].value, (CFIndex)i);
        CFTypeRef right = position == MRK_Q_MEMBERS ? f->owned[b->default_slot].value
            : CFArrayGetValueAtIndex((CFArrayRef)f->owned[b->search_slot].value, (CFIndex)i);
        ++after->comparisons_entered;
        MRKQCall *call = mrk_q_call(f, MRK_Q_EQUAL, MRK_W_BEFORE_CALL); if (!call) return 0;
        errno = 0; Boolean equal = CFEqual(left, right); int saved = errno;
        mrk_q_return(call, equal != 0, saved);
        ++after->comparisons_returned;
        if (!equal || !mrk_w_same(a->identities[position], b->identities[position])) return mrk_q_fail(f);
        if (!mrk_q_admit(f, MRK_W_AFTER_CALL)) return 0;
    }
    after->unchanged = 1;
    return 1;
}

static int mrk_q_random(MRKQFixture *f, uint8_t *out, size_t length) {
    MRKQCall *call = mrk_q_call(f, MRK_Q_RANDOM, MRK_W_BEFORE_CALL); if (!call) return 0;
    errno = 0; int rc = SecRandomCopyBytes(kSecRandomDefault, length, out); int saved = errno;
    mrk_q_return(call, rc, saved);
    if (rc != errSecSuccess || !mrk_q_nonzero(out, length)) return mrk_q_fail(f);
    return mrk_q_admit(f, MRK_W_AFTER_CALL);
}
static int mrk_q_entropy(MRKQFixture *f) {
    if (!mrk_q_random(f, f->token, sizeof(f->token)) || !mrk_q_random(f, f->key, sizeof(f->key))
        || !mrk_q_random(f, f->ids, sizeof(f->ids)) || !mrk_q_random(f, f->password, sizeof(f->password))) return 0;
    for (unsigned i = 0; i < 4; ++i) {
        if (!mrk_w_ids(f->ids + i * 32, f->ids + i * 32 + 16)) return mrk_q_fail(f);
        for (unsigned j = 0; j < i; ++j)
            if (!memcmp(f->ids + i * 32, f->ids + j * 32, 32)) return mrk_q_fail(f);
    }
    f->result.material_generated = 1;
    return 1;
}
static int mrk_q_prepare_root(MRKQFixture *f) {
    MRKWrappingFrame *s = &f->ns;
    if (!f->result.material_generated) return mrk_q_fail(f);
    // Reuse the exact readonly production selector. No password database or
    // HOME substitute exists here; its actual selected native prefix is reused.
    s->qualification.observation.version = 1;
    s->qualification.observation.mode = MRK_W_Q_SELECTOR;
    s->qualification.observation.configured = 1;
    (void)mrk_w_account(s);
    if (s->result.outcome != MRK_W_PENDING || s->result.flags & (MRK_W_STOP | MRK_W_UNKNOWN)
        || !s->qualification.observation.account_selected || !s->qualification.observation.selector_boundary_returned)
        return mrk_q_fail(f);
    static const char login[] = "/Library/Keychains/login.keychain-db";
    static const char parent[] = "/Library/Keychains/";
    static const char prefix[] = "mrk-wrapping-qualification-";
    static const char hex[] = "0123456789abcdef";
    size_t selected = strnlen(s->path, sizeof(s->path));
    if (selected < sizeof(login) || memcmp(s->path + selected - (sizeof(login) - 1), login, sizeof(login))) return mrk_q_fail(f);
    size_t home = selected - (sizeof(login) - 1);
    memcpy(f->root_name, prefix, sizeof(prefix) - 1);
    for (unsigned i = 0; i < 16; ++i) {
        f->root_name[sizeof(prefix) - 1 + i * 2] = hex[f->token[i] >> 4];
        f->root_name[sizeof(prefix) + i * 2] = hex[f->token[i] & 15];
    }
    f->root_name[sizeof(prefix) - 1 + 32] = 0;
    size_t root_bytes = strlen(f->root_name);
    if (home + sizeof(parent) - 1 + root_bytes + 1 + sizeof(mrk_q_leaf) > sizeof(s->path)) return mrk_q_fail(f);
    memcpy(s->path + home, parent, sizeof(parent) - 1);
    memcpy(s->path + home + sizeof(parent) - 1, f->root_name, root_bytes + 1);
    if (!mrk_q_private_spelling(s->path)) return mrk_q_fail(f);
    uint32_t components = 0;
    for (const char *p = s->path; *p; ++p) if (*p == '/') ++components;
    if (components + 1 > MRK_Q_DIRECTORY_BOUND
        || strlen(s->path) + 1 + sizeof(mrk_q_leaf) + sizeof(mrk_q_saved) > sizeof(s->component_names)) return mrk_q_fail(f);
    s->qualification.observation.mode = 0; // No qualification root pin before creation.
    // The token root is the not-yet-opened final component. Thus this SAME
    // parser/acquirer admits only existing protected native-home ancestry.
    if (!mrk_w_path_admission(s, home) || s->result.directory_count + 1 > MRK_Q_DIRECTORY_BOUND) return mrk_q_fail(f);
    f->root_index = s->result.directory_count;
    MRKWrappingFd *parent_fd = &s->fds[f->root_index - 1];
    if (!mrk_q_fgetpath(f, parent_fd->fd, f->canonical)) return 0;
    size_t canonical_parent = strlen(f->canonical), root_path_bytes = strlen(s->path);
    if (canonical_parent + 1 + root_bytes + 1 + sizeof(mrk_q_leaf) > sizeof(f->canonical_path)) return mrk_q_fail(f);
    memcpy(f->canonical_path, f->canonical, canonical_parent);
    f->canonical_path[canonical_parent] = '/';
    memcpy(f->canonical_path + canonical_parent + 1, f->root_name, root_bytes);
    size_t canonical_root = canonical_parent + 1 + root_bytes;
    f->canonical_path[canonical_root] = '/';
    memcpy(f->canonical_path + canonical_root + 1, mrk_q_leaf, sizeof(mrk_q_leaf));
    memcpy(f->native_path, s->path, root_path_bytes);
    f->native_path[root_path_bytes] = '/';
    memcpy(f->native_path + root_path_bytes + 1, mrk_q_leaf, sizeof(mrk_q_leaf));
    // Check both admitted/native and actual provider-ancestor spellings BEFORE
    // mkdir/Create. There is no alternate location if either spelling refuses.
    if (!mrk_q_private_spelling(f->native_path) || !mrk_q_private_spelling(f->canonical_path)
        || !mrk_q_absent(f, parent_fd->fd, f->root_name)) return mrk_q_fail(f);
    MRKQCall *mkdir_call = mrk_q_call(f, MRK_Q_MKDIR, MRK_W_BEFORE_CALL); if (!mkdir_call) return 0;
    errno = 0; int mkdir_result = mkdirat(parent_fd->fd, f->root_name, 0700); int mkdir_errno = errno;
    mrk_q_return(mkdir_call, mkdir_result, mkdir_errno);
    if (mkdir_result == 0) f->result.root_created = 1; // Before observing any cutoff after the actual effect.
    if (mkdir_result != 0 || !mrk_q_admit(f, MRK_W_AFTER_CALL)) return mrk_q_fail(f);
    // Upgrade only the fresh predeclared token-root slot and reserve the five
    // existing common leaf slots. No held original is reset/reopened or adopted.
    ++s->result.directory_count;
    s->result.descriptor_count = s->result.directory_count + MRK_W_CHECKPOINTS;
    MRKWrappingFd *root = &s->fds[f->root_index];
    root->directory = 1;
    size_t leaf_offset = root_path_bytes + 1;
    memcpy(s->component_names + leaf_offset, mrk_q_leaf, sizeof(mrk_q_leaf));
    f->saved_name_offset = (uint32_t)(leaf_offset + sizeof(mrk_q_leaf));
    memcpy(s->component_names + f->saved_name_offset, mrk_q_saved, sizeof(mrk_q_saved));
    for (uint32_t i = s->result.directory_count; i < s->result.descriptor_count; ++i) {
        MRKWrappingFd *slot = &s->fds[i];
        s->result.descriptors[i].reserved = 1;
        slot->directory = 0; slot->parent = f->root_index; slot->name_offset = (uint32_t)leaf_offset; slot->uid_rule = 1;
    }
    memcpy(s->path, f->native_path, strlen(f->native_path) + 1);
    if (!mrk_w_fd_acquire(s, f->root_index) || root->identity.mode != (mode_t)(S_IFDIR | 0700)
        || root->identity.uid != s->uid) return mrk_q_fail(f);
    if (!mrk_q_fgetpath(f, root->fd, f->observed) || strlen(f->observed) != canonical_root
        || memcmp(f->observed, f->canonical_path, canonical_root)) return mrk_q_fail(f);
    f->pin.version = 1; f->pin.bytes = sizeof(f->pin);
    f->pin.root_device = (uint64_t)(uint32_t)root->identity.dev; f->pin.root_inode = (uint64_t)root->identity.ino;
    f->pin.root_mode = (uint32_t)root->identity.mode; f->pin.root_uid = (uint32_t)root->identity.uid;
    f->pin.root_gid = (uint32_t)root->identity.gid; memcpy(f->pin.token, f->token, sizeof(f->token));
    return mrk_q_ancestry(f) && mrk_q_absent(f, root->fd, mrk_q_leaf) && mrk_q_absent(f, root->fd, mrk_q_demunged);
}
static int mrk_q_create(MRKQFixture *f) {
    if (!mrk_q_prepare_root(f) || !mrk_q_selection(f, 0, NULL) || !mrk_q_ancestry(f)) return 0;
    MRKWrappingFd *root = &f->ns.fds[f->root_index];
    if (!mrk_q_absent(f, root->fd, mrk_q_leaf) || !mrk_q_absent(f, root->fd, mrk_q_demunged)) return 0;
    MRKQOwned *created = mrk_q_slot(f, &f->created_slot); if (!created) return 0;
    MRKQCall *call = mrk_q_call(f, MRK_Q_KEYCHAIN_CREATE, MRK_W_BEFORE_CALL); if (!call) return 0;
    f->result.create_effect = 2; // MayHaveCreated BEFORE the sole call, never reset on failure.
    mrk_q_cf_enter(f, f->created_slot);
    errno = 0;
    OSStatus rc = SecKeychainCreate(f->native_path, (UInt32)sizeof(f->password), f->password, false, NULL, &created->pending.keychain);
    int saved = errno;
    created->value = created->pending.keychain; mrk_q_return(call, rc, saved);
    mrk_q_cf_return(f, f->created_slot, rc == errSecSuccess);
    if (rc == errSecSuccess) f->result.create_effect = 1;
    if (rc != errSecSuccess || !created->value || f->result.unknown
        || !mrk_q_admit(f, MRK_W_AFTER_CALL) || CFGetTypeID(created->value) != SecKeychainGetTypeID()) return mrk_q_fail(f);
    if (!mrk_q_getpath(f, (SecKeychainRef)created->value) || strcmp(f->observed, f->native_path)
        || !mrk_q_ancestry(f) || !mrk_w_fd_acquire(&f->ns, f->ns.result.directory_count)) return mrk_q_fail(f);
    const MRKWrappingIdentity *leaf = &f->ns.fds[f->ns.result.directory_count].identity;
    return mrk_q_selection(f, 1, leaf) && mrk_q_selection_unchanged(f, 1) && mrk_q_ancestry(f);
}
static int mrk_q_foreign_uuids(MRKQFixture *f) {
    if (mrk_q_nonzero(f->foreign_user, sizeof(uuid_t)) || mrk_q_nonzero(f->foreign_group, sizeof(uuid_t))) return mrk_q_fail(f);
    // Fixed read-only membership mappings, never account creation or group/user
    // equivalence. Nobody's USER UUID and wheel's GROUP UUID must be distinct
    // from both trusted USER UUIDs; no principal bytes/IDs enter public output.
    MRK_Q_SCALAR(MRK_Q_USER_UUID, mbr_uid_to_uuid((uid_t)-2, f->foreign_user), q_rc == 0);
    MRK_Q_SCALAR(MRK_Q_GROUP_UUID, mbr_gid_to_uuid((gid_t)0, f->foreign_group), q_rc == 0);
    if (!mrk_q_nonzero(f->foreign_user, sizeof(uuid_t)) || !mrk_q_nonzero(f->foreign_group, sizeof(uuid_t))
        || !memcmp(f->foreign_user, f->foreign_group, sizeof(uuid_t))
        || !memcmp(f->foreign_user, f->ns.root_uuid, sizeof(uuid_t)) || !memcmp(f->foreign_user, f->ns.user_uuid, sizeof(uuid_t))
        || !memcmp(f->foreign_group, f->ns.root_uuid, sizeof(uuid_t)) || !memcmp(f->foreign_group, f->ns.user_uuid, sizeof(uuid_t)))
        return mrk_q_fail(f);
    return 1;
}
static int mrk_q_save_acl(MRKQFixture *f, MRKQMutation *m) {
    if (m->saved || m->filesec || m->original || m->replacement || f->active_acl || f->active_mode || !mrk_q_ancestry(f))
        return mrk_q_fail(f);
    MRKQCall *call = mrk_q_call(f, MRK_Q_FILESEC_INIT, MRK_W_BEFORE_CALL); if (!call) return 0;
    errno = 0; m->filesec = filesec_init(); int saved = errno;
    mrk_q_return(call, m->filesec != NULL, saved);
    if (!m->filesec || !mrk_q_admit(f, MRK_W_AFTER_CALL)) return mrk_q_fail(f);
    int fd = f->ns.fds[f->root_index].fd;
    MRK_Q_SCALAR(MRK_Q_FSTATX, fstatx_np(fd, &m->snapshot, m->filesec), q_rc == 0);
    if (!mrk_w_same(mrk_w_identity(&m->snapshot), f->ns.fds[f->root_index].identity)) return mrk_q_fail(f);
    MRK_Q_SCALAR(MRK_Q_OWNER_PROPERTY, filesec_get_property(m->filesec, FILESEC_OWNER, &m->owner),
        q_rc == 0 && m->owner == m->snapshot.st_uid);
    MRK_Q_SCALAR(MRK_Q_GROUP_PROPERTY, filesec_get_property(m->filesec, FILESEC_GROUP, &m->group),
        q_rc == 0 && m->group == m->snapshot.st_gid);
    MRK_Q_SCALAR(MRK_Q_MODE_PROPERTY, filesec_get_property(m->filesec, FILESEC_MODE, &m->mode),
        q_rc == 0 && m->mode == m->snapshot.st_mode);
    MRK_Q_SCALAR(MRK_Q_ACL_PRESENT, filesec_query_property(m->filesec, FILESEC_ACL, &m->present), q_rc == 0 && (m->present == 0 || m->present == 1));
    if (m->present) {
        call = mrk_q_call(f, MRK_Q_ACL_EXPORT, MRK_W_BEFORE_CALL); if (!call) return 0;
        errno = 0; int rc = filesec_get_property(m->filesec, FILESEC_ACL, &m->original); saved = errno;
        mrk_q_return(call, rc, saved);
        if (rc || !m->original || (void *)m->original == _FILESEC_REMOVE_ACL || (void *)m->original == _FILESEC_UNSET_PROPERTY) {
            // Sentinel bits are not allocations. A populated failed export
            // remains unknown and is never passed to free as a cleanup guess.
            if ((void *)m->original == _FILESEC_REMOVE_ACL || (void *)m->original == _FILESEC_UNSET_PROPERTY) m->original = NULL;
            if (rc && m->original) mrk_q_unknown(f);
            return mrk_q_fail(f);
        }
        if (!mrk_q_admit(f, MRK_W_AFTER_CALL)) return 0;
        MRK_Q_SCALAR(MRK_Q_ACL_VALID, acl_valid(m->original), q_rc == 0);
    }
    if (!mrk_q_ancestry(f)) return 0;
    m->saved = 1;
    return 1;
}
static int mrk_q_acl_entry(MRKQFixture *f, MRKQMutation *m, acl_tag_t tag, const uuid_t principal,
    acl_permset_mask_t rights, int inherit_only) {
    m->entry = NULL;
    MRK_Q_SCALAR(MRK_Q_ACL_ENTRY, acl_create_entry(&m->replacement, &m->entry), q_rc == 0 && m->entry != NULL);
    MRK_Q_SCALAR(MRK_Q_ACL_TAG, acl_set_tag_type(m->entry, tag), q_rc == 0);
    MRK_Q_SCALAR(MRK_Q_ACL_QUALIFIER, acl_set_qualifier(m->entry, principal), q_rc == 0);
    MRK_Q_SCALAR(MRK_Q_ACL_RIGHTS, acl_set_permset_mask_np(m->entry, rights), q_rc == 0);
    if (inherit_only) {
        MRK_Q_SCALAR(MRK_Q_ACL_FLAGS, acl_get_flagset_np(m->entry, &m->flags), q_rc == 0);
        MRK_Q_SCALAR(MRK_Q_ACL_ADD_FLAG, acl_add_flag_np(m->flags, ACL_ENTRY_FILE_INHERIT), q_rc == 0);
        MRK_Q_SCALAR(MRK_Q_ACL_ADD_FLAG, acl_add_flag_np(m->flags, ACL_ENTRY_DIRECTORY_INHERIT), q_rc == 0);
        MRK_Q_SCALAR(MRK_Q_ACL_ADD_FLAG, acl_add_flag_np(m->flags, ACL_ENTRY_ONLY_INHERIT), q_rc == 0);
        MRK_Q_SCALAR(MRK_Q_ACL_SET_FLAGS, acl_set_flagset_np(m->entry, m->flags), q_rc == 0);
    }
    return 1;
}
static int mrk_q_install_acl(MRKQFixture *f, uint32_t index) {
    if (index >= 3 || (index == 0 && !mrk_q_foreign_uuids(f))) return mrk_q_fail(f);
    MRKQMutation *m = &f->mutations[index];
    if (!mrk_q_save_acl(f, m)) return 0;
    MRKQCall *call = mrk_q_call(f, MRK_Q_ACL_INIT, MRK_W_BEFORE_CALL); if (!call) return 0;
    errno = 0; m->replacement = acl_init(index == 0 ? 2 : 1); int saved = errno;
    mrk_q_return(call, m->replacement != NULL, saved);
    if (!m->replacement || !mrk_q_admit(f, MRK_W_AFTER_CALL)) return mrk_q_fail(f);
    if (index == 0) {
        if (!mrk_q_acl_entry(f, m, ACL_EXTENDED_DENY, f->foreign_user, ACL_DELETE, 0)
            || !mrk_q_acl_entry(f, m, ACL_EXTENDED_ALLOW, f->foreign_group,
                ACL_READ_DATA | ACL_READ_ATTRIBUTES | ACL_READ_SECURITY, 0)) return 0;
    } else if (!mrk_q_acl_entry(f, m, ACL_EXTENDED_ALLOW, index == 1 ? f->foreign_user : f->foreign_group,
        ACL_WRITE_DATA, index == 2)) return 0;
    MRK_Q_SCALAR(MRK_Q_ACL_VALID, acl_valid(m->replacement), q_rc == 0);
    if (!mrk_q_ancestry(f)) return 0;
    call = mrk_q_call(f, MRK_Q_ACL_SET, MRK_W_BEFORE_CALL); if (!call) return 0;
    // The original allocation and effect remain retained if this call fails or
    // never returns. No failed setter becomes permission to restore/retry.
    errno = 0; int rc = acl_set_fd_np(f->ns.fds[f->root_index].fd, m->replacement, ACL_TYPE_EXTENDED); saved = errno;
    mrk_q_return(call, rc, saved);
    if (rc) return mrk_q_fail(f);
    m->changed = 1; f->active_acl = index + 1;
    if (!mrk_q_admit(f, MRK_W_AFTER_CALL) || !mrk_q_ancestry(f)) return 0;
    return 1;
}
static int mrk_q_acl_free(MRKQFixture *f, acl_t *original) {
    if (!*original) return 1;
    MRKQCall *call = mrk_q_call(f, MRK_Q_ACL_FREE, MRK_W_BEFORE_RELEASE); if (!call) return 0;
    errno = 0; int rc = acl_free(*original); int saved = errno;
    mrk_q_return(call, rc, saved);
    if (rc) { mrk_q_unknown(f); return 0; }
    *original = NULL; // Only after this one actual successful free.
    return 1;
}
static int mrk_q_restore_acl(MRKQFixture *f, uint32_t index) {
    if (index >= 3 || f->active_acl != index + 1 || f->active_mode) return mrk_q_fail(f);
    MRKQMutation *m = &f->mutations[index];
    if (!m->saved || !m->changed || m->restored || !mrk_q_ancestry(f)) return mrk_q_fail(f);
    int fd = f->ns.fds[f->root_index].fd;
    MRKQCall *call = mrk_q_call(f, m->present ? MRK_Q_ACL_SET : MRK_Q_ACL_DELETE, MRK_W_BEFORE_CALL);
    if (!call) return 0;
    errno = 0;
    int rc = m->present ? acl_set_fd_np(fd, m->original, ACL_TYPE_EXTENDED) : acl_delete_fd_np(fd, ACL_TYPE_EXTENDED);
    int saved = errno; mrk_q_return(call, rc, saved);
    if (rc) return mrk_q_fail(f);
    m->restored = 1; f->active_acl = 0;
    if (!mrk_q_admit(f, MRK_W_AFTER_CALL) || !mrk_q_ancestry(f)) return 0;
    if (!mrk_q_acl_free(f, &m->replacement) || !mrk_q_acl_free(f, &m->original)) return 0;
    call = mrk_q_call(f, MRK_Q_FILESEC_FREE, MRK_W_BEFORE_RELEASE); if (!call) return 0;
    errno = 0; filesec_free(m->filesec); saved = errno;
    mrk_q_return(call, 0, saved); m->filesec = NULL; m->entry = NULL; m->flags = NULL;
    return 1;
}
static int mrk_q_mode(MRKQFixture *f, uint32_t kind, int restore) {
    MRKWrappingFd *root = &f->ns.fds[f->root_index];
    if (f->active_acl || !mrk_q_ancestry(f)
        || (!restore && f->active_mode) || (restore && f->active_mode != kind)) return mrk_q_fail(f);
    mode_t expected = restore ? (mode_t)(S_IFDIR | 0720) : (mode_t)(S_IFDIR | 0700);
    if (root->identity.mode != expected) return mrk_q_fail(f);
    MRKQCall *call = mrk_q_call(f, MRK_Q_CHMOD, MRK_W_BEFORE_CALL); if (!call) return 0;
    errno = 0; int rc = fchmod(root->fd, restore ? 0700 : 0720); int saved = errno;
    mrk_q_return(call, rc, saved);
    if (rc) return mrk_q_fail(f);
    // This recorded task-root-only effect updates its held role's expected mode,
    // never the immutable owner pin supplied to the adapter.
    root->identity.mode = restore ? (mode_t)(S_IFDIR | 0700) : (mode_t)(S_IFDIR | 0720);
    f->active_mode = restore ? 0 : kind;
    if (!mrk_q_admit(f, MRK_W_AFTER_CALL)) return 0;
    return mrk_q_ancestry(f);
}

static int mrk_q_link_check(MRKQFixture *f) {
    MRKWrappingFd *root = &f->ns.fds[f->root_index];
    memset(&f->metadata, 0, sizeof(f->metadata));
    MRK_Q_SCALAR(MRK_Q_LINK_STAT, fstatat(root->fd, mrk_q_leaf, &f->metadata, AT_SYMLINK_NOFOLLOW), q_rc == 0);
    if (!S_ISLNK(f->metadata.st_mode) || f->metadata.st_uid != f->ns.uid || f->metadata.st_nlink != 1
        || f->metadata.st_size != (off_t)(sizeof(mrk_q_saved) - 1)) return mrk_q_fail(f);
    if (f->link_changed == 2 && f->link_identity.st_ino
        && (!mrk_w_same(mrk_w_identity(&f->metadata), mrk_w_identity(&f->link_identity))
            || f->metadata.st_size != f->link_identity.st_size)) return mrk_q_fail(f);
    if (!f->link_identity.st_ino) f->link_identity = f->metadata;
    memset(f->link_text, 0, sizeof(f->link_text));
    MRK_Q_SCALAR(MRK_Q_READLINK, readlinkat(root->fd, mrk_q_leaf, f->link_text, sizeof(f->link_text)),
        q_rc == (int64_t)(sizeof(mrk_q_saved) - 1));
    if (memcmp(f->link_text, mrk_q_saved, sizeof(mrk_q_saved) - 1)) return mrk_q_fail(f);
    MRK_Q_SCALAR(MRK_Q_LINK_STAT, fstatat(root->fd, mrk_q_leaf, &f->metadata, AT_SYMLINK_NOFOLLOW), q_rc == 0);
    return mrk_w_same(mrk_w_identity(&f->metadata), mrk_w_identity(&f->link_identity))
        && f->metadata.st_size == f->link_identity.st_size ? 1 : mrk_q_fail(f);
}
static int mrk_q_symlink(MRKQFixture *f, int restore) {
    MRKWrappingFrame *s = &f->ns; MRKWrappingFd *root = &s->fds[f->root_index];
    uint32_t index = s->result.directory_count + 1;
    MRKWrappingFd *leaf = &s->fds[index];
    if (f->active_acl || f->active_mode || !mrk_q_ancestry(f)) return mrk_q_fail(f);
    if (!restore) {
        if (f->link_changed || !mrk_q_absent(f, root->fd, mrk_q_saved) || !mrk_w_fd_acquire(s, index)) return mrk_q_fail(f);
        MRKQCall *call = mrk_q_call(f, MRK_Q_RENAME, MRK_W_BEFORE_CALL); if (!call) return 0;
        errno = 0; int rc = renameatx_np(root->fd, mrk_q_leaf, root->fd, mrk_q_saved, RENAME_EXCL); int saved = errno;
        mrk_q_return(call, rc, saved);
        if (rc) return mrk_q_fail(f);
        leaf->name_offset = f->saved_name_offset; f->link_changed = 1;
        if (!mrk_q_admit(f, MRK_W_AFTER_CALL) || !mrk_q_pair(f, leaf, leaf->identity)) return 0;
        call = mrk_q_call(f, MRK_Q_SYMLINK_CALL, MRK_W_BEFORE_CALL); if (!call) return 0;
        errno = 0; rc = symlinkat(mrk_q_saved, root->fd, mrk_q_leaf); saved = errno;
        mrk_q_return(call, rc, saved);
        if (rc) return mrk_q_fail(f);
        f->link_changed = 2;
        return mrk_q_admit(f, MRK_W_AFTER_CALL) && mrk_q_link_check(f) && mrk_q_ancestry(f);
    }
    if (f->link_changed != 2 || f->link_unlinked || !mrk_q_link_check(f)
        || !mrk_q_pair(f, leaf, leaf->identity)) return mrk_q_fail(f);
    MRKQCall *call = mrk_q_call(f, MRK_Q_UNLINK_LINK, MRK_W_BEFORE_CALL); if (!call) return 0;
    errno = 0; int rc = unlinkat(root->fd, mrk_q_leaf, 0); int saved = errno;
    mrk_q_return(call, rc, saved);
    if (rc) return mrk_q_fail(f);
    f->link_unlinked = 1; f->link_changed = 3;
    if (!mrk_q_admit(f, MRK_W_AFTER_CALL) || !mrk_q_absent(f, root->fd, mrk_q_leaf)
        || !mrk_q_pair(f, leaf, leaf->identity)) return 0;
    call = mrk_q_call(f, MRK_Q_RENAME, MRK_W_BEFORE_CALL); if (!call) return 0;
    errno = 0; rc = renameatx_np(root->fd, mrk_q_saved, root->fd, mrk_q_leaf, RENAME_EXCL); saved = errno;
    mrk_q_return(call, rc, saved);
    if (rc) return mrk_q_fail(f);
    leaf->name_offset = s->fds[s->result.directory_count].name_offset; f->link_changed = 4;
    if (!mrk_q_admit(f, MRK_W_AFTER_CALL) || !mrk_w_fd_check(s, index) || !mrk_q_ancestry(f)) return 0;
    return mrk_q_absent(f, root->fd, mrk_q_saved);
}
static int mrk_q_lock(MRKQFixture *f, int unlock) {
    if (f->result.create_effect != 1 || f->active_acl || f->active_mode || f->link_changed != 4
        || !mrk_q_ancestry(f)) return mrk_q_fail(f);
    SecKeychainRef original = (SecKeychainRef)f->owned[f->created_slot].value;
    if (!mrk_q_getpath(f, original) || strcmp(f->observed, f->native_path)) return mrk_q_fail(f);
    MRKQCall *call = mrk_q_call(f, unlock ? MRK_Q_KEYCHAIN_UNLOCK : MRK_Q_KEYCHAIN_LOCK, MRK_W_BEFORE_CALL);
    if (!call) return 0;
    errno = 0;
    OSStatus rc = unlock ? SecKeychainUnlock(original, (UInt32)sizeof(f->password), f->password, true) : SecKeychainLock(original);
    int saved = errno; mrk_q_return(call, rc, saved);
    if (rc != errSecSuccess || !mrk_q_admit(f, MRK_W_AFTER_CALL)) return mrk_q_fail(f);
    return mrk_q_ancestry(f);
}
static int mrk_q_sync_guard(MRKQFixture *f) {
    if (f->result.sync_entered) return mrk_q_fail(f);
    uint32_t index = 0; MRKQOwned *slot = mrk_q_slot(f, &index); if (!slot) return 0;
    MRKQCall *call = mrk_q_call(f, MRK_Q_SYNC_COPY, MRK_W_BEFORE_CALL); if (!call) return 0;
    f->result.sync_entered = 1; mrk_q_cf_enter(f, index);
    errno = 0;
    slot->pending.preference = CFPreferencesCopyValue(CFSTR("KeychainSyncList"),
        CFSTR("com.apple.keychainsync"), kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
    int saved = errno;
    slot->value = slot->pending.preference;
    mrk_q_return(call, slot->value != NULL, saved); mrk_q_cf_return(f, index, 1);
    f->result.sync_returned = 1;
    if (!mrk_q_admit(f, MRK_W_AFTER_CALL)) return 0;
    if (slot->value) {
        if (CFGetTypeID(slot->value) != CFArrayGetTypeID()) return mrk_q_fail(f);
        call = mrk_q_call(f, MRK_Q_SYNC_COUNT, MRK_W_BEFORE_CALL); if (!call) return 0;
        errno = 0; CFIndex count = CFArrayGetCount((CFArrayRef)slot->value); saved = errno;
        mrk_q_return(call, (int64_t)count, saved);
        if (count != 0 || !mrk_q_admit(f, MRK_W_AFTER_CALL)) return mrk_q_fail(f);
        // Retire this actual empty-array original BEFORE Delete. A release
        // exception/unknown makes Delete unavailable, not merely a later error.
        if (!mrk_q_release(f, index)) return 0;
    }
    // Null is normal API-reported absence, not proof of an atomic preference
    // file snapshot. No arbitrary member parser, setter or Synchronize exists.
    f->result.sync_absent_empty = 1;
    return 1;
}
static int mrk_q_release_all(MRKQFixture *f) {
    for (uint32_t i = 0; i < f->result.ref_count; ++i) {
        MRKWrappingReference *r = &f->result.references[i];
        if (r->call_entered != r->call_returned || (r->release_entered && !r->release_returned)) {
            mrk_q_unknown(f); return 0;
        }
    }
    for (uint32_t left = f->result.ref_count; left; --left) {
        MRKWrappingReference *r = &f->result.references[left - 1];
        if (r->release_returned) continue; // The sync original was already retired exactly once.
        if (!mrk_q_release(f, left - 1)) return 0;
    }
    return 1;
}
static int mrk_q_retire(MRKQFixture *f) {
    // This is only fixture custody. The private Rust original caller separately
    // verifies every retained adapter return/candidate and its original cutoff.
    if (f->result.create_effect != 1 || f->active_acl || f->active_mode || f->link_changed != 4
        || !mrk_q_ancestry(f)) return mrk_q_fail(f);
    for (uint32_t i = 0; i < 3; ++i) {
        MRKQMutation *m = &f->mutations[i];
        if (!m->saved || !m->changed || !m->restored || m->filesec || m->original || m->replacement) return mrk_q_fail(f);
    }
    MRKWrappingFrame *s = &f->ns;
    uint32_t current_index = s->result.directory_count + 2;
    if (!mrk_w_fd_acquire(s, current_index)) return mrk_q_fail(f);
    const MRKWrappingIdentity *leaf = &s->fds[current_index].identity;
    if (!mrk_q_selection(f, 2, leaf) || !mrk_q_selection_unchanged(f, 2)
        || !mrk_q_sync_guard(f) || !mrk_q_ancestry(f)
        || !mrk_q_pair(f, &s->fds[current_index], *leaf)) return 0;
    SecKeychainRef original = (SecKeychainRef)f->owned[f->created_slot].value;
    if (!mrk_q_getpath(f, original) || strcmp(f->observed, f->native_path)) return mrk_q_fail(f);
    MRKQCall *call = mrk_q_call(f, MRK_Q_KEYCHAIN_DELETE, MRK_W_BEFORE_CALL); if (!call) return 0;
    errno = 0; OSStatus rc = SecKeychainDelete(original); int saved = errno;
    mrk_q_return(call, rc, saved);
    if (rc == errSecSuccess) f->result.provider_deleted = 1;
    if (rc != errSecSuccess || !mrk_q_admit(f, MRK_W_AFTER_CALL)) return mrk_q_fail(f);
    MRKWrappingFd *root = &s->fds[f->root_index];
    if (!mrk_q_selection(f, 3, NULL) || !mrk_q_selection_unchanged(f, 3)
        || !mrk_q_ancestry(f) || !mrk_q_absent(f, root->fd, mrk_q_leaf)
        || !mrk_q_absent(f, root->fd, mrk_q_demunged) || !mrk_q_absent(f, root->fd, mrk_q_saved)) return 0;
    if (!mrk_q_release_all(f) || !mrk_w_acl_settled(s) || !mrk_q_ancestry(f)) return 0;
    // At most an empty-root rmdir. Unexpected provider files/sidecars make this
    // fail and remain owned evidence; no recursive census/removal or generic
    // unlink list attempts to manufacture complete retirement.
    call = mrk_q_call(f, MRK_Q_RMDIR, MRK_W_BEFORE_CALL); if (!call) return 0;
    errno = 0; rc = unlinkat(s->fds[root->parent].fd, f->root_name, AT_REMOVEDIR); saved = errno;
    mrk_q_return(call, rc, saved);
    if (rc) return mrk_q_fail(f);
    f->result.root_removed = 1;
    if (!mrk_q_admit(f, MRK_W_AFTER_CALL)) return 0;
    // The exact owned edge's successful removal, not a later named-object
    // replacement, admits retirement of that now-unlinked held original.
    if (!mrk_w_fd_cleanup(s)) { mrk_q_unknown(f); return 0; }
    if (!mrk_w_acl_settled(s)) { mrk_q_unknown(f); return 0; }
    // A cutoff can be observed while common cleanup finishes independent
    // original closes. Preserve those actual close/delete/rmdir facts, but
    // never turn a stopped/unknown/failed fixture action into finalization.
    if (f->result.failed || f->result.unknown || f->result.stopped
        || (s->result.flags & (MRK_W_STOP | MRK_W_UNKNOWN))) return mrk_q_fail(f);
    s->result.flags |= MRK_W_KNOWN | MRK_W_KEY_WIPED;
    s->result.phase = MRK_W_RETURN;
    f->result.finalized = 1;
    return 1;
}
size_t mrk_wrapping_fixture_frame_bytes(void) { return sizeof(MRKQFixture); }
uint32_t mrk_wrapping_fixture_abi(void) { return 0x51460101u; }
void *mrk_wrapping_fixture_new(void) {
    MRKQFixture *f = calloc(1, sizeof(MRKQFixture));
    if (f) {
        f->result.version = 1; f->result.bytes = sizeof(f->result);
        f->ns.result.version = MRK_W_VERSION; f->ns.result.operation = MRK_W_LOOKUP;
        f->ns.result.flags = MRK_W_KEY_WIPED; f->ns.result.phase = MRK_W_ENTRY;
        f->root_index = f->created_slot = UINT32_MAX;
        for (uint32_t i = 0; i < MRK_W_FDS; ++i) f->ns.fds[i].fd = f->ns.fds[i].consumed_number = -1;
        mrk_q_snapshot(f);
    }
    return f;
}
void mrk_wrapping_fixture_run(void *frame, uint32_t action, MRKQAdmission admission, void *context, MRKQResult *out) {
    if (!frame || !out) return;
    MRKQFixture *f = frame;
    if (f->running || f->spent_free || f->result.failed || f->result.unknown || f->result.stopped || f->result.finalized
        || !admission || !context || action != f->result.action_count + 1 || action > MRK_Q_ACTIONS) {
        mrk_q_unknown(f); mrk_q_snapshot(f); *out = f->result; return;
    }
    uint32_t index = f->result.action_count++;
    MRKQAction *r = &f->result.actions[index];
    r->kind = action; r->entered = 1; r->first_call = f->result.call_count;
    f->running = 1; f->active_action = action; f->admission = admission; f->context = context;
    f->ns.admission = mrk_q_namespace_admission; f->ns.context = f;
    int complete = 0;
    @try {
        switch (action) {
            case MRK_Q_ENTROPY: complete = mrk_q_entropy(f); break;
            case MRK_Q_CREATE: complete = mrk_q_create(f); break;
            case MRK_Q_DENY_READ: complete = mrk_q_install_acl(f, 0); break;
            case MRK_Q_RESTORE_DENY: complete = mrk_q_restore_acl(f, 0); break;
            case MRK_Q_FOREIGN_USER: complete = mrk_q_install_acl(f, 1); break;
            case MRK_Q_RESTORE_USER: complete = mrk_q_restore_acl(f, 1); break;
            case MRK_Q_FOREIGN_GROUP: complete = mrk_q_install_acl(f, 2); break;
            case MRK_Q_RESTORE_GROUP: complete = mrk_q_restore_acl(f, 2); break;
            case MRK_Q_POSIX: complete = mrk_q_mode(f, 1, 0); break;
            case MRK_Q_RESTORE_POSIX: complete = mrk_q_mode(f, 1, 1); break;
            case MRK_Q_SYMLINK: complete = mrk_q_symlink(f, 0); break;
            case MRK_Q_RESTORE_SYMLINK: complete = mrk_q_symlink(f, 1); break;
            case MRK_Q_POST_ADD: complete = mrk_q_mode(f, 2, 0); break;
            case MRK_Q_RESTORE_POST_ADD: complete = mrk_q_mode(f, 2, 1); break;
            case MRK_Q_LOCK: complete = mrk_q_lock(f, 0); break;
            case MRK_Q_UNLOCK: complete = mrk_q_lock(f, 1); break;
            case MRK_Q_RETIRE: complete = mrk_q_retire(f); break;
            default: mrk_q_unknown(f); break;
        }
    } @catch (NSException *exception) {
        (void)exception; f->result.exception = 1; mrk_q_unknown(f);
    }
    if (!complete || f->ns.result.flags & (MRK_W_STOP | MRK_W_UNKNOWN)) f->result.failed = 1;
    if (f->ns.result.flags & MRK_W_UNKNOWN) f->result.unknown = 1;
    r->completed = complete && !f->result.failed; r->returned = 1; r->end_call = f->result.call_count;
    f->running = 0; f->active_action = 0;
    f->admission = NULL; f->context = NULL; f->ns.admission = NULL; f->ns.context = NULL;
    mrk_q_snapshot(f); *out = f->result;
}
uint32_t mrk_wrapping_fixture_material(void *frame, uint8_t *token, uint8_t *key, uint8_t *ids) {
    if (!frame || !token || !key || !ids) return 0;
    MRKQFixture *f = frame;
    if (f->running || f->material_issued || !f->result.material_generated || f->result.failed
        || f->result.action_count != 1 || !f->result.actions[0].completed) return 0;
    f->material_issued = 1;
    memcpy(token, f->token, sizeof(f->token)); memcpy(key, f->key, sizeof(f->key)); memcpy(ids, f->ids, sizeof(f->ids));
    return 1;
}
uint32_t mrk_wrapping_fixture_binding(void *frame, MRKWrappingQualificationFixture *out) {
    if (!frame || !out) return 0;
    MRKQFixture *f = frame;
    if (f->running || f->binding_issued || f->result.failed || f->result.create_effect != 1
        || f->result.action_count != 2 || !f->result.actions[1].completed || f->pin.bytes != sizeof(f->pin)) return 0;
    f->binding_issued = 1; *out = f->pin; return 1;
}
uint32_t mrk_wrapping_fixture_free(void *frame) {
    if (!frame) return 0;
    MRKQFixture *f = frame;
    if (f->running || f->spent_free || f->result.failed || f->result.unknown || f->result.stopped || !f->result.finalized
        || f->result.action_count != MRK_Q_ACTIONS || !f->result.actions[MRK_Q_ACTIONS - 1].completed
        || !f->result.callbacks_cleared || !mrk_w_acl_settled(&f->ns)) return 0;
    for (uint32_t i = 0; i < f->result.ref_count; ++i) {
        MRKWrappingReference *r = &f->result.references[i];
        if (r->call_entered != r->call_returned || r->nonnull_returned != r->release_returned
            || r->release_entered != r->release_returned || f->owned[i].value || f->owned[i].known_owned) return 0;
    }
    for (uint32_t i = 0; i < f->ns.result.descriptor_count; ++i) {
        MRKWrappingDescriptor *r = &f->ns.result.descriptors[i];
        if (r->open_entered != r->open_returned || r->acquired != r->closed || r->close_entered != r->close_returned) return 0;
    }
    f->spent_free = 1;
    mrk_w_wipe(f, sizeof(*f)); free(f);
    return 1; // Actual own-allocation retirement, not provider erasure/finality.
}
#undef MRK_Q_SCALAR
