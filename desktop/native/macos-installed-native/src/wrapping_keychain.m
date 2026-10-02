// Public SDK boundary for the unused, explicitly selected login-Keychain profile.
// This owns no worker/deadline. The application keeps the original native child
// and its return reachable through STOP, every Security call and actual cleanup.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <CoreFoundation/CoreFoundation.h>
#include <sys/stat.h>
#include <sys/acl.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <membership.h>
#include <uuid/uuid.h>
#include <pwd.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <pthread.h>
#include "wrapping_interaction_policy.h"
#include "vault_helper_control.h"

// Only the separately owned debug qualification build may compile these entries.
// build.rs supplies both definitions after its dedicated-cfg/profile checks;
// the Rust sibling additionally checks actual target debug_assertions.
#if defined(MRK_WRAPPING_KEYCHAIN_QUALIFICATION)
#if MRK_WRAPPING_KEYCHAIN_QUALIFICATION != 1 || !defined(MRK_INSTALLED_OBSERVATION) \
    || !defined(MRK_WRAPPING_KEYCHAIN_QUALIFICATION_DEBUG) \
    || MRK_WRAPPING_KEYCHAIN_QUALIFICATION_DEBUG != 1 || defined(NDEBUG)
#error "wrapping qualification requires the checked instrumented debug build"
#endif
#endif

extern int mrk_user(uint32_t *uid); // Existing ordinary-user/platform admission.

#define MRK_W_REFS 24u
#define MRK_W_CALLS 12u
#define MRK_W_PATH 4096u
#define MRK_W_ACCOUNT 68u
#define MRK_W_METADATA 52u
#define MRK_W_KEY 32u
#define MRK_W_FDS 72u
#define MRK_W_COMPONENTS 64u
#define MRK_W_CHECKPOINTS 5u
#define MRK_W_ACL_SNAPSHOTS 400u
#define MRK_W_ACES 128u
#define MRK_W_NATIVE_CALLS 300000u
#define MRK_W_VERSION 3u

enum {
    MRK_W_ADD = 1, MRK_W_LOOKUP = 2,
    MRK_W_PENDING = 0, MRK_W_ADDED = 1, MRK_W_FOUND = 2,
    MRK_W_MISSING = 3, MRK_W_DUPLICATE = 4, MRK_W_LOCKED = 5,
    MRK_W_INTERACTION = 6, MRK_W_AUTH_FAILED = 7, MRK_W_USER_CANCELED = 8,
    MRK_W_UNAVAILABLE = 9, MRK_W_UNSUPPORTED = 10, MRK_W_INPUT = 11,
    MRK_W_SHAPE = 12, MRK_W_ALLOCATION = 13, MRK_W_STOPPED = 14,
    MRK_W_CUSTODY = 15, MRK_W_NATIVE_FAILURE = 16, MRK_W_EXCEPTION = 17
};
enum { MRK_W_NOT_ENTERED = 0, MRK_W_DID_ADD = 1, MRK_W_DID_DUPLICATE = 2, MRK_W_MAY_HAVE_ADDED = 3 };
enum {
    MRK_W_ENTRY = 1, MRK_W_ACCOUNT_PHASE = 2, MRK_W_PATH_PHASE = 3,
    MRK_W_OPEN = 4, MRK_W_GET_PATH = 5, MRK_W_GET_STATUS = 6,
    MRK_W_QUERY = 7, MRK_W_TRUSTED = 8, MRK_W_ACCESS = 9,
    MRK_W_ADD_CALL = 10, MRK_W_LOOKUP_CALL = 11, MRK_W_PARENT = 12,
    MRK_W_VALIDATE = 13, MRK_W_RELEASE = 14, MRK_W_DELIVERY = 15,
    MRK_W_RETURN = 16, MRK_W_NAMESPACE = 17, MRK_W_FILESYSTEM = 18,
    MRK_W_ACL = 19, MRK_W_UUID = 20, MRK_W_FD_RELEASE = 21
};
enum {
    MRK_W_KNOWN = 1u, MRK_W_UNKNOWN = 2u, MRK_W_STOP = 4u,
    MRK_W_ITEM_VERIFIED = 8u, MRK_W_KEY_READY = 16u, MRK_W_USER = 32u,
    MRK_W_STATUS_OBSERVED = 64u, MRK_W_KEY_WIPED = 128u,
    MRK_W_NATIVE_EXCEPTION = 256u, MRK_W_CALLBACK_UNKNOWN = 512u,
    MRK_W_NAMESPACE_VERIFIED = 1024u
};
enum { MRK_W_BEFORE_CALL = 0, MRK_W_AFTER_CALL = 1, MRK_W_BEFORE_RELEASE = 2, MRK_W_BEFORE_DELIVERY = 3 };
enum { MRK_W_CONTINUE = 1, MRK_W_CUTOFF = 2, MRK_W_RETAIN = 3 };

typedef struct {
    uint32_t reserved, call_entered, call_returned, nonnull_returned;
    uint32_t release_entered, release_returned;
} MRKWrappingReference;
typedef struct { uint32_t phase, entered, returned; int32_t status; } MRKWrappingCall;
typedef struct {
    uint32_t reserved, open_entered, open_returned, acquired;
    int32_t open_errno;
    uint32_t close_entered, close_returned, closed;
    int32_t close_result, close_errno;
} MRKWrappingDescriptor;
// Cumulative counts for one reusable, prearmed ACL working cell. None of these
// counters substitutes for an actual returned allocation/free observation.
typedef struct {
    uint32_t snapshots_entered, snapshots_returned, snapshots_admitted, entries;
    uint32_t filesec_init_entered, filesec_init_returned, filesec_acquired;
    uint32_t filesec_free_entered, filesec_free_returned;
    uint32_t acl_export_entered, acl_export_returned, acl_acquired;
    uint32_t acl_free_entered, acl_free_returned, acl_freed;
    uint32_t qualifier_entered, qualifier_returned, qualifier_acquired;
    uint32_t qualifier_free_entered, qualifier_free_returned, qualifier_freed;
} MRKWrappingAcl;
// Last actual nonowning/ACL call and first refused call, not a transcript. For
// pointer-return calls result is nonnull0/1; for filesec_free it is0 only after
// the void call returned. Original pointers remain in the private working cell.
typedef struct {
    uint32_t entered, returned, last_call, last_returned;
    int32_t last_result, last_errno;
    uint32_t failure_call;
    int32_t failure_result, failure_errno;
} MRKWrappingNative;
enum {
    MRK_W_N_LSTAT = 1, MRK_W_N_FSTATAT = 2, MRK_W_N_FSTAT = 3,
    MRK_W_N_STATFS = 4, MRK_W_N_ROOT_UUID = 5, MRK_W_N_USER_UUID = 6,
    MRK_W_N_FILESEC_INIT = 7, MRK_W_N_FSTATX = 8, MRK_W_N_OWNER = 9,
    MRK_W_N_GROUP = 10, MRK_W_N_MODE = 11, MRK_W_N_PRESENCE = 12,
    MRK_W_N_ACL_EXPORT = 13, MRK_W_N_ACL_VALID = 14, MRK_W_N_ENTRY = 15,
    MRK_W_N_TAG = 16, MRK_W_N_RIGHTS = 17, MRK_W_N_QUALIFIER = 18,
    MRK_W_N_QUALIFIER_FREE = 19, MRK_W_N_ACL_FREE = 20, MRK_W_N_FILESEC_FREE = 21
};
typedef struct {
    uint32_t version, operation, outcome, effect, phase, failure_phase, flags;
    int32_t account_errno;
    uint32_t keychain_status, slot_count, call_count, key_bytes, run_returned;
    MRKWrappingReference references[MRK_W_REFS];
    MRKWrappingCall calls[MRK_W_CALLS];
    uint32_t directory_count, descriptor_count, namespace_entered, namespace_returned, namespace_passed;
    MRKWrappingDescriptor descriptors[MRK_W_FDS];
    MRKWrappingAcl acl;
    MRKWrappingNative native;
    MRKInteractionPolicy policy;
} MRKWrappingResult;
_Static_assert(sizeof(MRKWrappingDescriptor) == 40, "fixed descriptor observations");
_Static_assert(sizeof(MRKWrappingAcl) == 84, "fixed ACL observations");
_Static_assert(sizeof(MRKWrappingNative) == 36, "fixed native-call observations");
_Static_assert(sizeof(MRKWrappingResult) == 4052, "fixed Rust/native wrapping observation ABI v3");

typedef uint32_t (*MRKWrappingAdmission)(void *, const MRKWrappingResult *, uint32_t);
typedef uint32_t (*MRKWrappingConsume)(void *, const uint8_t *, size_t);
// Fixed Rust cleanup bridge: original child endpoint only; slots3/4 only.
typedef uint32_t (*MRKWrappingCleanupAdmission)(void *, uint32_t);
// Prearmed SDK-typed out storage; these pointer bits are not a second +1 ref.
typedef union {
    SecKeychainRef keychain;
    SecTrustedApplicationRef trusted;
    SecAccessRef access;
} MRKWrappingReturned;
typedef struct { CFTypeRef value; MRKWrappingReturned pending; uint32_t index; } MRKWrappingOwned;
// Private fixed-profile adaptation of SourceBook's retained no-follow edges.
// Directory relations exclude sibling timestamp/link churn. A leaf original is
// paired only at its checkpoint; the provider may legitimately replace its DB.
typedef struct {
    dev_t dev; ino_t ino; mode_t mode; uid_t uid; gid_t gid;
} MRKWrappingIdentity;
typedef struct {
    int fd, consumed_number;
    uint32_t parent, name_offset, directory, uid_rule, identity_ready;
    MRKWrappingIdentity identity;
} MRKWrappingFd;
typedef struct {
    filesec_t filesec;
    acl_t acl;
    void *qualifier;
    acl_entry_t entry;
    acl_tag_t tag;
    acl_permset_mask_t rights;
    uid_t owner; gid_t group; mode_t mode; int present;
    struct stat snapshot;
} MRKWrappingAclCell;
#if defined(MRK_WRAPPING_KEYCHAIN_QUALIFICATION)
enum { MRK_W_Q_SELECTOR = 1, MRK_W_Q_FIXTURE = 2, MRK_W_Q_HELPERS = 3, MRK_W_Q_SHAPES = 20 };
typedef struct {
    uint32_t version, bytes;
    uint64_t root_device, root_inode;
    uint32_t root_mode, root_uid, root_gid, reserved;
    uint8_t token[16];
} MRKWrappingQualificationFixture;
typedef struct {
    uint32_t version, mode, configured, run_returned;
    uint32_t account_selected, fixture_selected, root_identity_matched, selector_boundary_returned;
    uint32_t callbacks_cleared, helpers_entered, helpers_returned, helper_matches;
} MRKWrappingQualificationObservation;
_Static_assert(sizeof(MRKWrappingQualificationFixture) == 56, "qualification fixture input ABI");
_Static_assert(sizeof(MRKWrappingQualificationObservation) == 48, "qualification scalar output ABI");
typedef struct {
    MRKWrappingQualificationFixture fixture;
    MRKWrappingQualificationObservation observation;
    uint32_t root_name_offset;
} MRKWrappingQualification;
#endif

typedef struct MRKInteractionGuard {
    MRKInteractionPolicy *policy;
    uint32_t acquired;
    int (*forward)(void *);
    void *owner;
    MRKWrappingCleanupAdmission cleanup;
    void *cleanup_context;
#if defined(MRK_WRAPPING_KEYCHAIN_QUALIFICATION)
    const MRKWrappingQualificationFixture *fixture;
#endif
    // One existing namespace-only child, borrowed only through the outer call.
    uint32_t *namespace_parent_settled;
} MRKInteractionGuard;

#if defined(MRK_WRAPPING_KEYCHAIN_QUALIFICATION) || defined(MRK_WRAPPING_VAULT_HELPER)
#if defined(MRK_WRAPPING_VAULT_HELPER)
extern uint32_t mrk_wrapping_vault_helper_role(void) __attribute__((weak_import));
#else
// Only the two fixed executable mains define this read-only symbol. Library,
// libtest, observer and shipping application builds cannot activate a role.
extern uint32_t mrk_wrapping_private_process_role(void) __attribute__((weak_import));
#endif
// ONE process state in this translation unit (fixture.m is included below).
// Check pthread_main_np BEFORE every access; the inspected SDK setting itself
// is process/library-instance state, not thread-local or another process's state.
static struct {
    pid_t pid;
    uint32_t role, poisoned, add_after_call;
    MRKInteractionGuard *active;
} mrk_w_process;
static uint32_t mrk_w_private_role(void) {
#if defined(MRK_WRAPPING_VAULT_HELPER)
    if (pthread_main_np() != 1 || !mrk_wrapping_vault_helper_role) return 0;
    return mrk_wrapping_vault_helper_role() == 3 ? 3 : 0;
#else
    if (pthread_main_np() != 1 || !mrk_wrapping_private_process_role) return 0;
    uint32_t role = mrk_wrapping_private_process_role();
    return role == 1 || role == 2 ? role : 0;
#endif
}
static int mrk_w_policy_final_owner(const MRKInteractionPolicy *policy) {
    if (pthread_main_np() != 1) return 0;
    uint32_t role = mrk_w_private_role();
    return role && policy->role == role && mrk_w_process.pid == getpid()
        && mrk_w_process.role == role && !mrk_w_process.active && !mrk_w_process.poisoned;
}
static int mrk_w_process_original(const MRKInteractionGuard *guard) {
    if (pthread_main_np() != 1) return 0;
    return guard && guard->acquired && mrk_w_process.active == guard
        && mrk_w_process.pid == getpid() && mrk_w_process.role == mrk_w_private_role();
}
static int mrk_w_policy_acquire(MRKInteractionGuard *guard, MRKInteractionPolicy *policy,
    uint32_t kind, uint32_t operation) {
    uint32_t role = mrk_w_private_role();
    mrk_p_init(policy, kind, role);
    guard->policy = policy;
    if (!role) { mrk_p_fail(policy, MRK_P_SCOPE_FAILURE); mrk_vault_control_failure(); return 0; }
    // mrk_w_private_role's successful main-thread check precedes process state.
    pid_t pid = getpid();
    int matched = !mrk_w_process.pid || (mrk_w_process.pid == pid && mrk_w_process.role == role);
    if (!mrk_p_scope_permitted(role, kind, operation, 1, matched,
            mrk_w_process.active != NULL, mrk_w_process.poisoned)) {
        mrk_p_fail(policy, MRK_P_SCOPE_FAILURE); mrk_vault_control_failure(); return 0;
    }
    mrk_w_process.pid = pid; mrk_w_process.role = role;
    mrk_w_process.active = guard; guard->acquired = 1; policy->scope_admitted = 1;
    return 1;
}
static void mrk_w_policy_call(MRKInteractionGuard *guard, uint32_t slot) {
    MRKInteractionPolicy *policy = guard->policy;
    if (!mrk_w_process_original(guard)) { mrk_p_fail(policy, MRK_P_SCOPE_FAILURE); mrk_vault_control_failure(); return; }
    uint32_t admission = MRK_W_RETAIN;
    if (slot < MRK_P_RESTORE) {
        if (guard->forward && guard->owner && guard->forward(guard->owner)) admission = MRK_W_CONTINUE;
    } else if (guard->cleanup && guard->cleanup_context) {
        // This fixed leg never accesses the forward closure/Facts/diagnostic I/O.
        admission = guard->cleanup(guard->cleanup_context, slot);
    }
    if (!mrk_p_start(policy, slot, admission)) { mrk_vault_control_failure(); return; }
    @try {
        OSStatus status;
        if (slot == MRK_P_DISABLE || slot == MRK_P_RESTORE) {
            Boolean requested = (Boolean)policy->calls[slot].value;
            status = SecKeychainSetUserInteractionAllowed(requested);
            mrk_p_return(policy, slot, status, requested);
            if (policy->failed) mrk_vault_control_failure();
        } else {
            Boolean observed = (Boolean)255; // No default false observation.
            status = SecKeychainGetUserInteractionAllowed(&observed);
            mrk_p_return(policy, slot, status, observed);
            if (policy->failed) mrk_vault_control_failure();
        }
    } @catch (NSException *exception) {
        (void)exception; mrk_p_exception(policy, slot); mrk_vault_control_failure();
    }
}
static int mrk_w_policy_install(MRKInteractionGuard *guard) {
    for (uint32_t slot = MRK_P_ORIGINAL; slot <= MRK_P_INSTALLED; ++slot) {
        mrk_w_policy_call(guard, slot);
        if (guard->policy->failed) return 0;
    }
    return guard->policy->installed == 1;
}
static int mrk_w_policy_finish(MRKInteractionGuard *guard, int resources_settled) {
    MRKInteractionPolicy *policy = guard->policy;
    if (!guard->acquired) { policy->finished = 1; return 0; }
    if (!mrk_w_process_original(guard)) {
        mrk_p_fail(policy, MRK_P_SCOPE_FAILURE); mrk_vault_control_failure(); policy->finished = 1; return 0;
    }
    if (policy->restore_due) {
        // Each original has its own SDK exception boundary/admission. Even an
        // exception or failure in SetOriginal cannot skip a still-admitted
        // GetRestored. Equality never repairs a failed/unreturned SetOriginal.
        mrk_w_policy_call(guard, MRK_P_RESTORE);
        mrk_w_policy_call(guard, MRK_P_RESTORED);
    }
    policy->finished = 1;
    // An independently refused reentry may have poisoned this original while
    // its own restoration still returned. Preserve cleanup, never early KNOWN.
    int settled = mrk_p_finality(policy, resources_settled && !mrk_w_process.poisoned);
    if (guard->namespace_parent_settled && settled) *guard->namespace_parent_settled = 1;
    guard->namespace_parent_settled = NULL;
    if (!settled) { mrk_w_process.poisoned = 1; mrk_vault_control_failure(); } // Absorbing; exit is not restoration.
    mrk_w_process.add_after_call = 0; mrk_w_process.active = NULL; guard->acquired = 0;
    return settled;
}
#else
// Ordinary/observer code has no weak role symbol or interaction Get/Set path.
static int mrk_w_policy_final_owner(const MRKInteractionPolicy *policy) { (void)policy; return 0; }
static int mrk_w_policy_acquire(MRKInteractionGuard *guard, MRKInteractionPolicy *policy,
    uint32_t kind, uint32_t operation) {
    (void)operation; mrk_p_init(policy, kind, 0); guard->policy = policy;
    mrk_p_fail(policy, MRK_P_SCOPE_FAILURE); mrk_vault_control_failure(); return 0;
}
static int mrk_w_policy_install(MRKInteractionGuard *guard) { (void)guard; return 0; }
static int mrk_w_policy_finish(MRKInteractionGuard *guard, int resources_settled) {
    (void)resources_settled; guard->policy->finished = 1; return 0;
}
#endif
// Pure finite-data ABI validation; no process, SDK or activation operation.
uint32_t mrk_wrapping_policy_validate(const MRKInteractionPolicy *policy, uint32_t final) {
    return policy && final <= 1 && mrk_p_valid(policy, (int)final);
}
uint32_t mrk_wrapping_policy_complete(const MRKInteractionPolicy *policy, uint32_t namespace_only) {
    if (!policy || namespace_only > 1 || !mrk_p_valid(policy, 1)) return 0;
    return namespace_only ? mrk_p_namespace_complete(policy) : mrk_p_complete(policy);
}

typedef struct {
    MRKWrappingResult result;
    MRKWrappingOwned owned[MRK_W_REFS];
    MRKWrappingAdmission admission;
    void *context;
    uint32_t uid, ran, consuming, key_backing_borrowed;
    uint8_t vault[16], generation[16], metadata[MRK_W_METADATA], key[MRK_W_KEY];
    char account[MRK_W_ACCOUNT + 1], path[MRK_W_PATH], observed_path[MRK_W_PATH];
    char account_scratch[16384];
    MRKWrappingFd fds[MRK_W_FDS];
    MRKWrappingAclCell acl_cell;
    struct stat held_stat, named_stat;
    struct statfs filesystem;
    uuid_t root_uuid, user_uuid;
    char component_names[MRK_W_PATH];
    uint32_t component_offsets[MRK_W_COMPONENTS], component_ends[MRK_W_COMPONENTS];
    uint32_t independent_fd_cleanup, resources_settled;
    MRKInteractionGuard interaction;
#if defined(MRK_WRAPPING_KEYCHAIN_QUALIFICATION)
    MRKWrappingQualification qualification;
#endif
} MRKWrappingFrame;
_Static_assert(sizeof(MRKWrappingFrame) <= 65536, "bounded adapter-owned native frame");

static void mrk_w_wipe(void *pointer, size_t bytes) {
    volatile uint8_t *p = (volatile uint8_t *)pointer;
    for (size_t i = 0; i < bytes; ++i) p[i] = 0;
    atomic_signal_fence(memory_order_seq_cst);
}
static void mrk_w_wipe_key(MRKWrappingFrame *s) {
    mrk_w_wipe(s->key, sizeof(s->key));
    s->result.key_bytes = 0;
    s->result.flags |= MRK_W_KEY_WIPED;
}
static int mrk_w_fail(MRKWrappingFrame *s, uint32_t outcome) {
    mrk_vault_control_failure(); // Stamp the actual first failure, before cleanup/callback delivery.
    if (!s->result.failure_phase) s->result.failure_phase = s->result.phase;
    if (s->result.outcome == MRK_W_PENDING || s->result.outcome == MRK_W_ADDED || s->result.outcome == MRK_W_FOUND)
        s->result.outcome = outcome;
    return 0;
}
static void mrk_w_unknown(MRKWrappingFrame *s, uint32_t outcome) {
    s->independent_fd_cleanup = 0;
    s->result.flags |= MRK_W_UNKNOWN;
    s->result.flags &= ~(MRK_W_KNOWN | MRK_W_KEY_READY);
    mrk_w_fail(s, outcome);
    // A lookup copy has never backed a CF object. An add's no-copy CFData may
    // still refer to key[], so do not mutate or free that uncertain backing.
    if (s->result.operation == MRK_W_LOOKUP || !s->key_backing_borrowed) mrk_w_wipe_key(s);
}
static int mrk_w_admit(MRKWrappingFrame *s, uint32_t checkpoint) {
    if ((s->result.flags & MRK_W_UNKNOWN) && !(s->independent_fd_cleanup
        && s->result.phase == MRK_W_FD_RELEASE && checkpoint == MRK_W_BEFORE_RELEASE)) return 0;
    if (!s->admission || !s->context) { mrk_w_unknown(s, MRK_W_CUSTODY); return 0; }
    if ((s->result.flags & MRK_W_STOP) && checkpoint == MRK_W_BEFORE_CALL) return 0;
    uint32_t reply;
#if defined(MRK_WRAPPING_KEYCHAIN_QUALIFICATION)
    int add_window = s->interaction.acquired && mrk_w_process_original(&s->interaction)
        && s->result.operation == MRK_W_ADD && s->result.phase == MRK_W_ADD_CALL
        && checkpoint == MRK_W_AFTER_CALL && s->result.effect == MRK_W_DID_ADD
        && s->interaction.policy->installed && !s->interaction.policy->failed;
    if (add_window) mrk_w_process.add_after_call = 1;
    @try { reply = s->admission(s->context, &s->result, checkpoint); }
    @finally { if (add_window) mrk_w_process.add_after_call = 0; }
#else
    reply = s->admission(s->context, &s->result, checkpoint);
#endif
    if (reply != MRK_W_CONTINUE && reply != MRK_W_CUTOFF) {
        s->result.flags |= MRK_W_CALLBACK_UNKNOWN;
        if (s->result.policy.kind == MRK_P_OPERATION && s->result.policy.scope_admitted)
            mrk_p_forward_refused(&s->result.policy);
        mrk_w_unknown(s, MRK_W_CUSTODY);
        return 0;
    }
    if (reply == MRK_W_CUTOFF) {
        s->result.flags |= MRK_W_STOP;
        mrk_w_fail(s, MRK_W_STOPPED);
    }
#if defined(MRK_WRAPPING_VAULT_HELPER)
    // PRIVATE Cutoff means stop forward work while permitting original cleanup.
    // Shipping helper has a separate ABSOLUTE cleanup limit. Recheck after its
    //callback too: expiration is never permission for another CF/ACL/FD consume.
    if (checkpoint == MRK_W_BEFORE_RELEASE && mrk_vault_control_admit(1) != MRK_W_CONTINUE) {
        mrk_w_unknown(s, MRK_W_CUSTODY); return 0;
    }
#endif
    // Cutoff permits only this original's cleanup, never another native query,
    // item effect or key delivery. It cannot undo an already entered add.
    return checkpoint == MRK_W_BEFORE_RELEASE || !(s->result.flags & MRK_W_STOP);
}
static int mrk_w_policy_forward(void *owner) {
    return mrk_w_admit((MRKWrappingFrame *)owner, MRK_W_BEFORE_CALL);
}
static MRKWrappingOwned *mrk_w_slot(MRKWrappingFrame *s) {
    if (s->result.slot_count >= MRK_W_REFS) { mrk_w_fail(s, MRK_W_ALLOCATION); return NULL; }
    uint32_t i = s->result.slot_count++;
    s->owned[i].index = i;
    s->result.references[i].reserved = 1;
    return &s->owned[i];
}
static void mrk_w_cf_enter(MRKWrappingFrame *s, MRKWrappingOwned *slot) {
    s->result.references[slot->index].call_entered = 1;
}
static void mrk_w_cf_return(MRKWrappingFrame *s, MRKWrappingOwned *slot) {
    MRKWrappingReference *r = &s->result.references[slot->index];
    r->call_returned = 1;
    r->nonnull_returned = slot->value != NULL;
}
static MRKWrappingCall *mrk_w_call(MRKWrappingFrame *s, uint32_t phase) {
    s->result.phase = phase;
    if (!mrk_w_admit(s, MRK_W_BEFORE_CALL)) return NULL;
    if (s->result.call_count >= MRK_W_CALLS) { mrk_w_fail(s, MRK_W_ALLOCATION); return NULL; }
    MRKWrappingCall *call = &s->result.calls[s->result.call_count++];
    call->phase = phase;
    call->entered = 1; // Immediately before the one original API invocation.
    return call;
}
static void mrk_w_return(MRKWrappingCall *call, OSStatus status) {
    call->status = status;
    call->returned = 1; // status is meaningful only after this actual return.
}
static int mrk_w_type(MRKWrappingFrame *s, CFTypeRef object, CFTypeID expected) {
    if (!object || CFGetTypeID(object) != expected) return mrk_w_fail(s, MRK_W_SHAPE);
    return 1;
}
static uint32_t mrk_w_status_outcome(OSStatus status, uint32_t phase) {
    if (status == errSecInteractionNotAllowed || status == errSecInteractionRequired) return MRK_W_INTERACTION;
    if (status == errSecAuthFailed) return MRK_W_AUTH_FAILED;
    if (status == errSecUserCanceled) return MRK_W_USER_CANCELED;
    if (status == errSecItemNotFound && phase == MRK_W_LOOKUP_CALL) return MRK_W_MISSING;
    if (status == errSecDuplicateItem && phase == MRK_W_ADD_CALL) return MRK_W_DUPLICATE;
    if (status == errSecParam || status == errSecUnimplemented) return MRK_W_UNSUPPORTED;
    if (status == errSecNotAvailable || status == errSecNoSuchKeychain || status == errSecNoDefaultKeychain)
        return MRK_W_UNAVAILABLE;
    return MRK_W_NATIVE_FAILURE;
}
static int mrk_w_status(MRKWrappingFrame *s, OSStatus status, uint32_t phase) {
    if (status == errSecSuccess) return 1;
    return mrk_w_fail(s, mrk_w_status_outcome(status, phase));
}
static int mrk_w_ids(const uint8_t *vault, const uint8_t *generation) {
    if (!vault || !generation || !memcmp(vault, generation, 16)) return 0;
    uint8_t a = 0, b = 0;
    for (unsigned i = 0; i < 16; ++i) { a |= vault[i]; b |= generation[i]; }
    return a != 0 && b != 0;
}
static int mrk_w_native_enter(MRKWrappingFrame *s, uint32_t phase, uint32_t call, uint32_t checkpoint) {
    s->result.phase = phase;
    if (!mrk_w_admit(s, checkpoint)) return 0;
    MRKWrappingNative *n = &s->result.native;
    if (n->entered != n->returned || n->entered >= MRK_W_NATIVE_CALLS) {
        mrk_w_unknown(s, MRK_W_CUSTODY); return 0;
    }
    ++n->entered; n->last_call = call; n->last_returned = 0;
    n->last_result = n->last_errno = 0;
    return 1;
}
static void mrk_w_native_return(MRKWrappingFrame *s, int result, int actual_errno) {
    MRKWrappingNative *n = &s->result.native;
    n->last_result = result; n->last_errno = actual_errno;
    n->last_returned = 1; ++n->returned; // Before any callback/STOP observation.
}
static int mrk_w_native_fail(MRKWrappingFrame *s, uint32_t outcome) {
    MRKWrappingNative *n = &s->result.native;
    if (!n->failure_call && n->last_returned) {
        n->failure_call = n->last_call;
        n->failure_result = n->last_result; n->failure_errno = n->last_errno;
    }
    return mrk_w_fail(s, outcome);
}
static MRKWrappingIdentity mrk_w_identity(const struct stat *st) {
    return (MRKWrappingIdentity){ .dev = st->st_dev, .ino = st->st_ino,
        .mode = st->st_mode, .uid = st->st_uid, .gid = st->st_gid };
}
static int mrk_w_same(MRKWrappingIdentity a, MRKWrappingIdentity b) {
    return a.dev == b.dev && a.ino == b.ino && a.mode == b.mode && a.uid == b.uid && a.gid == b.gid;
}
#if defined(MRK_WRAPPING_KEYCHAIN_QUALIFICATION)
static int mrk_w_qualification_select(MRKWrappingFrame *s, size_t home_length) {
    MRKWrappingQualification *q = &s->qualification;
    // The caller cannot supply a path. Account/login selection already ran, and
    // its native home prefix is the only prefix reused. The generated token
    // names ONE task-owned protected root; the leaf spelling is fixed.
    static const char parent[] = "/Library/Keychains/";
    static const char root[] = "mrk-wrapping-qualification-";
    static const char leaf[] = "/synthetic.keychain-db";
    static const char hex[] = "0123456789abcdef";
    const size_t prefix = sizeof(parent) - 1 + sizeof(root) - 1;
    if (!q->observation.configured || q->fixture.root_uid != s->uid
        || home_length > sizeof(s->path) - prefix - 32 - sizeof(leaf))
        return mrk_w_fail(s, MRK_W_INPUT);
    memcpy(s->path + home_length, parent, sizeof(parent) - 1);
    q->root_name_offset = (uint32_t)(home_length + sizeof(parent) - 1);
    memcpy(s->path + q->root_name_offset, root, sizeof(root) - 1);
    size_t at = home_length + prefix;
    for (unsigned i = 0; i < 16; ++i) {
        s->path[at + i * 2] = hex[q->fixture.token[i] >> 4];
        s->path[at + i * 2 + 1] = hex[q->fixture.token[i] & 15];
    }
    memcpy(s->path + at + 32, leaf, sizeof(leaf));
    q->observation.fixture_selected = 1;
    return 1;
}
static int mrk_w_qualification_root(MRKWrappingFrame *s, const MRKWrappingFd *slot, const struct stat *st) {
    MRKWrappingQualification *q = &s->qualification;
    if (q->observation.mode != MRK_W_Q_FIXTURE || !slot->directory
        || slot->name_offset != q->root_name_offset) return 1;
    const MRKWrappingQualificationFixture *pin = &q->fixture;
    if (!q->observation.fixture_selected || (uint64_t)(uint32_t)st->st_dev != pin->root_device
        || (uint64_t)st->st_ino != pin->root_inode || (uint32_t)st->st_mode != pin->root_mode
        || (uint32_t)st->st_uid != pin->root_uid || (uint32_t)st->st_gid != pin->root_gid) return 0;
    // Scalar observation only, not a replacement for the complete shared
    // same-FD ACL/APFS/parent-edge admission that follows this identity check.
    q->observation.root_identity_matched = 1;
    return 1;
}
#endif
static int mrk_w_protected(MRKWrappingFrame *s, const MRKWrappingFd *slot, const struct stat *st) {
    if ((slot->directory ? !S_ISDIR(st->st_mode) : !S_ISREG(st->st_mode)) || (st->st_mode & 0022)) return 0;
#if defined(MRK_WRAPPING_KEYCHAIN_QUALIFICATION)
    if (!mrk_w_qualification_root(s, slot, st)) return 0;
#endif
    // Root itself is root-owned; before home either root or this native user is
    // trusted. The home component and every later directory/leaf are user-owned.
    return slot->uid_rule == 0 ? st->st_uid == 0
        : slot->uid_rule == 1 ? st->st_uid == s->uid : st->st_uid == 0 || st->st_uid == s->uid;
}
static int mrk_w_named(MRKWrappingFrame *s, const MRKWrappingFd *slot, struct stat *out) {
    uint32_t call = slot->parent == UINT32_MAX ? MRK_W_N_LSTAT : MRK_W_N_FSTATAT;
    if (!mrk_w_native_enter(s, MRK_W_FILESYSTEM, call, MRK_W_BEFORE_CALL)) return 0;
    memset(out, 0, sizeof(*out));
    errno = 0;
    int rc = slot->parent == UINT32_MAX ? lstat("/", out)
        : fstatat(s->fds[slot->parent].fd, s->component_names + slot->name_offset, out, AT_SYMLINK_NOFOLLOW);
    int actual_errno = errno;
    mrk_w_native_return(s, rc, actual_errno);
    if (rc) return mrk_w_native_fail(s, MRK_W_UNAVAILABLE);
    return mrk_w_admit(s, MRK_W_AFTER_CALL);
}
static int mrk_w_held(MRKWrappingFrame *s, const MRKWrappingFd *slot, struct stat *out) {
    if (!mrk_w_native_enter(s, MRK_W_FILESYSTEM, MRK_W_N_FSTAT, MRK_W_BEFORE_CALL)) return 0;
    memset(out, 0, sizeof(*out));
    errno = 0; int rc = fstat(slot->fd, out); int actual_errno = errno;
    mrk_w_native_return(s, rc, actual_errno);
    if (rc) return mrk_w_native_fail(s, MRK_W_UNAVAILABLE);
    return mrk_w_admit(s, MRK_W_AFTER_CALL);
}
static int mrk_w_filesystem(MRKWrappingFrame *s, const MRKWrappingFd *slot) {
    if (!mrk_w_native_enter(s, MRK_W_FILESYSTEM, MRK_W_N_STATFS, MRK_W_BEFORE_CALL)) return 0;
    memset(&s->filesystem, 0, sizeof(s->filesystem));
    errno = 0; int rc = fstatfs(slot->fd, &s->filesystem); int actual_errno = errno;
    mrk_w_native_return(s, rc, actual_errno);
    if (rc) return mrk_w_native_fail(s, MRK_W_UNAVAILABLE);
    if (strncmp(s->filesystem.f_fstypename, "apfs", sizeof(s->filesystem.f_fstypename))
        || !(s->filesystem.f_flags & MNT_LOCAL)
        || (s->filesystem.f_flags & (MNT_UNION | MNT_AUTOMOUNTED | MNT_IGNORE_OWNERSHIP)))
        return mrk_w_native_fail(s, MRK_W_UNSUPPORTED);
    // System/Data firmlinks can cross dev_t. Admit each held object locally;
    // neither Linux-style xdev nor textual aliases are a substitute.
    return mrk_w_admit(s, MRK_W_AFTER_CALL);
}
static int mrk_w_qualifier_free(MRKWrappingFrame *s) {
    MRKWrappingAclCell *w = &s->acl_cell; MRKWrappingAcl *a = &s->result.acl;
    if (!w->qualifier) return 1;
    if (a->qualifier_acquired != a->qualifier_freed + 1
        || a->qualifier_free_entered != a->qualifier_freed) {
        mrk_w_unknown(s, MRK_W_CUSTODY); return 0;
    }
    if (!mrk_w_native_enter(s, MRK_W_ACL, MRK_W_N_QUALIFIER_FREE, MRK_W_BEFORE_RELEASE)) return 0;
    ++a->qualifier_free_entered;
    errno = 0; int rc = acl_free(w->qualifier); int actual_errno = errno;
    ++a->qualifier_free_returned; mrk_w_native_return(s, rc, actual_errno);
    if (rc) { mrk_w_native_fail(s, MRK_W_CUSTODY); mrk_w_unknown(s, MRK_W_CUSTODY); return 0; }
    ++a->qualifier_freed; w->qualifier = NULL;
#if defined(MRK_WRAPPING_VAULT_HELPER)
    if (mrk_vault_control_admit(1) != MRK_W_CONTINUE) { mrk_w_unknown(s, MRK_W_CUSTODY); return 0; }
#endif
    return 1;
}
static int mrk_w_acl_dispose(MRKWrappingFrame *s) {
    if (s->result.flags & MRK_W_UNKNOWN) return 0;
    MRKWrappingAclCell *w = &s->acl_cell; MRKWrappingAcl *a = &s->result.acl;
    if (!mrk_w_qualifier_free(s)) return 0;
    if (w->acl) {
        if (a->acl_acquired != a->acl_freed + 1 || a->acl_free_entered != a->acl_freed) {
            mrk_w_unknown(s, MRK_W_CUSTODY); return 0;
        }
        if (!mrk_w_native_enter(s, MRK_W_ACL, MRK_W_N_ACL_FREE, MRK_W_BEFORE_RELEASE)) return 0;
        ++a->acl_free_entered;
        errno = 0; int rc = acl_free(w->acl); int actual_errno = errno;
        ++a->acl_free_returned; mrk_w_native_return(s, rc, actual_errno);
        if (rc) { mrk_w_native_fail(s, MRK_W_CUSTODY); mrk_w_unknown(s, MRK_W_CUSTODY); return 0; }
        ++a->acl_freed; w->acl = NULL; w->entry = NULL;
#if defined(MRK_WRAPPING_VAULT_HELPER)
        if (mrk_vault_control_admit(1) != MRK_W_CONTINUE) { mrk_w_unknown(s, MRK_W_CUSTODY); return 0; }
#endif
    }
    if (w->filesec) {
        if (a->filesec_acquired != a->filesec_free_returned + 1
            || a->filesec_free_entered != a->filesec_free_returned) {
            mrk_w_unknown(s, MRK_W_CUSTODY); return 0;
        }
        if (!mrk_w_native_enter(s, MRK_W_ACL, MRK_W_N_FILESEC_FREE, MRK_W_BEFORE_RELEASE)) return 0;
        ++a->filesec_free_entered;
        errno = 0; filesec_free(w->filesec); int actual_errno = errno;
        ++a->filesec_free_returned; mrk_w_native_return(s, 0, actual_errno);
        w->filesec = NULL; // Only after the original void call actually returned.
#if defined(MRK_WRAPPING_VAULT_HELPER)
        if (mrk_vault_control_admit(1) != MRK_W_CONTINUE) { mrk_w_unknown(s, MRK_W_CUSTODY); return 0; }
#endif
    }
    return 1;
}
static int mrk_w_acl_body(MRKWrappingFrame *s, const MRKWrappingFd *slot) {
    MRKWrappingAclCell *w = &s->acl_cell; MRKWrappingAcl *a = &s->result.acl;
    if (!mrk_w_native_enter(s, MRK_W_ACL, MRK_W_N_FILESEC_INIT, MRK_W_BEFORE_CALL)) return 0;
    ++a->filesec_init_entered;
    errno = 0; w->filesec = filesec_init(); int actual_errno = errno;
    ++a->filesec_init_returned;
    if (w->filesec) ++a->filesec_acquired;
    mrk_w_native_return(s, w->filesec != NULL, actual_errno);
    if (!w->filesec) return mrk_w_native_fail(s, MRK_W_ALLOCATION);
    if (!mrk_w_admit(s, MRK_W_AFTER_CALL)) return 0;
    // Every output is prearmed in this retained frame. A successful, populated
    // same-FD snapshot is required; errno-only "ACL absent" is not accepted.
#define MRK_W_ACL_READ(code, expression, complete) do { \
    if (!mrk_w_native_enter(s, MRK_W_ACL, (code), MRK_W_BEFORE_CALL)) return 0; \
    errno = 0; int rc = (expression); int saved_errno = errno; \
    mrk_w_native_return(s, rc, saved_errno); \
    if (rc || !(complete)) return mrk_w_native_fail(s, MRK_W_UNSUPPORTED); \
    if (!mrk_w_admit(s, MRK_W_AFTER_CALL)) return 0; \
} while (0)
    MRK_W_ACL_READ(MRK_W_N_FSTATX, fstatx_np(slot->fd, &w->snapshot, w->filesec),
        mrk_w_protected(s, slot, &w->snapshot) && mrk_w_same(mrk_w_identity(&w->snapshot), slot->identity));
    MRK_W_ACL_READ(MRK_W_N_OWNER, filesec_get_property(w->filesec, FILESEC_OWNER, &w->owner), w->owner == w->snapshot.st_uid);
    MRK_W_ACL_READ(MRK_W_N_GROUP, filesec_get_property(w->filesec, FILESEC_GROUP, &w->group), w->group == w->snapshot.st_gid);
    MRK_W_ACL_READ(MRK_W_N_MODE, filesec_get_property(w->filesec, FILESEC_MODE, &w->mode), w->mode == w->snapshot.st_mode);
    MRK_W_ACL_READ(MRK_W_N_PRESENCE, filesec_query_property(w->filesec, FILESEC_ACL, &w->present), 1);
    if (!w->present) return 1; // Successful complete explicit absence.
    if (!mrk_w_native_enter(s, MRK_W_ACL, MRK_W_N_ACL_EXPORT, MRK_W_BEFORE_CALL)) return 0;
    ++a->acl_export_entered;
    errno = 0; int rc = filesec_get_property(w->filesec, FILESEC_ACL, &w->acl); actual_errno = errno;
    ++a->acl_export_returned; mrk_w_native_return(s, rc, actual_errno);
    int sentinel = (void *)w->acl == _FILESEC_REMOVE_ACL || (void *)w->acl == _FILESEC_UNSET_PROPERTY;
    if (w->acl && !sentinel) {
        if (rc) { // A populated failed out-call has uncertain ownership, not a free permit.
            mrk_w_native_fail(s, MRK_W_CUSTODY); mrk_w_unknown(s, MRK_W_CUSTODY); return 0;
        }
        ++a->acl_acquired;
    } else {
        w->acl = NULL; // Recognized sentinels are not allocations and are never freed.
        return mrk_w_native_fail(s, MRK_W_SHAPE);
    }
    if (!mrk_w_admit(s, MRK_W_AFTER_CALL)) return 0;
    MRK_W_ACL_READ(MRK_W_N_ACL_VALID, acl_valid(w->acl), 1);
    const acl_permset_mask_t mutations = (acl_permset_mask_t)(ACL_WRITE_DATA | ACL_APPEND_DATA | ACL_DELETE
        | ACL_DELETE_CHILD | ACL_WRITE_ATTRIBUTES | ACL_WRITE_EXTATTRIBUTES | ACL_WRITE_SECURITY | ACL_CHANGE_OWNER);
    const acl_permset_mask_t known = mutations | (acl_permset_mask_t)(ACL_READ_DATA | ACL_EXECUTE
        | ACL_READ_ATTRIBUTES | ACL_READ_EXTATTRIBUTES | ACL_READ_SECURITY | ACL_SYNCHRONIZE);
    for (uint32_t index = 0; index <= MRK_W_ACES; ++index) {
        if (!mrk_w_native_enter(s, MRK_W_ACL, MRK_W_N_ENTRY, MRK_W_BEFORE_CALL)) return 0;
        w->entry = NULL;
        errno = 0; rc = acl_get_entry(w->acl, index ? ACL_NEXT_ENTRY : ACL_FIRST_ENTRY, &w->entry); actual_errno = errno;
        mrk_w_native_return(s, rc, actual_errno);
        // Public Darwin enumeration: success0 is an entry; -1/EINVAL is end on
        // this already valid ACL. We make the extra end call at the128-entry cap.
        if (rc == -1 && actual_errno == EINVAL) {
            if (w->entry) return mrk_w_native_fail(s, MRK_W_SHAPE);
            if (!mrk_w_admit(s, MRK_W_AFTER_CALL)) return 0;
            return 1;
        }
        if (rc || !w->entry || index == MRK_W_ACES) return mrk_w_native_fail(s, MRK_W_UNSUPPORTED);
        ++a->entries;
        if (!mrk_w_admit(s, MRK_W_AFTER_CALL)) return 0;
        w->tag = ACL_UNDEFINED_TAG; w->rights = 0;
        MRK_W_ACL_READ(MRK_W_N_TAG, acl_get_tag_type(w->entry, &w->tag),
            w->tag == ACL_EXTENDED_ALLOW || w->tag == ACL_EXTENDED_DENY);
        // This PUBLIC rights-mask API does not inspect an opaque ACL layout.
        MRK_W_ACL_READ(MRK_W_N_RIGHTS, acl_get_permset_mask_np(w->entry, &w->rights), !(w->rights & ~known));
        if (!mrk_w_native_enter(s, MRK_W_ACL, MRK_W_N_QUALIFIER, MRK_W_BEFORE_CALL)) return 0;
        ++a->qualifier_entered;
        errno = 0; w->qualifier = acl_get_qualifier(w->entry); actual_errno = errno;
        ++a->qualifier_returned;
        if (w->qualifier) ++a->qualifier_acquired;
        mrk_w_native_return(s, w->qualifier != NULL, actual_errno);
        if (!w->qualifier) return mrk_w_native_fail(s, MRK_W_UNSUPPORTED);
        // Public extended-ACL qualifiers are UUID allocations. Both trusted UUIDs
        // came from mbr_uid_to_uuid(USER IDs), never group-membership equivalence.
        int trusted = !memcmp(w->qualifier, s->root_uuid, sizeof(uuid_t))
            || !memcmp(w->qualifier, s->user_uuid, sizeof(uuid_t));
        if (w->tag == ACL_EXTENDED_ALLOW && (w->rights & mutations) && !trusted)
            return mrk_w_native_fail(s, MRK_W_UNSUPPORTED);
        // Treat EVERY allow as potentially applicable, including inherit-only.
        // DENY grants nothing. Flags never excuse a foreign mutating allow; we
        // do not claim complete enumeration of unknown applicability flags.
        if (!mrk_w_admit(s, MRK_W_AFTER_CALL) || !mrk_w_qualifier_free(s)) return 0;
    }
#undef MRK_W_ACL_READ
    return mrk_w_native_fail(s, MRK_W_UNSUPPORTED);
}
static int mrk_w_acl_snapshot(MRKWrappingFrame *s, const MRKWrappingFd *slot) {
    MRKWrappingAcl *a = &s->result.acl;
    if (s->acl_cell.filesec || s->acl_cell.acl || s->acl_cell.qualifier
        || a->snapshots_entered != a->snapshots_returned || a->snapshots_entered >= MRK_W_ACL_SNAPSHOTS) {
        mrk_w_unknown(s, MRK_W_CUSTODY); return 0;
    }
    // Only settled original working cells are reused. No live allocation is
    // erased or replaced by a fresh descriptor after an unknown disposal.
    memset(&s->acl_cell, 0, sizeof(s->acl_cell));
    ++a->snapshots_entered;
    int admitted = mrk_w_acl_body(s, slot);
    int disposed = mrk_w_acl_dispose(s);
    ++a->snapshots_returned;
    if (admitted && disposed && !(s->result.flags & (MRK_W_UNKNOWN | MRK_W_STOP))) {
        ++a->snapshots_admitted; return 1;
    }
    return 0;
}
static int mrk_w_fd_check(MRKWrappingFrame *s, uint32_t index) {
    MRKWrappingFd *slot = &s->fds[index];
    if (!slot->identity_ready || slot->fd < 0 || !s->result.descriptors[index].acquired) {
        mrk_w_unknown(s, MRK_W_CUSTODY); return 0;
    }
    if (!mrk_w_held(s, slot, &s->held_stat) || !mrk_w_named(s, slot, &s->named_stat)) return 0;
    if (!mrk_w_protected(s, slot, &s->held_stat) || !mrk_w_protected(s, slot, &s->named_stat)
        || !mrk_w_same(slot->identity, mrk_w_identity(&s->held_stat))
        || !mrk_w_same(slot->identity, mrk_w_identity(&s->named_stat)))
        return mrk_w_native_fail(s, MRK_W_UNSUPPORTED);
    if (!mrk_w_filesystem(s, slot) || !mrk_w_acl_snapshot(s, slot)) return 0;
    // Surround the complete same-FD ACL observation with paired held/edge checks.
    if (!mrk_w_held(s, slot, &s->held_stat) || !mrk_w_named(s, slot, &s->named_stat)) return 0;
    if (!mrk_w_same(slot->identity, mrk_w_identity(&s->held_stat))
        || !mrk_w_same(slot->identity, mrk_w_identity(&s->named_stat)))
        return mrk_w_native_fail(s, MRK_W_UNSUPPORTED);
    return 1;
}
static int mrk_w_fd_acquire(MRKWrappingFrame *s, uint32_t index) {
    MRKWrappingFd *slot = &s->fds[index]; MRKWrappingDescriptor *r = &s->result.descriptors[index];
    if (!r->reserved || r->open_entered || slot->fd != -1
        || (slot->parent != UINT32_MAX && (slot->parent >= index || s->fds[slot->parent].fd < 0))) {
        mrk_w_unknown(s, MRK_W_CUSTODY); return 0;
    }
    if (!mrk_w_named(s, slot, &s->named_stat)) return 0;
    if (!mrk_w_protected(s, slot, &s->named_stat)) return mrk_w_native_fail(s, MRK_W_UNSUPPORTED);
    slot->identity = mrk_w_identity(&s->named_stat); slot->identity_ready = 1;
    s->result.phase = MRK_W_FILESYSTEM;
    if (!mrk_w_admit(s, MRK_W_BEFORE_CALL)) return 0;
    int flags = O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | (slot->directory ? O_DIRECTORY : 0);
    r->open_entered = 1;
    errno = 0;
    slot->fd = slot->parent == UINT32_MAX ? open("/", flags)
        : openat(s->fds[slot->parent].fd, s->component_names + slot->name_offset, flags);
    r->open_errno = errno; r->open_returned = 1; r->acquired = slot->fd >= 0;
    if (!r->acquired) { s->result.account_errno = r->open_errno; return mrk_w_fail(s, MRK_W_UNAVAILABLE); }
    if (!mrk_w_admit(s, MRK_W_AFTER_CALL)) return 0;
    return mrk_w_fd_check(s, index);
}
static int mrk_w_user_uuids(MRKWrappingFrame *s) {
    if (!mrk_w_native_enter(s, MRK_W_UUID, MRK_W_N_ROOT_UUID, MRK_W_BEFORE_CALL)) return 0;
    errno = 0; int rc = mbr_uid_to_uuid((uid_t)0, s->root_uuid); int actual_errno = errno;
    mrk_w_native_return(s, rc, actual_errno);
    if (rc) return mrk_w_native_fail(s, MRK_W_UNSUPPORTED);
    if (!mrk_w_admit(s, MRK_W_AFTER_CALL)) return 0;
    if (!mrk_w_native_enter(s, MRK_W_UUID, MRK_W_N_USER_UUID, MRK_W_BEFORE_CALL)) return 0;
    errno = 0; rc = mbr_uid_to_uuid((uid_t)s->uid, s->user_uuid); actual_errno = errno;
    mrk_w_native_return(s, rc, actual_errno);
    if (rc) return mrk_w_native_fail(s, MRK_W_UNSUPPORTED);
    uint8_t root_bits = 0, user_bits = 0;
    for (size_t i = 0; i < sizeof(uuid_t); ++i) { root_bits |= s->root_uuid[i]; user_bits |= s->user_uuid[i]; }
    if (!root_bits || !user_bits || !memcmp(s->root_uuid, s->user_uuid, sizeof(uuid_t)))
        return mrk_w_native_fail(s, MRK_W_SHAPE);
    return mrk_w_admit(s, MRK_W_AFTER_CALL);
}
static int mrk_w_path_admission(MRKWrappingFrame *s, size_t home_length) {
    size_t length = strnlen(s->path, sizeof(s->path));
    if (!home_length || length >= sizeof(s->path) || s->path[0] != '/' || s->result.descriptor_count)
        return mrk_w_fail(s, MRK_W_INPUT);
    memcpy(s->component_names, s->path, length + 1);
    uint32_t components = 0; size_t start = 1;
    for (size_t i = 1; i <= length; ++i) {
        if (i != length && s->path[i] != '/') continue;
        size_t bytes = i - start;
        if (!bytes || bytes > 255 || components >= MRK_W_COMPONENTS
            || (bytes == 1 && s->path[start] == '.')
            || (bytes == 2 && s->path[start] == '.' && s->path[start + 1] == '.'))
            return mrk_w_fail(s, MRK_W_UNSUPPORTED);
        s->component_offsets[components] = (uint32_t)start;
        s->component_ends[components] = (uint32_t)i;
        ++components; s->component_names[i] = 0; start = i + 1;
    }
    if (!components || components + MRK_W_CHECKPOINTS > MRK_W_FDS) return mrk_w_fail(s, MRK_W_UNSUPPORTED);
    // root + (components minus the leaf) directories; five predeclared, distinct
    // leaf originals, one per checkpoint. No new arbitrary path enters later.
    s->result.directory_count = components;
    s->result.descriptor_count = components + MRK_W_CHECKPOINTS;
    for (uint32_t i = 0; i < s->result.descriptor_count; ++i) {
        MRKWrappingFd *slot = &s->fds[i];
        s->result.descriptors[i].reserved = 1;
        slot->directory = i < components;
        slot->parent = i == 0 ? UINT32_MAX : i < components ? i - 1 : components - 1;
        slot->name_offset = i == 0 ? 0 : s->component_offsets[i < components ? i - 1 : components - 1];
        slot->uid_rule = i == 0 ? 0 : i >= components || s->component_ends[i - 1] >= home_length ? 1 : 2;
    }
    if (!mrk_w_user_uuids(s)) return 0;
    for (uint32_t i = 0; i < components; ++i) if (!mrk_w_fd_acquire(s, i)) return 0;
    return 1;
}
static int mrk_w_namespace(MRKWrappingFrame *s, uint32_t checkpoint) {
    s->result.phase = MRK_W_NAMESPACE;
    if (!mrk_w_admit(s, MRK_W_BEFORE_CALL)) return 0;
    if (checkpoint >= MRK_W_CHECKPOINTS || !s->result.directory_count
        || s->result.namespace_entered != checkpoint || s->result.namespace_returned != checkpoint
        || s->result.namespace_passed != checkpoint) {
        mrk_w_unknown(s, MRK_W_CUSTODY); return 0;
    }
    ++s->result.namespace_entered;
    int admitted = 1;
    for (uint32_t i = 0; i < s->result.directory_count; ++i)
        if (!mrk_w_fd_check(s, i)) { admitted = 0; break; }
    if (admitted && !mrk_w_fd_acquire(s, s->result.directory_count + checkpoint)) admitted = 0;
    ++s->result.namespace_returned;
    s->result.phase = MRK_W_NAMESPACE;
    if (admitted) {
        ++s->result.namespace_passed;
        if (s->result.namespace_passed == MRK_W_CHECKPOINTS) s->result.flags |= MRK_W_NAMESPACE_VERIFIED;
    }
    // The held leaf snapshots may have different inodes after normal provider
    // writes. No cross-checkpoint DB inode, hash, size or timestamp equality.
    return admitted;
}
static int mrk_w_account(MRKWrappingFrame *s) {
    s->result.phase = MRK_W_ACCOUNT_PHASE;
    if (!mrk_w_admit(s, MRK_W_BEFORE_CALL)) return 0;
    uint32_t uid = 0;
    int user = mrk_user(&uid);
    if (user) { s->result.account_errno = user; return mrk_w_fail(s, user == ENOTSUP ? MRK_W_UNSUPPORTED : MRK_W_UNAVAILABLE); }
    s->uid = uid;
    s->result.flags |= MRK_W_USER;
    struct passwd password, *matched = NULL;
    int result = getpwuid_r((uid_t)uid, &password, s->account_scratch, sizeof(s->account_scratch), &matched);
    if (result || matched != &password || password.pw_uid != uid || !password.pw_dir) {
        s->result.account_errno = result;
        return mrk_w_fail(s, result == ERANGE ? MRK_W_UNSUPPORTED : MRK_W_UNAVAILABLE);
    }
    uintptr_t begin = (uintptr_t)s->account_scratch, end = begin + sizeof(s->account_scratch), home = (uintptr_t)password.pw_dir;
    if (home < begin || home >= end) return mrk_w_fail(s, MRK_W_SHAPE);
    size_t available = (size_t)(end - home);
    size_t length = strnlen(password.pw_dir, available);
    static const char suffix[] = "/Library/Keychains/login.keychain-db";
    if (length < 2 || length == available || password.pw_dir[0] != '/' || password.pw_dir[length - 1] == '/'
        || length > sizeof(s->path) - sizeof(suffix)) return mrk_w_fail(s, MRK_W_UNSUPPORTED);
    memcpy(s->path, password.pw_dir, length);
    memcpy(s->path + length, suffix, sizeof(suffix));
#if defined(MRK_WRAPPING_KEYCHAIN_QUALIFICATION)
    if (s->qualification.observation.mode) s->qualification.observation.account_selected = 1;
    if (s->qualification.observation.mode == MRK_W_Q_SELECTOR) {
        // Deliberately leave outcome Pending: this is only a selected spelling,
        // NOT an item/provider success or an invented native refusal/status.
        s->qualification.observation.selector_boundary_returned = 1;
        mrk_w_wipe(s->account_scratch, sizeof(s->account_scratch));
        return 0;
    }
    if (s->qualification.observation.mode == MRK_W_Q_FIXTURE && !mrk_w_qualification_select(s, length)) return 0;
    if (s->qualification.observation.mode != MRK_W_Q_HELPERS) {
#endif
    s->result.phase = MRK_W_PATH_PHASE;
    if (!mrk_w_admit(s, MRK_W_BEFORE_CALL) || !mrk_w_path_admission(s, length)) return 0;
#if defined(MRK_WRAPPING_KEYCHAIN_QUALIFICATION)
    }
#endif
    static const char hex[] = "0123456789abcdef";
    memcpy(s->account, "v1:", 3);
    for (unsigned i = 0; i < 16; ++i) {
        s->account[3 + i * 2] = hex[s->vault[i] >> 4];
        s->account[4 + i * 2] = hex[s->vault[i] & 15];
        s->account[36 + i * 2] = hex[s->generation[i] >> 4];
        s->account[37 + i * 2] = hex[s->generation[i] & 15];
    }
    s->account[35] = ':'; s->account[MRK_W_ACCOUNT] = 0;
    static const uint8_t domain[16] = "MRK-WRAP-MAC-v1"; // 15 ASCII bytes plus NUL, exactly16.
    memcpy(s->metadata, domain, sizeof(domain));
    for (unsigned i = 0; i < 4; ++i) s->metadata[16 + i] = (uint8_t)(uid >> (24 - i * 8));
    memcpy(s->metadata + 20, s->vault, 16);
    memcpy(s->metadata + 36, s->generation, 16);
    // No password/home pointer escapes this call; no account strings are logged.
    mrk_w_wipe(s->account_scratch, sizeof(s->account_scratch));
    return 1;
}
static MRKWrappingOwned *mrk_w_open(MRKWrappingFrame *s) {
    if (!mrk_w_namespace(s, 0)) return NULL; // Before the actual SecKeychainOpen.
    MRKWrappingOwned *original = mrk_w_slot(s);
    if (!original) return NULL;
    MRKWrappingCall *call = mrk_w_call(s, MRK_W_OPEN);
    if (!call) return NULL;
    mrk_w_cf_enter(s, original);
    OSStatus status = SecKeychainOpen(s->path, &original->pending.keychain);
    original->value = original->pending.keychain;
    mrk_w_return(call, status); mrk_w_cf_return(s, original);
    int opened = mrk_w_status(s, status, MRK_W_OPEN);
    if (!mrk_w_admit(s, MRK_W_AFTER_CALL) || !mrk_w_namespace(s, 1)) return NULL;
    if (!opened || !mrk_w_type(s, original->value, SecKeychainGetTypeID())) return NULL;
    call = mrk_w_call(s, MRK_W_GET_PATH);
    if (!call) return NULL;
    UInt32 bytes = sizeof(s->observed_path);
    status = SecKeychainGetPath((SecKeychainRef)original->value, &bytes, s->observed_path);
    mrk_w_return(call, status);
    if (!mrk_w_status(s, status, MRK_W_GET_PATH) || !mrk_w_admit(s, MRK_W_AFTER_CALL)) return NULL;
    size_t expected = strnlen(s->path, sizeof(s->path));
    size_t actual = strnlen(s->observed_path, sizeof(s->observed_path));
    // GetPath proves spelling only: the public SDK exposes no provider-FD inode
    // attestation. Retained ancestry/ACL/leaf checks are bounded checkpoints under
    // the trusted-OS/current-user boundary, not hostile same-user swapback proof.
    // Require a complete bounded NUL-terminated identical path. Whether the
    // returned count includes the terminator cannot permit a different spelling.
    if (!bytes || bytes > sizeof(s->observed_path) || actual >= sizeof(s->observed_path)
        || actual != expected || (bytes != actual && bytes != actual + 1)
        || memcmp(s->path, s->observed_path, actual + 1)) { mrk_w_fail(s, MRK_W_SHAPE); return NULL; }
    call = mrk_w_call(s, MRK_W_GET_STATUS);
    if (!call) return NULL;
    SecKeychainStatus observed = 0;
    status = SecKeychainGetStatus((SecKeychainRef)original->value, &observed);
    mrk_w_return(call, status);
    if (!mrk_w_status(s, status, MRK_W_GET_STATUS)) return NULL;
    s->result.keychain_status = observed;
    s->result.flags |= MRK_W_STATUS_OBSERVED;
    if (!(observed & kSecUnlockStateStatus)) { mrk_w_fail(s, MRK_W_LOCKED); return NULL; }
    if (!mrk_w_admit(s, MRK_W_AFTER_CALL)) return NULL;
    return original;
}
static MRKWrappingOwned *mrk_w_string(MRKWrappingFrame *s, const char *text, size_t length) {
    s->result.phase = MRK_W_QUERY;
    if (!mrk_w_admit(s, MRK_W_BEFORE_CALL)) return NULL;
    MRKWrappingOwned *slot = mrk_w_slot(s); if (!slot) return NULL;
    mrk_w_cf_enter(s, slot);
    slot->value = CFStringCreateWithBytes(NULL, (const UInt8 *)text, (CFIndex)length, kCFStringEncodingASCII, false);
    mrk_w_cf_return(s, slot);
    if (!slot->value) { mrk_w_fail(s, MRK_W_ALLOCATION); return NULL; }
    if (!mrk_w_type(s, slot->value, CFStringGetTypeID())) return NULL;
    return slot;
}
static MRKWrappingOwned *mrk_w_data(MRKWrappingFrame *s, const uint8_t *bytes, size_t length, int no_copy) {
    s->result.phase = MRK_W_QUERY;
    if (!mrk_w_admit(s, MRK_W_BEFORE_CALL)) return NULL;
    MRKWrappingOwned *slot = mrk_w_slot(s); if (!slot) return NULL;
    mrk_w_cf_enter(s, slot);
    if (no_copy) s->key_backing_borrowed = 1;
    slot->value = no_copy
        ? CFDataCreateWithBytesNoCopy(NULL, bytes, (CFIndex)length, kCFAllocatorNull)
        : CFDataCreate(NULL, bytes, (CFIndex)length);
    if (no_copy && !slot->value) s->key_backing_borrowed = 0;
    mrk_w_cf_return(s, slot);
    if (!slot->value) { mrk_w_fail(s, MRK_W_ALLOCATION); return NULL; }
    if (!mrk_w_type(s, slot->value, CFDataGetTypeID())) return NULL;
    return slot;
}
static MRKWrappingOwned *mrk_w_singleton(MRKWrappingFrame *s, CFTypeRef value) {
    s->result.phase = MRK_W_QUERY;
    if (!mrk_w_admit(s, MRK_W_BEFORE_CALL)) return NULL;
    MRKWrappingOwned *slot = mrk_w_slot(s); if (!slot) return NULL;
    const void *values[] = { value };
    mrk_w_cf_enter(s, slot);
    slot->value = CFArrayCreate(NULL, values, 1, &kCFTypeArrayCallBacks);
    mrk_w_cf_return(s, slot);
    if (!slot->value) { mrk_w_fail(s, MRK_W_ALLOCATION); return NULL; }
    if (!mrk_w_type(s, slot->value, CFArrayGetTypeID()) || CFArrayGetCount((CFArrayRef)slot->value) != 1) {
        mrk_w_fail(s, MRK_W_SHAPE); return NULL;
    }
    return slot;
}
static MRKWrappingOwned *mrk_w_access(MRKWrappingFrame *s) {
    MRKWrappingOwned *trusted = mrk_w_slot(s); if (!trusted) return NULL;
    MRKWrappingCall *call = mrk_w_call(s, MRK_W_TRUSTED); if (!call) return NULL;
    mrk_w_cf_enter(s, trusted);
    OSStatus status = SecTrustedApplicationCreateFromPath(NULL, &trusted->pending.trusted);
    trusted->value = trusted->pending.trusted;
    mrk_w_return(call, status); mrk_w_cf_return(s, trusted);
    if (!mrk_w_status(s, status, MRK_W_TRUSTED) || !mrk_w_admit(s, MRK_W_AFTER_CALL)
        || !mrk_w_type(s, trusted->value, SecTrustedApplicationGetTypeID())) return NULL;
    MRKWrappingOwned *list = mrk_w_singleton(s, trusted->value);
    if (!list) return NULL;
    MRKWrappingOwned *access = mrk_w_slot(s); if (!access) return NULL;
    call = mrk_w_call(s, MRK_W_ACCESS); if (!call) return NULL;
    mrk_w_cf_enter(s, access);
    // Explicit singleton current executable, never NULL/empty/wildcard trust.
    status = SecAccessCreate(CFSTR("MobileReleaseKit vault wrapping key v1"), (CFArrayRef)list->value, &access->pending.access);
    access->value = access->pending.access;
    mrk_w_return(call, status); mrk_w_cf_return(s, access);
    if (!mrk_w_status(s, status, MRK_W_ACCESS) || !mrk_w_admit(s, MRK_W_AFTER_CALL)
        || !mrk_w_type(s, access->value, SecAccessGetTypeID())) return NULL;
    return access;
}
static MRKWrappingOwned *mrk_w_dictionary(MRKWrappingFrame *s, const void **keys, const void **values, CFIndex count) {
    s->result.phase = MRK_W_QUERY;
    if (count <= 0 || count > 16 || !mrk_w_admit(s, MRK_W_BEFORE_CALL)) return NULL;
    MRKWrappingOwned *slot = mrk_w_slot(s); if (!slot) return NULL;
    mrk_w_cf_enter(s, slot);
    slot->value = CFDictionaryCreate(NULL, keys, values, count, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    mrk_w_cf_return(s, slot);
    if (!slot->value) { mrk_w_fail(s, MRK_W_ALLOCATION); return NULL; }
    if (!mrk_w_type(s, slot->value, CFDictionaryGetTypeID()) || CFDictionaryGetCount((CFDictionaryRef)slot->value) != count) {
        mrk_w_fail(s, MRK_W_SHAPE); return NULL;
    }
    return slot;
}
static int mrk_w_original_item(MRKWrappingFrame *s, CFTypeRef item, SecKeychainRef original) {
    s->result.phase = MRK_W_VALIDATE;
    if (!mrk_w_type(s, item, SecKeychainItemGetTypeID())) return 0;
    MRKWrappingOwned *parent = mrk_w_slot(s); if (!parent) return 0;
    MRKWrappingCall *call = mrk_w_call(s, MRK_W_PARENT); if (!call) return 0;
    mrk_w_cf_enter(s, parent);
    OSStatus status = SecKeychainItemCopyKeychain((SecKeychainItemRef)item, &parent->pending.keychain);
    parent->value = parent->pending.keychain;
    mrk_w_return(call, status); mrk_w_cf_return(s, parent);
    if (!mrk_w_status(s, status, MRK_W_PARENT) || !mrk_w_admit(s, MRK_W_AFTER_CALL)
        || !mrk_w_type(s, parent->value, SecKeychainGetTypeID())) return 0;
    if (!CFEqual(parent->value, original)) return mrk_w_fail(s, MRK_W_SHAPE);
    s->result.flags |= MRK_W_ITEM_VERIFIED;
    return 1;
}
static int mrk_w_exact_string(MRKWrappingFrame *s, CFTypeRef object, const char *expected, size_t bytes, size_t cap) {
    if (!mrk_w_type(s, object, CFStringGetTypeID())) return 0;
    CFIndex length = CFStringGetLength((CFStringRef)object);
    if (length != (CFIndex)bytes || bytes > cap || cap > 96) return mrk_w_fail(s, MRK_W_SHAPE);
    char text[97] = {0};
    if (!CFStringGetCString((CFStringRef)object, text, (CFIndex)(cap + 1), kCFStringEncodingUTF8)) return mrk_w_fail(s, MRK_W_SHAPE);
    size_t actual = strnlen(text, cap + 1);
    if (actual != bytes || memcmp(text, expected, bytes)) return mrk_w_fail(s, MRK_W_SHAPE);
    return 1;
}
static int mrk_w_context_data(MRKWrappingFrame *s, CFTypeRef object) {
    if (!mrk_w_type(s, object, CFDataGetTypeID()) || CFDataGetLength((CFDataRef)object) != MRK_W_METADATA)
        return mrk_w_fail(s, MRK_W_SHAPE);
    const UInt8 *bytes = CFDataGetBytePtr((CFDataRef)object);
    if (!bytes || memcmp(bytes, s->metadata, MRK_W_METADATA)) return mrk_w_fail(s, MRK_W_SHAPE);
    return 1;
}
static int mrk_w_key_data(MRKWrappingFrame *s, CFTypeRef object) {
    if (!mrk_w_type(s, object, CFDataGetTypeID()) || CFDataGetLength((CFDataRef)object) != MRK_W_KEY)
        return mrk_w_fail(s, MRK_W_SHAPE);
    return 1;
}
#if defined(MRK_WRAPPING_KEYCHAIN_QUALIFICATION)
static void mrk_w_qualification_helpers(MRKWrappingFrame *s) {
    MRKWrappingQualificationObservation *q = &s->qualification.observation;
    // Fixed helper-shape checks, NOT provider returns or a fault-injection seam.
    // Each real CF allocation is prearmed in the normal frame and disposed by
    // the normal cleanup. Expected predicate refusals are never reset; actual
    // SDK/custody observations and the first refusal remain untouched.
#define MRK_W_Q_CHECK(expression, expected) do { \
    s->result.phase = MRK_W_VALIDATE; \
    if (q->helpers_entered >= MRK_W_Q_SHAPES || !mrk_w_admit(s, MRK_W_BEFORE_CALL)) return; \
    uint32_t index = q->helpers_entered++; \
    int actual = !!(expression); \
    ++q->helpers_returned; \
    if (actual == (expected)) q->helper_matches |= 1u << index; \
    if (!mrk_w_admit(s, MRK_W_AFTER_CALL)) return; \
} while (0)
    memset(s->observed_path, 0, sizeof(s->observed_path));
    MRK_W_Q_CHECK(mrk_w_ids(s->vault, s->generation), 1);
    MRK_W_Q_CHECK(mrk_w_ids((const uint8_t *)s->observed_path, s->generation), 0);
    MRK_W_Q_CHECK(mrk_w_ids(s->vault, (const uint8_t *)s->observed_path), 0);
    MRK_W_Q_CHECK(mrk_w_ids(s->vault, s->vault), 0);
    MRKWrappingOwned *account = mrk_w_string(s, s->account, MRK_W_ACCOUNT); if (!account) return;
    MRK_W_Q_CHECK(mrk_w_exact_string(s, account->value, s->account, MRK_W_ACCOUNT, MRK_W_ACCOUNT), 1);
    MRK_W_Q_CHECK(mrk_w_exact_string(s, kCFBooleanFalse, s->account, MRK_W_ACCOUNT, MRK_W_ACCOUNT), 0);
    MRKWrappingOwned *short_account = mrk_w_string(s, s->account, MRK_W_ACCOUNT - 1); if (!short_account) return;
    MRK_W_Q_CHECK(mrk_w_exact_string(s, short_account->value, s->account, MRK_W_ACCOUNT, MRK_W_ACCOUNT), 0);
    memcpy(s->observed_path, s->account, MRK_W_ACCOUNT); s->observed_path[8] = 0;
    MRKWrappingOwned *nul_account = mrk_w_string(s, s->observed_path, MRK_W_ACCOUNT); if (!nul_account) return;
    MRK_W_Q_CHECK(mrk_w_exact_string(s, nul_account->value, s->account, MRK_W_ACCOUNT, MRK_W_ACCOUNT), 0);
    MRKWrappingOwned *context = mrk_w_data(s, s->metadata, MRK_W_METADATA, 0); if (!context) return;
    MRK_W_Q_CHECK(mrk_w_context_data(s, context->value), 1);
    MRK_W_Q_CHECK(mrk_w_context_data(s, kCFBooleanFalse), 0);
    MRKWrappingOwned *short_context = mrk_w_data(s, s->metadata, MRK_W_METADATA - 1, 0); if (!short_context) return;
    MRK_W_Q_CHECK(mrk_w_context_data(s, short_context->value), 0);
    const uint32_t changed_offsets[] = { 15, 16, 20, 36 }; // Domain NUL, UID, vault, generation.
    for (unsigned i = 0; i < 4; ++i) {
        memcpy(s->observed_path, s->metadata, MRK_W_METADATA);
        s->observed_path[changed_offsets[i]] ^= 1;
        MRKWrappingOwned *changed = mrk_w_data(s, (const uint8_t *)s->observed_path, MRK_W_METADATA, 0);
        if (!changed) return;
        MRK_W_Q_CHECK(mrk_w_context_data(s, changed->value), 0);
    }
    memset(s->observed_path, 0, MRK_W_KEY + 1);
    MRKWrappingOwned *key = mrk_w_data(s, (const uint8_t *)s->observed_path, MRK_W_KEY, 0); if (!key) return;
    MRK_W_Q_CHECK(mrk_w_key_data(s, key->value), 1);
    MRKWrappingOwned *short_key = mrk_w_data(s, (const uint8_t *)s->observed_path, MRK_W_KEY - 1, 0); if (!short_key) return;
    MRK_W_Q_CHECK(mrk_w_key_data(s, short_key->value), 0);
    MRKWrappingOwned *long_key = mrk_w_data(s, (const uint8_t *)s->observed_path, MRK_W_KEY + 1, 0); if (!long_key) return;
    MRK_W_Q_CHECK(mrk_w_key_data(s, long_key->value), 0);
    MRK_W_Q_CHECK(mrk_w_key_data(s, kCFBooleanFalse), 0);
    MRK_W_Q_CHECK(mrk_w_exact_string(s, account->value, s->account, MRK_W_ACCOUNT, 97), 0);
#undef MRK_W_Q_CHECK
}
#endif
static void mrk_w_operation(MRKWrappingFrame *s) {
    if (!mrk_w_account(s)) return;
#if defined(MRK_WRAPPING_KEYCHAIN_QUALIFICATION)
    if (s->qualification.observation.mode == MRK_W_Q_HELPERS) { mrk_w_qualification_helpers(s); return; }
#endif
    MRKWrappingOwned *original = mrk_w_open(s); if (!original) return;
    static const char service_text[] = "dev.mobile-release-kit.desktop/vault/wrapping-key/v1";
    MRKWrappingOwned *service = mrk_w_string(s, service_text, sizeof(service_text) - 1);
    if (!service) return;
    MRKWrappingOwned *account = mrk_w_string(s, s->account, MRK_W_ACCOUNT);
    if (!account) return;
    MRKWrappingOwned *generic = NULL, *access = NULL, *value = NULL, *search = NULL;
    if (s->result.operation == MRK_W_ADD) {
        generic = mrk_w_data(s, s->metadata, MRK_W_METADATA, 0); if (!generic) return;
        access = mrk_w_access(s); if (!access) return;
        // Immutable CFData view of stable adapter-owned key backing. It is never
        // wiped or freed until every original CF release actually returned.
        value = mrk_w_data(s, s->key, MRK_W_KEY, 1); if (!value) return;
    } else {
        search = mrk_w_singleton(s, original->value); if (!search) return;
    }
    const void *keys[16], *values[16]; CFIndex count = 0;
#define MRK_W_PAIR(k, v) do { keys[count] = (k); values[count] = (v); ++count; } while (0)
    MRK_W_PAIR(kSecClass, kSecClassGenericPassword);
    MRK_W_PAIR(kSecAttrService, service->value);
    MRK_W_PAIR(kSecAttrAccount, account->value);
    MRK_W_PAIR(kSecAttrSynchronizable, kCFBooleanFalse);
    // Preserve the query shape (never Skip/missing fallback), but classic items
    // do not establish a per-query UIFail guarantee. The enclosing fixed-helper
    // process guard supplies/observes noninteraction and exact restoration.
    MRK_W_PAIR(kSecUseAuthenticationUI, kSecUseAuthenticationUIFail);
    MRK_W_PAIR(kSecReturnRef, kCFBooleanTrue);
    if (s->result.operation == MRK_W_ADD) {
        MRK_W_PAIR(kSecUseKeychain, original->value);
        MRK_W_PAIR(kSecAttrGeneric, generic->value);
        MRK_W_PAIR(kSecAttrLabel, CFSTR("MobileReleaseKit vault wrapping key v1"));
        MRK_W_PAIR(kSecAttrAccess, access->value);
        MRK_W_PAIR(kSecValueData, value->value);
    } else {
        MRK_W_PAIR(kSecMatchSearchList, search->value);
        MRK_W_PAIR(kSecMatchLimit, kSecMatchLimitOne);
        MRK_W_PAIR(kSecReturnAttributes, kCFBooleanTrue);
        MRK_W_PAIR(kSecReturnData, kCFBooleanTrue);
    }
#undef MRK_W_PAIR
    MRKWrappingOwned *query = mrk_w_dictionary(s, keys, values, count); if (!query) return;
    uint32_t actual_uid = 0;
    int user = mrk_user(&actual_uid);
    if (user || actual_uid != s->uid) { s->result.account_errno = user; mrk_w_fail(s, MRK_W_UNAVAILABLE); return; }
    if (!mrk_w_namespace(s, 2)) return; // Before the one item call.
    MRKWrappingOwned *result = mrk_w_slot(s); if (!result) return;
    uint32_t phase = s->result.operation == MRK_W_ADD ? MRK_W_ADD_CALL : MRK_W_LOOKUP_CALL;
    MRKWrappingCall *call = mrk_w_call(s, phase); if (!call) return;
    mrk_w_cf_enter(s, result);
    OSStatus status;
    if (s->result.operation == MRK_W_ADD) {
        s->result.effect = MRK_W_MAY_HAVE_ADDED; mrk_vault_control_effect(3);
        status = SecItemAdd((CFDictionaryRef)query->value, &result->value);
        mrk_w_return(call, status); mrk_w_cf_return(s, result);
        // These are actual API effect facts, not permission to publish a store.
        if (status == errSecSuccess) { s->result.effect = MRK_W_DID_ADD; mrk_vault_control_effect(1); }
        else if (status == errSecDuplicateItem) { s->result.effect = MRK_W_DID_DUPLICATE; mrk_vault_control_effect(2); }
    } else {
        status = SecItemCopyMatching((CFDictionaryRef)query->value, &result->value);
        mrk_w_return(call, status); mrk_w_cf_return(s, result);
    }
    if (status != errSecSuccess) {
        // A nonnull result on a failed call is not an empty/missing item.
        if (result->value) mrk_w_fail(s, MRK_W_SHAPE);
        else mrk_w_status(s, status, phase);
    }
    // Actual result/+1 and add effect above precede STOP and the postcheck. A
    // post-add filesystem refusal cannot turn Added/MayHaveAdded into no effect.
    if (!mrk_w_admit(s, MRK_W_AFTER_CALL) || !mrk_w_namespace(s, 3)) return;
    if (status != errSecSuccess) return;
    if (s->result.operation == MRK_W_ADD) {
        if (mrk_w_original_item(s, result->value, (SecKeychainRef)original->value)) s->result.outcome = MRK_W_ADDED;
        return;
    }
    s->result.phase = MRK_W_VALIDATE;
    if (!mrk_w_type(s, result->value, CFDictionaryGetTypeID())) return;
    CFDictionaryRef dictionary = (CFDictionaryRef)result->value;
    CFIndex entries = CFDictionaryGetCount(dictionary);
    if (entries <= 0 || entries > 32) { mrk_w_fail(s, MRK_W_SHAPE); return; }
    CFTypeRef found_service = CFDictionaryGetValue(dictionary, kSecAttrService);
    CFTypeRef found_account = CFDictionaryGetValue(dictionary, kSecAttrAccount);
    CFTypeRef found_generic = CFDictionaryGetValue(dictionary, kSecAttrGeneric);
    CFTypeRef found_class = CFDictionaryGetValue(dictionary, kSecClass);
    CFTypeRef synchronized = CFDictionaryGetValue(dictionary, kSecAttrSynchronizable);
    CFTypeRef item = CFDictionaryGetValue(dictionary, kSecValueRef);
    CFTypeRef secret = CFDictionaryGetValue(dictionary, kSecValueData);
    if (!mrk_w_exact_string(s, found_service, service_text, sizeof(service_text) - 1, 96)
        || !mrk_w_exact_string(s, found_account, s->account, MRK_W_ACCOUNT, MRK_W_ACCOUNT)
        || !mrk_w_context_data(s, found_generic)) return;
    if (found_class && (!mrk_w_type(s, found_class, CFStringGetTypeID()) || !CFEqual(found_class, kSecClassGenericPassword))) {
        mrk_w_fail(s, MRK_W_SHAPE); return;
    }
    if (synchronized && (!mrk_w_type(s, synchronized, CFBooleanGetTypeID()) || CFBooleanGetValue((CFBooleanRef)synchronized))) {
        mrk_w_fail(s, MRK_W_SHAPE); return;
    }
    if (!mrk_w_key_data(s, secret)) return;
    if (!mrk_w_original_item(s, item, (SecKeychainRef)original->value)) return;
    const UInt8 *bytes = CFDataGetBytePtr((CFDataRef)secret);
    if (!bytes) { mrk_w_fail(s, MRK_W_SHAPE); return; }
    memcpy(s->key, bytes, MRK_W_KEY); // Never mutate immutable CFData/provider memory.
    s->result.key_bytes = MRK_W_KEY;
    s->result.flags &= ~MRK_W_KEY_WIPED;
    s->result.outcome = MRK_W_FOUND; // Not key-ready until actual cleanup and final admission.
}
static int mrk_w_cf_cleanup(MRKWrappingFrame *s) {
    if (s->result.flags & MRK_W_UNKNOWN) return 0;
    for (uint32_t i = 0; i < s->result.call_count; ++i)
        if (!s->result.calls[i].returned) { mrk_w_unknown(s, MRK_W_CUSTODY); return 0; }
    for (uint32_t i = 0; i < s->result.slot_count; ++i) {
        MRKWrappingReference *r = &s->result.references[i];
        if (r->call_entered != r->call_returned || (!!s->owned[i].value != !!r->nonnull_returned)) {
            mrk_w_unknown(s, MRK_W_CUSTODY); return 0;
        }
    }
    for (uint32_t left = s->result.slot_count; left; --left) {
        MRKWrappingOwned *slot = &s->owned[left - 1];
        MRKWrappingReference *r = &s->result.references[left - 1];
        if (!r->nonnull_returned) continue; // Reserved/null slots are NOT releases.
        s->result.phase = MRK_W_RELEASE;
        if (!mrk_w_admit(s, MRK_W_BEFORE_RELEASE)) return 0;
        r->release_entered = 1;
        @try {
            CFRelease(slot->value);
            r->release_returned = 1; // The original void call actually returned.
            slot->value = NULL;
        } @catch (NSException *exception) {
            (void)exception;
            s->result.flags |= MRK_W_NATIVE_EXCEPTION;
            mrk_w_unknown(s, MRK_W_CUSTODY);
            return 0; // Never retry a possibly consumed pointer or later release.
        }
#if defined(MRK_WRAPPING_VAULT_HELPER)
        if (mrk_vault_control_admit(1) != MRK_W_CONTINUE) { mrk_w_unknown(s, MRK_W_CUSTODY); return 0; }
#endif
    }
    s->key_backing_borrowed = 0;
    return 1;
}
static int mrk_w_acl_settled(const MRKWrappingFrame *s) {
    const MRKWrappingAcl *a = &s->result.acl;
    return !s->acl_cell.filesec && !s->acl_cell.acl && !s->acl_cell.qualifier
        && a->snapshots_entered == a->snapshots_returned
        && a->filesec_init_entered == a->filesec_init_returned
        && a->filesec_acquired == a->filesec_free_entered && a->filesec_free_entered == a->filesec_free_returned
        && a->acl_export_entered == a->acl_export_returned
        && a->acl_acquired == a->acl_free_entered && a->acl_free_entered == a->acl_free_returned
        && a->acl_free_returned == a->acl_freed
        && a->qualifier_entered == a->qualifier_returned
        && a->qualifier_acquired == a->qualifier_free_entered && a->qualifier_free_entered == a->qualifier_free_returned
        && a->qualifier_free_returned == a->qualifier_freed
        && s->result.native.entered == s->result.native.returned;
}
static int mrk_w_fd_cleanup(MRKWrappingFrame *s) {
    if (s->result.flags & MRK_W_UNKNOWN) return 0;
    // Preflight the original slots: an in-flight open/close is not a returned
    // failed close and cannot enable the independent-close continuation below.
    for (uint32_t i = 0; i < s->result.descriptor_count; ++i) {
        MRKWrappingDescriptor *r = &s->result.descriptors[i]; MRKWrappingFd *slot = &s->fds[i];
        if (r->open_entered != r->open_returned || r->close_entered
            || (!!r->acquired != (slot->fd >= 0))) {
            mrk_w_unknown(s, MRK_W_CUSTODY); return 0;
        }
    }
    int all_closed = 1;
    for (uint32_t left = s->result.descriptor_count; left; --left) {
        MRKWrappingDescriptor *r = &s->result.descriptors[left - 1]; MRKWrappingFd *slot = &s->fds[left - 1];
        if (!r->acquired) continue; // Unentered/failed opens own no descriptor.
        s->result.phase = MRK_W_FD_RELEASE;
        if (!mrk_w_admit(s, MRK_W_BEFORE_RELEASE)) { s->independent_fd_cleanup = 0; return 0; }
        slot->consumed_number = slot->fd; slot->fd = -1; // Spend BEFORE the one close.
        r->close_entered = 1;
        errno = 0; int rc = close(slot->consumed_number); int actual_errno = errno;
        r->close_result = rc; r->close_errno = actual_errno;
        r->close_returned = 1; r->closed = rc == 0;
        if (rc) {
            all_closed = 0; mrk_w_unknown(s, MRK_W_CUSTODY);
            // This one narrow state follows a KNOWN RETURNED failed close only.
            // Other original descriptor numbers remain safe independent closes.
            // Never retry this slot, even for EINTR or a possibly reused number.
            s->independent_fd_cleanup = 1;
        }
#if defined(MRK_WRAPPING_VAULT_HELPER)
        if (mrk_vault_control_admit(1) != MRK_W_CONTINUE) {
            s->independent_fd_cleanup = 0; mrk_w_unknown(s, MRK_W_CUSTODY); return 0;
        }
#endif
    }
    s->independent_fd_cleanup = 0;
    return all_closed;
}
static void mrk_w_cleanup(MRKWrappingFrame *s) {
    if (!mrk_w_cf_cleanup(s)) return;
    if (!mrk_w_acl_settled(s)) { mrk_w_unknown(s, MRK_W_CUSTODY); return; }
    if (!(s->result.flags & MRK_W_STOP) && s->result.namespace_passed == 4
        && s->result.namespace_entered == 4 && s->result.namespace_returned == 4) {
        (void)mrk_w_namespace(s, 4); // Fifth check, before descriptor retirement.
    }
    if (s->result.flags & MRK_W_UNKNOWN) return;
    if (!mrk_w_acl_settled(s)) { mrk_w_unknown(s, MRK_W_CUSTODY); return; }
    if (!mrk_w_fd_cleanup(s)) return;
    if ((s->result.outcome == MRK_W_ADDED || s->result.outcome == MRK_W_FOUND)
        && !(s->result.flags & MRK_W_NAMESPACE_VERIFIED)) mrk_w_fail(s, MRK_W_SHAPE);
    // Resource settlement is not policy restoration; do not publish KNOWN yet.
    s->resources_settled = 1;
}
size_t mrk_wrapping_frame_bytes(void) { return sizeof(MRKWrappingFrame); }
void *mrk_wrapping_frame_new(void) {
    MRKWrappingFrame *s = calloc(1, sizeof(MRKWrappingFrame));
    if (s) {
        s->result.version = MRK_W_VERSION; s->result.flags = MRK_W_KNOWN;
        for (uint32_t i = 0; i < MRK_W_FDS; ++i) s->fds[i].fd = s->fds[i].consumed_number = -1;
    }
    return s;
}
void mrk_wrapping_run(void *frame, uint32_t operation, const uint8_t *vault, const uint8_t *generation,
    const uint8_t *key, MRKWrappingAdmission admission, void *context,
    MRKWrappingCleanupAdmission cleanup, void *cleanup_context, MRKWrappingResult *out) {
    if (!frame || !out) return;
    MRKWrappingFrame *s = frame;
    if (s->ran || s->consuming) { mrk_w_unknown(s, MRK_W_CUSTODY); *out = s->result; return; }
    s->ran = 1; s->result.operation = operation; s->result.phase = MRK_W_ENTRY; s->result.flags = 0;
    s->admission = admission; s->context = context;
    s->interaction.forward = mrk_w_policy_forward; s->interaction.owner = s;
    s->interaction.cleanup = cleanup; s->interaction.cleanup_context = cleanup_context;
#if defined(MRK_WRAPPING_KEYCHAIN_QUALIFICATION)
    s->interaction.fixture = s->qualification.observation.mode == MRK_W_Q_FIXTURE
        && s->qualification.observation.configured ? &s->qualification.fixture : NULL;
#endif
    int scope = mrk_w_policy_acquire(&s->interaction, &s->result.policy, MRK_P_OPERATION, operation);
    @try {
        if ((operation != MRK_W_ADD && operation != MRK_W_LOOKUP) || !mrk_w_ids(vault, generation)
            || (operation == MRK_W_ADD ? !key : key != NULL) || !admission || !context
            || !cleanup || !cleanup_context || !scope
#if defined(MRK_WRAPPING_KEYCHAIN_QUALIFICATION)
            || (s->qualification.observation.version && !s->qualification.observation.configured)
#endif
            ) {
            mrk_w_fail(s, MRK_W_INPUT);
            mrk_p_fail(&s->result.policy, MRK_P_SCOPE_FAILURE);
        } else if (mrk_w_policy_install(&s->interaction)) {
            memcpy(s->vault, vault, 16); memcpy(s->generation, generation, 16);
            if (operation == MRK_W_ADD) { memcpy(s->key, key, MRK_W_KEY); s->result.key_bytes = MRK_W_KEY; }
            mrk_w_operation(s);
        } else { mrk_w_unknown(s, MRK_W_CUSTODY); }
    } @catch (NSException *exception) {
        (void)exception;
        s->result.flags |= MRK_W_NATIVE_EXCEPTION;
        mrk_w_unknown(s, MRK_W_EXCEPTION);
    }
    @try { mrk_w_cleanup(s); }
    @catch (NSException *exception) {
        (void)exception; s->result.flags |= MRK_W_NATIVE_EXCEPTION;
        mrk_w_unknown(s, MRK_W_CUSTODY); // No retry of an interrupted cleanup.
    }
    // Ordinary cleanup's exception/UNKNOWN cannot skip independent restoration.
    if (mrk_w_policy_finish(&s->interaction, s->resources_settled && !(s->result.flags & MRK_W_UNKNOWN)))
        s->result.flags |= MRK_W_KNOWN;
    else mrk_w_unknown(s, MRK_W_CUSTODY);
    if (s->result.flags & MRK_W_KNOWN) {
        s->result.phase = MRK_W_DELIVERY;
        int deliver = mrk_w_admit(s, MRK_W_BEFORE_DELIVERY);
        if (deliver && s->result.operation == MRK_W_LOOKUP && s->result.outcome == MRK_W_FOUND
            && (s->result.flags & MRK_W_ITEM_VERIFIED) && (s->result.flags & MRK_W_NAMESPACE_VERIFIED)
            && s->result.key_bytes == MRK_W_KEY)
            s->result.flags |= MRK_W_KEY_READY;
        else mrk_w_wipe_key(s);
    }
#if defined(MRK_WRAPPING_KEYCHAIN_QUALIFICATION) || defined(MRK_WRAPPING_VAULT_HELPER)
    if (pthread_main_np() == 1 && (s->result.flags & MRK_W_UNKNOWN || s->result.policy.failed))
        mrk_w_process.poisoned = 1;
#endif
    // The retained frame never contains a dangling worker-stack callback.
    s->admission = NULL; s->context = NULL;
    s->interaction.forward = NULL; s->interaction.owner = NULL;
    s->interaction.cleanup = NULL; s->interaction.cleanup_context = NULL;
    s->result.phase = MRK_W_RETURN; s->result.run_returned = 1;
    *out = s->result;
}
#if defined(MRK_WRAPPING_KEYCHAIN_QUALIFICATION)
uint32_t mrk_wrapping_qualification_abi(void) { return 0x514b0201u; }
void mrk_wrapping_qualification_run(void *frame, uint32_t mode,
    const MRKWrappingQualificationFixture *fixture, uint32_t operation,
    const uint8_t *vault, const uint8_t *generation, const uint8_t *key,
    MRKWrappingAdmission admission, void *context, MRKWrappingCleanupAdmission cleanup,
    void *cleanup_context, MRKWrappingResult *out,
    MRKWrappingQualificationObservation *observation) {
    if (!frame || !out || !observation) return;
    MRKWrappingFrame *s = frame;
    MRKWrappingQualification *q = &s->qualification;
    if (s->ran || s->consuming || q->observation.mode) {
        mrk_w_unknown(s, MRK_W_CUSTODY); *out = s->result; *observation = q->observation; return;
    }
    q->observation.version = 1; q->observation.mode = mode;
    if ((mode == MRK_W_Q_SELECTOR || mode == MRK_W_Q_HELPERS) && !fixture && operation == MRK_W_LOOKUP) {
        q->observation.configured = 1;
    } else if (mode == MRK_W_Q_FIXTURE && fixture) {
        uint8_t token_bits = 0;
        for (unsigned i = 0; i < sizeof(fixture->token); ++i) token_bits |= fixture->token[i];
        if (fixture->version == 1 && fixture->bytes == sizeof(*fixture) && !fixture->reserved
            && fixture->root_device <= UINT32_MAX && fixture->root_inode && fixture->root_uid
            && fixture->root_mode == (uint32_t)(S_IFDIR | 0700) && token_bits) {
            q->fixture = *fixture; q->observation.configured = 1;
        }
    }
    // No replacement query or duplicated provider/cleanup path. This is the
    // production entry with one checked, cfg-only selection on the same frame.
    mrk_wrapping_run(frame, operation, vault, generation, key, admission, context, cleanup, cleanup_context, out);
    q->observation.run_returned = s->result.run_returned;
    q->observation.callbacks_cleared = s->admission == NULL && s->context == NULL
        && s->interaction.forward == NULL && s->interaction.owner == NULL
        && s->interaction.cleanup == NULL && s->interaction.cleanup_context == NULL;
    *observation = q->observation;
}
#endif
void mrk_wrapping_retain_unknown(void *frame) {
    if (!frame) return;
    MRKWrappingFrame *s = frame;
    mrk_w_unknown(s, MRK_W_CUSTODY);
    s->admission = NULL; s->context = NULL;
    s->interaction.forward = NULL; s->interaction.owner = NULL;
    s->interaction.cleanup = NULL; s->interaction.cleanup_context = NULL;
}
uint32_t mrk_wrapping_consume(void *frame, MRKWrappingConsume consume, void *context) {
    if (!frame || !consume || !context) return 0;
    MRKWrappingFrame *s = frame;
    if (s->consuming || !s->result.run_returned || s->result.operation != MRK_W_LOOKUP
        || !(s->result.flags & MRK_W_KNOWN) || !(s->result.flags & MRK_W_KEY_READY)
        || !(s->result.flags & MRK_W_NAMESPACE_VERIFIED) || !mrk_p_complete(&s->result.policy)
        || !mrk_w_policy_final_owner(&s->result.policy)
        || (s->result.flags & (MRK_W_UNKNOWN | MRK_W_STOP)) || s->result.key_bytes != MRK_W_KEY) return 0;
    s->consuming = 1;
    s->result.flags &= ~MRK_W_KEY_READY; // Spend before the single synchronous callback.
    uint32_t returned = consume(context, s->key, MRK_W_KEY);
    mrk_w_wipe_key(s);
    s->consuming = 0;
    return returned == 1 ? 1 : 0;
}
uint32_t mrk_wrapping_frame_retire(void *frame) {
    if (!frame) return 0;
#if defined(MRK_WRAPPING_VAULT_HELPER)
    // Includes Rust finish/consume/Drop callers. No implicit late native free;
    //a refusal leaves the original allocation retained and never refunds it.
    if (mrk_vault_control_admit(1) != MRK_W_CONTINUE) return 0;
#endif
    MRKWrappingFrame *s = frame;
    // No Security/ACL call, CF release, descriptor close or retry in Drop/retire.
    if (s->consuming || !(s->result.flags & MRK_W_KNOWN) || (s->result.flags & MRK_W_UNKNOWN)
        || s->admission || s->context || s->interaction.forward || s->interaction.owner
        || s->interaction.cleanup || s->interaction.cleanup_context || s->interaction.acquired
        || (s->ran && (!mrk_p_complete(&s->result.policy) || !mrk_w_policy_final_owner(&s->result.policy)))) return 0;
    for (uint32_t i = 0; i < s->result.slot_count; ++i)
        if (s->owned[i].value || s->result.references[i].nonnull_returned != s->result.references[i].release_returned) return 0;
    if (!mrk_w_acl_settled(s)) return 0;
    for (uint32_t i = 0; i < s->result.descriptor_count; ++i) {
        MRKWrappingDescriptor *r = &s->result.descriptors[i];
        if (s->fds[i].fd >= 0 || r->open_entered != r->open_returned
            || r->acquired != r->closed || r->close_entered != r->close_returned) return 0;
    }
    mrk_w_wipe(s, sizeof(*s));
    free(s);
#if defined(MRK_WRAPPING_VAULT_HELPER)
    // Report the actual returned free truthfully, but latch any elapsed original
    //cutoff/clock error before a later helper step or candidate can be accepted.
    (void)mrk_vault_control_admit(1);
#endif
    return 1; // The adapter-owned allocation's original free actually returned.
}

#if defined(MRK_WRAPPING_KEYCHAIN_QUALIFICATION)
#include "wrapping_keychain_fixture.m"
#endif
