// Shared scalar decision logic for PRIVATE process-scoped Keychain qualification.
// No process state, clock, SDK provider, filesystem or executable selection lives
// here. The one process/SDK binding lives in wrapping_keychain.m's existing TU.
#ifndef MRK_WRAPPING_INTERACTION_POLICY_H
#define MRK_WRAPPING_INTERACTION_POLICY_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define MRK_P_CALLS 5u
enum { MRK_P_OPERATION = 1, MRK_P_FIXTURE = 2, MRK_P_NAMESPACE_CHILD = 3 };
enum { MRK_P_ORIGINAL = 0, MRK_P_DISABLE, MRK_P_INSTALLED, MRK_P_RESTORE, MRK_P_RESTORED };
enum { MRK_P_SCOPE_FAILURE = 6, MRK_P_CALLBACK_FAILURE = 7, MRK_P_CHILD_FAILURE = 8 };
typedef struct {
    uint32_t entered, returned, refused, exception;
    int32_t status;
    uint32_t value, value_valid;
} MRKInteractionCall;
typedef struct {
    uint32_t version, kind, role, entered, scope_admitted;
    uint32_t original_valid, original_value, installed, restore_due, restored;
    uint32_t failed, first_failure, finished, callback_refused, cleanup_refused;
    uint32_t namespace_entered, namespace_returned, namespace_completed;
    MRKInteractionCall calls[MRK_P_CALLS];
} MRKInteractionPolicy;
_Static_assert(sizeof(MRKInteractionCall) == 28, "five fixed policy originals");
_Static_assert(sizeof(MRKInteractionPolicy) == 212, "fixed process policy ABI v1");

static inline int mrk_p_scope_permitted(uint32_t role, uint32_t kind, uint32_t operation,
    int main_thread, int pid_matched, int already_active, int poisoned) {
    return main_thread && pid_matched && !already_active && !poisoned
        && ((kind == MRK_P_OPERATION && (operation == 1 || operation == 2)
                && (role == 1 || role == 3 || (role == 2 && operation == 2)))
            || (kind == MRK_P_FIXTURE && operation == 0 && role == 1));
}
static inline int mrk_p_namespace_permitted(uint32_t role, int main_thread, int pid_matched,
    int installed, int add_after_call, int binding_matched, int already_started, int poisoned) {
    return role == 1 && main_thread && pid_matched && installed && add_after_call
        && binding_matched && !already_started && !poisoned;
}
static inline void mrk_p_fail(MRKInteractionPolicy *p, uint32_t first) {
    p->failed = 1;
    if (!p->first_failure) p->first_failure = first;
}
static inline void mrk_p_init(MRKInteractionPolicy *p, uint32_t kind, uint32_t role) {
    memset(p, 0, sizeof(*p));
    p->version = 1; p->kind = kind; p->role = role; p->entered = 1;
}
static inline int mrk_p_spent(const MRKInteractionCall *c) {
    return c->entered || c->refused;
}
static inline int mrk_p_good(const MRKInteractionCall *c) {
    return c->entered == 1 && c->returned == 1 && !c->refused && !c->exception
        && c->status == 0 && c->value_valid == 1;
}
static inline int mrk_p_start(MRKInteractionPolicy *p, uint32_t slot, uint32_t admission) {
    if (p->finished || !p->scope_admitted || p->kind == MRK_P_NAMESPACE_CHILD || slot >= MRK_P_CALLS)
        return 0;
    MRKInteractionCall *c = &p->calls[slot];
    if (mrk_p_spent(c)) { mrk_p_fail(p, slot + 1); return 0; } // No retry, even after refusal.
    int ready = slot == MRK_P_ORIGINAL
        || (slot == MRK_P_DISABLE && mrk_p_good(&p->calls[MRK_P_ORIGINAL]) && p->original_valid)
        || (slot == MRK_P_INSTALLED && mrk_p_good(&p->calls[MRK_P_DISABLE]))
        || (slot == MRK_P_RESTORE && p->restore_due && p->original_valid)
        || (slot == MRK_P_RESTORED && p->restore_due && p->original_valid && mrk_p_spent(&p->calls[MRK_P_RESTORE]));
    if (!ready || (slot < MRK_P_RESTORE && p->failed) || admission != 1) {
        c->refused = 1;
        if (slot >= MRK_P_RESTORE) p->cleanup_refused = 1; else p->callback_refused = 1;
        mrk_p_fail(p, slot + 1); return 0;
    }
    c->entered = 1;
    if (slot == MRK_P_DISABLE || slot == MRK_P_RESTORE) {
        c->value = slot == MRK_P_DISABLE ? 0 : p->original_value;
        c->value_valid = 1; // Exact setter REQUEST, not a getter observation.
    } else c->value = 255; // Getter sentinel is never a known Boolean.
    if (slot == MRK_P_DISABLE) p->restore_due = 1; // BEFORE a possibly effective setter.
    return 1;
}
static inline void mrk_p_return(MRKInteractionPolicy *p, uint32_t slot, int32_t status, uint32_t value) {
    if (slot >= MRK_P_CALLS) { mrk_p_fail(p, MRK_P_SCOPE_FAILURE); return; }
    MRKInteractionCall *c = &p->calls[slot];
    if (!c->entered || c->returned || c->exception) { mrk_p_fail(p, slot + 1); return; }
    c->status = status; c->returned = 1;
    if (slot != MRK_P_DISABLE && slot != MRK_P_RESTORE) {
        c->value = value; c->value_valid = value <= 1;
    }
    if (status != 0 || !c->value_valid) mrk_p_fail(p, slot + 1);
    if (slot == MRK_P_ORIGINAL && mrk_p_good(c)) {
        p->original_valid = 1; p->original_value = c->value;
    }
    if (slot == MRK_P_INSTALLED) {
        p->installed = mrk_p_good(c) && c->value == 0;
        if (!p->installed) mrk_p_fail(p, slot + 1);
    }
    if (slot == MRK_P_RESTORED) {
        p->restored = mrk_p_good(c) && p->original_valid && c->value == p->original_value;
        if (!p->restored) mrk_p_fail(p, slot + 1);
    }
}
static inline void mrk_p_exception(MRKInteractionPolicy *p, uint32_t slot) {
    if (slot >= MRK_P_CALLS) { mrk_p_fail(p, MRK_P_SCOPE_FAILURE); return; }
    // The SDK call did not return. An exception never synthesizes an OSStatus.
    if (p->calls[slot].entered && !p->calls[slot].returned) p->calls[slot].exception = 1;
    mrk_p_fail(p, slot + 1);
}
static inline void mrk_p_forward_refused(MRKInteractionPolicy *p) {
    p->callback_refused = 1;
    mrk_p_fail(p, MRK_P_CALLBACK_FAILURE);
}
static inline int mrk_p_complete(const MRKInteractionPolicy *p) {
    if (!p->finished || !p->scope_admitted || p->failed || p->kind == MRK_P_NAMESPACE_CHILD
        || !p->original_valid || !p->installed || !p->restore_due || !p->restored
        || p->namespace_entered != p->namespace_returned || p->namespace_entered != p->namespace_completed)
        return 0;
    for (uint32_t i = 0; i < MRK_P_CALLS; ++i) if (!mrk_p_good(&p->calls[i])) return 0;
    return p->calls[MRK_P_DISABLE].value == 0 && p->calls[MRK_P_INSTALLED].value == 0
        && p->calls[MRK_P_RESTORE].value == p->original_value
        && p->calls[MRK_P_RESTORED].value == p->original_value;
}
static inline int mrk_p_finality(const MRKInteractionPolicy *p, int resources_settled) {
    return resources_settled && mrk_p_complete(p);
}
static inline int mrk_p_namespace_complete(const MRKInteractionPolicy *p) {
    return p->kind == MRK_P_NAMESPACE_CHILD && p->scope_admitted == 1 && p->role == 1
        && p->finished == 1 && !p->failed && p->namespace_entered == 1
        && p->namespace_returned == 1 && p->namespace_completed == 1;
}
static inline int mrk_p_valid(const MRKInteractionPolicy *p, int final) {
    static const MRKInteractionPolicy empty = {0};
    if (!p->kind) return memcmp(p, &empty, sizeof(*p)) == 0;
    if (p->version != 1 || p->kind > MRK_P_NAMESPACE_CHILD || p->role > 3 || p->entered != 1
        || p->scope_admitted > 1 || (p->scope_admitted && (p->role == 0 || (p->kind != MRK_P_OPERATION && p->role != 1)))
        || p->original_valid > 1 || p->original_value > 1 || p->installed > 1 || p->restore_due > 1 || p->restored > 1
        || p->failed > 1 || p->first_failure > MRK_P_CHILD_FAILURE || p->finished > 1
        || p->callback_refused > 1 || p->cleanup_refused > 1
        || p->namespace_entered > 1 || p->namespace_returned > p->namespace_entered
        || p->namespace_completed > p->namespace_returned
        || (p->failed != (p->first_failure != 0)) || ((p->callback_refused || p->cleanup_refused) && !p->failed)
        || (final && !p->finished)) return 0;
    for (uint32_t i = 0; i < MRK_P_CALLS; ++i) {
        const MRKInteractionCall *c = &p->calls[i];
        static const MRKInteractionCall unused = {0};
        if (!mrk_p_spent(c)) {
            if (memcmp(c, &unused, sizeof(*c))) return 0;
            continue;
        }
        if (c->entered > 1 || c->returned > c->entered || c->refused > 1 || c->exception > c->entered
            || c->entered + c->refused != 1 || c->returned + c->exception > 1 || c->value_valid > 1
            || c->value > 255 || (!c->returned && c->status) || (c->refused && (c->value || c->value_valid))
            || ((c->refused || c->exception || (c->returned && (c->status || !c->value_valid))) && !p->failed))
            return 0;
        if (c->entered && (i == MRK_P_DISABLE || i == MRK_P_RESTORE)) {
            if (!c->value_valid || c->value != (i == MRK_P_DISABLE ? 0 : p->original_value)) return 0;
        } else if (c->returned && c->value_valid != (c->value <= 1)) return 0;
        if (i == MRK_P_DISABLE && c->entered && !mrk_p_good(&p->calls[MRK_P_ORIGINAL])) return 0;
        if (i == MRK_P_INSTALLED && c->entered && !mrk_p_good(&p->calls[MRK_P_DISABLE])) return 0;
        if (i >= MRK_P_RESTORE && (!p->restore_due || !p->original_valid)) return 0;
        if (i == MRK_P_RESTORED && !mrk_p_spent(&p->calls[MRK_P_RESTORE])) return 0;
    }
    if (p->kind == MRK_P_NAMESPACE_CHILD) {
        if (memcmp(p->calls, empty.calls, sizeof(p->calls)) || p->original_valid || p->original_value
            || p->installed || p->restore_due || p->restored || p->callback_refused || p->cleanup_refused)
            return 0;
        return !p->finished || p->failed || mrk_p_namespace_complete(p);
    }
    if (p->original_valid != (uint32_t)mrk_p_good(&p->calls[MRK_P_ORIGINAL])
        || p->original_value != (p->original_valid ? p->calls[MRK_P_ORIGINAL].value : 0)
        || p->restore_due != p->calls[MRK_P_DISABLE].entered
        || p->installed != (uint32_t)(mrk_p_good(&p->calls[MRK_P_INSTALLED]) && p->calls[MRK_P_INSTALLED].value == 0)
        || p->restored != (uint32_t)(mrk_p_good(&p->calls[MRK_P_RESTORED]) && p->original_valid
            && p->calls[MRK_P_RESTORED].value == p->original_value))
        return 0;
    if (!p->scope_admitted && (!p->failed || mrk_p_spent(&p->calls[0]) || p->namespace_entered)) return 0;
    if (p->finished && !p->failed && !mrk_p_complete(p)) return 0;
    return 1;
}

// Platform-free scalar regression entry for THIS shared logic; no SDK
// substitution, clock, child owner or production activation path. Root's existing
// reviewed execution route is responsible for compiling/running this test.
#if defined(MRK_WRAPPING_POLICY_SCALAR_TEST)
#include <assert.h>
static void mrk_p_test_get(MRKInteractionPolicy *p, uint32_t slot, int32_t status, uint32_t value) {
    assert(mrk_p_start(p, slot, 1)); mrk_p_return(p, slot, status, value);
}
static MRKInteractionPolicy mrk_p_test_installed(uint32_t original) {
    MRKInteractionPolicy p; mrk_p_init(&p, MRK_P_OPERATION, 1); p.scope_admitted = 1;
    mrk_p_test_get(&p, 0, 0, original); mrk_p_test_get(&p, 1, 0, 0); mrk_p_test_get(&p, 2, 0, 0);
    assert(p.installed && p.restore_due && !p.restored && !mrk_p_complete(&p));
    return p;
}
static void mrk_p_test_restore(MRKInteractionPolicy *p, int32_t setter, uint32_t observed) {
    mrk_p_test_get(p, 3, setter, p->original_value); mrk_p_test_get(p, 4, 0, observed); p->finished = 1;
}
int main(void) {
    assert(mrk_p_scope_permitted(1, MRK_P_OPERATION, 1, 1, 1, 0, 0));
    assert(mrk_p_scope_permitted(2, MRK_P_OPERATION, 2, 1, 1, 0, 0));
    assert(mrk_p_scope_permitted(3, MRK_P_OPERATION, 1, 1, 1, 0, 0));
    assert(mrk_p_scope_permitted(3, MRK_P_OPERATION, 2, 1, 1, 0, 0));
    assert(!mrk_p_scope_permitted(3, MRK_P_FIXTURE, 0, 1, 1, 0, 0));
    assert(!mrk_p_namespace_permitted(3, 1, 1, 1, 1, 1, 0, 0));
    assert(mrk_p_scope_permitted(1, MRK_P_FIXTURE, 0, 1, 1, 0, 0));
    assert(!mrk_p_scope_permitted(0, MRK_P_OPERATION, 1, 1, 1, 0, 0));
    assert(!mrk_p_scope_permitted(2, MRK_P_OPERATION, 1, 1, 1, 0, 0));
    assert(!mrk_p_scope_permitted(2, MRK_P_FIXTURE, 0, 1, 1, 0, 0));
    assert(!mrk_p_scope_permitted(1, MRK_P_OPERATION, 1, 0, 1, 0, 0));
    assert(!mrk_p_scope_permitted(1, MRK_P_OPERATION, 1, 1, 0, 0, 0));
    assert(!mrk_p_scope_permitted(1, MRK_P_OPERATION, 1, 1, 1, 1, 0));
    assert(!mrk_p_scope_permitted(1, MRK_P_OPERATION, 1, 1, 1, 0, 1));
    assert(mrk_p_namespace_permitted(1, 1, 1, 1, 1, 1, 0, 0));
    assert(!mrk_p_namespace_permitted(2, 1, 1, 1, 1, 1, 0, 0));
    assert(!mrk_p_namespace_permitted(1, 0, 1, 1, 1, 1, 0, 0));
    assert(!mrk_p_namespace_permitted(1, 1, 0, 1, 1, 1, 0, 0));
    assert(!mrk_p_namespace_permitted(1, 1, 1, 0, 1, 1, 0, 0));
    assert(!mrk_p_namespace_permitted(1, 1, 1, 1, 0, 1, 0, 0));
    assert(!mrk_p_namespace_permitted(1, 1, 1, 1, 1, 0, 0, 0));
    assert(!mrk_p_namespace_permitted(1, 1, 1, 1, 1, 1, 1, 0));
    assert(!mrk_p_namespace_permitted(1, 1, 1, 1, 1, 1, 0, 1));
    for (uint32_t original = 0; original <= 1; ++original) {
        MRKInteractionPolicy p = mrk_p_test_installed(original);
        mrk_p_test_restore(&p, 0, original); assert(mrk_p_valid(&p, 1) && mrk_p_complete(&p));
        assert(mrk_p_finality(&p, 1) && !mrk_p_finality(&p, 0));
        MRKInteractionPolicy bad = p; bad.calls[3].value ^= 1; assert(!mrk_p_valid(&bad, 1));
        bad = p; bad.calls[4].returned = 0; assert(!mrk_p_valid(&bad, 1));
        bad = p; bad.finished = 0; assert(!mrk_p_complete(&bad));
    }
    for (uint32_t scenario = 0; scenario < 3; ++scenario) {
        MRKInteractionPolicy p; mrk_p_init(&p, MRK_P_OPERATION, 1); p.scope_admitted = 1;
        if (scenario == 0) mrk_p_test_get(&p, 0, -1, 255);
        if (scenario == 1) mrk_p_test_get(&p, 0, 0, 255);
        if (scenario == 2) { assert(mrk_p_start(&p, 0, 1)); mrk_p_exception(&p, 0); }
        p.finished = 1; assert(mrk_p_valid(&p, 1) && !p.restore_due && !mrk_p_complete(&p));
    }
    for (uint32_t scenario = 0; scenario < 2; ++scenario) {
        MRKInteractionPolicy p; mrk_p_init(&p, MRK_P_OPERATION, 1); p.scope_admitted = 1;
        mrk_p_test_get(&p, 0, 0, 1); mrk_p_test_get(&p, 1, 0, 0);
        mrk_p_test_get(&p, 2, scenario ? 0 : -1, scenario ? 1 : 0);
        assert(!p.installed && p.restore_due); mrk_p_test_restore(&p, 0, 1);
        assert(mrk_p_valid(&p, 1) && p.restored && p.first_failure == 3 && !mrk_p_complete(&p));
    }
    MRKInteractionPolicy p; mrk_p_init(&p, MRK_P_OPERATION, 1); p.scope_admitted = 1;
    assert(!mrk_p_start(&p, 0, 2)); p.finished = 1;
    assert(mrk_p_valid(&p, 1) && !p.restore_due && !mrk_p_complete(&p));
    mrk_p_init(&p, MRK_P_OPERATION, 1); p.scope_admitted = 1;
    mrk_p_test_get(&p, 0, 0, 0); assert(mrk_p_start(&p, 1, 1)); mrk_p_exception(&p, 1);
    mrk_p_test_restore(&p, 0, 0);
    assert(mrk_p_valid(&p, 1) && p.restored && !p.calls[1].returned && p.first_failure == 2 && !mrk_p_complete(&p));
    mrk_p_init(&p, MRK_P_OPERATION, 1); p.scope_admitted = 1;
    mrk_p_test_get(&p, 0, 0, 1); assert(mrk_p_start(&p, 1, 1));
    assert(p.restore_due); mrk_p_return(&p, 1, -1, 0); mrk_p_test_restore(&p, 0, 1);
    assert(mrk_p_valid(&p, 1) && p.restored && p.first_failure == 2 && !mrk_p_complete(&p));
    p = mrk_p_test_installed(1); mrk_p_test_restore(&p, -1, 1);
    assert(mrk_p_valid(&p, 1) && p.restored && p.failed && !mrk_p_complete(&p));
    p = mrk_p_test_installed(1); mrk_p_test_restore(&p, 0, 0);
    assert(mrk_p_valid(&p, 1) && !p.restored && !mrk_p_complete(&p));
    p = mrk_p_test_installed(1); mrk_p_forward_refused(&p); mrk_p_test_restore(&p, 0, 1);
    assert(mrk_p_valid(&p, 1) && p.restored && p.first_failure == 7 && !mrk_p_complete(&p));
    p = mrk_p_test_installed(1); assert(!mrk_p_start(&p, 3, 2)); assert(!mrk_p_start(&p, 4, 2)); p.finished = 1;
    assert(mrk_p_valid(&p, 1) && p.restore_due && !p.restored && p.cleanup_refused && !mrk_p_complete(&p));
    p = mrk_p_test_installed(1); assert(mrk_p_start(&p, 3, 1)); mrk_p_exception(&p, 3);
    mrk_p_test_get(&p, 4, 0, 1); p.finished = 1;
    assert(mrk_p_valid(&p, 1) && p.restored && !p.calls[3].returned && !mrk_p_complete(&p));
    assert(!mrk_p_start(&p, 3, 1)); // The first cleanup attempt remains spent.
    p = mrk_p_test_installed(1); p.namespace_entered = 1; p.namespace_returned = 1; p.namespace_completed = 1;
    mrk_p_test_restore(&p, -1, 1); assert(mrk_p_valid(&p, 1) && !mrk_p_complete(&p));
    mrk_p_init(&p, MRK_P_NAMESPACE_CHILD, 1); p.scope_admitted = 1;
    p.namespace_entered = p.namespace_returned = p.namespace_completed = p.finished = 1;
    assert(mrk_p_valid(&p, 1) && mrk_p_namespace_complete(&p) && !mrk_p_complete(&p));
    p.restored = 1; assert(!mrk_p_valid(&p, 1));
    return 0;
}
#endif
#endif
