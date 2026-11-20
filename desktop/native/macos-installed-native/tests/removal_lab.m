// Removal lab translation unit (cargo feature "removal-lab" only; build.rs
// compiles this file INSTEAD of src/removal_coordinator.m, never alongside it,
// and lib.rs refuses the feature together with any shipping role).
//
// The production coordinator is compiled verbatim below. The lab adds exactly
// one entry: it starts a fresh peer at stage 1 (after SOURCE) and records the
// same borrowed-original baseline p_source records. SOURCE itself (producer
// signer, static code, own dynamic code) is identity-bound: only the signed,
// installed product can pass it, so it is validated end to end only. Every
// later checkpoint still runs the production p_borrowed_post exact rechecks.
#include "../src/removal_coordinator.m"

int mrk_removal_lab_enter_open(void *raw) {
    MRKRemovalPeer *b = raw;
    if (!p_original(b) || b->entered || b->report.stage != 0 || b->report.calls || b->report.failed
        || b->report.unknown || b->sources_ready) return 0;
    for (unsigned i = 0; i < MRK_REMOVE_PEER_BORROWED; i++) {
        int fd = b->input.borrowed[i];
        if (fd < 3 || fstat(fd, &b->borrowed[i]) != 0 || fcntl(fd, F_GETFD) != FD_CLOEXEC) return 0;
        for (unsigned j = 0; j < i; j++) if (fd == b->input.borrowed[j]) return 0;
    }
    b->sources_ready = 1;
    b->report.request_directory = p_stat_data(&b->borrowed[18]);
    b->report.stage = 1;
    return 1;
}
