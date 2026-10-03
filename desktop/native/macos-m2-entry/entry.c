/* One fixed exec. Pure C/libSystem before SH; no AppKit/Foundation/payload load. */
#include "fixture.h"
extern char **environ;

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1 || !mrk_account()) return 64;
    int root = mrk_root();
    if (root < 0) return 65;
    mrk_gate_open_outcome gate_outcome;
    int gate = mrk_open_gate_captured(root, &gate_outcome);
    if (gate < 0) {
        /* The original refusal is already irrevocable. Use only this admitted
           root, never change the selected return or continue after logging. */
        const int selected_return = 66;
        char open_error[16], record[768];
        int e = gate_outcome.allocated_fd < 0
            ? snprintf(open_error, sizeof(open_error), "%d", gate_outcome.open_errno)
            : snprintf(open_error, sizeof(open_error), "null");
        int n = e > 0 && (size_t)e < sizeof(open_error) ? snprintf(record, sizeof(record),
            "{\"schemaVersion\":1,\"source\":\"%s\",\"case\":\"ls-full-payload\","
            "\"phase\":\"entry-gate-admission\",\"selectedReturnCode\":66,"
            "\"originalRootDescriptor\":%d,\"gateOpenDescriptor\":%d,\"gateOpenErrno\":%s,"
            "\"gateMatchAccepted\":%s,\"rejectedGateCloseReturned\":%s}\n",
            MRK_SOURCE, root, gate_outcome.allocated_fd, open_error,
            gate_outcome.match_accepted < 0 ? "null" : gate_outcome.match_accepted ? "true" : "false",
            gate_outcome.rejected_close_returned < 0 ? "null" : gate_outcome.rejected_close_returned ? "true" : "false") : -1;
        if (n > 0 && (size_t)n < sizeof(record))
            (void)mrk_record(root, "entry-gate-refused.json", record);
        /* A readable diagnostic is not a writer-fsync or actual exit receipt. */
        return selected_return;
    }
    if (flock(gate, LOCK_SH | LOCK_NB)) {
        int busy = errno == EWOULDBLOCK;
        const char *record = "{\"schemaVersion\":1,\"source\":\"" MRK_SOURCE
            "\",\"refusedBeforeExec\":true,\"exclusiveWouldBlock\":true}\n";
        int written = busy && mrk_record(root, "entry-busy.json", record);
        int gate_closed = mrk_close(&gate), root_closed = mrk_close(&root);
        return written && gate_closed && root_closed ? 75 : 67;
    }
    if (fcntl(gate, F_GETFD) != FD_CLOEXEC || fcntl(gate, F_SETFD, 0)
        || fcntl(gate, F_GETFD) != 0 || !mrk_gate_matches(root, gate)) _exit(68);
    char descriptor[16], original_pid[16];
    int a = snprintf(descriptor, sizeof(descriptor), "%d", gate);
    int b = snprintf(original_pid, sizeof(original_pid), "%d", getpid());
    if (a < 1 || (size_t)a >= sizeof(descriptor) || b < 1 || (size_t)b >= sizeof(original_pid)) _exit(69);
    if (!mrk_close(&root)) _exit(70);
    char *const next[] = {MRK_PAYLOAD_EXE, descriptor, original_pid, NULL};
    execve(MRK_PAYLOAD_EXE, next, environ);
    /* Real exec failure: keep the original SH open until kernel process exit. */
    int exec_error = errno;
    root = mrk_root();
    int held = root >= 0 && mrk_gate_matches(root, gate) && fcntl(gate, F_GETFD) == 0
        && mrk_exclusive_probe(root) == 0;
    char record[512];
    int n = snprintf(record, sizeof(record),
        "{\"schemaVersion\":1,\"source\":\"%s\",\"case\":\"ls-full-payload\",\"phase\":\"entry-exec-returned\","
        "\"execErrno\":%d,\"execReturnedENOENT\":%s,\"originalGateStillHeld\":%s}\n",
        MRK_SOURCE, exec_error, exec_error == ENOENT ? "true" : "false", held ? "true" : "false");
    int written = n > 0 && (size_t)n < sizeof(record) && root >= 0
        && mrk_record(root, "entry-failed-exec.json", record);
    int root_closed = root >= 0 && mrk_close(&root);
    _exit(exec_error == ENOENT && held && written && root_closed ? 76 : 71);
    /* No LOCK_UN and no early close(gate), including the failure path. */
}
