"""#47 regression: the production drain-tail pipe predicate on real Darwin pipes.

XNU's pipe_stat reports st_uid/st_gid of the *calling* credential. The app is
unprivileged, so the former `st_uid==0` owner predicate refused every genuine
root-helper tail with EPROTO at the Receive phase, leaving Prepare-and-quit
Unknown with the helper still running. This test compiles the exact production
function text and checks it accepts a genuine non-blocking close-on-exec read end
and refuses every changed property.
"""
from pathlib import Path
import os
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'desktop/native/macos-installed-native/src/android_registration.m'


def production_predicate() -> str:
    text = SOURCE.read_text()
    start = text.index('static int maintenance_pipe_same(mrk_android_client *c,int fd,const struct stat *before) {')
    end = text.index('\n}\n', start) + 3
    return text[start:end]


HARNESS = r"""
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
typedef struct { int unused; } mrk_android_client;
PREDICATE
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed line %d: %s\n", __LINE__, #x); return 1; } } while (0)
static int prepared(int fds[2]) {
    if (pipe(fds)) return 0;
    if (fds[0] < 3) { int moved = fcntl(fds[0], F_DUPFD, 3); close(fds[0]); fds[0] = moved; }
    return fds[0] >= 3 && fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0 && fcntl(fds[0], F_SETFD, FD_CLOEXEC) == 0;
}
int main(void) {
    mrk_android_client c = {0};
    int fds[2], other[2];
    CHECK(prepared(fds) && prepared(other));
    struct stat identity, foreign;
    CHECK(fstat(fds[0], &identity) == 0 && fstat(other[0], &foreign) == 0);
    /* Darwin documents the caller projection for anonymous pipes. */
    CHECK(S_ISFIFO(identity.st_mode) && identity.st_uid == geteuid() && identity.st_gid == getegid());
    CHECK(maintenance_pipe_same(&c, fds[0], &identity));
    int negatives = 0;
    /* A different pipe (same flags) is not the original identity. */
    CHECK(!maintenance_pipe_same(&c, other[0], &identity)); negatives++;
    CHECK(!maintenance_pipe_same(&c, fds[0], &foreign)); negatives++;
    /* Write end, blocking read end, missing close-on-exec, appended flags. */
    CHECK(!maintenance_pipe_same(&c, fds[1], &identity)); negatives++;
    CHECK(fcntl(fds[0], F_SETFL, 0) == 0); CHECK(!maintenance_pipe_same(&c, fds[0], &identity)); negatives++;
    CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0); CHECK(maintenance_pipe_same(&c, fds[0], &identity));
    CHECK(fcntl(fds[0], F_SETFD, 0) == 0); CHECK(!maintenance_pipe_same(&c, fds[0], &identity)); negatives++;
    CHECK(fcntl(fds[0], F_SETFD, FD_CLOEXEC) == 0); CHECK(maintenance_pipe_same(&c, fds[0], &identity));
    CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK | O_ASYNC) == 0 || 1);
    if (fcntl(fds[0], F_GETFL) & O_ASYNC) { CHECK(!maintenance_pipe_same(&c, fds[0], &identity)); negatives++; }
    CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
    /* A regular file opened read-only/non-blocking is not a FIFO. */
    char path[] = "/tmp/mrk-pipe-XXXXXX"; int file = mkstemp(path); CHECK(file >= 0); unlink(path);
    int ro = open("/dev/null", O_RDONLY | O_NONBLOCK | O_CLOEXEC); CHECK(ro >= 3);
    struct stat devnull; CHECK(fstat(ro, &devnull) == 0);
    CHECK(!maintenance_pipe_same(&c, ro, &devnull)); negatives++;
    /* Descriptors below 3 are refused even if otherwise valid. */
    CHECK(!maintenance_pipe_same(&c, 0, &identity)); negatives++;
    close(file); close(ro);
    /* The former uid-0 owner predicate is unsatisfiable for a non-root caller. */
    const int former_owner_holds = identity.st_uid == 0;
    printf("{\"genuineAccepted\":true,\"negativeCases\":%d,\"callerUid\":%u,\"formerOwnerPredicateHolds\":%s}\n",
        negatives, (unsigned)identity.st_uid, former_owner_holds ? "true" : "false");
    return 0;
}
"""


@unittest.skipUnless(sys.platform == 'darwin', 'Darwin pipe semantics')
class MaintenancePipeTests(unittest.TestCase):
    def test_source_has_no_root_owner_pipe_predicate(self):
        predicate = production_predicate()
        self.assertNotIn('st_uid==0', predicate)
        self.assertIn('now.st_uid==geteuid()', predicate)
        self.assertIn('now.st_gid==getegid()', predicate)
        # Every original identity field is still compared.
        for field in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_flags'):
            self.assertRegex(predicate, rf'now\.{field}==before->{field}')
        self.assertIn('fcntl(fd,F_GETFD)==FD_CLOEXEC', predicate)
        self.assertIn('S_ISFIFO(now.st_mode)', predicate)

    def test_real_pipe_predicate(self):
        code = HARNESS.replace('PREDICATE', production_predicate())
        with tempfile.TemporaryDirectory(prefix='mrk-pipe-') as directory:
            source, binary = Path(directory) / 'pipe.c', Path(directory) / 'pipe'
            source.write_text(code)
            compiled = subprocess.run(['/usr/bin/clang', '-std=c11', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(binary)],
                                      capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertRegex(result.stdout, r'"negativeCases":(7|8)')
            if os.geteuid() != 0:
                self.assertIn('"formerOwnerPredicateHolds":false', result.stdout)


if __name__ == '__main__':
    unittest.main()
