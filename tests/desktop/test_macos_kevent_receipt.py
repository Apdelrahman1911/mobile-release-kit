"""Real Darwin receipts and exit events through both production receipt predicates."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]

def condition(text, marker):
    start = text.index('(', text.index(marker))
    end, depth = start + 1, 1
    while depth:
        depth += (text[end] == '(') - (text[end] == ')')
        end += 1
    return text[start + 1:end - 1]

NATIVE = r"""
#include <sys/event.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <signal.h>
struct Client {pid_t peer_pid;};
struct Peer {struct {uintptr_t peer_pid;} report;};
static int app(int count, struct kevent receipt, struct kevent change, struct Client *c) {return !(APP_CONDITION);}
static int remover(int n, struct kevent receipt, struct kevent change, struct Peer *b) {return !(REMOVER_CONDITION);}
static int app_exit(int count,struct kevent event,struct Client *c){const uint16_t allowed=APP_EXIT_ALLOWED;return !(APP_EXIT_CONDITION);}
static int remover_exit(int n,struct kevent event,struct Peer *b){const uint16_t allowed=REMOVAL_EXIT_ALLOWED;return !(REMOVAL_EXIT_CONDITION);}
#define CHECK(x) do {if(!(x)){fprintf(stderr,"failed line %d: %s\n",__LINE__,#x);return 1;}}while(0)
int main(int argc,char **argv){
 CHECK(argc==1);(void)argv;pid_t target=getppid();CHECK(target>1);
 struct Client client={target};struct Peer peer={{target}};
 for(int role=0;role<2;role++){
  int fd=kqueue();CHECK(fd>=3);CHECK(fcntl(fd,F_SETFD,FD_CLOEXEC)==0);
  struct kevent change,receipt;struct timespec zero={0,0};
  EV_SET(&change,(uintptr_t)target,EVFILT_PROC,EV_ADD|EV_ENABLE|EV_RECEIPT|(role?0:EV_ONESHOT),NOTE_EXIT,0,role?(void*)&peer:NULL);
  int n=kevent(fd,&change,1,&receipt,1,&zero);CHECK(n==1);
  int accepted=role?remover(n,receipt,change,&peer):app(n,receipt,change,&client);
  CHECK(receipt.data==0);CHECK(accepted);
  struct kevent bad=receipt;bad.data=EPERM;CHECK(!(role?remover(n,bad,change,&peer):app(n,bad,change,&client)));
  bad=receipt;bad.flags&=~EV_ERROR;CHECK(!(role?remover(n,bad,change,&peer):app(n,bad,change,&client)));
  bad=receipt;bad.flags|=EV_EOF;CHECK(!(role?remover(n,bad,change,&peer):app(n,bad,change,&client)));
  bad=receipt;bad.ident++;CHECK(!(role?remover(n,bad,change,&peer):app(n,bad,change,&client)));
  bad=receipt;bad.filter=EVFILT_READ;CHECK(!(role?remover(n,bad,change,&peer):app(n,bad,change,&client)));
  bad=receipt;bad.udata=role?NULL:(void*)&peer;CHECK(!(role?remover(n,bad,change,&peer):app(n,bad,change,&client)));
  CHECK(!(role?remover(0,receipt,change,&peer):app(0,receipt,change,&client)));
  struct kevent pending;CHECK(kevent(fd,NULL,0,&pending,1,&zero)==0);
  CHECK(close(fd)==0);
  printf("{\"role\":\"%s\",\"receiptFlags\":%u,\"data\":%ld,\"fixedAccepted\":true,\"negativeCases\":7,\"noExitObserved\":true,\"watcherClosed\":true}\n",role?"remover":"app",receipt.flags,(long)receipt.data);
 }
 for(int role=0;role<2;role++){
  int barrier[2];CHECK(pipe(barrier)==0);pid_t child=fork();CHECK(child>=0);
  if(child==0){close(barrier[1]);char v;(void)read(barrier[0],&v,1);_exit(0);}
  close(barrier[0]);int fd=kqueue();CHECK(fd>=3);
  struct Client c={child};struct Peer b={{(uintptr_t)child}};struct kevent change,receipt,event;struct timespec zero={0,0},limit={3,0};
  EV_SET(&change,(uintptr_t)child,EVFILT_PROC,EV_ADD|EV_ENABLE|EV_RECEIPT|(role?0:EV_ONESHOT),NOTE_EXIT,0,role?(void*)&b:NULL);
  int n=kevent(fd,&change,1,&receipt,1,&zero);
  if(!(role?remover(n,receipt,change,&b):app(n,receipt,change,&c))){close(barrier[1]);waitpid(child,NULL,0);CHECK(0);}
  CHECK(kevent(fd,NULL,0,&event,1,&zero)==0);close(barrier[1]);
  n=kevent(fd,NULL,0,&event,1,&limit);int status=0;CHECK(waitpid(child,&status,0)==child);CHECK(WIFEXITED(status)&&WEXITSTATUS(status)==0);
  CHECK(n==1&&event.ident==(uintptr_t)child&&event.filter==EVFILT_PROC&&event.fflags==NOTE_EXIT);
  fprintf(stderr,"exit role=%d flags=%u fflags=%u data=%ld\n",role,event.flags,event.fflags,(long)event.data);
  CHECK(role?remover_exit(n,event,&b):app_exit(n,event,&c));
  struct kevent wrong=event;wrong.flags|=EV_ERROR;CHECK(!(role?remover_exit(n,wrong,&b):app_exit(n,wrong,&c)));
  wrong=event;wrong.flags&=~EV_EOF;CHECK(!(role?remover_exit(n,wrong,&b):app_exit(n,wrong,&c)));
  wrong=event;wrong.ident++;CHECK(!(role?remover_exit(n,wrong,&b):app_exit(n,wrong,&c)));
  wrong=event;wrong.filter=EVFILT_READ;CHECK(!(role?remover_exit(n,wrong,&b):app_exit(n,wrong,&c)));
  wrong=event;wrong.fflags=NOTE_FORK;CHECK(!(role?remover_exit(n,wrong,&b):app_exit(n,wrong,&c)));
  wrong=event;wrong.udata=role?NULL:(void*)&b;CHECK(!(role?remover_exit(n,wrong,&b):app_exit(n,wrong,&c)));
  CHECK(!(role?remover_exit(0,event,&b):app_exit(0,event,&c)));
CHECK(event.udata==(role?(void*)&b:NULL));CHECK(close(fd)==0);
  printf("lifecycle role=%s actual NOTE_EXIT observed, owned child reaped, watcher closed\n",role?"remover":"app");
 }
 return 0;
}
"""

@unittest.skipUnless(sys.platform == 'darwin', 'Darwin kevent integration')
class KeventReceiptTests(unittest.TestCase):
    def test_real_receipts_refusals_and_exit_events(self):
        native = ROOT / 'desktop/native/macos-installed-native/src'
        app = condition((native / 'android_registration.m').read_text(), 'if (count!=1 || receipt.ident')
        removal = condition((native / 'removal_coordinator.m').read_text(), 'if(n!=1||receipt.ident')
        app_text = (native / 'android_registration.m').read_text()
        removal_text = (native / 'removal_coordinator.m').read_text()
        app_exit = condition(app_text, 'if (count!=1 || event.ident')
        removal_exit = condition(removal_text, 'if(n!=1||event.ident')
        import re
        app_allowed = re.search(r'const uint16_t allowed=([^;]+);', app_text).group(1)
        removal_allowed = re.search(r'const uint16_t allowed=([^;]+);', removal_text).group(1)
        code = (NATIVE.replace('APP_CONDITION', app).replace('REMOVER_CONDITION', removal)
                .replace('APP_EXIT_CONDITION', app_exit).replace('REMOVAL_EXIT_CONDITION', removal_exit)
                .replace('APP_EXIT_ALLOWED', app_allowed).replace('REMOVAL_EXIT_ALLOWED', removal_allowed))
        with tempfile.TemporaryDirectory(prefix='mrk-kevent-') as directory:
            source, binary = Path(directory) / 'receipt.c', Path(directory) / 'receipt'
            source.write_text(code)
            compiled = subprocess.run(['/usr/bin/clang', '-std=c11', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(binary)], capture_output=True, text=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.count('"negativeCases":7'), 2)
            self.assertEqual(result.stdout.count('actual NOTE_EXIT observed'), 2)
            print(result.stdout, end='')

if __name__ == '__main__':
    unittest.main()
