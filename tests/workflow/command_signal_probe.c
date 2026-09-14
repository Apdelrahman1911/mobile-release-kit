/* Read-only native signal oracle: Python targets install their own policies. */
#define _GNU_SOURCE 1
#define _DARWIN_C_SOURCE 1
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    const int numbers[] = {
        SIGINT, SIGTERM, SIGCHLD, SIGUSR1, SIGPIPE,
#ifdef SIGXFZ
        SIGXFZ,
#endif
#ifdef SIGXFSZ
        SIGXFSZ,
#endif
    };
    sigset_t mask;
    struct sigaction action;
    const unsigned count = sizeof(numbers) / sizeof(numbers[0]);
    if (NSIG <= 1 || NSIG > 1024 || sigprocmask(SIG_SETMASK, NULL, &mask) != 0)
        return 79;
    printf("{\"pid\":%ld,\"nsig\":%d,\"policy\":[", (long)getpid(), NSIG);
    for (unsigned index = 0; index < count; ++index) {
        if (sigaction(numbers[index], NULL, &action) != 0)
            return 79;
        const int policy = action.sa_handler == SIG_DFL ? 0 : action.sa_handler == SIG_IGN ? 1 : 2;
        printf("%s[%d,%d]", index ? "," : "", numbers[index], policy);
    }
    printf("],\"mask\":[");
    for (int number = 1; number < NSIG; ++number)
        printf("%s[%d,%d]", number == 1 ? "" : ",", number, sigismember(&mask, number));
    printf("]}\n");
    return ferror(stdout) ? 79 : 0;
}
