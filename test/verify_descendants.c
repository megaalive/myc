/* Test fixture: spawns a child sleep process, then exits.
 * Used by _regress_run.bat to verify that myc kills the entire
 * process group (parent + descendants) on timeout/kill. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int main(void)
{
    pid_t pid = fork();
    if (pid == 0) {
        /* Child: sleep for a long time. */
        sleep(30);
        return 0;
    } else if (pid > 0) {
        /* Parent: exit immediately. */
        printf("parent pid=%d child pid=%d\n", getpid(), pid);
        return 0;
    }
    fprintf(stderr, "fork failed\n");
    return 1;
}