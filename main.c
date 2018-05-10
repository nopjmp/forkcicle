#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>

#define LOG(...) printf(__VA_ARGS__);
//#define ELOG(...) fprintf(stderr, __VA_ARGS__);
#define ELOG(...)

#define ARRAY_SIZE(x) sizeof(x) / sizeof(0[x])

void sig_handler(int signo)
{
    pid_t pid;
    char *buf = NULL;
    size_t len = 255;
    char command[256] = {0};

    // using ps since there doesn't seem to be a C interface for getting all child pids
    snprintf(command, len + 1, "ps -o pid= --ppid %u", getpid());
    FILE *fp = (FILE*)popen(command, "r");
    while (getline(&buf, &len, fp) >= 0) {
	pid = atol(buf);
	// if we couldn't parse just ignore it 0 is never a valid pid
	if (pid != 0) {
	    ELOG("sending signal %d to %ld\n", signo, (long)pid);
	    kill(pid, signo);
	}
    }
    free(buf);
    fclose(fp);    
}

void setup_signal_handler()
{
    const int forward[] = {SIGTERM, SIGHUP, SIGINT, SIGUSR1, SIGUSR2, SIGCONT};
    for (unsigned int i = 0; i < ARRAY_SIZE(forward); i++) {
	if (signal(forward[i], sig_handler) == SIG_ERR)
	    LOG("can't catch signal %s\n", strsignal(forward[i]));
    }
}

int main(int argc, char** argv)
{
    // become the subreaper
    if (prctl(PR_SET_CHILD_SUBREAPER, 1) < 0)
	ELOG("Could not set child subreaper.\n");

    // just in case we die for some reason
    // NOTE: this won't kill double forked processes
    if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0)
	ELOG("Could not set pdeathsig.\n");

    if (argc < 2) {
	LOG("usage: %s command [args]", argv[0]);
	return -1;
    }

    pid_t pid = fork();
    if (pid == 0) {
	ELOG("forked pid %ld\n", (long)getpid());
	return execvp(argv[1], argv+1);
    } else {
	setup_signal_handler();	
	for (;;) {
	    // wait for the last child
	    pid = wait(NULL);
	    ELOG("%ld => %s\n", (long)pid, strerror(errno));
	    if (pid == -1 && errno == ECHILD) {
		// all of our children have been reap'd exit
		return 0;
	    }
	    errno = 0;
	}
    }
    
    return 0;
}
