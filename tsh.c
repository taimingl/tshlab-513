/**
 * @file tsh.c
 * @brief A tiny shell program with job control
 *
 * TODO: Delete this comment and replace it with your own.
 * <The line above is not a sufficient documentation.
 *  You will need to write your program documentation.
 *  Follow the 15-213/18-213/15-513 style guide at
 *  http://www.cs.cmu.edu/~213/codeStyle.html.>
 *
 * @author Taiming Liu <taimingl@andrew.cmu.edu>
 */

#include "csapp.h"
#include "tsh_helper.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * If DEBUG is defined, enable contracts and printing on dbg_printf.
 */
#ifdef DEBUG
/* When debugging is enabled, these form aliases to useful functions */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_requires(...) assert(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_ensures(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated for these */
#define dbg_printf(...)
#define dbg_requires(...)
#define dbg_assert(...)
#define dbg_ensures(...)
#endif

/* Function prototypes */
void eval(const char *cmdline);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
void sigquit_handler(int sig);
void cleanup(void);

/**
 * @brief main routine of the shell program.
 *
 * Takes command and arguments from command line and exexcute requested
 * programs.
 *
 * @param[in] argc number of command line arguments
 * @param[in] argv pointer to array of command line arguments
 *
 */
int main(int argc, char **argv) {
    int c;
    char cmdline[MAXLINE_TSH]; // Cmdline for fgets
    bool emit_prompt = true;   // Emit prompt (default)

    // Redirect stderr to stdout (so that driver will get all output
    // on the pipe connected to stdout)
    if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) {
        perror("dup2 error");
        exit(1);
    }

    // Parse the command line
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
        case 'h': // Prints help message
            usage();
            break;
        case 'v': // Emits additional diagnostic info
            verbose = true;
            break;
        case 'p': // Disables prompt printing
            emit_prompt = false;
            break;
        default:
            usage();
        }
    }

    // Create environment variable
    if (putenv(strdup("MY_ENV=42")) < 0) {
        perror("putenv error");
        exit(1);
    }

    // Set buffering mode of stdout to line buffering.
    // This prevents lines from being printed in the wrong order.
    if (setvbuf(stdout, NULL, _IOLBF, 0) < 0) {
        perror("setvbuf error");
        exit(1);
    }

    // Initialize the job list
    init_job_list();

    // Register a function to clean up the job list on program termination.
    // The function may not run in the case of abnormal termination (e.g. when
    // using exit or terminating due to a signal handler), so in those cases,
    // we trust that the OS will clean up any remaining resources.
    if (atexit(cleanup) < 0) {
        perror("atexit error");
        exit(1);
    }

    // Install the signal handlers
    Signal(SIGINT, sigint_handler);   // Handles Ctrl-C
    Signal(SIGTSTP, sigtstp_handler); // Handles Ctrl-Z
    Signal(SIGCHLD, sigchld_handler); // Handles terminated or stopped child

    Signal(SIGTTIN, SIG_IGN);
    Signal(SIGTTOU, SIG_IGN);

    Signal(SIGQUIT, sigquit_handler);

    // Execute the shell's read/eval loop
    while (true) {
        if (emit_prompt) {
            printf("%s", prompt);

            // We must flush stdout since we are not printing a full line.
            fflush(stdout);
        }

        if ((fgets(cmdline, MAXLINE_TSH, stdin) == NULL) && ferror(stdin)) {
            perror("fgets error");
            exit(1);
        }

        if (feof(stdin)) {
            // End of file (Ctrl-D)
            printf("\n");
            return 0;
        }

        // Remove any trailing newline
        char *newline = strchr(cmdline, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }

        // Evaluate the command line
        eval(cmdline);
    }

    return -1; // control never reaches here
}

/**
 * @brief <What does eval do?>
 *
 * TODO: Delete this comment and replace it with your own.
 *
 * NOTE: The shell is supposed to be a long-running process, so this function
 *       (and its helpers) should avoid exiting on error.  This is not to say
 *       they shouldn't detect and print (or otherwise handle) errors!
 */
void eval(const char *cmdline) {
    parseline_return parse_result;
    struct cmdline_tokens token;
    pid_t pid; // process ID
    // int fd;    /* output file descriptor*/

    // Parse command line
    parse_result = parseline(cmdline, &token);

    /* cmd line error */
    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        printf("parse cmd line error or empty cmd line args\n");
        return;
    }

    /* quit command */
    if (token.builtin == BUILTIN_QUIT) {
        exit(0);
    }

    /* Output file */
    // if (token.outfile != NULL) {
    //     fd = open(token.outfile, O_RDONLY|O_CREAT);
    //     if (fd < 0) {
    //         printf("Output file reading/writing error\n");
    //         // exit(1);
    //     }
    // }

    /* jobs command */
    if (token.builtin == BUILTIN_JOBS) {
        // if (token.outfile != NULL) {
        //     list_jobs(fd);
        // } else {
        //     list_jobs(1);
        // }
        list_jobs(1);
        return;
    }

    sigset_t mask_all, mask_empty;
    sigfillset(&mask_all);
    sigemptyset(&mask_empty);
    sigprocmask(SIG_BLOCK, &mask_all, NULL); /* Block signals */

    if ((pid = fork()) == 0) { /* Child runs user job */
        if (setpgid(0, 0) < 0) {
            perror("Set process gid error");
        }
        sigprocmask(SIG_UNBLOCK, &mask_all, NULL); /* Unblock signals */
        if (execve(token.argv[0], token.argv, environ) < 0) {
            printf("%s: Command not found. \n", token.argv[0]);
            fflush(stdout);
            exit(0);
        }
        // sigprocmask(SIG_BLOCK, &mask_all, NULL);
    }

    /**
     * (!) TODO: unix_error function not callable
     */
    /* Parent process */
    job_state j_state = parse_result == PARSELINE_FG ? FG : BG;
    // printf("job state %d\n", j_state);
    add_job(pid, j_state, cmdline);
    // sigprocmask(SIG_UNBLOCK, &mask_all, NULL); /* Unblock signals */

    if (j_state == FG) { // foreground job
        sigemptyset(&mask_empty);
        while (fg_job() != 0) {
            sigsuspend(&mask_empty);
        }
    } else {
        printf("[%d] (%d) %s\n", job_from_pid(pid), pid, cmdline);
    }

    return;
}

/*****************
 * Signal handlers
 *****************/

/**
 * @brief <What does sigchld_handler do?>
 *
 * TODO: Delete this comment and replace it with your own.
 */
void sigchld_handler(int sig) {
    int olderrno = errno;
    sigset_t mask_all, prev_all;
    pid_t pid;
    int status;

    sigfillset(&mask_all);
    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) >
           0) { /* Reap zombie child */
        sigprocmask(SIG_BLOCK, &mask_all, &prev_all);
        if (WIFSIGNALED(status)) {
            if (WTERMSIG(status) == 2) {
                sio_printf("Job [%d] terminated by signal %d\n",
                           job_from_pid(pid), WTERMSIG(status));
            }
            delete_job(job_from_pid(pid)); /* Delete child job from job list */
        } else if (WIFSTOPPED(status)) {
            job_set_state(job_from_pid(pid), ST);
            sio_printf("Job [%d] stopped by signal %d\n", job_from_pid(pid),
                       WSTOPSIG(status));
        } else {
            delete_job(job_from_pid(pid)); /* Delete child job from job list */
        }
        sigprocmask(SIG_SETMASK, &prev_all, NULL);
        // if (!WIFEXITED(status)) {
        //     sio_printf("Child %d terminated abnormally\n", pid);
        // }
        // sigprocmask(SIG_BLOCK, &mask_all, &prev_all);
        // delete_job(job_from_pid(pid)); /* Delete child job from job list */
        // sigprocmask(SIG_SETMASK, &prev_all, NULL);
    }
    // if (errno != ECHILD) {
    //     sio_eprintf("waitpid error\n");
    // }
    errno = olderrno;
}

/**
 * @brief <What does sigint_handler do?>
 *
 * TODO: Delete this comment and replace it with your own.
 */
void sigint_handler(int sig) {}

/**
 * @brief <What does sigtstp_handler do?>
 *
 * TODO: Delete this comment and replace it with your own.
 */
void sigtstp_handler(int sig) {}

/**
 * @brief Attempt to clean up global resources when the program exits.
 *
 * In particular, the job list must be freed at this time, since it may
 * contain leftover buffers from existing or even deleted jobs.
 */
void cleanup(void) {
    // Signals handlers need to be removed before destroying the joblist
    Signal(SIGINT, SIG_DFL);  // Handles Ctrl-C
    Signal(SIGTSTP, SIG_DFL); // Handles Ctrl-Z
    Signal(SIGCHLD, SIG_DFL); // Handles terminated or stopped child

    destroy_job_list();
}
