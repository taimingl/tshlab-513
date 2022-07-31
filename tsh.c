/**
 * @file tsh.c
 * @brief A tiny shell program with job control
 *
 * A tiny shell program capable built-in syscalls with additional built-in
 * calls of jobs, bg, and fg. Utilized signal handling and I/O
 * redirecting to execture user requests.
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

        fflush(stdout);
        fflush(stdout);
    }

    return -1; // control never reaches here
}

/**
 * @brief evaluate command line requests entered by user
 *
 * For built-in requests, jobs, fg, bg, execute immediately.
 * For other requests, fork a child to run the request.
 * If the request is requested to be run on the foreground,
 * parent uses job_lists to timely reap terminated children jobs.
 *
 * @param[in] cmdline parsed cmd line structure containing req info.
 *
 */
void eval(const char *cmdline) {
    parseline_return parse_result;
    struct cmdline_tokens token;
    pid_t pid;                  // process ID
    int fd_in = STDIN_FILENO;   /* output file descriptor*/
    int fd_out = STDOUT_FILENO; /* output file descriptor*/

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

    /* Redirct I/O */
    if (token.outfile != NULL) {
        fd_out = open(token.outfile, O_CREAT | O_TRUNC | O_RDWR, 0644);
        if (fd_out < 0) {
            printf("Output file reading/writing error\n");
            // sigprocmask(SIG_SETMASK, &prev_one, NULL);
            return;
        }
    }
    if (token.infile != NULL) {
        fd_in = open(token.infile, O_RDONLY, 0644);
        if (fd_in < 0) {
            printf("Input file reading/writing error\n");
            // sigprocmask(SIG_SETMASK, &prev_one, NULL);
            return;
        }
    }

    /* Block signals */
    sigset_t mask_all, prev_one;
    sigfillset(&mask_all);
    sigprocmask(SIG_BLOCK, &mask_all, &prev_one);

    /* jobs command */
    if (token.builtin == BUILTIN_JOBS) {
        list_jobs(fd_out);
        sigprocmask(SIG_SETMASK, &prev_one, NULL); /* Unblock signals */
        return;
    }

    if (token.builtin == BUILTIN_BG || token.builtin == BUILTIN_FG) {
        if (token.argv[1] == NULL) {
            if (token.builtin == BUILTIN_BG) {
                printf("bg command requires PID or %%jobid argument\n");
            } else {
                printf("fg command requires PID or %%jobid argument\n");
            }
            sigprocmask(SIG_SETMASK, &prev_one, NULL); /* Unblock signals */
            return;
        } else {
            if (token.argv[1][0] == '%') {
                if (!isdigit(token.argv[1][1])) {
                    if (token.builtin == BUILTIN_BG) {
                        printf("bg command requires PID or %%jobid argument\n");
                    } else {
                        printf("fg command requires PID or %%jobid argument\n");
                    }
                    sigprocmask(SIG_SETMASK, &prev_one,
                                NULL); /* Unblock signals */
                    return;
                }
                jid_t jid = atoi(&token.argv[1][1]);
                if (job_exists(jid)) {
                    pid = job_get_pid(jid);
                } else {
                    printf("%%%d: No such job\n", jid);
                    sigprocmask(SIG_SETMASK, &prev_one,
                                NULL); /* Unblock signals */
                    return;
                }
            } else {
                if (!isdigit(token.argv[1][0])) {
                    if (token.builtin == BUILTIN_BG) {
                        printf("bg: argument must be a PID or %%jobid\n");
                    } else {
                        printf("fg: argument must be a PID or %%jobid\n");
                    }
                    sigprocmask(SIG_SETMASK, &prev_one,
                                NULL); /* Unblock signals */
                    return;
                }
                pid = atoi(&token.argv[1][0]);
            }
        }
        if (token.builtin == BUILTIN_BG) {
            printf("[%d] (%d) %s\n", job_from_pid(pid), pid,
                   job_get_cmdline(job_from_pid(pid)));
            if (kill(-pid, SIGCONT) == -1) {
                printf("Error: failed to kill background job\n");
            }
            job_set_state(job_from_pid(pid), BG);
        }
        if (token.builtin == BUILTIN_FG) {
            // printf("[%d] (%d) %s\n", job_from_pid(pid), pid,
            //        job_get_cmdline(job_from_pid(pid)));
            if (kill(-pid, SIGCONT) == -1) {
                printf("Error: failed to kill background job\n");
            }
            job_set_state(job_from_pid(pid), FG);
            while (fg_job() != 0) {
                sigsuspend(&prev_one);
            }
        }
        sigprocmask(SIG_SETMASK, &prev_one, NULL); /* Unblock signals */
        return;
    }

    pid = fork();
    if (pid == 0) {                                /* Child runs user job */
        sigprocmask(SIG_SETMASK, &prev_one, NULL); /* Unblock signals */
        /* Redirect I/O */
        if (fd_out < 0 || fd_in < 0) {
            exit(1);
        }
        if (fd_out != STDOUT_FILENO) {
            dup2(fd_out, STDOUT_FILENO);
            close(fd_out);
        }
        if (fd_in != STDIN_FILENO) {
            dup2(fd_in, STDIN_FILENO);
            close(fd_in);
        }
        if (setpgid(0, 0) < 0) {
            perror("Set process gid error");
        }
        if (execve(token.argv[0], token.argv, environ) < 0) {
            printf("%s: Command not found. \n", token.argv[0]);
            fflush(stdout);
            exit(0);
        }
        // sigprocmask(SIG_BLOCK, &mask_all, &prev_one);
    } else if (pid < 0) {
        // Non built //Error condition if fork fails
        printf("Error: Failed to fork a child process.\n");
        sigprocmask(SIG_SETMASK, &prev_one, NULL); /* Unblock signals */
        return;
    }

    /* Parent process */
    job_state j_state = parse_result == PARSELINE_FG ? FG : BG;
    sigprocmask(SIG_BLOCK, &mask_all, NULL);
    add_job(pid, j_state, cmdline);

    if (j_state == FG) { // foreground job
        // suspend until all children's reapped
        while (fg_job() != 0) {
            sigsuspend(&prev_one);
        }
    } else {
        printf("[%d] (%d) %s\n", job_from_pid(pid), pid, cmdline);
    }

    sigprocmask(SIG_SETMASK, &prev_one, NULL); /* Unblock signals */

    return;
}

/*****************
 * Signal handlers
 *****************/

/**
 * @brief Handles SIGCHLD sinals when receives from kernel.
 *
 * Reaps all the children running on both foreground and background,
 * and delete the process from the job_list.
 *
 * @param[in] sig singal code received.
 */
void sigchld_handler(int sig) {
    int olderrno = errno;
    sigset_t mask_all, prev_one;
    pid_t pid;
    int status;

    sigfillset(&mask_all);
    sigprocmask(SIG_BLOCK, &mask_all, &prev_one); /* Block signals */
    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) >
           0) { /* Reap zombie child */
        if (WIFEXITED(status)) {
            delete_job(job_from_pid(pid)); /* Delete child job from job list */
        } else if (WIFSIGNALED(status)) {
            sio_printf("Job [%d] (%d) terminated by signal %d\n",
                       job_from_pid(pid), pid, WTERMSIG(status));
            delete_job(job_from_pid(pid));
        } else if (WIFSTOPPED(status)) {
            job_set_state(job_from_pid(pid), ST);
            sio_printf("Job [%d] (%d) stopped by signal %d\n",
                       job_from_pid(pid), pid, WSTOPSIG(status));
        }
    }
    sigprocmask(SIG_SETMASK, &prev_one, NULL); /* Unblock signals */
    errno = olderrno;
}

/**
 * @brief Handles SIGINT signal when received from kernel.
 *
 * Receies SIGINT signal when user types Ctrl-C. First finds the job
 * currently running on the foreground and kills the process. Skip
 * if nothing found.
 *
 * @param[in] sig singal code received
 */
void sigint_handler(int sig) {
    int olderrno = errno;
    sigset_t mask_all, prev_one;
    jid_t jid;
    pid_t pid;

    sigfillset(&mask_all);
    sigprocmask(SIG_BLOCK, &mask_all, &prev_one); /* Block signals */

    jid = fg_job();
    if (jid != 0) {
        pid = job_get_pid(jid);

        if (kill(-pid, SIGINT) == -1) { // kill all processes with the same gid
            sio_eprintf("Error: failed to kill fg jobs");
            return;
        }
    }

    sigprocmask(SIG_SETMASK, &prev_one, NULL); /* Unblock signals */
    errno = olderrno;

    return;
}

/**
 * @brief Handles SIGTSTP signal when received from kernel.
 *
 * Receies SIGTSTP signal when user types Ctrl-Z. First finds the job
 * currently running on the foreground and kills the process. Skip
 * if nothing found.
 *
 * @param[in] sig singal code received
 */
void sigtstp_handler(int sig) {
    int olderrno = errno;
    sigset_t mask_all, prev_one;
    jid_t jid;
    pid_t pid;

    sigfillset(&mask_all);
    sigprocmask(SIG_BLOCK, &mask_all, &prev_one); /* Block signals */

    jid = fg_job();
    if (jid != 0) {
        pid = job_get_pid(jid);

        if (kill(-pid, SIGTSTP) == -1) { // kill all processes with the same gid
            sio_eprintf("Error: failed to kill fg jobs");
            return;
        }
    }

    sigprocmask(SIG_SETMASK, &prev_one, NULL); /* Unblock signals */
    errno = olderrno;

    return;
}

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
