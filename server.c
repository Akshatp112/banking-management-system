/* server.c - accept loop, one worker thread per client, command dispatch */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"
#include "db.h"
#include "net.h"
#include "session.h"
#include "handlers.h"
#include "auth.h"

static volatile sig_atomic_t g_stop = 0;

/* ------------------------------------------------ single-instance lock ---- */
/* Two servers on the same database would be a recipe for trouble. We ask the
 * kernel for an exclusive fcntl() lock on a small file. A second server cannot
 * get it and exits. The kernel releases the lock automatically when the
 * process dies, so a crash never leaves a stale lock behind. */
static int acquire_server_lock(void)
{
    int fd = open(LOCK_PATH, O_CREAT | O_RDWR, 0644);
    if (fd < 0) { perror("open lock file"); return -1; }

    struct flock fl;
    memset(&fl, 0, sizeof fl);
    fl.l_type   = F_WRLCK;      /* exclusive */
    fl.l_whence = SEEK_SET;
    fl.l_start  = 0;
    fl.l_len    = 0;            /* 0 = the whole file */

    if (fcntl(fd, F_SETLK, &fl) == -1) {
        fprintf(stderr, "Another server is already running (cannot lock %s).\n", LOCK_PATH);
        close(fd);
        return -1;
    }

    char pid[32];                                   /* record our pid, for humans */
    int n = snprintf(pid, sizeof pid, "%d\n", (int)getpid());
    if (ftruncate(fd, 0) == 0 && write(fd, pid, (size_t)n) < 0) perror("write pid");
    return fd;                                      /* keep open for the server's whole life */
}

/* ---------------------------------------------------- command handling ---- */
#define ROLE_BIT(r) (1u << (r))
#define PUBLIC      0u           /* usable before logging in */
#define CUSTOMER_ONLY ROLE_BIT(ROLE_CUSTOMER)
#define EMPLOYEE_ONLY ROLE_BIT(ROLE_EMPLOYEE)
#define MANAGER_ONLY  ROLE_BIT(ROLE_MANAGER)
#define ADMIN_ONLY    ROLE_BIT(ROLE_ADMIN)
#define ALL_STAFF     (ROLE_BIT(ROLE_EMPLOYEE) | ROLE_BIT(ROLE_MANAGER) | ROLE_BIT(ROLE_ADMIN))
#define ANY_ROLE    (ROLE_BIT(ROLE_CUSTOMER) | ROLE_BIT(ROLE_EMPLOYEE) | \
                     ROLE_BIT(ROLE_MANAGER)  | ROLE_BIT(ROLE_ADMIN))

typedef struct {
    const char *name;
    unsigned    roles;     /* PUBLIC, or the set of roles allowed to run it */
    Handler     fn;
    int         free_text; /* 1 = may carry more than MAX_ARGS words (uses 'rest') */
} Command;

static int cmd_ping(Session *s, int argc, char **argv, const char *rest)
{
    (void)argc; (void)argv; (void)rest;
    net_send_line(s->fd, "OK PONG");
    return HANDLER_CONTINUE;
}

static int cmd_quit(Session *s, int argc, char **argv, const char *rest)
{
    (void)argc; (void)argv; (void)rest;
    net_send_line(s->fd, "OK BYE");
    return HANDLER_CLOSE;
}

static int cmd_whoami(Session *s, int argc, char **argv, const char *rest)
{
    (void)argc; (void)argv; (void)rest;
    net_send_line(s->fd, "OK %d %d", s->user_id, (int)s->role);
    return HANDLER_CONTINUE;
}

static int cmd_logout(Session *s, int argc, char **argv, const char *rest)
{
    (void)argc; (void)argv; (void)rest;
    session_logout(s);
    net_send_line(s->fd, "OK LOGGED_OUT");
    return HANDLER_CONTINUE;
}


/* THE one place where "who may run what" is decided.
 * From step 5 on, adding a feature = writing a handler + adding one row here. */
static const Command COMMANDS[] = {
    /* everyone */
    { "PING",            PUBLIC,                     cmd_ping,               0 },
    { "QUIT",            PUBLIC,                     cmd_quit,               0 },
    { "LOGIN",           PUBLIC,                     cmd_login,              0 },
    { "LOGOUT",          PUBLIC,                     cmd_logout,             0 },   /* public so a deactivated user can still log out */
    { "WHOAMI",          ANY_ROLE,                   cmd_whoami,             0 },
    { "CHANGE_PASS",     ANY_ROLE,                   cmd_change_pass,        0 },
    /* customer */
    { "BALANCE",         CUSTOMER_ONLY,              cmd_balance,            0 },
    { "DEPOSIT",         CUSTOMER_ONLY,              cmd_deposit,            0 },
    { "WITHDRAW",        CUSTOMER_ONLY,              cmd_withdraw,           0 },
    { "TRANSFER",        CUSTOMER_ONLY,              cmd_transfer,           0 },
    { "HISTORY",         CUSTOMER_ONLY,              cmd_history,            0 },
    { "FEEDBACK",        CUSTOMER_ONLY,              cmd_feedback,           1 },
    { "LOAN_QUOTE",      CUSTOMER_ONLY,              cmd_loan_quote,         0 },
    { "APPLY_LOAN",      CUSTOMER_ONLY,              cmd_apply_loan,         0 },
    { "MY_LOANS",        CUSTOMER_ONLY,              cmd_my_loans,           0 },
    { "REPAY",           CUSTOMER_ONLY,              cmd_repay,              0 },
    /* employee */
    { "ADD_CUSTOMER",    EMPLOYEE_ONLY,              cmd_add_customer,       0 },
    { "MOD_CUSTOMER",    EMPLOYEE_ONLY,              cmd_mod_customer,       0 },
    { "PASSBOOK",        EMPLOYEE_ONLY,              cmd_passbook,           0 },
    { "VIEW_ASSIGNED",   EMPLOYEE_ONLY,              cmd_view_assigned,      0 },
    { "PROCESS_LOAN",    EMPLOYEE_ONLY,              cmd_process_loan,       0 },
    /* employee, manager, admin */
    { "FIND_USER",       ALL_STAFF,                  cmd_find_user,          0 },
    /* manager (SET_ACTIVE: admin too) */
    { "SET_ACTIVE",      MANAGER_ONLY | ADMIN_ONLY,  cmd_set_active,         0 },
    { "REVIEW_FEEDBACK", MANAGER_ONLY,               cmd_review_feedback,    0 },
    { "PENDING_LOANS",   MANAGER_ONLY,               cmd_pending_loans,      0 },
    { "ASSIGN_LOAN",     MANAGER_ONLY,               cmd_assign_loan,        0 },
    /* admin */
    { "ADD_EMPLOYEE",    ADMIN_ONLY,                 cmd_add_employee,       0 },
    { "MOD_USER",        ADMIN_ONLY,                 cmd_mod_user,           0 },
    { "SET_ROLE",        ADMIN_ONLY,                 cmd_set_role,           0 },
    { "VIEW_AUDIT",      ADMIN_ONLY,                 cmd_view_audit,         0 },
};
#define NUM_COMMANDS (sizeof COMMANDS / sizeof COMMANDS[0])

static int dispatch(Session *s, const char *line)
{
    char  work[MAX_LINE];
    char *argv[MAX_ARGS];
    int   argc = 0;
    char *save = NULL;

    snprintf(work, sizeof work, "%s", line);
    char *tok = strtok_r(work, " \t", &save);
    while (tok && argc < MAX_ARGS) {
        argv[argc++] = tok;
        tok = strtok_r(NULL, " \t", &save);
    }
    if (argc == 0) return HANDLER_CONTINUE;
    int overflow = (tok != NULL);                /* more words than MAX_ARGS */

    /* "rest" = everything after the command word, for free-text arguments (feedback). */
    const char *rest = line;
    while (*rest == ' ' || *rest == '\t') rest++;
    while (*rest && *rest != ' ' && *rest != '\t') rest++;
    while (*rest == ' ' || *rest == '\t') rest++;

    for (size_t i = 0; i < NUM_COMMANDS; i++) {
        if (strcasecmp(argv[0], COMMANDS[i].name) != 0) continue;

        if (overflow && !COMMANDS[i].free_text) {
            net_send_line(s->fd, "ERR TOO_MANY_ARGUMENTS");
            return HANDLER_CONTINUE;
        }
        if (COMMANDS[i].roles != PUBLIC) {
            if (!s->logged_in) {
                net_send_line(s->fd, "ERR NOT_LOGGED_IN");
                return HANDLER_CONTINUE;
            }
            /* Who you were at login is not necessarily who you are now: re-read
             * role and active flag, so a demotion or deactivation bites at once. */
            int v = session_revalidate(s);
            if (v == SESSION_REVOKED) { net_send_line(s->fd, "ERR ACCOUNT_DEACTIVATED"); return HANDLER_CONTINUE; }
            if (v != SESSION_OK)      { net_send_line(s->fd, "ERR INTERNAL");            return HANDLER_CONTINUE; }
            if (!(COMMANDS[i].roles & ROLE_BIT(s->role))) {     /* role comes from the SESSION */
                net_send_line(s->fd, "ERR FORBIDDEN");
                return HANDLER_CONTINUE;
            }
        }
        return COMMANDS[i].fn(s, argc, argv, rest);
    }
    net_send_line(s->fd, overflow ? "ERR TOO_MANY_ARGUMENTS" : "ERR UNKNOWN_COMMAND");
    return HANDLER_CONTINUE;
}

/* ------------------------------------------------------ worker thread ---- */
typedef struct {
    int  fd;
    char peer[48];
} ClientCtx;

static void *worker(void *arg)
{
    ClientCtx *ctx = arg;
    Session s;
    memset(&s, 0, sizeof s);
    s.fd = ctx->fd;
    snprintf(s.peer, sizeof s.peer, "%s", ctx->peer);
    free(ctx);

    printf("[%s] connected\n", s.peer);

    s.db = db_open(DB_PATH);                    /* this thread's own connection */
    if (!s.db) {
        net_send_line(s.fd, "ERR INTERNAL database unavailable");
    } else {
        LineReader r;
        net_reader_init(&r, s.fd);
        net_send_line(s.fd, "OK BANK READY");

        char line[MAX_LINE];
        for (;;) {
            int n = net_read_line(&r, line, sizeof line);
            if (n == NET_EOF || n == NET_ERR) break;
            if (n == NET_TIMEOUT) { net_send_line(s.fd, "ERR IDLE_TIMEOUT"); break; }
            if (n == NET_TOO_LONG) { net_send_line(s.fd, "ERR LINE_TOO_LONG"); continue; }
            if (n == 0) continue;
            if (dispatch(&s, line) == HANDLER_CLOSE) break;
        }
    }

    /* Cleanup runs on EVERY exit path: normal quit, crash, timeout, dropped cable.
     * This is why a dead client can never leave its user "stuck logged in". */
    session_logout(&s);
    db_close(s.db);
    close(s.fd);
    client_slot_release();
    printf("[%s] disconnected\n", s.peer);
    return NULL;
}

/* --------------------------------------------------------------- main ---- */
static void on_signal(int sig) { (void)sig; g_stop = 1; }

int main(int argc, char **argv)
{
    int port = DEFAULT_PORT, seed_demo = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--seed-demo") == 0) { seed_demo = 1; continue; }
        port = atoi(argv[i]);
        if (port < 1 || port > 65535) {
            fprintf(stderr, "usage: %s [--seed-demo] [port]\n", argv[0]);
            return 1;
        }
    }
    setvbuf(stdout, NULL, _IOLBF, 0);

    int lock_fd = acquire_server_lock();
    if (lock_fd < 0) return 1;

    /* Make sure the schema exists before any client connects. */
    sqlite3 *boot = db_open(DB_PATH);
    if (!boot || db_init_schema(boot) != DB_OK) { fprintf(stderr, "database setup failed\n"); return 1; }
    if (auth_init() != 0)                       { fprintf(stderr, "auth setup failed\n"); return 1; }
    if (auth_bootstrap(boot, seed_demo) != 0)   { fprintf(stderr, "first-run setup failed\n"); return 1; }
    db_close(boot);

    session_global_init();

    signal(SIGPIPE, SIG_IGN);                   /* writing to a closed socket -> error, not death */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;                  /* no SA_RESTART: accept() must wake up on Ctrl+C */
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    int lfd = net_listen(port);
    if (lfd < 0) return 1;
    printf("Bank server listening on port %d (max %d clients, idle timeout %ds)\n",
           port, MAX_CLIENTS, IDLE_TIMEOUT_SEC);

    while (!g_stop) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof peer;
        int cfd = accept(lfd, (struct sockaddr *)&peer, &plen);
        if (cfd < 0) {
            if (errno == EINTR) continue;       /* signal: loop re-checks g_stop */
            perror("accept");
            usleep(100000);                     /* avoid a busy loop on persistent errors */
            continue;
        }

        /* Semaphore check: is there a free slot? Reject politely if not. */
        if (!client_slot_try_acquire()) {
            net_send_line(cfd, "ERR SERVER_BUSY try again later");
            close(cfd);
            continue;
        }

        struct timeval tv = { IDLE_TIMEOUT_SEC, 0 };
        setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);   /* read() gives up after this */

        ClientCtx *ctx = malloc(sizeof *ctx);
        if (!ctx) { close(cfd); client_slot_release(); continue; }
        ctx->fd = cfd;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof ip);
        snprintf(ctx->peer, sizeof ctx->peer, "%s:%d", ip, ntohs(peer.sin_port));

        pthread_t tid;
        if (pthread_create(&tid, NULL, worker, ctx) != 0) {
            perror("pthread_create");
            close(cfd); free(ctx); client_slot_release();
            continue;
        }
        pthread_detach(tid);                    /* nobody joins workers; they clean up themselves */
    }

    printf("Shutting down.\n");
    close(lfd);
    close(lock_fd);                             /* releases the lock */
    return 0;
}
