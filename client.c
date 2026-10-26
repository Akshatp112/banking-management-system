/* client.c - menu-driven terminal client
 *
 * The client is deliberately "dumb": it never decides who you are or what you
 * may do. It shows a menu for the role the SERVER reported at login, turns your
 * answers into protocol lines, and prints the replies. If someone edits this
 * file to show an admin menu to a customer, the server still answers FORBIDDEN.
 *
 * Usage: ./bank_client [host] [port]        (defaults 127.0.0.1 8080)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>
#include <termios.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>

#include "common.h"
#include "net.h"

static int         sock = -1;
static LineReader  srv_in;          /* replies from the server  */
static LineReader  kbd_in;          /* lines typed by the user  */
static int         use_color;
static int         my_id, my_role;

#define RED    (use_color ? "\033[31m" : "")
#define GREEN  (use_color ? "\033[32m" : "")
#define BOLD   (use_color ? "\033[1m"  : "")
#define RESET  (use_color ? "\033[0m"  : "")

static const char *ROLE_NAMES[] = { "?", "Customer", "Employee", "Manager", "Administrator" };

/* ------------------------------------------------------------ plumbing --- */
static void quit_client(int code)
{
    if (sock >= 0) { net_send_line(sock, "QUIT"); close(sock); }
    printf("Goodbye.\n");
    exit(code);
}

static void connection_lost(void)
{
    printf("\n%sThe server closed the connection.%s (idle timeout, or the server stopped)\n", RED, RESET);
    exit(1);
}

/* Read one line from the user. Returns 0, or -1 at end of input. */
static int ask(const char *prompt, char *buf, size_t n, int secret)
{
    struct termios old, quiet;
    int tty = secret && isatty(STDIN_FILENO);

    if (tty) {                                   /* switch off echo: passwords must not appear on screen */
        tcgetattr(STDIN_FILENO, &old);
        quiet = old;
        quiet.c_lflag &= ~(tcflag_t)ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &quiet);
    }
    printf("%s", prompt);
    fflush(stdout);

    int rc = net_read_line(&kbd_in, buf, n);
    if (tty) { tcsetattr(STDIN_FILENO, TCSANOW, &old); printf("\n"); }

    if (rc == NET_TOO_LONG) { printf("Input too long.\n"); buf[0] = '\0'; return 0; }
    if (rc < 0) return -1;

    char *s = buf;                               /* trim leading/trailing blanks */
    while (*s == ' ' || *s == '\t') s++;
    memmove(buf, s, strlen(s) + 1);
    for (size_t i = strlen(buf); i > 0 && (buf[i - 1] == ' ' || buf[i - 1] == '\t'); i--) buf[i - 1] = '\0';
    return 0;
}

static void ask_or_quit(const char *prompt, char *buf, size_t n, int secret)
{
    if (ask(prompt, buf, n, secret) < 0) { printf("\n"); quit_client(0); }
}

static void read_reply(char *buf, size_t n)
{
    int rc = net_read_line(&srv_in, buf, n);
    if (rc < 0) connection_lost();
}

static int has_blank(const char *s) { return strpbrk(s, " \t") != NULL; }

/* ------------------------------------------------------ friendly errors --- */
static const struct { const char *code, *text; } ERRS[] = {
    { "INVALID_CREDENTIALS",  "Wrong username or password" },
    { "ACCOUNT_LOCKED",       "Account temporarily locked after too many failed attempts" },
    { "ACCOUNT_DEACTIVATED",  "This account is deactivated" },
    { "ALREADY_LOGGED_IN",    "This user is already logged in" },
    { "NOT_LOGGED_IN",        "Please log in first" },
    { "FORBIDDEN",            "You are not allowed to do that" },
    { "INSUFFICIENT_FUNDS",   "Insufficient funds" },
    { "INVALID_AMOUNT",       "Invalid amount" },
    { "NO_SUCH_ACCOUNT",      "No such account" },
    { "SAME_ACCOUNT",         "You cannot transfer to your own account" },
    { "TARGET_UNAVAILABLE",   "The receiving account is not available" },
    { "LIMIT_EXCEEDED",       "That would exceed the allowed limit" },
    { "USERNAME_TAKEN",       "That username is already taken" },
    { "INVALID_USERNAME",     "Invalid username" },
    { "WEAK_PASSWORD",        "Password not acceptable" },
    { "SAME_PASSWORD",        "The new password must differ from the old one" },
    { "NO_SUCH_USER",         "No such user" },
    { "NO_SUCH_LOAN",         "No such loan (or it is not yours to act on)" },
    { "NO_SUCH_EMPLOYEE",     "That user is not an active employee" },
    { "LOAN_NOT_ACTIVE",      "That loan is not currently being repaid" },
    { "LOAN_NOT_ASSIGNABLE",  "That loan has already been decided" },
    { "EXCEEDS_OUTSTANDING",  "That is more than the outstanding amount" },
    { "TOO_MANY_LOANS",       "You already have the maximum number of open loans" },
    { "LOAN_AMOUNT_RANGE",    "Loan amount out of range" },
    { "INVALID_TENURE",       "Invalid tenure" },
    { "INVALID_DATE",         "Invalid date" },
    { "INVALID_RANGE",        "The start date is after the end date" },
    { "INVALID_ROLE",         "Invalid role" },
    { "CANNOT_CHANGE_SELF",   "You cannot do that to your own account" },
    { "FORBIDDEN_TARGET",     "You cannot change that kind of user" },
    { "SERVER_BUSY",          "The server is busy, please try again shortly" },
    { "TOO_LONG",             "Text too long" },
    { "INTERNAL",             "Something went wrong on the server" },
};

static void show_error(const char *reply)
{
    const char *p = reply + 4;                              /* skip "ERR " */
    char code[48];
    size_t i = 0;
    while (p[i] && p[i] != ' ' && i < sizeof code - 1) { code[i] = p[i]; i++; }
    code[i] = '\0';
    const char *rest = p[i] == ' ' ? p + i + 1 : "";

    if (strcmp(code, "IDLE_TIMEOUT") == 0) {
        printf("%sYou were logged out after a period of inactivity.%s\n", RED, RESET);
        exit(1);
    }
    for (size_t k = 0; k < sizeof ERRS / sizeof ERRS[0]; k++) {
        if (strcmp(code, ERRS[k].code) == 0) {
            printf("%sError:%s %s", RED, RESET, ERRS[k].text);
            if (rest[0]) printf(" (%s)", rest);
            printf("\n");
            return;
        }
    }
    printf("%sError:%s %s\n", RED, RESET, p);                /* unknown code: show it as is */
}

/* ----------------------------------------------------------------- tables -- */
#define MAX_COLS 12

static void print_table(const char *const *headers, int ncols, char *lines, int n)
{
    if (n == 0) { printf("  (no records)\n"); return; }

    int width[MAX_COLS];
    char *cell[100][MAX_COLS];
    for (int c = 0; c < ncols; c++) width[c] = (int)strlen(headers[c]);

    for (int r = 0; r < n; r++) {                           /* split each line at '|' */
        char *p = lines + (size_t)r * MAX_LINE;
        for (int c = 0; c < ncols; c++) {
            cell[r][c] = p;
            char *bar = (c < ncols - 1) ? strchr(p, '|') : NULL;
            if (bar) { *bar = '\0'; p = bar + 1; } else p = p + strlen(p);
            int len = (int)strlen(cell[r][c]);
            if (len > width[c]) width[c] = len;
        }
    }
    printf("  %s", BOLD);
    for (int c = 0; c < ncols; c++) printf("%-*s  ", width[c], headers[c]);
    printf("%s\n  ", RESET);
    for (int c = 0; c < ncols; c++) { for (int k = 0; k < width[c]; k++) putchar('-'); printf("  "); }
    printf("\n");
    for (int r = 0; r < n; r++) {
        printf("  ");
        for (int c = 0; c < ncols; c++) printf("%-*s  ", width[c], cell[r][c]);
        printf("\n");
    }
}

static const char *H_TXN[]      = { "Id", "Time (UTC)", "Type", "Amount", "Balance after", "Details" };
static const char *H_LOAN[]     = { "Loan", "Customer", "Account", "Status", "Principal", "Months", "Rate %", "EMI", "Outstanding", "Assigned to", "Applied" };
static const char *H_FEEDBACK[] = { "Id", "Time (UTC)", "Customer", "Message" };
static const char *H_AUDIT[]    = { "Id", "Time (UTC)", "User", "Action", "Details" };

/* ------------------------------------------------------------- menu data -- */
typedef enum {
    K_PLAIN, K_BALANCE, K_TXN, K_REPAY, K_APPLY, K_QUOTE, K_NEWCUST, K_NEWUSER, K_FIND,
    K_T_TXN, K_T_LOAN, K_T_FEEDBACK, K_T_AUDIT
} Kind;

typedef struct {
    const char *prompt;      /* NULL for a literal */
    const char *literal;     /* fixed word inserted into the command (e.g. USERNAME) */
    int secret, optional, text;
} Arg;

typedef struct {
    const char *label;
    const char *cmd;
    Kind        kind;
    Arg         args[4];
} Item;

#define ARG(p)    { .prompt = (p) }
#define SECRET(p) { .prompt = (p), .secret = 1 }
#define OPT(p)    { .prompt = (p), .optional = 1 }
#define TEXT(p)   { .prompt = (p), .text = 1 }
#define LIT(s)    { .literal = (s) }
#define PW_CHANGE { .label = "Change my password", .cmd = "CHANGE_PASS", .kind = K_PLAIN, \
                    .args = { SECRET("Current password"), SECRET("New password") } }

static const Item CUSTOMER[] = {
    { .label = "Check balance",           .cmd = "BALANCE",  .kind = K_BALANCE },
    { .label = "Deposit",                 .cmd = "DEPOSIT",  .kind = K_TXN, .args = { ARG("Amount (Rs)") } },
    { .label = "Withdraw",                .cmd = "WITHDRAW", .kind = K_TXN, .args = { ARG("Amount (Rs)") } },
    { .label = "Transfer to another account", .cmd = "TRANSFER", .kind = K_TXN,
      .args = { ARG("Receiving account number"), ARG("Amount (Rs)") } },
    { .label = "Transaction history",     .cmd = "HISTORY",  .kind = K_T_TXN,
      .args = { OPT("From date YYYY-MM-DD"), OPT("To date YYYY-MM-DD") } },
    { .label = "Loan calculator (EMI)",   .cmd = "LOAN_QUOTE", .kind = K_QUOTE,
      .args = { ARG("Loan amount (Rs)"), ARG("Tenure in months") } },
    { .label = "Apply for a loan",        .cmd = "APPLY_LOAN", .kind = K_APPLY,
      .args = { ARG("Loan amount (Rs)"), ARG("Tenure in months") } },
    { .label = "My loans",                .cmd = "MY_LOANS", .kind = K_T_LOAN },
    { .label = "Repay a loan",            .cmd = "REPAY",    .kind = K_REPAY,
      .args = { ARG("Loan number"), OPT("Amount (Rs), Enter = one EMI") } },
    { .label = "Send feedback",           .cmd = "FEEDBACK", .kind = K_PLAIN, .args = { TEXT("Your message") } },
    PW_CHANGE,
};

static const Item EMPLOYEE[] = {
    { .label = "Add a customer",          .cmd = "ADD_CUSTOMER", .kind = K_NEWCUST,
      .args = { ARG("New username"), SECRET("Initial password"), OPT("Opening deposit (Rs), Enter = none") } },
    { .label = "Rename a customer",       .cmd = "MOD_CUSTOMER", .kind = K_PLAIN,
      .args = { ARG("Customer user id"), LIT("USERNAME"), ARG("New username") } },
    { .label = "Reset a customer's password", .cmd = "MOD_CUSTOMER", .kind = K_PLAIN,
      .args = { ARG("Customer user id"), LIT("PASSWORD"), SECRET("New password") } },
    { .label = "View a customer's passbook", .cmd = "PASSBOOK", .kind = K_T_TXN,
      .args = { ARG("Account number"), OPT("From date YYYY-MM-DD"), OPT("To date YYYY-MM-DD") } },
    { .label = "Find a user by name",     .cmd = "FIND_USER", .kind = K_FIND, .args = { ARG("Username") } },
    { .label = "Loans assigned to me",    .cmd = "VIEW_ASSIGNED", .kind = K_T_LOAN },
    { .label = "Approve / reject a loan", .cmd = "PROCESS_LOAN", .kind = K_PLAIN,
      .args = { ARG("Loan number"), ARG("Decision (APPROVE or REJECT)") } },
    PW_CHANGE,
};

static const Item MANAGER[] = {
    { .label = "Activate / deactivate an account", .cmd = "SET_ACTIVE", .kind = K_PLAIN,
      .args = { ARG("User id"), ARG("1 = activate, 0 = deactivate") } },
    { .label = "Pending loan applications", .cmd = "PENDING_LOANS", .kind = K_T_LOAN },
    { .label = "Assign a loan to an employee", .cmd = "ASSIGN_LOAN", .kind = K_PLAIN,
      .args = { ARG("Loan number"), ARG("Employee user id") } },
    { .label = "Review customer feedback", .cmd = "REVIEW_FEEDBACK", .kind = K_T_FEEDBACK },
    { .label = "Find a user by name",     .cmd = "FIND_USER", .kind = K_FIND, .args = { ARG("Username") } },
    PW_CHANGE,
};

static const Item ADMIN[] = {
    { .label = "Add an employee",         .cmd = "ADD_EMPLOYEE", .kind = K_NEWUSER,
      .args = { ARG("New username"), SECRET("Initial password") } },
    { .label = "Rename a user",           .cmd = "MOD_USER", .kind = K_PLAIN,
      .args = { ARG("User id"), LIT("USERNAME"), ARG("New username") } },
    { .label = "Reset a user's password", .cmd = "MOD_USER", .kind = K_PLAIN,
      .args = { ARG("User id"), LIT("PASSWORD"), SECRET("New password") } },
    { .label = "Change an employee's role", .cmd = "SET_ROLE", .kind = K_PLAIN,
      .args = { ARG("User id"), ARG("New role (2 = employee, 3 = manager)") } },
    { .label = "Activate / deactivate a user", .cmd = "SET_ACTIVE", .kind = K_PLAIN,
      .args = { ARG("User id"), ARG("1 = activate, 0 = deactivate") } },
    { .label = "View audit log",          .cmd = "VIEW_AUDIT", .kind = K_T_AUDIT, .args = { OPT("How many entries (default 20)") } },
    { .label = "Find a user by name",     .cmd = "FIND_USER", .kind = K_FIND, .args = { ARG("Username") } },
    PW_CHANGE,
};

/* ------------------------------------------------------------ one action --- */
static void show_table(Kind kind, const char *reply)
{
    int n = 0;
    if (sscanf(reply, "OK %d", &n) != 1 || n < 0 || n > 100) { printf("Unexpected reply: %s\n", reply); return; }

    char *lines = malloc((size_t)(n ? n : 1) * MAX_LINE);
    if (!lines) return;
    for (int i = 0; i < n; i++) read_reply(lines + (size_t)i * MAX_LINE, MAX_LINE);

    switch (kind) {
    case K_T_TXN:      print_table(H_TXN,      6,  lines, n); break;
    case K_T_LOAN:     print_table(H_LOAN,     11, lines, n); break;
    case K_T_FEEDBACK: print_table(H_FEEDBACK, 4,  lines, n); break;
    default:           print_table(H_AUDIT,    5,  lines, n); break;
    }
    free(lines);
}

static void show_ok(Kind kind, const char *reply)
{
    char a[40], b[40], c[40];
    long long id;
    int x, y, z, w;

    printf("%s", GREEN);
    switch (kind) {
    case K_BALANCE:
        if (sscanf(reply, "OK %d %39s", &x, a) == 2) printf("Account %d - balance: Rs %s", x, a);
        else printf("%s", reply);
        break;
    case K_TXN:
        if (sscanf(reply, "OK %lld %39s", &id, a) == 2) printf("Done. Receipt #%lld. New balance: Rs %s", id, a);
        else printf("%s", reply);
        break;
    case K_REPAY:
        if (sscanf(reply, "OK %lld %39s %39s", &id, a, b) == 3)
            printf("Payment received (receipt #%lld). Balance: Rs %s. Still owed on this loan: Rs %s", id, a, b);
        else printf("%s", reply);
        break;
    case K_APPLY:
        if (sscanf(reply, "OK %d %39s %39s", &x, a, b) == 3)
            printf("Application #%d submitted. Monthly EMI: Rs %s at %s%% per year", x, a, b);
        else printf("%s", reply);
        break;
    case K_QUOTE:
        if (sscanf(reply, "OK %39s %39s %39s", a, b, c) == 3)
            printf("Monthly EMI: Rs %s | Total repayable: Rs %s | Interest rate: %s%% per year", a, b, c);
        else printf("%s", reply);
        break;
    case K_NEWCUST:
        if (sscanf(reply, "OK %d %d", &x, &y) == 2) printf("Customer created. User id %d, account number %d", x, y);
        else printf("%s", reply);
        break;
    case K_NEWUSER:
        if (sscanf(reply, "OK %d", &x) == 1) printf("User created. User id %d", x);
        else printf("%s", reply);
        break;
    case K_FIND:
        if (sscanf(reply, "OK %d %d %d %d", &x, &y, &z, &w) == 4) {
            printf("User id %d | role: %s | %s", x, (y >= 1 && y <= 4) ? ROLE_NAMES[y] : "?",
                   z ? "active" : "DEACTIVATED");
            if (w) printf(" | account number %d", w);
        } else printf("%s", reply);
        break;
    default:
        printf("Done: %s", reply[2] == ' ' ? reply + 3 : reply + 2);
    }
    printf("%s\n", RESET);
}

static void run_item(const Item *it)
{
    char cmd[MAX_LINE], in[MAX_LINE];
    size_t used = (size_t)snprintf(cmd, sizeof cmd, "%s", it->cmd);

    for (int k = 0; k < 4 && (it->args[k].prompt || it->args[k].literal); k++) {
        const Arg *a = &it->args[k];
        if (a->literal) { used += (size_t)snprintf(cmd + used, sizeof cmd - used, " %s", a->literal); continue; }

        char prompt[160];
        snprintf(prompt, sizeof prompt, a->optional ? "  %s (optional): " : "  %s: ", a->prompt);
        ask_or_quit(prompt, in, sizeof in, a->secret);

        if (in[0] == '\0') {
            if (a->optional) break;                          /* skip this and the remaining optional ones */
            printf("Cancelled: a value is required.\n");
            return;
        }
        if (!a->text && has_blank(in)) { printf("Cancelled: spaces are not allowed here.\n"); return; }
        if (used + strlen(in) + 2 >= sizeof cmd)           { printf("Cancelled: input too long.\n"); return; }
        used += (size_t)snprintf(cmd + used, sizeof cmd - used, " %s", in);
    }

    if (net_send_line(sock, "%s", cmd) != 0) connection_lost();
    char reply[MAX_LINE];
    read_reply(reply, sizeof reply);

    if (strncmp(reply, "ERR", 3) == 0) { show_error(reply); return; }
    if (it->kind >= K_T_TXN) show_table(it->kind, reply);
    else                     show_ok(it->kind, reply);
}

static void run_menu(const Item *items, int n)
{
    char in[64];
    for (;;) {
        printf("\n%s=== %s menu (user id %d) ===%s\n", BOLD, ROLE_NAMES[my_role], my_id, RESET);
        for (int i = 0; i < n; i++) printf("  %2d. %s\n", i + 1, items[i].label);
        printf("   0. Log out\n   q. Quit\n");

        ask_or_quit("Choice: ", in, sizeof in, 0);
        if (strcmp(in, "q") == 0 || strcmp(in, "Q") == 0) quit_client(0);
        if (strcmp(in, "0") == 0) {
            char reply[MAX_LINE];
            net_send_line(sock, "LOGOUT");
            read_reply(reply, sizeof reply);
            printf("Logged out.\n");
            return;
        }
        int choice = atoi(in);
        if (choice < 1 || choice > n) { printf("Please choose a number from the menu.\n"); continue; }
        run_item(&items[choice - 1]);
    }
}

/* ----------------------------------------------------------------- login --- */
static void login_screen(void)
{
    char user[MAX_LINE], pass[MAX_LINE], reply[MAX_LINE];
    for (;;) {
        printf("\n%s=== Bank login ===%s\n", BOLD, RESET);
        ask_or_quit("Username (or 'quit'): ", user, sizeof user, 0);
        if (strcmp(user, "quit") == 0) quit_client(0);
        ask_or_quit("Password: ", pass, sizeof pass, 1);

        if (!user[0] || !pass[0] || has_blank(user) || has_blank(pass)) {
            printf("%sError:%s username and password are required and cannot contain spaces\n", RED, RESET);
            continue;
        }
        if (net_send_line(sock, "LOGIN %s %s", user, pass) != 0) connection_lost();
        memset(pass, 0, sizeof pass);                        /* do not keep the password around */
        read_reply(reply, sizeof reply);

        int id, role;
        if (sscanf(reply, "OK LOGGED_IN %d %d", &id, &role) == 2 && role >= 1 && role <= 4) {
            my_id = id; my_role = role;
            printf("%sWelcome! Logged in as %s.%s\n", GREEN, ROLE_NAMES[role], RESET);
            return;
        }
        show_error(reply);
    }
}

/* ------------------------------------------------------------------ main --- */
int main(int argc, char **argv)
{
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    const char *port = argc > 2 ? argv[2] : "8080";

    signal(SIGPIPE, SIG_IGN);
    use_color = isatty(STDOUT_FILENO);
    setvbuf(stdout, NULL, _IOLBF, 0);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0 || !res) {
        fprintf(stderr, "Cannot resolve %s:%s\n", host, port);
        return 1;
    }
    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0 || connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        fprintf(stderr, "Cannot connect to the bank server at %s:%s (%s). Is it running?\n",
                host, port, strerror(errno));
        return 1;
    }
    freeaddrinfo(res);

    net_reader_init(&srv_in, sock);
    net_reader_init(&kbd_in, STDIN_FILENO);

    char banner[MAX_LINE];
    read_reply(banner, sizeof banner);
    if (strncmp(banner, "OK", 2) != 0) { show_error(banner); return 1; }
    printf("Connected to the bank server at %s:%s\n", host, port);

    for (;;) {
        login_screen();
        switch (my_role) {
        case ROLE_CUSTOMER: run_menu(CUSTOMER, (int)(sizeof CUSTOMER / sizeof CUSTOMER[0])); break;
        case ROLE_EMPLOYEE: run_menu(EMPLOYEE, (int)(sizeof EMPLOYEE / sizeof EMPLOYEE[0])); break;
        case ROLE_MANAGER:  run_menu(MANAGER,  (int)(sizeof MANAGER  / sizeof MANAGER[0]));  break;
        default:            run_menu(ADMIN,    (int)(sizeof ADMIN    / sizeof ADMIN[0]));    break;
        }
    }
}
