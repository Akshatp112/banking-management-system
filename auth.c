/* auth.c - passwords, accounts creation, LOGIN and CHANGE_PASS */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <crypt.h>

#include "auth.h"
#include "audit.h"
#include "db.h"
#include "net.h"
#include "handlers.h"

static char dummy_hash[HASH_MAX];

/* ------------------------------------------------------------ randomness -- */
/* Salts and generated passwords must be unpredictable, so they come from the
 * kernel's random source, read with plain system calls. */
static int rand_bytes(unsigned char *buf, size_t n)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) { close(fd); return -1; }
        got += (size_t)r;
    }
    close(fd);
    return 0;
}

/* 64 symbols, so (byte & 63) picks each one with equal probability. */
static const char ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./";

static int random_string(char *out, size_t len)
{
    unsigned char raw[64];
    if (len > sizeof raw || rand_bytes(raw, len) != 0) return -1;
    for (size_t i = 0; i < len; i++) out[i] = ALPHABET[raw[i] & 63];
    out[len] = '\0';
    return 0;
}

/* --------------------------------------------------------------- hashing -- */
int auth_hash_password(const char *plain, char *out, size_t out_size)
{
    char salt[17], setting[64];
    if (random_string(salt, 16) != 0) return -1;
    snprintf(setting, sizeof setting, "$6$rounds=%d$%s$", PASSWORD_ROUNDS, salt);

    struct crypt_data *cd = calloc(1, sizeof *cd);     /* big struct: keep it off the stack */
    if (!cd) return -1;
    char *res = crypt_r(plain, setting, cd);           /* reentrant: safe with many threads */
    int rc = -1;
    if (res && res[0] != '*' && strlen(res) < out_size) {
        snprintf(out, out_size, "%s", res);
        rc = 0;
    }
    explicit_bzero(cd, sizeof *cd);                    /* don't leave password material in freed memory */
    free(cd);
    return rc;
}

/* Compare without stopping at the first difference, so the time taken does
 * not reveal how many leading characters were right. */
static int const_time_equal(const char *a, const char *b, size_t len)
{
    unsigned char diff = 0;
    for (size_t i = 0; i < len; i++) diff |= (unsigned char)(a[i] ^ b[i]);
    return diff == 0;
}

int auth_verify_password(const char *plain, const char *stored)
{
    struct crypt_data *cd = calloc(1, sizeof *cd);
    if (!cd) return 0;
    /* Hashing 'plain' with the stored string as the "setting" reuses its salt and rounds. */
    char *res = crypt_r(plain, stored, cd);
    int ok = res && res[0] != '*' &&
             strlen(res) == strlen(stored) &&
             const_time_equal(res, stored, strlen(stored));
    explicit_bzero(cd, sizeof *cd);
    free(cd);
    return ok;
}

int auth_init(void)
{
    /* Used so that "no such user" takes as long as "wrong password": otherwise
     * response time would reveal which usernames exist. */
    return auth_hash_password("not-a-real-password", dummy_hash, sizeof dummy_hash);
}

/* ------------------------------------------------------------ validation -- */
int auth_valid_username(const char *name)
{
    size_t n = strlen(name);
    if (n < USERNAME_MIN || n > USERNAME_MAX) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = name[i];
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') || c == '_';
        if (!ok) return 0;
    }
    return 1;
}

int auth_valid_password(const char *pw)
{
    size_t n = strlen(pw);
    if (n < PASSWORD_MIN || n > PASSWORD_MAX) return 0;
    for (size_t i = 0; i < n; i++)
        if (pw[i] < 0x21 || pw[i] > 0x7E) return 0;      /* printable, no spaces (protocol is space-separated) */
    return 1;
}

/* ---------------------------------------------------------- user creation -- */
/* The caller has ALREADY called db_begin() and decides commit/rollback.
 * 'hash' comes from auth_hash_password(), computed BEFORE the transaction so we
 * never hold the write lock while doing slow hashing.
 * A customer also gets an account; a non-zero opening balance is written to the
 * ledger as a DEPOSIT so the books always add up. */
int auth_create_user_tx(sqlite3 *db, const char *username, const char *hash, Role role,
                        paise_t initial_balance_paise, int *user_id_out, int *account_id_out)
{
    sqlite3_stmt *st = NULL;
    int step;
    long long uid, acct = 0;

    if (sqlite3_prepare_v2(db,
            "INSERT INTO Users(username, password_hash, role) VALUES(?1, ?2, ?3);",
            -1, &st, NULL) != SQLITE_OK) return AUTH_ERR;
    sqlite3_bind_text(st, 1, username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, hash,     -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, role);
    step = sqlite3_step(st);
    sqlite3_finalize(st);
    if (step == SQLITE_CONSTRAINT) return AUTH_EXISTS;
    if (step != SQLITE_DONE)       return AUTH_ERR;
    uid = sqlite3_last_insert_rowid(db);

    if (role == ROLE_CUSTOMER) {                          /* only customers hold an account */
        if (sqlite3_prepare_v2(db,
                "INSERT INTO Accounts(user_id, balance_paise) VALUES(?1, ?2);",
                -1, &st, NULL) != SQLITE_OK) return AUTH_ERR;
        sqlite3_bind_int64(st, 1, uid);
        sqlite3_bind_int64(st, 2, initial_balance_paise);
        step = sqlite3_step(st);
        sqlite3_finalize(st);
        if (step != SQLITE_DONE) return AUTH_ERR;
        acct = sqlite3_last_insert_rowid(db);

        if (initial_balance_paise > 0) {
            if (sqlite3_prepare_v2(db,
                    "INSERT INTO Transactions(account_id, type, amount_paise, balance_after_paise, details) "
                    "VALUES(?1, 'DEPOSIT', ?2, ?2, 'opening deposit');",
                    -1, &st, NULL) != SQLITE_OK) return AUTH_ERR;
            sqlite3_bind_int64(st, 1, acct);
            sqlite3_bind_int64(st, 2, initial_balance_paise);
            step = sqlite3_step(st);
            sqlite3_finalize(st);
            if (step != SQLITE_DONE) return AUTH_ERR;
        }
    }
    if (user_id_out)    *user_id_out    = (int)uid;
    if (account_id_out) *account_id_out = (int)acct;
    return AUTH_OK;
}

/* Convenience wrapper that owns the whole transaction (used by bootstrap). */
int auth_create_user(sqlite3 *db, const char *username, const char *password,
                     Role role, paise_t initial_balance_paise, int *user_id_out)
{
    if (!auth_valid_username(username) || !auth_valid_password(password) ||
        role < ROLE_CUSTOMER || role > ROLE_ADMIN ||
        initial_balance_paise < 0 || initial_balance_paise > MAX_TXN_PAISE)
        return AUTH_INVALID;

    char hash[HASH_MAX];
    if (auth_hash_password(password, hash, sizeof hash) != 0) return AUTH_ERR;

    if (db_begin(db) != DB_OK) return AUTH_ERR;
    int rc = auth_create_user_tx(db, username, hash, role, initial_balance_paise, user_id_out, NULL);
    if (rc != AUTH_OK) { db_rollback(db); return rc; }       /* user row AND account row, or neither */
    if (db_commit(db) != DB_OK) return AUTH_ERR;
    return AUTH_OK;
}

/* -------------------------------------------------------------- bootstrap -- */
static int count_users(sqlite3 *db)
{
    sqlite3_stmt *st;
    int n = -1;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM Users;", -1, &st, NULL) != SQLITE_OK) return -1;
    if (sqlite3_step(st) == SQLITE_ROW) n = (int)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return n;
}

int auth_bootstrap(sqlite3 *db, int seed_demo)
{
    if (seed_demo) {
        /* DEMO ONLY: well-known passwords. Never use on a real deployment. */
        static const struct { const char *name, *pw; Role role; paise_t bal; } demo[] = {
            { "cust1",  "Cust@123",  ROLE_CUSTOMER, 500000 },   /* Rs 5000.00 */
            { "cust2",  "Cust@456",  ROLE_CUSTOMER,  20000 },   /* Rs  200.00 */
            { "emp1",   "Emp@123",   ROLE_EMPLOYEE,      0 },
            { "mgr1",   "Mgr@123",   ROLE_MANAGER,       0 },
            { "admin1", "Admin@123", ROLE_ADMIN,         0 },
        };
        int created = 0;
        for (size_t i = 0; i < sizeof demo / sizeof demo[0]; i++) {
            int rc = auth_create_user(db, demo[i].name, demo[i].pw, demo[i].role, demo[i].bal, NULL);
            if (rc == AUTH_OK) created++;
            else if (rc != AUTH_EXISTS) return -1;
        }
        if (created) printf("Demo accounts created (cust1, cust2, emp1, mgr1, admin1) - demo use only.\n");
        return 0;
    }

    int n = count_users(db);
    if (n < 0) return -1;
    if (n > 0) return 0;                                  /* already set up */

    char generated[17];
    const char *pw = getenv("BANK_ADMIN_PASSWORD");
    int from_env = pw && auth_valid_password(pw);
    if (!from_env) {
        if (random_string(generated, 12) != 0) return -1;
        pw = generated;
    }
    if (auth_create_user(db, "admin", pw, ROLE_ADMIN, 0, NULL) != AUTH_OK) return -1;

    if (from_env) printf("First run: created admin account 'admin' (password from BANK_ADMIN_PASSWORD).\n");
    else          printf("First run: created admin account 'admin' with password: %s\n"
                         "           Shown only once - change it after logging in.\n", pw);
    return 0;
}

/* ----------------------------------------------------- login / lockout ---- */
/* Record a wrong password. Doing "+1, and lock if the limit is reached" inside
 * ONE UPDATE statement makes it atomic: if several wrong guesses arrive at the
 * same moment, none is lost. (In step 2 we needed BEGIN IMMEDIATE because we
 * read first and wrote later; here the read and write are the same statement.)
 * Returns 1 if this failure just locked the account. */
static int note_failed_attempt(sqlite3 *db, int user_id)
{
    static const char *sql_update =
        "UPDATE Users SET "
        "  locked_until    = CASE WHEN failed_attempts + 1 >= ?1 THEN ?2 ELSE locked_until END,"
        "  failed_attempts = CASE WHEN failed_attempts + 1 >= ?1 THEN 0  ELSE failed_attempts + 1 END "
        "WHERE user_id = ?3;";
    time_t now = time(NULL);
    sqlite3_stmt *st;

    if (sqlite3_prepare_v2(db, sql_update, -1, &st, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int64(st, 1, MAX_FAILED_ATTEMPTS);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)now + LOCKOUT_SECONDS);
    sqlite3_bind_int64(st, 3, user_id);
    sqlite3_step(st);
    sqlite3_finalize(st);

    int locked = 0;
    if (sqlite3_prepare_v2(db, "SELECT locked_until FROM Users WHERE user_id = ?1;",
                           -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, user_id);
        if (sqlite3_step(st) == SQLITE_ROW) locked = sqlite3_column_int64(st, 0) > now;
        sqlite3_finalize(st);
    }
    return locked;
}

static void clear_failed_attempts(sqlite3 *db, int user_id)
{
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db,
            "UPDATE Users SET failed_attempts = 0 WHERE user_id = ?1 AND failed_attempts <> 0;",
            -1, &st, NULL) != SQLITE_OK) return;
    sqlite3_bind_int64(st, 1, user_id);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

int cmd_login(Session *s, int argc, char **argv, const char *rest)
{
    (void)rest;
    if (s->logged_in) { net_send_line(s->fd, "ERR ALREADY_LOGGED_IN"); return HANDLER_CONTINUE; }
    if (argc != 3)    { net_send_line(s->fd, "ERR USAGE LOGIN username password"); return HANDLER_CONTINUE; }

    const char *uname = argv[1], *pw = argv[2];

    /* Malformed names can't exist in the database; refuse them with the SAME
     * message as a wrong password so nothing about the rules leaks. */
    if (!auth_valid_username(uname) || strlen(pw) > PASSWORD_MAX) {
        audit_log(s->db, 0, "LOGIN_FAIL", "malformed credentials");
        net_send_line(s->fd, "ERR INVALID_CREDENTIALS");
        return HANDLER_CONTINUE;
    }

    /* Look the user up with a bound parameter: the username is data, never SQL. */
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(s->db,
            "SELECT user_id, password_hash, role, is_active, locked_until "
            "FROM Users WHERE username = ?1;", -1, &st, NULL) != SQLITE_OK) {
        net_send_line(s->fd, "ERR INTERNAL");
        return HANDLER_CONTINUE;
    }
    sqlite3_bind_text(st, 1, uname, -1, SQLITE_TRANSIENT);

    int found = 0, uid = 0, role = 0, active = 0;
    long long locked_until = 0;
    char hash[HASH_MAX];
    int step = sqlite3_step(st);
    if (step == SQLITE_ROW) {
        found        = 1;
        uid          = (int)sqlite3_column_int64(st, 0);
        snprintf(hash, sizeof hash, "%s", (const char *)sqlite3_column_text(st, 1));
        role         = (int)sqlite3_column_int64(st, 2);
        active       = (int)sqlite3_column_int64(st, 3);
        locked_until = sqlite3_column_int64(st, 4);
    }
    sqlite3_finalize(st);
    if (step != SQLITE_ROW && step != SQLITE_DONE) {
        net_send_line(s->fd, "ERR INTERNAL");
        return HANDLER_CONTINUE;
    }

    char detail[96];
    if (!found) {
        auth_verify_password(pw, dummy_hash);             /* same time cost as a real check */
        snprintf(detail, sizeof detail, "unknown username '%s' from %s", uname, s->peer);
        audit_log(s->db, 0, "LOGIN_FAIL", detail);
        net_send_line(s->fd, "ERR INVALID_CREDENTIALS");
        return HANDLER_CONTINUE;
    }

    /* Locked accounts are refused BEFORE checking the password; otherwise an
     * attacker could keep guessing during the lock and learn when they hit. */
    long long now = (long long)time(NULL);
    if (locked_until > now) {
        snprintf(detail, sizeof detail, "login while locked from %s", s->peer);
        audit_log(s->db, uid, "LOGIN_BLOCKED", detail);
        net_send_line(s->fd, "ERR ACCOUNT_LOCKED retry_in=%lld", locked_until - now);
        return HANDLER_CONTINUE;
    }

    if (!auth_verify_password(pw, hash)) {
        int locked = note_failed_attempt(s->db, uid);
        snprintf(detail, sizeof detail, "wrong password from %s", s->peer);
        audit_log(s->db, uid, "LOGIN_FAIL", detail);
        if (locked) audit_log(s->db, uid, "ACCOUNT_LOCKED", "too many failed attempts");
        net_send_line(s->fd, "ERR INVALID_CREDENTIALS");
        return HANDLER_CONTINUE;
    }

    /* Password is right. Only now do we reveal the account's state. */
    if (!active) {
        audit_log(s->db, uid, "LOGIN_DENIED", "account deactivated");
        net_send_line(s->fd, "ERR ACCOUNT_DEACTIVATED");
        return HANDLER_CONTINUE;
    }
    if (role < ROLE_CUSTOMER || role > ROLE_ADMIN) {
        net_send_line(s->fd, "ERR INTERNAL");
        return HANDLER_CONTINUE;
    }

    clear_failed_attempts(s->db, uid);

    if (session_try_login(s, uid, (Role)role) == SESSION_ALREADY) {
        audit_log(s->db, uid, "LOGIN_DENIED", "already logged in elsewhere");
        net_send_line(s->fd, "ERR ALREADY_LOGGED_IN");
        return HANDLER_CONTINUE;
    }

    snprintf(detail, sizeof detail, "from %s", s->peer);
    audit_log(s->db, uid, "LOGIN_OK", detail);
    net_send_line(s->fd, "OK LOGGED_IN %d %d", uid, role);
    return HANDLER_CONTINUE;
}

int cmd_change_pass(Session *s, int argc, char **argv, const char *rest)
{
    (void)rest;
    if (argc != 3) { net_send_line(s->fd, "ERR USAGE CHANGE_PASS old new"); return HANDLER_CONTINUE; }
    const char *oldpw = argv[1], *newpw = argv[2];

    if (!auth_valid_password(newpw)) {
        net_send_line(s->fd, "ERR WEAK_PASSWORD need %d-%d visible characters, no spaces", PASSWORD_MIN, PASSWORD_MAX);
        return HANDLER_CONTINUE;
    }
    if (strcmp(oldpw, newpw) == 0) {
        net_send_line(s->fd, "ERR SAME_PASSWORD");
        return HANDLER_CONTINUE;
    }

    char hash[HASH_MAX] = "";
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(s->db, "SELECT password_hash FROM Users WHERE user_id = ?1;",
                           -1, &st, NULL) != SQLITE_OK) {
        net_send_line(s->fd, "ERR INTERNAL");
        return HANDLER_CONTINUE;
    }
    sqlite3_bind_int64(st, 1, s->user_id);
    if (sqlite3_step(st) == SQLITE_ROW)
        snprintf(hash, sizeof hash, "%s", (const char *)sqlite3_column_text(st, 0));
    sqlite3_finalize(st);

    if (!hash[0] || !auth_verify_password(oldpw, hash)) {
        /* Wrong old password counts towards lockout too: someone at an
         * unattended terminal must not be able to guess it freely. */
        note_failed_attempt(s->db, s->user_id);
        audit_log(s->db, s->user_id, "PASSWORD_CHANGE_FAIL", "wrong current password");
        net_send_line(s->fd, "ERR INVALID_CREDENTIALS");
        return HANDLER_CONTINUE;
    }

    char newhash[HASH_MAX];
    if (auth_hash_password(newpw, newhash, sizeof newhash) != 0 ||
        sqlite3_prepare_v2(s->db, "UPDATE Users SET password_hash = ?1 WHERE user_id = ?2;",
                           -1, &st, NULL) != SQLITE_OK) {
        net_send_line(s->fd, "ERR INTERNAL");
        return HANDLER_CONTINUE;
    }
    sqlite3_bind_text(st, 1, newhash, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, s->user_id);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);

    if (rc != SQLITE_DONE) { net_send_line(s->fd, "ERR INTERNAL"); return HANDLER_CONTINUE; }
    audit_log(s->db, s->user_id, "PASSWORD_CHANGED", "");
    net_send_line(s->fd, "OK PASSWORD_CHANGED");
    return HANDLER_CONTINUE;
}
