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
