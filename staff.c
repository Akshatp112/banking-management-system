/* staff.c - employee, manager and admin commands
 *
 * WHO may run a command is decided in the command table (server.c).
 * This file decides WHICH TARGETS a role may touch:
 *     employee -> customers only
 *     manager  -> customers only (activate / deactivate)
 *     admin    -> any user except themselves, and never changes an admin's role
 * Every change is audited inside the same transaction that makes it, so the log
 * can never claim something that was rolled back, or miss something that stuck.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "common.h"
#include "db.h"
#include "audit.h"
#include "auth.h"
#include "net.h"
#include "money.h"
#include "accounts.h"
#include "handlers.h"

#define ROLE_BIT(r) (1u << (r))

/* ------------------------------------------------------------- helpers ---- */
typedef struct {
    int  id;
    char name[USERNAME_MAX + 1];
    int  role;
    int  active;
    int  account_id;       /* 0 if the user has no account */
} UserRow;

static const char *SQL_USER_BY_ID =
    "SELECT u.user_id, u.username, u.role, u.is_active, COALESCE(a.account_id, 0) "
    "FROM Users u LEFT JOIN Accounts a ON a.user_id = u.user_id WHERE u.user_id = ?1;";
static const char *SQL_USER_BY_NAME =
    "SELECT u.user_id, u.username, u.role, u.is_active, COALESCE(a.account_id, 0) "
    "FROM Users u LEFT JOIN Accounts a ON a.user_id = u.user_id WHERE u.username = ?1;";

/* 1 = found, 0 = none, -1 = error. Pass either an id or a name. */
static int load_user(sqlite3 *db, int by_id, int id, const char *name, UserRow *u)
{
    sqlite3_stmt *st;
    int rc, result = -1;

    if (sqlite3_prepare_v2(db, by_id ? SQL_USER_BY_ID : SQL_USER_BY_NAME, -1, &st, NULL) != SQLITE_OK)
        return -1;
    if (by_id) sqlite3_bind_int64(st, 1, id);
    else       sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        u->id = (int)sqlite3_column_int64(st, 0);
        snprintf(u->name, sizeof u->name, "%s", (const char *)sqlite3_column_text(st, 1));
        u->role       = (int)sqlite3_column_int64(st, 2);
        u->active     = (int)sqlite3_column_int64(st, 3);
        u->account_id = (int)sqlite3_column_int64(st, 4);
        result = 1;
    } else if (rc == SQLITE_DONE) {
        result = 0;
    }
    sqlite3_finalize(st);
    return result;
}

static void reply_begin_failure(Session *s, int rc)
{
    net_send_line(s->fd, rc == DB_BUSY ? "ERR SERVER_BUSY retry shortly" : "ERR INTERNAL");
}

static int run_update(sqlite3 *db, const char *sql, const char *text1, long long int1, long long int2)
{
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int idx = 1;
    if (text1) sqlite3_bind_text(st, idx++, text1, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, idx++, int1);
    if (int2 >= 0) sqlite3_bind_int64(st, idx++, int2);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : (rc == SQLITE_CONSTRAINT ? -2 : -1);
}

/* Generic "send these rows": every column is joined with '|'.
 * Only for listings whose columns are already text-friendly. */
#define ROW_LINE 400
static void reply_rows(Session *s, sqlite3_stmt *st, int max_rows)
{
    char *lines = malloc((size_t)max_rows * ROW_LINE);
    if (!lines) { sqlite3_finalize(st); net_send_line(s->fd, "ERR INTERNAL"); return; }

    int n = 0, rc, cols = sqlite3_column_count(st);
    while ((rc = sqlite3_step(st)) == SQLITE_ROW && n < max_rows) {
        char *line = lines + (size_t)n * ROW_LINE;
        size_t used = 0;
        line[0] = '\0';
        for (int c = 0; c < cols && used < ROW_LINE - 1; c++) {
            const char *t = (const char *)sqlite3_column_text(st, c);
            used += (size_t)snprintf(line + used, ROW_LINE - used, "%s%s", c ? "|" : "", t ? t : "");
        }
        n++;
    }
    sqlite3_finalize(st);

    if (rc != SQLITE_DONE && rc != SQLITE_ROW) net_send_line(s->fd, "ERR INTERNAL");
    else {
        net_send_line(s->fd, "OK %d", n);
        for (int i = 0; i < n; i++) net_send_line(s->fd, "%s", lines + (size_t)i * ROW_LINE);
    }
    free(lines);
}

/* ============================================================ EMPLOYEE ==== */

/* Shared by ADD_CUSTOMER and ADD_EMPLOYEE */
static int create_user_command(Session *s, int argc, char **argv, Role role, const char *audit_action)
{
    paise_t initial = 0;
    int max_args = (role == ROLE_CUSTOMER) ? 4 : 3;

    if (argc < 3 || argc > max_args) {
        net_send_line(s->fd, role == ROLE_CUSTOMER ? "ERR USAGE ADD_CUSTOMER username password [opening_deposit]"
                                                   : "ERR USAGE ADD_EMPLOYEE username password");
        return HANDLER_CONTINUE;
    }
    if (!auth_valid_username(argv[1])) {
        net_send_line(s->fd, "ERR INVALID_USERNAME %d-%d letters, digits or underscore", USERNAME_MIN, USERNAME_MAX);
        return HANDLER_CONTINUE;
    }
    if (!auth_valid_password(argv[2])) {
        net_send_line(s->fd, "ERR WEAK_PASSWORD need %d-%d visible characters, no spaces", PASSWORD_MIN, PASSWORD_MAX);
        return HANDLER_CONTINUE;
    }
    if (argc == 4 && money_parse(argv[3], &initial) != 0) {
        net_send_line(s->fd, "ERR INVALID_AMOUNT");
        return HANDLER_CONTINUE;
    }

    char hash[HASH_MAX];
    if (auth_hash_password(argv[2], hash, sizeof hash) != 0) {       /* slow: do it BEFORE taking the lock */
        net_send_line(s->fd, "ERR INTERNAL");
        return HANDLER_CONTINUE;
    }

    int rc = db_begin(s->db);
    if (rc != DB_OK) { reply_begin_failure(s, rc); return HANDLER_CONTINUE; }

    int uid = 0, acct = 0;
    rc = auth_create_user_tx(s->db, argv[1], hash, role, initial, &uid, &acct);
    if (rc == AUTH_EXISTS) { db_rollback(s->db); net_send_line(s->fd, "ERR USERNAME_TAKEN"); return HANDLER_CONTINUE; }
    if (rc != AUTH_OK)     { db_rollback(s->db); net_send_line(s->fd, "ERR INTERNAL");       return HANDLER_CONTINUE; }

    char detail[96];
    snprintf(detail, sizeof detail, "created '%s' (user %d)", argv[1], uid);
    audit_log(s->db, s->user_id, audit_action, detail);

    if (db_commit(s->db) != DB_OK) { net_send_line(s->fd, "ERR INTERNAL"); return HANDLER_CONTINUE; }

    if (role == ROLE_CUSTOMER) net_send_line(s->fd, "OK %d %d", uid, acct);   /* user id, account id */
    else                       net_send_line(s->fd, "OK %d", uid);
    return HANDLER_CONTINUE;
}

int cmd_add_customer(Session *s, int argc, char **argv, const char *rest)
{ (void)rest; return create_user_command(s, argc, argv, ROLE_CUSTOMER, "ADD_CUSTOMER"); }

int cmd_add_employee(Session *s, int argc, char **argv, const char *rest)
{ (void)rest; return create_user_command(s, argc, argv, ROLE_EMPLOYEE, "ADD_EMPLOYEE"); }

/* Shared by MOD_CUSTOMER (employee, customers only) and MOD_USER (admin, anyone).
 *   <cmd> user_id USERNAME new_name
 *   <cmd> user_id PASSWORD new_password      (also clears any login lockout) */
static int modify_command(Session *s, int argc, char **argv, unsigned allowed_targets, const char *audit_action)
{
    int target_id;
    if (argc != 4 || id_parse(argv[1], &target_id) != 0) {
        net_send_line(s->fd, "ERR USAGE %s user_id USERNAME|PASSWORD value", argv[0]);
        return HANDLER_CONTINUE;
    }
    int is_name = strcasecmp(argv[2], "USERNAME") == 0, is_pass = strcasecmp(argv[2], "PASSWORD") == 0;
    if (!is_name && !is_pass) { net_send_line(s->fd, "ERR USAGE field must be USERNAME or PASSWORD"); return HANDLER_CONTINUE; }

    char hash[HASH_MAX] = "";
    if (is_name && !auth_valid_username(argv[3])) { net_send_line(s->fd, "ERR INVALID_USERNAME"); return HANDLER_CONTINUE; }
    if (is_pass) {
        if (!auth_valid_password(argv[3])) { net_send_line(s->fd, "ERR WEAK_PASSWORD"); return HANDLER_CONTINUE; }
        if (auth_hash_password(argv[3], hash, sizeof hash) != 0) { net_send_line(s->fd, "ERR INTERNAL"); return HANDLER_CONTINUE; }
    }

    int rc = db_begin(s->db);
    if (rc != DB_OK) { reply_begin_failure(s, rc); return HANDLER_CONTINUE; }

    /* Look at the target INSIDE the transaction: its role cannot change between the check and the update. */
    UserRow u;
    int f = load_user(s->db, 1, target_id, NULL, &u);
    const char *err = NULL;
    if (f < 0)  { err = "INTERNAL"; goto fail; }
    if (f == 0 || !(allowed_targets & ROLE_BIT(u.role))) { err = "NO_SUCH_USER"; goto fail; }   /* don't reveal who exists */

    if (is_name) rc = run_update(s->db, "UPDATE Users SET username = ?1 WHERE user_id = ?2;", argv[3], target_id, -1);
    else         rc = run_update(s->db, "UPDATE Users SET password_hash = ?1, failed_attempts = 0, locked_until = 0 "
                                        "WHERE user_id = ?2;", hash, target_id, -1);
    if (rc == -2) { err = "USERNAME_TAKEN"; goto fail; }
    if (rc != 0)  { err = "INTERNAL";       goto fail; }

    char detail[96];                                                  /* never log the new password */
    if (is_name) snprintf(detail, sizeof detail, "user %d renamed '%s' -> '%s'", u.id, u.name, argv[3]);
    else         snprintf(detail, sizeof detail, "password reset for user %d ('%s')", u.id, u.name);
    audit_log(s->db, s->user_id, audit_action, detail);

    if (db_commit(s->db) != DB_OK) { net_send_line(s->fd, "ERR INTERNAL"); return HANDLER_CONTINUE; }
    net_send_line(s->fd, "OK UPDATED");
    return HANDLER_CONTINUE;

fail:
    db_rollback(s->db);
    net_send_line(s->fd, "ERR %s", err);
    return HANDLER_CONTINUE;
}

int cmd_mod_customer(Session *s, int argc, char **argv, const char *rest)
{ (void)rest; return modify_command(s, argc, argv, ROLE_BIT(ROLE_CUSTOMER), "MOD_CUSTOMER"); }

int cmd_mod_user(Session *s, int argc, char **argv, const char *rest)
{
    (void)rest;
    unsigned all = ROLE_BIT(ROLE_CUSTOMER) | ROLE_BIT(ROLE_EMPLOYEE) | ROLE_BIT(ROLE_MANAGER) | ROLE_BIT(ROLE_ADMIN);
    return modify_command(s, argc, argv, all, "MOD_USER");
}

int cmd_passbook(Session *s, int argc, char **argv, const char *rest)
{
    (void)rest;
    int acct_id;
    if ((argc != 2 && argc != 4) || id_parse(argv[1], &acct_id) != 0) {
        net_send_line(s->fd, "ERR USAGE PASSBOOK account_id [from_date to_date]");
        return HANDLER_CONTINUE;
    }
    const char *from, *to;
    if (history_parse_range(s, argc == 4 ? 2 : 0, argv + 2, &from, &to) != 0) return HANDLER_CONTINUE;

    AcctInfo a;
    int f = account_by_id(s->db, acct_id, &a);
    if (f < 0)  { net_send_line(s->fd, "ERR INTERNAL");        return HANDLER_CONTINUE; }
    if (f == 0) { net_send_line(s->fd, "ERR NO_SUCH_ACCOUNT"); return HANDLER_CONTINUE; }

    char detail[64];                                                  /* viewing someone's finances is itself logged */
    snprintf(detail, sizeof detail, "viewed passbook of account %d", acct_id);
    audit_log(s->db, s->user_id, "PASSBOOK_VIEW", detail);
    history_send(s, a.account_id, from, to);
    return HANDLER_CONTINUE;
}

/* FIND_USER username -> "OK user_id role active account_id" (employees see customers only) */
int cmd_find_user(Session *s, int argc, char **argv, const char *rest)
{
    (void)rest;
    if (argc != 2) { net_send_line(s->fd, "ERR USAGE FIND_USER username"); return HANDLER_CONTINUE; }

    UserRow u;
    int f = auth_valid_username(argv[1]) ? load_user(s->db, 0, 0, argv[1], &u) : 0;
    if (f < 0) { net_send_line(s->fd, "ERR INTERNAL"); return HANDLER_CONTINUE; }
    if (f == 0 || (s->role == ROLE_EMPLOYEE && u.role != ROLE_CUSTOMER)) {
        net_send_line(s->fd, "ERR NO_SUCH_USER");
        return HANDLER_CONTINUE;
    }
    net_send_line(s->fd, "OK %d %d %d %d", u.id, u.role, u.active, u.account_id);
    return HANDLER_CONTINUE;
}
