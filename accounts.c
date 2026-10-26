/* accounts.c - BALANCE, DEPOSIT, WITHDRAW, TRANSFER, HISTORY (customer commands)
 *
 * The pattern in every money-changing handler:
 *
 *     parse + validate input            (no database yet)
 *     db_begin()                        (BEGIN IMMEDIATE: we now own the write lock)
 *     read what we need, check rules    (nobody can change it under us)
 *     change balances + write ledger    (+ audit row for transfers)
 *     db_commit()                       (the all-or-nothing point)
 *     ONLY NOW tell the client "OK"     (never promise before the commit succeeded)
 *
 * Any failure on the way jumps to 'fail', which rolls everything back.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "db.h"
#include "audit.h"
#include "net.h"
#include "handlers.h"
#include "money.h"
#include "accounts.h"

/* ------------------------------------------------------------ db helpers --- */
static const char *SQL_ACCT_BY_USER =
    "SELECT a.account_id, a.balance_paise, u.is_active "
    "FROM Accounts a JOIN Users u ON u.user_id = a.user_id WHERE a.user_id = ?1;";
static const char *SQL_ACCT_BY_ID =
    "SELECT a.account_id, a.balance_paise, u.is_active "
    "FROM Accounts a JOIN Users u ON u.user_id = a.user_id WHERE a.account_id = ?1;";

/* 1 = found, 0 = no such account, -1 = database error */
static int load_account(sqlite3 *db, const char *sql, int key, AcctInfo *a)
{
    sqlite3_stmt *st;
    int rc, result = -1;

    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int64(st, 1, key);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        a->account_id = (int)sqlite3_column_int64(st, 0);
        a->balance    = sqlite3_column_int64(st, 1);
        a->active     = (int)sqlite3_column_int64(st, 2);
        result = 1;
    } else if (rc == SQLITE_DONE) {
        result = 0;
    }
    sqlite3_finalize(st);
    return result;
}

int account_by_user(sqlite3 *db, int user_id, AcctInfo *a)
{ return load_account(db, SQL_ACCT_BY_USER, user_id, a); }

int account_by_id(sqlite3 *db, int account_id, AcctInfo *a)
{ return load_account(db, SQL_ACCT_BY_ID, account_id, a); }

int account_set_balance(sqlite3 *db, int account_id, paise_t new_balance)
{
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db, "UPDATE Accounts SET balance_paise = ?1 WHERE account_id = ?2;",
                           -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int64(st, 1, new_balance);
    sqlite3_bind_int64(st, 2, account_id);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* Append one ledger row; returns its txn_id, or -1 */
long long ledger_record(sqlite3 *db, int account_id, const char *type,
                            paise_t amount, paise_t balance_after, const char *details)
{
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO Transactions(account_id, type, amount_paise, balance_after_paise, details) "
            "VALUES(?1, ?2, ?3, ?4, ?5);", -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int64(st, 1, account_id);
    sqlite3_bind_text (st, 2, type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, amount);
    sqlite3_bind_int64(st, 4, balance_after);
    sqlite3_bind_text (st, 5, details, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? sqlite3_last_insert_rowid(db) : -1;
}

static void reply_begin_failure(Session *s, int rc)
{
    if (rc == DB_BUSY) net_send_line(s->fd, "ERR SERVER_BUSY retry shortly");
    else               net_send_line(s->fd, "ERR INTERNAL");
}

/* ------------------------------------------------------------- BALANCE ---- */
int cmd_balance(Session *s, int argc, char **argv, const char *rest)
{
    (void)argv; (void)rest;
    if (argc != 1) { net_send_line(s->fd, "ERR USAGE BALANCE"); return HANDLER_CONTINUE; }

    AcctInfo a;
    int rc = load_account(s->db, SQL_ACCT_BY_USER, s->user_id, &a);   /* one statement: no transaction needed */
    if (rc < 0)  { net_send_line(s->fd, "ERR INTERNAL");   return HANDLER_CONTINUE; }
    if (rc == 0) { net_send_line(s->fd, "ERR NO_ACCOUNT"); return HANDLER_CONTINUE; }

    char money[32];
    money_format(a.balance, money, sizeof money);
    net_send_line(s->fd, "OK %d %s", a.account_id, money);
    return HANDLER_CONTINUE;
}

/* ------------------------------------------------ DEPOSIT and WITHDRAW ---- */
static int cash_operation(Session *s, int argc, char **argv, int is_deposit)
{
    const char *usage = is_deposit ? "ERR USAGE DEPOSIT amount" : "ERR USAGE WITHDRAW amount";
    paise_t amt;
    if (argc != 2) { net_send_line(s->fd, "%s", usage); return HANDLER_CONTINUE; }
    if (money_parse(argv[1], &amt) != 0) {
        net_send_line(s->fd, "ERR INVALID_AMOUNT use e.g. 250 or 250.75 (max 1 crore)");
        return HANDLER_CONTINUE;
    }

    const char *err = NULL;
    long long txn_id = -1;
    paise_t new_balance = 0;
    AcctInfo a;

    int rc = db_begin(s->db);                                         /* take the write lock FIRST */
    if (rc != DB_OK) { reply_begin_failure(s, rc); return HANDLER_CONTINUE; }

    int found = load_account(s->db, SQL_ACCT_BY_USER, s->user_id, &a);
    if (found < 0)  { err = "INTERNAL";   goto fail; }
    if (found == 0) { err = "NO_ACCOUNT"; goto fail; }
    if (!a.active)  { err = "ACCOUNT_DEACTIVATED"; goto fail; }       /* may have changed since login */

    if (is_deposit) {
        if (a.balance > MAX_BALANCE_PAISE - amt) { err = "LIMIT_EXCEEDED"; goto fail; }
        new_balance = a.balance + amt;
    } else {
        if (a.balance < amt) { err = "INSUFFICIENT_FUNDS"; goto fail; }   /* checked under the lock */
        new_balance = a.balance - amt;
    }

    if (account_set_balance(s->db, a.account_id, new_balance) != 0) { err = "INTERNAL"; goto fail; }
    txn_id = ledger_record(s->db, a.account_id, is_deposit ? "DEPOSIT" : "WITHDRAW",
                        amt, new_balance, is_deposit ? "cash deposit" : "cash withdrawal");
    if (txn_id < 0) { err = "INTERNAL"; goto fail; }

    if (db_commit(s->db) != DB_OK) { net_send_line(s->fd, "ERR INTERNAL"); return HANDLER_CONTINUE; }

    char money[32];
    money_format(new_balance, money, sizeof money);
    net_send_line(s->fd, "OK %lld %s", txn_id, money);               /* reply only AFTER the commit */
    return HANDLER_CONTINUE;

fail:
    db_rollback(s->db);
    net_send_line(s->fd, "ERR %s", err);
    return HANDLER_CONTINUE;
}

int cmd_deposit(Session *s, int argc, char **argv, const char *rest)
{ (void)rest; return cash_operation(s, argc, argv, 1); }

int cmd_withdraw(Session *s, int argc, char **argv, const char *rest)
{ (void)rest; return cash_operation(s, argc, argv, 0); }

/* ------------------------------------------------------------ TRANSFER ---- */
int cmd_transfer(Session *s, int argc, char **argv, const char *rest)
{
    (void)rest;
    int to_id;
    paise_t amt;

    if (argc != 3) { net_send_line(s->fd, "ERR USAGE TRANSFER to_account amount"); return HANDLER_CONTINUE; }
    if (id_parse(argv[1], &to_id) != 0)    { net_send_line(s->fd, "ERR NO_SUCH_ACCOUNT"); return HANDLER_CONTINUE; }
    if (money_parse(argv[2], &amt) != 0) {
        net_send_line(s->fd, "ERR INVALID_AMOUNT use e.g. 250 or 250.75 (max 1 crore)");
        return HANDLER_CONTINUE;
    }

    const char *err = NULL;
    AcctInfo from, to;
    long long txn_id = -1;
    char detail[96], money_amt[32];

    int rc = db_begin(s->db);
    if (rc != DB_OK) { reply_begin_failure(s, rc); return HANDLER_CONTINUE; }

    int f = load_account(s->db, SQL_ACCT_BY_USER, s->user_id, &from);
    if (f < 0)  { err = "INTERNAL";   goto fail; }
    if (f == 0) { err = "NO_ACCOUNT"; goto fail; }
    if (!from.active) { err = "ACCOUNT_DEACTIVATED"; goto fail; }

    int t = load_account(s->db, SQL_ACCT_BY_ID, to_id, &to);
    if (t < 0)  { err = "INTERNAL"; goto fail; }
    if (t == 0) { err = "NO_SUCH_ACCOUNT"; goto fail; }               /* the senior's code lost the money here */
    if (to.account_id == from.account_id) { err = "SAME_ACCOUNT"; goto fail; }
    if (!to.active) { err = "TARGET_UNAVAILABLE"; goto fail; }

    if (from.balance < amt)                        { err = "INSUFFICIENT_FUNDS"; goto fail; }
    if (to.balance > MAX_BALANCE_PAISE - amt)      { err = "LIMIT_EXCEEDED";     goto fail; }

    paise_t from_after = from.balance - amt, to_after = to.balance + amt;

    /* Both sides change inside ONE transaction: either both happen or neither. */
    if (account_set_balance(s->db, from.account_id, from_after) != 0 ||
        account_set_balance(s->db, to.account_id,   to_after)   != 0) { err = "INTERNAL"; goto fail; }

    snprintf(detail, sizeof detail, "to account %d", to.account_id);
    txn_id = ledger_record(s->db, from.account_id, "TRANSFER_OUT", amt, from_after, detail);
    snprintf(detail, sizeof detail, "from account %d", from.account_id);
    if (txn_id < 0 ||
        ledger_record(s->db, to.account_id, "TRANSFER_IN", amt, to_after, detail) < 0) { err = "INTERNAL"; goto fail; }

    money_format(amt, money_amt, sizeof money_amt);
    snprintf(detail, sizeof detail, "account %d -> account %d, Rs %s", from.account_id, to.account_id, money_amt);
    audit_log(s->db, s->user_id, "TRANSFER", detail);                 /* inside the transaction: logged iff it happened */

    if (db_commit(s->db) != DB_OK) { net_send_line(s->fd, "ERR INTERNAL"); return HANDLER_CONTINUE; }

    char money_bal[32];
    money_format(from_after, money_bal, sizeof money_bal);
    net_send_line(s->fd, "OK %lld %s", txn_id, money_bal);
    return HANDLER_CONTINUE;

fail:
    db_rollback(s->db);
    net_send_line(s->fd, "ERR %s", err);
    return HANDLER_CONTINUE;
}

/* ------------------------------------------------------------- HISTORY ---- */
/* True only for real calendar dates in YYYY-MM-DD form. SQLite normalises
 * impossible dates (2024-02-30 -> 2024-03-01), so "date(x) == x" catches them. */
static int valid_date(sqlite3 *db, const char *d)
{
    if (strlen(d) != 10 || d[4] != '-' || d[7] != '-') return 0;
    for (int i = 0; i < 10; i++)
        if (i != 4 && i != 7 && (d[i] < '0' || d[i] > '9')) return 0;

    sqlite3_stmt *st;
    int ok = 0;
    if (sqlite3_prepare_v2(db, "SELECT date(?1) = ?1;", -1, &st, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(st, 1, d, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) ok = sqlite3_column_int64(st, 0) == 1;
    sqlite3_finalize(st);
    return ok;
}

int history_parse_range(Session *s, int ndates, char **dates, const char **from, const char **to)
{
    *from = "1970-01-01";
    *to   = "2999-12-31";
    if (ndates == 0) return 0;

    if (!valid_date(s->db, dates[0]) || !valid_date(s->db, dates[1])) {
        net_send_line(s->fd, "ERR INVALID_DATE use YYYY-MM-DD");
        return -1;
    }
    if (strcmp(dates[0], dates[1]) > 0) { net_send_line(s->fd, "ERR INVALID_RANGE"); return -1; }
    *from = dates[0];
    *to   = dates[1];
    return 0;
}

#define HISTORY_LINE 160

void history_send(Session *s, int account_id, const char *from, const char *to)
{
    /* Collect rows first so we can announce the count ("OK n") before the rows. */
    char *lines = malloc((size_t)HISTORY_MAX_ROWS * HISTORY_LINE);
    if (!lines) { net_send_line(s->fd, "ERR INTERNAL"); return; }

    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(s->db,
            "SELECT txn_id, created_at, type, amount_paise, balance_after_paise, COALESCE(details,'') "
            "FROM Transactions "
            "WHERE account_id = ?1 AND created_at >= ?2 AND created_at < date(?3, '+1 day') "
            "ORDER BY txn_id DESC LIMIT ?4;", -1, &st, NULL) != SQLITE_OK) {
        free(lines);
        net_send_line(s->fd, "ERR INTERNAL");
        return;
    }
    sqlite3_bind_int64(st, 1, account_id);
    sqlite3_bind_text (st, 2, from, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (st, 3, to,   -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, HISTORY_MAX_ROWS);

    int n = 0, rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW && n < HISTORY_MAX_ROWS) {
        char amt[32], bal[32];
        money_format(sqlite3_column_int64(st, 3), amt, sizeof amt);
        money_format(sqlite3_column_int64(st, 4), bal, sizeof bal);
        snprintf(lines + (size_t)n * HISTORY_LINE, HISTORY_LINE, "%lld|%s|%s|%s|%s|%s",
                 (long long)sqlite3_column_int64(st, 0),
                 (const char *)sqlite3_column_text(st, 1),
                 (const char *)sqlite3_column_text(st, 2),
                 amt, bal,
                 (const char *)sqlite3_column_text(st, 5));
        n++;
    }
    sqlite3_finalize(st);

    if (rc != SQLITE_DONE && rc != SQLITE_ROW) net_send_line(s->fd, "ERR INTERNAL");
    else {
        net_send_line(s->fd, "OK %d", n);
        for (int i = 0; i < n; i++) net_send_line(s->fd, "%s", lines + (size_t)i * HISTORY_LINE);
    }
    free(lines);
}

int cmd_history(Session *s, int argc, char **argv, const char *rest)
{
    (void)rest;
    if (argc != 1 && argc != 3) {
        net_send_line(s->fd, "ERR USAGE HISTORY [from_date to_date]  (YYYY-MM-DD)");
        return HANDLER_CONTINUE;
    }
    const char *from, *to;
    if (history_parse_range(s, argc == 3 ? 2 : 0, argv + 1, &from, &to) != 0) return HANDLER_CONTINUE;

    AcctInfo a;
    int found = account_by_user(s->db, s->user_id, &a);
    if (found < 0)  { net_send_line(s->fd, "ERR INTERNAL");   return HANDLER_CONTINUE; }
    if (found == 0) { net_send_line(s->fd, "ERR NO_ACCOUNT"); return HANDLER_CONTINUE; }

    history_send(s, a.account_id, from, to);
    return HANDLER_CONTINUE;
}

/* ------------------------------------------------------------ FEEDBACK ---- */
#define FEEDBACK_MAX 400

int cmd_feedback(Session *s, int argc, char **argv, const char *rest)
{
    (void)argv;
    if (argc < 2 || rest[0] == '\0') { net_send_line(s->fd, "ERR USAGE FEEDBACK your message"); return HANDLER_CONTINUE; }

    char msg[FEEDBACK_MAX + 1];
    size_t len = strlen(rest);
    if (len > FEEDBACK_MAX) { net_send_line(s->fd, "ERR TOO_LONG max %d characters", FEEDBACK_MAX); return HANDLER_CONTINUE; }
    memcpy(msg, rest, len + 1);
    while (len > 0 && (msg[len - 1] == ' ' || msg[len - 1] == '\t')) msg[--len] = '\0';
    for (size_t i = 0; i < len; i++)                    /* '|' separates columns in listings */
        if (msg[i] == '|' || msg[i] == '\t') msg[i] = (msg[i] == '|') ? '/' : ' ';

    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(s->db, "INSERT INTO Feedback(user_id, message) VALUES(?1, ?2);",
                           -1, &st, NULL) != SQLITE_OK) {
        net_send_line(s->fd, "ERR INTERNAL");
        return HANDLER_CONTINUE;
    }
    sqlite3_bind_int64(st, 1, s->user_id);
    sqlite3_bind_text (st, 2, msg, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);

    if (rc != SQLITE_DONE) net_send_line(s->fd, "ERR INTERNAL");
    else net_send_line(s->fd, "OK %lld", (long long)sqlite3_last_insert_rowid(s->db));
    return HANDLER_CONTINUE;
}
