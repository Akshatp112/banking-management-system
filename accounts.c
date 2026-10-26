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
