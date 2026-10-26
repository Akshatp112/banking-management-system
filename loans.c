/* loans.c - the loan lifecycle
 *
 *     customer APPLY_LOAN        -> PENDING
 *     manager  ASSIGN_LOAN       -> ASSIGNED   (to one employee; may be reassigned until decided)
 *     employee PROCESS_LOAN      -> APPROVED (money is credited)  or  REJECTED
 *     customer REPAY ...         -> APPROVED (balance shrinks)    ...  CLOSED (fully repaid)
 *
 * Money rules:
 *   - EMI is computed ONCE, at application time, and rounded to a whole paisa.
 *     Everything after that is exact integer arithmetic.
 *   - Total payable = EMI x months (fixed schedule). Prepaying does not reduce
 *     interest: a deliberate simplification, stated in the README.
 *   - Every step that moves money changes the balance, the loan and the ledger
 *     in ONE transaction, and every state change re-checks the loan's state
 *     INSIDE that transaction, so two actors can never both "win".
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "common.h"
#include "db.h"
#include "audit.h"
#include "net.h"
#include "money.h"
#include "accounts.h"
#include "handlers.h"

/* ------------------------------------------------------------- the maths -- */
/* Annual interest in basis points (100 bp = 1%), by tenure. */
static int loan_rate_bp(int months)
{
    if (months <= 12) return 900;
    if (months <= 36) return 1000;
    return 1100;
}

/* Standard EMI formula:  EMI = P * r * (1+r)^n / ((1+r)^n - 1),  r = annual rate / 12.
 * (1+r)^n is built by repeated multiplication, so no math library is needed. */
static paise_t compute_emi(paise_t principal, int rate_bp, int months)
{
    if (rate_bp == 0) return (principal + months - 1) / months;      /* round up: never collect less than P */

    long double r = (long double)rate_bp / 10000.0L / 12.0L;
    long double growth = 1.0L;
    for (int i = 0; i < months; i++) growth *= (1.0L + r);

    long double emi = (long double)principal * r * growth / (growth - 1.0L);
    paise_t p = (paise_t)(emi + 0.5L);                               /* nearest paisa */
    return p < 1 ? 1 : p;
}

static void fmt_rate(int rate_bp, char *buf, size_t n)
{
    snprintf(buf, n, "%d.%02d", rate_bp / 100, rate_bp % 100);
}

static int parse_principal_and_months(Session *s, char **argv, paise_t *principal, int *months)
{
    if (money_parse(argv[1], principal) != 0) {
        net_send_line(s->fd, "ERR INVALID_AMOUNT use e.g. 50000 or 50000.50");
        return -1;
    }
    if (*principal < LOAN_MIN_PAISE || *principal > LOAN_MAX_PAISE) {
        char lo[32], hi[32];
        money_format(LOAN_MIN_PAISE, lo, sizeof lo);
        money_format(LOAN_MAX_PAISE, hi, sizeof hi);
        net_send_line(s->fd, "ERR LOAN_AMOUNT_RANGE between %s and %s", lo, hi);
        return -1;
    }
    if (id_parse(argv[2], months) != 0 || *months > LOAN_MAX_MONTHS) {
        net_send_line(s->fd, "ERR INVALID_TENURE 1-%d months", LOAN_MAX_MONTHS);
        return -1;
    }
    return 0;
}

static void reply_begin_failure(Session *s, int rc)
{
    net_send_line(s->fd, rc == DB_BUSY ? "ERR SERVER_BUSY retry shortly" : "ERR INTERNAL");
}

/* -------------------------------------------------------------- listings -- */
/* Same columns for every loan listing:
 *   loan_id|customer|account|status|principal|months|rate%|emi|outstanding|assigned_to|created */
#define LOAN_SELECT \
    "SELECT l.loan_id, cu.username, l.account_id, l.status, l.principal_paise, l.tenure_months, " \
    "       l.rate_bp, l.emi_paise, l.outstanding_paise, COALESCE(eu.username, '-'), l.created_at " \
    "FROM Loans l JOIN Accounts a ON a.account_id = l.account_id " \
    "JOIN Users cu ON cu.user_id = a.user_id " \
    "LEFT JOIN Users eu ON eu.user_id = l.assigned_to "

#define LOAN_LINE 220
#define LOAN_ROWS 100

static void reply_loans(Session *s, const char *sql, int bind_user_id)
{
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(s->db, sql, -1, &st, NULL) != SQLITE_OK) {
        net_send_line(s->fd, "ERR INTERNAL");
        return;
    }
    if (bind_user_id) sqlite3_bind_int64(st, 1, s->user_id);

    char *lines = malloc((size_t)LOAN_ROWS * LOAN_LINE);
    if (!lines) { sqlite3_finalize(st); net_send_line(s->fd, "ERR INTERNAL"); return; }

    int n = 0, rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW && n < LOAN_ROWS) {
        char principal[32], emi[32], outstanding[32], rate[16];
        money_format(sqlite3_column_int64(st, 4), principal, sizeof principal);
        fmt_rate((int)sqlite3_column_int64(st, 6), rate, sizeof rate);
        money_format(sqlite3_column_int64(st, 7), emi, sizeof emi);
        money_format(sqlite3_column_int64(st, 8), outstanding, sizeof outstanding);
        snprintf(lines + (size_t)n * LOAN_LINE, LOAN_LINE, "%lld|%s|%lld|%s|%s|%d|%s|%s|%s|%s|%s",
                 (long long)sqlite3_column_int64(st, 0), (const char *)sqlite3_column_text(st, 1),
                 (long long)sqlite3_column_int64(st, 2), (const char *)sqlite3_column_text(st, 3),
                 principal, (int)sqlite3_column_int64(st, 5), rate, emi, outstanding,
                 (const char *)sqlite3_column_text(st, 9), (const char *)sqlite3_column_text(st, 10));
        n++;
    }
    sqlite3_finalize(st);

    if (rc != SQLITE_DONE && rc != SQLITE_ROW) net_send_line(s->fd, "ERR INTERNAL");
    else {
        net_send_line(s->fd, "OK %d", n);
        for (int i = 0; i < n; i++) net_send_line(s->fd, "%s", lines + (size_t)i * LOAN_LINE);
    }
    free(lines);
}

/* ------------------------------------------------------------ one loan row -- */
typedef struct {
    long long id;
    int       account_id;
    int       assigned_to;       /* 0 = nobody */
    paise_t   principal, emi, outstanding;
    int       months;
    char      status[16];
} Loan;

/* 1 = found, 0 = none, -1 = error.  owner_user_id > 0 restricts to that customer's loans. */
static int load_loan(sqlite3 *db, long long loan_id, int owner_user_id, Loan *l)
{
    sqlite3_stmt *st;
    int rc, result = -1;
    if (sqlite3_prepare_v2(db,
            "SELECT l.loan_id, l.account_id, COALESCE(l.assigned_to, 0), l.principal_paise, "
            "       l.emi_paise, l.outstanding_paise, l.tenure_months, l.status "
            "FROM Loans l JOIN Accounts a ON a.account_id = l.account_id "
            "WHERE l.loan_id = ?1 AND (?2 = 0 OR a.user_id = ?2);", -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int64(st, 1, loan_id);
    sqlite3_bind_int64(st, 2, owner_user_id);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        l->id          = sqlite3_column_int64(st, 0);
        l->account_id  = (int)sqlite3_column_int64(st, 1);
        l->assigned_to = (int)sqlite3_column_int64(st, 2);
        l->principal   = sqlite3_column_int64(st, 3);
        l->emi         = sqlite3_column_int64(st, 4);
        l->outstanding = sqlite3_column_int64(st, 5);
        l->months      = (int)sqlite3_column_int64(st, 6);
        snprintf(l->status, sizeof l->status, "%s", (const char *)sqlite3_column_text(st, 7));
        result = 1;
    } else if (rc == SQLITE_DONE) {
        result = 0;
    }
    sqlite3_finalize(st);
    return result;
}

/* UPDATE helper: up to three integer parameters, ?1..?3 (pass -1 for unused trailing ones). */
static int exec3(sqlite3 *db, const char *sql, long long a, long long b, long long c)
{
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int64(st, 1, a);
    if (b >= 0) sqlite3_bind_int64(st, 2, b);
    if (c >= 0) sqlite3_bind_int64(st, 3, c);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* ================================================================ CUSTOMER == */

/* LOAN_QUOTE amount months -> "OK emi total_payable rate%" (changes nothing) */
int cmd_loan_quote(Session *s, int argc, char **argv, const char *rest)
{
    (void)rest;
    paise_t principal; int months;
    if (argc != 3) { net_send_line(s->fd, "ERR USAGE LOAN_QUOTE amount months"); return HANDLER_CONTINUE; }
    if (parse_principal_and_months(s, argv, &principal, &months) != 0) return HANDLER_CONTINUE;

    int rate = loan_rate_bp(months);
    paise_t emi = compute_emi(principal, rate, months);
    char e[32], t[32], r[16];
    money_format(emi, e, sizeof e);
    money_format(emi * months, t, sizeof t);
    fmt_rate(rate, r, sizeof r);
    net_send_line(s->fd, "OK %s %s %s", e, t, r);
    return HANDLER_CONTINUE;
}

/* APPLY_LOAN amount months -> "OK loan_id emi rate%" */
int cmd_apply_loan(Session *s, int argc, char **argv, const char *rest)
{
    (void)rest;
    paise_t principal; int months;
    if (argc != 3) { net_send_line(s->fd, "ERR USAGE APPLY_LOAN amount months"); return HANDLER_CONTINUE; }
    if (parse_principal_and_months(s, argv, &principal, &months) != 0) return HANDLER_CONTINUE;

    int rate = loan_rate_bp(months);
    paise_t emi = compute_emi(principal, rate, months);

    int rc = db_begin(s->db);
    if (rc != DB_OK) { reply_begin_failure(s, rc); return HANDLER_CONTINUE; }

    const char *err = NULL;
    AcctInfo a;
    sqlite3_stmt *st = NULL;
    long long loan_id = 0;

    int f = account_by_user(s->db, s->user_id, &a);
    if (f < 0)  { err = "INTERNAL"; goto fail; }
    if (f == 0) { err = "NO_ACCOUNT"; goto fail; }

    /* The open-loan limit is checked under the write lock, so two simultaneous
     * applications cannot both slip under it. */
    if (sqlite3_prepare_v2(s->db,
            "SELECT COUNT(*) FROM Loans WHERE account_id = ?1 AND status IN ('PENDING','ASSIGNED','APPROVED');",
            -1, &st, NULL) != SQLITE_OK) { err = "INTERNAL"; goto fail; }
    sqlite3_bind_int64(st, 1, a.account_id);
    int open = (sqlite3_step(st) == SQLITE_ROW) ? (int)sqlite3_column_int64(st, 0) : LOAN_MAX_OPEN;
    sqlite3_finalize(st); st = NULL;
    if (open >= LOAN_MAX_OPEN) { err = "TOO_MANY_LOANS"; goto fail; }

    if (sqlite3_prepare_v2(s->db,
            "INSERT INTO Loans(account_id, principal_paise, rate_bp, tenure_months, emi_paise) "
            "VALUES(?1, ?2, ?3, ?4, ?5);", -1, &st, NULL) != SQLITE_OK) { err = "INTERNAL"; goto fail; }
    sqlite3_bind_int64(st, 1, a.account_id);
    sqlite3_bind_int64(st, 2, principal);
    sqlite3_bind_int64(st, 3, rate);
    sqlite3_bind_int64(st, 4, months);
    sqlite3_bind_int64(st, 5, emi);
    int step = sqlite3_step(st);
    sqlite3_finalize(st); st = NULL;
    if (step != SQLITE_DONE) { err = "INTERNAL"; goto fail; }
    loan_id = sqlite3_last_insert_rowid(s->db);

    char detail[96], money[32];
    money_format(principal, money, sizeof money);
    snprintf(detail, sizeof detail, "loan %lld: Rs %s for %d months", loan_id, money, months);
    audit_log(s->db, s->user_id, "LOAN_APPLIED", detail);

    if (db_commit(s->db) != DB_OK) { net_send_line(s->fd, "ERR INTERNAL"); return HANDLER_CONTINUE; }

    char e[32], r[16];
    money_format(emi, e, sizeof e);
    fmt_rate(rate, r, sizeof r);
    net_send_line(s->fd, "OK %lld %s %s", loan_id, e, r);
    return HANDLER_CONTINUE;

fail:
    if (st) sqlite3_finalize(st);
    db_rollback(s->db);
    net_send_line(s->fd, "ERR %s", err);
    return HANDLER_CONTINUE;
}

int cmd_my_loans(Session *s, int argc, char **argv, const char *rest)
{
    (void)argv; (void)rest;
    if (argc != 1) { net_send_line(s->fd, "ERR USAGE MY_LOANS"); return HANDLER_CONTINUE; }
    reply_loans(s, LOAN_SELECT "WHERE a.user_id = ?1 ORDER BY l.loan_id DESC LIMIT 100;", 1);
    return HANDLER_CONTINUE;
}

/* REPAY loan_id [amount]   (no amount = pay one EMI, or whatever is left if less)
 * -> "OK txn_id balance outstanding" */
int cmd_repay(Session *s, int argc, char **argv, const char *rest)
{
    (void)rest;
    int loan_id;
    paise_t amt = 0;
    if ((argc != 2 && argc != 3) || id_parse(argv[1], &loan_id) != 0) {
        net_send_line(s->fd, "ERR USAGE REPAY loan_id [amount]");
        return HANDLER_CONTINUE;
    }
    if (argc == 3 && money_parse(argv[2], &amt) != 0) {
        net_send_line(s->fd, "ERR INVALID_AMOUNT");
        return HANDLER_CONTINUE;
    }

    int rc = db_begin(s->db);
    if (rc != DB_OK) { reply_begin_failure(s, rc); return HANDLER_CONTINUE; }

    const char *err = NULL;
    Loan l;
    AcctInfo a;
    long long txn_id;

    int f = load_loan(s->db, loan_id, s->user_id, &l);                  /* only MY loans are visible */
    if (f < 0)  { err = "INTERNAL"; goto fail; }
    if (f == 0) { err = "NO_SUCH_LOAN"; goto fail; }
    if (strcmp(l.status, "APPROVED") != 0) { err = "LOAN_NOT_ACTIVE"; goto fail; }

    if (argc == 2) amt = l.emi < l.outstanding ? l.emi : l.outstanding;
    if (amt > l.outstanding) { err = "EXCEEDS_OUTSTANDING"; goto fail; }

    f = account_by_user(s->db, s->user_id, &a);
    if (f < 0)  { err = "INTERNAL"; goto fail; }
    if (f == 0) { err = "NO_ACCOUNT"; goto fail; }
    if (!a.active) { err = "ACCOUNT_DEACTIVATED"; goto fail; }
    if (a.balance < amt) { err = "INSUFFICIENT_FUNDS"; goto fail; }

    paise_t new_balance = a.balance - amt, new_outstanding = l.outstanding - amt;
    if (account_set_balance(s->db, a.account_id, new_balance) != 0 ||
        exec3(s->db, "UPDATE Loans SET outstanding_paise = ?1, status = CASE WHEN ?1 = 0 THEN 'CLOSED' ELSE status END "
                     "WHERE loan_id = ?2;", new_outstanding, l.id, -1) != 0 ||
        exec3(s->db, "INSERT INTO Repayments(loan_id, amount_paise) VALUES(?1, ?2);", l.id, amt, -1) != 0) {
        err = "INTERNAL"; goto fail;
    }
    char detail[64];
    snprintf(detail, sizeof detail, "loan %lld repayment", l.id);
    txn_id = ledger_record(s->db, a.account_id, "LOAN_REPAY", amt, new_balance, detail);
    if (txn_id < 0) { err = "INTERNAL"; goto fail; }

    if (new_outstanding == 0) audit_log(s->db, s->user_id, "LOAN_CLOSED", detail);

    if (db_commit(s->db) != DB_OK) { net_send_line(s->fd, "ERR INTERNAL"); return HANDLER_CONTINUE; }

    char bal[32], out[32];
    money_format(new_balance, bal, sizeof bal);
    money_format(new_outstanding, out, sizeof out);
    net_send_line(s->fd, "OK %lld %s %s", txn_id, bal, out);
    return HANDLER_CONTINUE;

fail:
    db_rollback(s->db);
    net_send_line(s->fd, "ERR %s", err);
    return HANDLER_CONTINUE;
}
