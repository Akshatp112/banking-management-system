/* accounts.h - account lookups and history output, shared with the staff commands */
#ifndef ACCOUNTS_H
#define ACCOUNTS_H

#include <sqlite3.h>
#include "common.h"
#include "session.h"

typedef struct { int account_id; paise_t balance; int active; } AcctInfo;

/* 1 = found, 0 = no such account, -1 = database error. 'active' is the owner's is_active flag. */
int account_by_user(sqlite3 *db, int user_id,    AcctInfo *a);
int account_by_id  (sqlite3 *db, int account_id, AcctInfo *a);

/* Change a balance (call inside a transaction). 0 = ok, -1 = error. */
int account_set_balance(sqlite3 *db, int account_id, paise_t new_balance);

/* Append one ledger row (call inside the same transaction as the balance change).
 * Returns the new txn_id, or -1. type: DEPOSIT, WITHDRAW, TRANSFER_OUT, TRANSFER_IN, LOAN_DISBURSE, LOAN_REPAY. */
long long ledger_record(sqlite3 *db, int account_id, const char *type,
                        paise_t amount, paise_t balance_after, const char *details);

/* Validate optional "from to" dates. ndates is 0 (use defaults) or 2.
 * On a bad date/range it sends the ERR line itself and returns -1. */
int  history_parse_range(Session *s, int ndates, char **dates, const char **from, const char **to);

/* Send "OK n" followed by n rows, newest first (max HISTORY_MAX_ROWS). */
void history_send(Session *s, int account_id, const char *from, const char *to);

#endif
