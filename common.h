/* common.h - constants shared by every module */
#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

#define DEFAULT_PORT       8080

#ifndef MAX_CLIENTS
#define MAX_CLIENTS        50        /* size of the semaphore: max simultaneous clients */
#endif
#ifndef IDLE_TIMEOUT_SEC
#define IDLE_TIMEOUT_SEC   300       /* drop a client that sends nothing for this long */
#endif
#define MAX_LINE           512       /* longest accepted request line */
#define MAX_ARGS           8

/* Login protection (overridable at compile time so tests can use small values) */
#ifndef MAX_FAILED_ATTEMPTS
#define MAX_FAILED_ATTEMPTS 5        /* wrong passwords in a row before the account locks */
#endif
#ifndef LOCKOUT_SECONDS
#define LOCKOUT_SECONDS     300      /* how long the account stays locked */
#endif
#ifndef PASSWORD_ROUNDS
#define PASSWORD_ROUNDS     50000    /* SHA-512 rounds: higher = slower for attackers */
#endif
#define USERNAME_MIN 3
#define USERNAME_MAX 20
#define PASSWORD_MIN 6
#define PASSWORD_MAX 64

/* Money limits (in paise) */
#define MAX_TXN_PAISE      1000000000LL        /* Rs 1,00,00,000.00 per single transaction */
#define MAX_BALANCE_PAISE  100000000000000LL   /* keeps balance arithmetic far from overflow */
#define HISTORY_MAX_ROWS   100

/* Loan policy */
#define LOAN_MIN_PAISE     100000LL            /* Rs 1,000 */
#define LOAN_MAX_PAISE     100000000LL         /* Rs 10,00,000 */
#define LOAN_MAX_MONTHS    120
#define LOAN_MAX_OPEN      3                   /* pending + assigned + running loans per customer */

#define DB_PATH            "bank.db"
#define LOCK_PATH          "bank.lock"
#define DB_BUSY_TIMEOUT_MS 5000      /* how long a writer waits for another writer */

/* Money is ALWAYS an integer number of paise (1 rupee = 100 paise).
 * Never use float/double for money: 0.1 + 0.2 != 0.3 in binary floating point. */
typedef int64_t paise_t;

/* Roles. The server reads the role from the database at login and keeps it
 * in the session. The client never sends it. */
typedef enum {
    ROLE_NONE     = 0,
    ROLE_CUSTOMER = 1,
    ROLE_EMPLOYEE = 2,
    ROLE_MANAGER  = 3,
    ROLE_ADMIN    = 4
} Role;

#endif /* COMMON_H */
