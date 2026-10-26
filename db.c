/* db.c - database layer */
#include <stdio.h>
#include "common.h"
#include "db.h"

/* ---------------------------------------------------------------- schema -- */
/* Rules baked into the schema itself, so even a buggy handler cannot break them:
 *   - CHECK(balance_paise >= 0)  : an account can never go negative
 *   - FOREIGN KEY ... REFERENCES : no transaction for a non-existent account
 *   - CHECK on role/status/type  : only valid values can be stored
 */
static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS Users("
    "  user_id         INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  username        TEXT    NOT NULL UNIQUE,"
    "  password_hash   TEXT    NOT NULL,"            /* crypt() string: salt is inside */
    "  role            INTEGER NOT NULL CHECK(role BETWEEN 1 AND 4),"
    "  is_active       INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)),"
    "  failed_attempts INTEGER NOT NULL DEFAULT 0,"
    "  locked_until    INTEGER NOT NULL DEFAULT 0"   /* unix time; 0 = not locked */
    ");"

    "CREATE TABLE IF NOT EXISTS Accounts("
    "  account_id    INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  user_id       INTEGER NOT NULL UNIQUE REFERENCES Users(user_id),"
    "  balance_paise INTEGER NOT NULL DEFAULT 0 CHECK(balance_paise >= 0)"
    ");"

    "CREATE TABLE IF NOT EXISTS Transactions("
    "  txn_id              INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  account_id          INTEGER NOT NULL REFERENCES Accounts(account_id),"
    "  type                TEXT    NOT NULL CHECK(type IN "
    "     ('DEPOSIT','WITHDRAW','TRANSFER_OUT','TRANSFER_IN','LOAN_DISBURSE','LOAN_REPAY')),"
    "  amount_paise        INTEGER NOT NULL CHECK(amount_paise > 0),"
    "  balance_after_paise INTEGER NOT NULL,"         /* running balance for the passbook */
    "  details             TEXT,"
    "  created_at          TEXT    NOT NULL DEFAULT (datetime('now'))"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_txn_account_time ON Transactions(account_id, created_at);"

    "CREATE TABLE IF NOT EXISTS Loans("
    "  loan_id           INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  account_id        INTEGER NOT NULL REFERENCES Accounts(account_id),"
    "  assigned_to       INTEGER REFERENCES Users(user_id),"       /* employee */
    "  principal_paise   INTEGER NOT NULL CHECK(principal_paise > 0),"
    "  rate_bp           INTEGER NOT NULL DEFAULT 0,"              /* basis points: 850 = 8.50% */
    "  tenure_months     INTEGER NOT NULL CHECK(tenure_months > 0),"
    "  emi_paise         INTEGER NOT NULL DEFAULT 0,"
    "  outstanding_paise INTEGER NOT NULL DEFAULT 0 CHECK(outstanding_paise >= 0),"
    "  status            TEXT    NOT NULL DEFAULT 'PENDING' CHECK(status IN "
    "     ('PENDING','ASSIGNED','APPROVED','REJECTED','CLOSED')),"
    "  created_at        TEXT    NOT NULL DEFAULT (datetime('now'))"
    ");"

    "CREATE TABLE IF NOT EXISTS Repayments("
    "  repayment_id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  loan_id      INTEGER NOT NULL REFERENCES Loans(loan_id),"
    "  amount_paise INTEGER NOT NULL CHECK(amount_paise > 0),"
    "  paid_at      TEXT    NOT NULL DEFAULT (datetime('now'))"
    ");"

    "CREATE TABLE IF NOT EXISTS Feedback("
    "  feedback_id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  user_id     INTEGER NOT NULL REFERENCES Users(user_id),"
    "  message     TEXT    NOT NULL,"
    "  created_at  TEXT    NOT NULL DEFAULT (datetime('now'))"
    ");"

    "CREATE TABLE IF NOT EXISTS AuditLog("
    "  log_id     INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  user_id    INTEGER,"                            /* NULL for unknown-user login failures */
    "  action     TEXT NOT NULL,"
    "  details    TEXT,"
    "  created_at TEXT NOT NULL DEFAULT (datetime('now'))"
    ");";

/* ------------------------------------------------------------ primitives -- */
int db_log_errors = 1;

int db_exec(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc == SQLITE_OK) return DB_OK;

    if (db_log_errors)
        fprintf(stderr, "db_exec failed: %s\n", err ? err : sqlite3_errmsg(db));
    sqlite3_free(err);
    return (rc == SQLITE_BUSY) ? DB_BUSY : DB_ERR;
}

/* ------------------------------------------------------------ connection -- */
sqlite3 *db_open(const char *path)
{
    sqlite3 *db = NULL;

    /* NOMUTEX: SQLite skips its internal per-connection mutex. That is only
     * safe because each thread owns its connection exclusively. */
    int rc = sqlite3_open_v2(path, &db,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX,
                NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "cannot open %s: %s\n", path, db ? sqlite3_errmsg(db) : "out of memory");
        if (db) sqlite3_close(db);
        return NULL;
    }

    /* If another thread holds the write lock, wait up to this long instead of
     * failing instantly with "database is locked". */
    sqlite3_busy_timeout(db, DB_BUSY_TIMEOUT_MS);

    if (db_exec(db, "PRAGMA foreign_keys = ON;")   != DB_OK ||   /* per-connection! */
        db_exec(db, "PRAGMA journal_mode = WAL;")  != DB_OK ||   /* readers don't block writer */
        db_exec(db, "PRAGMA synchronous = FULL;")  != DB_OK) {   /* fsync on commit = durability */
        sqlite3_close(db);
        return NULL;
    }
    return db;
}

void db_close(sqlite3 *db)
{
    if (db) sqlite3_close(db);
}

int db_init_schema(sqlite3 *db)
{
    return db_exec(db, SCHEMA_SQL);
}

/* ---------------------------------------------------------- transactions -- */
int db_begin(sqlite3 *db)
{
    /* IMMEDIATE = take the write lock NOW, before reading anything.
     * Only one writer can be inside at a time, so "read balance, decide,
     * update balance" can no longer interleave with another client. */
    return db_exec(db, "BEGIN IMMEDIATE;");
}

int db_commit(sqlite3 *db)
{
    int rc = db_exec(db, "COMMIT;");
    if (rc != DB_OK) db_rollback(db);
    return rc;
}

void db_rollback(sqlite3 *db)
{
    /* sqlite3_get_autocommit() is 0 while a transaction is open. */
    if (!sqlite3_get_autocommit(db))
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
}
