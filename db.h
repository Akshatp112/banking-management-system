/* db.h - database layer: connection setup, schema, transaction helpers */
#ifndef DB_H
#define DB_H

#include <sqlite3.h>

#define DB_OK     0
#define DB_ERR   -1
#define DB_BUSY  -2   /* another writer held the lock longer than the timeout */

/* 1 = db_exec prints failures to stderr (default). Tests set 0 for expected errors. */
extern int db_log_errors;

/* Open ONE connection. Every worker thread opens its own and never shares it.
 * Returns NULL on failure. */
sqlite3 *db_open(const char *path);
void     db_close(sqlite3 *db);

/* Create all tables if they do not exist. Call once at server start-up. */
int db_init_schema(sqlite3 *db);

/* Run a fixed SQL string that contains NO user input (schema, pragmas, BEGIN...).
 * For anything involving user data use sqlite3_prepare_v2 + sqlite3_bind_*. */
int db_exec(sqlite3 *db, const char *sql);

/* Transactions. Pattern for every money-changing handler:
 *
 *     if (db_begin(db) != DB_OK) return error;
 *     ... check + update ...        // all inside the transaction
 *     if (failed) { db_rollback(db); return error; }
 *     return db_commit(db);
 */
int  db_begin(sqlite3 *db);      /* BEGIN IMMEDIATE: takes the write lock now */
int  db_commit(sqlite3 *db);
void db_rollback(sqlite3 *db);   /* safe to call even if no transaction is open */

#endif /* DB_H */
