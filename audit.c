/* audit.c */
#include <stdio.h>
#include "audit.h"

void audit_log(sqlite3 *db, int user_id, const char *action, const char *details)
{
    sqlite3_stmt *st = NULL;
    const char *sql = "INSERT INTO AuditLog(user_id, action, details) VALUES(?1, ?2, ?3);";

    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "audit: prepare failed: %s\n", sqlite3_errmsg(db));
        return;
    }
    if (user_id > 0) sqlite3_bind_int64(st, 1, user_id);
    else             sqlite3_bind_null(st, 1);
    sqlite3_bind_text(st, 2, action,  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, details ? details : "", -1, SQLITE_TRANSIENT);

    if (sqlite3_step(st) != SQLITE_DONE)
        fprintf(stderr, "audit: insert failed: %s\n", sqlite3_errmsg(db));
    sqlite3_finalize(st);
}
