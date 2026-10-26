/* audit.h - append-only record of who did what */
#ifndef AUDIT_H
#define AUDIT_H

#include <sqlite3.h>

/* user_id <= 0 means "nobody identified" (e.g. login attempt for an unknown name).
 * Never fails the caller: a logging problem must not break a banking operation. */
void audit_log(sqlite3 *db, int user_id, const char *action, const char *details);

#endif
