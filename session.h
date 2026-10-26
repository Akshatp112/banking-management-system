/* session.h - per-connection state, the one-session-per-user table, client-slot semaphore */
#ifndef SESSION_H
#define SESSION_H

#include <sqlite3.h>
#include "common.h"

#define SESSION_OK        0
#define SESSION_ALREADY  -1    /* this user is already logged in on another connection */
#define SESSION_REVOKED  -2    /* the account has been deactivated since login */
#define SESSION_ERROR    -3

/* Everything the server knows about one connected client.
 * user_id and role are set ONLY by session_try_login(), after the server has
 * verified the user. The client can never set or change them. */
typedef struct {
    int       fd;
    sqlite3  *db;          /* this thread's own database connection */
    int       logged_in;
    int       user_id;
    Role      role;
    char      peer[48];    /* "ip:port" for log messages */
} Session;

void session_global_init(void);

/* Semaphore: at most MAX_CLIENTS connections are served at once. */
int  client_slot_try_acquire(void);    /* 1 = got a slot, 0 = server full */
void client_slot_release(void);

/* Mark this connection as user_id/role. Fails if that user is already logged in elsewhere. */
int  session_try_login(Session *s, int user_id, Role role);

/* Re-read this user's role and active flag from the database. A login only
 * proves who someone WAS a minute ago. If a manager deactivated the account or
 * an admin changed the role since, the session must not keep the old powers.
 * Updates s->role when it changed. Returns SESSION_OK, SESSION_REVOKED or SESSION_ERROR. */
int  session_revalidate(Session *s);

/* Log out (also called automatically when the connection ends, even after a crash). */
void session_logout(Session *s);

#endif
