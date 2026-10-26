/* session.c */
#include <pthread.h>
#include <semaphore.h>
#include "session.h"

static sem_t           slots;                       /* counts free client slots */
static pthread_mutex_t active_lock = PTHREAD_MUTEX_INITIALIZER;
static int             active_users[MAX_CLIENTS];   /* user_ids that are logged in right now */
static int             active_count = 0;

void session_global_init(void)
{
    sem_init(&slots, 0, MAX_CLIENTS);   /* starts at MAX_CLIENTS free slots */
}

int client_slot_try_acquire(void)
{
    return sem_trywait(&slots) == 0;    /* decrement if > 0, else fail immediately */
}

void client_slot_release(void)
{
    sem_post(&slots);                   /* increment: a slot is free again */
}

int session_try_login(Session *s, int user_id, Role role)
{
    int rc = SESSION_OK;

    /* The check "is he already in?" and the insert "now he is in" must be ONE
     * indivisible step, otherwise two simultaneous logins both pass the check.
     * The mutex makes it indivisible. */
    pthread_mutex_lock(&active_lock);
    for (int i = 0; i < active_count; i++) {
        if (active_users[i] == user_id) { rc = SESSION_ALREADY; break; }
    }
    if (rc == SESSION_OK && active_count < MAX_CLIENTS)
        active_users[active_count++] = user_id;
    pthread_mutex_unlock(&active_lock);

    if (rc == SESSION_OK) {
        s->logged_in = 1;
        s->user_id   = user_id;
        s->role      = role;
    }
    return rc;
}

void session_logout(Session *s)
{
    if (!s->logged_in) return;

    pthread_mutex_lock(&active_lock);
    for (int i = 0; i < active_count; i++) {
        if (active_users[i] == s->user_id) {
            active_users[i] = active_users[--active_count];   /* swap-remove */
            break;
        }
    }
    pthread_mutex_unlock(&active_lock);

    s->logged_in = 0;
    s->user_id   = 0;
    s->role      = ROLE_NONE;
}

int session_revalidate(Session *s)
{
    sqlite3_stmt *st;
    int result = SESSION_ERROR;

    if (sqlite3_prepare_v2(s->db, "SELECT role, is_active FROM Users WHERE user_id = ?1;",
                           -1, &st, NULL) != SQLITE_OK) return SESSION_ERROR;
    sqlite3_bind_int64(st, 1, s->user_id);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        int role = (int)sqlite3_column_int64(st, 0), active = (int)sqlite3_column_int64(st, 1);
        if (!active || role < ROLE_CUSTOMER || role > ROLE_ADMIN) result = SESSION_REVOKED;
        else { s->role = (Role)role; result = SESSION_OK; }
    } else if (rc == SQLITE_DONE) {
        result = SESSION_REVOKED;                          /* user no longer exists */
    }
    sqlite3_finalize(st);
    return result;
}
