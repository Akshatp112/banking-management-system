/* auth.h - password hashing, user creation, login and password-change commands */
#ifndef AUTH_H
#define AUTH_H

#include <stddef.h>
#include <sqlite3.h>
#include "common.h"

#define AUTH_OK       0
#define AUTH_EXISTS  -1    /* username already taken */
#define AUTH_INVALID -2    /* username/password/amount failed validation */
#define AUTH_ERR     -3    /* database or system failure */

#define HASH_MAX 256

/* Call once at start-up, before any thread exists. */
int auth_init(void);

/* Salted SHA-512 via crypt_r(). 'out' receives one string containing the
 * algorithm, rounds, random salt and hash, e.g. $6$rounds=50000$<salt>$<hash>. */
int auth_hash_password(const char *plain, char *out, size_t out_size);
int auth_verify_password(const char *plain, const char *stored);   /* 1 = match */

int auth_valid_username(const char *name);
int auth_valid_password(const char *pw);

/* Create a user (and, for customers, an account with initial_balance_paise).
 * One transaction: either everything is created or nothing is. */
int auth_create_user(sqlite3 *db, const char *username, const char *password,
                     Role role, paise_t initial_balance_paise, int *user_id_out);

/* Same, but inside a transaction the CALLER opened (so it can add more steps,
 * e.g. an audit row, before committing). 'hash' is the output of auth_hash_password. */
int auth_create_user_tx(sqlite3 *db, const char *username, const char *hash, Role role,
                        paise_t initial_balance_paise, int *user_id_out, int *account_id_out);

/* First-run setup. If there are no users, creates an 'admin' account
 * (password from $BANK_ADMIN_PASSWORD, or random and printed once).
 * With seed_demo, creates sample accounts for every role instead. */
int auth_bootstrap(sqlite3 *db, int seed_demo);

#endif
