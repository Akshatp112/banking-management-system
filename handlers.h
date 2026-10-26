/* handlers.h - the shape every command handler has, plus the handlers each module exports */
#ifndef HANDLERS_H
#define HANDLERS_H

#include "session.h"

#define HANDLER_CONTINUE 0     /* keep serving this client */
#define HANDLER_CLOSE    1     /* close the connection after the handler returns */

/* argv[0] is the command word, argv[1..argc-1] the arguments.
 * 'rest' points at the raw text after the command word (for free-text input). */
typedef int (*Handler)(Session *s, int argc, char **argv, const char *rest);

/* auth.c */
int cmd_login(Session *s, int argc, char **argv, const char *rest);
int cmd_change_pass(Session *s, int argc, char **argv, const char *rest);

/* accounts.c (customers) */
int cmd_balance(Session *s, int argc, char **argv, const char *rest);
int cmd_deposit(Session *s, int argc, char **argv, const char *rest);
int cmd_withdraw(Session *s, int argc, char **argv, const char *rest);
int cmd_transfer(Session *s, int argc, char **argv, const char *rest);
int cmd_history(Session *s, int argc, char **argv, const char *rest);
int cmd_feedback(Session *s, int argc, char **argv, const char *rest);

/* loans.c */
int cmd_loan_quote(Session *s, int argc, char **argv, const char *rest);     /* customer */
int cmd_apply_loan(Session *s, int argc, char **argv, const char *rest);     /* customer */
int cmd_my_loans(Session *s, int argc, char **argv, const char *rest);       /* customer */
int cmd_repay(Session *s, int argc, char **argv, const char *rest);          /* customer */
int cmd_pending_loans(Session *s, int argc, char **argv, const char *rest);  /* manager  */
int cmd_assign_loan(Session *s, int argc, char **argv, const char *rest);    /* manager  */
int cmd_view_assigned(Session *s, int argc, char **argv, const char *rest);  /* employee */
int cmd_process_loan(Session *s, int argc, char **argv, const char *rest);   /* employee */

/* staff.c (employee / manager / admin) */
int cmd_add_customer(Session *s, int argc, char **argv, const char *rest);
int cmd_mod_customer(Session *s, int argc, char **argv, const char *rest);
int cmd_passbook(Session *s, int argc, char **argv, const char *rest);
int cmd_find_user(Session *s, int argc, char **argv, const char *rest);
int cmd_set_active(Session *s, int argc, char **argv, const char *rest);
int cmd_review_feedback(Session *s, int argc, char **argv, const char *rest);
int cmd_add_employee(Session *s, int argc, char **argv, const char *rest);
int cmd_mod_user(Session *s, int argc, char **argv, const char *rest);
int cmd_set_role(Session *s, int argc, char **argv, const char *rest);
int cmd_view_audit(Session *s, int argc, char **argv, const char *rest);

#endif
