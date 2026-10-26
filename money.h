/* money.h - parsing and printing amounts, shared by customer and staff commands */
#ifndef MONEY_H
#define MONEY_H

#include <stddef.h>
#include "common.h"

/* Accepts "100", "100.5", "100.50". Rejects signs, exponents, a third decimal,
 * "100." and ".5". Result must be 1 paise .. MAX_TXN_PAISE. Returns 0 or -1. */
int  money_parse(const char *s, paise_t *out);
void money_format(paise_t p, char *buf, size_t n);     /* 12345 -> "123.45" */

/* Positive integer of at most 9 digits (user ids, account ids). Returns 0 or -1. */
int  id_parse(const char *s, int *out);

#endif
