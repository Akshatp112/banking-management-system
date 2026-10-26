/* money.c */
#include <stdio.h>
#include "money.h"

int money_parse(const char *s, paise_t *out)
{
    long long whole = 0, frac = 0;
    int digits = 0, i = 0;

    while (s[i] >= '0' && s[i] <= '9') {
        if (++digits > 10) return -1;                 /* also prevents overflow */
        whole = whole * 10 + (s[i++] - '0');
    }
    if (digits == 0) return -1;

    if (s[i] == '.') {
        int fd = 0;
        i++;
        while (s[i] >= '0' && s[i] <= '9') {
            if (++fd > 2) return -1;
            frac = frac * 10 + (s[i++] - '0');
        }
        if (fd == 0) return -1;
        if (fd == 1) frac *= 10;                      /* "5.5" means 5.50 */
    }
    if (s[i] != '\0') return -1;

    paise_t p = whole * 100 + frac;
    if (p <= 0 || p > MAX_TXN_PAISE) return -1;
    *out = p;
    return 0;
}

void money_format(paise_t p, char *buf, size_t n)
{
    snprintf(buf, n, "%lld.%02lld", (long long)(p / 100), (long long)(p % 100));
}

int id_parse(const char *s, int *out)
{
    long long v = 0;
    int n = 0;
    for (; s[n]; n++) {
        if (s[n] < '0' || s[n] > '9' || n >= 9) return -1;
        v = v * 10 + (s[n] - '0');
    }
    if (n == 0 || v <= 0) return -1;
    *out = (int)v;
    return 0;
}
