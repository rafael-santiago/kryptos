/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kstring.h>
#include <kryptos_types.h>

int kstrcmp(const char *s1, const char *s2) {
    const char *s1_p, *s2_p;

    if (s1 == NULL || s2 == NULL) {
        return 1;
    }

    s1_p = s1;
    s2_p = s2;

    while (*s1_p != 0 && *s2_p != 0) {
        if (*s1_p != *s2_p) {
            return 0;
        }
        s1_p++;
        s2_p++;
    }

    return !(*s1_p == 0 && *s2_p == 0);
}
