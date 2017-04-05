/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_memory.h>
#include <kryptos_types.h>

#ifdef KRYPTOS_USER_MODE
#include <stdio.h>
#include <unistd.h>
#endif // KRYPTOS_USER_MODE

void *kryptos_newseg(const size_t ssize) {
    void *segment = malloc(ssize);

#ifdef KRYPTOS_USER_MODE
    if (segment == NULL) {
        printf("kryptos panic: no memory!\n");
        exit(1);
    }
#endif
}

void kryptos_freeseg(void *seg) {
    if (seg != NULL) {
#if defined(KRYPTOS_USER_MODE)
        free(seg);
#elif defined(KRYPTOS_KERNEL_MODE)
#endif
    }
}
