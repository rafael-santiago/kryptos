/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_memory.h>

#if defined(KRYPTOS_USER_MODE)
# include <stdio.h>
# include <unistd.h>
#elif defined(KRYPTOS_KERNEL_MODE) && defined(__FreeBSD__)
  MALLOC_DECLARE(M_KRYPTOS);
  MALLOC_DEFINE(M_KRYPTOS, "kryptos_general_memory_buffer", "buffer allocated by libkryptos");
#elif defined(KRYPTOS_KERNEL_MODE) && defined(__linux__)
#endif // KRYPTOS_USER_MODE

void *kryptos_newseg(const size_t ssize) {
#ifdef KRYPTOS_USER_MODE
    void *segment = malloc(ssize);
    if (segment == NULL) {
        printf("kryptos panic: no memory!\n");
        exit(1);
    }
#elif defined(__FreeBSD__)
    void *segment = malloc(ssize, M_KRYPTOS, M_NOWAIT);
#endif
    return segment;
}

void kryptos_freeseg(void *seg) {
    if (seg != NULL) {
#if defined(KRYPTOS_USER_MODE)
        free(seg);
#elif defined(KRYPTOS_KERNEL_MODE) && defined(__FreeBSD__)
        free(seg, M_KRYPTOS);
#elif defined(KRYPTOS_KERNEL_MODE) && defined(__linux__)
#endif
    }
}

void *kryptos_realloc(void *addr, const size_t ssize) {
#if defined(KRYPTOS_USER_MODE)
    return realloc(addr, ssize);
#elif defined(KRYPTOS_KERNEL_MODE) && defined(__FreeBSD__)
    return realloc(addr, ssize, M_KRYPTOS, M_NOWAIT);
#elif defined(KRYPTOS_KERNEL_MODE) && defined(__linux__)
#endif
}
