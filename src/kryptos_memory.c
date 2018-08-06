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
# include <string.h>
#elif defined(KRYPTOS_KERNEL_MODE) && (defined(__FreeBSD__) || defined(__NetBSD__))
  MALLOC_DECLARE(M_KRYPTOS);
  MALLOC_DEFINE(M_KRYPTOS, "kryptos_general_memory_buffer", "buffer allocated by libkryptos");
#endif // KRYPTOS_USER_MODE

void *kryptos_newseg(const size_t ssize) {
    void *segment;
#ifdef KRYPTOS_USER_MODE
    segment = malloc(ssize);
    if (segment == NULL) {
        printf("kryptos panic: no memory!\n");
        exit(1);
    }
#elif defined(__FreeBSD__) || defined(__NetBSD__)
    segment = malloc(ssize, M_KRYPTOS, M_NOWAIT);
#elif defined(__linux__)
    segment = kmalloc(ssize, GFP_ATOMIC);
#else
    segment = NULL;
#endif
    return segment;
}

void kryptos_freeseg(void *seg, const size_t ssize) {
    if (seg != NULL) {
        if (ssize > 0) {
            // PARANOID-TODO(Rafael): To be paranoid enough and go ahead with some data wiping over RAM data or not to be?
            // TODO(Rafael): Yes, apply data wiping here too.
            memset(seg, 0, ssize);
        }
#if defined(KRYPTOS_USER_MODE)
        free(seg);
#elif defined(KRYPTOS_KERNEL_MODE) && (defined(__FreeBSD__) || defined(__NetBSD__))
        free(seg, M_KRYPTOS);
#elif defined(KRYPTOS_KERNEL_MODE) && defined(__linux__)
        kfree(seg);
#endif
    }
}

void *kryptos_realloc(void *addr, const size_t ssize) {
#if defined(KRYPTOS_USER_MODE)
    return realloc(addr, ssize);
#elif defined(KRYPTOS_KERNEL_MODE) && (defined(__FreeBSD__) || defined(__NetBSD__))
    return realloc(addr, ssize, M_KRYPTOS, M_NOWAIT);
#elif defined(KRYPTOS_KERNEL_MODE) && defined(__linux__)
    return krealloc(addr, ssize, GFP_ATOMIC);
#else
    return NULL;
#endif
}
