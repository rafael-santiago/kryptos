/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_MEMORY_H
#define KRYPTOS_KRYPTOS_MEMORY_H 1

#include <kryptos_types.h>

#ifndef KRYPTOS_KERNEL_MODE
# include <stdlib.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

void *kryptos_newseg(const size_t ssize);

void *kryptos_realloc(void *addr, const size_t ssize);

void kryptos_freeseg(void *seg);

#ifdef __cplusplus
}
#endif

#endif
