/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_MEMORY_H
#define KRYPTOS_KRYPTOS_MEMORY_H 1

#include <stdlib.h>

void *kryptos_newseg(const size_t ssize);

void kryptos_freeseg(void *seg);

#endif
