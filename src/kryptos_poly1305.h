/*
 *                                Copyright (C) 2021 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_POLY1305_H
#define KRYPTOS_KRYPTOS_POLY1305_H 1

#include <kryptos_types.h>

#ifdef __cplusplus
extern "C" {
#endif

void kryptos_poly1305(kryptos_task_ctx **ktask);

void kryptos_do_poly1305(kryptos_task_ctx **ktask);

#ifdef __cplusplus
}
#endif

#endif
