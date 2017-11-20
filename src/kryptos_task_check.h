/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_TASK_CHECK_H
#define KRYPTOS_KRYPTOS_TASK_CHECK_H 1

#include <kryptos_types.h>

#ifdef __cplusplus
extern "C" {
#endif

int kryptos_task_check(kryptos_task_ctx **ktask);

int kryptos_task_check_sign(kryptos_task_ctx **ktask);

int kryptos_task_check_verify(kryptos_task_ctx **ktask);

#ifdef __cplusplus
}
#endif

#endif
