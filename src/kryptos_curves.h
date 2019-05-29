/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_CURVES_H
#define KRYPTOS_KRYPTOS_CURVES_H 1

#include <kryptos_types.h>

#ifdef __cplusplus
extern "C" {
#endif

kryptos_curve_ctx *kryptos_curve_new_curve_ctx(kryptos_curve_id_t id);

void kryptos_del_curve_ctx(kryptos_curve_ctx *curve);

#ifdef __cplusplus
}
#endif

#endif
