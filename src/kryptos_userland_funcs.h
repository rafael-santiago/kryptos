/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_USERLAND_FUNCS_H
#define KRYPTOS_KRYPTOS_USERLAND_FUNCS_H 1

#ifdef KRYPTOS_KERNEL_MODE

#include <kryptos_types.h>

#define isdigit(d) ( (d) >= '0' && (d) <= '9' )

kryptos_u8_t toupper(const kryptos_u8_t c);

#endif

#endif
