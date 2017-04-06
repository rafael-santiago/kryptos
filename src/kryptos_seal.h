/*
 *                          Copyright (C) 2007, 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_SEAL_H
#define KRYPTOS_KRYPTOS_SEAL_H 1

#include <kryptos_types.h>

// INFO(Rafael): Until now these are the available versions.
typedef enum kryptos_sealknds {
    kKryptosSEAL20 = 2, kKryptosSEAL30
}kryptos_seal_version_t;

void kryptos_seal_stream(kryptos_task_ctx **ktask);

#endif
