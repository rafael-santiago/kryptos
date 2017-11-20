/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_BLOCK_PARSER_H
#define KRYPTOS_KRYPTOS_BLOCK_PARSER_H 1

#include <kryptos_types.h>

#ifdef __cplusplus
extern "C" {
#endif

kryptos_u8_t *kryptos_block_parser(kryptos_u8_t *out, const size_t block_size,
                                   kryptos_u8_t *in, kryptos_u8_t *in_end, kryptos_u8_t **next);

#ifdef __cplusplus
}
#endif

#endif
