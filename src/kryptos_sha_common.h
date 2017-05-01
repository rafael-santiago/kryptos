/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_SHA_COMMON_H
#define KRYPTOS_KRYPTOS_SHA_COMMON_H 1

#include <kryptos_types.h>

void kryptos_sha_apply_pad(kryptos_u32_t *input, const size_t input_nr,
                           const size_t *block_index_decision_table,
                           const kryptos_u32_t curr_len, const kryptos_u32_t total_len,
                           int *paddin2times, kryptos_u32_t len_block_offset);

void kryptos_sha_ld_u8buf_into_input(kryptos_u8_t *buffer, const int buffer_size,
                                     kryptos_u32_t *input, const size_t input_nr,
                                     const size_t *block_index_decision_table);

#endif
