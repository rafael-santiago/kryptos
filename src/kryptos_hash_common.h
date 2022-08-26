/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_HASH_COMMON_H
#define KRYPTOS_KRYPTOS_HASH_COMMON_H 1

#include <kryptos_types.h>

#ifdef __cplusplus
extern "C" {
#endif

void kryptos_hash_apply_pad_on_u32_block(kryptos_u32_t *input, const size_t input_nr,
                                         const size_t *block_index_decision_table,
                                         const kryptos_u64_t curr_len, const kryptos_u64_t total_len,
                                         int *paddin2times, const kryptos_u8_t padtok, kryptos_u32_t len_block_offset);

void kryptos_hash_ld_u8buf_as_u32_blocks(kryptos_u8_t *buffer, const size_t buffer_size,
                                         kryptos_u32_t *input, const size_t input_nr,
                                         const size_t *block_index_decision_table);

void kryptos_hash_apply_pad_on_u64_block(kryptos_u64_t *input, const size_t input_nr,
                                         const size_t *block_index_decision_table,
                                         const kryptos_u64_t curr_len, const kryptos_u64_t total_len,
                                         int *paddin2times, const kryptos_u8_t padtok, kryptos_u64_t len_block_offset);

void kryptos_hash_ld_u8buf_as_u64_blocks(kryptos_u8_t *buffer, const size_t buffer_size,
                                         kryptos_u64_t *input, const size_t input_nr,
                                         const size_t *block_index_decision_table);

void kryptos_hash_do_update(kryptos_task_ctx **ktask, const kryptos_u8_t *input, const size_t input_size);

void kryptos_hash_do_finalize(kryptos_task_ctx **ktask, const int to_hex);

#ifdef __cplusplus
}
#endif

#endif
