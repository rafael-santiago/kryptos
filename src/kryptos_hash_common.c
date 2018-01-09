/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_hash_common.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <string.h>
#endif

// INFO(Rafael): The following functions are useful for hash algorithms that use Merkle-Damgard construction.

void kryptos_hash_apply_pad_on_u32_block(kryptos_u32_t *input, size_t const input_nr,
                                         const size_t *block_index_decision_table,
                                         const kryptos_u64_t curr_len, const kryptos_u64_t total_len,
                                         int *paddin2times, const kryptos_u8_t padtok, kryptos_u32_t len_block_offset) {
    size_t b = block_index_decision_table[curr_len], shlv;
    if (*paddin2times == 0) {
        shlv = 24 - ((curr_len % 4) << 3);
        input[b] = (input[b] << 8 | padtok) << shlv;
    }

    if (curr_len < len_block_offset || *paddin2times) {
        input[input_nr - 2] = total_len >> 32;
        input[input_nr - 1] = total_len & 0x00000000ffffffff;
        if (*paddin2times) {
            *paddin2times = 0;
        }
    } else {
        *paddin2times = 1;
    }
}

void kryptos_hash_ld_u8buf_as_u32_blocks(kryptos_u8_t *buffer, const int buffer_size,
                                         kryptos_u32_t *input, const size_t input_nr,
                                         const size_t *block_index_decision_table) {
    size_t b, i;
    if (buffer_size > (input_nr << 2)) {
        // INFO(Rafael): Let's skip it. It should never happen in normal conditions.
        return;
    }

    memset(input, 0, sizeof(input[0]) * input_nr);

    for (b = 0; b < buffer_size; b++) {
        i = block_index_decision_table[b];
        input[i] = input[i] << 8 | buffer[b];
    }
}

void kryptos_hash_apply_pad_on_u64_block(kryptos_u64_t *input, size_t const input_nr,
                                         const size_t *block_index_decision_table,
                                         const kryptos_u64_t curr_len, const kryptos_u64_t total_len,
                                         int *paddin2times, const kryptos_u8_t padtok, kryptos_u64_t len_block_offset) {
    size_t b = block_index_decision_table[curr_len], shlv;
    if (*paddin2times == 0) {
        shlv = 56 - ((curr_len % 8) << 3);
        input[b] = (input[b] << 8 | padtok) << shlv;
    }

    if (curr_len < len_block_offset || *paddin2times) {
        input[input_nr - 1] = total_len;
        if (*paddin2times) {
            *paddin2times = 0;
        }
    } else {
        *paddin2times = 1;
    }
}

void kryptos_hash_ld_u8buf_as_u64_blocks(kryptos_u8_t *buffer, const int buffer_size,
                                         kryptos_u64_t *input, const size_t input_nr,
                                         const size_t *block_index_decision_table) {
    size_t b, i;
    if (buffer_size > (input_nr << 3)) {
        // INFO(Rafael): Let's skip it. It should never happen in normal conditions.
        return;
    }

    memset(input, 0, sizeof(input[0]) * input_nr);

    for (b = 0; b < buffer_size; b++) {
        i = block_index_decision_table[b];
        input[i] = input[i] << 8 | buffer[b];
    }
}
