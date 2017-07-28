/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_padding.h>
#include <kryptos_memory.h>
#include <kryptos_random.h>
#ifdef KRYPTOS_USER_MODE
#include <string.h>
#endif

kryptos_u8_t *kryptos_ansi_x923_padding(const kryptos_u8_t *buffer, size_t *buffer_size,
                                        const size_t block_size_in_bytes, const int randomize) {
    kryptos_u8_t *bpad = NULL;
    size_t padded_size = 0;
    kryptos_u8_t byte;
    size_t p;

    if (buffer_size == NULL || block_size_in_bytes == 0 || *buffer_size == 0) {
        return NULL;
    }

    padded_size = *buffer_size;

    //  INFO(Rafael): We will always pad.
    if ((padded_size % block_size_in_bytes) == 0) {
        padded_size++;
    }

    while ((padded_size % block_size_in_bytes) != 0) {
        padded_size++;
    }

    bpad = (kryptos_u8_t *) kryptos_newseg(padded_size);

    memcpy(bpad, buffer, *buffer_size);
    if (randomize == 0) {
        memset(bpad + (*buffer_size), 0, padded_size - *buffer_size - 1);
    } else {
        for (p = (*buffer_size); p < padded_size - 1; p++) {
            byte = kryptos_get_random_byte();
            bpad[p] = byte;
        }
    }
    bpad[padded_size - 1] = (kryptos_u8_t)(padded_size - *buffer_size); // INFO(Rafael): duh!
    *buffer_size = padded_size;

    return bpad;
}
