/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_padding.h>
#include <kryptos_types.h>
#include <kryptos_memory.h>
#ifdef KRYPTOS_USER_MODE
#include <string.h>
#endif

unsigned char *kryptos_ansi_x923_padding(const unsigned char *buffer, size_t *buffer_size,
                                         const size_t block_size_in_bytes) {
    unsigned char *bpad = NULL;
    size_t pad_nr = 0;
    size_t padded_size = 0;

    if (buffer_size == NULL || block_size_in_bytes == 0 || *buffer_size == 0) {
        return (unsigned char *)buffer;
    }

    padded_size = *buffer_size;

    //  INFO(Rafael): We will always pad.
    if ((padded_size % block_size_in_bytes) == 0) {
        padded_size++;
    }

    while ((padded_size % block_size_in_bytes) != 0) {
        pad_nr++;
        padded_size++;
    }

    bpad = (unsigned char *) kryptos_newseg(padded_size);

#ifdef KRYPTOS_USER_MODE
    memcpy(bpad, buffer, *buffer_size);
    memset(bpad + (*buffer_size) + 1, 0, padded_size - *buffer_size - 1);
    bpad[padded_size - 1] = (unsigned char)(padded_size - *buffer_size); // INFO(Rafael): duh!
    *buffer_size = padded_size;
#else
    // TODO(Rafael): Kernel mode trinket.
#endif

    return bpad;
}
