/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_base16.h>
#include <kryptos_memory.h>

static kryptos_u8_t kryptos_base16_state[] = {
    '0', '1', '2', '3',
    '4', '5', '6', '7',
    '8', '9', 'A', 'B',
    'C', 'D', 'E', 'F'
};

typedef kryptos_u8_t *(*kryptos_base16_buffer_processor)(const kryptos_u8_t *buffer,
                                                         const size_t buffer_size, size_t *out_size);

static kryptos_u8_t *kryptos_base16_encode_buffer(const kryptos_u8_t *buffer,
                                                  const size_t buffer_size,
                                                  size_t *out_size);

static kryptos_u8_t *kryptos_base16_decode_buffer(const kryptos_u8_t *buffer,
                                                  const size_t buffer_size,
                                                  size_t *out_size);

KRYPTOS_IMPL_ENCODING_SETUP(base16, ktask, kKryptosEncodingBASE16);

KRYPTOS_IMPL_ENCODING_PROCESSOR(base16, kKryptosEncodingBASE16, ktask,
                                kryptos_base16_buffer_processor,
                                base16_buffer_processor,
                                kryptos_base16_encode_buffer,
                                kryptos_base16_decode_buffer,
                                (*ktask)->out = base16_buffer_processor((*ktask)->in,
                                (*ktask)->in_size, &(*ktask)->out_size))

static kryptos_u8_t *kryptos_base16_encode_buffer(const kryptos_u8_t *buffer,
                                                  const size_t buffer_size,
                                                  size_t *out_size) {
    kryptos_u8_t *output = NULL;
    const kryptos_u8_t *bp = NULL, *bp_end = NULL;
    kryptos_u8_t *op = NULL, *op_end = NULL;

    if (out_size == NULL) {
        return NULL;
    }

    *out_size = 0;

    if (buffer == NULL || buffer_size == 0) {
        goto kryptos_base16_encode_buffer_epilogue;
    }

    *out_size = buffer_size << 1;

    output = (kryptos_u8_t *)kryptos_newseg(*out_size);
    if (output == NULL) {
        *out_size = 0;
        goto kryptos_base16_encode_buffer_epilogue;
    }

    op = output;
    op_end = op + *out_size;

    bp = buffer;
    bp_end = bp + buffer_size;

    while (bp != bp_end && op != op_end) {
        op[0] = kryptos_base16_state[bp[0] >> 4];
        op[1] = kryptos_base16_state[bp[0] & 0xF];
        op += 2;
        bp += 1;
    }

kryptos_base16_encode_buffer_epilogue:

    op = op_end = NULL;
    bp = bp_end = NULL;

    return output;
}

static kryptos_u8_t *kryptos_base16_decode_buffer(const kryptos_u8_t *buffer,
                                                  const size_t buffer_size,
                                                  size_t *out_size) {
    kryptos_u8_t *output = NULL, *op = NULL, *op_end = NULL;
    const kryptos_u8_t *bp = NULL, *bp_end = NULL;

    if (out_size == NULL) {
        return NULL;
    }

    *out_size = 0;

    if (buffer == NULL || buffer_size == 0) {
        goto kryptos_base16_decode_buffer_epilogue;
    }

    *out_size = buffer_size >> 1;

    output = (kryptos_u8_t *)kryptos_newseg(*out_size);
    if (output == NULL) {
        *out_size = 0;
        goto kryptos_base16_decode_buffer_epilogue;
    }

    op = output;
    op_end = op + *out_size;

    bp = buffer;
    bp_end = bp + buffer_size;

#define kryptos_base16_state_1(b) ( ((b) >= '0' && (b) <= '9') ?\
                                                    ((b) - 48) :\
                                                    ((b) - 55) )

    while (bp != bp_end && op != op_end) {
        *op = ((kryptos_u8_t)kryptos_base16_state_1(bp[0]) << 4) |
                             kryptos_base16_state_1(bp[1]);
        bp += 2;
        op += 1;
    }

#undef kryptos_base16_state_1

kryptos_base16_decode_buffer_epilogue:

    op = op_end = NULL;
    bp = bp_end = NULL;

    return output;
}
