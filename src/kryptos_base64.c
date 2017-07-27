/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_base64.h>
#include <kryptos_memory.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <string.h>
#endif

static kryptos_u8_t kryptos_base64_state[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
    'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
    'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
    's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2',
    '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

static kryptos_u8_t kryptos_base64_state_1 [] = {
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255,  62, 255, 255, 255,  63,           // INFO(Rafael): '+' and '/'.
     52,  53,  54,  55,  56,  57,  58,  59,  60,  61,
    255, 255, 255,   0, 255, 255, 255,                // INFO(Rafael): '0'..'9' and '='.
      0,   1,   2,   3,   4,   5,   6,   7,   8,   9,
     10,  11,  12,  13,  14,  15,  16,  17,  18,  19,
     20,  21,  22,  23,  24,  25,                     // INFO(Rafael): 'A'..'Z'.
      0,   0,   0,   0,   0,   0,
     26,  27,  28,  29,  30,  31,  32,  33,  34,  35,
     36,  37,  38,  39,  40,  41,  42,  43,  44,  45,
     46,  47,  48,  49,  50,  51,                     // INFO(Rafael): 'a'..'z'.
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255
};

#define kryptos_base64_get_encoded_byte(b) ( (b) != '=' ? (b) : 0 )

typedef kryptos_u8_t *(*kryptos_base64_buffer_processor)(const kryptos_u8_t *buffer,
                                                         const size_t buffer_size, size_t *out_size);

static kryptos_u8_t *kryptos_base64_encode_buffer(const kryptos_u8_t *buffer, const size_t buffer_size, size_t *out_size);

static kryptos_u8_t *kryptos_base64_decode_buffer(const kryptos_u8_t *buffer, const size_t buffer_size, size_t *out_size);

KRYPTOS_IMPL_ENCODING_PROCESSOR(base64, kKryptosEncodingBASE64, ktask,
                                kryptos_base64_buffer_processor,
                                base64_buffer_processor,
                                kryptos_base64_encode_buffer,
                                kryptos_base64_decode_buffer,
                                (*ktask)->out = base64_buffer_processor((*ktask)->in, (*ktask)->in_size, &(*ktask)->out_size))

static kryptos_u8_t *kryptos_base64_encode_buffer(const kryptos_u8_t *buffer, const size_t buffer_size, size_t *out_size) {
    const kryptos_u8_t *bp, *bp_end;
    kryptos_u8_t *out, *out_p;
    kryptos_u32_t block;
    size_t block_size, pad_size;

    if (buffer == NULL || buffer_size == 0) {
        *out_size = 0;
        return NULL;
    }

    bp = buffer;
    bp_end = bp + buffer_size;

    *out_size = (buffer_size * 8) / 6;

    while ((*out_size % 4) != 0) {
        *out_size += 1;
    }

    out = (kryptos_u8_t *) kryptos_newseg(*out_size);
    out_p = out;

    while (bp != bp_end) {

        block = 0;
        block_size = 0;

        while (bp != bp_end && block_size < 3) {
            block = block << 8 | *bp;
            block_size++;
            bp++;
        }

        pad_size = 3 - block_size;

        block = block << (pad_size << 3);

        *out_p       = kryptos_base64_state[(block & 0x00FC0000) >> 18];
        *(out_p + 1) = kryptos_base64_state[(block & 0x0003F000) >> 12];
        *(out_p + 2) = kryptos_base64_state[(block & 0x00000FC0) >>  6];
        *(out_p + 3) = kryptos_base64_state[block & 0x0000003F];

        out_p += 4 - pad_size;
    }

    while (pad_size > 0) {
        *out_p = '=';
        out_p++;
        pad_size--;
    }

    bp = NULL;
    bp_end = NULL;
    block = 0;

    return out;
}

static kryptos_u8_t *kryptos_base64_decode_buffer(const kryptos_u8_t *buffer, const size_t buffer_size, size_t *out_size) {
    const kryptos_u8_t *bp, *bp_end;
    kryptos_u8_t *out, *out_p, *out_end;
    kryptos_u32_t block;
    size_t pad_size = 0;

    if (buffer == NULL || buffer_size == 0) {
        *out_size = 0;
        return NULL;
    }

    bp_end = buffer + buffer_size;
    bp = bp_end - 1;

    while (*bp == '=') {
        pad_size++;
        bp--;
    }

    bp = buffer;

    *out_size = ((buffer_size * 6) / 8) - pad_size;
    out = (kryptos_u8_t *) kryptos_newseg(*out_size + 1);
    memset(out, 0, *out_size + 1);
    out_p = out;
    out_end = out_p + *out_size;

    while (out_p != out_end && bp != bp_end) {
        block = (kryptos_u32_t) kryptos_base64_state_1[kryptos_base64_get_encoded_byte(    *bp  )] << 18 |
                (kryptos_u32_t) kryptos_base64_state_1[kryptos_base64_get_encoded_byte(*(bp + 1))] << 12 |
                (kryptos_u32_t) kryptos_base64_state_1[kryptos_base64_get_encoded_byte(*(bp + 2))] <<  6 |
                (kryptos_u32_t) kryptos_base64_state_1[kryptos_base64_get_encoded_byte(*(bp + 3))];

        *out_p = (block & 0x00FF0000) >> 16;
        out_p++;

        if (out_p == out_end) {
            continue;
        }

        *out_p = (block & 0x0000FF00) >>  8;
        out_p++;

        if (out_p == out_end) {
            continue;
        }

        *out_p = (block & 0x000000FF);
        out_p++;

        bp += 4;
    }

    pad_size = 0;
    bp = NULL;
    bp_end = NULL;
    block = 0;
    out_end = NULL;

    return out;
}

#undef kryptos_base64_get_encoded_byte
