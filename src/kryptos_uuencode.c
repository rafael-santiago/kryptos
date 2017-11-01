/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_uuencode.h>
#include <kryptos_memory.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <string.h>
#endif

#define KRYPTOS_UUENCODE_BYTES_PER_LINE 60

typedef kryptos_u8_t *(*kryptos_uuencode_buffer_processor)(const kryptos_u8_t *buffer,
                                                           const size_t buffer_size, size_t *out_size);

static kryptos_u8_t *kryptos_uuencode_encode_buffer(const kryptos_u8_t *buffer, const size_t buffer_size, size_t *out_size);

static kryptos_u8_t *kryptos_uuencode_decode_buffer(const kryptos_u8_t *buffer, const size_t buffer_size, size_t *out_size);

KRYPTOS_IMPL_ENCODING_SETUP(uuencode, ktask, kKryptosEncodingUUENCODE);

KRYPTOS_IMPL_ENCODING_PROCESSOR(uuencode, kKryptosEncodingUUENCODE, ktask,
                                kryptos_uuencode_buffer_processor,
                                uuencode_buffer_processor,
                                kryptos_uuencode_encode_buffer,
                                kryptos_uuencode_decode_buffer,
                                (*ktask)->out = uuencode_buffer_processor((*ktask)->in, (*ktask)->in_size, &(*ktask)->out_size))


kryptos_u8_t *kryptos_uuencode_encode_buffer(const kryptos_u8_t *buffer, const size_t buffer_size, size_t *out_size) {
    const kryptos_u8_t *bp, *bp_end;
    kryptos_u8_t *out_p, *out;
    kryptos_u32_t block;
    size_t block_size, pad_size, enc_total;
    kryptos_u8_t curr_line[KRYPTOS_UUENCODE_BYTES_PER_LINE], *cp, *cp_end;

    if (out_size == NULL) {
        return NULL;
    }

    if (buffer == NULL || buffer_size == 0) {
        *out_size = 0;
        return NULL;
    }

    *out_size = (buffer_size * 8) / 6;
    *out_size += *out_size / KRYPTOS_UUENCODE_BYTES_PER_LINE + (*out_size % KRYPTOS_UUENCODE_BYTES_PER_LINE != 0) + 4;

    out = (kryptos_u8_t *) kryptos_newseg(*out_size + KRYPTOS_UUENCODE_BYTES_PER_LINE);
    if (out == NULL) {
        *out_size = 0;
        return NULL;
    }
    memset(out, 0, *out_size + KRYPTOS_UUENCODE_BYTES_PER_LINE);
    out_p = out;

    bp = buffer;
    bp_end = bp + buffer_size;
    cp = &curr_line[0];
    cp_end = cp + KRYPTOS_UUENCODE_BYTES_PER_LINE;

    enc_total = 0;

    while (bp != bp_end) {
        block_size = 0;
        block = 0;
        while (bp != bp_end && block_size < 3) {
            block = block << 8 | *bp;
            bp++;
            block_size++;
        }

        enc_total += block_size;

        pad_size = 3 - block_size;

        if (pad_size == 1) {
            block = block << 16 | 0x00000101;
        } else if (pad_size == 2) {
            block = block << 8 | 0x01;
        }

           *cp    = 32 + ((block & 0x00FC0000) >> 18);
        *(cp + 1) = 32 + ((block & 0x0003F000) >> 12);
        *(cp + 2) = 32 + ((block & 0x00000FC0) >>  6);
        *(cp + 3) = 32 + (block & 0x0000003F);

        cp += 4;

        if (cp == cp_end || bp == bp_end) {
            *out_p = 32 + enc_total;
            memcpy(out_p + 1, curr_line, (cp - &curr_line[0]));
            out_p += KRYPTOS_UUENCODE_BYTES_PER_LINE + 1;
            *out_p = '\n';
            out_p++;
            cp = &curr_line[0];
            enc_total = 0;
        }
    }

    out_p = (out + *out_size) - 3;
    *( out_p ) = '\n';
    *(out_p + 1) = '`';
    *(out_p + 2) = '\n';

    block = 0;
    pad_size = block_size = enc_total = 0;
    bp = bp_end = NULL;
    cp = cp_end = out_p = NULL;
    memset(curr_line, 0, sizeof(curr_line));

    return out;
}


static kryptos_u8_t *kryptos_uuencode_decode_buffer(const kryptos_u8_t *buffer, const size_t buffer_size, size_t *out_size) {
    const kryptos_u8_t *bp, *bp_end;
    kryptos_u8_t *out, *out_p;
    size_t enc_total;
    kryptos_u32_t block;
    ssize_t shlv;

    if (out_size == NULL) {
        return NULL;
    }

    if (buffer == NULL || buffer_size == 0) {
        *out_size = 0;
        return NULL;
    }

    *out_size = ((buffer_size * 6) / 8) - 4;

    out = (kryptos_u8_t *) kryptos_newseg(*out_size + KRYPTOS_UUENCODE_BYTES_PER_LINE);
    if (out == NULL) {
        *out_size = 0;
        return NULL;
    }
    out_p = out;
    memset(out, 0, *out_size + KRYPTOS_UUENCODE_BYTES_PER_LINE);

    bp = buffer;
    bp_end = bp + buffer_size;

    while (bp < bp_end && *bp != '`') {
        enc_total = *bp - 32;
        bp++;
        while (enc_total > 0 && bp < bp_end) {
            block = (kryptos_u32_t)    (*bp - 32)    << 18 |
                    (kryptos_u32_t) (*(bp + 1) - 32) << 12 |
                    (kryptos_u32_t) (*(bp + 2) - 32) <<  6 |
                    (kryptos_u32_t) (*(bp + 3) - 32);

            shlv = 16;

            while (enc_total > 0 && shlv >= 0) {
                *out_p = (block & (0xff << shlv)) >> shlv;
                shlv -= 8;
                out_p++;
                enc_total--;
            }

            bp += 4;
        }
        bp++;
    }

    bp = bp_end = NULL;
    out_p = NULL;
    enc_total = 0;
    block = 0;
    shlv = 0;

    return out;
}

#undef KRYPTOS_UUENCODE_BYTES_PER_LINE
