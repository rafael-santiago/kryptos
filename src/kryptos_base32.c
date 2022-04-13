/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_base32.h>
#include <kryptos_memory.h>

static kryptos_u8_t kryptos_base32_state[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
    'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
    'W', 'X', 'Y', 'Z', '2', '3', '4', '5', '6', '7'
};

static kryptos_u8_t kryptos_base32_state_1 [] = {
      0, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255,  26,  27,  28,  29,  30,  31,
    255, 255, 255, 255, 255, 255, 255, 255,
    255,   0,   1,   2,   3,   4,   5,   6,
      7,   8,   9,  10,  11,  12,  13,  14,
     15,  16,  17,  18,  19,  20,  21,  22,
     23,  24,  25, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255
};

#define kryptos_base32_get_encoded_byte(b) ( (b) != '=' ? (b) : 0 )

typedef kryptos_u8_t *(*kryptos_base32_buffer_processor)(const kryptos_u8_t *buffer,
                                                         const size_t buffer_size, size_t *out_size);

static kryptos_u8_t *kryptos_base32_encode_buffer(const kryptos_u8_t *buffer, const size_t buffer_size,
                                                  size_t *out_size);

static kryptos_u8_t *kryptos_base32_decode_buffer(const kryptos_u8_t *buffer, const size_t buffer_size,
                                                  size_t *out_size);


KRYPTOS_IMPL_ENCODING_SETUP(base32, ktask, kKryptosEncodingBASE32);

KRYPTOS_IMPL_ENCODING_PROCESSOR(base32, kKryptosEncodingBASE32, ktask,
                                kryptos_base32_buffer_processor,
                                base32_buffer_processor,
                                kryptos_base32_encode_buffer,
                                kryptos_base32_decode_buffer,
                                (*ktask)->out = base32_buffer_processor((*ktask)->in, (*ktask)->in_size, &(*ktask)->out_size))

static kryptos_u8_t *kryptos_base32_encode_buffer(const kryptos_u8_t *buffer, const size_t buffer_size,
                                                  size_t *out_size) {
    kryptos_u8_t *output = NULL, *op = NULL, *op_end = NULL;
    const kryptos_u8_t *bp = NULL, *bp_end = NULL;
    kryptos_u64_t block = 0;
    size_t block_size = 0;
    size_t pad_size = 0;

    if (out_size == NULL) {
        return NULL;
    }

    *out_size = 0;

    if (buffer == NULL || buffer_size == 0) {
        return NULL;
    }

    // INFO(Rafael): +4 here is for rounding up, in this way we can use a straightforward ceil()
    //               without depending on math.h, specially because we need to run it into several
    //               kernels.
    *out_size = (((buffer_size + 4) / 5) << 3);

    if (buffer_size >= 6) {
        while ((*out_size % 8) != 0) {
            *out_size += 1;
        }
    }

    output = (kryptos_u8_t *)kryptos_newseg(*out_size);
    if (output == NULL) {
        kryptos_freeseg(output, *out_size);
        output = NULL;
        *out_size = 0;
        goto kryptos_base32_encode_buffer_epilogue;
    }

    op = output;
    op_end = op + *out_size;

    bp = buffer;
    bp_end = bp + buffer_size;

    while (bp != bp_end && op != op_end) {
        while (bp != bp_end && block_size < 5) {
            block = (block << 8) | *bp;
            bp++;
            block_size += 1;
        }

        pad_size = 5 - block_size;

        block = (block << (pad_size << 3));

        op[0] = kryptos_base32_state[((block & 0x000000F800000000) >> 35)];
        op[1] = kryptos_base32_state[((block & 0x00000007C0000000) >> 30)];
        op[2] = kryptos_base32_state[((block & 0x000000003E000000) >> 25)];
        op[3] = kryptos_base32_state[((block & 0x0000000001F00000) >> 20)];
        op[4] = kryptos_base32_state[((block & 0x00000000000F8000) >> 15)];
        op[5] = kryptos_base32_state[((block & 0x0000000000007C00) >> 10)];
        op[6] = kryptos_base32_state[((block & 0x00000000000003E0) >>  5)];
        op[7] = kryptos_base32_state[(block & 0x000000000000001F)];

        op += 8;

        block = 0;
        block_size = 0;
    }

    if (pad_size > 0) {
        switch (pad_size) {
            case 4:
                op -= 6;
                break;

            case 3:
                op -= 4;
                break;

            case 2:
                op -= 3;
                break;

            case 1:
                op -= 1;
                break;

            default:
                break;
        }
        while (op != op_end) {
            *op = '=';
            op++;
        }
    }

kryptos_base32_encode_buffer_epilogue:

    bp = bp_end = NULL;
    op = op_end = NULL;
    block = 0;
    block_size = pad_size = 0;

    return output;
}


static kryptos_u8_t *kryptos_base32_decode_buffer(const kryptos_u8_t *buffer, const size_t buffer_size,
                                              size_t *out_size) {
    kryptos_u8_t *output = NULL, *op = NULL, *op_end = NULL;
    const kryptos_u8_t *bp = NULL, *bp_end = NULL;
    kryptos_u64_t block = 0;
    size_t block_size = 0;
    size_t pad_size = 0;

    if (out_size == NULL) {
        return NULL;
    }

    *out_size = 0;

    if (buffer == NULL || buffer_size == 0) {
        goto kryptos_base32_decode_buffer_epilogue;
    }

    // INFO(Rafael): In practice, sometimes it will allocate one or two more bytes,
    //               but we will correct it later at the end of the decoding process.
    //               However, we do not reallocate it.
    *out_size = (((buffer_size - 4) * 5) >> 3) + 2;

    output = (kryptos_u8_t *)kryptos_newseg(*out_size);

    if (output == NULL) {
        *out_size = 0;
        goto kryptos_base32_decode_buffer_epilogue;
    }

    op = output;
    op_end = op + *out_size;

    bp = buffer;
    bp_end = bp + buffer_size;

    while (bp != bp_end && op != op_end) {
        while (bp != bp_end && block_size < 40) {
            block = (block << 5) | kryptos_base32_state_1[kryptos_base32_get_encoded_byte(*bp)];
            block_size += 5;
            bp++;
            if (bp != bp_end) {
                pad_size += (*bp == '=');
            }
        }

        if (pad_size == 0) {
            // INFO(Rafael): Non-last block or last exact (unpadded) block.
            op[0] = ((block >> 32) & 0xFF);
            op[1] = ((block >> 24) & 0xFF);
            op[2] = ((block >> 16) & 0xFF);
            op[3] = ((block >>  8) & 0xFF);
            op[4] = block & 0xFF;
            op += 5;
        } else {
            // INFO(Rafael): Last block and it was padded.
            switch (pad_size) {
                case 6:
                    op[0] = ((block >> 32) & 0xFF);
                    op += 1;
                    break;

                case 4:
                    op[0] = ((block >> 32) & 0xFF);
                    op[1] = ((block >> 24) & 0xFF);
                    op += 2;
                    break;

                case 3:
                    op[0] = ((block >> 32) & 0xFF);
                    op[1] = ((block >> 24) & 0xFF);
                    op[2] = ((block >> 16) & 0xFF);
                    op += 3;
                    break;

                case 1:
                    op[0] = ((block >> 32) & 0xFF);
                    op[1] = ((block >> 24) & 0xFF);
                    op[2] = ((block >> 16) & 0xFF);
                    op[3] = ((block >>  8) & 0xFF);
                    op += 4;
                    break;

                default:
                    break;
            }
        }
        block_size = 0;
    }

    *out_size = (op - output);

kryptos_base32_decode_buffer_epilogue:

    op = op_end = NULL;
    bp = bp_end = NULL;
    block = 0;
    block_size = 0;

    return output;
}

#undef kryptos_base32_get_encoded_byte
