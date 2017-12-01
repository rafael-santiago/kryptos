/*
 *                          Copyright (C) 2007, 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_idea.h>
#include <kryptos_endianness_utils.h>
#include <kryptos_random.h>
#include <kryptos_padding.h>
#include <kryptos_task_check.h>
#include <kryptos.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <string.h>
#endif

#define kryptos_idea_get_byte_from_u32(x, b) ( (x) << (24 - (8 * abs(3 - (b) ) ) ) >> 24 )

#define kryptos_idea_get_byte_from_u16(x,b) ( (kryptos_u8_t) ( (x) << (8 * (b) ) >> 8 ) )

#define kryptos_idea_mul(x, y) ( (x) == 0  ? (1 - (y)) : (y) == 0 ? (1 - (x)) : (((kryptos_u32_t)(x) * (y)) % 0x10001) )

struct kryptos_idea_subkeys {
    kryptos_u16_t K[52];
};

typedef void (*kryptos_idea_block_processor)(kryptos_u8_t *block, const struct kryptos_idea_subkeys *sks);

static void kryptos_idea_128bit_roll(kryptos_u32_t *x, int degree);

static void kryptos_idea_key_expander(const kryptos_u8_t *key, const size_t key_size, struct kryptos_idea_subkeys *sks);

static void kryptos_idea_ld_user_key(kryptos_u32_t *key, const kryptos_u8_t *user_key, const size_t user_key_size);

static void kryptos_idea_block_encrypt(kryptos_u8_t *block, const struct kryptos_idea_subkeys *sks);

static void kryptos_idea_get_inv_multiplier(kryptos_u16_t *inv, kryptos_u16_t value);

static void kryptos_idea_inv_subkeys(struct kryptos_idea_subkeys *sks);

static void kryptos_idea_block_decrypt(kryptos_u8_t *block, const struct kryptos_idea_subkeys *sks);

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_SETUP(idea, kKryptosCipherIDEA, KRYPTOS_IDEA_BLOCKSIZE)

KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(idea,
                                    ktask,
                                    kryptos_idea_subkeys,
                                    sks,
                                    kryptos_idea_block_processor,
                                    idea_block_processor,
                                    kryptos_idea_key_expander((*ktask)->key, (*ktask)->key_size, &sks),
                                    kryptos_idea_block_encrypt, /*No additional steps before encrypting*/,
                                    kryptos_idea_block_decrypt, kryptos_idea_inv_subkeys(&sks),
                                    KRYPTOS_IDEA_BLOCKSIZE,
                                    idea_cipher_epilogue,
                                    outblock,
                                    idea_block_processor(outblock, &sks))

static void kryptos_idea_128bit_roll(kryptos_u32_t *x, int degree) {
    kryptos_u32_t xx[4];

    xx[0] = x[0] >> 31;
    xx[1] = x[1] >> 31;
    xx[2] = x[2] >> 31;
    xx[3] = x[3] >> 31;

    x[0] = x[0] << 1 | xx[1];
    x[1] = x[1] << 1 | xx[2];
    x[2] = x[2] << 1 | xx[3];
    x[3] = x[3] << 1 | xx[0];

    if (degree > 1) {
        kryptos_idea_128bit_roll(x, --degree);
    }
}

static void kryptos_idea_ld_user_key(kryptos_u32_t *key, const kryptos_u8_t *user_key, const size_t user_key_size) {
    //  TIP(Rafael): Let's make a cipher implementation the most self-contained possible. So is easier to
    //               apply improvements here without screwing up the implementation of other ciphers that maybe
    //               we do not have any idea about.

    const kryptos_u8_t *kp, *kp_end;
    size_t b;
    size_t w;

    kryptos_ld_user_key_prologue(key, 4, user_key, user_key_size, kp, kp_end, w, b, return);

    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_idea_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_idea_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_idea_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_idea_ld_user_key_epilogue);

    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_idea_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_idea_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_idea_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_idea_ld_user_key_epilogue);

    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_idea_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_idea_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_idea_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_idea_ld_user_key_epilogue);

    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_idea_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_idea_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_idea_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_idea_ld_user_key_epilogue);

    kryptos_ld_user_key_epilogue(kryptos_idea_ld_user_key_epilogue, key, w, b, kp, kp_end);
}

static void kryptos_idea_key_expander(const kryptos_u8_t *key, const size_t key_size, struct kryptos_idea_subkeys *sks) {
    kryptos_u32_t uk[4];
    size_t w;

    kryptos_idea_ld_user_key(uk, key, key_size);

    for (w = 0; w < 48; kryptos_idea_128bit_roll(uk, 25), w += 8) {
        sks->K[  w  ] = (kryptos_u16_t) (uk[0] >> 16);
        sks->K[w + 1] = (kryptos_u16_t) (uk[0] & 0x0000ffff);
        sks->K[w + 2] = (kryptos_u16_t) (uk[1] >> 16);
        sks->K[w + 3] = (kryptos_u16_t) (uk[1] & 0x0000ffff);
        sks->K[w + 4] = (kryptos_u16_t) (uk[2] >> 16);
        sks->K[w + 5] = (kryptos_u16_t) (uk[2] & 0x0000ffff);
        sks->K[w + 6] = (kryptos_u16_t) (uk[3] >> 16);
        sks->K[w + 7] = (kryptos_u16_t) (uk[3] & 0x0000ffff);
    }

    sks->K[ w ] = (kryptos_u16_t) (uk[0] >> 16);
    sks->K[w+1] = (kryptos_u16_t) (uk[0] & 0x0000ffff);
    sks->K[w+2] = (kryptos_u16_t) (uk[1] >> 16);
    sks->K[w+3] = (kryptos_u16_t) (uk[1] & 0x0000ffff);

    memset(uk, 0L, sizeof(kryptos_u32_t) * 4);
}

static void kryptos_idea_block_encrypt(kryptos_u8_t *block, const struct kryptos_idea_subkeys *sks) {
    kryptos_u16_t y1, y2, z1, z2;
    kryptos_u16_t out[4];
    size_t r;

    out[0] = kryptos_get_u16_as_big_endian(block, 2);
    out[1] = kryptos_get_u16_as_big_endian(block + 2, 2);
    out[2] = kryptos_get_u16_as_big_endian(block + 4, 2);
    out[3] = kryptos_get_u16_as_big_endian(block + 6, 2);

    for (r = 0; r < 48; r += 6) {
        // INFO(Rafael): Iteration first part.
        out[0] = kryptos_idea_mul(out[0], sks->K[r]);
        out[3] = kryptos_idea_mul(out[3], sks->K[r + 3]);
        y1 = out[1];
        out[1] = out[2] + sks->K[r + 2];
        out[2] = y1 + sks->K[r + 1];

        // INFO(Rafael): Iteration second part.
        y1 = out[0] ^ out[1];
        z1 = out[2] ^ out[3];
        y2  = kryptos_idea_mul(sks->K[r + 4], y1);
        y2 += z1;
        y2  = kryptos_idea_mul(y2, sks->K[r + 5]);

        z2  = kryptos_idea_mul(sks->K[r + 4], y1);
        z2 += y2;

        out[0] = out[0] ^ y2;
        out[1] = out[1] ^ y2;
        out[2] = out[2] ^ z2;
        out[3] = out[3] ^ z2;
    }

    // INFO(Rafael): Final T transform
    out[0] = kryptos_idea_mul(out[0], sks->K[48]);
    out[3] = kryptos_idea_mul(out[3], sks->K[51]);
    y1 = out[1];
    out[1] = out[2] + sks->K[49];
    out[2] = y1 + sks->K[50];

    kryptos_cpy_u16_as_big_endian(block, 8, out[0]);
    kryptos_cpy_u16_as_big_endian(block + 2, 6, out[1]);
    kryptos_cpy_u16_as_big_endian(block + 4, 4, out[2]);
    kryptos_cpy_u16_as_big_endian(block + 6, 2, out[3]);

    memset(out, 0, sizeof(out));
    y1 = y2 = z1 = z2 = 0;
    r = 0;
}

static void kryptos_idea_get_inv_multiplier(kryptos_u16_t *inv, kryptos_u16_t value) {
    kryptos_u16_t t0, t1, q, y;

    if (value <= 1) {
        //*inv = value;
        return;
    }

    t1 = 0x10001 / value;
    y = 0x10001 % value;
    if (y == 1) {
        *inv = ((1 - t1) & 0xffff);
        goto kryptos_idea_get_inv_mul_epilogue;
    }

    t0 = 1;

    do {
        q = value / y;
        value = value % y;
        t0 += q * t1;
        if (value == 1) {
            *inv = t0;
            goto kryptos_idea_get_inv_mul_epilogue;
        }
        q = y / value;
        y = y % value;
        t1 += q * t0;
    } while (y != 1);
    *inv = ((1 - t1) & 0xffff);

kryptos_idea_get_inv_mul_epilogue:
    t0 = t1 = q = y = 0;
}

static void kryptos_idea_inv_subkeys(struct kryptos_idea_subkeys *sks) {
    size_t w;

    for (w = 0; w < 52; w += 6) {
        // CLUE(Rafael): Why return by reference instead of returning the value?
        //               "Finished with my woman 'cause she couldn't help me with my mind...", what is the song name???
        kryptos_idea_get_inv_multiplier(&sks->K[w], sks->K[w]);
        kryptos_idea_get_inv_multiplier(&sks->K[w + 3], sks->K[w + 3]);
    }
}

static void kryptos_idea_block_decrypt(kryptos_u8_t *block, const struct kryptos_idea_subkeys *sks) {
    //  INFO(Rafael): The IDEA was designed to use the same ciphering circuit both on encryption and decryption.
    //                In this case, the subkeys are permutated when performing the decryption.
    //                Here, I am not doing this. My deciphering implementation traverses inversely the subkeys and
    //                only pre calculates the inverses of SK_{w} and SK_{w + 3}. We do not need the inverses of
    //                SK_{w + 4} and SK_{w + 5} and each addition's inverse is applied directly through subtractions.

    kryptos_u16_t y1, y2, z1, z2;
    kryptos_u16_t out[4];
    int r;

    out[0] = kryptos_get_u16_as_big_endian(block, 2);
    out[1] = kryptos_get_u16_as_big_endian(block + 2, 2);
    out[2] = kryptos_get_u16_as_big_endian(block + 4, 2);
    out[3] = kryptos_get_u16_as_big_endian(block + 6, 2);

    // INFO(Rafael): Initial T transform.
    out[0] = kryptos_idea_mul(out[0], sks->K[48]);
    out[3] = kryptos_idea_mul(out[3], sks->K[51]);
    y1 = out[1];
    out[1] = out[2] - sks->K[50];
    out[2] = y1 - sks->K[49];

    for (r = 42; r >= 0; r -= 6) {
        // INFO(Rafael): Iteration first part.
        y1 = out[0] ^ out[1];
        z1 = out[2] ^ out[3];

        y2  = kryptos_idea_mul(sks->K[r + 4], y1);
        y2 += z1;
        y2  = kryptos_idea_mul(y2, sks->K[r + 5]);

        z2  = kryptos_idea_mul(sks->K[r + 4], y1);
        z2 += y2;

        out[0] = out[0] ^ y2;
        out[1] = out[1] ^ y2;
        out[2] = out[2] ^ z2;
        out[3] = out[3] ^ z2;

        // INFO(Rafael): Iteration second part.
        out[0] = kryptos_idea_mul(out[0], sks->K[r]);
        out[3] = kryptos_idea_mul(out[3], sks->K[r + 3]);
        y1 = out[1];
        out[1] = out[2] - sks->K[r + 1];
        out[2] = y1 - sks->K[r + 2];
    }

    kryptos_cpy_u16_as_big_endian(block, 8, out[0]);
    kryptos_cpy_u16_as_big_endian(block + 2, 6, out[1]);
    kryptos_cpy_u16_as_big_endian(block + 4, 4, out[2]);
    kryptos_cpy_u16_as_big_endian(block + 6, 2, out[3]);

    memset(out, 0, sizeof(out));
    y1 = y2 = z1 = z2 = 0;
    r = 0;
}

#undef kryptos_idea_get_byte_from_u32

#undef kryptos_idea_get_byte_from_u16

#undef kryptos_idea_mul
