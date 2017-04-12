/*
 *                          Copyright (C) 2007, 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_idea.h>
#include <kryptos_endianess_utils.h>
#include <kryptos_random.h>
#include <kryptos_padding.h>
#include <kryptos_task_check.h>
#include <kryptos.h>
#include <string.h>

#define kryptos_idea_get_byte_from_u32(x, b) ( (x) << (24 - (8 * abs(3 - (b) ) ) ) >> 24 )

#define kryptos_idea_get_byte_from_u16(x,b) ( (kryptos_u8_t) ( (x) << (8 * (b) ) >> 8 ) )

#define kryptos_idea_mul(x, y) ( (x) == 0  ? (1 - (y)) : (y) == 0 ? (1 - (x)) : (((kryptos_u32_t)(x) * (y)) % 0x10001) )

struct kryptos_idea_subkeys {
    kryptos_u16_t K[52];
};

typedef void (*kryptos_idea_block_processor)(kryptos_u8_t *block, struct kryptos_idea_subkeys sks);

static void kryptos_idea_128bit_roll(kryptos_u32_t x[4], int degree);

static void kryptos_idea_key_expander(const kryptos_u8_t *key, const size_t key_size, struct kryptos_idea_subkeys *sks);

static void kryptos_idea_ld_user_key(kryptos_u32_t key[4], const kryptos_u8_t *user_key, const size_t user_key_size);

static void kryptos_idea_block_encrypt(kryptos_u8_t *block, struct kryptos_idea_subkeys sks);

static kryptos_u16_t kryptos_idea_get_inv_multiplier(kryptos_u16_t value);

static void kryptos_idea_inv_subkeys(struct kryptos_idea_subkeys *sks);

static void kryptos_idea_block_decrypt(kryptos_u8_t *block, struct kryptos_idea_subkeys sks);

static void kryptos_idea_128bit_roll(kryptos_u32_t x[4], int degree) {
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

static void kryptos_idea_ld_user_key(kryptos_u32_t key[4], const kryptos_u8_t *user_key, const size_t user_key_size) {
    //  TIP(Rafael): Let's make a cipher implementation the most self-contained possible. So is easier to
    //               apply improvements here without screw up the implementation of other ciphers that maybe
    //               we do not have any idea about.

    const kryptos_u8_t *kp, *kp_end;
    size_t b;
    size_t w;

    memset(key, 0, sizeof(kryptos_u32_t) * 4);

    if (user_key == NULL || user_key_size == 0) {
        return;
    }

    kp = user_key;
    kp_end = kp + user_key_size;
    b = 0;
    w = 0;

#define kryptos_idea_ld_user_key_byte(state, kp, kp_end, label) {\
    if (kp == kp_end) goto kryptos_idea_ld_user_key_ ## label;\
    state = (state << 8) | (kryptos_u32_t)*kp;\
    kp++;\
    b = (b + 1) % sizeof(kryptos_u32_t);\
    if (b == 0) {\
        w = 1;\
    }\
}

    kryptos_idea_ld_user_key_byte(key[w], kp, kp_end, epilogue);
    kryptos_idea_ld_user_key_byte(key[w], kp, kp_end, epilogue);
    kryptos_idea_ld_user_key_byte(key[w], kp, kp_end, epilogue);
    kryptos_idea_ld_user_key_byte(key[w], kp, kp_end, epilogue);

    kryptos_idea_ld_user_key_byte(key[w], kp, kp_end, epilogue);
    kryptos_idea_ld_user_key_byte(key[w], kp, kp_end, epilogue);
    kryptos_idea_ld_user_key_byte(key[w], kp, kp_end, epilogue);
    kryptos_idea_ld_user_key_byte(key[w], kp, kp_end, epilogue);

    kryptos_idea_ld_user_key_byte(key[w], kp, kp_end, epilogue);
    kryptos_idea_ld_user_key_byte(key[w], kp, kp_end, epilogue);
    kryptos_idea_ld_user_key_byte(key[w], kp, kp_end, epilogue);
    kryptos_idea_ld_user_key_byte(key[w], kp, kp_end, epilogue);

    kryptos_idea_ld_user_key_byte(key[w], kp, kp_end, epilogue);
    kryptos_idea_ld_user_key_byte(key[w], kp, kp_end, epilogue);
    kryptos_idea_ld_user_key_byte(key[w], kp, kp_end, epilogue);
    kryptos_idea_ld_user_key_byte(key[w], kp, kp_end, epilogue);


#undef kryptos_idea_ld_user_key_byte

kryptos_idea_ld_user_key_epilogue:

    key[w] = key[w] << (b * sizeof(kryptos_u8_t));

    b = w = 0;
    kp = NULL;
    kp_end = NULL;
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

static void kryptos_idea_block_encrypt(kryptos_u8_t *block, struct kryptos_idea_subkeys sks) {
    kryptos_u16_t y1, y2, z1, z2;
    kryptos_u16_t out[4];
    size_t r;

    out[0] = kryptos_get_u16_as_big_endian(block, 2);
    out[1] = kryptos_get_u16_as_big_endian(block + 2, 2);
    out[2] = kryptos_get_u16_as_big_endian(block + 4, 2);
    out[3] = kryptos_get_u16_as_big_endian(block + 6, 2);

    for (r = 0; r < 48; r += 6) {
        // INFO(Rafael): Iteration first part.
        out[0] = kryptos_idea_mul(out[0], sks.K[r]);
        out[3] = kryptos_idea_mul(out[3], sks.K[r + 3]);
        y1 = out[1];
        out[1] = out[2] + sks.K[r + 2];
        out[2] = y1 + sks.K[r + 1];

        // INFO(Rafael): Iteration second part.
        y1 = out[0] ^ out[1];
        z1 = out[2] ^ out[3];
        y2  = kryptos_idea_mul(sks.K[r + 4], y1);
        y2 += z1;
        y2  = kryptos_idea_mul(y2, sks.K[r + 5]);

        z2  = kryptos_idea_mul(sks.K[r + 4], y1);
        z2 += y2;

        out[0] = out[0] ^ y2;
        out[1] = out[1] ^ y2;
        out[2] = out[2] ^ z2;
        out[3] = out[3] ^ z2;
    }

    // INFO(Rafael): Final T transform
    out[0] = kryptos_idea_mul(out[0], sks.K[48]);
    out[3] = kryptos_idea_mul(out[3], sks.K[51]);
    y1 = out[1];
    out[1] = out[2] + sks.K[49];
    out[2] = y1 + sks.K[50];

    kryptos_cpy_u16_as_big_endian(block, 8, out[0]);
    kryptos_cpy_u16_as_big_endian(block + 2, 6, out[1]);
    kryptos_cpy_u16_as_big_endian(block + 4, 4, out[2]);
    kryptos_cpy_u16_as_big_endian(block + 6, 2, out[3]);

    memset(out, 0, sizeof(out));
    y1 = y2 = z1 = z2 = 0;
    r = 0;
}

static kryptos_u16_t kryptos_idea_get_inv_multiplier(kryptos_u16_t value) {
    kryptos_u16_t t0, t1, q, y;
    kryptos_u16_t inv = 0;

    if (value <= 1) {
        return value;
    }

    t1 = 0x10001 / value;
    y = 0x10001 % value;
    if (y == 1) {
        inv = ((1 - t1) & 0xffff);
        goto kryptos_idea_get_inv_mul_epilogue;
    }

    t0 = 1;

    do {
        q = value / y;
        value = value % y;
        t0 += q * t1;
        if (value == 1) {
            inv = t0;
            goto kryptos_idea_get_inv_mul_epilogue;
        }
        q = y / value;
        y = y % value;
        t1 += q * t0;
    } while (y != 1);
    inv = ((1 - t1) & 0xffff);

kryptos_idea_get_inv_mul_epilogue:
    t0 = t1 = q = y = 0;
    return inv;
}

static void kryptos_idea_inv_subkeys(struct kryptos_idea_subkeys *sks) {
    size_t w;

    for (w = 0; w < 52; w += 6) {
        sks->K[  w  ] = kryptos_idea_get_inv_multiplier(sks->K[w]);
        sks->K[w + 3] = kryptos_idea_get_inv_multiplier(sks->K[w + 3]);
    }
}

static void kryptos_idea_block_decrypt(kryptos_u8_t *block, struct kryptos_idea_subkeys sks) {
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
    out[0] = kryptos_idea_mul(out[0], sks.K[48]);
    out[3] = kryptos_idea_mul(out[3], sks.K[51]);
    y1 = out[1];
    out[1] = out[2] - sks.K[50];
    out[2] = y1 - sks.K[49];

    for (r = 42; r >= 0; r -= 6) {
        // INFO(Rafael): Iteration first part.
        y1 = out[0] ^ out[1];
        z1 = out[2] ^ out[3];

        y2  = kryptos_idea_mul(sks.K[r + 4], y1);
        y2 += z1;
        y2  = kryptos_idea_mul(y2, sks.K[r + 5]);

        z2  = kryptos_idea_mul(sks.K[r + 4], y1);
        z2 += y2;

        out[0] = out[0] ^ y2;
        out[1] = out[1] ^ y2;
        out[2] = out[2] ^ z2;
        out[3] = out[3] ^ z2;

        // INFO(Rafael): Iteration second part.
        out[0] = kryptos_idea_mul(out[0], sks.K[r]);
        out[3] = kryptos_idea_mul(out[3], sks.K[r + 3]);
        y1 = out[1];
        out[1] = out[2] - sks.K[r + 1];
        out[2] = y1 - sks.K[r + 2];
    }

    kryptos_cpy_u16_as_big_endian(block, 8, out[0]);
    kryptos_cpy_u16_as_big_endian(block + 2, 6, out[1]);
    kryptos_cpy_u16_as_big_endian(block + 4, 4, out[2]);
    kryptos_cpy_u16_as_big_endian(block + 6, 2, out[3]);

    memset(out, 0, sizeof(out));
    y1 = y2 = z1 = z2 = 0;
    r = 0;
}

void kryptos_idea_cipher(kryptos_task_ctx **ktask) {
    struct kryptos_idea_subkeys sks;
    kryptos_idea_block_processor idea_block_processor = NULL;
    kryptos_u8_t *in_p, *in_end, *out_p;
    kryptos_u8_t *outblock, *outblock_p, *inblock, *inblock_p;
    size_t in_size;

    if (kryptos_task_check(ktask) == 0) {
        return;
    }

    kryptos_idea_key_expander((*ktask)->key, (*ktask)->key_size, &sks);

    if ((*ktask)->action == kKryptosDecrypt) {
        idea_block_processor = kryptos_idea_block_decrypt;
        kryptos_idea_inv_subkeys(&sks);
    } else {
        idea_block_processor = kryptos_idea_block_encrypt;
    }

    kryptos_meta_block_processing_prologue(KRYPTOS_IDEA_BLOCKSIZE,
                                           inblock, inblock_p,
                                           outblock, outblock_p,
                                           in_size, (*ktask)->in_size);

    kryptos_meta_block_processing(KRYPTOS_IDEA_BLOCKSIZE,
                                  (*ktask)->action,
                                  (*ktask)->mode,
                                  (*ktask)->iv,
                                  (*ktask)->in,
                                  in_p, in_end,
                                  &in_size,
                                  (*ktask)->out, out_p,
                                  &(*ktask)->out_size,
                                  inblock_p,
                                  outblock_p,
                                  idea_cipher_epilogue, idea_block_processor(outblock, sks));

    kryptos_meta_block_processing_epilogue(idea_cipher_epilogue,
                                           inblock, inblock_p, in_p, in_end,
                                           outblock, outblock_p, out_p,
                                           in_size,
                                           sks, ktask);
    idea_block_processor = NULL;
}

void kryptos_idea_setup(kryptos_task_ctx *ktask, kryptos_u8_t *key, const size_t key_size,
                       const kryptos_cipher_mode_t mode) {
    if (ktask == NULL) {
        return;
    }

    ktask->cipher = kKryptosCipherIDEA;
    ktask->mode = mode;
    ktask->key = key;
    ktask->key_size = key_size;

    if (mode == kKryptosCBC && ktask->iv == NULL) {
        ktask->iv = kryptos_get_random_block(KRYPTOS_IDEA_BLOCKSIZE);
        ktask->iv_size = KRYPTOS_IDEA_BLOCKSIZE;
    }
}
