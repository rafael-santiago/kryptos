/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_shacal2.h>
#include <kryptos_endianness_utils.h>
#include <kryptos_task_check.h>
#include <kryptos_random.h>
#include <kryptos_padding.h>
#include <kryptos.h>

// INFO(Rafael): The SHACAL-2 implementation follows the same approach and ideas introduced in 'kryptos_shacal1.c'.

#define kryptos_shacal2_CH(x, y, z) ( ( (x) & (y) ) ^ ( (~(x)) & (z) ) )

#define kryptos_shacal2_MAJ(x, y, z) ( ( (x) & (y) ) ^ ( (x) & (z) ) ^ ( (y) & (z) ) )

#define kryptos_shacal2_ROTR(x, lv) ( ( (x) >> (lv) ) | ( (x) << ( (sizeof(x) << 3) - (lv) ) ) )

#define kryptos_shacal2_ROTL(x, lv) ( ( (x) << (lv) ) | ( (x) >> ( (sizeof(x) << 3) - (lv) ) ) )

#define kryptos_shacal2_BSIG0(x) ( kryptos_shacal2_ROTR(x,  2) ^\
                                   kryptos_shacal2_ROTR(x, 13) ^\
                                   kryptos_shacal2_ROTR(x, 22) )

#define kryptos_shacal2_BSIG1(x) ( kryptos_shacal2_ROTR(x,  6) ^\
                                   kryptos_shacal2_ROTR(x, 11) ^\
                                   kryptos_shacal2_ROTR(x, 25) )

#define kryptos_shacal2_SSIG0(x) ( kryptos_shacal2_ROTR(x,  7) ^\
                                   kryptos_shacal2_ROTR(x, 18) ^\
                                      ( (x) >> 3 ) )

#define kryptos_shacal2_SSIG1(x) ( kryptos_shacal2_ROTR(x, 17) ^\
                                   kryptos_shacal2_ROTR(x, 19) ^\
                                      ( (x) >> 10 ) )

static kryptos_u32_t kryptos_shacal2_K[64] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25b, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

struct kryptos_shacal2_subkeys {
    kryptos_u32_t W[64];
};

typedef void (*kryptos_shacal2_block_processor)(kryptos_u8_t *block, const struct kryptos_shacal2_subkeys *sks);

static void kryptos_shacal2_ld_user_key(kryptos_u32_t *key, const kryptos_u8_t *user_key, const size_t user_key_size);

static void kryptos_shacal2_key_sched(const kryptos_u8_t *key, const size_t key_size, struct kryptos_shacal2_subkeys *sks);

static void kryptos_shacal2_block_encrypt(kryptos_u8_t *block, const struct kryptos_shacal2_subkeys *sks);

static void kryptos_shacal2_block_decrypt(kryptos_u8_t *block, const struct kryptos_shacal2_subkeys *sks);

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_SETUP(shacal2, kKryptosCipherSHACAL2, KRYPTOS_SHACAL2_BLOCKSIZE)

KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(shacal2,
                                    ktask,
                                    kryptos_shacal2_subkeys,
                                    sks,
                                    kryptos_shacal2_block_processor,
                                    shacal2_block_processor,
                                    kryptos_shacal2_key_sched((*ktask)->key, (*ktask)->key_size, &sks),
                                    kryptos_shacal2_block_encrypt, /* No additional steps before encrypting */,
                                    kryptos_shacal2_block_decrypt, /* No additional steps before decrypting */,
                                    KRYPTOS_SHACAL2_BLOCKSIZE,
                                    shacal2_cipher_epilogue,
                                    outblock,
                                    shacal2_block_processor(outblock, &sks))

static void kryptos_shacal2_ld_user_key(kryptos_u32_t *key, const kryptos_u8_t *user_key, const size_t user_key_size) {
    const kryptos_u8_t *kp, *kp_end;
    size_t w, b;

    kryptos_ld_user_key_prologue(key, 16, user_key, user_key_size, kp, kp_end, w, b, return);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal2_ld_user_key_epilogue);
    kryptos_ld_user_key_epilogue(kryptos_shacal2_ld_user_key_epilogue, key, w, b, kp, kp_end);
}

static void kryptos_shacal2_key_sched(const kryptos_u8_t *key, const size_t key_size, struct kryptos_shacal2_subkeys *sks) {
    size_t t;

    kryptos_shacal2_ld_user_key(&sks->W[0], key, key_size);

    for (t = 16; t < 64; t++) {
        sks->W[t] = kryptos_shacal2_SSIG1(sks->W[t -  2]) + sks->W[t -  7] +
                    kryptos_shacal2_SSIG0(sks->W[t - 15]) + sks->W[t - 16];
    }
}

static void kryptos_shacal2_block_encrypt(kryptos_u8_t *block, const struct kryptos_shacal2_subkeys *sks) {
    kryptos_u32_t a, b, c, d, e, f, g, h, T1, T2;
    size_t t;

    a = kryptos_get_u32_as_big_endian(block     , 4);
    b = kryptos_get_u32_as_big_endian(block +  4, 4);
    c = kryptos_get_u32_as_big_endian(block +  8, 4);
    d = kryptos_get_u32_as_big_endian(block + 12, 4);
    e = kryptos_get_u32_as_big_endian(block + 16, 4);
    f = kryptos_get_u32_as_big_endian(block + 20, 4);
    g = kryptos_get_u32_as_big_endian(block + 24, 4);
    h = kryptos_get_u32_as_big_endian(block + 28, 4);

    for (t = 0; t < 64; t++) {
        T1 = h + kryptos_shacal2_BSIG1(e) + kryptos_shacal2_CH(e, f, g) + kryptos_shacal2_K[t] + sks->W[t];
        T2 = kryptos_shacal2_BSIG0(a) + kryptos_shacal2_MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    kryptos_cpy_u32_as_big_endian(block     , 32, a);
    kryptos_cpy_u32_as_big_endian(block +  4, 28, b);
    kryptos_cpy_u32_as_big_endian(block +  8, 24, c);
    kryptos_cpy_u32_as_big_endian(block + 12, 20, d);
    kryptos_cpy_u32_as_big_endian(block + 16, 16, e);
    kryptos_cpy_u32_as_big_endian(block + 20, 12, f);
    kryptos_cpy_u32_as_big_endian(block + 24,  8, g);
    kryptos_cpy_u32_as_big_endian(block + 28,  4, h);

    a = b = c = d = e = f = g = h = T1 = T2 = 0;
}

static void kryptos_shacal2_block_decrypt(kryptos_u8_t *block, const struct kryptos_shacal2_subkeys *sks) {
    kryptos_u32_t a, b, c, d, e, f, g, h, T1, T2;
    ssize_t t;

    a = kryptos_get_u32_as_big_endian(block     , 4);
    b = kryptos_get_u32_as_big_endian(block +  4, 4);
    c = kryptos_get_u32_as_big_endian(block +  8, 4);
    d = kryptos_get_u32_as_big_endian(block + 12, 4);
    e = kryptos_get_u32_as_big_endian(block + 16, 4);
    f = kryptos_get_u32_as_big_endian(block + 20, 4);
    g = kryptos_get_u32_as_big_endian(block + 24, 4);
    h = kryptos_get_u32_as_big_endian(block + 28, 4);

    for (t = 63; t >= 0; t--) {
        // INFO(Rafael): Decrypt it is even easier than SHACAL-1 since we do not need any inverse for any circular shift.
        T1 = a;
        a = b;
        b = c;
        c = d;
        d = e;
        e = f;
        f = g;
        g = h;
        T2 = kryptos_shacal2_BSIG0(a) + kryptos_shacal2_MAJ(a, b, c);
        T1 -= T2;
        d -= T1;
        h = T1 - (kryptos_shacal2_BSIG1(e) + kryptos_shacal2_CH(e, f, g) + kryptos_shacal2_K[t] + sks->W[t]);
    }

    kryptos_cpy_u32_as_big_endian(block     , 32, a);
    kryptos_cpy_u32_as_big_endian(block +  4, 28, b);
    kryptos_cpy_u32_as_big_endian(block +  8, 24, c);
    kryptos_cpy_u32_as_big_endian(block + 12, 20, d);
    kryptos_cpy_u32_as_big_endian(block + 16, 16, e);
    kryptos_cpy_u32_as_big_endian(block + 20, 12, f);
    kryptos_cpy_u32_as_big_endian(block + 24,  8, g);
    kryptos_cpy_u32_as_big_endian(block + 28,  4, h);

    a = b = c = d = e = f = g = h = T1 = T2 = 0;
}

#undef kryptos_shacal2_CH

#undef kryptos_shacal2_MAJ

#undef kryptos_shacal2_ROTR

#undef kryptos_shacal2_BSIG0

#undef kryptos_shacal2_BSIG1

#undef kryptos_shacal2_SSIG0

#undef kryptos_shacal2_SSIG1