/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_noekeon.h>
#include <kryptos_endianness_utils.h>
#include <kryptos_task_check.h>
#include <kryptos_random.h>
#include <kryptos_padding.h>
#include <kryptos.h>

// INFO(Rafael): This implementation follows the original cipher specification and considers the remarks from authors relating
//               to rounds total.

#define KRYPTOS_NOEKEON_ROUNDS_NR 16

#define kryptos_noekeon_Round(k, s, c1, c2, t) {\
    (s)[0] ^= (c1);\
    kryptos_noekeon_Theta(k, s, t);\
    (s)[0] ^= (c2);\
    kryptos_noekeon_Pi1(s);\
    kryptos_noekeon_Gamma(s, t);\
    kryptos_noekeon_Pi2(s);\
}

// CLUE(Rafael): I am considering that any architecture will perform ~(a[3] | a[2]) quicker than (~a[3] & ~a[2]).
//               In general it should be true. If it does not, change according to your requirements.

#define kryptos_noekeon_Gamma(a, t) {\
    (a)[1] ^= ~((a)[3] | (a)[2]);\
    (a)[0] ^= (a)[2] & (a)[1];\
    (t) = (a)[3];\
    (a)[3] = (a)[0];\
    (a)[0] = (t);\
    (a)[2] ^= (a)[0] ^ (a)[1] ^ (a)[3];\
    (a)[1] ^= ~((a)[3] | (a)[2]);\
    (a)[0] ^= (a)[2] & (a)[1];\
}

#define kryptos_noekeon_Theta(k, a, t) {\
    (t) = (a)[0] ^ (a)[2];\
    (t) ^= kryptos_noekeon_lsh(t, 24) ^ kryptos_noekeon_lsh(t, 8);\
    (a)[1] ^= (t);\
    (a)[3] ^= (t);\
    (a)[0] ^= (k)[0];\
    (a)[1] ^= (k)[1];\
    (a)[2] ^= (k)[2];\
    (a)[3] ^= (k)[3];\
    (t) = (a)[1] ^ (a)[3];\
    (t) ^= kryptos_noekeon_lsh(t, 24) ^ kryptos_noekeon_lsh(t, 8);\
    (a)[0] ^= (t);\
    (a)[2] ^= (t);\
}

#define kryptos_noekeon_lsh(v, l) ( ( (v) << (l) ) | ( (v) >> (32 - (l)) ) )

// CLUE(Rafael): '#define kryptos_noekeon_rsh(v, l) kryptos_noekeon_lsh(v, 32 - l)'???!! Go to sleep (in hell) buddy!.. :)

#define kryptos_noekeon_Pi1(a) {\
    (a)[1] = kryptos_noekeon_lsh(a[1], 1);\
    (a)[2] = kryptos_noekeon_lsh(a[2], 5);\
    (a)[3] = kryptos_noekeon_lsh(a[3], 2);\
}

#define kryptos_noekeon_Pi2(a) {\
    (a)[1] = kryptos_noekeon_lsh(a[1], 31);\
    (a)[2] = kryptos_noekeon_lsh(a[2], 27);\
    (a)[3] = kryptos_noekeon_lsh(a[3], 30);\
}

static kryptos_u32_t kryptos_noekeon_RC[KRYPTOS_NOEKEON_ROUNDS_NR + 1] = {
    0x00000080, 0x0000001B, 0x00000036, 0x0000006C,
    0x000000D8, 0x000000AB, 0x0000004D, 0x0000009A,
    0x0000002F, 0x0000005E, 0x000000BC, 0x00000063,
    0x000000C6, 0x00000097, 0x00000035, 0x0000006A, 0x000000D4
};

struct kryptos_noekeon_subkeys {
    kryptos_u32_t K[4], NULL_K[4], temp;
};

typedef void (*kryptos_noekeon_block_processor)(kryptos_u8_t *block, const struct kryptos_noekeon_subkeys *sks);

static void kryptos_noekeon_key_sched(const kryptos_u8_t *key, const size_t key_size, struct kryptos_noekeon_subkeys *sks,
                                      const int indirect_key_mode);

static void kryptos_noekeon_block_encrypt(kryptos_u8_t *block, const struct kryptos_noekeon_subkeys *sks);

static void kryptos_noekeon_block_decrypt(kryptos_u8_t *block, const struct kryptos_noekeon_subkeys *sks);

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_SETUP(noekeon, kKryptosCipherNOEKEON, KRYPTOS_NOEKEON_BLOCKSIZE)

KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(noekeon,
                                    ktask,
                                    kryptos_noekeon_subkeys,
                                    sks,
                                    kryptos_noekeon_block_processor,
                                    noekeon_block_processor,
                                    kryptos_noekeon_key_sched((*ktask)->key, (*ktask)->key_size, &sks, 1),
                                    kryptos_noekeon_block_encrypt, /* No additional steps for encrypting */,
                                    kryptos_noekeon_block_decrypt,
                                    {
                                        sks.NULL_K[0] = sks.NULL_K[1] = sks.NULL_K[2] = sks.NULL_K[3] = 0;
                                        kryptos_noekeon_Theta(sks.NULL_K, sks.K, sks.temp);
                                    },
                                    KRYPTOS_NOEKEON_BLOCKSIZE,
                                    noekeon_cipher_epilogue,
                                    outblock,
                                    noekeon_block_processor(outblock, &sks),
                                    NULL /* GCM E function arg */)

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_GCM_E(noekeon)

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_SETUP(noekeon_d, kKryptosCipherNOEKEOND, KRYPTOS_NOEKEON_BLOCKSIZE)

KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(noekeon_d,
                                    ktask,
                                    kryptos_noekeon_subkeys,
                                    sks,
                                    kryptos_noekeon_block_processor,
                                    noekeon_block_processor,
                                    kryptos_noekeon_key_sched((*ktask)->key, (*ktask)->key_size, &sks, 0),
                                    kryptos_noekeon_block_encrypt, /* No additional steps for encrypting */,
                                    kryptos_noekeon_block_decrypt,
                                    {
                                        sks.NULL_K[0] = sks.NULL_K[1] = sks.NULL_K[2] = sks.NULL_K[3] = 0;
                                        kryptos_noekeon_Theta(sks.NULL_K, sks.K, sks.temp);
                                    },
                                    KRYPTOS_NOEKEON_BLOCKSIZE,
                                    noekeon_cipher_epilogue,
                                    outblock,
                                    noekeon_block_processor(outblock, &sks),
                                    NULL /* GCM E function arg */)

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_GCM_E(noekeon_d)

static void kryptos_noekeon_key_sched(const kryptos_u8_t *key, const size_t key_size, struct kryptos_noekeon_subkeys *sks,
                                      const int indirect_key_mode) {
    const kryptos_u8_t *kp, *kp_end;
    size_t w, b;
    kryptos_u8_t block[KRYPTOS_NOEKEON_BLOCKSIZE];

    if (indirect_key_mode) {
        block[ 0] = block[ 1] = block[ 2] = block[ 3] =
        block[ 4] = block[ 5] = block[ 6] = block[ 7] =
        block[ 8] = block[ 9] = block[10] = block[11] =
        block[12] = block[13] = block[14] = block[15] = 0;

        // TODO(Rafael): Maybe save one call here too, it seems a kind of useless.
        memcpy(block, key, key_size);

        sks->K[0] = sks->K[1] = sks->K[2] = sks->K[3] = 0;

        kryptos_noekeon_block_encrypt(block, sks);

        sks->K[0] = block[ 0] << 24 | block[ 1] << 16 | block[ 2] << 8 | block[ 3];
        sks->K[1] = block[ 4] << 24 | block[ 5] << 16 | block[ 6] << 8 | block[ 7];
        sks->K[2] = block[ 8] << 24 | block[ 9] << 16 | block[10] << 8 | block[11];
        sks->K[3] = block[12] << 24 | block[13] << 16 | block[14] << 8 | block[15];

        block[ 0] = block[ 1] = block[ 2] = block[ 3] =
        block[ 4] = block[ 5] = block[ 6] = block[ 7] =
        block[ 8] = block[ 9] = block[10] = block[11] =
        block[12] = block[13] = block[14] = block[15] = 0;
    } else {
        // INFO(Rafael): Let's save one call.
        kryptos_ld_user_key_prologue(sks->K, 4, key, key_size, kp, kp_end, w, b, return);
            kryptos_ld_user_key_byte(sks->K, 4, w, b, kp, kp_end, kryptos_noekeon_ld_user_key_epilogue);
            kryptos_ld_user_key_byte(sks->K, 4, w, b, kp, kp_end, kryptos_noekeon_ld_user_key_epilogue);
            kryptos_ld_user_key_byte(sks->K, 4, w, b, kp, kp_end, kryptos_noekeon_ld_user_key_epilogue);
            kryptos_ld_user_key_byte(sks->K, 4, w, b, kp, kp_end, kryptos_noekeon_ld_user_key_epilogue);
            kryptos_ld_user_key_byte(sks->K, 4, w, b, kp, kp_end, kryptos_noekeon_ld_user_key_epilogue);
            kryptos_ld_user_key_byte(sks->K, 4, w, b, kp, kp_end, kryptos_noekeon_ld_user_key_epilogue);
            kryptos_ld_user_key_byte(sks->K, 4, w, b, kp, kp_end, kryptos_noekeon_ld_user_key_epilogue);
            kryptos_ld_user_key_byte(sks->K, 4, w, b, kp, kp_end, kryptos_noekeon_ld_user_key_epilogue);
            kryptos_ld_user_key_byte(sks->K, 4, w, b, kp, kp_end, kryptos_noekeon_ld_user_key_epilogue);
            kryptos_ld_user_key_byte(sks->K, 4, w, b, kp, kp_end, kryptos_noekeon_ld_user_key_epilogue);
            kryptos_ld_user_key_byte(sks->K, 4, w, b, kp, kp_end, kryptos_noekeon_ld_user_key_epilogue);
            kryptos_ld_user_key_byte(sks->K, 4, w, b, kp, kp_end, kryptos_noekeon_ld_user_key_epilogue);
            kryptos_ld_user_key_byte(sks->K, 4, w, b, kp, kp_end, kryptos_noekeon_ld_user_key_epilogue);
            kryptos_ld_user_key_byte(sks->K, 4, w, b, kp, kp_end, kryptos_noekeon_ld_user_key_epilogue);
            kryptos_ld_user_key_byte(sks->K, 4, w, b, kp, kp_end, kryptos_noekeon_ld_user_key_epilogue);
            kryptos_ld_user_key_byte(sks->K, 4, w, b, kp, kp_end, kryptos_noekeon_ld_user_key_epilogue);
        kryptos_ld_user_key_epilogue(kryptos_noekeon_ld_user_key_epilogue, sks->K, 4, w, b, kp, kp_end);
    }
}

static void kryptos_noekeon_block_encrypt(kryptos_u8_t *block, const struct kryptos_noekeon_subkeys *sks) {
    kryptos_u32_t temp, state[4];

    state[0] = kryptos_get_u32_as_big_endian(     block, 4);
    state[1] = kryptos_get_u32_as_big_endian(block +  4, 4);
    state[2] = kryptos_get_u32_as_big_endian(block +  8, 4);
    state[3] = kryptos_get_u32_as_big_endian(block + 12, 4);

    kryptos_noekeon_Round(sks->K, state, kryptos_noekeon_RC[ 0], 0, temp);
    kryptos_noekeon_Round(sks->K, state, kryptos_noekeon_RC[ 1], 0, temp);
    kryptos_noekeon_Round(sks->K, state, kryptos_noekeon_RC[ 2], 0, temp);
    kryptos_noekeon_Round(sks->K, state, kryptos_noekeon_RC[ 3], 0, temp);
    kryptos_noekeon_Round(sks->K, state, kryptos_noekeon_RC[ 4], 0, temp);
    kryptos_noekeon_Round(sks->K, state, kryptos_noekeon_RC[ 5], 0, temp);
    kryptos_noekeon_Round(sks->K, state, kryptos_noekeon_RC[ 6], 0, temp);
    kryptos_noekeon_Round(sks->K, state, kryptos_noekeon_RC[ 7], 0, temp);
    kryptos_noekeon_Round(sks->K, state, kryptos_noekeon_RC[ 8], 0, temp);
    kryptos_noekeon_Round(sks->K, state, kryptos_noekeon_RC[ 9], 0, temp);
    kryptos_noekeon_Round(sks->K, state, kryptos_noekeon_RC[10], 0, temp);
    kryptos_noekeon_Round(sks->K, state, kryptos_noekeon_RC[11], 0, temp);
    kryptos_noekeon_Round(sks->K, state, kryptos_noekeon_RC[12], 0, temp);
    kryptos_noekeon_Round(sks->K, state, kryptos_noekeon_RC[13], 0, temp);
    kryptos_noekeon_Round(sks->K, state, kryptos_noekeon_RC[14], 0, temp);
    kryptos_noekeon_Round(sks->K, state, kryptos_noekeon_RC[15], 0, temp);

    state[0] ^= kryptos_noekeon_RC[16];

    kryptos_noekeon_Theta(sks->K, state, temp);

    kryptos_cpy_u32_as_big_endian(     block, 16, state[0]);
    kryptos_cpy_u32_as_big_endian(block +  4, 12, state[1]);
    kryptos_cpy_u32_as_big_endian(block +  8,  8, state[2]);
    kryptos_cpy_u32_as_big_endian(block + 12,  4, state[3]);

    temp = state[0] = state[1] = state[2] = state[3] = 0;
}

static void kryptos_noekeon_block_decrypt(kryptos_u8_t *block, const struct kryptos_noekeon_subkeys *sks) {
    kryptos_u32_t temp, state[4];

    // WARN(Rafael): At this point the computation of the 'inverse' working key has already occurred,
    //               in the cipher's processor.

    state[0] = kryptos_get_u32_as_big_endian(     block, 4);
    state[1] = kryptos_get_u32_as_big_endian(block +  4, 4);
    state[2] = kryptos_get_u32_as_big_endian(block +  8, 4);
    state[3] = kryptos_get_u32_as_big_endian(block + 12, 4);

    kryptos_noekeon_Round(sks->K, state, 0, kryptos_noekeon_RC[16], temp);
    kryptos_noekeon_Round(sks->K, state, 0, kryptos_noekeon_RC[15], temp);
    kryptos_noekeon_Round(sks->K, state, 0, kryptos_noekeon_RC[14], temp);
    kryptos_noekeon_Round(sks->K, state, 0, kryptos_noekeon_RC[13], temp);
    kryptos_noekeon_Round(sks->K, state, 0, kryptos_noekeon_RC[12], temp);
    kryptos_noekeon_Round(sks->K, state, 0, kryptos_noekeon_RC[11], temp);
    kryptos_noekeon_Round(sks->K, state, 0, kryptos_noekeon_RC[10], temp);
    kryptos_noekeon_Round(sks->K, state, 0, kryptos_noekeon_RC[ 9], temp);
    kryptos_noekeon_Round(sks->K, state, 0, kryptos_noekeon_RC[ 8], temp);
    kryptos_noekeon_Round(sks->K, state, 0, kryptos_noekeon_RC[ 7], temp);
    kryptos_noekeon_Round(sks->K, state, 0, kryptos_noekeon_RC[ 6], temp);
    kryptos_noekeon_Round(sks->K, state, 0, kryptos_noekeon_RC[ 5], temp);
    kryptos_noekeon_Round(sks->K, state, 0, kryptos_noekeon_RC[ 4], temp);
    kryptos_noekeon_Round(sks->K, state, 0, kryptos_noekeon_RC[ 3], temp);
    kryptos_noekeon_Round(sks->K, state, 0, kryptos_noekeon_RC[ 2], temp);
    kryptos_noekeon_Round(sks->K, state, 0, kryptos_noekeon_RC[ 1], temp);

    kryptos_noekeon_Theta(sks->K, state, temp);

    state[0] ^= kryptos_noekeon_RC[0];

    kryptos_cpy_u32_as_big_endian(     block, 16, state[0]);
    kryptos_cpy_u32_as_big_endian(block +  4, 12, state[1]);
    kryptos_cpy_u32_as_big_endian(block +  8,  8, state[2]);
    kryptos_cpy_u32_as_big_endian(block + 12,  4, state[3]);

    temp = state[0] = state[1] = state[2] = state[3] = 0;
}

#undef kryptos_noekeon_Round

#undef kryptos_noekeon_Gamma

#undef kryptos_noekeon_Theta

#undef kryptos_noekeon_lsh

#undef kryptos_noekeon_Pi1

#undef kryptos_noekeon_Pi2
