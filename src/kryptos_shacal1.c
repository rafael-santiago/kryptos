/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_shacal1.h>
#include <kryptos_endianness_utils.h>
#include <kryptos_task_check.h>
#include <kryptos_random.h>
#include <kryptos_padding.h>
#include <kryptos.h>

// WARN(Rafael): I prefer separating SHA-1 implementation from SHACAL-1, so please do not try to put the macros together.
//               Also pass extra boolean flags and all this obvious stuff. Here in this library the implementations must
//               exist without any dependency from another. If someone just want to extract some isolated stuff, it will
//               be quick, easier and work at first glance.

#define kryptos_shacal1_Sn(x, n) ( (x) << (n) | (x) >> ((sizeof((x)) << 3) - (n)) )

#define kryptos_shacal1_F(Fx, t, B, C, D){\
    if ((t) >= 0 && (t) <= 19) {\
        Fx = ((B) & (C)) | ((~(B)) & (D));\
    } else if (((t) >= 20 && (t) <= 39) || ((t) >= 60 && (t) <= 79)) {\
        Fx = (B) ^ (C) ^ (D);\
    } else if ((t) >= 40 && (t) <= 59) {\
        Fx = ((B) & (C)) | ((B) & (D)) | ((C) & (D));\
    }\
}

#define kryptos_shacal1_K(Kx, t){\
    if ((t) >= 0 && (t) <= 19) {\
        Kx = 0x5A827999;\
    } else if ((t) >= 20 && (t) <= 39) {\
        Kx = 0x6ED9EBA1;\
    } else if ((t) >= 40 && (t) <= 59) {\
        Kx = 0x8F1BBCDC;\
    } else if ((t) >= 60 && (t) <= 79) {\
        Kx = 0xCA62C1D6;\
    }\
}

struct kryptos_shacal1_subkeys {
    kryptos_u32_t W[80];
};

typedef void (*kryptos_shacal1_block_processor)(kryptos_u8_t *block, const struct kryptos_shacal1_subkeys *sks);

static void kryptos_shacal1_key_sched(const kryptos_u8_t *key, const size_t key_size, struct kryptos_shacal1_subkeys *sks);

static void kryptos_shacal1_ld_user_key(kryptos_u32_t *key, const kryptos_u8_t *user_key, const size_t user_key_size);

static void kryptos_shacal1_block_encrypt(kryptos_u8_t *block, const struct kryptos_shacal1_subkeys *sks);

static void kryptos_shacal1_block_decrypt(kryptos_u8_t *block, const struct kryptos_shacal1_subkeys *sks);

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_SETUP(shacal1, kKryptosCipherSHACAL1, KRYPTOS_SHACAL1_BLOCKSIZE)

KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(shacal1,
                                    ktask,
                                    kryptos_shacal1_subkeys,
                                    sks,
                                    kryptos_shacal1_block_processor,
                                    shacal1_block_processor,
                                    kryptos_shacal1_key_sched((*ktask)->key, (*ktask)->key_size, &sks),
                                    kryptos_shacal1_block_encrypt, /* No additional steps for encrypting */,
                                    kryptos_shacal1_block_decrypt, /* No additional steps for decrypting */,
                                    KRYPTOS_SHACAL1_BLOCKSIZE,
                                    shacal1_cipher_epilogue,
                                    outblock,
                                    shacal1_block_processor(outblock, &sks),
                                    NULL /* GCM E function arg (No GCM) */)

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_GCM_E_NO_SUPPORT(shacal1)

static void kryptos_shacal1_ld_user_key(kryptos_u32_t *key, const kryptos_u8_t *user_key, const size_t user_key_size) {
    const kryptos_u8_t *kp, *kp_end;
    size_t w, b;

    // INFO(Rafael): From zero up to 64 bytes. Padded with zeroes when shorter than 512-bits.

    kryptos_ld_user_key_prologue(key, 16, user_key, user_key_size, kp, kp_end, w, b, return);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_shacal1_ld_user_key_epilogue);
    kryptos_ld_user_key_epilogue(kryptos_shacal1_ld_user_key_epilogue, key, w, b, kp, kp_end);
}

static void kryptos_shacal1_key_sched(const kryptos_u8_t *key, const size_t key_size, struct kryptos_shacal1_subkeys *sks) {
    size_t t;

    kryptos_shacal1_ld_user_key(&sks->W[0], key, key_size);

    for (t = 16; t < 80; t++) {
        sks->W[t] = kryptos_shacal1_Sn(sks->W[t - 3] ^ sks->W[t - 8] ^ sks->W[t - 14] ^ sks->W[t - 16], 1);
    }
}

static void kryptos_shacal1_block_encrypt(kryptos_u8_t *block, const struct kryptos_shacal1_subkeys *sks) {
    kryptos_u32_t A, B, C, D, E, TEMP;
    kryptos_u32_t Fx, Kx;
    size_t t;

    A = kryptos_get_u32_as_big_endian(block     , 4);
    B = kryptos_get_u32_as_big_endian(block +  4, 4);
    C = kryptos_get_u32_as_big_endian(block +  8, 4);
    D = kryptos_get_u32_as_big_endian(block + 12, 4);
    E = kryptos_get_u32_as_big_endian(block + 16, 4);

    for (t = 0; t < 80; t++) {
        kryptos_shacal1_F(Fx, t, B, C, D);
        kryptos_shacal1_K(Kx, t);
        TEMP = kryptos_shacal1_Sn(A, 5) + Fx + E + sks->W[t] + Kx;
        E = D;
        D = C;
        C = kryptos_shacal1_Sn(B, 30);
        B = A;
        A = TEMP;
    }

    kryptos_cpy_u32_as_big_endian(block     , 20, A);
    kryptos_cpy_u32_as_big_endian(block +  4, 12, B);
    kryptos_cpy_u32_as_big_endian(block +  8, 16, C);
    kryptos_cpy_u32_as_big_endian(block + 12,  8, D);
    kryptos_cpy_u32_as_big_endian(block + 16,  4, E);

    A = B = C = D = E = Fx = Kx = TEMP = 0;
}

static void kryptos_shacal1_block_decrypt(kryptos_u8_t *block, const struct kryptos_shacal1_subkeys *sks) {
    kryptos_u32_t A, B, C, D, E, TEMP;
    kryptos_u32_t Fx, Kx;
    ssize_t t;

    A = kryptos_get_u32_as_big_endian(block     , 4);
    B = kryptos_get_u32_as_big_endian(block +  4, 4);
    C = kryptos_get_u32_as_big_endian(block +  8, 4);
    D = kryptos_get_u32_as_big_endian(block + 12, 4);
    E = kryptos_get_u32_as_big_endian(block + 16, 4);

    for (t = 79; t >= 0; t--) {
        // CLUE(Rafael): (32 - 30) = 2... This is also true when talking about circular shifts :)
        //
        //               The constant 32 is because we are rotating 32-bit registers...
        //
        //               By exploring this basic shift property give us the chance of avoiding the
        //               implementation of a circular right shift macro (what in this case would be a useless inverse macro).
        //
        //               Some authors give a different transformation for the subkeys during decryption in order to re-use
        //               the encryption circuit, however, this is software so I do not mind of implementing a new one. This
        //               is a little bit different from what you may find in literature; specially the compression function
        //               inverse, this directly uses the 2^32 sum inversion instead of getting the same result from different
        //               subkeys values (inverse round keys).
        TEMP = A;
        A = B;
        B = kryptos_shacal1_Sn(C, 2);
        C = D;
        D = E;
        kryptos_shacal1_F(Fx, t, B, C, D);
        kryptos_shacal1_K(Kx, t);
        E = TEMP - kryptos_shacal1_Sn(A, 5) - Fx - sks->W[t] - Kx;
    }

    kryptos_cpy_u32_as_big_endian(block     , 20, A);
    kryptos_cpy_u32_as_big_endian(block +  4, 12, B);
    kryptos_cpy_u32_as_big_endian(block +  8, 16, C);
    kryptos_cpy_u32_as_big_endian(block + 12,  8, D);
    kryptos_cpy_u32_as_big_endian(block + 16,  4, E);

    A =
    B =
    C =
    D =
    E = Fx = Kx = 0;
}

#undef kryptos_shacal1_Sn

#undef kryptos_shacal1_F

#undef kryptos_shacal1_K
