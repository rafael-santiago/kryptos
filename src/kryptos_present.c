/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_present.h>
#include <kryptos_task_check.h>
#include <kryptos_random.h>
#include <kryptos_padding.h>
#include <kryptos.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <string.h>
#endif

struct kryptos_present_kbuf {
    kryptos_u64_t h;
    size_t bits;
    union {
        kryptos_u16_t u16;
        kryptos_u64_t u64;
    }l;
};

static kryptos_u8_t kryptos_present_S[16] = {
    0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
};

static kryptos_u8_t kryptos_present_S_1[16] = {
    0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2, 0xD, 0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA
};

static kryptos_u8_t kryptos_present_P[64] = {
     0, 16, 32, 48,  1, 17, 33, 49,  2, 18, 34, 50,  3, 19, 35, 51,
     4, 20, 36, 52,  5, 21, 37, 53,  6, 22, 38, 54,  7, 23, 39, 55,
     8, 24, 40, 56,  9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
    12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63
};

// CLUE(Rafael): kldload ./irony-demux.ko
//
//               If you are bore enough for standing a bore pre-processor hanging, you should replace some macros here
//               to cute loop stuff but in this case you should also be hooked on occupying the CPU with complex counting jobs.
//               Stuff including HUGE infinite number fields such as... uhmmm let me see... oh! yes, look: '0..31', '0..63'.
//               There are also more complex ones: '31..0', '63..0'.
//
//               In this case, congrats! You should be proud of using decades of pretty smart people's work just by counting
//               such HUGE infinite number fields. Awesome!
//
//               kldunload irony_demux
//
//               SERIOUS: If the pre-processor hang is annoying you, you should expand on your own some macros during
//                        encryption/decryption. I think stupid make the CPU count every single time until 32 or 64.
//                        You can easily do it by yourself. Cannot you?

#define kryptos_present_addRoundKey(s, K, i) ( (s) ^= K[(i)] )

#define kryptos_present_sBoxLayer(s) {\
    s = ((kryptos_u64_t)kryptos_present_S[ (s) >> 60       ] << 60) |\
        ((kryptos_u64_t)kryptos_present_S[((s) >> 56) & 0xF] << 56) |\
        ((kryptos_u64_t)kryptos_present_S[((s) >> 52) & 0xF] << 52) |\
        ((kryptos_u64_t)kryptos_present_S[((s) >> 48) & 0xF] << 48) |\
        ((kryptos_u64_t)kryptos_present_S[((s) >> 44) & 0xF] << 44) |\
        ((kryptos_u64_t)kryptos_present_S[((s) >> 40) & 0xF] << 40) |\
        ((kryptos_u64_t)kryptos_present_S[((s) >> 36) & 0xF] << 36) |\
        ((kryptos_u64_t)kryptos_present_S[((s) >> 32) & 0xF] << 32) |\
        ((kryptos_u64_t)kryptos_present_S[((s) >> 28) & 0xF] << 28) |\
        ((kryptos_u64_t)kryptos_present_S[((s) >> 24) & 0xF] << 24) |\
        ((kryptos_u64_t)kryptos_present_S[((s) >> 20) & 0xF] << 20) |\
        ((kryptos_u64_t)kryptos_present_S[((s) >> 16) & 0xF] << 16) |\
        ((kryptos_u64_t)kryptos_present_S[((s) >> 12) & 0xF] << 12) |\
        ((kryptos_u64_t)kryptos_present_S[((s) >>  8) & 0xF] <<  8) |\
        ((kryptos_u64_t)kryptos_present_S[((s) >>  4) & 0xF] <<  4) | kryptos_present_S[(s) & 0xF];\
}

#define kryptos_present_pi(v, s, i) ( (v) |= (((s) & ((kryptos_u64_t)1 << (i))) >> (i)) << kryptos_present_P[(i)] )

#define kryptos_present_sBoxLayer_1(s) {\
    s = ((kryptos_u64_t)kryptos_present_S_1[(s) >> 60        ] << 60) |\
        ((kryptos_u64_t)kryptos_present_S_1[((s) >> 56) & 0xF] << 56) |\
        ((kryptos_u64_t)kryptos_present_S_1[((s) >> 52) & 0xF] << 52) |\
        ((kryptos_u64_t)kryptos_present_S_1[((s) >> 48) & 0xF] << 48) |\
        ((kryptos_u64_t)kryptos_present_S_1[((s) >> 44) & 0xF] << 44) |\
        ((kryptos_u64_t)kryptos_present_S_1[((s) >> 40) & 0xF] << 40) |\
        ((kryptos_u64_t)kryptos_present_S_1[((s) >> 36) & 0xF] << 36) |\
        ((kryptos_u64_t)kryptos_present_S_1[((s) >> 32) & 0xF] << 32) |\
        ((kryptos_u64_t)kryptos_present_S_1[((s) >> 28) & 0xF] << 28) |\
        ((kryptos_u64_t)kryptos_present_S_1[((s) >> 24) & 0xF] << 24) |\
        ((kryptos_u64_t)kryptos_present_S_1[((s) >> 20) & 0xF] << 20) |\
        ((kryptos_u64_t)kryptos_present_S_1[((s) >> 16) & 0xF] << 16) |\
        ((kryptos_u64_t)kryptos_present_S_1[((s) >> 12) & 0xF] << 12) |\
        ((kryptos_u64_t)kryptos_present_S_1[((s) >>  8) & 0xF] <<  8) |\
        ((kryptos_u64_t)kryptos_present_S_1[((s) >>  4) & 0xF] <<  4) | kryptos_present_S_1[(s) & 0xF];\
}

// WARN(Rafael): I have found better to save space by not storing P_1[] since 'pi_1' has only one additional P lookup when
//               compared to 'pi'. It is not time consuming.

#define kryptos_present_pi_1(v, s, i) ( (v) |= (((s) & ((kryptos_u64_t)1 << kryptos_present_P[(i)])) >>\
                                                                                             kryptos_present_P[(i)]) << (i) )

#define kryptos_present_pLayer(s, v) {\
    (v) = 0;\
    kryptos_present_pi(v, s,  0); kryptos_present_pi(v, s,  1); kryptos_present_pi(v, s,  2); kryptos_present_pi(v, s,  3);\
    kryptos_present_pi(v, s,  4); kryptos_present_pi(v, s,  5); kryptos_present_pi(v, s,  6); kryptos_present_pi(v, s,  7);\
    kryptos_present_pi(v, s,  8); kryptos_present_pi(v, s,  9); kryptos_present_pi(v, s, 10); kryptos_present_pi(v, s, 11);\
    kryptos_present_pi(v, s, 12); kryptos_present_pi(v, s, 13); kryptos_present_pi(v, s, 14); kryptos_present_pi(v, s, 15);\
    kryptos_present_pi(v, s, 16); kryptos_present_pi(v, s, 17); kryptos_present_pi(v, s, 18); kryptos_present_pi(v, s, 19);\
    kryptos_present_pi(v, s, 20); kryptos_present_pi(v, s, 21); kryptos_present_pi(v, s, 22); kryptos_present_pi(v, s, 23);\
    kryptos_present_pi(v, s, 24); kryptos_present_pi(v, s, 25); kryptos_present_pi(v, s, 26); kryptos_present_pi(v, s, 27);\
    kryptos_present_pi(v, s, 28); kryptos_present_pi(v, s, 29); kryptos_present_pi(v, s, 30); kryptos_present_pi(v, s, 31);\
    kryptos_present_pi(v, s, 32); kryptos_present_pi(v, s, 33); kryptos_present_pi(v, s, 34); kryptos_present_pi(v, s, 35);\
    kryptos_present_pi(v, s, 36); kryptos_present_pi(v, s, 37); kryptos_present_pi(v, s, 38); kryptos_present_pi(v, s, 39);\
    kryptos_present_pi(v, s, 40); kryptos_present_pi(v, s, 41); kryptos_present_pi(v, s, 42); kryptos_present_pi(v, s, 43);\
    kryptos_present_pi(v, s, 44); kryptos_present_pi(v, s, 45); kryptos_present_pi(v, s, 46); kryptos_present_pi(v, s, 47);\
    kryptos_present_pi(v, s, 48); kryptos_present_pi(v, s, 49); kryptos_present_pi(v, s, 50); kryptos_present_pi(v, s, 51);\
    kryptos_present_pi(v, s, 52); kryptos_present_pi(v, s, 53); kryptos_present_pi(v, s, 54); kryptos_present_pi(v, s, 55);\
    kryptos_present_pi(v, s, 56); kryptos_present_pi(v, s, 57); kryptos_present_pi(v, s, 58); kryptos_present_pi(v, s, 59);\
    kryptos_present_pi(v, s, 60); kryptos_present_pi(v, s, 61); kryptos_present_pi(v, s, 62); kryptos_present_pi(v, s, 63);\
    (s) = (v);\
}

#define kryptos_present_pLayer_1(s, v) {\
    (v) = 0;\
    kryptos_present_pi_1(v, s,  0); kryptos_present_pi_1(v, s,  1);\
    kryptos_present_pi_1(v, s,  2); kryptos_present_pi_1(v, s,  3);\
    kryptos_present_pi_1(v, s,  4); kryptos_present_pi_1(v, s,  5);\
    kryptos_present_pi_1(v, s,  6); kryptos_present_pi_1(v, s,  7);\
    kryptos_present_pi_1(v, s,  8); kryptos_present_pi_1(v, s,  9);\
    kryptos_present_pi_1(v, s, 10); kryptos_present_pi_1(v, s, 11);\
    kryptos_present_pi_1(v, s, 12); kryptos_present_pi_1(v, s, 13);\
    kryptos_present_pi_1(v, s, 14); kryptos_present_pi_1(v, s, 15);\
    kryptos_present_pi_1(v, s, 16); kryptos_present_pi_1(v, s, 17);\
    kryptos_present_pi_1(v, s, 18); kryptos_present_pi_1(v, s, 19);\
    kryptos_present_pi_1(v, s, 20); kryptos_present_pi_1(v, s, 21);\
    kryptos_present_pi_1(v, s, 22); kryptos_present_pi_1(v, s, 23);\
    kryptos_present_pi_1(v, s, 24); kryptos_present_pi_1(v, s, 25);\
    kryptos_present_pi_1(v, s, 26); kryptos_present_pi_1(v, s, 27);\
    kryptos_present_pi_1(v, s, 28); kryptos_present_pi_1(v, s, 29);\
    kryptos_present_pi_1(v, s, 30); kryptos_present_pi_1(v, s, 31);\
    kryptos_present_pi_1(v, s, 32); kryptos_present_pi_1(v, s, 33);\
    kryptos_present_pi_1(v, s, 34); kryptos_present_pi_1(v, s, 35);\
    kryptos_present_pi_1(v, s, 36); kryptos_present_pi_1(v, s, 37);\
    kryptos_present_pi_1(v, s, 38); kryptos_present_pi_1(v, s, 39);\
    kryptos_present_pi_1(v, s, 40); kryptos_present_pi_1(v, s, 41);\
    kryptos_present_pi_1(v, s, 42); kryptos_present_pi_1(v, s, 43);\
    kryptos_present_pi_1(v, s, 44); kryptos_present_pi_1(v, s, 45);\
    kryptos_present_pi_1(v, s, 46); kryptos_present_pi_1(v, s, 47);\
    kryptos_present_pi_1(v, s, 48); kryptos_present_pi_1(v, s, 49);\
    kryptos_present_pi_1(v, s, 50); kryptos_present_pi_1(v, s, 51);\
    kryptos_present_pi_1(v, s, 52); kryptos_present_pi_1(v, s, 53);\
    kryptos_present_pi_1(v, s, 54); kryptos_present_pi_1(v, s, 55);\
    kryptos_present_pi_1(v, s, 56); kryptos_present_pi_1(v, s, 57);\
    kryptos_present_pi_1(v, s, 58); kryptos_present_pi_1(v, s, 59);\
    kryptos_present_pi_1(v, s, 60); kryptos_present_pi_1(v, s, 61);\
    kryptos_present_pi_1(v, s, 62); kryptos_present_pi_1(v, s, 63);\
    (s) = (v);\
}

#define kryptos_present_round(i, s, K, v) {\
    kryptos_present_addRoundKey(s, K, i);\
    kryptos_present_sBoxLayer(s);\
    kryptos_present_pLayer(s, v);\
}

#define kryptos_present_round_1(i, s, K, v) {\
    kryptos_present_pLayer_1(s, v);\
    kryptos_present_sBoxLayer_1(s);\
    kryptos_present_addRoundKey(s, K, i);\
}

struct kryptos_present_subkeys {
    kryptos_u64_t K[32];
};

typedef void (*kryptos_present_block_processor)(kryptos_u8_t *block, const struct kryptos_present_subkeys *sks);

static void kryptos_present_key_sched(const kryptos_u8_t *key, const size_t key_size, const size_t key_bit_size,
                                      struct kryptos_present_subkeys *sks);

static void kryptos_present_rotl_u80(struct kryptos_present_kbuf *key, const size_t n);

static void kryptos_present_rotl_u128(struct kryptos_present_kbuf *key, const size_t n);

static void kryptos_present_block_encrypt(kryptos_u8_t *block, const struct kryptos_present_subkeys *sks);

static void kryptos_present_block_decrypt(kryptos_u8_t *block, const struct kryptos_present_subkeys *sks);

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_SETUP(present80, kKryptosCipherPRESENT, KRYPTOS_PRESENT_BLOCKSIZE)

KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(present80,
                                    ktask,
                                    kryptos_present_subkeys,
                                    sks,
                                    kryptos_present_block_processor,
                                    present_block_processor,
                                    kryptos_present_key_sched((*ktask)->key, (*ktask)->key_size, 80, &sks),
                                    kryptos_present_block_encrypt, /* No additional steps before encrypting */,
                                    kryptos_present_block_decrypt, /* No additional steps before decrypting */,
                                    KRYPTOS_PRESENT_BLOCKSIZE,
                                    present80_cipher_epilogue,
                                    outblock,
                                    present_block_processor(outblock, &sks),
                                    NULL /* GCM E function arg (No GCM) */)

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_GCM_E_NO_SUPPORT(present80)

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_SETUP(present128, kKryptosCipherPRESENT, KRYPTOS_PRESENT_BLOCKSIZE)

KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(present128,
                                    ktask,
                                    kryptos_present_subkeys,
                                    sks,
                                    kryptos_present_block_processor,
                                    present_block_processor,
                                    kryptos_present_key_sched((*ktask)->key, (*ktask)->key_size, 128, &sks),
                                    kryptos_present_block_encrypt, /* No additional steps before encrypting */,
                                    kryptos_present_block_decrypt, /* No additional steps before decrypting */,
                                    KRYPTOS_PRESENT_BLOCKSIZE,
                                    present128_cipher_epilogue,
                                    outblock,
                                    present_block_processor(outblock, &sks),
                                    NULL /* GCM E function arg (No GCM) */)

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_GCM_E_NO_SUPPORT(present128)

static void kryptos_present_rotl_u80(struct kryptos_present_kbuf *key, const size_t n) {
    size_t l;
    kryptos_u8_t h_h, l_h;

    for (l = 0; l < n; l++) {
        h_h = key->h >> 63;
        l_h = key->l.u16 >> 15;
        key->h = (key->h << 1) | l_h;
        key->l.u16 = (key->l.u16 << 1) | h_h;
    }
}

static void kryptos_present_rotl_u128(struct kryptos_present_kbuf *key, const size_t n) {
    size_t l;
    kryptos_u8_t h_h, l_h;

    for (l = 0; l < n; l++) {
        h_h = key->h >> 63;
        l_h = key->l.u64 >> 63;
        key->h = (key->h << 1) | l_h;
        key->l.u64 = (key->l.u64 << 1) | h_h;
    }
}

static void kryptos_present_key_sched(const kryptos_u8_t *key, const size_t key_size, const size_t key_bit_size,
                                      struct kryptos_present_subkeys *sks) {
    struct kryptos_present_kbuf K;
    kryptos_u8_t key_buf[128];
    void (*kryptos_present_rotl)(struct kryptos_present_kbuf *, const size_t);
    kryptos_u64_t temp;

    memset(key_buf, 0, sizeof(key_buf));
    memcpy(key_buf, key, key_size);

    K.bits = key_bit_size;

    switch (K.bits) {
        case 80:
            K.h = ((kryptos_u64_t)key_buf[0] << 56) |
                  ((kryptos_u64_t)key_buf[1] << 48) |
                  ((kryptos_u64_t)key_buf[2] << 40) |
                  ((kryptos_u64_t)key_buf[3] << 32) |
                  ((kryptos_u64_t)key_buf[4] << 24) |
                  ((kryptos_u64_t)key_buf[5] << 16) |
                  ((kryptos_u64_t)key_buf[6] <<  8) | key_buf[7];
            K.l.u16 = ((kryptos_u16_t)key_buf[8] << 8) | key_buf[9];
            kryptos_present_rotl = kryptos_present_rotl_u80;
            break;

        case 128:
            K.h = ((kryptos_u64_t)key_buf[0] << 56) |
                  ((kryptos_u64_t)key_buf[1] << 48) |
                  ((kryptos_u64_t)key_buf[2] << 40) |
                  ((kryptos_u64_t)key_buf[3] << 32) |
                  ((kryptos_u64_t)key_buf[4] << 24) |
                  ((kryptos_u64_t)key_buf[5] << 16) |
                  ((kryptos_u64_t)key_buf[6] <<  8) | key_buf[7];
            K.l.u64 = ((kryptos_u64_t)key_buf[ 8] << 56) |
                      ((kryptos_u64_t)key_buf[ 9] << 48) |
                      ((kryptos_u64_t)key_buf[10] << 40) |
                      ((kryptos_u64_t)key_buf[11] << 32) |
                      ((kryptos_u64_t)key_buf[12] << 24) |
                      ((kryptos_u64_t)key_buf[13] << 16) |
                      ((kryptos_u64_t)key_buf[14] <<  8) | key_buf[15];
            kryptos_present_rotl = kryptos_present_rotl_u128;
            break;

        default:
            kryptos_present_rotl = NULL; // WARN(Rafael): It is just for shut up pedantic compiler warnings and also
                                         //               to make sure to fuck any bad future extension.
            break;
    }

    memset(key_buf, 0, sizeof(key_buf));

#define kryptos_present_ksched_i(K) {\
    kryptos_present_rotl((K), 61);\
}

#define kryptos_present_ksched_ii(K) {\
    (K).h = ((kryptos_u64_t)kryptos_present_S[(K).h >> 60] << 60) | ((K).h & 0x0FFFFFFFFFFFFFFF);\
    if ((K).bits == 128) {\
        (K).h = ((kryptos_u64_t)kryptos_present_S[((K).h >> 56) & 0xF] << 56) | ((K).h & 0xF0FFFFFFFFFFFFFF);\
    }\
}

/*
 * CLUE(Rafael): Maybe at first glance it seems quite tricky but it is pretty obvious. The key state is organized within
 *               our 'big-endian minds' in the following way:
 *
 * b [0][1][2][3][4][5][6][7] W
 *   79 78 77 76 75 74 73 72 [0] __  __
 *   71 70 69 68 67 66 65 64 [1]   | __=> a 'W'
 *   63 62 61 60 59 58 57 56 [2]   |
 *   55 54 53 52 51 50 49 48 [3]   |
 *   47 46 45 44 43 42 41 40 [4]    -> h < kryptos_u64_t >
 *   39 38 37 36 35 34 33 32 [5]   |
 *   31 30 29 28 27 26 25 24 [6]   |
 *   23 22 21 20 19 18 17 16 [7] __|
 *   15       .  .  .        [8] __
 *            .  .  .        [9] __ -> l < kryptos_u16_t or kryptos_u64_t, it depends on the effective key size >
 *               .
 *               .
 *               .
 *                -----------> Obvious part: Since we are accessing the values instead of pointing to them, all bitwise
 *                                           operations are endianness independent.
 *
 *   So according to PRESENT spec, we need XOR the bits = { h {..., 19, 18, 17, 16}, l {15, ....} } with r and to put the
 *   result back without flipping the remaining bits. The last if else block is about creating the right remaining bitmask
 *   halve for appending the XOR op result. The 128bit version is similar but the bit positions change a little, I think that
 *   if you are reading or even reviewing it, you know crypto besides just 'plain programming' so any doubt, please, find the
 *   official PRESENT specification, more precisely the Appendix II.
 */

#define kryptos_present_ksched_iii(K, r, u64reg) {\
    if ((K).bits == 80) {\
        (u64reg) = (((K).h & 0xF) << 1) | ((K).l.u16 >> 15);\
    } else {\
        (u64reg) = (((K).h & 0x7) << 2) | ((K).l.u64 >> 62);\
    }\
    (u64reg) ^= (r);\
    if ((K).bits == 80) {\
        (K).h &= 0xFFFFFFFFFFFFFFF0;\
        (K).h |= ((u64reg) >> 1);\
        (K).l.u16 &= 0x7FFF;\
        (K).l.u16 |= ((u64reg & 0x1) << 15);\
    } else {\
        (K).h &= 0xFFFFFFFFFFFFFFF8;\
        (K).h |= ((u64reg) >> 2);\
        (K).l.u64 &= 0x3FFFFFFFFFFFFFFF;\
        (K).l.u64 |= ((u64reg & 0x3) << 62);\
    }\
}

#define kryptos_present_ld_sk(SK, K, r) {\
    (SK)[(r)] = (K).h;\
}

#define kryptos_present_mk_sk(SK, K, r, u64reg) {\
    kryptos_present_ksched_i(&K);\
    kryptos_present_ksched_ii(K);\
    kryptos_present_ksched_iii(K, r, u64reg);\
    kryptos_present_ld_sk(SK, K, r);\
}

    kryptos_present_ld_sk(sks->K, K, 0);

    kryptos_present_mk_sk(sks->K, K,  1, temp);
    kryptos_present_mk_sk(sks->K, K,  2, temp);
    kryptos_present_mk_sk(sks->K, K,  3, temp);
    kryptos_present_mk_sk(sks->K, K,  4, temp);
    kryptos_present_mk_sk(sks->K, K,  5, temp);
    kryptos_present_mk_sk(sks->K, K,  6, temp);
    kryptos_present_mk_sk(sks->K, K,  7, temp);
    kryptos_present_mk_sk(sks->K, K,  8, temp);
    kryptos_present_mk_sk(sks->K, K,  9, temp);
    kryptos_present_mk_sk(sks->K, K, 10, temp);
    kryptos_present_mk_sk(sks->K, K, 11, temp);
    kryptos_present_mk_sk(sks->K, K, 12, temp);
    kryptos_present_mk_sk(sks->K, K, 13, temp);
    kryptos_present_mk_sk(sks->K, K, 14, temp);
    kryptos_present_mk_sk(sks->K, K, 15, temp);
    kryptos_present_mk_sk(sks->K, K, 16, temp);
    kryptos_present_mk_sk(sks->K, K, 17, temp);
    kryptos_present_mk_sk(sks->K, K, 18, temp);
    kryptos_present_mk_sk(sks->K, K, 19, temp);
    kryptos_present_mk_sk(sks->K, K, 20, temp);
    kryptos_present_mk_sk(sks->K, K, 21, temp);
    kryptos_present_mk_sk(sks->K, K, 22, temp);
    kryptos_present_mk_sk(sks->K, K, 23, temp);
    kryptos_present_mk_sk(sks->K, K, 24, temp);
    kryptos_present_mk_sk(sks->K, K, 25, temp);
    kryptos_present_mk_sk(sks->K, K, 26, temp);
    kryptos_present_mk_sk(sks->K, K, 27, temp);
    kryptos_present_mk_sk(sks->K, K, 28, temp);
    kryptos_present_mk_sk(sks->K, K, 29, temp);
    kryptos_present_mk_sk(sks->K, K, 30, temp);
    kryptos_present_mk_sk(sks->K, K, 31, temp);

    // WARN(Rafael): 'paranoid housekeeping'.

    temp = 0;
    memset(&K, 0, sizeof(K));

    kryptos_present_rotl = NULL;

#undef kryptos_present_ksched_i

#undef kryptos_present_ksched_ii

#undef kryptos_present_ksched_iii

#undef kryptos_present_ld_sk

#undef kryptos_present_mk_sk
}

static void kryptos_present_block_encrypt(kryptos_u8_t *block, const struct kryptos_present_subkeys *sks) {
    kryptos_u64_t temp, state;

    state = (kryptos_u64_t)block[0] << 56 |
            (kryptos_u64_t)block[1] << 48 |
            (kryptos_u64_t)block[2] << 40 |
            (kryptos_u64_t)block[3] << 32 |
            (kryptos_u64_t)block[4] << 24 |
            (kryptos_u64_t)block[5] << 16 |
            (kryptos_u64_t)block[6] <<  8 | block[7];

    kryptos_present_round( 0, state, sks->K, temp);
    kryptos_present_round( 1, state, sks->K, temp);
    kryptos_present_round( 2, state, sks->K, temp);
    kryptos_present_round( 3, state, sks->K, temp);
    kryptos_present_round( 4, state, sks->K, temp);
    kryptos_present_round( 5, state, sks->K, temp);
    kryptos_present_round( 6, state, sks->K, temp);
    kryptos_present_round( 7, state, sks->K, temp);
    kryptos_present_round( 8, state, sks->K, temp);
    kryptos_present_round( 9, state, sks->K, temp);
    kryptos_present_round(10, state, sks->K, temp);
    kryptos_present_round(11, state, sks->K, temp);
    kryptos_present_round(12, state, sks->K, temp);
    kryptos_present_round(13, state, sks->K, temp);
    kryptos_present_round(14, state, sks->K, temp);
    kryptos_present_round(15, state, sks->K, temp);
    kryptos_present_round(16, state, sks->K, temp);
    kryptos_present_round(17, state, sks->K, temp);
    kryptos_present_round(18, state, sks->K, temp);
    kryptos_present_round(19, state, sks->K, temp);
    kryptos_present_round(20, state, sks->K, temp);
    kryptos_present_round(21, state, sks->K, temp);
    kryptos_present_round(22, state, sks->K, temp);
    kryptos_present_round(23, state, sks->K, temp);
    kryptos_present_round(24, state, sks->K, temp);
    kryptos_present_round(25, state, sks->K, temp);
    kryptos_present_round(26, state, sks->K, temp);
    kryptos_present_round(27, state, sks->K, temp);
    kryptos_present_round(28, state, sks->K, temp);
    kryptos_present_round(29, state, sks->K, temp);
    kryptos_present_round(30, state, sks->K, temp);

    kryptos_present_addRoundKey(state, sks->K, 31);

    block[0] = (state >> 56) & 0xFF;
    block[1] = (state >> 48) & 0xFF;
    block[2] = (state >> 40) & 0xFF;
    block[3] = (state >> 32) & 0xFF;
    block[4] = (state >> 24) & 0xFF;
    block[5] = (state >> 16) & 0xFF;
    block[6] = (state >>  8) & 0xFF;
    block[7] = state & 0xFF;
}

static void kryptos_present_block_decrypt(kryptos_u8_t *block, const struct kryptos_present_subkeys *sks) {
    kryptos_u64_t temp, state;

    state = (kryptos_u64_t)block[0] << 56 |
            (kryptos_u64_t)block[1] << 48 |
            (kryptos_u64_t)block[2] << 40 |
            (kryptos_u64_t)block[3] << 32 |
            (kryptos_u64_t)block[4] << 24 |
            (kryptos_u64_t)block[5] << 16 |
            (kryptos_u64_t)block[6] <<  8 | block[7];


    kryptos_present_addRoundKey(state, sks->K, 31);

    kryptos_present_round_1(30, state, sks->K, temp);
    kryptos_present_round_1(29, state, sks->K, temp);
    kryptos_present_round_1(28, state, sks->K, temp);
    kryptos_present_round_1(27, state, sks->K, temp);
    kryptos_present_round_1(26, state, sks->K, temp);
    kryptos_present_round_1(25, state, sks->K, temp);
    kryptos_present_round_1(24, state, sks->K, temp);
    kryptos_present_round_1(23, state, sks->K, temp);
    kryptos_present_round_1(22, state, sks->K, temp);
    kryptos_present_round_1(21, state, sks->K, temp);
    kryptos_present_round_1(20, state, sks->K, temp);
    kryptos_present_round_1(19, state, sks->K, temp);
    kryptos_present_round_1(18, state, sks->K, temp);
    kryptos_present_round_1(17, state, sks->K, temp);
    kryptos_present_round_1(16, state, sks->K, temp);
    kryptos_present_round_1(15, state, sks->K, temp);
    kryptos_present_round_1(14, state, sks->K, temp);
    kryptos_present_round_1(13, state, sks->K, temp);
    kryptos_present_round_1(12, state, sks->K, temp);
    kryptos_present_round_1(11, state, sks->K, temp);
    kryptos_present_round_1(10, state, sks->K, temp);
    kryptos_present_round_1( 9, state, sks->K, temp);
    kryptos_present_round_1( 8, state, sks->K, temp);
    kryptos_present_round_1( 7, state, sks->K, temp);
    kryptos_present_round_1( 6, state, sks->K, temp);
    kryptos_present_round_1( 5, state, sks->K, temp);
    kryptos_present_round_1( 4, state, sks->K, temp);
    kryptos_present_round_1( 3, state, sks->K, temp);
    kryptos_present_round_1( 2, state, sks->K, temp);
    kryptos_present_round_1( 1, state, sks->K, temp);
    kryptos_present_round_1( 0, state, sks->K, temp);

    block[0] = (state >> 56) & 0xFF;
    block[1] = (state >> 48) & 0xFF;
    block[2] = (state >> 40) & 0xFF;
    block[3] = (state >> 32) & 0xFF;
    block[4] = (state >> 24) & 0xFF;
    block[5] = (state >> 16) & 0xFF;
    block[6] = (state >>  8) & 0xFF;
    block[7] = state & 0xFF;
}

#undef kryptos_present_addRoundKey

#undef kryptos_present_sBoxLayer

#undef kryptos_present_sBoxLayer_1

#undef kryptos_present_pi

#undef kryptos_present_pLayer

#undef kryptos_present_pi_1

#undef kryptos_present_round

#undef kryptos_present_round_1
