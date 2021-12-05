/*
 *                                Copyright (C) 2021 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_salsa20.h>
#include <kryptos_salsa20_core.h>
#include <kryptos_task_check.h>
#include <kryptos.h>

struct kryptos_salsa20_keystream {
    kryptos_u8_t K[64];
    kryptos_u64_t l;
};

#define kryptos_salsa20_getbyte(b, n) (( (b) >> (24 - (8 * (n))) ) & 0xFF)

#define kryptos_salsa20_littleendian(w) ( (((kryptos_u32_t)(w)) << 24) |\
                                          (((kryptos_u32_t)(w) & 0x0000FF00) << 8) |\
                                          (((kryptos_u32_t)(w) & 0x00FF0000) >> 8) |\
                                          (((kryptos_u32_t)(w)) >> 24) )

#define KRYPTOS_SALSA20_THETA0 0x65787061
#define KRYPTOS_SALSA20_THETA1 0x6E642033
#define KRYPTOS_SALSA20_THETA2 0x322D6279
#define KRYPTOS_SALSA20_THETA3 0x7465206B

static void kryptos_salsa20_keystream_feed(const kryptos_u8_t *key, const size_t key_size, const kryptos_u64_t n,
                                           struct kryptos_salsa20_keystream *ks);

void kryptos_salsa20_cipher(kryptos_task_ctx **ktask) {
    struct kryptos_salsa20_keystream ks;
    kryptos_u8_t *ip = NULL, *ip_end = NULL;
    kryptos_u8_t *kp = NULL, *kp_end = NULL;
    kryptos_u8_t *op = NULL;
    kryptos_u64_t nonce = 0;

    memset(&ks, 0, sizeof(ks));

    if (kryptos_task_check(ktask) == 0) {
        return;
    }

    if ((*ktask)->key_size != 32 &&
        (*ktask)->key_size != 16) {
        (*ktask)->result = kKryptosKeyError;
        (*ktask)->result_verbose = "Key size for Salsa20 must be a 16 or 32-bit value.";
        goto kryptos_salsa20_cipher_epilogue;
    }

    ks.l = 0;
    ip = (*ktask)->in;
    ip_end = ip + (*ktask)->in_size;

    (*ktask)->out_size = ip_end - ip;
    (*ktask)->out = (kryptos_u8_t *)kryptos_newseg((*ktask)->out_size);
    if ((*ktask)->out == NULL) {
        (*ktask)->out_size = 0;
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "No memory to get a valid output.";
        goto kryptos_salsa20_cipher_epilogue;
    }

    op = &(*ktask)->out[0];

    nonce = (((kryptos_u64_t)(*ktask)->iv[0]) << 56) |
            (((kryptos_u64_t)(*ktask)->iv[1]) << 48) |
            (((kryptos_u64_t)(*ktask)->iv[2]) << 40) |
            (((kryptos_u64_t)(*ktask)->iv[3]) << 32) |
            (((kryptos_u64_t)(*ktask)->iv[4]) << 24) |
            (((kryptos_u64_t)(*ktask)->iv[5]) << 16) |
            (((kryptos_u64_t)(*ktask)->iv[6]) <<  8) |
            ((kryptos_u64_t)(*ktask)->iv[7]);

    while (ip != ip_end) {
        kryptos_salsa20_keystream_feed((*ktask)->key, (*ktask)->key_size, nonce, &ks);
        kp = &ks.K[0];
        kp_end = kp + sizeof(ks.K);
        while (ip != ip_end && kp != kp_end) {
            *op = *ip ^ *kp;
            kp++;
            ip++;
            op++;
        }
    }

    (*ktask)->result = kKryptosSuccess;

kryptos_salsa20_cipher_epilogue:

    nonce = 0;

    ip = ip_end = kp = kp_end = op = NULL;
    memset(&ks, 0, sizeof(ks));
}

void kryptos_salsa20_setup(kryptos_task_ctx *ktask, kryptos_u8_t *key, const size_t key_size,
                           kryptos_u8_t *iv64) {
    if (ktask == NULL) {
        return;
    }

    ktask->cipher = kKryptosCipherSalsa20;
    ktask->key = key;
    ktask->key_size = key_size;
    ktask->iv = iv64;
    ktask->iv_size = sizeof(kryptos_u64_t);
}

static void kryptos_salsa20_keystream_feed(const kryptos_u8_t *key, const size_t key_size, const kryptos_u64_t n,
                                           struct kryptos_salsa20_keystream *ks) {
    kryptos_u32_t n_u32[2];

    n_u32[0] = (kryptos_u32_t) (n >> 32);
    n_u32[1] = (kryptos_u32_t) (n & 0xFFFFFFFF);

    switch (key_size) {
        case 16:
            // INFO(Rafael): The loading scheme is Salsa20(T0, k, T1, n, T2, k, T3).
            ks->K[ 0] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA0, 0);
            ks->K[ 1] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA0, 1);
            ks->K[ 2] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA0, 2);
            ks->K[ 3] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA0, 3);
            ks->K[ 4] = key[ 0];
            ks->K[ 5] = key[ 1];
            ks->K[ 6] = key[ 2];
            ks->K[ 7] = key[ 3];
            ks->K[ 8] = key[ 4];
            ks->K[ 9] = key[ 5];
            ks->K[10] = key[ 6];
            ks->K[11] = key[ 7];
            ks->K[12] = key[ 8];
            ks->K[13] = key[ 9];
            ks->K[14] = key[10];
            ks->K[15] = key[11];
            ks->K[16] = key[12];
            ks->K[17] = key[13];
            ks->K[18] = key[14];
            ks->K[19] = key[15];
            ks->K[20] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA1, 0);
            ks->K[21] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA1, 1);
            ks->K[22] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA1, 2);
            ks->K[23] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA1, 3);
            ks->K[24] = kryptos_salsa20_getbyte(n_u32[0], 0);
            ks->K[25] = kryptos_salsa20_getbyte(n_u32[0], 1);
            ks->K[26] = kryptos_salsa20_getbyte(n_u32[0], 2);
            ks->K[27] = kryptos_salsa20_getbyte(n_u32[0], 3);
            ks->K[28] = kryptos_salsa20_getbyte(n_u32[1], 0);
            ks->K[29] = kryptos_salsa20_getbyte(n_u32[1], 1);
            ks->K[30] = kryptos_salsa20_getbyte(n_u32[1], 2);
            ks->K[31] = kryptos_salsa20_getbyte(n_u32[1], 3);
            n_u32[1] = (kryptos_u32_t) (ks->l >> 32);
            n_u32[0] = (kryptos_u32_t) (ks->l & 0xFFFFFFFF);
            n_u32[0] = kryptos_salsa20_littleendian(n_u32[0]);
            n_u32[1] = kryptos_salsa20_littleendian(n_u32[1]);
            ks->K[32] = kryptos_salsa20_getbyte(n_u32[0], 0);
            ks->K[33] = kryptos_salsa20_getbyte(n_u32[0], 1);
            ks->K[34] = kryptos_salsa20_getbyte(n_u32[0], 2);
            ks->K[35] = kryptos_salsa20_getbyte(n_u32[0], 3);
            ks->K[36] = kryptos_salsa20_getbyte(n_u32[1], 0);
            ks->K[37] = kryptos_salsa20_getbyte(n_u32[1], 1);
            ks->K[38] = kryptos_salsa20_getbyte(n_u32[1], 2);
            ks->K[39] = kryptos_salsa20_getbyte(n_u32[1], 3);
            ks->K[40] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA2, 0);
            ks->K[41] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA2, 1);
            ks->K[42] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA2, 2);
            ks->K[43] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA2, 3);
            ks->K[44] = key[ 0];
            ks->K[45] = key[ 1];
            ks->K[46] = key[ 2];
            ks->K[47] = key[ 3];
            ks->K[48] = key[ 4];
            ks->K[49] = key[ 5];
            ks->K[50] = key[ 6];
            ks->K[51] = key[ 7];
            ks->K[52] = key[ 8];
            ks->K[53] = key[ 9];
            ks->K[54] = key[10];
            ks->K[55] = key[11];
            ks->K[56] = key[12];
            ks->K[57] = key[13];
            ks->K[58] = key[14];
            ks->K[59] = key[15];
            ks->K[60] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA3, 0);
            ks->K[61] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA3, 1);
            ks->K[62] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA3, 2);
            ks->K[63] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA3, 3);
            break;

        case 32:
            // INFO(Rafael): The loading scheme is Salsa20(T0, k0, T1, n, T2, k1, T3).
            ks->K[ 0] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA0, 0);
            ks->K[ 1] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA0, 1);
            ks->K[ 2] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA0, 2);
            ks->K[ 3] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA0, 3);
            ks->K[ 4] = key[ 0];
            ks->K[ 5] = key[ 1];
            ks->K[ 6] = key[ 2];
            ks->K[ 7] = key[ 3];
            ks->K[ 8] = key[ 4];
            ks->K[ 9] = key[ 5];
            ks->K[10] = key[ 6];
            ks->K[11] = key[ 7];
            ks->K[12] = key[ 8];
            ks->K[13] = key[ 9];
            ks->K[14] = key[10];
            ks->K[15] = key[11];
            ks->K[16] = key[12];
            ks->K[17] = key[13];
            ks->K[18] = key[14];
            ks->K[19] = key[15];
            ks->K[20] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA1, 0);
            ks->K[21] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA1, 1);
            ks->K[22] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA1, 2);
            ks->K[23] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA1, 3);
            ks->K[24] = kryptos_salsa20_getbyte(n_u32[0], 0);
            ks->K[25] = kryptos_salsa20_getbyte(n_u32[0], 1);
            ks->K[26] = kryptos_salsa20_getbyte(n_u32[0], 2);
            ks->K[27] = kryptos_salsa20_getbyte(n_u32[0], 3);
            ks->K[28] = kryptos_salsa20_getbyte(n_u32[1], 0);
            ks->K[29] = kryptos_salsa20_getbyte(n_u32[1], 1);
            ks->K[30] = kryptos_salsa20_getbyte(n_u32[1], 2);
            ks->K[31] = kryptos_salsa20_getbyte(n_u32[1], 3);
            n_u32[1] = (kryptos_u32_t) (ks->l >> 32);
            n_u32[0] = (kryptos_u32_t) (ks->l & 0xFFFFFFFF);
            n_u32[0] = kryptos_salsa20_littleendian(n_u32[0]);
            n_u32[1] = kryptos_salsa20_littleendian(n_u32[1]);
            ks->K[32] = kryptos_salsa20_getbyte(n_u32[0], 0);
            ks->K[33] = kryptos_salsa20_getbyte(n_u32[0], 1);
            ks->K[34] = kryptos_salsa20_getbyte(n_u32[0], 2);
            ks->K[35] = kryptos_salsa20_getbyte(n_u32[0], 3);
            ks->K[36] = kryptos_salsa20_getbyte(n_u32[1], 0);
            ks->K[37] = kryptos_salsa20_getbyte(n_u32[1], 1);
            ks->K[38] = kryptos_salsa20_getbyte(n_u32[1], 2);
            ks->K[39] = kryptos_salsa20_getbyte(n_u32[1], 3);
            ks->K[40] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA2, 0);
            ks->K[41] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA2, 1);
            ks->K[42] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA2, 2);
            ks->K[43] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA2, 3);
            ks->K[44] = key[16];
            ks->K[45] = key[17];
            ks->K[46] = key[18];
            ks->K[47] = key[19];
            ks->K[48] = key[20];
            ks->K[49] = key[21];
            ks->K[50] = key[22];
            ks->K[51] = key[23];
            ks->K[52] = key[24];
            ks->K[53] = key[25];
            ks->K[54] = key[26];
            ks->K[55] = key[27];
            ks->K[56] = key[28];
            ks->K[57] = key[29];
            ks->K[58] = key[30];
            ks->K[59] = key[31];
            ks->K[60] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA3, 0);
            ks->K[61] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA3, 1);
            ks->K[62] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA3, 2);
            ks->K[63] = kryptos_salsa20_getbyte(KRYPTOS_SALSA20_THETA3, 3);
            break;

        default:
            // WARN(Rafael): It should never happen in normal conditions task check would not let us arrive here.
            break;
    }

    n_u32[0] = n_u32[1] = 0;
    ks->l += 1;

    kryptos_salsa20_H(ks->K, sizeof(ks->K));
}

#undef kryptos_salsa20_getbyte
#undef kryptos_salsa20_littleendian

#undef KRYPTOS_SALSA20_THETA0
#undef KRYPTOS_SALSA20_THETA1
#undef KRYPTOS_SALSA20_THETA2
#undef KRYPTOS_SALSA20_THETA3
