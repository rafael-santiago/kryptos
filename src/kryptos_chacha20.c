/*
 *                                Copyright (C) 2021 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_chacha20.h>
#include <kryptos_salsa20_core.h>
#include <kryptos_task_check.h>
#include <kryptos.h>

#define kryptos_chacha20_getbyte(b, n) (( (b) >> (24 - (8 * (n))) ) & 0xFF)

#define kryptos_chacha20_littleendian(w) ( (((kryptos_u32_t)(w)) << 24) |\
                                          (((kryptos_u32_t)(w) & 0x0000FF00) << 8) |\
                                          (((kryptos_u32_t)(w) & 0x00FF0000) >> 8) |\
                                          (((kryptos_u32_t)(w)) >> 24) )

#define KRYPTOS_CHACHA20_THETA0 0x61707865
#define KRYPTOS_CHACHA20_THETA1 0x3320646E
#define KRYPTOS_CHACHA20_THETA2 0x79622D32
#define KRYPTOS_CHACHA20_THETA3 0x6B206574

struct kryptos_chacha20_keystream {
    kryptos_u8_t K[64];
    kryptos_u32_t l;
};

static void kryptos_chacha20_keystream_feed(const kryptos_u8_t *key, const kryptos_u8_t *n,
                                            struct kryptos_chacha20_keystream *ks);

void kryptos_chacha20_cipher(kryptos_task_ctx **ktask) {
    struct kryptos_chacha20_keystream ks;
    kryptos_u8_t *ip = NULL, *ip_end = NULL;
    kryptos_u8_t *op = NULL;
    kryptos_u8_t *kp = NULL, *kp_end = NULL;


    if (kryptos_task_check(ktask) == 0) {
        return;
    }

    memset(&ks, 0, sizeof(ks));

    if ((*ktask)->key_size != 32) {
        (*ktask)->result = kKryptosKeyError;
        (*ktask)->result_verbose = "Key size for ChaCha20 must be a 32-byte value.";
        goto kryptos_chacha20_cipher_epilogue;
    }

    ks.l = 0;
    ip = (*ktask)->in;
    ip_end = ip + (*ktask)->in_size;

    (*ktask)->out_size = (ip_end - ip);
    (*ktask)->out = (kryptos_u8_t *)kryptos_newseg(ip_end - ip);

    if ((*ktask)->out == NULL) {
        (*ktask)->out_size = 0;
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "No memory to get a valid output.";
        goto kryptos_chacha20_cipher_epilogue;
    }

    op = (*ktask)->out;

    while (ip != ip_end) {
        kryptos_chacha20_keystream_feed((*ktask)->key, (*ktask)->iv, &ks);
        kp = &ks.K[0];
        kp_end = kp + sizeof(ks.K);
        while (kp != kp_end && ip != ip_end) {
            *op = *kp ^ *ip;
            kp++;
            ip++;
            op++;
        }
    }

    (*ktask)->result = kKryptosSuccess;

kryptos_chacha20_cipher_epilogue:

    memset(&ks, 0, sizeof(ks));

    ip = ip_end = op = kp = kp_end = NULL;
}

void kryptos_chacha20_setup(kryptos_task_ctx *ktask, kryptos_u8_t *key, const size_t key_size,
                            kryptos_u8_t *iv64) {
    if (ktask == NULL) {
        return;
    }

    ktask->cipher = kKryptosCipherCHACHA20;
    ktask->key = key;
    ktask->key_size = key_size;
    ktask->iv = iv64;
    ktask->iv_size = KRYPTOS_CHACHA20_IVSIZE;
}

static void kryptos_chacha20_keystream_feed(const kryptos_u8_t *key, const kryptos_u8_t *n,
                                           struct kryptos_chacha20_keystream *ks) {
    // INFO(Rafael): ChaCha20 only supports 256-bit keys pass key_size here is pointless.
    ks->K[ 0] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA0, 0);
    ks->K[ 1] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA0, 1);
    ks->K[ 2] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA0, 2);
    ks->K[ 3] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA0, 3);
    ks->K[ 4] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA1, 0);
    ks->K[ 5] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA1, 1);
    ks->K[ 6] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA1, 2);
    ks->K[ 7] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA1, 3);
    ks->K[ 8] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA2, 0);
    ks->K[ 9] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA2, 1);
    ks->K[10] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA2, 2);
    ks->K[11] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA2, 3);
    ks->K[12] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA3, 0);
    ks->K[13] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA3, 1);
    ks->K[14] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA3, 2);
    ks->K[15] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA3, 3);
    ks->K[16] = key[ 3];
    ks->K[17] = key[ 2];
    ks->K[18] = key[ 1];
    ks->K[19] = key[ 0];

    ks->K[20] = key[ 7];
    ks->K[21] = key[ 6];
    ks->K[22] = key[ 5];
    ks->K[23] = key[ 4];

    ks->K[24] = key[11];
    ks->K[25] = key[10];
    ks->K[26] = key[ 9];
    ks->K[27] = key[ 8];

    ks->K[28] = key[15];
    ks->K[29] = key[14];
    ks->K[30] = key[13];
    ks->K[31] = key[12];

    ks->K[32] = key[19];
    ks->K[33] = key[18];
    ks->K[34] = key[17];
    ks->K[35] = key[16];

    ks->K[36] = key[23];
    ks->K[37] = key[22];
    ks->K[38] = key[21];
    ks->K[39] = key[20];

    ks->K[40] = key[27];
    ks->K[41] = key[26];
    ks->K[42] = key[25];
    ks->K[43] = key[24];

    ks->K[44] = key[31];
    ks->K[45] = key[30];
    ks->K[46] = key[29];
    ks->K[47] = key[28];

    ks->K[48] = kryptos_chacha20_getbyte(ks->l, 0);
    ks->K[49] = kryptos_chacha20_getbyte(ks->l, 1);
    ks->K[50] = kryptos_chacha20_getbyte(ks->l, 2);
    ks->K[51] = kryptos_chacha20_getbyte(ks->l, 3);

    ks->K[52] = n[ 3];
    ks->K[53] = n[ 2];
    ks->K[54] = n[ 1];
    ks->K[55] = n[ 0];

    ks->K[56] = n[ 7];
    ks->K[57] = n[ 6];
    ks->K[58] = n[ 5];
    ks->K[59] = n[ 4];

    ks->K[60] = n[11];
    ks->K[61] = n[10];
    ks->K[62] = n[ 9];
    ks->K[63] = n[ 8];

    kryptos_chacha20_H(ks->K, sizeof(ks->K));

    ks->l += 1;
}
