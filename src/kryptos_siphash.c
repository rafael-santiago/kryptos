/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_siphash.h>
#include <kryptos.h>
#include <kryptos_endianness_utils.h>

#define KRYPTOS_SIPHASH_HASH_SIZE 8

#define KRYPTOS_SIPHASH_KEY_SIZE 16

#define kryptos_siphash_rotl(v, l) ( ((v) << (l)) | ((v) >> ((sizeof(v) << 3) - (l))) )

#define kryptos_sipround(v0, v1, v2, v3) {\
    (v0) += (v1);\
    (v2) += (v3);\
    (v1) = kryptos_siphash_rotl(v1, 13);\
    (v3) = kryptos_siphash_rotl(v3, 16);\
    (v1) ^= (v0);\
    (v3) ^= (v2);\
    (v0) = kryptos_siphash_rotl(v0, 32);\
    (v2) += (v1);\
    (v0) += (v3);\
    (v1) = kryptos_siphash_rotl(v1, 17);\
    (v3) = kryptos_siphash_rotl(v3, 21);\
    (v1) ^= (v2);\
    (v3) ^= (v0);\
    (v2) = kryptos_siphash_rotl(v2, 32);\
}

#define KRYPTOS_SIPHASH_V0_XMSK 0x736F6D6570736575
#define KRYPTOS_SIPHASH_V1_XMSK 0x646F72616E646F6D
#define KRYPTOS_SIPHASH_V2_XMSK 0x6C7967656E657261
#define KRYPTOS_SIPHASH_V3_XMSK 0x7465646279746573

static void kryptos_do_siphash(kryptos_u64_t *output,
                               const kryptos_u8_t *message, const size_t message_size,
                               const kryptos_u8_t *key, const size_t key_size,
                               const size_t c, const size_t d);

size_t kryptos_siphash_size(void) {
    return KRYPTOS_SIPHASH_HASH_SIZE;
}

void kryptos_siphash(kryptos_task_ctx **ktask, const size_t c, const size_t d) {
    kryptos_u64_t output = 0;
    kryptos_u8_t key[KRYPTOS_SIPHASH_KEY_SIZE];
    kryptos_u8_t *kp = NULL, *kp_end = NULL;
    size_t k = 0;
    kryptos_u8_t *tagged_message = NULL;
    size_t tagged_message_size = 0;

    memset(key, 0, sizeof(key));

    if ((*ktask)->key == NULL || (*ktask)->key == 0) {
        (*ktask)->result = kKryptosKeyError;
        (*ktask)->result_verbose = "Null key.";
        goto kryptos_siphash_epilogue;
    } else if ((*ktask)->key != NULL && (*ktask)->key_size <= KRYPTOS_SIPHASH_KEY_SIZE) {
        memcpy(key, (*ktask)->key, (*ktask)->key_size);
    } else if ((*ktask)->key != NULL) {
        memcpy(key, (*ktask)->key, KRYPTOS_SIPHASH_KEY_SIZE);
        kp = (*ktask)->key + KRYPTOS_SIPHASH_KEY_SIZE;
        kp_end = (*ktask)->key + (*ktask)->key_size;
        while (kp != kp_end) {
            key[k] ^= *kp;
            kp++;
            k = (k + 1) % KRYPTOS_SIPHASH_KEY_SIZE;
        }
    }

    switch ((*ktask)->action) {
        case kKryptosEncrypt:
            if ((*ktask)->out == NULL || (*ktask)->out_size == 0) {
                (*ktask)->result = kKryptosSipHashError;
                (*ktask)->result_verbose = "No message to tag at output buffer.";
                goto kryptos_siphash_epilogue;
            }

            kryptos_do_siphash(&output, (*ktask)->out, (*ktask)->out_size, key, KRYPTOS_SIPHASH_KEY_SIZE, c, d);

            tagged_message = (kryptos_u8_t *)kryptos_newseg(sizeof(kryptos_u64_t) + (*ktask)->out_size);
            if (tagged_message == NULL) {
                (*ktask)->result = kKryptosProcessError;
                (*ktask)->result_verbose = "Not enough memory to output.";
                goto kryptos_siphash_epilogue;
            }

            // INFO(Rafael): SipHash on its spec by its presented test vector, implicitly states that
            //               the MAC is expressed in big-endian by design. Thus, I am letting it explicitly
            //               big-endian here.
            tagged_message[0] = ((output >> 56) & 0xFF);
            tagged_message[1] = ((output >> 48) & 0xFF);
            tagged_message[2] = ((output >> 40) & 0xFF);
            tagged_message[3] = ((output >> 32) & 0xFF);
            tagged_message[4] = ((output >> 24) & 0xFF);
            tagged_message[5] = ((output >> 16) & 0xFF);
            tagged_message[6] = ((output >>  8) & 0xFF);
            tagged_message[7] = output & 0xFF;

            memcpy(tagged_message + sizeof(kryptos_u64_t), (*ktask)->out, (*ktask)->out_size);

            kryptos_freeseg((*ktask)->out, (*ktask)->out_size);
            (*ktask)->out = tagged_message;
            tagged_message = NULL; // INFO(Rafael): Resource transferred.
            (*ktask)->out_size += sizeof(kryptos_u64_t);

            (*ktask)->result = kKryptosSuccess;
            break;

        case kKryptosDecrypt:
            if ((*ktask)->in == NULL || (*ktask)->in_size <= sizeof(kryptos_u64_t)) {
                (*ktask)->result = kKryptosSipHashError;
                (*ktask)->result_verbose = "No message to verify at input buffer.";
                goto kryptos_siphash_epilogue;
            }

            kryptos_do_siphash(&output, (*ktask)->in + sizeof(kryptos_u64_t), (*ktask)->in_size - sizeof(kryptos_u64_t),
                               key, KRYPTOS_SIPHASH_KEY_SIZE, c, d);

            if (output != kryptos_get_u64_as_big_endian((*ktask)->in, sizeof(kryptos_u64_t))) {
                (*ktask)->result = kKryptosSipHashError;
                (*ktask)->result_verbose = "Corrupted data.";
                goto kryptos_siphash_epilogue;
            }

            tagged_message = (*ktask)->in;
            tagged_message_size = (*ktask)->in_size;

            (*ktask)->in = (kryptos_u8_t *)kryptos_newseg(tagged_message_size - sizeof(kryptos_u64_t));
            if ((*ktask)->in == NULL) {
                (*ktask)->result = kKryptosProcessError;
                (*ktask)->result_verbose = "Not enough memory to authenticate the message buffer.";
                (*ktask)->in = tagged_message;
                tagged_message = NULL;
                tagged_message_size = 0;
                goto kryptos_siphash_epilogue;
            }

            memcpy((*ktask)->in, tagged_message + sizeof(kryptos_u64_t), tagged_message_size - sizeof(kryptos_u64_t));
            (*ktask)->in_size -= sizeof(kryptos_u64_t);

            (*ktask)->result = kKryptosSuccess;
            break;

        default:
            (*ktask)->result = kKryptosNoSupport;
            (*ktask)->result_verbose = "SipHash only operates over encrypt or decrypt actions.";
            break;
    }

kryptos_siphash_epilogue:

    output = 0;
    k = 0;
    kp = kp_end = NULL;

    memset(key, 0, sizeof(key));

    if (tagged_message != NULL) {
        kryptos_freeseg(tagged_message, tagged_message_size);
        tagged_message = NULL;
    }

    tagged_message_size = 0;
}

kryptos_u64_t kryptos_siphash_sum(const kryptos_u8_t *message,
                                  const size_t message_size,
                                  const kryptos_u8_t *key,
                                  const size_t key_size,
                                  const size_t c, const size_t d) {
    const kryptos_u8_t *kp = NULL, *kp_end = NULL;
    kryptos_u8_t ekey[KRYPTOS_SIPHASH_KEY_SIZE];
    size_t k = 0;
    kryptos_u64_t sum = 0;

    if (c == 0 || d == 0 ||
        key == NULL || key_size == 0 ||
        (message == NULL && message_size > 0)) {
        goto kryptos_siphash_sum_epilogue;
    }

    memset(ekey, 0, sizeof(ekey));

    if (key_size <= KRYPTOS_SIPHASH_KEY_SIZE) {
        memcpy(ekey, key, key_size);
    } else {
        memcpy(ekey, key, KRYPTOS_SIPHASH_KEY_SIZE);
        kp = key + KRYPTOS_SIPHASH_KEY_SIZE;
        kp_end = key + key_size;
        while (kp != kp_end) {
            ekey[k] ^= *kp;
            kp++;
            k = (k + 1) % KRYPTOS_SIPHASH_KEY_SIZE;
        }
    }

    kryptos_do_siphash(&sum, message, message_size, key, KRYPTOS_SIPHASH_KEY_SIZE, c, d);

kryptos_siphash_sum_epilogue:

    kp = kp_end = NULL;
    memset(ekey, 0, sizeof(ekey));
    k = 0;

    return sum;
}


static void kryptos_do_siphash(kryptos_u64_t *output,
                               const kryptos_u8_t *message, const size_t message_size,
                               const kryptos_u8_t *key, const size_t key_size,
                               const size_t c, const size_t d) {
    kryptos_u64_t *cwp = NULL, *cwp_end = NULL;
    kryptos_u64_t k[2];
    kryptos_u64_t v[4];
    kryptos_u64_t m = 0;
    const kryptos_u8_t *up = NULL, *up_end = NULL;
    size_t i = 0;

    k[0] = k[1] = 0;
    v[0] = v[1] = v[2] = v[3] = 0;

    // INFO(Rafael): Loading user key into k vector.

    // INFO(Rafael): At this point we have checked already that user key has 128-bit.
    up = key;
    up_end = up + key_size;
    cwp = &k[0];
    cwp_end = cwp + sizeof(k) / sizeof(k[0]);
    i = 0;
    while (up != up_end) {
        *cwp |= (((kryptos_u64_t)*up << (i << 3)));
        up++;
        i = (i + 1) % sizeof(kryptos_u64_t);
        cwp += ((i % sizeof(kryptos_u64_t)) == 0);
    }

    // INFO(Rafael): Initialising v vector.

    v[0] = KRYPTOS_SIPHASH_V0_XMSK ^ k[0];
    v[1] = KRYPTOS_SIPHASH_V1_XMSK ^ k[1];
    v[2] = KRYPTOS_SIPHASH_V2_XMSK ^ k[0];
    v[3] = KRYPTOS_SIPHASH_V3_XMSK ^ k[1];

    // INFO(Rafael): Compression.

#define kryptos_siphash_get_next_message_chunk(m, mi, up, up_end, msize) {\
    (m) = 0;\
    (mi) = 0;\
    if (((up) + 8) > (up_end)) {\
        (m) = (kryptos_u64_t)((msize) % 256) << 56;\
    }\
    while ((up) != (up_end) && (mi) < 8) {\
        (m) |= (((kryptos_u64_t)*(up) << ((mi) << 3)));\
        (up)++;\
        (mi)++;\
    }\
}

    up = message;
    up_end = up + message_size;
    while (up != up_end) {
        kryptos_siphash_get_next_message_chunk(m, i, up, up_end, message_size);
        // INFO(Rafael): 'v3 ^= mi...'
        v[3] ^= m;
        // INFO(Rafael): '...and then c iterations of SipRound, followed by...'
        for (i = 0; i < c; i++) {
            kryptos_sipround(v[0], v[1], v[2], v[3]);
        }
        // INFO(Rafael): '...v0 ^= mi...'
        v[0] ^= m;
    }

    if ((message_size % 8) == 0) {
        v[3] ^= ((kryptos_u64_t)(message_size % 256) << 56);
        for (i = 0; i < c; i++) {
            kryptos_sipround(v[0], v[1], v[2], v[3]);
        }
        v[0] ^= ((kryptos_u64_t)(message_size % 256) << 56);
    }

#undef kryptos_siphash_get_next_message_chunk

    // INFO(Rafael): Finalization.
    //               '...After all the message words have been processed, SipHash-c-d xors
    //                  the constant ff to the state: v2 ^= ff...'

    v[2] ^= 0xFF;

    // INFO(Rafael): '...then does d iterations of SipRound, ...'

    for (i = 0; i < d; i++) {
        kryptos_sipround(v[0], v[1], v[2], v[3]);
    }

    // INFO(Rafael): '...and returns the 64-bit value v0 ^ v1 ^ v2 ^v3.'

    *output = v[0] ^ v[1] ^ v[2] ^ v[3];

    cwp = cwp_end = NULL;
    up = up_end = NULL;

    k[0] = k[1] = 0;
    v[0] = v[1] = v[2] = v[3] = 0;
    m = 0;
    i = 0;
}

#undef KRYPTOS_SIPHASH_HASH_SIZE
#undef KRYPTOS_SIPHASH_KEY_SIZE

#undef kryptos_siphash_rotl
#undef kryptos_sipround

#undef KRYPTOS_SIPHASH_V0_XMSK
#undef KRYPTOS_SIPHASH_V1_XMSK
#undef KRYPTOS_SIPHASH_V2_XMSK
#undef KRYPTOS_SIPHASH_V3_XMSK
