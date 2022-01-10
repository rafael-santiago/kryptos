/*
 *                                Copyright (C) 2021 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_poly1305.h>
#include <kryptos_poly1305_mp.h>
#include <kryptos_memory.h>
#include <kryptos_random.h>
#include <kryptos.h>
//#include <stdio.h>

static kryptos_u8_t *kryptos_poly1305_tag(const kryptos_u8_t *message, const size_t message_size,
                                          const kryptos_u8_t *key, const size_t key_size);

static kryptos_u8_t *kryptos_poly1305_get_tag_from_num(const kryptos_poly1305_number_t a);

void do_kryptos_poly1305(kryptos_task_ctx **ktask) {
    kryptos_u8_t key[16];
    size_t k = 0;
    kryptos_u8_t *user_key = NULL, *up = NULL, *up_end = NULL;
    size_t user_key_size = 0;

    memset(key, 0, sizeof(key));

    if (ktask == NULL || (*ktask) == NULL || (*ktask)->key == NULL || (*ktask)->key_size == 0) {
        goto do_kryptos_poly1305_epilogue;
    }

    if ((*ktask)->key_size > 16) {
        user_key = (*ktask)->key;
        user_key_size = (*ktask)->key_size;

        // INFO(Rafael): Copying the first 128-bits.
        memcpy(key, user_key, sizeof(key));
        up = user_key + sizeof(key);
        up_end = user_key + user_key_size;

        // INFO(Rafael): "Compressing" the remaining bytes by xoring them up
        //               with the 128-bit most significant key slice.
        while (up != up_end) {
            key[k] ^= *up;
            up++;
            k = (k + 1) % sizeof(key);
        }

        (*ktask)->key = &key[0];
        (*ktask)->key_size = sizeof(key);
    }

    kryptos_poly1305(ktask);

do_kryptos_poly1305_epilogue:

    if (user_key != NULL) {
        (*ktask)->key = user_key;
        (*ktask)->key_size = user_key_size;
    }

    up = up_end = user_key = NULL;
    k = user_key_size = 0;

    memset(key, 0, sizeof(key));
}

void kryptos_poly1305(kryptos_task_ctx **ktask) {
    kryptos_u8_t *key = NULL;
    kryptos_u8_t *nonce = NULL;
    size_t nonce_size = 0;
    kryptos_u8_t *tag = NULL;
    kryptos_u8_t *tagged_message = NULL;
    size_t tagged_message_size = 0;

    if ((*ktask)->key_size > 32) {
        (*ktask)->result = kKryptosPOLY1305Error;
        (*ktask)->result_verbose = "Unable to authenticate a message with a key greater than 256-bits.";
        goto kryptos_poly1305_epilogue;
    }

    switch ((*ktask)->action) {
        case kKryptosEncrypt:
            if ((*ktask)->out == NULL || (*ktask)->out_size == 0) {
                (*ktask)->result = kKryptosPOLY1305Error;
                (*ktask)->result_verbose = "No message to tag at output buffer.";
                goto kryptos_poly1305_epilogue;
            }

            if ((*ktask)->key == NULL || (*ktask)->key_size == 0) {
                (*ktask)->result = kKryptosPOLY1305Error;
                (*ktask)->result_verbose = "No key to authenticate.";
                goto kryptos_poly1305_epilogue;
            }

            // INFO(Rafael): Key sizes less than 32-bits will be padded with a nonce.
            //               Key size equals to 256-bits assumes that the s chunk is an external nonce.
            nonce_size = 32 - (*ktask)->key_size;
            if (nonce_size > 0) {
                if ((nonce = kryptos_get_random_block(nonce_size)) == NULL) {
                    (*ktask)->result = kKryptosPOLY1305Error;
                    (*ktask)->result_verbose = "Unable to get a valid nonce.";
                    goto kryptos_poly1305_epilogue;
                }
                key = (kryptos_u8_t *)kryptos_newseg(32);
                if (key == NULL) {
                    (*ktask)->result = kKryptosPOLY1305Error;
                    (*ktask)->result_verbose = "Unable to get temporary memory segment to fit the entire key.";
                    goto kryptos_poly1305_epilogue;
                }
                memcpy(key, (*ktask)->key, (*ktask)->key_size);
                memcpy(key + (*ktask)->key_size, nonce, nonce_size);
            } else {
                key = (*ktask)->key;
            }

            if ((tag = kryptos_poly1305_tag((*ktask)->out, (*ktask)->out_size, key, 32)) == NULL) {
                (*ktask)->result = kKryptosPOLY1305Error;
                (*ktask)->result_verbose = "Unable to generate message tag.";
                goto kryptos_poly1305_epilogue;
            }

            tagged_message_size = 16 + nonce_size + (*ktask)->out_size;
            tagged_message = (kryptos_u8_t *)kryptos_newseg(tagged_message_size);
            if (tagged_message == NULL) {
                (*ktask)->result = kKryptosPOLY1305Error;
                (*ktask)->result_verbose = "Not enough memory to authenticate message buffer.";
                goto kryptos_poly1305_epilogue;
            }

            // INFO(Rafael): Output schema -> <tag>[<nonce>]<message>.

            memcpy(tagged_message, tag, 16);

            if (nonce_size > 0) {
                memcpy(tagged_message + 16, nonce, nonce_size);
            }

            memcpy(tagged_message + 16 + nonce_size, (*ktask)->out, (*ktask)->out_size);
            kryptos_freeseg((*ktask)->out, (*ktask)->out_size);
            (*ktask)->out_size = tagged_message_size;
            (*ktask)->out = tagged_message;
            tagged_message = NULL;

            break;

        case kKryptosDecrypt:
            if ((*ktask)->in == NULL || (*ktask)->in_size == 0) {
                (*ktask)->result = kKryptosPOLY1305Error;
                (*ktask)->result_verbose = "No message to verify.";
                goto kryptos_poly1305_epilogue;
            }

            if ((*ktask)->key == NULL || (*ktask)->key_size == 0) {
                (*ktask)->result = kKryptosPOLY1305Error;
                (*ktask)->result_verbose = "No key to authenticate.";
                goto kryptos_poly1305_epilogue;
            }

            if ((*ktask)->key_size < 32) {
                nonce_size = 32 - (*ktask)->key_size;
            }

            if ((*ktask)->in_size <= nonce_size + 16) {
                (*ktask)->result = kKryptosPOLY1305Error;
                (*ktask)->result_verbose = "Message buffer seems to be incomplete.";
                goto kryptos_poly1305_epilogue;
            }

            if (nonce_size > 0) {
                if ((nonce = (kryptos_u8_t *)kryptos_newseg(nonce_size)) == NULL) {
                    (*ktask)->result = kKryptosPOLY1305Error;
                    (*ktask)->result_verbose = "Not enough memory to parse nonce.";
                    goto kryptos_poly1305_epilogue;
                }

                memcpy(nonce, (*ktask)->in + 16, nonce_size);

                if ((key = (kryptos_u8_t *)kryptos_newseg(nonce_size + (*ktask)->key_size)) == NULL) {
                    (*ktask)->result = kKryptosPOLY1305Error;
                    (*ktask)->result_verbose = "Not enough memory to make the session key.";
                    goto kryptos_poly1305_epilogue;
                }

                memcpy(key, (*ktask)->key, (*ktask)->key_size);
                memcpy(key + (*ktask)->key_size, nonce, nonce_size);

            } else {
                key = (*ktask)->key;
            }

            tag = kryptos_poly1305_tag((*ktask)->in + 16 + nonce_size, (*ktask)->in_size - 16 - nonce_size,
                                       key, 32);
            if (tag == NULL) {
                (*ktask)->result = kKryptosPOLY1305Error;
                (*ktask)->result_verbose = "Unable to generate message tag.";
                goto kryptos_poly1305_epilogue;
            }

            if (memcmp(tag, (*ktask)->in, 16) != 0) {
                (*ktask)->result = kKryptosPOLY1305Error;
                (*ktask)->result_verbose = "Corrupted data.";
                goto kryptos_poly1305_epilogue;
            }

            tagged_message = (*ktask)->in;
            tagged_message_size = (*ktask)->in_size;

            (*ktask)->in_size -= (16 + nonce_size);
            (*ktask)->in = (kryptos_u8_t *)kryptos_newseg((*ktask)->in_size);
            if ((*ktask)->in == NULL) {
                (*ktask)->result = kKryptosPOLY1305Error;
                (*ktask)->result_verbose = "No memory to extract original authenticated message.";
                goto kryptos_poly1305_epilogue;
            }

            memcpy((*ktask)->in, tagged_message + 16 + nonce_size, (*ktask)->in_size);

            break;

        default:
            (*ktask)->result = kKryptosPOLY1305Error;
            (*ktask)->result_verbose = "Unknown action.";
            break;
    }

    (*ktask)->result = kKryptosSuccess;
    (*ktask)->result_verbose = NULL;

kryptos_poly1305_epilogue:

    if (key != NULL && key != (*ktask)->key) {
        kryptos_freeseg(key, 32);
    }

    if (nonce != NULL) {
        kryptos_freeseg(nonce, nonce_size);
    }

    if (tag != NULL) {
        kryptos_freeseg(tag, 16);
        tag = NULL;
    }

    if (tagged_message != NULL) {
        kryptos_freeseg(tagged_message, tagged_message_size);
        tagged_message = NULL;
    }

    key = nonce = NULL;
    nonce_size = tagged_message_size = 0;
}

static kryptos_u8_t *kryptos_poly1305_tag(const kryptos_u8_t *message, const size_t message_size,
                                          const kryptos_u8_t *key, const size_t key_size) {
    kryptos_u8_t working_key[32], poly_mbuf[17];
    kryptos_u8_t *tag = NULL;
    kryptos_poly1305_number_t p, r, s, a, n, a_mod;
    const kryptos_u8_t *mp = NULL, *mp_end = NULL;
    kryptos_u8_t *bp = NULL, *bp_end = NULL;

    memset(working_key, 0, sizeof(working_key));

    if (message == NULL || message_size == 0 || key == NULL || key_size == 0) {
        goto kryptos_poly1305_tag_epilogue;
    }

    memcpy(working_key, key, key_size);
    /*
    printf("KEY: %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X\n"
           "     %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X\n",
            working_key[0], working_key[1], working_key[2], working_key[3], working_key[4], working_key[5],
            working_key[6], working_key[7], working_key[8], working_key[9], working_key[10], working_key[11],
            working_key[12], working_key[13], working_key[14], working_key[15], working_key[16], working_key[17],
            working_key[18], working_key[19], working_key[20], working_key[21], working_key[22], working_key[23],
            working_key[24], working_key[25], working_key[26], working_key[27], working_key[28], working_key[29],
            working_key[30], working_key[31]);
    */

    // INFO(Rafael): This is is the "Clamp(r)" and the mask to apply when it is still not loaded as number.
    working_key[ 3] &= 0x0F;
    working_key[ 7] &= 0x0F;
    working_key[11] &= 0x0F;
    working_key[15] &= 0x0F;
    working_key[ 4] &= 0xFC;
    working_key[ 8] &= 0xFC;
    working_key[12] &= 0xFC;

    /*
    printf("R:   %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X\n"
           "     %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X %.2X\n",
            working_key[0], working_key[1], working_key[2], working_key[3], working_key[4], working_key[5],
            working_key[6], working_key[7], working_key[8], working_key[9], working_key[10], working_key[11],
            working_key[12], working_key[13], working_key[14], working_key[15], working_key[16], working_key[17],
            working_key[18], working_key[19], working_key[20], working_key[21], working_key[22], working_key[23],
            working_key[24], working_key[25], working_key[26], working_key[27], working_key[28], working_key[29],
            working_key[30], working_key[31]);
    */

    kryptos_poly1305_le_bytes_to_num(r, working_key, 16);

    kryptos_poly1305_le_bytes_to_num(s, &working_key[16], 16);

    /*
    printf("S = %llx %llx %llx %llx %llx %llx %llx\n", s[0], s[1], s[2], s[3], s[4], s[5], s[6]);
    printf("R = %llx %llx %llx %llx %llx %llx %llx\n", r[0], r[1], r[2], r[3], r[4], r[5], r[6]);
    */

    memset(a, 0, sizeof(kryptos_poly1305_number_t));

    // INFO(Rafael): Setting P to 2^130-5.

#if defined(KRYPTOS_MP_EXTENDED_RADIX)
    p[ 0] = 0xFFFFFFFFFFFFFFFB;
    p[ 1] = 0xFFFFFFFFFFFFFFFF;
    p[ 2] = 0x0000000000000003;
    p[ 3] = 0x0000000000000000;
    p[ 4] = 0x0000000000000000;
    p[ 5] = 0x0000000000000000;
    p[ 6] = 0x0000000000000000;
#else
    p[ 0] = 0xFFFFFFFB;
    p[ 1] = 0xFFFFFFFF;
    p[ 2] = 0xFFFFFFFF;
    p[ 3] = 0xFFFFFFFF;
    p[ 4] = 0x00000003;
    p[ 5] = 0x00000000;
    p[ 6] = 0x00000000;
    p[ 7] = 0x00000000;
    p[ 8] = 0x00000000;
    p[ 9] = 0x00000000;
    p[10] = 0x00000000;
#endif

    mp = message;
    mp_end = message + message_size;

    memset(poly_mbuf, 0x01, sizeof(poly_mbuf));
    bp = &poly_mbuf[0];
    bp_end = bp + sizeof(poly_mbuf) - 1;

    while(mp != mp_end) {
        if (bp != bp_end && (mp + 1) != mp_end) {
            *bp = *mp;
            bp++;
            mp++;
        } else {
            if ((mp + 1) == mp_end && bp != bp_end) {
                *bp = *mp;
                bp++;
                mp++;
            }
            /*
            printf("MBUF (size=%lu)= ", 17 - (bp_end - bp));
            for (b = 0; b < 17 - (bp_end - bp); b++) {
                printf("%.2X ", poly_mbuf[b]);
            }
            printf("\n");
            */
            kryptos_poly1305_le_bytes_to_num(n, poly_mbuf, 17 - (bp_end - bp));
            //printf("Acc = %llx %llx %llx %llx %llx %llx %llx\n", a[0], a[1], a[2], a[3], a[4], a[5], a[6]);
            //printf("Block with 0x01 = %llx %llx %llx %llx %llx %llx %llx\n", n[0], n[1], n[2], n[3], n[4], n[5], n[6]);
            kryptos_poly1305_add(a, n);
            //printf("Acc + Block = %llx %llx %llx %llx %llx %llx %llx\n", a[0], a[1], a[2], a[3], a[4], a[5], a[6]);
            kryptos_poly1305_mul(a, r);
            //printf("(Acc + Block) * r = %llx %llx %llx %llx %llx %llx %llx\n", a[0], a[1], a[2], a[3], a[4], a[5], a[6]);
            kryptos_poly1305_div(a, p, a_mod);
            memcpy(a, a_mod, sizeof(kryptos_poly1305_number_t));
            //printf("(Acc + Block) * r) %% P = %llx %llx %llx %llx %llx %llx %llx\n--\n", a[0], a[1], a[2], a[3], a[4], a[5], a[6]);

            memset(poly_mbuf, 0x01, sizeof(poly_mbuf));
            bp = &poly_mbuf[0];
        }
    }

    kryptos_poly1305_add(a, s);
    //printf("Acc + s = %llx %llx %llx %llx %llx %llx %llx\n", a[0], a[1], a[2], a[3], a[4], a[5], a[6]);

    tag = kryptos_poly1305_get_tag_from_num(a);

kryptos_poly1305_tag_epilogue:

    memset(working_key, 0, sizeof(working_key));
    memset(p, 0, sizeof(kryptos_poly1305_number_t));
    memset(r, 0, sizeof(kryptos_poly1305_number_t));
    memset(s, 0, sizeof(kryptos_poly1305_number_t));
    memset(a, 0, sizeof(kryptos_poly1305_number_t));
    memset(n, 0, sizeof(kryptos_poly1305_number_t));
    memset(a_mod, 0, sizeof(kryptos_poly1305_number_t));

    mp = mp_end = NULL;

    return tag;
}

static kryptos_u8_t *kryptos_poly1305_get_tag_from_num(const kryptos_poly1305_number_t a) {
    kryptos_u8_t *t = (kryptos_u8_t *)kryptos_newseg(16);
    if (t == NULL) {
        return NULL;
    }

#define get_byte(w, n) ( ( (w) >> (((sizeof(kryptos_poly1305_numfrac_t) << 3) - 8) - ((n) << 3)) ) & 0xFF )

#if defined(KRYPTOS_MP_EXTENDED_RADIX)
    t[ 0] = get_byte(a[ 0], 7);
    t[ 1] = get_byte(a[ 0], 6);
    t[ 2] = get_byte(a[ 0], 5);
    t[ 3] = get_byte(a[ 0], 4);
    t[ 4] = get_byte(a[ 0], 3);
    t[ 5] = get_byte(a[ 0], 2);
    t[ 6] = get_byte(a[ 0], 1);
    t[ 7] = get_byte(a[ 0], 0);
    t[ 8] = get_byte(a[ 1], 7);
    t[ 9] = get_byte(a[ 1], 6);
    t[10] = get_byte(a[ 1], 5);
    t[11] = get_byte(a[ 1], 4);
    t[12] = get_byte(a[ 1], 3);
    t[13] = get_byte(a[ 1], 2);
    t[14] = get_byte(a[ 1], 1);
    t[15] = get_byte(a[ 1], 0);
#else
    t[ 0] = get_byte(a[ 0], 3);
    t[ 1] = get_byte(a[ 0], 2);
    t[ 2] = get_byte(a[ 0], 1);
    t[ 3] = get_byte(a[ 0], 0);
    t[ 4] = get_byte(a[ 1], 3);
    t[ 5] = get_byte(a[ 1], 2);
    t[ 6] = get_byte(a[ 1], 1);
    t[ 7] = get_byte(a[ 1], 0);
    t[ 8] = get_byte(a[ 2], 3);
    t[ 9] = get_byte(a[ 2], 2);
    t[10] = get_byte(a[ 2], 1);
    t[11] = get_byte(a[ 2], 0);
    t[12] = get_byte(a[ 3], 3);
    t[13] = get_byte(a[ 3], 2);
    t[14] = get_byte(a[ 3], 1);
    t[15] = get_byte(a[ 3], 0);
#endif

#undef get_byte

    return t;
}
