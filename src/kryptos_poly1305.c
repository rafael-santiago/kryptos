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

static kryptos_u8_t *kryptos_poly1305_tag(const kryptos_u8_t *message, const size_t message_size,
                                          const kryptos_u8_t *key, const size_t key_size);

static kryptos_u8_t *kryptos_poly1305_get_tag_from_num(const kryptos_poly1305_number_t a);

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
            //               Key size equals to 256-bits assumes that the s chunk is a external nonce.
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

            if ((*ktask)->in_size < nonce_size + 16) {
                (*ktask)->result = kKryptosPOLY1305Error;
                (*ktask)->result_verbose = "Message buffer seems to be incomplete.";
                goto kryptos_poly1305_epilogue;
            }

            if (nonce_size > 0) {
                if ((nonce = (kryptos_u8_t *)kryptos_newseg(nonce_size)) == NULL) {
                    (*ktask)->result = kKryptosPOLY1305Error;
                    (*ktask)->result_verbose = "No enough memory to parse nonce.";
                    goto kryptos_poly1305_epilogue;
                }

                memcpy(nonce, (*ktask)->in + 16, nonce_size);

                if ((key = (kryptos_u8_t *)kryptos_newseg(nonce_size + (*ktask)->key_size)) == NULL) {
                    (*ktask)->result = kKryptosPOLY1305Error;
                    (*ktask)->result_verbose = "No enough memory to make the session key.";
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
    kryptos_u8_t working_key[32];
    kryptos_u8_t *tag = NULL;
    kryptos_poly1305_number_t p, r, s, a, n, a_mod;
    size_t m_pad = 0;
    kryptos_u8_t *msg = NULL, *mp = NULL, *mp_end = NULL;

    memset(working_key, 0, sizeof(working_key));

    if (message == NULL || message_size == 0 || key == NULL || key_size == 0) {
        goto kryptos_poly1305_tag_epilogue;
    }

    memcpy(working_key, key, key_size);

    // INFO(Rafael): This is is the "Clamp(r)" and the mask to apply when it is still not loaded as number.
    working_key[ 3] &= 0xFF;
    working_key[ 7] &= 0xFF;
    working_key[11] &= 0xFF;
    working_key[15] &= 0xFF;
    working_key[ 4] &= 0xFC;
    working_key[ 8] &= 0xFC;
    working_key[12] &= 0xFC;

    kryptos_poly1305_le_bytes_to_num(r, working_key, 16);

    kryptos_poly1305_le_bytes_to_num(s, &working_key[16], 16);

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

    m_pad = (message_size % 16);

    msg = (kryptos_u8_t *) kryptos_newseg(message_size + m_pad);
    if (msg == NULL) {
        goto kryptos_poly1305_tag_epilogue;
    }

    memset(msg, 0, message_size + m_pad);
    memcpy(msg, message, message_size);
    if (m_pad > 0) {
        msg[m_pad + message_size] = 0x01;
    }

    mp = msg;
    mp_end = mp + message_size + m_pad;

    while(mp != mp_end) {
        kryptos_poly1305_le_bytes_to_num(n, mp, 16);
        kryptos_poly1305_add(a, n);
        kryptos_poly1305_mul(a, r);
        kryptos_poly1305_div(a, p, a_mod);
        memcpy(a, a_mod, sizeof(kryptos_poly1305_number_t));
        mp += 16;
    }

    kryptos_poly1305_add(a, s);

    tag = kryptos_poly1305_get_tag_from_num(a);

kryptos_poly1305_tag_epilogue:

    memset(working_key, 0, sizeof(working_key));
    memset(p, 0, sizeof(kryptos_poly1305_number_t));
    memset(r, 0, sizeof(kryptos_poly1305_number_t));
    memset(s, 0, sizeof(kryptos_poly1305_number_t));
    memset(a, 0, sizeof(kryptos_poly1305_number_t));
    memset(n, 0, sizeof(kryptos_poly1305_number_t));
    memset(a_mod, 0, sizeof(kryptos_poly1305_number_t));

    if (msg != NULL) {
        kryptos_freeseg(msg, message_size + m_pad);
    }

    m_pad = 0;

    msg = mp = mp_end = NULL;

    return tag;
}

static kryptos_u8_t *kryptos_poly1305_get_tag_from_num(const kryptos_poly1305_number_t a) {
    kryptos_u8_t *t = (kryptos_u8_t *)kryptos_newseg(16);
    if (t == NULL) {
        return NULL;
    }

#define get_byte(w, n) ( ( (w) >> (((sizeof(kryptos_poly1305_numfrac_t) << 3) - 8) - ((n) << 3)) ) & 0xFF )

#if defined(KRYPTOS_MP_EXTENDED_RADIX)
    t[ 0] = get_byte(a[ 0], 0);
    t[ 1] = get_byte(a[ 0], 1);
    t[ 2] = get_byte(a[ 0], 2);
    t[ 3] = get_byte(a[ 0], 3);
    t[ 4] = get_byte(a[ 0], 4);
    t[ 5] = get_byte(a[ 0], 5);
    t[ 6] = get_byte(a[ 0], 6);
    t[ 7] = get_byte(a[ 0], 7);
    t[ 8] = get_byte(a[ 1], 0);
    t[ 9] = get_byte(a[ 1], 1);
    t[10] = get_byte(a[ 1], 2);
    t[11] = get_byte(a[ 1], 3);
    t[12] = get_byte(a[ 1], 4);
    t[13] = get_byte(a[ 1], 5);
    t[14] = get_byte(a[ 1], 6);
    t[15] = get_byte(a[ 1], 7);
#else
    t[ 0] = get_byte(a[ 0], 0);
    t[ 1] = get_byte(a[ 0], 1);
    t[ 2] = get_byte(a[ 0], 2);
    t[ 3] = get_byte(a[ 0], 3);
    t[ 4] = get_byte(a[ 1], 0);
    t[ 5] = get_byte(a[ 1], 1);
    t[ 6] = get_byte(a[ 1], 2);
    t[ 7] = get_byte(a[ 1], 3);
    t[ 8] = get_byte(a[ 2], 0);
    t[ 9] = get_byte(a[ 2], 1);
    t[10] = get_byte(a[ 2], 2);
    t[11] = get_byte(a[ 2], 3);
    t[12] = get_byte(a[ 3], 0);
    t[13] = get_byte(a[ 3], 1);
    t[14] = get_byte(a[ 3], 2);
    t[15] = get_byte(a[ 3], 3);
#endif

#undef get_byte

    return t;
}
