/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_hmac.h>
#include <kryptos.h>
#include <kryptos_memory.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <stdlib.h>
# include <string.h>
#endif

#define KRYPTOS_HMAC_IPAD 0x36

#define KRYPTOS_HMAC_OPAD 0x5C

static kryptos_u8_t *kryptos_hmac_gen(const kryptos_u8_t *key, const size_t key_size,
                                      kryptos_u8_t *x, const size_t x_size,
                                      kryptos_hash_func h,
                                      kryptos_hash_size_func h_input_size,
                                      kryptos_hash_size_func h_size,
                                      size_t *out_size, kryptos_task_result_t *result, char **result_verbose);

static void kryptos_hmac_check(kryptos_task_ctx **ktask,
                               kryptos_hash_func h,
                               kryptos_hash_size_func h_input_size,
                               kryptos_hash_size_func h_size);

void kryptos_hmac(kryptos_task_ctx **ktask,
                  kryptos_hash_func h,
                  kryptos_hash_size_func h_input_size,
                  kryptos_hash_size_func h_size) {

    if (ktask == NULL) {
        return;
    }

    if (h == NULL || h_input_size == NULL || h_size == NULL) {
        (*ktask)->result = kKryptosHMACError;
        (*ktask)->result_verbose = "The hash algorithm was not properly specified.";
        return;
    }

    if ((*ktask)->key == NULL || (*ktask)->key_size == 0) {
        (*ktask)->result = kKryptosHMACError;
        (*ktask)->result_verbose = "Null key.";
        return;
    }

    switch ((*ktask)->action) {
        case kKryptosEncrypt:

            // INFO(Rafael): The "in" was previously encrypted into "out".

            if ((*ktask)->out == NULL || (*ktask)->out_size == 0) {
                (*ktask)->result = kKryptosHMACError;
                (*ktask)->result_verbose = "Null output.";
                return;
            }

            (*ktask)->out = kryptos_hmac_gen((*ktask)->key, (*ktask)->key_size,
                                             (*ktask)->out, (*ktask)->out_size,
                                             h, h_input_size, h_size, &(*ktask)->out_size,
                                             &(*ktask)->result, &(*ktask)->result_verbose);

            break;

        case kKryptosDecrypt:

            // INFO(Rafael): The "in" is a HMAC output. If it is ok, the "x" will be extracted
            //               and placed into "in" buffer. The "in" buffer changes its allocation.

            if ((*ktask)->in == NULL || (*ktask)->in_size == 0) {
                (*ktask)->result = kKryptosHMACError;
                (*ktask)->result_verbose = "Null input.";
                return;
            }

            kryptos_hmac_check(ktask, h, h_input_size, h_size);

            break;

        default:

            (*ktask)->result = kKryptosHMACError;
            (*ktask)->result_verbose = "Invalid action.";

            break;
    }
}

static void kryptos_hmac_check(kryptos_task_ctx **ktask,
                               kryptos_hash_func h,
                               kryptos_hash_size_func h_input_size,
                               kryptos_hash_size_func h_size) {
    kryptos_u8_t *hmac = NULL, *x = NULL;
    size_t hmac_size = h_size(), x_size = (*ktask)->in_size - hmac_size, temp_size;

    x = (kryptos_u8_t *) kryptos_newseg(x_size);

    if (x != NULL) {
        if ((*ktask)->in_size <= hmac_size) {
            (*ktask)->result = kKryptosHMACError;
            (*ktask)->result_verbose = "Incomplete input data.";
        } else {
            // WARN(Rafael): We need to copy the following bytes from the original input because x is always freed when the
            //               HMAC extraction succeeds.
            memcpy(x, (*ktask)->in + hmac_size, x_size);
            hmac = kryptos_hmac_gen((*ktask)->key, (*ktask)->key_size,
                                    x, x_size,
                                    h, h_input_size, h_size, &temp_size, &(*ktask)->result, &(*ktask)->result_verbose);
        }
    } else {
        (*ktask)->result = kKryptosHMACError;
        (*ktask)->result_verbose = "No memory to copy x.";
    }

    if (kryptos_last_task_succeed((*ktask))) {
        if (hmac == NULL || memcmp(hmac, (*ktask)->in, hmac_size) != 0) {
            (*ktask)->result = kKryptosHMACError;
            (*ktask)->result_verbose = (hmac != NULL) ? "Corrupted data." : "Null HMAC returned.";
        } else {
            // INFO(Rafael): The input is not corrupted. We will extract the x from the current input.
            //               Making it our new input.
            x = (kryptos_u8_t *) kryptos_newseg(x_size);
            if (x != NULL) {
                memcpy(x, (*ktask)->in + hmac_size, x_size);
                kryptos_freeseg((*ktask)->in, (*ktask)->in_size);
                (*ktask)->in_size = x_size;
                (*ktask)->in = x;
                x = NULL;
            } else {
                (*ktask)->result = kKryptosHMACError;
                (*ktask)->result_verbose = "No memory to extract x.";
            }
        }
    } else if (x != NULL) {
        // INFO(Rafael): If the task is not completed x has a strong probability of leaking.
        kryptos_freeseg(x, x_size);
    }

    if (hmac != NULL) {
        kryptos_freeseg(hmac, hmac_size);
    }

    hmac_size = 0;

    x_size = 0;

    temp_size = 0;
}

static kryptos_u8_t *kryptos_hmac_gen(const kryptos_u8_t *key, const size_t key_size,
                                      kryptos_u8_t *x, const size_t x_size,
                                      kryptos_hash_func h,
                                      kryptos_hash_size_func h_input_size,
                                      kryptos_hash_size_func h_size,
                                      size_t *out_size, kryptos_task_result_t *result, char **result_verbose) {
    //
    //  INFO(Rafael): This function will free x when the HMAC is successfully generated returning back what should be
    //                our new x and so the out_size will be the new x_size.
    //

    kryptos_u8_t *k_xor_ipad = NULL, *k_xor_opad = NULL, *kp = NULL, *kp_end = NULL, *lkey = NULL;
    size_t hash_input_size = 0, hash_size = 0, k_xor_size = 0, lkey_size;
    kryptos_task_ctx iktask, oktask;
    kryptos_u8_t *temp_data = NULL;
    size_t temp_size = 0;
    kryptos_u8_t *out = NULL;

    // INFO(Rafael): Boring necessary check code.

    kryptos_task_init_as_null(&iktask);
    kryptos_task_init_as_null(&oktask);

    if (h == NULL) {
        *result = kKryptosHMACError;
        *result_verbose = "Null hash function.";
        goto kryptos_hmac_gen_epilogue;
    }

    if (h_input_size == NULL) {
        *result = kKryptosHMACError;
        *result_verbose = "Null hash_input_size function.";
        goto kryptos_hmac_gen_epilogue;
    }

    if (h_size == NULL) {
        *result = kKryptosHMACError;
        *result_verbose = "Null hash_size function.";
        goto kryptos_hmac_gen_epilogue;
    }

    hash_input_size = h_input_size();
    hash_size = h_size();

    iktask.mirror_p = &iktask;
    oktask.mirror_p = &oktask;

    if (key_size > hash_input_size) {
        // INFO(Rafael): If the key size is greater than the hash block size, we need hash it
        //               and consider its hash result as the effective HMAC key.
        iktask.in = (kryptos_u8_t *)key;
        iktask.in_size = key_size;

        h(&iktask.mirror_p, 0);

        if (!kryptos_last_task_succeed(&iktask)) {
            *result = kKryptosHMACError;
            *result_verbose = iktask.result_verbose;
            goto kryptos_hmac_gen_epilogue;
        }

        lkey = iktask.out;
        lkey_size = iktask.out_size;
        iktask.out = NULL;
    } else {
        lkey = (kryptos_u8_t *)key;
        lkey_size = key_size;
    }

    k_xor_size = hash_input_size;

    k_xor_ipad = (kryptos_u8_t *) kryptos_newseg(k_xor_size);
    if (k_xor_ipad == NULL) {
        *result = kKryptosHMACError;
        *result_verbose = "No memory when getting k_xor_ipad.";
        goto kryptos_hmac_gen_epilogue;
    }

    k_xor_opad = (kryptos_u8_t *) kryptos_newseg(k_xor_size);
    if (k_xor_opad == NULL) {
        *result = kKryptosHMACError;
        *result_verbose = "No memory when getting k_xor_opad.";
        goto kryptos_hmac_gen_epilogue;
    }

    // INFO(Rafael): Key padding (inner, outter).

    memset(k_xor_ipad, 0, k_xor_size);
    memcpy(k_xor_ipad, lkey, lkey_size);

    memset(k_xor_opad, 0, k_xor_size);
    memcpy(k_xor_opad, lkey, lkey_size);

    // INFO(Rafael): Key xoring (inner, outter).

    kp = k_xor_ipad;
    kp_end = kp + k_xor_size;

    while (kp != kp_end) {
        *kp = *kp ^ KRYPTOS_HMAC_IPAD;
        kp++;
    }

    kp = k_xor_opad;
    kp_end = kp + k_xor_size;

    while (kp != kp_end) {
        *kp = *kp ^ KRYPTOS_HMAC_OPAD;
        kp++;
    }

    // INFO(Rafael): Evaluating h((k+ ^ ipad)||x).

    iktask.in_size = k_xor_size + x_size;
    iktask.in = (kryptos_u8_t *) kryptos_newseg(iktask.in_size);
    if (iktask.in == NULL) {
        *result = kKryptosHMACError;
        *result_verbose = "No memory when getting iktask->in.";
        goto kryptos_hmac_gen_epilogue;
    }

    memcpy(iktask.in, k_xor_ipad, k_xor_size);
    memcpy(iktask.in + k_xor_size, x, x_size);

    h(&iktask.mirror_p, 0);

    if (!kryptos_last_task_succeed(&iktask)) {
        *result = kKryptosHMACError;
        *result_verbose = iktask.result_verbose;
        goto kryptos_hmac_gen_epilogue;
    }

    // INFO(Rafael): Evaluating h((k+ ^ opad)||h((k+ ^ ipad)||x)).

    oktask.in_size = k_xor_size + iktask.out_size;
    oktask.in = (kryptos_u8_t *) kryptos_newseg(oktask.in_size);
    if (oktask.in == NULL) {
        *result = kKryptosHMACError;
        *result_verbose = "No memory when getting oktask->in.";
        goto kryptos_hmac_gen_epilogue;
    }

    memcpy(oktask.in, k_xor_opad, k_xor_size);
    memcpy(oktask.in + k_xor_size, iktask.out, iktask.out_size);

    h(&oktask.mirror_p, 0);

    if (!kryptos_last_task_succeed(&oktask)) {
        *result = kKryptosHMACError;
        *result_verbose = oktask.result_verbose;
        goto kryptos_hmac_gen_epilogue;
    }

    // INFO(Rafael): We got the HMAC(K|x) in oktask.out, let's append it with our current x.

    temp_data = x;
    temp_size = x_size;

    *out_size = temp_size + oktask.out_size;
    out = (kryptos_u8_t *) kryptos_newseg(*out_size);
    if (out == NULL) {
        *result = kKryptosHMACError;
        *result_verbose = "No memory to produce the final HMAC output.";
        out = temp_data;
        *out_size = temp_size;
        temp_data = NULL;
        temp_size = 0;
        goto kryptos_hmac_gen_epilogue;
    }

    memcpy(out, oktask.out, oktask.out_size);
    memcpy(out + oktask.out_size, temp_data, temp_size); // and so we done!

    *result = kKryptosSuccess;
    *result_verbose = NULL;

kryptos_hmac_gen_epilogue:

    // INFO(Rafael): Here goes all necessary housekeeping. Independent if we succeed or not during the HMAC evaluation.

    kp = kp_end = NULL;

    if (k_xor_ipad != NULL) {
        kryptos_freeseg(k_xor_ipad, k_xor_size);
        k_xor_ipad = NULL;
    }

    if (k_xor_opad != NULL) {
        kryptos_freeseg(k_xor_opad, k_xor_size);
        k_xor_opad = NULL;
    }

    if (lkey != key) {
        kryptos_freeseg(lkey, lkey_size);
        lkey = NULL;
        lkey_size = 0;
    }

    kryptos_task_free(&iktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);
    kryptos_task_init_as_null(&iktask);
    kryptos_task_free(&oktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);
    kryptos_task_init_as_null(&oktask);

    if (temp_data != NULL) {
        kryptos_freeseg(temp_data, temp_size);
        temp_size = 0;
    }

    hash_input_size = hash_size = k_xor_size = 0;

    return out;
}

#undef KRYPTOS_HMAC_IPAD

#undef KRYPTOS_HMAC_OPAD
