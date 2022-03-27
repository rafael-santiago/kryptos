/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_hotp.h>
#include <kryptos_memory.h>
#include <kryptos.h>

#define KRYPTOS_HOTP_C_PARAM            0
#define KRYPTOS_HOTP_T_PARAM            1
#define KRYPTOS_HOTP_s_PARAM            2
#define KRYPTOS_HOTP_D_PARAM            3
#define KRYPTOS_HOTP_H_PARAM            4
#define KRYPTOS_HOTP_H_INPUT_SIZE_PARAM 5
#define KRYPTOS_HOTP_H_SIZE_PARAM       6

#define KRYPTOS_HOTP_C_PARAM_SIZE sizeof(kryptos_u64_t)
#define KRYPTOS_HOTP_T_PARAM_SIZE sizeof(size_t)
#define KRYPTOS_HOTP_s_PARAM_SIZE sizeof(size_t)
#define KRYPTOS_HOTP_D_PARAM_SIZE sizeof(size_t)

#define KRYPTOS_HOTP_PARAM_SIZE(param) KRYPTOS_HOTP_ ## param ## _PARAM_SIZE

static void kryptos_do_hotp(kryptos_task_ctx **ktask);

static kryptos_u32_t kryptos_hotp_trunc(const kryptos_u8_t *in, const size_t in_size, const size_t d);

kryptos_task_result_t kryptos_hotp_init(kryptos_task_ctx *ktask,
                                        const kryptos_action_t action,
                                        kryptos_u8_t *shared_secret,
                                        const size_t shared_secret_size,
                                        kryptos_u64_t *moving_factor,
                                        size_t *throttling_param,
                                        size_t *resync_param,
                                        size_t *number_of_digits,
                                        kryptos_hash_func h,
                                        kryptos_hash_size_func h_input_size,
                                        kryptos_hash_size_func h_size) {
    if (ktask == NULL                                     ||
        shared_secret == NULL                             ||
        shared_secret_size == 0                           ||
        moving_factor == NULL                             ||
        number_of_digits == NULL                          ||
        (*number_of_digits == 0 || *number_of_digits > 9) ||
        h == NULL                                         ||
        h_input_size == NULL                              ||
        h_size == NULL                                    ||
        (action != kKryptosGenerateToken && action != kKryptosValidateToken)) {
        return kKryptosInvalidParams;
    }

    if (h_size() < 15) {
        // INFO(Rafael): Truncation function expects a hash of at least 15 bytes.
        //               In normal conditions it should never fail since there is
        //               no real life cryptographic hash with such small digest size.
        //               It would be impossible to deliver a sound crypto hash with so
        //               few bytes. Anyway, adding this foolproof lock here will no hurt.
        return kKryptosInvalidParams;
    }

    if (action == kKryptosValidateToken &&
        (throttling_param == NULL ||
         *throttling_param == 0   ||
         resync_param == NULL)) {
        return kKryptosInvalidParams;
    }

    kryptos_task_init_as_null(ktask);

    ktask->action = action;

    ktask->key = shared_secret;
    ktask->key_size = shared_secret_size;

    ktask->arg[KRYPTOS_HOTP_C_PARAM] = moving_factor;
    ktask->arg[KRYPTOS_HOTP_T_PARAM] = throttling_param;
    ktask->arg[KRYPTOS_HOTP_s_PARAM] = resync_param;
    ktask->arg[KRYPTOS_HOTP_D_PARAM] = number_of_digits;
    ktask->arg[KRYPTOS_HOTP_H_PARAM] = (void *)h;
    ktask->arg[KRYPTOS_HOTP_H_INPUT_SIZE_PARAM] = (void *)h_input_size,
    ktask->arg[KRYPTOS_HOTP_H_SIZE_PARAM] = (void *)h_size;

    return kKryptosSuccess;
}

kryptos_task_result_t kryptos_hotp(kryptos_task_ctx **ktask) {
    size_t s;

    kryptos_do_hotp(ktask);

    if ((*ktask)->result == kKryptosSuccess) {
        *(kryptos_u64_t *)(*ktask)->arg[KRYPTOS_HOTP_C_PARAM] += 1;
    } else if ((*ktask)->result == kKryptosInvalidToken  &&
               (*ktask)->action == kKryptosValidateToken &&
               *(size_t *)(*ktask)->arg[KRYPTOS_HOTP_T_PARAM] > 0) {
        for (s = 0; s < *(size_t *)(*ktask)->arg[KRYPTOS_HOTP_s_PARAM] && !kryptos_last_task_succeed(*ktask); s++) {
            *(kryptos_u64_t *)(*ktask)->arg[KRYPTOS_HOTP_C_PARAM] += 1;
            kryptos_do_hotp(ktask);
        }
        if (kryptos_last_task_succeed(*ktask)) {
            *(kryptos_u64_t *)(*ktask)->arg[KRYPTOS_HOTP_C_PARAM] += 1;
        }
    }

    return (*ktask)->result;
}

static void kryptos_do_hotp(kryptos_task_ctx **ktask) {
    kryptos_task_ctx hmac_t, *ktask_hmac = &hmac_t;
    kryptos_u32_t token = 0;
    kryptos_u64_t c = 0;

    kryptos_task_init_as_null(ktask_hmac);

    if ((*ktask)->action == kKryptosValidateToken && *(size_t *)(*ktask)->arg[KRYPTOS_HOTP_T_PARAM] == 0) {
        (*ktask)->result = kKryptosInvalidToken;
        (*ktask)->result_verbose = "Throttle parameter has exceeded its limit. It seems to be a brute force attack. "
                                   "If you want to go ahead and try it more you must call kryptos_hotp_init() again.";
        goto kryptos_do_hotp_epilogue;
    }

    ktask_hmac->action = kKryptosEncrypt;
    ktask_hmac->out_size = KRYPTOS_HOTP_PARAM_SIZE(C);
    ktask_hmac->out = (kryptos_u8_t *)kryptos_newseg(KRYPTOS_HOTP_PARAM_SIZE(C));
    if (ktask_hmac->out == NULL) {
        (*ktask)->result_verbose = "No memory to allocate moving factor.";
        (*ktask)->result = kKryptosProcessError;
        goto kryptos_do_hotp_epilogue;
    }

    c = *(kryptos_u64_t *)(*ktask)->arg[KRYPTOS_HOTP_C_PARAM];
    ktask_hmac->out[0] = ((c >> 56) & 0xFF);
    ktask_hmac->out[1] = ((c >> 48) & 0xFF);
    ktask_hmac->out[2] = ((c >> 40) & 0xFF);
    ktask_hmac->out[3] = ((c >> 32) & 0xFF);
    ktask_hmac->out[4] = ((c >> 24) & 0xFF);
    ktask_hmac->out[5] = ((c >> 16) & 0xFF);
    ktask_hmac->out[6] = ((c >>  8) & 0xFF);
    ktask_hmac->out[7] =   c        & 0xFF;
    c = 0;

    ktask_hmac->key = (*ktask)->key;
    ktask_hmac->key_size = (*ktask)->key_size;

    kryptos_hmac(&ktask_hmac,
                 (kryptos_hash_func)(*ktask)->arg[KRYPTOS_HOTP_H_PARAM],
                 (kryptos_hash_size_func)(*ktask)->arg[KRYPTOS_HOTP_H_INPUT_SIZE_PARAM],
                 (kryptos_hash_size_func)(*ktask)->arg[KRYPTOS_HOTP_H_SIZE_PARAM]);

    if (!kryptos_last_task_succeed(ktask_hmac)) {
        (*ktask)->result_verbose = ktask_hmac->result_verbose;
        (*ktask)->result = ktask_hmac->result;
        goto kryptos_do_hotp_epilogue;
    }

    token = kryptos_hotp_trunc(ktask_hmac->out,
                               ((kryptos_hash_size_func)(*ktask)->arg[KRYPTOS_HOTP_H_SIZE_PARAM])(),
                               *(size_t *)(*ktask)->arg[KRYPTOS_HOTP_D_PARAM]);

    (*ktask)->result = kKryptosSuccess;

    switch ((*ktask)->action) {
        case kKryptosGenerateToken:
            (*ktask)->out = (kryptos_u8_t *)kryptos_newseg(sizeof(token));
            if ((*ktask)->out != NULL) {
                (*ktask)->out_size = sizeof(token);
                memcpy((*ktask)->out, &token, sizeof(token));
                (*ktask)->result_verbose = NULL;
            } else {
                (*ktask)->result = kKryptosProcessError;
                (*ktask)->result_verbose = "No memory to copy token data.";
            }
            break;

        case kKryptosValidateToken:
            if ((*ktask)->in_size == sizeof(token) && memcmp(&token, (*ktask)->in, sizeof(token)) == 0) {
                (*ktask)->result_verbose = NULL;
            } else {
                (*ktask)->result = kKryptosInvalidToken;
                (*ktask)->result_verbose = "The passed token is invalid.";
                if (*(size_t *)(*ktask)->arg[KRYPTOS_HOTP_T_PARAM] > 0) {
                    *(size_t *)(*ktask)->arg[KRYPTOS_HOTP_T_PARAM] -= 1;
                }
            }
            break;

        default:
            break;
    }

kryptos_do_hotp_epilogue:

    kryptos_task_free(ktask_hmac, KRYPTOS_TASK_OUT);

    kryptos_task_init_as_null(ktask_hmac);
}

static kryptos_u32_t kryptos_hotp_trunc(const kryptos_u8_t *in, const size_t in_size, const size_t d) {
    size_t s_bits;
    kryptos_u32_t s_num;
    static kryptos_u32_t ten2d_1_lt[] = {
        1,
        10,
        100,
        1000,
        10000,
        100000,
        1000000,
        10000000,
        100000000,
        1000000000,
    };
    if (in == NULL || in_size == 0) {
        return 0;
    }

    s_bits = in[in_size - 1] & 0xF;
    s_num = (((kryptos_u32_t)(in[s_bits] & 0x7F) << 24) |
             ((kryptos_u32_t)(in[s_bits + 1])    << 16) |
             ((kryptos_u32_t)(in[s_bits + 2])    <<  8) | (kryptos_u32_t)(in[s_bits + 3])) % ten2d_1_lt[d];
    s_bits = 0;
    return s_num;
}

#undef KRYPTOS_HOTP_C_PARAM
#undef KRYPTOS_HOTP_T_PARAM
#undef KRYPTOS_HOTP_s_PARAM
#undef KRYPTOS_HOTP_D_PARAM
#undef KRYPTOS_HOTP_H_PARAM
#undef KRYPTOS_HOTP_H_INPUT_SIZE_PARAM
#undef KRYPTOS_HOTP_H_SIZE_PARAM

#undef KRYPTOS_HOTP_C_PARAM_SIZE
#undef KRYPTOS_HOTP_T_PARAM_SIZE
#undef KRYPTOS_HOTP_s_PARAM_SIZE
#undef KRYPTOS_HOTP_D_PARAM_SIZE

#undef KRYPTOS_HOTP_PARAM_SIZE
