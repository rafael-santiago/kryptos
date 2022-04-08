/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_TOTP_H
#define KRYPTOS_KRYPTOS_TOTP_H 1

#include <kryptos_types.h>

#ifdef __cplusplus
extern "C" {
#endif

kryptos_task_result_t kryptos_totp_init(kryptos_task_ctx *ktask,
                                        const kryptos_action_t action,
                                        kryptos_u8_t *shared_secret,
                                        const size_t shared_secret_size,
                                        kryptos_u64_t *initial_counter_time,
                                        kryptos_u64_t *time_step,
                                        size_t *number_of_digits,
                                        kryptos_hash_func h,
                                        kryptos_hash_size_func h_input_size,
                                        kryptos_hash_size_func h_size);

kryptos_task_result_t kryptos_totp(kryptos_task_ctx **ktask);

#ifdef __cplusplus
}
#endif

#endif
