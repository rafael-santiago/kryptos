/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_TESTS_KERNEL_OTP_TESTS_H
#define KRYPTOS_KRYPTOS_TESTS_KERNEL_OTP_TESTS_H 1

#include <tests/cutest/src/kutest.h>

KUTE_DECLARE_TEST_CASE(kryptos_hotp_tests);

KUTE_DECLARE_TEST_CASE(kryptos_hotp_sequencing_tests);

KUTE_DECLARE_TEST_CASE(kryptos_hotp_client_server_syncd_interaction_tests);

KUTE_DECLARE_TEST_CASE(kryptos_hotp_client_server_unsyncd_interaction_tests);

KUTE_DECLARE_TEST_CASE(kryptos_hotp_init_bad_params_tests);

KUTE_DECLARE_TEST_CASE(kryptos_otp_hash_macro_tests);

KUTE_DECLARE_TEST_CASE(kryptos_otp_macro_tests);

KUTE_DECLARE_TEST_CASE(kryptos_totp_init_bad_params_tests);

KUTE_DECLARE_TEST_CASE(kryptos_totp_client_server_syncd_interaction_tests);

#endif
