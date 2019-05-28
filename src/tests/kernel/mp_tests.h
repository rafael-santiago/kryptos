/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_TESTS_KERNEL_MP_TESTS_H
#define KRYPTOS_KRYPTOS_TESTS_KERNEL_MP_TESTS_H 1

#include <tests/cutest/src/kutest.h>

KUTE_DECLARE_TEST_CASE(kryptos_mp_new_value_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_hex_value_as_mp_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_value_as_hex_tests);

KUTE_DECLARE_TEST_CASE(kryptos_assign_mp_value_tests);

KUTE_DECLARE_TEST_CASE(kryptos_assign_hex_value_to_mp_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_eq_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_ne_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_get_gt_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_gt_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_ge_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_lt_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_le_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_is_neg_tests);

//KUTE_DECLARE_TEST_CASE(kryptos_mp_bitcount_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_add_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_sub_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_mul_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_not_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_signed_add_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_signed_sub_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_signed_mul_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_lsh_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_rsh_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_signed_rsh_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_div_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_div_2p_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_pow_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_is_odd_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_is_even_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_me_mod_n_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_fermat_test_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_miller_rabin_test_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_is_prime_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_gen_prime_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_montgomery_reduction_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_gcd_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_modinv_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_bitcount_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_mul_digit_tests);

KUTE_DECLARE_TEST_CASE(kryptos_raw_buffer_as_mp_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_as_task_out_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_mod_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_add_s_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_sub_s_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_mul_s_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_bits_total_in_base2_tests);

KUTE_DECLARE_TEST_CASE(kryptos_mp_bit_n_tests);

#endif
