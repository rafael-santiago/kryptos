/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kutest.h>
#if defined(__FreeBSD__)
# include <sys/cdefs.h>
# include <sys/malloc.h>
# include <sys/module.h>
# include <sys/param.h>
# include <sys/kernel.h>
# include <sys/systm.h>
#elif defined(__linux__)
# include <linux/init.h>
# include <linux/module.h>
#endif

#include <generic_tests.h>
#include <dsl_tests.h>
#include <encoding_tests.h>
#include <hash_tests.h>
#include <mp_tests.h>
#include <asymmetric_ciphers_tests.h>

KUTE_DECLARE_TEST_CASE(ktest_monkey);

KUTE_TEST_CASE(ktest_monkey)
    KUTE_RUN_TEST(kryptos_padding_tests);
    KUTE_RUN_TEST(kryptos_get_random_block_tests);
    KUTE_RUN_TEST(kryptos_block_parser_tests);
    KUTE_RUN_TEST(kryptos_endianess_utils_tests);
    KUTE_RUN_TEST(kryptos_apply_iv_tests);
    KUTE_RUN_TEST(kryptos_iv_data_flush_tests);
    KUTE_RUN_TEST(kryptos_task_check_tests);
    KUTE_RUN_TEST(kryptos_hex_tests);
    KUTE_RUN_TEST(kryptos_hash_common_tests);

    KUTE_RUN_TEST(kryptos_dsl_tests);

    KUTE_RUN_TEST(kryptos_base64_tests);
    KUTE_RUN_TEST(kryptos_uuencode_tests);
    KUTE_RUN_TEST(kryptos_huffman_tests);
    KUTE_RUN_TEST(kryptos_pem_get_data_tests);
    KUTE_RUN_TEST(kryptos_pem_put_data_tests);

    KUTE_RUN_TEST(kryptos_hash_tests);
    KUTE_RUN_TEST(kryptos_hmac_tests);

    KUTE_RUN_TEST(kryptos_mp_new_value_tests);
    KUTE_RUN_TEST(kryptos_mp_hex_value_as_mp_tests);
    KUTE_RUN_TEST(kryptos_mp_value_as_hex_tests);
    KUTE_RUN_TEST(kryptos_assign_mp_value_tests);
    KUTE_RUN_TEST(kryptos_assign_hex_value_to_mp_tests);
    KUTE_RUN_TEST(kryptos_mp_eq_tests);
    KUTE_RUN_TEST(kryptos_mp_ne_tests);
    KUTE_RUN_TEST(kryptos_mp_get_gt_tests);
    KUTE_RUN_TEST(kryptos_mp_gt_tests);
    KUTE_RUN_TEST(kryptos_mp_ge_tests);
    KUTE_RUN_TEST(kryptos_mp_lt_tests);
    KUTE_RUN_TEST(kryptos_mp_le_tests);
    KUTE_RUN_TEST(kryptos_mp_is_neg_tests);
    KUTE_RUN_TEST(kryptos_mp_bitcount_tests);
    KUTE_RUN_TEST(kryptos_mp_add_tests);
    KUTE_RUN_TEST(kryptos_mp_sub_tests);
    KUTE_RUN_TEST(kryptos_mp_mul_tests);
    KUTE_RUN_TEST(kryptos_mp_mul_digit_tests);
    KUTE_RUN_TEST(kryptos_mp_not_tests);
    KUTE_RUN_TEST(kryptos_mp_inv_signal_tests);
    KUTE_RUN_TEST(kryptos_mp_lsh_tests);
    KUTE_RUN_TEST(kryptos_mp_rsh_tests);
    KUTE_RUN_TEST(kryptos_mp_signed_rsh_tests);
    KUTE_RUN_TEST(kryptos_mp_div_tests);
    KUTE_RUN_TEST(kryptos_mp_div_2p_tests);
    KUTE_RUN_TEST(kryptos_mp_pow_tests);
    KUTE_RUN_TEST(kryptos_mp_is_odd_tests);
    KUTE_RUN_TEST(kryptos_mp_is_even_tests);
    KUTE_RUN_TEST(kryptos_mp_me_mod_n_tests);
    KUTE_RUN_TEST(kryptos_mp_fermat_test_tests);
    KUTE_RUN_TEST(kryptos_mp_miller_rabin_test_tests);
    KUTE_RUN_TEST(kryptos_mp_is_prime_tests);
    KUTE_RUN_TEST(kryptos_mp_gen_prime_tests);
    KUTE_RUN_TEST(kryptos_mp_montgomery_reduction_tests);
    KUTE_RUN_TEST(kryptos_mp_gcd_tests);
    KUTE_RUN_TEST(kryptos_mp_modinv_tests);
    KUTE_RUN_TEST(kryptos_raw_buffer_as_mp_tests);
    KUTE_RUN_TEST(kryptos_mp_as_task_out_tests);

    KUTE_RUN_TEST(kryptos_pem_get_mp_data_tests);

    KUTE_RUN_TEST(kryptos_verify_dl_params_tests);
    KUTE_RUN_TEST(kryptos_generate_dl_params_tests);

    KUTE_RUN_TEST(kryptos_dh_mk_domain_params_tests);
    KUTE_RUN_TEST(kryptos_dh_verify_domain_params_tests);
    KUTE_RUN_TEST(kryptos_dh_get_modp_from_params_buf_tests);
    KUTE_RUN_TEST(kryptos_dh_get_modp_tests);
    KUTE_RUN_TEST(kryptos_dh_get_random_s_tests);
    KUTE_RUN_TEST(kryptos_dh_eval_t_tests);
    KUTE_RUN_TEST(kryptos_dh_standard_key_exchange_bare_bone_tests);
    KUTE_RUN_TEST(kryptos_dh_process_stdxchg_tests);
    KUTE_RUN_TEST(kryptos_dh_mk_key_pair_tests);
    KUTE_RUN_TEST(kryptos_dh_process_modxchg_tests);

    KUTE_RUN_TEST(kryptos_rsa_mk_key_pair_tests);
    KUTE_RUN_TEST(kryptos_rsa_cipher_tests);
    KUTE_RUN_TEST(kryptos_rsa_cipher_c99_tests);
    KUTE_RUN_TEST(kryptos_padding_mgf_tests);
    KUTE_RUN_TEST(kryptos_oaep_padding_tests);

    KUTE_RUN_TEST(kryptos_rsa_oaep_cipher_tests);
    KUTE_RUN_TEST(kryptos_rsa_oaep_cipher_c99_tests);

    KUTE_RUN_TEST(kryptos_elgamal_mk_key_pair_tests);
    KUTE_RUN_TEST(kryptos_elgamal_verify_public_key_tests);
    KUTE_RUN_TEST(kryptos_elgamal_cipher_tests);
    KUTE_RUN_TEST(kryptos_elgamal_cipher_c99_tests);

    KUTE_RUN_TEST(kryptos_elgamal_oaep_cipher_tests);
    KUTE_RUN_TEST(kryptos_elgamal_oaep_cipher_c99_tests);

KUTE_TEST_CASE_END

KUTE_MAIN(ktest_monkey);
