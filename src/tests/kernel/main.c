/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <tests/cutest/src/kutest.h>
#if defined(__FreeBSD__) || defined(__NetBSD__)
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
#include <poly1305_mp_tests.h>
#include <poly1305_tests.h>
#include <siphash_tests.h>
#include <kdf_tests.h>
#include <otp_tests.h>
#include <mp_tests.h>
#include <symmetric_ciphers_tests.h>
#include <asymmetric_ciphers_tests.h>
#include <bad_buf_tests.h>
#include <ecc_tests.h>

KUTE_DECLARE_TEST_CASE(ktest_monkey);

KUTE_TEST_CASE(ktest_monkey)
    KUTE_RUN_TEST(kryptos_memset_tests);
    KUTE_RUN_TEST(kryptos_padding_tests);
    KUTE_RUN_TEST(kryptos_unbiased_rand_mod_u8_tests);
    KUTE_RUN_TEST(kryptos_unbiased_rand_mod_u16_tests);
    KUTE_RUN_TEST(kryptos_unbiased_rand_mod_u32_tests);
    KUTE_RUN_TEST(kryptos_unbiased_rand_mod_u64_tests);
    KUTE_RUN_TEST(kryptos_sys_get_random_block_tests);
    KUTE_RUN_TEST(kryptos_get_random_block_tests);
    KUTE_RUN_TEST(kryptos_block_parser_tests);
    KUTE_RUN_TEST(kryptos_endianness_utils_tests);
    KUTE_RUN_TEST(kryptos_apply_iv_tests);
    KUTE_RUN_TEST(kryptos_iv_data_flush_tests);
    KUTE_RUN_TEST(kryptos_gcm_gf_mul_tests);
    KUTE_RUN_TEST(kryptos_gcm_tests);
    KUTE_RUN_TEST(kryptos_task_check_tests);
    KUTE_RUN_TEST(kryptos_hex_tests);
    KUTE_RUN_TEST(kryptos_u8_ptr_to_hex_tests);
    KUTE_RUN_TEST(kryptos_hash_common_tests);

    KUTE_RUN_TEST(kryptos_dsl_tests);

    KUTE_RUN_TEST(kryptos_base64_tests);
    KUTE_RUN_TEST(kryptos_base64_dsl_tests);
    KUTE_RUN_TEST(kryptos_base32_tests);
    KUTE_RUN_TEST(kryptos_base32_dsl_tests);
    KUTE_RUN_TEST(kryptos_base16_tests);
    KUTE_RUN_TEST(kryptos_base16_dsl_tests);
    KUTE_RUN_TEST(kryptos_uuencode_tests);
    KUTE_RUN_TEST(kryptos_uuencode_dsl_tests);
    KUTE_RUN_TEST(kryptos_huffman_tests);
    KUTE_RUN_TEST(kryptos_pem_get_data_tests);
    KUTE_RUN_TEST(kryptos_pem_put_data_tests);

    // INFO(Rafael): Operation modes (complementary tests).

    KUTE_RUN_TEST(kryptos_ctr_mode_sequencing_tests);

    // INFO(Rafael): We only test the GCM mode after ensuring that everything is fine with CTR.

    KUTE_RUN_TEST(kryptos_des_gcm_tests);
    KUTE_RUN_TEST(kryptos_idea_gcm_tests);
    KUTE_RUN_TEST(kryptos_blowfish_gcm_tests);
    KUTE_RUN_TEST(kryptos_feal_gcm_tests);
    KUTE_RUN_TEST(kryptos_rc2_gcm_tests);
    KUTE_RUN_TEST(kryptos_camellia128_gcm_tests);
    KUTE_RUN_TEST(kryptos_camellia192_gcm_tests);
    KUTE_RUN_TEST(kryptos_camellia256_gcm_tests);
    KUTE_RUN_TEST(kryptos_cast5_gcm_tests);
    KUTE_RUN_TEST(kryptos_saferk64_gcm_tests);
    KUTE_RUN_TEST(kryptos_aes128_gcm_tests);
    KUTE_RUN_TEST(kryptos_aes192_gcm_tests);
    KUTE_RUN_TEST(kryptos_aes256_gcm_tests);
    KUTE_RUN_TEST(kryptos_serpent_gcm_tests);
    KUTE_RUN_TEST(kryptos_triple_des_gcm_tests);
    KUTE_RUN_TEST(kryptos_triple_des_ede_gcm_tests);
    KUTE_RUN_TEST(kryptos_tea_gcm_tests);
    KUTE_RUN_TEST(kryptos_xtea_gcm_tests);
    KUTE_RUN_TEST(kryptos_misty1_gcm_tests);
    KUTE_RUN_TEST(kryptos_rc5_gcm_tests);
    KUTE_RUN_TEST(kryptos_rc6_128_gcm_tests);
    KUTE_RUN_TEST(kryptos_rc6_192_gcm_tests);
    KUTE_RUN_TEST(kryptos_rc6_256_gcm_tests);
    KUTE_RUN_TEST(kryptos_mars128_gcm_tests);
    KUTE_RUN_TEST(kryptos_mars192_gcm_tests);
    KUTE_RUN_TEST(kryptos_mars256_gcm_tests);
    KUTE_RUN_TEST(kryptos_present80_gcm_tests);
    KUTE_RUN_TEST(kryptos_present128_gcm_tests);
    KUTE_RUN_TEST(kryptos_shacal1_gcm_tests);
    KUTE_RUN_TEST(kryptos_shacal2_gcm_tests);
    KUTE_RUN_TEST(kryptos_noekeon_gcm_tests);
    KUTE_RUN_TEST(kryptos_noekeon_d_gcm_tests);
    KUTE_RUN_TEST(kryptos_gost_ds_gcm_tests);
    KUTE_RUN_TEST(kryptos_gost_gcm_tests);
    KUTE_RUN_TEST(kryptos_twofish128_gcm_tests);
    KUTE_RUN_TEST(kryptos_twofish192_gcm_tests);
    KUTE_RUN_TEST(kryptos_twofish256_gcm_tests);

    KUTE_RUN_TEST(kryptos_des_weak_keys_detection_tests);

    KUTE_RUN_TEST(kryptos_bcrypt_tests);
    KUTE_RUN_TEST(kryptos_bcrypt_verify_tests);

    KUTE_RUN_TEST(kryptos_bad_decryption_tests);
    //KUTE_RUN_TEST(kryptos_bad_hmac_tests);

    KUTE_RUN_TEST(kryptos_hash_tests);
    KUTE_RUN_TEST(kryptos_blake2sN_tests);
    KUTE_RUN_TEST(kryptos_blake2bN_tests);

    KUTE_RUN_TEST(kryptos_djb2_tests);

    KUTE_RUN_TEST(kryptos_hmac_basic_tests);
    KUTE_RUN_TEST(kryptos_hmac_tests);

    // INFO(Rafael): Poly1305 suff.

    KUTE_RUN_TEST(kryptos_poly1305_le_bytes_to_num_tests);
    KUTE_RUN_TEST(kryptos_poly1305_le_num_tests);
    KUTE_RUN_TEST(kryptos_poly1305_ld_raw_bytes_tests);
    KUTE_RUN_TEST(kryptos_poly1305_eq_tests);
    KUTE_RUN_TEST(kryptos_poly1305_get_gt_tests);
    KUTE_RUN_TEST(kryptos_poly1305_ne_tests);
    KUTE_RUN_TEST(kryptos_poly1305_gt_tests);
    KUTE_RUN_TEST(kryptos_poly1305_lt_tests);
    KUTE_RUN_TEST(kryptos_poly1305_ge_tests);
    KUTE_RUN_TEST(kryptos_poly1305_not_tests);
    KUTE_RUN_TEST(kryptos_poly1305_lsh_tests);
    KUTE_RUN_TEST(kryptos_poly1305_rsh_tests);
    KUTE_RUN_TEST(kryptos_poly1305_add_tests);
    // TIP(Rafael): Kryptos multi-precision stuff uses 2's complement to express negative numbers
    //              so it is important to ensure that it is working before testing subtraction.
    KUTE_RUN_TEST(kryptos_poly1305_inv_cmplt_tests);
    KUTE_RUN_TEST(kryptos_poly1305_sub_tests);
    KUTE_RUN_TEST(kryptos_poly1305_mul_tests);
    KUTE_RUN_TEST(kryptos_poly1305_mul_digit_tests);
    KUTE_RUN_TEST(kryptos_poly1305_div_tests);

    KUTE_RUN_TEST(kryptos_poly1305_basic_tests);

    KUTE_RUN_TEST(kryptos_poly1305_tests);

    KUTE_RUN_TEST(kryptos_siphash_size_tests);
    KUTE_RUN_TEST(kryptos_siphash_basic_tests);

    KUTE_RUN_TEST(kryptos_siphash_sum_tests);

    // TODO(Rafael): Once implemented enable it.
    KUTE_RUN_TEST(kryptos_siphash_tests);

    KUTE_RUN_TEST(kryptos_do_hkdf_tests);
    KUTE_RUN_TEST(kryptos_hkdf_macro_tests);
    KUTE_RUN_TEST(kryptos_do_pbkdf2_tests);
    KUTE_RUN_TEST(kryptos_pbkdf2_macro_tests);
#if !defined(__NetBSD__)
    // WARN(Rafael): For some reason argon2 is causing kernel panics in NetBSD however it seems fine in Linux and FreeBSD.
    //               By now I am deactivating it on NetBSD. I need to investigate it better.
    KUTE_RUN_TEST(kryptos_do_argon2_tests);
    KUTE_RUN_TEST(kryptos_argon2_macro_tests);
    KUTE_RUN_TEST(kryptos_do_argon2_bounds_tests);
    KUTE_RUN_TEST(kryptos_argon2_macro_bounds_tests);
#endif

    // INFO(Rafael): OTP stuff.

    KUTE_RUN_TEST(kryptos_hotp_tests);
    KUTE_RUN_TEST(kryptos_hotp_init_bad_params_tests);
    KUTE_RUN_TEST(kryptos_hotp_sequencing_tests);
    KUTE_RUN_TEST(kryptos_hotp_client_server_syncd_interaction_tests);
    KUTE_RUN_TEST(kryptos_hotp_client_server_unsyncd_interaction_tests);

    KUTE_RUN_TEST(kryptos_totp_init_bad_params_tests);
    KUTE_RUN_TEST(kryptos_totp_client_server_syncd_interaction_tests);

    KUTE_RUN_TEST(kryptos_otp_hash_macro_tests);
    KUTE_RUN_TEST(kryptos_otp_macro_tests);

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
    KUTE_RUN_TEST(kryptos_mp_add_tests);
    KUTE_RUN_TEST(kryptos_mp_sub_tests);
    KUTE_RUN_TEST(kryptos_mp_mul_tests);
    KUTE_RUN_TEST(kryptos_mp_mul_digit_tests);
    KUTE_RUN_TEST(kryptos_mp_not_tests);
    KUTE_RUN_TEST(kryptos_mp_inv_tests);
    KUTE_RUN_TEST(kryptos_mp_lsh_tests);
    KUTE_RUN_TEST(kryptos_mp_rsh_tests);
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
    KUTE_RUN_TEST(kryptos_mp_modinv_rs_tests);
    KUTE_RUN_TEST(kryptos_mp_modinv_tests);
    KUTE_RUN_TEST(kryptos_raw_buffer_as_mp_tests);
    KUTE_RUN_TEST(kryptos_mp_as_task_out_tests);
    KUTE_RUN_TEST(kryptos_mp_add_s_tests);
    KUTE_RUN_TEST(kryptos_mp_sub_s_tests);
    KUTE_RUN_TEST(kryptos_mp_mul_s_tests);
    KUTE_RUN_TEST(kryptos_mp_mod_tests);
    KUTE_RUN_TEST(kryptos_mp_get_bitmap_tests);
    // INFO(Rafael): Barrett reduction depends on kryptos_mp_get_bitmap(), so it needs to run after that.
    KUTE_RUN_TEST(kryptos_mp_barrett_reduction_tests);

    KUTE_RUN_TEST(kryptos_pem_get_mp_data_tests);

    KUTE_RUN_TEST(kryptos_ec_set_point_tests);
    KUTE_RUN_TEST(kryptos_ec_set_curve_tests);
    KUTE_RUN_TEST(kryptos_ec_add_tests);
    KUTE_RUN_TEST(kryptos_ec_dbl_tests);
    KUTE_RUN_TEST(kryptos_ec_mul_tests);

    KUTE_RUN_TEST(kryptos_verify_dl_params_tests);
    KUTE_RUN_TEST(kryptos_generate_dl_params_tests);

    KUTE_RUN_TEST(kryptos_dh_mk_domain_params_tests);
    KUTE_RUN_TEST(kryptos_dh_verify_domain_params_tests);
    KUTE_RUN_TEST(kryptos_dh_get_modp_from_params_buf_tests);
    KUTE_RUN_TEST(kryptos_dh_get_modp_tests);
    KUTE_RUN_TEST(kryptos_dh_get_random_s_tests);
    KUTE_RUN_TEST(kryptos_dh_eval_t_tests);

#ifndef SKIP_DH_XCHG_TESTS
    KUTE_RUN_TEST(kryptos_dh_standard_key_exchange_bare_bone_tests);
    KUTE_RUN_TEST(kryptos_dh_process_stdxchg_tests);
    KUTE_RUN_TEST(kryptos_dh_mk_key_pair_tests);
    KUTE_RUN_TEST(kryptos_dh_process_modxchg_tests);
#else
# if defined(__FreeBSD__) || defined(__NetBSD__)
    uprintf("WARN: The Diffie-Hellman-Merkle exchange tests were skipped.\n");
# elif defined(__linux__)
    printk(KERN_ERR "WARN: The Diffie-Hellman-Merkle exchange tests were skipped.\n");
# elif defined(_WIN32)
    KdPrint(("WARN: The Diffie-Hellman-Merkle exchange tests were skipped.\n"));
# endif
#endif

    KUTE_RUN_TEST(kryptos_rsa_mk_key_pair_tests);
    KUTE_RUN_TEST(kryptos_rsa_cipher_tests);
    KUTE_RUN_TEST(kryptos_rsa_cipher_c99_tests);
    KUTE_RUN_TEST(kryptos_padding_mgf_tests);
    KUTE_RUN_TEST(kryptos_oaep_padding_tests);

#ifndef SKIP_RSA_OAEP_TESTS
    KUTE_RUN_TEST(kryptos_rsa_oaep_cipher_tests);
    KUTE_RUN_TEST(kryptos_rsa_oaep_cipher_c99_tests);
#else
# if defined(__FreeBSD__) || defined(__NetBSD__)
    uprintf("WARN: The RSA-OAEP tests were skipped.\n");
# elif defined(__linux__)
    printk(KERN_ERR "WARN: The RSA-OAEP tests were skipped.\n");
# elif defined(_WIN32)
    KdPrint(("WARN: The RSA-OAEP tests were skipped.\n"));
# endif
#endif

    KUTE_RUN_TEST(kryptos_elgamal_mk_key_pair_tests);
    KUTE_RUN_TEST(kryptos_elgamal_verify_public_key_tests);
    KUTE_RUN_TEST(kryptos_elgamal_cipher_tests);
    KUTE_RUN_TEST(kryptos_elgamal_cipher_c99_tests);

#ifndef SKIP_ELGAMAL_OAEP_TESTS
    KUTE_RUN_TEST(kryptos_elgamal_oaep_cipher_tests);
    KUTE_RUN_TEST(kryptos_elgamal_oaep_cipher_c99_tests);
#else
# if defined(__FreeBSD__) || defined(__NetBSD__)
    uprintf("WARN: The Elgamal-OAEP tests were skipped.\n");
# elif defined(__linux__)
    printk(KERN_ERR "WARN: The Elgamal-OAEP tests were skipped.\n");
# elif defined(_WIN32)
    KdPrint(("WARN: The Elgamal-OAEP tests were skipped.\n"));
# endif
#endif

    KUTE_RUN_TEST(kryptos_pss_encoding_tests);

#ifndef SKIP_RSA_SIGNATURE_TESTS
    KUTE_RUN_TEST(kryptos_rsa_digital_signature_basic_scheme_tests);
    KUTE_RUN_TEST(kryptos_rsa_digital_signature_basic_scheme_c99_tests);
    KUTE_RUN_TEST(kryptos_rsa_emsa_pss_digital_signature_scheme_tests);
    KUTE_RUN_TEST(kryptos_rsa_emsa_pss_digital_signature_scheme_c99_tests);
#else
# if defined(__FreeBSD__) || defined(__NetBSD__)
    uprintf("WARN: The RSA signature tests were skipped.\n");
# elif defined(__linux__)
    printk(KERN_ERR "WARN: The RSA signature tests were skipped.\n");
# elif defined(_WIN32)
    KdPrint(("WARN: The RSA signature tests were skipped.\n"));
# endif
#endif

#ifndef SKIP_DSA_SIGNATURE_TESTS
    KUTE_RUN_TEST(kryptos_dsa_mk_key_pair_tests);
    KUTE_RUN_TEST(kryptos_dsa_digital_signature_scheme_tests);
    KUTE_RUN_TEST(kryptos_dsa_digital_signature_scheme_c99_tests);
#else
# if defined(__FreeBSD__) || defined(__NetBSD__)
    uprintf("WARN: The DSA signature tests were skipped.\n");
# elif defined(__linux__)
    printk(KERN_ERR "WARN: The DSA signature tests were skipped.\n");
# elif defined(_WIN32)
    KdPrint(("WARN: The DSA signature tests were skipped.\n"));
# endif
#endif

    KUTE_RUN_TEST(kryptos_new_standard_curve_tests);
    KUTE_RUN_TEST(kryptos_ecdh_get_curve_from_params_buf_tests);
    KUTE_RUN_TEST(kryptos_ecdh_get_random_k_tests);
    KUTE_RUN_TEST(kryptos_ecdh_process_xchg_tests);
    KUTE_RUN_TEST(kryptos_ecdh_process_xchg_with_stdcurves_tests);

#ifndef SKIP_ECDSA_SIGNATURE_TESTS
    KUTE_RUN_TEST(kryptos_ecdsa_mk_key_pair_tests);
    KUTE_RUN_TEST(kryptos_ecdsa_digital_signature_scheme_tests);
    KUTE_RUN_TEST(kryptos_ecdsa_digital_signature_scheme_c99_tests);
#else
# if defined(__FreeBSD__) || defined(__NetBSD__)
    uprintf("WARN: The ECDSA signature tests were skipped.\n");
# elif defined(__linux__)
    printk(KERN_ERR "WARN: The ECDSA signature tests were skipped.\n");
# elif defined(_WIN32)
    KdPrint(("WARN: The ECDSA signature tests were skipped.\n"));
# endif
#endif

    //KUTE_RUN_TEST(kryptos_new_standard_curve_tests);
KUTE_TEST_CASE_END

KUTE_MAIN(ktest_monkey);
