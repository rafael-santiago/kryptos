/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_HASH_TESTS_H
#define KRYPTOS_TESTS_HASH_TESTS_H 1

#include <cutest.h>

CUTE_DECLARE_TEST_CASE(kryptos_sha1_tests);

CUTE_DECLARE_TEST_CASE(kryptos_sha1_hash_macro_tests);

CUTE_DECLARE_TEST_CASE(kryptos_sha224_tests);

CUTE_DECLARE_TEST_CASE(kryptos_sha224_hash_macro_tests);

CUTE_DECLARE_TEST_CASE(kryptos_sha256_tests);

CUTE_DECLARE_TEST_CASE(kryptos_sha256_hash_macro_tests);

CUTE_DECLARE_TEST_CASE(kryptos_sha384_tests);

CUTE_DECLARE_TEST_CASE(kryptos_sha384_hash_macro_tests);

CUTE_DECLARE_TEST_CASE(kryptos_sha512_tests);

CUTE_DECLARE_TEST_CASE(kryptos_sha512_hash_macro_tests);

CUTE_DECLARE_TEST_CASE(kryptos_md4_tests);

CUTE_DECLARE_TEST_CASE(kryptos_md4_hash_macro_tests);

CUTE_DECLARE_TEST_CASE(kryptos_md5_tests);

CUTE_DECLARE_TEST_CASE(kryptos_md5_hash_macro_tests);

CUTE_DECLARE_TEST_CASE(kryptos_ripemd128_tests);

CUTE_DECLARE_TEST_CASE(kryptos_ripemd128_hash_macro_tests);

CUTE_DECLARE_TEST_CASE(kryptos_ripemd160_tests);

CUTE_DECLARE_TEST_CASE(kryptos_ripemd160_hash_macro_tests);

CUTE_DECLARE_TEST_CASE(kryptos_sha3_224_tests);

CUTE_DECLARE_TEST_CASE(kryptos_sha3_224_hash_macro_tests);

CUTE_DECLARE_TEST_CASE(kryptos_sha3_256_tests);

CUTE_DECLARE_TEST_CASE(kryptos_sha3_256_hash_macro_tests);

CUTE_DECLARE_TEST_CASE(kryptos_sha3_384_tests);

CUTE_DECLARE_TEST_CASE(kryptos_sha3_384_hash_macro_tests);

CUTE_DECLARE_TEST_CASE(kryptos_sha3_512_tests);

CUTE_DECLARE_TEST_CASE(kryptos_sha3_512_hash_macro_tests);

CUTE_DECLARE_TEST_CASE(kryptos_keccak224_tests);

CUTE_DECLARE_TEST_CASE(kryptos_keccak224_hash_macro_tests);

CUTE_DECLARE_TEST_CASE(kryptos_keccak256_tests);

CUTE_DECLARE_TEST_CASE(kryptos_keccak256_hash_macro_tests);

CUTE_DECLARE_TEST_CASE(kryptos_keccak384_tests);

CUTE_DECLARE_TEST_CASE(kryptos_keccak384_hash_macro_tests);

CUTE_DECLARE_TEST_CASE(kryptos_keccak512_tests);

CUTE_DECLARE_TEST_CASE(kryptos_keccak512_hash_macro_tests);

CUTE_DECLARE_TEST_CASE(kryptos_blake2s256_tests);

CUTE_DECLARE_TEST_CASE(kryptos_blake2s256_hash_macro_tests);

CUTE_DECLARE_TEST_CASE(kryptos_blake2s256_keyed_tests);

CUTE_DECLARE_TEST_CASE(kryptos_blake2s256_hash_macro_keyed_tests);

CUTE_DECLARE_TEST_CASE(kryptos_blake2b512_tests);

CUTE_DECLARE_TEST_CASE(kryptos_blake2b512_hash_macro_tests);

CUTE_DECLARE_TEST_CASE(kryptos_blake2b512_keyed_tests);

CUTE_DECLARE_TEST_CASE(kryptos_blake2b512_hash_macro_keyed_tests);

CUTE_DECLARE_TEST_CASE(kryptos_blake2sN_tests);

CUTE_DECLARE_TEST_CASE(kryptos_blake2sN_hash_macro_tests);

CUTE_DECLARE_TEST_CASE(kryptos_blake2bN_tests);

CUTE_DECLARE_TEST_CASE(kryptos_blake2bN_hash_macro_tests);

CUTE_DECLARE_TEST_CASE(kryptos_tiger_tests);

CUTE_DECLARE_TEST_CASE(kryptos_tiger_hash_macro_tests);

CUTE_DECLARE_TEST_CASE(kryptos_whirlpool_tests);

CUTE_DECLARE_TEST_CASE(kryptos_whirlpool_hash_macro_tests);

CUTE_DECLARE_TEST_CASE_SUITE(kryptos_hmac_tests);

CUTE_DECLARE_TEST_CASE(kryptos_hmac_basic_tests);

#endif
