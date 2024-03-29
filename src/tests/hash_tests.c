/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "hash_tests.h"
#include "test_vectors.h"
#include <kryptos.h>
#include <kryptos_salsa20_core.h>
#include <stdlib.h>

#if defined(KRYPTOS_C99) && !defined(KRYPTOS_NO_HMAC_TESTS)

CUTE_DECLARE_TEST_CASE(kryptos_des_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_idea_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_blowfish_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_feal_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_rc2_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_rc5_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_rc6_128_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_rc6_192_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_rc6_256_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_camellia128_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_camellia192_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_camellia256_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_cast5_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_saferk64_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_aes128_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_aes192_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_aes256_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_serpent_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_triple_des_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_triple_des_ede_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_tea_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_xtea_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_misty1_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_mars128_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_mars192_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_mars256_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_present80_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_present128_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_shacal1_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_shacal2_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_noekeon_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_noekeon_d_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_gost_ds_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_gost_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_twofish128_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_twofish192_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_twofish256_hmac_tests);

#endif

CUTE_TEST_CASE(kryptos_sha1_tests)
    kryptos_run_hash_tests(sha1, 64, 20);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha1_hash_macro_tests)
    kryptos_run_hash_macro_tests(sha1, 64, 20);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha1_inc_hash_tests)
    kryptos_run_inc_hash_tests(sha1);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha224_tests)
    kryptos_run_hash_tests(sha224, 64, 28);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha224_hash_macro_tests)
    kryptos_run_hash_macro_tests(sha224, 64, 28);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha224_inc_hash_tests)
    kryptos_run_inc_hash_tests(sha224);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha256_tests)
    kryptos_run_hash_tests(sha256, 64, 32);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha256_hash_macro_tests)
    kryptos_run_hash_macro_tests(sha256, 64, 32);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha256_inc_hash_tests)
    kryptos_run_inc_hash_tests(sha256);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha384_tests)
    kryptos_run_hash_tests(sha384, 128, 48);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha384_hash_macro_tests)
    kryptos_run_hash_macro_tests(sha384, 128, 48);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha384_inc_hash_tests)
    kryptos_run_inc_hash_tests(sha384);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha512_tests)
    kryptos_run_hash_tests(sha512, 128, 64);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha512_hash_macro_tests)
    kryptos_run_hash_macro_tests(sha512, 128, 64);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha512_inc_hash_tests)
    kryptos_run_inc_hash_tests(sha512);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_md4_tests)
    kryptos_run_hash_tests(md4, 64, 16);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_md4_hash_macro_tests)
    kryptos_run_hash_macro_tests(md4, 64, 16);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_md4_inc_hash_tests)
    kryptos_run_inc_hash_tests(md4);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_md5_tests)
    kryptos_run_hash_tests(md5, 64, 16);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_md5_hash_macro_tests)
    kryptos_run_hash_macro_tests(md5, 64, 16);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_md5_inc_hash_tests)
    kryptos_run_inc_hash_tests(md5);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_ripemd128_tests)
    kryptos_run_hash_tests(ripemd128, 64, 16);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_ripemd128_hash_macro_tests)
    kryptos_run_hash_macro_tests(ripemd128, 64, 16);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_ripemd128_inc_hash_tests)
    kryptos_run_inc_hash_tests(ripemd128);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_ripemd160_tests)
    kryptos_run_hash_tests(ripemd160, 64, 20);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_ripemd160_hash_macro_tests)
    kryptos_run_hash_macro_tests(ripemd160, 64, 20);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_ripemd160_inc_hash_tests)
    kryptos_run_inc_hash_tests(ripemd160);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha3_224_tests)
    kryptos_run_hash_tests(sha3_224, 144, 28);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha3_224_hash_macro_tests)
    kryptos_run_hash_macro_tests(sha3_224, 144, 28);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha3_224_inc_hash_tests)
    kryptos_run_inc_hash_tests(sha3_224);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha3_256_tests)
    kryptos_run_hash_tests(sha3_256, 136, 32);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha3_256_hash_macro_tests)
    kryptos_run_hash_macro_tests(sha3_256, 136, 32);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha3_256_inc_hash_tests)
    kryptos_run_inc_hash_tests(sha3_256);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha3_384_tests)
    kryptos_run_hash_tests(sha3_384, 104, 48);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha3_384_hash_macro_tests)
    kryptos_run_hash_macro_tests(sha3_384, 104, 48);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha3_384_inc_hash_tests)
    kryptos_run_inc_hash_tests(sha3_384);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha3_512_tests)
    kryptos_run_hash_tests(sha3_512, 72, 64);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha3_512_hash_macro_tests)
    kryptos_run_hash_macro_tests(sha3_512, 72, 64);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha3_512_inc_hash_tests)
    kryptos_run_inc_hash_tests(sha3_512);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_keccak224_tests)
    kryptos_run_hash_tests(keccak224, 144, 28);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_keccak224_hash_macro_tests)
    kryptos_run_hash_macro_tests(keccak224, 144, 28);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_keccak224_inc_hash_tests)
    kryptos_run_inc_hash_tests(keccak224);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_keccak256_tests)
    kryptos_run_hash_tests(keccak256, 136, 32);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_keccak256_hash_macro_tests)
    kryptos_run_hash_macro_tests(keccak256, 136, 32);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_keccak256_inc_hash_tests)
    kryptos_run_inc_hash_tests(keccak256);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_keccak384_tests)
    kryptos_run_hash_tests(keccak384, 104, 48);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_keccak384_hash_macro_tests)
    kryptos_run_hash_macro_tests(keccak384, 104, 48);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_keccak384_inc_hash_tests)
    kryptos_run_inc_hash_tests(keccak384);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_keccak512_tests)
    kryptos_run_hash_tests(keccak512, 72, 64);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_keccak512_hash_macro_tests)
    kryptos_run_hash_macro_tests(keccak512, 72, 64);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_keccak512_inc_hash_tests)
    kryptos_run_inc_hash_tests(keccak512);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_tiger_tests)
    kryptos_run_hash_tests(tiger, 64, 24);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_tiger_hash_macro_tests)
    kryptos_run_hash_macro_tests(tiger, 64, 24);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_tiger_inc_hash_tests)
    kryptos_run_inc_hash_tests(tiger);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_whirlpool_tests)
    kryptos_run_hash_tests(whirlpool, 64, 64);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_whirlpool_hash_macro_tests)
    kryptos_run_hash_macro_tests(whirlpool, 64, 64);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_whirlpool_inc_hash_tests)
    kryptos_run_inc_hash_tests(whirlpool);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blake2s256_tests)
    kryptos_run_hash_tests(blake2s256, 64, 32)
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blake2s256_hash_macro_tests)
    kryptos_run_hash_macro_tests(blake2s256, 64, 32)
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blake2s256_inc_hash_tests)
    kryptos_run_inc_hash_tests(blake2s256);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blake2b512_tests)
    kryptos_run_hash_tests(blake2b512, 128, 64)
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blake2b512_hash_macro_tests)
    kryptos_run_hash_macro_tests(blake2b512, 128, 64)
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blake2b512_inc_hash_tests)
    kryptos_run_inc_hash_tests(blake2b512);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blake2sN_tests)
    // INFO(Rafael): Tests for Blake2sN are simpler than Blake2s256 because all
    //               here depends on Blake2s256 parts (tested against official test vectors).

    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    ktask->in = "abc";
    ktask->in_size = 3;

    ktask->out_size = 33; // INFO(Rafael): Greater than Blake2s hash size limit.
    kryptos_blake2sN_hash(&ktask, 0);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 0);

    ktask->out_size = 28; // INFO(Rafael): Blake2s224 raw output.
    kryptos_blake2sN_hash(&ktask, 0);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    ktask->out_size = 28; // INFO(Rafael): Blake2s224 hex output.
    kryptos_blake2sN_hash(&ktask, 1);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blake2sN_hash_macro_tests)
    // INFO(Rafael): Tests for Blake2sN are simpler than Blake2s256 because all
    //               here depends on Blake2s256 parts (tested against official test vectors).

    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    ktask->out_size = 33; // INFO(Rafael): Greater than Blake2s hash size limit.
    kryptos_hash(blake2sN, ktask, "abc", 3, 0);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 0);

    ktask->out_size = 28; // INFO(Rafael): Blake2s224 raw output.
    kryptos_hash(blake2sN, ktask, "abc", 3, 0);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    ktask->out_size = 28; // INFO(Rafael): Blake2s224 hex output.
    kryptos_hash(blake2sN, ktask, "abc", 3, 1);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blake2sN_inc_hash_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_task_init_as_null(ktask);
    kryptos_hash_init(blake2sN, ktask);
    kryptos_hash_update(ktask, "ab", 2);
    CUTE_ASSERT(ktask->result == kKryptosSuccess);
    kryptos_hash_update(ktask, "c", 1);
    CUTE_ASSERT(ktask->result == kKryptosSuccess);
    ktask->out_size = 20;
    kryptos_hash_finalize(ktask, 0);
    CUTE_ASSERT(ktask->result == kKryptosSuccess);
    CUTE_ASSERT(ktask->out != NULL);
    CUTE_ASSERT(ktask->out_size == 20);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blake2bN_tests)
    // INFO(Rafael): Tests for Blake2bN are simpler than Blake2b512 because all
    //               here depends on Blake2b512 parts (tested against official test vectors).
    //               Moreover, it is being used in Argon2 (also tested against its official test vectors).

    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    ktask->in = "abc";
    ktask->in_size = 3;

    ktask->out_size = 65; // INFO(Rafael): Greater than Blake2b hash size limit.
    kryptos_blake2bN_hash(&ktask, 0);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 0);

    ktask->out_size = 48; // INFO(Rafael): Blake2b384 raw output.
    kryptos_blake2bN_hash(&ktask, 0);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    ktask->out_size = 48; // INFO(Rafael): Blake2b384 hex output.
    kryptos_blake2bN_hash(&ktask, 1);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blake2bN_hash_macro_tests)
    // INFO(Rafael): Tests for Blake2bN are simpler than Blake2b512 because all
    //               here depends on Blake2b512 parts (tested against official test vectors).
    //               Moreover, it is being used in Argon2 (also tested against its official test vectors).

    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    ktask->out_size = 65; // INFO(Rafael): Greater than Blake2b hash size limit.
    kryptos_hash(blake2bN, ktask, "abc", 3, 0);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 0);

    ktask->out_size = 48; // INFO(Rafael): Blake2b384 raw output.
    kryptos_hash(blake2bN, ktask, "abc", 3, 0);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    ktask->out_size = 48; // INFO(Rafael): Blake2b384 hex output.
    kryptos_hash(blake2bN, ktask, "abc", 3, 1);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blake2bN_inc_hash_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_task_init_as_null(ktask);
    kryptos_hash_init(blake2bN, ktask);
    kryptos_hash_update(ktask, "ab", 2);
    CUTE_ASSERT(ktask->result == kKryptosSuccess);
    kryptos_hash_update(ktask, "c", 1);
    CUTE_ASSERT(ktask->result == kKryptosSuccess);
    ktask->out_size = 36;
    kryptos_hash_finalize(ktask, 0);
    CUTE_ASSERT(ktask->result == kKryptosSuccess);
    CUTE_ASSERT(ktask->out != NULL);
    CUTE_ASSERT(ktask->out_size == 36);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blake2s256_keyed_tests)
    size_t test_vector_nr = sizeof(blake2s256_keyed_test_vector) / sizeof(blake2s256_keyed_test_vector[0]), t;
    kryptos_task_ctx tsk, *ktask = &tsk;

    kryptos_task_init_as_null(ktask);

    ktask->in = blake2s256_keyed_test_vector[0].in;
    ktask->in_size = blake2s256_keyed_test_vector[0].in_size;
    ktask->key = "";
    ktask->key_size = 9999;
    kryptos_blake2s256_hash(&ktask, 0);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosKeyError);

    for (t = 0; t < test_vector_nr; t++) {
        ktask->in = blake2s256_keyed_test_vector[t].in;
        ktask->in_size = blake2s256_keyed_test_vector[t].in_size;
        ktask->key = blake2s256_keyed_test_vector[t].key;
        ktask->key_size = blake2s256_keyed_test_vector[t].key_size;
        kryptos_blake2s256_hash(&ktask, 0);
        CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
        CUTE_ASSERT(ktask->out != NULL);
        CUTE_ASSERT(ktask->out_size == blake2s256_keyed_test_vector[t].hash_size);
        CUTE_ASSERT(memcmp(ktask->out, blake2s256_keyed_test_vector[t].hash, ktask->out_size) == 0);
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
        ktask->in = blake2s256_keyed_test_vector[t].in;
        ktask->in_size = blake2s256_keyed_test_vector[t].in_size;
        ktask->key = blake2s256_keyed_test_vector[t].key;
        ktask->key_size = blake2s256_keyed_test_vector[t].key_size;
        kryptos_blake2s256_hash(&ktask, 1);
        CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
        CUTE_ASSERT(ktask->out != NULL);
        CUTE_ASSERT(ktask->out_size == blake2s256_keyed_test_vector[t].xhash_size);
        CUTE_ASSERT(memcmp(ktask->out, blake2s256_keyed_test_vector[t].xhash, ktask->out_size) == 0);
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blake2s256_hash_macro_keyed_tests)
    size_t test_vector_nr = sizeof(blake2s256_keyed_test_vector) / sizeof(blake2s256_keyed_test_vector[0]), t;
    kryptos_task_ctx tsk, *ktask = &tsk;

    kryptos_task_init_as_null(ktask);

    ktask->key = "";
    ktask->key_size = 9999;
    kryptos_hash(blake2s256, ktask, blake2s256_keyed_test_vector[0].in, blake2s256_keyed_test_vector[0].in_size, 0);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosKeyError);

    for (t = 0; t < test_vector_nr; t++) {
        ktask->key = blake2s256_keyed_test_vector[t].key;
        ktask->key_size = blake2s256_keyed_test_vector[t].key_size;
        kryptos_hash(blake2s256, ktask, blake2s256_keyed_test_vector[t].in, blake2s256_keyed_test_vector[t].in_size, 0);
        CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
        CUTE_ASSERT(ktask->out != NULL);
        CUTE_ASSERT(ktask->out_size == blake2s256_keyed_test_vector[t].hash_size);
        CUTE_ASSERT(memcmp(ktask->out, blake2s256_keyed_test_vector[t].hash, ktask->out_size) == 0);
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
        ktask->key = blake2s256_keyed_test_vector[t].key;
        ktask->key_size = blake2s256_keyed_test_vector[t].key_size;
        kryptos_hash(blake2s256, ktask, blake2s256_keyed_test_vector[t].in, blake2s256_keyed_test_vector[t].in_size, 1);
        CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
        CUTE_ASSERT(ktask->out != NULL);
        CUTE_ASSERT(ktask->out_size == blake2s256_keyed_test_vector[t].xhash_size);
        CUTE_ASSERT(memcmp(ktask->out, blake2s256_keyed_test_vector[t].xhash, ktask->out_size) == 0);
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blake2s256_inc_hash_keyed_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_task_init_as_null(ktask);
    kryptos_hash_init(blake2s256, ktask);
    kryptos_hash_update(ktask, "ab", 2);
    CUTE_ASSERT(ktask->result == kKryptosSuccess);
    kryptos_hash_update(ktask, "c", 1);
    CUTE_ASSERT(ktask->result == kKryptosSuccess);
    ktask->key = (kryptos_u8_t *)"xablablau";
    ktask->key_size = 9;
    kryptos_hash_finalize(ktask, 0);
    CUTE_ASSERT(ktask->result == kKryptosSuccess);
    CUTE_ASSERT(ktask->out != NULL);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blake2b512_keyed_tests)
    size_t test_vector_nr = sizeof(blake2b512_keyed_test_vector) / sizeof(blake2b512_keyed_test_vector[0]), t;
    kryptos_task_ctx tsk, *ktask = &tsk;

    kryptos_task_init_as_null(ktask);

    ktask->in = blake2b512_keyed_test_vector[0].in;
    ktask->in_size = blake2b512_keyed_test_vector[0].in_size;
    ktask->key = "";
    ktask->key_size = 9999;
    kryptos_blake2b512_hash(&ktask, 0);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosKeyError);

    for (t = 0; t < test_vector_nr; t++) {
        ktask->in = blake2b512_keyed_test_vector[t].in;
        ktask->in_size = blake2b512_keyed_test_vector[t].in_size;
        ktask->key = blake2b512_keyed_test_vector[t].key;
        ktask->key_size = blake2b512_keyed_test_vector[t].key_size;
        kryptos_blake2b512_hash(&ktask, 0);
        CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
        CUTE_ASSERT(ktask->out != NULL);
        CUTE_ASSERT(ktask->out_size == blake2b512_keyed_test_vector[t].hash_size);
        CUTE_ASSERT(memcmp(ktask->out, blake2b512_keyed_test_vector[t].hash, ktask->out_size) == 0);
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
        ktask->in = blake2b512_keyed_test_vector[t].in;
        ktask->in_size = blake2b512_keyed_test_vector[t].in_size;
        ktask->key = blake2b512_keyed_test_vector[t].key;
        ktask->key_size = blake2b512_keyed_test_vector[t].key_size;
        kryptos_blake2b512_hash(&ktask, 1);
        CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
        CUTE_ASSERT(ktask->out != NULL);
        CUTE_ASSERT(ktask->out_size == blake2b512_keyed_test_vector[t].xhash_size);
        CUTE_ASSERT(memcmp(ktask->out, blake2b512_keyed_test_vector[t].xhash, ktask->out_size) == 0);
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blake2b512_hash_macro_keyed_tests)
    size_t test_vector_nr = sizeof(blake2b512_keyed_test_vector) / sizeof(blake2b512_keyed_test_vector[0]), t;
    kryptos_task_ctx tsk, *ktask = &tsk;

    kryptos_task_init_as_null(ktask);

    ktask->key = "";
    ktask->key_size = 9999;
    kryptos_hash(blake2b512, ktask, blake2b512_keyed_test_vector[0].in, blake2b512_keyed_test_vector[0].in_size, 0);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosKeyError);

    for (t = 0; t < test_vector_nr; t++) {
        ktask->key = blake2b512_keyed_test_vector[t].key;
        ktask->key_size = blake2b512_keyed_test_vector[t].key_size;
        kryptos_hash(blake2b512, ktask, blake2b512_keyed_test_vector[t].in, blake2b512_keyed_test_vector[t].in_size, 0);
        CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
        CUTE_ASSERT(ktask->out != NULL);
        CUTE_ASSERT(ktask->out_size == blake2b512_keyed_test_vector[t].hash_size);
        CUTE_ASSERT(memcmp(ktask->out, blake2b512_keyed_test_vector[t].hash, ktask->out_size) == 0);
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
        ktask->key = blake2b512_keyed_test_vector[t].key;
        ktask->key_size = blake2b512_keyed_test_vector[t].key_size;
        kryptos_hash(blake2b512, ktask, blake2b512_keyed_test_vector[t].in, blake2b512_keyed_test_vector[t].in_size, 1);
        CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
        CUTE_ASSERT(ktask->out != NULL);
        CUTE_ASSERT(ktask->out_size == blake2b512_keyed_test_vector[t].xhash_size);
        CUTE_ASSERT(memcmp(ktask->out, blake2b512_keyed_test_vector[t].xhash, ktask->out_size) == 0);
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blake2b512_inc_hash_keyed_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_task_init_as_null(ktask);
    kryptos_hash_init(blake2sN, ktask);
    kryptos_hash_update(ktask, "ab", 2);
    CUTE_ASSERT(ktask->result == kKryptosSuccess);
    kryptos_hash_update(ktask, "c", 1);
    CUTE_ASSERT(ktask->result == kKryptosSuccess);
    ktask->key = (kryptos_u8_t *)"tchum!";
    ktask->key_size = 6;
    ktask->out_size = 16;
    kryptos_hash_finalize(ktask, 0);
    CUTE_ASSERT(ktask->result == kKryptosSuccess);
    CUTE_ASSERT(ktask->out != NULL);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_hmac_basic_tests)
    struct test_step {
        kryptos_hash_func h;
        kryptos_hash_size_func h_input_size;
        kryptos_hash_size_func h_size;
        kryptos_u8_t *key;
        size_t key_size;
        kryptos_u8_t *data;
        size_t data_size;
        kryptos_u8_t *expected;
        size_t expected_size;
    };
#define add_hmac_test_step(h, k, ks, d, ds, e, es)\
 { kryptos_ ## h ## _hash, kryptos_ ## h ## _hash_input_size, kryptos_ ## h ## _hash_size, k, ks, d, ds, e, es }
    // INFO(Rafael): Test vector from RFC-4231.
    struct test_step test_vector[] = {
        // INFO(Rafael): Test case 1.
        add_hmac_test_step(sha224,
                           "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20,
                           "\x48\x69\x20\x54\x68\x65\x72\x65", 8,
                           "\x89\x6f\xb1\x12\x8a\xbb\xdf\x19\x68\x32\x10\x7c\xd4\x9d"
                           "\xf3\x3f\x47\xb4\xb1\x16\x99\x12\xba\x4f\x53\x68\x4b\x22", 28),
        add_hmac_test_step(sha256,
                           "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20,
                           "\x48\x69\x20\x54\x68\x65\x72\x65", 8,
                           "\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b"
                           "\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7", 32),
        add_hmac_test_step(sha384,
                           "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20,
                           "\x48\x69\x20\x54\x68\x65\x72\x65", 8,
                           "\xaf\xd0\x39\x44\xd8\x48\x95\x62\x6b\x08\x25\xf4\xab\x46\x90\x7f"
                           "\x15\xf9\xda\xdb\xe4\x10\x1e\xc6\x82\xaa\x03\x4c\x7c\xeb\xc5\x9c"
                           "\xfa\xea\x9e\xa9\x07\x6e\xde\x7f\x4a\xf1\x52\xe8\xb2\xfa\x9c\xb6", 48),
        add_hmac_test_step(sha512,
                           "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20,
                           "\x48\x69\x20\x54\x68\x65\x72\x65", 8,
                           "\x87\xaa\x7c\xde\xa5\xef\x61\x9d\x4f\xf0\xb4\x24\x1a\x1d\x6c\xb0"
                           "\x23\x79\xf4\xe2\xce\x4e\xc2\x78\x7a\xd0\xb3\x05\x45\xe1\x7c\xde"
                           "\xda\xa8\x33\xb7\xd6\xb8\xa7\x02\x03\x8b\x27\x4e\xae\xa3\xf4\xe4"
                           "\xbe\x9d\x91\x4e\xeb\x61\xf1\x70\x2e\x69\x6c\x20\x3a\x12\x68\x54", 64),
        // INFO(Rafael): Test case 2.
        add_hmac_test_step(sha224,
                           "\x4a\x65\x66\x65", 4,
                           "\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61\x20\x77\x61\x6e"
                           "\x74\x20\x66\x6f\x72\x20\x6e\x6f\x74\x68\x69\x6e\x67\x3f", 28,
                           "\xa3\x0e\x01\x09\x8b\xc6\xdb\xbf\x45\x69\x0f\x3a\x7e\x9e"
                           "\x6d\x0f\x8b\xbe\xa2\xa3\x9e\x61\x48\x00\x8f\xd0\x5e\x44", 28),
        add_hmac_test_step(sha256,
                           "\x4a\x65\x66\x65", 4,
                           "\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61\x20\x77\x61\x6e"
                           "\x74\x20\x66\x6f\x72\x20\x6e\x6f\x74\x68\x69\x6e\x67\x3f", 28,
                           "\x5b\xdc\xc1\x46\xbf\x60\x75\x4e\x6a\x04\x24\x26\x08\x95\x75\xc7"
                           "\x5a\x00\x3f\x08\x9d\x27\x39\x83\x9d\xec\x58\xb9\x64\xec\x38\x43", 32),
        add_hmac_test_step(sha384,
                           "\x4a\x65\x66\x65", 4,
                           "\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61\x20\x77\x61\x6e"
                           "\x74\x20\x66\x6f\x72\x20\x6e\x6f\x74\x68\x69\x6e\x67\x3f", 28,
                           "\xaf\x45\xd2\xe3\x76\x48\x40\x31\x61\x7f\x78\xd2\xb5\x8a\x6b\x1b"
                           "\x9c\x7e\xf4\x64\xf5\xa0\x1b\x47\xe4\x2e\xc3\x73\x63\x22\x44\x5e"
                           "\x8e\x22\x40\xca\x5e\x69\xe2\xc7\x8b\x32\x39\xec\xfa\xb2\x16\x49", 48),
        add_hmac_test_step(sha512,
                           "\x4a\x65\x66\x65", 4,
                           "\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61\x20\x77\x61\x6e"
                           "\x74\x20\x66\x6f\x72\x20\x6e\x6f\x74\x68\x69\x6e\x67\x3f", 28,
                           "\x16\x4b\x7a\x7b\xfc\xf8\x19\xe2\xe3\x95\xfb\xe7\x3b\x56\xe0\xa3"
                           "\x87\xbd\x64\x22\x2e\x83\x1f\xd6\x10\x27\x0c\xd7\xea\x25\x05\x54"
                           "\x97\x58\xbf\x75\xc0\x5a\x99\x4a\x6d\x03\x4f\x65\xf8\xf0\xe6\xfd"
                           "\xca\xea\xb1\xa3\x4d\x4a\x6b\x4b\x63\x6e\x07\x0a\x38\xbc\xe7\x37", 64),
        // INFO(Rafael): Test case 3.
        add_hmac_test_step(sha224,
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 20,
                           "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                           "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                           "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                           "\xdd\xdd", 50,
                           "\x7f\xb3\xcb\x35\x88\xc6\xc1\xf6\xff\xa9\x69\x4d\x7d\x6a"
                           "\xd2\x64\x93\x65\xb0\xc1\xf6\x5d\x69\xd1\xec\x83\x33\xea", 28),
        add_hmac_test_step(sha256,
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 20,
                           "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                           "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                           "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                           "\xdd\xdd", 50,
                           "\x77\x3e\xa9\x1e\x36\x80\x0e\x46\x85\x4d\xb8\xeb\xd0\x91\x81\xa7"
                           "\x29\x59\x09\x8b\x3e\xf8\xc1\x22\xd9\x63\x55\x14\xce\xd5\x65\xfe", 32),
        add_hmac_test_step(sha384,
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 20,
                           "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                           "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                           "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                           "\xdd\xdd", 50,
                           "\x88\x06\x26\x08\xd3\xe6\xad\x8a\x0a\xa2\xac\xe0\x14\xc8\xa8\x6f"
                           "\x0a\xa6\x35\xd9\x47\xac\x9f\xeb\xe8\x3e\xf4\xe5\x59\x66\x14\x4b"
                           "\x2a\x5a\xb3\x9d\xc1\x38\x14\xb9\x4e\x3a\xb6\xe1\x01\xa3\x4f\x27", 48),
        add_hmac_test_step(sha512,
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 20,
                           "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                           "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                           "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                           "\xdd\xdd", 50,
                           "\xfa\x73\xb0\x08\x9d\x56\xa2\x84\xef\xb0\xf0\x75\x6c\x89\x0b\xe9"
                           "\xb1\xb5\xdb\xdd\x8e\xe8\x1a\x36\x55\xf8\x3e\x33\xb2\x27\x9d\x39"
                           "\xbf\x3e\x84\x82\x79\xa7\x22\xc8\x06\xb4\x85\xa4\x7e\x67\xc8\x07"
                           "\xb9\x46\xa3\x37\xbe\xe8\x94\x26\x74\x27\x88\x59\xe1\x32\x92\xfb", 64),
        // INFO(Rafael): Test case 4.
        add_hmac_test_step(sha224,
                           "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
                           "\x11\x12\x13\x14\x15\x16\x17\x18\x19", 25,
                           "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                           "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                           "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                           "\xcd\xcd", 50,
                           "\x6c\x11\x50\x68\x74\x01\x3c\xac\x6a\x2a\xbc\x1b\xb3\x82"
                           "\x62\x7c\xec\x6a\x90\xd8\x6e\xfc\x01\x2d\xe7\xaf\xec\x5a", 28),
        add_hmac_test_step(sha256,
                           "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
                           "\x11\x12\x13\x14\x15\x16\x17\x18\x19", 25,
                           "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                           "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                           "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                           "\xcd\xcd", 50,
                           "\x82\x55\x8a\x38\x9a\x44\x3c\x0e\xa4\xcc\x81\x98\x99\xf2\x08\x3a"
                           "\x85\xf0\xfa\xa3\xe5\x78\xf8\x07\x7a\x2e\x3f\xf4\x67\x29\x66\x5b", 32),
        add_hmac_test_step(sha384,
                           "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
                           "\x11\x12\x13\x14\x15\x16\x17\x18\x19", 25,
                           "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                           "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                           "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                           "\xcd\xcd", 50,
                           "\x3e\x8a\x69\xb7\x78\x3c\x25\x85\x19\x33\xab\x62\x90\xaf\x6c\xa7"
                           "\x7a\x99\x81\x48\x08\x50\x00\x9c\xc5\x57\x7c\x6e\x1f\x57\x3b\x4e"
                           "\x68\x01\xdd\x23\xc4\xa7\xd6\x79\xcc\xf8\xa3\x86\xc6\x74\xcf\xfb", 48),
        add_hmac_test_step(sha512,
                           "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
                           "\x11\x12\x13\x14\x15\x16\x17\x18\x19", 25,
                           "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                           "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                           "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                           "\xcd\xcd", 50,
                           "\xb0\xba\x46\x56\x37\x45\x8c\x69\x90\xe5\xa8\xc5\xf6\x1d\x4a\xf7"
                           "\xe5\x76\xd9\x7f\xf9\x4b\x87\x2d\xe7\x6f\x80\x50\x36\x1e\xe3\xdb"
                           "\xa9\x1c\xa5\xc1\x1a\xa2\x5e\xb4\xd6\x79\x27\x5c\xc5\x78\x80\x63"
                           "\xa5\xf1\x97\x41\x12\x0c\x4f\x2d\xe2\xad\xeb\xeb\x10\xa2\x98\xdd", 64),
        // INFO(Rafael): Test case 6.
        add_hmac_test_step(sha224,
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa", 131,
                           "\x54\x65\x73\x74\x20\x55\x73\x69\x6e\x67\x20\x4c\x61\x72\x67\x65"
                           "\x72\x20\x54\x68\x61\x6e\x20\x42\x6c\x6f\x63\x6b\x2d\x53\x69\x7a"
                           "\x65\x20\x4b\x65\x79\x20\x2d\x20\x48\x61\x73\x68\x20\x4b\x65\x79"
                           "\x20\x46\x69\x72\x73\x74", 54,
                           "\x95\xe9\xa0\xdb\x96\x20\x95\xad\xae\xbe\x9b\x2d\x6f\x0d"
                           "\xbc\xe2\xd4\x99\xf1\x12\xf2\xd2\xb7\x27\x3f\xa6\x87\x0e", 28),
        add_hmac_test_step(sha256,
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa", 131,
                           "\x54\x65\x73\x74\x20\x55\x73\x69\x6e\x67\x20\x4c\x61\x72\x67\x65"
                           "\x72\x20\x54\x68\x61\x6e\x20\x42\x6c\x6f\x63\x6b\x2d\x53\x69\x7a"
                           "\x65\x20\x4b\x65\x79\x20\x2d\x20\x48\x61\x73\x68\x20\x4b\x65\x79"
                           "\x20\x46\x69\x72\x73\x74", 54,
                           "\x60\xe4\x31\x59\x1e\xe0\xb6\x7f\x0d\x8a\x26\xaa\xcb\xf5\xb7\x7f"
                           "\x8e\x0b\xc6\x21\x37\x28\xc5\x14\x05\x46\x04\x0f\x0e\xe3\x7f\x54", 32),
        add_hmac_test_step(sha384,
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa", 131,
                           "\x54\x65\x73\x74\x20\x55\x73\x69\x6e\x67\x20\x4c\x61\x72\x67\x65"
                           "\x72\x20\x54\x68\x61\x6e\x20\x42\x6c\x6f\x63\x6b\x2d\x53\x69\x7a"
                           "\x65\x20\x4b\x65\x79\x20\x2d\x20\x48\x61\x73\x68\x20\x4b\x65\x79"
                           "\x20\x46\x69\x72\x73\x74", 54,
                           "\x4e\xce\x08\x44\x85\x81\x3e\x90\x88\xd2\xc6\x3a\x04\x1b\xc5\xb4"
                           "\x4f\x9e\xf1\x01\x2a\x2b\x58\x8f\x3c\xd1\x1f\x05\x03\x3a\xc4\xc6"
                           "\x0c\x2e\xf6\xab\x40\x30\xfe\x82\x96\x24\x8d\xf1\x63\xf4\x49\x52", 48),
        add_hmac_test_step(sha512,
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa", 131,
                           "\x54\x65\x73\x74\x20\x55\x73\x69\x6e\x67\x20\x4c\x61\x72\x67\x65"
                           "\x72\x20\x54\x68\x61\x6e\x20\x42\x6c\x6f\x63\x6b\x2d\x53\x69\x7a"
                           "\x65\x20\x4b\x65\x79\x20\x2d\x20\x48\x61\x73\x68\x20\x4b\x65\x79"
                           "\x20\x46\x69\x72\x73\x74", 54,
                           "\x80\xb2\x42\x63\xc7\xc1\xa3\xeb\xb7\x14\x93\xc1\xdd\x7b\xe8\xb4"
                           "\x9b\x46\xd1\xf4\x1b\x4a\xee\xc1\x12\x1b\x01\x37\x83\xf8\xf3\x52"
                           "\x6b\x56\xd0\x37\xe0\x5f\x25\x98\xbd\x0f\xd2\x21\x5d\x6a\x1e\x52"
                           "\x95\xe6\x4f\x73\xf6\x3f\x0a\xec\x8b\x91\x5a\x98\x5d\x78\x65\x98", 64)
    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), t;
    kryptos_task_ctx task, *ktask = &task;

    for (t = 0; t < test_vector_nr; t++) {
        kryptos_task_init_as_null(ktask);
        ktask->action = kKryptosEncrypt;
        ktask->key = test_vector[t].key;
        ktask->key_size = test_vector[t].key_size;
        ktask->out_size = test_vector[t].data_size;
        ktask->out = (kryptos_u8_t *) kryptos_newseg(ktask->out_size);
        CUTE_ASSERT(ktask->out != NULL);
        memcpy(ktask->out, test_vector[t].data, ktask->out_size);
        kryptos_hmac(&ktask, test_vector[t].h, test_vector[t].h_input_size, test_vector[t].h_size);
        CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
        CUTE_ASSERT(ktask->out_size == test_vector[t].expected_size + test_vector[t].data_size);
        // INFO(Rafael): The implementation of HMAC in kryptos during its evaluation phase concats the hash out with the data.
        CUTE_ASSERT(memcmp(ktask->out, test_vector[t].expected, test_vector[t].expected_size) == 0);
        CUTE_ASSERT(memcmp(ktask->out + test_vector[t].expected_size, test_vector[t].data, test_vector[t].data_size) == 0);
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
    }

#undef add_hmac_test_step
CUTE_TEST_CASE_END

CUTE_TEST_CASE_SUITE(kryptos_hmac_tests)

#if defined(KRYPTOS_C99) && !defined(KRYPTOS_NO_HMAC_TESTS)
    CUTE_RUN_TEST(kryptos_des_hmac_tests);
    CUTE_RUN_TEST(kryptos_idea_hmac_tests);
    CUTE_RUN_TEST(kryptos_blowfish_hmac_tests);
    CUTE_RUN_TEST(kryptos_feal_hmac_tests);
    CUTE_RUN_TEST(kryptos_rc2_hmac_tests);
    CUTE_RUN_TEST(kryptos_rc5_hmac_tests);
    CUTE_RUN_TEST(kryptos_rc6_128_hmac_tests);
    CUTE_RUN_TEST(kryptos_rc6_192_hmac_tests);
    CUTE_RUN_TEST(kryptos_rc6_256_hmac_tests);
    CUTE_RUN_TEST(kryptos_camellia128_hmac_tests);
    CUTE_RUN_TEST(kryptos_camellia192_hmac_tests);
    CUTE_RUN_TEST(kryptos_camellia256_hmac_tests);
    CUTE_RUN_TEST(kryptos_cast5_hmac_tests);
    CUTE_RUN_TEST(kryptos_saferk64_hmac_tests);
    CUTE_RUN_TEST(kryptos_aes128_hmac_tests);
    CUTE_RUN_TEST(kryptos_aes192_hmac_tests);
    CUTE_RUN_TEST(kryptos_aes256_hmac_tests);
    CUTE_RUN_TEST(kryptos_serpent_hmac_tests);
    CUTE_RUN_TEST(kryptos_triple_des_hmac_tests);
    CUTE_RUN_TEST(kryptos_triple_des_ede_hmac_tests);
    CUTE_RUN_TEST(kryptos_tea_hmac_tests);
    CUTE_RUN_TEST(kryptos_xtea_hmac_tests);
    CUTE_RUN_TEST(kryptos_misty1_hmac_tests);
    CUTE_RUN_TEST(kryptos_mars128_hmac_tests);
    CUTE_RUN_TEST(kryptos_mars192_hmac_tests);
    CUTE_RUN_TEST(kryptos_mars256_hmac_tests);
    CUTE_RUN_TEST(kryptos_present80_hmac_tests);
    CUTE_RUN_TEST(kryptos_present128_hmac_tests);
    CUTE_RUN_TEST(kryptos_shacal1_hmac_tests);
    CUTE_RUN_TEST(kryptos_shacal2_hmac_tests);
    CUTE_RUN_TEST(kryptos_noekeon_hmac_tests);
    CUTE_RUN_TEST(kryptos_noekeon_d_hmac_tests);
    CUTE_RUN_TEST(kryptos_gost_ds_hmac_tests);
    CUTE_RUN_TEST(kryptos_gost_hmac_tests);
    CUTE_RUN_TEST(kryptos_twofish128_hmac_tests);
    CUTE_RUN_TEST(kryptos_twofish192_hmac_tests);
    CUTE_RUN_TEST(kryptos_twofish256_hmac_tests);
#else
# if !defined(KRYPTOS_NO_HMAC_TESTS)
    // TODO(Rafael): When there is no C99 support add a simple bare bone test with at least one block cipher and all
    //               available hash functions.
    printf("WARN: This test runs only when libkryptos is compiled with C99 support. It will be skipped.\n");
# else
    printf("WARN: You have requested build this binary without the HMAC tests.\n");
# endif // !defined(KRYPTOS_SKIP_HMAC_TESTS)
#endif // defined(KRYPTOS_C99) && !defined(KRYPTOS_SKIP_HMAC_TESTS)

CUTE_TEST_CASE_SUITE_END

#if defined(KRYPTOS_C99) && !defined(KRYPTOS_NO_HMAC_TESTS)

CUTE_TEST_CASE(kryptos_des_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, whirlpool, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, blake2s256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, blake2b512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, blake3, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, whirlpool, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, blake2s256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, blake2b512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, blake3, key, key_size, kKryptosCBC);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_idea_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, whirlpool, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, blake2s256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, blake2b512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, blake3, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, whirlpool, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, blake2s256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, blake2b512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, blake3, key, key_size, kKryptosCBC);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blowfish_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, whirlpool, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, blake2s256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, blake2b512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, blake3, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, whirlpool, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, blake2s256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, blake2b512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, blake3, key, key_size, kKryptosCBC);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_feal_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;
    int feal_rounds = 8;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha1, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha224, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha256, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha384, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha512, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha3_224, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha3_256, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha3_384, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha3_512, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, keccak224, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, keccak256, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, keccak384, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, keccak512, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, md4, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, md5, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, ripemd128, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, ripemd160, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, tiger, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, whirlpool, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, blake2s256, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, blake2b512, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, blake3, key, key_size, kKryptosECB, &feal_rounds);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha1, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha224, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha256, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha384, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha512, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha3_224, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha3_256, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha3_384, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha3_512, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, keccak224, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, keccak256, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, keccak384, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, keccak512, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, md4, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, md5, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, ripemd128, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, ripemd160, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, tiger, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, whirlpool, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, blake2s256, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, blake2b512, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, blake3, key, key_size, kKryptosCBC, &feal_rounds);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rc2_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;
    int rc2_T1 = 64;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha1, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha224, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha256, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha384, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha512, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha3_224, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha3_256, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha3_384, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha3_512, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, keccak224, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, keccak256, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, keccak384, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, keccak512, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, md4, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, md5, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, ripemd128, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, ripemd160, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, tiger, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, whirlpool, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, blake2s256, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, blake2b512, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, blake3, key, key_size, kKryptosECB, &rc2_T1);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha1, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha224, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha256, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha384, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha512, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha3_224, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha3_256, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha3_384, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha3_512, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, keccak224, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, keccak256, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, keccak384, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, keccak512, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, md4, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, md5, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, ripemd128, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, ripemd160, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, tiger, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, whirlpool, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, blake2s256, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, blake2b512, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, blake3, key, key_size, kKryptosCBC, &rc2_T1);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rc5_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;
    int rc5_rounds = 20;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, sha1, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, sha224, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, sha256, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, sha384, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, sha512, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, sha3_224, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, sha3_256, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, sha3_384, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, sha3_512, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, keccak224, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, keccak256, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, keccak384, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, keccak512, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, md4, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, md5, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, ripemd128, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, ripemd160, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, tiger, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, whirlpool, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, blake2s256, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, blake2b512, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, blake3, key, key_size, kKryptosECB, &rc5_rounds);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, sha1, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, sha224, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, sha256, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, sha384, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, sha512, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, sha3_224, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, sha3_256, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, sha3_384, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, sha3_512, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, keccak224, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, keccak256, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, keccak384, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, keccak512, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, md4, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, md5, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, ripemd128, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, ripemd160, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, tiger, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, whirlpool, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, blake2s256, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, blake2b512, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc5, blake3, key, key_size, kKryptosCBC, &rc5_rounds);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rc6_128_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;
    int rc6_rounds = 40;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, sha1, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, sha224, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, sha256, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, sha384, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, sha512, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, sha3_224, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, sha3_256, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, sha3_384, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, sha3_512, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, keccak224, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, keccak256, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, keccak384, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, keccak512, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, md4, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, md5, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, ripemd128, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, ripemd160, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, tiger, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, whirlpool, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, blake2s256, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, blake2b512, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, blake3, key, key_size, kKryptosECB, &rc6_rounds);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, sha1, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, sha224, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, sha256, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, sha384, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, sha512, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, sha3_224, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, sha3_256, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, sha3_384, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, sha3_512, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, keccak224, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, keccak256, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, keccak384, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, keccak512, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, md4, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, md5, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, ripemd128, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, ripemd160, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, tiger, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, whirlpool, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, blake2s256, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, blake2b512, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_128, blake3, key, key_size, kKryptosCBC, &rc6_rounds);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rc6_192_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;
    int rc6_rounds = 40;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, sha1, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, sha224, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, sha256, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, sha384, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, sha512, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, sha3_224, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, sha3_256, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, sha3_384, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, sha3_512, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, keccak224, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, keccak256, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, keccak384, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, keccak512, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, md4, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, md5, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, ripemd128, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, ripemd160, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, tiger, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, whirlpool, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, blake2s256, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, blake2b512, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, blake3, key, key_size, kKryptosECB, &rc6_rounds);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, sha1, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, sha224, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, sha256, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, sha384, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, sha512, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, sha3_224, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, sha3_256, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, sha3_384, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, sha3_512, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, keccak224, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, keccak256, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, keccak384, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, keccak512, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, md4, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, md5, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, ripemd128, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, ripemd160, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, tiger, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, whirlpool, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, blake2s256, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, blake2b512, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_192, blake3, key, key_size, kKryptosCBC, &rc6_rounds);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rc6_256_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;
    int rc6_rounds = 40;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, sha1, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, sha224, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, sha256, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, sha384, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, sha512, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, sha3_224, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, sha3_256, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, sha3_384, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, sha3_512, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, keccak224, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, keccak256, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, keccak384, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, keccak512, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, md4, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, md5, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, ripemd128, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, ripemd160, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, tiger, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, whirlpool, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, blake2s256, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, blake2b512, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, blake3, key, key_size, kKryptosECB, &rc6_rounds);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, sha1, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, sha224, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, sha256, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, sha384, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, sha512, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, sha3_224, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, sha3_256, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, sha3_384, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, sha3_512, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, keccak224, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, keccak256, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, keccak384, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, keccak512, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, md4, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, md5, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, ripemd128, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, ripemd160, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, tiger, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, whirlpool, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, blake2s256, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, blake2b512, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc6_256, blake3, key, key_size, kKryptosCBC, &rc6_rounds);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_camellia128_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, whirlpool, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, blake2s256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, blake2b512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, blake3, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, whirlpool, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, blake2s256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, blake2b512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia128, blake3, key, key_size, kKryptosCBC);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_camellia192_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, whirlpool, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, blake2s256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, blake2b512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, blake3, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, whirlpool, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, blake2s256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, blake2b512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia192, blake3, key, key_size, kKryptosCBC);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_camellia256_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, whirlpool, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, blake2s256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, blake2b512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, blake3, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, whirlpool, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, blake2s256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, blake2b512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia256, blake3, key, key_size, kKryptosCBC);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_cast5_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, whirlpool, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, blake2s256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, blake2b512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, blake3, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, whirlpool, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, blake2s256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, blake2b512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, blake3, key, key_size, kKryptosCBC);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_saferk64_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;
    int saferk64_rounds = 6;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha1, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha224, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha256, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha384, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha512, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha3_224, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha3_256, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha3_384, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha3_512, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, keccak224, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, keccak256, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, keccak384, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, keccak512, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, md4, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, md5, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, ripemd128, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, ripemd160, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, tiger, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, whirlpool, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, blake2s256, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, blake2b512, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, blake3, key, key_size, kKryptosECB, &saferk64_rounds);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha1, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha224, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha256, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha384, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha512, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha3_224, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha3_256, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha3_384, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha3_512, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, keccak224, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, keccak256, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, keccak384, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, keccak512, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, md4, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, md5, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, ripemd128, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, ripemd160, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, tiger, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, whirlpool, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, blake2s256, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, blake2b512, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, blake3, key, key_size, kKryptosCBC, &saferk64_rounds);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_aes128_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, whirlpool, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, blake2s256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, blake2b512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, blake3, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, whirlpool, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, blake2s256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, blake2b512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, blake3, key, key_size, kKryptosCBC);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_aes192_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, whirlpool, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, blake2s256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, blake2b512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, blake3, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, whirlpool, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, blake2s256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, blake2b512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, blake3, key, key_size, kKryptosCBC);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_aes256_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, whirlpool, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, blake2s256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, blake2b512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, blake3, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, whirlpool, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, blake2s256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, blake2b512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, blake3, key, key_size, kKryptosCBC);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_serpent_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, whirlpool, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, blake2s256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, blake2b512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, blake3, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, whirlpool, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, blake2s256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, blake2b512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, blake3, key, key_size, kKryptosCBC);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_triple_des_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;
    kryptos_u8_t *triple_des_key2, *triple_des_key3;
    size_t triple_des_key2_size, triple_des_key3_size;

    triple_des_key2 = "gowithflow";
    triple_des_key2_size = 10;
    triple_des_key3 = "hangintree";
    triple_des_key3_size = 10;
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha1, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha224, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha256, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha384, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha512, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha3_224, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha3_256, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha3_384, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha3_512, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, keccak224, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, keccak256, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, keccak384, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, keccak512, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, md4, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, md5, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, ripemd128, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, ripemd160, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, tiger, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, whirlpool, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, blake2s256, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, blake2b512, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, blake3, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);


    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha1, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha224, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha256, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha384, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha512, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha3_224, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha3_256, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha3_384, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha3_512, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, keccak224, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, keccak256, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, keccak384, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, keccak512, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, md4, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, md5, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, ripemd128, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, ripemd160, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, tiger, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, whirlpool, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, blake2s256, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, blake2b512, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, blake3, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_triple_des_ede_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;
    kryptos_u8_t *triple_des_key2, *triple_des_key3;
    size_t triple_des_key2_size, triple_des_key3_size;

    triple_des_key2 = "gowithflow";
    triple_des_key2_size = 10;
    triple_des_key3 = "hangintree";
    triple_des_key3_size = 10;
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha1, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha224, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha256, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha384, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha512, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha3_224, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha3_256, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha3_384, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha3_512, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, keccak224, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, keccak256, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, keccak384, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, keccak512, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, md4, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, md5, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, ripemd128, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, ripemd160, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, tiger, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, whirlpool, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, blake2s256, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, blake2b512, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, blake3, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha1, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha224, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha256, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha384, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha512, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha3_224, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha3_256, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha3_384, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha3_512, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, keccak224, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, keccak256, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, keccak384, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, keccak512, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, md4, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, md5, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, ripemd128, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, ripemd160, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, tiger, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, whirlpool, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, blake2s256, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, blake2b512, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, blake3, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_tea_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, whirlpool, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, blake2s256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, blake2b512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, blake3, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, whirlpool, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, blake2s256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, blake2b512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, blake3, key, key_size, kKryptosCBC);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_xtea_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;
    int xtea_rounds = 64;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha1, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha224, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha256, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha384, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha512, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha3_224, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha3_256, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha3_384, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha3_512, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, keccak224, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, keccak256, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, keccak384, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, keccak512, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, md4, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, md5, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, ripemd128, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, ripemd160, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, tiger, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, whirlpool, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, blake2s256, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, blake2b512, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, blake3, key, key_size, kKryptosECB, &xtea_rounds);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha1, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha224, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha256, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha384, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha512, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha3_224, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha3_256, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha3_384, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha3_512, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, keccak224, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, keccak256, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, keccak384, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, keccak512, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, md4, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, md5, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, ripemd128, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, ripemd160, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, tiger, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, whirlpool, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, blake2s256, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, blake2b512, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, blake3, key, key_size, kKryptosCBC, &xtea_rounds);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_misty1_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, whirlpool, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, blake2s256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, blake2b512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, blake3, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, whirlpool, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, blake2s256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, blake2b512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, blake3, key, key_size, kKryptosCBC);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mars128_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, whirlpool, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, blake2s256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, blake2b512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, blake3, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, whirlpool, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, blake2s256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, blake2b512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars128, blake3, key, key_size, kKryptosCBC);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mars192_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, whirlpool, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, blake2s256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, blake2b512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, blake3, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, whirlpool, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, blake2s256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, blake2b512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars192, blake3, key, key_size, kKryptosCBC);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mars256_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, whirlpool, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, blake2s256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, blake2b512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, blake3, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, whirlpool, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, blake2s256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, blake2b512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, mars256, blake3, key, key_size, kKryptosCBC);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_present80_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, whirlpool, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, blake2s256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, blake2b512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, blake3, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, whirlpool, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, blake2s256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, blake2b512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present80, blake3, key, key_size, kKryptosCBC);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_present128_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, whirlpool, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, blake2s256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, blake2b512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, blake3, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, whirlpool, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, blake2s256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, blake2b512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, present128, blake3, key, key_size, kKryptosCBC);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_shacal1_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, whirlpool, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, blake2s256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, blake2b512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, blake3, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, whirlpool, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, blake2s256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, blake2b512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal1, blake3, key, key_size, kKryptosCBC);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_shacal2_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, whirlpool, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, blake2s256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, blake2b512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, blake3, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, whirlpool, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, blake2s256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, blake2b512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, shacal2, blake3, key, key_size, kKryptosCBC);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_noekeon_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, whirlpool, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, blake2s256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, blake2b512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, blake3, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, whirlpool, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, blake2s256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, blake2b512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon, blake3, key, key_size, kKryptosCBC);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_noekeon_d_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, whirlpool, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, blake2s256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, blake2b512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, blake3, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, whirlpool, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, blake2s256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, blake2b512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, noekeon_d, blake3, key, key_size, kKryptosCBC);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_gost_ds_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, whirlpool, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, blake2s256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, blake2b512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, blake3, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, whirlpool, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, blake2s256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, blake2b512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost_ds, blake3, key, key_size, kKryptosCBC);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_gost_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;
    kryptos_u8_t s1[16] = {
         4, 10,  9,  2, 13,  8,  0, 14,  6, 11,  1, 12,  7, 15,  5,  3
    };
    kryptos_u8_t s2[16] = {
        14, 11,  4, 12,  6, 13, 15, 10,  2,  3,  8,  1,  0,  7,  5,  9
    };
    kryptos_u8_t s3[16] = {
        5,  8,  1, 13, 10,  3,  4,  2, 14, 15, 12,  7,  6,  0,  9, 11
    };
    kryptos_u8_t s4[16] = {
        7, 13, 10,  1,  0,  8,  9, 15, 14,  4,  6, 12, 11,  2,  5,  3
    };
    kryptos_u8_t s5[16] = {
        6, 12,  7,  1,  5, 15, 13,  8,  4, 10,  9, 14,  0,  3, 11,  2
    };
    kryptos_u8_t s6[16] = {
        4, 11, 10,  0,  7,  2,  1, 13,  3,  6,  8,  5,  9, 12, 15, 14
    };
    kryptos_u8_t s7[16] = {
        13, 11,  4,  1,  3, 15,  5,  9,  0, 10, 14,  7,  6,  8,  2, 12
    };
    kryptos_u8_t s8[16] = {
         1, 15, 13,  0,  5,  7, 10,  4,  9,  2,  3, 14,  6, 11,  8, 12
    };

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, sha1, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, sha224, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, sha256, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, sha384, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, sha512, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, sha3_224, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, sha3_256, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, sha3_384, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, sha3_512, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, keccak224, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, keccak256, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, keccak384, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, keccak512, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, md4, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, md5, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, ripemd128, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, ripemd160, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, tiger, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, whirlpool, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, blake2s256, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, blake2b512, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, blake3, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, sha1, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, sha224, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, sha256, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, sha384, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, sha512, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, sha3_224, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, sha3_256, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, sha3_384, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, sha3_512, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, keccak224, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, keccak256, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, keccak384, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, keccak512, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, md4, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, md5, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, ripemd128, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, ripemd160, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, tiger, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, whirlpool, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, blake2s256, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, blake2b512, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, gost, blake3, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_twofish128_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, whirlpool, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, blake2s256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, blake2b512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, blake3, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, whirlpool, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, blake2s256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, blake2b512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish128, blake3, key, key_size, kKryptosCBC);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_twofish192_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, whirlpool, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, blake2s256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, blake2b512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, blake3, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, whirlpool, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, blake2s256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, blake2b512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish192, blake3, key, key_size, kKryptosCBC);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_twofish256_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, whirlpool, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, blake2s256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, blake2b512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, blake3, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, whirlpool, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, blake2s256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, blake2b512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, twofish256, blake3, key, key_size, kKryptosCBC);
CUTE_TEST_CASE_END

#endif

CUTE_TEST_CASE(kryptos_djb2_tests)
    struct test_vector_ctx {
        kryptos_u8_t *input;
        size_t input_size;
        kryptos_u64_t expected;
    } test_vector[] = {
        { "Hello", 5, 0x000000310D4F2079 },
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);

    while (test != test_end) {
        CUTE_ASSERT(kryptos_djb2(test->input, test->input_size) == test->expected);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_salsa20_H_tests)
    struct salsa20_H_test_vector_ctx {
        kryptos_u32_t in[16];
        kryptos_u32_t out[16];
    } test_vector[] = {
        {
            { 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
              0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
            { 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
              0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 }
        },
        {
            { 0xD39F0D73, 0x4C3752B7, 0x0375DE25, 0xBFBBEA88, 0x31EDB330, 0x016AB2DB, 0xAFC7A630, 0x5610B3CF,
              0x1FF0203F, 0x0F535DA1, 0x74933071, 0xEE37CC24, 0x4FC9EB4F, 0x03519C2F, 0xCB1AF4F3, 0x58766836 },
            { 0x6D2AB2A8, 0x9CF0F8EE, 0xA8C4BECB, 0x1A6EAA9A, 0x1D1D961A, 0x961EEBF9, 0xBEA3FB30, 0x45903339,
              0x7628989D, 0xB4391B5E, 0x6B2AEC23, 0x1B6F7272, 0xDBECE887, 0x6F9B6E12, 0x18E85F9E, 0xB31330CA }
        },
        {
            { 0x58766836, 0x4FC9EB4F, 0x03519C2F, 0xCB1AF4F3, 0xBFBBEA88, 0xD39F0D73, 0x4C3752B7, 0x0375DE25,
              0x5610B3CF, 0x31EDB330, 0x016AB2DB, 0xAFC7A630, 0xEE37CC24, 0x1FF0203F, 0x0F535DA1, 0x74933071 },
            { 0xB31330CA, 0xDBECE887, 0x6F9B6E12, 0x18E85F9E, 0x1A6EAA9A, 0x6D2AB2A8, 0x9CF0F8EE, 0xA8C4BECB,
              0x45903339, 0x1D1D961A, 0x961EEBF9, 0xBEA3FB30, 0x1B6F7272, 0x7628989D, 0xB4391B5E, 0x6B2AEC23 },
        },
    }, *tp = &test_vector[0], *tp_end = tp + sizeof(test_vector) / sizeof(test_vector[0]);
    kryptos_u8_t x[64];
    kryptos_u32_t xw[16];

    CUTE_ASSERT(kryptos_salsa20_H(NULL, 16) == 0);
    CUTE_ASSERT(kryptos_salsa20_H(x, 0) == 0);
    CUTE_ASSERT(kryptos_salsa20_H(x, 15) == 0);
    CUTE_ASSERT(kryptos_salsa20_H(x, 17) == 0);
    CUTE_ASSERT(kryptos_salsa20_H(x, -1) == 0);

    while (tp != tp_end) {
        x[ 0] = (tp->in[0] >> 24) & 0xFF;
        x[ 1] = ((tp->in[0] & 0x00FF0000) >> 16) & 0xFF;
        x[ 2] = ((tp->in[0] & 0x0000FF00) >>  8) & 0xFF;
        x[ 3] = tp->in[0] & 0xFF;
        x[ 4] = (tp->in[1] >> 24) & 0xFF;
        x[ 5] = ((tp->in[1] & 0x00FF0000) >> 16) & 0xFF;
        x[ 6] = ((tp->in[1] & 0x0000FF00) >>  8) & 0xFF;
        x[ 7] = tp->in[1] & 0xFF;
        x[ 8] = (tp->in[2] >> 24) & 0xFF;
        x[ 9] = ((tp->in[2] & 0x00FF0000) >> 16) & 0xFF;
        x[10] = ((tp->in[2] & 0x0000FF00) >>  8) & 0xFF;
        x[11] = tp->in[2] & 0xFF;
        x[12] = (tp->in[3] >> 24) & 0xFF;
        x[13] = ((tp->in[3] & 0x00FF0000) >> 16) & 0xFF;
        x[14] = ((tp->in[3] & 0x0000FF00) >>  8) & 0xFF;
        x[15] = tp->in[3] & 0xFF;
        x[16] = (tp->in[4] >> 24) & 0xFF;
        x[17] = ((tp->in[4] & 0x00FF0000) >> 16) & 0xFF;
        x[18] = ((tp->in[4] & 0x0000FF00) >>  8) & 0xFF;
        x[19] = tp->in[4] & 0xFF;
        x[20] = (tp->in[5] >> 24) & 0xFF;
        x[21] = ((tp->in[5] & 0x00FF0000) >> 16) & 0xFF;
        x[22] = ((tp->in[5] & 0x0000FF00) >>  8) & 0xFF;
        x[23] = tp->in[5] & 0xFF;
        x[24] = (tp->in[6] >> 24) & 0xFF;
        x[25] = ((tp->in[6] & 0x00FF0000) >> 16) & 0xFF;
        x[26] = ((tp->in[6] & 0x0000FF00) >>  8) & 0xFF;
        x[27] = tp->in[6] & 0xFF;
        x[28] = (tp->in[7] >> 24) & 0xFF;
        x[29] = ((tp->in[7] & 0x00FF0000) >> 16) & 0xFF;
        x[30] = ((tp->in[7] & 0x0000FF00) >>  8) & 0xFF;
        x[31] = tp->in[7] & 0xFF;
        x[32] = (tp->in[8] >> 24) & 0xFF;
        x[33] = ((tp->in[8] & 0x00FF0000) >> 16) & 0xFF;
        x[34] = ((tp->in[8] & 0x0000FF00) >>  8) & 0xFF;
        x[35] = tp->in[8] & 0xFF;
        x[36] = (tp->in[9] >> 24) & 0xFF;
        x[37] = ((tp->in[9] & 0x00FF0000) >> 16) & 0xFF;
        x[38] = ((tp->in[9] & 0x0000FF00) >>  8) & 0xFF;
        x[39] = tp->in[9] & 0xFF;
        x[40] = (tp->in[10] >> 24) & 0xFF;
        x[41] = ((tp->in[10] & 0x00FF0000) >> 16) & 0xFF;
        x[42] = ((tp->in[10] & 0x0000FF00) >>  8) & 0xFF;
        x[43] = tp->in[10] & 0xFF;
        x[44] = (tp->in[11] >> 24) & 0xFF;
        x[45] = ((tp->in[11] & 0x00FF0000) >> 16) & 0xFF;
        x[46] = ((tp->in[11] & 0x0000FF00) >>  8) & 0xFF;
        x[47] = tp->in[11] & 0xFF;
        x[48] = (tp->in[12] >> 24) & 0xFF;
        x[49] = ((tp->in[12] & 0x00FF0000) >> 16) & 0xFF;
        x[50] = ((tp->in[12] & 0x0000FF00) >>  8) & 0xFF;
        x[51] = tp->in[12] & 0xFF;
        x[52] = (tp->in[13] >> 24) & 0xFF;
        x[53] = ((tp->in[13] & 0x00FF0000) >> 16) & 0xFF;
        x[54] = ((tp->in[13] & 0x0000FF00) >>  8) & 0xFF;
        x[55] = tp->in[13] & 0xFF;
        x[56] = (tp->in[14] >> 24) & 0xFF;
        x[57] = ((tp->in[14] & 0x00FF0000) >> 16) & 0xFF;
        x[58] = ((tp->in[14] & 0x0000FF00) >>  8) & 0xFF;
        x[59] = tp->in[14] & 0xFF;
        x[60] = (tp->in[15] >> 24) & 0xFF;
        x[61] = ((tp->in[15] & 0x00FF0000) >> 16) & 0xFF;
        x[62] = ((tp->in[15] & 0x0000FF00) >>  8) & 0xFF;
        x[63] = tp->in[15] & 0xFF;

        CUTE_ASSERT(kryptos_salsa20_H(x, sizeof(x)) == 1);

        xw[ 0] = ((kryptos_u32_t)x[ 0]) << 24 |
                 ((kryptos_u32_t)x[ 1]) << 16 |
                 ((kryptos_u32_t)x[ 2]) <<  8 |
                 ((kryptos_u32_t)x[ 3]);
        xw[ 1] = ((kryptos_u32_t)x[ 4]) << 24 |
                 ((kryptos_u32_t)x[ 5]) << 16 |
                 ((kryptos_u32_t)x[ 6]) <<  8 |
                 ((kryptos_u32_t)x[ 7]);
        xw[ 2] = ((kryptos_u32_t)x[ 8]) << 24 |
                 ((kryptos_u32_t)x[ 9]) << 16 |
                 ((kryptos_u32_t)x[10]) <<  8 |
                 ((kryptos_u32_t)x[11]);
        xw[ 3] = ((kryptos_u32_t)x[12]) << 24 |
                 ((kryptos_u32_t)x[13]) << 16 |
                 ((kryptos_u32_t)x[14]) <<  8 |
                 ((kryptos_u32_t)x[15]);
        xw[ 4] = ((kryptos_u32_t)x[16]) << 24 |
                 ((kryptos_u32_t)x[17]) << 16 |
                 ((kryptos_u32_t)x[18]) <<  8 |
                 ((kryptos_u32_t)x[19]);
        xw[ 5] = ((kryptos_u32_t)x[20]) << 24 |
                 ((kryptos_u32_t)x[21]) << 16 |
                 ((kryptos_u32_t)x[22]) <<  8 |
                 ((kryptos_u32_t)x[23]);
        xw[ 6] = ((kryptos_u32_t)x[24]) << 24 |
                 ((kryptos_u32_t)x[25]) << 16 |
                 ((kryptos_u32_t)x[26]) <<  8 |
                 ((kryptos_u32_t)x[27]);
        xw[ 7] = ((kryptos_u32_t)x[28]) << 24 |
                 ((kryptos_u32_t)x[29]) << 16 |
                 ((kryptos_u32_t)x[30]) <<  8 |
                 ((kryptos_u32_t)x[31]);
        xw[ 8] = ((kryptos_u32_t)x[32]) << 24 |
                 ((kryptos_u32_t)x[33]) << 16 |
                 ((kryptos_u32_t)x[34]) <<  8 |
                 ((kryptos_u32_t)x[35]);
        xw[ 9] = ((kryptos_u32_t)x[36]) << 24 |
                 ((kryptos_u32_t)x[37]) << 16 |
                 ((kryptos_u32_t)x[38]) <<  8 |
                 ((kryptos_u32_t)x[39]);
        xw[10] = ((kryptos_u32_t)x[40]) << 24 |
                 ((kryptos_u32_t)x[41]) << 16 |
                 ((kryptos_u32_t)x[42]) <<  8 |
                 ((kryptos_u32_t)x[43]);
        xw[11] = ((kryptos_u32_t)x[44]) << 24 |
                 ((kryptos_u32_t)x[45]) << 16 |
                 ((kryptos_u32_t)x[46]) <<  8 |
                 ((kryptos_u32_t)x[47]);
        xw[12] = ((kryptos_u32_t)x[48]) << 24 |
                 ((kryptos_u32_t)x[49]) << 16 |
                 ((kryptos_u32_t)x[50]) <<  8 |
                 ((kryptos_u32_t)x[51]);
        xw[13] = ((kryptos_u32_t)x[52]) << 24 |
                 ((kryptos_u32_t)x[53]) << 16 |
                 ((kryptos_u32_t)x[54]) <<  8 |
                 ((kryptos_u32_t)x[55]);
        xw[14] = ((kryptos_u32_t)x[56]) << 24 |
                 ((kryptos_u32_t)x[57]) << 16 |
                 ((kryptos_u32_t)x[58]) <<  8 |
                 ((kryptos_u32_t)x[59]);
        xw[15] = ((kryptos_u32_t)x[60]) << 24 |
                 ((kryptos_u32_t)x[61]) << 16 |
                 ((kryptos_u32_t)x[62]) <<  8 |
                 ((kryptos_u32_t)x[63]);

        CUTE_ASSERT(xw[ 0] == tp->out[ 0]);
        CUTE_ASSERT(xw[ 1] == tp->out[ 1]);
        CUTE_ASSERT(xw[ 2] == tp->out[ 2]);
        CUTE_ASSERT(xw[ 3] == tp->out[ 3]);
        CUTE_ASSERT(xw[ 4] == tp->out[ 4]);
        CUTE_ASSERT(xw[ 5] == tp->out[ 5]);
        CUTE_ASSERT(xw[ 6] == tp->out[ 6]);
        CUTE_ASSERT(xw[ 7] == tp->out[ 7]);
        CUTE_ASSERT(xw[ 8] == tp->out[ 8]);
        CUTE_ASSERT(xw[ 9] == tp->out[ 9]);
        CUTE_ASSERT(xw[10] == tp->out[10]);
        CUTE_ASSERT(xw[11] == tp->out[11]);
        CUTE_ASSERT(xw[12] == tp->out[12]);
        CUTE_ASSERT(xw[13] == tp->out[13]);
        CUTE_ASSERT(xw[14] == tp->out[14]);
        CUTE_ASSERT(xw[15] == tp->out[15]);

        tp++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_chacha20_H_tests)
    struct test_ctx {
        kryptos_u8_t *key;
        kryptos_u8_t *nonce;
        kryptos_u32_t initial_ct;
        kryptos_u8_t *expected_keystream;
        size_t expected_keystream_size;
        size_t ct_nr;
    } test_vector[] = {
        // INFO(Rafael): Test vectors picked from RFC-7539.
        //
        //           "- Hey Beavis, why every test vector related to ChaCha/Salsa sucks?"
        //           "- Yeah! yeah! it stinks Butt..Head... hehehe!"
        //           "- Huhuh!"
        //           "- Did you write it?"
        //           "- Ohhh... yeah... I meant... no! No until I can remember heheheheh..
        //              What did you say? HehHehHeheheHe"
        //           "- HuHuhu!"
        //
        //      Sad but true. Anyway, the draft was much more spooky. If suddenly
        //      this draft come across you: it is not a rabbit but -> Run Awaaaaayyyy! <-
        {
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
            "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F",
            "\x00\x00\x00\x09\x00\x00\x00\x4a\x00\x00\x00\x00",
            0x00000001,
            "\x10\xF1\xE7\xE4\xD1\x3B\x59\x15\x50\x0F\xDD\x1F\xA3\x20\x71\xC4"
            "\xC7\xD1\xF4\xC7\x33\xC0\x68\x03\x04\x22\xAA\x9A\xC3\xD4\x6C\x4E"
            "\xD2\x82\x64\x46\x07\x9F\xAA\x09\x14\xC2\xD7\x05\xD9\x8B\x02\xA2"
            "\xB5\x12\x9C\xD1\xDE\x16\x4E\xB9\xCB\xD0\x83\xE8\xA2\x50\x3C\x4E",
            64,
            1
        },
        {
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
            "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F",
            "\x00\x00\x00\x00\x00\x00\x00\x4A\x00\x00\x00\x00",
            0x00000001,
            "\x22\x4F\x51\xF3\x40\x1B\xD9\xE1\x2F\xDE\x27\x6F\xB8\x63\x1D\xED"
            "\x8C\x13\x1F\x82\x3D\x2C\x06\xE2\x7E\x4F\xCA\xEC\x9E\xF3\xCF\x78"
            "\x8A\x3B\x0A\xA3\x72\x60\x0A\x92\xB5\x79\x74\xCD\xED\x2B\x93\x34"
            "\x79\x4C\xBA\x40\xC6\x3E\x34\xCD\xEA\x21\x2C\x4C\xF0\x7D\x41\xB7"
            "\x69\xA6\x74\x9F\x3F\x63\x0F\x41\x22\xCA\xFE\x28\xEC\x4D\xC4\x7E"
            "\x26\xD4\x34\x6D\x70\xB9\x8C\x73\xF3\xE9\xC5\x3A\xC4\x0C\x59\x45"
            "\x39\x8B\x6E\xDA\x1A\x83\x2C\x89\xC1\x67\xEA\xCD\x90\x1D\x7E\x2B"
            "\xF3\x63",
            114,
            4
        },
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    kryptos_u8_t x[64];
    kryptos_u32_t u32[2];
    size_t e;
    kryptos_u32_t ct;
    kryptos_u8_t *kp, *kp_end;

    while (test != test_end) {
#define kryptos_chacha20_getbyte(b, n) (( (b) >> (24 - (8 * (n))) ) & 0xFF)

#define kryptos_chacha20_littleendian(w) ( (((kryptos_u32_t)(w)) << 24) |\
                                          (((kryptos_u32_t)(w) & 0x0000FF00) << 8) |\
                                          (((kryptos_u32_t)(w) & 0x00FF0000) >> 8) |\
                                          (((kryptos_u32_t)(w)) >> 24) )

#define KRYPTOS_CHACHA20_THETA0 0x61707865
#define KRYPTOS_CHACHA20_THETA1 0x3320646E
#define KRYPTOS_CHACHA20_THETA2 0x79622D32
#define KRYPTOS_CHACHA20_THETA3 0x6B206574

        kp = &test->expected_keystream[0];
        kp_end = kp + test->expected_keystream_size;
        for (ct = test->initial_ct; ct <= test->ct_nr; ct++) {
            x[ 0] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA0, 0);
            x[ 1] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA0, 1);
            x[ 2] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA0, 2);
            x[ 3] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA0, 3);
            x[ 4] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA1, 0);
            x[ 5] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA1, 1);
            x[ 6] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA1, 2);
            x[ 7] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA1, 3);
            x[ 8] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA2, 0);
            x[ 9] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA2, 1);
            x[10] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA2, 2);
            x[11] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA2, 3);
            x[12] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA3, 0);
            x[13] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA3, 1);
            x[14] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA3, 2);
            x[15] = kryptos_chacha20_getbyte(KRYPTOS_CHACHA20_THETA3, 3);
            x[16] = test->key[ 3];
            x[17] = test->key[ 2];
            x[18] = test->key[ 1];
            x[19] = test->key[ 0];

            x[20] = test->key[ 7];
            x[21] = test->key[ 6];
            x[22] = test->key[ 5];
            x[23] = test->key[ 4];

            x[24] = test->key[11];
            x[25] = test->key[10];
            x[26] = test->key[ 9];
            x[27] = test->key[ 8];

            x[28] = test->key[15];
            x[29] = test->key[14];
            x[30] = test->key[13];
            x[31] = test->key[12];

            x[32] = test->key[19];
            x[33] = test->key[18];
            x[34] = test->key[17];
            x[35] = test->key[16];

            x[36] = test->key[23];
            x[37] = test->key[22];
            x[38] = test->key[21];
            x[39] = test->key[20];

            x[40] = test->key[27];
            x[41] = test->key[26];
            x[42] = test->key[25];
            x[43] = test->key[24];

            x[44] = test->key[31];
            x[45] = test->key[30];
            x[46] = test->key[29];
            x[47] = test->key[28];

            x[48] = kryptos_chacha20_getbyte(ct, 0);
            x[49] = kryptos_chacha20_getbyte(ct, 1);
            x[50] = kryptos_chacha20_getbyte(ct, 2);
            x[51] = kryptos_chacha20_getbyte(ct, 3);


            x[52] = test->nonce[ 3];
            x[53] = test->nonce[ 2];
            x[54] = test->nonce[ 1];
            x[55] = test->nonce[ 0];

            x[56] = test->nonce[ 7];
            x[57] = test->nonce[ 6];
            x[58] = test->nonce[ 5];
            x[59] = test->nonce[ 4];

            x[60] = test->nonce[11];
            x[61] = test->nonce[10];
            x[62] = test->nonce[ 9];
            x[63] = test->nonce[ 8];

            CUTE_ASSERT(kryptos_chacha20_H(x, sizeof(x)) == 1);

            for (e = 0; e < 64 && kp != kp_end; e++, kp++) {
                CUTE_ASSERT(x[e] == *kp);
            }
        }

#undef kryptos_chacha20_getbyte

#undef kryptos_chacha20_littleendian

#undef KRYPTOS_CHACHA20_THETA0
#undef KRYPTOS_CHACHA20_THETA1
#undef KRYPTOS_CHACHA20_THETA2
#undef KRYPTOS_CHACHA20_THETA3

        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blake3_tests)
    struct blake3_main_test_vector_ctx *test = &blake3_main_test_vector[0];
    struct blake3_main_test_vector_ctx *test_end = test + sizeof(blake3_main_test_vector) / sizeof(blake3_main_test_vector[0]);
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    while (test != test_end) {
        ktask->in = (kryptos_u8_t *)kryptos_newseg(test->in_size);

        CUTE_ASSERT(ktask->in != NULL);

        for (ktask->in_size = 0; ktask->in_size < test->in_size; ktask->in_size++) {
            ktask->in[ktask->in_size] = ktask->in_size % 251;
        }
        // INFO(Rafael): kryptos_blake3_hash primitive outputs the algorithm default size that is a digest of 256-bits.
        kryptos_blake3_hash(&ktask, 0);
        CUTE_ASSERT(ktask->result == kKryptosSuccess);

        CUTE_ASSERT(ktask->out_size == 32);
        CUTE_ASSERT(memcmp(ktask->out, test->hash, 32) == 0);

        kryptos_freeseg(ktask->out, ktask->out_size);
        ktask->out = NULL;
        ktask->out_size = 0;

        kryptos_blake3_hash(&ktask, 1);
        CUTE_ASSERT(ktask->result == kKryptosSuccess);

        CUTE_ASSERT(ktask->out_size == 64);
        CUTE_ASSERT(memcmp(ktask->out, test->xhash, 64) == 0);

        kryptos_freeseg(ktask->out, ktask->out_size);
        ktask->out = NULL;
        ktask->out_size = 0;

        // INFO(Rafael): The keyed hash mode.

        ktask->key = "whats the Elvish word for friend";
        ktask->key_size = 32;

        kryptos_blake3_hash(&ktask, 0);
        CUTE_ASSERT(ktask->result == kKryptosSuccess);

        CUTE_ASSERT(ktask->out_size == 32);
        CUTE_ASSERT(memcmp(ktask->out, test->keyed_hash, 32) == 0);

        kryptos_freeseg(ktask->out, ktask->out_size);
        ktask->out = NULL;
        ktask->out_size = 0;

        kryptos_blake3_hash(&ktask, 1);
        CUTE_ASSERT(ktask->result == kKryptosSuccess);

        CUTE_ASSERT(ktask->out_size == 64);
        CUTE_ASSERT(memcmp(ktask->out, test->xkeyed_hash, 64) == 0);

        kryptos_freeseg(ktask->out, ktask->out_size);
        ktask->out = NULL;
        ktask->out_size = 0;

        // INFO(Rafael): Null key or wrong sized keys must fail.

        ktask->key = NULL;
        ktask->key_size = 32;

        kryptos_blake3_hash(&ktask, 0);
        CUTE_ASSERT(ktask->result == kKryptosKeyError);

        kryptos_blake3_hash(&ktask, 1);
        CUTE_ASSERT(ktask->result == kKryptosKeyError);

        ktask->key = "Computer Liebe"; // 'Melon' would be pretty foreseeable :P

        // INFO(Rafael): Test all 2^(cpu_size) possibilities would be time consuming.
        //               So let's pick meaningful intervals of it and testing by expecting failures.

        for (ktask->key_size = 0; ktask->key_size < 32; ktask->key_size++) {
            kryptos_blake3_hash(&ktask, 0);
            CUTE_ASSERT(ktask->result == kKryptosKeyError);

            kryptos_blake3_hash(&ktask, 1);
            CUTE_ASSERT(ktask->result == kKryptosKeyError);
        }

        for (ktask->key_size = 33; ktask->key_size < 1024; ktask->key_size++) {
            kryptos_blake3_hash(&ktask, 0);
            CUTE_ASSERT(ktask->result == kKryptosKeyError);

            kryptos_blake3_hash(&ktask, 1);
            CUTE_ASSERT(ktask->result == kKryptosKeyError);
        }

        for (ktask->key_size = SIZE_MAX; ktask->key_size >= SIZE_MAX - 1024; ktask->key_size--) {
            kryptos_blake3_hash(&ktask, 0);
            CUTE_ASSERT(ktask->result == kKryptosKeyError);

            kryptos_blake3_hash(&ktask, 1);
            CUTE_ASSERT(ktask->result == kKryptosKeyError);
        }

        // INFO(Rafael): For the sake of organization, the derive key mode is
        //               implemented in `kdf_tests.c`. KDF tests are tested
        //               later hash tests, so when arriving there, the most
        //               of BLAKE3 will be tested already.

        kryptos_freeseg(ktask->in, ktask->in_size);
        ktask->in = NULL;
        ktask->in_size = 0;
        ktask->key = NULL;
        ktask->key_size = 0;

        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blake3N_tests)
    struct blake3_main_test_vector_ctx *test = &blake3_main_test_vector[0];
    struct blake3_main_test_vector_ctx *test_end = test + sizeof(blake3_main_test_vector) / sizeof(blake3_main_test_vector[0]);
    kryptos_task_ctx t, *ktask = &t;
    size_t out_size = 0;

    kryptos_task_init_as_null(ktask);

    while (test != test_end) {
        ktask->in = (kryptos_u8_t *)kryptos_newseg(test->in_size);

        CUTE_ASSERT(ktask->in != NULL);

        for (ktask->in_size = 0; ktask->in_size < test->in_size; ktask->in_size++) {
            ktask->in[ktask->in_size] = ktask->in_size % 251;
        }

        // INFO(Rafael): kryptos_blake3N_hash primitive outputs the algorithm default size that is a digest of 256-bits.

        for (out_size = 1; out_size < 132; out_size++) {
            ktask->out_size = out_size;
            // INFO(Rafael): BLAKE3_N can spit outputs from 8 to 2^64 bits but here we only
            //               can ensure until 131 bytes 'cause of this is the limit of the
            //               official test vectors.
            kryptos_blake3N_hash(&ktask, 0);
            CUTE_ASSERT(ktask->result == kKryptosSuccess);

            CUTE_ASSERT(ktask->out_size != 0);
            CUTE_ASSERT(memcmp(ktask->out, test->hash, ktask->out_size) == 0);

            kryptos_freeseg(ktask->out, ktask->out_size);
            ktask->out = NULL;

            kryptos_blake3N_hash(&ktask, 1);
            CUTE_ASSERT(ktask->result == kKryptosSuccess);

            CUTE_ASSERT(ktask->out_size != 0);
            CUTE_ASSERT(memcmp(ktask->out, test->xhash, ktask->out_size) == 0);

            kryptos_freeseg(ktask->out, ktask->out_size);
            ktask->out = NULL;

            // INFO(Rafael): The keyed hash mode.

            ktask->out_size = out_size;

            ktask->key = "whats the Elvish word for friend";
            ktask->key_size = 32;

            kryptos_blake3N_hash(&ktask, 0);
            CUTE_ASSERT(ktask->result == kKryptosSuccess);

            CUTE_ASSERT(ktask->out_size != 0);
            CUTE_ASSERT(memcmp(ktask->out, test->keyed_hash, ktask->out_size) == 0);

            kryptos_freeseg(ktask->out, ktask->out_size);
            ktask->out = NULL;

            kryptos_blake3N_hash(&ktask, 1);
            CUTE_ASSERT(ktask->result == kKryptosSuccess);

            CUTE_ASSERT(ktask->out_size != 0);
            CUTE_ASSERT(memcmp(ktask->out, test->xkeyed_hash, ktask->out_size) == 0);

            kryptos_freeseg(ktask->out, ktask->out_size);
            ktask->out = NULL;

            // INFO(Rafael): Null key or wrong sized keys must fail.

            ktask->key = NULL;
            ktask->key_size = 32;

            kryptos_blake3N_hash(&ktask, 0);
            CUTE_ASSERT(ktask->result == kKryptosKeyError);

            kryptos_blake3N_hash(&ktask, 1);
            CUTE_ASSERT(ktask->result == kKryptosKeyError);

            ktask->key = "I think I lost my headache!!!!!!";

            // INFO(Rafael): Test all 2^(cpu_size) possibilities would be time consuming.
            //               So let's pick meaningful intervals of it and testing by expecting failures.

            for (ktask->key_size = 0; ktask->key_size < 32; ktask->key_size++) {
                kryptos_blake3N_hash(&ktask, 0);
                CUTE_ASSERT(ktask->result == kKryptosKeyError);

                kryptos_blake3N_hash(&ktask, 1);
                CUTE_ASSERT(ktask->result == kKryptosKeyError);
            }

            for (ktask->key_size = 33; ktask->key_size < 1024; ktask->key_size++) {
                kryptos_blake3N_hash(&ktask, 0);
                CUTE_ASSERT(ktask->result == kKryptosKeyError);

                kryptos_blake3N_hash(&ktask, 1);
                CUTE_ASSERT(ktask->result == kKryptosKeyError);
            }

            for (ktask->key_size = SIZE_MAX; ktask->key_size >= SIZE_MAX - 1024; ktask->key_size--) {
                kryptos_blake3N_hash(&ktask, 0);
                CUTE_ASSERT(ktask->result == kKryptosKeyError);

                kryptos_blake3N_hash(&ktask, 1);
                CUTE_ASSERT(ktask->result == kKryptosKeyError);
            }

            // INFO(Rafael): For the sake of organization, the derive key mode is
            //               implemented in `kdf_tests.c`. KDF tests are tested
            //               later hash tests, so when arriving there, the most
            //               of BLAKE3_N will be tested already.
            ktask->key = NULL;
            ktask->key_size = 0;
        }

        kryptos_freeseg(ktask->in, ktask->in_size);
        ktask->in = NULL;
        ktask->in_size = 0;

        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blake3_hash_macro_tests)
    kryptos_run_hash_macro_tests(blake3, 64, 32)
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blake3_inc_hash_tests)
    kryptos_run_inc_hash_tests(blake3);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blake3N_hash_macro_tests)
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    ktask->out_size = 33; // INFO(Rafael): One byte greater than Blake3 hash size limit.
    kryptos_hash(blake3N, ktask, "abc", 3, 0);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    ktask->out_size = 96; // INFO(Rafael): Blake3/768 raw output.
    kryptos_hash(blake3N, ktask, "abc", 3, 0);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    ktask->out_size = 96; // INFO(Rafael): Blake3/768 hex output.
    kryptos_hash(blake3N, ktask, "abc", 3, 1);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blake3N_inc_hash_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_task_init_as_null(ktask);
    kryptos_hash_init(blake3N, ktask);
    kryptos_hash_update(ktask, "ab", 2);
    CUTE_ASSERT(ktask->result == kKryptosSuccess);
    kryptos_hash_update(ktask, "c", 1);
    CUTE_ASSERT(ktask->result == kKryptosSuccess);
    ktask->out_size = 192;
    kryptos_hash_finalize(ktask, 0);
    CUTE_ASSERT(ktask->result == kKryptosSuccess);
    CUTE_ASSERT(ktask->out != NULL);
    CUTE_ASSERT(ktask->out_size == 192);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blake3_inc_hash_keyed_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_task_init_as_null(ktask);
    kryptos_hash_init(blake3, ktask);
    kryptos_hash_update(ktask, "ab", 2);
    CUTE_ASSERT(ktask->result == kKryptosSuccess);
    kryptos_hash_update(ktask, "c", 1);
    CUTE_ASSERT(ktask->result == kKryptosSuccess);
    ktask->key = (kryptos_u8_t *)"autopilot.......................";
    ktask->key_size = 32;
    kryptos_hash_finalize(ktask, 0);
    CUTE_ASSERT(ktask->result == kKryptosSuccess);
    CUTE_ASSERT(ktask->out != NULL);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blake3N_inc_hash_keyed_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_task_init_as_null(ktask);
    kryptos_hash_init(blake3N, ktask);
    kryptos_hash_update(ktask, "ab", 2);
    CUTE_ASSERT(ktask->result == kKryptosSuccess);
    kryptos_hash_update(ktask, "c", 1);
    CUTE_ASSERT(ktask->result == kKryptosSuccess);
    ktask->out_size = 192;
    ktask->key = (kryptos_u8_t *)"parangaricutirimirruaru*!@#$%&()";
    ktask->key_size = 32;
    kryptos_hash_finalize(ktask, 0);
    CUTE_ASSERT(ktask->result == kKryptosSuccess);
    CUTE_ASSERT(ktask->out != NULL);
    CUTE_ASSERT(ktask->out_size == 192);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
CUTE_TEST_CASE_END
