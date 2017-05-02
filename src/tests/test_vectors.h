/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_TEST_VECTORS_H
#define KRYPTOS_TESTS_TEST_VECTORS_H 1

#include <kryptos_types.h>
#include "des_test_vector.h"
#include "idea_test_vector.h"
#include "blowfish_test_vector.h"
#include "feal_test_vector.h"
#include "rc2_test_vector.h"
#include "camellia_test_vector.h"
#include "cast5_test_vector.h"
#include "saferk64_test_vector.h"
#include "aes_test_vector.h"
#include "serpent_test_vector.h"
#include "sha1_test_vector.h"
#include "sha224_test_vector.h"
#include "sha256_test_vector.h"

static kryptos_u8_t *cbc_test_data[] = {
    "PEACE, n.In international affairs, a period of cheating "
        "between two periods of fighting. -- Ambrose Pierce, The Devil's Dictionary",
    "PAST, n.That part of Eternity with some small fraction of which we "
        "have a slight and regrettable acquaintance. A moving line called the "
        "Present parts it from an imaginary period known as the Future. These "
        "two grand divisions of Eternity, of which the one is continually "
        "effacing the other, are entirely unlike. The one is dark with sorrow "
        "and disappointment, the other bright with prosperity and joy. The "
        "Past is the region of sobs, the Future is the realm of song. In the one "
        "crouches Memory, clad in sackcloth and ashes, mumbling penitential prayer; "
        "in the sunshine of the other Hope flies with a free wing, beckoning to temples "
        "of success and bowers of ease. Yet the Past is the Future of yesterday, the Future "
        "is the Past of tomorrow. They are one -- the knowledge and the dream. -- Ambrose Pierce, The Devil's Dictionary",
    "PAGAN, n.A benighted person who prefers home-made deities and indigenous religious "
        "rites. -- Ambrose Pierce, The Devil's Dictionary",
    "PASSPORT, n.A document treacherously inflicted upon a citizen "
        "going abroad, exposing him as an alien and pointing him out for "
        "special reprobation and outrage. -- Ambrose Pierce, The Devil's Dictionary",
    "PARDON, v.To remit a penalty and restore to a life of crime. To add to the lure "
        "of crime the temptation of ingratitude. -- Ambrose Pierce, The Devil's Dictionary",
    "PLEASE, v.To lay the foundation for a superstructure of imposition. "
        "-- Ambrose Pierce, The Devil's Dictionary",
    "PAINTING, n.The art of protecting flat surfaces from the weather and exposing "
        "them to the critic. -- Ambrose Pierce, The Devil's Dictionary",
    "QUOTIENT, n.A number showing how many times a sum of money "
        "belonging to one person is contained in the pocket of another -- "
        "usually about as many times as it can got there. -- Ambrose Pierce, The Devil's Dictionary",
    "VIRTUES, n.pl.Certain abstentions. -- Ambrose Pierce, The Devil's Dictionary",
    "BED, n.A rack for the torture of the wicked; a citadel unfortified against remorse. "
        " -- Ambrose Pierce, The Devil's Dictionary",
    "BAYONET, n.An instrument for pricking the bubble of a nation's conceit. "
        " -- Ambrose Pierce, The Devil's Dictionary",
    "BELLADONNA, n.In Italian a beautiful lady; In English a deadly poison. "
        "A striking example of the essential identity of the two tongues."
        " -- Ambrose Pierce, The Devil's Dictionary",
    "BORE, n.A person who talks when you wish him to listen. -- Ambrose Pierce, The Devil's Dictionary",
    "BRIDE, n.A Woman with a fine prospect of happiness behind her. -- Ambrose Pierce, The Devil's Dictionary",
    "BRUTE, n.See HUSBAND. -- Ambrose Pierce, The Devil's Dictionary",
    "HUSBAND, n.One who, having dined, is charged with the care of the plate. -- Ambrose Pierce, The Devil's Dictionary",
    "WEDDING, n.A ceremony at which two persons undertake to become one, one undertakes to become nothing, "
        "and nothing undertakes to become supportable. -- Ambrose Pierce, The Devil's Dictionary",
    "WITCH, n.[1.] An ugly and repulsive old woman, in a wicked league with the devil. "
        "[2] A beautiful and attractive young woman, in wickedness a league beyond the devil."
        " -- Ambrose Pierce, The Devil's Dictionary",
    "\"When you have learned to snatch the error code from the trap frame, it will be time for you to leave.\"\n\n"
        "-- The Tao of Programming BOOK 1.",
    "A program should be light and agile, its subroutines connected like a string of pearls. "
        "The spirit and intent of the program should be retained throughout. There should be neither too "
        "little nor too much. Neither needless loops nor useless variables; neither lack of structure nor "
        "overwhelming rigidity.\n"
        "A program should follow the \"Law of Least Astonishment\". What is this law? It is simply that the "
        "program should always respond to the users in the way that least astonishes them. "
        "A program, no matter how complex, should act as a single unit. The program should be directed by the "
        "logic within rather than by outward appearances.\n"
        "If the program fails in these requirements, it will be in a state of disorder and confusion. "
        "The only way to correct this is to rewrite the program. -- The Tao of Programming [BOOK 4]"
    "Epilogue\n"
        "Thus spake the Master Programmer:\n"
        "\t\t\"Time for you to leave.\" -- The Tao of Programming"
};

#define kryptos_run_block_cipher_tests(cipher_name, blocksize) {\
    kryptos_task_ctx t, *ktask = &t;\
    size_t cbc_test_data_nr = sizeof(cbc_test_data) / sizeof(cbc_test_data[0]);\
    size_t data_size = 0;\
    kryptos_u8_t *key = "beetlejuice";\
    size_t key_size = 11;\
    size_t test_vector_nr = sizeof(cipher_name ## _test_vector) / sizeof(cipher_name ## _test_vector[0]), tv;\
    kryptos_task_init_as_null(&t);\
    for (tv = 0; tv < test_vector_nr; tv++) {\
        kryptos_ ## cipher_name ## _setup(&t, cipher_name ## _test_vector[tv].key, cipher_name ## _test_vector[tv].key_size, kKryptosECB);\
        t.in = cipher_name ## _test_vector[tv].plain;\
        t.in_size = cipher_name ## _test_vector[tv].block_size;\
        kryptos_task_set_encrypt_action(&t);\
        kryptos_ ## cipher_name  ## _cipher(&ktask);\
        CUTE_ASSERT(t.out != NULL);\
        CUTE_ASSERT(t.out_size == (t.in_size << 1));\
        /*printf("%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x\n", *(t.out), *(t.out+1), *(t.out+2), *(t.out+3), *(t.out+4), *(t.out+5), *(t.out+6), *(t.out+7));*/\
        CUTE_ASSERT(memcmp(t.out, cipher_name ## _test_vector[tv].cipher, cipher_name ## _test_vector[tv].block_size) == 0);\
        t.in = t.out;\
        t.in_size = t.out_size;\
        kryptos_task_set_decrypt_action(&t);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(t.out != NULL);\
        CUTE_ASSERT(t.out_size == cipher_name ## _test_vector[tv].block_size);\
        CUTE_ASSERT(memcmp(t.out, cipher_name ## _test_vector[tv].decrypted, cipher_name ## _test_vector[tv].block_size) == 0);\
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);\
    }\
    for (tv = 0; tv < cbc_test_data_nr; tv++) {\
        data_size = strlen(cbc_test_data[tv]);\
        kryptos_ ## cipher_name ## _setup(&t, key, 11, kKryptosCBC);\
        t.in = cbc_test_data[tv];\
        t.in_size = data_size;\
        kryptos_task_set_encrypt_action(&t);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(t.out != NULL);\
        t.in = t.out;\
        t.in_size = t.out_size;\
        kryptos_task_set_decrypt_action(&t);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(t.out != NULL);\
        CUTE_ASSERT(t.out_size == data_size);\
        CUTE_ASSERT(memcmp(t.out, cbc_test_data[tv], t.out_size) == 0);\
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
    }\
}

#define kryptos_run_block_cipher_tests_with_custom_setup(cipher_name, blocksize, t, tv, args, args_nr,\
                                                         cipher_setup_ecb_stmt, cipher_setup_cbc_stmt) {\
    kryptos_task_ctx *ktask = &t;\
    size_t cbc_test_data_nr = sizeof(cbc_test_data) / sizeof(cbc_test_data[0]);\
    size_t data_size = 0;\
    size_t test_vector_nr = sizeof(cipher_name ## _test_vector) / sizeof(cipher_name ## _test_vector[0]), tv;\
    kryptos_task_init_as_null(&t);\
    for (tv = 0; tv < test_vector_nr; tv++) {\
        cipher_setup_ecb_stmt;\
        t.in = cipher_name ## _test_vector[tv].plain;\
        t.in_size = cipher_name ## _test_vector[tv].block_size;\
        kryptos_task_set_encrypt_action(&t);\
        kryptos_ ## cipher_name  ## _cipher(&ktask);\
        CUTE_ASSERT(t.out != NULL);\
        CUTE_ASSERT(t.out_size == (t.in_size << 1));\
        /*printf("%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x\n", *(t.out), *(t.out+1), *(t.out+2), *(t.out+3), *(t.out+4), *(t.out+5), *(t.out+6), *(t.out+7));*/\
        CUTE_ASSERT(memcmp(t.out, cipher_name ## _test_vector[tv].cipher, cipher_name ## _test_vector[tv].block_size) == 0);\
        t.in = t.out;\
        t.in_size = t.out_size;\
        kryptos_task_set_decrypt_action(&t);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(t.out != NULL);\
        CUTE_ASSERT(t.out_size == cipher_name ## _test_vector[tv].block_size);\
        CUTE_ASSERT(memcmp(t.out, cipher_name ## _test_vector[tv].decrypted, cipher_name ## _test_vector[tv].block_size) == 0);\
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);\
    }\
    for (tv = 0; tv < cbc_test_data_nr; tv++) {\
        data_size = strlen(cbc_test_data[tv]);\
        cipher_setup_cbc_stmt;\
        t.in = cbc_test_data[tv];\
        t.in_size = data_size;\
        kryptos_task_set_encrypt_action(&t);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(t.out != NULL);\
        t.in = t.out;\
        t.in_size = t.out_size;\
        kryptos_task_set_decrypt_action(&t);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        CUTE_ASSERT(t.out != NULL);\
        CUTE_ASSERT(t.out_size == data_size);\
        CUTE_ASSERT(memcmp(t.out, cbc_test_data[tv], t.out_size) == 0);\
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
    }\
}

// TODO(Rafael): Implement the hash test runner.

#define kryptos_run_hash_tests(hash) {\
    kryptos_task_ctx t, *ktask = &t;\
    size_t tv, tv_nr = sizeof(hash ## _test_vector) / sizeof(hash ## _test_vector[0]);\
    for (tv = 0; tv < tv_nr; tv++) {\
        t.in = hash ## _test_vector[tv].message;\
        t.in_size = hash ## _test_vector[tv].message_size;\
        kryptos_ ## hash ## _hash(&ktask, 0);\
        CUTE_ASSERT(t.out != NULL);\
        CUTE_ASSERT(t.out_size == hash ## _test_vector[tv].raw_hash_size);\
        CUTE_ASSERT(memcmp(t.out, hash ## _test_vector[tv].raw_hash, t.out_size) == 0);\
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);\
        kryptos_ ## hash ## _hash(&ktask, 1);\
        CUTE_ASSERT(t.out != NULL);\
        CUTE_ASSERT(t.out_size == hash## _test_vector[tv].hex_hash_size);\
        CUTE_ASSERT(memcmp(t.out, hash ## _test_vector[tv].hex_hash, t.out_size) == 0);\
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);\
    }\
}

#endif // KRYPTOS_TESTS_TEST_VECTORS_H
