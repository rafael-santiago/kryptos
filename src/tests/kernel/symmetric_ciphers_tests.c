/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <symmetric_ciphers_tests.h>
#include <kryptos.h>

static kryptos_u8_t *gcm_test_data[] = {
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

#define kryptos_run_gcm_tests_no_support(cipher_name) {\
    kryptos_task_ctx t, *ktask = &t;\
    kryptos_u8_t *key = "GCMTest";\
    size_t key_size = 7;\
    kryptos_task_init_as_null(ktask);\
    ktask->in = "nosupp";\
    ktask->in_size = 6;\
    kryptos_ ## cipher_name ## _setup(ktask, key, key_size, kKryptosGCM);\
    kryptos_task_set_encrypt_action(ktask);\
    kryptos_ ## cipher_name ## _cipher(&ktask);\
    KUTE_ASSERT(kryptos_last_task_succeed(ktask) == 0);\
    KUTE_ASSERT(ktask->result == kKryptosNoSupport);\
    KUTE_ASSERT(ktask->out == NULL);\
    kryptos_task_free(ktask, KRYPTOS_TASK_IV);\
}

#define kryptos_run_gcm_tests_no_support_with_custom_setup(cipher_name, ktask, setup_stmt) {\
    kryptos_task_ctx t, *ktask = &t;\
    kryptos_task_init_as_null(ktask);\
    ktask->in = "nosupp";\
    ktask->in_size = 6;\
    setup_stmt;\
    kryptos_task_set_encrypt_action(ktask);\
    kryptos_ ## cipher_name ## _cipher(&ktask);\
    KUTE_ASSERT(kryptos_last_task_succeed(ktask) == 0);\
    KUTE_ASSERT(ktask->result == kKryptosNoSupport);\
    KUTE_ASSERT(ktask->out == NULL);\
    kryptos_task_free(ktask, KRYPTOS_TASK_IV);\
}

#define kryptos_run_gcm_tests(cipher_name) {\
    size_t tv, tv_nr = sizeof(gcm_test_data) / sizeof(gcm_test_data[0]);\
    kryptos_task_ctx t, *ktask = &t;\
    kryptos_u8_t *key = "GCMTest";\
    size_t key_size = 7, data_size;\
    for (tv = 0; tv < tv_nr; tv++) {\
        /*INFO(Rafael): Authentication success without aad.*/\
        kryptos_task_init_as_null(ktask);\
        ktask->in = gcm_test_data[tv];\
        data_size = strlen(ktask->in);\
        ktask->in_size = data_size;\
        kryptos_ ## cipher_name ## _setup(ktask, key, key_size, kKryptosGCM);\
        kryptos_task_set_encrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        KUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
        KUTE_ASSERT(ktask->out != NULL);\
        ktask->in = ktask->out;\
        ktask->in_size = ktask->out_size;\
        kryptos_task_set_decrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        KUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
        KUTE_ASSERT(ktask->out != NULL);\
        KUTE_ASSERT(ktask->out_size == data_size);\
        KUTE_ASSERT(memcmp(ktask->out, gcm_test_data[tv], data_size) == 0);\
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
        /*INFO(Rafael): Authentication failure without add.*/\
        kryptos_task_init_as_null(ktask);\
        ktask->in = gcm_test_data[tv];\
        data_size = strlen(ktask->in);\
        ktask->in_size = data_size;\
        kryptos_ ## cipher_name ## _setup(ktask, key, key_size, kKryptosGCM);\
        kryptos_task_set_encrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        KUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
        KUTE_ASSERT(ktask->out != NULL);\
        ktask->in = ktask->out;\
        ktask->in_size = ktask->out_size;\
        ktask->out = NULL;\
        ktask->out_size = 0;\
        ktask->in[ktask->in_size >> 1] = ~ktask->in[ktask->in_size >> 1];\
        kryptos_task_set_decrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        KUTE_ASSERT(kryptos_last_task_succeed(ktask) == 0);\
        KUTE_ASSERT(ktask->result == kKryptosGMACError);\
        KUTE_ASSERT(ktask->out == NULL);\
        kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
        /*INFO(Rafael): Authentication success with aad.*/\
        kryptos_task_init_as_null(ktask);\
        kryptos_task_set_gcm_aad(ktask, "boo", 3);\
        ktask->in = gcm_test_data[tv];\
        data_size = strlen(ktask->in);\
        ktask->in_size = data_size;\
        kryptos_ ## cipher_name ## _setup(ktask, key, key_size, kKryptosGCM);\
        kryptos_task_set_encrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        KUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
        KUTE_ASSERT(ktask->out != NULL);\
        ktask->in = ktask->out;\
        ktask->in_size = ktask->out_size;\
        kryptos_task_set_decrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        KUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
        KUTE_ASSERT(ktask->out != NULL);\
        KUTE_ASSERT(ktask->out_size == data_size);\
        KUTE_ASSERT(memcmp(ktask->out, gcm_test_data[tv], data_size) == 0);\
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
        /*INFO(Rafael): Authentication failure with add.*/\
        kryptos_task_init_as_null(ktask);\
        kryptos_task_set_gcm_aad(ktask, "boo", 3);\
        ktask->in = gcm_test_data[tv];\
        data_size = strlen(ktask->in);\
        ktask->in_size = data_size;\
        kryptos_ ## cipher_name ## _setup(ktask, key, key_size, kKryptosGCM);\
        kryptos_task_set_encrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        KUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
        KUTE_ASSERT(ktask->out != NULL);\
        ktask->in = ktask->out;\
        ktask->in_size = ktask->out_size;\
        ktask->out = NULL;\
        ktask->out_size = 0;\
        kryptos_task_set_gcm_aad(ktask, "bo", 2);\
        kryptos_task_set_decrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        KUTE_ASSERT(kryptos_last_task_succeed(ktask) == 0);\
        KUTE_ASSERT(ktask->result == kKryptosGMACError);\
        KUTE_ASSERT(ktask->out == NULL);\
        kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
    }\
}

#define kryptos_run_gcm_tests_with_custom_setup(cipher_name, ktask, setup_stmt) {\
    size_t tv, tv_nr = sizeof(gcm_test_data) / sizeof(gcm_test_data[0]);\
    kryptos_task_ctx t, *ktask = &t;\
    size_t data_size;\
    for (tv = 0; tv < tv_nr; tv++) {\
        /*INFO(Rafael): Authentication success without aad.*/\
        kryptos_task_init_as_null(ktask);\
        ktask->in = gcm_test_data[tv];\
        data_size = strlen(ktask->in);\
        ktask->in_size = data_size;\
        setup_stmt;\
        kryptos_task_set_encrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        KUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
        KUTE_ASSERT(ktask->out != NULL);\
        ktask->in = ktask->out;\
        ktask->in_size = ktask->out_size;\
        kryptos_task_set_decrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        KUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
        KUTE_ASSERT(ktask->out != NULL);\
        KUTE_ASSERT(ktask->out_size == data_size);\
        KUTE_ASSERT(memcmp(ktask->out, gcm_test_data[tv], data_size) == 0);\
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
        /*INFO(Rafael): Authentication failure without add.*/\
        kryptos_task_init_as_null(ktask);\
        ktask->in = gcm_test_data[tv];\
        data_size = strlen(ktask->in);\
        ktask->in_size = data_size;\
        setup_stmt;\
        kryptos_task_set_encrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        KUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
        KUTE_ASSERT(ktask->out != NULL);\
        ktask->in = ktask->out;\
        ktask->in_size = ktask->out_size;\
        ktask->out = NULL;\
        ktask->out_size = 0;\
        ktask->in[ktask->in_size >> 1] = ~ktask->in[ktask->in_size >> 1];\
        kryptos_task_set_decrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        KUTE_ASSERT(kryptos_last_task_succeed(ktask) == 0);\
        KUTE_ASSERT(ktask->result == kKryptosGMACError);\
        KUTE_ASSERT(ktask->out == NULL);\
        kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
        /*INFO(Rafael): Authentication success with aad.*/\
        kryptos_task_init_as_null(ktask);\
        kryptos_task_set_gcm_aad(ktask, "boo", 3);\
        ktask->in = gcm_test_data[tv];\
        data_size = strlen(ktask->in);\
        ktask->in_size = data_size;\
        setup_stmt;\
        kryptos_task_set_encrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        KUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
        KUTE_ASSERT(ktask->out != NULL);\
        ktask->in = ktask->out;\
        ktask->in_size = ktask->out_size;\
        kryptos_task_set_decrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        KUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
        KUTE_ASSERT(ktask->out != NULL);\
        KUTE_ASSERT(ktask->out_size == data_size);\
        KUTE_ASSERT(memcmp(ktask->out, gcm_test_data[tv], data_size) == 0);\
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
        /*INFO(Rafael): Authentication failure with add.*/\
        kryptos_task_init_as_null(ktask);\
        kryptos_task_set_gcm_aad(ktask, "boo", 3);\
        ktask->in = gcm_test_data[tv];\
        data_size = strlen(ktask->in);\
        ktask->in_size = data_size;\
        setup_stmt;\
        kryptos_task_set_encrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        KUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);\
        KUTE_ASSERT(ktask->out != NULL);\
        ktask->in = ktask->out;\
        ktask->in_size = ktask->out_size;\
        ktask->out = NULL;\
        ktask->out_size = 0;\
        kryptos_task_set_gcm_aad(ktask, "bo", 2);\
        kryptos_task_set_decrypt_action(ktask);\
        kryptos_ ## cipher_name ## _cipher(&ktask);\
        KUTE_ASSERT(kryptos_last_task_succeed(ktask) == 0);\
        KUTE_ASSERT(ktask->result == kKryptosGMACError);\
        KUTE_ASSERT(ktask->out == NULL);\
        kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
    }\
}

KUTE_TEST_CASE(kryptos_ctr_mode_sequencing_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u32_t ctr = 10;
    kryptos_u8_t *data = "ISLEEPTHROUGHTHEWAR";
    size_t data_size = 19;

    kryptos_task_init_as_null(ktask);

    kryptos_task_set_in(ktask, data, data_size);

    kryptos_task_set_encrypt_action(ktask);

    kryptos_task_set_ctr_mode(ktask, &ctr);
    kryptos_misty1_setup(ktask, "bulls", 5, kKryptosCTR);
    kryptos_misty1_cipher(&ktask);

    KUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
    KUTE_ASSERT(ktask->out != NULL);

    KUTE_ASSERT(ctr == 13);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);

    kryptos_task_set_decrypt_action(ktask);

    kryptos_misty1_setup(ktask, "bulls", 5, kKryptosCTR);
    kryptos_misty1_cipher(&ktask);

    KUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
    KUTE_ASSERT(ktask->out != NULL);
    KUTE_ASSERT(ktask->out_size == data_size);

    KUTE_ASSERT(memcmp(ktask->out, data, data_size) == 0);

    kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT | KRYPTOS_TASK_IV);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_des_weak_keys_detection_tests)
#define REGISTER_DES_WEAK_KEY(k) (k)
    static kryptos_u8_t *wkey[] = {
        // WARN(Rafael): DES' weak keys.
        REGISTER_DES_WEAK_KEY("\x01\x01\x01\x01\x01\x01\x01\x01"), REGISTER_DES_WEAK_KEY("\x1F\x1F\x1F\x1F\x0E\x0E\x0E\x0E"),
        REGISTER_DES_WEAK_KEY("\xE0\xE0\xE0\xE0\xF1\xF1\xF1\xF1"), REGISTER_DES_WEAK_KEY("\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE"),
        // WARN(Rafael): DES' semiweak keys.
        REGISTER_DES_WEAK_KEY("\x01\xFE\x01\xFE\x01\xFE\x01\xFE"), REGISTER_DES_WEAK_KEY("\xFE\x01\xFE\x01\xFE\x01\xFE\x01"),
        REGISTER_DES_WEAK_KEY("\x1F\xE0\x1F\xE0\x0E\xF1\x0E\xF1"), REGISTER_DES_WEAK_KEY("\xE0\xF1\xE0\xF1\xF1\x0E\xF1\x0E"),
        REGISTER_DES_WEAK_KEY("\x01\xE0\x01\xE0\x01\xF1\x01\xF1"), REGISTER_DES_WEAK_KEY("\xE0\x01\xE0\x01\xF1\x01\xF1\x01"),
        REGISTER_DES_WEAK_KEY("\x1F\xFE\x1F\xFE\x0E\xFE\x0E\xFE"), REGISTER_DES_WEAK_KEY("\xFE\x1F\xFE\x1F\xFE\x0E\xFE\x0E"),
        REGISTER_DES_WEAK_KEY("\x01\xF1\x01\xF1\x01\x0E\x01\x0E"), REGISTER_DES_WEAK_KEY("\x1F\x01\x1F\x01\x0E\x01\x0E\x01"),
        REGISTER_DES_WEAK_KEY("\x0E\xFE\x0E\xFE\xF1\xFE\xF1\xFE"), REGISTER_DES_WEAK_KEY("\xFE\x0E\xFE\x0E\xFE\xF1\xFE\xF1"),
        // WARN(Rafael): DES' possibly weak keys.
        REGISTER_DES_WEAK_KEY("\x1F\x1F\x01\x01\x0E\x0E\x01\x01"), REGISTER_DES_WEAK_KEY("\x0E\x01\x0E\xF1\xF1\x01\x01\xF1"),
        REGISTER_DES_WEAK_KEY("\x01\x1F\x1F\x01\x01\x0E\x0E\x01"), REGISTER_DES_WEAK_KEY("\xFE\xF1\x01\xE0\xFE\x0E\x01\xF1"),
        REGISTER_DES_WEAK_KEY("\x1F\x01\x01\x1F\x0E\x01\x01\x0E"), REGISTER_DES_WEAK_KEY("\xFE\x01\x1F\xE0\xFE\x01\x0E\xF1"),
        REGISTER_DES_WEAK_KEY("\x01\x01\x1F\x1F\x01\x01\x0E\x0E"), REGISTER_DES_WEAK_KEY("\xE0\x1F\x1F\xE0\xF1\x0E\x0E\xF1"),
        REGISTER_DES_WEAK_KEY("\xE0\xE0\x01\x01\xF1\xF1\x01\x01"), REGISTER_DES_WEAK_KEY("\xFE\x01\x01\xFE\xFE\x01\x01\xFE"),
        REGISTER_DES_WEAK_KEY("\xFE\xFE\x01\x01\xFE\xFE\x01\x01"), REGISTER_DES_WEAK_KEY("\xE0\x1F\x01\xFE\xF1\x0E\x01\xFE"),
        REGISTER_DES_WEAK_KEY("\xFE\xE0\x1F\x01\xFE\xF1\x0E\x01"), REGISTER_DES_WEAK_KEY("\xE0\x01\x1F\xFE\xF1\x01\x0E\xFE"),
        REGISTER_DES_WEAK_KEY("\xE0\xFE\x1F\x01\xF1\xFE\x0E\x01"), REGISTER_DES_WEAK_KEY("\xFE\x1F\x1F\xFE\xFE\x0E\x0E\xFE"),
        REGISTER_DES_WEAK_KEY("\xFE\xE0\x01\x1F\xFE\xF1\x01\x0E"), REGISTER_DES_WEAK_KEY("\x1F\xFE\x01\xE0\x0E\xFE\x01\xF1"),
        REGISTER_DES_WEAK_KEY("\xE0\xFE\x01\x1F\xF1\xFE\x01\x0E"), REGISTER_DES_WEAK_KEY("\x01\xFE\x1F\xE0\x01\xFE\x0E\xF1"),
        REGISTER_DES_WEAK_KEY("\xE0\xE0\x1F\x1F\xF1\xF1\x0E\x0E"), REGISTER_DES_WEAK_KEY("\x1F\xE0\x01\xFE\x0E\xF1\x01\xFE"),
        REGISTER_DES_WEAK_KEY("\xFE\xFE\x1F\x1F\xFE\xFE\x0E\x0E"), REGISTER_DES_WEAK_KEY("\x01\xE0\x1F\xFE\x01\xF1\x0E\xFE"),
        REGISTER_DES_WEAK_KEY("\xFE\x1F\xE0\x01\xFE\x0E\xF1\x01"), REGISTER_DES_WEAK_KEY("\x01\x01\xE0\xE0\x01\x01\xF1\xF1"),
        REGISTER_DES_WEAK_KEY("\xE0\x1F\xFE\x01\xF1\x0E\xFE\x01"), REGISTER_DES_WEAK_KEY("\x1F\x1F\xE0\xE0\x0E\x0E\xF1\xF1"),
        REGISTER_DES_WEAK_KEY("\xFE\x01\xE0\x1F\xFE\x01\xF1\x0E"), REGISTER_DES_WEAK_KEY("\x1F\x01\xFE\xE0\x0E\x01\xFE\xF1"),
        REGISTER_DES_WEAK_KEY("\xE0\x01\xFE\x1F\xF1\x01\xFE\x0E"), REGISTER_DES_WEAK_KEY("\x01\x1F\xFE\xE0\x01\x0E\xFE\xF1"),
        REGISTER_DES_WEAK_KEY("\x01\xE0\xE0\x01\x01\xF1\xF1\x01"), REGISTER_DES_WEAK_KEY("\x1F\x01\xE0\xFE\x0E\x01\xF1\xFE"),
        REGISTER_DES_WEAK_KEY("\x1F\xFE\xE0\x01\x0E\xFE\xF0\x01"), REGISTER_DES_WEAK_KEY("\x01\x1F\xE0\xFE\x01\x0E\xF1\xFE"),
        REGISTER_DES_WEAK_KEY("\x1F\xE0\xFE\x01\x0E\xF1\xFE\x01"), REGISTER_DES_WEAK_KEY("\x01\x01\xFE\xFE\x01\x01\xFE\xFE"),
        REGISTER_DES_WEAK_KEY("\x01\xFE\xFE\x01\x01\xFE\xFE\x01"), REGISTER_DES_WEAK_KEY("\x1F\x1F\xFE\xFE\x0E\x0E\xFE\xFE"),
        REGISTER_DES_WEAK_KEY("\x1F\xE0\xE0\x1F\x0E\xF1\xF1\x0E"), REGISTER_DES_WEAK_KEY("\xFE\xFE\xE0\xE0\xFE\xFE\xF1\xF1"),
        REGISTER_DES_WEAK_KEY("\x01\xFE\xE0\x1F\x01\xFE\xF1\x0E"), REGISTER_DES_WEAK_KEY("\xE0\xFE\xFE\xE0\xF1\xFE\xFE\xF1"),
        REGISTER_DES_WEAK_KEY("\x01\xE0\xFE\x1F\x01\xF1\xFE\x0E"), REGISTER_DES_WEAK_KEY("\xFE\xE0\xE0\xFE\xFE\xF1\xF1\xFE"),
        REGISTER_DES_WEAK_KEY("\x1F\xFE\xFE\x1F\x0E\xFE\xFE\x0E"), REGISTER_DES_WEAK_KEY("\xE0\xE0\xFE\xFE\xF1\xF1\xFE\xFE")
    };
#undef REGISTER_DES_WEAK_KEY
    size_t wkey_nr = sizeof(wkey) / sizeof(wkey[0]), w, wkeys_size = 8;
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *k1 = "101", *k2 = "255";
    size_t k1_size = 3, k2_size = 3;

    for (w = 0; w < wkey_nr; w++) {
        kryptos_task_init_as_null(ktask);
        kryptos_task_set_in(ktask, "Skeletons", 9);
        kryptos_task_set_encrypt_action(ktask);
        kryptos_des_setup(ktask, wkey[w], wkeys_size, kKryptosECB);
        kryptos_des_cipher(&ktask);
        KUTE_ASSERT(ktask->result == kKryptosKeyError);
    }

    for (w = 0; w < wkey_nr; w++) {
        kryptos_task_init_as_null(ktask);
        kryptos_task_set_in(ktask, "Skeletons", 9);
        kryptos_task_set_encrypt_action(ktask);
        kryptos_triple_des_setup(ktask, wkey[w], wkeys_size, kKryptosECB, k1, &k1_size, k2, &k2_size);
        kryptos_triple_des_cipher(&ktask);
        KUTE_ASSERT(ktask->result == kKryptosKeyError);
        kryptos_triple_des_setup(ktask, k1, k1_size, kKryptosECB, wkey[w], &wkeys_size, k2, &k2_size);
        kryptos_triple_des_cipher(&ktask);
        KUTE_ASSERT(ktask->result == kKryptosKeyError);
        kryptos_triple_des_setup(ktask, k1, k1_size, kKryptosECB, k2, &k2_size, wkey[w], &wkeys_size);
        kryptos_triple_des_cipher(&ktask);
        KUTE_ASSERT(ktask->result == kKryptosKeyError);
    }

    for (w = 0; w < wkey_nr; w++) {
        kryptos_task_init_as_null(ktask);
        kryptos_task_set_in(ktask, "Skeletons", 9);
        kryptos_task_set_encrypt_action(ktask);
        kryptos_triple_des_ede_setup(ktask, wkey[w], wkeys_size, kKryptosECB, k1, &k1_size, k2, &k2_size);
        kryptos_triple_des_ede_cipher(&ktask);
        KUTE_ASSERT(ktask->result == kKryptosKeyError);
        kryptos_triple_des_ede_setup(ktask, k1, k1_size, kKryptosECB, wkey[w], &wkeys_size, k2, &k2_size);
        kryptos_triple_des_ede_cipher(&ktask);
        KUTE_ASSERT(ktask->result == kKryptosKeyError);
        kryptos_triple_des_ede_setup(ktask, k1, k1_size, kKryptosECB, k2, &k2_size, wkey[w], &wkeys_size);
        kryptos_triple_des_ede_cipher(&ktask);
        KUTE_ASSERT(ktask->result == kKryptosKeyError);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_bcrypt_tests)
    struct bcrypt_test {
        const kryptos_u8_t *password;
        const size_t password_size;
        const int cost;
        const kryptos_u8_t *salt;
        const size_t salt_size;
        const kryptos_u8_t *hash;
        const size_t hash_size;
    };
#define add_test_step(p, p_sz, c, s, s_sz, h, h_sz) { p, p_sz, c, s, s_sz, h, h_sz }
    struct bcrypt_test test_vector[] = {
        add_test_step("", 0,
                       4, "\xD5\x72\x68\x31\x2B\xC8\x21\x2A\x9D\x01\xD0\x4F\x7B\xD9\xFF\x3D", 16,
                      "$2a$04$zVHmKQtGGQob.b/Nc7l9NO8UlrYcW05FiuCj/SxsFO/ZtiN9.mNzy", 60),
        add_test_step("", 0,
                       5, "\xD5\x72\x68\x31\x2B\xC8\x21\x2A\x9D\x01\xD0\x4F\x7B\xD9\xFF\x3D", 16,
                      "$2a$05$zVHmKQtGGQob.b/Nc7l9NOWES.1hkVBgy5IWImh9DOjKNU8atY4Iy", 60),
        add_test_step("", 0,
                       6, "\xD5\x72\x68\x31\x2B\xC8\x21\x2A\x9D\x01\xD0\x4F\x7B\xD9\xFF\x3D", 16,
                      "$2a$06$zVHmKQtGGQob.b/Nc7l9NOjOl7l4oz3WSh5fJ6414Uw8IXRAUoiaO", 60),
        add_test_step("", 0,
                       7, "\xD5\x72\x68\x31\x2B\xC8\x21\x2A\x9D\x01\xD0\x4F\x7B\xD9\xFF\x3D", 16,
                      "$2a$07$zVHmKQtGGQob.b/Nc7l9NOBsj1dQpBA1HYNGpIETIByoNX9jc.hOi", 60),
        add_test_step("", 0,
                       8, "\xD5\x72\x68\x31\x2B\xC8\x21\x2A\x9D\x01\xD0\x4F\x7B\xD9\xFF\x3D", 16,
                      "$2a$08$zVHmKQtGGQob.b/Nc7l9NOiLTUh/9MDpX86/DLyEzyiFjqjBFePgO", 60),
        add_test_step("messycrypt", 10,
                       4, "\xD5\x72\x68\x31\x2B\xC8\x21\x2A\x9D\x01\xD0\x4F\x7B\xD9\xFF\x3D", 16,
                      "$2a$04$zVHmKQtGGQob.b/Nc7l9NOW2pAwmViS9PCMB6D5D0ehLM6L7H3OGC", 60)
    };
#undef add_test_step
    size_t t, test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]);
    kryptos_u8_t *hash;
    size_t hash_size;

    for (t = 0; t < test_vector_nr; t++) {
        hash = kryptos_bcrypt(test_vector[t].cost,
                              test_vector[t].salt, test_vector[t].salt_size,
                              test_vector[t].password, test_vector[t].password_size, &hash_size);
        KUTE_ASSERT(hash != NULL);
        KUTE_ASSERT(hash_size == test_vector[t].hash_size);
        KUTE_ASSERT(memcmp(hash, test_vector[t].hash, hash_size) == 0);
        kryptos_freeseg(hash, hash_size);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_bcrypt_verify_tests)
    kryptos_u8_t *password[] = {
        "messycrypt", "No Good, Mr. Holden", "Bad idea.", "Nothing Ventured"
    };
    size_t password_nr = sizeof(password) / sizeof(password[0]), p;
    kryptos_u8_t *hash;
    size_t hash_size;
    kryptos_u8_t *salt;

    // INFO(Rafael): Malformed or unsupported hashes.

    hash = "$3a$04$zVHmKQtGGQob.b/Nc7l9NOW2pAwmViS9PCMB6D5D0ehLM6L7H3OGC";
    KUTE_ASSERT(kryptos_bcrypt_verify("Wrong", 5, hash, strlen(hash)) == 0);

    hash = "$2x$04$zVHmKQtGGQob.b/Nc7l9NOW2pAwmViS9PCMB6D5D0ehLM6L7H3OGC";
    KUTE_ASSERT(kryptos_bcrypt_verify("Wrong", 5, hash, strlen(hash)) == 0);

    hash = "2x$04$zVHmKQtGGQob.b/Nc7l9NOW2pAwmViS9PCMB6D5D0ehLM6L7H3OGC";
    KUTE_ASSERT(kryptos_bcrypt_verify("Wrong", 5, hash, strlen(hash)) == 0);

    hash = "$2a04$zVHmKQtGGQob.b/Nc7l9NOW2pAwmViS9PCMB6D5D0ehLM6L7H3OGC";
    KUTE_ASSERT(kryptos_bcrypt_verify("Wrong", 5, hash, strlen(hash)) == 0);

    hash = "$2x$0a$zVHmKQtGGQob.b/Nc7l9NOW2pAwmViS9PCMB6D5D0ehLM6L7H3OGC";
    KUTE_ASSERT(kryptos_bcrypt_verify("Wrong", 5, hash, strlen(hash)) == 0);

    hash = "$2x$a4$zVHmKQtGGQob.b/Nc7l9NOW2pAwmViS9PCMB6D5D0ehLM6L7H3OGC";
    KUTE_ASSERT(kryptos_bcrypt_verify("Wrong", 5, hash, strlen(hash)) == 0);

    hash = "$2x$32$zVHmKQtGGQob.b/Nc7l9NOW2pAwmViS9PCMB6D5D0ehLM6L7H3OGC";
    KUTE_ASSERT(kryptos_bcrypt_verify("Wrong", 5, hash, strlen(hash)) == 0);

    hash = "$2x$00$zVHmKQtGGQob.b/Nc7l9NOW2pAwmViS9PCMB6D5D0ehLM6L7H3OGC";
    KUTE_ASSERT(kryptos_bcrypt_verify("Wrong", 5, hash, strlen(hash)) == 0);

    hash = "$2x$04$zVHmKQtGGQo";
    KUTE_ASSERT(kryptos_bcrypt_verify("Wrong", 5, hash, strlen(hash)) == 0);

    for (p = 0; p < password_nr; p++) {
        salt = kryptos_get_random_block(16);
        KUTE_ASSERT(salt != NULL);
        hash = kryptos_bcrypt(4 + p, salt, 16, password[p], strlen(password[p]), &hash_size);
        KUTE_ASSERT(hash != NULL);
        KUTE_ASSERT(kryptos_bcrypt_verify("Wrong", 5, hash, hash_size) == 0);
        KUTE_ASSERT(kryptos_bcrypt_verify(password[p], strlen(password[p]), hash, hash_size) == 1);
        kryptos_freeseg(hash, hash_size);
        kryptos_freeseg(salt, 16);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_des_gcm_tests)
    kryptos_run_gcm_tests_no_support(des);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_idea_gcm_tests)
    kryptos_run_gcm_tests_no_support(idea);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_blowfish_gcm_tests)
    kryptos_run_gcm_tests_no_support(blowfish);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_feal_gcm_tests)
    int rounds = 1;
    kryptos_run_gcm_tests_no_support_with_custom_setup(feal, ktask, kryptos_feal_setup(ktask, "feal", 4,
                                                                                       kKryptosGCM, &rounds));
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_rc2_gcm_tests)
    int T1 = 32;
    kryptos_run_gcm_tests_no_support_with_custom_setup(rc2, ktask, kryptos_rc2_setup(ktask, "rc2", 3, kKryptosGCM,
                                                                                     &T1));
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_camellia128_gcm_tests)
    kryptos_run_gcm_tests(camellia128);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_camellia192_gcm_tests)
    kryptos_run_gcm_tests(camellia192);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_camellia256_gcm_tests)
    kryptos_run_gcm_tests(camellia256);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_cast5_gcm_tests)
    kryptos_run_gcm_tests_no_support(cast5);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_saferk64_gcm_tests)
    int rounds = 67;
    kryptos_run_gcm_tests_no_support_with_custom_setup(saferk64, ktask, kryptos_saferk64_setup(ktask, "saferk64", 8,
                                                                                               kKryptosGCM, &rounds));
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_aes128_gcm_tests)
    kryptos_run_gcm_tests(aes128);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_aes192_gcm_tests)
    kryptos_run_gcm_tests(aes192);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_aes256_gcm_tests)
    kryptos_run_gcm_tests(aes256);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_serpent_gcm_tests)
    kryptos_run_gcm_tests(serpent);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_triple_des_gcm_tests)
    kryptos_u8_t *k2 = "3des'", *k3 = "3des''";
    size_t k2_size = 5, k3_size = 6;
    kryptos_run_gcm_tests_no_support_with_custom_setup(triple_des, ktask, kryptos_triple_des_setup(ktask, "3des", 4,
                                                                                                   kKryptosGCM,
                                                                                                   k2, &k2_size,
                                                                                                   k3, &k3_size));
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_triple_des_ede_gcm_tests)
    kryptos_u8_t *k2 = "3des'", *k3 = "3des''";
    size_t k2_size = 5, k3_size = 6;
    kryptos_run_gcm_tests_no_support_with_custom_setup(triple_des_ede, ktask, kryptos_triple_des_ede_setup(ktask, "3des", 4,
                                                                                                           kKryptosGCM,
                                                                                                           k2, &k2_size,
                                                                                                           k3, &k3_size));
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_tea_gcm_tests)
    kryptos_run_gcm_tests_no_support_with_custom_setup(tea, ktask, kryptos_tea_setup(ktask,
                                                                                     "teateateateateat", 16, kKryptosGCM));
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_xtea_gcm_tests)
    int rounds = 17;
    kryptos_run_gcm_tests_no_support_with_custom_setup(xtea, ktask, kryptos_xtea_setup(ktask, "teateateateateat", 16,
                                                                                       kKryptosGCM, &rounds));
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_misty1_gcm_tests)
    kryptos_run_gcm_tests_no_support(misty1);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_rc5_gcm_tests)
    int rounds = 60;
    kryptos_run_gcm_tests_no_support_with_custom_setup(rc5, ktask, kryptos_rc5_setup(ktask, "rc5", 3, kKryptosGCM, &rounds));
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_rc6_128_gcm_tests)
    int rounds = 48;
    kryptos_run_gcm_tests_with_custom_setup(rc6_128, ktask, kryptos_rc6_128_setup(ktask, "rc6", 3, kKryptosGCM, &rounds));
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_rc6_192_gcm_tests)
    int rounds = 48;
    kryptos_run_gcm_tests_with_custom_setup(rc6_192, ktask, kryptos_rc6_192_setup(ktask, "rc6", 3, kKryptosGCM, &rounds));
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_rc6_256_gcm_tests)
    int rounds = 48;
    kryptos_run_gcm_tests_with_custom_setup(rc6_256, ktask, kryptos_rc6_256_setup(ktask, "rc6", 3, kKryptosGCM, &rounds));
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mars128_gcm_tests)
    kryptos_run_gcm_tests(mars128);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mars192_gcm_tests)
    kryptos_run_gcm_tests(mars192);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mars256_gcm_tests)
    kryptos_run_gcm_tests(mars256);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_present80_gcm_tests)
    kryptos_run_gcm_tests_no_support(present80);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_present128_gcm_tests)
    kryptos_run_gcm_tests_no_support(present128);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_shacal1_gcm_tests)
    kryptos_run_gcm_tests_no_support(shacal1);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_shacal2_gcm_tests)
    kryptos_run_gcm_tests_no_support(shacal2);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_noekeon_gcm_tests)
    kryptos_run_gcm_tests(noekeon);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_noekeon_d_gcm_tests)
    kryptos_run_gcm_tests(noekeon_d);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_gost_ds_gcm_tests)
    kryptos_run_gcm_tests_no_support(gost_ds);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_gost_gcm_tests)
    struct gost_sboxes_ctx {
        kryptos_u8_t *s1, *s2, *s3, *s4, *s5, *s6, *s7, *s8;
    };
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
    kryptos_run_gcm_tests_no_support_with_custom_setup(gost, ktask, kryptos_gost_setup(ktask, "gost", 4, kKryptosGCM,
                                                       s1, s2, s3, s4, s5, s6, s7, s8));
KUTE_TEST_CASE_END
