/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <symmetric_ciphers_tests.h>
#include <kryptos.h>

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
