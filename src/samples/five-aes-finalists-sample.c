/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>

typedef int (*cipher_processor_func)(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);

static int aes128_gcm(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int aes192_gcm(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int aes256_gcm(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int mars128_gcm(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int mars192_gcm(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int mars256_gcm(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int serpent_gcm(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int rc6_128_gcm(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int rc6_192_gcm(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int rc6_256_gcm(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int twofish128_gcm(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int twofish192_gcm(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int twofish256_gcm(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int aes128_ecb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int aes192_ecb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int aes256_ecb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int mars128_ecb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int mars192_ecb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int mars256_ecb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int serpent_ecb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int rc6_128_ecb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int rc6_192_ecb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int rc6_256_ecb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int twofish128_ecb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int twofish192_ecb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int twofish256_ecb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int aes128_cbc(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int aes192_cbc(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int aes256_cbc(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int mars128_cbc(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int mars192_cbc(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int mars256_cbc(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int serpent_cbc(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int rc6_128_cbc(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int rc6_192_cbc(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int rc6_256_cbc(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int twofish128_cbc(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int twofish192_cbc(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int twofish256_cbc(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int aes128_ofb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int aes192_ofb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int aes256_ofb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int mars128_ofb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int mars192_ofb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int mars256_ofb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int serpent_ofb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int rc6_128_ofb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int rc6_192_ofb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int rc6_256_ofb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int twofish128_ofb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int twofish192_ofb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int twofish256_ofb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int aes128_ctr(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int aes192_ctr(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int aes256_ctr(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int mars128_ctr(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int mars192_ctr(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int mars256_ctr(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int serpent_ctr(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int rc6_128_ctr(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int rc6_192_ctr(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int rc6_256_ctr(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int twofish128_ctr(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int twofish192_ctr(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);
static int twofish256_ctr(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size);

static void print_buffer(const char *prefix, const char *buf, const size_t buf_size);

int main(void) {
    kryptos_u8_t *message = (kryptos_u8_t *)"Freedom is nothing else but the chance to do better. (Camus)";
    size_t message_size = strlen((char *)message);
    kryptos_task_ctx t, *ktask = &t;
    size_t f;
    kryptos_u8_t *key = (kryptos_u8_t *)"F41r135W34rB00t5";
    size_t key_size = strlen((char *)key);
    struct cipher_suite {
        const char *name;
        cipher_processor_func processor;
    } ciphers[] = {
        { "rijndael-128/ecb", aes128_ecb },
        { "rijndael-192/ecb", aes192_ecb },
        { "rijndael-256/ecb", aes256_ecb },
        { "rijndael-128/cbc", aes128_cbc },
        { "rijndael-192/cbc", aes192_cbc },
        { "rijndael-256/cbc", aes256_cbc },
        { "rijndael-128/ofb", aes128_ofb },
        { "rijndael-192/ofb", aes192_ofb },
        { "rijndael-256/ofb", aes256_ofb },
        { "rijndael-128/ctr", aes128_ctr },
        { "rijndael-192/ctr", aes192_ctr },
        { "rijndael-256/ctr", aes256_ctr },
        { "rijndael-128/gcm", aes128_gcm },
        { "rijndael-192/gcm", aes192_gcm },
        { "rijndael-256/gcm", aes256_gcm },
        { "mars-128/ecb", mars128_ecb },
        { "mars-192/ecb", mars192_ecb },
        { "mars-256/ecb", mars256_ecb },
        { "mars-128/cbc", mars128_cbc },
        { "mars-192/cbc", mars192_cbc },
        { "mars-256/cbc", mars256_cbc },
        { "mars-128/ofb", mars128_ofb },
        { "mars-192/ofb", mars192_ofb },
        { "mars-256/ofb", mars256_ofb },
        { "mars-128/ctr", mars128_ctr },
        { "mars-192/ctr", mars192_ctr },
        { "mars-256/ctr", mars256_ctr },
        { "mars-128/gcm", mars128_gcm },
        { "mars-192/gcm", mars192_gcm },
        { "mars-256/gcm", mars256_gcm },
        { "serpent/ecb", serpent_ecb },
        { "serpent/cbc", serpent_cbc },
        { "serpent/ofb", serpent_ofb },
        { "serpent/ctr", serpent_ctr },
        { "serpent/gcm", serpent_gcm },
        { "rc6-128/ecb", rc6_128_ecb },
        { "rc6-192/ecb", rc6_192_ecb },
        { "rc6-256/ecb", rc6_256_ecb },
        { "rc6-128/cbc", rc6_128_cbc },
        { "rc6-192/cbc", rc6_192_cbc },
        { "rc6-256/cbc", rc6_256_cbc },
        { "rc6-128/ofb", rc6_128_ofb },
        { "rc6-192/ofb", rc6_192_ofb },
        { "rc6-256/ofb", rc6_256_ofb },
        { "rc6-128/ctr", rc6_128_ctr },
        { "rc6-192/ctr", rc6_192_ctr },
        { "rc6-256/ctr", rc6_256_ctr },
        { "rc6-128/gcm", rc6_128_gcm },
        { "rc6-192/gcm", rc6_192_gcm },
        { "rc6-256/gcm", rc6_256_gcm },
        { "twofish-128/ecb", twofish128_ecb },
        { "twofish-192/ecb", twofish192_ecb },
        { "twofish-256/ecb", twofish256_ecb },
        { "twofish-128/cbc", twofish128_cbc },
        { "twofish-192/cbc", twofish192_cbc },
        { "twofish-256/cbc", twofish256_cbc },
        { "twofish-128/ofb", twofish128_ofb },
        { "twofish-192/ofb", twofish192_ofb },
        { "twofish-256/ofb", twofish256_ofb },
        { "twofish-128/ctr", twofish128_ctr },
        { "twofish-192/ctr", twofish192_ctr },
        { "twofish-256/ctr", twofish256_ctr },
        { "twofish-128/gcm", twofish128_gcm },
        { "twofish-192/gcm", twofish192_gcm },
        { "twofish-256/gcm", twofish256_gcm },
    }, *cipher = &ciphers[0], *cipher_end = cipher + sizeof(ciphers) / sizeof(ciphers[0]);
    int err = EXIT_FAILURE;

    kryptos_task_init_as_null(ktask);

    while (cipher != cipher_end) {
        printf(">>> Running %s...\n", cipher->name);
        kryptos_task_set_in(ktask, message, message_size);
        print_buffer("\toriginal message: ", (char *)message, message_size);
        kryptos_task_set_encrypt_action(ktask);
        if (cipher->processor(&ktask, key, key_size) == EXIT_FAILURE) {
            printf("error: %s.\n", (ktask->result_verbose != NULL) ? ktask->result_verbose : "general failure.");
            goto epilogue;
        }
        print_buffer("\tciphertext: ", (char *)ktask->out, ktask->out_size);
        kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
        kryptos_task_set_decrypt_action(ktask);
        if (cipher->processor(&ktask, key, key_size) == EXIT_FAILURE) {
            printf("error: %s.\n", (ktask->result_verbose != NULL) ? ktask->result_verbose : "general failure.");
            goto epilogue;
        }
        print_buffer("\tplaintext: ", (char *)ktask->out, ktask->out_size);
        kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT | KRYPTOS_TASK_IV);
        cipher++;
        printf("<<< done.\n");
    }

    err = EXIT_SUCCESS;

epilogue:

    kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT | KRYPTOS_TASK_IV);

    return err;
}

static void print_buffer(const char *prefix, const char *buf, const size_t buf_size) {
    const char *bp = buf;
    const char *bp_end = bp + buf_size;
    if (prefix != NULL) {
        printf("%s", prefix);
    }
    if (bp != NULL) {
        while (bp != bp_end) {
            printf("%c", isprint(*bp) ? *bp : '.');
            bp++;
        }
        printf("\n");
    }
}

static int aes128_gcm(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(aes128, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosGCM);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int aes192_gcm(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(aes192, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosGCM);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int aes256_gcm(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(aes256, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosGCM);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int mars128_gcm(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(mars128, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosGCM);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int mars192_gcm(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(mars192, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosGCM);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int mars256_gcm(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(mars256, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosGCM);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int serpent_gcm(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(serpent, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosGCM);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int rc6_128_gcm(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    int rounds = 40;
    kryptos_run_cipher(rc6_128, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosGCM, &rounds);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int rc6_192_gcm(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    int rounds = 40;
    kryptos_run_cipher(rc6_192, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosGCM, &rounds);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int rc6_256_gcm(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    int rounds = 40;
    kryptos_run_cipher(rc6_256, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosGCM, &rounds);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int twofish128_gcm(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(twofish128, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosGCM);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int twofish192_gcm(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(twofish192, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosGCM);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int twofish256_gcm(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(twofish256, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosGCM);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int aes128_ecb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(aes128, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosECB);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int aes192_ecb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(aes192, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosECB);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int aes256_ecb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(aes256, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosECB);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int mars128_ecb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(mars128, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosECB);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int mars192_ecb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(mars192, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosECB);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int mars256_ecb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(mars256, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosECB);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int serpent_ecb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(serpent, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosECB);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int rc6_128_ecb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    int rounds = 40;
    kryptos_run_cipher(rc6_128, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosECB, &rounds);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int rc6_192_ecb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    int rounds = 40;
    kryptos_run_cipher(rc6_192, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosECB, &rounds);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int rc6_256_ecb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    int rounds = 40;
    kryptos_run_cipher(rc6_256, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosECB, &rounds);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int twofish128_ecb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(twofish128, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosECB);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int twofish192_ecb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(twofish192, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosECB);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int twofish256_ecb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(twofish256, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosECB);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int aes128_cbc(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(aes128, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosCBC);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int aes192_cbc(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(aes192, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosCBC);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int aes256_cbc(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(aes256, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosCBC);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int mars128_cbc(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(mars128, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosCBC);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int mars192_cbc(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(mars192, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosCBC);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int mars256_cbc(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(mars256, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosCBC);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int serpent_cbc(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(serpent, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosCBC);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int rc6_128_cbc(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    int rounds = 40;
    kryptos_run_cipher(rc6_128, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosCBC, &rounds);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int rc6_192_cbc(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    int rounds = 40;
    kryptos_run_cipher(rc6_192, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosCBC, &rounds);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int rc6_256_cbc(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    int rounds = 40;
    kryptos_run_cipher(rc6_256, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosCBC, &rounds);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int twofish128_cbc(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(twofish128, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosCBC);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int twofish192_cbc(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(twofish192, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosCBC);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int twofish256_cbc(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(twofish256, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosCBC);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int aes128_ofb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(aes128, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosOFB);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int aes192_ofb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(aes192, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosOFB);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int aes256_ofb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(aes256, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosOFB);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int mars128_ofb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(mars128, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosOFB);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int mars192_ofb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(mars192, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosOFB);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int mars256_ofb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(mars256, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosOFB);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int serpent_ofb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(serpent, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosOFB);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int rc6_128_ofb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    int rounds = 40;
    kryptos_run_cipher(rc6_128, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosOFB, &rounds);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int rc6_192_ofb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    int rounds = 40;
    kryptos_run_cipher(rc6_192, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosOFB, &rounds);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int rc6_256_ofb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    int rounds = 40;
    kryptos_run_cipher(rc6_256, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosOFB, &rounds);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int twofish128_ofb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(twofish128, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosOFB);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int twofish192_ofb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(twofish192, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosOFB);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int twofish256_ofb(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(twofish256, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosOFB);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int aes128_ctr(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(aes128, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosCTR);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int aes192_ctr(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(aes192, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosCTR);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int aes256_ctr(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(aes256, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosCTR);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int mars128_ctr(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(mars128, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosCTR);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int mars192_ctr(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(mars192, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosCTR);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int mars256_ctr(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(mars256, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosCTR);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int serpent_ctr(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(serpent, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosCTR);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int rc6_128_ctr(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    int rounds = 40;
    kryptos_run_cipher(rc6_128, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosCTR, &rounds);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int rc6_192_ctr(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    int rounds = 40;
    kryptos_run_cipher(rc6_192, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosCTR, &rounds);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int rc6_256_ctr(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    int rounds = 40;
    kryptos_run_cipher(rc6_256, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosCTR, &rounds);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int twofish128_ctr(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(twofish128, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosCTR);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int twofish192_ctr(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(twofish192, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosCTR);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int twofish256_ctr(kryptos_task_ctx **ktask, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_run_cipher(twofish256, (*ktask), (kryptos_u8_t *)key, key_size, kKryptosCTR);
    return (kryptos_last_task_succeed(*ktask)) ? EXIT_SUCCESS : EXIT_FAILURE;
}
