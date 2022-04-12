/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define DIGITS_NR 6
#define TIME_STEP 30
// INFO(Rafael): If you want to test it with your smartphone
//               by using "LastPass... Authenticator" or "Google
//               Authenticator" and stuff just add the following
//               base-32 encoded key:
//
//                      ONRWSZLOORUWC3DJMJSXEYLU
#define SHARED_SECRET (kryptos_u8_t *)"scientialiberat"
#define SHARED_SECRET_SIZE 15
#define T0 0

static int server(void);

static int client(void);

int main(int argc, char **argv) {
    int err = EXIT_FAILURE;
#if defined(KRYPTOS_C99)
    if (argc >= 2) {
        if (strcmp(argv[1], "--client") == 0) {
            err = client();
        } else if (strcmp(argv[1], "--server") == 0) {
            err = server();
        } else {
            goto usage;
        }
    } else {
usage:
        fprintf(stderr, "user: %s --client | --server\n", argv[0]);
    }
#else

    fprintf(stderr, "error: your kryptos build has no support for c99 conveniences.\n");
#endif

    return err;
}

static int client(void) {
    kryptos_task_ctx c, *client = &c;
    kryptos_u64_t t0 = 0;
    kryptos_u64_t x = TIME_STEP;
    size_t d = DIGITS_NR;
    kryptos_u8_t *shared_secret = SHARED_SECRET;
    size_t shared_secret_size = SHARED_SECRET_SIZE;
    int err = EXIT_FAILURE;

    if (kryptos_otp_init(totp,
                         client,
                         kKryptosGenerateToken,
                         shared_secret, shared_secret_size,
                         &t0, &x, &d, kryptos_otp_hash(sha1)) != kKryptosSuccess) {
        fprintf(stderr, "error: %s\n", (client->result_verbose != NULL) ? client->result_verbose
                                                                        : "Generic failure.");
        return EXIT_FAILURE;
    }

    if (kryptos_otp(totp, client) == kKryptosSuccess) {
        fprintf(stdout, "Your current token is '%06u'\n", *(kryptos_u32_t *)client->out);
        err = EXIT_SUCCESS;
    } else {
        fprintf(stderr, "error: %s\n", (client->result_verbose != NULL) ? client->result_verbose
                                                                        : "Generic failure.");
    }

    kryptos_otp_free_token(client);
    if (err == EXIT_SUCCESS) {
        kryptos_task_set_encode_action(client);
        kryptos_run_encoder(base32, client, shared_secret, shared_secret_size);
        if (kryptos_last_task_succeed(client)) {
            fprintf(stdout, "Try to add the following key to your 2FA favorite app: '");
            fwrite(client->out, 1, client->out_size, stdout);
            fprintf(stdout, "'.\n");
            kryptos_task_free(client, KRYPTOS_TASK_OUT);
        }
    }

    return err;
}

static int server(void) {
    kryptos_task_ctx s, *server = &s;
    kryptos_u64_t t0 = T0;
    kryptos_u64_t x = TIME_STEP;
    size_t d = DIGITS_NR;
    kryptos_u8_t *shared_secret = SHARED_SECRET;
    size_t shared_secret_size = SHARED_SECRET_SIZE;
    int err = EXIT_FAILURE;
    kryptos_u32_t token = 0;

    if (kryptos_otp_init(totp,
                         server,
                         kKryptosValidateToken,
                         shared_secret, shared_secret_size,
                         &t0, &x, &d, kryptos_otp_hash(sha1)) != kKryptosSuccess) {
        fprintf(stderr, "error: %s\n", (server->result_verbose != NULL) ? server->result_verbose
                                                                        : "Generic failure.");
        return EXIT_FAILURE;
    }

    fprintf(stderr, "Type the required token: ");
#if !defined(_MSC_VER)
    scanf("%d", &token);
#else
    scanf_s("%d", &token, sizeof(token));
#endif

    kryptos_otp_set_token(server, (kryptos_u8_t *)&token, sizeof(token));

    if (kryptos_otp(totp, server) == kKryptosSuccess) {
        fprintf(stdout, "Access granted.\n");
        err = EXIT_SUCCESS;
    } else {
        printf("error: %s\n", (server->result_verbose != NULL) ? server->result_verbose
                                                               : "Generic failure.");
    }

    return err;
}

#undef DIGITS_NR
#undef TIME_STEP
#undef SHARED_SECRET
#undef SHARED_SECRET_SIZE
#undef T0
