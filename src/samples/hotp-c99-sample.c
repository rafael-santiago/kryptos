/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos.h>
#include <sys/stat.h>
#if !defined(_MSC_VER)
# include <unistd.h>
#else
# include <io.h>
# define read _read
# define write _write
#endif
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define HOTP_SAMPLE_COUNTER_FILE ".hotpct"

#define HOTP_SAMPLE_SHARED_SECRET "SingASimpleSong"

#define HOTP_SAMPLE_SHARED_SECRET_SIZE 15

static int server(void);

static int client(void);

static int read_counter_data(const char *counter_filepath, kryptos_u64_t *data);

static int write_counter_data(const char *counter_filepath, const kryptos_u64_t data);

int main(int argc, char **argv) {
    int err = EXIT_FAILURE;
#if defined(KRYPTOS_C99)
    if (argc > 1) {
        if (strcmp(argv[1], "--server") == 0) {
            err = server();
        } else if (strcmp(argv[1], "--client") == 0) {
            err = client();
        } else {
            goto main_usage;
        }
    } else {
main_usage:
        fprintf(stderr, "use: %s --server | --client\n", argv[0]);
    }
#else
    fprintf(stderr, "error: your kryptos build has no support for c99 conveniences.\n");
#endif
    return err;
}

static int server(void) {
    kryptos_u64_t counter = 0;
    int err = EXIT_FAILURE;
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u32_t token = 0;
    size_t number_of_digits = 6;
    size_t resync = 5;
    size_t throttling = 10 * resync;

    kryptos_task_init_as_null(ktask);

    if ((err = read_counter_data(HOTP_SAMPLE_COUNTER_FILE, &counter))  != EXIT_SUCCESS) {
        fprintf(stderr, "error: unable to read counter file (%s).\n", HOTP_SAMPLE_COUNTER_FILE);
        goto server_epilogue;
    }

    if (kryptos_otp_init(hotp, ktask, kKryptosValidateToken,
                         (kryptos_u8_t *)HOTP_SAMPLE_SHARED_SECRET, HOTP_SAMPLE_SHARED_SECRET_SIZE,
                         &counter, &throttling, &resync, &number_of_digits,
                         kryptos_otp_hash(sha384)) != kKryptosSuccess) {
        fprintf(stderr, "error: %s\n",
                            (ktask->result_verbose != NULL) ? ktask->result_verbose
                                                            : "during HOTP initialising.");
        goto server_epilogue;
    }

    do {
        fprintf(stderr, "Type the required token: ");
#if !defined(_MSC_VER)
        scanf("%d", &token);
#else
        scanf_s("%d", &token, sizeof(token));
#endif
        ktask->in = (kryptos_u8_t *)&token;
        ktask->in_size = sizeof(token);
        kryptos_otp(hotp, ktask);
    } while (throttling != 0 && ktask->result != kKryptosSuccess);

    if (kryptos_last_task_succeed(ktask)) {
        fprintf(stdout, "info: the token was successfully validated.\n");
        err = write_counter_data(HOTP_SAMPLE_COUNTER_FILE, counter);
    } else {
        fprintf(stdout, "error: %s\n", (ktask->result_verbose != NULL) ?
                      ktask->result_verbose : "max attempts exceeded.");
    }

server_epilogue:

    return err;
}

static int client(void) {
    kryptos_u64_t counter = 0;
    int err = EXIT_FAILURE;
    kryptos_task_ctx t, *ktask = &t;
    size_t number_of_digits = 6;

    kryptos_task_init_as_null(ktask);

    if ((err = read_counter_data(HOTP_SAMPLE_COUNTER_FILE, &counter)) != EXIT_SUCCESS) {
        fprintf(stderr, "error: unbale to read counter file (%s).\n", HOTP_SAMPLE_COUNTER_FILE);
        goto client_epilogue;
    }

    if (kryptos_otp_init(hotp, ktask, kKryptosGenerateToken,
                         (kryptos_u8_t *)HOTP_SAMPLE_SHARED_SECRET, HOTP_SAMPLE_SHARED_SECRET_SIZE,
                         &counter, NULL, NULL, &number_of_digits,
                         kryptos_otp_hash(sha384)) != kKryptosSuccess) {
        fprintf(stderr, "error: %s\n",
                    (ktask->result_verbose != NULL) ? ktask->result_verbose
                                                    : "during HOTP initalising.");
        goto client_epilogue;
    }

    kryptos_otp(hotp, ktask);
    if (kryptos_last_task_succeed(ktask)) {
        fprintf(stdout, "info: your token is '%d'.\n", *(kryptos_u32_t *)ktask->out);
        err = EXIT_SUCCESS;
    } else {
        fprintf(stderr, "error: %s\n",
                (ktask->result_verbose != NULL) ? ktask->result_verbose
                                                : "unbale to generate a token.");
    }

client_epilogue:

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    return err;
}

static int read_counter_data(const char *counter_filepath, kryptos_u64_t *data) {
    int fd = -1;
    struct stat st;
    int err = EXIT_FAILURE;

    if (counter_filepath == NULL || data == NULL) {
        return EXIT_FAILURE;
    }

    if (stat(counter_filepath, &st) != 0) {
        *data = 0;
        return EXIT_SUCCESS;
    }

#if !defined(_MSC_VER)
    if ((fd = open(counter_filepath, O_RDONLY)) == -1) {
        fprintf(stderr, "error: unable to open counter file.\n");
        return EXIT_FAILURE;
    }
#else
    if (_sopen_s(&fd, counter_filepath, O_RDONLY, _SH_DENYWR, _S_IREAD) != 0) {
        fprintf(stderr, "error: unable to open counter file.\n");
        return EXIT_FAILURE;
    }
#endif

    if (read(fd, data, sizeof(kryptos_u64_t)) == -1) {
        fprintf(stderr, "error: unable to read counter data.\n");
        goto read_counter_data_epilogue;
    }

    err = EXIT_SUCCESS;

read_counter_data_epilogue:

    if (fd > -1) {
#if !defined(_MSC_VER)
        close(fd);
#else
        _close(fd);
#endif
    }

    return err;
}

static int write_counter_data(const char *counter_filepath, const kryptos_u64_t data) {
    int fd = -1;
    int err = EXIT_FAILURE;
#if !defined(_MSC_VER)
    if ((fd = open(counter_filepath, O_WRONLY | O_CREAT | S_IRUSR | S_IWUSR)) == -1) {
        fprintf(stderr, "error: unable to open counter file.\n");
        return EXIT_SUCCESS;
    }
#else
    if (_sopen_s(&fd, counter_filepath, O_WRONLY | O_CREAT, _SH_DENYNO, _S_IREAD | _S_IWRITE) != 0) {
        fprintf(stderr, "error: unable to open counter file.\n");
        return EXIT_SUCCESS;
    }
#endif
    if (write(fd, &data, sizeof(kryptos_u64_t)) == -1) {
        fprintf(stderr, "error: unable to write counter data.\n");
        goto write_counter_data_epilogue;
    }

    err = EXIT_SUCCESS;

write_counter_data_epilogue:

    if (fd > -1) {
#if !defined(_MSC_VER)
        close(fd);
#else
        _close(fd);
#endif
    }

    return err;
}

#undef HOTP_SAMPLE_COUNTER_FILE

#undef HOTP_SAMPLE_SHARED_SECRET

#undef HOTP_SAMPLE_SHARED_SECRET_SIZE

#if defined(_MSC_VER)
# undef read
# undef write
#endif
