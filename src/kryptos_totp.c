/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_totp.h>
#include <kryptos_hotp.h>
#include <kryptos_memory.h>
#include <kryptos.h>
#if !defined(KRYPTOS_KERNEL_MODE)
# if (defined(__unix__) && !defined(__NetBSD__)) || (defined(_WIN32) && defined(_MSC_VER))
#  include <time.h>
# endif
# include <errno.h>
#elif defined(__linux__)
# include <linux/timekeeping.h>
#elif defined(__FreeBSD__) || defined(__NetBSD__)
# include <sys/time.h>
#elif defined(_WIN32)
# define KRYPTOS_TOTP_WIN_UNIX_EPOCHS_DELTA_AS_WIN_EPOCH  0x019DB1DED53E8000
# define KRYPTOS_TOTP_SECS_IN_NS                                    10000000
#endif

#define KRYPTOS_TOTP_T0_PARAM           7
#define KRYPTOS_TOTP_X_PARAM            8
#define KRYPTOS_HOTP_C_PARAM            0
#define KRYPTOS_HOTP_T_PARAM            1
#define KRYPTOS_HOTP_s_PARAM            2

#if (defined(_WIN32) || defined(__NetBSD__)) && (defined(__GNUC__) || defined(__clang__))
 // TIP(Rafael): This algorithm is tough when testing because, we need to hook the time() call
 //              making it return the Unix time expected by each test case present in the RFC.
 //              MinGW does not handle properly the idea of considering the nearest defintion,
 //              since it will be packed into a '.a' at the link-time the time() call will not
 //              be resolved to the test hook (why? dunno). MSVC has the option of do not take
 //              into consideration the default CRT but MinGW is a little bit primitive in this
 //              subject AFAIK. This is the way I found to make my intentions extremelly clearer
 //              for ld and making it let me alone doing my stuff! ;)
 //
 //              Due to it, on Windows when using MinGW never ever include 'time.h' from here
 //              otherwise you will break TOTP validation tests.
 //
 //              Remark: the same for NetBSD.
 extern time_t time(time_t *);
#endif

static kryptos_task_result_t totp_get_curr_time(kryptos_u64_t *t);

kryptos_task_result_t kryptos_totp_init(kryptos_task_ctx *ktask,
                                        const kryptos_action_t action,
                                        kryptos_u8_t *shared_secret,
                                        const size_t shared_secret_size,
                                        kryptos_u64_t *initial_counter_time,
                                        kryptos_u64_t *time_step,
                                        size_t *number_of_digits,
                                        kryptos_hash_func h,
                                        kryptos_hash_size_func h_input_size,
                                        kryptos_hash_size_func h_size) {
    kryptos_task_result_t tr = kKryptosInvalidParams;
    kryptos_u64_t counter = 0;
    size_t throttling_param = 20;
    size_t resync_param = 6;

    if (ktask == NULL || initial_counter_time == NULL || time_step == NULL) {
        return kKryptosInvalidParams;
    }

    kryptos_task_init_as_null(ktask);

    tr = kryptos_hotp_init(ktask, action,
                           shared_secret, shared_secret_size,
                           &counter,
                           &throttling_param,
                           &resync_param,
                           number_of_digits,
                           h, h_input_size, h_size);

    if (tr == kKryptosSuccess) {
        ktask->arg[KRYPTOS_TOTP_T0_PARAM] = initial_counter_time;
        ktask->arg[KRYPTOS_TOTP_X_PARAM] = time_step;
        ktask->arg[KRYPTOS_HOTP_C_PARAM] = NULL;
        ktask->arg[KRYPTOS_HOTP_s_PARAM] = NULL;
        ktask->arg[KRYPTOS_HOTP_T_PARAM] = NULL;
    }

    return tr;
}

kryptos_task_result_t kryptos_totp(kryptos_task_ctx **ktask) {
    kryptos_u64_t c, timestamp = 0;
    kryptos_task_result_t tr = totp_get_curr_time(&timestamp);
    size_t ntry = 3;
    size_t resync = 0, throttling = 0;

    if (tr != kKryptosSuccess) {
        (*ktask)->result = tr;
        (*ktask)->result_verbose = "Unable to get current Unix time.";
        return tr;
    }

    // INFO(Rafael): Those are just bogus parameters since TOTP impose a time based resync.
    (*ktask)->arg[KRYPTOS_HOTP_s_PARAM] = &resync;
    (*ktask)->arg[KRYPTOS_HOTP_T_PARAM] = &throttling;

    do {
        resync = 1;
        throttling = 1;
        c = (ntry > 1) ? timestamp - *(kryptos_u64_t *)(*ktask)->arg[KRYPTOS_TOTP_T0_PARAM]
                       : timestamp + *(kryptos_u64_t *)(*ktask)->arg[KRYPTOS_TOTP_T0_PARAM];
        c /= *(kryptos_u64_t *)(*ktask)->arg[KRYPTOS_TOTP_X_PARAM];
        (*ktask)->arg[KRYPTOS_HOTP_C_PARAM] = &c;

        tr = kryptos_hotp(ktask);

        // INFO(Rafael): According to RFC, when validation has failed we can implement a
        //               tolerance window. According to this document on cases with X
        //               equals to 30 it is recommended a tolerance of two timestamps
        //               backward plus the current one. I will generalize it for
        //               whatever X value but we will try only one backward and one
        //               ahead.

        if (tr != kKryptosSuccess && (*ktask)->action == kKryptosValidateToken &&
            timestamp > *(kryptos_u64_t *)(*ktask)->arg[KRYPTOS_TOTP_X_PARAM]) {
            timestamp -= *(kryptos_u64_t *)(*ktask)->arg[KRYPTOS_TOTP_X_PARAM];
            ntry -= 1;
        }
    } while (tr != kKryptosSuccess && (*ktask)->action == kKryptosValidateToken &&
             timestamp > *(kryptos_u64_t *)(*ktask)->arg[KRYPTOS_TOTP_X_PARAM]  &&
             ntry > 0);

    (*ktask)->arg[KRYPTOS_HOTP_C_PARAM] = NULL;
    (*ktask)->arg[KRYPTOS_HOTP_s_PARAM] = NULL;
    (*ktask)->arg[KRYPTOS_HOTP_T_PARAM] = NULL;

    c = timestamp = 0;
    resync = throttling = 0;

    return tr;
}

static kryptos_task_result_t totp_get_curr_time(kryptos_u64_t *t) {
    kryptos_task_result_t tr = kKryptosSuccess;

#if !defined(KRYPTOS_KERNEL_MODE)
    *t = (kryptos_u64_t)time(NULL);

    if (*t == ((time_t)-1) && errno != 0) {
        tr = kKryptosProcessError;
    }
#elif defined(__linux__)
    *t = (kryptos_u64_t)ktime_get_real_seconds();
#elif defined(__FreeBSD__) || defined(__NetBSD__)
    struct timespec tsp;
    nanotime(&tsp);
    *t = (kryptos_u64_t)tsp.tv_sec;
    memset(&tsp, 0, sizeof(tsp));
#elif defined(_WIN32)
    LARGE_INTEGER curr_time = { 0 };
    KeQuerySystemTimePrecise(&curr_time);
    *t = (kryptos_u64_t)((curr_time.QuadPart -
                                KRYPTOS_TOTP_WIN_UNIX_EPOCHS_DELTA_AS_WIN_EPOCH) / KRYPTOS_TOTP_SECS_IN_NS);
    curr_time.QuadPart = 0;
#else
# error Some code wanted.
#endif

    return tr;
}

#undef KRYPTOS_TOTP_T0_PARAM
#undef KRYPTOS_TOTP_X_PARAM
#undef KRYPTOS_HOTP_C_PARAM
#undef KRYPTOS_HOTP_T_PARAM
#undef KRYPTOS_HOTP_s_PARAM

#if defined(KRYPTOS_KERNEL_MODE) && defined(_WIN32)
# undef KRYPTOS_TOTP_WIN_UNIX_EPOCHS_DELTA_AS_WIN_EPOCH
# undef KRYPTOS_TOTP_SECS_IN_NS
#endif
