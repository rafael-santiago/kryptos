/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_TESTS_KERNEL_KASSERT_H
#define KRYPTOS_KRYPTOS_TESTS_KERNEL_KASSERT_H 1

#if defined(__FreeBSD__)

#define KUTE_ASSERT_CHECK(msg, chk) do {\
    if ((chk) == 0) {\
        uprintf("%s is false.\n", msg);\
        return 1;\
    }\
} while (0)

#elif defined(__linux__)

#define KUTE_ASSERT_CHECK(msg, chk) do {\
    if ((chk) == 0) {\
        printk(KERN_WARNING msg " is false.");\
        return 1;\
    }\
} while (0)

#endif

#define KUTE_ASSERT(chk) KUTE_ASSERT_CHECK(#chk, chk)

#endif
