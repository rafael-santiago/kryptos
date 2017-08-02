/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_TESTS_KERNEL_KUTEST_H
#define KRYPTOS_KRYPTOS_TESTS_KERNEL_KUTEST_H 1

#if defined(__FreeBSD__)

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/libkern.h>

#define KUTE_ASSERT_CHECK(msg, chk) do {\
    if ((chk) == 0) {\
        uprintf("hmm bad, bad bug in %s at line %d: %s is false.\n", __FILE__, __LINE__, msg);\
        return 1;\
    }\
} while (0)

#define KUTE_RUN_TEST(test) do {\
    uprintf("-- running %s...\n", #test);\
    if (test() != 0) {\
        return 1;\
    }\
    uprintf("-- passed.\n");\
} while (0)

#elif defined(__linux__)

#define KUTE_ASSERT_CHECK(msg, chk) do {\
    if ((chk) == 0) {\
        printk(KERN_WARNING msg " is false.");\
        return 1;\
    }\
} while (0)

#define KUTE_RUN_TEST(test) do {\
    printk(KERN_WARNING "-- running " #test "...\n");\
    if (test() != 0) {\
        return 1;\
    }\
    printk(KERN_WARNING "-- passed.\n");\
} while (0)

#endif

#define KUTE_ASSERT(chk) KUTE_ASSERT_CHECK(#chk, chk)

#define KUTE_TEST_CASE(test) int test(void) {

#define KUTE_TEST_CASE_END      return 0;\
                           }

#define KUTE_DECLARE_TEST_CASE(test) int test(void)

#endif
