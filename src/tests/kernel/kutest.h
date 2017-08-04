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

static int g_kutest_ran_tests = 0;

#define KUTE_ASSERT_CHECK(msg, chk) do {\
    if ((chk) == 0) {\
        uprintf("hmm bad, bad bug in %s at line %d: %s is false.\n", __FILE__, __LINE__, msg);\
        return 1;\
    }\
} while (0)

#define KUTE_RUN_TEST(test) do {\
    uprintf("-- running %s...\n", #test);\
    g_kutest_ran_tests++;\
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
    g_kutest_ran_tests++;\
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

#if defined(__FreeBSD__)

#define KUTE_MAIN(test)\
static int modld(struct module *module, int cmd, void *arg) {\
    int exit_code = 0;\
    switch (cmd) {\
        case MOD_LOAD:\
            uprintf("*** kryptos test module loaded...\n");\
            if ((exit_code = test()) == 0) {\
                uprintf("*** all tests passed. [%d test(s) ran]\n", g_kutest_ran_tests);\
            } else {\
                uprintf("fail: [%d test(s) ran]\n", g_kutest_ran_tests);\
            }\
            break;\
        case MOD_UNLOAD:\
            uprintf("*** kryptos test module unloaded\n");\
            break;\
        default:\
            exit_code = EOPNOTSUPP;\
            break;\
    }\
    return exit_code;\
}\
static moduledata_t test ## _mod = {\
    #test,\
    modld,\
    NULL\
};\
DECLARE_MODULE(test, test ## _mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);

#else

#endif

#endif
