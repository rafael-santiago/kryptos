/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <mod.h>

#ifdef __FreeBSD__

static moduledata_t kryptos_test_mod = {
    "kryptos_test_mod",
    modld,
    NULL
};

DECLARE_MODULE(kryptos_test, kryptos_test_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);

#else

# ifdef __linux__

# endif

#endif