/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_USERLAND_FUNCS_H
#define KRYPTOS_KRYPTOS_USERLAND_FUNCS_H 1

#include <kryptos_types.h>

#if defined(KRYPTOS_KERNEL_MODE) && !defined(__NetBSD__)
# define isdigit(d) ( (d) >= '0' && (d) <= '9' )
  kryptos_u8_t toupper(const kryptos_u8_t c);
#endif

# if memcmp != kryptos_memcmp
# warning Timing attacks are not being mitigated.
#endif

// INFO(Rafael): Depending on the compiler flag (as instance -O) the compiler will
//               strip off memset calls at the end of the function. In this case, the
//               memset call is for cleanup issues and must be done. Using the following
//               scheme (define a macro called 'memset' that is replaced to 'kryptos_memset'
//                       a.k.a. the libraries' local memset implementation) is possible to
//               keep the 'cleanup memset' even with the -O optimizing flag. If you have
//               doubts, try to inspect the final assembly on your own, it also would be
//               prudent since the compiler heuristics can change. Anyway, the build is doing
//               it for you by default and it will break if some memset is found.
# if memset != kryptos_memset
# warning Memset calls used in cleanups are not being ensured.
#endif

#endif
