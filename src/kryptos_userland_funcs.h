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

#if defined(KRYPTOS_MITIGATE_TIMING_ATTACKS)
  // INFO(Rafael): Since the linker uses the nearest symbol definition, we can easily overwrite the
  //               memcmp calls without replacing the previous references.
  int memcmp(const void *s1, const void *s2, size_t n);
#else
# warning Timing attacks are not being mitigated.
#endif

#if defined(KRYPTOS_ENSURE_MEMSET_CLEANUPS)
  // TODO(Rafael): Unstable, find a clean way of doing it but that works! :-\
  void *kryptos_memset(void *s, int c, size_t n);
  void * (volatile *memset)(void *, int, size_t) = kryptos_memset;
#else
# warning Memset calls used in cleanups are not being ensured.
#endif

#endif
