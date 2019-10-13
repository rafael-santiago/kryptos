/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_memory.h>
#if defined(KRYPTOS_USER_MODE) && !defined(_WIN32)
# include <sys/mman.h>
# if !defined(__linux__)
#  include <unistd.h>
# endif
#endif
#if defined(_WIN32)
# include <windows.h>
#endif

#if defined(KRYPTOS_DATA_WIPING_WHEN_FREEING_MEMORY_FREAK_PARANOID_PERSON)
# include <kryptos_random.h>
# if !defined(KRYPTOS_DATA_WIPING_WHEN_FREEING_MEMORY)
# define KRYPTOS_DATA_WIPING_WHEN_FREEING_MEMORY 1
# endif
#endif

#if !defined(KRYPTOS_DATA_WIPING_WHEN_FREEING_MEMORY)
# warning No data wiping is being applied when freeing memory.
#endif

#if defined(KRYPTOS_USER_MODE)
# include <stdio.h>
# include <unistd.h>
# include <string.h>
#elif defined(KRYPTOS_KERNEL_MODE) && (defined(__FreeBSD__) || defined(__NetBSD__))
  MALLOC_DECLARE(M_KRYPTOS);
  MALLOC_DEFINE(M_KRYPTOS, "kryptos_general_memory_buffer", "buffer allocated by libkryptos");
#endif // KRYPTOS_USER_MODE

#if defined(KRYPTOS_USER_MODE)
static int g_kryptos_memory_avoid_ram_swap = 0;
#endif

#if defined(KRYPTOS_USER_MODE)

void kryptos_avoid_ram_swap(void) {
    g_kryptos_memory_avoid_ram_swap = 1;
}

void kryptos_allow_ram_swap(void) {
    g_kryptos_memory_avoid_ram_swap = 0;
}

#endif

void *kryptos_newseg(const size_t ssize) {
    void *segment;
#ifdef KRYPTOS_USER_MODE
# if !defined(_WIN32) && !defined(__minix__)
    size_t offset = 0;
# endif
    segment = malloc(ssize);
    /*if (segment == NULL) {
        fprintf(stderr, "kryptos panic: no memory!\n");
    }*/
#elif defined(__FreeBSD__) || defined(__NetBSD__)
    segment = malloc(ssize, M_KRYPTOS, M_NOWAIT);
#elif defined(__linux__)
    segment = kmalloc(ssize, GFP_ATOMIC);
#else
    segment = NULL;
#endif

#if defined(KRYPTOS_USER_MODE) && !defined(_WIN32)

# if !defined(__minix__)
    if (g_kryptos_memory_avoid_ram_swap && segment != NULL) {
#  if !defined(__linux__) && !defined(_WIN32)
        //INFO(Rafael): The lock address must be page aligned.
        offset = (size_t)segment % sysconf(_SC_PAGE_SIZE);
#  endif
        if (mlock(segment - offset, ssize + offset) != 0) {
            perror("libkryptos/mlock()");
            // INFO(Rafael): If we cannot ensure the swap avoidance it is better to return a NULL segment.
            kryptos_freeseg(segment, ssize);
            segment = NULL;
        }
    }
# endif
#elif defined(KRYPTOS_USER_MODE) && defined(_WIN32)

    if (g_kryptos_memory_avoid_ram_swap && segment != NULL) {
        if (VirtualLock(segment, ssize) == 0) {
            perror("libkryptos/VirtualLock()");
            // INFO(Rafael): If we cannot ensure the swap avoidance it is better to return a NULL segment.
            kryptos_freeseg(segment, ssize);
            segment = NULL;
        }
    }
#endif

    return segment;
}

void kryptos_freeseg(void *seg, const size_t ssize) {
#if defined(KRYPTOS_DATA_WIPING_WHEN_FREEING_MEMORY_FREAK_PARANOID_PERSON)
    kryptos_u8_t *bp, *bp_end;
    size_t n;
#endif
#if defined(KRYPTOS_USER_MODE) && !defined(_WIN32) && !defined(__minix__)
    size_t offset = 0;
#endif
    if (seg != NULL) {
        if (ssize > 0) {
#if !defined(KRYPTOS_DATA_WIPING_WHEN_FREEING_MEMORY)
            memset(seg, 0, ssize);
#else
            memset(seg, 255, ssize);
            memset(seg, 0, ssize);
# if defined(KRYPTOS_DATA_WIPING_WHEN_FREEING_MEMORY_FREAK_PARANOID_PERSON)
            // WARN(Rafael): It slow down a bunch the library, however, if you can wait and you are this kind of person,
            //               I would recommend you to define this long macro when building this library.
            n = 5;
            while (n-- > 0) {
                bp = (kryptos_u8_t *)seg;
                bp_end = bp + ssize;
                while (bp != bp_end) {
                    *bp = kryptos_get_random_byte();
                    bp++;
                }
            }
# endif
#endif
        }

#if defined(KRYPTOS_USER_MODE) && !defined(_WIN32) && !defined(__minix__)
    offset = (size_t)seg % sysconf(_SC_PAGE_SIZE);
    if (g_kryptos_memory_avoid_ram_swap && ssize > 0) {
        munlock(seg - offset, ssize + offset);
    }
#elif defined(KRYPTOS_USER_MODE) && defined(_WIN32)
    // INFO(Rafael): Since the lock is page oriented. It is better hold it in memory
    //               until process exits otherwise is possible unlock another locked
    //               regions. By now we will not unlock anything.
    //if (g_kryptos_memory_avoid_ram_swap && ssize > 0) {
    //    VirtualUnlock(seg, ssize);
    //}
#endif

#if defined(KRYPTOS_USER_MODE)
        free(seg);
#elif defined(KRYPTOS_KERNEL_MODE) && (defined(__FreeBSD__) || defined(__NetBSD__))
        free(seg, M_KRYPTOS);
#elif defined(KRYPTOS_KERNEL_MODE) && defined(__linux__)
        kfree(seg);
#endif
    }
}

void *kryptos_realloc(void *addr, const size_t ssize) {
#if defined(KRYPTOS_USER_MODE)
# if defined(_WIN32)
    return realloc(addr, ssize);
# else
    void *new_area = realloc(addr, ssize);
    if (g_kryptos_memory_avoid_ram_swap) {
//#  if !defined(__linux__) && !defined(__FreeBSD__)
        //INFO(Rafael): The lock address must be page aligned.
//#  endif
#  if !defined(__minix__)
        if (mlock(new_area, ssize) != 0) {
            perror("libkryptos/mlock()");
            // INFO(Rafael): If we cannot ensure the swap avoidance it is better to return a NULL segment.
            kryptos_freeseg(new_area, ssize);
            new_area = NULL;
        }
    }
#  endif
    return new_area;
# endif
#elif defined(KRYPTOS_KERNEL_MODE) && (defined(__FreeBSD__) || defined(__NetBSD__))
    return realloc(addr, ssize, M_KRYPTOS, M_NOWAIT);
#elif defined(KRYPTOS_KERNEL_MODE) && defined(__linux__)
    return krealloc(addr, ssize, GFP_ATOMIC);
#else
    return NULL;
#endif
}
