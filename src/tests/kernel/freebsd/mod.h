/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_KERNEL_FREEBSD_MOD_H
#define KRYPTOS_TESTS_KERNEL_FREEBSD_MOD_H 1

#include <sys/cdefs.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>

int modld(struct module *module, int cmd, void *args);

#endif