/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <mod.h>
#include <ktests.h>

int modld(struct module *module, int cmd, void *arg) {
    int exit_code = 0;

    switch (cmd) {
        case MOD_LOAD:
            uprintf("*** kryptos test module loaded...\n");
            exit_code = ktest_monkey();
            break;

        case MOD_UNLOAD:
            uprintf("*** kryptos test module unloaded\n");
            break;

        default:
            exit_code = EOPNOTSUPP;
            break;
    }

    return exit_code;
}
