/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_task_check.h>
#include <kryptos_des.h>

static int kryptos_task_check_cbc_params(kryptos_task_ctx **ktask);

int kryptos_task_check(kryptos_task_ctx **ktask) {
    if (ktask == NULL || *ktask == NULL) {
        return 0;
    }

    if ((*ktask)->key == NULL || (*ktask)->key_size == 0) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "Invalid key data.";
        goto kryptos_task_check_error;
    }

    if ((*ktask)->cipher < 0 || (*ktask)->cipher >= kKryptosCipherNr) {
        (*ktask)->result = kKryptosInvalidCipher;
        (*ktask)->result_verbose = "Invalid cipher.";
        goto kryptos_task_check_error;
    }

    if (( (*ktask)->cipher != kKryptosCipherARC4 &&
          (*ktask)->cipher != kKryptosCipherSEAL ) && (*ktask)->mode != kKryptosECB && (*ktask)->mode != kKryptosCBC) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "Invalid operation mode.";
        goto kryptos_task_check_error;
    }

    if (( (*ktask)->cipher != kKryptosCipherARC4 &&
          (*ktask)->cipher != kKryptosCipherSEAL ) && (*ktask)->mode == kKryptosCBC &&
        kryptos_task_check_cbc_params(ktask) == 0) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "Invalid iv data.";
        goto kryptos_task_check_error;
    }

    if (( (*ktask)->cipher != kKryptosCipherARC4 &&
          (*ktask)->cipher != kKryptosCipherSEAL ) &&
        (*ktask)->action != kKryptosEncrypt && (*ktask)->action != kKryptosDecrypt) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "Invalid task action.";
        goto kryptos_task_check_error;
    }

    if ((*ktask)->in == NULL || (*ktask)->in_size == 0) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "No input.";
        goto kryptos_task_check_error;
    }

kryptos_task_check_success:
    (*ktask)->result = kKryptosSuccess;
    (*ktask)->result_verbose = NULL;
    return 1;

kryptos_task_check_error:
    return 0;
}

static int kryptos_task_check_cbc_params(kryptos_task_ctx **ktask) {
    if ((*ktask)->iv == NULL || (*ktask)->iv_size == 0) {
        return 0;
    }

    switch ((*ktask)->cipher) {
        case kKryptosCipherDES:
            return ((*ktask)->iv_size == KRYPTOS_DES_BLOCKSIZE);
            break;
    }

    return 0;
}
