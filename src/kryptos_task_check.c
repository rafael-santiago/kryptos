/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_task_check.h>
#include <kryptos_des.h>
#include <kryptos_idea.h>
#include <kryptos_blowfish.h>
#include <kryptos_feal.h>
#include <kryptos_camellia.h>
#include <kryptos_cast5.h>
#include <kryptos_rc2.h>
#include <kryptos_saferk64.h>
#include <kryptos_aes.h>
#include <kryptos_serpent.h>
#include <kryptos_rsa.h>
#include <kryptos_pem.h>
#include <kryptos_memory.h>

static int kryptos_task_check_iv_data(kryptos_task_ctx **ktask);

static int kryptos_task_check_rsa_params(kryptos_task_ctx **ktask);

int kryptos_task_check(kryptos_task_ctx **ktask) {
    if (ktask == NULL || *ktask == NULL) {
        return 0;
    }

    if ((*ktask)->key == NULL || (*ktask)->key_size == 0) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "Invalid key data.";
        goto kryptos_task_check_error;
    }

    if ((*ktask)->cipher >= kKryptosCipherNr) {
        (*ktask)->result = kKryptosInvalidCipher;
        (*ktask)->result_verbose = "Invalid cipher.";
        goto kryptos_task_check_error;
    }

    if (( (*ktask)->cipher != kKryptosCipherARC4  &&
          (*ktask)->cipher != kKryptosCipherSEAL  &&
          (*ktask)->cipher != kKryptosCipherRSA ) && (*ktask)->mode != kKryptosECB  &&
                                                      (*ktask)->mode != kKryptosCBC &&
                                                      (*ktask)->mode != kKryptosOFB) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "Invalid operation mode.";
        goto kryptos_task_check_error;
    }

    if (( (*ktask)->cipher != kKryptosCipherARC4  &&
          (*ktask)->cipher != kKryptosCipherSEAL  &&
          (*ktask)->cipher != kKryptosCipherRSA ) && ((*ktask)->mode == kKryptosCBC || (*ktask)->mode == kKryptosOFB) &&
                                                                            kryptos_task_check_iv_data(ktask) == 0) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "Invalid iv data.";
        goto kryptos_task_check_error;
    }

    if (( (*ktask)->cipher != kKryptosCipherARC4   &&
          (*ktask)->cipher != kKryptosCipherSEAL ) &&
        (*ktask)->action != kKryptosEncrypt && (*ktask)->action != kKryptosDecrypt) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "Invalid task action.";
        goto kryptos_task_check_error;
    }

    if ((*ktask)->cipher == kKryptosCipherRSA) {
        if (kryptos_task_check_rsa_params(ktask) == 0) {
            goto kryptos_task_check_error;
        }
    }

    if ((*ktask)->in == NULL || (*ktask)->in_size == 0) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "No input.";
        goto kryptos_task_check_error;
    }

    (*ktask)->result = kKryptosSuccess;
    (*ktask)->result_verbose = NULL;
    return 1;

kryptos_task_check_error:
    return 0;
}

static int kryptos_task_check_iv_data(kryptos_task_ctx **ktask) {
    if ((*ktask)->iv == NULL || (*ktask)->iv_size == 0) {
        return 0;
    }

    switch ((*ktask)->cipher) {
        case kKryptosCipherDES:
        case kKryptosCipher3DES:
        case kKryptosCipher3DESEDE:
            return ((*ktask)->iv_size == KRYPTOS_DES_BLOCKSIZE);
            break;

        case kKryptosCipherIDEA:
            return ((*ktask)->iv_size == KRYPTOS_IDEA_BLOCKSIZE);
            break;

        case kKryptosCipherBLOWFISH:
            return ((*ktask)->iv_size == KRYPTOS_BLOWFISH_BLOCKSIZE);
            break;

        case kKryptosCipherFEAL:
            return ((*ktask)->iv_size == KRYPTOS_FEAL_BLOCKSIZE);
            break;

        case kKryptosCipherCAMELLIA:
            return ((*ktask)->iv_size == KRYPTOS_CAMELLIA_BLOCKSIZE);
            break;

        case kKryptosCipherCAST5:
            return ((*ktask)->iv_size == KRYPTOS_CAST5_BLOCKSIZE);
            break;

        case kKryptosCipherRC2:
            return ((*ktask)->iv_size == KRYPTOS_RC2_BLOCKSIZE);
            break;

        case kKryptosCipherSAFERK64:
            return ((*ktask)->iv_size == KRYPTOS_SAFERK64_BLOCKSIZE);
            break;

        case kKryptosCipherAES:
            return ((*ktask)->iv_size == KRYPTOS_AES_BLOCKSIZE);
            break;

        case kKryptosCipherSERPENT:
            return ((*ktask)->iv_size == KRYPTOS_SERPENT_BLOCKSIZE);
            break;

        default: // WARN(Rafael): Only to shut up the cumbersome compiler warning.
            break;
    }

    return 0;
}

static int kryptos_task_check_rsa_params(kryptos_task_ctx **ktask) {
    kryptos_u8_t *data = NULL;
    size_t dsize = 0;

    if ((*ktask)->key == NULL || (*ktask)->key_size == 0) {
        (*ktask)->result = kKryptosKeyError;
        (*ktask)->result_verbose = "RSA key not supplied.";
        return 0;
    }

    if ((*ktask)->action == kKryptosEncrypt) {
        data = kryptos_pem_get_data(KRYPTOS_RSA_PEM_HDR_PARAM_E, (*ktask)->key, (*ktask)->key_size, &dsize);
        if (data != NULL) {
            kryptos_freeseg(data);
            data = kryptos_pem_get_data(KRYPTOS_RSA_PEM_HDR_PARAM_N, (*ktask)->key, (*ktask)->key_size, &dsize);
        }

        if (data == NULL) {
            (*ktask)->result = kKryptosKeyError;
            (*ktask)->result_verbose = "RSA public key not supplied.";
            return 0;
        } else {
            kryptos_freeseg(data);
        }
    } else {
        data = kryptos_pem_get_data(KRYPTOS_RSA_PEM_HDR_PARAM_D, (*ktask)->key, (*ktask)->key_size, &dsize);
        if (data != NULL) {
            kryptos_freeseg(data);
            data = kryptos_pem_get_data(KRYPTOS_RSA_PEM_HDR_PARAM_N, (*ktask)->key, (*ktask)->key_size, &dsize);
        }

        if (data == NULL) {
            (*ktask)->result = kKryptosKeyError;
            (*ktask)->result_verbose = "RSA private key not supplied.";
            return 0;
        } else {
            kryptos_freeseg(data);
        }
    }

    return 1;
}
