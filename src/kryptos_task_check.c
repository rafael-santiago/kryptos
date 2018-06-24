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
#include <kryptos_rc5.h>
#include <kryptos_rc6.h>
#include <kryptos_saferk64.h>
#include <kryptos_aes.h>
#include <kryptos_serpent.h>
#include <kryptos_tea.h>
#include <kryptos_xtea.h>
#include <kryptos_misty1.h>
#include <kryptos_mars.h>
#include <kryptos_present.h>
#include <kryptos_shacal1.h>
#include <kryptos_shacal2.h>
#include <kryptos_noekeon.h>
#include <kryptos_gost.h>
#include <kryptos_rabbit.h>
#include <kryptos_rsa.h>
#include <kryptos_elgamal.h>
#include <kryptos_dsa.h>
#include <kryptos_pem.h>
#include <kryptos_memory.h>

static int kryptos_task_check_iv_data(kryptos_task_ctx **ktask);

static int kryptos_task_check_rsa_params(kryptos_task_ctx **ktask);

static int kryptos_task_check_rsa_oaep_additional_params(kryptos_task_ctx **ktask);

static int kryptos_task_check_elgamal_params(kryptos_task_ctx **ktask);

static int kryptos_task_check_sign_rsa(kryptos_task_ctx **ktask);

static int kryptos_task_check_verify_rsa(kryptos_task_ctx **ktask);

static int kryptos_task_check_rsa_emsa_pss_additional_params(kryptos_task_ctx **ktask);

static int kryptos_task_check_sign_dsa(kryptos_task_ctx **ktask);

static int kryptos_task_check_verify_dsa(kryptos_task_ctx **ktask);

static int kryptos_task_check_dsa_domain_params(kryptos_task_ctx **ktask);

// WARN(Rafael): If you have changed something in RSA-OAEP additional parameters maybe should be better to implement a
//               separated function to verify the additional parameters of Elgamal-OAEP.

#define kryptos_task_check_elgamal_oaep_additional_params(ktask) kryptos_task_check_rsa_oaep_additional_params(ktask)

#define kryptos_task_check_basic_input_and_key_checks(ktask, escape_stmt) {\
    if ((*ktask)->in == NULL || (*ktask)->in_size == 0) {\
        (*ktask)->result = kKryptosInvalidParams;\
        (*ktask)->result_verbose = "No input.";\
        escape_stmt;\
    }\
    if ((*ktask)->key == NULL || (*ktask)->key_size == 0) {\
        (*ktask)->result = kKryptosKeyError;\
        (*ktask)->result_verbose = "NULL key.";\
        escape_stmt;\
    }\
}

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

    if (( (*ktask)->cipher != kKryptosCipherARC4        &&
          (*ktask)->cipher != kKryptosCipherSEAL        &&
          (*ktask)->cipher != kKryptosCipherRABBIT      &&
          (*ktask)->cipher != kKryptosCipherRSA         &&
          (*ktask)->cipher != kKryptosCipherRSAOAEP     &&
          (*ktask)->cipher != kKryptosCipherELGAMAL     &&
          (*ktask)->cipher != kKryptosCipherELGAMALOAEP   ) && (*ktask)->mode != kKryptosECB  &&
                                                               (*ktask)->mode != kKryptosCBC  &&
                                                               (*ktask)->mode != kKryptosOFB  &&
                                                               (*ktask)->mode != kKryptosCTR) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "Invalid operation mode.";
        goto kryptos_task_check_error;
    }

    // INFO(Rafael): When the used stream cipher is RABBIT we can check the iv (if supplied).

    if (( (*ktask)->cipher != kKryptosCipherARC4    &&
          (*ktask)->cipher != kKryptosCipherSEAL    &&
          (*ktask)->cipher != kKryptosCipherRSA     &&
          (*ktask)->cipher != kKryptosCipherRSAOAEP &&
          (*ktask)->cipher != kKryptosCipherELGAMAL ) && ( (*ktask)->mode == kKryptosCBC ||
                                                           (*ktask)->mode == kKryptosOFB ||
                                                           (*ktask)->mode == kKryptosCTR ||
                                                           (*ktask)->cipher == kKryptosCipherRABBIT) &&
                                                              kryptos_task_check_iv_data(ktask) == 0) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "Invalid iv data.";
        goto kryptos_task_check_error;
    }

    if (( (*ktask)->cipher != kKryptosCipherARC4   &&
          (*ktask)->cipher != kKryptosCipherSEAL   &&
          (*ktask)->cipher != kKryptosCipherRABBIT   ) &&
        (*ktask)->action != kKryptosEncrypt && (*ktask)->action != kKryptosDecrypt &&
        (*ktask)->action != kKryptosEncryptWithoutRandomPad) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "Invalid task action.";
        goto kryptos_task_check_error;
    }

    if ((*ktask)->cipher == kKryptosCipherRSA || (*ktask)->cipher == kKryptosCipherRSAOAEP) {
        if (kryptos_task_check_rsa_params(ktask) == 0) {
            goto kryptos_task_check_error;
        }

        if ((*ktask)->cipher == kKryptosCipherRSAOAEP && kryptos_task_check_rsa_oaep_additional_params(ktask) == 0) {
            goto kryptos_task_check_error;
        }
    } else if ((*ktask)->cipher == kKryptosCipherELGAMAL || (*ktask)->cipher == kKryptosCipherELGAMALOAEP) {
        if (kryptos_task_check_elgamal_params(ktask) == 0) {
            goto kryptos_task_check_error;
        }

        if ((*ktask)->cipher == kKryptosCipherELGAMALOAEP && kryptos_task_check_elgamal_oaep_additional_params(ktask) == 0) {
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

int kryptos_task_check_sign(kryptos_task_ctx **ktask) {
    if (ktask == NULL || *ktask == NULL) {
        return 0;
    }

    switch ((*ktask)->cipher) {
        case kKryptosCipherRSA:
        case kKryptosCipherRSAEMSAPSS:
            return kryptos_task_check_sign_rsa(ktask);

        case kKryptosCipherDSA:
            return kryptos_task_check_sign_dsa(ktask);

        default:
            (*ktask)->result = kKryptosInvalidParams;
            (*ktask)->result_verbose = "Invalid algorithm.";
            break;
    }

    return 0;
}

static int kryptos_task_check_sign_rsa(kryptos_task_ctx **ktask) {

    kryptos_u8_t *data = NULL;
    size_t data_size = 0;

    kryptos_task_check_basic_input_and_key_checks(ktask, goto kryptos_task_check_sign_rsa_error);

    switch ((*ktask)->cipher) {
        case kKryptosCipherRSA:
        case kKryptosCipherRSAEMSAPSS:
            data = kryptos_pem_get_data(KRYPTOS_RSA_PEM_HDR_PARAM_D, (*ktask)->key, (*ktask)->key_size, &data_size);

            if (data == NULL || data_size == 0) {
                (*ktask)->result = kKryptosKeyError;
                (*ktask)->result_verbose = "Invalid RSA private key.";
                goto kryptos_task_check_sign_rsa_error;
            }

            kryptos_freeseg(data, data_size);
            data_size = 0;

            data = kryptos_pem_get_data(KRYPTOS_RSA_PEM_HDR_PARAM_N, (*ktask)->key, (*ktask)->key_size, &data_size);

            if (data == NULL || data_size == 0) {
                (*ktask)->result = kKryptosKeyError;
                (*ktask)->result_verbose = "Invalid RSA private key.";
                goto kryptos_task_check_sign_rsa_error;
            }

            kryptos_freeseg(data, data_size);
            data = NULL;
            break;

        default:
            (*ktask)->result = kKryptosInvalidParams;
            (*ktask)->result_verbose = "Invalid algorithm.";
            goto kryptos_task_check_sign_rsa_error;
    }

    (*ktask)->result = kKryptosSuccess;
    (*ktask)->result_verbose = NULL;

    return ((*ktask)->cipher == kKryptosCipherRSA) ? 1 : kryptos_task_check_rsa_emsa_pss_additional_params(ktask);

kryptos_task_check_sign_rsa_error:

    if (data != NULL) {
        kryptos_freeseg(data, data_size);
    }

    data_size = 0;

    return 0;
}

int kryptos_task_check_verify(kryptos_task_ctx **ktask) {
    // CLUE(Rafael): Keep reading the code and you will discover the standard meaning of the jargon "verify"
    //               in Cryptology.

    if (ktask == NULL || *ktask == NULL) {
        return 0;
    }

    switch ((*ktask)->cipher) {
        case kKryptosCipherRSA:
        case kKryptosCipherRSAEMSAPSS:
            return kryptos_task_check_verify_rsa(ktask);

        case kKryptosCipherDSA:
            return kryptos_task_check_verify_dsa(ktask);

        default:
            (*ktask)->result = kKryptosInvalidParams;
            (*ktask)->result_verbose = "Invalid algorithm.";
            break;
    }

    return 0;
}

static int kryptos_task_check_verify_rsa(kryptos_task_ctx **ktask) {
    kryptos_u8_t *data = NULL;
    size_t data_size = 0;

    kryptos_task_check_basic_input_and_key_checks(ktask, goto kryptos_task_check_verify_rsa_error);

    switch ((*ktask)->cipher) {
        case kKryptosCipherRSA:
        case kKryptosCipherRSAEMSAPSS:
            data = kryptos_pem_get_data(KRYPTOS_RSA_PEM_HDR_PARAM_E, (*ktask)->key, (*ktask)->key_size, &data_size);

            if (data == NULL || data_size == 0) {
                (*ktask)->result = kKryptosKeyError;
                (*ktask)->result_verbose = "Invalid RSA public key.";
                goto kryptos_task_check_verify_rsa_error;
            }

            kryptos_freeseg(data, data_size);
            data = NULL;
            data_size = 0;

            data = kryptos_pem_get_data(KRYPTOS_RSA_PEM_HDR_PARAM_N, (*ktask)->key, (*ktask)->key_size, &data_size);

            if (data == NULL || data_size == 0) {
                (*ktask)->result = kKryptosKeyError;
                (*ktask)->result_verbose = "Invalid RSA public key.";
                goto kryptos_task_check_verify_rsa_error;
            }

            kryptos_freeseg(data, data_size);
            data = NULL;
            break;

        default:
            (*ktask)->result = kKryptosInvalidParams;
            (*ktask)->result_verbose = "Invalid algorithm.";
            goto kryptos_task_check_verify_rsa_error;
    }

    (*ktask)->result = kKryptosSuccess;
    (*ktask)->result_verbose = NULL;

    return ((*ktask)->cipher == kKryptosCipherRSA) ? 1 : kryptos_task_check_rsa_emsa_pss_additional_params(ktask);

kryptos_task_check_verify_rsa_error:

    if (data != NULL) {
        kryptos_freeseg(data, data_size);
    }

    data_size = 0;

    return 0;
}

static int kryptos_task_check_iv_data(kryptos_task_ctx **ktask) {
    if (((*ktask)->iv == NULL || (*ktask)->iv_size == 0) && (*ktask)->cipher != kKryptosCipherRABBIT) {
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

        case kKryptosCipherRC5:
            return ((*ktask)->iv_size == KRYPTOS_RC5_BLOCKSIZE);
            break;

        case kKryptosCipherRC6128:
        case kKryptosCipherRC6192:
        case kKryptosCipherRC6256:
            return ((*ktask)->iv_size == KRYPTOS_RC6_BLOCKSIZE);
            break;

        case kKryptosCipherSAFERK64:
            return ((*ktask)->iv_size == KRYPTOS_SAFERK64_BLOCKSIZE);
            break;

        case kKryptosCipherTEA:
            return ((*ktask)->iv_size == KRYPTOS_TEA_BLOCKSIZE);
            break;

        case kKryptosCipherXTEA:
            return ((*ktask)->iv_size == KRYPTOS_XTEA_BLOCKSIZE);
            break;

        case kKryptosCipherAES128:
        case kKryptosCipherAES192:
        case kKryptosCipherAES256:
            return ((*ktask)->iv_size == KRYPTOS_AES_BLOCKSIZE);
            break;

        case kKryptosCipherSERPENT:
            return ((*ktask)->iv_size == KRYPTOS_SERPENT_BLOCKSIZE);
            break;

        case kKryptosCipherMISTY1:
            return ((*ktask)->iv_size == KRYPTOS_MISTY1_BLOCKSIZE);
            break;

        case kKryptosCipherMARS128:
        case kKryptosCipherMARS192:
        case kKryptosCipherMARS256:
            return ((*ktask)->iv_size == KRYPTOS_MARS_BLOCKSIZE);
            break;

        case kKryptosCipherPRESENT:
            return ((*ktask)->iv_size == KRYPTOS_PRESENT_BLOCKSIZE);
            break;

        case kKryptosCipherSHACAL1:
            return ((*ktask)->iv_size == KRYPTOS_SHACAL1_BLOCKSIZE);
            break;

        case kKryptosCipherSHACAL2:
            return ((*ktask)->iv_size == KRYPTOS_SHACAL2_BLOCKSIZE);
            break;

        case kKryptosCipherNOEKEON:
        case kKryptosCipherNOEKEOND:
            return ((*ktask)->iv_size == KRYPTOS_NOEKEON_BLOCKSIZE);
            break;

        case kKryptosCipherGOST:
            return ((*ktask)->iv_size == KRYPTOS_GOST_BLOCKSIZE);
            break;

        case kKryptosCipherRABBIT:
            return (((*ktask)->iv == NULL && (*ktask)->iv_size == 0) ||
                    (*ktask)->iv_size == (KRYPTOS_RABBIT_BLOCKSIZE >> 1));
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
            kryptos_freeseg(data, dsize);
            dsize = 0;
            data = kryptos_pem_get_data(KRYPTOS_RSA_PEM_HDR_PARAM_N, (*ktask)->key, (*ktask)->key_size, &dsize);
        }

        if (data == NULL) {
            (*ktask)->result = kKryptosKeyError;
            (*ktask)->result_verbose = "RSA public key not supplied.";
            return 0;
        } else {
            kryptos_freeseg(data, dsize);
        }
    } else {
        data = kryptos_pem_get_data(KRYPTOS_RSA_PEM_HDR_PARAM_D, (*ktask)->key, (*ktask)->key_size, &dsize);
        if (data != NULL) {
            kryptos_freeseg(data, dsize);
            dsize = 0;
            data = kryptos_pem_get_data(KRYPTOS_RSA_PEM_HDR_PARAM_N, (*ktask)->key, (*ktask)->key_size, &dsize);
        }

        if (data == NULL) {
            (*ktask)->result = kKryptosKeyError;
            (*ktask)->result_verbose = "RSA private key not supplied.";
            return 0;
        } else {
            kryptos_freeseg(data, dsize);
            dsize = 0;
        }
    }

    return 1;
}

static int kryptos_task_check_rsa_oaep_additional_params(kryptos_task_ctx **ktask) {
    // CLUE(Rafael): arg[0] must hold the label pointer.
    //               arg[1] must hold the label_size pointer.

    if ((*ktask)->arg[0] == NULL && (*ktask)->arg[1] != NULL) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "Label token indicated as null but with size greater than zero.";
        return 0;
    }

    if ((*ktask)->arg[0] != NULL && (*ktask)->arg[1] == NULL) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "Label token indicated as non-null but with size equals to zero.";
        return 0;
    }

    // CLUE(Rafael): arg[2] must hold the chosen hash function pointer.
    //               arg[3] must hold the chosen hash_size function pointer.

    if ((*ktask)->arg[2] == NULL && (*ktask)->arg[3] != NULL) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "Hash function indicated as null but Hash_size function is non-null.";
        return 0;
    }

    if ((*ktask)->arg[2] != NULL && (*ktask)->arg[3] == NULL) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "Hash function indicated as non-null but Hash_size function is null.";
        return 0;
    }

    return 1;
}

static int kryptos_task_check_elgamal_params(kryptos_task_ctx **ktask) {
    kryptos_u8_t *data = NULL;
    size_t dsize = 0;

    if ((*ktask)->key == NULL || (*ktask)->key_size == 0) {
        (*ktask)->result = kKryptosKeyError;
        (*ktask)->result_verbose = "ELGAMAL key not supplied.";
        return 0;
    }

    if ((*ktask)->action == kKryptosEncrypt) {
        data = kryptos_pem_get_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_P, (*ktask)->key, (*ktask)->key_size, &dsize);

        if (data != NULL) {
            kryptos_freeseg(data, dsize);
            data = kryptos_pem_get_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_B, (*ktask)->key, (*ktask)->key_size, &dsize);

            if (data != NULL) {
                kryptos_freeseg(data, dsize);
                dsize = 0;
                data = kryptos_pem_get_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_G, (*ktask)->key, (*ktask)->key_size, &dsize);
            }
        }

        if (data == NULL) {
            (*ktask)->result = kKryptosKeyError;
            (*ktask)->result_verbose = "ELGAMAL public key not supplied.";
            return 0;
        } else {
            kryptos_freeseg(data, dsize);
            dsize = 0;
        }
    } else if ((*ktask)->action == kKryptosDecrypt) {
        data = kryptos_pem_get_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_P, (*ktask)->key, (*ktask)->key_size, &dsize);

        if (data != NULL) {
            kryptos_freeseg(data, dsize);
            data = kryptos_pem_get_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_D, (*ktask)->key, (*ktask)->key_size, &dsize);
        }

        if (data == NULL) {
            (*ktask)->result = kKryptosKeyError;
            (*ktask)->result_verbose = "ELGAMAL private key not supplied.";
            return 0;
        } else {
            kryptos_freeseg(data, dsize);
            dsize = 0;
        }
    }

    return 1;
}

static int kryptos_task_check_rsa_emsa_pss_additional_params(kryptos_task_ctx **ktask) {
    if ((*ktask)->arg[0] == NULL) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "No salt size indicated.";
        return 0;
    }

    if ((*ktask)->arg[1] == NULL && (*ktask)->arg[2] != NULL) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "No hash algorithm was indicated but a hash_size function was.";
        return 0;
    }

    if ((*ktask)->arg[1] != NULL && (*ktask)->arg[2] == NULL) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "Hash algorithm indicated without a valid hash_size function.";
        return 0;
    }

    return 1;
}

static int kryptos_task_check_sign_dsa(kryptos_task_ctx **ktask) {
    kryptos_u8_t *data;
    size_t data_size;

    kryptos_task_check_basic_input_and_key_checks(ktask, return 0);

    if (!kryptos_task_check_dsa_domain_params(ktask)) {
        return 0;
    }

    data = kryptos_pem_get_data(KRYPTOS_DSA_PEM_HDR_PARAM_D, (*ktask)->key, (*ktask)->key_size, &data_size);

    if (data == NULL) {
        (*ktask)->result = kKryptosKeyError;
        (*ktask)->result_verbose = "Unable to get d.";
        return 0;
    }

    kryptos_freeseg(data, data_size);
    data_size = 0;

    (*ktask)->result = kKryptosSuccess;
    (*ktask)->result_verbose = NULL;

    return 1;
}

static int kryptos_task_check_verify_dsa(kryptos_task_ctx **ktask) {
    kryptos_u8_t *data;
    size_t data_size;

    kryptos_task_check_basic_input_and_key_checks(ktask, return 0);

    if (!kryptos_task_check_dsa_domain_params(ktask)) {
        return 0;
    }

    data = kryptos_pem_get_data(KRYPTOS_DSA_PEM_HDR_PARAM_E, (*ktask)->key, (*ktask)->key_size, &data_size);

    if (data == NULL) {
        (*ktask)->result = kKryptosKeyError;
        (*ktask)->result_verbose = "Unable to get e.";
        return 0;
    }

    kryptos_freeseg(data, data_size);
    data_size = 0;

    (*ktask)->result = kKryptosSuccess;
    (*ktask)->result_verbose = NULL;

    return 1;
}

static int kryptos_task_check_dsa_domain_params(kryptos_task_ctx **ktask) {
    kryptos_u8_t *data;
    size_t data_size;

    data = kryptos_pem_get_data(KRYPTOS_DSA_PEM_HDR_PARAM_P, (*ktask)->key, (*ktask)->key_size, &data_size);

    if (data == NULL || data_size == 0) {
        (*ktask)->result = kKryptosKeyError;
        (*ktask)->result_verbose = "Unable to get p.";
        return 0;
    }

    kryptos_freeseg(data, data_size);
    data_size = 0;

    data = kryptos_pem_get_data(KRYPTOS_DSA_PEM_HDR_PARAM_Q, (*ktask)->key, (*ktask)->key_size, &data_size);

    if (data == NULL || data_size == 0) {
        (*ktask)->result = kKryptosKeyError;
        (*ktask)->result_verbose = "Unable to get q.";
        return 0;
    }

    kryptos_freeseg(data, data_size);
    data_size = 0;

    data = kryptos_pem_get_data(KRYPTOS_DSA_PEM_HDR_PARAM_G, (*ktask)->key, (*ktask)->key_size, &data_size);

    if (data == NULL || data_size == 0) {
        (*ktask)->result = kKryptosKeyError;
        (*ktask)->result_verbose = "Unable to get g.";
        return 0;
    }

    kryptos_freeseg(data, data_size);
    data_size = 0;

    return 1;
}

#undef kryptos_task_check_elgamal_oaep_additional_params

#undef kryptos_task_check_basic_input_and_key_checks
