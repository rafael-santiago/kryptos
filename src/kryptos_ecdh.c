/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_ecdh.h>
#include <kryptos_curves.h>
#include <kryptos_ec_utils.h>
#include <kryptos_pem.h>
#include <kryptos_memory.h>
#include <kryptos_mp.h>
#include <kryptos_random.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <string.h>
# include <stdio.h>
# include <stdlib.h>
#endif

kryptos_task_result_t kryptos_ecdh_get_curve_from_params_buf(const kryptos_u8_t *params, const size_t params_size,
                                                             kryptos_curve_ctx **curve) {
    kryptos_task_result_t result = kKryptosProcessError;
    kryptos_u8_t *temp = NULL;
    size_t temp_size;

    if (params == NULL || params_size == 0 || curve == NULL) {
        return kKryptosInvalidParams;
    }

    *curve = NULL;

    *curve = (kryptos_curve_ctx *) kryptos_newseg(sizeof(kryptos_curve_ctx));

    if (*curve == NULL) {
        goto kryptos_ecdh_get_curve_from_params_buf_epilogue;
    }

    (*curve)->ec = (kryptos_ec_t *) kryptos_newseg(sizeof(kryptos_ec_t));

    if ((*curve)->ec == NULL) {
        goto kryptos_ecdh_get_curve_from_params_buf_epilogue;
    }

    (*curve)->ec->p = (*curve)->ec->a = (*curve)->ec->b = NULL;

    (*curve)->g = (kryptos_ec_pt_t *) kryptos_newseg(sizeof(kryptos_ec_pt_t));

    if ((*curve)->g == NULL) {
        goto kryptos_ecdh_get_curve_from_params_buf_epilogue;
    }

    (*curve)->g->x = (*curve)->g->y = NULL;

    (*curve)->q = NULL;

    if ((result = kryptos_pem_get_mp_data(KRYPTOS_ECDH_PEM_HDR_PARAM_EC_P,
                                          params, params_size, &(*curve)->ec->p)) != kKryptosSuccess) {
        goto kryptos_ecdh_get_curve_from_params_buf_epilogue;
    }

    if ((result = kryptos_pem_get_mp_data(KRYPTOS_ECDH_PEM_HDR_PARAM_EC_A,
                                          params, params_size, &(*curve)->ec->a)) != kKryptosSuccess) {
        goto kryptos_ecdh_get_curve_from_params_buf_epilogue;
    }

    if ((result = kryptos_pem_get_mp_data(KRYPTOS_ECDH_PEM_HDR_PARAM_EC_B,
                                          params, params_size, &(*curve)->ec->b)) != kKryptosSuccess) {
        goto kryptos_ecdh_get_curve_from_params_buf_epilogue;
    }

    if ((result = kryptos_pem_get_mp_data(KRYPTOS_ECDH_PEM_HDR_PARAM_EC_GX,
                                          params, params_size, &(*curve)->g->x)) != kKryptosSuccess) {
        goto kryptos_ecdh_get_curve_from_params_buf_epilogue;
    }

    if ((result = kryptos_pem_get_mp_data(KRYPTOS_ECDH_PEM_HDR_PARAM_EC_GY,
                                          params, params_size, &(*curve)->g->y)) != kKryptosSuccess) {
        goto kryptos_ecdh_get_curve_from_params_buf_epilogue;
    }

    if ((result = kryptos_pem_get_mp_data(KRYPTOS_ECDH_PEM_HDR_PARAM_EC_Q,
                                          params, params_size, &(*curve)->q)) != kKryptosSuccess) {
        goto kryptos_ecdh_get_curve_from_params_buf_epilogue;
    }

    result = kKryptosProcessError;

    temp = kryptos_pem_get_data(KRYPTOS_ECDH_PEM_HDR_PARAM_EC_BITS, params, params_size, &temp_size);

    if (temp == NULL) {
        goto kryptos_ecdh_get_curve_from_params_buf_epilogue;
    }

#if defined(__linux__) && defined(KRYPTOS_KERNEL_MODE)
    (*curve)->bits = simple_strtoul((char *)temp, NULL, 10);
#else
    (*curve)->bits = strtoul((char *)temp, NULL, 10);
#endif

    result = kKryptosSuccess;

kryptos_ecdh_get_curve_from_params_buf_epilogue:

    if (result != kKryptosSuccess && curve != NULL && (*curve) != NULL) {
        kryptos_del_curve_ctx(*curve);
        *curve = NULL;
    }

    if (temp != NULL) {
        kryptos_freeseg(temp, temp_size);
    }

    return result;
}

kryptos_task_result_t kryptos_ecdh_get_random_k(kryptos_mp_value_t **k, const kryptos_mp_value_t *q, const size_t bits) {
    kryptos_mp_value_t *_2 = NULL;
    kryptos_task_result_t result = kKryptosProcessError;
    kryptos_mp_digit_t mask = 0;
    size_t d;

    if (k == NULL || q == NULL) {
        goto kryptos_ecdh_get_random_k_epilogue;
    }

    if ((_2 = kryptos_hex_value_as_mp("2", 1)) == NULL) {
        goto kryptos_ecdh_get_random_k_epilogue;
    }

    (*k) = kryptos_new_mp_value((bits == 0 || kryptos_mp_bit2byte(bits) > q->data_size) ?
                                        kryptos_mp_byte2bit(q->data_size) : bits);

    if ((*k) == NULL) {
        goto kryptos_ecdh_get_random_k_epilogue;
    }

#ifndef KRYPTOS_MP_U32_DIGIT
    mask = 0xFF;
#else
    mask = 0xFFFFFFFF;
    if (bits < 32) {
        mask = mask >> (32 - bits);
    }
#endif

    do {
        for (d = 0; d < (*k)->data_size; d++) {
#ifndef KRYPTOS_MP_U32_DIGIT
            (*k)->data[d] = kryptos_get_random_byte();
#else
            (*k)->data[d] = (((kryptos_u32_t)kryptos_get_random_byte()) << 24 |
                             ((kryptos_u32_t)kryptos_get_random_byte()) << 16 |
                             ((kryptos_u32_t)kryptos_get_random_byte()) <<  8 |
                             ((kryptos_u32_t)kryptos_get_random_byte())) & mask;
#endif
        }
    } while (kryptos_mp_lt((*k), _2) || kryptos_mp_ge((*k), q));

    result = kKryptosSuccess;

kryptos_ecdh_get_random_k_epilogue:

    if (_2 != NULL) {
        kryptos_del_mp_value(_2);
    }

    return result;
}

void kryptos_ecdh_process_xchg(struct kryptos_ecdh_xchg_ctx **data) {
    kryptos_ec_pt_t *kpub = NULL, *t = NULL;
    char temp[40];
    kryptos_mp_value_t *x = NULL, *y = NULL;

    if (data == NULL) {
        return;
    }

    (*data)->result = kKryptosProcessError;
    (*data)->result_verbose = NULL;

    if ((*data)->in == NULL) {
        // INFO(Rafael): Sender Alice.

        if ((*data)->k == NULL) {
            // INFO(Rafael): Alice needs to pick a random k between { 2, ..., #q - 1 } and send it out to Bob.
            (*data)->result = kryptos_ecdh_get_random_k(&(*data)->k, (*data)->curve->q, (*data)->curve->bits);
            if ((*data)->result != kKryptosSuccess) {
                (*data)->result_verbose = "Error on choosing K.";
                goto kryptos_ecdh_process_xchg_epilogue;
            }

            (*data)->result = kKryptosProcessError;

            kryptos_ec_mul(&kpub, (*data)->curve->g, (*data)->k, (*data)->curve->ec);

            if (kpub == NULL) {
                (*data)->result_verbose = "Error on computing KPUB.";
                goto kryptos_ecdh_process_xchg_epilogue;
            }

            snprintf(temp, sizeof(temp) - 1, "%d", (*data)->curve->bits);

            (*data)->result = kryptos_pem_put_data(&(*data)->out, &(*data)->out_size,
                                                   KRYPTOS_ECDH_PEM_HDR_PARAM_EC_BITS,
                                                   (kryptos_u8_t *)temp, strlen(temp));

            if ((*data)->result != kKryptosSuccess) {
                (*data)->result_verbose = "Error on making PEM output (bits).";
                goto kryptos_ecdh_process_xchg_epilogue;
            }

            (*data)->result = kryptos_pem_put_data(&(*data)->out, &(*data)->out_size,
                                                   KRYPTOS_ECDH_PEM_HDR_PARAM_EC_P,
                                                   (kryptos_u8_t *)(*data)->curve->ec->p->data,
                                                   ((*data)->curve->ec->p->data_size * sizeof(kryptos_mp_digit_t)));

            if ((*data)->result != kKryptosSuccess) {
                (*data)->result_verbose = "Error on making PEM output (P).";
                goto kryptos_ecdh_process_xchg_epilogue;
            }

            (*data)->result = kryptos_pem_put_data(&(*data)->out, &(*data)->out_size,
                                                   KRYPTOS_ECDH_PEM_HDR_PARAM_EC_A,
                                                   (kryptos_u8_t *)(*data)->curve->ec->a->data,
                                                   ((*data)->curve->ec->a->data_size * sizeof(kryptos_mp_digit_t)));

            if ((*data)->result != kKryptosSuccess) {
                (*data)->result_verbose = "Error on making PEM output (A).";
                goto kryptos_ecdh_process_xchg_epilogue;
            }

            (*data)->result = kryptos_pem_put_data(&(*data)->out, &(*data)->out_size,
                                                   KRYPTOS_ECDH_PEM_HDR_PARAM_EC_B,
                                                   (kryptos_u8_t *)(*data)->curve->ec->b->data,
                                                   ((*data)->curve->ec->b->data_size * sizeof(kryptos_mp_digit_t)));

            if ((*data)->result != kKryptosSuccess) {
                (*data)->result_verbose = "Error on making PEM output (B).";
                goto kryptos_ecdh_process_xchg_epilogue;
            }

            (*data)->result = kryptos_pem_put_data(&(*data)->out, &(*data)->out_size,
                                                   KRYPTOS_ECDH_PEM_HDR_PARAM_EC_GX,
                                                   (kryptos_u8_t *)(*data)->curve->g->x->data,
                                                   ((*data)->curve->g->x->data_size * sizeof(kryptos_mp_digit_t)));

            if ((*data)->result != kKryptosSuccess) {
                (*data)->result_verbose = "Error on making PEM output (GX).";
                goto kryptos_ecdh_process_xchg_epilogue;
            }

            (*data)->result = kryptos_pem_put_data(&(*data)->out, &(*data)->out_size,
                                                   KRYPTOS_ECDH_PEM_HDR_PARAM_EC_GY,
                                                   (kryptos_u8_t *)(*data)->curve->g->y->data,
                                                   ((*data)->curve->g->y->data_size * sizeof(kryptos_mp_digit_t)));

            if ((*data)->result != kKryptosSuccess) {
                (*data)->result_verbose = "Error on making PEM output (GY).";
                goto kryptos_ecdh_process_xchg_epilogue;
            }

            (*data)->result = kryptos_pem_put_data(&(*data)->out, &(*data)->out_size,
                                                   KRYPTOS_ECDH_PEM_HDR_PARAM_EC_Q,
                                                   (kryptos_u8_t *)(*data)->curve->q->data,
                                                   ((*data)->curve->q->data_size * sizeof(kryptos_mp_digit_t)));

            if ((*data)->result != kKryptosSuccess) {
                (*data)->result_verbose = "Error on making PEM output (Q).";
                goto kryptos_ecdh_process_xchg_epilogue;
            }

            (*data)->result = kryptos_pem_put_data(&(*data)->out, &(*data)->out_size,
                                                   KRYPTOS_ECDH_PEM_HDR_PARAM_KPX,
                                                   (kryptos_u8_t *)kpub->x->data,
                                                   (kpub->x->data_size * sizeof(kryptos_mp_digit_t)));

            if ((*data)->result != kKryptosSuccess) {
                (*data)->result_verbose = "Error on making PEM output (KPX).";
                goto kryptos_ecdh_process_xchg_epilogue;
            }

            (*data)->result = kryptos_pem_put_data(&(*data)->out, &(*data)->out_size,
                                                   KRYPTOS_ECDH_PEM_HDR_PARAM_KPY,
                                                   (kryptos_u8_t *)kpub->y->data,
                                                   (kpub->y->data_size * sizeof(kryptos_mp_digit_t)));

            if ((*data)->result != kKryptosSuccess) {
                (*data)->result_verbose = "Error on making PEM output (KPY).";
                goto kryptos_ecdh_process_xchg_epilogue;
            }
        }
    } else if ((*data)->k == NULL) {
        // INFO(Rafael): Receiver Bob.

        if ((*data)->in != NULL && (*data)->curve == NULL) {
            // INFO(Rafael): Bob has received from Alice all public parameters. He needs to load the curve info, create it
            //               and finally compute locally the T_{ab} and send out to Alice his KP(x,y).

            (*data)->result = kryptos_ecdh_get_curve_from_params_buf((*data)->in, (*data)->in_size, &(*data)->curve);

            if ((*data)->result != kKryptosSuccess) {
                (*data)->result_verbose = "Error on loading public parameters.";
                goto kryptos_ecdh_process_xchg_epilogue;
            }

            (*data)->result = kryptos_ecdh_get_random_k(&(*data)->k, (*data)->curve->q, (*data)->curve->bits);
            if ((*data)->result != kKryptosSuccess) {
                (*data)->result_verbose = "Error on choosing K.";
                goto kryptos_ecdh_process_xchg_epilogue;
            }

            kryptos_ec_mul(&kpub, (*data)->curve->g, (*data)->k, (*data)->curve->ec);

            if (kpub == NULL) {
                (*data)->result = kKryptosProcessError;
                (*data)->result_verbose = "Error on computing KP(x,y).";
                goto kryptos_ecdh_process_xchg_epilogue;
            }

            // INFO(Rafael): Now Bob packs the point KP into a PEM to send to Alice.

            (*data)->result = kryptos_pem_put_data(&(*data)->out, &(*data)->out_size,
                                                   KRYPTOS_ECDH_PEM_HDR_PARAM_KPX,
                                                   (kryptos_u8_t *)kpub->x->data,
                                                   (kpub->x->data_size * sizeof(kryptos_mp_digit_t)));

            if ((*data)->result != kKryptosSuccess) {
                (*data)->result_verbose = "Error on making PEM output (KPX).";
                goto kryptos_ecdh_process_xchg_epilogue;
            }

            (*data)->result = kryptos_pem_put_data(&(*data)->out, &(*data)->out_size,
                                                   KRYPTOS_ECDH_PEM_HDR_PARAM_KPY,
                                                   (kryptos_u8_t *)kpub->y->data,
                                                   (kpub->y->data_size * sizeof(kryptos_mp_digit_t)));

            if ((*data)->result != kKryptosSuccess) {
                (*data)->result_verbose = "Error on making PEM output (KPY).";
                goto kryptos_ecdh_process_xchg_epilogue;
            }

            // INFO(Rafael): Now loading the public point computed from Alice to get the session key T_{ab}.

            kryptos_ec_del_point(kpub);

            (*data)->result = kryptos_pem_get_mp_data(KRYPTOS_ECDH_PEM_HDR_PARAM_KPX,
                                                      (*data)->in, (*data)->in_size,
                                                      &x);

            if ((*data)->result != kKryptosSuccess) {
                (*data)->result_verbose = "Error on loading public point KP(x,y).";
                goto kryptos_ecdh_process_xchg_epilogue;
            }

            (*data)->result = kryptos_pem_get_mp_data(KRYPTOS_ECDH_PEM_HDR_PARAM_KPY,
                                                      (*data)->in, (*data)->in_size,
                                                      &y);

            if ((*data)->result != kKryptosSuccess) {
                (*data)->result_verbose = "Error on loading public point KP(x,y).";
                goto kryptos_ecdh_process_xchg_epilogue;
            }

            if (kryptos_ec_set_point(&kpub, x, y) != 1) {
                (*data)->result_verbose = "Error on loading public point KP(x,y).";
                goto kryptos_ecdh_process_xchg_epilogue;
            }

            // INFO(Rafael): Now Bob computes the T_{ab}.

            kryptos_ec_mul(&t, kpub, (*data)->k, (*data)->curve->ec);

            if (t == NULL) {
                (*data)->result = kKryptosProcessError;
                (*data)->result_verbose = "Error on computing final T.";
                goto kryptos_ecdh_process_xchg_epilogue;
            }

            (*data)->curve->bits = 0;
            kryptos_del_curve_ctx((*data)->curve);
            (*data)->curve = NULL;

            kryptos_del_mp_value((*data)->k);

            // INFO(Rafael): We do not need y.

            (*data)->k = t->x;
            t->x = NULL;
        }
    } else {
        // INFO(Rafael): Alice has received the KP(x,y) from Bob and she needs to compute the joint secret T_{ab}.

        (*data)->result = kryptos_pem_get_mp_data(KRYPTOS_ECDH_PEM_HDR_PARAM_KPX, (*data)->in, (*data)->in_size,
                                                  &x);

        if ((*data)->result != kKryptosSuccess) {
            (*data)->result_verbose = "Error on getting data from PEM (KPX).";
            goto kryptos_ecdh_process_xchg_epilogue;
        }

        (*data)->result = kryptos_pem_get_mp_data(KRYPTOS_ECDH_PEM_HDR_PARAM_KPY, (*data)->in, (*data)->in_size,
                                                  &y);

        if ((*data)->result != kKryptosSuccess) {
            (*data)->result_verbose = "Error on getting data from PEM (KPY).";
            goto kryptos_ecdh_process_xchg_epilogue;
        }

        (*data)->result = kKryptosProcessError;

        if (kryptos_ec_set_point(&kpub, x, y) != 1) {
            (*data)->result_verbose = "Error on setting point KP(x, y).";
            goto kryptos_ecdh_process_xchg_epilogue;
        }

        kryptos_ec_mul(&t, kpub, (*data)->k, (*data)->curve->ec);

        if (t == NULL) {
            (*data)->result = kKryptosProcessError;
            (*data)->result_verbose = "Error on computing final T.";
            goto kryptos_ecdh_process_xchg_epilogue;
        }

        (*data)->curve->bits = 0;
        kryptos_del_curve_ctx((*data)->curve);
        (*data)->curve = NULL;

        kryptos_del_mp_value((*data)->k);

        // INFO(Rafael): We do not need y.

        (*data)->k = t->x;
        t->x = NULL;

        (*data)->result = kKryptosSuccess;
    }

kryptos_ecdh_process_xchg_epilogue:

    if ((*data)->result != kKryptosSuccess) {
        kryptos_clear_ecdh_xchg_ctx(*data);
        if ((*data)->out != NULL) {
            kryptos_freeseg((*data)->out, (*data)->out_size);
            (*data)->out_size = 0;
            (*data)->out = NULL;
        }
    }

    if (kpub != NULL) {
        kryptos_ec_del_point(kpub);
    }

    if (t != NULL) {
        kryptos_ec_del_point(t);
    }

    if (x != NULL) {
        kryptos_del_mp_value(x);
    }

    if (y != NULL) {
        kryptos_del_mp_value(y);
    }
}

void kryptos_clear_ecdh_xchg_ctx(struct kryptos_ecdh_xchg_ctx *data) {
    if (data != NULL) {
        kryptos_del_curve_ctx(data->curve);

        if (data->in != NULL) {
            kryptos_freeseg(data->in, data->in_size);
        }

        if (data->out != NULL) {
            kryptos_freeseg(data->out, data->out_size);
        }

        if (data->k != NULL) {
            kryptos_del_mp_value(data->k);
        }

        kryptos_ecdh_init_xchg_ctx(data);
    }
}
