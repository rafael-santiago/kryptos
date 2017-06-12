/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_PEM_H
#define KRYPTOS_KRYPTOS_PEM_H 1

#include <kryptos_types.h>

kryptos_u8_t *kryptos_pem_get_data(const kryptos_u8_t *header, const kryptos_u8_t *buf, const size_t buf_size,
                                   size_t *data_size);

kryptos_task_result_t kryptos_pem_put_data(kryptos_u8_t **pem_buf, size_t *pem_buf_size,
                                           const kryptos_u8_t *header, const kryptos_u8_t *data, const size_t data_size);

#endif
