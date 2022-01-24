/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_SIPHASH_H
#define KRYPTOS_KRYPTOS_SIPHASH_H 1

#include <kryptos_types.h>

#ifdef __cplusplus
extern "C" {
#endif

// INFO(Rafael): Why kryptos_siphash_hash_size() function is absent?
//               It is intentional. A way of blocking the use of this
//               hash as a cryptographic hash function or a hash on
//               some crypto scheme or function that needs a crypto
//               hash (such as HMAC, OAEP, PBKDF2 etc). It is colision
//               prone because produces a very small output. Using it
//               on those stuff will introduce weaknesses on the whole
//               process depeding on it. Be care!
//
//               Being SipHash a PRF, you can use it as a hash table key
//               function, as a PRNG or even as a MAC (for short messages).
size_t kryptos_siphash_size(void);

void kryptos_siphash(kryptos_task_ctx **ktask, const size_t c, const size_t d);

kryptos_u64_t kryptos_siphash_sum(const kryptos_u8_t *message,
                                  const size_t message_size,
                                  const kryptos_u8_t *key,
                                  const size_t key_size,
                                  const size_t c, const size_t d);

#ifdef __cplusplus
}
#endif

#endif
