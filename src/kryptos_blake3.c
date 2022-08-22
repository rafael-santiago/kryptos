/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_blake3.h>
#include <kryptos_endianness_utils.h>
#include <kryptos_memory.h>
#include <kryptos_hex.h>
#include <kryptos.h>

#define KRYPTOS_BLAKE3_BYTES_PER_BLOCK 64

#define KRYPTOS_BLAKE3_HASH_SIZE 32

// INFO(Rafael): This implementation is NOT incremental, by design, all hash primitives in kryptos
//               must be called when all data intended to be hashed is loaded into memory. If you
//               need to hash data greater than your available memory, kryptos hashing is not for
//               you. Even so, being BLAKE3 a Merkle tree, we need to emulate tree based data input
//               processing anyway, however, I am not complicating it with multi-threading, it
//               is still a crypto library, if you need something that requires synchronization
//               primitives well as all basic multi-threading stuff, I believe that you are totally
//               able to customize this code or any other without much tips, your requirements are
//               rather specific and out from general usage scope of crypto that most of people does
//               and also needs.
//
//               In short, what was being done in this code module is the following:
//
//                __________________________________________________________________________
//               |_________________i_______n________p_________u__________t_______________...$  <-- no more data.
//                _________________|________________|____________________|__________________
//               |___[64b-1K]______|____[64b-1K]____|_____[64b-1K]_______|____[64b-1K]___...|
//                      |                  |                 |                  |
//          [64b]       C________ _________C                 C__________ _______C        ...
//                               |                                      |
//                               P0                                     P1
//                               |                                      |
//          [64b]                C__________________ ___________________C                ...
//                                                  |
//          [64b]                                  ...
//           ...                               _____|_____
//          [64b]                             |__R_O_O_T__|
//                                                  |
//       [32b-2^64]                                 C+ => [SUM]
//
// However, the parent mergings are not so elementary as it seems to be in the clumsy abstracted
// diagram above. We need to follow some sequencing rules dictated by the parity nature of the
// bits in the chunk counter itself, but here in my implementation it is being explored in a
// more simplified way that only tries to (re)compress when it really should can be done (at least once).
// In other words, here when the parent compression routine is called one unconditional and zero or
// n conditionals node compressions will be done. In this way, we do not need to stay calling
// parent compression on every chunk post processing iteration. I believe that at the end it
// will be less cpu intensive by cuting some function call overhead that should not be called
// during some execution contexts, due to an obvious lack of additional information.
//
// If you did not understand anything, imagine a binary tree upside-down being merged from its
// leafs until its root. In general it is what is happening here.

static kryptos_u32_t kryptos_blake3_IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

typedef enum {
    kBLAKE3ModeHash = 0,
    kBLAKE3ModeKeyedHash,
    kBLAKE3ModeDeriveKey1stStage,
    kBLAKE3ModeDeriveKey2ndStage
}kryptos_blake3_mode_t;

typedef enum {
    kBLAKE3PCGetL = 0,
    kBLAKE3PCGetR
}kryptos_blake3_pc_state_t; // INFO(Rafael): Here we are simplifying parents subtree processing.
                            //               Avoid entering into a loop everytime even having nothing to process.
                            //               It will make this part of BLAKE3 acts like a finite-state machine.
                            //               But what in a computer is not a finite-state machine?!

// INFO(Rafael): This struct represents one chaining value entry into parent chaining value stack.
//               Maybe this stack could be pre-allocated, but for now I have not been intended to do it.
struct kryptos_blake3_pc_stack_ctx {
    kryptos_u32_t h[8];
    struct kryptos_blake3_pc_stack_ctx *next;
};

// INFO(Rafael): The main algorithm context, where all registers, flags and, states are gathered by representing
//               the whole hashing task.
struct kryptos_blake3_ctx {
    kryptos_blake3_mode_t mode;
    int err;
    size_t wanted_out_size;
    size_t curr_out_size;
    kryptos_u8_t *in;
    kryptos_u64_t in_size;
    kryptos_u8_t *out;
    kryptos_u64_t out_size;
    kryptos_u8_t *key;
    size_t key_size;
    kryptos_u32_t h[8];
    kryptos_u32_t hh[8];
    kryptos_u32_t v[16];
    kryptos_u32_t vv[16];
    kryptos_u32_t k[8];
    kryptos_u32_t m[16];
    kryptos_u32_t mm[16];
    kryptos_u32_t tm[16];
    kryptos_u64_t t;
    kryptos_u32_t b;
    kryptos_u32_t d;
    struct kryptos_blake3_pc_stack_ctx *pc_stack;
    kryptos_blake3_pc_state_t pc_state;
    size_t chunk_nr;
};

// INFO(Rafael): BLAKE3 circuits and its "board", a.k.a. compression function.

#define kryptos_blake3_RSH(v, l) ( ((v) << ((sizeof(v) << 3) - (l))) | ((v) >> (l)) )

#define kryptos_blake3_G(a, b, c, d, m) {\
    (a) = (a) + (b) + (m)[0];\
    (d) = kryptos_blake3_RSH((d) ^ (a), 16);\
    (c) = (c) + (d);\
    (b) = kryptos_blake3_RSH((b) ^ (c), 12);\
    (a) = (a) + (b) + (m)[1];\
    (d) = kryptos_blake3_RSH((d) ^ (a), 8);\
    (c) = (c) + (d);\
    (b) = kryptos_blake3_RSH((b) ^ (c), 7);\
}

#define kryptos_blake3_ROUND(v, m) {\
    kryptos_blake3_G(v[ 0], v[ 4], v[ 8], v[12], &m[ 0]);\
    kryptos_blake3_G(v[ 1], v[ 5], v[ 9], v[13], &m[ 2]);\
    kryptos_blake3_G(v[ 2], v[ 6], v[10], v[14], &m[ 4]);\
    kryptos_blake3_G(v[ 3], v[ 7], v[11], v[15], &m[ 6]);\
    kryptos_blake3_G(v[ 0], v[ 5], v[10], v[15], &m[ 8]);\
    kryptos_blake3_G(v[ 1], v[ 6], v[11], v[12], &m[10]);\
    kryptos_blake3_G(v[ 2], v[ 7], v[ 8], v[13], &m[12]);\
    kryptos_blake3_G(v[ 3], v[ 4], v[ 9], v[14], &m[14]);\
}

#define kryptos_blake3_PERM(m, tm) {\
    memcpy((tm), (m), sizeof((m)));\
    (m)[ 0] = (tm)[ 2];\
    (m)[ 1] = (tm)[ 6];\
    (m)[ 2] = (tm)[ 3];\
    (m)[ 3] = (tm)[10];\
    (m)[ 4] = (tm)[ 7];\
    (m)[ 5] = (tm)[ 0];\
    (m)[ 6] = (tm)[ 4];\
    (m)[ 7] = (tm)[13];\
    (m)[ 8] = (tm)[ 1];\
    (m)[ 9] = (tm)[11];\
    (m)[10] = (tm)[12];\
    (m)[11] = (tm)[ 5];\
    (m)[12] = (tm)[ 9];\
    (m)[13] = (tm)[14];\
    (m)[14] = (tm)[15];\
    (m)[15] = (tm)[ 8];\
    memset((tm), 0, sizeof((tm)));\
}

#define kryptos_blake3_COMPRESS(ctx) {\
    kryptos_blake3_ROUND((ctx)->v, (ctx)->m);\
    kryptos_blake3_PERM((ctx)->m, (ctx)->tm);\
    kryptos_blake3_ROUND((ctx)->v, (ctx)->m);\
    kryptos_blake3_PERM((ctx)->m, (ctx)->tm);\
    kryptos_blake3_ROUND((ctx)->v, (ctx)->m);\
    kryptos_blake3_PERM((ctx)->m, (ctx)->tm);\
    kryptos_blake3_ROUND((ctx)->v, (ctx)->m);\
    kryptos_blake3_PERM((ctx)->m, (ctx)->tm);\
    kryptos_blake3_ROUND((ctx)->v, (ctx)->m);\
    kryptos_blake3_PERM((ctx)->m, (ctx)->tm);\
    kryptos_blake3_ROUND((ctx)->v, (ctx)->m);\
    kryptos_blake3_PERM((ctx)->m, (ctx)->tm);\
    kryptos_blake3_ROUND((ctx)->v, (ctx)->m);\
    (ctx)->v[ 0] = (ctx)->v[ 0] ^ (ctx)->v[ 8];\
    (ctx)->v[ 1] = (ctx)->v[ 1] ^ (ctx)->v[ 9];\
    (ctx)->v[ 2] = (ctx)->v[ 2] ^ (ctx)->v[10];\
    (ctx)->v[ 3] = (ctx)->v[ 3] ^ (ctx)->v[11];\
    (ctx)->v[ 4] = (ctx)->v[ 4] ^ (ctx)->v[12];\
    (ctx)->v[ 5] = (ctx)->v[ 5] ^ (ctx)->v[13];\
    (ctx)->v[ 6] = (ctx)->v[ 6] ^ (ctx)->v[14];\
    (ctx)->v[ 7] = (ctx)->v[ 7] ^ (ctx)->v[15];\
    (ctx)->v[ 8] = (ctx)->v[ 8] ^ (ctx)->h[ 0];\
    (ctx)->v[ 9] = (ctx)->v[ 9] ^ (ctx)->h[ 1];\
    (ctx)->v[10] = (ctx)->v[10] ^ (ctx)->h[ 2];\
    (ctx)->v[11] = (ctx)->v[11] ^ (ctx)->h[ 3];\
    (ctx)->v[12] = (ctx)->v[12] ^ (ctx)->h[ 4];\
    (ctx)->v[13] = (ctx)->v[13] ^ (ctx)->h[ 5];\
    (ctx)->v[14] = (ctx)->v[14] ^ (ctx)->h[ 6];\
    (ctx)->v[15] = (ctx)->v[15] ^ (ctx)->h[ 7];\
    (ctx)->h[ 0] = (ctx)->v[ 0];\
    (ctx)->h[ 1] = (ctx)->v[ 1];\
    (ctx)->h[ 2] = (ctx)->v[ 2];\
    (ctx)->h[ 3] = (ctx)->v[ 3];\
    (ctx)->h[ 4] = (ctx)->v[ 4];\
    (ctx)->h[ 5] = (ctx)->v[ 5];\
    (ctx)->h[ 6] = (ctx)->v[ 6];\
    (ctx)->h[ 7] = (ctx)->v[ 7];\
}

// INFO(Rafael): Relevant functions macros to save and restore pre ROOT compression relevant registers
//               to reconstruct this pre-state later when producing the wanted size output. See spec
//               2.6 section.

#define kryptos_blake3_save_ctx_regs(ctx) {\
    memcpy((ctx)->hh, (ctx)->h, sizeof((ctx)->hh));\
    memcpy((ctx)->vv, (ctx)->v, sizeof((ctx)->vv));\
    memcpy((ctx)->mm, (ctx)->m, sizeof((ctx)->mm));\
}

#define kryptos_blake3_restore_ctx_regs(ctx) {\
    memcpy((ctx)->h, (ctx)->hh, sizeof((ctx)->h));\
    memcpy((ctx)->v, (ctx)->vv, sizeof((ctx)->v));\
    memcpy((ctx)->m, (ctx)->mm, sizeof((ctx)->m));\
}

// INFO(Rafael): d's flag values of BLAKE3, any doubt take a look at its spec.

#define KRYPTOS_BLAKE3_CHUNK_START             1
#define KRYPTOS_BLAKE3_CHUNK_END           (1<<1)
#define KRYPTOS_BLAKE3_PARENT              (1<<2)
#define KRYPTOS_BLAKE3_ROOT                (1<<3)
#define KRYPTOS_BLAKE3_KEYED_HASH          (1<<4)
#define KRYPTOS_BLAKE3_DERIVE_KEY_CONTEXT  (1<<5)
#define KRYPTOS_BLAKE3_DERIVE_KEY_MATERIAL (1<<6)

#define KRYPTOS_BLAKE3_EXIT_FAILURE 1
#define KRYPTOS_BLAKE3_EXIT_SUCCESS 0

static void kryptos_do_blake3(struct kryptos_blake3_ctx *data);

static int kryptos_blake3_do_chunks(struct kryptos_blake3_ctx *data);

static int kryptos_blake3_do_parents(struct kryptos_blake3_ctx *data,
                                     const kryptos_u8_t *curr_input,
                                     const kryptos_u8_t *input_end);

static int kryptos_blake3_push_pc(struct kryptos_blake3_pc_stack_ctx **pc_stack,
                                  const kryptos_u32_t *h);

static int kryptos_blake3_pop_pc(struct kryptos_blake3_pc_stack_ctx **pc_stack,
                                 kryptos_u32_t *h);

static int kryptos_blake3_flush_pc_stack(struct kryptos_blake3_ctx *data,
                                         const kryptos_u8_t *curr_input,
                                         const kryptos_u8_t *input_end);

static int kryptos_blake3_pc_do_compress(struct kryptos_blake3_ctx *data,
                                         const kryptos_u8_t *curr_input,
                                         const kryptos_u8_t *input_end);

static int kryptos_blake3_pc_compress(struct kryptos_blake3_ctx *data,
                                      const int is_input_end);

static int kryptos_blake3_get_sum(struct kryptos_blake3_ctx *data);

#define kryptos_blake3_is_pc_stack_empty(s) ( (s) == NULL )

#define kryptos_blake3_new_pc_stack_item(s, h) {\
    (s) = (struct kryptos_blake3_pc_stack_ctx *) kryptos_newseg(sizeof(struct kryptos_blake3_pc_stack_ctx));\
    if ((s) != NULL) {\
        memcpy((s)->h, h, sizeof((s)->h));\
        (s)->next = NULL;\
    }\
}

#define kryptos_blake3_free_pc_stack_item(s) {\
    if ((s) != NULL) {\
        kryptos_freeseg((s), sizeof(struct kryptos_blake3_pc_stack_ctx));\
    }\
}

// INFO(Rafael): BLAKE3-(256) implementation.

KRYPTOS_IMPL_HASH_SIZE(blake3, KRYPTOS_BLAKE3_HASH_SIZE);

KRYPTOS_IMPL_HASH_INPUT_SIZE(blake3, KRYPTOS_BLAKE3_BYTES_PER_BLOCK);

KRYPTOS_IMPL_HASH_PROCESSOR(blake3, ktask, kryptos_blake3_ctx, ctx, blake3_epilogue,
                            {
                                if (((*ktask)->key == NULL && (*ktask)->key_size != 0) ||
                                    ((*ktask)->key != NULL && (*ktask)->key_size != KRYPTOS_BLAKE3_HASH_SIZE)) {
                                    (*ktask)->result = kKryptosKeyError;
                                    (*ktask)->result_verbose = "A null or a key with invalid size was passed. "
                                                               "It must have 256-bits.";
                                    goto kryptos_blake3_epilogue;
                                }
                                memset(&ctx, 0, sizeof(ctx));
                                ctx.wanted_out_size = KRYPTOS_BLAKE3_HASH_SIZE;
                                ctx.in = (*ktask)->in;
                                ctx.in_size = (*ktask)->in_size;
                                ctx.key = (*ktask)->key;
                                ctx.key_size = (*ktask)->key_size;
                                ctx.mode = ((*ktask)->key == NULL) ? kBLAKE3ModeHash : kBLAKE3ModeKeyedHash;
                            },
                            kryptos_do_blake3(&ctx),
                            {
                                if (ctx.err != KRYPTOS_BLAKE3_EXIT_SUCCESS
                                    || ctx.out == NULL || ctx.out_size != KRYPTOS_BLAKE3_HASH_SIZE) {
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "Internal error during BLAKE3 hash computing.";
                                    goto kryptos_blake3_epilogue;
                                }
                                (*ktask)->out = (kryptos_u8_t *)kryptos_newseg(KRYPTOS_BLAKE3_HASH_SIZE);
                                if ((*ktask)->out == NULL) {
                                    kryptos_freeseg(ctx.out, ctx.out_size);
                                    memset(&ctx, 0, sizeof(ctx));
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_blake3_epilogue;
                                }
                                memcpy((*ktask)->out, ctx.out, KRYPTOS_BLAKE3_HASH_SIZE);
                                (*ktask)->out_size = KRYPTOS_BLAKE3_HASH_SIZE;
                                kryptos_freeseg(ctx.out, ctx.out_size);
                                memset(&ctx, 0, sizeof(ctx));
                            },
                            {
                                if (ctx.err != KRYPTOS_BLAKE3_EXIT_SUCCESS
                                    || ctx.out == NULL || ctx.out_size != KRYPTOS_BLAKE3_HASH_SIZE) {
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "Internal error during BLAKE3 hash computing.";
                                    goto kryptos_blake3_epilogue;
                                }
                                (*ktask)->out = (kryptos_u8_t *)kryptos_newseg((KRYPTOS_BLAKE3_HASH_SIZE << 1) + 1);
                                if ((*ktask)->out == NULL) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_blake3_epilogue;
                                }
                                kryptos_u32_to_hex((*ktask)->out     , 65, (kryptos_u32_t)ctx.out[ 0] << 24 |
                                                                           (kryptos_u32_t)ctx.out[ 1] << 16 |
                                                                           (kryptos_u32_t)ctx.out[ 2] <<  8 |
                                                                           (kryptos_u32_t)ctx.out[ 3]);
                                kryptos_u32_to_hex((*ktask)->out +  8, 57, (kryptos_u32_t)ctx.out[ 4] << 24 |
                                                                           (kryptos_u32_t)ctx.out[ 5] << 16 |
                                                                           (kryptos_u32_t)ctx.out[ 6] <<  8 |
                                                                           (kryptos_u32_t)ctx.out[ 7]);
                                kryptos_u32_to_hex((*ktask)->out + 16, 49, (kryptos_u32_t)ctx.out[ 8] << 24 |
                                                                           (kryptos_u32_t)ctx.out[ 9] << 16 |
                                                                           (kryptos_u32_t)ctx.out[10] <<  8 |
                                                                           (kryptos_u32_t)ctx.out[11]);
                                kryptos_u32_to_hex((*ktask)->out + 24, 41, (kryptos_u32_t)ctx.out[12] << 24 |
                                                                           (kryptos_u32_t)ctx.out[13] << 16 |
                                                                           (kryptos_u32_t)ctx.out[14] <<  8 |
                                                                           (kryptos_u32_t)ctx.out[15]);
                                kryptos_u32_to_hex((*ktask)->out + 32, 33, (kryptos_u32_t)ctx.out[16] << 24 |
                                                                           (kryptos_u32_t)ctx.out[17] << 16 |
                                                                           (kryptos_u32_t)ctx.out[18] <<  8 |
                                                                           (kryptos_u32_t)ctx.out[19]);
                                kryptos_u32_to_hex((*ktask)->out + 40, 25, (kryptos_u32_t)ctx.out[20] << 24 |
                                                                           (kryptos_u32_t)ctx.out[21] << 16 |
                                                                           (kryptos_u32_t)ctx.out[22] <<  8 |
                                                                           (kryptos_u32_t)ctx.out[23]);
                                kryptos_u32_to_hex((*ktask)->out + 48, 17, (kryptos_u32_t)ctx.out[24] << 24 |
                                                                           (kryptos_u32_t)ctx.out[25] << 16 |
                                                                           (kryptos_u32_t)ctx.out[26] <<  8 |
                                                                           (kryptos_u32_t)ctx.out[27]);
                                kryptos_u32_to_hex((*ktask)->out + 56,  9, (kryptos_u32_t)ctx.out[28] << 24 |
                                                                           (kryptos_u32_t)ctx.out[29] << 16 |
                                                                           (kryptos_u32_t)ctx.out[30] <<  8 |
                                                                           (kryptos_u32_t)ctx.out[31]);
                                (*ktask)->out_size = KRYPTOS_BLAKE3_HASH_SIZE << 1;
                                kryptos_freeseg(ctx.out, ctx.out_size);
                                memset(&ctx, 0, sizeof(ctx));
                            })

// INFO(Rafael): BLAKE3 with extended output implementation.

KRYPTOS_IMPL_HASH_INPUT_SIZE(blake3N, KRYPTOS_BLAKE3_BYTES_PER_BLOCK);

KRYPTOS_IMPL_HASH_PROCESSOR(blake3N, ktask, kryptos_blake3_ctx, ctx, blake3N_epilogue,
                            {
                                if (((*ktask)->key == NULL && (*ktask)->key_size != 0) ||
                                    ((*ktask)->key != NULL && (*ktask)->key_size != KRYPTOS_BLAKE3_HASH_SIZE)) {
                                    (*ktask)->result = kKryptosKeyError;
                                    (*ktask)->result_verbose = "A null or a key with invalid size was passed.";
                                    goto kryptos_blake3N_epilogue;
                                }
                                if ((*ktask)->out_size == 0) {
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "At least 1 byte of output must be asked.";
                                    goto kryptos_blake3N_epilogue;
                                }
                                memset(&ctx, 0, sizeof(ctx));
                                ctx.wanted_out_size = (*ktask)->out_size;
                                ctx.in = (*ktask)->in;
                                ctx.in_size = (*ktask)->in_size;
                                ctx.key = (*ktask)->key;
                                ctx.key_size = (*ktask)->key_size;
                                ctx.mode = ((*ktask)->key == NULL) ? kBLAKE3ModeHash : kBLAKE3ModeKeyedHash;
                            },
                            kryptos_do_blake3(&ctx),
                            {
                                if (ctx.err != KRYPTOS_BLAKE3_EXIT_SUCCESS
                                    || ctx.out == NULL || ctx.out_size < (*ktask)->out_size) {
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "Internal error during BLAKE3 hash computing.";
                                    goto kryptos_blake3N_epilogue;
                                }
                                (*ktask)->out = (kryptos_u8_t *)kryptos_newseg((*ktask)->out_size);
                                if ((*ktask)->out == NULL) {
                                    kryptos_freeseg(ctx.out, ctx.out_size);
                                    memset(&ctx, 0, sizeof(ctx));
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_blake3N_epilogue;
                                }
                                memcpy((*ktask)->out, ctx.out, (*ktask)->out_size);
                                kryptos_freeseg(ctx.out, ctx.out_size);
                                memset(&ctx, 0, sizeof(ctx));
                            },
                            {
                                if (ctx.err != KRYPTOS_BLAKE3_EXIT_SUCCESS
                                    || ctx.out == NULL || ctx.out_size < (*ktask)->out_size) {
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "Internal error during BLAKE3 hash computing.";
                                    goto kryptos_blake3N_epilogue;
                                }
                                (*ktask)->out = kryptos_u8_ptr_to_hex(ctx.out, (*ktask)->out_size, &(*ktask)->out_size);
                                if ((*ktask)->out == NULL) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_blake3N_epilogue;
                                }
                                kryptos_freeseg(ctx.out, ctx.out_size);
                                memset(&ctx, 0, sizeof(ctx));
                            })

// INFO(Rafael): This is NOT the hash algorithm hash compute function. This is the BLAKE3's KDF.

kryptos_u8_t *kryptos_blake3(kryptos_u8_t *ctx_string, const size_t ctx_string_size,
                             kryptos_u8_t *key, const size_t key_size, const size_t derived_size) {
    struct kryptos_blake3_ctx data;
    kryptos_u8_t *derived_key = NULL;

    if (ctx_string == NULL || ctx_string == 0 || key == NULL || derived_size == 0) {
        return NULL;
    }

    memset(&data, 0, sizeof(data));

    data.wanted_out_size = derived_size;

    // INFO(Rafael): 'The third mode, derive_key, has two stages. First the context string
    //                is hashed (...). Then the key material is hashed'.

    data.in = ctx_string;
    data.in_size = ctx_string_size;
    data.mode = kBLAKE3ModeDeriveKey1stStage;
    kryptos_do_blake3(&data);
    if (data.err == KRYPTOS_BLAKE3_EXIT_SUCCESS && data.out == NULL) {
        data.in = key;
        data.in_size = key_size;
        data.mode = kBLAKE3ModeDeriveKey2ndStage;
        kryptos_do_blake3(&data);
        if (data.err != KRYPTOS_BLAKE3_EXIT_SUCCESS
            || data.out == NULL) {
            return NULL;
        }
        derived_key = data.out;
        data.out = NULL; // INFO(Rafael): Resource transferred.
    }

    memset(&data, 0, sizeof(data));

    return derived_key;
}

static void kryptos_do_blake3(struct kryptos_blake3_ctx *data) {
    if (data == NULL || data->in == NULL) {
        return;
    }

    data->err = KRYPTOS_BLAKE3_EXIT_FAILURE;

    data->out = NULL;
    data->out_size = 0;

    data->err = kryptos_blake3_do_chunks(data);

    if (data->err == KRYPTOS_BLAKE3_EXIT_SUCCESS
        && data->out != NULL && data->out_size > data->wanted_out_size) {
        // INFO(Rafael): This implementation produces 256-bits hash material per
        //               iteration. Here we are avoid leaking part of unused hash
        //               when the wanted out size lets some remaining bytes.
        memset(data->out + data->wanted_out_size, 0,
               data->out_size - data->wanted_out_size);
    }

    if (data->mode != kBLAKE3ModeDeriveKey1stStage) {
        memset(data->h, 0, sizeof(data->h));
    }

    memset(data->v, 0, sizeof(data->v));
    memset(data->vv, 0, sizeof(data->vv));
    memset(data->k, 0, sizeof(data->k));
    memset(data->m, 0, sizeof(data->m));
    memset(data->mm, 0, sizeof(data->mm));
    memset(data->hh, 0, sizeof(data->hh));
    memset(data->tm, 0, sizeof(data->tm));
    data->t = 0;
    data->b = data->d = 0;
    data->mode = 0;
    data->chunk_nr = 0;
}

static int kryptos_blake3_do_chunks(struct kryptos_blake3_ctx *data) {
    const kryptos_u8_t *ip = NULL, *ip_end = NULL;
    kryptos_u8_t *op = NULL, *op_end = NULL;
    size_t mi = 0;
    size_t block_nr = 0, delta_off = 0;
    int done = 0;

    if (data->wanted_out_size == data->curr_out_size) {
        return KRYPTOS_BLAKE3_EXIT_SUCCESS;
    }

    if (data->in_size <= (KRYPTOS_BLAKE3_BYTES_PER_BLOCK<<4)
        && data->mode != kBLAKE3ModeDeriveKey1stStage) {
        // INFO(Rafael): It will not generate any parent compression
        //               the output will be gotten from here.
        data->out_size = data->wanted_out_size;
        while (data->out_size % KRYPTOS_BLAKE3_HASH_SIZE) {
            data->out_size++;
        }
        data->out = (kryptos_u8_t *)kryptos_newseg(data->out_size);
        if (data->out == NULL) {
            data->out_size = 0;
            return KRYPTOS_BLAKE3_EXIT_FAILURE;
        }
        memset(data->out, 0, data->out_size);
        op = data->out;
        op_end = op + data->out_size;
    }

    switch (data->mode) {
        case kBLAKE3ModeHash:
            // INFO(Rafael): 'In the hash mode, k0...k7 are constants IV0...IV7,
            //                and no additional flags are set.'
            data->k[0] = kryptos_blake3_IV[0];
            data->k[1] = kryptos_blake3_IV[1];
            data->k[2] = kryptos_blake3_IV[2];
            data->k[3] = kryptos_blake3_IV[3];
            data->k[4] = kryptos_blake3_IV[4];
            data->k[5] = kryptos_blake3_IV[5];
            data->k[6] = kryptos_blake3_IV[6];
            data->k[7] = kryptos_blake3_IV[7];
            data->d = 0;
            break;

        case kBLAKE3ModeKeyedHash:
            // INFO(Rafael): 'In the keyed_hash mode, k0...k7 are parsed in little-endian order
            //                from the 256-bit key given by the caller, and the KEYED_HASH flag is set
            //                for every compression.'
            data->k[ 0] = kryptos_get_u32_as_little_endian(&data->key[ 0], sizeof(kryptos_u32_t));
            data->k[ 1] = kryptos_get_u32_as_little_endian(&data->key[ 4], sizeof(kryptos_u32_t));
            data->k[ 2] = kryptos_get_u32_as_little_endian(&data->key[ 8], sizeof(kryptos_u32_t));
            data->k[ 3] = kryptos_get_u32_as_little_endian(&data->key[12], sizeof(kryptos_u32_t));
            data->k[ 4] = kryptos_get_u32_as_little_endian(&data->key[16], sizeof(kryptos_u32_t));
            data->k[ 5] = kryptos_get_u32_as_little_endian(&data->key[20], sizeof(kryptos_u32_t));
            data->k[ 6] = kryptos_get_u32_as_little_endian(&data->key[24], sizeof(kryptos_u32_t));
            data->k[ 7] = kryptos_get_u32_as_little_endian(&data->key[28], sizeof(kryptos_u32_t));
            data->d = KRYPTOS_BLAKE3_KEYED_HASH;
            break;

        case kBLAKE3ModeDeriveKey1stStage:
            // INFO(Rafael): 'The third mode, derive_key, has two stages. First the context string is
            //                hashed, with k0...k7 set to the constants IV0...IV7, and the DERIVE_KEY_CONTEXT
            //                flag set for every compression.'
            data->k[0] = kryptos_blake3_IV[0];
            data->k[1] = kryptos_blake3_IV[1];
            data->k[2] = kryptos_blake3_IV[2];
            data->k[3] = kryptos_blake3_IV[3];
            data->k[4] = kryptos_blake3_IV[4];
            data->k[5] = kryptos_blake3_IV[5];
            data->k[6] = kryptos_blake3_IV[6];
            data->k[7] = kryptos_blake3_IV[7];
            data->d = KRYPTOS_BLAKE3_DERIVE_KEY_CONTEXT;
            break;

        case kBLAKE3ModeDeriveKey2ndStage:
            // INFO(Rafael): 'Then the key material is hashed, with k0 ... k7 set to the first 8 output
            //                words of the first stage, and the DERIVE_KEY_MATERIAL flag set for every
            //                compression.'
            data->k[0] = data->h[0];
            data->k[1] = data->h[1];
            data->k[2] = data->h[2];
            data->k[3] = data->h[3];
            data->k[4] = data->h[4];
            data->k[5] = data->h[5];
            data->k[6] = data->h[6];
            data->k[7] = data->h[7];
            data->d = KRYPTOS_BLAKE3_DERIVE_KEY_MATERIAL;
            break;
    }

    // INFO(Rafael): 'The input chaining value h0...h7 for the first block of each chunk is composed of the
    //                key words k0...k7.'

    data->v[0] = data->h[0] = data->k[0];
    data->v[1] = data->h[1] = data->k[1];
    data->v[2] = data->h[2] = data->k[2];
    data->v[3] = data->h[3] = data->k[3];
    data->v[4] = data->h[4] = data->k[4];
    data->v[5] = data->h[5] = data->k[5];
    data->v[6] = data->h[6] = data->k[6];
    data->v[7] = data->h[7] = data->k[7];

    ip = data->in;
    ip_end = ip + data->in_size;

    // INFO(Rafael): 'The first block of each chunk sets the CHUNK_START flag, and the last block
    //                of each chunk sets the CHUNK_END flag.'
    data->d |= KRYPTOS_BLAKE3_CHUNK_START;

    memset(data->m, 0, sizeof(data->m));

    mi = 0;

    data->t = 0;
    data->pc_stack = NULL;
    data->pc_state = kBLAKE3PCGetL;
    data->chunk_nr = 0;
    data->curr_out_size = 0;

    do {
        // INFO(Rafael): Getting the next block.
        if ((ip_end - ip) >= sizeof(kryptos_u32_t)) {
            data->m[mi++] = kryptos_get_u32_as_little_endian(ip, sizeof(kryptos_u32_t));
            data->b += sizeof(kryptos_u32_t);
            ip += sizeof(kryptos_u32_t);
        } else {
            delta_off = (ip_end - ip);
            data->b += (kryptos_u32_t)delta_off;
            while (ip != ip_end) {
                data->m[mi] = data->m[mi] << 8 | (kryptos_u32_t)ip[0];
                ip++;
            }
            data->m[mi] <<= ((sizeof(kryptos_u32_t) - delta_off) << 3);
            data->m[mi] = kryptos_u32_rev(data->m[mi]);
            block_nr = 15;
            mi = 16;
        }

        if (mi == 16 || ip == ip_end) {
            block_nr++;
            if (block_nr == 16 || ip == ip_end) {
                // INFO(Rafael): '(blah blah blah)...and the last block of each chunk sets the CHUNK_END flag.'
                data->d |= KRYPTOS_BLAKE3_CHUNK_END;
            }
            if (ip == ip_end && data->in_size <= (KRYPTOS_BLAKE3_BYTES_PER_BLOCK<<4)) {
                data->d |= KRYPTOS_BLAKE3_ROOT;
            }
            // INFO(Rafael): v[0] .. v[7] is already set with the last result of compression.
            data->v[ 8] = kryptos_blake3_IV[ 0];
            data->v[ 9] = kryptos_blake3_IV[ 1];
            data->v[10] = kryptos_blake3_IV[ 2];
            data->v[11] = kryptos_blake3_IV[ 3];
            data->v[12] = data->t & 0xFFFFFFFF;
            data->v[13] = data->t >> 32;
            data->v[14] = data->b;
            data->v[15] = data->d;
            if (data->d & KRYPTOS_BLAKE3_ROOT) {
                kryptos_blake3_save_ctx_regs(data);
            }
            kryptos_blake3_COMPRESS(data);
            if (op != NULL && (data->d & KRYPTOS_BLAKE3_ROOT)) {
                if (op >= op_end) {
                    // INFO(Rafael): It should never happen in normal conditions.
                    kryptos_freeseg(data->out, data->out_size);
                    data->out = NULL;
                    data->out_size = 0;
                    return KRYPTOS_BLAKE3_EXIT_FAILURE;
                }
                // INFO(Rafael): 'BLAKE3 can produce outputs of any byte length 0 <= l < 2^64.
                //                This is done by repeating the root compression - that is, the very
                //                last call to the compression function, which sets the ROOT flag -
                //                with incrementing values of the counter t. The results of these
                //                repeated root compressions are then concatenated to form the output.'
                //
                //                But here this output getting is only for cases when we have an input less than
                //                or equals to the chunk size (1KB). Because in this case the last block
                //                of this only chunk will be the ROOT. On cases that input is greater than 1KB,
                //                we will use the output getting from the parent processing part.
                kryptos_blake3_get_sum(data);
            }
            if (block_nr == 16 || ip == ip_end) {
                if (op == NULL
                    && kryptos_blake3_do_parents(data, ip, ip_end) == KRYPTOS_BLAKE3_EXIT_FAILURE) {
                    break;
                }
                // INFO(Rafael): It means that we consumed 16 * 64 bytes = 1024 bytes = one more chunk.
                data->t += 1;
                // INFO(Rafael): 'The first block of each chunk sets the CHUNK_START flag'.
                data->d = KRYPTOS_BLAKE3_CHUNK_START;
                if (data->mode == kBLAKE3ModeKeyedHash) {
                    data->d |= KRYPTOS_BLAKE3_KEYED_HASH;
                } else if (data->mode == kBLAKE3ModeDeriveKey1stStage) {
                    data->d |= KRYPTOS_BLAKE3_DERIVE_KEY_CONTEXT;
                } else if (data->mode == kBLAKE3ModeDeriveKey2ndStage) {
                    data->d |= KRYPTOS_BLAKE3_DERIVE_KEY_MATERIAL;
                }
                if (ip < ip_end) {
                    // INFO(Rafael): 'The input chaining value h0...h7 for the first block of each chunk is composed of the
                    //               key words k0...k7.'
                    data->v[0] = data->h[0] = data->k[0];
                    data->v[1] = data->h[1] = data->k[1];
                    data->v[2] = data->h[2] = data->k[2];
                    data->v[3] = data->h[3] = data->k[3];
                    data->v[4] = data->h[4] = data->k[4];
                    data->v[5] = data->h[5] = data->k[5];
                    data->v[6] = data->h[6] = data->k[6];
                    data->v[7] = data->h[7] = data->k[7];
                }
                block_nr = 0;
            }
            mi = 0;
            memset(data->m, 0, sizeof(data->m));
            if (block_nr > 0) {
                data->d &= (~KRYPTOS_BLAKE3_CHUNK_START);
            }
            data->b = 0;
        }
        done = (op == NULL) ? ip >= ip_end : data->curr_out_size >= data->wanted_out_size;
    } while (!done);

    return KRYPTOS_BLAKE3_EXIT_SUCCESS;
}

static int kryptos_blake3_do_parents(struct kryptos_blake3_ctx *data,
                                     const kryptos_u8_t *curr_input,
                                     const kryptos_u8_t *input_end) {
    int err = KRYPTOS_BLAKE3_EXIT_FAILURE;

    err = kryptos_blake3_flush_pc_stack(data, curr_input, input_end);

    if (err == KRYPTOS_BLAKE3_EXIT_SUCCESS
        && curr_input == input_end
        && data->mode != kBLAKE3ModeDeriveKey1stStage) {
        while (err == KRYPTOS_BLAKE3_EXIT_SUCCESS
               && !kryptos_blake3_is_pc_stack_empty(data->pc_stack)
               && data->pc_stack->next != NULL) {
            err = kryptos_blake3_pc_do_compress(data,
                                                curr_input,
                                                input_end);
        }
        data->t = 1;
        data->out_size = data->wanted_out_size;
        while (data->out_size % KRYPTOS_BLAKE3_HASH_SIZE) {
            data->out_size++;
        }
        data->out = (kryptos_u8_t *)kryptos_newseg(data->out_size);
        if (data->out == NULL) {
            data->out_size = 0;
            err = KRYPTOS_BLAKE3_EXIT_FAILURE;
            goto kryptos_blake3_do_parents_epilogue;
        }
        // INFO(Rafael): 'BLAKE3 can produce outputs of any byte length 0 <= l < 2^64. This is done
        //                by repeating the root compression - that is, the very last call to the compression
        //                function, which sets the ROOT flag - with incrementing values of the counter t.
        //                The results of these repeated root compressions are then concatenated to form output.'
        //
        kryptos_blake3_get_sum(data);
    }

    if (err == KRYPTOS_BLAKE3_EXIT_SUCCESS && curr_input == input_end) {
        while (!kryptos_blake3_is_pc_stack_empty(data->pc_stack)) {
            kryptos_blake3_pop_pc(&data->pc_stack, &data->m[0]);
        }
    }

kryptos_blake3_do_parents_epilogue:

    return err;
}

static int kryptos_blake3_flush_pc_stack(struct kryptos_blake3_ctx *data,
                                         const kryptos_u8_t *curr_input,
                                         const kryptos_u8_t *input_end) {
    int err = KRYPTOS_BLAKE3_EXIT_FAILURE;

    err = kryptos_blake3_push_pc(&data->pc_stack, data->h);
    if (err != KRYPTOS_BLAKE3_EXIT_SUCCESS) {
        goto kryptos_blake3_flush_pc_stack_epilogue;
    }

    data->chunk_nr += 1;

    switch (data->pc_state) {
        case kBLAKE3PCGetL:
            data->pc_state = kBLAKE3PCGetR;
            break;

        case kBLAKE3PCGetR:
            err = kryptos_blake3_pc_do_compress(data, curr_input, input_end);
            if (err == KRYPTOS_BLAKE3_EXIT_SUCCESS) {
                data->pc_state = kBLAKE3PCGetL;
            }
            break;

        default:
            err = KRYPTOS_BLAKE3_EXIT_FAILURE;
            break;
    }

kryptos_blake3_flush_pc_stack_epilogue:

    return KRYPTOS_BLAKE3_EXIT_SUCCESS;
}

static int kryptos_blake3_pc_do_compress(struct kryptos_blake3_ctx *data,
                                         const kryptos_u8_t *curr_input,
                                         const kryptos_u8_t *input_end) {
    int err = KRYPTOS_BLAKE3_EXIT_FAILURE;
    // TIP(Rafael): data->chunk_nr >> 1 indicate us if we need to do at least one more recompression.
    //              "Minus" one because we already processed one in advance (before the while loop).
    //              When we arrive here, we got at least one chunk pair, so this first is always unconditional.
    //              Any doubt check on the spec in section 5.1.2.
    size_t temp = data->chunk_nr >> 1;
    int is_input_end = (curr_input == input_end);

    err = kryptos_blake3_pc_compress(data, is_input_end);

    while (err == KRYPTOS_BLAKE3_EXIT_SUCCESS
           && ((temp & 0x1) == 0)
           && !kryptos_blake3_is_pc_stack_empty(data->pc_stack)
           && data->pc_stack->next != NULL) {
        err = kryptos_blake3_pc_compress(data, is_input_end);
        temp >>= 1;
    }

    return err;
}

static int kryptos_blake3_pc_compress(struct kryptos_blake3_ctx *data,
                                      const int is_input_end) {
    int err = KRYPTOS_BLAKE3_EXIT_FAILURE;
    // INFO(Rafael): We will compress those two childs and push the result back.
    data->v[ 8] = kryptos_blake3_IV[ 0];
    data->v[ 9] = kryptos_blake3_IV[ 1];
    data->v[10] = kryptos_blake3_IV[ 2];
    data->v[11] = kryptos_blake3_IV[ 3];
    data->v[12] = 0; // INFO(Rafael): t's fraction
    data->v[13] = 0; // INFO(Rafael): t's fraction
    data->v[14] = KRYPTOS_BLAKE3_BYTES_PER_BLOCK;
    data->v[15] = KRYPTOS_BLAKE3_PARENT;

    data->v[0] = data->h[0] = data->k[0];
    data->v[1] = data->h[1] = data->k[1];
    data->v[2] = data->h[2] = data->k[2];
    data->v[3] = data->h[3] = data->k[3];
    data->v[4] = data->h[4] = data->k[4];
    data->v[5] = data->h[5] = data->k[5];
    data->v[6] = data->h[6] = data->k[6];
    data->v[7] = data->h[7] = data->k[7];

    err = kryptos_blake3_pop_pc(&data->pc_stack, &data->m[8]);
    if (err != KRYPTOS_BLAKE3_EXIT_SUCCESS) {
        goto kryptos_blake3_pc_compress_epilogue;
    }

    err = kryptos_blake3_pop_pc(&data->pc_stack, &data->m[0]);
    if (err != KRYPTOS_BLAKE3_EXIT_SUCCESS) {
        goto kryptos_blake3_pc_compress_epilogue;
    }

    if (is_input_end && kryptos_blake3_is_pc_stack_empty(data->pc_stack)) {
        data->v[15] |= KRYPTOS_BLAKE3_ROOT;
    }
    if (data->mode == kBLAKE3ModeKeyedHash) {
        data->v[15] |= KRYPTOS_BLAKE3_KEYED_HASH;
    } else if (data->mode == kBLAKE3ModeDeriveKey1stStage) {
        data->v[15] |= KRYPTOS_BLAKE3_DERIVE_KEY_CONTEXT;
    } else if (data->mode == kBLAKE3ModeDeriveKey2ndStage) {
        data->v[15] |= KRYPTOS_BLAKE3_DERIVE_KEY_MATERIAL;
    }

    if (data->v[15] & KRYPTOS_BLAKE3_ROOT) {
        kryptos_blake3_save_ctx_regs(data);
    }

    kryptos_blake3_COMPRESS(data);

    err = kryptos_blake3_push_pc(&data->pc_stack, data->h);

kryptos_blake3_pc_compress_epilogue:

    return err;
}

static int kryptos_blake3_push_pc(struct kryptos_blake3_pc_stack_ctx **pc_stack, const kryptos_u32_t *h) {
    struct kryptos_blake3_pc_stack_ctx *new_item = NULL;

    if (pc_stack == NULL || h == NULL) {
        return KRYPTOS_BLAKE3_EXIT_FAILURE;
    }

    kryptos_blake3_new_pc_stack_item(new_item, h);
    if (new_item == NULL) {
        return KRYPTOS_BLAKE3_EXIT_FAILURE;
    }

    if (*pc_stack != NULL) {
        new_item->next = (*pc_stack);
    }

    (*pc_stack) = new_item;

    return KRYPTOS_BLAKE3_EXIT_SUCCESS;
}

static int kryptos_blake3_pop_pc(struct kryptos_blake3_pc_stack_ctx **pc_stack, kryptos_u32_t *h) {
    struct kryptos_blake3_pc_stack_ctx *new_top = NULL;

    if (pc_stack == NULL || kryptos_blake3_is_pc_stack_empty(*pc_stack) || h == NULL) {
        return KRYPTOS_BLAKE3_EXIT_FAILURE;
    }

    new_top = (*pc_stack)->next;
    memcpy(h, (*pc_stack)->h, sizeof((*pc_stack)->h));
    kryptos_blake3_free_pc_stack_item((*pc_stack));
    (*pc_stack) = new_top;

    return KRYPTOS_BLAKE3_EXIT_SUCCESS;
}

static int kryptos_blake3_get_sum(struct kryptos_blake3_ctx *data) {
    kryptos_u8_t *op = NULL;
    kryptos_u8_t *op_end = NULL;
    int should_compress_more = 1;

    if (data->out == NULL || data->out_size == 0 || data->wanted_out_size == 0) {
        return KRYPTOS_BLAKE3_EXIT_FAILURE;
    }

    data->t = 1;

    op = data->out;
    op_end = op + data->out_size;
    // INFO(Rafael): 'BLAKE3 can produce outputs of any byte length 0 <= l < 2^64. This is done
    //                by repeating the root compression - that is, the very last call to the compression
    //                function, which sets the ROOT flag - with incrementing values of the counter t.
    //                The results of these repeated root compressions are then concatenated to form output.'
    //
    do {
        op[ 0] =  data->v[0] & 0xFF;
        op[ 1] = (data->v[0] >>  8) & 0xFF;
        op[ 2] = (data->v[0] >> 16) & 0xFF;
        op[ 3] =  data->v[0] >> 24;
        op[ 4] =  data->v[1] & 0xFF;
        op[ 5] = (data->v[1] >>  8) & 0xFF;
        op[ 6] = (data->v[1] >> 16) & 0xFF;
        op[ 7] =  data->v[1] >> 24;
        op[ 8] =  data->v[2] & 0xFF;
        op[ 9] = (data->v[2] >>  8) & 0xFF;
        op[10] = (data->v[2] >> 16) & 0xFF;
        op[11] =  data->v[2] >> 24;
        op[12] =  data->v[3] & 0xFF;
        op[13] = (data->v[3] >>  8) & 0xFF;
        op[14] = (data->v[3] >> 16) & 0xFF;
        op[15] =  data->v[3] >> 24;
        op[16] =  data->v[4] & 0xFF;
        op[17] = (data->v[4] >>  8) & 0xFF;
        op[18] = (data->v[4] >> 16) & 0xFF;
        op[19] =  data->v[4] >> 24;
        op[20] =  data->v[5] & 0xFF;
        op[21] = (data->v[5] >>  8) & 0xFF;
        op[22] = (data->v[5] >> 16) & 0xFF;
        op[23] =  data->v[5] >> 24;
        op[24] =  data->v[6] & 0xFF;
        op[25] = (data->v[6] >>  8) & 0xFF;
        op[26] = (data->v[6] >> 16) & 0xFF;
        op[27] =  data->v[6] >> 24;
        op[28] =  data->v[7] & 0xFF;
        op[29] = (data->v[7] >>  8) & 0xFF;
        op[30] = (data->v[7] >> 16) & 0xFF;
        op[31] =  data->v[7] >> 24;
        op += 32;
        data->curr_out_size += 32;
        should_compress_more = (data->curr_out_size < data->wanted_out_size && op < op_end);
        if (should_compress_more) {
            // INFO(Rafael): This implementation always spits outputs that are 32-byte multiple,
            //               if we should compress more, for sure that we have at least more
            //               32-bytes unfilled ahead in the output buffer.
            op[ 0] =  data->v[ 8] & 0xFF;
            op[ 1] = (data->v[ 8] >>  8) & 0xFF;
            op[ 2] = (data->v[ 8] >> 16) & 0xFF;
            op[ 3] =  data->v[ 8] >> 24;
            op[ 4] =  data->v[ 9] & 0xFF;
            op[ 5] = (data->v[ 9] >>  8) & 0xFF;
            op[ 6] = (data->v[ 9] >> 16) & 0xFF;
            op[ 7] =  data->v[ 9] >> 24;
            op[ 8] =  data->v[10] & 0xFF;
            op[ 9] = (data->v[10] >>  8) & 0xFF;
            op[10] = (data->v[10] >> 16) & 0xFF;
            op[11] =  data->v[10] >> 24;
            op[12] =  data->v[11] & 0xFF;
            op[13] = (data->v[11] >>  8) & 0xFF;
            op[14] = (data->v[11] >> 16) & 0xFF;
            op[15] =  data->v[11] >> 24;
            op[16] =  data->v[12] & 0xFF;
            op[17] = (data->v[12] >>  8) & 0xFF;
            op[18] = (data->v[12] >> 16) & 0xFF;
            op[19] =  data->v[12] >> 24;
            op[20] =  data->v[13] & 0xFF;
            op[21] = (data->v[13] >>  8) & 0xFF;
            op[22] = (data->v[13] >> 16) & 0xFF;
            op[23] =  data->v[13] >> 24;
            op[24] =  data->v[14] & 0xFF;
            op[25] = (data->v[14] >>  8) & 0xFF;
            op[26] = (data->v[14] >> 16) & 0xFF;
            op[27] =  data->v[14] >> 24;
            op[28] =  data->v[15] & 0xFF;
            op[29] = (data->v[15] >>  8) & 0xFF;
            op[30] = (data->v[15] >> 16) & 0xFF;
            op[31] =  data->v[15] >> 24;
            op += 32;
            data->curr_out_size += 32;
            if (data->curr_out_size > data->wanted_out_size || op >= op_end) {
                break;
            }
            kryptos_blake3_restore_ctx_regs(data);
            data->v[12] = data->t & 0xFFFFFFFF;
            data->v[13] = data->t >> 32;
            kryptos_blake3_COMPRESS(data);
            data->t += 1;
        }
    } while (should_compress_more);

    return KRYPTOS_BLAKE3_EXIT_SUCCESS;
}

#undef KRYPTOS_BLAKE3_BYTES_PER_BLOCK

#undef KRYPTOS_BLAKE3_HASH_SIZE

#undef kryptos_blake3_RSH

#undef kryptos_blake3_G

#undef kryptos_blake3_ROUND

#undef kryptos_blake3_PERM

#undef kryptos_blake3_COMPRESS

#undef kryptos_blake3_save_ctx_regs

#undef kryptos_blake3_restore_ctx_regs

#undef KRYPTOS_BLAKE3_CHUNK_START
#undef KRYPTOS_BLAKE3_CHUNK_END
#undef KRYPTOS_BLAKE3_PARENT
#undef KRYPTOS_BLAKE3_ROOT
#undef KRYPTOS_BLAKE3_KEYED_HASH
#undef KRYPTOS_BLAKE3_DERIVE_KEY_CONTEXT
#undef KRYPTOS_BLAKE3_DERIVE_KEY_MATERIAL

#undef KRYPTOS_BLAKE3_EXIT_FAILURE
#undef KRYPTOS_BLAKE3_EXIT_SUCCESS

#undef kryptos_blake3_is_pc_stack_empty

#undef kryptos_blake3_new_pc_stack_item

#undef kryptos_blake3_free_pc_stack_item
