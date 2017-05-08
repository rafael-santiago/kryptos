/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_huffman.h>
#include <kryptos_memory.h>
#include <string.h>

#define KRYPTOS_HUFFMAN_MAX_CODE_SIZE 255

#define kryptos_huffman_new_tree(t) {\
    (t) = (struct kryptos_huffman_tree_ctx *) kryptos_newseg(sizeof(struct kryptos_huffman_tree_ctx));\
    (t)->l = NULL;\
    (t)->r = NULL;\
    (t)->byte = 0;\
}

#define kryptos_huffman_del_tree(t) {\
    kryptos_huffman_deltree_recurr((t));\
    kryptos_freeseg((t));\
    (t) = NULL;\
}

struct kryptos_huffman_tree_ctx {
    kryptos_u8_t byte;
    struct kryptos_huffman_tree_ctx *l, *r;
};

struct kryptos_huffman_freq_ctx {
    kryptos_u8_t byte;
    size_t freq;
    struct kryptos_huffman_tree_ctx *subtree;
};

static struct kryptos_huffman_freq_ctx freq_table[256];

static struct kryptos_huffman_tree_ctx *htree = NULL;

static kryptos_u8_t hcodes[256][KRYPTOS_HUFFMAN_MAX_CODE_SIZE];

static void kryptos_huffman_eval_byte_freq(const kryptos_u8_t *in, const size_t in_size);

static void kryptos_huffman_sort_nodes(void);

static void kryptos_huffman_mktree(void);

static void kryptos_huffman_get_codes(void);

static void kryptos_huffman_scan_codes(kryptos_u8_t *path_buff, const size_t path_index, const size_t path_buff_size, struct kryptos_huffman_tree_ctx *branch);

static void kryptos_huffman_deltree_recurr(struct kryptos_huffman_tree_ctx *htree);

static void kryptos_huffman_eval_byte_freq(const kryptos_u8_t *in, const size_t in_size) {
    const kryptos_u8_t *in_p, *in_p_end;
    struct kryptos_huffman_freq_ctx *curr_byte;

    memset(freq_table, 0, sizeof(freq_table));

    in_p = in;
    in_p_end = in + in_size;

    while (in_p != in_p_end) {
        curr_byte = &freq_table[*in_p];

        if (curr_byte->byte == 0) {
            curr_byte->byte = *in_p;
        }

        curr_byte->freq++;

        in_p++;
    }

    kryptos_huffman_sort_nodes();
}

static void kryptos_huffman_sort_nodes(void) {
    int swp;
    struct kryptos_huffman_freq_ctx aux;
    size_t n;

    swp = 1;

    while (swp) {
        swp = 0;

        for (n = 0; n < 254 && swp == 0; n++) {
            if (freq_table[n].freq > freq_table[n + 1].freq) {
                aux = freq_table[n];
                freq_table[n] = freq_table[n + 1];
                freq_table[n + 1] = aux;
                swp = 1;
            }
        }
    }
/*
    for (n = 0; n < 255; n++) {
        if (freq_table[n].freq > 0) {
            printf("%c %d times.\n", freq_table[n].byte, freq_table[n].freq);
        }
    }
    printf("--\n");
*/
}

static void kryptos_huffman_mktree(void) {
    size_t n;
    int has_merged = 1;
    struct kryptos_huffman_tree_ctx *subtree = NULL;

    for (n = 0; n < 255; n++) {
        if (freq_table[n].freq > 0) {
            kryptos_huffman_new_tree(freq_table[n].subtree);
            kryptos_huffman_new_tree(freq_table[n].subtree->l);
            freq_table[n].subtree->l->byte = freq_table[n].byte;
        }
    }

    while (has_merged) {
        has_merged = 0;
        for (n = 0; n < 254; n++) {
            if (freq_table[n].freq > 0 && freq_table[n + 1].freq > 0) {
                if (freq_table[n].subtree->r == NULL) {
                    // INFO(Rafael): freq_table[n].subtree->r points.
                    freq_table[n].subtree->r = (freq_table[n + 1].subtree->r == NULL) ?
                                                    freq_table[n + 1].subtree->l :
                                                    freq_table[n + 1].subtree;
                    freq_table[n].freq += freq_table[n + 1].freq;
                    freq_table[n].byte = 0;
                    freq_table[n + 1].byte = 0;
                    freq_table[n + 1].freq = 0;
                    if (freq_table[n + 1].subtree->r == NULL) {
                        kryptos_freeseg(freq_table[n + 1].subtree);
                    }
                    freq_table[n + 1].subtree = NULL;
                    htree = freq_table[n].subtree;
                } else if (freq_table[n + 1].subtree->r == NULL) {
                    // INFO(Rafael): freq_table[n + 1].subtree->r points.
                    freq_table[n + 1].subtree->r = (freq_table[n].subtree->r == NULL) ?
                                                        freq_table[n].subtree->l :
                                                        freq_table[n].subtree;
                    freq_table[n + 1].freq += freq_table[n].freq;
                    freq_table[n + 1].byte = 0;
                    freq_table[n].byte = 0;
                    freq_table[n].freq = 0;
                    if (freq_table[n].subtree->r == NULL) {
                        kryptos_freeseg(freq_table[n].subtree);
                    }
                    freq_table[n].subtree = NULL;
                    htree = freq_table[n + 1].subtree;
                } else {
                    // INFO(Rafael): A new subtree points (L: freq_table[n].subtree / R: freq_table[n+1].subtree).
                    subtree = freq_table[n].subtree;
                    freq_table[n].freq += freq_table[n + 1].freq;
                    kryptos_huffman_new_tree(freq_table[n].subtree);
                    freq_table[n].subtree->l = subtree;
                    freq_table[n].subtree->r = freq_table[n + 1].subtree;
                    freq_table[n + 1].subtree = NULL;
                    freq_table[n + 1].freq = 0;
                    htree = freq_table[n].subtree;
                }
                kryptos_huffman_sort_nodes();
            }
        }
    }
}

static void kryptos_huffman_deltree_recurr(struct kryptos_huffman_tree_ctx *htree) {
    if (htree == NULL) {
        return;
    }

    kryptos_huffman_deltree_recurr(htree->l);

    kryptos_huffman_deltree_recurr(htree->r);

    if (htree->l != NULL) {
        kryptos_freeseg(htree->l);
        htree->l = NULL;
    }

    if (htree->r != NULL) {
        kryptos_freeseg(htree->r);
        htree->r = NULL;
    }
}

static void kryptos_huffman_get_codes(void) {
    kryptos_u8_t path_buff[KRYPTOS_HUFFMAN_MAX_CODE_SIZE];
    kryptos_huffman_scan_codes(path_buff, 0, KRYPTOS_HUFFMAN_MAX_CODE_SIZE, htree);
}

static void kryptos_huffman_scan_codes(kryptos_u8_t *path_buff, const size_t path_index, const size_t path_buff_size, struct kryptos_huffman_tree_ctx *branch) {
    kryptos_u8_t *code;

    if (path_index > path_buff_size) {
        // WARN(Rafael): It should never happen.
        return;
    }

    if (branch->l == NULL && branch->r == NULL) {
        code = &hcodes[branch->byte][0];
        memset(code, 0, sizeof(code));
        memcpy(code, path_buff, path_index);
        //printf("%c %s\n", branch->byte, code);
        return;
    }

    if (branch->l != NULL) {
        path_buff[path_index] = '0';
        kryptos_huffman_scan_codes(path_buff, path_index + 1, path_buff_size, branch->l);
    }

    if (branch->r != NULL) {
        path_buff[path_index] = '1';
        kryptos_huffman_scan_codes(path_buff, path_index + 1, path_buff_size, branch->r);
    }
}

kryptos_u8_t *kryptos_huffman_deflate(const kryptos_u8_t *in, const size_t in_size) {
    // INFO(Rafael): Huffman coding evaluation.
    kryptos_huffman_eval_byte_freq(in, in_size);
    kryptos_huffman_mktree();
    kryptos_huffman_get_codes();
    kryptos_huffman_del_tree(htree);
}
