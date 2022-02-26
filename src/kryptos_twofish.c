/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_twofish.h>
#include <kryptos_task_check.h>
#include <kryptos_padding.h>
#include <kryptos.h>

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// Máxima: 'Uhmm vou implementar o Twofish só de zoeira, perdeu o AES deve ser tranquilo, baba! Vou completar a         !!
//              implementação dos cinco finalistas, meu "mini Everest" pessoal... Deixa eu ver a spec aqui...'          !!                                                                   !!
//                                                                                                                      !!
//         Três semanas depois, ainda preso nessa represa de castor chamada Twofish. [Thu 17 Feb 2022 01:34:12 AM BRST] !!
//                                                                                                                      !!
//         Tem certeza que quer ler isso? É meio... insalubre! Sugiro usar por fora e ser feliz. Enfim... eu te avisei  !!
//         passou daqui, deixe sua sanidade do lado de fora antes de prosseguir.                                        !!
//                                                                                                                      !!
//         Se atualizassem os doze trabalhos de Hércules, haveria um décimo terceiro que seria implementar o Twofish,   !!
//         quase certo. Reza a lenda que Dante chegou num dos círculos do inferno e tinha uma sala lotada de 486, com   !!
//         muita gente "boa" implementando o Twofish por lá, um galerão!... Por isso já sigo ensaiando e vejo que você  !!
//         também... ba-dum-tssss!!!! :-P                                                                               !!
//                                                                                                                      !!
//         Última tentativa: ouça o Black Knight do Monty Python -> 'Thou shall not pass'. Vai lá mesmo assim?!         !!
//                                                                                         Boa sorte, nóia!             !!
//                                                                                                                      !!
//                                                                                                           -- Rafael  !!
//         Segue um incentivo para as almas corajosas:                                                                  !!
//                                                                                                                      !!
//              '- Follow. But! Follow only if ye be men of valour, for the entrance to this cave is guarded by a       !!
//                 creature so foul, so cruel that no man yet has fought with it and lived! Bones of full fifty men lie !!
//                 strewn about its lair. So, brave knights, if you do doubt your courage of your strength, come no     !!
//                 further, for death awaits you all with nasty, big, pointy tee-tee-TEETH!' -- Tim the Enchanter       !!
//                                                                                                                      !!
//              '- What an eccentric performance.' -- Arthur                                                            !!
// -----------------------------------------------------------------------------------------------------------------------
//         PS: E aí já voltou? Estou notando você meio confuso(a), desnorteado(a) e levemente traumatizado(a)...        !!
//             Já vai?! Vai não, pega a spec lá, bora estudar mais a fundo e fazer um refactoring!                      !!
//             MuHauhauhUAHUhauahuahuahauhauhauahauhaauHAUAhauAHAUHAuh!                                                 !!
//                                                                                                                      !!
//             '- I warned you, but did you listen to me? Oh, no, you knew it all, didn't you? Oh, it's just a harmless !!
//                little FISH [sic], isn't it? Well, it's always the same. I always tell them--' -- Tim the Enchanter   !!
//                                                                                                Warns of Rabbit Peril !!
//                                                                                                                      !!
//             '- Oh, shut up!' -- Arthur                                                                               !!
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

#define KRYPTOS_TWOFISH_SK_WORDS_NR            40
#define KRYPTOS_TWOFISH_SBOXES_NR               4
#define KRYPTOS_TWOFISH_S_NR            (256 >> 6) // INFO(Rafael): N/64 (Maximum N is 256).
#define KRYPTOS_TWOFISH_M_NR                    8  // INFO(Rafael): Maximum of words picked from input key.

// INFO(Rafael): Unfortunately Twofish is bloated with tons of presets and what could not be expressed as a preset
//               generates more instructions than keeping the result of those instructions as presets. For this implementation
//               I am considering that the price of having those presets in memory is cheapear than calculate them all
//               on-the-fly. Take a breath and here we go...

#if !defined(KRYPTOS_TWOFISH_WITH_PRE_COMPUTED_Q_PERMS)

static kryptos_u8_t kryptos_twofish_q0_lt[KRYPTOS_TWOFISH_SBOXES_NR][16] = {
    { 0x08, 0x01, 0x07, 0x0D, 0x06, 0x0F, 0x03, 0x02, 0x00, 0x0B, 0x05, 0x09, 0x0E, 0x0C, 0x0A, 0x04 },
    { 0x0E, 0x0C, 0x0B, 0x08, 0x01, 0x02, 0x03, 0x05, 0x0F, 0x04, 0x0A, 0x06, 0x07, 0x00, 0x09, 0x0D },
    { 0x0B, 0x0A, 0x05, 0x0E, 0x06, 0x0D, 0x09, 0x00, 0x0C, 0x08, 0x0F, 0x03, 0x02, 0x04, 0x07, 0x01 },
    { 0x0D, 0x07, 0x0F, 0x04, 0x01, 0x02, 0x06, 0x0E, 0x09, 0x0B, 0x03, 0x00, 0x08, 0x05, 0x0C, 0x0A }
};

static kryptos_u8_t kryptos_twofish_q1_lt[KRYPTOS_TWOFISH_SBOXES_NR][16] = {
    { 0x02, 0x08, 0x0B, 0x0D, 0x0F, 0x07, 0x06, 0x0E, 0x03, 0x01, 0x09, 0x04, 0x00, 0x0A, 0x0C, 0x05 },
    { 0x01, 0x0E, 0x02, 0x0B, 0x04, 0x0C, 0x03, 0x07, 0x06, 0x0D, 0x0A, 0x05, 0x0F, 0x09, 0x00, 0x08 },
    { 0x04, 0x0C, 0x07, 0x05, 0x01, 0x06, 0x09, 0x0A, 0x00, 0x0E, 0x0D, 0x08, 0x02, 0x0B, 0x03, 0x0F },
    { 0x0B, 0x09, 0x05, 0x01, 0x0C, 0x03, 0x0D, 0x0E, 0x06, 0x04, 0x07, 0x0F, 0x02, 0x00, 0x08, 0x0A }
};

#else

static kryptos_u8_t kryptos_twofish_q0_sbox[256] = {
    0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76,
    0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38,
    0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C,
    0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48,
    0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23,
    0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82,
    0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C,
    0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61,
    0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B,
    0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1,
    0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66,
    0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7,
    0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA,
    0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71,
    0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8,
    0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7,
    0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2,
    0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90,
    0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB,
    0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF,
    0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B,
    0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64,
    0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A,
    0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A,
    0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02,
    0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D,
    0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72,
    0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
    0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8,
    0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4,
    0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00,
    0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0
};

static kryptos_u8_t kryptos_twofish_q1_sbox[256] = {
    0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8,
    0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B,
    0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1,
    0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F,
    0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D,
    0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5,
    0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3,
    0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51,
    0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96,
    0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C,
    0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70,
    0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8,
    0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC,
    0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2,
    0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9,
    0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17,
    0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3,
    0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E,
    0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49,
    0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9,
    0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01,
    0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48,
    0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19,
    0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64,
    0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5,
    0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69,
    0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E,
    0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC,
    0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB,
    0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9,
    0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2,
    0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91
};

#endif

// INFO(Rafael): Multiplication based on GF(2^8) with irreducible polynomial equals to
//               x^8 + x^6 + x^5 + x^3 + 1 (a.k.a 0x169). It is used during encryption/decryption.
static kryptos_u8_t kryptos_twofish_mds_log_table[] = {
    0x00, 0x00, 0x10, 0x01, 0x20, 0x02, 0x11, 0xCC, 0x30, 0xCD, 0x12, 0x7D, 0x21, 0xD7, 0xDC, 0x03,
    0x40, 0x04, 0xDD, 0x77, 0x22, 0x99, 0x8D, 0xD8, 0x31, 0x19, 0xE7, 0xCE, 0xEC, 0x7E, 0x13, 0x91,
    0x50, 0x92, 0x14, 0xA4, 0xED, 0x6B, 0x87, 0x7F, 0x32, 0x62, 0xA9, 0x1A, 0x9D, 0xCF, 0xE8, 0xD3,
    0x41, 0x4A, 0x29, 0x05, 0xF7, 0x78, 0xDE, 0xB6, 0xFC, 0xD9, 0x8E, 0x3D, 0x23, 0x26, 0xA1, 0x9A,
    0x60, 0x9B, 0xA2, 0x85, 0x24, 0xFA, 0xB4, 0x27, 0xFD, 0x1E, 0x7B, 0xDA, 0x97, 0x3E, 0x8F, 0xE5,
    0x42, 0xAF, 0x72, 0x4B, 0xB9, 0x06, 0x2A, 0x58, 0xAD, 0xB7, 0xDF, 0xE1, 0xF8, 0x5E, 0xE3, 0x79,
    0x51, 0xC2, 0x5A, 0x93, 0x39, 0xA5, 0x15, 0x2C, 0x08, 0x80, 0x88, 0x66, 0xEE, 0xBB, 0xC6, 0x6C,
    0x0D, 0xD4, 0xE9, 0x74, 0x9E, 0x47, 0x4D, 0xD0, 0x33, 0x44, 0x36, 0x63, 0xB1, 0x1B, 0xAA, 0x55,
    0x70, 0x56, 0xAB, 0x5C, 0xB2, 0x83, 0x95, 0x1C, 0x34, 0x53, 0x0B, 0x45, 0xC4, 0x64, 0x37, 0xC0,
    0x0E, 0xCA, 0x2E, 0xD5, 0x8B, 0x75, 0xEA, 0x17, 0xA7, 0xD1, 0x4E, 0x69, 0x9F, 0x3B, 0xF5, 0x48,
    0x52, 0x0A, 0xBF, 0xC3, 0x82, 0x94, 0x5B, 0x6F, 0xC9, 0x2D, 0x16, 0x8A, 0x3A, 0xF4, 0x68, 0xA6,
    0xBD, 0x6D, 0xC7, 0xF2, 0xEF, 0xF0, 0xF1, 0xBC, 0x09, 0xBE, 0x6E, 0x81, 0xF3, 0x67, 0x89, 0xC8,
    0x61, 0xA8, 0xD2, 0x9C, 0x6A, 0x86, 0xA3, 0x4F, 0x49, 0x28, 0xB5, 0xF6, 0x25, 0xA0, 0x3C, 0xFB,
    0x18, 0xE6, 0x90, 0xEB, 0x98, 0x8C, 0x76, 0x3F, 0xFE, 0x0F, 0xCB, 0x1F, 0xD6, 0xDB, 0x7C, 0x2F,
    0x1D, 0x7A, 0xE4, 0x96, 0xF9, 0xB3, 0x84, 0x5F, 0xAE, 0x71, 0x57, 0xB8, 0x5D, 0xE2, 0xE0, 0xAC,
    0x43, 0x35, 0x54, 0xB0, 0x46, 0x4C, 0x73, 0x0C, 0xC1, 0x59, 0x2B, 0x38, 0xBA, 0xC5, 0x65, 0x07
};

static kryptos_u8_t kryptos_twofish_mds_antilog_table[] = {
    0x01, 0x03, 0x05, 0x0F, 0x11, 0x33, 0x55, 0xFF, 0x68, 0xB8, 0xA1, 0x8A, 0xF7, 0x70, 0x90, 0xD9,
    0x02, 0x06, 0x0A, 0x1E, 0x22, 0x66, 0xAA, 0x97, 0xD0, 0x19, 0x2B, 0x7D, 0x87, 0xE0, 0x49, 0xDB,
    0x04, 0x0C, 0x14, 0x3C, 0x44, 0xCC, 0x3D, 0x47, 0xC9, 0x32, 0x56, 0xFA, 0x67, 0xA9, 0x92, 0xDF,
    0x08, 0x18, 0x28, 0x78, 0x88, 0xF1, 0x7A, 0x8E, 0xFB, 0x64, 0xAC, 0x9D, 0xCE, 0x3B, 0x4D, 0xD7,
    0x10, 0x30, 0x50, 0xF0, 0x79, 0x8B, 0xF4, 0x75, 0x9F, 0xC8, 0x31, 0x53, 0xF5, 0x76, 0x9A, 0xC7,
    0x20, 0x60, 0xA0, 0x89, 0xF2, 0x7F, 0x81, 0xEA, 0x57, 0xF9, 0x62, 0xA6, 0x83, 0xEC, 0x5D, 0xE7,
    0x40, 0xC0, 0x29, 0x7B, 0x8D, 0xFE, 0x6B, 0xBD, 0xAE, 0x9B, 0xC4, 0x25, 0x6F, 0xB1, 0xBA, 0xA7,
    0x80, 0xE9, 0x52, 0xF6, 0x73, 0x95, 0xD6, 0x13, 0x35, 0x5F, 0xE1, 0x4A, 0xDE, 0x0B, 0x1D, 0x27,
    0x69, 0xBB, 0xA4, 0x85, 0xE6, 0x43, 0xC5, 0x26, 0x6A, 0xBE, 0xAB, 0x94, 0xD5, 0x16, 0x3A, 0x4E,
    0xD2, 0x1F, 0x21, 0x63, 0xA5, 0x86, 0xE3, 0x4C, 0xD4, 0x15, 0x3F, 0x41, 0xC3, 0x2C, 0x74, 0x9C,
    0xCD, 0x3E, 0x42, 0xC6, 0x23, 0x65, 0xAF, 0x98, 0xC1, 0x2A, 0x7E, 0x82, 0xEF, 0x58, 0xE8, 0x51,
    0xF3, 0x7C, 0x84, 0xE5, 0x46, 0xCA, 0x37, 0x59, 0xEB, 0x54, 0xFC, 0x6D, 0xB7, 0xB0, 0xB9, 0xA2,
    0x8F, 0xF8, 0x61, 0xA3, 0x8C, 0xFD, 0x6E, 0xB2, 0xBF, 0xA8, 0x91, 0xDA, 0x07, 0x09, 0x1B, 0x2D,
    0x77, 0x99, 0xC2, 0x2F, 0x71, 0x93, 0xDC, 0x0D, 0x17, 0x39, 0x4B, 0xDD, 0x0E, 0x12, 0x36, 0x5A,
    0xEE, 0x5B, 0xED, 0x5E, 0xE2, 0x4F, 0xD1, 0x1A, 0x2E, 0x72, 0x96, 0xD3, 0x1C, 0x24, 0x6C, 0xB4,
    0xB5, 0xB6, 0xB3, 0xBC, 0xAD, 0x9E, 0xCB, 0x34, 0x5C, 0xE4, 0x45, 0xCF, 0x38, 0x48, 0xD8
};

// INFO(Rafael): Multiplication based on GF(2^8) with irreducible polynomial equals to
//               x^8 + x^6 + x^3 + x^2 + 1 (a.k.a 0x14D). It is used during key schedule only.
static kryptos_u8_t kryptos_twofish_rs_log_table[] = {
    0x00, 0x00, 0x7A, 0x01, 0xF4, 0x02, 0x7B, 0xB5, 0x6F, 0xB6, 0x7C, 0x54, 0xF5, 0xE0, 0x30, 0x03,
    0xE9, 0x04, 0x31, 0x13, 0xF6, 0x6B, 0xCE, 0xE1, 0x70, 0xFA, 0x5B, 0xB7, 0xAA, 0x55, 0x7D, 0x38,
    0x64, 0x39, 0x7E, 0x96, 0xAB, 0x28, 0x8D, 0x56, 0x71, 0x92, 0xE5, 0xFB, 0x49, 0xB8, 0x5C, 0xA4,
    0xEA, 0x0A, 0x75, 0x05, 0xD5, 0x14, 0x32, 0x9C, 0x25, 0xE2, 0xCF, 0xD2, 0xF7, 0xCB, 0xB2, 0x6C,
    0xDE, 0x6D, 0xB3, 0x78, 0xF8, 0xA8, 0x11, 0xCC, 0x26, 0x62, 0xA2, 0xE3, 0x08, 0xD3, 0xD0, 0xB0,
    0xEB, 0xC1, 0x0D, 0x0B, 0x60, 0x06, 0x76, 0x0F, 0xC3, 0x9D, 0x33, 0x44, 0xD6, 0xED, 0x1F, 0x15,
    0x65, 0xD8, 0x84, 0x3A, 0xEF, 0x97, 0x7F, 0xBC, 0x50, 0x57, 0x8E, 0x21, 0xAC, 0x1B, 0x17, 0x29,
    0x9F, 0xA5, 0x5D, 0x41, 0x4A, 0xC5, 0x4D, 0xB9, 0x72, 0xC8, 0x46, 0x93, 0x2D, 0xFC, 0xE6, 0x35,
    0x59, 0x36, 0xE7, 0x69, 0x2E, 0x52, 0xF2, 0xFD, 0x73, 0x9A, 0x23, 0xC9, 0x8B, 0x94, 0x47, 0x90,
    0xA0, 0xAE, 0xDC, 0xA6, 0x1D, 0x42, 0x5E, 0xBF, 0x82, 0xBA, 0x4E, 0x19, 0x4B, 0x3F, 0x2B, 0xC6,
    0x66, 0x88, 0x3C, 0xD9, 0x87, 0x3B, 0x85, 0x86, 0xDA, 0xBD, 0x80, 0x3D, 0xF0, 0x67, 0x89, 0x98,
    0x3E, 0x2A, 0x18, 0x81, 0xAD, 0xDB, 0xBE, 0x1C, 0x51, 0xF1, 0x68, 0x58, 0x99, 0x22, 0x8F, 0x8A,
    0xDF, 0x2F, 0x53, 0x6E, 0xFE, 0x79, 0xB4, 0xF3, 0x6A, 0xCD, 0x12, 0xE8, 0xF9, 0x5A, 0x37, 0xA9,
    0xCA, 0xB1, 0xD1, 0x24, 0x09, 0x74, 0x9B, 0xD4, 0x27, 0x8C, 0x95, 0x63, 0x91, 0xE4, 0xA3, 0x48,
    0x1A, 0x16, 0x20, 0x4F, 0xD7, 0x83, 0xBB, 0xEE, 0xC4, 0x4C, 0x40, 0x9E, 0xC7, 0x45, 0x34, 0x2C,
    0xEC, 0x1E, 0x43, 0xC2, 0xC0, 0x0C, 0x0E, 0x5F, 0xA7, 0x10, 0x77, 0xDD, 0x61, 0xA1, 0xAF, 0x07
};

static kryptos_u8_t kryptos_twofish_rs_antilog_table[] = {
    0x01, 0x03, 0x05, 0x0F, 0x11, 0x33, 0x55, 0xFF, 0x4C, 0xD4, 0x31, 0x53, 0xF5, 0x52, 0xF6, 0x57,
    0xF9, 0x46, 0xCA, 0x13, 0x35, 0x5F, 0xE1, 0x6E, 0xB2, 0x9B, 0xE0, 0x6D, 0xB7, 0x94, 0xF1, 0x5E,
    0xE2, 0x6B, 0xBD, 0x8A, 0xD3, 0x38, 0x48, 0xD8, 0x25, 0x6F, 0xB1, 0x9E, 0xEF, 0x7C, 0x84, 0xC1,
    0x0E, 0x12, 0x36, 0x5A, 0xEE, 0x7F, 0x81, 0xCE, 0x1F, 0x21, 0x63, 0xA5, 0xA2, 0xAB, 0xB0, 0x9D,
    0xEA, 0x73, 0x95, 0xF2, 0x5B, 0xED, 0x7A, 0x8E, 0xDF, 0x2C, 0x74, 0x9C, 0xE9, 0x76, 0x9A, 0xE3,
    0x68, 0xB8, 0x85, 0xC2, 0x0B, 0x1D, 0x27, 0x69, 0xBB, 0x80, 0xCD, 0x1A, 0x2E, 0x72, 0x96, 0xF7,
    0x54, 0xFC, 0x49, 0xDB, 0x20, 0x60, 0xA0, 0xAD, 0xBA, 0x83, 0xC8, 0x15, 0x3F, 0x41, 0xC3, 0x08,
    0x18, 0x28, 0x78, 0x88, 0xD5, 0x32, 0x56, 0xFA, 0x43, 0xC5, 0x02, 0x06, 0x0A, 0x1E, 0x22, 0x66,
    0xAA, 0xB3, 0x98, 0xE5, 0x62, 0xA6, 0xA7, 0xA4, 0xA1, 0xAE, 0xBF, 0x8C, 0xD9, 0x26, 0x6A, 0xBE,
    0x8F, 0xDC, 0x29, 0x7B, 0x8D, 0xDA, 0x23, 0x65, 0xAF, 0xBC, 0x89, 0xD6, 0x37, 0x59, 0xEB, 0x70,
    0x90, 0xFD, 0x4A, 0xDE, 0x2F, 0x71, 0x93, 0xF8, 0x45, 0xCF, 0x1C, 0x24, 0x6C, 0xB4, 0x91, 0xFE,
    0x4F, 0xD1, 0x3E, 0x42, 0xC6, 0x07, 0x09, 0x1B, 0x2D, 0x77, 0x99, 0xE6, 0x67, 0xA9, 0xB6, 0x97,
    0xF4, 0x51, 0xF3, 0x58, 0xE8, 0x75, 0x9F, 0xEC, 0x79, 0x8B, 0xD0, 0x3D, 0x47, 0xC9, 0x16, 0x3A,
    0x4E, 0xD2, 0x3B, 0x4D, 0xD7, 0x34, 0x5C, 0xE4, 0x61, 0xA3, 0xA8, 0xB5, 0x92, 0xFB, 0x40, 0xC0,
    0x0D, 0x17, 0x39, 0x4B, 0xDD, 0x2A, 0x7E, 0x82, 0xCB, 0x10, 0x30, 0x50, 0xF0, 0x5D, 0xE7, 0x64,
    0xAC, 0xB9, 0x86, 0xC7, 0x04, 0x0C, 0x14, 0x3C, 0x44, 0xCC, 0x19, 0x2B, 0x7D, 0x87, 0xC4
};


#define KRYPTOS_TWOFISH_RS_R0 0x01A455875A58DB9E
#define KRYPTOS_TWOFISH_RS_R1 0xA45682F31EC668E5
#define KRYPTOS_TWOFISH_RS_R2 0x02A1FCC147AE3D19
#define KRYPTOS_TWOFISH_RS_R3 0xA455875A58DB9E03

#define KRYPTOS_TWOFISH_MDS_R0            0xEFEF5B01
#define KRYPTOS_TWOFISH_MDS_R1            0x015BEFEF
#define KRYPTOS_TWOFISH_MDS_R2            0xEF01EF5B
#define KRYPTOS_TWOFISH_MDS_R3            0x5BEF015B

#define kryptos_twofish_wrol(w, l) ( ((w) << (l)) | ((w) >> (32 - (l))) )

#define kryptos_twofish_wror(w, l) ( ((w) >> (l)) | ((w) << (32 - (l))) )

#define kryptos_twofish_nrol(n, l) ( ( ((n) << (l)) | ((n) >> (4 - (l))) ) & 0xF )

#define kryptos_twofish_nror(n, l) ( ( ((n) >> (l)) | ((n) << (4 - (l))) ) & 0xF )

// INFO(Rafael): All the following macros compound the four Twofish's circuits g, MDS, PHT and F.

#if !defined(KRYPTOS_TWOFISH_WITH_PRE_COMPUTED_Q_PERMS)

# define kryptos_twofish_qn_perm(x, y, a, b, t) {\
     (a)[0] = ((x) >> 4);\
     (b)[0] = ((x) & 0xF);\
     (a)[1] = (a)[0] ^ b[0];\
     (b)[1] = ((a)[0] ^ kryptos_twofish_nror((b)[0], 1) ^ ((a)[0] << 3)) & 0xF;\
     (a)[2] = (t)[0][(a)[1]];\
     (b)[2] = (t)[1][(b)[1]];\
     (a)[3] = (a)[2] ^ (b)[2];\
     (b)[3] = ((a)[2] ^ kryptos_twofish_nror((b)[2], 1) ^ ((a)[2] << 3)) & 0xF;\
     (y) = ((y) << 8) | (((t)[3][(b)[3]] << 4) | (t)[2][(a)[3]]);\
}

# define kryptos_twofish_q0_perm(x, y, a, b) kryptos_twofish_qn_perm(x, y, a, b, kryptos_twofish_q0_lt)

# define kryptos_twofish_q1_perm(x, y, a, b) kryptos_twofish_qn_perm(x, y, a, b, kryptos_twofish_q1_lt)

#else
// INFO(Rafael): 'a' and 'b' here are just stubs, since we are storing more 512 bytes in memory I find
//               consume a 128-bit chunk to avoid changing all other macros due to the chosen pre-computed
//               Q is okay. Moreover, by default I am not using it.
# define kryptos_twofish_q0_perm(x, y, a, b) {\
    (y) = ((y) << 8) | kryptos_twofish_q0_sbox[(x)];\
}

# define kryptos_twofish_q1_perm(x, y, a, b) {\
    (y) = ((y) << 8) | kryptos_twofish_q1_sbox[(x)];\
}

#endif // !defined(KRYPTOS_TWOFISH_WITH_PRE_COMPUTED_Q_PERMS)

// INFO(Rafael): "table" parameter will swap the irreducible polynomial and as a result the "mappings"
//               of the multiplication operation.
#define kryptos_twofish_gfmul(x, y, table)\
    (((x) != 0 && (y) != 0) ?\
    kryptos_twofish_ ## table ## _antilog_table[(kryptos_twofish_ ## table ## _log_table[x] +\
                                                 kryptos_twofish_ ## table ## _log_table[y]) % 0xFF] : 0)

#define kryptos_twofish_get_byte_n(x, n) (((x) >> (((sizeof(x) << 3) - 8) - ((n) << 3))) & 0xFF)

#define kryptos_twofish_g(r0, r1, f0, f1, a, b, S, k, tt) {\
    /* INFO(Rafael): Even the circuit hh is originally designed for key schedule, we can use it here because S was\
       previously patched accordingly. */\
    kryptos_twofish_hh(r0, f0, k, (S)[0], (S)[1], (S)[2], (S)[3], a, b, tt);\
    kryptos_twofish_hh(r1, f1, k, (S)[0], (S)[1], (S)[2], (S)[3], a, b, tt);\
}

// INFO(Rafael): Here we could indicate the byte of the each element from the matrixes "inline" but I prefer let the
//               byte-by-byte nature of the operation explicit and let compiler unroll it. This algorithm has pretty
//               insane parts, let's be more "high-level" for a moment, please! :)

#define kryptos_twofish_mds(y, tt){\
    (tt) = (y);\
    (y) = (((kryptos_u32_t)kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(tt, 0),\
                                                 kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_MDS_R0, 0), mds) << 24) |\
           ((kryptos_u32_t)kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(tt, 0),\
                                                 kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_MDS_R0, 1), mds) << 16) |\
           ((kryptos_u32_t)kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(tt, 0),\
                                                 kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_MDS_R0, 2), mds) <<  8) |\
           ((kryptos_u32_t)kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(tt, 0),\
                                                 kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_MDS_R0, 3), mds)));\
    (y) ^= (((kryptos_u32_t)kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(tt, 1),\
                                                 kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_MDS_R1, 0), mds) << 24) |\
           ((kryptos_u32_t)kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(tt, 1),\
                                                 kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_MDS_R1, 1), mds) << 16) |\
           ((kryptos_u32_t)kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(tt, 1),\
                                                 kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_MDS_R1, 2), mds) <<  8) |\
           ((kryptos_u32_t)kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(tt, 1),\
                                                 kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_MDS_R1, 3), mds)));\
    (y) ^= (((kryptos_u32_t)kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(tt, 2),\
                                                 kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_MDS_R2, 0), mds) << 24) |\
           ((kryptos_u32_t)kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(tt, 2),\
                                                 kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_MDS_R2, 1), mds) << 16) |\
           ((kryptos_u32_t)kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(tt, 2),\
                                                 kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_MDS_R2, 2), mds) <<  8) |\
           ((kryptos_u32_t)kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(tt, 2),\
                                                 kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_MDS_R2, 3), mds)));\
    (y) ^= (((kryptos_u32_t)kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(tt, 3),\
                                                 kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_MDS_R3, 0), mds) << 24) |\
           ((kryptos_u32_t)kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(tt, 3),\
                                                 kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_MDS_R3, 1), mds) << 16) |\
           ((kryptos_u32_t)kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(tt, 3),\
                                                 kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_MDS_R3, 2), mds) <<  8) |\
           ((kryptos_u32_t)kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(tt, 3),\
                                                 kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_MDS_R3, 3), mds)));\
}

#define kryptos_twofish_rs(m)\
    /* INFO(Rafael): The reason of the endianness inversion here is because we will use S array with hh circuit. */\
    kryptos_twofish_inv_endianness(\
        ((kryptos_u32_t)(kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 0),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R0, 0), rs) ^\
                         kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 1),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R0, 1), rs) ^\
                         kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 2),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R0, 2), rs) ^\
                         kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 3),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R0, 3), rs) ^\
                         kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 4),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R0, 4), rs) ^\
                         kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 5),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R0, 5), rs) ^\
                         kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 6),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R0, 6), rs) ^\
                         kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 7),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R0, 7), rs))) |\
        ((kryptos_u32_t)(kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 0),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R1, 0), rs) ^\
                         kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 1),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R1, 1), rs) ^\
                         kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 2),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R1, 2), rs) ^\
                         kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 3),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R1, 3), rs) ^\
                         kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 4),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R1, 4), rs) ^\
                         kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 5),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R1, 5), rs) ^\
                         kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 6),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R1, 6), rs) ^\
                         kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 7),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R1, 7), rs)) <<  8) |\
        ((kryptos_u32_t)(kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 0),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R2, 0), rs) ^\
                         kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 1),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R2, 1), rs) ^\
                         kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 2),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R2, 2), rs) ^\
                         kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 3),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R2, 3), rs) ^\
                         kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 4),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R2, 4), rs) ^\
                         kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 5),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R2, 5), rs) ^\
                         kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 6),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R2, 6), rs) ^\
                         kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 7),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R2, 7), rs)) <<  16) |\
        ((kryptos_u32_t)(kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 0),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R3, 0), rs) ^\
                         kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 1),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R3, 1), rs) ^\
                         kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 2),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R3, 2), rs) ^\
                         kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 3),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R3, 3), rs) ^\
                         kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 4),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R3, 4), rs) ^\
                         kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 5),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R3, 5), rs) ^\
                         kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 6),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R3, 6), rs) ^\
                         kryptos_twofish_gfmul(kryptos_twofish_get_byte_n(m, 7),\
                                               kryptos_twofish_get_byte_n(KRYPTOS_TWOFISH_RS_R3, 7), rs)) << 24)\
    )

#define kryptos_twofish_pht(t0, t1, tt) {\
    (tt) = (t0);\
    (t0) = ((t0) + (t1));\
    (t1) = ((tt) + ((t1)<<1)) & 0xFFFFFFFF;\
}

#define kryptos_twofish_f(r0, r1, f0, f1, S, k, K_2r8, K_2r9, ax, bx, tt) {\
    /* INFO(Rafael): The endianness inversion is a dirty trick for reusing hh circuit also here. */\
    kryptos_twofish_g(kryptos_twofish_inv_endianness(r0),\
                      kryptos_twofish_wror(kryptos_twofish_inv_endianness(r1), 8),\
                      f0, f1, ax, bx, S, k, tt);\
    kryptos_twofish_pht(f0, f1, tt);\
    (f0) += (K_2r8);\
    (f1) += (K_2r9);\
}

#define kryptos_twofish_hh(ic, Kc, k, S0, S1, S2, S3, a, b, tt) {\
    (tt) = (ic);\
    if ((k) == 4) {\
        kryptos_twofish_q1_perm(kryptos_twofish_get_byte_n(tt, 0), Kc, a, b);\
        kryptos_twofish_q0_perm(kryptos_twofish_get_byte_n(tt, 1), Kc, a, b);\
        kryptos_twofish_q0_perm(kryptos_twofish_get_byte_n(tt, 2), Kc, a, b);\
        kryptos_twofish_q1_perm(kryptos_twofish_get_byte_n(tt, 3), Kc, a, b);\
        (Kc) ^=  (S3);\
        (tt) = (Kc);\
    }\
    if ((k) >= 3) {\
        kryptos_twofish_q1_perm(kryptos_twofish_get_byte_n(tt, 0), Kc, a, b);\
        kryptos_twofish_q1_perm(kryptos_twofish_get_byte_n(tt, 1), Kc, a, b);\
        kryptos_twofish_q0_perm(kryptos_twofish_get_byte_n(tt, 2), Kc, a, b);\
        kryptos_twofish_q0_perm(kryptos_twofish_get_byte_n(tt, 3), Kc, a, b);\
        (Kc) ^= (S2);\
        (tt) = (Kc);\
    }\
    kryptos_twofish_q0_perm(kryptos_twofish_get_byte_n(tt, 0), Kc, a, b);\
    kryptos_twofish_q1_perm(kryptos_twofish_get_byte_n(tt, 1), Kc, a, b);\
    kryptos_twofish_q0_perm(kryptos_twofish_get_byte_n(tt, 2), Kc, a, b);\
    kryptos_twofish_q1_perm(kryptos_twofish_get_byte_n(tt, 3), Kc, a, b);\
    (Kc) ^= (S1);\
    (tt) = (Kc);\
    kryptos_twofish_q0_perm(kryptos_twofish_get_byte_n(tt, 0), Kc, a, b);\
    kryptos_twofish_q0_perm(kryptos_twofish_get_byte_n(tt, 1), Kc, a, b);\
    kryptos_twofish_q1_perm(kryptos_twofish_get_byte_n(tt, 2), Kc, a, b);\
    kryptos_twofish_q1_perm(kryptos_twofish_get_byte_n(tt, 3), Kc, a, b);\
    (Kc) ^= (S0);\
    (tt) = (Kc);\
    kryptos_twofish_q1_perm(kryptos_twofish_get_byte_n(tt, 0), Kc, a, b);\
    kryptos_twofish_q0_perm(kryptos_twofish_get_byte_n(tt, 1), Kc, a, b);\
    kryptos_twofish_q1_perm(kryptos_twofish_get_byte_n(tt, 2), Kc, a, b);\
    kryptos_twofish_q0_perm(kryptos_twofish_get_byte_n(tt, 3), Kc, a, b);\
    kryptos_twofish_mds(Kc, tt);\
}

#define kryptos_twofish_h_iter(ic, in, Kc, Kn, k, SM, a, b, tt) {\
    kryptos_twofish_hh(((kryptos_u32_t)(ic) << 24) |\
                       ((kryptos_u32_t)(ic) << 16) |\
                       ((kryptos_u32_t)(ic) <<  8) |\
                       ((kryptos_u32_t)(ic)), Kc, k, SM[0], SM[2], SM[4], SM[6], a, b, tt);\
    kryptos_twofish_hh(((kryptos_u32_t)(in) << 24) |\
                       ((kryptos_u32_t)(in) << 16) |\
                       ((kryptos_u32_t)(in) <<  8) |\
                       ((kryptos_u32_t)(in)), Kn, k, SM[1], SM[3], SM[5], SM[7], a, b, tt);\
    (Kn) = kryptos_twofish_wrol(Kn, 8);\
    kryptos_twofish_pht(Kc, Kn, tt);\
    (Kn) = kryptos_twofish_wrol(Kn, 9);\
}

// INFO(Rafael): Function h is behaving a little bit different from original spec. Here SM was patched to store Modd and Meven
//               acting like a 256-bit key (but in the sequence [recycling] that the original bitsize has expecting).
#define kryptos_twofish_h(i, K, k, SM, a, b, tt) {\
    kryptos_twofish_h_iter(i, (i) + 1,  (K)[0], (K)[1], k, SM, a, b, tt);\
    kryptos_twofish_h_iter((i) + 2, (i) + 3, (K)[2], (K)[3], k, SM, a, b, tt);\
}

#define kryptos_twofish_inv_endianness(v)  ( (((v) & 0xFF000000) >> 24)  |\
                                             (((v) & 0x00FF0000) >>  8) |\
                                             (((v) & 0x0000FF00) <<  8) |\
                                             (((v) & 0x000000FF) << 24) )

struct kryptos_twofish_subkeys {
    kryptos_u32_t K[KRYPTOS_TWOFISH_SK_WORDS_NR];
    kryptos_u32_t S[KRYPTOS_TWOFISH_S_NR];
    size_t k;
};

typedef void (*kryptos_twofish_block_processor)(kryptos_u8_t *block, const struct kryptos_twofish_subkeys *sks);

static void kryptos_twofish_eval_skeys(const kryptos_u8_t *key, const size_t key_size,
                                       struct kryptos_twofish_subkeys *sks);

static void kryptos_twofish128_eval_skeys(const kryptos_u8_t *key, const size_t key_size,
                                          struct kryptos_twofish_subkeys *sks);

static void kryptos_twofish192_eval_skeys(const kryptos_u8_t *key, const size_t key_size,
                                          struct kryptos_twofish_subkeys *sks);

static void kryptos_twofish256_eval_skeys(const kryptos_u8_t *key, const size_t key_size,
                                          struct kryptos_twofish_subkeys *sks);

static void kryptos_twofish_encrypt_block(kryptos_u8_t *block, const struct kryptos_twofish_subkeys *sks);

static void kryptos_twofish_decrypt_block(kryptos_u8_t *block, const struct kryptos_twofish_subkeys *sks);

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_SETUP(twofish128, kKryptosCipherTwofish128, KRYPTOS_TWOFISH_BLOCKSIZE)

KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(twofish128,
                                    ktask,
                                    kryptos_twofish_subkeys,
                                    sks,
                                    kryptos_twofish_block_processor,
                                    twofish_block_processor,
                                    kryptos_twofish128_eval_skeys((*ktask)->key,
                                                                  (*ktask)->key_size,
                                                                  &sks),
                                    kryptos_twofish_encrypt_block, /* No additional steps before encrypting */,
                                    kryptos_twofish_decrypt_block, /* No additional steps before decrypting */,
                                    KRYPTOS_TWOFISH_BLOCKSIZE,
                                    twofish128_cipher_epilogue,
                                    outblock,
                                    twofish_block_processor(outblock, &sks),
                                    NULL /* GCM E function arg */)

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_GCM_E(twofish128)

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_SETUP(twofish192, kKryptosCipherTwofish192, KRYPTOS_TWOFISH_BLOCKSIZE)

KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(twofish192,
                                    ktask,
                                    kryptos_twofish_subkeys,
                                    sks,
                                    kryptos_twofish_block_processor,
                                    twofish_block_processor,
                                    kryptos_twofish192_eval_skeys((*ktask)->key,
                                                                  (*ktask)->key_size,
                                                                  &sks),
                                    kryptos_twofish_encrypt_block, /* No additional steps before encrypting */,
                                    kryptos_twofish_decrypt_block, /* No additional steps before decrypting */,
                                    KRYPTOS_TWOFISH_BLOCKSIZE,
                                    twofish192_cipher_epilogue,
                                    outblock,
                                    twofish_block_processor(outblock, &sks),
                                    NULL /* GCM E function arg */)

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_GCM_E(twofish192)

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_SETUP(twofish256, kKryptosCipherTwofish256, KRYPTOS_TWOFISH_BLOCKSIZE)

KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(twofish256,
                                    ktask,
                                    kryptos_twofish_subkeys,
                                    sks,
                                    kryptos_twofish_block_processor,
                                    twofish_block_processor,
                                    kryptos_twofish256_eval_skeys((*ktask)->key,
                                                                  (*ktask)->key_size,
                                                                  &sks),
                                    kryptos_twofish_encrypt_block, /* No additional steps before encrypting */,
                                    kryptos_twofish_decrypt_block, /* No additional steps before decrypting */,
                                    KRYPTOS_TWOFISH_BLOCKSIZE,
                                    twofish256_cipher_epilogue,
                                    outblock,
                                    twofish_block_processor(outblock, &sks),
                                    NULL /* GCM E function arg */)

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_GCM_E(twofish256)

static void kryptos_twofish128_eval_skeys(const kryptos_u8_t *key, const size_t key_size,
                                          struct kryptos_twofish_subkeys *sks) {
    kryptos_u8_t ek[16];

    memset(ek, 0, sizeof(ek));
    memcpy(ek, key, (key_size > sizeof(ek)) ? sizeof(ek) : key_size);

    sks->k = 2;
    kryptos_twofish_eval_skeys(ek, sizeof(ek), sks);

    memset(ek, 0, sizeof(ek));
}

static void kryptos_twofish192_eval_skeys(const kryptos_u8_t *key, const size_t key_size,
                                          struct kryptos_twofish_subkeys *sks) {
    kryptos_u8_t ek[24];

    memset(ek, 0, sizeof(ek));
    memcpy(ek, key, (key_size > sizeof(ek)) ? sizeof(ek) : key_size);

    sks->k = 3;
    kryptos_twofish_eval_skeys(ek, sizeof(ek), sks);

    memset(ek, 0, sizeof(ek));
}

static void kryptos_twofish256_eval_skeys(const kryptos_u8_t *key, const size_t key_size,
                                          struct kryptos_twofish_subkeys *sks) {
    kryptos_u8_t ek[32];

    memset(ek, 0, sizeof(ek));
    memcpy(ek, key, (key_size > sizeof(ek)) ? sizeof(ek) : key_size);

    sks->k = 4;
    kryptos_twofish_eval_skeys(ek, sizeof(ek), sks);

    memset(ek, 0, sizeof(ek));
}


static void kryptos_twofish_eval_skeys(const kryptos_u8_t *key, const size_t key_size, struct kryptos_twofish_subkeys *sks) {
    kryptos_u32_t M[KRYPTOS_TWOFISH_M_NR];
    kryptos_u8_t ek[32];
    size_t s;
    kryptos_u8_t a[4], b[4];
    kryptos_u32_t tt;

    memcpy(ek, key, key_size & ((sks->k < 4) ? 0x1F : 0x2F)); // INFO(Rafael): It is just a kind of 'foolproof lock',
                                                              //                but if a key size different from 16,
                                                              //                24 or 32 has arrived here, Rome is
                                                              //                burning for hours... Go find some
                                                              //                gasoline, I will tune the violin :)

    // INFO(Rafael): It seems tricky but here I prefer ensuring endianness without calling any reversing function
    //               or even tricky indexed math oriented for-loops.

    switch (sks->k) {
        case 2: // INFO(Rafael): Twofish128 instance.
            M[0] = ((kryptos_u32_t)ek[ 3])       |
                   ((kryptos_u32_t)ek[ 2] <<  8) |
                   ((kryptos_u32_t)ek[ 1] << 16) |
                   ((kryptos_u32_t)ek[ 0] << 24);
            M[1] = ((kryptos_u32_t)ek[ 7])       |
                   ((kryptos_u32_t)ek[ 6] <<  8) |
                   ((kryptos_u32_t)ek[ 5] << 16) |
                   ((kryptos_u32_t)ek[ 4] << 24);
            M[2] = ((kryptos_u32_t)ek[11])       |
                   ((kryptos_u32_t)ek[10] <<  8) |
                   ((kryptos_u32_t)ek[ 9] << 16) |
                   ((kryptos_u32_t)ek[ 8] << 24);
            M[3] = ((kryptos_u32_t)ek[15])       |
                   ((kryptos_u32_t)ek[14] <<  8) |
                   ((kryptos_u32_t)ek[13] << 16) |
                   ((kryptos_u32_t)ek[12] << 24);
            M[4] = M[0];
            M[5] = M[1];
            M[6] = M[2];
            M[7] = M[3];
            break;

        case 3: // INFO(Rafael): Twofish192 instance.
            M[0] = ((kryptos_u32_t)ek[ 3])       |
                   ((kryptos_u32_t)ek[ 2] <<  8) |
                   ((kryptos_u32_t)ek[ 1] << 16) |
                   ((kryptos_u32_t)ek[ 0] << 24);
            M[1] = ((kryptos_u32_t)ek[ 7])       |
                   ((kryptos_u32_t)ek[ 6] <<  8) |
                   ((kryptos_u32_t)ek[ 5] << 16) |
                   ((kryptos_u32_t)ek[ 4] << 24);
            M[2] = ((kryptos_u32_t)ek[11])       |
                   ((kryptos_u32_t)ek[10] <<  8) |
                   ((kryptos_u32_t)ek[ 9] << 16) |
                   ((kryptos_u32_t)ek[ 8] << 24);
            M[3] = ((kryptos_u32_t)ek[15])       |
                   ((kryptos_u32_t)ek[14] <<  8) |
                   ((kryptos_u32_t)ek[13] << 16) |
                   ((kryptos_u32_t)ek[12] << 24);
            M[4] = ((kryptos_u32_t)ek[19])       |
                   ((kryptos_u32_t)ek[18] <<  8) |
                   ((kryptos_u32_t)ek[17] << 16) |
                   ((kryptos_u32_t)ek[16] << 24);
            M[5] = ((kryptos_u32_t)ek[23])       |
                   ((kryptos_u32_t)ek[22] <<  8) |
                   ((kryptos_u32_t)ek[21] << 16) |
                   ((kryptos_u32_t)ek[20] << 24);
            M[6] = M[0];
            M[7] = M[1];
            break;

        case 4: // INFO(Rafael): Twofish256 instance.
            M[0] = ((kryptos_u32_t)ek[ 3])       |
                   ((kryptos_u32_t)ek[ 2] <<  8) |
                   ((kryptos_u32_t)ek[ 1] << 16) |
                   ((kryptos_u32_t)ek[ 0] << 24);
            M[1] = ((kryptos_u32_t)ek[ 7])       |
                   ((kryptos_u32_t)ek[ 6] <<  8) |
                   ((kryptos_u32_t)ek[ 5] << 16) |
                   ((kryptos_u32_t)ek[ 4] << 24);
            M[2] = ((kryptos_u32_t)ek[11])       |
                   ((kryptos_u32_t)ek[10] <<  8) |
                   ((kryptos_u32_t)ek[ 9] << 16) |
                   ((kryptos_u32_t)ek[ 8] << 24);
            M[3] = ((kryptos_u32_t)ek[15])       |
                   ((kryptos_u32_t)ek[14] <<  8) |
                   ((kryptos_u32_t)ek[13] << 16) |
                   ((kryptos_u32_t)ek[12] << 24);
            M[4] = ((kryptos_u32_t)ek[19])       |
                   ((kryptos_u32_t)ek[18] <<  8) |
                   ((kryptos_u32_t)ek[17] << 16) |
                   ((kryptos_u32_t)ek[16] << 24);
            M[5] = ((kryptos_u32_t)ek[23])       |
                   ((kryptos_u32_t)ek[22] <<  8) |
                   ((kryptos_u32_t)ek[21] << 16) |
                   ((kryptos_u32_t)ek[20] << 24);
            M[6] = ((kryptos_u32_t)ek[27])       |
                   ((kryptos_u32_t)ek[26] <<  8) |
                   ((kryptos_u32_t)ek[25] << 16) |
                   ((kryptos_u32_t)ek[24] << 24);
            M[7] = ((kryptos_u32_t)ek[31])       |
                   ((kryptos_u32_t)ek[30] <<  8) |
                   ((kryptos_u32_t)ek[29] << 16) |
                   ((kryptos_u32_t)ek[28] << 24);
            break;

        default:
            return; // WARN(Rafael): It should never happen in normal conditions.
    }

    // INFO(Rafael): This is far from being a strict indication of what to todo with all key sizes cases, but in original
    //               algorithm spec, at some point, the text states that '...Keys of any length shorter than 256 bits
    //               can be used by padding them with zeroes until the next larger defined key length.' So I am giving
    //               it a try here. <:-(
    //
    //               So this is a tricky attempt to re-use the same h function circuit for all keys sizes. It just mock
    //               up any key shorter than 256-bit as a real 256-bit key. Maybe a more symmetric way of thinking. In
    //               general it works.
    //
    //               Ah symmetry.... :) With it all we need to do at h is traversing M in two acts: the first must
    //               consume all even positions (in ascending order) and the second must consume the odd positions
    //               (in ascending order). e.g.:
    //
    //                          h (...) {
    //                                  hh(    i, i + 1, M[0], M[2], M[4], M[6])
    //                                  hh(i + 2, i + 3, M[1], M[3], M[5], M[7])
    //                          }
    //
    //               Yes, each h call will give us four 32-bit sub-keys. Rather different from the spec but it does the
    //               work!

    // INFO(Rafael): Static S keys taking into consideration the current bitsize version (128, 192 or 256).
    //               k constant indicates how many 64-bit words we can do with the informed effective key (ek).
    for (s = 0; s < sks->k; s++) {
        // INFO(Rafael): In order to reuse hh circuit also during encryption/decryption I will do some
        //               patching on S array. This patching is only about dispose the S words in reverse order.
        //               In this way the right XORing sequence during q permutation will be done.
        sks->S[sks->k - s - 1] = kryptos_twofish_rs(((kryptos_u64_t)M[s << 1] << 32) | (kryptos_u64_t)M[(s << 1) + 1]);
    }

    // INFO(Rafael): Due to key schedule from now on is being handled as a 256-bit key expansion ***but*** with M patched
    //               according to the original key size, we are able to produce four 32-bit chunks per h call. Since h
    //               consumes M[0..7] on every call. In this way we need to call h ten times instead of twenty, but you can
    //               consult the spec >:-) if you do not believe in me... he-he-he.
    for (s = 0; s < KRYPTOS_TWOFISH_SK_WORDS_NR; s += 4) {
        kryptos_twofish_h(s, &sks->K[s], sks->k, M, a, b, tt);
    }

    memset(M, 0, sizeof(M));
    memset(ek, 0, sizeof(ek));
    memset(a, 0, sizeof(a));
    memset(b, 0, sizeof(b));
    s = 0;
    tt = 0;
}

static void kryptos_twofish_encrypt_block(kryptos_u8_t *block, const struct kryptos_twofish_subkeys *sks) {
    kryptos_u32_t R[4], f0 = 0, f1 = 0, tt = 0;
    kryptos_u8_t a[4], b[4];

    R[0] = ((kryptos_u32_t)block[ 3] << 24) |
           ((kryptos_u32_t)block[ 2] << 16) |
           ((kryptos_u32_t)block[ 1] <<  8) |
           ((kryptos_u32_t)block[ 0]);
    R[1] = ((kryptos_u32_t)block[ 7] << 24) |
           ((kryptos_u32_t)block[ 6] << 16) |
           ((kryptos_u32_t)block[ 5] <<  8) |
           ((kryptos_u32_t)block[ 4]);
    R[2] = ((kryptos_u32_t)block[11] << 24) |
           ((kryptos_u32_t)block[10] << 16) |
           ((kryptos_u32_t)block[ 9] <<  8) |
           ((kryptos_u32_t)block[ 8]);
    R[3] = ((kryptos_u32_t)block[15] << 24) |
           ((kryptos_u32_t)block[14] << 16) |
           ((kryptos_u32_t)block[13] <<  8) |
           ((kryptos_u32_t)block[12]);

    // INFO(Rafael): I. Input whitening.
    R[0] ^= sks->K[0];
    R[1] ^= sks->K[1];
    R[2] ^= sks->K[2];
    R[3] ^= sks->K[3];

#define kryptos_twofish_round_iter(R, Kc, Kn, k, f0, f1, a, b, tt, assign_type) {\
        kryptos_twofish_f(R[0], R[1], f0, f1,\
                          sks->S, k, Kc, Kn, a, b, tt);\
        f0 = kryptos_twofish_wror(f0 ^ R[2], 1);\
        f1 = kryptos_twofish_wrol(R[3], 1) ^ f1;\
        kryptos_twofish_assign_ ## assign_type(R, f0, f1);\
}

// INFO(Rafael): It is just for keeping up the sanity. Otherwise the final output whitening would be
//               asymmetric by using key chunks in a different order from the specified in original Twofish's
//               article. This algorithm has a bunch of tricky parts by nature putting more obfuscate stuff into it
//               would be a great desservice for someone trying to figure something out. Sometimes it is worth pay
//               the price for readbility. Almost always, you in the future tend to be thankful for your past design
//               decision. Moreover, in this specific case we will save two useless attributions.

#define kryptos_twofish_assign_next(R, f0, f1) {\
        R[2] = R[0];\
        R[3] = R[1];\
        R[0] = f0;\
        R[1] = f1;\
}

#define kryptos_twofish_assign_done(R, f0, f1) {\
        R[2] = f0;\
        R[3] = f1;\
}

    kryptos_twofish_round_iter(R, sks->K[ 8], sks->K[ 9], sks->k, f0, f1, a, b, tt, next);
    kryptos_twofish_round_iter(R, sks->K[10], sks->K[11], sks->k, f0, f1, a, b, tt, next);
    kryptos_twofish_round_iter(R, sks->K[12], sks->K[13], sks->k, f0, f1, a, b, tt, next);
    kryptos_twofish_round_iter(R, sks->K[14], sks->K[15], sks->k, f0, f1, a, b, tt, next);
    kryptos_twofish_round_iter(R, sks->K[16], sks->K[17], sks->k, f0, f1, a, b, tt, next);
    kryptos_twofish_round_iter(R, sks->K[18], sks->K[19], sks->k, f0, f1, a, b, tt, next);
    kryptos_twofish_round_iter(R, sks->K[20], sks->K[21], sks->k, f0, f1, a, b, tt, next);
    kryptos_twofish_round_iter(R, sks->K[22], sks->K[23], sks->k, f0, f1, a, b, tt, next);
    kryptos_twofish_round_iter(R, sks->K[24], sks->K[25], sks->k, f0, f1, a, b, tt, next);
    kryptos_twofish_round_iter(R, sks->K[26], sks->K[27], sks->k, f0, f1, a, b, tt, next);
    kryptos_twofish_round_iter(R, sks->K[28], sks->K[29], sks->k, f0, f1, a, b, tt, next);
    kryptos_twofish_round_iter(R, sks->K[30], sks->K[31], sks->k, f0, f1, a, b, tt, next);
    kryptos_twofish_round_iter(R, sks->K[32], sks->K[33], sks->k, f0, f1, a, b, tt, next);
    kryptos_twofish_round_iter(R, sks->K[34], sks->K[35], sks->k, f0, f1, a, b, tt, next);
    kryptos_twofish_round_iter(R, sks->K[36], sks->K[37], sks->k, f0, f1, a, b, tt, next);
    kryptos_twofish_round_iter(R, sks->K[38], sks->K[39], sks->k, f0, f1, a, b, tt, done);

#undef kryptos_twofish_round_iter

#undef kryptos_twofish_assign_next

#undef kryptos_twofish_assign_done

    // INFO(Rafael): III. Output whitening.
    R[0] ^= sks->K[4];
    R[1] ^= sks->K[5];
    R[2] ^= sks->K[6];
    R[3] ^= sks->K[7];

    block[ 0] = kryptos_twofish_get_byte_n(R[0], 3);
    block[ 1] = kryptos_twofish_get_byte_n(R[0], 2);
    block[ 2] = kryptos_twofish_get_byte_n(R[0], 1);
    block[ 3] = kryptos_twofish_get_byte_n(R[0], 0);
    block[ 4] = kryptos_twofish_get_byte_n(R[1], 3);
    block[ 5] = kryptos_twofish_get_byte_n(R[1], 2);
    block[ 6] = kryptos_twofish_get_byte_n(R[1], 1);
    block[ 7] = kryptos_twofish_get_byte_n(R[1], 0);
    block[ 8] = kryptos_twofish_get_byte_n(R[2], 3);
    block[ 9] = kryptos_twofish_get_byte_n(R[2], 2);
    block[10] = kryptos_twofish_get_byte_n(R[2], 1);
    block[11] = kryptos_twofish_get_byte_n(R[2], 0);
    block[12] = kryptos_twofish_get_byte_n(R[3], 3);
    block[13] = kryptos_twofish_get_byte_n(R[3], 2);
    block[14] = kryptos_twofish_get_byte_n(R[3], 1);
    block[15] = kryptos_twofish_get_byte_n(R[3], 0);

    memset(R, 0, sizeof(R));
    memset(a, 0, sizeof(a));
    memset(b, 0, sizeof(b));
    f0 = f1 = tt = 0;
}

static void kryptos_twofish_decrypt_block(kryptos_u8_t *block, const struct kryptos_twofish_subkeys *sks) {
    kryptos_u32_t R[4], f0 = 0, f1 = 0, tt = 0;
    kryptos_u8_t a[4], b[4];

    R[0] = ((kryptos_u32_t)block[ 3] << 24) |
           ((kryptos_u32_t)block[ 2] << 16) |
           ((kryptos_u32_t)block[ 1] <<  8) |
           ((kryptos_u32_t)block[ 0]);
    R[1] = ((kryptos_u32_t)block[ 7] << 24) |
           ((kryptos_u32_t)block[ 6] << 16) |
           ((kryptos_u32_t)block[ 5] <<  8) |
           ((kryptos_u32_t)block[ 4]);
    R[2] = ((kryptos_u32_t)block[11] << 24) |
           ((kryptos_u32_t)block[10] << 16) |
           ((kryptos_u32_t)block[ 9] <<  8) |
           ((kryptos_u32_t)block[ 8]);
    R[3] = ((kryptos_u32_t)block[15] << 24) |
           ((kryptos_u32_t)block[14] << 16) |
           ((kryptos_u32_t)block[13] <<  8) |
           ((kryptos_u32_t)block[12]);

    // INFO(Rafael): I. Input whitening, patched for convenience.
    f0 = R[2];
    f1 = R[3];
    R[2] = R[0] ^ sks->K[4];
    R[3] = R[1] ^ sks->K[5];
    R[0] = f0 ^ sks->K[6];
    R[1] = f1 ^ sks->K[7];


    // INFO(Rafael): I really sought to avoid this tour de force but it was
    //               the way that I could be able to found to keep doing one
    //               inversion per iteration. By making it almost the same of the
    //               block encryption logics, besides more tidy and sane, too.
    //               Yes, at the end this is a big cheating, Arsène Lupin was here... ;)
#define kryptos_twofish_round_iter(R, Kc, Kn, k, f0, f1, a, b, tt, iter_type) {\
        kryptos_twofish_round_iter_## iter_type(R, Kc, Kn, k, f0, f1, a, b, tt);\
}

#define kryptos_twofish_round_iter_next_left(R, Kc, Kn, k, f0, f1, a, b, tt) {\
        kryptos_twofish_f(R[2], R[3], f0, f1,\
                          sks->S, k, Kc, Kn, a, b, tt);\
        R[0] = kryptos_twofish_wrol(R[0], 1) ^ f0;\
        R[1] = kryptos_twofish_wror(R[1] ^ f1, 1);\
}

#define kryptos_twofish_round_iter_next_right(R, Kc, Kn, k, f0, f1, a, b, tt) {\
        kryptos_twofish_f(R[0], R[1], f0, f1,\
                          sks->S, k, Kc, Kn, a, b, tt);\
        R[2] = kryptos_twofish_wrol(R[2], 1) ^ f0;\
        R[3] = kryptos_twofish_wror(R[3] ^ f1, 1);\
}

#define kryptos_twofish_round_iter_done(R, Kc, Kn, k, f0, f1, a, b, tt) {\
    kryptos_twofish_round_iter_next_right(R, Kc, Kn, k, f0, f1, a, b, tt);\
}

    kryptos_twofish_round_iter(R, sks->K[38], sks->K[39], sks->k, f0, f1, a, b, tt, next_left);
    kryptos_twofish_round_iter(R, sks->K[36], sks->K[37], sks->k, f0, f1, a, b, tt, next_right);
    kryptos_twofish_round_iter(R, sks->K[34], sks->K[35], sks->k, f0, f1, a, b, tt, next_left);
    kryptos_twofish_round_iter(R, sks->K[32], sks->K[33], sks->k, f0, f1, a, b, tt, next_right);
    kryptos_twofish_round_iter(R, sks->K[30], sks->K[31], sks->k, f0, f1, a, b, tt, next_left);
    kryptos_twofish_round_iter(R, sks->K[28], sks->K[29], sks->k, f0, f1, a, b, tt, next_right);
    kryptos_twofish_round_iter(R, sks->K[26], sks->K[27], sks->k, f0, f1, a, b, tt, next_left);
    kryptos_twofish_round_iter(R, sks->K[24], sks->K[25], sks->k, f0, f1, a, b, tt, next_right);
    kryptos_twofish_round_iter(R, sks->K[22], sks->K[23], sks->k, f0, f1, a, b, tt, next_left);
    kryptos_twofish_round_iter(R, sks->K[20], sks->K[21], sks->k, f0, f1, a, b, tt, next_right);
    kryptos_twofish_round_iter(R, sks->K[18], sks->K[19], sks->k, f0, f1, a, b, tt, next_left);
    kryptos_twofish_round_iter(R, sks->K[16], sks->K[17], sks->k, f0, f1, a, b, tt, next_right);
    kryptos_twofish_round_iter(R, sks->K[14], sks->K[15], sks->k, f0, f1, a, b, tt, next_left);
    kryptos_twofish_round_iter(R, sks->K[12], sks->K[13], sks->k, f0, f1, a, b, tt, next_right);
    kryptos_twofish_round_iter(R, sks->K[10], sks->K[11], sks->k, f0, f1, a, b, tt, next_left);
    kryptos_twofish_round_iter(R, sks->K[ 8], sks->K[ 9], sks->k, f0, f1, a, b, tt, done);

#undef kryptos_twofish_round_iter

#undef kryptos_twofish_round_iter_next_left

#undef kryptos_twofish_round_iter_next_right

#undef kryptos_twofish_round_iter_done

    // INFO(Rafael): III. Output whitening.
    R[0] ^= sks->K[0];
    R[1] ^= sks->K[1];
    R[2] ^= sks->K[2];
    R[3] ^= sks->K[3];

    block[ 0] = kryptos_twofish_get_byte_n(R[0], 3);
    block[ 1] = kryptos_twofish_get_byte_n(R[0], 2);
    block[ 2] = kryptos_twofish_get_byte_n(R[0], 1);
    block[ 3] = kryptos_twofish_get_byte_n(R[0], 0);
    block[ 4] = kryptos_twofish_get_byte_n(R[1], 3);
    block[ 5] = kryptos_twofish_get_byte_n(R[1], 2);
    block[ 6] = kryptos_twofish_get_byte_n(R[1], 1);
    block[ 7] = kryptos_twofish_get_byte_n(R[1], 0);
    block[ 8] = kryptos_twofish_get_byte_n(R[2], 3);
    block[ 9] = kryptos_twofish_get_byte_n(R[2], 2);
    block[10] = kryptos_twofish_get_byte_n(R[2], 1);
    block[11] = kryptos_twofish_get_byte_n(R[2], 0);
    block[12] = kryptos_twofish_get_byte_n(R[3], 3);
    block[13] = kryptos_twofish_get_byte_n(R[3], 2);
    block[14] = kryptos_twofish_get_byte_n(R[3], 1);
    block[15] = kryptos_twofish_get_byte_n(R[3], 0);

    memset(R, 0, sizeof(R));
    memset(a, 0, sizeof(a));
    memset(b, 0, sizeof(b));
    f0 = f1 = tt = 0;
}

#undef KRYPTOS_TWOFISH_SK_WORDS_NR
#undef KRYPTOS_TWOFISH_SBOXES_NR
#undef KRYPTOS_TWOFISH_S_NR
#undef KRYPTOS_TWOFISH_M_NR
#undef KRYPTOS_TWOFISH_ROUNDS_NR

#undef KRYPTOS_TWOFISH_MDS_R0
#undef KRYPTOS_TWOFISH_MDS_R1
#undef KRYPTOS_TWOFISH_MDS_R2
#undef KRYPTOS_TWOFISH_MDS_R3

#undef kryptos_twofish_wrol

#undef kryptos_twofish_wror

#undef kryptos_twofish_nrol

#undef kryptos_twofish_nror

#undef kryptos_twofish_qn_perm

#undef kryptos_twofish_q0_perm

#undef kryptos_twofish_q1_perm

#undef kryptos_twofish_gfmul

#undef kryptos_twofish_get_byte_n

#undef kryptos_twofish_g_128

#undef kryptos_twofish_g_192

#undef kryptos_twofish_g_256

#undef kryptos_twofish_g

#undef kryptos_twofish_mds

#undef kryptos_twofish_rs

#undef kryptos_twofish_pht

#undef kryptos_twofish_f

#undef kryptos_twofish_inv_endianness
