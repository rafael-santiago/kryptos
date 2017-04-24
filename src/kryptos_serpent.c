/*
 *                          Copyright (C) 2017, 2007 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_serpent.h>
#include <kryptos_endianess_utils.h>
#include <kryptos_task_check.h>
#include <kryptos_random.h>
#include <kryptos_padding.h>
#include <kryptos.h>
#include <stdarg.h>
#include <string.h>

#define kryptos_serpent_get_u8_from_u32(w,b) ( (kryptos_u8_t) ( (w) >> (24 - ((b) << 3)) )

#define kryptos_serpent_u32_rl(w,l) (kryptos_u32_t) ( ( (w) << (l) ) | ( (w) >> ( 32 - (l) ) ) )

#define kryptos_serpent_get_u1_from_u4(x, b) ( (kryptos_u8_t) ( ( (x) << ( 4 + (b) ) ) >> 7  ) )

#define kryptos_serpent_get_u4_from_u32(w, n) ( (n) == 0 ? (((w & 0xf0000000) >> 28) & 0x0f) :\
		   			        (n) == 1 ? (((w & 0x0f000000) >> 24) & 0x0f) :\
					        (n) == 2 ? (((w & 0x00f00000) >> 20) & 0x0f) :\
					        (n) == 3 ? (((w & 0x000f0000) >> 16) & 0x0f) :\
					        (n) == 4 ? (((w & 0x0000f000) >> 12) & 0x0f) :\
					        (n) == 5 ? (((w & 0x00000f00) >>  8) & 0x0f) :\
					        (n) == 6 ? (((w & 0x000000f0) >>  4) & 0x0f) :\
					        (n) == 7 ? (((w & 0x0000000f)) & 0x0f) : 0 )

#define kryptos_serpent_get_u4_from_4u32(w, n) (\
 (n) >=  0 && (n) <=  7  ?  kryptos_serpent_get_u4_from_u32((w)[0], (n))      :\
 (n) >=  8 && (n) <= 15  ?  kryptos_serpent_get_u4_from_u32((w)[1], (n) - 8)  :\
 (n) >= 16 && (n) <= 23  ?  kryptos_serpent_get_u4_from_u32((w)[2], (n) - 16) :\
 (n) >= 24 && (n) <= 31  ?  kryptos_serpent_get_u4_from_u32((w)[3], (n) - 24) : 0 )

#define kryptos_serpent_phi 0x9e3779b9

/*bitmasks*/
#define kryptos_serpent_bitmask00 0x80000000
#define kryptos_serpent_bitmask01 0x40000000
#define kryptos_serpent_bitmask02 0x20000000
#define kryptos_serpent_bitmask03 0x10000000
#define kryptos_serpent_bitmask04 0x08000000
#define kryptos_serpent_bitmask05 0x04000000
#define kryptos_serpent_bitmask06 0x02000000
#define kryptos_serpent_bitmask07 0x01000000
#define kryptos_serpent_bitmask08 0x00800000
#define kryptos_serpent_bitmask09 0x00400000
#define kryptos_serpent_bitmask10 0x00200000
#define kryptos_serpent_bitmask11 0x00100000
#define kryptos_serpent_bitmask12 0x00080000
#define kryptos_serpent_bitmask13 0x00040000
#define kryptos_serpent_bitmask14 0x00020000
#define kryptos_serpent_bitmask15 0x00010000
#define kryptos_serpent_bitmask16 0x00008000
#define kryptos_serpent_bitmask17 0x00004000
#define kryptos_serpent_bitmask18 0x00002000
#define kryptos_serpent_bitmask19 0x00001000
#define kryptos_serpent_bitmask20 0x00000800
#define kryptos_serpent_bitmask21 0x00000400
#define kryptos_serpent_bitmask22 0x00000200
#define kryptos_serpent_bitmask23 0x00000100
#define kryptos_serpent_bitmask24 0x00000080
#define kryptos_serpent_bitmask25 0x00000040
#define kryptos_serpent_bitmask26 0x00000020
#define kryptos_serpent_bitmask27 0x00000010
#define kryptos_serpent_bitmask28 0x00000008
#define kryptos_serpent_bitmask29 0x00000004
#define kryptos_serpent_bitmask30 0x00000002
#define kryptos_serpent_bitmask31 0x00000001

#define kryptos_serpentLTRound(lto, lti) (\
  lto[  0] = kryptos_serpentLT(7, lti,  16,  52,  56,  70,  83,  94, 105), lto[  1] = kryptos_serpentLT(3, lti,  72, 114, 125),\
  lto[  2] = kryptos_serpentLT(7, lti,   2,   9,  15,  30,  76,  84, 126), lto[  3] = kryptos_serpentLT(3, lti,  36,  90, 103),\
  lto[  4] = kryptos_serpentLT(7, lti,  20,  56,  60,  74,  87,  98, 109), lto[  5] = kryptos_serpentLT(3, lti,   1,  76, 118),\
  lto[  6] = kryptos_serpentLT(7, lti,   2,   6,  13,  19,  34,  80,  88), lto[  7] = kryptos_serpentLT(3, lti,  40,  94, 107),\
  lto[  8] = kryptos_serpentLT(7, lti,  24,  60,  64,  78,  91, 102, 113), lto[  9] = kryptos_serpentLT(3, lti,   5,  80, 122),\
  lto[ 10] = kryptos_serpentLT(7, lti,   6,  10,  17,  23,  38,  84,  92), lto[ 11] = kryptos_serpentLT(3, lti,  44,  98, 111),\
  lto[ 12] = kryptos_serpentLT(7, lti,  28,  64,  68,  82,  95, 106, 117), lto[ 13] = kryptos_serpentLT(3, lti,   9,  84, 126),\
  lto[ 14] = kryptos_serpentLT(7, lti,  10,  14,  21,  27,  42,  88,  96), lto[ 15] = kryptos_serpentLT(3, lti,  48, 102, 115),\
  lto[ 16] = kryptos_serpentLT(7, lti,  32,  68,  72,  86,  99, 110, 121), lto[ 17] = kryptos_serpentLT(3, lti,   2,  13,  88),\
  lto[ 18] = kryptos_serpentLT(7, lti,  14,  18,  25,  31,  46,  92, 100), lto[ 19] = kryptos_serpentLT(3, lti,  52, 106, 119),\
  lto[ 20] = kryptos_serpentLT(7, lti,  36,  72,  76,  90, 103, 114, 125), lto[ 21] = kryptos_serpentLT(3, lti,   6,  17,  92),\
  lto[ 22] = kryptos_serpentLT(7, lti,  18,  22,  29,  35,  50,  96, 104), lto[ 23] = kryptos_serpentLT(3, lti,  56, 110, 123),\
  lto[ 24] = kryptos_serpentLT(7, lti,   1,  40,  76,  80,  94, 107, 118), lto[ 25] = kryptos_serpentLT(3, lti,  10,  21,  96),\
  lto[ 26] = kryptos_serpentLT(7, lti,  22,  26,  33,  39,  54, 100, 108), lto[ 27] = kryptos_serpentLT(3, lti,  60, 114, 127),\
  lto[ 28] = kryptos_serpentLT(7, lti,   5,  44,  80,  84,  98, 111, 122), lto[ 29] = kryptos_serpentLT(3, lti,  14,  25, 100),\
  lto[ 30] = kryptos_serpentLT(7, lti,  26,  30,  37,  43,  58, 104, 112), lto[ 31] = kryptos_serpentLT(2, lti,   3,  118    ),\
  lto[ 32] = kryptos_serpentLT(7, lti,   9,  48,  84,  88, 102, 115, 126), lto[ 33] = kryptos_serpentLT(3, lti,  18,  29, 104),\
  lto[ 34] = kryptos_serpentLT(7, lti,  30,  34,  41,  47,  62, 108, 116), lto[ 35] = kryptos_serpentLT(2, lti,   7, 122     ),\
  lto[ 36] = kryptos_serpentLT(7, lti,   2,  13,  52,  88,  92, 106, 119), lto[ 37] = kryptos_serpentLT(3, lti,  22,  33, 108),\
  lto[ 38] = kryptos_serpentLT(7, lti,  34,  38,  45,  51,  66, 112, 120), lto[ 39] = kryptos_serpentLT(2, lti,  11, 126     ),\
  lto[ 40] = kryptos_serpentLT(7, lti,   6,  17,  56,  92,  96, 110, 123), lto[ 41] = kryptos_serpentLT(3, lti,  26,  37, 112),\
  lto[ 42] = kryptos_serpentLT(7, lti,  38,  42,  49,  55,  70, 116, 124), lto[ 43] = kryptos_serpentLT(3, lti,   2,  15,  76),\
  lto[ 44] = kryptos_serpentLT(7, lti,  10,  21,  60,  96, 100, 114, 127), lto[ 45] = kryptos_serpentLT(3, lti,  30,  41, 116),\
  lto[ 46] = kryptos_serpentLT(7, lti,   0,  42,  46,  53,  59,  74, 120), lto[ 47] = kryptos_serpentLT(3, lti,   6,  19,  80),\
  lto[ 48] = kryptos_serpentLT(6, lti,   3,  14,  25, 100, 104, 118     ), lto[ 49] = kryptos_serpentLT(3, lti,  34,  45, 120),\
  lto[ 50] = kryptos_serpentLT(7, lti,   4,  46,  50,  57,  63,  78, 124), lto[ 51] = kryptos_serpentLT(3, lti,  10,  23,  84),\
  lto[ 52] = kryptos_serpentLT(6, lti,   7,  18,  29, 104, 108, 122     ), lto[ 53] = kryptos_serpentLT(3, lti,  38,  49, 124),\
  lto[ 54] = kryptos_serpentLT(7, lti,   0,   8,  50,  54,  61,  67,  82), lto[ 55] = kryptos_serpentLT(3, lti,  14,  27,  88),\
  lto[ 56] = kryptos_serpentLT(6, lti,  11,  22,  33, 108, 112, 126     ), lto[ 57] = kryptos_serpentLT(3, lti,   0,  42,  53),\
  lto[ 58] = kryptos_serpentLT(7, lti,   4,  12,  54,  58,  65,  71,  86), lto[ 59] = kryptos_serpentLT(3, lti,  18,  31,  92),\
  lto[ 60] = kryptos_serpentLT(7, lti,   2,  15,  26,  37,  76, 112, 116), lto[ 61] = kryptos_serpentLT(3, lti,   4,  46,  57),\
  lto[ 62] = kryptos_serpentLT(7, lti,   8,  16,  58,  62,  69,  75,  90), lto[ 63] = kryptos_serpentLT(3, lti,  22,  35,  96),\
  lto[ 64] = kryptos_serpentLT(7, lti,   6,  19,  30,  41,  80, 116, 120), lto[ 65] = kryptos_serpentLT(3, lti,   8,  50,  61),\
  lto[ 66] = kryptos_serpentLT(7, lti,  12,  20,  62,  66,  73,  79,  94), lto[ 67] = kryptos_serpentLT(3, lti,  26,  39, 100),\
  lto[ 68] = kryptos_serpentLT(7, lti,  10,  23,  34,  45,  84, 120, 124), lto[ 69] = kryptos_serpentLT(3, lti,  12,  54,  65),\
  lto[ 70] = kryptos_serpentLT(7, lti,  16,  24,  66,  70,  77,  83,  98), lto[ 71] = kryptos_serpentLT(3, lti,  30,  43, 104),\
  lto[ 72] = kryptos_serpentLT(7, lti,   0,  14,  27,  38,  49,  88, 124), lto[ 73] = kryptos_serpentLT(3, lti,  16,  58,  69),\
  lto[ 74] = kryptos_serpentLT(7, lti,  20,  28,  70,  74,  81,  87, 102), lto[ 75] = kryptos_serpentLT(3, lti,  34,  47, 108),\
  lto[ 76] = kryptos_serpentLT(7, lti,   0,   4,  18,  31,  42,  53,  92), lto[ 77] = kryptos_serpentLT(3, lti,  20,  62,  73),\
  lto[ 78] = kryptos_serpentLT(7, lti,  24,  32,  74,  78,  85,  91, 106), lto[ 79] = kryptos_serpentLT(3, lti,  38,  51, 112),\
  lto[ 80] = kryptos_serpentLT(7, lti,   4,   8,  22,  35,  46,  57,  96), lto[ 81] = kryptos_serpentLT(3, lti,  24,  66,  77),\
  lto[ 82] = kryptos_serpentLT(7, lti,  28,  36,  78,  82,  89,  95, 110), lto[ 83] = kryptos_serpentLT(3, lti,  42,  55, 116),\
  lto[ 84] = kryptos_serpentLT(7, lti,   8,  12,  26,  39,  50,  61, 100), lto[ 85] = kryptos_serpentLT(3, lti,  28,  70,  81),\
  lto[ 86] = kryptos_serpentLT(7, lti,  32,  40,  82,  86,  93,  99, 114), lto[ 87] = kryptos_serpentLT(3, lti,  46,  59, 120),\
  lto[ 88] = kryptos_serpentLT(7, lti,  12,  16,  30,  43,  54,  65, 104), lto[ 89] = kryptos_serpentLT(3, lti,  32,  74,  85),\
  lto[ 90] = kryptos_serpentLT(4, lti,  36,  90, 103, 118               ), lto[ 91] = kryptos_serpentLT(3, lti,  50,  63, 124),\
  lto[ 92] = kryptos_serpentLT(7, lti,  16,  20,  34,  47,  58,  69, 108), lto[ 93] = kryptos_serpentLT(3, lti,  36,  78,  89),\
  lto[ 94] = kryptos_serpentLT(4, lti,  40,  94, 107, 122               ), lto[ 95] = kryptos_serpentLT(3, lti,   0,  54,  67),\
  lto[ 96] = kryptos_serpentLT(7, lti,  20,  24,  38,  51,  62,  73, 112), lto[ 97] = kryptos_serpentLT(3, lti,  40,  82,  93),\
  lto[ 98] = kryptos_serpentLT(4, lti,  44,  98, 111, 126               ), lto[ 99] = kryptos_serpentLT(3, lti,   4,  58,  71),\
  lto[100] = kryptos_serpentLT(7, lti,  24,  28,  42,  55,  66,  77, 116), lto[101] = kryptos_serpentLT(3, lti,  44,  86,  97),\
  lto[102] = kryptos_serpentLT(4, lti,   2,  48, 102, 115               ), lto[103] = kryptos_serpentLT(3, lti,   8,  62,  75),\
  lto[104] = kryptos_serpentLT(7, lti,  28,  32,  46,  59,  70,  81, 120), lto[105] = kryptos_serpentLT(3, lti,  48,  90, 101),\
  lto[106] = kryptos_serpentLT(4, lti,   6,  52, 106, 119               ), lto[107] = kryptos_serpentLT(3, lti,  12,  66,  79),\
  lto[108] = kryptos_serpentLT(7, lti,  32,  36,  50,  63,  74,  85, 124), lto[109] = kryptos_serpentLT(3, lti,  52,  94, 105),\
  lto[110] = kryptos_serpentLT(4, lti,  10,  56, 110, 123               ), lto[111] = kryptos_serpentLT(3, lti,  16,  70,  83),\
  lto[112] = kryptos_serpentLT(7, lti,   0,  36,  40,  54,  67,  78,  89), lto[113] = kryptos_serpentLT(3, lti,  56,  98, 109),\
  lto[114] = kryptos_serpentLT(4, lti,  14,  60, 114, 127               ), lto[115] = kryptos_serpentLT(3, lti,  20,  74,  87),\
  lto[116] = kryptos_serpentLT(7, lti,   4,  40,  44,  58,  71,  82,  93), lto[117] = kryptos_serpentLT(3, lti,  60, 102, 113),\
  lto[118] = kryptos_serpentLT(6, lti,   3,  18,  72, 114, 118, 125     ), lto[119] = kryptos_serpentLT(3, lti,  24,  78,  91),\
  lto[120] = kryptos_serpentLT(7, lti,   8,  44,  48,  62,  75,  86,  97), lto[121] = kryptos_serpentLT(3, lti,  64, 106, 117),\
  lto[122] = kryptos_serpentLT(6, lti,   1,   7,  22,  76, 118, 122     ), lto[123] = kryptos_serpentLT(3, lti,  28,  82,  95),\
  lto[124] = kryptos_serpentLT(7, lti,  12,  48,  52,  66,  79,  90, 101), lto[125] = kryptos_serpentLT(3, lti,  68, 110, 121),\
  lto[126] = kryptos_serpentLT(6, lti,   5,  11,  26,  80, 122, 126     ), lto[127] = kryptos_serpentLT(3, lti,  32,  86,  99) )

#define kryptos_serpentSRound(b, bx) (\
 (b)[0] = (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b,  0), kryptos_serpent_boxes[(bx)]) << 28 |\
          (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b,  1), kryptos_serpent_boxes[(bx)]) << 24 |\
	  (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b,  2), kryptos_serpent_boxes[(bx)]) << 20 |\
	  (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b,  3), kryptos_serpent_boxes[(bx)]) << 16 |\
	  (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b,  4), kryptos_serpent_boxes[(bx)]) << 12 |\
	  (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b,  5), kryptos_serpent_boxes[(bx)]) <<  8 |\
	  (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b,  6), kryptos_serpent_boxes[(bx)]) <<  4 |\
	  (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b,  7), kryptos_serpent_boxes[(bx)]),\
 (b)[1] = (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b,  8), kryptos_serpent_boxes[(bx)]) << 28 |\
          (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b,  9), kryptos_serpent_boxes[(bx)]) << 24 |\
          (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 10), kryptos_serpent_boxes[(bx)]) << 20 |\
          (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 11), kryptos_serpent_boxes[(bx)]) << 16 |\
          (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 12), kryptos_serpent_boxes[(bx)]) << 12 |\
	  (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 13), kryptos_serpent_boxes[(bx)]) <<  8 |\
	  (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 14), kryptos_serpent_boxes[(bx)]) <<  4 |\
	  (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 15), kryptos_serpent_boxes[(bx)]),\
 (b)[2] = (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 16), kryptos_serpent_boxes[(bx)]) << 28 |\
          (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 17), kryptos_serpent_boxes[(bx)]) << 24 |\
	  (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 18), kryptos_serpent_boxes[(bx)]) << 20 |\
	  (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 19), kryptos_serpent_boxes[(bx)]) << 16 |\
	  (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 20), kryptos_serpent_boxes[(bx)]) << 12 |\
	  (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 21), kryptos_serpent_boxes[(bx)]) <<  8 |\
	  (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 22), kryptos_serpent_boxes[(bx)]) <<  4 |\
	  (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 23), kryptos_serpent_boxes[(bx)]),\
 (b)[3] = (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 24), kryptos_serpent_boxes[(bx)]) << 28 |\
          (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 25), kryptos_serpent_boxes[(bx)]) << 24 |\
     	  (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 26), kryptos_serpent_boxes[(bx)]) << 20 |\
	  (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 27), kryptos_serpent_boxes[(bx)]) << 16 |\
	  (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 28), kryptos_serpent_boxes[(bx)]) << 12 |\
	  (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 29), kryptos_serpent_boxes[(bx)]) <<  8 |\
	  (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 30), kryptos_serpent_boxes[(bx)]) <<  4 |\
	  (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 31), kryptos_serpent_boxes[(bx)]) )

#define kryptos_serpentInvLTRound(lto, lti) (\
  lto[  0] = kryptos_serpentLT(3, lti,  53,  55,  72), lto[  1] = kryptos_serpentLT(4, lti,   1,   5,  20,  90               ),\
  lto[  2] = kryptos_serpentLT(2, lti,  15, 102     ), lto[  3] = kryptos_serpentLT(3, lti,   3,  31,  90                    ),\
  lto[  4] = kryptos_serpentLT(3, lti,  57,  59,  76), lto[  5] = kryptos_serpentLT(4, lti,   5,   9,  24,  94               ),\
  lto[  6] = kryptos_serpentLT(2, lti,  19, 106     ), lto[  7] = kryptos_serpentLT(3, lti,   7,  35,  94                    ),\
  lto[  8] = kryptos_serpentLT(3, lti,  61,  63,  80), lto[  9] = kryptos_serpentLT(4, lti,   9,  13,  28,  98               ),\
  lto[ 10] = kryptos_serpentLT(2, lti,  23, 110     ), lto[ 11] = kryptos_serpentLT(3, lti,  11,  39,  98                    ),\
  lto[ 12] = kryptos_serpentLT(3, lti,  65,  67,  84), lto[ 13] = kryptos_serpentLT(4, lti,  13,  17,  32, 102               ),\
  lto[ 14] = kryptos_serpentLT(2, lti,  27, 114     ), lto[ 15] = kryptos_serpentLT(6, lti,   1,   3,  15,  20,  43, 102     ),\
  lto[ 16] = kryptos_serpentLT(3, lti,  69,  71,  88), lto[ 17] = kryptos_serpentLT(4, lti,  17,  21,  36, 106               ),\
  lto[ 18] = kryptos_serpentLT(3, lti,   1,  31, 118), lto[ 19] = kryptos_serpentLT(6, lti,   5,   7,  19,  24,  47, 106     ),\
  lto[ 20] = kryptos_serpentLT(3, lti,  73,  75,  92), lto[ 21] = kryptos_serpentLT(4, lti,  21,  25,  40, 110               ),\
  lto[ 22] = kryptos_serpentLT(3, lti,   5,  35, 122), lto[ 23] = kryptos_serpentLT(6, lti,   9,  11,  23,  28,  51, 110     ),\
  lto[ 24] = kryptos_serpentLT(3, lti,  77,  79,  96), lto[ 25] = kryptos_serpentLT(4, lti,  25,  29,  44, 114               ),\
  lto[ 26] = kryptos_serpentLT(3, lti,   9,  39, 126), lto[ 27] = kryptos_serpentLT(6, lti,  13,  15,  27,  32,  55, 114     ),\
  lto[ 28] = kryptos_serpentLT(3, lti,  81,  83, 100), lto[ 29] = kryptos_serpentLT(5, lti,   1,  29,  33,  48, 118          ),\
  lto[ 30] = kryptos_serpentLT(3, lti,   2,  13,  43), lto[ 31] = kryptos_serpentLT(7, lti,   1,  17,  19,  31,  36,  59, 118),\
  lto[ 32] = kryptos_serpentLT(3, lti,  85,  87, 104), lto[ 33] = kryptos_serpentLT(5, lti,   5,  33,  37,  52, 122          ),\
  lto[ 34] = kryptos_serpentLT(3, lti,   6,  17,  47), lto[ 35] = kryptos_serpentLT(7, lti,   5,  21,  23,  35,  40,  63, 122),\
  lto[ 36] = kryptos_serpentLT(3, lti,  89,  91, 108), lto[ 37] = kryptos_serpentLT(5, lti,   9,  37,  41,  56, 126          ),\
  lto[ 38] = kryptos_serpentLT(3, lti,  10,  21,  51), lto[ 39] = kryptos_serpentLT(7, lti,   9,  25,  27,  39,  44,  67, 126),\
  lto[ 40] = kryptos_serpentLT(3, lti,  93,  95, 112), lto[ 41] = kryptos_serpentLT(5, lti,   2,  13,  41,  45,  60          ),\
  lto[ 42] = kryptos_serpentLT(3, lti,  14,  25,  55), lto[ 43] = kryptos_serpentLT(7, lti,   2,  13,  29,  31,  43,  48,  71),\
  lto[ 44] = kryptos_serpentLT(3, lti,  97,  99, 116), lto[ 45] = kryptos_serpentLT(5, lti,   6,  17,  45,  49,  64          ),\
  lto[ 46] = kryptos_serpentLT(3, lti,  18,  29,  59), lto[ 47] = kryptos_serpentLT(7, lti,   6,  17,  33,  35,  47,  52,  75),\
  lto[ 48] = kryptos_serpentLT(3, lti, 101, 103, 120), lto[ 49] = kryptos_serpentLT(5, lti,  10,  21,  49,  53,  68          ),\
  lto[ 50] = kryptos_serpentLT(3, lti,  22,  33,  63), lto[ 51] = kryptos_serpentLT(7, lti,  10,  21,  37,  39,  51,  56,  79),\
  lto[ 52] = kryptos_serpentLT(3, lti, 105, 107, 124), lto[ 53] = kryptos_serpentLT(5, lti,  14,  25,  53,  57,  72          ),\
  lto[ 54] = kryptos_serpentLT(3, lti,  26,  37,  67), lto[ 55] = kryptos_serpentLT(7, lti,  14,  25,  41,  43,  55,  60,  83),\
  lto[ 56] = kryptos_serpentLT(3, lti,   0, 109, 111), lto[ 57] = kryptos_serpentLT(5, lti,  18,  29,  57,  61,  76          ),\
  lto[ 58] = kryptos_serpentLT(3, lti,  30,  41,  71), lto[ 59] = kryptos_serpentLT(7, lti,  18,  29,  45,  47,  59,  64,  87),\
  lto[ 60] = kryptos_serpentLT(3, lti,   4, 113, 115), lto[ 61] = kryptos_serpentLT(5, lti,  22,  33,  61,  65,  80          ),\
  lto[ 62] = kryptos_serpentLT(3, lti,  34,  45,  75), lto[ 63] = kryptos_serpentLT(7, lti,  22,  33,  49,  51,  63,  68,  91),\
  lto[ 64] = kryptos_serpentLT(3, lti,   8, 117, 119), lto[ 65] = kryptos_serpentLT(5, lti,  26,  37,  65,  69,  84          ),\
  lto[ 66] = kryptos_serpentLT(3, lti,  38,  49,  79), lto[ 67] = kryptos_serpentLT(7, lti,  26,  37,  53,  55,  67,  72,  95),\
  lto[ 68] = kryptos_serpentLT(3, lti,  12, 121, 123), lto[ 69] = kryptos_serpentLT(5, lti,  30,  41,  69,  73,  88          ),\
  lto[ 70] = kryptos_serpentLT(3, lti,  42,  53,  83), lto[ 71] = kryptos_serpentLT(7, lti,  30,  41,  57,  59,  71,  76,  99),\
  lto[ 72] = kryptos_serpentLT(3, lti,  16, 125, 127), lto[ 73] = kryptos_serpentLT(5, lti,  34,  45,  73,  77,  92          ),\
  lto[ 74] = kryptos_serpentLT(3, lti,  46,  57,  87), lto[ 75] = kryptos_serpentLT(7, lti,  34,  45,  61,  63,  75,  80, 103),\
  lto[ 76] = kryptos_serpentLT(3, lti,   1,   3,  20), lto[ 77] = kryptos_serpentLT(5, lti,  38,  49,  77,  81,  96          ),\
  lto[ 78] = kryptos_serpentLT(3, lti,  50,  61,  91), lto[ 79] = kryptos_serpentLT(7, lti,  38,  49,  65,  67,  79,  84, 107),\
  lto[ 80] = kryptos_serpentLT(3, lti,   5,   7,  24), lto[ 81] = kryptos_serpentLT(5, lti,  42,  53,  81,  85, 100          ),\
  lto[ 82] = kryptos_serpentLT(3, lti,  54,  65,  95), lto[ 83] = kryptos_serpentLT(7, lti,  42,  53,  69,  71,  83,  88, 111),\
  lto[ 84] = kryptos_serpentLT(3, lti,   9,  11,  28), lto[ 85] = kryptos_serpentLT(5, lti,  46,  57,  85,  89, 104          ),\
  lto[ 86] = kryptos_serpentLT(3, lti,  58,  69,  99), lto[ 87] = kryptos_serpentLT(7, lti,  46,  57,  73,  75,  87,  92, 115),\
  lto[ 88] = kryptos_serpentLT(3, lti,  13,  15,  32), lto[ 89] = kryptos_serpentLT(5, lti,  50,  61,  89,  93, 108          ),\
  lto[ 90] = kryptos_serpentLT(3, lti,  62,  73, 103), lto[ 91] = kryptos_serpentLT(7, lti,  50,  61,  77,  79,  91,  96, 119),\
  lto[ 92] = kryptos_serpentLT(3, lti,  17,  19,  36), lto[ 93] = kryptos_serpentLT(5, lti,  54,  65,  93,  97, 112          ),\
  lto[ 94] = kryptos_serpentLT(3, lti,  66,  77, 107), lto[ 95] = kryptos_serpentLT(7, lti,  54,  65,  81,  83,  95, 100, 123),\
  lto[ 96] = kryptos_serpentLT(3, lti,  21,  23,  40), lto[ 97] = kryptos_serpentLT(5, lti,  58,  69,  97, 101, 116          ),\
  lto[ 98] = kryptos_serpentLT(3, lti,  70,  81, 111), lto[ 99] = kryptos_serpentLT(7, lti,  58,  69,  85,  87,  99, 104, 127),\
  lto[100] = kryptos_serpentLT(3, lti,  25,  27,  44), lto[101] = kryptos_serpentLT(5, lti,  62,  73, 101, 105, 120          ),\
  lto[102] = kryptos_serpentLT(3, lti,  74,  85, 115), lto[103] = kryptos_serpentLT(7, lti,   3,  62,  73,  89,  91, 103, 108),\
  lto[104] = kryptos_serpentLT(3, lti,  29,  31,  48), lto[105] = kryptos_serpentLT(5, lti,  66,  77, 105, 109, 124          ),\
  lto[106] = kryptos_serpentLT(3, lti,  78,  89, 119), lto[107] = kryptos_serpentLT(7, lti,   7,  66,  77,  93,  95, 107, 112),\
  lto[108] = kryptos_serpentLT(3, lti,  33,  35,  52), lto[109] = kryptos_serpentLT(5, lti,   0,  70,  81, 109, 113          ),\
  lto[110] = kryptos_serpentLT(3, lti,  82,  93, 123), lto[111] = kryptos_serpentLT(7, lti,  11,  70,  81,  97,  99, 111, 116),\
  lto[112] = kryptos_serpentLT(3, lti,  37,  39,  56), lto[113] = kryptos_serpentLT(5, lti,   4,  74,  85, 113, 117          ),\
  lto[114] = kryptos_serpentLT(3, lti,  86,  97, 127), lto[115] = kryptos_serpentLT(7, lti,  15,  74,  85, 101, 103, 115, 120),\
  lto[116] = kryptos_serpentLT(3, lti,  41,  43,  60), lto[117] = kryptos_serpentLT(5, lti,   8,  78,  89, 117, 121          ),\
  lto[118] = kryptos_serpentLT(2, lti,   3,  90     ), lto[119] = kryptos_serpentLT(7, lti,  19,  78,  89, 105, 107, 119, 124),\
  lto[120] = kryptos_serpentLT(3, lti,  45,  47,  64), lto[121] = kryptos_serpentLT(5, lti,  12,  82,  93, 121, 125          ),\
  lto[122] = kryptos_serpentLT(2, lti,   7,  94     ), lto[123] = kryptos_serpentLT(7, lti,   0,  23,  82,  93, 109, 111, 123),\
  lto[124] = kryptos_serpentLT(3, lti,  49,  51,  68), lto[125] = kryptos_serpentLT(5, lti,   1,  16,  86,  97, 125          ),\
  lto[126] = kryptos_serpentLT(2, lti,  11,  98     ), lto[127] = kryptos_serpentLT(7, lti,   4,  27,  86,  97, 113, 115, 127) )

#define kryptos_serpentInvSRound(b, bx) (\
 b[0] = (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b,  0), kryptos_serpent_invboxes[(bx)]) << 28 |\
        (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b,  1), kryptos_serpent_invboxes[(bx)]) << 24 |\
	(kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b,  2), kryptos_serpent_invboxes[(bx)]) << 20 |\
	(kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b,  3), kryptos_serpent_invboxes[(bx)]) << 16 |\
	(kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b,  4), kryptos_serpent_invboxes[(bx)]) << 12 |\
	(kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b,  5), kryptos_serpent_invboxes[(bx)]) <<  8 |\
	(kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b,  6), kryptos_serpent_invboxes[(bx)]) <<  4 |\
	(kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b,  7), kryptos_serpent_invboxes[(bx)]),\
 b[1] = (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b,  8), kryptos_serpent_invboxes[(bx)]) << 28 |\
        (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b,  9), kryptos_serpent_invboxes[(bx)]) << 24 |\
        (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 10), kryptos_serpent_invboxes[(bx)]) << 20 |\
        (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 11), kryptos_serpent_invboxes[(bx)]) << 16 |\
        (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 12), kryptos_serpent_invboxes[(bx)]) << 12 |\
	(kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 13), kryptos_serpent_invboxes[(bx)]) <<  8 |\
	(kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 14), kryptos_serpent_invboxes[(bx)]) <<  4 |\
	(kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 15), kryptos_serpent_invboxes[(bx)]),\
 b[2] = (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 16), kryptos_serpent_invboxes[(bx)]) << 28 |\
        (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 17), kryptos_serpent_invboxes[(bx)]) << 24 |\
	(kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 18), kryptos_serpent_invboxes[(bx)]) << 20 |\
	(kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 19), kryptos_serpent_invboxes[(bx)]) << 16 |\
	(kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 20), kryptos_serpent_invboxes[(bx)]) << 12 |\
	(kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 21), kryptos_serpent_invboxes[(bx)]) <<  8 |\
	(kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 22), kryptos_serpent_invboxes[(bx)]) <<  4 |\
	(kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 23), kryptos_serpent_invboxes[(bx)]),\
 b[3] = (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 24), kryptos_serpent_invboxes[(bx)]) << 28 |\
        (kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 25), kryptos_serpent_invboxes[(bx)]) << 24 |\
	(kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 26), kryptos_serpent_invboxes[(bx)]) << 20 |\
	(kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 27), kryptos_serpent_invboxes[(bx)]) << 16 |\
	(kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 28), kryptos_serpent_invboxes[(bx)]) << 12 |\
	(kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 29), kryptos_serpent_invboxes[(bx)]) <<  8 |\
	(kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 30), kryptos_serpent_invboxes[(bx)]) <<  4 |\
	(kryptos_u32_t) kryptos_serpentS(kryptos_serpent_get_u4_from_4u32(b, 31), kryptos_serpent_invboxes[(bx)]) );

#define kryptos_serpentS(input, sbox) ( (sbox)[(input)] )

// INFO(Rafael): The Serpent s-boxes.

static kryptos_u8_t kryptos_serpent_boxes[8][16] = { // INFO(Rafael): This one is used on scheduling and ciphering.
  3,  8, 15,  1, 10,  6,  5, 11, 14, 13,  4,  2,  7,  0,  9, 12,
 15, 12,  2,  7,  9,  0,  5, 10,  1, 11, 14,  8,  6, 13,  3,  4,
  8,  6,  7,  9,  3, 12, 10, 15, 13,  1, 14,  4,  0, 11,  5,  2,
  0, 15, 11,  8, 12,  9,  6,  3, 13,  1,  2,  4, 10,  7,  5, 14,
  1, 15,  8,  3, 12,  0, 11,  6,  2,  5,  4, 10,  9, 14,  7, 13,
 15,  5,  2, 11,  4, 10,  9, 12,  0,  3, 14,  8, 13,  6,  7,  1,
  7,  2, 12,  5,  8,  4,  6, 11, 14,  9,  1, 15, 13,  3, 10,  0,
  1, 13, 15,  0, 14,  8,  2, 11,  7,  4, 12, 10,  9,  3,  5,  6
};

static kryptos_u8_t kryptos_serpent_invboxes[8][16] = { // INFO(Rafael): The inverse.
 13,  3, 11,  0, 10,  6,  5, 12,  1, 14,  4,  7, 15,  9,  8,  2,
  5,  8,  2, 14, 15,  6, 12,  3, 11,  4,  7,  9,  1, 13, 10,  0,
 12,  9, 15,  4, 11, 14,  1,  2,  0,  3,  6, 13,  5,  8, 10,  7,
  0,  9, 10,  7, 11, 14,  6, 13,  3,  5, 12,  2,  4,  8, 15,  1,
  5,  0,  8,  3, 10,  9,  7, 14,  2, 12, 11,  6,  4, 15, 13,  1,
  8, 15,  2,  9,  4,  1, 13, 14, 11,  6,  5,  3,  7, 12, 10,  0,
 15, 10,  1, 13,  5,  3,  6,  0,  4,  9, 14,  7,  2, 12,  8, 11,
  3,  0,  6, 13,  9, 14, 15,  8,  5, 12, 11,  7, 10,  1,  4,  2
};

// INFO(Rafael): Permutations...

static kryptos_u8_t kryptos_serpent_ip[128] = { // INFO(Rafael): ...initial.
   0,  32,  64,  96,   1,  33,  65,  97,   2,  34,  66,  98,   3,  35,  67,  99,
   4,  36,  68, 100,   5,  37,  69, 101,   6,  38,  70, 102,   7,  39,  71, 103,
   8,  40,  72, 104,   9,  41,  73, 105,  10,  42,  74, 106,  11,  43,  75, 107,
  12,  44,  76, 108,  13,  45,  77, 109,  14,  46,  78, 110,  15,  47,  79, 111,
  16,  48,  80, 112,  17,  49,  81, 113,  18,  50,  82, 114,  19,  51,  83, 115,
  20,  52,  84, 116,  21,  53,  85, 117,  22,  54,  86, 118,  23,  55,  87, 119,
  24,  56,  88, 120,  25,  57,  89, 121,  26,  58,  90, 122,  27,  59,  91, 123,
  28,  60,  92, 124,  29,  61,  93, 125,  30,  62,  94, 126,  31,  63,  95, 127
};

static kryptos_u8_t kryptos_serpent_fp[128] = { // INFO(Rafael): ...and final.
   0,   4,   8,  12,  16,  20,  24,  28,  32,  36,  40,  44,  48,  52,  56,  60,
  64,  68,  72,  76,  80,  84,  88,  92,  96, 100, 104, 108, 112, 116, 120, 124,
   1,   5,   9,  13,  17,  21,  25,  29,  33,  37,  41,  45,  49,  53,  57,  61,
  65,  69,  73,  77,  81,  85,  89,  93,  97, 101, 105, 109, 113, 117, 121, 125,
   2,   6,  10,  14,  18,  22,  26,  30,  34,  38,  42,  46,  50,  54,  58,  62,
  66,  70,  74,  78,  82,  86,  90,  94,  98, 102, 106, 110, 114, 118, 122, 126,
   3,   7,  11,  15,  19,  23,  27,  31,  35,  39,  43,  47,  51,  55,  59,  63,
  67,  71,  75,  79,  83,  87,  91,  95,  99, 103, 107, 111, 115, 119, 123, 127
};

struct kryptos_serpent_subkeys {
 kryptos_u32_t k[33][4];
};

typedef void (*kryptos_serpent_block_processor)(kryptos_u8_t * block, struct kryptos_serpent_subkeys sks);

static kryptos_u8_t kryptos_serpentLT(const int bits, kryptos_u8_t input[128], ...);

static void kryptos_serpentXP(const kryptos_u8_t input[128], kryptos_u8_t output[128], const kryptos_u8_t p[128]);

static void kryptos_serpent_ld_u32buf_into_u8buf(kryptos_u8_t *output, const kryptos_u32_t *source, size_t bit_size);

static void kryptos_serpent_ld_u8buf_into_u32buf(kryptos_u32_t *output, kryptos_u8_t source[128], size_t bit_size);

static void kryptos_serpent_ld_user_key(kryptos_u32_t key[8], const kryptos_u8_t *user_key, const size_t user_key_size);

static void kryptos_serpent_key_schedule(const kryptos_u8_t *key, const size_t key_size, struct kryptos_serpent_subkeys *sks);

static void kryptos_serpent_permutation(const kryptos_u32_t in[4], kryptos_u32_t out[4], const kryptos_u8_t p[128]);

static void kryptos_serpent_lshift_u32(kryptos_u32_t *inout, const size_t level);

static kryptos_u8_t kryptos_serpent_mku4(kryptos_u32_t w0, kryptos_u32_t w1, kryptos_u32_t w2, kryptos_u32_t w3, const int b);

static void kryptos_serpent_ld_inv_u32buf_into_u8buf(kryptos_u8_t *output, const kryptos_u32_t *source, size_t bit_size);

static void kryptos_serpent_ld_inv_u8buf_into_u32buf(kryptos_u32_t *output, kryptos_u8_t source[128], size_t bit_size);

static void kryptos_serpent_block_encrypt(kryptos_u8_t *block, struct kryptos_serpent_subkeys sks);

static void kryptos_serpent_block_decrypt(kryptos_u8_t *block, struct kryptos_serpent_subkeys sks);

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_SETUP(serpent, kKryptosCipherSERPENT, KRYPTOS_SERPENT_BLOCKSIZE)

KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(serpent,
                                    ktask,
                                    kryptos_serpent_subkeys,
                                    sks,
                                    kryptos_serpent_block_processor,
                                    serpent_block_processor,
                                    kryptos_serpent_key_schedule((*ktask)->key, (*ktask)->key_size, &sks),
                                    kryptos_serpent_block_encrypt, /* No additional steps before encrypting */,
                                    kryptos_serpent_block_decrypt, /* No additional steps before decrypting */,
                                    KRYPTOS_SERPENT_BLOCKSIZE,
                                    serpent_cipher_epilogue,
                                    outblock,
                                    serpent_block_processor(outblock, sks))

static kryptos_u8_t kryptos_serpentLT(const int bits, kryptos_u8_t input[128], ...) {
    size_t w;
    va_list blist;
    kryptos_u8_t bxored = 0;
    int bit;

    va_start(blist, input);

    for (w = 0; w < bits; w++) {
        bit = va_arg(blist, int);
        bxored ^= input[bit];
    }

    va_end(blist);

    return bxored;
}

static void kryptos_serpentXP(const kryptos_u8_t input[128], kryptos_u8_t output[128], const kryptos_u8_t p[128]) {
    size_t w;
    for (w = 0; w < 128; w++) {
        output[w] = input[p[w]];
    }
}

static void kryptos_serpent_ld_u32buf_into_u8buf(kryptos_u8_t *output, const kryptos_u32_t *source, size_t bit_size) {
    size_t w = 0;
    while (w < bit_size) {
        output[     w] = (*source & kryptos_serpent_bitmask00) >> 31;
        output[w +  1] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask01),  1) >> 31;
        output[w +  2] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask02),  2) >> 31;
        output[w +  3] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask03),  3) >> 31;
        output[w +  4] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask04),  4) >> 31;
        output[w +  5] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask05),  5) >> 31;
        output[w +  6] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask06),  6) >> 31;
        output[w +  7] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask07),  7) >> 31;
        output[w +  8] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask08),  8) >> 31;
        output[w +  9] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask09),  9) >> 31;
        output[w + 10] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask10), 10) >> 31;
        output[w + 11] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask11), 11) >> 31;
        output[w + 12] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask12), 12) >> 31;
        output[w + 13] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask13), 13) >> 31;
        output[w + 14] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask14), 14) >> 31;
        output[w + 15] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask15), 15) >> 31;
        output[w + 16] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask16), 16) >> 31;
        output[w + 17] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask17), 17) >> 31;
        output[w + 18] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask18), 18) >> 31;
        output[w + 19] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask19), 19) >> 31;
        output[w + 20] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask20), 20) >> 31;
        output[w + 21] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask21), 21) >> 31;
        output[w + 22] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask22), 22) >> 31;
        output[w + 23] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask23), 23) >> 31;
        output[w + 24] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask24), 24) >> 31;
        output[w + 25] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask25), 25) >> 31;
        output[w + 26] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask26), 26) >> 31;
        output[w + 27] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask27), 27) >> 31;
        output[w + 28] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask28), 28) >> 31;
        output[w + 29] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask29), 29) >> 31;
        output[w + 30] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask30), 30) >> 31;
        output[w + 31] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask31), 31) >> 31;
        w += 32;
        source++;
    }
}

static void kryptos_serpent_ld_u8buf_into_u32buf(kryptos_u32_t *output, kryptos_u8_t source[128], size_t bit_size) {
    size_t w, b;

    for (w = 0, b = 0, output[w] = 0; b < bit_size; b++) {
        output[w] = output[w] << 1 | (kryptos_u32_t) source[b];
        if ((b + 1) % 32 == 0 && b < bit_size - 1) {
            w++;
            output[w] = 0;
        }
    }

    while (b % 32) {
        output[w] = output[w] << 1;
        b++;
    }
}

static void kryptos_serpent_ld_user_key(kryptos_u32_t key[8], const kryptos_u8_t *user_key, const size_t user_key_size) {
    const kryptos_u8_t *kp, *kp_end;
    size_t w, b;
    kryptos_ld_user_key_prologue(key, 8, user_key, user_key_size, kp, kp_end, w, b, return);

    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);

    kryptos_ld_user_key_epilogue(kryptos_aes_ld_user_key_epilogue, key, w, b, kp, kp_end);
}


static void kryptos_serpent_key_schedule(const kryptos_u8_t *key, const size_t key_size, struct kryptos_serpent_subkeys *sks) {
    // INFO(Rafael): This function expands the user key to 132 32-bit values.
    kryptos_u32_t wkey[8];
    kryptos_u32_t tw[140];
    kryptos_u8_t nibble, bfar[128], outp[128];
    size_t w, b, x;
    kryptos_u8_t padded_ukey[32];

    memset(wkey,0, sizeof(kryptos_u32_t) << 3);
    memcpy(padded_ukey, key, key_size);

    if (key_size < 32){ // INFO(Rafael): We must pad the user-key if it has less than 256-bits.
        padded_ukey[key_size] = 0x80;
        memset(&padded_ukey[key_size+1], 0, sizeof(padded_ukey) - key_size + 1);
     }

    kryptos_serpent_ld_user_key(wkey, padded_ukey, sizeof(padded_ukey));

    tw[0] = wkey[3];
    tw[1] = wkey[2];
    tw[2] = wkey[1];

    tw[3] = wkey[0];
    tw[4] = wkey[7];
    tw[5] = wkey[6];
    tw[6] = wkey[5];
    tw[7] = wkey[4];

    for(w = 8; w < 140; w++) {
        tw[w] = kryptos_serpent_u32_rl((tw[w-8] ^ tw[w-5] ^ tw[w-3] ^ tw[w-1] ^ kryptos_serpent_phi ^ (w-8)), 11);
    }

    // INFO(Rafael): Eliminating the initial eight 32-bit values previously used.
    kryptos_serpent_lshift_u32(tw, 140);
    kryptos_serpent_lshift_u32(tw, 140);
    kryptos_serpent_lshift_u32(tw, 140);
    kryptos_serpent_lshift_u32(tw, 140);
    kryptos_serpent_lshift_u32(tw, 140);
    kryptos_serpent_lshift_u32(tw, 140);
    kryptos_serpent_lshift_u32(tw, 140);
    kryptos_serpent_lshift_u32(tw, 140);

    for (w = 0, x = 0; w < 132; w += 4, x++) {
        wkey[0] = wkey[1] = wkey[2] = wkey[3] = 0;
        for (b = 0; b < 32; b++) {
            nibble = kryptos_serpent_mku4(tw[w+3], tw[w+2], tw[w+1], tw[w],b);

            switch (w % 32) {
                case  0:
                case  1:
                case  2:
                case  3:
                    nibble = kryptos_serpentS(nibble, kryptos_serpent_boxes[3]);
                    break;

                case  4:
                case  5:
                case  6:
                case  7:
                    nibble = kryptos_serpentS(nibble, kryptos_serpent_boxes[2]);
                    break;

                case  8:
                case  9:
                case 10:
                case 11:
                    nibble = kryptos_serpentS(nibble, kryptos_serpent_boxes[1]);
                    break;

                case 12:
                case 13:
                case 14:
                case 15:
                    nibble = kryptos_serpentS(nibble, kryptos_serpent_boxes[0]);
                    break;

                case 16:
                case 17:
                case 18:
                case 19:
                    nibble = kryptos_serpentS(nibble, kryptos_serpent_boxes[7]);
                    break;

                case 20:
                case 21:
                case 22:
                case 23:
                    nibble = kryptos_serpentS(nibble, kryptos_serpent_boxes[6]);
                    break;

                case 24:
                case 25:
                case 26:
                case 27:
                    nibble = kryptos_serpentS(nibble, kryptos_serpent_boxes[5]);
                    break;

                case 28:
                case 29:
                case 30:
                case 31:
                    nibble = kryptos_serpentS(nibble, kryptos_serpent_boxes[4]);
                    break;
            }

            wkey[0] |= (kryptos_u32_t) kryptos_serpent_get_u1_from_u4(nibble, 0) << b;
            wkey[1] |= (kryptos_u32_t) kryptos_serpent_get_u1_from_u4(nibble, 1) << b;
            wkey[2] |= (kryptos_u32_t) kryptos_serpent_get_u1_from_u4(nibble, 2) << b;
            wkey[3] |= (kryptos_u32_t) kryptos_serpent_get_u1_from_u4(nibble, 3) << b;
        }

        // CLUE(Rafael): It will be adjusted later during the permutation.
        sks->k[x][0] = wkey[0];
        sks->k[x][1] = wkey[1];
        sks->k[x][2] = wkey[2];
        sks->k[x][3] = wkey[3];

        // INFO(Rafael): Permutation.
        kryptos_serpent_permutation(sks->k[x], sks->k[x], kryptos_serpent_ip);
    }

    memset(padded_ukey, 0, sizeof(padded_ukey));
    memset(wkey, 0, sizeof(wkey));
    memset(tw, 0, sizeof(tw));
    memset(bfar, 0, sizeof(bfar));
    memset(outp, 0, sizeof(outp));
    w = b = x = 0;
}

static void kryptos_serpent_permutation(const kryptos_u32_t in[4], kryptos_u32_t out[4], const kryptos_u8_t p[128]) {
    kryptos_u32_t t[4];
    kryptos_u8_t bfar[128], outp[128];

    kryptos_serpent_ld_u32buf_into_u8buf(bfar, in, 128);
    kryptos_serpentXP(bfar, outp, p);
    kryptos_serpent_ld_u8buf_into_u32buf(t, outp, 128);

    out[0] = t[3];
    out[1] = t[2];
    out[2] = t[1];
    out[3] = t[0];
}

static void kryptos_serpent_lshift_u32(kryptos_u32_t *inout, const size_t level) {
    size_t w;
    for (w = 1; w < level; w++) {
        inout[w-1] = inout[w];
    }
}

static kryptos_u8_t kryptos_serpent_mku4(kryptos_u32_t w0, kryptos_u32_t w1, kryptos_u32_t w2, kryptos_u32_t w3, const int b) {
    w0 = kryptos_serpent_u32_rl(w0, 31 - b) >> 31;
    w1 = kryptos_serpent_u32_rl(w1, 31 - b) >> 31;
    w2 = kryptos_serpent_u32_rl(w2, 31 - b) >> 31;
    w3 = kryptos_serpent_u32_rl(w3, 31 - b) >> 31;
    return (kryptos_u8_t) (w0 << 3 | w1 << 2 | w2 << 1 | w3);
}

static void kryptos_serpent_block_encrypt(kryptos_u8_t *block, struct kryptos_serpent_subkeys sks) {
    kryptos_u32_t b[4], t[4];
    kryptos_u8_t ltout[128], ltin[128];
    size_t r, box;

    t[0] = kryptos_get_u32_as_big_endian(block, 4);
    t[1] = kryptos_get_u32_as_big_endian(block + 4, 4);
    t[2] = kryptos_get_u32_as_big_endian(block + 8, 4);
    t[3] = kryptos_get_u32_as_big_endian(block + 12, 4);

    // INFO(Rafael): Initial permutation.
    kryptos_serpent_permutation(t, b, kryptos_serpent_ip);

    for (r = 0, box = 0; r < 31; r++, box = (box + 1) % 8) {
        b[0] ^= sks.k[r][0]; // INFO(Rafael): xoring.
        b[1] ^= sks.k[r][1];
        b[2] ^= sks.k[r][2];
        b[3] ^= sks.k[r][3];
        // INFO(Rafael): sbox.
        kryptos_serpentSRound(b, box);
        kryptos_serpent_ld_inv_u32buf_into_u8buf(ltin, b, 128);
        // INFO(Rafael): linear transforming.
        kryptos_serpentLTRound(ltout, ltin);
        kryptos_serpent_ld_inv_u8buf_into_u32buf(b, ltout, 128);
    }
    // INFO(Rafael): The last round.
    b[0] ^= sks.k[31][0]; // INFO(Rafael): xoring.
    b[1] ^= sks.k[31][1];
    b[2] ^= sks.k[31][2];
    b[3] ^= sks.k[31][3];
    // INFO(Rafael): sbox.
    kryptos_serpentSRound(b, 7);
    b[0] ^= sks.k[32][0]; // INFO(Rafael): xoring instead of lt.
    b[1] ^= sks.k[32][1];
    b[2] ^= sks.k[32][2];
    b[3] ^= sks.k[32][3];
    kryptos_serpent_permutation(b, b, kryptos_serpent_fp); // INFO(Rafael): Final permutation.

    kryptos_cpy_u32_as_big_endian(block, 16, b[3]);
    kryptos_cpy_u32_as_big_endian(block + 4, 12, b[2]);
    kryptos_cpy_u32_as_big_endian(block + 8, 8, b[1]);
    kryptos_cpy_u32_as_big_endian(block + 12, 4, b[0]);

    memset(b, 0, sizeof(b));
    memset(ltout, 0, sizeof(ltout));
    memset(ltin, 0, sizeof(ltin));
    memset(t, 0, sizeof(t));
}

static void kryptos_serpent_ld_inv_u32buf_into_u8buf(kryptos_u8_t *output, const kryptos_u32_t *source, size_t bit_size) {
    size_t w = 0;

    while (w < bit_size) {
        output[w + 31] = (*source & kryptos_serpent_bitmask00) >> 31;
        output[w + 30] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask01),  1) >> 31;
        output[w + 29] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask02),  2) >> 31;
        output[w + 28] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask03),  3) >> 31;
        output[w + 27] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask04),  4) >> 31;
        output[w + 26] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask05),  5) >> 31;
        output[w + 25] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask06),  6) >> 31;
        output[w + 24] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask07),  7) >> 31;
        output[w + 23] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask08),  8) >> 31;
        output[w + 22] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask09),  9) >> 31;
        output[w + 21] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask10), 10) >> 31;
        output[w + 20] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask11), 11) >> 31;
        output[w + 19] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask12), 12) >> 31;
        output[w + 18] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask13), 13) >> 31;
        output[w + 17] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask14), 14) >> 31;
        output[w + 16] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask15), 15) >> 31;
        output[w + 15] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask16), 16) >> 31;
        output[w + 14] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask17), 17) >> 31;
        output[w + 13] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask18), 18) >> 31;
        output[w + 12] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask19), 19) >> 31;
        output[w + 11] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask20), 20) >> 31;
        output[w + 10] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask21), 21) >> 31;
        output[w +  9] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask22), 22) >> 31;
        output[w +  8] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask23), 23) >> 31;
        output[w +  7] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask24), 24) >> 31;
        output[w +  6] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask25), 25) >> 31;
        output[w +  5] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask26), 26) >> 31;
        output[w +  4] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask27), 27) >> 31;
        output[w +  3] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask28), 28) >> 31;
        output[w +  2] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask29), 29) >> 31;
        output[w +  1] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask30), 30) >> 31;
        output[     w] = kryptos_serpent_u32_rl((*source & kryptos_serpent_bitmask31), 31) >> 31;
        w += 32;
        source++;
    }
}

static void kryptos_serpent_ld_inv_u8buf_into_u32buf(kryptos_u32_t *output, kryptos_u8_t source[128], size_t bit_size) {
    size_t w, b, from = 32, w_limit = (bit_size / from);
    for (w = 0, b = from-1, output[w] = 0; w < w_limit; b--) {
        output[w] = output[w] << 1 | (kryptos_u32_t) source[b];
        if ((b) % from == 0) {
            w++;
            output[w] = 0;
            b = (from * (w + 1));
        }
    }
}

static void kryptos_serpent_block_decrypt(kryptos_u8_t *block, struct kryptos_serpent_subkeys sks) {
    kryptos_u32_t b[4], t[4];
    kryptos_u8_t ltout[128], ltin[128];
    ssize_t r, box;

    t[0] = kryptos_get_u32_as_big_endian(block, 4);
    t[1] = kryptos_get_u32_as_big_endian(block + 4, 4);
    t[2] = kryptos_get_u32_as_big_endian(block + 8, 4);
    t[3] = kryptos_get_u32_as_big_endian(block + 12, 4);

    // INFO(Rafael): Initial permutation.
    kryptos_serpent_permutation(t, b, kryptos_serpent_ip);

    // INFO(Rafael): The last round.
    b[0] ^= sks.k[32][0]; // INFO(Rafael): xoring.
    b[1] ^= sks.k[32][1];
    b[2] ^= sks.k[32][2];
    b[3] ^= sks.k[32][3];
    // INFO(Rafael): sbox.
    kryptos_serpentInvSRound(b, 7);
    b[0] ^= sks.k[31][0]; // INFO(Rafael): xoring instead of lt.
    b[1] ^= sks.k[31][1];
    b[2] ^= sks.k[31][2];
    b[3] ^= sks.k[31][3];

    for (r = 30, box = 6; r >= 0; r--, (box > 0 ? box -- : (box = 7))) {
        kryptos_serpent_ld_inv_u32buf_into_u8buf(ltin, b, 128);
        // INFO(Rafael): linear transforming.
        kryptos_serpentInvLTRound(ltout, ltin);
        kryptos_serpent_ld_inv_u8buf_into_u32buf(b, ltout, 128);
        // INFO(Rafael): sbox.
        kryptos_serpentInvSRound(b, box);
        b[0] ^= sks.k[r][0]; // INFO(Rafael): xoring.
        b[1] ^= sks.k[r][1];
        b[2] ^= sks.k[r][2];
        b[3] ^= sks.k[r][3];
    }

    kryptos_serpent_permutation(b, b, kryptos_serpent_fp); // INFO(Rafael): Final permutation.

    kryptos_cpy_u32_as_big_endian(block, 16, b[3]);
    kryptos_cpy_u32_as_big_endian(block + 4, 12, b[2]);
    kryptos_cpy_u32_as_big_endian(block + 8, 8, b[1]);
    kryptos_cpy_u32_as_big_endian(block + 12, 4, b[0]);

    memset(b, 0, sizeof(b));
    memset(ltout, 0, sizeof(ltout));
    memset(ltin, 0, sizeof(ltin));
    memset(t, 0, sizeof(t));
}
